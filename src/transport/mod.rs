pub(crate) mod dispatcher;
mod http;
mod socks;

use crate::{config::AGENT_CONFIG, error::AgentError};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};

use tracing::{debug, error};

use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::ProxyTcpPayload;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryption;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassProxyMessage, PpaassProxyMessagePayload};
use scopeguard::ScopeGuard;

use crate::codec::PpaassProxyEdgeCodec;

use crate::transport::http::HttpClientTransport;
use crate::transport::socks::Socks5ClientTransport;
use tokio::net::TcpStream;
use tokio_io_timeout::TimeoutStream;
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_util::codec::{BytesCodec, Framed};

pub(crate) const TRANSPORT_MONITOR_FILE_PREFIX: &str = "transport";

#[non_exhaustive]
pub(crate) struct ClientTransportTcpDataRelay<T: FnOnce(String) + Send + 'static> {
    transport_id: String,
    client_tcp_stream: TcpStream,
    src_address: PpaassUnifiedAddress,
    dst_address: PpaassUnifiedAddress,
    proxy_connection_write:
        SplitSink<Framed<TimeoutStream<TcpStream>, PpaassProxyEdgeCodec>, PpaassAgentMessage>,
    proxy_connection_read: SplitStream<Framed<TimeoutStream<TcpStream>, PpaassProxyEdgeCodec>>,
    init_data: Option<Bytes>,
    payload_encryption: PpaassMessagePayloadEncryption,
    transport_number_scopeguard: ScopeGuard<String, T>,
}

pub(crate) enum ClientTransport {
    Socks5(Socks5ClientTransport),
    Http(HttpClientTransport),
}

pub async fn tcp_relay<T: FnOnce(String) + Send + 'static>(
    tcp_relay_info: ClientTransportTcpDataRelay<T>,
) -> Result<(), AgentError> {
    let user_token = AGENT_CONFIG.get_user_token();
    let ClientTransportTcpDataRelay {
        transport_id,
        client_tcp_stream,
        src_address,
        dst_address,
        mut proxy_connection_write,
        proxy_connection_read,
        init_data,
        payload_encryption,
        transport_number_scopeguard,
    } = tcp_relay_info;
    let mut client_tcp_stream = TimeoutStream::new(client_tcp_stream);
    client_tcp_stream.set_write_timeout(Some(Duration::from_secs(120)));
    client_tcp_stream.set_read_timeout(Some(Duration::from_secs(120)));
    debug!(
        "Agent going to relay tcp data from source: {src_address} to destination: {dst_address}"
    );
    let client_io_framed = Framed::with_capacity(
        client_tcp_stream,
        BytesCodec::new(),
        AGENT_CONFIG.get_client_receive_buffer_size(),
    );
    let (mut client_io_write, client_io_read) = client_io_framed.split::<BytesMut>();

    if let Some(init_data) = init_data {
        let agent_message = PpaassMessageGenerator::generate_agent_tcp_data_message(
            user_token.to_string(),
            payload_encryption.clone(),
            init_data,
        )?;
        proxy_connection_write.send(agent_message).await?;
    }

    {
        let transport_id = transport_id.clone();
        let dst_address = dst_address.clone();
        tokio::spawn(async move {
            // Forward client data to proxy
            if let Err(e) = TokioStreamExt::map_while(client_io_read, |client_message| {
                let client_message = client_message.ok()?;
                let tcp_data = PpaassMessageGenerator::generate_agent_tcp_data_message(
                    user_token.to_string(),
                    payload_encryption.clone(),
                    client_message.freeze(),
                )
                .ok()?;
                Some(Ok(tcp_data))
            })
            .forward(&mut proxy_connection_write)
            .await
            {
                error!("Tunnel {transport_id} error happen when relay tcp data from client to proxy for destination [{dst_address}], error: {e:?}");
            }
            if let Err(e) = proxy_connection_write.close().await {
                error!(
                    "Tunnel {transport_id} fail to close proxy connection beccause of error: {e:?}"
                );
            };
        });
    }

    tokio::spawn(async move {
        let _transport_number_scopeguard = transport_number_scopeguard;
        if let Err(e) = TokioStreamExt::map_while(proxy_connection_read, |proxy_message| {
            let proxy_message = proxy_message.ok()?;
            let PpaassProxyMessage {
                payload: PpaassProxyMessagePayload::Tcp(ProxyTcpPayload::Data { content }),
                ..
            } = proxy_message
            else {
                error!("Fail to parse proxy message payload because of not a tcp data");
                return None;
            };
            Some(Ok(BytesMut::from_iter(content)))
        })
        .forward(&mut client_io_write)
        .await
        {
            error!("Tunnel {transport_id} error happen when relay tcp data from proxy to client for destination [{dst_address}], error: {e:?}",);
        }
        if let Err(e) = client_io_write.close().await {
            error!(
                "Tunnel {transport_id} fail to close client connection beccause of error: {e:?}"
            );
        };
    });

    Ok(())
}
