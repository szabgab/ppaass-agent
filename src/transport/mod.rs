pub(crate) mod dispatcher;
mod http;
mod socks;

use crate::{config::AGENT_CONFIG, error::AgentError, trace};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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

use crate::trace::{TraceSubscriber, TransportTraceType};

use tokio::net::TcpStream;
use tokio_io_timeout::TimeoutStream;
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_util::codec::{BytesCodec, Framed};

pub(crate) const TRANSPORT_MONITOR_FILE_PREFIX: &str = "transport";

struct ClientTransportTcpDataRelay<T: FnOnce(String) + Send + 'static> {
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

fn generate_transport_number_scopeguard(
    transport_number: Arc<AtomicU64>,
    transport_trace_subscriber: Arc<TraceSubscriber>,
    transport_id: &str,
) -> ScopeGuard<String, impl FnOnce(String)> {
    let transport_trace_subscriber = transport_trace_subscriber.clone();
    let transport_number = transport_number.clone();
    scopeguard::guard(transport_id.to_string(), move |transport_id| {
        transport_number.fetch_sub(1, Ordering::Release);
        trace::trace_transport(
            transport_trace_subscriber,
            TransportTraceType::DropTcp,
            &transport_id,
            transport_number,
        );
        debug!("Transport [{transport_id}] dropped in tcp process",)
    })
}

async fn tcp_relay<T: FnOnce(String) + Send + 'static>(
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
            let client_io_read = TokioStreamExt::fuse(client_io_read);
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
                error!("Transport [{transport_id}] error happen when relay tcp data from client to proxy for destination [{dst_address}], error: {e:?}");
            }
            if let Err(e) = proxy_connection_write.close().await {
                error!(
                    "Transport [{transport_id}] fail to close proxy connection beccause of error: {e:?}"
                );
            };
        });
    }

    tokio::spawn(async move {
        let _transport_number_scopeguard = transport_number_scopeguard;
        let proxy_connection_read = TokioStreamExt::fuse(proxy_connection_read);
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
            error!("Transport [{transport_id}] error happen when relay tcp data from proxy to client for destination [{dst_address}], error: {e:?}",);
        }
        if let Err(e) = client_io_write.close().await {
            error!(
                "Transport [{transport_id}] fail to close client connection beccause of error: {e:?}"
            );
        };
    });

    Ok(())
}
