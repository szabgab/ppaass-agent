pub(crate) mod dispatcher;
mod http;
mod socks;

use self::dispatcher::ClientTransportHandshakeInfo;
use crate::{config::AGENT_CONFIG, error::AgentError};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};

use log::{debug, error};

use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::ProxyTcpPayload;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryption;
use ppaass_protocol::message::{PpaassAgentMessage, PpaassProxyMessage, PpaassProxyMessagePayload};

use crate::codec::PpaassProxyEdgeCodec;

use tokio::net::{TcpStream, UdpSocket};
use tokio_io_timeout::TimeoutStream;
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_util::codec::{BytesCodec, Framed};

pub(crate) enum ClientTransportDataRelayInfo {
    Tcp(ClientTransportTcpDataRelay),
    Udp(ClientTransportUdpDataRelay),
}

#[non_exhaustive]
pub(crate) struct ClientTransportTcpDataRelay {
    tunnel_id: String,
    client_tcp_stream: TcpStream,
    src_address: PpaassUnifiedAddress,
    dst_address: PpaassUnifiedAddress,
    proxy_connection_write:
        SplitSink<Framed<TimeoutStream<TcpStream>, PpaassProxyEdgeCodec>, PpaassAgentMessage>,
    proxy_connection_read: SplitStream<Framed<TimeoutStream<TcpStream>, PpaassProxyEdgeCodec>>,
    init_data: Option<Bytes>,
    payload_encryption: PpaassMessagePayloadEncryption,
}

#[non_exhaustive]
pub(crate) struct ClientTransportUdpDataRelay {
    client_tcp_stream: TcpStream,
    agent_udp_bind_socket: UdpSocket,
    client_udp_restrict_address: PpaassUnifiedAddress,
}

#[async_trait]
pub(crate) trait ClientTransportHandshake {
    async fn handshake(
        &self,
        handshake_info: ClientTransportHandshakeInfo,
    ) -> Result<
        (
            ClientTransportDataRelayInfo,
            Box<dyn ClientTransportRelay + Send + Sync>,
        ),
        AgentError,
    >;
}

#[async_trait]
pub(crate) trait ClientTransportRelay {
    async fn udp_relay(
        &self,
        _udp_relay_info: ClientTransportUdpDataRelay,
    ) -> Result<(), AgentError> {
        Ok(())
    }

    async fn tcp_relay(
        &self,
        tcp_relay_info: ClientTransportTcpDataRelay,
    ) -> Result<(), AgentError> {
        let user_token = AGENT_CONFIG.get_user_token();
        let ClientTransportTcpDataRelay {
            tunnel_id,
            client_tcp_stream,
            src_address,
            dst_address,
            mut proxy_connection_write,
            proxy_connection_read,
            init_data,
            payload_encryption,
        } = tcp_relay_info;

        debug!("Agent going to relay tcp data from source: {src_address} to destination: {dst_address}");
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
            let tunnel_id = tunnel_id.clone();
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
                    error!("Tunnel {tunnel_id} error happen when relay tcp data from client to proxy for destination [{dst_address}], error: {e:?}");
                }
                if let Err(e) = proxy_connection_write.close().await {
                    error!("Tunnel {tunnel_id} fail to close proxy connection beccause of error: {e:?}");
                };
            });
        }

        tokio::spawn(async move {
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
                error!("Tunnel {tunnel_id} error happen when relay tcp data from proxy to client for destination [{dst_address}], error: {e:?}",);
            }
            if let Err(e) = client_io_write.close().await {
                error!(
                    "Tunnel {tunnel_id} fail to close client connection beccause of error: {e:?}"
                );
            };
        });

        Ok(())
    }
}
