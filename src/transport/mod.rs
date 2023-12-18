pub(crate) mod dispatcher;
mod http;
mod socks;

use crate::config::AGENT_CONFIG;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use futures::StreamExt as FuturesStreamExt;
use futures::{
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream,
};
use log::error;

use pin_project::pin_project;
use ppaass_protocol::message::agent::{
    AgentMessage, AgentMessagePayload, RelayData as AgentRelayData,
};
use ppaass_protocol::message::proxy::RelayData as ProxyRelayData;
use ppaass_protocol::message::proxy::{ProxyMessage, ProxyMessagePayload};
use ppaass_protocol::values::address::UnifiedNetAddress;
use ppaass_protocol::values::security::{Encryption, SecureInfo};

use crate::codec::ProxyConnectionCodec;
use crate::error::AgentError;
use crate::util::random_32_bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
};
use tokio_stream::StreamExt as TokioStreamExt;
use tokio_util::codec::{BytesCodec, Framed};
use uuid::Uuid;

#[pin_project]
struct ClientConnectionWrite<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    src_address: UnifiedNetAddress,

    #[pin]
    client_bytes_framed_write: SplitSink<Framed<T, BytesCodec>, BytesMut>,
}

impl<T> ClientConnectionWrite<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        src_address: UnifiedNetAddress,
        client_bytes_framed_write: SplitSink<Framed<T, BytesCodec>, BytesMut>,
    ) -> Self {
        Self {
            src_address,
            client_bytes_framed_write,
        }
    }
}

impl<T> Sink<BytesMut> for ClientConnectionWrite<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Error = AgentError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.client_bytes_framed_write
            .poll_ready(cx)
            .map_err(crate::error::AgentError::GeneralIo)
    }

    fn start_send(self: Pin<&mut Self>, item: BytesMut) -> Result<(), Self::Error> {
        let this = self.project();
        this.client_bytes_framed_write
            .start_send(item)
            .map_err(crate::error::AgentError::GeneralIo)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.client_bytes_framed_write
            .poll_flush(cx)
            .map_err(crate::error::AgentError::GeneralIo)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.client_bytes_framed_write
            .poll_close(cx)
            .map_err(crate::error::AgentError::GeneralIo)
    }
}

#[pin_project]
struct ClientConnectionRead<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    src_address: UnifiedNetAddress,
    #[pin]
    client_bytes_framed_read: SplitStream<Framed<T, BytesCodec>>,
}

impl<T> ClientConnectionRead<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        src_address: UnifiedNetAddress,
        client_bytes_framed_read: SplitStream<Framed<T, BytesCodec>>,
    ) -> Self {
        Self {
            src_address,
            client_bytes_framed_read,
        }
    }
}

impl<T> Stream for ClientConnectionRead<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    type Item = Result<BytesMut, AgentError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        this.client_bytes_framed_read
            .poll_next(cx)
            .map_err(crate::error::AgentError::GeneralIo)
    }
}

pub(crate) enum ClientTransportDataRelayInfo {
    Tcp(ClientTransportTcpDataRelay),
    Udp(ClientTransportUdpDataRelay),
}

#[non_exhaustive]
pub(crate) struct ClientTransportTcpDataRelay {
    client_tcp_stream: TcpStream,
    src_address: UnifiedNetAddress,
    dst_address: UnifiedNetAddress,
    proxy_connection: Framed<TcpStream, ProxyConnectionCodec>,
    init_data: Option<Bytes>,
    agent_edge_id: String,
    proxy_edge_id: String,
}

#[non_exhaustive]
pub(crate) struct ClientTransportUdpDataRelay {
    client_tcp_stream: TcpStream,
    agent_udp_bind_socket: UdpSocket,
    client_udp_restrict_address: UnifiedNetAddress,
    agent_edge_id: String,
    proxy_edge_id: String,
}

pub(crate) struct ClientTransportRelay {}

impl ClientTransportRelay {
    pub(crate) async fn tcp_relay(
        tcp_relay_info: ClientTransportTcpDataRelay,
    ) -> Result<(), AgentError> {
        let user_token = AGENT_CONFIG
            .get_user_token()
            .ok_or(AgentError::Other("User token not configured.".to_string()))?;
        let ClientTransportTcpDataRelay {
            client_tcp_stream,
            src_address,
            dst_address,
            mut proxy_connection,
            init_data,
            agent_edge_id,
            proxy_edge_id,
        } = tcp_relay_info;
        let client_io_framed = Framed::with_capacity(
            client_tcp_stream,
            BytesCodec::new(),
            AGENT_CONFIG.get_client_receive_buffer_size(),
        );
        let (client_io_write, client_io_read) = client_io_framed.split::<BytesMut>();
        let (mut client_io_write, client_io_read) = (
            ClientConnectionWrite::new(src_address.clone(), client_io_write),
            ClientConnectionRead::new(src_address.clone(), client_io_read),
        );

        let (mut proxy_connection_write, proxy_connection_read) = proxy_connection.split();

        tokio::spawn(Self::relay_client_data_to_proxy(
            proxy_connection_write,
            client_io_read,
            user_token.to_string(),
            agent_edge_id.clone(),
            proxy_edge_id.clone(),
            src_address.clone(),
            dst_address.clone(),
            init_data,
        ));
        tokio::spawn(Self::relay_proxy_data_to_client(
            proxy_connection_read,
            client_io_write,
        ));
        Ok(())
    }

    async fn relay_proxy_data_to_client(
        mut proxy_connection_read: SplitStream<Framed<TcpStream, ProxyConnectionCodec>>,
        mut client_io_write: ClientConnectionWrite<TcpStream>,
    ) {
        loop {
            let mut proxy_connection_read = proxy_connection_read
                .timeout(Duration::from_secs(AGENT_CONFIG.get_proxy_relay_timeout()));
            let proxy_message = match proxy_connection_read.try_next().await {
                Ok(Some(Ok(proxy_message))) => proxy_message,
                Ok(Some(Err(e))) => {
                    error!("Fail to read data from proxy because of error: {e:?}");
                    return;
                }
                Ok(None) => {
                    return;
                }
                Err(_) => {
                    return;
                }
            };
            let ProxyMessage {
                message_id,
                secure_info,
                payload,
            } = proxy_message;
            match payload {
                ProxyMessagePayload::InitTunnelResult(_) => {
                    return;
                }
                ProxyMessagePayload::RelayData(ProxyRelayData {
                    agent_edge_id,
                    proxy_edge_id,
                    src_address,
                    dst_address,
                    data,
                }) => {
                    let data = BytesMut::from_iter(data);
                    if let Err(e) = client_io_write.send(data).await {
                        error!("Fail to relay proxy data to client because of error: {e:?}");
                    };
                }
                ProxyMessagePayload::CloseTunnelCommand(_) => {
                    return;
                }
            }
        }
    }

    async fn relay_client_data_to_proxy(
        mut proxy_connection_write: SplitSink<
            Framed<TcpStream, ProxyConnectionCodec>,
            AgentMessage,
        >,
        client_connection_read: ClientConnectionRead<TcpStream>,
        user_token: String,
        agent_edge_id: String,
        proxy_edge_id: String,
        src_address: UnifiedNetAddress,
        dst_address: UnifiedNetAddress,
        init_data: Option<Bytes>,
    ) {
        if let Some(init_data) = init_data {
            let agent_relay_data_message = AgentMessage {
                message_id: Uuid::new_v4().to_string(),
                secure_info: SecureInfo {
                    user_token: user_token.to_string(),
                    encryption: Encryption::Aes(random_32_bytes()),
                },
                payload: AgentMessagePayload::RelayData(AgentRelayData {
                    agent_edge_id: agent_edge_id.clone(),
                    proxy_edge_id: proxy_edge_id.clone(),
                    src_address: src_address.clone(),
                    dst_address: dst_address.clone(),
                    data: init_data,
                }),
            };
            proxy_connection_write
                .send(agent_relay_data_message)
                .await?;
        }
        loop {
            let mut client_connection_read = client_connection_read
                .timeout(Duration::from_secs(AGENT_CONFIG.get_client_relay_timeout()));
            let client_data = match client_connection_read.try_next().await {
                Ok(None) => return,
                Ok(Some(Ok(data))) => data.freeze(),
                Ok(Some(Err(e))) => {
                    return;
                }
                Err(e) => {
                    return;
                }
            };
            let agent_relay_message = AgentMessage {
                message_id: Uuid::new_v4().to_string(),
                secure_info: SecureInfo {
                    user_token: user_token.to_string(),
                    encryption: Encryption::Aes(random_32_bytes()),
                },
                payload: AgentMessagePayload::RelayData(AgentRelayData {
                    agent_edge_id: agent_edge_id.clone(),
                    proxy_edge_id: proxy_edge_id.clone(),
                    src_address: src_address.clone(),
                    dst_address: dst_address.clone(),
                    data: client_data,
                }),
            };
            if let Err(e) = proxy_connection_write.send(agent_relay_message).await {
                error!("Fail to relay client data to proxy because of error: {e:?}");
            }
        }
    }
}
