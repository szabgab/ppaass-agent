pub(crate) mod dispatcher;
mod http;

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use self::dispatcher::ClientTransportHandshakeInfo;
use crate::{config::AGENT_CONFIG, crypto::AgentServerRsaCryptoFetcher, error::AgentError};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use futures::{
    stream::{SplitSink, SplitStream},
    Sink, SinkExt, Stream,
};

use log::error;
use pin_project::pin_project;

use ppaass_io::Connection;
use ppaass_protocol::error::ProtocolError;
use ppaass_protocol::message::{
    AgentTcpPayload, Encryption, NetAddress, PayloadType, ProxyTcpPayload, WrapperMessage,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
};

use tokio_util::codec::{BytesCodec, Framed};

#[pin_project]
struct ClientConnectionWrite<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    src_address: NetAddress,

    #[pin]
    client_bytes_framed_write: SplitSink<Framed<T, BytesCodec>, BytesMut>,
}

impl<T> ClientConnectionWrite<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        src_address: NetAddress,
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
            .map_err(|e| AgentError::Io(e))
    }

    fn start_send(self: Pin<&mut Self>, item: BytesMut) -> Result<(), Self::Error> {
        let this = self.project();
        this.client_bytes_framed_write
            .start_send(item)
            .map_err(|e| AgentError::Io(e))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.client_bytes_framed_write
            .poll_flush(cx)
            .map_err(|e| AgentError::Io(e))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.client_bytes_framed_write
            .poll_close(cx)
            .map_err(|e| AgentError::Io(e))
    }
}

#[pin_project]
struct ClientConnectionRead<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    src_address: NetAddress,
    #[pin]
    client_bytes_framed_read: SplitStream<Framed<T, BytesCodec>>,
}

impl<T> ClientConnectionRead<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    fn new(
        src_address: NetAddress,
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
            .map_err(|e| AgentError::Io(e))
    }
}

pub(crate) enum ClientTransportDataRelayInfo {
    Tcp(ClientTransportTcpDataRelay),
    Udp(ClientTransportUdpDataRelay),
}

#[non_exhaustive]
pub(crate) struct ClientTransportTcpDataRelay {
    client_tcp_stream: TcpStream,
    src_address: NetAddress,
    dst_address: NetAddress,
    proxy_connection: Connection<TcpStream, Arc<AgentServerRsaCryptoFetcher>>,
    init_data: Option<Bytes>,
    connection_id: String,
}

#[non_exhaustive]
pub(crate) struct ClientTransportUdpDataRelay {
    client_tcp_stream: TcpStream,
    agent_udp_bind_socket: UdpSocket,
    client_udp_restrict_address: NetAddress,
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
            client_tcp_stream,
            src_address,
            dst_address,
            mut proxy_connection,
            init_data,
            connection_id,
        } = tcp_relay_info;

        let client_io_framed = Framed::with_capacity(
            client_tcp_stream,
            BytesCodec::new(),
            AGENT_CONFIG.get_client_receive_buffer_size(),
        );
        let (client_io_write, client_io_read) = client_io_framed.split::<BytesMut>();
        let (mut client_io_write, mut client_io_read) = (
            ClientConnectionWrite::new(src_address.clone(), client_io_write),
            ClientConnectionRead::new(src_address.clone(), client_io_read),
        );
        if let Some(init_data) = init_data {
            let agent_tcp_data = ppaass_protocol::new_agent_tcp_data(
                user_token.to_string(),
                connection_id.clone(),
                init_data,
            )?;
            proxy_connection.send(agent_tcp_data).await?;
        }

        let (mut proxy_connection_write, mut proxy_connection_read) = proxy_connection.split();

        tokio::spawn(async move {
            loop {
                let client_message = match client_io_read.next().await {
                    None => return,
                    Some(Err(e)) => {
                        error!("Fail to read client message because of error: {e:?}");
                        return;
                    }
                    Some(Ok(client_message)) => client_message,
                };

                let agent_tcp_data = match ppaass_protocol::new_agent_tcp_data(
                    user_token.to_string(),
                    connection_id.clone(),
                    client_message.freeze(),
                ) {
                    Ok(agent_tcp_data) => agent_tcp_data,
                    Err(e) => {
                        error!("Fail to create agent tcp data because of error: {e:?}");
                        continue;
                    }
                };

                if let Err(e) = proxy_connection_write.send(agent_tcp_data).await {
                    return;
                };
            }
        });

        tokio::spawn(async move {
            loop {
                let proxy_wrapped_message = match proxy_connection_read.next().await {
                    None => return,
                    Some(Err(e)) => {
                        error!("Fail to read proxy message because of error: {e:?}");
                        return;
                    }
                    Some(Ok(proxy_wrapped_message)) => proxy_wrapped_message,
                };
                if proxy_wrapped_message.payload_type != PayloadType::Tcp {
                    return;
                }
                let proxy_message_payload = proxy_wrapped_message.payload;
                if let Ok(ProxyTcpPayload::Data {
                    connection_id,
                    data,
                }) = proxy_message_payload.try_into()
                {
                    let mut bytes_to_send = BytesMut::new();
                    bytes_to_send.extend_from_slice(&data);
                    client_io_write.send(bytes_to_send).await;
                    return;
                };
            }
        });

        Ok(())
    }
}
