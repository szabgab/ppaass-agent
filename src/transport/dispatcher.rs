use std::sync::Arc;
use std::{mem::size_of, net::SocketAddr};

use bytes::BytesMut;
use futures_util::StreamExt;

use ppaass_crypto::crypto::RsaCryptoFetcher;
use tracing::{debug, error};

use tokio::net::TcpStream;

use tokio_util::codec::{Decoder, Framed, FramedParts};

use crate::{
    config::AgentConfig,
    error::AgentError,
    proxy::ProxyConnectionFactory,
    transport::{http::HttpClientTransport, socks::Socks5ClientTransport},
    SOCKS_V4, SOCKS_V5,
};

pub(crate) enum ClientTransport<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    Socks5(Socks5ClientTransport<F>),
    Http(HttpClientTransport<F>),
}

pub(crate) enum ClientProtocol {
    /// The client side choose to use HTTP proxy
    Http,
    /// The client side choose to use Socks5 proxy
    Socks5,
    /// The client side choose to use Socks4 proxy
    Socks4,
}

pub(crate) struct SwitchClientProtocolDecoder;

impl Decoder for SwitchClientProtocolDecoder {
    type Item = ClientProtocol;

    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Use the first byte to decide what protocol the client side is using.
        if src.len() < size_of::<u8>() {
            return Ok(None);
        }
        let protocol_flag = src[0];
        match protocol_flag {
            SOCKS_V5 => Ok(Some(ClientProtocol::Socks5)),
            SOCKS_V4 => Ok(Some(ClientProtocol::Socks4)),
            _ => Ok(Some(ClientProtocol::Http)),
        }
    }
}

pub(crate) struct ClientTransportDispatcher<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    config: Arc<AgentConfig>,
    proxy_connection_factory: Arc<ProxyConnectionFactory<F>>,
}

impl<F> ClientTransportDispatcher<F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub(crate) fn new(
        config: Arc<AgentConfig>,
        proxy_connection_factory: ProxyConnectionFactory<F>,
    ) -> Self {
        Self {
            config,
            proxy_connection_factory: Arc::new(proxy_connection_factory),
        }
    }

    pub(crate) async fn dispatch(
        &self,
        client_tcp_stream: TcpStream,
        client_socket_address: SocketAddr,
    ) -> Result<ClientTransport<F>, AgentError> {
        let mut client_message_framed = Framed::with_capacity(
            client_tcp_stream,
            SwitchClientProtocolDecoder,
            self.config.client_receive_buffer_size(),
        );
        let client_protocol = match client_message_framed.next().await {
            Some(Ok(client_protocol)) => client_protocol,
            Some(Err(e)) => {
                error!("Fail to read protocol from client io because of error: {e:?}");
                return Err(e);
            }
            None => {
                error!("Fail to read protocol from client io because of nothing to read.");
                return Err(AgentError::Other(format!(
                    "Nothing to read from client: {client_socket_address}"
                )));
            }
        };

        match client_protocol {
            ClientProtocol::Socks5 => {
                // For socks5 protocol
                let FramedParts {
                    io: client_tcp_stream,
                    read_buf: initial_buf,
                    ..
                } = client_message_framed.into_parts();
                debug!("Client tcp connection [{client_socket_address}] begin to serve socks 5 protocol");
                Ok(ClientTransport::Socks5(Socks5ClientTransport::new(
                    client_tcp_stream,
                    client_socket_address.into(),
                    initial_buf,
                    client_socket_address,
                    self.config.clone(),
                    self.proxy_connection_factory.clone(),
                )))
            }
            ClientProtocol::Socks4 => {
                // For socks4 protocol
                error!("Client tcp connection [{client_socket_address}] do not support socks v4 protocol");
                Err(AgentError::Other(format!("Client tcp connection [{client_socket_address}] do not support socks v4 protocol")))
            }
            ClientProtocol::Http => {
                // For http protocol
                let FramedParts {
                    io: client_tcp_stream,
                    read_buf: initial_buf,
                    ..
                } = client_message_framed.into_parts();
                debug!(
                    "Client tcp connection [{client_socket_address}] begin to serve http protocol"
                );
                Ok(ClientTransport::Http(HttpClientTransport::new(
                    client_tcp_stream,
                    client_socket_address.into(),
                    initial_buf,
                    client_socket_address,
                    self.config.clone(),
                    self.proxy_connection_factory.clone(),
                )))
            }
        }
    }
}
