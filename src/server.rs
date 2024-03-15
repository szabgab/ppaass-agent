use std::net::SocketAddr;

use crate::{config::AgentConfig, error::AgentError};
use crate::{
    crypto::AgentServerRsaCryptoFetcher,
    proxy::ProxyConnectionFactory,
    transport::dispatcher::{ClientTransport, ClientTransportDispatcher},
};

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

pub struct AgentServer<'config>
where
    'config: 'static,
{
    config: &'config AgentConfig,
}

impl<'config> AgentServer<'config> {
    pub(crate) fn new(config: &'config AgentConfig) -> Self {
        Self { config }
    }
    async fn accept_client_connection(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), AgentError> {
        let (client_tcp_stream, client_socket_address) = tcp_listener.accept().await?;
        client_tcp_stream.set_nodelay(true)?;
        Ok((client_tcp_stream, client_socket_address))
    }

    pub async fn start(&mut self) -> Result<(), AgentError> {
        let agent_server_bind_addr = if self.config.get_ipv6() {
            format!("::1:{}", self.config.get_port())
        } else {
            format!("0.0.0.0:{}", self.config.get_port())
        };
        info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
        let tcp_listener = TcpListener::bind(&agent_server_bind_addr).await?;
        let rsa_crypto_fetcher = {
            let rsa_crypto_fetcher = Box::new(AgentServerRsaCryptoFetcher::new(self.config)?);
            Box::leak(rsa_crypto_fetcher)
        };
        let rsa_crypto_fetcher = &*rsa_crypto_fetcher;

        let proxy_connection_factory = {
            let proxy_connection_factory = Box::new(ProxyConnectionFactory::new(
                self.config,
                rsa_crypto_fetcher,
            )?);
            Box::leak(proxy_connection_factory)
        };
        let proxy_connection_factory = &*proxy_connection_factory;
        let client_transport_dispatcher = {
            let client_transport_dispatcher = Box::new(ClientTransportDispatcher::new(
                self.config,
                proxy_connection_factory,
            ));
            Box::leak(client_transport_dispatcher)
        };
        let client_transport_dispatcher = &*client_transport_dispatcher;

        loop {
            let (client_tcp_stream, client_socket_address) =
                match Self::accept_client_connection(&tcp_listener).await {
                    Ok(accept_result) => accept_result,
                    Err(e) => {
                        error!(
                            "Agent server fail to accept client connection because of error: {e:?}"
                        );
                        continue;
                    }
                };
            debug!(
                "Accept client tcp connection on address: {}",
                client_socket_address
            );

            Self::handle_client_connection(
                client_tcp_stream,
                client_socket_address,
                client_transport_dispatcher,
            );
        }
    }

    fn handle_client_connection(
        client_tcp_stream: TcpStream,
        client_socket_address: SocketAddr,
        client_transport_dispatcher: &'static ClientTransportDispatcher<
            '_,
            '_,
            '_,
            AgentServerRsaCryptoFetcher,
        >,
    ) {
        tokio::spawn(async move {
            let client_transport = client_transport_dispatcher
                .dispatch(client_tcp_stream, client_socket_address)
                .await?;
            match client_transport {
                ClientTransport::Socks5(socks5_transport) => {
                    socks5_transport.process().await?;
                }
                ClientTransport::Http(http_transport) => {
                    http_transport.process().await?;
                }
            };
            debug!("Client transport [{client_socket_address}] complete to serve.");
            Ok::<(), AgentError>(())
        });
    }
}
