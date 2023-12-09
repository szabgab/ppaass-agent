use std::{net::SocketAddr, sync::Arc};

use crate::error::AgentError;
use crate::transport::dispatcher::ClientTransportDispatcher;
use crate::transport::ClientTransportDataRelayInfo;
use crate::{config::AGENT_CONFIG, handler::ProxyConnectionManager};
use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Default)]
pub struct AgentServer {}

impl AgentServer {
    async fn accept_client_connection(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), AgentError> {
        let (client_tcp_stream, client_socket_address) =
            tcp_listener.accept().await.map_err(AgentError::Io)?;
        client_tcp_stream
            .set_nodelay(true)
            .map_err(AgentError::Io)?;
        Ok((client_tcp_stream, client_socket_address))
    }

    pub async fn start(&mut self) -> Result<(), AgentError> {
        let agent_server_bind_addr = if AGENT_CONFIG.get_ipv6() {
            format!("::1:{}", AGENT_CONFIG.get_port())
        } else {
            format!("0.0.0.0:{}", AGENT_CONFIG.get_port())
        };
        info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
        let tcp_listener = TcpListener::bind(&agent_server_bind_addr)
            .await
            .map_err(AgentError::Io)?;

        let proxy_connection_pool = Arc::new(
            Pool::builder(ProxyConnectionManager::new()?)
                .max_size(16)
                .build()
                .map_err(|e| {
                    AgentError::Other(format!(
                        "Fail to create proxy connection pool because of error: {e:?}"
                    ))
                })?,
        );
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
            let proxy_connection_pool = proxy_connection_pool.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client_connection(
                    client_tcp_stream,
                    client_socket_address,
                    proxy_connection_pool,
                )
                .await
                {
                    error!("Fail to handle client connection [{client_socket_address}] because of error: {e:?}")
                };
            });
        }
    }

    async fn handle_client_connection(
        client_tcp_stream: TcpStream,
        client_socket_address: SocketAddr,
        proxy_connection_pool: Arc<Pool<ProxyConnectionManager>>,
    ) -> Result<(), AgentError> {
        let (handshake_info, handshake) = ClientTransportDispatcher::dispatch(
            client_tcp_stream,
            client_socket_address,
            proxy_connection_pool,
        )
        .await?;
        let (relay_info, relay) = handshake.handshake(handshake_info).await?;
        match relay_info {
            ClientTransportDataRelayInfo::Tcp(tcp_relay_info) => {
                relay.tcp_relay(tcp_relay_info).await?
            }
            ClientTransportDataRelayInfo::Udp(udp_relay_info) => {
                relay.udp_relay(udp_relay_info).await?
            }
        }
        debug!("Client transport [{client_socket_address}] complete to serve.");
        Ok(())
    }
}
