use std::net::SocketAddr;

use crate::error::AgentError;
use crate::transport::dispatcher::ClientTransportDispatcher;
use crate::transport::ClientTransportDataRelayInfo;
use crate::{config::AGENT_CONFIG, error::NetworkError};
use log::{debug, error, info};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Default)]
pub struct AgentServer {}

impl AgentServer {
    async fn accept_client_connection(tcp_listener: &TcpListener) -> Result<(TcpStream, SocketAddr), NetworkError> {
        let (client_tcp_stream, client_socket_address) = tcp_listener.accept().await.map_err(NetworkError::AcceptConnection)?;
        client_tcp_stream.set_nodelay(true).map_err(NetworkError::PropertyModification)?;
        Ok((client_tcp_stream, client_socket_address))
    }

    pub async fn start(&mut self) -> Result<(), AgentError> {
        let agent_server_bind_addr = if AGENT_CONFIG.get_ipv6() {
            format!("::1:{}", AGENT_CONFIG.get_port())
        } else {
            format!("0.0.0.0:{}", AGENT_CONFIG.get_port())
        };
        info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
        let tcp_listener = TcpListener::bind(&agent_server_bind_addr).await.map_err(NetworkError::TcpBind)?;
        loop {
            let (client_tcp_stream, client_socket_address) = match Self::accept_client_connection(&tcp_listener).await {
                Ok(accept_result) => accept_result,
                Err(e) => {
                    error!("Agent server fail to accept client connection because of error: {e:?}");
                    continue;
                },
            };
            debug!("Accept client tcp connection on address: {}", client_socket_address);
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client_connection(client_tcp_stream, client_socket_address).await {
                    error!("Fail to handle client connection [{client_socket_address}] because of error: {e:?}")
                };
            });
        }
    }

    async fn handle_client_connection(client_tcp_stream: TcpStream, client_socket_address: SocketAddr) -> Result<(), AgentError> {
        let (handshake_info, handshake) = ClientTransportDispatcher::dispatch(client_tcp_stream, client_socket_address).await?;
        let (relay_info, relay) = handshake.handshake(handshake_info).await?;
        match relay_info {
            ClientTransportDataRelayInfo::Tcp(tcp_relay_info) => relay.tcp_relay(tcp_relay_info).await?,
            ClientTransportDataRelayInfo::Udp(udp_relay_info) => relay.udp_relay(udp_relay_info).await?,
        }
        debug!("Client transport [{client_socket_address}] complete to serve.");
        Ok(())
    }
}
