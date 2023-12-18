mod codec;
mod message;

use std::net::SocketAddr;

use futures::{SinkExt, StreamExt};

use log::{debug, error};
use ppaass_protocol::message::agent::{AgentMessage, AgentMessagePayload, InitTunnelCommand};
use ppaass_protocol::message::proxy::{InitTunnelResult, ProxyMessage, ProxyMessagePayload};
use ppaass_protocol::values::address::UnifiedNetAddress;
use ppaass_protocol::values::security::{Encryption, SecureInfo};

use tokio::{io::AsyncReadExt, net::TcpStream};
use tokio_util::codec::{Framed, FramedParts};
use uuid::Uuid;

use self::message::Socks5InitCommandResultStatus;

use crate::{
    config::AGENT_CONFIG,
    connection::PROXY_CONNECTION_FACTORY,
    error::AgentError,
    transport::{
        socks::{
            codec::{Socks5AuthCommandContentCodec, Socks5InitCommandContentCodec},
            message::{
                Socks5AuthCommandResult, Socks5AuthMethod, Socks5InitCommandResult,
                Socks5InitCommandType,
            },
        },
        ClientTransportDataRelayInfo, ClientTransportTcpDataRelay,
    },
};

use crate::util::random_32_bytes;

use super::dispatcher::ClientTransportHandshakeInfo;

pub(crate) struct Socks5ClientTransport;

impl Socks5ClientTransport {
    pub(crate) async fn handshake(
        handshake_info: ClientTransportHandshakeInfo,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        let ClientTransportHandshakeInfo {
            initial_buf,
            src_address,
            client_tcp_stream,
        } = handshake_info;
        let mut client_auth_framed_parts =
            FramedParts::new(client_tcp_stream, Socks5AuthCommandContentCodec);
        client_auth_framed_parts.read_buf = initial_buf;
        let mut client_auth_framed = Framed::from_parts(client_auth_framed_parts);
        let client_auth_command = client_auth_framed
            .next()
            .await
            .ok_or(AgentError::Other("No client data anymore.".to_string()))??;
        debug!(
            "Client tcp connection [{src_address}] start socks5 authenticate process, authenticate methods in request: {:?}",
            client_auth_command.methods
        );
        let client_auth_response =
            Socks5AuthCommandResult::new(Socks5AuthMethod::NoAuthenticationRequired);
        client_auth_framed.send(client_auth_response).await?;
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = client_auth_framed.into_parts();

        let mut socks5_init_framed = Framed::new(client_tcp_stream, Socks5InitCommandContentCodec);
        let socks5_init_command = socks5_init_framed
            .next()
            .await
            .ok_or(AgentError::Other("No client data anymore.".to_string()))??;
        debug!(
            "Client tcp connection [{src_address}] start socks5 init process, command type: {:?}, destination address: {:?}",
            socks5_init_command.request_type, socks5_init_command.dst_address
        );

        let relay_info = match socks5_init_command.request_type {
            Socks5InitCommandType::Bind => {
                Self::handle_bind_command(
                    src_address,
                    socks5_init_command.dst_address.into(),
                    socks5_init_framed,
                )
                .await?
            }
            Socks5InitCommandType::UdpAssociate => {
                Self::handle_udp_associate_command(
                    socks5_init_command.dst_address.into(),
                    socks5_init_framed,
                )
                .await?
            }
            Socks5InitCommandType::Connect => {
                Self::handle_connect_command(
                    src_address,
                    socks5_init_command.dst_address.into(),
                    socks5_init_framed,
                )
                .await?
            }
        };

        Ok(relay_info)
    }

    #[allow(unused)]
    async fn handle_bind_command(
        src_address: UnifiedNetAddress,
        dst_address: UnifiedNetAddress,
        mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        unimplemented!("Still not implement the socks5 bind command")
    }

    async fn handle_udp_associate_command(
        client_udp_restrict_address: UnifiedNetAddress,
        mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        unimplemented!("Still not implement the socks5 bind command")
    }

    async fn handle_connect_command(
        src_address: UnifiedNetAddress,
        dst_address: UnifiedNetAddress,
        mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        match &dst_address {
            UnifiedNetAddress::Ip(ip_addr) => {
                if *ip_addr == "0.0.0.1".parse::<SocketAddr>().unwrap()
                    || *ip_addr == "127.0.0.1".parse::<SocketAddr>().unwrap()
                    || *ip_addr == "0:0:0:0:0:0:0:1".parse::<SocketAddr>().unwrap()
                {
                    return Err(AgentError::Other(
                        "0.0.0.1 or 127.0.0.1 or 0:0:0:0:0:0:0:1 is not a valid destination address".to_string(),
                    ));
                }
            }

            UnifiedNetAddress::Domain { host, port: _ } => {
                if host.eq("0.0.0.1")
                    || host.eq("127.0.0.1")
                    || host.eq("localhost")
                    || host.eq("0:0:0:0:0:0:0:1")
                {
                    return Err(AgentError::Other(
                        "0.0.0.1 or 127.0.0.1 or 0:0:0:0:0:0:0:1 or localhost is not a valid destination address".to_string(),
                    ));
                }
            }
            _ => {}
        };

        let user_token = AGENT_CONFIG
            .get_user_token()
            .ok_or(AgentError::Other("User token not configured.".to_string()))?;
        let agent_edge_id = Uuid::new_v4().to_string();
        let tcp_init_request = AgentMessage {
            message_id: Uuid::new_v4().to_string(),
            secure_info: SecureInfo {
                user_token: user_token.to_string(),
                encryption: Encryption::Aes(random_32_bytes()),
            },
            payload: AgentMessagePayload::InitTunnelCommand(InitTunnelCommand::Tcp {
                src_address: src_address.clone(),
                dst_address,
                agent_edge_id: agent_edge_id.clone(),
            }),
        };
        let mut proxy_connection = PROXY_CONNECTION_FACTORY.create_connection().await?;

        if let Err(e) = proxy_connection.send(tcp_init_request).await {
            error!(
                "Fail to send tcp init request to proxy in socks5 agent because of error: {e:?}"
            );
            return Err(e.into());
        };

        let ProxyMessage {
            message_id,
            secure_info,
            payload,
        } = proxy_connection
            .next()
            .await
            .ok_or(AgentError::Other(format!(
                "All data read from proxy connection: {agent_edge_id}"
            )))??;

        let InitTunnelResult {
            src_address,
            dst_address,
            agent_edge_id,
            proxy_edge_id,
        } = match payload {
            ProxyMessagePayload::InitTunnelResult(init_tunnel_result) => init_tunnel_result,
            _ => {
                return Err(AgentError::Other("Not a tcp init response.".to_string()));
            }
        };
        let dst_address = match dst_address {
            None => {
                return Err(AgentError::Other("Not a tcp init response.".to_string()));
            }
            Some(dst_address) => dst_address,
        };

        let socks5_init_success_result = Socks5InitCommandResult::new(
            Socks5InitCommandResultStatus::Succeeded,
            Some(dst_address.clone().try_into()?),
        );
        socks5_init_framed.send(socks5_init_success_result).await?;
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = socks5_init_framed.into_parts();

        Ok(ClientTransportDataRelayInfo::Tcp(
            ClientTransportTcpDataRelay {
                client_tcp_stream,
                src_address,
                dst_address,
                proxy_connection,
                init_data: None,
                agent_edge_id,
                proxy_edge_id,
            },
        ))
    }
}
