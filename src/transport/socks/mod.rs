mod codec;
mod message;

use std::net::{SocketAddr, ToSocketAddrs};

use async_trait::async_trait;
use bytes::Bytes;

use futures::{SinkExt, StreamExt};

use log::{debug, error, info};
use ppaass_crypto::random_32_bytes;
use ppaass_protocol::generator::PpaassMessageGenerator;
use ppaass_protocol::message::payload::tcp::{ProxyTcpInitResult, ProxyTcpPayload};
use ppaass_protocol::message::payload::udp::ProxyUdpPayload;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use ppaass_protocol::message::values::encryption::PpaassMessagePayloadEncryptionSelector;
use ppaass_protocol::message::{PpaassProxyMessage, PpaassProxyMessagePayload};

use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
};
use tokio_util::codec::{Framed, FramedParts};

use self::message::{Socks5InitCommandResultStatus, Socks5UdpDataPacket};

use crate::crypto::AgentServerPayloadEncryptionTypeSelector;
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
        ClientTransportDataRelayInfo, ClientTransportHandshake, ClientTransportTcpDataRelay,
    },
};

use super::{
    dispatcher::ClientTransportHandshakeInfo, ClientTransportRelay, ClientTransportUdpDataRelay,
};

pub(crate) struct Socks5ClientTransport;

#[async_trait]
impl ClientTransportRelay for Socks5ClientTransport {
    async fn udp_relay(
        &self,
        udp_relay_info: ClientTransportUdpDataRelay,
    ) -> Result<(), AgentError> {
        let ClientTransportUdpDataRelay {
            client_tcp_stream,
            client_udp_restrict_address,
            agent_udp_bind_socket,
        } = udp_relay_info;
        debug!("Agent begin to relay udp packet for client: {client_udp_restrict_address:?}");
        tokio::select! {
            udp_relay_tcp_check_result = Self::check_udp_relay_tcp_connection(client_tcp_stream)=>{
                Ok(udp_relay_tcp_check_result?)
            },
            udp_relay_result = Self::relay_udp_data(client_udp_restrict_address,agent_udp_bind_socket)=>{
                Ok(udp_relay_result?)
            }
        }
    }
}

#[async_trait]
impl ClientTransportHandshake for Socks5ClientTransport {
    async fn handshake(
        &self,
        handshake_info: ClientTransportHandshakeInfo,
    ) -> Result<
        (
            ClientTransportDataRelayInfo,
            Box<dyn ClientTransportRelay + Send + Sync>,
        ),
        AgentError,
    > {
        let ClientTransportHandshakeInfo {
            initial_buf,
            src_address,
            client_tcp_stream,
            client_socket_addr,
        } = handshake_info;
        let mut client_auth_framed_parts =
            FramedParts::new(client_tcp_stream, Socks5AuthCommandContentCodec);
        client_auth_framed_parts.read_buf = initial_buf;
        let mut client_auth_framed = Framed::from_parts(client_auth_framed_parts);
        let client_auth_command =
            client_auth_framed
                .next()
                .await
                .ok_or(AgentError::Other(format!(
            "Nothing to read from socks5 client when reading auth command: {client_socket_addr}"
        )))??;

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
        let socks5_init_command =
            socks5_init_framed
                .next()
                .await
                .ok_or(AgentError::Other(format!(
            "Nothing to read from socks5 client when reading init command: {client_socket_addr}"
        )))??;
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
                    client_socket_addr,
                    socks5_init_framed,
                )
                .await?
            }
        };

        Ok((relay_info, Box::new(Self)))
    }
}

impl Socks5ClientTransport {
    async fn check_udp_relay_tcp_connection(
        mut client_tcp_stream: TcpStream,
    ) -> Result<(), AgentError> {
        loop {
            let mut client_data_buf = [0u8; 1];
            let size = client_tcp_stream.read(&mut client_data_buf).await?;
            if size == 0 {
                info!("Client udp associate tcp stream closed: {client_tcp_stream:?}");
                return Ok(());
            }
        }
    }
    async fn relay_udp_data(
        client_udp_restrict_address: PpaassUnifiedAddress,
        agent_udp_bind_socket: UdpSocket,
    ) -> Result<(), AgentError> {
        let user_token = AGENT_CONFIG.get_user_token();
        let payload_encryption =
            AgentServerPayloadEncryptionTypeSelector::select(user_token, Some(random_32_bytes()));
        loop {
            let mut client_udp_buf = [0u8; 65535];
            let (len, client_udp_address) =
                agent_udp_bind_socket.recv_from(&mut client_udp_buf).await?;
            let src_address: PpaassUnifiedAddress = client_udp_address.into();
            if client_udp_restrict_address != src_address {
                error!("The udp packet sent from client not valid, client udp restrict address: {client_udp_restrict_address}, src address: {src_address}");
                continue;
            }
            let client_udp_buf = client_udp_buf[..len].to_vec();
            let client_udp_bytes = Bytes::from_iter(client_udp_buf);
            let client_to_dst_socks5_udp_packet: Socks5UdpDataPacket =
                client_udp_bytes.try_into()?;
            let dst_address: PpaassUnifiedAddress = client_to_dst_socks5_udp_packet.address.into();
            let agent_udp_message = PpaassMessageGenerator::generate_agent_udp_data_message(
                user_token.to_string(),
                payload_encryption.clone(),
                client_udp_restrict_address.clone(),
                dst_address.clone(),
                client_to_dst_socks5_udp_packet.data,
                true,
            )?;
            let mut proxy_connection = PROXY_CONNECTION_FACTORY.create_connection().await?;
            proxy_connection.send(agent_udp_message).await?;
            let proxy_udp_message = match proxy_connection.next().await {
                Some(Ok(proxy_udp_message)) => proxy_udp_message,
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(()),
            };
            let PpaassProxyMessage {
                payload: proxy_message_payload,
                ..
            } = proxy_udp_message;
            let PpaassProxyMessagePayload::Udp(ProxyUdpPayload {
                src_address,
                dst_address,
                data,
            }) = proxy_message_payload
            else {
                return Err(AgentError::Other("Not a udp data from proxy.".to_string()));
            };
            debug!("Udp packet send from agent to client, dst_address: {dst_address}, src_address: {src_address}");
            let agent_to_client_socks5_udp_packet = Socks5UdpDataPacket {
                frag: 0,
                address: dst_address.clone().try_into()?,
                data,
            };
            let agent_socks5_udp_packet_bytes: Bytes = agent_to_client_socks5_udp_packet.into();
            let src_socket_address = src_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
            agent_udp_bind_socket
                .send_to(&agent_socks5_udp_packet_bytes, &src_socket_address[..])
                .await?;
        }
    }

    #[allow(unused)]
    async fn handle_bind_command(
        src_address: PpaassUnifiedAddress,
        dst_address: PpaassUnifiedAddress,
        mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        unimplemented!("Still not implement the socks5 bind command")
    }

    async fn handle_udp_associate_command(
        client_udp_restrict_address: PpaassUnifiedAddress,
        mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        debug!(
            "Client do socks5 udp associate on restrict address: {client_udp_restrict_address:?}"
        );
        let agent_udp_bind_socket = UdpSocket::bind("0.0.0.0:0").await?;
        debug!("Agent bind udp socket: {agent_udp_bind_socket:?}");
        let socks5_init_success_result = Socks5InitCommandResult::new(
            Socks5InitCommandResultStatus::Succeeded,
            Some(agent_udp_bind_socket.local_addr()?.into()),
        );
        socks5_init_framed.send(socks5_init_success_result).await?;
        debug!("Agent send socks5 udp associate response to client: {agent_udp_bind_socket:?}");
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = socks5_init_framed.into_parts();
        Ok(ClientTransportDataRelayInfo::Udp(
            ClientTransportUdpDataRelay {
                agent_udp_bind_socket,
                client_tcp_stream,
                client_udp_restrict_address,
            },
        ))
    }

    async fn handle_connect_command(
        src_address: PpaassUnifiedAddress,
        dst_address: PpaassUnifiedAddress,
        client_socket_addr: SocketAddr,
        mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        match &dst_address {
            PpaassUnifiedAddress::Ip(socket_addr) => {
                if socket_addr.ip().is_loopback() {
                    return Err(AgentError::Other(format!(
                        "Loopback address is not allowed: {socket_addr}"
                    )));
                }
                if socket_addr.ip().is_unspecified() {
                    return Err(AgentError::Other(format!(
                        "Unspecified address is not allowed: {socket_addr}"
                    )));
                }
            }
            PpaassUnifiedAddress::Domain { host, port } => {
                if host.eq("0.0.0.1") || host.eq("127.0.0.1") || host.eq("localhost") {
                    return Err(AgentError::Other(format!(
                        "0.0.0.1 or 127.0.0.1 is not a valid destination address: {host}:{port}"
                    )));
                }
            }
        };

        let user_token = AGENT_CONFIG.get_user_token();
        let payload_encryption =
            AgentServerPayloadEncryptionTypeSelector::select(user_token, Some(random_32_bytes()));
        let tcp_init_request = PpaassMessageGenerator::generate_agent_tcp_init_message(
            user_token.to_string(),
            src_address.clone(),
            dst_address.clone(),
            payload_encryption.clone(),
        )?;
        let mut proxy_connection = PROXY_CONNECTION_FACTORY.create_connection().await?;

        debug!("Client tcp connection [{src_address}] success create proxy connection.",);
        if let Err(e) = proxy_connection.send(tcp_init_request).await {
            error!(
                "Fail to send tcp init request to proxy in socks5 agent because of error: {e:?}"
            );
            return Err(e);
        };

        let proxy_message = match proxy_connection.next().await {
            None => {
                error!("Fail to receive tcp init response from proxy in socks5 agent because of connection exhausted: {client_socket_addr}");
                return Err(AgentError::Other(format!("Fail to receive tcp init response from proxy in socks5 agent because of connection exhausted: {client_socket_addr}")));
            }
            Some(Ok(proxy_message)) => proxy_message,
            Some(Err(e)) => {
                error!("Fail to receive tcp init response from proxy in socks5 agent because of error: {e:?}");
                return Err(e.into());
            }
        };

        let PpaassProxyMessage {
            payload: proxy_message_payload,
            ..
        } = proxy_message;
        let PpaassProxyMessagePayload::Tcp(ProxyTcpPayload::Init { result, .. }) =
            proxy_message_payload
        else {
            return Err(AgentError::Other(format!(
                "Not a tcp init response for client: {client_socket_addr}"
            )));
        };
        let tunnel_id = match result {
            ProxyTcpInitResult::Success(tunnel_id) => tunnel_id,
            ProxyTcpInitResult::Fail(reason) => {
                error!("Client socks5 tcp connection [{src_address}] fail to initialize tcp connection with proxy because of reason: {reason:?}");
                return Err(AgentError::Other(format!(
                    "Client socks5 tcp connection [{src_address}] fail to initialize tcp connection with proxy because of reason: {reason:?}"
                )));
            }
        };
        debug!("Client socks5 tcp connection [{src_address}] success to initialize tcp connection with proxy on tunnel: {tunnel_id}");
        let socks5_init_success_result = Socks5InitCommandResult::new(
            Socks5InitCommandResultStatus::Succeeded,
            Some(dst_address.clone().try_into()?),
        );
        socks5_init_framed.send(socks5_init_success_result).await?;
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = socks5_init_framed.into_parts();
        debug!(
            "Client tcp connection [{src_address}] success to do sock5 handshake begin to relay."
        );
        Ok(ClientTransportDataRelayInfo::Tcp(
            ClientTransportTcpDataRelay {
                tunnel_id,
                client_tcp_stream,
                src_address,
                dst_address,
                proxy_connection,
                init_data: None,
            },
        ))
    }
}
