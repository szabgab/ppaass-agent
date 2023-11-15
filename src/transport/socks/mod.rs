mod codec;
mod message;

use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::anyhow;
use async_trait::async_trait;
use bytes::Bytes;

use futures::{SinkExt, StreamExt};
use ppaass_common::{
    tcp::{ProxyTcpInit, ProxyTcpInitResultType},
    PpaassMessageGenerator, PpaassMessagePayloadEncryptionSelector, PpaassMessageProxyProtocol, PpaassMessageProxyTcpPayloadType,
    PpaassMessageProxyUdpPayloadType, PpaassNetAddress, PpaassProxyMessage, PpaassProxyMessagePayload,
};

use log::{debug, error, info};

use tokio::{
    io::AsyncReadExt,
    net::{TcpStream, UdpSocket},
};
use tokio_util::codec::{Framed, FramedParts};

use self::message::{Socks5InitCommandResultStatus, Socks5UdpDataPacket};

use crate::{
    config::AGENT_CONFIG,
    connection::PROXY_CONNECTION_FACTORY,
    error::{AgentError, DecoderError, EncoderError, NetworkError},
    transport::{
        socks::{
            codec::{Socks5AuthCommandContentCodec, Socks5InitCommandContentCodec},
            message::{Socks5AuthCommandResult, Socks5AuthMethod, Socks5InitCommandResult, Socks5InitCommandType},
        },
        ClientTransportDataRelayInfo, ClientTransportHandshake, ClientTransportTcpDataRelay,
    },
    AgentServerPayloadEncryptionTypeSelector,
};

use ppaass_common::generate_uuid;

use super::{dispatcher::ClientTransportHandshakeInfo, ClientTransportRelay, ClientTransportUdpDataRelay};

pub(crate) struct Socks5ClientTransport;

#[async_trait]
impl ClientTransportRelay for Socks5ClientTransport {
    async fn udp_relay(&self, udp_relay_info: ClientTransportUdpDataRelay) -> Result<(), AgentError> {
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
        &self, handshake_info: ClientTransportHandshakeInfo,
    ) -> Result<(ClientTransportDataRelayInfo, Box<dyn ClientTransportRelay + Send + Sync>), AgentError> {
        let ClientTransportHandshakeInfo {
            initial_buf,
            src_address,
            client_tcp_stream,
        } = handshake_info;
        let mut client_auth_framed_parts = FramedParts::new(client_tcp_stream, Socks5AuthCommandContentCodec);
        client_auth_framed_parts.read_buf = initial_buf;
        let mut client_auth_framed = Framed::from_parts(client_auth_framed_parts);
        let client_auth_command = client_auth_framed
            .next()
            .await
            .ok_or(NetworkError::ConnectionExhausted)?
            .map_err(DecoderError::Socks5)?;
        debug!(
            "Client tcp connection [{src_address}] start socks5 authenticate process, authenticate methods in request: {:?}",
            client_auth_command.methods
        );
        let client_auth_response = Socks5AuthCommandResult::new(Socks5AuthMethod::NoAuthenticationRequired);
        client_auth_framed.send(client_auth_response).await.map_err(EncoderError::Socks5)?;
        let FramedParts { io: client_tcp_stream, .. } = client_auth_framed.into_parts();

        let mut socks5_init_framed = Framed::new(client_tcp_stream, Socks5InitCommandContentCodec);
        let socks5_init_command = socks5_init_framed
            .next()
            .await
            .ok_or(NetworkError::ConnectionExhausted)?
            .map_err(DecoderError::Socks5)?;
        debug!(
            "Client tcp connection [{src_address}] start socks5 init process, command type: {:?}, destination address: {:?}",
            socks5_init_command.request_type, socks5_init_command.dst_address
        );

        let relay_info = match socks5_init_command.request_type {
            Socks5InitCommandType::Bind => Self::handle_bind_command(src_address, socks5_init_command.dst_address.into(), socks5_init_framed).await?,
            Socks5InitCommandType::UdpAssociate => Self::handle_udp_associate_command(socks5_init_command.dst_address.into(), socks5_init_framed).await?,
            Socks5InitCommandType::Connect => Self::handle_connect_command(src_address, socks5_init_command.dst_address.into(), socks5_init_framed).await?,
        };

        Ok((relay_info, Box::new(Self)))
    }
}

impl Socks5ClientTransport {
    async fn check_udp_relay_tcp_connection(mut client_tcp_stream: TcpStream) -> Result<(), AgentError> {
        loop {
            let mut client_data_buf = [0u8; 1];
            let size = client_tcp_stream.read(&mut client_data_buf).await?;
            if size == 0 {
                info!("Client udp associate tcp stream closed: {client_tcp_stream:?}");
                return Ok(());
            }
        }
    }
    async fn relay_udp_data(client_udp_restrict_address: PpaassNetAddress, agent_udp_bind_socket: UdpSocket) -> Result<(), AgentError> {
        let user_token = AGENT_CONFIG
            .get_user_token()
            .ok_or(AgentError::Configuration("User token not configured.".to_string()))?;
        let payload_encryption = AgentServerPayloadEncryptionTypeSelector::select(user_token, Some(Bytes::from(generate_uuid().into_bytes())));
        loop {
            let mut client_udp_buf = [0u8; 65535];
            let (len, client_udp_address) = match agent_udp_bind_socket.recv_from(&mut client_udp_buf).await {
                Ok(len) => len,
                Err(e) => return Err(NetworkError::ClientUdpRecv(e).into()),
            };
            let src_address: PpaassNetAddress = client_udp_address.into();
            if client_udp_restrict_address != src_address {
                error!("The udp packet sent from client not valid, client udp restrict address: {client_udp_restrict_address}, src address: {src_address}");
                continue;
            }
            let client_udp_buf = client_udp_buf[..len].to_vec();
            let client_udp_bytes = Bytes::from_iter(client_udp_buf);
            let client_to_dst_socks5_udp_packet: Socks5UdpDataPacket = client_udp_bytes.try_into().map_err(DecoderError::Socks5)?;
            let dst_address: PpaassNetAddress = client_to_dst_socks5_udp_packet.address.into();
            let agent_udp_message = PpaassMessageGenerator::generate_agent_udp_data_message(
                user_token,
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
                payload: PpaassProxyMessagePayload { protocol, data },
                ..
            } = proxy_udp_message;
            if protocol != PpaassMessageProxyProtocol::Udp(PpaassMessageProxyUdpPayloadType::Data) {
                return Err(AgentError::Other(anyhow!("Invalid proxy udp payload type")));
            };
            debug!("Udp packet send from agent to client, dst_address: {dst_address}, src_address: {src_address}");
            let agent_to_client_socks5_udp_packet = Socks5UdpDataPacket {
                frag: 0,
                address: dst_address.clone().try_into()?,
                data,
            };
            let agent_socks5_udp_packet_bytes: Bytes = agent_to_client_socks5_udp_packet.into();
            let src_socket_address = src_address.to_socket_addrs()?.collect::<Vec<SocketAddr>>();
            agent_udp_bind_socket.send_to(&agent_socks5_udp_packet_bytes, &src_socket_address[..]).await?;
        }
    }

    #[allow(unused)]
    async fn handle_bind_command(
        src_address: PpaassNetAddress, dst_address: PpaassNetAddress, mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        unimplemented!("Still not implement the socks5 bind command")
    }

    async fn handle_udp_associate_command(
        client_udp_restrict_address: PpaassNetAddress, mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        debug!("Client do socks5 udp associate on restrict address: {client_udp_restrict_address:?}");
        let agent_udp_bind_socket = UdpSocket::bind("0.0.0.0:0").await?;
        debug!("Agent bind udp socket: {agent_udp_bind_socket:?}");
        let socks5_init_success_result =
            Socks5InitCommandResult::new(Socks5InitCommandResultStatus::Succeeded, Some(agent_udp_bind_socket.local_addr()?.into()));
        socks5_init_framed.send(socks5_init_success_result).await.map_err(EncoderError::Socks5)?;
        debug!("Agent send socks5 udp associate response to client: {agent_udp_bind_socket:?}");
        let FramedParts { io: client_tcp_stream, .. } = socks5_init_framed.into_parts();
        Ok(ClientTransportDataRelayInfo::Udp(ClientTransportUdpDataRelay {
            agent_udp_bind_socket,
            client_tcp_stream,
            client_udp_restrict_address,
        }))
    }

    async fn handle_connect_command(
        src_address: PpaassNetAddress, dst_address: PpaassNetAddress, mut socks5_init_framed: Framed<TcpStream, Socks5InitCommandContentCodec>,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        match &dst_address {
            PpaassNetAddress::IpV4 { ip: [0, 0, 0, 1], port: _ } => {
                return Err(AgentError::Other(anyhow!("0.0.0.1 or 127.0.0.1 is not a valid destination address")))
            },
            PpaassNetAddress::IpV4 { ip: [127, 0, 0, 1], port: _ } => return Err(AgentError::Other(anyhow!("127.0.0.1 is not a valid destination address"))),
            PpaassNetAddress::IpV6 {
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                port: _,
            } => return Err(AgentError::Other(anyhow!("0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:1 is not a valid destination address"))),
            PpaassNetAddress::Domain { host, port: _ } => {
                if host.eq("0.0.0.1") || host.eq("127.0.0.1") {
                    return Err(AgentError::Other(anyhow!("0.0.0.1 or 127.0.0.1 is not a valid destination address")));
                }
            },
            _ => {},
        };

        let user_token = AGENT_CONFIG
            .get_user_token()
            .ok_or(AgentError::Configuration("User token not configured.".to_string()))?;
        let payload_encryption = AgentServerPayloadEncryptionTypeSelector::select(user_token, Some(Bytes::from(generate_uuid().into_bytes())));
        let tcp_init_request =
            PpaassMessageGenerator::generate_agent_tcp_init_message(user_token, src_address.clone(), dst_address.clone(), payload_encryption.clone())?;
        let mut proxy_connection = PROXY_CONNECTION_FACTORY.create_connection().await?;

        debug!(
            "Client tcp connection [{src_address}] take proxy connectopn [{}] to do proxy.",
            proxy_connection.get_connection_id()
        );
        if let Err(e) = proxy_connection.send(tcp_init_request).await {
            error!("Fail to send tcp init request to proxy in socks5 agent because of error: {e:?}");
            return Err(e.into());
        };

        let proxy_message = match proxy_connection.next().await {
            None => {
                error!("Fail to receive tcp init response from proxy in socks5 agent because of connection exhausted");
                return Err(NetworkError::ConnectionExhausted.into());
            },
            Some(Ok(proxy_message)) => proxy_message,
            Some(Err(e)) => {
                error!("Fail to receive tcp init response from proxy in socks5 agent because of error: {e:?}");
                return Err(e.into());
            },
        };
        let PpaassProxyMessage {
            payload: PpaassProxyMessagePayload { protocol, data },
            ..
        } = proxy_message;
        let tcp_init_response = match protocol {
            PpaassMessageProxyProtocol::Tcp(PpaassMessageProxyTcpPayloadType::Init) => data.try_into()?,
            _ => {
                error!("Client tcp connection [{src_address}] receive invalid message from proxy, protocol: {protocol:?}");
                return Err(AgentError::InvalidProxyResponse("Not a tcp init response.".to_string()));
            },
        };
        let ProxyTcpInit {
            id: tcp_loop_key,
            dst_address,
            result_type: response_type,
            ..
        } = tcp_init_response;
        match response_type {
            ProxyTcpInitResultType::Success => {
                debug!("Client tcp connection [{src_address}] receive init tcp loop init response: {tcp_loop_key}");
            },
            ProxyTcpInitResultType::Fail => {
                error!("Client tcp connection [{src_address}] fail to do tcp loop init, tcp loop key: [{tcp_loop_key}]");
                return Err(AgentError::InvalidProxyResponse("Proxy tcp init fail.".to_string()));
            },
            ProxyTcpInitResultType::ConnectToDstFail => {
                error!("Client tcp connection [{src_address}] fail to do tcp loop init, because of proxy fail connect to destination, tcp loop key: [{tcp_loop_key}]");
                return Err(AgentError::InvalidProxyResponse("Proxy tcp init fail.".to_string()));
            },
        }
        let socks5_init_success_result = Socks5InitCommandResult::new(Socks5InitCommandResultStatus::Succeeded, Some(dst_address.clone().try_into()?));
        socks5_init_framed.send(socks5_init_success_result).await.map_err(EncoderError::Socks5)?;
        let FramedParts { io: client_tcp_stream, .. } = socks5_init_framed.into_parts();
        debug!("Client tcp connection [{src_address}] success to do sock5 handshake begin to relay, tcp loop key: [{tcp_loop_key}].");
        Ok(ClientTransportDataRelayInfo::Tcp(ClientTransportTcpDataRelay {
            client_tcp_stream,
            src_address,
            dst_address,
            proxy_connection,
            init_data: None,
        }))
    }
}
