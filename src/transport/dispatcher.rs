use std::{mem::size_of, net::SocketAddr};

use bytes::BytesMut;
use futures::StreamExt;
use log::{debug, error};
use ppaass_protocol::values::address::UnifiedNetAddress;
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Framed, FramedParts};

use crate::{
    config::AGENT_CONFIG,
    error::AgentError,
    transport::{http::HttpClientTransport, socks::Socks5ClientTransport},
    SOCKS_V4, SOCKS_V5,
};

use super::{ClientTransportDataRelayInfo, ClientTransportRelay};

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

pub(crate) struct ClientTransportHandshakeInfo {
    pub(crate) client_tcp_stream: TcpStream,
    pub(crate) src_address: UnifiedNetAddress,
    pub(crate) initial_buf: BytesMut,
}

pub(crate) struct ClientTransportDispatcher;

impl ClientTransportDispatcher {
    pub(crate) async fn dispatch(
        client_tcp_stream: TcpStream,
        client_socket_address: SocketAddr,
    ) -> Result<(), AgentError> {
        let mut client_message_framed = Framed::with_capacity(
            client_tcp_stream,
            SwitchClientProtocolDecoder,
            AGENT_CONFIG.get_client_receive_buffer_size(),
        );
        let client_protocol = match client_message_framed.next().await {
            Some(Ok(client_protocol)) => client_protocol,
            Some(Err(e)) => {
                error!("Fail to read protocol from client io because of error: {e:?}");
                return Err(e.into());
            }
            None => {
                error!("Fail to read protocol from client io because of nothing to read.");
                return Err(AgentError::ClientCodec(
                    "Invalid client protocol".to_string(),
                ));
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
                let client_transport_data_relay_info =
                    Socks5ClientTransport::handshake(ClientTransportHandshakeInfo {
                        client_tcp_stream,
                        initial_buf,
                        src_address: client_socket_address.into(),
                    })
                    .await?;
                match client_transport_data_relay_info {
                    ClientTransportDataRelayInfo::Tcp(relay_info) => {
                        ClientTransportRelay::tcp_relay(relay_info).await
                    }

                    ClientTransportDataRelayInfo::Udp(relay_info) => {
                        // Socks5ClientTransport::udp_relay(relay_info).await
                        unimplemented!("Udp not implemeted")
                    }
                }
            }
            ClientProtocol::Socks4 => {
                // For socks4 protocol
                error!("Client tcp connection [{client_socket_address}] do not support socks v4 protocol");
                Err(AgentError::ClientCodec(
                    "Invalid client protocol".to_string(),
                ))
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
                let http_relay_info =
                    HttpClientTransport::handshake(ClientTransportHandshakeInfo {
                        client_tcp_stream,
                        src_address: client_socket_address.into(),
                        initial_buf,
                    })
                    .await?;
                match http_relay_info {
                    ClientTransportDataRelayInfo::Tcp(relay_info) => {
                        ClientTransportRelay::tcp_relay(relay_info).await
                    }
                    ClientTransportDataRelayInfo::Udp(_) => Err(AgentError::Other(
                        "Invalid relay type for http transport".to_string(),
                    )),
                }
            }
        }
    }
}
