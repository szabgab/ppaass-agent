pub(crate) mod codec;

use bytecodec::{bytes::BytesEncoder, EncodeExt};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use httpcodec::{BodyEncoder, HttpVersion, ReasonPhrase, RequestEncoder, Response, StatusCode};
use log::debug;
use ppaass_protocol::message::agent::{AgentMessage, AgentMessagePayload, InitTunnelCommand};
use ppaass_protocol::message::proxy::{InitTunnelResult, ProxyMessage, ProxyMessagePayload};
use ppaass_protocol::values::address::UnifiedNetAddress;
use ppaass_protocol::values::security::{Encryption, SecureInfo};

use crate::util::random_32_bytes;
use crate::{
    config::AGENT_CONFIG,
    connection::PROXY_CONNECTION_FACTORY,
    error::AgentError,
    transport::{
        http::codec::HttpCodec, ClientTransportDataRelayInfo, ClientTransportTcpDataRelay,
    },
};
use tokio_util::codec::{Framed, FramedParts};
use url::Url;
use uuid::Uuid;

use super::dispatcher::ClientTransportHandshakeInfo;

const HTTPS_SCHEMA: &str = "https";
const SCHEMA_SEP: &str = "://";
const CONNECT_METHOD: &str = "connect";
const HTTPS_DEFAULT_PORT: u16 = 443;
const HTTP_DEFAULT_PORT: u16 = 80;
const OK_CODE: u16 = 200;
const CONNECTION_ESTABLISHED: &str = "Connection Established";

#[derive(Debug)]
pub(crate) struct HttpClientTransport;

impl HttpClientTransport {
    pub(crate) async fn handshake(
        handshake_info: ClientTransportHandshakeInfo,
    ) -> Result<ClientTransportDataRelayInfo, AgentError> {
        let ClientTransportHandshakeInfo {
            initial_buf,
            src_address,
            client_tcp_stream,
        } = handshake_info;
        let mut framed_parts = FramedParts::new(client_tcp_stream, HttpCodec::default());
        framed_parts.read_buf = initial_buf;
        let mut http_framed = Framed::from_parts(framed_parts);
        let http_message = http_framed
            .next()
            .await
            .ok_or(AgentError::Other("Complete read from client".to_string()))??;
        let http_method = http_message.method().to_string().to_lowercase();
        let (request_url, init_data) = if http_method == CONNECT_METHOD {
            (
                format!(
                    "{}{}{}",
                    HTTPS_SCHEMA,
                    SCHEMA_SEP,
                    http_message.request_target()
                ),
                None,
            )
        } else {
            let request_url = http_message.request_target().to_string();
            let mut http_data_encoder = RequestEncoder::<BodyEncoder<BytesEncoder>>::default();
            let encode_result: Bytes = http_data_encoder
                .encode_into_bytes(http_message)
                .map_err(|e| {
                    AgentError::ClientCodec(format!(
                        "Fail to encode http response because of error: {e:?}"
                    ))
                })?
                .into();
            (request_url, Some(encode_result))
        };

        let parsed_request_url = Url::parse(request_url.as_str()).map_err(|e| {
            AgentError::Other(format!(
                "Fail to parse url [{request_url}] because of error: {e:?}"
            ))
        })?;
        let target_port = match parsed_request_url.port() {
            None => match parsed_request_url.scheme() {
                HTTPS_SCHEMA => HTTPS_DEFAULT_PORT,
                _ => HTTP_DEFAULT_PORT,
            },
            Some(v) => v,
        };
        let target_host = parsed_request_url
            .host()
            .ok_or(AgentError::Other(format!(
                "Fail to parse request url because of no target host: {parsed_request_url:?}"
            )))?
            .to_string();
        if target_host.eq("0.0.0.1") || target_host.eq("127.0.0.1") {
            return Err(AgentError::Other(format!(
                "0.0.0.1 or 127.0.0.1 is not a valid destination address"
            )));
        }
        let dst_address = UnifiedNetAddress::Domain {
            host: target_host,
            port: target_port,
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

        debug!(
            "Client tcp connection [{src_address}] take proxy connection [{agent_edge_id}] to do proxy"
        );
        proxy_connection.send(tcp_init_request).await?;

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

        if init_data.is_none() {
            //For https proxy
            let http_connect_success_response = Response::new(
                HttpVersion::V1_1,
                StatusCode::new(OK_CODE).unwrap(),
                ReasonPhrase::new(CONNECTION_ESTABLISHED).unwrap(),
                vec![],
            );
            http_framed.send(http_connect_success_response).await?;
        }
        let FramedParts {
            io: client_tcp_stream,
            ..
        } = http_framed.into_parts();
        Ok(ClientTransportDataRelayInfo::Tcp(
            ClientTransportTcpDataRelay {
                client_tcp_stream,
                src_address,
                dst_address,
                proxy_connection,
                init_data,
                agent_edge_id,
                proxy_edge_id,
            },
        ))
    }
}
