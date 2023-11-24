pub(crate) mod codec;

use std::sync::Arc;

use async_trait::async_trait;
use bytecodec::{bytes::BytesEncoder, EncodeExt};

use bytes::Bytes;
use deadpool::managed::Pool;
use derive_more::Constructor;
use futures::{SinkExt, StreamExt};
use httpcodec::{BodyEncoder, HttpVersion, ReasonPhrase, RequestEncoder, Response, StatusCode};
use log::debug;

use ppaass_protocol::message::{
    NetAddress, ProxyTcpInitResponseStatus, ProxyTcpPayload, UnwrappedProxyTcpPayload,
};
use ppaass_protocol::unwrap_proxy_tcp_payload;
use tokio_util::codec::{Framed, FramedParts};
use url::Url;

use crate::{
    config::AGENT_CONFIG,
    error::AgentError,
    pool::ProxyConnectionManager,
    transport::{
        http::codec::HttpCodec, ClientTransportDataRelayInfo, ClientTransportTcpDataRelay,
    },
};

use super::{
    dispatcher::ClientTransportHandshakeInfo, ClientTransportHandshake, ClientTransportRelay,
};

const HTTPS_SCHEMA: &str = "https";
const SCHEMA_SEP: &str = "://";
const CONNECT_METHOD: &str = "connect";
const HTTPS_DEFAULT_PORT: u16 = 443;
const HTTP_DEFAULT_PORT: u16 = 80;
const OK_CODE: u16 = 200;
const CONNECTION_ESTABLISHED: &str = "Connection Established";

#[derive(Constructor)]
pub(crate) struct HttpClientTransport {
    proxy_connection_pool: Arc<Pool<ProxyConnectionManager>>,
}

impl ClientTransportRelay for HttpClientTransport {}

#[async_trait]
impl ClientTransportHandshake for HttpClientTransport {
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
        } = handshake_info;
        let mut framed_parts = FramedParts::new(client_tcp_stream, HttpCodec::default());
        framed_parts.read_buf = initial_buf;
        let mut http_framed = Framed::from_parts(framed_parts);
        let http_message = http_framed.next().await.ok_or(AgentError::Other(
            "Client http connection exhausted".to_string(),
        ))??;
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
                    AgentError::Other(format!(
                        "Fail to encode http request body because of error: {e:?}"
                    ))
                })?
                .into();
            (request_url, Some(encode_result))
        };

        let parsed_request_url = Url::parse(request_url.as_str())
            .map_err(|e| AgentError::Other(format!("Fail to parse url because of error: {e:?}")))?;
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
                "No host in the request url: {parsed_request_url}"
            )))?
            .to_string();
        if target_host.eq("0.0.0.1") || target_host.eq("127.0.0.1") {
            return Err(AgentError::Other(
                "0.0.0.1 or 127.0.0.1 is not a valid destination address".to_string(),
            ));
        }
        let dst_address = NetAddress::Domain {
            host: target_host,
            port: target_port,
        };
        let user_token = AGENT_CONFIG.get_user_token();
        let mut proxy_connection = self.proxy_connection_pool.get().await.map_err(|e| {
            AgentError::Other(format!(
                "Fail to get proxy connection because of error: {e:?}"
            ))
        })?;
        debug!(
            "Client tcp connection [{src_address}] take proxy connection [{}] to do proxy",
            proxy_connection.get_connection_id()
        );
        let agent_tcp_init_request = ppaass_protocol::new_agent_tcp_init_request(
            user_token.to_string(),
            src_address,
            dst_address,
        )?;
        proxy_connection.send(agent_tcp_init_request).await?;

        let proxy_wrapper_message =
            proxy_connection
                .next()
                .await
                .ok_or(AgentError::Other(format!(
                    "Proxy connection [{}] exhausted.",
                    proxy_connection.get_connection_id()
                )))??;
        let UnwrappedProxyTcpPayload { payload, .. } =
            unwrap_proxy_tcp_payload(proxy_wrapper_message)?;
        let (tunnel_id, src_address, dst_address) = match payload {
            ProxyTcpPayload::Data { tunnel_id, .. } => {
                return Err(AgentError::Other(format!(
                    "Proxy connection [{tunnel_id}] fail to connect destination because of invalid status"
                )));
            }
            ProxyTcpPayload::InitResponse(ProxyTcpInitResponseStatus::Failure {
                tunnel_id,
                src_address,
                dst_address,
                reason,
            }) => {
                return Err(AgentError::Other(format!(
                    "Proxy connection [{tunnel_id}] fail to connect destination because of reason: {reason:?}, source address: {src_address:?}, destination address: {dst_address:?}"
                )));
            }
            ProxyTcpPayload::InitResponse(ProxyTcpInitResponseStatus::Success {
                tunnel_id,
                src_address,
                dst_address,
            }) => (tunnel_id, src_address, dst_address),
            ProxyTcpPayload::CloseRequest { tunnel_id } => {
                return Err(AgentError::Other(format!(
                    "Proxy connection [{tunnel_id}] closed by peer."
                )));
            }
        };

        debug!("Proxy connection [{tunnel_id}] success connect to: {dst_address:?} from source: {src_address:?} ");

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
        Ok((
            ClientTransportDataRelayInfo::Tcp(ClientTransportTcpDataRelay {
                client_tcp_stream,
                src_address,
                dst_address,
                proxy_connection,
                init_data,
                tunnel_id,
            }),
            Box::new(Self {
                proxy_connection_pool: self.proxy_connection_pool.clone(),
            }),
        ))
    }
}
