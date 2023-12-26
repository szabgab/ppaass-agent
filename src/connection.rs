use std::{fmt::Debug, str::FromStr};
use std::{net::SocketAddr, time::Duration};

use lazy_static::lazy_static;
use tokio::{net::TcpStream, time::timeout};

use log::{debug, error};
use tokio_util::codec::Framed;

use crate::codec::PpaassProxyEdgeCodec;
use crate::{config::AGENT_CONFIG, crypto::RSA_CRYPTO, error::AgentError};

lazy_static! {
    pub(crate) static ref PROXY_CONNECTION_FACTORY: ProxyConnectionFactory =
        ProxyConnectionFactory::new().expect("Fail to initialize proxy connection pool.");
}

#[derive(Debug)]
pub(crate) struct ProxyConnectionFactory {
    proxy_addresses: Vec<SocketAddr>,
}

impl ProxyConnectionFactory {
    pub(crate) fn new() -> Result<Self, AgentError> {
        let proxy_addresses_configuration = AGENT_CONFIG.get_proxy_addresses();
        let proxy_addresses: Vec<SocketAddr> = proxy_addresses_configuration
            .iter()
            .filter_map(|addr| SocketAddr::from_str(addr).ok())
            .collect::<Vec<SocketAddr>>();
        if proxy_addresses.is_empty() {
            error!("No available proxy address for runtime to use.");
            panic!("No available proxy address for runtime to use.")
        }
        Ok(Self { proxy_addresses })
    }

    pub(crate) async fn create_connection(
        &self,
    ) -> Result<Framed<TcpStream, PpaassProxyEdgeCodec>, AgentError> {
        debug!("Take proxy connection from pool.");
        let proxy_tcp_stream = match timeout(
            Duration::from_secs(AGENT_CONFIG.get_connect_to_proxy_timeout()),
            TcpStream::connect(self.proxy_addresses.as_slice()),
        )
        .await
        {
            Err(_) => {
                error!("Fail connect to proxy because of timeout.");
                return Err(AgentError::Other(format!(
                    "Fail to create proxy connection because of timeout: {}",
                    AGENT_CONFIG.get_connect_to_proxy_timeout()
                )));
            }
            Ok(Ok(proxy_tcp_stream)) => proxy_tcp_stream,
            Ok(Err(e)) => {
                error!("Fail connect to proxy because of error: {e:?}");
                return Err(AgentError::StdIo(e));
            }
        };
        debug!("Success connect to proxy.");
        proxy_tcp_stream.set_nodelay(true)?;
        proxy_tcp_stream.set_linger(None)?;
        let proxy_connection = Framed::with_capacity(
            proxy_tcp_stream,
            PpaassProxyEdgeCodec::new(AGENT_CONFIG.get_compress(), RSA_CRYPTO.clone()),
            AGENT_CONFIG.get_proxy_send_buffer_size(),
        );
        Ok(proxy_connection)
    }
}
