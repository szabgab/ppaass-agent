use std::{fmt::Debug, str::FromStr, sync::Arc};
use std::{net::SocketAddr, time::Duration};

use lazy_static::lazy_static;
use ppaass_io::Connection;
use tokio::{net::TcpStream, time::timeout};

use log::{debug, error};

use crate::{
    config::AGENT_CONFIG,
    crypto::AgentServerRsaCryptoFetcher,
    error::{AgentError, NetworkError},
    RSA_CRYPTO_FETCHER,
};

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
        let proxy_addresses_configuration = AGENT_CONFIG
            .get_proxy_addresses()
            .expect("Fail to parse proxy addresses from configuration file");
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

    pub(crate) async fn create_connection<'r>(
        &self,
    ) -> Result<Connection<TcpStream, Arc<AgentServerRsaCryptoFetcher>>, AgentError> {
        debug!("Take proxy connection from pool.");
        let proxy_tcp_stream = match timeout(
            Duration::from_secs(AGENT_CONFIG.get_connect_to_proxy_timeout()),
            TcpStream::connect(self.proxy_addresses.as_slice()),
        )
        .await
        {
            Err(_) => {
                error!("Fail connect to proxy because of timeout.");
                return Err(
                    NetworkError::Timeout(AGENT_CONFIG.get_connect_to_proxy_timeout()).into(),
                );
            }
            Ok(Ok(proxy_tcp_stream)) => proxy_tcp_stream,
            Ok(Err(e)) => {
                error!("Fail connect to proxy because of error: {e:?}");
                return Err(NetworkError::TcpConnect(e).into());
            }
        };
        debug!("Success connect to proxy.");
        proxy_tcp_stream
            .set_nodelay(true)
            .map_err(NetworkError::PropertyModification)?;
        let proxy_connection = Connection::new(
            proxy_tcp_stream,
            RSA_CRYPTO_FETCHER
                .get()
                .expect("Fail to get rsa crypto fetcher because of unknown reason.")
                .clone(),
            AGENT_CONFIG.get_compress(),
            AGENT_CONFIG.get_proxy_send_buffer_size(),
        );
        Ok(proxy_connection)
    }
}
