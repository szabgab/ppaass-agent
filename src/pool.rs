use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use deadpool::managed::{self, Manager};
use log::{debug, error};
use ppaass_io::Connection;
use tokio::{net::TcpStream, time::timeout};

use crate::{
    config::AGENT_CONFIG, crypto::AgentServerRsaCryptoFetcher, error::AgentError,
    RSA_CRYPTO_FETCHER,
};

pub(crate) struct ProxyConnectionManager {
    proxy_addresses: Vec<SocketAddr>,
}

impl ProxyConnectionManager {
    pub fn new() -> Result<Self, AgentError> {
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
}

#[async_trait::async_trait]
impl Manager for ProxyConnectionManager {
    type Type = Connection<TcpStream, Arc<AgentServerRsaCryptoFetcher>>;
    type Error = AgentError;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        debug!("Take proxy connection from pool.");
        let proxy_tcp_stream = match timeout(
            Duration::from_secs(AGENT_CONFIG.get_connect_to_proxy_timeout()),
            TcpStream::connect(self.proxy_addresses.as_slice()),
        )
        .await
        {
            Err(_) => {
                error!("Fail connect to proxy because of timeout.");
                return Err(AgentError::Timeout(
                    AGENT_CONFIG.get_connect_to_proxy_timeout(),
                ));
            }
            Ok(Ok(proxy_tcp_stream)) => proxy_tcp_stream,
            Ok(Err(e)) => {
                error!("Fail connect to proxy because of error: {e:?}");
                return Err(AgentError::Io(e));
            }
        };
        debug!("Success connect to proxy.");
        proxy_tcp_stream.set_nodelay(true).map_err(AgentError::Io)?;
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

    async fn recycle(
        &self,
        _: &mut Self::Type,
        _: &managed::Metrics,
    ) -> managed::RecycleResult<AgentError> {
        Ok(())
    }
}
