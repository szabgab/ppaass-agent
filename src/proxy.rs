use std::str::FromStr;
use std::{net::SocketAddr, time::Duration};

use ppaass_crypto::crypto::RsaCryptoFetcher;
use tokio::{net::TcpStream, time::timeout};

use tokio_io_timeout::TimeoutStream;
use tokio_util::codec::Framed;
use tracing::{debug, error};

use crate::error::AgentError;
use crate::{codec::PpaassProxyEdgeCodec, config::AgentConfig};

pub(crate) struct ProxyConnectionFactory<'config, 'crypto, F>
where
    F: RsaCryptoFetcher,
{
    proxy_addresses: Vec<SocketAddr>,
    config: &'config AgentConfig,
    rsa_crypto_featcher: &'crypto F,
}

impl<'config, 'crypto, F> ProxyConnectionFactory<'config, 'crypto, F>
where
    F: RsaCryptoFetcher + Send + Sync + 'static,
{
    pub(crate) fn new(
        config: &'config AgentConfig,
        rsa_crypto_featcher: &'crypto F,
    ) -> Result<Self, AgentError> {
        let proxy_addresses_configuration = config.get_proxy_addresses();
        let proxy_addresses: Vec<SocketAddr> = proxy_addresses_configuration
            .iter()
            .filter_map(|addr| SocketAddr::from_str(addr).ok())
            .collect::<Vec<SocketAddr>>();
        if proxy_addresses.is_empty() {
            error!("No available proxy address for runtime to use.");
            panic!("No available proxy address for runtime to use.")
        }
        Ok(Self {
            proxy_addresses,
            config,
            rsa_crypto_featcher,
        })
    }

    pub(crate) async fn create_proxy_connection(
        &self,
    ) -> Result<Framed<TimeoutStream<TcpStream>, PpaassProxyEdgeCodec<&'crypto F>>, AgentError>
    {
        debug!("Take proxy connection from pool.");
        let proxy_tcp_stream = match timeout(
            Duration::from_secs(self.config.get_connect_to_proxy_timeout()),
            TcpStream::connect(self.proxy_addresses.as_slice()),
        )
        .await
        {
            Err(_) => {
                error!("Fail connect to proxy because of timeout.");
                return Err(AgentError::Other(format!(
                    "Fail to create proxy connection because of timeout: {}",
                    self.config.get_connect_to_proxy_timeout()
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
        let mut proxy_tcp_stream = TimeoutStream::new(proxy_tcp_stream);
        proxy_tcp_stream.set_read_timeout(Some(Duration::from_secs(120)));
        proxy_tcp_stream.set_write_timeout(Some(Duration::from_secs(120)));
        let proxy_connection = Framed::with_capacity(
            proxy_tcp_stream,
            PpaassProxyEdgeCodec::new(self.config.get_compress(), self.rsa_crypto_featcher),
            self.config.get_proxy_send_buffer_size(),
        );
        Ok(proxy_connection)
    }
}
