use std::{collections::HashMap, sync::Arc};
use std::{net::SocketAddr, str::FromStr, time::Duration};

use futures_util::{SinkExt, StreamExt};
use log::{debug, error};
use ppaass_io::Connection;
use ppaass_protocol::{
    message::{PayloadType, WrapperMessage},
    unwrap_proxy_tcp_payload,
};
use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        Mutex, Notify,
    },
    time::timeout,
};
use uuid::Uuid;

use crate::{
    config::AGENT_CONFIG, crypto::AgentServerRsaCryptoFetcher, error::AgentError,
    RSA_CRYPTO_FETCHER,
};

pub(crate) struct ProxyConnectionTx {
    pub key: String,
    usage: Mutex<usize>,
    pub proxy_outbound_tx: UnboundedSender<WrapperMessage>,
}

pub(crate) struct ProxyConnectionHandler {
    proxy_connections: Arc<Mutex<HashMap<String, Arc<ProxyConnectionTx>>>>,
    proxy_to_tcp_tunnel_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<WrapperMessage>>>>,
    proxy_to_udp_tunnel_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<WrapperMessage>>>>,
}

impl ProxyConnectionHandler {
    pub async fn new() -> Result<ProxyConnectionHandler, AgentError> {
        let proxy_addresses_configuration = AGENT_CONFIG.get_proxy_addresses();
        let proxy_addresses: Vec<SocketAddr> = proxy_addresses_configuration
            .iter()
            .filter_map(|addr| SocketAddr::from_str(addr).ok())
            .collect::<Vec<SocketAddr>>();
        if proxy_addresses.is_empty() {
            error!("No available proxy address for runtime to use.");
            panic!("No available proxy address for runtime to use.")
        }
        let configured_proxy_connection_number = AGENT_CONFIG.get_proxy_connection_number();
        let proxy_connections = Arc::new(Mutex::new(Default::default()));
        let handler = ProxyConnectionHandler {
            proxy_connections: proxy_connections.clone(),
            proxy_to_tcp_tunnel_tx_repo: Arc::new(Mutex::new(HashMap::new())),
            proxy_to_udp_tunnel_tx_repo: Arc::new(Mutex::new(HashMap::new())),
        };

        let proxy_connection_refresh = Arc::new(Notify::new());
        for _ in 0..configured_proxy_connection_number {
            Self::initialize_proxy_connection(
                &proxy_addresses,
                proxy_connections.clone(),
                handler.proxy_to_tcp_tunnel_tx_repo.clone(),
                handler.proxy_to_udp_tunnel_tx_repo.clone(),
                proxy_connection_refresh.clone(),
            )
            .await?;
        }
        let proxy_to_tcp_tunnel_tx_repo = handler.proxy_to_tcp_tunnel_tx_repo.clone();
        let proxy_to_udp_tunnel_tx_repo = handler.proxy_to_udp_tunnel_tx_repo.clone();
        tokio::spawn(async move {
            loop {
                proxy_connection_refresh.notified().await;
                let proxy_number_to_refresh = {
                    let proxy_connections = proxy_connections.lock().await;
                    let proxy_number_to_refresh =
                        configured_proxy_connection_number - proxy_connections.len();
                    proxy_number_to_refresh
                };
                for _ in 0..proxy_number_to_refresh {
                    if let Err(e) = Self::initialize_proxy_connection(
                        &proxy_addresses,
                        proxy_connections.clone(),
                        proxy_to_tcp_tunnel_tx_repo.clone(),
                        proxy_to_udp_tunnel_tx_repo.clone(),
                        proxy_connection_refresh.clone(),
                    )
                    .await
                    {
                        error!("Fail to  refresh proxy connection because of error: {e:?}");
                        proxy_connection_refresh.notify_waiters();
                    }
                }
            }
        });

        Ok(handler)
    }

    /// Initialize the proxy connection, start the backgroud task for each proxy connection
    async fn initialize_proxy_connection(
        proxy_addresses: &[SocketAddr],
        proxy_connections: Arc<Mutex<HashMap<String, Arc<ProxyConnectionTx>>>>,
        proxy_to_tcp_tunnel_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<WrapperMessage>>>>,
        proxy_to_udp_tunnel_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<WrapperMessage>>>>,
        proxy_connection_refresh: Arc<Notify>,
    ) -> Result<(), AgentError> {
        let proxy_connection = Self::create_connection(proxy_addresses).await?;
        let (mut proxy_connection_write, mut proxy_connection_read) = proxy_connection.split();
        let (proxy_connection_write_tx, mut proxy_connection_write_rx) =
            unbounded_channel::<WrapperMessage>();
        let proxy_connection_tx = Arc::new(ProxyConnectionTx {
            key: Uuid::new_v4().to_string(),
            usage: Mutex::new(0),
            proxy_outbound_tx: proxy_connection_write_tx,
        });
        let proxy_connection_key = proxy_connection_tx.key.clone();
        proxy_connections
            .lock()
            .await
            .insert(proxy_connection_key.clone(), proxy_connection_tx);
        {
            let proxy_connections = proxy_connections.clone();
            let proxy_connection_key = proxy_connection_key.clone();
            let proxy_connection_refresh = proxy_connection_refresh.clone();
            tokio::spawn(async move {
                while let Some(wrapper_message) = proxy_connection_write_rx.recv().await {
                    if let Err(e) = proxy_connection_write.send(wrapper_message).await {
                        error!("Proxy connection [{proxy_connection_key}] fail to send agent message to proxy because of error, remove it from the connection repository: {e:?}");
                        let mut proxy_connections = proxy_connections.lock().await;
                        proxy_connections.remove(&proxy_connection_key);
                        proxy_connection_refresh.notify_waiters();
                        break;
                    };
                }
            });
        }

        tokio::spawn(async move {
            loop {
                let proxy_message = match proxy_connection_read.next().await {
                    None => {
                        debug!("Proxy connection [{proxy_connection_key}] closed by remote, remove it from the connection repository.");
                        let mut proxy_connections = proxy_connections.lock().await;
                        proxy_connections.remove(&proxy_connection_key);
                        proxy_connection_refresh.notify_waiters();
                        break;
                    }
                    Some(Ok(proxy_message)) => proxy_message,
                    Some(Err(e)) => {
                        error!("Fail to read proxy connection because of error: {e:?}");
                        break;
                    }
                };
                match proxy_message.payload_type {
                    PayloadType::Tcp => {
                        let proxy_to_tcp_tunnel_tx = {
                            let proxy_to_tcp_tunnel_tx_repo =
                                proxy_to_tcp_tunnel_tx_repo.lock().await;
                            let Some(proxy_to_tcp_tunnel_tx) =
                                proxy_to_tcp_tunnel_tx_repo.get(&proxy_tcp_payload.payload)
                            else {
                                error!("Can not find proxy to tcp transport sender for proxy connection: {proxy_connection_key}");
                                break;
                            };
                            proxy_to_tcp_tunnel_tx.clone()
                        };
                        if let Err(e) = proxy_to_tcp_tunnel_tx.send(proxy_message) {
                            error!(
                                "Fail to send proxy connection read sender because of error: {e:?}"
                            );
                            break;
                        };
                    }
                    PayloadType::Udp => {
                        let proxy_to_udp_tunnel_tx = {
                            let proxy_to_udp_tunnel_tx_repo =
                                proxy_to_udp_tunnel_tx_repo.lock().await;
                            let Some(proxy_to_udp_tunnel_tx) =
                                proxy_to_udp_tunnel_tx_repo.get(&proxy_connection_key)
                            else {
                                error!("Can not find proxy to udp transport sender for proxy connection: {proxy_connection_key}");
                                break;
                            };
                            proxy_to_udp_tunnel_tx.clone()
                        };
                        if let Err(e) = proxy_to_udp_tunnel_tx.send(proxy_message) {
                            error!(
                                "Fail to send proxy connection read sender because of error: {e:?}"
                            );
                            break;
                        };
                    }
                }
            }
        });
        Ok(())
    }

    pub(crate) async fn register_proxy_to_tcp_tunnel_tx(
        &self,
        tunnel_id: String,
        proxy_to_tcp_tunnel_tx: UnboundedSender<WrapperMessage>,
    ) {
        let mut proxy_to_tcp_tunnel_tx_repo = self.proxy_to_tcp_tunnel_tx_repo.lock().await;
        proxy_to_tcp_tunnel_tx_repo.insert(tunnel_id, proxy_to_tcp_tunnel_tx);
    }

    pub(crate) async fn register_proxy_to_udp_tunnel_tx(
        &self,
        tunnel_id: String,
        proxy_to_udp_tunnel_tx: UnboundedSender<WrapperMessage>,
    ) {
        let mut proxy_to_udp_tunnel_tx_repo = self.proxy_to_udp_tunnel_tx_repo.lock().await;
        proxy_to_udp_tunnel_tx_repo.insert(tunnel_id, proxy_to_udp_tunnel_tx);
    }

    pub(crate) async fn fetch_proxy_connection_output_sender(
        &self,
    ) -> Result<Arc<ProxyConnectionTx>, AgentError> {
        let proxy_connections = self.proxy_connections.lock().await;
        let mut target_usage = 0usize;
        let mut target_key = "";
        for proxy_connection in proxy_connections.values() {
            let proxy_connection_usage = proxy_connection.usage.lock().await;
            if target_usage > *proxy_connection_usage {
                target_usage = *proxy_connection_usage;
                target_key = &proxy_connection.key;
            }
        }
        if let Some(proxy_connection) = proxy_connections.get(target_key) {
            let mut proxy_connection_usage = proxy_connection.usage.lock().await;
            *proxy_connection_usage += 1;
            return Ok(proxy_connection.clone());
        }
        return Err(AgentError::Other(format!(
            "Proxy connection list is empty."
        )));
    }

    async fn create_connection(
        proxy_addresses: &[SocketAddr],
    ) -> Result<Connection<TcpStream, Arc<AgentServerRsaCryptoFetcher>>, AgentError> {
        debug!("Take proxy connection from pool.");
        let proxy_tcp_stream = match timeout(
            Duration::from_secs(AGENT_CONFIG.get_connect_to_proxy_timeout()),
            TcpStream::connect(proxy_addresses),
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
}
