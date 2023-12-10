use std::{collections::HashMap, sync::Arc};
use std::{net::SocketAddr, str::FromStr, time::Duration};

use futures_util::{SinkExt, StreamExt};
use log::{debug, error};
use ppaass_protocol::message::agent::AgentMessage;
use ppaass_protocol::message::proxy::{InitTunnelResult, ProxyMessage, ProxyMessagePayload};
use ppaass_protocol::values::tunnel::TunnelType;

use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{unbounded_channel, UnboundedSender},
        Mutex, Notify,
    },
    time::timeout,
};
use uuid::Uuid;

use crate::edge::ProxyEdge;
use crate::{
    config::AGENT_CONFIG, crypto::AgentServerRsaCryptoFetcher, error::AgentError,
    RSA_CRYPTO_FETCHER,
};

struct ProxyEdgeWriteTx {
    usage: Mutex<usize>,
    proxy_edge_id: String,
    proxy_edge_write_tx: UnboundedSender<AgentMessage>,
}

pub(crate) struct ProxyEdgeHandler {
    proxy_edge_write_tx_repo: Arc<Mutex<HashMap<String, Arc<ProxyEdgeWriteTx>>>>,
    proxy_edge_write_tx_repo_notify: Arc<Notify>,
    proxy_edge_read_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
}

impl ProxyEdgeHandler {
    pub async fn new() -> Result<Self, AgentError> {
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
        let proxy_edge_write_tx_repo = Arc::new(Mutex::new(Default::default()));
        let proxy_edge_write_tx_repo_notify = Arc::new(Notify::new());
        let proxy_edge_handler = Self {
            proxy_edge_write_tx_repo: proxy_edge_write_tx_repo.clone(),
            proxy_edge_write_tx_repo_notify: proxy_edge_write_tx_repo_notify.clone(),
            proxy_edge_read_tx_repo: Default::default(),
        };
        for _ in 0..configured_proxy_connection_number {
            Self::start_proxy_edge(
                &proxy_addresses,
                proxy_edge_write_tx_repo.clone(),
                proxy_edge_write_tx_repo_notify.clone(),
                proxy_edge_handler.proxy_edge_read_tx_repo.clone(),
            )
            .await?;
        }

        let proxy_edge_read_tx_repo = proxy_edge_handler.proxy_edge_read_tx_repo.clone();

        tokio::spawn(async move {
            loop {
                proxy_edge_write_tx_repo_notify.notified().await;
                let proxy_edge_number_to_refresh = {
                    let proxy_edge_write_tx_repo = proxy_edge_write_tx_repo.lock().await;
                    let proxy_edge_number_to_refresh =
                        configured_proxy_connection_number - proxy_edge_write_tx_repo.len();
                    proxy_edge_number_to_refresh
                };
                for _ in 0..proxy_edge_number_to_refresh {
                    if let Err(e) = Self::start_proxy_edge(
                        &proxy_addresses,
                        proxy_edge_write_tx_repo.clone(),
                        proxy_edge_write_tx_repo_notify.clone(),
                        proxy_edge_read_tx_repo.clone(),
                    )
                    .await
                    {
                        error!("Fail to  refresh proxy edge because of error: {e:?}");
                        proxy_edge_write_tx_repo_notify.notify_waiters();
                    }
                }
            }
        });

        Ok(proxy_edge_handler)
    }

    /// Initialize the proxy connection, start the backgroud task for each proxy connection
    async fn start_proxy_edge(
        proxy_addresses: &[SocketAddr],
        proxy_edge_write_tx_repo: Arc<Mutex<HashMap<String, Arc<ProxyEdgeWriteTx>>>>,
        proxy_edge_write_tx_repo_notify: Arc<Notify>,
        proxy_edge_read_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
    ) -> Result<(), AgentError> {
        let proxy_edge = Self::create_proxy_edge(proxy_addresses).await?;
        let (mut proxy_edge_write, mut proxy_edge_read) = proxy_edge.split();
        let (proxy_edge_write_tx, mut proxy_edge_write_rx) = unbounded_channel::<AgentMessage>();
        let proxy_edge_id = Uuid::new_v4().to_string();
        let proxy_edge_write_tx = Arc::new(ProxyEdgeWriteTx {
            proxy_edge_id,
            usage: Mutex::new(0),
            proxy_edge_write_tx,
        });
        let proxy_edge_id = proxy_edge_id.clone();
        proxy_edge_write_tx_repo
            .lock()
            .await
            .insert(proxy_edge_id.clone(), proxy_edge_write_tx);
        {
            let proxy_edge_write_tx_repo = proxy_edge_write_tx_repo.clone();
            let proxy_edge_id = proxy_edge_id.clone();
            let proxy_edge_write_tx_repo_notify = proxy_edge_write_tx_repo_notify.clone();
            tokio::spawn(async move {
                while let Some(agent_message) = proxy_edge_write_rx.recv().await {
                    if let Err(e) = proxy_edge_write.send(agent_message).await {
                        error!("Proxy edge [{proxy_edge_id}] fail to send agent message to proxy because of error, remove it from the proxy edge repository: {e:?}");
                        let mut proxy_edge_write_tx_repo = proxy_edge_write_tx_repo.lock().await;
                        proxy_edge_write_tx_repo.remove(&proxy_edge_id);
                        proxy_edge_write_tx_repo_notify.notify_waiters();
                        break;
                    };
                }
            });
        }

        tokio::spawn(async move {
            loop {
                let proxy_message = match proxy_edge_read.next().await {
                    None => {
                        debug!("Proxy edge [{proxy_edge_id}] closed by remote, remove it from the connection repository.");
                        let mut agent_edge_repo = agent_edge_repo.lock().await;
                        agent_edge_repo.remove(&agent_edge_id);
                        agent_edge_repo_notify.notify_waiters();
                        break;
                    }
                    Some(Ok(proxy_message)) => proxy_message,
                    Some(Err(e)) => {
                        error!("Fail to read proxy connection because of error: {e:?}");
                        break;
                    }
                };
                match proxy_message.tunnel.tunnel_type {
                    TunnelType::Tcp => {
                        match proxy_message.payload {
                            ProxyMessagePayload::InitTunnelResult(InitTunnelResult {
                                src_address,
                                dst_address,
                            }) => {
                                let Some(proxy_edge_id) = proxy_message.tunnel.proxy_edge_id else {
                                    continue;
                                };
                                let mut proxy_edge_read_tx_repo =
                                    proxy_edge_read_tx_repo.lock().await;
                                proxy_edge_read_tx_repo.insert(proxy_edge_id);
                            }
                            ProxyMessagePayload::RelayData(_) => {}
                            ProxyMessagePayload::CloseTunnelCommand(_) => {}
                        }
                        let proxy_edge_id = proxy_message.tunnel.proxy_edge_id;
                    }
                    TunnelType::Udp => {}
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
    ) -> Result<Arc<AgentEdgeTx>, AgentError> {
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

    async fn create_proxy_edge(
        proxy_addresses: &[SocketAddr],
    ) -> Result<ProxyEdge<TcpStream, Arc<AgentServerRsaCryptoFetcher>>, AgentError> {
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
        let proxy_edge = ProxyEdge::new(
            proxy_tcp_stream,
            RSA_CRYPTO_FETCHER
                .get()
                .expect("Fail to get rsa crypto fetcher because of unknown reason.")
                .clone(),
            AGENT_CONFIG.get_compress(),
            AGENT_CONFIG.get_proxy_send_buffer_size(),
        );
        Ok(proxy_edge)
    }
}
