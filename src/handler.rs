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

pub(crate) struct AgentEdgeTx {
    usage: Mutex<usize>,
    pub agent_edge_id: String,
    pub agent_edge_write_tx: UnboundedSender<AgentMessage>,
}

pub(crate) struct AgentEdgeHandler {
    agent_edge_repo: Arc<Mutex<HashMap<String, Arc<AgentEdgeTx>>>>,
    agent_edge_repo_notify: Arc<Notify>,
    proxy_edge_read_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
    proxy_edge_write_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
}

impl AgentEdgeHandler {
    pub async fn new() -> Result<AgentEdgeHandler, AgentError> {
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
        let agent_edge_repo = Arc::new(Mutex::new(Default::default()));
        let agent_edge_repo_notify = Arc::new(Notify::new());
        let agent_edge_handler = AgentEdgeHandler {
            agent_edge_repo: agent_edge_repo.clone(),
            agent_edge_repo_notify: agent_edge_repo_notify.clone(),
            proxy_edge_read_tx_repo: Default::default(),
            proxy_edge_write_tx_repo: Default::default(),
        };
        for _ in 0..configured_proxy_connection_number {
            Self::start_agent_edge(
                &proxy_addresses,
                agent_edge_repo.clone(),
                agent_edge_repo_notify.clone(),
            )
            .await?;
        }

        tokio::spawn(async move {
            loop {
                agent_edge_repo_notify.notified().await;
                let agent_edge_number_to_refresh = {
                    let agent_edge_repo = agent_edge_repo.lock().await;
                    let agent_edge_number_to_refresh =
                        configured_proxy_connection_number - agent_edge_repo.len();
                    agent_edge_number_to_refresh
                };
                for _ in 0..agent_edge_number_to_refresh {
                    if let Err(e) = Self::start_agent_edge(
                        &proxy_addresses,
                        agent_edge_repo.clone(),
                        agent_edge_repo_notify.clone(),
                    )
                    .await
                    {
                        error!("Fail to  refresh proxy connection because of error: {e:?}");
                        agent_edge_repo_notify.notify_waiters();
                    }
                }
            }
        });

        Ok(agent_edge_handler)
    }

    /// Initialize the proxy connection, start the backgroud task for each proxy connection
    async fn start_agent_edge(
        proxy_addresses: &[SocketAddr],
        agent_edge_repo: Arc<Mutex<HashMap<String, Arc<AgentEdgeTx>>>>,
        agent_edge_repo_notify: Arc<Notify>,
        proxy_edge_read_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
        proxy_edge_write_tx_repo: Arc<Mutex<HashMap<String, UnboundedSender<ProxyMessage>>>>,
    ) -> Result<(), AgentError> {
        let proxy_edge = Self::create_proxy_edge(proxy_addresses).await?;
        let (mut agent_edge_write, mut agent_edge_read) = proxy_edge.split();
        let (agent_edge_write_tx, mut agent_edge_write_rx) = unbounded_channel::<AgentMessage>();
        let agent_edge_tx = Arc::new(AgentEdgeTx {
            agent_edge_id: Uuid::new_v4().to_string(),
            usage: Mutex::new(0),
            agent_edge_write_tx,
        });
        let agent_edge_id = agent_edge_tx.agent_edge_id.clone();
        agent_edge_repo
            .lock()
            .await
            .insert(agent_edge_id.clone(), agent_edge_tx);
        {
            let agent_edge_repo = agent_edge_repo.clone();
            let agent_edge_id = agent_edge_id.clone();
            let agent_edge_repo_notify = agent_edge_repo_notify.clone();
            tokio::spawn(async move {
                while let Some(agent_message) = agent_edge_write_rx.recv().await {
                    if let Err(e) = agent_edge_write.send(agent_message).await {
                        error!("Agent edge [{agent_edge_id}] fail to send agent message to proxy because of error, remove it from the agent edge repository: {e:?}");
                        let mut agent_edge_repo = agent_edge_repo.lock().await;
                        agent_edge_repo.remove(&agent_edge_id);
                        agent_edge_repo_notify.notify_waiters();
                        break;
                    };
                }
            });
        }

        tokio::spawn(async move {
            loop {
                let proxy_message = match agent_edge_read.next().await {
                    None => {
                        debug!("Agent edge [{agent_edge_id}] closed by remote, remove it from the connection repository.");
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
