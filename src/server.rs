use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use std::time::Duration;

use crate::{config::AgentConfig, error::AgentError};
use crate::{
    crypto::AgentServerRsaCryptoFetcher,
    proxy::ProxyConnectionFactory,
    transport::dispatcher::{ClientTransport, ClientTransportDispatcher},
};

use crate::trace::init_global_tracing_subscriber;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio::time::sleep;

use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info};
use tracing_appender::non_blocking::WorkerGuard;

const AGENT_SERVER_RUNTIME_NAME: &str = "AGENT-SERVER";

#[derive(Debug)]
pub enum AgentServerSignal {
    Finalize(AgentServerFinalizeSignal),
    Common(AgentServerCommonSignal),
}

#[derive(Debug)]
pub enum AgentServerFinalizeSignal {
    Stop,
}

#[derive(Debug)]
pub enum AgentServerCommonSignal {
    Other,
}

pub struct AgentServerGuard {
    join_handle: JoinHandle<()>,
    runtime: Runtime,
    signal_sender: Sender<AgentServerSignal>,
}

impl AgentServerGuard {
    pub fn blocking(&self) {
        self.runtime.block_on(async {
            while !self.join_handle.is_finished() {
                sleep(Duration::from_millis(100)).await;
            }
        });
    }

    pub async fn send_finalize_signal(
        self,
        finalize_signal: AgentServerFinalizeSignal,
    ) -> Result<(), AgentError> {
        self.signal_sender
            .send(AgentServerSignal::Finalize(finalize_signal))
            .await
            .map_err(|e| {
                AgentError::Other(format!(
                    "Fail to send finalize signal to agent server because of error: {e:?}"
                ))
            })
    }

    pub async fn send_common_signal(
        &self,
        common_signal: AgentServerCommonSignal,
    ) -> Result<(), AgentError> {
        self.signal_sender
            .send(AgentServerSignal::Common(common_signal))
            .await
            .map_err(|e| {
                AgentError::Other(format!(
                    "Fail to send common signal to agent server because of error: {e:?}"
                ))
            })
    }
}

pub struct AgentServer {
    config: Arc<AgentConfig>,
    runtime: Runtime,
    client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
    _tracing_guard: WorkerGuard,
}

impl AgentServer {
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        let config = Arc::new(config);
        let _tracing_guard = init_global_tracing_subscriber(
            LevelFilter::from_str(config.max_log_level()).unwrap_or(LevelFilter::ERROR),
        )?;
        let rsa_crypto_fetcher = AgentServerRsaCryptoFetcher::new(&config)?;
        let proxy_connection_factory =
            ProxyConnectionFactory::new(config.clone(), rsa_crypto_fetcher)?;
        let client_transport_dispatcher =
            ClientTransportDispatcher::new(config.clone(), proxy_connection_factory);
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .thread_name(AGENT_SERVER_RUNTIME_NAME)
            .worker_threads(config.worker_thread_number())
            .build()?;
        Ok(Self {
            config,
            runtime,
            client_transport_dispatcher: Arc::new(client_transport_dispatcher),
            _tracing_guard,
        })
    }
    async fn accept_client_connection(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), AgentError> {
        let (client_tcp_stream, client_socket_address) = tcp_listener.accept().await?;
        client_tcp_stream.set_nodelay(true)?;
        Ok((client_tcp_stream, client_socket_address))
    }

    async fn run(
        config: Arc<AgentConfig>,
        client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
        mut signal_receiver: Receiver<AgentServerSignal>,
    ) -> Result<(), AgentError> {
        let agent_server_bind_addr = if config.ipv6() {
            format!("::1:{}", config.port())
        } else {
            format!("0.0.0.0:{}", config.port())
        };
        info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
        let tcp_listener = TcpListener::bind(&agent_server_bind_addr).await?;
        loop {
            tokio::select! {
                // Receive the server signal
                signal_result = signal_receiver.recv() => {
                    match signal_result {
                        None => return Ok(()),
                        Some(single) => {
                            match single {
                                AgentServerSignal::Finalize(AgentServerFinalizeSignal::Stop) => {
                                    // Server stop and quite the loop
                                    return Ok(())
                                }
                                AgentServerSignal::Common(AgentServerCommonSignal::Other) => {
                                    debug!("Receive common signal continue the loop");
                                    continue;
                                }
                            }
                        }
                    }
                }
                // Accept client connection, and handle client connection
                accept_result = Self::accept_client_connection(&tcp_listener) => {
                    match accept_result{
                        Ok((client_tcp_stream, client_socket_address)) => {
                            debug!("Accept client tcp connection on address: {client_socket_address}");
                            Self::handle_client_connection(client_tcp_stream, client_socket_address, client_transport_dispatcher.clone());
                        }
                        Err(e) => {
                            error!("Agent server fail to accept client connection because of error: {e:?}");
                            continue;
                        }
                    }
                }
            }
        }
    }

    pub fn start(self) -> AgentServerGuard {
        let (signal_sender, signal_receiver) = channel::<AgentServerSignal>(1024);
        let join_handle = self.runtime.spawn(async move {
            if let Err(e) = Self::run(
                self.config,
                self.client_transport_dispatcher,
                signal_receiver,
            )
            .await
            {
                error!("Fail to start agent server because of error: {e:?}");
            }
        });
        AgentServerGuard {
            join_handle,
            signal_sender,
            runtime: self.runtime,
        }
    }

    fn handle_client_connection(
        client_tcp_stream: TcpStream,
        client_socket_address: SocketAddr,
        client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
    ) {
        tokio::spawn(async move {
            let client_transport = client_transport_dispatcher
                .dispatch(client_tcp_stream, client_socket_address)
                .await?;
            match client_transport {
                ClientTransport::Socks5(socks5_transport) => {
                    socks5_transport.process().await?;
                }
                ClientTransport::Http(http_transport) => {
                    http_transport.process().await?;
                }
            };
            debug!("Client transport [{client_socket_address}] complete to serve.");
            Ok::<(), AgentError>(())
        });
    }
}
