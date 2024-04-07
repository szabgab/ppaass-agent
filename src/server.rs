use crate::{config::AgentConfig, error::AgentError};
use crate::{
    crypto::AgentServerRsaCryptoFetcher,
    proxy::ProxyConnectionFactory,
    transport::dispatcher::{ClientTransport, ClientTransportDispatcher},
};
use std::net::SocketAddr;
use std::sync::Arc;

use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

use tracing::{debug, error, info};

const AGENT_SERVER_RUNTIME_NAME: &str = "AGENT-SERVER";

#[derive(Debug)]
pub enum AgentServerSignal {
    FailToListen(String),
    SuccessToListen(String),
    ClientConnectionAcceptSuccess {
        client_socket_address: SocketAddr,
        message: String,
    },
    ClientConnectionAcceptFail(String),
    ClientConnectionBeforeRelayFail {
        client_socket_address: SocketAddr,
        message: String,
    },
    ClientConnectionTransportCreateProxyConnectionFail {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionTransportCreateProxyConnectionSuccess {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionTransportCreateSuccess {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionTransportCreateFail {
        client_socket_address: SocketAddr,
        dst_address: PpaassUnifiedAddress,
        message: String,
    },
    ClientConnectionReadProxyConnectionWriteClose {
        client_socket_address: SocketAddr,
        message: String,
    },
    ClientConnectionWriteProxyConnectionReadClose {
        client_socket_address: SocketAddr,
        message: String,
    },
}

pub struct AgentServerGuard {
    _join_handle: JoinHandle<()>,
    runtime: Runtime,
}

impl AgentServerGuard {
    pub fn blocking(self, signal_rx: Receiver<AgentServerSignal>) {
        let mut signal_rx = signal_rx;
        self.runtime.block_on(async {
            while let Some(signal) = signal_rx.recv().await {
                println!("Agent server signal: {signal:?}");
            }
        });
    }
}

pub struct AgentServer {
    config: Arc<AgentConfig>,
    runtime: Runtime,
    client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
}

impl AgentServer {
    pub fn new(config: AgentConfig) -> Result<Self, AgentError> {
        let config = Arc::new(config);
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
        signal_tx: Sender<AgentServerSignal>,
    ) -> Result<(), AgentError> {
        let agent_server_bind_addr = if config.ipv6() {
            format!("::1:{}", config.port())
        } else {
            format!("0.0.0.0:{}", config.port())
        };
        info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
        let tcp_listener = match TcpListener::bind(&agent_server_bind_addr).await {
            Ok(tcp_listener) => tcp_listener,
            Err(e) => {
                signal_tx
                    .send(AgentServerSignal::FailToListen(format!(
                        "Fail to listen tcp port: {}",
                        config.port()
                    )))
                    .await
                    .map_err(|e| {
                        AgentError::Other(format!("Fail to send signal because of error: {e:?}"))
                    })?;
                return Err(AgentError::StdIo(e));
            }
        };
        signal_tx
            .send(AgentServerSignal::SuccessToListen(format!(
                "Fail to listen tcp port: {}",
                config.port()
            )))
            .await
            .map_err(|e| {
                AgentError::Other(format!("Fail to send signal because of error: {e:?}"))
            })?;
        loop {
            match Self::accept_client_connection(&tcp_listener).await {
                Ok((client_tcp_stream, client_socket_address)) => {
                    signal_tx
                        .send(AgentServerSignal::ClientConnectionAcceptSuccess {
                            client_socket_address,
                            message: format!(
                                "Success to accept client connection: {client_socket_address}"
                            ),
                        })
                        .await
                        .map_err(|e| {
                            AgentError::Other(format!(
                                "Fail to send signal because of error: {e:?}"
                            ))
                        })?;
                    debug!("Accept client tcp connection on address: {client_socket_address}");
                    Self::handle_client_connection(
                        client_tcp_stream,
                        client_socket_address,
                        client_transport_dispatcher.clone(),
                        signal_tx.clone(),
                    );
                }
                Err(e) => {
                    error!("Agent server fail to accept client connection because of error: {e:?}");
                    signal_tx
                        .send(AgentServerSignal::ClientConnectionAcceptFail(format!(
                            "Fail to accept client connection because of error: {e}"
                        )))
                        .await
                        .map_err(|e| {
                            AgentError::Other(format!(
                                "Fail to send signal because of error: {e:?}"
                            ))
                        })?;
                    continue;
                }
            }
        }
    }

    pub fn start(self) -> (AgentServerGuard, Receiver<AgentServerSignal>) {
        let (server_signal_tx, server_signal_rx) = channel(1024);
        let join_handle = self.runtime.spawn(async move {
            if let Err(e) = Self::run(
                self.config,
                self.client_transport_dispatcher,
                server_signal_tx,
            )
            .await
            {
                error!("Fail to start agent server because of error: {e:?}");
            }
        });
        (
            AgentServerGuard {
                _join_handle: join_handle,
                runtime: self.runtime,
            },
            server_signal_rx,
        )
    }

    fn handle_client_connection(
        client_tcp_stream: TcpStream,
        client_socket_address: SocketAddr,
        client_transport_dispatcher: Arc<ClientTransportDispatcher<AgentServerRsaCryptoFetcher>>,
        signal_tx: Sender<AgentServerSignal>,
    ) {
        tokio::spawn(async move {
            let client_transport = match client_transport_dispatcher
                .dispatch(client_tcp_stream, client_socket_address)
                .await
            {
                Ok(client_transport) => client_transport,
                Err(e) => {
                    error!("Fail to dispatch client connection [{client_socket_address}] to transport because of error: {e:?}");
                    if let Err(e) = signal_tx
                        .send(AgentServerSignal::ClientConnectionBeforeRelayFail {
                            client_socket_address,
                            message: format!(
                                "Fail to process client connection: {client_socket_address}"
                            ),
                        })
                        .await
                    {
                        error!("Fail to send signal because of error: {e:?}");
                    }
                    return;
                }
            };
            match client_transport {
                ClientTransport::Socks5(socks5_transport) => {
                    if let Err(e) = socks5_transport.process(signal_tx.clone()).await {
                        error!("Fail to process socks5 client connection [{client_socket_address}] in transport because of error: {e:?}");
                        if let Err(e) = signal_tx
                            .send(AgentServerSignal::ClientConnectionBeforeRelayFail{
                                client_socket_address,
                                message:format!(
                                    "Fail to process socks5 client connection: {client_socket_address}"
                                )
                            })
                            .await
                        {
                            error!("Fail to send signal because of error: {e:?}");
                        }
                    };
                }
                ClientTransport::Http(http_transport) => {
                    if let Err(e) = http_transport.process(signal_tx.clone()).await {
                        error!("Fail to process http client connection [{client_socket_address}] in transport because of error: {e:?}");
                        if let Err(e) = signal_tx
                            .send(AgentServerSignal::ClientConnectionBeforeRelayFail{
                                client_socket_address,
                                message:format!(
                                    "Fail to process http client connection: {client_socket_address}"
                                )
                            })
                            .await
                        {
                            error!("Fail to send signal because of error: {e:?}");
                        }
                    };
                }
            };
        });
    }
}
