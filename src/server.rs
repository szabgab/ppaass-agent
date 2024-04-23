use crate::{
    command::AgentServerCommand, config::AgentServerConfig, error::AgentServerError,
    event::AgentServerEvent, publish_server_event,
};
use crate::{
    crypto::AgentServerRsaCryptoFetcher,
    proxy::ProxyConnectionFactory,
    transport::dispatcher::{ClientDispatcher, Tunnel},
};

use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::Duration,
};

use anyhow::Result;
use ppaass_protocol::message::values::address::PpaassUnifiedAddress;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use tokio::{
    net::{TcpListener, TcpStream},
    time::interval,
};

use tracing::{debug, error, info};

pub struct AgentServer {
    config: Arc<AgentServerConfig>,
    client_dispatcher: ClientDispatcher<AgentServerRsaCryptoFetcher>,
}

impl AgentServer {
    pub fn new(config: Arc<AgentServerConfig>) -> Result<Self> {
        let rsa_crypto_fetcher = AgentServerRsaCryptoFetcher::new(&config)?;
        let proxy_connection_factory =
            ProxyConnectionFactory::new(config.clone(), rsa_crypto_fetcher)?;
        let client_dispatcher = ClientDispatcher::new(config.clone(), proxy_connection_factory);
        Ok(Self {
            config,
            client_dispatcher,
        })
    }

    pub fn start(self) -> (Sender<AgentServerCommand>, Receiver<AgentServerEvent>) {
        let (server_event_tx, server_event_rx) = channel(1024);
        let (server_command_tx, mut server_command_rx) = channel(1024);
        let config = self.config;
        let client_dispatcher = self.client_dispatcher;
        let upload_bytes_amount: Arc<AtomicU64> = Default::default();
        let download_bytes_amount: Arc<AtomicU64> = Default::default();
        let stoped_status: Arc<AtomicBool> = Default::default();
        tokio::spawn(async move {
            let agent_server_bind_addr = if config.ipv6() {
                format!("::1:{}", config.port())
            } else {
                format!("0.0.0.0:{}", config.port())
            };
            info!("Agent server start to serve request on address: {agent_server_bind_addr}.");
            let tcp_listener = match TcpListener::bind(&agent_server_bind_addr).await {
                Ok(tcp_listener) => tcp_listener,
                Err(e) => {
                    error!(
                        "Fail to listen tcp port {} because of error: {e:?}",
                        config.port()
                    );
                    publish_server_event(
                        &server_event_tx,
                        AgentServerEvent::ServerStartFail {
                            listening_port: config.port(),
                            reason: format!("Fail to listen tcp port: {}", config.port()),
                        },
                    )
                    .await;
                    return;
                }
            };

            publish_server_event(
                &server_event_tx,
                AgentServerEvent::ServerStartSuccess(config.port()),
            )
            .await;

            // Start the network state event task
            let upload_bytes_amount = upload_bytes_amount.clone();
            let download_bytes_amount = download_bytes_amount.clone();
            let server_event_tx = server_event_tx.clone();
            let server_event_tick_interval_val = config.server_signal_tick_interval();
            let mb_per_second_div_base = (server_event_tick_interval_val * 1024 * 1024) as f64;
            let mut server_event_tick_interval =
                interval(Duration::from_secs(server_event_tick_interval_val));

            loop {
                let upload_bytes_amount_pre_val = upload_bytes_amount.fetch_add(0, Relaxed);
                let download_bytes_amount_pre_val = download_bytes_amount.fetch_add(0, Relaxed);
                tokio::select! {
                    // Listening to server command
                    server_command = server_command_rx.recv() => {
                        match server_command {
                            Some(server_command) => {
                                match server_command {
                                    AgentServerCommand::Stop => {
                                        info!("Agent server stopped because of receive stop command.");
                                        stoped_status.swap(true, Ordering::Relaxed);
                                        publish_server_event(&server_event_tx, AgentServerEvent::ServerStopSuccess).await;
                                        return;
                                    },
                                }
                            },
                            None => {
                                info!("Agent server stopped because of no command tx.");
                                publish_server_event(&server_event_tx, AgentServerEvent::ServerStopSuccess).await;
                                return;
                            },
                        }
                    }
                    // Send netowrk
                    _ = server_event_tick_interval.tick() => {
                        let upload_bytes_amount_current_val =
                            upload_bytes_amount.fetch_add(0, Relaxed);
                        let download_bytes_amount_current_val =
                            download_bytes_amount.fetch_add(0, Relaxed);

                        let upload_mb_per_second =
                            (upload_bytes_amount_current_val - upload_bytes_amount_pre_val) as f64
                                / mb_per_second_div_base;

                        let download_mb_per_second = (download_bytes_amount_current_val
                            - download_bytes_amount_pre_val)
                            as f64
                            / mb_per_second_div_base;

                        publish_server_event(
                            &server_event_tx,
                            AgentServerEvent::NetworkState {
                                upload_mb_amount: upload_bytes_amount_current_val as f64
                                    / (1024 * 1024) as f64,
                                upload_mb_per_second,
                                download_mb_amount: download_bytes_amount_current_val as f64
                                    / (1024 * 1024) as f64,
                                download_mb_per_second,
                            },
                        )
                        .await;
                    }
                    // Accepting client connection
                    client_accept_result = Self::accept_client_connection(&tcp_listener) => {
                        match client_accept_result{
                            Ok((client_tcp_stream, client_socket_address)) => {
                                debug!("Accept client tcp connection on address: {client_socket_address}");
                                Self::handle_client_connection(
                                    client_tcp_stream,
                                    client_socket_address.into(),
                                    client_dispatcher.clone(),
                                    server_event_tx.clone(),
                                    upload_bytes_amount.clone(),
                                    download_bytes_amount.clone(),
                                    stoped_status.clone()
                                );
                            }
                            Err(e) => {
                                error!("Agent server fail to accept client connection because of error: {e:?}");
                                continue;
                            }
                        }
                    }
                }
            }
        });
        (server_command_tx, server_event_rx)
    }

    async fn accept_client_connection(
        tcp_listener: &TcpListener,
    ) -> Result<(TcpStream, SocketAddr), AgentServerError> {
        let (client_tcp_stream, client_socket_address) = tcp_listener.accept().await?;
        client_tcp_stream.set_nodelay(true)?;
        Ok((client_tcp_stream, client_socket_address))
    }

    fn handle_client_connection(
        client_tcp_stream: TcpStream,
        client_socket_address: PpaassUnifiedAddress,
        client_dispatcher: ClientDispatcher<AgentServerRsaCryptoFetcher>,
        server_event_tx: Sender<AgentServerEvent>,
        upload_bytes_amount: Arc<AtomicU64>,
        download_bytes_amount: Arc<AtomicU64>,
        stoped_status: Arc<AtomicBool>,
    ) {
        tokio::spawn(async move {
            let tunnel = match client_dispatcher
                .dispatch(
                    client_tcp_stream,
                    &client_socket_address,
                    &server_event_tx,
                    upload_bytes_amount,
                    download_bytes_amount,
                )
                .await
            {
                Ok(tunnel) => tunnel,
                Err(e) => {
                    error!("Fail to dispatch client connection [{client_socket_address}] to transport because of error: {e:?}");
                    return;
                }
            };

            match tunnel {
                Tunnel::Socks5(socks5_tunnel) => {
                    if let Err(e) = socks5_tunnel.process(&server_event_tx, stoped_status).await {
                        error!("Fail to process socks5 tunnel for client connection [{client_socket_address}] because of error: {e:?}");
                    }
                }
                Tunnel::Http(http_transport) => {
                    if let Err(e) = http_transport
                        .process(&server_event_tx, stoped_status)
                        .await
                    {
                        error!("Fail to process http tunnel for client connection [{client_socket_address}] because of error: {e:?}");
                    }
                }
            }
        });
    }
}
