use std::path::PathBuf;

use clap::{command, Parser};
use serde::{Deserialize, Serialize};

#[derive(Parser, Clone, Debug, Serialize, Deserialize)]
#[command(
    version,
    about,
    long_about = "The agent part of the ppaass application"
)]
pub struct AgentServerConfig {
    /// The user token
    #[arg(short, long, default_value = "user1")]
    user_token: String,
    /// Whether you use ip v6
    #[arg(short = '6', long, default_value = "false")]
    ipv6: bool,
    /// Port of the ppaass proxy
    #[arg(short, long, default_value = "10080")]
    port: u16,
    /// The root directory used to store the rsa
    /// files for each user
    #[arg(short, long, default_value = "./resources/rsa/")]
    rsa_dir: PathBuf,
    /// The threads number
    #[arg(short, long, default_value = "128")]
    worker_thread_number: usize,
    /// Whether enable compressing
    #[arg(short, long, default_value = "true")]
    compress: bool,
    /// The proxy addresses
    #[arg(long, default_value = "64.176.193.76:80")]
    proxy_addresses: Vec<String>,
    /// The client receive buffer size
    #[arg(long, default_value = "65536")]
    client_receive_buffer_size: usize,
    /// The proxy send buffer size
    #[arg(long, default_value = "65536")]
    proxy_send_buffer_size: usize,
    /// The timeout for connect to proxy
    #[arg(long, default_value = "120")]
    connect_to_proxy_timeout: u64,
    /// The max log level
    #[arg(long, default_value = "ERROR")]
    max_log_level: String,
    /// The timeout for proxy connection read
    #[arg(long, default_value = "120")]
    proxy_connection_read_timeout: u64,
    /// The timeout for proxy connection write
    #[arg(long, default_value = "120")]
    proxy_connection_write_timeout: u64,

    #[arg(long, default_value = "120")]
    client_connection_read_timeout: u64,
    /// The timeout for proxy connection write
    #[arg(long, default_value = "120")]
    client_connection_write_timeout: u64,

    /// The timeout for proxy connection write
    #[arg(long, default_value = "1")]
    server_signal_tick_interval: u64,
}

impl AgentServerConfig {
    pub fn set_user_token(&mut self, user_token: String) {
        self.user_token = user_token;
    }
    pub fn set_ipv6(&mut self, ipv6: bool) {
        self.ipv6 = ipv6;
    }
    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }
    pub fn set_rsa_dir(&mut self, rsa_dir: PathBuf) {
        self.rsa_dir = rsa_dir;
    }
    pub fn set_worker_thread_number(&mut self, worker_thread_number: usize) {
        self.worker_thread_number = worker_thread_number;
    }
    pub fn set_compress(&mut self, compress: bool) {
        self.compress = compress;
    }
    pub fn set_proxy_addresses(&mut self, proxy_addresses: Vec<String>) {
        self.proxy_addresses = proxy_addresses;
    }
    pub fn set_client_receive_buffer_size(&mut self, client_receive_buffer_size: usize) {
        self.client_receive_buffer_size = client_receive_buffer_size;
    }
    pub fn set_proxy_send_buffer_size(&mut self, proxy_send_buffer_size: usize) {
        self.proxy_send_buffer_size = proxy_send_buffer_size;
    }
    pub fn set_connect_to_proxy_timeout(&mut self, connect_to_proxy_timeout: u64) {
        self.connect_to_proxy_timeout = connect_to_proxy_timeout;
    }
    pub fn set_max_log_level(&mut self, max_log_level: String) {
        self.max_log_level = max_log_level;
    }
    pub fn set_proxy_connection_read_timeout(&mut self, proxy_connection_read_timeout: u64) {
        self.proxy_connection_read_timeout = proxy_connection_read_timeout;
    }
    pub fn set_proxy_connection_write_timeout(&mut self, proxy_connection_write_timeout: u64) {
        self.proxy_connection_write_timeout = proxy_connection_write_timeout;
    }
    pub fn user_token(&self) -> &str {
        &self.user_token
    }
    pub fn ipv6(&self) -> bool {
        self.ipv6
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn rsa_dir(&self) -> &PathBuf {
        &self.rsa_dir
    }
    pub fn worker_thread_number(&self) -> usize {
        self.worker_thread_number
    }
    pub fn compress(&self) -> bool {
        self.compress
    }
    pub fn proxy_addresses(&self) -> &Vec<String> {
        &self.proxy_addresses
    }
    pub fn client_receive_buffer_size(&self) -> usize {
        self.client_receive_buffer_size
    }
    pub fn proxy_send_buffer_size(&self) -> usize {
        self.proxy_send_buffer_size
    }
    pub fn connect_to_proxy_timeout(&self) -> u64 {
        self.connect_to_proxy_timeout
    }
    pub fn max_log_level(&self) -> &str {
        &self.max_log_level
    }
    pub fn proxy_connection_read_timeout(&self) -> u64 {
        self.proxy_connection_read_timeout
    }
    pub fn proxy_connection_write_timeout(&self) -> u64 {
        self.proxy_connection_write_timeout
    }

    pub fn client_connection_read_timeout(&self) -> u64 {
        self.client_connection_read_timeout
    }
    pub fn client_connection_write_timeout(&self) -> u64 {
        self.client_connection_write_timeout
    }

    pub fn set_client_connection_read_timeout(&mut self, client_connection_read_timeout: u64) {
        self.client_connection_read_timeout = client_connection_read_timeout;
    }

    pub fn set_client_connection_write_timeout(&mut self, client_connection_write_timeout: u64) {
        self.client_connection_write_timeout = client_connection_write_timeout;
    }

    pub fn server_signal_tick_interval(&self) -> u64 {
        self.server_signal_tick_interval
    }

    pub fn set_server_signal_tick_interval(&mut self, server_signal_tick_interval: u64) {
        self.server_signal_tick_interval = server_signal_tick_interval
    }
}
