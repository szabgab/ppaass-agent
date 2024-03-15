use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::{command, Parser};

use tracing::level_filters::LevelFilter;

#[derive(Parser)]
#[command(
    version,
    about,
    long_about = "The agent part of the ppaass application"
)]
pub struct AgentConfig {
    /// The user token
    #[arg(short, long, default_value = "user1")]
    user_token: String,
    /// Whether use ip v6
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
}

impl AgentConfig {
    pub fn get_user_token(&self) -> &str {
        &self.user_token
    }

    pub fn get_proxy_addresses(&self) -> &Vec<String> {
        &self.proxy_addresses
    }

    pub fn get_ipv6(&self) -> bool {
        self.ipv6
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn get_rsa_dir(&self) -> &Path {
        &self.rsa_dir
    }

    pub fn get_worker_thread_number(&self) -> usize {
        self.worker_thread_number
    }

    pub fn get_compress(&self) -> bool {
        self.compress
    }

    pub fn get_proxy_send_buffer_size(&self) -> usize {
        self.proxy_send_buffer_size
    }

    pub fn get_connect_to_proxy_timeout(&self) -> u64 {
        self.connect_to_proxy_timeout
    }
    pub fn get_client_receive_buffer_size(&self) -> usize {
        self.client_receive_buffer_size
    }

    pub(crate) fn get_max_log_level(&self) -> LevelFilter {
        LevelFilter::from_str(&self.max_log_level).unwrap_or(LevelFilter::ERROR)
    }
}
