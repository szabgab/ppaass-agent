use std::fs::read_to_string;

use lazy_static::lazy_static;
use serde_derive::{Deserialize, Serialize};

lazy_static! {
    pub static ref AGENT_CONFIG: AgentConfig = {
        let agent_configuration_file = read_to_string("resources/config/ppaass-agent.toml")
            .expect("Fail to read agent configuration file.");
        toml::from_str(&agent_configuration_file)
            .expect("Fail to parse agent configuration file content.")
    };
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AgentConfig {
    //The user token
    user_token: String,
    /// Whether use ip v6
    ipv6: Option<bool>,
    /// Port of the ppaass proxy
    port: u16,
    /// The root directory used to store the rsa
    /// files for each user
    rsa_dir: String,
    /// The threads number
    worker_thread_number: Option<usize>,
    /// Whether enable compressing
    compress: Option<bool>,
    /// The proxy addresses
    proxy_addresses: Vec<String>,
    client_receive_buffer_size: Option<usize>,
    proxy_send_buffer_size: Option<usize>,
    connect_to_proxy_timeout: Option<u64>,
    proxy_relay_timeout: Option<u64>,
    client_relay_timeout: Option<u64>,
}

impl AgentConfig {
    pub fn get_user_token(&self) -> &str {
        &self.user_token
    }

    pub fn get_proxy_addresses(&self) -> &Vec<String> {
        &self.proxy_addresses
    }

    pub fn get_ipv6(&self) -> bool {
        self.ipv6.unwrap_or(false)
    }

    pub fn get_port(&self) -> u16 {
        self.port
    }

    pub fn get_rsa_dir(&self) -> &str {
        &self.rsa_dir
    }

    pub fn get_worker_thread_number(&self) -> usize {
        self.worker_thread_number.unwrap_or(128)
    }

    pub fn get_compress(&self) -> bool {
        self.compress.unwrap_or(false)
    }

    pub fn get_proxy_send_buffer_size(&self) -> usize {
        self.proxy_send_buffer_size.unwrap_or(1024 * 512)
    }

    pub fn get_connect_to_proxy_timeout(&self) -> u64 {
        self.connect_to_proxy_timeout.unwrap_or(20)
    }
    pub fn get_client_receive_buffer_size(&self) -> usize {
        self.client_receive_buffer_size.unwrap_or(1024 * 512)
    }

    pub fn get_proxy_relay_timeout(&self) -> u64 {
        self.proxy_relay_timeout.unwrap_or(20)
    }

    pub fn get_client_relay_timeout(&self) -> u64 {
        self.client_relay_timeout.unwrap_or(20)
    }
}
