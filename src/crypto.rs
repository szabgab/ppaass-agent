use std::collections::HashMap;

use crate::config::AGENT_CONFIG;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use log::error;
use ppaass_common::{RsaCrypto, RsaCryptoFetcher, RsaError};

lazy_static! {
    pub(crate) static ref RSA_CRYPTO: AgentServerRsaCryptoFetcher = AgentServerRsaCryptoFetcher::new().expect("Can not initialize agent rsa crypto fetcher.");
}

#[derive(Debug)]
pub(crate) struct AgentServerRsaCryptoFetcher {
    cache: HashMap<String, RsaCrypto>,
}

impl AgentServerRsaCryptoFetcher {
    pub(crate) fn new() -> Result<Self> {
        let mut result = Self { cache: HashMap::new() };
        let rsa_dir_path = AGENT_CONFIG.get_rsa_dir().context("fail to get rsa directory from configuration file")?;
        let rsa_dir = std::fs::read_dir(rsa_dir_path).context("fail to read rsa directory")?;
        rsa_dir.for_each(|entry| {
            let Ok(entry) = entry else {
                error!("fail to read {rsa_dir_path} directory because of error.");
                return;
            };
            let user_token = entry.file_name();
            let user_token = user_token.to_str();
            let Some(user_token) = user_token else {
                error!("fail to read user_token from file name: {:?}", entry.file_name());
                return;
            };
            let public_key_path = format!("{rsa_dir_path}{user_token}/ProxyPublicKey.pem");
            let public_key_path = std::path::Path::new(&public_key_path);
            let public_key_file = match std::fs::File::open(public_key_path) {
                Err(e) => {
                    error!("fail to read public key file {public_key_path:?} because of error: {e:?}");
                    return;
                },
                Ok(v) => v,
            };
            let private_key_path = format!("{rsa_dir_path}{user_token}/AgentPrivateKey.pem");
            let private_key_path = std::path::Path::new(std::path::Path::new(&private_key_path));
            let private_key_file = match std::fs::File::open(private_key_path) {
                Err(e) => {
                    error!("fail to read private key file {private_key_path:?} because of error: {e:?}");
                    return;
                },
                Ok(v) => v,
            };

            let rsa_crypto = match RsaCrypto::new(public_key_file, private_key_file) {
                Err(e) => {
                    error!("fail to create rsa crypto for user: {user_token} because of error: {e:?}");
                    return;
                },
                Ok(v) => v,
            };
            result.cache.insert(user_token.to_string(), rsa_crypto);
        });
        Ok(result)
    }
}

impl RsaCryptoFetcher for AgentServerRsaCryptoFetcher {
    fn fetch(&self, user_token: impl AsRef<str>) -> Result<Option<&RsaCrypto>, RsaError> {
        Ok(self.cache.get(user_token.as_ref()))
    }
}
