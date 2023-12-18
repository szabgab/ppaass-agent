use crate::error::AgentError;
use derive_more::Constructor;

use super::Socks5Address;

#[derive(Debug)]
pub(crate) enum Socks5InitCommandType {
    Connect,
    Bind,
    UdpAssociate,
}

impl TryFrom<u8> for Socks5InitCommandType {
    type Error = AgentError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Socks5InitCommandType::Connect),
            2 => Ok(Socks5InitCommandType::Bind),
            3 => Ok(Socks5InitCommandType::UdpAssociate),
            unknown_type => Err(AgentError::Other(format!(
                "Unkown socks5 init command: {unknown_type}"
            ))),
        }
    }
}

#[derive(Debug)]
pub(crate) enum Socks5InitCommandResultStatus {
    Succeeded,
    Failure,
    ConnectionNotAllowedByRuleSet,
    NetworkUnReachable,
    HostUnReachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned,
}

impl TryFrom<u8> for Socks5InitCommandResultStatus {
    type Error = AgentError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Socks5InitCommandResultStatus::Succeeded),
            1 => Ok(Socks5InitCommandResultStatus::Failure),
            2 => Ok(Socks5InitCommandResultStatus::ConnectionNotAllowedByRuleSet),
            3 => Ok(Socks5InitCommandResultStatus::NetworkUnReachable),
            4 => Ok(Socks5InitCommandResultStatus::HostUnReachable),
            5 => Ok(Socks5InitCommandResultStatus::ConnectionRefused),
            6 => Ok(Socks5InitCommandResultStatus::TtlExpired),
            7 => Ok(Socks5InitCommandResultStatus::CommandNotSupported),
            8 => Ok(Socks5InitCommandResultStatus::AddressTypeNotSupported),
            9 => Ok(Socks5InitCommandResultStatus::Unassigned),
            unknown_status => Err(AgentError::Other(format!(
                "Unkown sock5 init command result status: {unknown_status}"
            ))),
        }
    }
}

impl From<Socks5InitCommandResultStatus> for u8 {
    fn from(value: Socks5InitCommandResultStatus) -> Self {
        match value {
            Socks5InitCommandResultStatus::Succeeded => 0,
            Socks5InitCommandResultStatus::Failure => 1,
            Socks5InitCommandResultStatus::ConnectionNotAllowedByRuleSet => 2,
            Socks5InitCommandResultStatus::NetworkUnReachable => 3,
            Socks5InitCommandResultStatus::HostUnReachable => 4,
            Socks5InitCommandResultStatus::ConnectionRefused => 5,
            Socks5InitCommandResultStatus::TtlExpired => 6,
            Socks5InitCommandResultStatus::CommandNotSupported => 7,
            Socks5InitCommandResultStatus::AddressTypeNotSupported => 8,
            Socks5InitCommandResultStatus::Unassigned => 9,
        }
    }
}

#[derive(Debug, Constructor)]
pub(crate) struct Socks5InitCommand {
    pub(crate) request_type: Socks5InitCommandType,
    pub(crate) dst_address: Socks5Address,
}

#[derive(Debug, Constructor)]
pub(crate) struct Socks5InitCommandResult {
    pub(crate) status: Socks5InitCommandResultStatus,
    pub(crate) bind_address: Option<Socks5Address>,
}
