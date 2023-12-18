use derive_more::Constructor;

#[derive(Debug)]
pub(crate) enum Socks5AuthMethod {
    NoAuthenticationRequired,
    GssApi,
    UsernameAndPassword,
    IanaAssigned,
    ReservedForPrivateMethods,
    NoAcceptableMethods,
}

impl From<u8> for Socks5AuthMethod {
    fn from(v: u8) -> Self {
        match v {
            0 => Socks5AuthMethod::NoAuthenticationRequired,
            1 => Socks5AuthMethod::GssApi,
            2 => Socks5AuthMethod::UsernameAndPassword,
            3 => Socks5AuthMethod::IanaAssigned,
            8 => Socks5AuthMethod::ReservedForPrivateMethods,
            16 => Socks5AuthMethod::NoAcceptableMethods,
            _ => Socks5AuthMethod::NoAuthenticationRequired,
        }
    }
}

impl From<Socks5AuthMethod> for u8 {
    fn from(value: Socks5AuthMethod) -> Self {
        match value {
            Socks5AuthMethod::NoAuthenticationRequired => 0,
            Socks5AuthMethod::GssApi => 1,
            Socks5AuthMethod::UsernameAndPassword => 2,
            Socks5AuthMethod::IanaAssigned => 3,
            Socks5AuthMethod::ReservedForPrivateMethods => 8,
            Socks5AuthMethod::NoAcceptableMethods => 16,
        }
    }
}

#[derive(Debug, Constructor)]
pub(crate) struct Socks5AuthCommand {
    pub(crate) methods: Vec<Socks5AuthMethod>,
}

#[derive(Debug, Constructor)]
pub(crate) struct Socks5AuthCommandResult {
    pub(crate) method: Socks5AuthMethod,
}
