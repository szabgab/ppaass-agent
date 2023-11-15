use std::{
    fmt::Debug,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ppaass_common::PpaassNetAddress;

mod auth;
mod init;
mod udp;

pub(crate) use auth::*;
pub(crate) use init::*;
pub(crate) use udp::*;

use crate::error::{ConversionError, ParseError};

const IPV4_FLAG: u8 = 1;
const IPV6_FLAG: u8 = 4;
const DOMAIN_FLAG: u8 = 3;

#[derive(Debug, Clone)]
pub(crate) enum Socks5Address {
    IpV4([u8; 4], u16),
    IpV6([u8; 16], u16),
    Domain(String, u16),
}

impl Socks5Address {
    pub(crate) fn parse(input: &mut impl Buf) -> Result<Socks5Address, ParseError> {
        if !input.has_remaining() {
            return Err(ParseError::InputExhausted("Input bytes exhausted, remaining: 0".to_string()));
        }
        let address_type = input.get_u8();
        let address = match address_type {
            IPV4_FLAG => {
                if input.remaining() < 6 {
                    return Err(ParseError::InputExhausted(format!(
                        "Input bytes exhausted, remaining: {}, require: 6",
                        input.remaining()
                    )));
                }
                let mut addr_content = [0u8; 4];
                addr_content.iter_mut().for_each(|item| {
                    *item = input.get_u8();
                });
                let port = input.get_u16();
                Socks5Address::IpV4(addr_content, port)
            },
            IPV6_FLAG => {
                if input.remaining() < 18 {
                    return Err(ParseError::InputExhausted(format!(
                        "Input bytes exhausted, remaining: {}, require: 18",
                        input.remaining()
                    )));
                }
                let mut addr_content = [0u8; 16];
                addr_content.iter_mut().for_each(|item| {
                    *item = input.get_u8();
                });
                let port = input.get_u16();
                Socks5Address::IpV6(addr_content, port)
            },
            DOMAIN_FLAG => {
                if input.remaining() < 1 {
                    return Err(ParseError::InputExhausted(format!(
                        "Input bytes exhausted, remaining: {}, require: 1",
                        input.remaining()
                    )));
                }
                let domain_name_length = input.get_u8() as usize;
                if input.remaining() < domain_name_length + 2 {
                    return Err(ParseError::InputExhausted(format!(
                        "Input bytes exhausted, remaining: {}, require: {}",
                        input.remaining(),
                        domain_name_length + 2
                    )));
                }
                let domain_name_bytes = input.copy_to_bytes(domain_name_length);
                let domain_name = match String::from_utf8_lossy(domain_name_bytes.chunk()).to_string().as_str() {
                    "0" => "127.0.0.1".to_string(),
                    v => v.to_string(),
                };
                let port = input.get_u16();
                Socks5Address::Domain(domain_name, port)
            },
            unknown_addr_type => {
                return Err(ParseError::InvalidFormat(format!("Invalid address type: {unknown_addr_type}")));
            },
        };
        Ok(address)
    }
}

impl TryFrom<Socks5Address> for SocketAddr {
    type Error = ConversionError;

    fn try_from(socks5_addr: Socks5Address) -> Result<Self, Self::Error> {
        match socks5_addr {
            Socks5Address::IpV4(ip, port) => Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port))),
            Socks5Address::IpV6(ip, port) => {
                let mut ip_cursor = Cursor::new(ip);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(
                        ip_cursor.get_u16(),
                        ip_cursor.get_u16(),
                        ip_cursor.get_u16(),
                        ip_cursor.get_u16(),
                        ip_cursor.get_u16(),
                        ip_cursor.get_u16(),
                        ip_cursor.get_u16(),
                        ip_cursor.get_u16(),
                    ),
                    port,
                    0,
                    0,
                )))
            },
            Socks5Address::Domain(host, port) => {
                let address_string = format!("{host}:{port}");
                let addresses = address_string.to_socket_addrs()?.collect::<Vec<_>>();
                let result = addresses.get(0).ok_or(ConversionError::Format(address_string))?;
                Ok(*result)
            },
        }
    }
}

impl From<SocketAddr> for Socks5Address {
    fn from(socket_addr: SocketAddr) -> Self {
        match socket_addr {
            SocketAddr::V4(addr) => Socks5Address::IpV4(addr.ip().octets(), addr.port()),
            SocketAddr::V6(addr) => Socks5Address::IpV6(addr.ip().octets(), addr.port()),
        }
    }
}

impl ToString for Socks5Address {
    fn to_string(&self) -> String {
        match self {
            Self::IpV4(ip_content, port) => {
                format!("{}.{}.{}.{}:{}", ip_content[0], ip_content[1], ip_content[2], ip_content[3], port)
            },
            Self::IpV6(ip_content, port) => {
                let mut ip_content_bytes = Bytes::from(ip_content.to_vec());
                format!(
                    "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{}",
                    ip_content_bytes.get_u16(),
                    ip_content_bytes.get_u16(),
                    ip_content_bytes.get_u16(),
                    ip_content_bytes.get_u16(),
                    ip_content_bytes.get_u16(),
                    ip_content_bytes.get_u16(),
                    ip_content_bytes.get_u16(),
                    ip_content_bytes.get_u16(),
                    port
                )
            },
            Self::Domain(host, port) => {
                format!("{host}:{port}")
            },
        }
    }
}

impl From<Socks5Address> for Bytes {
    fn from(address: Socks5Address) -> Self {
        let mut result = BytesMut::new();
        match address {
            Socks5Address::IpV4(addr_content, port) => {
                result.put_u8(IPV4_FLAG);
                result.put_slice(&addr_content);
                result.put_u16(port);
            },
            Socks5Address::IpV6(addr_content, port) => {
                result.put_u8(IPV6_FLAG);
                result.put_slice(&addr_content);
                result.put_u16(port);
            },
            Socks5Address::Domain(addr_content, port) => {
                result.put_u8(DOMAIN_FLAG);
                result.put_u8(addr_content.len() as u8);
                result.put_slice(addr_content.as_bytes());
                result.put_u16(port);
            },
        }
        result.into()
    }
}

impl From<Socks5Address> for PpaassNetAddress {
    fn from(value: Socks5Address) -> Self {
        match value {
            Socks5Address::IpV4(host, port) => PpaassNetAddress::IpV4 { ip: host, port },
            Socks5Address::IpV6(host, port) => PpaassNetAddress::IpV6 { ip: host, port },
            Socks5Address::Domain(host, port) => PpaassNetAddress::Domain { host, port },
        }
    }
}

impl TryFrom<PpaassNetAddress> for Socks5Address {
    type Error = ConversionError;
    fn try_from(net_addr: PpaassNetAddress) -> Result<Self, Self::Error> {
        match net_addr {
            PpaassNetAddress::IpV4 { ip, port } => Ok(Socks5Address::IpV4(ip, port)),
            PpaassNetAddress::IpV6 { ip, port } => Ok(Socks5Address::IpV6(ip, port)),
            PpaassNetAddress::Domain { host, port } => Ok(Socks5Address::Domain(host, port)),
        }
    }
}
