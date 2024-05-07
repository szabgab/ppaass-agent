use super::Socks5Address;
use crate::error::AgentServerError;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::mem::size_of;

/// Socks5 udp data request
#[derive(Debug)]
pub(crate) struct Socks5UdpDataPacket {
    pub frag: u8,
    pub address: Socks5Address,
    pub data: Bytes,
}

impl TryFrom<Bytes> for Socks5UdpDataPacket {
    type Error = AgentServerError;

    fn try_from(mut src: Bytes) -> Result<Self, Self::Error> {
        // Check the buffer
        if !src.has_remaining() {
            return Err(AgentServerError::Other(
                "No remaining to convert socks5 udp packet".to_string(),
            ));
        }
        // Check and skip the revision
        if src.remaining() < size_of::<u16>() {
            return Err(AgentServerError::Other(
                "No remaining to convert socks5 udp packet".to_string(),
            ));
        }
        src.get_u16();
        if src.remaining() < size_of::<u8>() {
            return Err(AgentServerError::Other(
                "No remaining to convert socks5 udp packet".to_string(),
            ));
        }
        let frag = src.get_u8();
        let address = Socks5Address::parse(&mut src)?;
        Ok(Socks5UdpDataPacket {
            frag,
            address,
            data: src,
        })
    }
}

impl From<Socks5UdpDataPacket> for Bytes {
    fn from(packet: Socks5UdpDataPacket) -> Self {
        let Socks5UdpDataPacket {
            frag,
            address,
            data,
        } = packet;
        let mut result = BytesMut::new();
        result.put_u16(0);
        result.put_u8(frag);
        result.put::<Bytes>(address.into());
        result.put(data.as_ref());
        result.freeze()
    }
}
