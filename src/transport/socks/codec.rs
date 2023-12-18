use bytes::{Buf, BufMut, Bytes, BytesMut};

use log::error;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::AgentError;
use crate::SOCKS_V5;

use super::message::{
    Socks5Address, Socks5AuthCommand, Socks5AuthCommandResult, Socks5AuthMethod, Socks5InitCommand,
    Socks5InitCommandResult, Socks5InitCommandType,
};

#[derive(Debug, Default)]
pub(crate) struct Socks5AuthCommandContentCodec;

impl Decoder for Socks5AuthCommandContentCodec {
    type Item = Socks5AuthCommand;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 2 {
            return Ok(None);
        }
        let version = src.get_u8();
        if version != SOCKS_V5 {
            error!("The incoming protocol is not for socks 5: {version}.");
            return Err(AgentError::Other(format!(
                "The incoming protocol is not for socks5: {version}"
            )));
        }
        let methods_number = src.get_u8();
        let mut methods = Vec::<Socks5AuthMethod>::new();
        (0..methods_number).for_each(|_| {
            methods.push(Socks5AuthMethod::from(src.get_u8()));
        });
        Ok(Some(Socks5AuthCommand::new(methods)))
    }
}

impl Encoder<Socks5AuthCommandResult> for Socks5AuthCommandContentCodec {
    type Error = AgentError;

    fn encode(
        &mut self,
        item: Socks5AuthCommandResult,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.put_u8(SOCKS_V5);
        dst.put_u8(item.method.into());
        Ok(())
    }
}

#[derive(Debug, Default)]
pub(crate) struct Socks5InitCommandContentCodec;

impl Decoder for Socks5InitCommandContentCodec {
    type Item = Socks5InitCommand;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let version = src.get_u8();
        if version != SOCKS_V5 {
            error!("The incoming protocol is not for socks 5: {version}.");
            return Err(AgentError::Other(format!(
                "The incoming protocol is not for socks 5: {version}."
            )));
        }
        let request_type: Socks5InitCommandType = src.get_u8().try_into()?;
        src.get_u8();
        let dst_address = Socks5Address::parse(src)?;
        Ok(Some(Socks5InitCommand::new(request_type, dst_address)))
    }
}

impl Encoder<Socks5InitCommandResult> for Socks5InitCommandContentCodec {
    type Error = AgentError;

    fn encode(
        &mut self,
        item: Socks5InitCommandResult,
        dst: &mut BytesMut,
    ) -> Result<(), Self::Error> {
        dst.put_u8(5);
        dst.put_u8(item.status.into());
        dst.put_u8(0);
        if let Some(bind_address) = item.bind_address {
            dst.put::<Bytes>(bind_address.into());
        }
        Ok(())
    }
}
