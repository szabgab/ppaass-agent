use crate::crypto::{AgentRsaCryptoFetcher, RSA_CRYPTO};
use crate::error::AgentError;
use bytes::BytesMut;
use ppaass_codec::codec::agent::encoder::AgentMessageEncoder;
use ppaass_codec::codec::proxy::decoder::ProxyMessageDecoder;
use ppaass_protocol::message::agent::AgentMessage;
use ppaass_protocol::message::proxy::ProxyMessage;
use tokio_util::codec::{Decoder, Encoder};

pub(crate) struct ProxyConnectionCodec {
    encoder: AgentMessageEncoder<AgentRsaCryptoFetcher>,
    decoder: ProxyMessageDecoder<AgentRsaCryptoFetcher>,
}

impl ProxyConnectionCodec {
    pub fn new(compress: bool) -> Self {
        Self {
            encoder: AgentMessageEncoder::new(compress, RSA_CRYPTO.clone()),
            decoder: ProxyMessageDecoder::new(RSA_CRYPTO.clone()),
        }
    }
}

impl Decoder for ProxyConnectionCodec {
    type Item = ProxyMessage;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.decoder.decode(src).map_err(AgentError::Codec)
    }
}

impl Encoder<AgentMessage> for ProxyConnectionCodec {
    type Error = AgentError;

    fn encode(&mut self, item: AgentMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encoder.encode(item, dst).map_err(AgentError::Codec)
    }
}
