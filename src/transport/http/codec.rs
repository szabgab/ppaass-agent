use bytecodec::{
    bytes::{BytesEncoder, RemainingBytesDecoder},
    ErrorKind,
};
use bytecodec::{io::IoDecodeExt, EncodeExt};

use bytes::{Buf, BufMut, BytesMut};
use httpcodec::{BodyDecoder, BodyEncoder, Request, RequestDecoder, Response, ResponseEncoder};

use crate::error::AgentServerError;
use tokio_util::codec::{Decoder, Encoder};
use tracing::error;

#[derive(Debug, Default)]
pub(crate) struct HttpCodec {
    request_decoder: RequestDecoder<BodyDecoder<RemainingBytesDecoder>>,
    response_encoder: ResponseEncoder<BodyEncoder<BytesEncoder>>,
}

impl Decoder for HttpCodec {
    type Item = Request<Vec<u8>>;
    type Error = AgentServerError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decode_result = match self.request_decoder.decode_exact(src.chunk()) {
            Ok(decode_result) => decode_result,
            Err(e) => match e.kind() {
                ErrorKind::IncompleteDecoding => return Ok(None),
                other_kind => {
                    error!("Http agent fail to decode because of error: {other_kind:?}");
                    return Err(AgentServerError::Other(format!(
                        "Http agent fail to decode because of error: {other_kind:?}"
                    )));
                }
            },
        };
        Ok(Some(decode_result))
    }
}

impl Encoder<Response<Vec<u8>>> for HttpCodec {
    type Error = AgentServerError;

    fn encode(&mut self, item: Response<Vec<u8>>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encode_result = self.response_encoder.encode_into_bytes(item).map_err(|e| {
            AgentServerError::Other(format!(
                "Fail to encode http response because of error: {e:?}"
            ))
        })?;
        dst.put_slice(encode_result.as_slice());
        Ok(())
    }
}
