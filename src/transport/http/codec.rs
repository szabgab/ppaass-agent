use bytecodec::{
    bytes::{BytesEncoder, RemainingBytesDecoder},
    ErrorKind,
};
use bytecodec::{io::IoDecodeExt, EncodeExt};

use bytes::{Buf, BufMut, BytesMut};
use httpcodec::{BodyDecoder, BodyEncoder, Request, RequestDecoder, Response, ResponseEncoder};

use log::error;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::AgentError;

#[derive(Debug, Default)]
pub(crate) struct HttpCodec {
    request_decoder: RequestDecoder<BodyDecoder<RemainingBytesDecoder>>,
    response_encoder: ResponseEncoder<BodyEncoder<BytesEncoder>>,
}

impl Decoder for HttpCodec {
    type Item = Request<Vec<u8>>;
    type Error = AgentError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let decode_result = match self.request_decoder.decode_exact(src.chunk()) {
            Ok(decode_result) => decode_result,
            Err(e) => match e.kind() {
                ErrorKind::IncompleteDecoding => return Ok(None),
                other_kind => {
                    error!("Http agent fail to decode because of error: {other_kind:?}");
                    return Err(AgentError::Other(format!(
                        "Fail to decode http request because of error: {e:?}"
                    )));
                }
            },
        };
        Ok(Some(decode_result))
    }
}

impl Encoder<Response<Vec<u8>>> for HttpCodec {
    type Error = AgentError;

    fn encode(&mut self, item: Response<Vec<u8>>, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let encode_result = self.response_encoder.encode_into_bytes(item).map_err(|e| {
            AgentError::Other(format!(
                "Fail to encode http response because of error: {e:?}"
            ))
        })?;
        dst.put_slice(encode_result.as_slice());
        Ok(())
    }
}
