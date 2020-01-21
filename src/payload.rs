use std::slice;

use crate::hex::{hex_byte, hex_nibble, NibbleResult};

pub enum DecodeError {
    IncompleteByte,
    InvalidNibble(u8),
}

pub struct EncodedPayload<'a>(&'a [u8]);

pub trait PayloadDecoder<'a>: From<&'a [u8]> + Iterator<Item = Result<u8, DecodeError>> {}

///////////////////////////////////////////////////////////////////////////////

pub struct HexDecodeIterator<'a>(slice::Iter<'a, u8>);

impl<'a> HexDecodeIterator<'a> {
    fn next_nibble_value(&mut self) -> Result<Option<u8>, DecodeError> {
        loop {
            let nibble_res = self.0.next().map(Clone::clone).map(hex_nibble);
            match nibble_res {
                None => return Ok(None),
                Some(NibbleResult::Ignore) => continue,
                Some(NibbleResult::Value(value)) => return Ok(Some(value)),
                Some(NibbleResult::Invalid(nibble)) => {
                    return Err(DecodeError::InvalidNibble(nibble))
                }
            }
        }
    }

    #[inline]
    fn next_byte(&mut self) -> Result<Option<u8>, DecodeError> {
        if let Some(high) = self.next_nibble_value()? {
            if let Some(low) = self.next_nibble_value()? {
                Ok(Some(hex_byte(high, low)))
            } else {
                Err(DecodeError::IncompleteByte)
            }
        } else {
            Ok(None)
        }
    }
}

impl<'a> From<&'a [u8]> for HexDecodeIterator<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(bytes.iter())
    }
}

impl<'a> Iterator for HexDecodeIterator<'a> {
    type Item = Result<u8, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_byte().transpose()
    }
}

impl<'a> PayloadDecoder<'a> for HexDecodeIterator<'a> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_iter_basic() {
        let payload = ".Aa.B.100.".as_bytes();
        let decode = HexDecodeIterator::from(payload);
        let decoded: Vec<u8> = decode.filter_map(Result::ok).collect();
        assert_eq!(decoded, vec![0xAA, 0xB1, 0x00]);
    }
}
