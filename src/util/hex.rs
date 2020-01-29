use bytes::BufMut;

const HEX_NIBBLE_INVALID: u8 = 0xFF;
const HEX_NIBBLE_IGNORED: u8 = 0xFE;

const DEC_TO_HEX_NIBBLE: &[u8] = b"0123456789abcdef";

const HEX_TO_DEC_NIBBLE: &[u8] = &[
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 016
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 032
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, // 048
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
    0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 064
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 080
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 096
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 112
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 128
];

#[derive(Debug, Clone, PartialEq)]
pub struct InvalidHexByte(pub u8, pub u8);

#[derive(Debug, PartialEq)]
pub enum NibbleResult {
    Ignore,
    Value(u8),
    Invalid(u8),
}

#[inline]
pub fn split_halves(byte: u8) -> (u8, u8) {
    (byte >> 4, byte & 0x0F)
}

#[inline]
pub fn join_halves(high: u8, low: u8) -> u8 {
    low | (high << 4)
}

#[inline]
pub fn decode_nibble(nibble: u8) -> NibbleResult {
    if nibble > 127 {
        return NibbleResult::Invalid(nibble);
    }
    assert!(nibble <= 127);
    match HEX_TO_DEC_NIBBLE[nibble as usize] {
        HEX_NIBBLE_IGNORED => NibbleResult::Ignore,
        HEX_NIBBLE_INVALID => NibbleResult::Invalid(nibble),
        value => NibbleResult::Value(value),
    }
}

#[inline]
pub fn encode_nibble(nibble: u8) -> u8 {
    assert!(nibble <= 0x0F, "nibble greater than 0x0F: {:?}", nibble);
    DEC_TO_HEX_NIBBLE[nibble as usize]
}

pub fn encode_into_buf<B: BufMut>(buf: &mut B, src: &[u8]) {
    for byte in src.iter() {
        let (high, low) = split_halves(*byte);
        buf.put_u8(encode_nibble(high));
        buf.put_u8(encode_nibble(low));
    }
}

pub fn decode_into_buf<B: BufMut>(buf: &mut B, src: &[u8]) -> Result<(), InvalidHexByte> {
    for chunk in src.chunks_exact(2) {
        if let [high, low] = chunk {
            match (decode_nibble(*high), decode_nibble(*low)) {
                (NibbleResult::Value(high), NibbleResult::Value(low)) => {
                    buf.put_u8(join_halves(high, low));
                }
                _ => return Err(InvalidHexByte(*high, *low)),
            }
        } else {
            panic!("hex decode src len not even");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    const TEST_BYTES_ENCODED: &[u8] = b"deadbeef";
    const TEST_BYTES_DECODED: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];

    #[test]
    fn test_join_halves() {
        assert_eq!(join_halves(0x00, 0x00), 0x00);
        assert_eq!(join_halves(0x00, 0x0F), 0x0F);
        assert_eq!(join_halves(0x0F, 0x00), 0xF0);
        assert_eq!(join_halves(0x0F, 0x0F), 0xFF);
    }

    #[test]
    fn test_split_halves() {
        assert_eq!(split_halves(0x00), (0x00, 0x00));
        assert_eq!(split_halves(0x0F), (0x00, 0x0F));
        assert_eq!(split_halves(0xF0), (0x0F, 0x00));
        assert_eq!(split_halves(0xFF), (0x0F, 0x0F));
    }

    #[test]
    fn test_decode_nibble() {
        // Number
        assert_eq!(decode_nibble(b'0'), NibbleResult::Value(0x0));
        assert_eq!(decode_nibble(b'9'), NibbleResult::Value(0x9));
        // Lowercase
        assert_eq!(decode_nibble(b'a'), NibbleResult::Value(0xA));
        assert_eq!(decode_nibble(b'f'), NibbleResult::Value(0xF));
        // Uppercase
        assert_eq!(decode_nibble(b'A'), NibbleResult::Value(0xA));
        assert_eq!(decode_nibble(b'F'), NibbleResult::Value(0xF));
        // Dot
        assert_eq!(decode_nibble(b'.'), NibbleResult::Ignore);
        // Invalid
        assert_eq!(decode_nibble(0xFF), NibbleResult::Invalid(0xFF));
    }

    #[test]
    fn test_encode_nibble() {
        assert_eq!(encode_nibble(0x0), b'0');
        assert_eq!(encode_nibble(0x1), b'1');
        assert_eq!(encode_nibble(0x2), b'2');
        assert_eq!(encode_nibble(0x3), b'3');
        assert_eq!(encode_nibble(0x4), b'4');
        assert_eq!(encode_nibble(0x5), b'5');
        assert_eq!(encode_nibble(0x6), b'6');
        assert_eq!(encode_nibble(0x7), b'7');
        assert_eq!(encode_nibble(0x8), b'8');
        assert_eq!(encode_nibble(0x9), b'9');
        assert_eq!(encode_nibble(0xA), b'a');
        assert_eq!(encode_nibble(0xB), b'b');
        assert_eq!(encode_nibble(0xC), b'c');
        assert_eq!(encode_nibble(0xD), b'd');
        assert_eq!(encode_nibble(0xE), b'e');
        assert_eq!(encode_nibble(0xF), b'f');
    }

    #[test]
    fn test_decode_into_buf() {
        let mut dst = BytesMut::new();
        decode_into_buf(&mut dst, TEST_BYTES_ENCODED).unwrap();
        assert_eq!(TEST_BYTES_DECODED, &dst[..]);
    }

    #[test]
    fn test_encode_into_buf() {
        let mut dst = BytesMut::new();
        encode_into_buf(&mut dst, TEST_BYTES_DECODED);
        assert_eq!(TEST_BYTES_ENCODED, &dst[..]);
    }
}
