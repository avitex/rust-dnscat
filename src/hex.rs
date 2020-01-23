const HEX_NIBBLE_INVALID: u8 = 0xFF;
const HEX_NIBBLE_IGNORED: u8 = 0xFE;

const DEC_TO_HEX_NIBBLE: &[u8] = b"0123456789abdef";

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

#[derive(Debug, PartialEq)]
pub enum NibbleResult {
    Ignore,
    Value(u8),
    Invalid(u8),
}

#[inline]
pub fn hex_byte(high: u8, low: u8) -> u8 {
    low | (high << 4)
}

#[inline]
pub fn byte_nibbles(byte: u8) -> (u8, u8) {
    (byte >> 4, byte & 0x0F)
}

pub fn hex_encode_into(src: &[u8], dst: &mut [u8]) {
    assert!(
        dst.len() / 2 == src.len(),
        "hex src length must be dst length / 2"
    );
    let mut i = 0;
    for byte in src.iter() {
        let (high, low) = byte_nibbles(*byte);
        dst[i] = DEC_TO_HEX_NIBBLE[high as usize];
        dst[i + 1] = DEC_TO_HEX_NIBBLE[low as usize];
        i += 2;
    }
}

pub fn hex_decode_into(src: &[u8], dst: &mut [u8]) -> Result<(), usize> {
    assert!(
        src.len() / 2 == dst.len(),
        "hex dst length must be src length / 2"
    );
    for (i, chunk) in src.chunks_exact(2).enumerate() {
        if let [high, low] = chunk {
            match (hex_nibble(*high), hex_nibble(*low)) {
                (NibbleResult::Value(high), NibbleResult::Value(low)) => {
                    dst[i] = hex_byte(high, low);
                }
                _ => return Err(i),
            }
        } else {
            unreachable!();
        }
    }
    Ok(())
}

#[inline]
pub fn hex_nibble(nibble: u8) -> NibbleResult {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_nibble_basic() {
        // Number
        assert_eq!(hex_nibble(b'0'), NibbleResult::Value(0x0));
        assert_eq!(hex_nibble(b'9'), NibbleResult::Value(0x9));
        // Lowercase
        assert_eq!(hex_nibble(b'a'), NibbleResult::Value(0xA));
        assert_eq!(hex_nibble(b'f'), NibbleResult::Value(0xF));
        // Uppercase
        assert_eq!(hex_nibble(b'A'), NibbleResult::Value(0xA));
        assert_eq!(hex_nibble(b'F'), NibbleResult::Value(0xF));
        // Dot
        assert_eq!(hex_nibble(b'.'), NibbleResult::Ignore);
        // Invalid
        assert_eq!(hex_nibble(0xFF), NibbleResult::Invalid(0xFF));
    }

    #[test]
    fn test_hex_byte() {
        assert_eq!(hex_byte(0x00, 0x00), 0x00);
        assert_eq!(hex_byte(0x00, 0x0F), 0x0F);
        assert_eq!(hex_byte(0x0F, 0x00), 0xF0);
        assert_eq!(hex_byte(0x0F, 0x0F), 0xFF);
    }
}
