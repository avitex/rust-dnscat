mod ip;

pub use self::ip::*;

#[derive(Debug, PartialEq)]
pub enum MessageError {
    TooLong,
    MissingSequence(u8),
    LengthOutOfBounds { min: usize, max: usize, len: usize },
}
