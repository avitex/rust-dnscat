mod ip;
mod hex;
pub mod payload;

pub use self::ip::*;

pub struct Message {}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    SYN = 0x00,
    MSG = 0x01,
    FIN = 0x02,
    ENC = 0x03,
    PING = 0xFF,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum EncryptionKind {
    INIT = 0x00,
    AUTH = 0x01,
}

#[derive(Debug, PartialEq)]
pub enum MessageError {
    TooLong,
    MissingSequence(u8),
    LengthOutOfBounds { min: usize, max: usize, len: usize },
}

pub struct GenericMessage {
    packet_id: u16,
    message_kind: MessageKind,
}

///////////////////////////////////////////////////////////////////////////////
// SYN

// (uint16_t) packet_id
// (uint8_t) message_type [0x00]
// (uint16_t) session_id
// (uint16_t) initial sequence number
// (uint16_t) options
// If OPT_NAME is set:
// (ntstring) session_name
pub struct SynMessage {
    session_id: u16,
    init_seq: u16,
    options: u16,
    session_name: Option<&'static str>,
}

// OPT_NAME - 0x01 [C->S]
// Packet contains an additional field called the session name, which is a free-form field containing user-readable data

// OPT_COMMAND - 0x20 [C->S]
// This is a command session, and will be tunneling command messages

// OPT_ENCRYPTED - 0x40 [C->S and S->C]
// We're negotiating encryption
// crypto_flags are currently undefined, and 0
// The public key x and y values are the BigInteger values converted directly to hex values, then padded on the left with zeroes (if necessary) to make 32 bytes.