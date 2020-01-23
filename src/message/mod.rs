mod hex;
mod ip;
pub mod payload;

use std::str::{self, Utf8Error};

use bitflags::bitflags;
use bytes::BufMut;

pub use self::ip::*;

use crate::transport::{Decode, Encode};
use crate::util::nom;

pub trait Message<'a>: Encode + Decode<'a> {
    fn kind() -> MessageKind;
}

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
    Parse,
    TooLong,
    Utf8(Utf8Error),
    MissingSequence(u8),
    LengthOutOfBounds { min: usize, max: usize, len: usize },
}

impl From<Utf8Error> for MessageError {
    fn from(err: Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

impl From<nom::Error<()>> for MessageError {
    fn from(_err: nom::Error<()>) -> Self {
        Self::Parse
    }
}

// pub struct MessageFrame<M: Message> {
//     packet_id: u16,
//     message: M,
// }

bitflags! {
    pub struct MessageOption: u16 {
        /// `OPT_NAME`
        ///
        /// Packet contains an additional field called the session name,
        /// which is a free-form field containing user-readable data
        const NAME = 0b0000_0001;
        /// `OPT_TUNNEL`
        #[deprecated]
        const TUNNEL = 0b0000_0010;
        /// `OPT_DATAGRAM`
        #[deprecated]
        const DATAGRAM = 0b0000_0100;
        /// `OPT_DOWNLOAD`
        #[deprecated]
        const DOWNLOAD = 0b0000_1000;
        /// `OPT_CHUNKED_DOWNLOAD`
        #[deprecated]
        const CHUCKED_DOWNLOAD = 0b0001_0000;
        /// `OPT_COMMAND`
        ///
        /// This is a command session, and will be tunneling command messages.
        const COMMAND = 0b0010_0000;
    }
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
pub struct SynMessage<'a> {
    sess_id: u16,
    init_seq: u16,
    opts: MessageOption,
    sess_name: &'a str,
}

impl<'a> SynMessage<'a> {
    pub fn has_session_name(&self) -> bool {
        self.opts.contains(MessageOption::NAME)
    }
}

impl<'a> Decode<'a> for SynMessage<'a> {
    type Error = MessageError;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = nom::be_u16(b)?;
        let (b, init_seq) = nom::be_u16(b)?;
        let (b, opts_raw) = nom::be_u16(b)?;
        let opts = MessageOption::from_bits_truncate(opts_raw);
        let (b, sess_name) = if opts.contains(MessageOption::NAME) {
            nom::nt_string(b)?
        } else {
            (b, "")
        };
        Ok((
            b,
            Self {
                sess_id,
                init_seq,
                opts,
                sess_name,
            },
        ))
    }
}

impl<'a> Encode for SynMessage<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.init_seq);
        b.put_u16(self.opts.bits());
        if self.has_session_name() {
            let sess_name_bytes = self.sess_name.as_bytes();
            b.put_slice(sess_name_bytes);
            b.put_u8(0);
        }
    }
}
