mod hex;
mod ip;
pub mod payload;

use std::str::{self, Utf8Error};

use bitflags::bitflags;
use bytes::BufMut;

pub use self::ip::*;

use crate::transport::{Decode, Encode};
use crate::util::nom;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    SYN = 0x00,
    MSG = 0x01,
    FIN = 0x02,
    ENC = 0x03,
    PING = 0xFF,
}

impl MessageKind {
    pub fn from_u8(kind: u8) -> Option<Self> {
        match kind {
            0x00 => Some(Self::SYN),
            0x01 => Some(Self::MSG),
            0x02 => Some(Self::FIN),
            0x03 => Some(Self::ENC),
            0xFF => Some(Self::PING),
            _ => None,
        }
    }
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
    UnknownKind(u8),
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

#[derive(Debug, Clone, PartialEq)]
pub enum Message<'a> {
    Syn(SynMessage<'a>),
    //Msg(MsgMessage<'a>),
    //Fin(FinMessage<'a>),
    //Enc(EncMessage<'a>),
    //Ping(PingMessage<'a>),
}

impl<'a> Message<'a> {
    pub fn decode_kind(kind: MessageKind, b: &'a [u8]) -> Result<(&'a [u8], Self), MessageError> {
        match kind {
            MessageKind::SYN => SynMessage::decode(b).map(|(b, m)| (b, Self::Syn(m))),
            _ => unimplemented!()
            // MessageKind::MSG => SynMessage::decode(b).map(|(b, m)| (b, Self::Msg(m))),
            // MessageKind::FIN => FinMessage::decode(b).map(|(b, m)| (b, Self::Fin(m))),
            // MessageKind::ENC => EncMessage::decode(b).map(|(b, m)| (b, Self::Enc(m))),
            // MessageKind::PING => PingMessage::decode(b).map(|(b, m)| (b, Self::Ping(m))),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageFrame<'a> {
    pub packet_id: u16,
    pub message: Message<'a>,
}

impl<'a> Decode<'a> for MessageFrame<'a> {
    type Error = MessageError;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, packet_id) = nom::be_u16(b)?;
        let (b, message_kind) = nom::be_u8(b)?;
        let message_kind = MessageKind::from_u8(message_kind)
            .ok_or_else(|| MessageError::UnknownKind(message_kind))?;
        let (b, message) = Message::decode_kind(message_kind, b)?;
        Ok((b, Self { packet_id, message }))
    }
}

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

#[derive(Debug, Clone, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &[u8] = &[];

    #[test]
    #[rustfmt::skip]
    fn test_parse_message_syn() {
        let data = &[
            // Packet ID
            0x00, 0x01,
            // Message kind
            0x00,
            // Session ID
            0x00, 0x01,
            // Init sequence
            0x00, 0x01,
            // Options (has name)
            0x00, 0x01,
            // Session name
            b'h', b'e', b'l', b'l', b'o', 0x00,
        ][..];
        assert_eq!(MessageFrame::decode(data), (Ok((EMPTY, MessageFrame {
            packet_id: 1,
            message: Message::Syn(SynMessage {
                sess_id: 1,
                init_seq: 1,
                opts: MessageOption::NAME,
                sess_name: "hello"
            }),
        }))));
    }
}
