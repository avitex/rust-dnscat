mod ip;
pub mod payload;

use std::str::{self, Utf8Error};

use arrayvec::ArrayVec;
use bitflags::bitflags;
use bytes::BufMut;

pub use self::ip::*;

use crate::transport::{Decode, Encode};
use crate::util::parse;

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

impl EncryptionKind {
    pub fn from_u8(kind: u8) -> Option<Self> {
        match kind {
            0x00 => Some(Self::INIT),
            0x01 => Some(Self::AUTH),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MessageError {
    Parse,
    TooLong,
    Utf8(Utf8Error),
    UnknownKind(u8),
    UnknownEncKind(u8),
    MissingSequence(u8),
    LengthOutOfBounds { min: usize, max: usize, len: usize },
}

impl From<Utf8Error> for MessageError {
    fn from(err: Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

impl From<parse::Error<()>> for MessageError {
    fn from(_err: parse::Error<()>) -> Self {
        Self::Parse
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message<'a> {
    Syn(SynMessage<'a>),
    Msg(MsgMessage<'a>),
    Fin(FinMessage<'a>),
    Enc(EncMessage),
    //Ping(PingMessage<'a>),
}

impl<'a> Message<'a> {
    pub fn kind(&self) -> MessageKind {
        match self {
            Self::Syn(_) => MessageKind::SYN,
            Self::Msg(_) => MessageKind::MSG,
            Self::Fin(_) => MessageKind::FIN,
            Self::Enc(_) => MessageKind::ENC,
            // Self::Ping(_) => MessageKind::PING,
        }
    }

    pub fn decode_kind(kind: MessageKind, b: &'a [u8]) -> Result<(&'a [u8], Self), MessageError> {
        match kind {
            MessageKind::SYN => SynMessage::decode(b).map(|(b, m)| (b, Self::Syn(m))),
            MessageKind::MSG => MsgMessage::decode(b).map(|(b, m)| (b, Self::Msg(m))),
            MessageKind::FIN => FinMessage::decode(b).map(|(b, m)| (b, Self::Fin(m))),
            MessageKind::ENC => EncMessage::decode(b).map(|(b, m)| (b, Self::Enc(m))),
            // MessageKind::PING => PingMessage::decode(b).map(|(b, m)| (b, Self::Ping(m))),
            _ => unimplemented!(),
        }
    }
}

impl<'a> Encode for Message<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        match self {
            Self::Syn(m) => m.encode(b),
            Self::Msg(m) => m.encode(b),
            Self::Fin(m) => m.encode(b),
            Self::Enc(m) => m.encode(b),
            // Self::Ping(m) => m.encode(b),
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
        let (b, packet_id) = parse::be_u16(b)?;
        let (b, message_kind) = parse::be_u8(b)?;
        let message_kind = MessageKind::from_u8(message_kind)
            .ok_or_else(|| MessageError::UnknownKind(message_kind))?;
        let (b, message) = Message::decode_kind(message_kind, b)?;
        Ok((b, Self { packet_id, message }))
    }
}

impl<'a> Encode for MessageFrame<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.packet_id);
        b.put_u8(self.message.kind() as u8);
        self.message.encode(b);
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
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, init_seq) = parse::be_u16(b)?;
        let (b, opts_raw) = parse::be_u16(b)?;
        let opts = MessageOption::from_bits_truncate(opts_raw);
        let (b, sess_name) = if opts.contains(MessageOption::NAME) {
            parse::nt_string(b)?
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

///////////////////////////////////////////////////////////////////////////////
// MSG

#[derive(Debug, Clone, PartialEq)]
pub struct MsgMessage<'a> {
    sess_id: u16,
    seq: u16,
    ack: u16,
    data: &'a [u8],
}

impl<'a> Decode<'a> for MsgMessage<'a> {
    type Error = MessageError;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, seq) = parse::be_u16(b)?;
        let (data, ack) = parse::be_u16(b)?;
        Ok((
            &[],
            Self {
                sess_id,
                seq,
                ack,
                data,
            },
        ))
    }
}

impl<'a> Encode for MsgMessage<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.seq);
        b.put_u16(self.ack);
        b.put_slice(self.data);
    }
}

///////////////////////////////////////////////////////////////////////////////
// FIN

#[derive(Debug, Clone, PartialEq)]
pub struct FinMessage<'a> {
    sess_id: u16,
    reason: &'a str,
}

impl<'a> Decode<'a> for FinMessage<'a> {
    type Error = MessageError;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, reason) = parse::nt_string(b)?;
        Ok((b, Self { sess_id, reason }))
    }
}

impl<'a> Encode for FinMessage<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_slice(self.reason.as_bytes());
    }
}

///////////////////////////////////////////////////////////////////////////////
// ENC

#[derive(Debug, Clone, PartialEq)]
pub enum EncMessageBody {
    Init {
        public_key_x: ArrayVec<[u8; 16]>,
        public_key_y: ArrayVec<[u8; 16]>,
    },
    Auth {
        authenticator: ArrayVec<[u8; 16]>,
    },
}

impl EncMessageBody {
    pub fn kind(&self) -> EncryptionKind {
        match self {
            Self::Init { .. } => EncryptionKind::INIT,
            Self::Auth { .. } => EncryptionKind::AUTH,
        }
    }

    pub fn decode_kind<'a>(
        kind: EncryptionKind,
        b: &'a [u8],
    ) -> Result<(&'a [u8], Self), MessageError> {
        match kind {
            EncryptionKind::INIT => {
                let mut public_key_x = ArrayVec::new();
                let mut public_key_y = ArrayVec::new();
                let (b, _) = parse::hex_string_null_padded(b, 32, &mut public_key_x)?;
                let (b, _) = parse::hex_string_null_padded(b, 32, &mut public_key_y)?;
                Ok((
                    b,
                    Self::Init {
                        public_key_x,
                        public_key_y,
                    },
                ))
            }
            EncryptionKind::AUTH => {
                let mut authenticator = ArrayVec::new();
                let (b, _) = parse::hex_string_null_padded(b, 32, &mut authenticator)?;
                Ok((b, Self::Auth { authenticator }))
            }
        }
    }
}

impl<'a> Encode for EncMessageBody {
    fn encode<B: BufMut>(&self, b: &mut B) {
        match self {
            Self::Init {
                public_key_x,
                public_key_y,
            } => {
                b.put_slice(public_key_x);
                b.put_slice(public_key_y);
            }
            Self::Auth { authenticator } => {
                b.put_slice(authenticator);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncMessage {
    sess_id: u16,
    flags: u16,
    body: EncMessageBody,
}

impl<'a> Decode<'a> for EncMessage {
    type Error = MessageError;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, enc_kind) = parse::be_u8(b)?;
        let enc_kind = EncryptionKind::from_u8(enc_kind)
            .ok_or_else(|| MessageError::UnknownEncKind(enc_kind))?;
        let (b, flags) = parse::be_u16(b)?;
        let (b, body) = EncMessageBody::decode_kind(enc_kind, b)?;
        Ok((
            b,
            Self {
                sess_id,
                flags,
                body,
            },
        ))
    }
}

impl Encode for EncMessage {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u8(self.body.kind() as u8);
        b.put_u16(self.flags);
        self.body.encode(b);
    }
}

///////////////////////////////////////////////////////////////////////////////
// PING

#[derive(Debug, Clone, PartialEq)]
pub struct PingMessage<'a> {
    sess_id: u16,
    ping_id: u16,
    data: &'a str,
}

impl<'a> Decode<'a> for PingMessage<'a> {
    type Error = MessageError;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, ping_id) = parse::be_u16(b)?;
        let (b, data) = parse::nt_string(b)?;
        Ok((
            b,
            Self {
                sess_id,
                ping_id,
                data,
            },
        ))
    }
}

impl<'a> Encode for PingMessage<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.ping_id);
        b.put_slice(self.data.as_bytes());
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
