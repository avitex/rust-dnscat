#![warn(missing_docs)]

use std::str::{self, Utf8Error};

use arrayvec::ArrayVec;
use bitflags::bitflags;
use bytes::BufMut;

use crate::transport::{Decode, Encode};
use crate::util::{hex, parse};

///////////////////////////////////////////////////////////////////////////////
// Packet

/// Container for all supported packets.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet<'a> {
    id: u16,
    body: PacketBody<'a>,
}

impl<'a> Packet<'a> {
    /// Constructs a new packet given a packet ID and body.
    pub fn new(id: u16, body: PacketBody<'a>) -> Self {
        Self { id, body }
    }

    /// Retrives the packet ID.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Retrives the packet kind.
    pub fn kind(&self) -> PacketKind {
        self.body.kind()
    }

    /// Retrives a reference to the packet body.
    pub fn body(&self) -> &PacketBody<'a> {
        &self.body
    }
}

impl<'a> Encode for Packet<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.id);
        b.put_u8(self.body.kind() as u8);
        self.body.encode(b);
    }
}

impl<'a> Decode<'a> for Packet<'a> {
    type Error = PacketDecodeError<'a>;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, id) = parse::be_u16(b)?;
        let (b, kind) = parse::be_u8(b)?;
        let kind = PacketKind::from_u8(kind).ok_or_else(|| PacketDecodeError::UnknownKind(kind))?;
        let (b, body) = PacketBody::decode_kind(kind, b)?;
        Ok((b, Self::new(id, body)))
    }
}

/// Enum of all supported packet bodies.
#[derive(Debug, Clone, PartialEq)]
pub enum PacketBody<'a> {
    /// `SYN` packet body.
    Syn(SynPacket<'a>),
     /// `MSG` packet body.
    Msg(MsgPacket<'a>),
     /// `FIN` packet body.
    Fin(FinPacket<'a>),
     /// `ENC` packet body.
    Enc(EncPacket),
     /// `PING` packet body.
    Ping(PingPacket<'a>),
}

impl<'a> PacketBody<'a> {
    /// Retrives the packet kind.
    pub fn kind(&self) -> PacketKind {
        match self {
            Self::Syn(_) => PacketKind::SYN,
            Self::Msg(_) => PacketKind::MSG,
            Self::Fin(_) => PacketKind::FIN,
            Self::Enc(_) => PacketKind::ENC,
            Self::Ping(_) => PacketKind::PING,
        }
    }

    /// Decodes a packet body given the packet kind.
    pub fn decode_kind(kind: PacketKind, b: &'a [u8]) -> Result<(&'a [u8], Self), PacketDecodeError> {
        match kind {
            PacketKind::SYN => SynPacket::decode(b).map(|(b, m)| (b, Self::Syn(m))),
            PacketKind::MSG => MsgPacket::decode(b).map(|(b, m)| (b, Self::Msg(m))),
            PacketKind::FIN => FinPacket::decode(b).map(|(b, m)| (b, Self::Fin(m))),
            PacketKind::ENC => EncPacket::decode(b).map(|(b, m)| (b, Self::Enc(m))),
            PacketKind::PING => PingPacket::decode(b).map(|(b, m)| (b, Self::Ping(m))),
        }
    }
}

impl<'a> Encode for PacketBody<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        match self {
            Self::Syn(m) => m.encode(b),
            Self::Msg(m) => m.encode(b),
            Self::Fin(m) => m.encode(b),
            Self::Enc(m) => m.encode(b),
            Self::Ping(m) => m.encode(b),
        }
    }
}

/// Enum of all supported packet kinds.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum PacketKind {
    /// `SYN` packet kind.
    SYN = 0x00,
    /// `MSG` packet kind.
    MSG = 0x01,
    /// `FIN` packet kind.
    FIN = 0x02,
    /// `ENC` packet kind.
    ENC = 0x03,
    /// `PING` packet king.
    PING = 0xFF,
}

impl PacketKind {
    /// Converts a packet kind value to a supported variant.
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

///////////////////////////////////////////////////////////////////////////////
// Packet Flags

bitflags! {
    /// Packet flags / options.
    pub struct PacketFlags: u16 {
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
// Packet Error

/// Enum of all possible errors when decoding packets.
#[derive(Debug, PartialEq)]
pub enum PacketDecodeError<'a> {
    /// Internal parse error with input that failed, and the error kind.
    Parse(&'a [u8], parse::ErrorKind),
    /// UTF8 decode error.
    Utf8(Utf8Error),
    /// Unknown packet kind.
    UnknownKind(u8),
    /// Unknown encryption packet kind.
    UnknownEncKind(u8),
    /// Incomplete input error.
    Incomplete(parse::Needed),
}

impl<'a> From<Utf8Error> for PacketDecodeError<'a> {
    fn from(err: Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

impl<'a> From<parse::Error<(&'a [u8], parse::ErrorKind)>> for PacketDecodeError<'a> {
    fn from(err: parse::Error<(&'a [u8], parse::ErrorKind)>) -> Self {
        match err {
            parse::Error::Error((i, kind)) => Self::Parse(i, kind),
            parse::Error::Failure((i, kind)) => Self::Parse(i, kind),
            parse::Error::Incomplete(needed) => Self::Incomplete(needed),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// SYN Packet

/// A `SYN` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct SynPacket<'a> {
    sess_id: u16,
    init_seq: u16,
    flags: PacketFlags,
    sess_name: &'a str,
}

impl<'a> SynPacket<'a> {
    /// Contructs a new `SYN` packet.
    ///
    /// # Notes
    ///
    /// The `NAME` packet flag is automatically set if `sess_name` is some.
    ///
    /// # Panics
    ///
    /// Panics if session flag or option is set, but has an empty str value.
    pub fn new(
        sess_id: u16,
        init_seq: u16,
        mut flags: PacketFlags,
        sess_name: Option<&'a str>,
    ) -> Self {
        if let Some(sess_name) = sess_name {
            assert!(
                !sess_name.is_empty(),
                "session name is some but has empty value"
            );
            flags.insert(PacketFlags::NAME);
        } else if flags.contains(PacketFlags::NAME) {
            panic!("session name flag is set but has empty value");
        };
        Self {
            sess_id,
            init_seq,
            flags,
            sess_name: sess_name.unwrap_or(""),
        }
    }

    /// Retrives the session ID.
    pub fn session_id(&self) -> u16 {
        self.sess_id
    }

    /// Retrives the initial sequence.
    pub fn initial_sequence(&self) -> u16 {
        self.init_seq
    }

    /// Retrives the packet flags.
    pub fn flags(&self) -> PacketFlags {
        self.flags
    }

    /// Retrives the session name.
    pub fn session_name(&self) -> Option<&'a str> {
        if self.has_session_name() {
            Some(self.sess_name)
        } else {
            None
        }
    }

    /// Returns `true` if the `NAME` packet flag is set, `false` if not.
    pub fn has_session_name(&self) -> bool {
        self.flags.contains(PacketFlags::NAME)
    }
}

impl<'a> Encode for SynPacket<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.init_seq);
        b.put_u16(self.flags.bits());
        if self.has_session_name() {
            let sess_name_bytes = self.sess_name.as_bytes();
            b.put_slice(sess_name_bytes);
            b.put_u8(0);
        }
    }
}

impl<'a> Decode<'a> for SynPacket<'a> {
    type Error = PacketDecodeError<'a>;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, init_seq) = parse::be_u16(b)?;
        let (b, flags_raw) = parse::be_u16(b)?;
        let flags = PacketFlags::from_bits_truncate(flags_raw);
        let (b, sess_name) = if flags.contains(PacketFlags::NAME) {
            let (b, sess_name) = parse::nt_string(b)?;
            (b, Some(sess_name))
        } else {
            (b, None)
        };
        Ok((b, Self::new(sess_id, init_seq, flags, sess_name)))
    }
}

///////////////////////////////////////////////////////////////////////////////
// MSG Packet

/// A `MSG` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct MsgPacket<'a> {
    sess_id: u16,
    seq: u16,
    ack: u16,
    data: &'a [u8],
}

impl<'a> MsgPacket<'a> {
    /// Constructs a new `MSG` packet.
    pub fn new(sess_id: u16, seq: u16, ack: u16, data: &'a [u8]) -> Self {
        Self {
            sess_id,
            seq,
            ack,
            data,
        }
    }

    /// Retrieves the session ID.
    pub fn session_id(&self) -> u16 {
        self.sess_id
    }

    /// Retrieves the seq number.
    pub fn seq(&self) -> u16 {
        self.seq
    }

    /// Retrieves the ack number.
    pub fn ack(&self) -> u16 {
        self.ack
    }

    /// Retrieves the message data.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}

impl<'a> Encode for MsgPacket<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.seq);
        b.put_u16(self.ack);
        b.put_slice(self.data);
    }
}

impl<'a> Decode<'a> for MsgPacket<'a> {
    type Error = PacketDecodeError<'a>;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, seq) = parse::be_u16(b)?;
        let (data, ack) = parse::be_u16(b)?;
        Ok((&[], Self::new(sess_id, seq, ack, data)))
    }
}

///////////////////////////////////////////////////////////////////////////////
// FIN Packet

/// A `FIN` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct FinPacket<'a> {
    sess_id: u16,
    reason: &'a str,
}

impl<'a> FinPacket<'a> {
    /// Constructs a new `FIN` packet.
    pub fn new(sess_id: u16, reason: &'a str) -> Self {
        Self { sess_id, reason }
    }

    /// Retrives the session ID.
    pub fn session_id(&self) -> u16 {
        self.sess_id
    }

    /// Retrives the reason for disconnect.
    pub fn reason(&self) -> &'a str {
        self.reason
    }
}

impl<'a> Encode for FinPacket<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_slice(self.reason.as_bytes());
        b.put_u8(0);
    }
}

impl<'a> Decode<'a> for FinPacket<'a> {
    type Error = PacketDecodeError<'a>;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, reason) = parse::nt_string(b)?;
        Ok((b, Self::new(sess_id, reason)))
    }
}

///////////////////////////////////////////////////////////////////////////////
// ENC Packet

/// A `ENC` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct EncPacket {
    sess_id: u16,
    cryp_flags: u16,
    body: EncPacketBody,
}

impl EncPacket {
    /// Constructs a new `ENC` packet.
    pub fn new(sess_id: u16, cryp_flags: u16, body: EncPacketBody) -> Self {
        Self {
            sess_id,
            cryp_flags,
            body,
        }
    }

    /// Retrieves the session ID.
    pub fn session_id(&self) -> u16 {
        self.sess_id
    }

    /// Retrives the crypto flags.
    /// 
    /// # Notes
    /// 
    /// This field is currently not used in the original specification.
    pub fn crypto_flags(&self) -> u16 {
        self.cryp_flags
    }

    /// Retrives the encryption packet kind.
    pub fn kind(&self) -> EncPacketKind {
        self.body.kind()
    }

    /// Retrives a reference to the encryption packet body.
    pub fn body(&self) -> &EncPacketBody {
        &self.body
    }
}

impl Encode for EncPacket {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u8(self.body.kind() as u8);
        b.put_u16(self.cryp_flags);
        self.body.encode(b);
    }
}

impl<'a> Decode<'a> for EncPacket {
    type Error = PacketDecodeError<'a>;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, enc_kind) = parse::be_u8(b)?;
        let enc_kind = EncPacketKind::from_u8(enc_kind)
            .ok_or_else(|| PacketDecodeError::UnknownEncKind(enc_kind))?;
        let (b, cryp_flags) = parse::be_u16(b)?;
        let (b, body) = EncPacketBody::decode_kind(enc_kind, b)?;
        Ok((b, Self::new(sess_id, cryp_flags, body)))
    }
}

/// Enum of all supported encryption packet bodies.
#[derive(Debug, Clone, PartialEq)]
pub enum EncPacketBody {
    /// `INIT` encyption packet body.
    Init {
        /// `X` component of public key. 
        public_key_x: ArrayVec<[u8; 16]>,
        /// `Y` component of public key.
        public_key_y: ArrayVec<[u8; 16]>,
    },
    /// `AUTH` encyption packet body.
    Auth {
        /// Authenticator value.
        authenticator: ArrayVec<[u8; 16]>,
    },
}

impl EncPacketBody {
    /// Retrives the encryption packet kind.
    pub fn kind(&self) -> EncPacketKind {
        match self {
            Self::Init { .. } => EncPacketKind::INIT,
            Self::Auth { .. } => EncPacketKind::AUTH,
        }
    }

    /// Decodes a encryption packet body given the encryption packet kind.
    pub fn decode_kind(kind: EncPacketKind, b: &[u8]) -> Result<(&[u8], Self), PacketDecodeError> {
        match kind {
            EncPacketKind::INIT => {
                let (b, public_key_x) = Self::decode_hex_part(b)?;
                let (b, public_key_y) = Self::decode_hex_part(b)?;
                Ok((
                    b,
                    Self::Init {
                        public_key_x,
                        public_key_y,
                    },
                ))
            }
            EncPacketKind::AUTH => {
                let (b, authenticator) = Self::decode_hex_part(b)?;
                Ok((b, Self::Auth { authenticator }))
            }
        }
    }

    fn encode_hex_part<B: BufMut>(b: &mut B, raw: &[u8]) {
        let mut part = ArrayVec::from([0u8; 32]);
        let part_len = raw.len() * 2;
        hex::encode_to_slice(&raw[..], &mut part[..part_len]);
        b.put_slice(&part[..]);
    }

    fn decode_hex_part(hex: &[u8]) -> Result<(&[u8], ArrayVec<[u8; 16]>), PacketDecodeError> {
        let mut part = ArrayVec::from([0u8; 16]);
        let (b, part_len) = parse::np_hex_string(hex, 32, &mut part[..])?;
        part.truncate(part_len);
        Ok((b, part))
    }
}

impl Encode for EncPacketBody {
    fn encode<B: BufMut>(&self, b: &mut B) {
        match self {
            Self::Init {
                ref public_key_x,
                ref public_key_y,
            } => {
                Self::encode_hex_part(b, &public_key_x[..]);
                Self::encode_hex_part(b, &public_key_y[..]);
            }
            Self::Auth { ref authenticator } => {
                Self::encode_hex_part(b, &authenticator[..]);
            }
        }
    }
}

/// Enum of all supported encryption packet kinds.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum EncPacketKind {
    /// `INIT` encryption packet kind.
    INIT = 0x00,
    /// `AUTH` encryption packet kind.
    AUTH = 0x01,
}

impl EncPacketKind {
    /// Converts a encryption packet kind value to a supported variant.
    pub fn from_u8(kind: u8) -> Option<Self> {
        match kind {
            0x00 => Some(Self::INIT),
            0x01 => Some(Self::AUTH),
            _ => None,
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// PING Packet

/// A `PING` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct PingPacket<'a> {
    sess_id: u16,
    ping_id: u16,
    data: &'a str,
}

impl<'a> PingPacket<'a> {
    /// Constructs a new `PING` packet.
    pub fn new(sess_id: u16, ping_id: u16, data: &'a str) -> Self {
        Self {
            sess_id,
            ping_id,
            data,
        }
    }

    /// Retrives the session ID.
    pub fn session_id(&self) -> u16 {
        self.sess_id
    }

    /// Retrives the ping ID.
    pub fn ping_id(&self) -> u16 {
        self.ping_id
    }

    /// Retrives the ping data.
    pub fn data(&self) -> &'a str {
        self.data
    }
}

impl<'a> Encode for PingPacket<'a> {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.ping_id);
        b.put_slice(self.data.as_bytes());
        b.put_u8(0);
    }
}

impl<'a> Decode<'a> for PingPacket<'a> {
    type Error = PacketDecodeError<'a>;

    fn decode(b: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        let (b, sess_id) = parse::be_u16(b)?;
        let (b, ping_id) = parse::be_u16(b)?;
        let (b, data) = parse::nt_string(b)?;
        Ok((b, Self::new(sess_id, ping_id, data)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_pkt_encdec_works(packet_in: &[u8], valid: Packet<'static>) {
        let decoded = match Packet::decode(packet_in) {
            Ok((&[], decoded)) => decoded,
            Ok((bytes, _)) => panic!("packet was not fully consumed (remaining: {:?})", bytes),
            Err(err) => panic!("error decoding packet: {:?}", err),
        };
        let mut packet_out = Vec::new();
        assert_eq!(valid, decoded, "valid = decoded");
        valid.encode(&mut packet_out);
        assert_eq!(packet_in, &packet_out[..], "packet = encoded")
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_syn() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                PacketKind::SYN as u8, // Packet kind
                0x00, 0x01, // Session ID
                0x00, 0x01, // Init sequence
                0x00, 0x01, // Flags (has name)
                b'h', b'e', b'l', b'l', b'o', 0x00, // Session name
            ],
            Packet {
                id: 1,
                body: PacketBody::Syn(SynPacket {
                    sess_id: 1,
                    init_seq: 1,
                    flags: PacketFlags::NAME,
                    sess_name: "hello",
                }),
            },
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_msg() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                PacketKind::MSG as u8, // Packet kind
                0x00, 0x01, // Session ID
                0x00, 0x02, // SEQ
                0x00, 0x03, // ACK
                b'h', b'e', b'l', b'l', b'o', // Data
            ],
            Packet {
                id: 1,
                body: PacketBody::Msg(MsgPacket {
                    sess_id: 1,
                    seq: 2,
                    ack: 3,
                    data: b"hello",
                }),
            },
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_fin() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                PacketKind::FIN as u8, // Packet kind
                0x00, 0x01, // Session ID
                b'd', b'r', b'a', b'g', b'o', b'n', b's', 0x00, // Reason
            ],
            Packet {
                id: 1,
                body: PacketBody::Fin(FinPacket {
                    sess_id: 1,
                    reason: "dragons",
                }),
            },
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_enc_init() {
        fn truncate_arr(mut arr: ArrayVec<[u8; 16]>, new_len: usize) -> ArrayVec<[u8; 16]> {
            arr.truncate(new_len);
            arr
        }
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                PacketKind::ENC as u8, // Packet kind
                0x00, 0x01, // Session ID
                EncPacketKind::INIT as u8, // Encryption kind
                0x00, 0x02, // Crypto flags
                0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, // Pubkey X (1)
                0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x00, 0x00, // Pubkey X (2)
                0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, // Pubkey Y (1)
                0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, 0x30, 0x34, // Pubkey Y (2)
            ],
            Packet {
                id: 1,
                body: PacketBody::Enc(EncPacket {
                    sess_id: 1,
                    cryp_flags: 2,
                    body: EncPacketBody::Init {
                        public_key_x: truncate_arr(ArrayVec::from([3u8; 16]), 15),
                        public_key_y: truncate_arr(ArrayVec::from([4u8; 16]), 16),
                    },
                }),
            },
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_enc_auth() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                PacketKind::ENC as u8, // Packet kind
                0x00, 0x01, // Session ID
                EncPacketKind::AUTH as u8, // Encryption kind
                0x00, 0x02, // Crypto flags
                0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, // Auth (1)
                0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, 0x30, 0x33, // Auth (2)
            ],
            Packet {
                id: 1,
                body: PacketBody::Enc(EncPacket {
                    sess_id: 1,
                    cryp_flags: 2,
                    body: EncPacketBody::Auth {
                        authenticator: ArrayVec::from([3u8; 16]),
                    },
                }),
            },
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_ping() {
        assert_pkt_encdec_works(
            &[
                0x00, 0x01, // Packet ID
                PacketKind::PING as u8, // Packet kind
                0x00, 0x01, // Session ID
                0x00, 0x02, // Ping ID
                b'd', b'r', b'a', b'g', b'o', b'n', b's', 0x00, // Data
            ],
            Packet {
                id: 1,
                body: PacketBody::Ping(PingPacket {
                    sess_id: 1,
                    ping_id: 2,
                    data: "dragons",
                }),
            },
        );
    }
}
