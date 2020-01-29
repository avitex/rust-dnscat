#![warn(missing_docs)]

use std::str::{self, Utf8Error};

use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes};

use crate::encdec::{Decode, Encode};
use crate::util::parse::{self, InvalidHexByte, Needed, NoNullTermError};
use crate::util::{hex, StringBytes};

///////////////////////////////////////////////////////////////////////////////
// Packet

/// Container for all supported packets.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    id: u16,
    body: PacketBody,
}

impl Packet {
    /// Constructs a new packet given a packet ID and body.
    pub fn new<B>(id: u16, body: B) -> Self
    where
        B: Into<PacketBody>,
    {
        Self {
            id,
            body: body.into(),
        }
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
    pub fn body(&self) -> &PacketBody {
        &self.body
    }
}

impl Encode for Packet {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.id);
        b.put_u8(self.body.kind() as u8);
        self.body.encode(b);
    }
}

impl Decode for Packet {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let id = parse::be_u16(b)?;
        let kind = parse::be_u8(b)?;
        let kind = PacketKind::from_u8(kind).ok_or_else(|| PacketDecodeError::UnknownKind(kind))?;
        let body = PacketBody::decode_kind(kind, b)?;
        Ok(Self::new(id, body))
    }
}

/// Enum of all supported packet bodies.
#[derive(Debug, Clone, PartialEq)]
pub enum PacketBody {
    /// `SYN` packet body.
    Syn(SynPacket),
    /// `MSG` packet body.
    Msg(MsgPacket),
    /// `FIN` packet body.
    Fin(FinPacket),
    /// `ENC` packet body.
    Enc(EncPacket),
    /// `PING` packet body.
    Ping(PingPacket),
}

impl PacketBody {
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
    ///
    /// Returns a tuple of the remaining buffer not used and the decoded packet body
    /// on success or a packet decode error on failure.
    pub fn decode_kind(kind: PacketKind, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match kind {
            PacketKind::SYN => SynPacket::decode(b).map(Self::Syn),
            PacketKind::MSG => MsgPacket::decode(b).map(Self::Msg),
            PacketKind::FIN => FinPacket::decode(b).map(Self::Fin),
            PacketKind::ENC => EncPacket::decode(b).map(Self::Enc),
            PacketKind::PING => PingPacket::decode(b).map(Self::Ping),
        }
    }
}

impl Encode for PacketBody {
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

impl From<SynPacket> for PacketBody {
    fn from(body: SynPacket) -> Self {
        PacketBody::Syn(body)
    }
}

impl From<MsgPacket> for PacketBody {
    fn from(body: MsgPacket) -> Self {
        PacketBody::Msg(body)
    }
}

impl From<FinPacket> for PacketBody {
    fn from(body: FinPacket) -> Self {
        PacketBody::Fin(body)
    }
}

impl From<EncPacket> for PacketBody {
    fn from(body: EncPacket) -> Self {
        PacketBody::Enc(body)
    }
}

impl From<PingPacket> for PacketBody {
    fn from(body: PingPacket) -> Self {
        PacketBody::Ping(body)
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
#[derive(Debug, Clone, PartialEq)]
pub enum PacketDecodeError {
    /// No null term error.
    NoNullTerm,
    /// UTF8 decode error.
    Utf8(Utf8Error),
    /// Unknown packet kind.
    UnknownKind(u8),
    /// Unknown encryption packet kind.
    UnknownEncKind(u8),
    /// Incomplete input error.
    Incomplete(usize),
    /// Nibble pair error.
    InvalidHexByte(u8, u8),
}

impl From<NoNullTermError> for PacketDecodeError {
    fn from(_: NoNullTermError) -> Self {
        Self::NoNullTerm
    }
}

impl From<Utf8Error> for PacketDecodeError {
    fn from(err: Utf8Error) -> Self {
        Self::Utf8(err)
    }
}

impl From<InvalidHexByte> for PacketDecodeError {
    fn from(err: InvalidHexByte) -> Self {
        Self::InvalidHexByte(err.0, err.1)
    }
}

impl From<Needed> for PacketDecodeError {
    fn from(needed: Needed) -> Self {
        Self::Incomplete(needed.0)
    }
}

///////////////////////////////////////////////////////////////////////////////
// SYN Packet

/// A `SYN` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct SynPacket {
    sess_id: u16,
    init_seq: u16,
    flags: PacketFlags,
    sess_name: StringBytes,
}

impl SynPacket {
    /// Contructs a new `SYN` packet.
    ///
    /// # Notes
    ///
    /// The `NAME` packet flag is automatically set if `sess_name` is some.
    ///
    /// # Panics
    ///
    /// Panics if session flag or option is set, but has an empty str value.
    pub fn new<S>(sess_id: u16, init_seq: u16, mut flags: PacketFlags, sess_name: Option<S>) -> Self
    where
        S: Into<StringBytes>,
    {
        let sess_name = if let Some(sess_name) = sess_name.map(Into::into) {
            assert!(
                !sess_name.is_empty(),
                "session name is some but has empty value"
            );
            flags.insert(PacketFlags::NAME);
            sess_name
        } else {
            if flags.contains(PacketFlags::NAME) {
                panic!("session name flag is set but has empty value");
            }
            StringBytes::new()
        };
        Self {
            sess_id,
            init_seq,
            flags,
            sess_name,
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
    pub fn session_name(&self) -> Option<&str> {
        if self.has_session_name() {
            Some(self.sess_name.as_ref())
        } else {
            None
        }
    }

    /// Returns `true` if the `NAME` packet flag is set, `false` if not.
    pub fn has_session_name(&self) -> bool {
        self.flags.contains(PacketFlags::NAME)
    }
}

impl Encode for SynPacket {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.init_seq);
        b.put_u16(self.flags.bits());
        if self.has_session_name() {
            b.put_slice(self.sess_name.as_bytes());
            b.put_u8(0);
        }
    }
}

impl Decode for SynPacket {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let sess_id = parse::be_u16(b)?;
        let init_seq = parse::be_u16(b)?;
        let flags_raw = parse::be_u16(b)?;
        let flags = PacketFlags::from_bits_truncate(flags_raw);
        let sess_name = if flags.contains(PacketFlags::NAME) {
            Some(parse::nt_string::<PacketDecodeError>(b)?)
        } else {
            None
        };
        Ok(Self::new(sess_id, init_seq, flags, sess_name))
    }
}

///////////////////////////////////////////////////////////////////////////////
// MSG Packet

/// A `MSG` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct MsgPacket {
    sess_id: u16,
    seq: u16,
    ack: u16,
    data: Bytes,
}

impl MsgPacket {
    /// Constructs a new `MSG` packet.
    pub fn new(sess_id: u16, seq: u16, ack: u16, data: Bytes) -> Self {
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
    pub fn data(&self) -> &Bytes {
        &self.data
    }

    /// Consumes self into the message data.
    pub fn into_data(self) -> Bytes {
        self.data
    }
}

impl Encode for MsgPacket {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.seq);
        b.put_u16(self.ack);
        b.put(self.data.clone());
    }
}

impl Decode for MsgPacket {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let sess_id = parse::be_u16(b)?;
        let seq = parse::be_u16(b)?;
        let ack = parse::be_u16(b)?;
        Ok(Self::new(sess_id, seq, ack, b.to_bytes()))
    }
}

///////////////////////////////////////////////////////////////////////////////
// FIN Packet

/// A `FIN` packet.
#[derive(Debug, Clone, PartialEq)]
pub struct FinPacket {
    sess_id: u16,
    reason: StringBytes,
}

impl FinPacket {
    /// Constructs a new `FIN` packet.
    pub fn new<S>(sess_id: u16, reason: S) -> Self
    where
        S: Into<StringBytes>,
    {
        Self {
            sess_id,
            reason: reason.into(),
        }
    }

    /// Retrives the session ID.
    pub fn session_id(&self) -> u16 {
        self.sess_id
    }

    /// Retrives the reason for disconnect.
    pub fn reason(&self) -> &str {
        self.reason.as_ref()
    }
}

impl Encode for FinPacket {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_slice(self.reason.as_bytes());
        b.put_u8(0);
    }
}

impl Decode for FinPacket {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let sess_id = parse::be_u16(b)?;
        let reason = parse::nt_string::<PacketDecodeError>(b)?;
        Ok(Self::new(sess_id, reason))
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

impl Decode for EncPacket {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let sess_id = parse::be_u16(b)?;
        let enc_kind = parse::be_u8(b)?;
        let enc_kind = EncPacketKind::from_u8(enc_kind)
            .ok_or_else(|| PacketDecodeError::UnknownEncKind(enc_kind))?;
        let cryp_flags = parse::be_u16(b)?;
        let body = EncPacketBody::decode_kind(enc_kind, b)?;
        Ok(Self::new(sess_id, cryp_flags, body))
    }
}

/// Enum of all supported encryption packet bodies.
#[derive(Debug, Clone, PartialEq)]
pub enum EncPacketBody {
    /// `INIT` encyption packet body.
    Init {
        /// `X` component of public key.
        public_key_x: Bytes,
        /// `Y` component of public key.
        public_key_y: Bytes,
    },
    /// `AUTH` encyption packet body.
    Auth {
        /// Authenticator value.
        authenticator: Bytes,
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
    ///
    /// Returns a tuple of the remaining buffer not used and the decoded encryption
    /// packet body on success or a packet decode error on failure.
    pub fn decode_kind(kind: EncPacketKind, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match kind {
            EncPacketKind::INIT => Ok(Self::Init {
                public_key_x: Self::decode_part(b)?,
                public_key_y: Self::decode_part(b)?,
            }),
            EncPacketKind::AUTH => Ok(Self::Auth {
                authenticator: Self::decode_part(b)?,
            }),
        }
    }

    fn decode_part(b: &mut Bytes) -> Result<Bytes, PacketDecodeError> {
        parse::np_hex_string::<PacketDecodeError>(b, 32)
    }

    fn encode_part<B: BufMut>(b: &mut B, part: &[u8]) {
        let mut hex = Vec::with_capacity(32);
        hex::encode_into_buf(&mut hex, part);
        hex.resize_with(32, || 0);
        b.put(hex.as_ref())
    }
}

impl Encode for EncPacketBody {
    fn encode<B: BufMut>(&self, b: &mut B) {
        match self {
            Self::Init {
                ref public_key_x,
                ref public_key_y,
            } => {
                Self::encode_part(b, &public_key_x[..]);
                Self::encode_part(b, &public_key_y[..]);
            }
            Self::Auth { ref authenticator } => {
                Self::encode_part(b, &authenticator[..]);
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
pub struct PingPacket {
    sess_id: u16,
    ping_id: u16,
    data: StringBytes,
}

impl PingPacket {
    /// Constructs a new `PING` packet.
    pub fn new<S>(sess_id: u16, ping_id: u16, data: S) -> Self
    where
        S: Into<StringBytes>,
    {
        Self {
            sess_id,
            ping_id,
            data: data.into(),
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
    pub fn data(&self) -> &str {
        self.data.as_ref()
    }
}

impl Encode for PingPacket {
    fn encode<B: BufMut>(&self, b: &mut B) {
        b.put_u16(self.sess_id);
        b.put_u16(self.ping_id);
        b.put_slice(self.data.as_bytes());
        b.put_u8(0);
    }
}

impl Decode for PingPacket {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let sess_id = parse::be_u16(b)?;
        let ping_id = parse::be_u16(b)?;
        let data = parse::nt_string::<PacketDecodeError>(b)?;
        Ok(Self::new(sess_id, ping_id, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_pkt_encdec_works(packet_in: &'static [u8], valid: Packet) {
        let mut bytes = Bytes::from_static(packet_in);
        let decoded = match Packet::decode(&mut bytes) {
            Ok(decoded) if bytes.len() == 0 => decoded,
            Ok(_) => panic!("bytes remaining after decode: {:?}", bytes),
            Err(err) => panic!("error decoding packet: {:?}", err),
        };
        let mut packet_out = Vec::new();
        assert_eq!(valid, decoded, "valid = decoded");
        valid.encode(&mut packet_out);
        assert_eq!(
            packet_in,
            &packet_out[..],
            "packet = encoded (len {} vs {} )",
            packet_in.len(),
            packet_out.len()
        )
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
                    sess_name: "hello".into(),
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
                    data: Bytes::from_static(b"hello"),
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
                    reason: "dragons".into(),
                }),
            },
        );
    }

    #[test]
    #[rustfmt::skip]
    fn test_parse_pkt_enc_init() {
        fn truncate_arr(mut arr: Bytes, new_len: usize) -> Bytes {
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
                        public_key_x: truncate_arr(Bytes::from(&[3u8; 16][..]), 15),
                        public_key_y: truncate_arr(Bytes::from(&[4u8; 16][..]), 16),
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
                        authenticator: Bytes::from(&[3u8; 16][..]),
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
                    data: "dragons".into(),
                }),
            },
        );
    }
}
