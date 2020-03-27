mod ping;
mod session;

use std::str::{self, Utf8Error};

use bitflags::bitflags;
use bytes::{BufMut, Bytes};
use failure::Fail;

use crate::util::parse::{self, Needed, NoNullTermError};
use crate::util::{hex, Decode, Encode};

/// A standard supported packet with an undecoded session body.
pub type LazyPacket = Packet<SupportedBody<SessionBodyBytes>>;

pub use self::ping::*;
pub use self::session::*;

/// Used to validate any part of a packet is always less than the max
/// size. We care that the length fits within a `u8` safetly.
fn as_valid_len(len: usize) -> u8 {
    assert!((len <= u8::max_value() as usize));
    len as u8
}

/// Packet ID (`u16`).
pub type PacketId = u16;

#[derive(Debug, Clone, PartialEq)]
pub struct Packet<T>
where
    T: PacketBody,
{
    pub head: T::Head,
    pub body: T,
}

impl<T> Packet<T>
where
    T: PacketBody,
{
    pub fn new(head: T::Head, body: T) -> Self {
        Self { head, body }
    }

    /// Retrives the packet ID.
    pub fn id(&self) -> PacketId {
        self.head.as_ref().id
    }

    /// Retrives the packet kind.
    pub fn kind(&self) -> PacketKind {
        self.head.as_ref().kind
    }

    /// Retrives a reference to the packet body.
    pub fn body(&self) -> &T {
        &self.body
    }

    /// Returns a mut reference to the packet body.
    pub fn body_mut(&mut self) -> &mut T {
        &mut self.body
    }

    /// Consumes self into the packet body.
    pub fn into_body(self) -> T {
        self.body
    }

    /// Consumes self into the packet head and body.
    pub fn split(self) -> (T::Head, T) {
        (self.head, self.body)
    }

    pub fn translate<U>(self) -> Packet<U>
    where
        U: PacketBody + From<T>,
        U::Head: From<T::Head>,
    {
        let (head, body) = self.split();
        Packet::new(head.into(), body.into())
    }

    pub fn max_size() -> u8 {
        u8::max_value()
    }
}

impl<T> Packet<SupportedBody<T>>
where
    T: PacketBody<Head = SessionHeader>,
{
    pub fn split_session(self) -> Option<(SessionHeader, T)> {
        match self.split() {
            (SupportedHeader::Session(h), SupportedBody::Session(b)) => Some((h, b)),
            _ => None,
        }
    }

    pub fn into_session(self) -> Option<Packet<T>> {
        self.split_session()
            .map(|(head, body)| Packet::new(head, body))
    }
}

impl<T> Encode for Packet<T>
where
    T: PacketBody,
{
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        self.head.encode(b);
        self.body.encode(b);
    }
}

impl<T> Decode for Packet<T>
where
    T: PacketBody,
{
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        let head = PacketHeader::decode(b)?;
        let head = <T as PacketBody>::Head::decode_head(head, b)?;
        let body = T::decode_body(&head, b)?;
        Ok(Self { head, body })
    }
}

///////////////////////////////////////////////////////////////////////////////
// Packet Head

pub trait PacketHead: Sized + Encode + AsRef<PacketHeader> {
    fn decode_head(head: PacketHeader, b: &mut Bytes) -> Result<Self, PacketDecodeError>;
}

///////////////////////////////////////////////////////////////////////////////
// Packet Body

pub trait PacketBody: Sized + Encode {
    type Head: PacketHead;

    /// Decode a packet kind.
    fn decode_body(head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError>;
}

///////////////////////////////////////////////////////////////////////////////
// Packet Header

#[derive(Debug, Clone, PartialEq)]
pub struct PacketHeader {
    pub id: PacketId,
    pub kind: PacketKind,
}

impl Encode for PacketHeader {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_u16(self.id);
        b.put_u8(self.kind.into());
    }
}

impl Decode for PacketHeader {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse::be_u16(b)?,
            kind: PacketKind::decode(b)?,
        })
    }
}

///////////////////////////////////////////////////////////////////////////////
// Packet Kind

/// Enum of all possible packet kinds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketKind {
    /// `SYN` packet kind.
    SYN,
    /// `MSG` packet kind.
    MSG,
    /// `FIN` packet kind.
    FIN,
    /// `ENC` packet kind.
    ENC,
    /// `PING` packet kind.
    PING,
    /// Unsupported packet kind.
    Other(u8),
}

impl PacketKind {
    pub fn can_encrypt(self) -> bool {
        match self {
            // TODO: Other is true to break things intentionally.
            Self::SYN | Self::MSG | Self::FIN | Self::Other(_) => true,
            Self::PING | Self::ENC => false,
        }
    }

    pub fn is_session(self) -> bool {
        match self {
            Self::SYN | Self::MSG | Self::FIN | Self::ENC => true,
            Self::PING | Self::Other(_) => false,
        }
    }
}

impl From<PacketKind> for u8 {
    fn from(kind: PacketKind) -> u8 {
        match kind {
            PacketKind::SYN => 0x00,
            PacketKind::MSG => 0x01,
            PacketKind::FIN => 0x02,
            PacketKind::ENC => 0x03,
            PacketKind::PING => 0xFF,
            PacketKind::Other(v) => v,
        }
    }
}

impl From<u8> for PacketKind {
    fn from(kind: u8) -> Self {
        match kind {
            0x00 => Self::SYN,
            0x01 => Self::MSG,
            0x02 => Self::FIN,
            0x03 => Self::ENC,
            0xFF => Self::PING,
            v => Self::Other(v),
        }
    }
}

impl Encode for PacketKind {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        b.put_u8((*self).into())
    }
}

impl Decode for PacketKind {
    type Error = PacketDecodeError;

    fn decode(b: &mut Bytes) -> Result<Self, Self::Error> {
        Ok(parse::be_u8(b)?.into())
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
        const CHUNKED_DOWNLOAD = 0b0001_0000;
        /// `OPT_COMMAND`
        ///
        /// This is a command session, and will be tunneling command messages.
        const COMMAND = 0b0010_0000;
        /// `OPT_ENCRYPTED`
        ///
        /// We're negotiating encryption.
        const ENCRYPTED = 0b0100_0000;
    }
}

impl Default for PacketFlags {
    fn default() -> Self {
        PacketFlags::empty()
    }
}

///////////////////////////////////////////////////////////////////////////////
// Packet Error

/// Enum of all possible errors when decoding packets.
#[derive(Debug, Clone, PartialEq, Fail)]
pub enum PacketDecodeError {
    /// No null term error.
    #[fail(display = "Expected a null terminator")]
    NoNullTerm,
    /// Hex decode error.
    #[fail(display = "Hex decode error: {}", _0)]
    Hex(hex::DecodeError),
    /// UTF8 decode error.
    #[fail(display = "UTF-8 decode error: {}", _0)]
    Utf8(Utf8Error),
    /// Unexpected packet kind.
    #[fail(display = "Unexpected packet kind: {:?}", _0)]
    UnexpectedKind(PacketKind),
    /// Unknown encryption packet kind.
    #[fail(display = "Unknown encryption subtype: {}", _0)]
    UnknownEncKind(u16),
    /// Incomplete input error.
    #[fail(display = "Incomplete ({})", _0)]
    Incomplete(Needed),
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

impl From<hex::DecodeError> for PacketDecodeError {
    fn from(err: hex::DecodeError) -> Self {
        Self::Hex(err)
    }
}

impl From<Needed> for PacketDecodeError {
    fn from(needed: Needed) -> Self {
        Self::Incomplete(needed)
    }
}

///////////////////////////////////////////////////////////////////////////////
// Supported

#[derive(Debug, Clone, PartialEq)]
pub enum SupportedHeader {
    Session(SessionHeader),
    Ping(PingHeader),
}

impl From<SessionHeader> for SupportedHeader {
    fn from(header: SessionHeader) -> Self {
        Self::Session(header)
    }
}

impl From<PingHeader> for SupportedHeader {
    fn from(header: PingHeader) -> Self {
        Self::Ping(header)
    }
}

impl Encode for SupportedHeader {
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        match self {
            Self::Session(h) => h.encode(b),
            Self::Ping(h) => h.encode(b),
        }
    }
}

impl AsRef<PacketHeader> for SupportedHeader {
    fn as_ref(&self) -> &PacketHeader {
        match self {
            Self::Session(h) => h.as_ref(),
            Self::Ping(h) => h.as_ref(),
        }
    }
}

impl PacketHead for SupportedHeader {
    fn decode_head(head: PacketHeader, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match head.kind {
            kind if kind.is_session() => SessionHeader::decode_head(head, b).map(Self::Session),
            PacketKind::PING => PingHeader::decode_head(head, b).map(Self::Ping),
            kind => Err(PacketDecodeError::UnexpectedKind(kind)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SupportedBody<T>
where
    T: PacketBody<Head = SessionHeader>,
{
    Session(T),
    Ping(PingBody),
}

impl From<SessionBodyBytes> for SupportedBody<SessionBodyBytes> {
    fn from(body: SessionBodyBytes) -> Self {
        Self::Session(body)
    }
}

impl From<SupportedSessionBody> for SupportedBody<SupportedSessionBody> {
    fn from(body: SupportedSessionBody) -> Self {
        Self::Session(body)
    }
}

impl<T> From<PingBody> for SupportedBody<T>
where
    T: PacketBody<Head = SessionHeader>,
{
    fn from(body: PingBody) -> Self {
        Self::Ping(body)
    }
}

impl<T> SupportedBody<T>
where
    T: PacketBody<Head = SessionHeader>,
{
    /// Returns a reference to the session body.
    ///
    /// Returns `None` if the body is not session framed.
    pub fn session_body(&self) -> Option<&T> {
        match self {
            Self::Session(ref body) => Some(body),
            _ => None,
        }
    }

    /// Returns a mut reference to the session body.
    ///
    /// Returns `None` if the body is not session framed.
    pub fn session_body_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Session(ref mut body) => Some(body),
            _ => None,
        }
    }
}

impl<T> Encode for SupportedBody<T>
where
    T: PacketBody<Head = SessionHeader>,
{
    fn encode<B: BufMut + ?Sized>(&self, b: &mut B) {
        match self {
            Self::Session(h) => h.encode(b),
            Self::Ping(h) => h.encode(b),
        }
    }
}

impl<T> PacketBody for SupportedBody<T>
where
    T: PacketBody<Head = SessionHeader>,
{
    type Head = SupportedHeader;

    fn decode_body(head: &Self::Head, b: &mut Bytes) -> Result<Self, PacketDecodeError> {
        match head {
            SupportedHeader::Session(h) => T::decode_body(h, b).map(Self::Session),
            SupportedHeader::Ping(h) => PingBody::decode_body(h, b).map(Self::Ping),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_diff() {
        let prev = Sequence(u16::max_value());
        let next = Sequence(50);
        assert_eq!(prev.steps_to(next), 51);
    }

    // #[test]
    // #[rustfmt::skip]
    // fn test_parse_pkt_ping() {
    //     assert_pkt_encdec_works(
    //         &[
    //             0x00, 0x01, // Packet ID
    //             0xFF, // Packet kind
    //             0x00, 0x02, // Ping ID
    //             b'd', b'r', b'a', b'g', b'o', b'n', b's', 0x00, // Data
    //         ],
    //         Packet {
    //             id: 1,
    //             body: SupportedBody::Ping(PingBody {
    //                 ping_id: 2,
    //                 data: "dragons".into(),
    //             }),
    //         },
    //     );
    // }
}
