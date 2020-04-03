mod echo;
mod split;

pub mod dns;

use std::task::{Context, Poll};

use failure::Fail;

pub use self::echo::PacketEchoTransport;
pub use self::split::*;

pub use crate::util::{hex, Decode, Encode};

pub trait Datagram: Encode + Decode + Send + 'static {}

impl<T> Datagram for T where T: Encode + Decode + Send + 'static {}

#[derive(Debug, Fail)]
pub enum DatagramError<D: Fail> {
    #[fail(display = "Decode error: {}", _0)]
    Decode(D),
    #[fail(display = "Datagram underflow")]
    Underflow,
    #[fail(display = "Hex decode error: {}", _0)]
    Hex(hex::DecodeError),
    #[fail(display = "Split datagram error: {}", _0)]
    Split(SplitDatagramError),
}

impl<D: Fail> From<hex::DecodeError> for DatagramError<D> {
    fn from(err: hex::DecodeError) -> Self {
        Self::Hex(err)
    }
}

impl<D: Fail> From<SplitDatagramError> for DatagramError<D> {
    fn from(err: SplitDatagramError) -> Self {
        Self::Split(err)
    }
}

pub trait Transport<D>
where
    D: Datagram,
{
    type Error: Fail;

    /// Poll receiving a datagram.
    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<D, Self::Error>>;

    /// Poll sending a datagram.
    fn poll_send(&mut self, cx: &mut Context<'_>, datagram: D) -> Poll<Result<(), Self::Error>>;

    /// Returns the max datagram size this transport supports.
    fn max_datagram_size(&self) -> usize;
}
