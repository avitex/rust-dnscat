mod echo;
mod split;

pub mod dns;

use std::future::Future;

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

pub trait ExchangeTransport<CS, SC = CS>
where
    CS: Datagram<Error = SC::Error>,
    SC: Datagram,
{
    /// Possible error that can occur during the exchange.
    type Error: Fail;

    /// Future representing an asynchronous exchange.
    type Future: Future<Output = Result<SC, Self::Error>> + 'static;

    /// Exchange a client datagram for a server datagram.
    fn exchange(&mut self, datagram: CS) -> Self::Future;

    /// Returns the max datagram size this transport supports.
    fn max_datagram_size(&self) -> usize;
}
