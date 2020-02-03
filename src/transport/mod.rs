mod split;

pub mod dns;

use std::future::Future;

pub use self::split::*;
pub use crate::util::{Decode, Encode};

pub trait Datagram: Encode + Decode + Send + 'static {}

impl<T> Datagram for T where T: Encode + Decode + Send + 'static {}

#[derive(Debug)]
pub enum DatagramError<D> {
    Decode(D),
    Overflow,
    Underflow,
    Malformed,
    Split(SplitDatagramError),
}

impl<D> From<SplitDatagramError> for DatagramError<D> {
    fn from(err: SplitDatagramError) -> Self {
        Self::Split(err)
    }
}

pub trait ExchangeTransport<CS, SC = CS>: 'static
where
    CS: Datagram<Error = SC::Error>,
    SC: Datagram,
{
    /// Possible error that can occur during the exchange.
    type Error: Send;
    /// Future representing an asynchronous exchange.
    type Future: Future<Output = Result<SC, Self::Error>> + 'static;
    /// Exchange a client datagram for a server datagram.
    fn exchange(&mut self, datagram: CS) -> Self::Future;
}
