pub mod dns;

use std::future::Future;

pub use crate::util::{Decode, Encode};

pub trait Datagram: Encode + Decode + Send + 'static {}

impl<T> Datagram for T where T: Encode + Decode + Send + 'static {}

pub trait ExchangeTransport<CS: Datagram, SC: Datagram = CS>: 'static {
    /// Possible error that can occur during the exchange.
    type Error;
    /// Future representing an asynchronous exchange.
    type Future: Future<Output = Result<SC, Self::Error>> + 'static;
    /// Exchange a client datagram for a server datagram.
    fn exchange(&mut self, datagram: CS) -> Self::Future;
}
