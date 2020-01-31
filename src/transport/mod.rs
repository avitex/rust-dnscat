mod split;

pub mod dns;

use std::future::Future;

use futures::future::BoxFuture;

pub use self::split::*;
pub use crate::util::{Decode, Encode};

pub trait Datagram: Encode + Decode + Send + 'static {}

impl<T> Datagram for T where T: Encode + Decode + Send + 'static {}

#[derive(Debug)]
pub enum ExchangeError<D, T> {
    Datagram(D),
    Transport(T),
}

pub type BoxExchangeFuture<D, TE> =
    BoxFuture<'static, Result<D, ExchangeError<<D as Decode>::Error, TE>>>;

pub trait ExchangeTransport<CS, SC = CS>: 'static
where
    CS: Datagram,
    SC: Datagram,
{
    /// Possible error that can occur during the exchange.
    type Error: Send;
    /// Future representing an asynchronous exchange.
    type Future: Future<Output = Result<SC, ExchangeError<SC::Error, Self::Error>>> + 'static;
    /// Exchange a client datagram for a server datagram.
    fn exchange(&mut self, datagram: CS) -> Self::Future;
}
