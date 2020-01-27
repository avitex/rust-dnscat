use std::future::Future;

use crate::packet::Packet;
use crate::transport::Datagram;

pub trait ExchangeTransport<'a, D>
where
    D: Datagram<'a>,
{
    type Error;

    type Future: Future<Output = Result<D, Self::Error>>;

    fn exchange(&'a mut self, datagram: D) -> Self::Future;
}

pub struct Connection<T> {
    transport: T,
}

impl<'a, T> Connection<T>
where
    T: ExchangeTransport<'a, Packet<'a>>,
{
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}
