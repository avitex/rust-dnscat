mod ip;
mod name;

use std::future::Future;

use bytes::BytesMut;
use futures::future::{self, TryFutureExt};

pub use self::ip::*;
pub use self::name::*;

use crate::transport::{Datagram, Decode, Encode};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
}

pub trait DnsClient {
    type Name;
    type Error;
    type Response;
    type QueryFuture: Future<Output = Result<Self::Response, Self::Error>>;

    fn query(&self, name: Self::Name) -> Self::QueryFuture;
}

pub trait DnsEndpoint {
    type Name;
    fn encode_data(&mut self, data: &[u8]) -> Self::Name;
    fn encode_data_limit(&self) -> usize;
}

pub enum DnsTransportError<T> {
    Internal(T),
    Placeholder,
    DatagramOverflow,
}

pub struct DnsClientTransport<C, E>
where
    E: DnsEndpoint,
{
    client: C,
    endpoint: E,
    tx_buf: BytesMut,
    rx_buf: BytesMut,
}

impl<C, E> DnsClientTransport<C, E>
where
    C: DnsClient,
    C::Name: From<E::Name>,
    E: DnsEndpoint,
{
    /// Exchanges a datagram with the remote host.
    pub fn exchange<'i, 'o, T>(
        &'o mut self,
        datagram: Datagram<'i, T>,
    ) -> impl Future<Output = Result<Datagram<'o, T>, DnsTransportError<C::Error>>>
    where
        T: Encode + Decode<'o>,
    {
        // Get the datagram size limit from DNS endpoint settings.
        let limit = self.endpoint.encode_data_limit();
        // Encode the datagram into the buffer.
        datagram.encode(&mut self.tx_buf);
        // Validate the datagram did not overflow the buffer limit.
        if self.tx_buf.len() > limit {
            self.tx_buf.clear();
            return future::Either::Left(future::err(DnsTransportError::DatagramOverflow));
        }
        // Build the domain name with the data.
        let domain_name = self.endpoint.encode_data(self.tx_buf.as_ref());
        // Query the DNS server and exchange a datagram.
        let datagram_res_fut = self
            .client
            .query(domain_name.into())
            .map_err(DnsTransportError::Internal)
            .and_then(|_response| future::err(DnsTransportError::Placeholder));
        // Return datagram result future
        future::Either::Right(datagram_res_fut)
    }
}
