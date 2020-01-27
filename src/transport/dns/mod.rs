mod ip;
mod name;

use std::future::Future;

use bytes::{Buf, BufMut, BytesMut};
use futures::future::{self, BoxFuture, TryFutureExt};

pub use self::ip::*;
pub use self::name::*;

use crate::transport::{Datagram, ExchangeTransport};

// #[derive(Debug, Clone, Copy, PartialEq)]
// pub enum DnsRecordType {
//     A,
//     AAAA,
//     CNAME,
//     TXT,
//     MX,
// }

pub trait DnsClient: Send + Sync {
    type Name;

    type Error: Send;

    type QueryFuture: Future<Output = Result<(), Self::Error>> + Send;

    fn query<B: BufMut>(&self, name: Self::Name, buf: &mut B) -> Self::QueryFuture;
}

pub trait DnsEndpoint: Send + Sync {
    type Name;

    fn encode_data(&mut self, data: &[u8]) -> Self::Name;

    fn encode_data_limit(&self) -> usize;
}

pub enum DnsTransportError<CE, DE> {
    Client(CE),
    Datagram(DE),
    DatagramOverflow,
    DatagramUnderflow,
}

pub struct DnsClientTransport<C, E> {
    client: C,
    endpoint: E,
    tx_buf: BytesMut,
    rx_buf: BytesMut,
}

impl<C, E> DnsClientTransport<C, E> {
    pub fn new(client: C, endpoint: E) -> Self {
        Self {
            client,
            endpoint,
            tx_buf: BytesMut::new(),
            rx_buf: BytesMut::new(),
        }
    }
}

impl<'a, C, D, E> ExchangeTransport<'a, D> for DnsClientTransport<C, E>
where
    C: DnsClient,
    C::Name: From<E::Name>,
    E: DnsEndpoint,
    D: Datagram<'a>,
    D::Error: Send,
{
    type Error = DnsTransportError<C::Error, D::Error>;
    type Future = BoxFuture<'a, Result<D, Self::Error>>;

    fn exchange(&'a mut self, datagram: D) -> Self::Future {
        // Get the datagram size limit from DNS endpoint settings.
        let limit = self.endpoint.encode_data_limit();
        // Encode the datagram into the buffer.
        datagram.encode(&mut self.tx_buf);
        // Validate the datagram did not overflow the buffer limit.
        if self.tx_buf.len() > limit {
            self.tx_buf.clear();
            return Box::pin(future::err(DnsTransportError::DatagramOverflow));
        }
        // Build the domain name with the data.
        let domain_name = self.endpoint.encode_data(self.tx_buf.as_ref());
        // Query the DNS server and exchange a datagram.
        let fut = self
            .client
            .query(domain_name.into(), &mut self.rx_buf)
            .map_err(DnsTransportError::Client)
            .and_then(move |_| {
                // Decode the response datagram and return it
                let res = D::decode(self.rx_buf.bytes())
                    .map_err(DnsTransportError::Datagram)
                    .and_then(|(bytes_left, datagram)| {
                        if bytes_left.len() == 0 {
                            Ok(datagram)
                        } else {
                            Err(DnsTransportError::DatagramUnderflow)
                        }
                    });
                future::ready(res)
            });
        Box::pin(fut)
    }
}
