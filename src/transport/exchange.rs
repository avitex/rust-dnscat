use std::future::Future;
use std::marker::PhantomData;

use bytes::{Bytes, BytesMut};

use crate::encdec::Decode;
use crate::transport::{Datagram, DatagramTransport};

pub trait ExchangeClient: Send + Sync + 'static {
    type Error: Send;

    type Query;

    type Future: Future<Output = Result<Bytes, Self::Error>> + Send;

    fn build(&mut self, buf: &[u8]) -> Result<Option<Self::Query>, Self::Error>;

    fn query(&mut self, query: Self::Query) -> Self::Future;
}

pub enum ExchangeError<CE, DE> {
    Client(CE),
    DatagramDecode(DE),
    DatagramOverflow,
    DatagramUnderflow,
}

pub struct ExchangeTransport<C, D> {
    client: C,
    tx_buf: BytesMut,
    marker: PhantomData<D>,
}

impl<C, D> ExchangeTransport<C, D> {
    pub fn new(client: C) -> Self {
        Self {
            client,
            tx_buf: BytesMut::new(),
            marker: PhantomData,
        }
    }
}

pub type ExchangeResult<C, D> =
    Result<D, ExchangeError<<C as ExchangeClient>::Error, <D as Decode>::Error>>;

impl<C, D> ExchangeTransport<C, D>
where
    C: ExchangeClient,
{
    pub async fn exchange(&mut self, datagram: D) -> ExchangeResult<C, D>
    where
        D: Datagram,
        D::Error: Send,
    {
        // Encode the datagram into the buffer.
        datagram.encode(&mut self.tx_buf);
        // Build the client query
        let query = match self.client.build(&self.tx_buf) {
            Ok(Some(query)) => query,
            Ok(None) => return Err(ExchangeError::DatagramOverflow),
            Err(err) => return Err(ExchangeError::Client(err)),
        };
        // Query and exchange a datagram.
        let mut rx_buf = self
            .client
            .query(query)
            .await
            .map_err(ExchangeError::Client)?;

        // Decode the response datagram.
        let datagram = D::decode(&mut rx_buf).map_err(ExchangeError::DatagramDecode)?;

        if rx_buf.is_empty() {
            Ok(datagram)
        } else {
            Err(ExchangeError::DatagramUnderflow)
        }
    }
}

impl<C, D> DatagramTransport for ExchangeTransport<C, D>
where
    C: ExchangeClient,
    D: Datagram,
{
    type Datagram = D;
}
