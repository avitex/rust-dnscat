use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::ready;
use log::warn;
use tokio::net::UdpSocket;
use tokio::runtime;
use tokio::task::JoinHandle;
use trust_dns_client::client::AsyncClient;
use trust_dns_proto::{
    error::ProtoError,
    op::Query,
    rr::{Record, RecordType},
    udp::{UdpClientStream, UdpResponse},
    xfer::{DnsHandle, DnsRequestOptions, DnsResponse},
};

use crate::transport::{Datagram, DatagramError, ExchangeTransport, SplitDatagram};
use crate::util::hex;

use super::{DnsEndpoint, DnsTransportError};

const DEFAULT_LOOKUP_OPTIONS: DnsRequestOptions = DnsRequestOptions {
    // We don't currently care about mDNS responses.
    expects_multiple_responses: false,
};

pub struct DnsClient<H, E> {
    dns_handle: H,
    runtime_handle: runtime::Handle,
    endpoint: Arc<E>,
}

impl<H, E> Clone for DnsClient<H, E>
where
    H: DnsHandle,
{
    fn clone(&self) -> Self {
        Self {
            dns_handle: self.dns_handle.clone(),
            runtime_handle: self.runtime_handle.clone(),
            endpoint: self.endpoint.clone(),
        }
    }
}

impl<E> DnsClient<AsyncClient<UdpResponse>, E>
where
    E: DnsEndpoint,
{
    pub async fn connect(addr: SocketAddr, endpoint: Arc<E>) -> Result<Self, ProtoError> {
        Self::connect_with_runtime(addr, endpoint, runtime::Handle::current()).await
    }

    async fn connect_with_runtime(
        addr: SocketAddr,
        endpoint: Arc<E>,
        rt: runtime::Handle,
    ) -> Result<Self, ProtoError> {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (client, bg) = AsyncClient::connect(stream).await?;
        rt.spawn(bg);
        Ok(Self::new(client, endpoint, rt))
    }
}

impl<H, E> DnsClient<H, E>
where
    H: DnsHandle,
    E: DnsEndpoint,
{
    pub fn new(dns_handle: H, endpoint: Arc<E>, runtime_handle: runtime::Handle) -> Self {
        Self {
            endpoint,
            dns_handle,
            runtime_handle,
        }
    }

    fn parse_response<D: Datagram>(
        &mut self,
        answers: Vec<Record>,
        record_type: RecordType,
    ) -> Result<D, DnsTransportError<D::Error>> {
        // We will filter for the record type we requested, and
        // drop record types we don't care about silently later.
        let answers = answers.into_iter().map(|r| r.unwrap_rdata());
        // Create the buffer we will put the data in.
        let mut bytes = BytesMut::new();
        // Parse the record data depending on the record type.
        match record_type {
            RecordType::A => {
                let addrs = answers.filter_map(|d| d.into_a().ok());
                SplitDatagram::write_iter_into(addrs, &mut bytes).map_err(DatagramError::from)?;
            }
            RecordType::AAAA => {
                let addrs = answers.filter_map(|d| d.into_aaaa().ok());
                SplitDatagram::write_iter_into(addrs, &mut bytes).map_err(DatagramError::from)?;
            }
            RecordType::CNAME => {
                let mut blobs = Vec::with_capacity(answers.len());
                let names = answers.filter_map(|d| d.into_cname().ok());
                for name in names {
                    blobs.push(self.endpoint.parse_cname_response(name)?);
                }
                SplitDatagram::write_iter_into(blobs, &mut bytes).map_err(DatagramError::from)?;
            }
            RecordType::MX => {
                let mut blobs = Vec::with_capacity(answers.len());
                let names = answers.filter_map(|d| d.into_mx().ok());
                for mx in names {
                    blobs.push(self.endpoint.parse_mx_response(mx.exchange().clone())?);
                }
                SplitDatagram::write_iter_into(blobs, &mut bytes).map_err(DatagramError::from)?;
            }
            RecordType::TXT => {
                let mut txts = answers.filter_map(|d| d.into_txt().ok());
                if let Some(txt) = txts.next() {
                    for blob in txt.txt_data() {
                        hex::decode_into_buf(&mut bytes, &blob[..], true)
                            .map_err(DatagramError::from)?;
                    }

                    if txts.next().is_some() {
                        warn!("using the first of multiple txt answers received");
                    }
                }
            }
            other => panic!("unsupported record type: {:?}", other),
        }
        let mut bytes = bytes.freeze();
        let datagram = D::decode(&mut bytes).map_err(DatagramError::Decode)?;
        if bytes.is_empty() {
            Ok(datagram)
        } else {
            Err(DatagramError::Underflow.into())
        }
    }
}

impl<H, E, CS, SC> ExchangeTransport<CS, SC> for DnsClient<H, E>
where
    H: DnsHandle,
    E: DnsEndpoint,
    CS: Datagram<Error = SC::Error>,
    SC: Datagram,
    SC::Error: Unpin,
{
    type Error = DnsTransportError<SC::Error>;

    type Future = ExchangeFuture<H, E, SC>;

    fn exchange(&mut self, datagram: CS) -> Self::Future {
        let mut request_data = BytesMut::new();
        datagram.encode(&mut request_data);
        ExchangeFuture::new(self, request_data.freeze())
    }

    fn max_datagram_size(&self) -> usize {
        self.endpoint.max_request_size()
    }
}

impl<H, E> fmt::Debug for DnsClient<H, E>
where
    E: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("DnsClient").field(&self.endpoint).finish()
    }
}

///////////////////////////////////////////////////////////////////////////////

pub enum ExchangeFuture<H, E, D>
where
    D: Datagram,
{
    Future {
        client: DnsClient<H, E>,
        record_type: RecordType,
        fut: JoinHandle<Result<DnsResponse, ProtoError>>,
    },
    Error(Option<DnsTransportError<D::Error>>),
}

impl<H, E, D> ExchangeFuture<H, E, D>
where
    H: DnsHandle,
    E: DnsEndpoint,
    D: Datagram,
{
    pub fn new(client: &mut DnsClient<H, E>, request_data: Bytes) -> Self {
        match client.endpoint.build_request(request_data) {
            Ok((name, record_type)) => {
                let query = Query::query(name, record_type);
                let fut = client.dns_handle.lookup(query, DEFAULT_LOOKUP_OPTIONS);
                let fut = client.runtime_handle.spawn(fut);
                Self::Future {
                    client: client.clone(),
                    record_type,
                    fut,
                }
            }
            Err(err) => Self::Error(Some(DnsTransportError::Endpoint(err))),
        }
    }
}

impl<H, E, D> Future for ExchangeFuture<H, E, D>
where
    H: DnsHandle,
    E: DnsEndpoint,
    D: Datagram,
    D::Error: Unpin,
{
    type Output = Result<D, DnsTransportError<D::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Future {
                fut,
                client,
                record_type,
            } => {
                let result = ready!(Pin::new(fut).poll(cx))
                    .expect("failed to execute dns lookup future")
                    .map_err(DnsTransportError::Proto)
                    .and_then(|mut response| {
                        let answers = response.take_answers();
                        client.parse_response(answers, *record_type)
                    });
                Poll::Ready(result)
            }
            Self::Error(err_opt) => {
                let err = err_opt.take().expect("exchange future already consumed");
                Poll::Ready(Err(err))
            }
        }
    }
}

impl<H, E, D> fmt::Debug for ExchangeFuture<H, E, D>
where
    E: fmt::Debug,
    D: Datagram,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ExchangeFuture")
    }
}
