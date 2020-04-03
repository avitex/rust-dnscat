use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

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

use crate::transport::{Datagram, DatagramError, SplitDatagram, Transport};
use crate::util::hex;

use super::{DnsEndpoint, DnsTransportError};

const DEFAULT_LOOKUP_OPTIONS: DnsRequestOptions = DnsRequestOptions {
    // We don't currently care about mDNS responses.
    expects_multiple_responses: false,
};

const MULTI_NAME_RESPONSE: bool = false;

pub struct DnsClient<H, E, D>
where
    D: Datagram,
{
    dns_handle: H,
    endpoint: E,
    runtime_handle: runtime::Handle,
    send_task: Option<Waker>,
    recv_task: Option<Waker>,
    exchange: Option<ExchangeFuture<D>>,
}

impl<E, D> DnsClient<AsyncClient<UdpResponse>, E, D>
where
    E: DnsEndpoint,
    D: Datagram,
{
    pub async fn connect(addr: SocketAddr, endpoint: E) -> Result<Self, ProtoError> {
        Self::connect_with_runtime(addr, endpoint, runtime::Handle::current()).await
    }

    async fn connect_with_runtime(
        addr: SocketAddr,
        endpoint: E,
        rt: runtime::Handle,
    ) -> Result<Self, ProtoError> {
        let stream = UdpClientStream::<UdpSocket>::new(addr);
        let (client, bg) = AsyncClient::connect(stream).await?;
        rt.spawn(bg);
        Ok(Self::new(client, endpoint, rt))
    }
}

impl<H, E, D> DnsClient<H, E, D>
where
    H: DnsHandle,
    E: DnsEndpoint,
    D: Datagram,
{
    pub fn new(dns_handle: H, endpoint: E, runtime_handle: runtime::Handle) -> Self {
        Self {
            recv_task: None,
            send_task: None,
            exchange: None,
            endpoint,
            dns_handle,
            runtime_handle,
        }
    }

    fn parse_response(
        &mut self,
        answers: Vec<Record>,
        record_type: RecordType,
    ) -> Result<D, DnsTransportError<D::Error>> {
        if answers.is_empty() {
            return Err(DnsTransportError::NoAnswers);
        }
        // We will filter for the record type we requested, and
        // drop record types we don't care about silently later.
        let answers = answers.into_iter().map(|r| r.unwrap_rdata());
        // Parse the record data depending on the record type.
        let mut bytes = match record_type {
            RecordType::A => {
                let mut buf = BytesMut::new();
                let addrs = answers.filter_map(|d| d.into_a().ok());
                SplitDatagram::write_iter_into(addrs, &mut buf).map_err(DatagramError::from)?;
                buf.freeze()
            }
            RecordType::AAAA => {
                let mut buf = BytesMut::new();
                let addrs = answers.filter_map(|d| d.into_aaaa().ok());
                SplitDatagram::write_iter_into(addrs, &mut buf).map_err(DatagramError::from)?;
                buf.freeze()
            }
            RecordType::CNAME if MULTI_NAME_RESPONSE => {
                let mut buf = BytesMut::new();
                let mut blobs = Vec::with_capacity(answers.len());
                let names = answers.filter_map(|d| d.into_cname().ok());
                for name in names {
                    blobs.push(self.endpoint.parse_cname_response(name)?);
                }
                SplitDatagram::write_iter_into(blobs, &mut buf).map_err(DatagramError::from)?;
                buf.freeze()
            }
            RecordType::CNAME => {
                let name = answers
                    .filter_map(|d| d.into_cname().ok())
                    .next()
                    .expect("a CNAME answer");
                self.endpoint.parse_cname_response(name)?
            }
            RecordType::MX if MULTI_NAME_RESPONSE => {
                let mut buf = BytesMut::new();
                let mut blobs = Vec::with_capacity(answers.len());
                let names = answers.filter_map(|d| d.into_mx().ok());
                for mx in names {
                    blobs.push(self.endpoint.parse_mx_response(mx.exchange().clone())?);
                }
                SplitDatagram::write_iter_into(blobs, &mut buf).map_err(DatagramError::from)?;
                buf.freeze()
            }
            RecordType::MX => {
                let name = answers
                    .filter_map(|d| d.into_mx().ok())
                    .next()
                    .expect("a MX answer");
                self.endpoint.parse_mx_response(name.exchange().clone())?
            }
            RecordType::TXT => {
                let mut buf = BytesMut::new();
                let mut txts = answers.filter_map(|d| d.into_txt().ok());
                if let Some(txt) = txts.next() {
                    for blob in txt.txt_data() {
                        hex::decode_into_buf(&mut buf, &blob[..], true)
                            .map_err(DatagramError::from)?;
                    }

                    if txts.next().is_some() {
                        warn!("using the first of multiple txt answers received");
                    }
                }
                buf.freeze()
            }
            other => panic!("unsupported record type: {:?}", other),
        };
        if bytes.is_empty() {
            return Err(DnsTransportError::NoData);
        }
        let datagram = D::decode(&mut bytes).map_err(DatagramError::Decode)?;
        if bytes.is_empty() {
            Ok(datagram)
        } else {
            Err(DatagramError::Underflow.into())
        }
    }
}

impl<H, E, D> Transport<D> for DnsClient<H, E, D>
where
    H: DnsHandle,
    E: DnsEndpoint,
    D: Datagram,
    D::Error: Unpin,
{
    type Error = DnsTransportError<D::Error>;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<D, Self::Error>> {
        match self.exchange.take() {
            None => {
                self.recv_task = Some(cx.waker().clone());
                Poll::Pending
            }
            Some(mut exchange) => match exchange.poll(cx, self) {
                Poll::Pending => {
                    self.exchange = Some(exchange);
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    if let Some(send_task) = self.send_task.take() {
                        send_task.wake();
                    }
                    Poll::Ready(result)
                }
            },
        }
    }

    fn poll_send(&mut self, cx: &mut Context<'_>, datagram: D) -> Poll<Result<(), Self::Error>> {
        if self.exchange.is_some() {
            self.send_task = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut request_data = BytesMut::new();
        datagram.encode(&mut request_data);
        let mut future = ExchangeFuture::new(self, request_data.freeze());
        let future = match future.poll(cx, self) {
            Poll::Pending => future,
            Poll::Ready(result) => ExchangeFuture::Ready(Some(result)),
        };
        self.exchange = Some(future);
        if let Some(recv_task) = self.recv_task.take() {
            recv_task.wake();
        }
        Poll::Ready(Ok(()))
    }

    fn max_datagram_size(&self) -> usize {
        self.endpoint.max_request_size()
    }
}

impl<H, E, D> fmt::Debug for DnsClient<H, E, D>
where
    E: fmt::Debug,
    D: Datagram,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DnsClient").field(&self.endpoint).finish()
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
enum ExchangeFuture<D>
where
    D: Datagram,
{
    Ready(Option<Result<D, DnsTransportError<D::Error>>>),
    Pending {
        record_type: RecordType,
        request_fut: JoinHandle<Result<DnsResponse, ProtoError>>,
    },
}

impl<D> ExchangeFuture<D>
where
    D: Datagram,
{
    fn new<H, E>(client: &mut DnsClient<H, E, D>, request_data: Bytes) -> Self
    where
        H: DnsHandle,
        E: DnsEndpoint,
    {
        match client.endpoint.build_request(request_data) {
            Ok((name, record_type)) => {
                let query = Query::query(name, record_type);
                let request_fut = client.dns_handle.lookup(query, DEFAULT_LOOKUP_OPTIONS);
                let request_fut = client.runtime_handle.spawn(request_fut);
                ExchangeFuture::Pending {
                    record_type,
                    request_fut,
                }
            }
            Err(err) => ExchangeFuture::Ready(Some(Err(DnsTransportError::Endpoint(err)))),
        }
    }

    fn poll<H, E>(
        &mut self,
        cx: &mut Context<'_>,
        client: &mut DnsClient<H, E, D>,
    ) -> Poll<Result<D, DnsTransportError<D::Error>>>
    where
        H: DnsHandle,
        E: DnsEndpoint,
    {
        match self {
            Self::Pending {
                request_fut,
                record_type,
            } => {
                let result = ready!(Pin::new(request_fut).poll(cx))
                    .expect("failed to execute dns lookup future")
                    .map_err(DnsTransportError::Proto)
                    .and_then(|mut response| {
                        let answers = response.take_answers();
                        client.parse_response(answers, *record_type)
                    });
                Poll::Ready(result)
            }
            Self::Ready(result_opt) => {
                let result = result_opt.take().expect("exchange future already consumed");
                Poll::Ready(result)
            }
        }
    }
}
