use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use futures::future::{self, BoxFuture, FutureExt};
use log::warn;
use tokio::net::UdpSocket;
use tokio::runtime;
use trust_dns_client::client::AsyncClient;
use trust_dns_proto::{
    error::ProtoError,
    op::Query,
    rr::{Name, Record, RecordType},
    udp::{UdpClientStream, UdpResponse},
    xfer::{DnsHandle, DnsRequestOptions},
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
    pub async fn connect(
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

    async fn lookup(
        &mut self,
        name: Name,
        record_type: RecordType,
    ) -> Result<Vec<Record>, ProtoError> {
        let query = Query::query(name, record_type);
        let fut = self.dns_handle.lookup(query, DEFAULT_LOOKUP_OPTIONS);
        let mut response = self
            .runtime_handle
            .spawn(fut)
            .map(|res| res.expect("failed to execute dns lookup future"))
            .await?;
        Ok(response.take_answers())
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
    SC::Error: Send,
{
    type Error = DnsTransportError<SC::Error>;

    type Future = BoxFuture<'static, Result<SC, Self::Error>>;

    fn exchange(&mut self, datagram: CS) -> Self::Future {
        let mut request_data = BytesMut::new();
        datagram.encode(&mut request_data);
        match self.endpoint.build_request(request_data.freeze()) {
            Ok((name, record_type)) => {
                let mut this = self.clone();
                Box::pin(async move {
                    let answers = this.lookup(name, record_type).await?;
                    this.parse_response(answers, record_type)
                })
            }
            Err(err) => Box::pin(future::err(DnsTransportError::Endpoint(err))),
        }
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
        write!(f, "DnsClient ( {:#?} )", self.endpoint)
    }
}
