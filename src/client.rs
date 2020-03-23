use std::borrow::Cow;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use std::{cmp, io};

use bytes::{Buf, Bytes};
use failure::Fail;
use futures::io::{AsyncRead, AsyncWrite};
use futures::{future, ready};
use futures_timer::Delay;
use log::{debug, warn};
use rand::prelude::{Rng, ThreadRng};
use tokio::io::{AsyncRead as TokioAsyncRead, AsyncWrite as TokioAsyncWrite};

use crate::encryption::Encryption;
use crate::packet::*;
use crate::session::{Session, SessionError};
use crate::transport::ExchangeTransport;

#[derive(Debug, Fail)]
pub enum ClientError<T: Fail, E: Fail> {
    #[fail(display = "Transport error: {}", _0)]
    Transport(T),
    #[fail(display = "Session error: {}", _0)]
    Session(SessionError<E>),
    #[fail(
        display = "Unexpected session ID (expected: {}, got: {})",
        expected, actual
    )]
    UnexpectedId {
        expected: SessionId,
        actual: SessionId,
    },
    #[fail(display = "Unexpected packet kind `{:?}`", _0)]
    UnexpectedKind(PacketKind),
}

impl<T: Fail, E: Fail> From<SessionError<E>> for ClientError<T, E> {
    fn from(err: SessionError<E>) -> Self {
        ClientError::Session(err)
    }
}

impl<T: Fail, E: Fail> From<ClientError<T, E>> for io::Error {
    fn from(err: ClientError<T, E>) -> Self {
        // TODO: better?
        io::Error::new(io::ErrorKind::Other, err.compat())
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct Exchange<T> {
    inner: T,
    attempt: usize,
    delay: Option<Delay>,
    body: SessionBodyBytes,
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct Client<T, E = (), R = ThreadRng>
where
    T: ExchangeTransport<LazyPacket>,
{
    random: R,
    transport: T,
    session: Session<E>,
    exchange: Option<Exchange<T::Future>>,
    max_retransmits: Option<usize>,
    random_delay: bool,
    retransmit_backoff: bool,
    last_transmit: Instant,
    min_delay: Duration,
    max_delay: (Duration, Option<Delay>),
    send_buf: Bytes,
    recv_buf: Bytes,
    send_task: Option<Waker>,
    recv_queue: VecDeque<Bytes>,
}

impl<T, E, R> Client<T, E, R>
where
    T: ExchangeTransport<LazyPacket>,
    T::Future: Unpin,
    E: Encryption,
    R: Rng,
{
    pub fn session(&self) -> &Session<E> {
        &self.session
    }

    async fn client_handshake(mut self) -> Result<Self, ClientError<T::Error, E::Error>> {
        debug!("starting client handshake");
        if self.session.is_encrypted() {
            self = self.client_encryption_handshake().await?;
        } else {
            debug!("skipping encryption handshake");
        }
        let body = self.session.build_syn();
        let body = self.session.build_body(body, true)?;
        self.basic_exchange(body).await?;
        Ok(self)
    }

    async fn client_encryption_handshake(self) -> Result<Self, ClientError<T::Error, E::Error>> {
        unimplemented!()
    }

    async fn basic_exchange(
        &mut self,
        body: SessionBodyBytes,
    ) -> Result<(), ClientError<T::Error, E::Error>> {
        self.start_exchange(body);
        future::poll_fn(|cx| self.poll_exchange(cx)).await?;
        Ok(())
    }

    fn poll_exchange(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<bool, ClientError<T::Error, E::Error>>> {
        let exchange = self
            .exchange
            .as_mut()
            .expect("attempted to poll empty exchange");

        let Exchange {
            body,
            inner,
            delay,
            attempt,
        } = exchange;

        if let Some(ref mut delay_fut) = delay {
            ready!(Pin::new(delay_fut).poll(cx));
            let packet = Self::build_session_packet(self.session.id(), body.clone());
            *delay = None;
            *attempt += 1;
            *inner = self.transport.exchange(packet);
        }

        let result = match ready!(Pin::new(inner).poll(cx)) {
            // TODO: destroy session if fatal?
            Err(err) => Err(ClientError::Transport(err)),
            Ok(packet) => match Self::parse_session_packet(self.session.id(), packet) {
                Ok(body) => self.session.handle_inbound(body).map_err(Into::into),
                Err(err) => Err(err),
            },
        };

        let chunk_opt = match result {
            Ok(chunk_opt) => chunk_opt,
            Err(err) if Some(*attempt) >= self.max_retransmits || self.session.is_closed() => {
                // TODO: notify session we are dead?
                self.exchange = None;
                return Poll::Ready(Err(err));
            }
            Err(err) => {
                let delay_dur = if self.random_delay {
                    self.random.gen_range(self.min_delay, self.max_delay.0)
                } else if self.retransmit_backoff {
                    Duration::from_secs(2u64.pow(*attempt as u32))
                } else {
                    self.min_delay
                };
                warn!(
                    "retrying exchange after {} secs after {}",
                    delay_dur.as_secs(),
                    err
                );
                *delay = Some(Delay::new(delay_dur));
                return self.poll_exchange(cx);
            }
        };

        self.last_transmit = Instant::now();
        self.exchange = None;

        if let Some(chunk) = chunk_opt {
            self.recv_queue_push(chunk);
            Poll::Ready(Ok(true))
        } else {
            Poll::Ready(Ok(false))
        }
    }

    fn parse_session_packet(
        session_id: SessionId,
        packet: LazyPacket,
    ) -> Result<SessionBodyBytes, ClientError<T::Error, E::Error>> {
        let kind = packet.kind();
        // Consume the received packet into a session frame if applicable
        if let Some(frame) = packet.into_body().into_session_frame() {
            // Check the session ID returned matches our session ID
            if session_id != frame.session_id() {
                Err(ClientError::UnexpectedId {
                    expected: session_id,
                    actual: frame.session_id(),
                })
            } else {
                // Return the framed session body bytes.
                Ok(frame.into_body().into())
            }
        } else {
            Err(ClientError::UnexpectedKind(kind))
        }
    }

    fn build_session_packet(session_id: SessionId, body: SessionBodyBytes) -> LazyPacket {
        // Wrap the encoded session body in a session body frame.
        let frame = SessionBodyFrame::new(session_id, body);
        // Wrap the session body frame in a packet frame and return.
        LazyPacket::new(SupportedBody::Session(frame))
    }

    fn next_transmit_delay(&mut self) -> Option<Delay> {
        let dur_since_last = Instant::now().duration_since(self.last_transmit);

        let dur = if self.random_delay {
            self.random
                .gen_range(self.min_delay, self.max_delay.0)
                .checked_sub(dur_since_last)
        } else if dur_since_last < self.min_delay {
            Some(self.min_delay - dur_since_last)
        } else {
            None
        };

        dur.map(Delay::new)
    }

    fn start_exchange(&mut self, body: SessionBodyBytes) {
        assert!(self.exchange.is_none());
        let packet = Self::build_session_packet(self.session.id(), body.clone());
        let inner = self.transport.exchange(packet);
        let delay = self.next_transmit_delay();
        self.exchange = Some(Exchange {
            inner,
            body,
            delay,
            attempt: 1,
        });
    }

    fn start_next_chunk_exchange(&mut self) -> Result<(), ClientError<T::Error, E::Error>> {
        let chunk = if self.send_buf.is_empty() {
            debug!("sending empty chunk");
            Bytes::new()
        } else {
            let budget = self.transport.max_datagram_size();
            let chunk_len = self.session.calc_chunk_len(self.send_buf.len(), budget);
            self.send_buf.split_to(chunk_len as usize)
        };
        let body = self.session.build_msg(chunk);
        let body = self.session.build_body(body, true)?;
        Ok(self.start_exchange(body))
    }

    fn is_recv_queue_full(&self) -> bool {
        self.recv_queue.len() == self.recv_queue.capacity()
    }

    fn recv_queue_pop(&mut self) -> Option<Bytes> {
        self.recv_queue.pop_front().map(|chunk| {
            // Capacity to recv again!
            self.send_task.take().map(Waker::wake);
            self.max_delay.1 = None;
            chunk
        })
    }

    fn recv_queue_push(&mut self, chunk: Bytes) {
        assert!(!self.is_recv_queue_full());
        self.recv_queue.push_back(chunk);
    }

    fn do_poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, ClientError<T::Error, E::Error>>> {
        if self.recv_buf.is_empty() {
            self.recv_buf = ready!(self.do_poll_recv(cx))?;
        }
        let len = cmp::min(buf.len(), self.recv_buf.len());
        self.recv_buf.split_to(len).copy_to_slice(&mut buf[..len]);
        Poll::Ready(Ok(len))
    }

    fn do_poll_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bytes, ClientError<T::Error, E::Error>>> {
        // First see if we have anything in the recv queue.
        if let Some(chunk) = self.recv_queue_pop() {
            return Poll::Ready(Ok(chunk));
        }
        // Okay we didn't, so now we see if there is an exchange
        // happening and poll it so we get woken when it finishes.
        // If the poll exchange returns `Poll::Ready(Ok(true))` we know
        // it pushed at least one chunk to the recv queue so we return it.
        if self.exchange.is_some() && ready!(self.poll_exchange(cx))? {
            let chunk = self.recv_queue_pop().unwrap();
            return Poll::Ready(Ok(chunk));
        }
        // There is no exchange currently running so we set a delay
        // to send an empty chunk to poke the server.
        if self.max_delay.1.is_none() {
            self.max_delay.1 = Some(Delay::new(self.max_delay.0));
        }
        // We poll the delay to see if we should send an empty chunk.
        let poll_delay = self.max_delay.1.as_mut().unwrap();
        match Pin::new(poll_delay).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.max_delay.1 = None;
                self.start_next_chunk_exchange()?;
                self.do_poll_recv(cx)
            }
        }
    }

    fn do_poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ClientError<T::Error, E::Error>>> {
        if self.is_recv_queue_full() {
            self.send_task = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // Flush the current send buffer out.
        ready!(self.do_poll_flush(cx))?;
        // Push the data into the send buffer.
        self.send_buf = buf.to_vec().into();
        // Setup the exchange.
        self.start_next_chunk_exchange()?;
        // Data is in the buffer!
        Poll::Ready(Ok(buf.len()))
    }

    fn do_poll_flush(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ClientError<T::Error, E::Error>>> {
        // If there is an exchange already happening we poll
        // it to completion.
        if self.exchange.is_some() {
            ready!(self.poll_exchange(cx))?;
        }
        // If we reach here, there is no exchange.
        if self.send_buf.is_empty() {
            // Nothing left in the buffer to send!
            Poll::Ready(Ok(()))
        } else {
            self.start_next_chunk_exchange()?;
            self.poll_exchange(cx).map_ok(drop)
        }
    }

    fn do_poll_close(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ClientError<T::Error, E::Error>>> {
        if self.exchange.is_none() && self.session.is_closed() {
            return Poll::Ready(Ok(()));
        }
        // If we get any errors while closing, just ignore them.
        if let Err(err) = ready!(self.do_poll_flush(cx)) {
            warn!("ignored error while closing {}", err);
        }
        let body = self.session.build_fin("");
        match self.session.build_body(body, true) {
            Ok(body) => {
                self.start_exchange(body);
                self.poll_exchange(cx).map_ok(drop)
            }
            Err(err) => {
                warn!("ignored error while closing {}", err);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<T, E, R> AsyncRead for Client<T, E, R>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: Encryption + Unpin,
    R: Rng + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.get_mut().do_poll_read(cx, buf).map_err(Into::into)
    }
}

impl<T, E, R> AsyncWrite for Client<T, E, R>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: Encryption + Unpin,
    R: Rng + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.get_mut().do_poll_write(cx, buf).map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().do_poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().do_poll_close(cx).map_err(Into::into)
    }
}

///////////////////////////////////////////////////////////////////////////////

impl<T, E, R> TokioAsyncRead for Client<T, E, R>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: Encryption + Unpin,
    R: Rng + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.get_mut().do_poll_read(cx, buf).map_err(Into::into)
    }
}

impl<T, E, R> TokioAsyncWrite for Client<T, E, R>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: Encryption + Unpin,
    R: Rng + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.get_mut().do_poll_write(cx, buf).map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().do_poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().do_poll_close(cx).map_err(Into::into)
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct ClientBuilder<R = ThreadRng>
where
    R: Rng,
{
    random: R,
    session_id: Option<u16>,
    session_name: Cow<'static, str>,
    initial_sequence: Option<u16>,
    is_command: bool,
    min_delay: Duration,
    max_delay: Duration,
    random_delay: bool,
    prefer_server_name: bool,
    recv_queue_size: usize,
    max_retransmits: Option<usize>,
    retransmit_backoff: bool,
    packet_trace: bool,
}

impl<R> ClientBuilder<R>
where
    R: Rng,
{
    pub fn default_with_random(random: R) -> Self {
        Self {
            random,
            packet_trace: false,
            session_id: None,
            session_name: Cow::Borrowed(""),
            initial_sequence: None,
            prefer_server_name: false,
            is_command: false,
            random_delay: false,
            recv_queue_size: 16,
            retransmit_backoff: true,
            max_retransmits: Some(20),
            min_delay: Duration::from_secs(0),
            max_delay: Duration::from_secs(1),
        }
    }

    pub fn session_id(mut self, id: u16) -> Self {
        self.session_id = Some(id);
        self
    }

    pub fn session_name<S>(mut self, name: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        self.session_name = name.into();
        self
    }

    pub fn initial_sequence(mut self, seq: u16) -> Self {
        self.initial_sequence = Some(seq);
        self
    }

    pub fn min_delay(mut self, duration: Duration) -> Self {
        self.min_delay = duration;
        self
    }

    pub fn max_delay(mut self, duration: Duration) -> Self {
        self.max_delay = duration;
        self
    }

    pub fn random_delay(mut self, value: bool) -> Self {
        self.random_delay = value;
        self
    }

    pub fn max_retransmits(mut self, max: Option<usize>) -> Self {
        assert_ne!(max, Some(0));
        self.max_retransmits = max;
        self
    }

    pub fn retransmit_backoff(mut self, value: bool) -> Self {
        self.retransmit_backoff = value;
        self
    }

    pub fn is_command(mut self, value: bool) -> Self {
        self.is_command = value;
        self
    }

    pub fn prefer_server_name(mut self, value: bool) -> Self {
        self.prefer_server_name = value;
        self
    }

    pub fn recv_queue_size(mut self, size: usize) -> Self {
        self.recv_queue_size = size;
        self
    }

    pub fn packet_trace(mut self, value: bool) -> Self {
        self.packet_trace = value;
        self
    }

    pub async fn connect<T, E>(
        self,
        transport: T,
        encryption: E,
    ) -> Result<Client<T, E, R>, ClientError<T::Error, E::Error>>
    where
        T: ExchangeTransport<LazyPacket>,
        T::Future: Unpin,
        E: Encryption,
    {
        self.generic_connect(transport, Some(encryption)).await
    }

    pub async fn connect_insecure<T>(
        self,
        transport: T,
    ) -> Result<Client<T, (), R>, ClientError<T::Error, Infallible>>
    where
        T: ExchangeTransport<LazyPacket>,
        T::Future: Unpin,
    {
        self.generic_connect(transport, None).await
    }

    async fn generic_connect<T, E>(
        self,
        transport: T,
        encryption: Option<E>,
    ) -> Result<Client<T, E, R>, ClientError<T::Error, E::Error>>
    where
        T: ExchangeTransport<LazyPacket>,
        T::Future: Unpin,
        E: Encryption,
    {
        let session_id = self.session_id.unwrap_or_else(rand::random);
        let session_name = if self.session_name.is_empty() {
            None
        } else {
            Some(self.session_name)
        };
        let init_seq = self
            .initial_sequence
            .map(Sequence)
            .unwrap_or_else(Sequence::random);
        let session = Session::new(
            session_id,
            session_name,
            init_seq,
            self.is_command,
            true,
            encryption,
            self.prefer_server_name,
            self.packet_trace,
        );
        let client = Client {
            random: self.random,
            session,
            transport,
            exchange: None,
            send_task: None,
            retransmit_backoff: self.retransmit_backoff,
            random_delay: self.random_delay,
            send_buf: Bytes::new(),
            recv_queue: VecDeque::with_capacity(self.recv_queue_size),
            recv_buf: Bytes::new(),
            last_transmit: Instant::now(),
            min_delay: self.min_delay,
            max_delay: (self.max_delay, None),
            max_retransmits: self.max_retransmits,
        };
        client.client_handshake().await
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::default_with_random(ThreadRng::default())
    }
}
