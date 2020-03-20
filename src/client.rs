use std::borrow::Cow;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use std::{cmp, io};

use bytes::{Buf, Bytes};
use failure::Fail;
use futures::io::{AsyncRead, AsyncWrite};
use futures::ready;
use futures_timer::Delay;
use log::debug;

use crate::encryption::Encryption;
use crate::packet::{LazyPacket, Sequence, SessionBodyBytes};
use crate::session::{Session, SessionError};
use crate::transport::ExchangeTransport;

#[derive(Debug, Fail)]
pub enum ClientError<T: Fail, E: Fail> {
    #[fail(display = "Transport error: {}", _0)]
    Transport(T),
    #[fail(display = "Session error: {}", _0)]
    Session(SessionError<E>),
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

#[derive(Debug)]
pub struct Client<T, E = ()>
where
    T: ExchangeTransport<LazyPacket>,
{
    transport: T,
    session: Session<E>,
    exchange: Option<T::Future>,
    exchange_sent: Option<SessionBodyBytes>,
    poll_delay: Option<Delay>,
    poll_interval: Duration,
    send_buf: Bytes,
    recv_buf: Bytes,
    send_task: Option<Waker>,
    recv_queue: VecDeque<Bytes>,
}

impl<T, E> Client<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    T::Future: Unpin,
    E: Encryption,
{
    async fn client_handshake(mut self) -> Result<Self, ClientError<T::Error, E::Error>> {
        debug!("starting client handshake");
        if self.session.is_encrypted() {
            self = self.client_encryption_handshake().await?;
        } else {
            debug!("skipping encryption handshake");
        }
        let packet = self.session.build_outbound_syn_packet()?;
        let response = self.exchange(packet).await?;
        self.session.handle_inbound(response)?;
        Ok(self)
    }

    async fn client_encryption_handshake(self) -> Result<Self, ClientError<T::Error, E::Error>> {
        unimplemented!()
    }

    async fn exchange(
        &mut self,
        packet: LazyPacket,
    ) -> Result<LazyPacket, ClientError<T::Error, E::Error>> {
        self.transport
            .exchange(packet)
            .await
            .map_err(ClientError::Transport)
    }

    fn poll_exchange(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<bool, ClientError<T::Error, E::Error>>> {
        let exchange = self
            .exchange
            .as_mut()
            .expect("attempted to poll empty exchange");
        let packet = ready!(Pin::new(exchange).poll(cx)).map_err(ClientError::Transport)?;
        self.exchange = None;
        if let Some(chunk) = self.session.handle_inbound(packet)? {
            self.recv_queue_push(chunk);
            Poll::Ready(Ok(true))
        } else {
            Poll::Ready(Ok(false))
        }
    }

    fn start_exchange(&mut self, body: SessionBodyBytes) {
        assert!(self.exchange.is_none());
        let packet = self.session.build_packet(body);
        self.exchange = Some(self.transport.exchange(packet));
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
        let body = self.session.build_outbound_message(chunk);
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
            self.poll_delay = None;
            chunk
        })
    }

    fn recv_queue_push(&mut self, chunk: Bytes) {
        assert!(!self.is_recv_queue_full());
        self.recv_queue.push_back(chunk);
    }

    fn poll_recv(
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
        if self.poll_delay.is_none() {
            self.poll_delay = Some(Delay::new(self.poll_interval));
        }
        // We poll the delay to see if we should send an empty chunk.
        let poll_delay = self.poll_delay.as_mut().unwrap();
        match Pin::new(poll_delay).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.poll_delay = None;
                self.start_next_chunk_exchange()?;
                self.poll_recv(cx)
            }
        }
    }

    fn poll_send(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ClientError<T::Error, E::Error>>> {
        if self.is_recv_queue_full() {
            self.send_task = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // Flush the current send buffer out.
        ready!(self.poll_flush(cx))?;
        // Push the data into the send buffer.
        self.send_buf = buf.to_vec().into();
        // Setup the exchange.
        self.start_next_chunk_exchange()?;
        // Data is in the buffer!
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
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

    fn poll_close(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), ClientError<T::Error, E::Error>>> {
        unimplemented!()
    }
}

impl<T, E> AsyncRead for Client<T, E>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: Encryption + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        if this.recv_buf.is_empty() {
            this.recv_buf = ready!(this.poll_recv(cx))?;
        }
        let len = cmp::min(buf.len(), this.recv_buf.len());
        this.recv_buf.split_to(len).copy_to_slice(&mut buf[..len]);
        Poll::Ready(Ok(len))
    }
}

impl<T, E> AsyncWrite for Client<T, E>
where
    T: ExchangeTransport<LazyPacket> + Unpin,
    T::Future: Unpin,
    E: Encryption + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.get_mut().poll_send(cx, buf).map_err(Into::into)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.get_mut().poll_flush(cx).map_err(Into::into)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        self.get_mut().poll_close(cx).map_err(Into::into)
    }
}

///////////////////////////////////////////////////////////////////////////////

pub struct ClientBuilder {
    session_id: Option<u16>,
    session_name: Cow<'static, str>,
    initial_seq: Option<u16>,
    is_command: bool,
    poll_interval: Duration,
    prefer_peer_name: bool,
    recv_queue_size: usize,
}

impl ClientBuilder {
    pub fn session_id(mut self, sess_id: u16) -> Self {
        self.session_id = Some(sess_id);
        self
    }

    pub fn session_name<S>(mut self, sess_name: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        self.session_name = sess_name.into();
        self
    }

    pub fn initial_sequence(mut self, init_seq: u16) -> Self {
        self.initial_seq = Some(init_seq);
        self
    }

    pub fn is_command(mut self, value: bool) -> Self {
        self.is_command = value;
        self
    }

    pub fn prefer_peer_name(mut self, value: bool) -> Self {
        self.prefer_peer_name = value;
        self
    }

    pub async fn connect<T, E>(
        self,
        transport: T,
        encryption: E,
    ) -> Result<Client<T, E>, ClientError<T::Error, E::Error>>
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
    ) -> Result<Client<T>, ClientError<T::Error, Infallible>>
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
    ) -> Result<Client<T, E>, ClientError<T::Error, E::Error>>
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
            .initial_seq
            .map(Sequence)
            .unwrap_or_else(Sequence::random);
        let session = Session::new(
            session_id,
            session_name,
            init_seq,
            self.is_command,
            true,
            encryption,
            self.prefer_peer_name,
        );
        let client = Client {
            session,
            transport,
            exchange: None,
            send_task: None,
            exchange_sent: None,
            poll_delay: None,
            send_buf: Bytes::new(),
            recv_queue: VecDeque::with_capacity(self.recv_queue_size),
            recv_buf: Bytes::new(),
            poll_interval: self.poll_interval,
        };
        client.client_handshake().await
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            session_id: None,
            session_name: Cow::Borrowed(""),
            initial_seq: None,
            prefer_peer_name: false,
            is_command: false,
            recv_queue_size: 2,
            poll_interval: Duration::from_secs(5),
        }
    }
}
