mod builder;
mod exchange;

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
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
use crate::packet::{LazyPacket, Packet, PacketKind, SessionBodyBytes};
use crate::session::{Session, SessionError};
use crate::transport::ExchangeTransport;

use self::exchange::Exchange;

pub use self::builder::ClientBuilder;

#[derive(Debug, Fail)]
pub enum ClientError<T: Fail> {
    #[fail(display = "Transport error: {}", _0)]
    Transport(T),
    #[fail(display = "Session error: {}", _0)]
    Session(SessionError),
    #[fail(display = "Unexpected packet kind `{:?}`", _0)]
    UnexpectedKind(PacketKind),
}

impl<T: Fail> From<SessionError> for ClientError<T> {
    fn from(err: SessionError) -> Self {
        ClientError::Session(err)
    }
}

impl<T: Fail> From<ClientError<T>> for io::Error {
    fn from(err: ClientError<T>) -> Self {
        // TODO: better?
        io::Error::new(io::ErrorKind::Other, err.compat())
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
struct ClientOpts {
    min_delay: Duration,
    max_delay: Duration,
    random_delay: bool,
    retransmit_backoff: bool,
}

#[derive(Debug)]
pub struct Client<T, E = (), R = ThreadRng>
where
    T: ExchangeTransport<LazyPacket>,
{
    transport: T,
    session: Session<E, R>,
    options: ClientOpts,
    exchange: Option<Exchange<T::Future>>,
    poll_delay: Option<Delay>,
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
    pub fn session(&self) -> &Session<E, R> {
        &self.session
    }

    async fn client_handshake(mut self) -> Result<Self, ClientError<T::Error>> {
        debug!("starting client handshake");

        if self.session.is_encrypted() {
            self = self.client_encryption_handshake().await?;
        } else {
            debug!("skipping encryption handshake");
        }

        let packet = self.session.build_syn()?;
        self.basic_exchange(packet).await?;

        Ok(self)
    }

    async fn client_encryption_handshake(mut self) -> Result<Self, ClientError<T::Error>> {
        debug!("starting encryption handshake");

        let packet = self.session.build_enc_init()?;
        self.basic_exchange(packet).await?;

        debug!("authenticating session...");

        let packet = self.session.build_enc_auth()?;
        self.basic_exchange(packet).await?;

        debug!("authenticated");

        Ok(self)
    }

    async fn basic_exchange(
        &mut self,
        packet: Packet<SessionBodyBytes>,
    ) -> Result<(), ClientError<T::Error>> {
        self.start_exchange(packet);
        future::poll_fn(|cx| self.poll_exchange(cx)).await?;
        Ok(())
    }

    fn poll_exchange(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, ClientError<T::Error>>> {
        let exchange = self
            .exchange
            .as_mut()
            .expect("attempted to poll empty exchange");

        let result = ready!(exchange.poll(
            cx,
            &mut self.session,
            &mut self.transport,
            &mut self.options,
        ));

        self.exchange = None;

        match result {
            Ok(Some(chunk)) => {
                self.recv_queue_push(chunk);
                Poll::Ready(Ok(true))
            }
            Ok(None) => Poll::Ready(Ok(false)),
            // TODO: destroy session if fatal?
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn start_exchange(&mut self, packet: Packet<SessionBodyBytes>) {
        assert!(self.exchange.is_none());
        self.exchange = Some(Exchange::new(
            packet,
            &mut self.session,
            &mut self.transport,
            &self.options,
        ));
    }

    fn start_next_chunk_exchange(&mut self) -> Result<(), ClientError<T::Error>> {
        let chunk = if self.send_buf.is_empty() {
            debug!("sending empty chunk");
            Bytes::new()
        } else {
            let budget = self.transport.max_datagram_size();
            let chunk_len = self.session.calc_chunk_len(self.send_buf.len(), budget);
            self.send_buf.split_to(chunk_len as usize)
        };
        let packet = self.session.build_msg(chunk)?;
        self.start_exchange(packet);
        Ok(())
    }

    fn is_recv_queue_full(&self) -> bool {
        self.recv_queue.len() == self.recv_queue.capacity()
    }

    fn recv_queue_pop(&mut self) -> Option<Bytes> {
        self.recv_queue.pop_front().map(|chunk| {
            // Capacity to recv again!
            if let Some(waker) = self.send_task.take() {
                waker.wake();
            }
            self.poll_delay = None;
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
    ) -> Poll<Result<usize, ClientError<T::Error>>> {
        if self.recv_buf.is_empty() {
            self.recv_buf = ready!(self.do_poll_recv(cx))?;
        }
        let len = cmp::min(buf.len(), self.recv_buf.len());
        self.recv_buf.split_to(len).copy_to_slice(&mut buf[..len]);
        Poll::Ready(Ok(len))
    }

    fn do_poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bytes, ClientError<T::Error>>> {
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
            self.poll_delay = Some(Delay::new(self.options.max_delay));
        }
        // We poll the delay to see if we should send an empty chunk.
        let poll_delay = self.poll_delay.as_mut().unwrap();
        match Pin::new(poll_delay).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(()) => {
                self.poll_delay = None;
                self.start_next_chunk_exchange()?;
                self.do_poll_recv(cx)
            }
        }
    }

    fn do_poll_write(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, ClientError<T::Error>>> {
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

    fn do_poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ClientError<T::Error>>> {
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

    fn do_poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ClientError<T::Error>>> {
        if self.exchange.is_none() && self.session.is_closed() {
            return Poll::Ready(Ok(()));
        }
        // If we get any errors while closing, just ignore them.
        if let Err(err) = ready!(self.do_poll_flush(cx)) {
            warn!("ignored error while closing {}", err);
        }
        match self.session.build_fin("") {
            Ok(packet) => {
                self.start_exchange(packet);
                self.poll_exchange(cx).map_ok(drop)
            }
            Err(err) => {
                warn!("ignored error while closing {}", err);
                Poll::Ready(Ok(()))
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

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
