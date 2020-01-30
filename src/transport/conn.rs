use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use futures::channel::mpsc;
use futures::io::{self, AsyncRead, AsyncWrite};
use futures::stream::StreamExt;
use futures::future;
use futures_timer::Delay;

use crate::packet::*;
use crate::transport::DatagramTransport;

type DatagramSender<D> = mpsc::Sender<D>;
type DatagramReceiver<D> = mpsc::Receiver<D>;

struct ConnectionInner<T>
where
    T: DatagramTransport,
{
    transport: T,
    sessions: HashMap<u16, DatagramSender<T::Datagram>>,
}

pub struct Connection<T>
where
    T: DatagramTransport,
{
    inner: Arc<Mutex<ConnectionInner<T>>>,
}

impl<T> Connection<T>
where
    T: DatagramTransport<Datagram = Packet>,
{
    pub fn connect(transport: T) -> (impl Future<Output = ()>, Self) {
        let inner = ConnectionInner {
            transport,
            sessions: HashMap::new(),
        };
        let this = Self {
            inner: Arc::new(Mutex::new(inner)),
        };
        (Self::run_exchanger(this.clone()), this)
    }

    async fn run_exchanger(self) {
        loop {}
    }

    fn lock_inner(&self) -> MutexGuard<ConnectionInner<T>> {
        self.inner.lock().expect("connection mutex poisoned")
    }

    fn register_session_channel(&self, inbound_tx: DatagramSender<T::Datagram>) -> u16 {
        let session_id = 0;
        let mut inner = self.lock_inner();
        inner.sessions.insert(session_id, inbound_tx);
        session_id
    }
}

impl<T> Clone for Connection<T>
where
    T: DatagramTransport,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

pub trait SessionEncryption {}

impl SessionEncryption for () {}

///////////////////////////////////////////////////////////////////////////////

pub struct SessionBuilder {
    name: Cow<'static, str>,
    init_seq: Option<u16>,
    datagram_cap: usize,
    recv_timeout: Duration,
    recv_max_retry: usize,
    prefer_server_name: bool,
}

impl SessionBuilder {
    pub fn name<S>(&mut self, name: S) -> &mut Self
    where
        S: Into<Cow<'static, str>>,
    {
        self.name = name.into();
        self
    }

    pub fn init_seq(&mut self, init_seq: u16) -> &mut Self {
        self.init_seq = Some(init_seq);
        self
    }

    pub fn datagram_capacity(&mut self, cap: usize) -> &mut Self {
        self.datagram_cap = cap;
        self
    }

    pub fn prefer_server_name(&mut self, value: bool) -> &mut Self {
        self.prefer_server_name = value;
        self
    }

    pub fn recv_max_retry(&mut self, recv_max_retry: usize) -> &mut Self {
        self.recv_max_retry = recv_max_retry;
        self
    }

    pub fn recv_timeout(&mut self, recv_timeout: Duration) -> &mut Self {
        self.recv_timeout = recv_timeout;
        self
    }

    pub async fn connect<T, E>(
        self,
        conn: &Connection<T>,
        encryption: E,
    ) -> Result<Session<T, E>, SessionError>
    where
        T: DatagramTransport<Datagram = Packet>,
        E: SessionEncryption,
    {
        self.generic_connect(conn, Some(encryption)).await
    }

    pub async fn connect_insecure<T>(self, conn: &Connection<T>) -> Result<Session<T>, SessionError>
    where
        T: DatagramTransport<Datagram = Packet>,
    {
        self.generic_connect(conn, None).await
    }

    async fn generic_connect<T, E>(
        self,
        conn: &Connection<T>,
        encryption: Option<E>,
    ) -> Result<Session<T, E>, SessionError>
    where
        T: DatagramTransport<Datagram = Packet>,
        E: SessionEncryption,
    {
        let (inbound_tx, inbound_rx) = mpsc::channel(self.datagram_cap);
        let session_id = conn.register_session_channel(inbound_tx);
        let session_name = if self.name.is_empty() {
            None
        } else {
            Some(self.name)
        };
        let data_seq = self.init_seq.unwrap_or_else(rand::random);
        let session = Session {
            id: session_id,
            name: session_name,
            conn: conn.clone(),
            data_ack: 0,
            data_seq,
            inbound_rx,
            command: false,
            encryption,
            recv_timeout: self.recv_timeout,
            recv_max_retry: self.recv_max_retry,
        };
        session.handshake(self.prefer_server_name).await
    }
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self {
            name: Cow::Borrowed(""),
            init_seq: None,
            datagram_cap: 16,
            recv_max_retry: 2,
            recv_timeout: Duration::from_secs(2),
            prefer_server_name: false,
        }
    }
}

pub enum SessionError {
    Closed,
    Timeout,
    EncryptionMismatch,
    PacketUnexpected(Packet),
}

pub struct Session<T, E = ()>
where
    T: DatagramTransport,
    E: SessionEncryption,
{
    id: u16,
    conn: Connection<T>,
    name: Option<Cow<'static, str>>,
    data_ack: u16,
    data_seq: u16,
    command: bool,
    encryption: Option<E>,
    recv_timeout: Duration,
    recv_max_retry: usize,
    inbound_rx: DatagramReceiver<T::Datagram>,
}

impl<T, E> Session<T, E>
where
    T: DatagramTransport<Datagram = Packet>,
    E: SessionEncryption,
{
    pub fn is_command(&self) -> bool {
        self.command
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    async fn handshake(mut self, prefer_server_name: bool) -> Result<Self, SessionError> {
        let mut packet_flags = PacketFlags::default();
        if self.is_command() {
            packet_flags.insert(PacketFlags::COMMAND);
        }
        if self.is_encrypted() {
            packet_flags.insert(PacketFlags::ENCRYPTED);
        }
        let mut attempt = 1;
        let server_syn = loop {
            // Build our SYN
            let client_syn =
                SynBody::new(self.id, self.data_seq, packet_flags, self.name.clone());
            // Send our SYN
            self.send_packet(client_syn).await?;
            // Recv server SYN
            match self.recv_packet().await {
                Ok(server_packet) => match server_packet {
                    SupportedSessionBody::Syn(server_syn)) => break server_syn,
                    (id, body) => {
                        let packet = Packet::new(id, body);
                        return Err(SessionError::PacketUnexpected(packet));
                    }
                },
                Err(SessionError::Timeout) => {
                    if attempt == self.recv_max_retry {
                        return Err(SessionError::Timeout);
                    }
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        };
        // Extract the server session name if we should and can.
        if (self.name.is_none() || prefer_server_name) && server_syn.session_name().is_some() {
            self.name = server_syn
                .session_name()
                .map(ToString::to_string)
                .map(Into::into);
        }
        // Extract if the server indicates this is a command session.
        self.command = server_syn.flags().contains(PacketFlags::COMMAND);
        // Check the encrypted flags match.
        if self.is_encrypted() == server_syn.flags().contains(PacketFlags::ENCRYPTED) {
            return Err(SessionError::EncryptionMismatch);
        }
        // Extract the server initial sequence
        self.data_ack = server_syn.initial_sequence();
        if self.is_encrypted() {
            
        }
        // Handshake done!
        Ok(self)
    }

    async fn send_packet<B>(&self, body: B) -> Result<(), SessionError>
    where
        B: Into<SupportedSessionBody>,
    {
        let packet = Packet::new(rand::random::<u16>(), SupportedBody::Session(SessionBodyFrame::new(self.id, body.into())));
        Ok(())
    }

    async fn recv_packet(&mut self) -> Result<Packet, SessionError> {
        match future::select(Delay::new(self.recv_timeout), self.inbound_rx.next()).await {
            future::Either::Left(((), _)) => Err(SessionError::Timeout),
            future::Either::Right((packet_opt, _)) => packet_opt.ok_or(SessionError::Closed),
        }
    }

    // let mut poll_waker = Delay::new(self.poll_interval);
    // let mut poll_waiting = false;
}

impl<T, E> AsyncRead for Session<T, E>
where
    T: DatagramTransport<Datagram = Packet>,
    E: SessionEncryption,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        unimplemented!()
    }
}

impl<T, E> AsyncWrite for Session<T, E>
where
    T: DatagramTransport<Datagram = Packet>,
    E: SessionEncryption,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        unimplemented!()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unimplemented!()
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unimplemented!()
    }
}
