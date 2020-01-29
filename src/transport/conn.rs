use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::BytesMut;
use futures::channel::mpsc;
use futures::io::{self, AsyncRead, AsyncWrite};
use futures::Stream;
use futures_timer::Delay;
use tokio::runtime::Runtime;
use tokio::task;

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

pub struct SessionBuilder {
    name: Cow<'static, str>,
    init_seq: u16,
    datagram_cap: usize,
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
        self.init_seq = init_seq;
        self
    }

    pub fn datagram_capacity(&mut self, cap: usize) -> &mut Self {
        self.datagram_cap = cap;
        self
    }

    pub async fn connect<T>(self, conn: &Connection<T>) -> Session<T>
    where
        T: DatagramTransport<Datagram = Packet>,
    {
        let (inbound_tx, inbound_rx) = mpsc::channel(self.datagram_cap);
        let session_id = conn.register_session_channel(inbound_tx);
        Session {
            id: session_id,
            name: self.name,
            conn: conn.clone(),
            packet_ack: 0,
            packet_seq: self.init_seq,
            inbound_rx,
        }
    }
}

impl Default for SessionBuilder {
    fn default() -> Self {
        Self {
            name: Cow::Borrowed(""),
            init_seq: 0,
            datagram_cap: 16,
        }
    }
}

pub struct Session<T>
where
    T: DatagramTransport,
{
    id: u16,
    conn: Connection<T>,
    name: Cow<'static, str>,
    packet_ack: u16,
    packet_seq: u16,
    inbound_rx: DatagramReceiver<T::Datagram>,
}

impl<T> Session<T>
where
    T: DatagramTransport,
{
    fn new_packet<B>(&self, body: B) -> Packet
    where
        B: Into<PacketBody>,
    {
        Packet::new(rand::random::<u16>(), body)
    }

    // let mut poll_waker = Delay::new(self.poll_interval);
    // let mut poll_waiting = false;
    // async fn run_handleshake(&self) -> Result<(), ()> {
    //     self.new_packet(SynPacket::new())
    // }
}

impl<T> AsyncRead for Session<T>
where
    T: DatagramTransport<Datagram = Packet>,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        unimplemented!()
    }
}

impl<T> AsyncWrite for Session<T>
where
    T: DatagramTransport<Datagram = Packet>,
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
