pub mod enc;

use std::borrow::Cow;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use futures::future;
use futures::io::{self, AsyncRead, AsyncWrite};
use futures::stream::StreamExt;
use futures_timer::Delay;

use crate::packet::{
    LazyPacket, Packet, PacketFlags, SessionBodyBytes, SessionBodyFrame, SupportedBody,
    SupportedSessionBody, SynBody,
};
use crate::transport::ExchangeTransport;

use self::enc::ConnectionEncryption;

///////////////////////////////////////////////////////////////////////////////

pub struct ConnectionBuilder {
    sess_id: Option<u16>,
    sess_name: Cow<'static, str>,
    init_seq: Option<u16>,
    recv_timeout: Duration,
    recv_max_retry: usize,
    prefer_server_name: bool,
}

impl ConnectionBuilder {
    pub fn session_id(&mut self, sess_id: u16) -> &mut Self {
        self.sess_id = Some(sess_id);
        self
    }

    pub fn session_name<S>(&mut self, sess_name: S) -> &mut Self
    where
        S: Into<Cow<'static, str>>,
    {
        self.sess_name = sess_name.into();
        self
    }

    pub fn initial_sequence(&mut self, init_seq: u16) -> &mut Self {
        self.init_seq = Some(init_seq);
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
        transport: T,
        encryption: E,
    ) -> Result<Connection<T, E>, ConnectionError>
    where
        T: ExchangeTransport<LazyPacket>,
        E: ConnectionEncryption,
    {
        self.generic_connect(transport, Some(encryption)).await
    }

    pub async fn connect_insecure<T>(self, transport: T) -> Result<Connection<T>, ConnectionError>
    where
        T: ExchangeTransport<LazyPacket>,
    {
        self.generic_connect(transport, None).await
    }

    async fn generic_connect<T, E>(
        self,
        transport: T,
        encryption: Option<E>,
    ) -> Result<Connection<T, E>, ConnectionError>
    where
        T: ExchangeTransport<LazyPacket>,
        E: ConnectionEncryption,
    {
        let sess_id = self.sess_id.unwrap_or_else(rand::random);
        let sess_name = if self.sess_name.is_empty() {
            None
        } else {
            Some(self.sess_name)
        };
        let command = false;
        let data_ack = 0;
        let data_seq = self.init_seq.unwrap_or_else(rand::random);
        let conn = Connection {
            sess_id,
            sess_name,
            transport,
            data_ack,
            data_seq,
            command,
            encryption,
            recv_timeout: self.recv_timeout,
            recv_max_retry: self.recv_max_retry,
        };
        conn.handshake(self.prefer_server_name).await
    }
}

impl Default for ConnectionBuilder {
    fn default() -> Self {
        Self {
            sess_id: None,
            sess_name: Cow::Borrowed(""),
            init_seq: None,
            recv_max_retry: 2,
            recv_timeout: Duration::from_secs(2),
            prefer_server_name: false,
        }
    }
}

pub enum ConnectionError {
    Closed,
    Timeout,
    EncryptionMismatch,
    Unexpected(SupportedSessionBody),
}

pub struct Connection<T, E = ()>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    sess_id: u16,
    sess_name: Option<Cow<'static, str>>,
    data_ack: u16,
    data_seq: u16,
    command: bool,
    transport: T,
    encryption: Option<E>,
    recv_timeout: Duration,
    recv_max_retry: usize,
}

impl<T, E> Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    pub fn is_command(&self) -> bool {
        self.command
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    async fn handshake(mut self, prefer_server_name: bool) -> Result<Self, ConnectionError> {
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
            let client_syn = SynBody::new(self.data_seq, packet_flags, self.sess_name.clone());
            // Send our SYN
            self.send_packet(client_syn).await?;
            // Recv server SYN
            match self.recv_packet().await {
                Ok(server_packet) => match server_packet {
                    SupportedSessionBody::Syn(server_syn) => break server_syn,
                    body => return Err(ConnectionError::Unexpected(body)),
                },
                Err(ConnectionError::Timeout) => {
                    if attempt == self.recv_max_retry {
                        return Err(ConnectionError::Timeout);
                    }
                    attempt += 1;
                }
                Err(err) => return Err(err),
            }
        };
        // Extract the server session name if we should and can.
        if (self.sess_name.is_none() || prefer_server_name) && server_syn.session_name().is_some() {
            self.sess_name = server_syn
                .session_name()
                .map(ToString::to_string)
                .map(Into::into);
        }
        // Extract if the server indicates this is a command session.
        self.command = server_syn.flags().contains(PacketFlags::COMMAND);
        // Check the encrypted flags match.
        if self.is_encrypted() == server_syn.flags().contains(PacketFlags::ENCRYPTED) {
            return Err(ConnectionError::EncryptionMismatch);
        }
        // Extract the server initial sequence
        self.data_ack = server_syn.initial_sequence();
        if self.is_encrypted() {}
        // Handshake done!
        Ok(self)
    }

    async fn send_packet<B>(&self, body: B) -> Result<(), ConnectionError>
    where
        B: Into<SupportedSessionBody>,
    {
        unimplemented!()
        // let packet_id = rand::random();
        // let packet_body = SupportedBody::Session(SessionBodyFrame::new(self.sess_id, body.into()));
        // let packet = Packet::new(packet_id, packet_body);
        // Ok(())
    }

    async fn recv_packet(&mut self) -> Result<SupportedSessionBody, ConnectionError> {
        unimplemented!()
        // match future::select(Delay::new(self.recv_timeout), self.transport.next()).await {
        //     future::Either::Left(((), _)) => Err(ConnectionError::Timeout),
        //     future::Either::Right((packet_opt, _)) => packet_opt.ok_or(ConnectionError::Closed),
        // }
    }
}

impl<T, E> AsyncRead for Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        unimplemented!()
    }
}

impl<T, E> AsyncWrite for Connection<T, E>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
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
