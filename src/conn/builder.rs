use std::borrow::Cow;
use std::collections::VecDeque;
use std::time::Duration;

use bytes::BytesMut;

use super::handshake::*;
use super::{Connection, ConnectionEncryption, ConnectionError, ExchangeTransport, LazyPacket};

pub struct ConnectionBuilder {
    sess_id: Option<u16>,
    sess_name: Cow<'static, str>,
    init_seq: Option<u16>,
    command: bool,
    recv_timeout: Duration,
    recv_max_retry: usize,
    prefer_peer_name: bool,
}

impl ConnectionBuilder {
    pub fn session_id(mut self, sess_id: u16) -> Self {
        self.sess_id = Some(sess_id);
        self
    }

    pub fn session_name<S>(mut self, sess_name: S) -> Self
    where
        S: Into<Cow<'static, str>>,
    {
        self.sess_name = sess_name.into();
        self
    }

    pub fn initial_sequence(mut self, init_seq: u16) -> Self {
        self.init_seq = Some(init_seq);
        self
    }

    pub fn command(mut self, value: bool) -> Self {
        self.command = value;
        self
    }

    pub fn prefer_peer_name(mut self, value: bool) -> Self {
        self.prefer_peer_name = value;
        self
    }

    pub fn recv_max_retry(mut self, recv_max_retry: usize) -> Self {
        self.recv_max_retry = recv_max_retry;
        self
    }

    pub fn recv_timeout(mut self, recv_timeout: Duration) -> Self {
        self.recv_timeout = recv_timeout;
        self
    }

    pub async fn connect<T, E>(
        self,
        transport: T,
        encryption: E,
    ) -> Result<Connection<T, E>, ConnectionError<T::Error, E::Error>>
    where
        T: ExchangeTransport<LazyPacket>,
        E: ConnectionEncryption,
    {
        self.generic_connect(transport, Some(encryption)).await
    }

    pub async fn connect_insecure<T>(
        self,
        transport: T,
    ) -> Result<Connection<T>, ConnectionError<T::Error, ()>>
    where
        T: ExchangeTransport<LazyPacket>,
    {
        self.generic_connect(transport, None).await
    }

    async fn generic_connect<T, E>(
        self,
        transport: T,
        encryption: Option<E>,
    ) -> Result<Connection<T, E>, ConnectionError<T::Error, E::Error>>
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
        let command = self.command;
        let peer_seq = 0;
        let self_seq = self.init_seq.unwrap_or_else(rand::random);
        let conn = Connection {
            sess_id,
            sess_name,
            transport,
            peer_seq,
            self_seq,
            command,
            encryption,
            send_buffer: BytesMut::new(),
            recv_buffer: VecDeque::new(),
            recv_timeout: self.recv_timeout,
            recv_max_retry: self.recv_max_retry,
        };
        client_handshake(conn, self.prefer_peer_name).await
    }
}

impl Default for ConnectionBuilder {
    fn default() -> Self {
        Self {
            sess_id: None,
            sess_name: Cow::Borrowed(""),
            init_seq: None,
            command: false,
            recv_max_retry: 2,
            recv_timeout: Duration::from_secs(2),
            prefer_peer_name: false,
        }
    }
}
