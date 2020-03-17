use std::borrow::Cow;
use std::collections::VecDeque;

use super::*;

pub struct ConnectionBuilder {
    sess_id: Option<u16>,
    sess_name: Cow<'static, str>,
    init_seq: Option<u16>,
    is_command: bool,
    prefer_peer_name: bool,
    send_retry_max: usize,
    recv_retry_max: usize,
    recv_data_buf_size: usize,
    send_data_buf_size: usize,
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

    pub fn is_command(mut self, value: bool) -> Self {
        self.is_command = value;
        self
    }

    pub fn prefer_peer_name(mut self, value: bool) -> Self {
        self.prefer_peer_name = value;
        self
    }
    pub fn recv_data_buf_size(mut self, size: usize) -> Self {
        self.recv_data_buf_size = size;
        self
    }

    pub fn send_data_buf_size(mut self, size: usize) -> Self {
        self.send_data_buf_size = size;
        self
    }

    pub fn recv_retry_max(mut self, recv_retry_max: usize) -> Self {
        self.recv_retry_max = recv_retry_max;
        self
    }

    pub fn send_retry_max(mut self, send_retry_max: usize) -> Self {
        self.send_retry_max = send_retry_max;
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
        let is_command = self.is_command;
        let peer_seq = Sequence(0);
        let self_seq = Sequence(self.init_seq.unwrap_or_else(rand::random));
        let conn = Connection {
            is_client: true,
            state: ConnectionState::Uninit,
            sess_id,
            sess_name,
            transport,
            peer_seq,
            self_seq,
            is_command,
            encryption,
            prefer_peer_name: self.prefer_peer_name,
            send_retry_max: self.send_retry_max,
            recv_retry_max: self.recv_retry_max,
            recv_data_buf: VecDeque::with_capacity(self.recv_data_buf_size),
            send_data_buf: VecDeque::with_capacity(self.send_data_buf_size),
        };
        conn.client_handshake().await
    }
}

impl Default for ConnectionBuilder {
    fn default() -> Self {
        Self {
            sess_id: None,
            sess_name: Cow::Borrowed(""),
            init_seq: None,
            prefer_peer_name: false,
            is_command: false,
            send_retry_max: 2,
            recv_retry_max: 2,
            recv_data_buf_size: 64,
            send_data_buf_size: 64,
        }
    }
}
