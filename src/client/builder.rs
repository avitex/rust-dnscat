use std::borrow::Cow;
use std::collections::VecDeque;
use std::time::Duration;

use bytes::Bytes;
use rand::prelude::{Rng, ThreadRng};

use crate::encryption::{Encryption, NoEncryption};
use crate::packet::{LazyPacket, Sequence};
use crate::session::{Session, SessionRole, SessionStage};
use crate::transport::ExchangeTransport;

use super::{Client, ClientError, ClientOpts};

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

    pub fn command(mut self, value: bool) -> Self {
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
    ) -> Result<Client<T, E, R>, ClientError<T::Error>>
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
    ) -> Result<Client<T, NoEncryption, R>, ClientError<T::Error>>
    where
        T: ExchangeTransport<LazyPacket>,
        T::Future: Unpin,
    {
        self.generic_connect(transport, None).await
    }

    async fn generic_connect<T, E>(
        mut self,
        transport: T,
        encryption: Option<E>,
    ) -> Result<Client<T, E, R>, ClientError<T::Error>>
    where
        T: ExchangeTransport<LazyPacket>,
        T::Future: Unpin,
        E: Encryption,
    {
        assert!(
            self.min_delay <= self.max_delay,
            "min delay should be equal to or less than max delay"
        );
        let init_seq = self.initial_sequence.unwrap_or_else(|| self.random.gen());
        let session_id = self.session_id.unwrap_or_else(|| self.random.gen());
        let session_name = if self.session_name.is_empty() {
            None
        } else {
            Some(self.session_name)
        };
        let session = Session {
            id: session_id,
            name: session_name,
            random: self.random,
            self_seq: Sequence(init_seq),
            self_seq_pending: Sequence(init_seq),
            peer_seq: Sequence(0),
            is_command: self.is_command,
            role: SessionRole::Client,
            encryption,
            stage: SessionStage::Uninit,
            prefer_peer_name: self.prefer_server_name,
            packet_trace: self.packet_trace,
            close_reason: None,
            last_exchange: None,
            exchange_attempt: None,
            max_exchange_attempts: self.max_retransmits,
        };
        let options = ClientOpts {
            retransmit_backoff: self.retransmit_backoff,
            random_delay: self.random_delay,
            min_delay: self.min_delay,
            max_delay: self.max_delay,
        };
        let client = Client {
            session,
            options,
            transport,
            exchange: None,
            send_task: None,
            poll_delay: None,
            send_buf: Bytes::new(),
            recv_queue: VecDeque::with_capacity(self.recv_queue_size),
            recv_buf: Bytes::new(),
        };
        client.client_handshake().await
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::default_with_random(ThreadRng::default())
    }
}
