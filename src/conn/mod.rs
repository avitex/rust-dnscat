pub mod enc;

use std::borrow::Cow;
use std::cmp;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use futures::io::{self, AsyncRead, AsyncWrite};

use crate::packet::*;
use crate::transport::*;

use self::enc::*;

///////////////////////////////////////////////////////////////////////////////

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
        conn.client_handshake(self.prefer_peer_name).await
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

#[derive(Debug)]
pub enum ConnectionError<TE, EE> {
    Closed,
    Timeout,
    EncryptionMismatch,
    Transport(TE),
    Encryption(EE),
    PacketDecode(PacketDecodeError),
    Unexpected(SupportedSessionBody),
}

#[derive(Debug)]
pub struct Connection<T, E = ()>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    sess_id: u16,
    sess_name: Option<Cow<'static, str>>,
    peer_seq: u16,
    self_seq: u16,
    command: bool,
    transport: T,
    encryption: Option<E>,
    send_buffer: BytesMut,
    recv_buffer: VecDeque<LazyPacket>,
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

    async fn client_encryption_handshake(
        &mut self,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        //let encryption = self.encryption.unwrap();
        Ok(())
    }

    async fn client_handshake(
        mut self,
        prefer_server_name: bool,
    ) -> Result<Self, ConnectionError<T::Error, E::Error>> {
        if self.is_encrypted() {
            self.client_encryption_handshake().await?;
        }
        let mut attempt = 1;
        let server_syn = loop {
            // Build our SYN
            let mut client_syn =
                SynBody::new(self.self_seq, self.is_command(), self.is_encrypted());
            if let Some(ref sess_name) = self.sess_name {
                client_syn.set_session_name(sess_name.clone());
            };
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
        if self.is_encrypted() != server_syn.flags().contains(PacketFlags::ENCRYPTED) {
            return Err(ConnectionError::EncryptionMismatch);
        }
        // Extract the server initial sequence
        self.peer_seq = server_syn.initial_sequence();
        // Handshake done!
        Ok(self)
    }

    fn peer_seq_add(&mut self, len: usize) -> u16 {
        assert!(len <= (u16::max_value() as usize));
        self.peer_seq = self.peer_seq.wrapping_add(len as u16);
        self.peer_seq
    }

    fn self_seq_add(&mut self, len: usize) -> u16 {
        assert!(len <= (u16::max_value() as usize));
        self.self_seq = self.self_seq.wrapping_add(len as u16);
        self.self_seq
    }

    fn max_message_data(&self) -> usize {
        let constant_size = Packet::<SessionBodyFrame<MsgBody>>::header_size()
            + SessionBodyFrame::<MsgBody>::header_size()
            + MsgBody::header_size();

        let constant_size = if let Some(ref encryption) = self.encryption {
            constant_size + encryption.additional_size()
        } else {
            constant_size
        };

        let absolute = self.transport.max_datagram_size() - constant_size;

        cmp::min(u16::max_value() as usize, absolute)
    }

    pub async fn send_data(
        &mut self,
        mut data: Bytes,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        'send_main: loop {
            if data.is_empty() {
                return Ok(());
            }
            let data_part_size = cmp::min(data.len(), self.max_message_data());
            let data_chuck = data.split_to(data_part_size);
            'send_chunk: loop {
                self.send_data_chunk(data_chuck.clone()).await?;
                match self.recv_packet().await? {
                    SupportedSessionBody::Msg(server_msg) => {
                        let bytes_acked = server_msg.ack().saturating_sub(self.self_seq) as usize;
                        if bytes_acked == data_part_size {
                            self.self_seq_add(bytes_acked);
                            self.peer_seq_add(server_msg.data().len());
                            dbg!(server_msg);
                            continue 'send_main;
                        } else {
                            continue 'send_chunk;
                        }
                    }
                    unexpected_body => return Err(ConnectionError::Unexpected(unexpected_body)),
                }
            }
        }
    }

    async fn send_data_chunk(
        &mut self,
        data_chuck: Bytes,
    ) -> Result<(), ConnectionError<T::Error, E::Error>> {
        let mut msg_body = MsgBody::new(self.self_seq, self.peer_seq);
        msg_body.set_data(data_chuck);
        self.send_packet(msg_body).await
    }

    async fn send_packet<B>(&mut self, body: B) -> Result<(), ConnectionError<T::Error, E::Error>>
    where
        B: Into<SupportedSessionBody>,
    {
        let packet_id = rand::random();
        let session_body = body.into();
        let packet_kind = session_body.packet_kind();
        session_body.encode(&mut self.send_buffer);
        let session_body_bytes = if let Some(ref mut encryption) = self.encryption {
            encryption.encrypt(&mut self.send_buffer)
        } else {
            self.send_buffer.to_bytes()
        };
        let session_body = SessionBodyBytes::new(packet_kind, session_body_bytes);
        let packet_body = SupportedBody::Session(SessionBodyFrame::new(self.sess_id, session_body));
        let packet = Packet::new(packet_id, packet_body);
        let response = self
            .transport
            .exchange(packet)
            .await
            .map_err(ConnectionError::Transport)?;
        self.recv_buffer.push_back(response);
        Ok(())
    }

    async fn recv_packet(
        &mut self,
    ) -> Result<SupportedSessionBody, ConnectionError<T::Error, E::Error>> {
        let session_frame = loop {
            let session_frame_opt = loop {
                if let Some(packet) = self.recv_buffer.pop_front() {
                    if packet.kind().is_session_framed() {
                        break packet.into_body().into_session_frame();
                    }
                } else {
                    break None;
                }
            };
            if let Some(session_frame) = session_frame_opt {
                break session_frame;
            } else {
                dbg!("sending empty chunk");
                self.send_data_chunk(Bytes::new()).await?;
            }
        };
        if self.sess_id != session_frame.session_id() {
            unimplemented!()
        }
        let session_body = session_frame.into_body();
        let packet_kind = session_body.packet_kind();
        let mut session_body_bytes = session_body.into_bytes();
        let mut session_body_bytes = if let Some(ref mut encryption) = self.encryption {
            encryption.decrypt(&mut session_body_bytes)
        } else {
            session_body_bytes
        };
        SupportedSessionBody::decode_kind(packet_kind, &mut session_body_bytes)
            .map_err(ConnectionError::PacketDecode)
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        unimplemented!()
    }
}
