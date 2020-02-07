use log::debug;

use super::*;

pub async fn client_handshake<T, E>(
    mut conn: Connection<T, E>,
    prefer_server_name: bool,
) -> Result<Connection<T, E>, ConnectionError<T::Error, E::Error>>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    debug!("starting client handshake");
    if conn.is_encrypted() {
        conn = client_encryption_handshake(conn).await?;
    } else {
        debug!("skipping encryption handshake");
    }
    let mut attempt = 1;
    let server_syn = loop {
        // Build our SYN
        let mut client_syn = SynBody::new(conn.self_seq, conn.is_command(), conn.is_encrypted());
        if let Some(ref sess_name) = conn.sess_name {
            client_syn.set_session_name(sess_name.clone());
        };
        // Send our SYN
        conn.send_session_body(client_syn).await?;
        // Recv server SYN
        match conn.recv_session_body().await {
            Ok(server_packet) => match server_packet {
                SupportedSessionBody::Syn(server_syn) => break server_syn,
                SupportedSessionBody::Fin(server_fin) => {
                    return Err(ConnectionError::PeerAbort {
                        reason: server_fin.into_reason(),
                    })
                }
                body => return Err(ConnectionError::UnexpectedPacketKind(body.packet_kind())),
            },
            Err(ConnectionError::Timeout) => {
                if attempt == conn.recv_retry_max {
                    return Err(ConnectionError::Timeout);
                }
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    };
    // Extract the server session name if we should and can.
    if (conn.sess_name.is_none() || prefer_server_name) && server_syn.session_name().is_some() {
        conn.sess_name = server_syn
            .session_name()
            .map(ToString::to_string)
            .map(Into::into);
    }
    // Extract if the server indicates this is a command session.
    conn.is_command = server_syn.is_command();
    // Check the encrypted flags match.
    if conn.is_encrypted() != server_syn.is_encrypted() {
        return Err(ConnectionError::EncryptionMismatch);
    }
    // Extract the server initial sequence
    conn.peer_seq = server_syn.initial_sequence();
    // Handshake done!
    Ok(conn)
}

async fn client_encryption_handshake<T, E>(
    _conn: Connection<T, E>,
) -> Result<Connection<T, E>, ConnectionError<T::Error, E::Error>>
where
    T: ExchangeTransport<LazyPacket>,
    E: ConnectionEncryption,
{
    // TODO: impl encryption handshake.
    // let encryption = self.encryption.unwrap();
    unimplemented!()
}
