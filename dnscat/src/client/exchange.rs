use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::ready;
use futures_timer::Delay;
use log::{trace, warn};
use rand::Rng;

use crate::encryption::Encryption;
use crate::packet::{LazyPacket, Packet, SessionBodyBytes};
use crate::session::Session;
use crate::transport::Transport;

use super::{ClientError, ClientOpts};

#[derive(Debug)]
pub(super) struct Exchange {
    delay: Option<Delay>,
    packet: Packet<SessionBodyBytes>,
    transmit: bool,
}

impl Exchange {
    pub(super) fn new<E, R>(
        packet: Packet<SessionBodyBytes>,
        session: &mut Session<E, R>,
        options: &ClientOpts,
    ) -> Self
    where
        E: Encryption,
        R: Rng,
    {
        Self {
            packet,
            transmit: true,
            delay: transmit_delay(options, session),
        }
    }

    pub(super) fn poll<T, E, R>(
        &mut self,
        cx: &mut Context<'_>,
        session: &mut Session<E, R>,
        transport: &mut T,
        options: &ClientOpts,
    ) -> Poll<Result<Option<Bytes>, ClientError<T::Error>>>
    where
        T: Transport<LazyPacket>,
        E: Encryption,
        R: Rng,
    {
        let exchange_attempt = session.exchange_attempt().expect("should be exchanging");

        if let Some(ref mut delay_fut) = self.delay {
            ready!(Pin::new(delay_fut).poll(cx));
            self.delay = None;
            if exchange_attempt > 1 {
                trace!("preparing retransmit");
                session.prepare_retransmit(&mut self.packet)?;
            }
        }

        let result = if self.transmit {
            trace!("polling exchange send");
            ready!(transport.poll_send(cx, self.packet.clone().translate()))
        } else {
            Ok(())
        };

        let result = match result {
            Ok(()) => {
                self.transmit = false;
                trace!("polling exchange recv");
                match ready!(transport.poll_recv(cx)) {
                    Err(err) => Err(ClientError::Transport(err)),
                    Ok(packet) => match (packet.kind(), packet.into_session()) {
                        (_, Some(packet)) => session.handle_inbound(packet).map_err(Into::into),
                        (kind, None) => Err(ClientError::UnexpectedKind(kind)),
                    },
                }
            }
            Err(err) => Err(ClientError::Transport(err)),
        };

        match result {
            Ok(chunk_opt) => Poll::Ready(Ok(chunk_opt)),
            Err(err) if session.is_closed() => {
                return Poll::Ready(Err(err));
            }
            Err(err) => {
                let delay_dur = retransmit_delay(options, session, exchange_attempt);
                warn!(
                    "retrying exchange after {} secs after {}",
                    delay_dur.as_secs(),
                    err
                );
                self.delay = Some(Delay::new(delay_dur));
                self.transmit = true;
                return self.poll(cx, session, transport, options);
            }
        }
    }
}

fn retransmit_delay<E, R>(
    opts: &ClientOpts,
    session: &mut Session<E, R>,
    attempt: usize,
) -> Duration
where
    R: Rng,
    E: Encryption,
{
    if opts.random_delay {
        session.random().gen_range(opts.min_delay, opts.max_delay)
    } else if opts.retransmit_backoff {
        Duration::from_secs(2u64.pow(attempt as u32))
    } else {
        opts.min_delay
    }
}

fn transmit_delay<E, R>(opts: &ClientOpts, session: &mut Session<E, R>) -> Option<Delay>
where
    R: Rng,
    E: Encryption,
{
    let dur_since_last = session
        .last_exchange()
        .map(|last| Instant::now().duration_since(last))
        .unwrap_or(Duration::from_secs(0));

    let dur = if opts.random_delay {
        session
            .random()
            .gen_range(opts.min_delay, opts.max_delay)
            .checked_sub(dur_since_last)
    } else if dur_since_last < opts.min_delay {
        Some(opts.min_delay - dur_since_last)
    } else {
        None
    };

    dur.map(Delay::new)
}
