use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::ready;
use futures_timer::Delay;
use log::warn;
use rand::Rng;

use crate::encryption::Encryption;
use crate::packet::{LazyPacket, Packet, SessionBodyBytes};
use crate::session::Session;
use crate::transport::ExchangeTransport;

use super::{ClientError, ClientOpts};

#[derive(Debug)]
pub(super) struct Exchange<F> {
    future: F,
    delay: Option<Delay>,
    packet: Packet<SessionBodyBytes>,
}

impl<F> Exchange<F> {
    pub(super) fn new<T, E, R>(
        packet: Packet<SessionBodyBytes>,
        session: &mut Session<E, R>,
        transport: &mut T,
        options: &ClientOpts,
    ) -> Self
    where
        F: Future<Output = Result<LazyPacket, T::Error>> + Unpin + 'static,
        T: ExchangeTransport<LazyPacket, Future = F>,
        E: Encryption,
        R: Rng,
    {
        let delay = transmit_delay(options, session);
        let future = transport.exchange(packet.clone().translate());
        Self {
            packet,
            future,
            delay,
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
        F: Future<Output = Result<LazyPacket, T::Error>> + Unpin + 'static,
        T: ExchangeTransport<LazyPacket, Future = F>,
        E: Encryption,
        R: Rng,
    {
        let exchange_attempt = session.exchange_attempt().expect("should be exchanging");

        if let Some(ref mut delay_fut) = self.delay {
            ready!(Pin::new(delay_fut).poll(cx));
            self.delay = None;
            if exchange_attempt > 1 {
                let packet = session.prepare_retransmit(self.packet.clone())?;
                self.future = transport.exchange(packet.translate());
            }
        }

        let result = match ready!(Pin::new(&mut self.future).poll(cx)) {
            Err(err) => Err(ClientError::Transport(err)),
            Ok(packet) => match (packet.kind(), packet.into_session()) {
                (_, Some(packet)) => session.handle_inbound(packet).map_err(Into::into),
                (kind, None) => Err(ClientError::UnexpectedKind(kind)),
            },
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
