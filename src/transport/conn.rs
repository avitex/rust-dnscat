use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_timer::Delay;
use futures::io::{self, AsyncRead, AsyncWrite};

use crate::packet::Packet;
use crate::transport::Datagram;

pub trait ExchangeTransport<'a, D>
where
    D: Datagram<'a>,
{
    type Error;

    type Future: Future<Output = Result<D, Self::Error>>;

    fn exchange(&'a mut self, datagram: D) -> Self::Future;
}

pub struct Connection<T> {
    transport: T,
    timeout_waker: Delay,
    timeout_waiting: bool,
}

impl<'a, T> Connection<T>
where
    T: ExchangeTransport<'a, Packet<'a>>,
{
    pub fn new(transport: T, poll_interval: Duration) -> Self {
        Self {
            transport,
            timeout_waker: Delay::new(poll_interval),
            timeout_waiting: false,
        }
    }
}

// impl<'a, T> AsyncRead for Connection<T>
// where
//     T: ExchangeTransport<'a, Packet<'a>>,
// {
//     fn poll_read(
//         self: Pin<&mut Self>,
//         cx: &mut Context,
//         buf: &mut [u8],
//     ) -> Poll<Result<usize, io::Error>> {

//     }
// }
