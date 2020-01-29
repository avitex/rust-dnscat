mod conn;
mod exchange;

pub mod dns;

use crate::encdec::{Decode, Encode};

pub use self::conn::*;
pub use self::exchange::*;

pub trait Datagram: Encode + Decode + Send + 'static {}

impl<T> Datagram for T where T: Encode + Decode + Send + 'static {}

pub trait DatagramTransport: 'static {
    type Datagram: Datagram;
}
