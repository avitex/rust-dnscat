pub mod dns;

use bytes::BufMut;

pub trait Encode {
    /// Encode into a buffer.
    ///
    /// # Panics
    ///
    /// Panics if self does not have enough capacity to encode into.
    fn encode<B: BufMut>(&self, buf: &mut B);
}

pub trait Decode<'a>: Sized {
    type Error;

    /// Decode from a buffer.
    ///
    /// # Panics
    ///
    /// Panics if self does not have enough capacity to encode into.
    fn decode(buf: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error>;
}
