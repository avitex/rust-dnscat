use bytes::BufMut;

/// Synchronously encode into a buffer.
pub trait Encode {
    /// Encode into a `BufMut` buffer.
    ///
    /// # Panics
    ///
    /// Panics if self does not have enough capacity to encode into.
    fn encode<B: BufMut>(&self, buf: &mut B);
}

/// Synchronously decode from a buffer.
pub trait Decode<'a>: Sized {
    /// Decode error type.
    type Error;

    /// Decode from a `&[u8]` buffer.
    ///
    /// Returns a tuple of the remaining buffer not used and the decoded type
    /// on success or a decode error on failure.
    fn decode(buf: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error>;
}

///////////////////////////////////////////////////////////////////////////////

pub trait Datagram<'a>: Encode + Decode<'a> + Send + 'a {}

impl<'a, T> Datagram<'a> for T where T: Encode + Decode<'a> + Send + 'a {}
