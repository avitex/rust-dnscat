use bytes::{BufMut, Bytes};
use failure::Fail;

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
pub trait Decode: Sized {
    /// Decode error type.
    type Error: Fail;

    /// Decode from a `Bytes` buffer.
    ///
    /// Returns the decoded type on success or a decode error on failure.
    fn decode(buf: &mut Bytes) -> Result<Self, Self::Error>;
}
