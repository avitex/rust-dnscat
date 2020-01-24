use std::marker::PhantomData;

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

pub struct Datagram<'a, T> {
    payload: T,
    lifetime: PhantomData<&'a ()>,
}

impl<'a, T> Datagram<'a, T> {
    pub fn new(payload: T) -> Self {
        Self {
            payload,
            lifetime: PhantomData,
        }
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }
}

impl<'a, T> Encode for Datagram<'a, T>
where
    T: Encode,
{
    fn encode<B: BufMut>(&self, buf: &mut B) {
        self.payload.encode(buf);
    }
}

impl<'a, T> Decode<'a> for Datagram<'a, T>
where
    T: Decode<'a>,
{
    type Error = T::Error;

    fn decode(buf: &'a [u8]) -> Result<(&'a [u8], Self), Self::Error> {
        T::decode(buf).map(|(b, payload)| (b, Self::new(payload)))
    }
}

// /// Returns `true` if encode overflowed buf, `false` if it fit.
// pub(crate) fn encode<B: BufMut>(&self, buf: &mut B, limit: usize) -> bool {
//     let mut buf = BoundedBufMut::new(buf, limit);
//     self.payload.encode(&mut buf);
//     buf.has_overflown()
// }
