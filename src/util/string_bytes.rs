use bytes::Bytes;

use std::borrow::Cow;
use std::ops::Deref;

pub use std::str::{self, Utf8Error};

#[derive(Debug, Clone, PartialEq)]
pub struct StringBytes(Bytes);

impl StringBytes {
    pub fn new() -> Self {
        Self(Bytes::new())
    }

    pub fn from_utf8(bytes: Bytes) -> Result<Self, Utf8Error> {
        str::from_utf8(bytes.as_ref())?;
        Ok(Self(bytes))
    }

    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl Default for StringBytes {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Cow<'static, str>> for StringBytes {
    fn from(s: Cow<'static, str>) -> Self {
        match s {
            Cow::Owned(s) => Self::from(s),
            Cow::Borrowed(s) => Self::from(s),
        }
    }
}

impl From<&'static str> for StringBytes {
    fn from(s: &'static str) -> Self {
        Self(Bytes::from_static(s.as_bytes()))
    }
}

impl From<String> for StringBytes {
    fn from(s: String) -> Self {
        Self(Bytes::from(s))
    }
}

impl AsRef<str> for StringBytes {
    fn as_ref(&self) -> &str {
        &*self
    }
}

impl AsRef<[u8]> for StringBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Deref for StringBytes {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        unsafe { str::from_utf8_unchecked(self.as_ref()) }
    }
}
