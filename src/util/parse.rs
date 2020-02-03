use std::mem::size_of;
use std::str::Utf8Error;

use bytes::{Buf, Bytes, BytesMut};

use crate::util::{hex, StringBytes};

#[derive(Debug, Clone, PartialEq)]
pub struct Needed(pub usize);

#[derive(Debug, Clone, PartialEq)]
pub struct NoNullTermError;

#[inline]
fn require_len(bytes: &Bytes, len: usize) -> Result<(), Needed> {
    if bytes.len() < len {
        Err(Needed(len - bytes.len()))
    } else {
        Ok(())
    }
}

#[inline]
fn require_size_of<T>(bytes: &Bytes) -> Result<(), Needed> {
    require_len(bytes, size_of::<T>())
}

#[inline]
pub fn be_u8(bytes: &mut Bytes) -> Result<u8, Needed> {
    require_size_of::<u8>(bytes)?;
    Ok(bytes.get_u8())
}

#[inline]
pub fn be_u16(bytes: &mut Bytes) -> Result<u16, Needed> {
    require_size_of::<u16>(bytes)?;
    Ok(bytes.get_u16())
}

pub fn nt_string<E>(bytes: &mut Bytes) -> Result<StringBytes, E>
where
    E: From<NoNullTermError>,
    E: From<Utf8Error>,
{
    let slice_len = {
        let mut parts = bytes.split(|x| *x == 0);
        let slice = parts.next().unwrap();
        if parts.next().is_none() {
            return Err(NoNullTermError.into());
        }
        slice.len()
    };
    let string = StringBytes::from_utf8(bytes.split_to(slice_len))?;
    bytes.advance(1);
    Ok(string)
}

pub fn np_hex_string<E>(bytes: &mut Bytes, len: usize) -> Result<Bytes, E>
where
    E: From<Needed>,
    E: From<hex::DecodeError>,
{
    let bytes = split_to(bytes, len)?;
    let slice = bytes.split(|x| *x == 0).next().unwrap();
    let mut raw_bytes = BytesMut::with_capacity(len / 2);
    hex::decode_into_buf(&mut raw_bytes, slice, false)?;
    Ok(raw_bytes.freeze())
}

#[inline]
pub fn split_to(bytes: &mut Bytes, len: usize) -> Result<Bytes, Needed> {
    require_len(bytes, len)?;
    Ok(bytes.split_to(len))
}
