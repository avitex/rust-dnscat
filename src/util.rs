pub mod parse {
    use nom::IResult;
    use std::str;

    use crate::hex::hex_decode_into;

    pub use nom::bytes::complete::*;
    pub use nom::combinator::*;
    pub use nom::error::{ErrorKind, ParseError};
    pub use nom::number::complete::*;
    pub use nom::sequence::*;
    pub use nom::Err as Error;

    pub fn hex_string_null_padded<'a, E: ParseError<&'a [u8]>>(
        src: &'a [u8],
        src_len: usize,
        dst: &mut [u8],
    ) -> IResult<&'a [u8], (), E> {
        let (b, src) = take(src_len)(src)?;
        let (_pad, src) = take_till1(|x| x == 0)(src)?;
        hex_string(src, dst).map(move |_| (b, ()))
    }

    pub fn hex_string<'a, E: ParseError<&'a [u8]>>(
        src: &'a [u8],
        dst: &mut [u8],
    ) -> IResult<&'a [u8], (), E> {
        match hex_decode_into(&src[..dst.len()], dst) {
            Ok(()) => Ok((&src[dst.len()..], ())),
            Err(_) => Err(Error::Error(E::from_error_kind(src, ErrorKind::HexDigit))),
        }
    }

    pub fn nt_string<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], &'a str, E> {
        let (i, s) = map_res(take_till1(|x| x == 0), str::from_utf8)(i)?;
        let (i, _) = take(1usize)(i)?;
        Ok((i, s))
    }
}
