pub mod nom {
    use nom::IResult;
    use std::str;

    pub use nom::bytes::complete::*;
    pub use nom::combinator::*;
    pub use nom::error::{ErrorKind, ParseError};
    pub use nom::number::complete::*;
    pub use nom::sequence::*;
    pub use nom::Err as Error;

    pub fn nt_string<'a, E: ParseError<&'a [u8]>>(i: &'a [u8]) -> IResult<&'a [u8], &'a str, E> {
        let (i, s) = map_res(take_till1(|x| x == 0), str::from_utf8)(i)?;
        let (i, _) = take(1usize)(i)?;
        Ok((i, s))
    }
}
