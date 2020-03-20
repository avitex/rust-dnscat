use std::convert::Infallible;

use bytes::{Buf, Bytes};
use failure::Fail;

pub trait Encryption {
    type Error: Fail;

    fn encrypt<B: Buf>(&mut self, payload: &mut B) -> Result<Bytes, Self::Error>;

    fn decrypt<B: Buf>(&mut self, payload: &mut B) -> Result<Bytes, Self::Error>;

    fn additional_size(&self) -> u8;
}

impl Encryption for () {
    // TODO: change this
    type Error = Infallible;

    fn encrypt<B: Buf>(&mut self, payload: &mut B) -> Result<Bytes, Self::Error> {
        Ok(payload.to_bytes())
    }

    fn decrypt<B: Buf>(&mut self, payload: &mut B) -> Result<Bytes, Self::Error> {
        Ok(payload.to_bytes())
    }

    fn additional_size(&self) -> u8 {
        0
    }
}
