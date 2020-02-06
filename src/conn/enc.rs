use bytes::{Buf, Bytes};

pub trait ConnectionEncryption {
    type Error;

    fn encrypt<B: Buf>(&mut self, payload: &mut B) -> Bytes;

    fn decrypt<B: Buf>(&mut self, payload: &mut B) -> Bytes;

    fn additional_size(&self) -> usize;
}

impl ConnectionEncryption for () {
    type Error = ();

    fn encrypt<B: Buf>(&mut self, payload: &mut B) -> Bytes {
        payload.to_bytes()
    }

    fn decrypt<B: Buf>(&mut self, payload: &mut B) -> Bytes {
        payload.to_bytes()
    }

    fn additional_size(&self) -> usize {
        0
    }
}
