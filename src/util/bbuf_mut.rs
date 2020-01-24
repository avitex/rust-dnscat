use bytes::BufMut;
use std::mem::MaybeUninit;

// TODO: TEST TEST TEST
pub struct BoundedBufMut<B: BufMut> {
    buf: B,
    limit: usize,
    cursor: usize,
    overflowed: bool,
}

impl<B> BoundedBufMut<B>
where
    B: BufMut,
{
    pub fn new(buf: B, limit: usize) -> Self {
        assert!(buf.remaining_mut() >= limit);
        Self {
            buf,
            limit,
            overflowed: false,
            cursor: 0,
        }
    }

    pub fn inner(&self) -> &B {
        &self.buf
    }

    pub fn actual_remaining_mut(&self) -> usize {
        if self.has_overflown() {
            return 0;
        }
        self.limit - self.cursor
    }

    pub fn has_overflown(&self) -> bool {
        self.overflowed
    }
}

impl<B> BufMut for BoundedBufMut<B>
where
    B: BufMut,
{
    fn remaining_mut(&self) -> usize {
        usize::max_value()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        if cnt > self.actual_remaining_mut() {
            self.overflowed = true;
        } else {
            self.cursor += cnt;
            self.buf.advance_mut(cnt);
        }
    }

    fn bytes_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        let remaining_mut = self.actual_remaining_mut();
        if remaining_mut > 0 {
            &mut self.buf.bytes_mut()[..remaining_mut]
        } else {
            &mut []
        }
    }
}
