use std::net::{Ipv4Addr, Ipv6Addr};
use std::{cmp, iter};

use bytes::{BufMut, Bytes, BytesMut};

const HEAD_HEADER_LEN: usize = 2;
const TAIL_HEADER_LEN: usize = 1;

/// Enum of all possible errors when handling split datagrams.
#[derive(Debug, PartialEq)]
pub enum SplitDatagramError {
    Empty,
    NotSorted,
    DataTooLong,
    MissingSequence(u8),
    LengthOutOfBounds { min: usize, max: usize, len: usize },
}

/// A split datagram consists of one head block and zero or more tail
/// blocks, where the block structures are IP addresses, or hostnames.
///
/// Both blocks start with a sequence number. The head block, with
/// a sequence number of zero, additionally contains the total length
/// of the data in the datagram. The max length of data a datagram can
/// contain is `255 bytes`.
///
/// As blocks are a fixed size, data that does not exactly fit within
/// the given blocks is padded, in our case with zero. When decoding,
/// padding is ignored.
///
/// # Structure
/// ```plain
/// +--------+    +--------+    +--------+
/// |  HEAD  | -> |  TAIL  | -> |  TAIL  | -> ...
/// +--------+    +--------+    +--------+
/// ```
/// **Head block**
/// ```plain
/// +-------------------+------------------------+---------------------+
/// |       SEQ         |           LEN          |         DATA        |
/// |  sequence number  |  total length of data  |  datagram data part |
/// |     (1 byte)      |         (1 byte)       |      (n bytes)      |
/// +-------------------+------------------------+---------------------+
/// ```
/// **Tail block**
/// ```plain
/// +-------------------+----------------------------------------------+
/// |       SEQ         |                     DATA                     |
/// |  sequence number  |               datagram data part             |
/// |     (1 byte)      |                  (n bytes)                   |
/// +-------------------+----------------------------------------------+
/// ```
///
#[derive(Debug, Clone, PartialEq)]
pub struct SplitDatagram<T> {
    data_len: usize,
    sorted: bool,
    blocks: Vec<T>,
}

impl<T> SplitDatagram<T>
where
    T: SplitDatagramBlock,
{
    /// Create a new empty split datagram.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Create a new empty split datagram with the given block capacity.
    ///
    /// # Panics
    ///
    /// Panics if the capacity is greater than `max_block_count`.
    pub fn with_capacity(cap: usize) -> Self {
        let sorted = true;
        let blocks = Vec::with_capacity(cap);
        Self {
            blocks,
            sorted,
            data_len: 0,
        }
    }

    /// Contructs a new split datagram from data.
    ///
    /// # Panics
    ///
    /// Panics if the data length exceeds `max_data_len`.
    pub fn from_data(data: &[u8], block_size: usize, init_seq: u8) -> Self {
        // Assert the length of data does not exceed the datagram limit
        assert!(data.len() <= Self::max_data_len(), "data length valid");
        // Validate block size.
        assert!(block_size > HEAD_HEADER_LEN, "block size valid");
        // Calculate block data sizes.
        let head_data_size = block_size - HEAD_HEADER_LEN;
        let tail_data_size = block_size - TAIL_HEADER_LEN;
        // Calcuate the index to split the data between head and tail
        let head_split_idx = cmp::min(data.len(), head_data_size);
        // Split the data for the head and tail
        let (head_data, tail_data) = data.split_at(head_split_idx);
        // Calculate the number of blocks required to meet the data length
        let block_count = (data.len() / tail_data_size) + 1;
        // Create a new datagram with the calculated block count
        let mut this = Self::with_capacity(block_count);
        // Push the head block to the datagram
        this.push_block_unchecked(T::new_head(init_seq, data.len() as u8, head_data));
        // Split the tail data into chucks that will fit
        let tail_chucks = tail_data.chunks(tail_data_size);
        // For each chuck, push a tail block
        for (seq, chunk) in Self::seq_counter(init_seq + 1).zip(tail_chucks) {
            this.push_block_unchecked(T::new_tail(seq, chunk));
        }
        // Explictly state the blocks are sorted
        this.sorted = true;
        this.data_len = data.len();
        // Return the constructed datagram
        this
    }

    /// Extend the datagram blocks from a block iterator.
    ///
    /// # Errors
    ///
    /// Returns `SplitDatagramError::DataTooLong` if the blocks pushed exceed the max
    /// for a datagram.
    pub fn extend_iter<I>(&mut self, iter: I) -> Result<(), SplitDatagramError>
    where
        I: IntoIterator<Item = T>,
    {
        let iter = iter.into_iter();
        if let (_, Some(upper_size)) = iter.size_hint() {
            if upper_size > Self::max_data_len() {
                return Err(SplitDatagramError::DataTooLong);
            }
            if self.blocks.capacity() < upper_size {
                self.blocks.reserve(upper_size - self.block_capacity());
            }
        }
        for block in iter {
            self.push_block(block)?;
        }
        Ok(())
    }

    /// Build a split datagram and write the data into a buffer in one pass.
    pub fn write_iter_into<I>(iter: I, buf: &mut BytesMut) -> Result<(), SplitDatagramError>
    where
        I: IntoIterator<Item = T>,
    {
        let mut datagram = Self::new();
        datagram.extend_iter(iter)?;
        datagram.sort_blocks();
        datagram.write_into(buf)?;
        Ok(())
    }

    /// Push a block into the datagram.
    ///
    /// # Errors
    ///
    /// Returns `SplitDatagramError::DataTooLong` if the datagram can not fit the block data.
    pub fn push_block(&mut self, block: T) -> Result<(), SplitDatagramError> {
        let is_head = self.blocks.is_empty();
        let next_data_len = self.data_len + block.data_field_len(is_head);
        if Self::max_data_len() < next_data_len {
            Err(SplitDatagramError::DataTooLong)
        } else {
            self.push_block_unchecked(block);
            self.data_len = next_data_len;
            Ok(())
        }
    }

    #[inline]
    fn push_block_unchecked(&mut self, block: T) {
        self.sorted = false;
        self.blocks.push(block);
    }

    /// Clear all blocks from the datagram.
    pub fn clear(&mut self) {
        self.data_len = 0;
        self.blocks.clear();
        self.sorted = true;
    }

    /// Calculates the bounds of data size based on the total recorded data and the
    /// last block size, ignoring data padding.
    ///
    /// Returns `(min_len, max_len)`
    pub fn data_len_bounds(&self) -> (usize, usize) {
        let last_block_is_head = self.blocks.len() == 1;
        let last_block_data_len = self
            .blocks
            .last()
            .map(|b| b.data_field_len(last_block_is_head))
            .unwrap_or(0);
        let min_len = self.data_len.saturating_sub(last_block_data_len);
        let min_len = if self.block_count() == 1 {
            min_len
        } else {
            min_len + 1
        };
        (min_len, self.data_len)
    }

    /// Returns the datagram's capacity for blocks.
    pub fn block_capacity(&self) -> usize {
        self.blocks.capacity()
    }

    /// Returns the number of blocks in the datagram.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// The max length of data that can be stored in a datagram.
    pub fn max_data_len() -> usize {
        u8::max_value() as usize
    }

    /// Returns a reference to the head block.
    ///
    /// Note this assumes you have sorted the blocks via `Self::sort_blocks`.
    ///
    /// Returns `SplitDatagramError::NotSorted` if not sorted or
    /// `SplitDatagramError::Empty` if no blocks are present.
    pub fn head(&self) -> Result<&T, SplitDatagramError> {
        if self.sorted {
            self.blocks.first().ok_or(SplitDatagramError::Empty)
        } else {
            Err(SplitDatagramError::NotSorted)
        }
    }

    /// Returns the head sequence number and length.
    ///
    /// Note this assumes you have sorted the blocks via `Self::sort_blocks`.
    ///
    /// Returns `SplitDatagramError::NotSorted` if not sorted or
    /// `SplitDatagramError::Empty` if no blocks are present.
    pub fn initial_sequence(&self) -> Result<u8, SplitDatagramError> {
        self.head().map(SplitDatagramBlock::seq_field)
    }

    /// Returns the indicated data length from the first block in the sequence.
    ///
    /// Note this assumes you have sorted the blocks via `Self::sort_blocks`.
    ///
    /// Returns `SplitDatagramError::NotSorted` if not sorted or
    /// `SplitDatagramError::Empty` if no blocks are present.
    pub fn indicated_data_len(&self) -> Result<usize, SplitDatagramError> {
        self.head()
            .map(SplitDatagramBlock::len_field)
            .map(|len| len as usize)
    }

    /// Sorts the datagram blocks by their sequence.
    pub fn sort_blocks(&mut self) {
        if !self.sorted {
            self.sorted = true;
            self.blocks.sort_by_key(SplitDatagramBlock::seq_field)
        }
    }

    /// Consume self into the blocks
    pub fn into_blocks(self) -> Vec<T> {
        self.blocks
    }

    /// Writes the datagram data in the blocks into a `BytesMut`.
    ///
    /// # Notes
    ///
    /// `sort_blocks` should be called before calling this function to order
    /// the blocks by their sequence number.
    ///
    /// # Errors
    ///
    /// Returns `SplitDatagramError::LengthOutOfBounds` if the head block length is
    /// outside of the bounds calculated from `data_len_bounds`.
    ///
    /// Returns `SplitDatagramError::MissingSequence` if there is no head block, or
    /// is missing a sequence number in the given blocks.
    pub fn write_into(&self, buf: &mut BytesMut) -> Result<(), SplitDatagramError> {
        // Get the initial head sequence number.
        let init_seq = self.initial_sequence()?;
        // Now get the indicated data length from the first block
        let data_len = self.indicated_data_len()?;
        // Calcuate the bounds for the data length
        let (data_len_min, data_len_max) = self.data_len_bounds();
        // Check the data is within the data length bounds
        if data_len < data_len_min || data_len > data_len_max {
            return Err(SplitDatagramError::LengthOutOfBounds {
                len: data_len,
                min: data_len_min,
                max: data_len_max,
            });
        }
        // Reserves enough capacity in the buffer to write the data to
        buf.reserve(data_len.saturating_sub(buf.capacity()));
        // For each block, check the sequence and extract the data into the buffer
        for (seq, block_ref) in Self::seq_counter(init_seq).zip(self.blocks.iter()) {
            if seq != block_ref.seq_field() {
                return Err(SplitDatagramError::MissingSequence(seq));
            }
            block_ref.write_data_field_into(buf, seq == init_seq);
        }
        buf.truncate(data_len);
        Ok(())
    }

    #[inline]
    fn seq_counter(start: u8) -> impl Iterator<Item = u8> {
        let mut count = start;
        iter::from_fn(move || {
            let this = count;
            count += 1;
            Some(this)
        })
    }
}

impl<T> Default for SplitDatagram<T>
where
    T: SplitDatagramBlock,
{
    fn default() -> Self {
        Self::new()
    }
}

fn block_data_iter<'a>(data: &'a [u8]) -> impl FnMut() -> u8 + 'a {
    let mut data = data.iter().copied();
    move || data.next().unwrap_or(0)
}

//////////////////////////////////////////

/// Trait implemented for split datagram block structures.
pub trait SplitDatagramBlock {
    fn new_head(seq: u8, len: u8, data: &[u8]) -> Self;

    fn new_tail(len: u8, data: &[u8]) -> Self;

    /// Get the total size of the block.
    fn len(&self) -> usize;

    /// Get the `SEQ` field from the block.
    fn seq_field(&self) -> u8;

    /// Get the `LEN` field, assuming it is a head block.
    fn len_field(&self) -> u8;

    // Get the `DATA` field.
    fn write_data_field_into<B: BufMut>(&self, buf: &mut B, head: bool);

    /// Get the header length of the block.
    #[inline]
    fn header_len(&self, head: bool) -> usize {
        if head {
            HEAD_HEADER_LEN
        } else {
            TAIL_HEADER_LEN
        }
    }

    /// Get the `DATA` field length.
    #[inline]
    fn data_field_len(&self, head: bool) -> usize {
        self.len() - self.header_len(head)
    }

    #[inline]
    fn is_empty(&self) -> bool {
        assert!(self.len() > 0);
        false
    }
}

impl SplitDatagramBlock for Ipv4Addr {
    fn new_head(seq: u8, len: u8, data: &[u8]) -> Self {
        Self::new(seq, len, data[0], data[1])
    }

    fn new_tail(seq: u8, data: &[u8]) -> Self {
        Self::new(seq, data[0], data[1], data[2])
    }

    fn len(&self) -> usize {
        4
    }

    fn seq_field(&self) -> u8 {
        self.octets()[0]
    }

    fn len_field(&self) -> u8 {
        self.octets()[1]
    }

    fn write_data_field_into<B: BufMut>(&self, buf: &mut B, head: bool) {
        buf.put_slice(&self.octets()[self.header_len(head)..]);
    }
}

impl SplitDatagramBlock for Ipv6Addr {
    fn new_head(seq: u8, len: u8, data: &[u8]) -> Self {
        let mut next = block_data_iter(data);
        Self::new(
            u16::from_be_bytes([seq, len]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
        )
    }

    fn new_tail(seq: u8, data: &[u8]) -> Self {
        let mut next = block_data_iter(data);
        Self::new(
            u16::from_be_bytes([seq, next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
            u16::from_be_bytes([next(), next()]),
        )
    }

    fn len(&self) -> usize {
        16
    }

    fn seq_field(&self) -> u8 {
        self.octets()[0]
    }

    fn len_field(&self) -> u8 {
        self.octets()[1]
    }

    fn write_data_field_into<B: BufMut>(&self, buf: &mut B, head: bool) {
        buf.put_slice(&self.octets()[self.header_len(head)..]);
    }
}

impl SplitDatagramBlock for Bytes {
    fn new_head(seq: u8, len: u8, data: &[u8]) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u8(seq);
        buf.put_u8(len);
        buf.put_slice(data);
        buf.freeze()
    }

    fn new_tail(seq: u8, data: &[u8]) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u8(seq);
        buf.put_slice(data);
        buf.freeze()
    }

    fn len(&self) -> usize {
        Bytes::len(self)
    }

    fn seq_field(&self) -> u8 {
        self[0]
    }

    fn len_field(&self) -> u8 {
        self[1]
    }

    fn write_data_field_into<B: BufMut>(&self, buf: &mut B, head: bool) {
        buf.put_slice(&self[self.header_len(head)..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_blocks(blocks: Vec<Ipv4Addr>) -> Result<Vec<u8>, SplitDatagramError> {
        let mut buf = BytesMut::new();
        let mut msg = SplitDatagram::new();
        msg.extend_iter(blocks).unwrap();
        msg.sort_blocks();
        msg.write_into(&mut buf)?;
        Ok(buf.to_vec())
    }

    #[test]
    fn test_split_datagram_basic() {
        assert_eq!(
            parse_blocks(vec![Ipv4Addr::new(1, 7, 6, 5), Ipv4Addr::new(0, 4, 9, 8)]),
            Ok(vec![9, 8, 7, 6])
        );
    }

    #[test]
    fn test_split_datagram_length_invalid() {
        assert_eq!(
            parse_blocks(vec![Ipv4Addr::new(0, 3, 0, 0)]),
            Err(SplitDatagramError::LengthOutOfBounds {
                len: 3,
                min: 0,
                max: 2,
            })
        );
        assert_eq!(
            parse_blocks(vec![Ipv4Addr::new(0, 6, 0, 0), Ipv4Addr::new(1, 0, 0, 0)]),
            Err(SplitDatagramError::LengthOutOfBounds {
                len: 6,
                min: 3,
                max: 5,
            })
        );
    }

    #[test]
    fn test_split_datagram_empty() {
        assert_eq!(parse_blocks(vec![]), Err(SplitDatagramError::Empty));
    }

    #[test]
    fn test_split_datagram_missing_sequence() {
        assert_eq!(
            parse_blocks(vec![
                Ipv4Addr::new(3, 0, 0, 0),
                Ipv4Addr::new(2, 0, 0, 0),
                Ipv4Addr::new(0, 8, 0, 0),
            ]),
            Err(SplitDatagramError::MissingSequence(1))
        );
    }

    #[test]
    fn test_split_datagram_from_data_ipv4() {
        let data = b"hello world";
        let datagram: SplitDatagram<Ipv4Addr> = SplitDatagram::from_data(data, 4, 0);
        assert_eq!(
            datagram.into_blocks(),
            vec![
                Ipv4Addr::new(0, 11, b'h', b'e'),
                Ipv4Addr::new(1, b'l', b'l', b'o'),
                Ipv4Addr::new(2, b' ', b'w', b'o'),
                Ipv4Addr::new(3, b'r', b'l', b'd')
            ]
        );
    }

    #[test]
    fn test_split_datagram_from_data_ipv6() {
        let data = &[0b0000_0001, 0b0000_0010];
        let datagram: SplitDatagram<Ipv6Addr> = SplitDatagram::from_data(data, 16, 0);
        let mut buf = BytesMut::new();
        datagram.write_into(&mut buf).unwrap();
        assert_eq!(buf.to_vec(), data);
        assert_eq!(
            datagram.into_blocks().first().unwrap().octets(),
            [0, 2, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
