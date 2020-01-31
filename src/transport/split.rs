use std::net::{Ipv4Addr, Ipv6Addr};
use std::{cmp, iter};

use bytes::BytesMut;

use crate::private::Sealed;

/// Enum of all possible errors when handling split datagrams.
#[derive(Debug, PartialEq)]
pub enum SplitDatagramError {
    TooLong,
    MissingSequence(u8),
    LengthOutOfBounds { min: usize, max: usize, len: usize },
}

/// A split datagram consists of one head block and zero or more tail
/// blocks, where the block structures are IP addresses.
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
pub struct SplitDatagram<T: SplitDatagramBlock> {
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
        Self { blocks, sorted }
    }

    /// Contructs a new split datagram from data.
    ///
    /// # Panics
    ///
    /// Panics if the data length exceeds `max_data_len`.
    pub fn from_data(data: &[u8]) -> Self {
        // Assert the length of data does not exceed the datagram limit
        assert!(data.len() <= Self::max_data_len(), "datagram data too long");
        // Calcuate the index to split the data between head and tail
        let head_split_idx = cmp::min(data.len(), Self::head_block_data_size());
        // Split the data for the head and tail
        let (head_data, tail_data) = data.split_at(head_split_idx);
        // Calculate the number of blocks required to meet the data length
        let block_count = data.len() / Self::tail_block_data_size() + 1;
        // Assert the block count does not exceed the max block count
        assert!(block_count <= Self::max_block_count());
        // Create a new datagram with the calculated block count
        let mut this = Self::with_capacity(block_count);
        // Push the head block to the datagram
        this.push_block_unchecked(Self::new_head_block(data.len() as u8, head_data));
        // Split the tail data into chucks that will fit
        let tail_chucks = tail_data.chunks(Self::tail_block_data_size());
        // For each chuck, push a tail block
        for (seq, chunk) in Self::seq_counter(1).zip(tail_chucks) {
            this.push_block_unchecked(Self::new_tail_block(seq, chunk));
        }
        // Explictly state the blocks are sorted
        this.sorted = true;
        // Return the constructed datagram
        this
    }

    /// Extend the datagram blocks from a block iterator.
    ///
    /// # Errors
    ///
    /// Returns `SplitDatagramError::TooLong` if the blocks pushed exceed the max
    /// for a datagram.
    pub fn extend_iter<I, B>(&mut self, iter: I) -> Result<(), SplitDatagramError>
    where
        I: IntoIterator<Item = B>,
        B: IntoSplitDatagramBlock<Block = T>,
    {
        let iter = iter.into_iter();
        if let (_, Some(upper_size)) = iter.size_hint() {
            if upper_size > Self::max_data_len() {
                return Err(SplitDatagramError::TooLong);
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

    /// Push a block into the datagram.
    ///
    /// # Notes
    ///
    /// This function does not check the total data length. Data length is
    /// verified when the blocks are constructed into the datagram data.
    ///
    /// # Errors
    ///
    /// Returns `SplitDatagramError::TooLong` the datagram has the max
    /// number of blocks.
    pub fn push_block<B>(&mut self, block: B) -> Result<(), SplitDatagramError>
    where
        B: IntoSplitDatagramBlock<Block = T>,
    {
        if self.can_push_block() {
            self.push_block_unchecked(block);
            Ok(())
        } else {
            Err(SplitDatagramError::TooLong)
        }
    }

    /// Clear all blocks from the datagram.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.sorted = true;
    }

    /// Returns whether or not another block can be pushed to the datagram.
    pub fn can_push_block(&self) -> bool {
        self.block_count() < Self::max_block_count()
    }

    /// Returns the datagram's capacity for blocks.
    pub fn block_capacity(&self) -> usize {
        self.blocks.capacity()
    }

    /// Returns the number of blocks in the datagram.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// The max number of blocks to fullfill the max amount of data possible
    /// in a datagram.
    ///
    /// This is calculated by: `floor(max_data_len / tail_block_data_size) + 1`.
    /// The addition of `1` accounts for the length byte on the first block.
    pub fn max_block_count() -> usize {
        (Self::max_data_len() / Self::tail_block_data_size()) + 1
    }

    /// The total size of a datagram block including the header.
    pub fn block_size() -> usize {
        assert!(T::size() > 2, "block size must be greater than 2");
        T::size()
    }

    /// The total size available for data in a head block.
    pub fn head_block_data_size() -> usize {
        Self::block_size() - 2
    }

    /// The total size available for data in a tail block.
    pub fn tail_block_data_size() -> usize {
        Self::block_size() - 1
    }

    /// The max length of data that can be stored in a datagram.
    pub fn max_data_len() -> usize {
        u8::max_value() as usize
    }

    /// Calculates the bounds of data size based on the number of blocks and
    /// the block size.
    ///
    /// The `max_len` is calculated by: `(block_count * tail_block_data_size) - 1`.
    /// The subtraction of `1` accounts for the length byte on the first block.
    ///
    /// The `min_len` is calcuated by: `|max_len - tail_block_data_size|`.
    ///
    /// Returns `(min_len, max_len)`
    pub fn data_len_bounds(&self) -> (usize, usize) {
        let max_len = (self.block_count() * Self::tail_block_data_size()) - 1;
        let min_len = max_len.saturating_sub(Self::tail_block_data_size() - 1);
        (min_len, max_len)
    }

    /// Returns the indicated data length from the first block in the sequence.
    ///
    /// None will be returned if there are no blocks or the first block in the
    /// buffer is not the first block in the sequence.
    pub fn data_len(&self) -> Option<usize> {
        self.blocks.first().and_then(|first| {
            if first.sequence() == 0 {
                Some(first.head_len() as usize)
            } else {
                None
            }
        })
    }

    /// Sorts the datagram blocks by their sequence.
    pub fn sort_blocks(&mut self) {
        if !self.sorted {
            self.blocks.sort_by_key(T::sequence)
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
        // Now get the indicated data length from the first block
        let data_len = self
            .data_len()
            .ok_or(SplitDatagramError::MissingSequence(0))?;
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
        let mut data_remaining = data_len;
        // For each block, check the sequence and extract the data into the buffer
        for (seq, block_ref) in Self::seq_counter(0).zip(self.blocks.iter()) {
            let block_data = match block_ref.sequence() {
                0 if seq == 0 => block_ref.head_data(),
                block_seq if block_seq == seq => block_ref.tail_data(),
                _ => return Err(SplitDatagramError::MissingSequence(seq)),
            };
            if data_remaining < block_data.len() {
                buf.extend_from_slice(&block_data[0..data_remaining]);
            } else {
                buf.extend_from_slice(block_data);
                data_remaining -= block_data.len();
            }
        }
        Ok(())
    }

    #[inline]
    fn push_block_unchecked<B>(&mut self, block: B)
    where
        B: IntoSplitDatagramBlock<Block = T>,
    {
        self.sorted = false;
        self.blocks.push(block.into_block());
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

    #[inline]
    fn new_head_block(len: u8, data: &[u8]) -> T {
        let mut block = T::zeroed();
        let bytes = block.bytes_mut();
        bytes[1] = len;
        bytes[2..=data.len()].copy_from_slice(data);
        block
    }

    #[inline]
    fn new_tail_block(seq: u8, data: &[u8]) -> T {
        let mut block = T::zeroed();
        let bytes = block.bytes_mut();
        bytes[0] = seq;
        bytes[1..=data.len()].copy_from_slice(data);
        block
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

//////////////////////////////////////////

/// Trait implemented for split datagram block structures.
pub trait SplitDatagramBlock: Sealed {
    /// The total size of the block structure.
    fn size() -> usize;

    /// Create a new zeroed block.
    fn zeroed() -> Self;

    /// Get a reference to the block bytes.
    fn bytes(&self) -> &[u8];

    /// Get a mutable reference to the block bytes.
    fn bytes_mut(&mut self) -> &mut [u8];

    /// Get the `SEQ` field from the block.
    fn sequence(&self) -> u8 {
        self.bytes()[0]
    }

    /// Get the `LEN` field, assuming it is a head block.
    fn head_len(&self) -> u8 {
        self.bytes()[1]
    }

    /// Get the `DATA` field, assuming it is a head block.
    fn head_data(&self) -> &[u8] {
        &self.bytes()[2..]
    }

    /// Get the `DATA` field, assuming it is a tail block.
    fn tail_data(&self) -> &[u8] {
        &self.bytes()[1..]
    }
}

/// Helper trait to convert types into split datagram blocks.
pub trait IntoSplitDatagramBlock {
    /// The block structure to convert to.
    type Block: SplitDatagramBlock;

    /// Consume self into the block structure.
    fn into_block(self) -> Self::Block;
}

impl<T> IntoSplitDatagramBlock for T
where
    T: SplitDatagramBlock,
{
    type Block = T;

    fn into_block(self) -> Self::Block {
        self
    }
}

/// Block structure for an IPv4 address.
pub struct Ipv4SplitDatagramBlock([u8; 4]);

impl SplitDatagramBlock for Ipv4SplitDatagramBlock {
    fn size() -> usize {
        4
    }

    fn zeroed() -> Self {
        Self([0u8; 4])
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl IntoSplitDatagramBlock for Ipv4Addr {
    type Block = Ipv4SplitDatagramBlock;

    fn into_block(self) -> Self::Block {
        Ipv4SplitDatagramBlock(self.octets())
    }
}

impl Sealed for Ipv4SplitDatagramBlock {}

/// Block structure for an IPv6 address.
pub struct Ipv6SplitDatagramBlock([u8; 16]);

impl SplitDatagramBlock for Ipv6SplitDatagramBlock {
    fn size() -> usize {
        16
    }

    fn zeroed() -> Self {
        Self([0u8; 16])
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl IntoSplitDatagramBlock for Ipv6Addr {
    type Block = Ipv6SplitDatagramBlock;

    fn into_block(self) -> Self::Block {
        Ipv6SplitDatagramBlock(self.octets())
    }
}

impl Sealed for Ipv6SplitDatagramBlock {}

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
        assert_eq!(
            parse_blocks(vec![]),
            Err(SplitDatagramError::MissingSequence(0))
        );
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
}
