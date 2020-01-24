use std::net::{Ipv4Addr, Ipv6Addr};
use std::{cmp, iter};

use crate::private::Sealed;

/// Enum of all possible errors when handling IP messages.
#[derive(Debug, PartialEq)]
pub enum IpMessageError {
    TooLong,
    MissingSequence(u8),
    LengthOutOfBounds { min: usize, max: usize, len: usize },
}

/// An IP message consists of one head block and zero or more tail blocks,
/// where the block structures are IP addresses.
///
/// Both blocks start with a sequence number. The head block, with
/// a sequence number of zero, additionally contains the total length
/// of the data in the message. The max length of data a message can
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
/// |  sequence number  |  total length of data  |  message data part  |
/// |     (1 byte)      |         (1 byte)       |      (n bytes)      |
/// +-------------------+------------------------+---------------------+
/// ```
/// **Tail block**
/// ```plain
/// +-------------------+----------------------------------------------+
/// |       SEQ         |                     DATA                     |
/// |  sequence number  |               message data part              |
/// |     (1 byte)      |                  (n bytes)                   |
/// +-------------------+----------------------------------------------+
/// ```
///
#[derive(Debug, Clone, PartialEq)]
pub struct IpMessage<T: IpMessageBlock> {
    sorted: bool,
    blocks: Vec<T>,
}

impl<T> IpMessage<T>
where
    T: IpMessageBlock,
{
    /// Create a new empty IP message.
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    /// Create a new empty IP message with the given block capacity.
    ///
    /// # Panics
    ///
    /// Panics if the capacity is greater than `max_block_count`.
    pub fn with_capacity(cap: usize) -> Self {
        let sorted = true;
        let blocks = Vec::with_capacity(cap);
        Self { blocks, sorted }
    }

    /// Contructs a new IP message from data.
    ///
    /// # Panics
    ///
    /// Panics if the data length exceeds `max_data_len`.
    pub fn from_data(data: &[u8]) -> Self {
        // Assert the length of data does not exceed the message limit
        assert!(data.len() <= Self::max_data_len(), "message data too long");
        // Calcuate the index to split the data between head and tail
        let head_split_idx = cmp::min(data.len(), Self::head_block_data_size());
        // Split the data for the head and tail
        let (head_data, tail_data) = data.split_at(head_split_idx);
        // Calculate the number of blocks required to meet the data length
        let block_count = data.len() / Self::tail_block_data_size() + 1;
        // Assert the block count does not exceed the max block count
        assert!(block_count <= Self::max_block_count());
        // Create a new message with the calculated block count
        let mut this = Self::with_capacity(block_count);
        // Push the head block to the message
        this.push_block_unchecked(Self::new_head_block(data.len() as u8, head_data));
        // Split the tail data into chucks that will fit
        let tail_chucks = tail_data.chunks(Self::tail_block_data_size());
        // For each chuck, push a tail block
        for (seq, chunk) in Self::seq_counter(1).zip(tail_chucks) {
            this.push_block_unchecked(Self::new_tail_block(seq, chunk));
        }
        // Explictly state the blocks are sorted
        this.sorted = true;
        // Return the constructed message
        this
    }

    /// Extend the message blocks from a block iterator.
    ///
    /// # Errors
    ///
    /// Returns `MessageError::TooLong` if the blocks pushed exceed the max
    /// for a message.
    pub fn extend_iter<I, B>(&mut self, iter: I) -> Result<(), IpMessageError>
    where
        I: IntoIterator<Item = B>,
        B: IntoIpMessageBlock<Block = T>,
    {
        let iter = iter.into_iter();
        if let (_, Some(upper_size)) = iter.size_hint() {
            if upper_size > Self::max_data_len() {
                return Err(IpMessageError::TooLong);
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

    /// Push a block into the message.
    ///
    /// # Notes
    ///
    /// This function does not check the total data length. Data length is
    /// verified when the blocks are constructed into the message data.
    ///
    /// # Errors
    ///
    /// Returns `Message::TooLong` the message has the max number of blocks.
    pub fn push_block<B>(&mut self, block: B) -> Result<(), IpMessageError>
    where
        B: IntoIpMessageBlock<Block = T>,
    {
        if self.can_push_block() {
            self.push_block_unchecked(block);
            Ok(())
        } else {
            Err(IpMessageError::TooLong)
        }
    }

    /// Clear all blocks from the message.
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.sorted = true;
    }

    /// Returns whether or not another block can be pushed to the message.
    pub fn can_push_block(&self) -> bool {
        self.block_count() < Self::max_block_count()
    }

    /// Returns the message's capacity for blocks.
    pub fn block_capacity(&self) -> usize {
        self.blocks.capacity()
    }

    /// Returns the number of blocks in the message.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// The max number of blocks to fullfill the max amount of data possible
    /// in a message.
    ///
    /// This is calculated by: `floor(max_data_len / tail_block_data_size) + 1`.
    /// The addition of `1` accounts for the length byte on the first block.
    pub fn max_block_count() -> usize {
        (Self::max_data_len() / Self::tail_block_data_size()) + 1
    }

    /// The total size of a message block including the header.
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

    /// The max length of data that can be stored in a message.
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

    /// Sorts the message blocks by their sequence.
    pub fn sort_blocks(&mut self) {
        if !self.sorted {
            self.blocks.sort_by_key(T::sequence)
        }
    }

    /// Consume self into the blocks
    pub fn into_blocks(self) -> Vec<T> {
        self.blocks
    }

    /// Builds the blocks into the message data.
    ///
    /// # Notes
    ///
    /// `sort_blocks` should be called before calling this function to order
    /// the blocks by their sequence number.
    ///
    /// # Errors
    ///
    /// Returns `MessageError::LengthOutOfBounds` if the head block length is
    /// outside of the bounds calculated from `data_len_bounds`.
    ///
    /// Returns `MessageError::MissingSequence` if there is no head block, or
    /// is missing a sequence number in the given blocks.
    pub fn to_data(&self) -> Result<Vec<u8>, IpMessageError> {
        // Now get the indicated data length from the first block
        let data_len = self.data_len().ok_or(IpMessageError::MissingSequence(0))?;
        // Calcuate the bounds for the data length
        let (data_len_min, data_len_max) = self.data_len_bounds();
        // Check the data is within the data length bounds
        if data_len < data_len_min || data_len > data_len_max {
            return Err(IpMessageError::LengthOutOfBounds {
                len: data_len,
                min: data_len_min,
                max: data_len_max,
            });
        }
        // Create a buffer to write the data to
        let mut data = Vec::with_capacity(data_len);
        let mut data_remaining = data_len;
        // For each block, check the sequence and extract the data into the buffer
        for (seq, block_ref) in Self::seq_counter(0).zip(self.blocks.iter()) {
            let block_data = match block_ref.sequence() {
                0 if seq == 0 => block_ref.head_data(),
                block_seq if block_seq == seq => block_ref.tail_data(),
                _ => return Err(IpMessageError::MissingSequence(seq)),
            };
            if data_remaining < block_data.len() {
                data.extend_from_slice(&block_data[0..data_remaining]);
            } else {
                data.extend_from_slice(block_data);
                data_remaining -= block_data.len();
            }
        }
        // Return the buffer
        Ok(data)
    }

    #[inline]
    fn push_block_unchecked<B>(&mut self, block: B)
    where
        B: IntoIpMessageBlock<Block = T>,
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

impl<T> Default for IpMessage<T>
where
    T: IpMessageBlock,
{
    fn default() -> Self {
        Self::new()
    }
}

//////////////////////////////////////////

/// Block trait implemented for IPv4 and IPv6 block structures.
pub trait IpMessageBlock: Sealed {
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

/// Helper trait to convert IP addresses into IP message blocks.
pub trait IntoIpMessageBlock {
    /// The block structure to convert to.
    type Block: IpMessageBlock;

    /// Consume self into the block structure.
    fn into_block(self) -> Self::Block;
}

impl<T> IntoIpMessageBlock for T
where
    T: IpMessageBlock,
{
    type Block = T;

    fn into_block(self) -> Self::Block {
        self
    }
}

/// Block structure for an IPv4 address.
pub struct Ipv4MessageBlock([u8; 4]);

impl IpMessageBlock for Ipv4MessageBlock {
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

impl IntoIpMessageBlock for Ipv4Addr {
    type Block = Ipv4MessageBlock;

    fn into_block(self) -> Self::Block {
        Ipv4MessageBlock(self.octets())
    }
}

impl Sealed for Ipv4MessageBlock {}

/// Block structure for an IPv6 address.
pub struct Ipv6MessageBlock([u8; 16]);

impl IpMessageBlock for Ipv6MessageBlock {
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

impl IntoIpMessageBlock for Ipv6Addr {
    type Block = Ipv6MessageBlock;

    fn into_block(self) -> Self::Block {
        Ipv6MessageBlock(self.octets())
    }
}

impl Sealed for Ipv6MessageBlock {}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_blocks(blocks: Vec<Ipv4Addr>) -> Result<Vec<u8>, IpMessageError> {
        let mut msg = IpMessage::new();
        msg.extend_iter(blocks).unwrap();
        msg.sort_blocks();
        msg.to_data()
    }

    #[test]
    fn test_ip_message_basic() {
        assert_eq!(
            parse_blocks(vec![Ipv4Addr::new(1, 7, 6, 5), Ipv4Addr::new(0, 4, 9, 8)]),
            Ok(vec![9, 8, 7, 6])
        );
    }

    #[test]
    fn test_ip_message_length_invalid() {
        assert_eq!(
            parse_blocks(vec![Ipv4Addr::new(0, 3, 0, 0)]),
            Err(IpMessageError::LengthOutOfBounds {
                len: 3,
                min: 0,
                max: 2,
            })
        );
        assert_eq!(
            parse_blocks(vec![Ipv4Addr::new(0, 6, 0, 0), Ipv4Addr::new(1, 0, 0, 0)]),
            Err(IpMessageError::LengthOutOfBounds {
                len: 6,
                min: 3,
                max: 5,
            })
        );
    }

    #[test]
    fn test_ip_message_empty() {
        assert_eq!(
            parse_blocks(vec![]),
            Err(IpMessageError::MissingSequence(0))
        );
    }

    #[test]
    fn test_ip_message_missing_sequence() {
        assert_eq!(
            parse_blocks(vec![
                Ipv4Addr::new(3, 0, 0, 0),
                Ipv4Addr::new(2, 0, 0, 0),
                Ipv4Addr::new(0, 8, 0, 0),
            ]),
            Err(IpMessageError::MissingSequence(1))
        );
    }
}
