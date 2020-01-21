use std::net::{Ipv4Addr, Ipv6Addr};

use crate::private::Sealed;

#[derive(Debug, PartialEq)]
pub enum MessageError {
    TooLong,
    MissingSequence(u8),
    UnexpectedLength { expected: usize, got: usize },
}

/// **First block**
/// ```plain
/// +--------+--------+----------------+
/// |  SEQ   |  SIZE  |     DATA       |
/// +--------+--------+----------------+
/// ```
/// **Consecutive blocks**
/// ```
/// +--------+-------------------------+
/// |  SEQ   |          DATA           |
/// +--------+-------------------------+
/// ```
pub struct IpMessage<T: IpMessageBlock> {
    sorted: bool,
    blocks: Vec<T>,
}

impl<T> IpMessage<T>
where
    T: IpMessageBlock,
{
    pub fn new() -> Self {
        Self::with_capacity(0)
    }

    pub fn with_capacity(cap: u8) -> Self {
        let sorted = false;
        let blocks = Vec::with_capacity(cap as usize);
        Self { blocks, sorted }
    }

    pub fn extend_iter<I, B>(&mut self, iter: I) -> Result<(), MessageError>
    where
        I: IntoIterator<Item = B>,
        B: IntoIpMessageBlock<Block = T>,
    {
        let iter = iter.into_iter();
        if let (_, Some(upper_size)) = iter.size_hint() {
            if upper_size > u8::max_value() as usize {
                return Err(MessageError::TooLong);
            }
            if self.blocks.capacity() < upper_size {
                self.blocks.reserve(upper_size - self.blocks.capacity());
            }
        }
        for block in iter {
            self.push_block(block)?;
        }
        Ok(())
    }

    pub fn push_block<P>(&mut self, block: B) -> Result<(), MessageError>
    where
        P: IntoIpMessageBlock<Block = T>,
    {
        if self.can_push() {
            self.sorted = false;
            self.blocks.push(block.into_block());
            Ok(())
        } else {
            Err(MessageError::TooLong)
        }
    }

    pub fn clear(&mut self) {
        self.blocks.clear();
        self.sorted = false;
    }

    pub fn can_push_block(&self) -> bool {
        self.block() + self.block_max_len() != u8::max_value()
    }

    pub fn capacity(&self) -> u8 {
        self.blocks.capacity() as u8
    }

    pub fn len(&self) -> u8 {
        self.blocks.len() as u8
    }

    /// The max number of blocks to fullfill the max amount of data possible
    /// in a message.
    ///
    /// This is calculated by: `floor(data-len-max / (block-size - 1)) + 1`.
    /// - The subtraction of `1` accounts for the sequence numbers on every block.
    /// - The addition of `1` accounts for the length byte on the first block.
    pub const fn len_max() -> u8 {
        (Self::data_len_max() / (Self::block_size() - 1)) + 1
    }

    /// The total size of a message block including the header.
    pub const fn block_size() -> u8 {
        assert!(T::SIZE > 2, "block size must be greater than 2");
        T::SIZE
    }

    /// The max length of data that can be stored in a message.
    pub const fn data_len_max() -> u8 {
        u8::max_value()
    }

    /// Calculates the expected range of data size based on the number of blocks and 
    /// the block size.
    ///
    /// The `max-len` is calculated by: `number-of-blocks * (block-size - 1) - 1`.
    /// - The first subtraction of `1` accounts for the sequence numbers on every block.
    /// - The second subtraction of `1` accounts for the length byte on the first block.
    ///
    /// The `min-len` is calcuated by: `|max-len - block-size|`.
    /// 
    /// Returns `(min-len, max-len)`
    pub fn data_len_estimate(&self) -> (u8, u8) {
        let max_len = (self.len() * (Self::block_size() - 1)) - 1;
        let min_len = max_len.saturating_sub(Self::block_size());
        (min_len, max_len)
    }

    /// Returns the indicated data length from the first block in the sequence.
    ///
    /// None will be returned if there are no blocks or the first block in the
    /// buffer is not the first block in the sequence.
    pub fn data_len(&self) -> Option<usize> {
        self.blocks.first().and_then(|first| {
            if first.sequence() == 0 {
                Some(first.data()[0] as usize)
            } else {
                None
            }
        })
    }

    pub fn sort_blocks(&mut self) {
        if !self.sorted {
            self.blocks.sort_by_key(T::sequence)
        }
    }

    pub fn to_data(&mut self) -> Result<Vec<u8>, MessageError> {
        // First sort the blocks
        self.sort_blocks();
        // Now get the indicated data length from the first block
        let data_len = self
            .data_len()
            .ok_or(MessageError::MissingSequence(0))?;
        // 
        let (data_len_min, data_len_max) = self.data_len_estimate();

        if current_len != expected_len {
            return Err(MessageError::UnexpectedLength {
                expected: expected_len,
                got: current_len,
            });
        }

        let mut data = Vec::with_capacity(expected_len * T::MAX_DATA_LEN);

        for (expected_seq, part_ref) in self.parts.iter().enumerate() {
            match part_ref.sequence() as usize {
                0 if expected_seq == 0 => data.extend_from_slice(&part_ref.data()[1..]),
                part_seq if part_seq == expected_seq => data.extend_from_slice(part_ref.data()),
                _ => return Err(MessageError::MissingSequence(expected_seq as u8)),
            }
        }

        Ok(data)
    }
}

//////////////////////////////////////////

pub trait IpMessageBlock: Sealed {
    const SIZE: u8;

    fn sequence(&self) -> u8;

    fn data(&self) -> &[u8];
}

pub trait IntoIpMessageBlock {
    type Block: IpMessageBlock;

    fn into_block(self) -> Self::Block;
}

pub struct Ipv4MessageBlock([u8; 4]);

impl IpMessageBlock for Ipv4MessageBlock {
    const SIZE: u8 = 4;

    fn sequence(&self) -> u8 {
        self.0[0]
    }

    fn data(&self) -> &[u8] {
        &self.0[1..]
    }
}

impl IntoIpMessageBlock for Ipv4Addr {
    type Block = Ipv4MessageBlock;

    fn into_block(self) -> Self::Block {
        Ipv4MessageBlock(self.octets())
    }
}

impl Sealed for Ipv4MessageBlock {}

pub struct Ipv6MessageBlock([u8; 16]);

impl IpMessageBlock for Ipv6MessageBlock {
    const SIZE: u8 = 16;

    fn sequence(&self) -> u8 {
        self.0[0]
    }

    fn data(&self) -> &[u8] {
        &self.0[1..]
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

    fn parse_blocks(blocks: Vec<Ipv4Addr>) -> Result<Vec<u8>, MessageError> {
        let mut msg = IpMessage::new();
        msg.extend_iter(blocks).unwrap();
        msg.to_data()
    }

    #[test]
    fn test_ip_message_basic() {
        let result = parse_blocks(vec![Ipv4Addr::new(1, 7, 6, 5), Ipv4Addr::new(0, 2, 9, 8)]);
        assert_eq!(result, Ok(vec![9, 8, 7, 6, 5]));
    }

    #[test]
    fn test_ip_message_length_invalid() {
        let result = parse_blocks(vec![Ipv4Addr::new(1, 7, 6, 5), Ipv4Addr::new(0, 3, 9, 8)]);
        assert_eq!(
            result,
            Err(MessageError::UnexpectedLength {
                expected: 3,
                got: 2
            })
        );
    }

    #[test]
    fn test_ip_message_missing_sequence() {
        let result = parse_blocks(vec![
            Ipv4Addr::new(3, 7, 6, 5),
            Ipv4Addr::new(2, 7, 6, 5),
            Ipv4Addr::new(0, 3, 9, 8),
        ]);
        assert_eq!(result, Err(MessageError::MissingSequence(1)));
    }
}
