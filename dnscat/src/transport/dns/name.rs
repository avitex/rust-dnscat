use std::{cmp, iter};

use bytes::{Bytes, BytesMut};
use failure::Fail;
use rand::{rngs::OsRng, Rng};
use trust_dns_proto::{error::ProtoError, rr::Name};

use crate::util::hex;

const NAME_MAX_SIZE: usize = 255;
const LABEL_MAX_SIZE: usize = 63;
const LABEL_COST: usize = 1;

/// An immutable wrapper around a `Name` with the guarantee
/// its internal representation is lowercase ASCII.
///
/// Note, also caches the value of `len()`.
#[derive(Debug, Clone)]
pub struct LowerAsciiName {
    name: Name,
    len: usize,
}

impl LowerAsciiName {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn from_name_unchecked(name: Name) -> Self {
        let len = name.len();
        let name = name.to_lowercase();
        Self { name, len }
    }
}

impl AsRef<Name> for LowerAsciiName {
    fn as_ref(&self) -> &Name {
        &self.name
    }
}

impl From<Name> for LowerAsciiName {
    fn from(name: Name) -> Self {
        if name.iter().flatten().all(u8::is_ascii) {
            Self::from_name_unchecked(name)
        } else {
            let name = Name::from_ascii(name.to_ascii()).unwrap();
            Self::from_name_unchecked(name)
        }
    }
}

#[derive(Debug, Clone, Fail)]
pub enum NameEncoderError {
    #[fail(display = "Data too large for name encoder")]
    DataTooLarge,
    #[fail(display = "Constant not found in name")]
    ConstantNotFound,
    #[fail(display = "Constant too large for name encoder")]
    ConstantTooLarge,
    #[fail(display = "DNS Protocol error: {}", _0)]
    Proto(ProtoError),
    #[fail(display = "Hex decode error: {}", _0)]
    Hex(hex::DecodeError),
}

#[derive(Debug, Clone)]
pub struct NameEncoder {
    budget: u8,
    labeller: Labeller,
    constant: LowerAsciiName,
}

impl NameEncoder {
    /// Constructs a new name encoder given a constant name and a labeller.
    ///
    /// If the constant name is a FQDN, the data will appear as subdomains and if
    /// not the data will appear as the domain name.
    pub fn new<C>(constant: C, labeller: Labeller) -> Result<Self, NameEncoderError>
    where
        C: Into<LowerAsciiName>,
    {
        let constant = constant.into();
        // We account for the root label cost as Name::len() does not.
        let constant_len = constant.len() + LABEL_COST;
        if constant_len >= NAME_MAX_SIZE {
            return Err(NameEncoderError::ConstantTooLarge);
        }
        let budget = (NAME_MAX_SIZE - constant_len) as u8;
        let this = Self {
            constant,
            labeller,
            budget,
        };
        Ok(this)
    }

    /// Returns the max length of data that can be encoded.
    pub fn max_data(&self) -> u8 {
        self.labeller.max_data_for_budget(self.budget)
    }

    /// Returns the max length of data that can be encoded in hex.
    pub fn max_hex_data(&self) -> u8 {
        self.max_data() / 2
    }

    /// Returns the budget available to encode data.
    pub fn budget(&self) -> u8 {
        self.budget
    }

    /// Returns a reference to the constant name.
    pub fn constant(&self) -> &Name {
        self.constant.as_ref()
    }

    /// Returns the length of the constant name.
    pub fn constant_len(&self) -> usize {
        self.constant.len()
    }

    /// Encode data as hex into into a FQDN.
    pub fn encode_hex(&mut self, bytes: &[u8]) -> Result<Name, NameEncoderError> {
        let mut hex_bytes = BytesMut::with_capacity(bytes.len() * 2);
        hex::encode_into_buf(&mut hex_bytes, bytes);
        self.encode(hex_bytes.as_ref())
    }

    /// Encodes data into a FQDN.
    pub fn encode(&mut self, bytes: &[u8]) -> Result<Name, NameEncoderError> {
        let labels = match self.labeller.label(bytes, self.budget) {
            Some(labels) => labels,
            None => return Err(NameEncoderError::DataTooLarge),
        };
        let constant = self.constant.as_ref();
        let const_labels = constant.iter();
        let result = if constant.is_fqdn() {
            Name::from_labels(labels.chain(const_labels))
        } else {
            Name::from_labels(const_labels.chain(labels))
        };
        result.map_err(NameEncoderError::Proto)
    }

    /// Decode hex data from a FQDN.
    pub fn decode_hex(&self, encoded_name: &Name) -> Result<Bytes, NameEncoderError> {
        let bytes = self.decode(encoded_name)?;
        let mut hex_bytes = BytesMut::with_capacity(bytes.len());
        hex::decode_into_buf(&mut hex_bytes, bytes.as_ref(), true)
            .map_err(NameEncoderError::Hex)?;
        Ok(hex_bytes.freeze())
    }

    /// Decode data from a FQDN.
    pub fn decode(&self, encoded_name: &Name) -> Result<Bytes, NameEncoderError> {
        let const_len = self.constant_len();
        let data_len = encoded_name.len().saturating_sub(const_len);
        let const_label_num = self.constant().num_labels() as usize;
        let data_label_num = (encoded_name.num_labels() as usize).saturating_sub(const_label_num);
        let mut data = BytesMut::with_capacity(data_len);
        if self.constant().is_fqdn() {
            if self.constant().zone_of(encoded_name) {
                data.extend(encoded_name.iter().take(data_label_num).flatten().copied());
                return Ok(data.freeze());
            }
        } else {
            let encoded_const_iter = encoded_name
                .iter()
                .flatten()
                .map(u8::to_ascii_lowercase)
                .take(const_len);
            if self
                .constant()
                .iter()
                .flatten()
                .copied()
                .eq(encoded_const_iter)
            {
                data.extend(encoded_name.iter().skip(const_label_num).flatten().copied());
                return Ok(data.freeze());
            }
        }
        Err(NameEncoderError::ConstantNotFound)
    }
}

#[derive(Debug, Clone)]
pub struct Labeller<R: Rng = OsRng> {
    random: Option<R>,
    max_size: u8,
}

impl Labeller {
    /// Constructs a labeller that splits data into labels of the max size possible.
    pub fn new() -> Self {
        Default::default()
    }

    /// Constructs a labeller that splits data into random labels sizes.
    pub fn random() -> Self {
        Self::random_with_source(Default::default())
    }

    /// Constructs a labeller that splits data into labels of a max size.
    pub fn exact(max_size: usize) -> Self {
        assert!(max_size > 1, "label size above 1");
        assert!(
            max_size <= LABEL_MAX_SIZE,
            "label size less than or equal to max"
        );
        Self {
            max_size: max_size as u8,
            random: None,
        }
    }
}

impl<R> Labeller<R>
where
    R: Rng,
{
    /// Constructs a labeller that splits data into random labels sizes.
    pub fn random_with_source(source: R) -> Self {
        Self {
            max_size: LABEL_MAX_SIZE as u8,
            random: Some(source),
        }
    }

    /// Calculates the max data that can be encoded for a budget.
    pub fn max_data_for_budget(&self, budget: u8) -> u8 {
        let total_label_size = self.max_size + LABEL_COST as u8;
        let min_labels = Self::u8_rounded_up_div(budget, total_label_size);
        budget - min_labels
    }

    /// Splits the bytes into a label iter, given a total data budget.
    ///
    /// Depending on how many labels the data will split into the data usage will
    /// grow, which is why have a budget to work against.
    ///
    /// Returns `None` if the labeller can not fit the data into the budget.
    pub fn label<'a>(
        &'a mut self,
        mut bytes: &'a [u8],
        budget: u8,
    ) -> Option<impl Iterator<Item = &'a [u8]>> {
        // No point continuing if it's not even in the valid range of a budget.
        if bytes.len() > u8::max_value() as usize {
            return None;
        }
        // We know it's in the valid range of a u8 now.
        let bytes_len = bytes.len() as u8;
        // Calculate the spare budget we have available.
        let spare_budget = budget.saturating_sub(bytes_len);
        // If we can't fit at least one label, fail early!
        if spare_budget == 0 {
            return None;
        }
        // Calculate the min number of labels we can possibly create.
        let min_labels = Self::u8_rounded_up_div(bytes_len, self.max_size);
        // Calculate the max number of labels we have room for and can
        // practically create.
        let max_labels = cmp::min(bytes_len, spare_budget / LABEL_COST as u8);
        // If the min number of labels we can create is greater than the max
        // number of labels, we clearly can't go any further.
        if min_labels > max_labels {
            return None;
        }
        let min_size = Self::u8_rounded_up_div(bytes_len, max_labels);
        // Now that we know we can split all the data up successfully,
        // we define a function that will generate sizes to split the
        // data up into.
        let mut bytes_left = bytes_len;
        let label_size_fn = move || {
            if bytes_left == 0 {
                return None;
            }
            let size = if let Some(ref mut rng) = self.random {
                rng.gen_range(min_size..(self.max_size + 1))
            } else {
                self.max_size
            };
            let size = cmp::min(bytes_left, size);
            bytes_left -= size;
            Some(size)
        };
        let labels_iter = iter::from_fn(label_size_fn).map(move |size| {
            let (slice, rest) = bytes.split_at(size as usize);
            bytes = rest;
            slice
        });
        Some(labels_iter)
    }

    // Integer division, rounding up
    #[inline]
    fn u8_rounded_up_div(num: u8, den: u8) -> u8 {
        let val = (num as u16 + (den as u16 - 1)) / den as u16;
        val as u8
    }
}

impl Default for Labeller {
    fn default() -> Self {
        Self::exact(LABEL_MAX_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn test_ascii_name() {
        let utf8_name: Name = "i❤️.rust".parse().unwrap();
        let ascii_name = LowerAsciiName::from(utf8_name);
        let ascii_name_labels = ascii_name.as_ref().iter().collect::<Vec<_>>();
        assert_eq!(ascii_name_labels, vec![&b"xn--i-7iq"[..], &b"rust"[..]]);
    }

    #[test]
    fn test_expected_name_len() {
        let name_no_trailing_dot = Name::from_ascii("a.a").unwrap();
        let name_with_trailing_dot = Name::from_ascii("a.a.").unwrap();
        // trailing and no trailing dot is same length.
        assert_eq!(name_no_trailing_dot.len(), name_with_trailing_dot.len());
        // no trailing is not fqdn
        assert_eq!(name_no_trailing_dot.is_fqdn(), false);
        // trailing is fqdn
        assert_eq!(name_with_trailing_dot.is_fqdn(), true);
        // length of name is all the count of chars (including dots).
        assert_eq!(name_with_trailing_dot.len(), 4);
    }

    #[test]
    fn test_labeller_exact() {
        let data = b"helloworld";
        let mut labeller = Labeller::exact(5);
        // Budget to have one split
        assert!(labeller
            .label(data, (data.len() + LABEL_COST) as u8)
            .is_none());
        // Budget to have two splits
        assert_eq!(
            labeller
                .label(data, (data.len() + LABEL_COST * 2) as u8)
                .unwrap()
                .collect_vec(),
            vec![b"hello", b"world"],
        );
        // Budget to have 3 splits.
        assert_eq!(
            labeller
                .label(data, (data.len() + LABEL_COST * 3) as u8)
                .unwrap()
                .collect_vec(),
            vec![b"hello", b"world"],
        );
    }

    #[test]
    fn test_labeller_default() {
        let data = &vec![b'!'; 128][..];
        let mut labeller = Labeller::default();
        // Budget to have one split
        assert!(labeller
            .label(data, (data.len() + LABEL_COST) as u8)
            .is_none());
        // Budget to have two splits
        assert!(labeller
            .label(data, (data.len() + LABEL_COST * 2) as u8)
            .is_none());
        // Budget to have two splits
        assert_eq!(
            labeller
                .label(data, (data.len() + LABEL_COST * 3) as u8)
                .unwrap()
                .collect_vec(),
            vec![&data[..63], &data[63..126], &data[126..128]],
        );
    }

    #[test]
    fn test_labeller_random() {
        let rng = rand_pcg::Pcg32::new(0, 0);
        let data = &vec![b'!'; 128][..];
        let mut labeller = Labeller::random_with_source(rng);
        assert_eq!(
            labeller
                .label(data, (data.len() + LABEL_COST * 10) as u8)
                .unwrap()
                .collect_vec(),
            vec![&data[..58], &data[58..82], &data[82..113], &data[113..128]],
        );
    }

    #[test]
    fn name_encoder_basic() {
        let data = b"helloworld";
        let domain_name = Name::from_ascii("example.com.").unwrap();
        let encoded_name_valid = Name::from_ascii("hello.world.example.com.").unwrap();
        let mut name_encoder = NameEncoder::new(domain_name, Labeller::exact(5)).unwrap();
        let encoded_name = name_encoder.encode(data).unwrap();
        assert_eq!(encoded_name, encoded_name_valid);
        assert_eq!(encoded_name.len(), 24);
        assert!(encoded_name.is_fqdn());
    }

    #[test]
    fn name_encoder_hex() {
        let data = &[1, 2, 3, 4, 5];
        let domain_name = Name::from_ascii("example.com.").unwrap();
        let encoded_name_valid = Name::from_ascii("01020.30405.example.com.").unwrap();
        let mut name_encoder = NameEncoder::new(domain_name, Labeller::exact(5)).unwrap();
        let encoded_name = name_encoder.encode_hex(data).unwrap();
        assert_eq!(encoded_name, encoded_name_valid);
        assert_eq!(encoded_name.len(), 24);
        assert!(encoded_name.is_fqdn());
    }

    #[test]
    fn name_encoder_budget_calc() {
        let label = vec![b'a'; 63];
        let name = Name::new()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..label.len() - 3])
            .unwrap();
        assert_eq!(name.len(), 253);
        assert_eq!(name.is_fqdn(), false);
        let name_encoder = NameEncoder::new(name, Labeller::default()).unwrap();
        assert_eq!(name_encoder.budget(), 1);
    }

    #[test]
    fn test_name_encoder_decode() {
        let domain_name = Name::from_ascii("example.com.").unwrap();
        let encoded_name = Name::from_ascii("dead.beef.example.com.").unwrap();
        let name_encoder = NameEncoder::new(domain_name, Labeller::default()).unwrap();
        let data = name_encoder.decode_hex(&encoded_name).unwrap();
        assert_eq!(data, &[0xDE, 0xAD, 0xBE, 0xEF][..]);
    }

    #[test]
    fn test_name_default_max_data_calc() {
        let domain_name = Name::from_ascii("example.com.").unwrap();
        let name_encoder = NameEncoder::new(domain_name, Labeller::default()).unwrap();
        assert_eq!(name_encoder.budget(), 242);
        assert_eq!(name_encoder.max_data(), 238);
    }
}
