use std::{cmp, iter};

use rand::{rngs::ThreadRng, Rng};
use trust_dns_proto::{error::ProtoError, rr::Name};

const NAME_MAX_SIZE: usize = 255;
const LABEL_MAX_SIZE: usize = 63;
const LABEL_COST: u8 = 1;

/// An immutable wrapper around a `Name` with the guarantee
/// its internal representation is ASCII.
///
/// Note, also caches the value of `len()`.
#[derive(Debug, Clone)]
pub struct AsciiName {
    name: Name,
    len: usize,
}

impl AsciiName {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn from_name_unchecked(name: Name) -> Self {
        let len = name.len();
        Self { name, len }
    }
}

impl AsRef<Name> for AsciiName {
    fn as_ref(&self) -> &Name {
        &self.name
    }
}

impl From<Name> for AsciiName {
    fn from(name: Name) -> Self {
        if name.iter().flatten().all(u8::is_ascii) {
            Self::from_name_unchecked(name)
        } else {
            let name = Name::from_ascii(name.to_ascii()).unwrap();
            Self::from_name_unchecked(name)
        }
    }
}

#[derive(Debug, Clone)]
pub enum NameEncoderError {
    DataTooLarge,
    ConstantTooLarge,
    Proto(ProtoError),
}

#[derive(Debug, Clone)]
pub struct NameEncoder {
    budget: u8,
    labeller: Labeller,
    constant: AsciiName,
}

impl NameEncoder {
    pub fn new<C>(constant: C, labeller: Labeller) -> Result<Self, NameEncoderError>
    where
        C: Into<AsciiName>,
    {
        let constant = constant.into();
        // TODO: check me, and test me more
        let constant_len = if constant.as_ref().is_fqdn() {
            constant.len()
        } else {
            constant.len() - 1
        };
        if constant_len >= NAME_MAX_SIZE {
            return Err(NameEncoderError::ConstantTooLarge);
        }
        let budget = (NAME_MAX_SIZE - constant.len()) as u8;
        let this = Self {
            constant,
            labeller,
            budget,
        };
        Ok(this)
    }

    pub fn budget(&self) -> u8 {
        self.budget
    }

    pub fn encode(&mut self, bytes: &[u8]) -> Result<Name, NameEncoderError> {
        let labels = match self.labeller.label(bytes, self.budget) {
            Some(labels) => labels,
            None => return Err(NameEncoderError::DataTooLarge),
        };
        let constant_name = self.constant.as_ref();
        let result = if constant_name.is_fqdn() {
            let labels = labels.chain(constant_name.iter());
            Name::from_labels(labels)
        } else {
            let labels = constant_name.iter().chain(labels);
            Name::from_labels(labels)
        };
        result.map_err(NameEncoderError::Proto)
    }
}

#[derive(Debug, Clone)]
pub struct Labeller<R: Rng = ThreadRng> {
    random: Option<R>,
    max_size: u8,
}

impl Labeller {
    /// Creates a labeller that splits data into labels of the max size possible.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a name builder that splits data into random labels sizes.
    pub fn random() -> Self {
        Self::random_with_source(Default::default())
    }

    /// Creates a name builder that splits data into labels of an max size.
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
    /// Creates a name builder that splits data into random labels sizes.
    pub fn random_with_source(source: R) -> Self {
        Self {
            max_size: LABEL_MAX_SIZE as u8,
            random: Some(source),
        }
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
        let max_labels = cmp::min(bytes_len, spare_budget / LABEL_COST);
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
                rng.gen_range(min_size, self.max_size + 1)
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
        (num + (den - 1)) / den
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
        let ascii_name = AsciiName::from(utf8_name);
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
            .label(data, data.len() as u8 + LABEL_COST)
            .is_none());
        // Budget to have two splits
        assert_eq!(
            labeller
                .label(data, data.len() as u8 + (LABEL_COST * 2))
                .unwrap()
                .collect_vec(),
            vec![b"hello", b"world"],
        );
        // Budget to have 3 splits.
        assert_eq!(
            labeller
                .label(data, data.len() as u8 + (LABEL_COST * 3))
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
            .label(data, data.len() as u8 + LABEL_COST)
            .is_none());
        // Budget to have two splits
        assert!(labeller
            .label(data, data.len() as u8 + (LABEL_COST * 2))
            .is_none());
        // Budget to have two splits
        assert_eq!(
            labeller
                .label(data, data.len() as u8 + (LABEL_COST * 3))
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
                .label(data, data.len() as u8 + (LABEL_COST * 10))
                .unwrap()
                .collect_vec(),
            vec![&data[..58], &data[58..82], &data[82..113], &data[113..128]],
        );
    }

    #[test]
    fn name_encoder_basic() {
        let data = b"helloworld";
        let domain_name = Name::from_ascii("example.com.").unwrap();
        let encoded_name = Name::from_ascii("hello.world.example.com.").unwrap();
        let mut name_encoder = NameEncoder::new(domain_name, Labeller::exact(5)).unwrap();
        assert_eq!(name_encoder.encode(data).unwrap(), encoded_name)
    }

    #[test]
    fn name_encoder_budget_prefix_calc() {
        let label = vec![b'a'; 63];
        let name = Name::new()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..label.len() - 2])
            .unwrap();
        assert_eq!(name.is_fqdn(), false);
        let name_encoder = NameEncoder::new(name, Labeller::default()).unwrap();
        assert_eq!(name_encoder.budget(), 1);
    }

    #[test]
    fn name_encoder_budget_suffix_calc() {
        let label = vec![b'a'; 63];
        let name = Name::root()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..])
            .unwrap()
            .append_label(&label[..label.len() - 2])
            .unwrap();
        assert_eq!(name.is_fqdn(), true);
        let name_encoder = NameEncoder::new(name, Labeller::default()).unwrap();
        assert_eq!(name_encoder.budget(), 1);
    }
}
