use std::cmp;

use trust_dns_proto::rr::Name;

const NAME_MAX_SIZE: usize = 255;
const LABEL_COST: usize = 1;
const LABEL_MAX_SIZE: usize = 63;

/// An immutable wrapper around a `Name` with the guarantee
/// its internal representation is ASCII.
/// 
/// Note, also caches the value of `len()`.
#[derive(Debug, Clone)]
pub struct AsciiName {
    name: Name,
    len: usize,
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

impl AsciiName {
    pub fn len(&self) -> usize {
        self.len
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

// #[derive(Debug, Clone)]
// pub struct NameBuilder {
//     budget: usize,
//     constant: AsciiName,
//     labeller: Labeller,
// }

// impl NameBuilder {
//     const MAX_SIZE: usize = 253;

//     pub fn new(constant: AsciiName, labeller: Labeller) -> Self {
//         let budget = Self::MAX_SIZE - constant.len();
//         Self {
//             constant,
//             chunking,
//             budget,
//         }
//     }

//     pub fn budget(&self) -> usize {
//         self.budget
//     }

//     pub fn build<I>(&self, iter: I) -> Option<Name>
//     where
//         I: ExactSizeIterator<Item = u8>,
//     {
//         self.chunking
//             .chunk(iter, self.budget)
//             .map(Name::from_labels)
//             .transpose()
//             .ok()
//             .flatten()
//     }
// }

#[derive(Debug, Clone)]
pub struct Labeller {
    random: bool,
    max_size: usize, 
}

impl Labeller {
    /// Creates a labeller that splits data into labels of the max size possible.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a name builder that splits data into labels of an max size.
    pub fn exact(max_size: usize) -> Self {
        assert!(max_size > 1, "label size above 1");
        assert!(max_size <= LABEL_MAX_SIZE, "label size less than or equal to max");
        Self {
            max_size,
            random: false,
        }
    }

    /// Creates a name builder that splits data into random labels sizes.
    pub fn random() -> Self {
        Self { max_size: LABEL_MAX_SIZE, random: true }
    }

    /// Splits the bytes into a label iter, given a total data budget.
    /// 
    /// Depending on how many labels the data will split into the data usage will
    /// grow, which is why have a budget to work against.
    ///
    /// Returns `None` if the labeller can not fit the data into the budget.
    pub fn label<'a, I>(&self, bytes: &'a [u8], budget: usize) -> Option<impl Iterator<Item = &'a [u8]>> {
        // If in the best conditions we can't fit the data, fail!
        if bytes.len() > budget - LABEL_COST {
            return None;
        }
        // Can we only fit one label in the budget?
        if bytes.len() == budget - LABEL_COST {
            // Is the data larger than the max label size?
            if bytes.len() > self.max_size {
                return None;
            } else {
                return Some(bytes.chunks(1))
            }
        }
        // Get the remainder bytes we can use for splitting
        let max_splits = (budget - bytes.len()) / LABEL_COST;
        // Calculate what is the minimum size this would be for the number of splits.
        // let min_size = bytes.len() / max_splits;
        // let max_size = cmp::min(max_splits_size, self.max_size);
        // if self.random {
        //     let min_size = 
        // } else {
        //     Some(bytes.chunks(max_splits))
        // }
        unimplemented!()
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
    fn test_expected_max_name() {
        let long_label = vec![b'a'; 63];
        let name = Name::new()
            .append_label(&long_label[..])
            .unwrap()
            .append_label(&long_label[..])
            .unwrap()
            .append_label(&long_label[..])
            .unwrap()
            .append_label(&long_label[..])
            .unwrap()
            .append_label(&long_label[..])
            .unwrap();
    }

    #[test]
    fn test_ascii_name() {
        let utf8_name: Name = "i❤️.rust".parse().unwrap();
        let ascii_name = AsciiName::from(utf8_name);
        let ascii_name_labels = ascii_name.as_ref().iter().collect::<Vec<_>>();
        assert_eq!(ascii_name_labels, vec![&b"xn--i-7iq"[..], &b"rust"[..]]);
    }
}
