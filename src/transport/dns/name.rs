use trust_dns_proto::rr::Name;

// const NAME_MAX_SIZE: usize = 255;
// const LABEL_COST: usize = 1;
// const LABEL_MAX_SIZE: usize = 63;

// #[derive(Debug, Clone)]
// pub struct AsciiName {
//     name: Name,
//     len: usize,
// }

// impl AsciiName {
//     pub fn from_name(name: Name) -> Self {
//         if name.iter().flatten().all(u8::is_ascii) {
//             Self::from_name_unchecked(name)
//         } else {
//             let name = Name::from_ascii(name.to_ascii()).unwrap();
//             Self::from_name_unchecked(name)
//         }
//     }

//     pub fn len(&self) -> usize {
//         self.len
//     }

//     fn from_name_unchecked(name: Name) -> Self {
//         Self {
//             name,
//             len: name.len(),
//         }
//     }
// }

// impl AsRef<Name> for AsciiName {
//     fn as_ref(&self) -> &Name {
//         &self.name
//     }
// }

// #[derive(Debug, Clone)]
// pub struct NameBuilder {
//     budget: usize,
//     constant: AsciiName,
//     chunking: LabelChunking,
// }

// impl NameBuilder {
//     const MAX_SIZE: usize = 253;

//     pub fn new(constant: AsciiName, chunking: LabelChunking) -> Self {
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
//         if iter.len() > self.budget {
//             return None;
//         }
//         self.chunking
//             .chunk(iter, self.budget)
//             .map(Name::from_labels)
//             .transpose()
//             .ok()
//             .flatten()
//     }
// }

// #[derive(Debug, Clone)]
// pub struct LabelChunking {
//     min: u8,
//     max: u8,
// }

// impl LabelChunking {
//     const MIN_SIZE: u8 = 1;
//     const MAX_SIZE: u8 = 63;

//     /// Creates a name builder that splits data into labels of an exact size.
//     pub fn exact(size: u8) -> Self {
//         Self::validate_size(size);
//         Self {
//             min: size,
//             max: size,
//         }
//     }

//     /// Creates a name builder that splits data into labels of the max size possible (63).
//     pub fn max() -> Self {
//         Self::exact(Self::MAX_SIZE)
//     }

//     /// Creates a name builder that splits data into labels sizes between min and max.
//     pub fn range(min: u8, max: u8) -> Self {
//         Self::validate_size(max);
//         Self::validate_size(min);
//         assert!(min < max, "chunk min size less than user max");
//         Self { min, max }
//     }

//     pub fn chuck_size_min(&self) -> usize {
//         self.min as usize
//     }

//     pub fn chuck_size_max(&self) -> usize {
//         self.max as usize
//     }

//     /// Chunks the labels, given an upper limit.
//     ///
//     /// Returns `None` if the chunker can not fit the data into the chunk limit.
//     pub fn chunk<I>(&self, iter: I, budget: usize) -> Option<impl Iterator<Item = &[u8]>>
//     where
//         I: ExactSizeIterator,
//     {
//         unimplemented!()
//     }

//     fn validate_size(size: u8) {
//         assert!(size > 1, "chunk size above 1");
//         assert!(size <= Self::MAX_SIZE, "chunk size less than max");
//     }
// }

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

    // #[test]
    // fn test_expected_max_name() {
    //     let long_label = vec![b'a'; 63];
    //     let name = Name::new()
    //         .append_label(&long_label[..]).unwrap()
    //         .append_label(&long_label[..]).unwrap()
    //         .append_label(&long_label[..]).unwrap()
    //         .append_label(&long_label[..]).unwrap()
    //         .append_label(&long_label[..]).unwrap();
    // }
}