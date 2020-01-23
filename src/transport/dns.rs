// const MAX_DOMAIN_NAME_LEN: usize = 253;
// pub type DOMAIN_NAME_BYTE_ARRAY = [u8; MAX_DOMAIN_NAME_LEN];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    TXT,
    MX,
}
