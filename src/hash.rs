pub use sha1::digest::Update;
pub use sha1::Digest;

use crate::big_number::BigNumber;

pub const HASH_LENGTH: usize = 20;
pub type Hash = [u8; HASH_LENGTH];
pub type HashFunc = sha1::Sha1;

///
/// not yet verified
///
pub fn hash<const KEY_BYTES: usize>(a: &BigNumber, b: &BigNumber) -> BigNumber {
    HashFunc::new()
        .chain(a.to_array_pad_zero::<KEY_BYTES>())
        .chain(b.to_array_pad_zero::<KEY_BYTES>())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_details::testdata;
    #[test]
    #[allow(non_snake_case)]
    /// u = H(A, B)
    fn should_hash_2_big_numbers() {
        // A from official example
        let A = BigNumber::from_bytes_be(&testdata::A_PUBLIC);
        let B = BigNumber::from_bytes_be(&testdata::B_PUBLIC);
        let u = hash::<128>(&A, &B);
        let expected = BigNumber::from_bytes_be(&testdata::U);
        assert_eq!(&u, &expected);
    }
}
