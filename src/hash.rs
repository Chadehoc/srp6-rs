pub use sha1::digest::Update;
pub use sha1::Digest;

use crate::big_number::{needed_precision, to_array_pad_zero};
use crypto_bigint::BoxedUint;

pub const HASH_LENGTH: usize = 20;
pub type Hash = [u8; HASH_LENGTH];
pub type HashFunc = sha1::Sha1;

///
/// not yet verified
///
pub fn hash(a: &BoxedUint, b: &BoxedUint, nbytes: usize) -> BoxedUint {
    let digest = HashFunc::new()
        .chain(to_array_pad_zero(a, nbytes))
        .chain(to_array_pad_zero(b, nbytes))
        .finalize();
    BoxedUint::from_be_slice(&digest, needed_precision(HASH_LENGTH)).expect("hash illisible")
}

pub fn from_hash<const KEYLEN: usize>(hash: &[u8]) -> BoxedUint {
    debug_assert_eq!(hash.len(), HASH_LENGTH, "not the expected hash length");
    BoxedUint::from_be_slice(hash, needed_precision(KEYLEN)).expect("hash illisible")
}

/*
pub fn hash<Enc: ArrayEncoding>(a: &Enc, b: &Enc) -> Enc
{
    let intended_size = Enc::ByteSize::USIZE;
    println!("intended size hash = {intended_size}");
    // 20 est la taille fixe d'un SHA1
    let padding_size = intended_size - 20;
    let digest = HashFunc::new()
        .chain(a.to_be_bytes())
        .chain(b.to_be_bytes())
        .finalize(); //.as_ref();
    let x = ByteArray::<Enc>::try_from_iter(std::iter::repeat_n(0u8, padding_size).chain(digest)).expect("mauvaise taille pour hash");
    Enc::from_be_byte_array(x)
}
*/
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_details::testdata;
    #[test]
    #[allow(non_snake_case)]
    /// u = H(A, B)
    fn should_hash_2_big_numbers() {
        // A from official example
        let A = BoxedUint::from_be_slice(&testdata::A_PUBLIC, 1024).unwrap();
        let B = BoxedUint::from_be_slice(&testdata::B_PUBLIC, 1024).unwrap();
        let u = hash(&A, &B, 128);
        let expected = BoxedUint::from_be_slice(&testdata::U, 1024).unwrap();
        assert_eq!(&u, &expected);
    }
}
