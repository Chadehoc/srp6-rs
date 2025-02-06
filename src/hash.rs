pub use sha1::digest::Update;
pub use sha1::Digest;

use crate::big_number::num_effective_bytes;
use crypto_bigint::BoxedUint;

pub const HASH_LENGTH: usize = 20;
pub type Hash = [u8; HASH_LENGTH];
pub type HashFunc = sha1::Sha1;

pub fn from_hash(hash: &[u8]) -> BoxedUint {
    debug_assert_eq!(hash.len(), HASH_LENGTH, "not the expected hash length");
    BoxedUint::from_be_slice(hash, (HASH_LENGTH as u32) * 8).expect("hash illisible")
}

/// Returns as byte vec in big endian byte order, padded in front by 0 for `len` bytes
pub fn to_array_pad_zero(big: &BoxedUint, len: usize) -> Vec<u8> {
    let nb = num_effective_bytes(big);
    assert!(nb <= len, "Padding to {len} from {nb} bytes");
    let offset = len - nb;
    let mut result = vec![0u8; len];
    // leading zeroes due to bits_precision
    let bytes1 = big.to_be_bytes();
    let leading_bytes = big.leading_zeros() as usize / 8;
    let bytes2 = &bytes1[leading_bytes..];
    result[offset..].clone_from_slice(bytes2);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_pad_0() {
        let x = BoxedUint::from_be_slice(&[0x11, 0xcd], 16).unwrap();
        assert_eq!(
            to_array_pad_zero(&x, 9),
            [0, 0, 0, 0, 0, 0, 0, 0x11, 0xcd_u8]
        );
    }
}
