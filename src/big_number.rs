use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, Limb, Odd,
};
use serde::{de::Error as DeError, de::Visitor, Deserialize, Serialize};
use std::fmt::Debug;

use crypto_bigint::{rand_core::OsRng, Random, Uint};

/// returns the byte vec in big endian byte order, padded by 0 for `len` bytes
pub fn to_array_pad_zero(big: &BoxedUint, nbytes: usize) -> Vec<u8> {
    // the initial implementation used wrongly little-indian
    // big-endian padding is in front
    let nb = (big.bits() as usize + 7) / 8;
    // may happen if client and server not using same KEYLEN,
    // better panic here, should be verified sooner
    assert!(nb <= nbytes, "Padding to {nbytes} from {nb} bytes");
    let offset = nbytes - nb;
    let mut result = vec![0u8; nbytes];
    // leading zeroes due to bits_precision
    let bytes1 = big.to_be_bytes();
    let leading_bytes = big.leading_zeros() as usize / 8;
    let bytes2 = &bytes1[leading_bytes..];
    result[offset..].clone_from_slice(bytes2);
    result
}

pub fn needed_precision(nbytes: usize) -> u32 {
    (nbytes * 8) as u32 + 4 * Limb::BITS
}

#[derive(Debug, Clone, Default, PartialEq, Eq, derive_more::Display)]
pub struct SerUint {
    pub num: BoxedUint,
}

impl SerUint {
    pub fn new(num: BoxedUint) -> SerUint {
        SerUint { num }
    }

    pub fn num_effective_bytes(&self) -> usize {
        (self.num.bits() as usize + 7) / 8
    }

    pub fn from_be_bytes(bytes: &[u8], bits_precision: u32) -> SerUint {
        SerUint {
            num: BoxedUint::from_be_slice(bytes, bits_precision)
                .expect("précision exacte attendue"),
        }
    }
}

impl Serialize for SerUint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.num.to_be_bytes().as_ref())
    }
}

impl<'de> Deserialize<'de> for SerUint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct UintVisitor;

        impl<'de> Visitor<'de> for UintVisitor {
            type Value = SerUint;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a byte array")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                let num = BoxedUint::from_be_slice(v, (v.len() * 8) as u32)
                    .expect("the size is ok by construction");
                Ok(SerUint { num })
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut data = Vec::new();
                while let Some(value) = seq.next_element()? {
                    data.push(value);
                }
                let num = BoxedUint::from_be_slice(&data, (data.len() * 8) as u32)
                    .expect("the size is ok by construction");
                Ok(SerUint { num })
            }
        }

        deserializer.deserialize_bytes(UintVisitor)
    }
}

/// Warning: `base` and `modulus` are cloned.
pub fn modpow(base: &BoxedUint, exp: &BoxedUint, modulus: &BoxedUint) -> BoxedUint {
    let monty_base = BoxedMontyForm::new(
        base.clone(),
        BoxedMontyParams::new(Odd::new(modulus.clone()).expect("non-odd modulus")),
    );
    monty_base.pow(exp).retrieve()
}

pub fn new_rand(key_len: usize) -> BoxedUint {
    match key_len {
        // 512 (4096 bits)
        Uint::<64>::BYTES => Uint::<64>::random(&mut OsRng).into(),
        // 256 (2048 bits)
        Uint::<32>::BYTES => Uint::<32>::random(&mut OsRng).into(),
        // 128 (1024 bits)
        Uint::<16>::BYTES => Uint::<16>::random(&mut OsRng).into(),
        _ => unimplemented!("key_len not implemented"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{
        modular::{BoxedMontyForm, BoxedMontyParams},
        Odd,
    };
    use hex_literal::hex;

    #[test]
    fn test_mod_exp() {
        let a = BoxedUint::from(6u64);
        let p = BoxedUint::from(3u64);
        let m = Odd::new(BoxedUint::from(7u64)).unwrap();
        let aa = BoxedMontyForm::new(a, BoxedMontyParams::new(m));
        let r = aa.pow(&p).retrieve();
        assert_eq!(&r, &BoxedUint::from(6u64), "{} is not 6", &r);
    }

    #[test]
    fn should_pad_0() {
        let x = SerUint::new(BoxedUint::from_be_slice(&[0x11, 0xcd], 16).unwrap());
        assert_eq!(
            to_array_pad_zero(&x.num, 9),
            [0, 0, 0, 0, 0, 0, 0, 0x11, 0xcd_u8]
        );
    }

    #[test]
    fn test_into_string_and_display() {
        let x = BoxedUint::from_be_hex(
            "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18",
            256,
        )
        .unwrap();
        let s: String = x.to_string();
        assert_eq!(
            s,
            "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18"
        );
    }

    #[test]
    fn test_serde() {
        for prec in [64u32, 128u32, 256u32] {
            let x =
                SerUint::new(BoxedUint::from_be_slice(&hex!("01020304 05060700"), prec).unwrap());
            let ser = serde_json::to_string(&x).unwrap();
            let de: SerUint = serde_json::from_str(&ser).unwrap();
            assert_eq!(de.num, x.num, "different values");
            assert_eq!(de.num.nlimbs(), x.num.nlimbs(), "different precisions");
        }
    }
}
