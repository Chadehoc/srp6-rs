use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint,
};
use serde::{de::Visitor, Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;

use crypto_bigint::{rand_core::OsRng, Random, Uint};

pub mod np {
    #[cfg(feature = "empirical")]
    const TOLERANCE: u32 = 2 * crypto_bigint::Limb::BITS;
    #[cfg(not(feature = "empirical"))]
    const TOLERANCE: u32 = 0;

    pub const fn needed_precision<const NBYTES: usize>() -> u32 {
        (NBYTES * 8) as u32 * 2 - TOLERANCE
    }

    pub const fn needed_precision_pk<const NBYTES: usize>() -> u32 {
        (NBYTES * 2) as u32 * 2 - TOLERANCE
    }
}

pub fn num_effective_bytes(big: &BoxedUint) -> usize {
    (big.bits() as usize).div_ceil(8)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, derive_more::Display)]
#[display("{}", num)]
pub struct PrivUint {
    pub num: BoxedUint,
    pub monty: Option<BoxedMontyForm>,
}

impl PrivUint {
    pub fn new(num: BoxedUint) -> PrivUint {
        PrivUint { num, monty: None }
    }

    pub fn from_be_bytes(bytes: &[u8], bits_precision: u32) -> PrivUint {
        PrivUint::new(
            BoxedUint::from_be_slice(bytes, bits_precision).expect("précision exacte attendue"),
        )
    }

    pub fn get_monty<const KEYLEN: usize>(&mut self, n: &Arc<BoxedMontyParams>) -> &BoxedMontyForm {
        if self.monty.is_none() {
            self.monty = Some(BoxedMontyForm::new_with_arc(
                self.num.widen(np::needed_precision::<KEYLEN>()),
                Arc::clone(n),
            ));
        }
        self.monty.as_ref().unwrap()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, derive_more::Display)]
#[display("{}", num)]
pub struct SerUint {
    pub num: BoxedUint,
    pub monty: Option<BoxedMontyForm>,
}

impl SerUint {
    pub fn new(num: BoxedUint) -> SerUint {
        SerUint { num, monty: None }
    }

    pub fn from_be_bytes(bytes: &[u8], bits_precision: u32) -> SerUint {
        SerUint::new(
            BoxedUint::from_be_slice(bytes, bits_precision).expect("précision exacte attendue"),
        )
    }

    pub fn get_monty<const KEYLEN: usize>(&mut self, n: &Arc<BoxedMontyParams>) -> &BoxedMontyForm {
        if self.monty.is_none() {
            self.monty = Some(BoxedMontyForm::new_with_arc(
                self.num.widen(np::needed_precision::<KEYLEN>()),
                Arc::clone(n),
            ));
        }
        self.monty.as_ref().unwrap()
    }
}

impl Serialize for SerUint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let prec = self.num.bits_precision().to_be_bytes();
        let data = self.num.to_be_bytes();
        let total = [prec.as_slice(), data.as_ref()].concat();
        serializer.serialize_bytes(&total)
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

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut tmp = [0u8; 4];
                for digit in tmp.iter_mut() {
                    *digit = seq.next_element()?.expect("prec not encoded");
                }
                let prec = u32::from_be_bytes(tmp);
                let mut data = Vec::new();
                while let Some(value) = seq.next_element()? {
                    data.push(value);
                }
                let num =
                    BoxedUint::from_be_slice(&data, prec).expect("the size is ok by construction");
                Ok(SerUint::new(num))
            }
        }

        deserializer.deserialize_bytes(UintVisitor)
    }
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
    fn test_serde_json() {
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
