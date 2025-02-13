//! Utilities around [`crypto_bigint::BoxedUint`].

use std::cell::OnceCell;
use std::fmt::Debug;
use std::sync::Arc;

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    rand_core::OsRng,
    BoxedUint, Random, Uint, Limb,
};
use serde::{de::Visitor, Deserialize, Serialize};
use zeroize::Zeroize;

/// Give good values to [`crypto_bigint::BoxedUint::bits_precision`].
///
/// Meant for `use np::*`.
///
/// Those values are critical for performance, but if lot large enough,
/// computations will crash with overflow. The safe side is to double the needed
/// size, but empirically (under feature `emp`) a bit shorter is ok (by a fixed,
/// not proportional values, because of Montgomery form compatibility
/// constraints). See test `primitives::tests::test_needed_precisions`, and
/// fuzzing tests.
pub mod np {
    #[cfg(feature = "emp")]
    const TOLERANCE: u32 = 128;
    #[cfg(not(feature = "emp"))]
    const TOLERANCE: u32 = 0;

    /// Needed precision (in bits) for full length keys.
    ///
    /// See module doc [`super`].
    pub const fn needed_precision<const KEYLEN: usize>() -> u32 {
        (KEYLEN * 8) as u32 * 2 - TOLERANCE
    }

    /// Needed precision (in bits) for private keys, which are 4x smaller.
    ///
    /// See module doc [`super`].
    pub const fn needed_precision_pk<const NBYTES: usize>() -> u32 {
        (NBYTES * 2) as u32 * 2 - TOLERANCE
    }
}

/// Nb of effective bytes used to represent this number.
pub fn num_effective_bytes(big: &BoxedUint) -> usize {
    (big.bits() as usize).div_ceil(8)
}

fn from_be_bytes(bytes: &[u8], bits_precision: u32) -> BoxedUint {
    BoxedUint::from_be_slice(bytes, bits_precision).unwrap_or_else(|e| {
        panic!(
            "wrong bits precision, expected {bits_precision}, given {}, error {e}",
            bytes.len() * 8
        )
    })
}

/// Add to [`BoxedUint`] an optional cache for its Montgomery form.
///
/// Non-serialisable version, typically for private keys, which
/// never transit over the network.
#[derive(Debug, Clone, Default, PartialEq, Eq, derive_more::Display)]
#[display("{}", num)]
pub struct MonUint {
    /// Wrapped value
    pub(crate) num: BoxedUint,
    /// Optional cache
    pub(crate) monty: OnceCell<BoxedMontyForm>,
}

impl MonUint {
    pub fn new(num: BoxedUint) -> MonUint {
        MonUint {
            num,
            monty: OnceCell::new(),
        }
    }

    /// Panics if wrong precision.
    pub fn from_be_bytes(bytes: &[u8], bits_precision: u32) -> MonUint {
        MonUint::new(from_be_bytes(bytes, bits_precision))
    }

    /// Get the Montgomery form of the number, with a cache to compute it only
    /// once on first demand.
    pub fn get_monty<const KEYLEN: usize>(&self, n: &Arc<BoxedMontyParams>) -> &BoxedMontyForm {
        match self.monty.get() {
            Some(m) => m,
            None => {
                let m = BoxedMontyForm::new_with_arc(
                    self.num.widen(np::needed_precision::<KEYLEN>()),
                    Arc::clone(n),
                );
                self.monty.set(m).unwrap();
                self.monty.get().unwrap()
            }
        }
    }
}

impl Zeroize for MonUint {
    fn zeroize(&mut self) {
        self.num = BoxedUint::zero();
        self.monty = OnceCell::default();
    }
}

#[cfg(feature = "arbitrary")]
/// Targetting SRP-2048 private keys (64 bytes).
impl<'a> arbitrary::Arbitrary<'a> for MonUint {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes = u.arbitrary::<[u8; 64]>()?;
        Ok(Self::from_be_bytes(&bytes, 64 * 8))
    }
}

/// Like a [``MonUint`] but serializable.
///
/// For e.g. public keys, that can be transferred over the network.
#[derive(Debug, Clone, Default, PartialEq, Eq, derive_more::Display)]
#[display("{}", num)]
pub struct SerUint {
    /// Wrapped value
    pub(crate) num: BoxedUint,
    /// Optional cache
    pub(crate) monty: OnceCell<BoxedMontyForm>,
}

impl SerUint {
    pub fn new(num: BoxedUint) -> SerUint {
        SerUint {
            num,
            monty: OnceCell::new(),
        }
    }

    /// Panics if wrong precision.
    pub fn from_be_bytes(bytes: &[u8], bits_precision: u32) -> SerUint {
        SerUint::new(from_be_bytes(bytes, bits_precision))
    }

    /// Only for [`SerUint`].
    pub fn to_be_bytes(&self) -> Box<[u8]> {
        self.num.to_be_bytes()
    }

    /// Get the Montgomery form of the number, with a cache to compute it only
    /// once on first demand.
    pub fn get_monty<const KEYLEN: usize>(&self, n: &Arc<BoxedMontyParams>) -> &BoxedMontyForm {
        match self.monty.get() {
            Some(m) => m,
            None => {
                let m = BoxedMontyForm::new_with_arc(
                    self.num.widen(np::needed_precision::<KEYLEN>()),
                    Arc::clone(n),
                );
                self.monty.set(m).unwrap();
                self.monty.get().unwrap()
            }
        }
    }

    /// Check the (key-)size of the represented number.
    pub fn num_bytes(&self) -> usize {
        num_effective_bytes(&self.num)
    }
}

impl Zeroize for SerUint {
    fn zeroize(&mut self) {
        self.num = BoxedUint::zero();
        self.monty = OnceCell::default();
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

            // json, for example
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

            // postcard, for example
            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {
                let tmp: [u8; 4] = v[0..4].try_into().unwrap();
                let prec = u32::from_be_bytes(tmp);
                let num =
                    BoxedUint::from_be_slice(&v[4..], prec).expect("size ok by construction");
                Ok(SerUint::new(num))
            }
        }

        deserializer.deserialize_bytes(UintVisitor)
    }
}

/// Wraps crypto_bigint's random number generation.
///
/// Used for private keys and salt.
pub fn new_rand(nbytes: usize) -> BoxedUint {
    const FOR128: usize = 128 / Limb::BYTES;
    const FOR64: usize = 64 / Limb::BYTES;
    const FOR32: usize = 32 / Limb::BYTES;
    const FOR16: usize = 16 / Limb::BYTES;
    match nbytes {
        // 128 bytes, for SRP4096 pk
        Uint::<FOR128>::BYTES => Uint::<FOR128>::random(&mut OsRng).into(),
        // 64 for SRP2048 pk
        Uint::<FOR64>::BYTES => Uint::<FOR64>::random(&mut OsRng).into(),
        // 32 for SRP1024 pk
        Uint::<FOR32>::BYTES => Uint::<FOR32>::random(&mut OsRng).into(),
        // 16 for salt (whatever the key length)
        Uint::<FOR16>::BYTES => Uint::<FOR16>::random(&mut OsRng).into(),
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
    use crate::{OpenConstants, UserDetails, user::Srp6User};

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

    #[test]
    fn test_serde_postcard() {
        let cst = OpenConstants::<256>::default();
        let details = Srp6User::<256>::generate_new_user_secrets(
            "username",
            "password",
            &cst);
        let transfer = postcard::to_stdvec(&details).expect("ser nok");
        let details_srv = postcard::from_bytes::<UserDetails>(&transfer).expect("deser nok");
        assert_eq!(details_srv.username, details.username);
        assert_eq!(details_srv.salt, details.salt);
    }

}
