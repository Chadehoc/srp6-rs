use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

/// also exporting the trait here
pub use num_traits::Zero;
pub use std::ops::{Add, Mul, Rem, Sub};

/// [`BigNumber`] helps to work with big numbers as in openssl used.
#[derive(PartialEq, Clone, PartialOrd, Serialize, Deserialize)]
pub struct BigNumber(BigUint);

#[derive(Error, Debug)]
pub enum BigNumberError {
    #[error("Invalid hex string.")]
    InvalidHexStr,
}

/// new empty unsigned big number
impl Default for BigNumber {
    fn default() -> Self {
        Self(BigUint::new(vec![]))
    }
}

impl BigNumber {
    /// new random initialized big number
    pub fn new_rand(n_bytes: usize) -> Self {
        let mut rng = thread_rng();
        let a = rng.gen_biguint((n_bytes * 8) as u64);
        // let a = if a.is_negative() { a.abs() } else { a };

        Self(a)
    }

    /// [`raw`] is expected to be big endian
    pub fn from_bytes_be(raw: &[u8]) -> Self {
        Self(BigUint::from_bytes_be(raw))
    }

    /// [`raw`] is expected to be little endian
    pub fn from_bytes_le(raw: &[u8]) -> Self {
        Self(BigUint::from_bytes_le(raw))
    }

    /// from a hex string, hex strings are always big endian:
    /// High
    ///    -> Low
    ///  "123acab"
    pub fn from_hex_str_be(str: &str) -> std::result::Result<Self, BigNumberError> {
        let str = if str.len() % 2 != 0 {
            format!("{:0>len$}", str, len = (str.len() / 2 + 1) * 2)
        } else {
            str.to_owned()
        };

        Ok(Self::from_bytes_be(
            hex::decode(str)
                .map_err(|_| BigNumberError::InvalidHexStr)?
                .as_slice(),
        ))
    }

    pub fn modpow(&self, exponent: &Self, modulo: &Self) -> Self {
        self.0.modpow(&exponent.0, &modulo.0).into()
    }

    pub fn num_bytes(&self) -> usize {
        (self.0.bits() as usize + 7) / 8
    }

    /// returns the byte vec in little endian byte order
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_bytes_le()
    }

    pub fn to_array<const N: usize>(&self) -> [u8; N] {
        self.to_array_pad_zero::<N>()
    }

    /// returns the byte vec in little endian byte order, padded by 0 for `len` bytes
    pub fn to_array_pad_zero<const N: usize>(&self) -> [u8; N] {
        let mut r = [0_u8; N];
        for (i, x) in self.to_vec().iter().take(N).enumerate() {
            r[i] = *x;
        }

        r
    }
}

#[test]
fn test_mod_exp() {
    let a = BigNumber::from_hex_str_be("6").unwrap();
    let p = BigNumber::from_hex_str_be("3").unwrap();
    let m = BigNumber::from_hex_str_be("7").unwrap();
    let r = a.modpow(&p, &m);

    assert_eq!(&r, &BigNumber::from(6), "{} is not 6", &r);
    assert_eq!(
        &a.modpow(&p, &m),
        &BigNumber::from(6),
        "{}.modExp(3, 7) is not 6",
        &r
    );
}

impl Debug for BigNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "BigNumber(\"{}\")", self)
    }
}

// region from traits
/// from a [`n`] basic u32
impl From<u32> for BigNumber {
    fn from(n: u32) -> Self {
        Self(BigUint::from(n))
    }
}

impl From<BigUint> for BigNumber {
    fn from(a: BigUint) -> Self {
        Self(a)
    }
}

impl<const N: usize> From<[u8; N]> for BigNumber {
    fn from(k: [u8; N]) -> Self {
        Self::from_bytes_le(&k)
    }
}

impl From<Sha1> for BigNumber {
    fn from(hasher: Sha1) -> Self {
        hasher.finalize().as_slice().into()
    }
}

impl From<&[u8]> for BigNumber {
    fn from(somewhere: &[u8]) -> Self {
        Self::from_bytes_le(somewhere)
    }
}

impl From<&BigNumber> for String {
    fn from(x: &BigNumber) -> Self {
        x.0.to_str_radix(16).to_uppercase()
    }
}

impl From<BigNumber> for String {
    fn from(x: BigNumber) -> Self {
        (&x).into()
    }
}

impl TryFrom<&str> for BigNumber {
    type Error = BigNumberError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::from_hex_str_be(value)
    }
}

impl TryFrom<String> for BigNumber {
    type Error = BigNumberError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_hex_str_be(value.as_str())
    }
}

#[test]
fn should_try_from_string() {
    use std::convert::TryInto;

    let s = "ab11cd".to_string();
    let x: BigNumber = s.try_into().unwrap();
    assert_eq!(x.to_vec(), &[0xcd, 0x11, 0xab]);
}

#[test]
fn should_from_bytes() {
    let x = BigNumber::from_bytes_be(&[0xab, 0x11, 0xcd]);
    assert_eq!(x.to_vec(), &[0xcd, 0x11, 0xab]);
}

#[test]
fn should_to_vec() {
    let x = BigNumber::from_hex_str_be("ab11cd").unwrap();
    assert_eq!(x.to_vec(), &[0xcd, 0x11, 0xab]);
}

#[test]
fn should_random_initialize() {
    let x = BigNumber::new_rand(10);
    assert_ne!(x, BigNumber::default());
}

#[test]
fn should_pad_0() {
    let x = BigNumber::from_bytes_be(&[0x11, 0xcd]);
    assert_eq!(x.to_array_pad_zero::<3>(), [0xcd_u8, 0x11, 0]);
}

#[test]
fn should_should_work_with_odd_byte_count() {
    assert_eq!(BigNumber::from_hex_str_be("6").unwrap().to_string(), "6");
}
// endregion

// region modulo
impl Rem for &BigNumber {
    type Output = BigNumber;

    fn rem(self, rhs: &BigNumber) -> Self::Output {
        (&self.0).rem(&rhs.0).into()
    }
}
#[test]
fn should_modulo_ref() {
    let a = &BigNumber::from(10);
    assert_eq!(a.rem(&BigNumber::from(4)), BigNumber::from(10 % 4));
}
impl Rem for BigNumber {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        (&self).rem(&rhs)
    }
}
#[test]
fn should_modulo() {
    let exp = BigNumber::from(7 % 6);
    assert_eq!(BigNumber::from(7) % BigNumber::from(6), exp);
}
// endregion

// region mul, add, sub
impl Mul for BigNumber {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        (self.0 * rhs.0).into()
    }
}

impl Mul for &BigNumber {
    type Output = BigNumber;

    fn mul(self, rhs: Self) -> Self::Output {
        (&self.0 * &rhs.0).into()
    }
}

#[test]
fn test_big_num_mul() {
    let a = BigNumber::from(4);
    let b = BigNumber::from(2);
    let exp = BigNumber::from(8);
    assert_eq!(a * b, exp);
}

impl Add for BigNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.0.add(rhs.0).into()
    }
}
impl<'b> Add<&'b BigNumber> for &BigNumber {
    type Output = BigNumber;

    fn add(self, rhs: &'b BigNumber) -> Self::Output {
        (&self.0).add(&rhs.0).into()
    }
}

impl Sub for BigNumber {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.0.sub(rhs.0).into()
    }
}
#[test]
fn should_subtract() {
    let (a, b) = (BigNumber::from(6), BigNumber::from(1));
    assert_eq!(a - b, BigNumber::from(5));
}

impl<'b> Sub<&'b BigNumber> for &BigNumber {
    type Output = BigNumber;

    fn sub(self, rhs: &'b BigNumber) -> Self::Output {
        (&self.0).sub(&rhs.0).into()
    }
}
#[test]
fn should_subtract_refs() {
    let (a, b) = (BigNumber::from(6), BigNumber::from(6));
    assert_eq!(&a - &b, BigNumber::from(0));
}
// endregion

impl Display for BigNumber {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let x: String = self.into();
        write!(f, "{}", x)
    }
}

#[test]
fn test_into_string_and_display() {
    let x = BigNumber::from_hex_str_be(
        "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18",
    )
    .unwrap();
    let s: String = x.into();
    assert_eq!(
        s,
        "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18"
    );
    assert_eq!(
        format!(
            "{}",
            BigNumber::from_hex_str_be(
                "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18",
            )
            .unwrap()
        ),
        "3E9D557B7899AC2A8DEC8D0046FB310A42A233BD1DF0244B574AB946A22A4A18"
    );
}

impl Zero for BigNumber {
    fn zero() -> Self {
        BigUint::zero().into()
    }

    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}
