//! Individual type aliases and computations defined in the RFCs.

use std::sync::Arc;

use crypto_bigint::{
    BoxedUint, Odd,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::bignum::{MonUint, SerUint, new_rand, np};
use crate::hash::{Digest, HASH_LENGTH, Hash, HashFunc, Update, from_hash, to_array_pad_zero};
use crate::{Result, Srp6Error};

/// Size of the `K` interleaved hash
pub const SESSION_KEY_HASH_LENGTH: usize = HASH_LENGTH * 2;

/// Size of the salt
pub const SALT_LENGTH: usize = 16;

/// Large safe modulus called `N`
#[doc(alias = "N")]
pub type PrimeModulus = Odd<BoxedUint>;

/// Modulus generator `g`
#[doc(alias = "g")]
pub type Generator = MonUint;

/// User's salt called `s`
#[doc(alias = "s")]
pub type Salt = [u8; SALT_LENGTH];

/// Public shared key called A (user), B (server)
#[doc(alias("A", "B"))]
pub type PublicKey = SerUint;

/// Private secret random number a (user), b (server)
#[doc(alias("a", "b"))]
pub type PrivateKey = MonUint;

/// Password Verifier is the users secret on the server side
#[doc(alias = "v")]
pub type PasswordVerifier = SerUint;

/// Multiplier parameter `k` = H(N, g)
#[doc(alias = "k")]
pub type MultiplierParameter = MonUint;

/// SessionKey `S`.
///
/// This is the only secret that will escape the handshake.
#[doc(alias = "S")]
pub type SessionKey = Zeroizing<BoxedUint>;

/// Session key hash `K`
#[doc(alias = "K")]
pub type SessionKeyHash = [u8; SESSION_KEY_HASH_LENGTH];

/// `M` and `M1` Proof of server and client
#[doc(alias("M", "M1", "M2"))]
pub type Proof = [u8; HASH_LENGTH];

/// Username `I` as [`String`]
#[doc(alias = "I")]
pub type Username = String;

/// Username reference `I` as [`&str`]
pub type UsernameRef<'a> = &'a str;

/// User details sent to the server at creation time
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UserDetails {
    pub username: Username,
    pub salt: Salt,
    pub verifier: PasswordVerifier,
}

/// User handshake data sent to the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserHandshake {
    pub username: Username,
    pub user_publickey: PublicKey,
}

/// Server handshake sent to the client.
///
/// Will be zeroized after use (contains the salt).
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ServerHandshake {
    pub salt: Salt,
    pub server_publickey: PublicKey,
}

/// Critical constants for SRP.
///
/// Use only recommended ones in RFC5054 (provided for 4096 and 2048 bits, 1024 only for tests).
#[derive(Debug, Clone)]
pub struct OpenConstants<const LEN: usize> {
    pub module: PrimeModulus,
    pub generator: Generator,
}

/// Host version of a session key for a given user.
///
/// ```plain, ignore
/// u = H(A, B)
/// S = (Av^u) ^ b
/// ```
pub(crate) fn calculate_session_key_S_for_host<const KEYLEN: usize>(
    monty_N: &Arc<BoxedMontyParams>,
    A: &PublicKey,
    B: &PublicKey,
    b: &PrivateKey,
    v: &PasswordVerifier,
) -> Result<SessionKey> {
    // A comes from the client
    // If server and client do not use the same key_len,
    // crypto_bigint will raise an assert... check ahead
    if A.num.nlimbs() != monty_N.modulus().nlimbs() {
        return Err(Srp6Error::InvalidPublicKey(A.clone()));
    }
    // safeguard A % N == 0 should be checked
    if bool::from((&A.num % monty_N.modulus().as_nz_ref()).is_zero()) {
        return Err(Srp6Error::InvalidPublicKey(A.clone()));
    }
    let u = calculate_u::<KEYLEN>(A, B);
    let monty_A = A.get_monty::<KEYLEN>(monty_N);
    let monty_v = v.get_monty::<KEYLEN>(monty_N);
    let base = monty_A * monty_v.pow(&u);
    let S = base.pow(&b.num).retrieve();
    Ok(Zeroizing::new(S))
}

/// Client version of the session key calculation.
///
/// ```plain, ignore
/// S = ((B - k * g^x) ^ (a + u * x)) % N
/// ```
#[allow(clippy::many_single_char_names, reason = "historical from forked repo")]
pub(crate) fn calculate_session_key_S_for_client<const KEYLEN: usize>(
    monty_N: &Arc<BoxedMontyParams>,
    g: &Generator,
    B: &PublicKey,
    A: &PublicKey,
    a: &PrivateKey,
    x: PrivateKey,
) -> Result<SessionKey> {
    // safeguard B % N == 0
    if bool::from((&B.num % monty_N.modulus().as_nz_ref()).is_zero()) {
        return Err(Srp6Error::InvalidPublicKey(B.clone()));
    }
    let u = calculate_u::<KEYLEN>(A, B);
    let ux = u * &x.num;
    let ux = ux.widen(np::needed_precision_pk::<KEYLEN>());
    let exp = &a.num + ux;
    let monty_g = g.get_monty::<KEYLEN>(monty_N);
    let g_mod_x = &monty_g.pow(&x.num);
    let k = calculate_k::<KEYLEN>(monty_N.modulus(), g);
    let monty_k = k.get_monty::<KEYLEN>(monty_N);
    let to_sub = monty_k * g_mod_x;
    let monty_B = B.get_monty::<KEYLEN>(monty_N);
    let base = monty_B - &to_sub;
    let S = base.pow(&exp).retrieve();
    Ok(Zeroizing::new(S))
}

/// Special hash of a session key `S`, called `K`.
pub(crate) fn calculate_session_key_hash_interleave_K<const KEYLEN: usize>(
    S: &SessionKey,
) -> SessionKeyHash {
    let S = to_array_pad_zero(S, KEYLEN);
    // take the even bytes out of S
    let mut half = Vec::with_capacity(KEYLEN / 2);
    for Si in S.iter().step_by(2) {
        half.push(*Si);
    }
    // hash the even portion of S
    let even_half_of_S_hash = HashFunc::new().chain(&half).finalize();
    // take the odd bytes of S
    half.clear();
    for Si in S.iter().skip(1).step_by(2) {
        half.push(*Si);
    }
    // hash the odd portion of S
    let odd_half_of_S_hash = HashFunc::new().chain(&half).finalize();
    // interleave
    let mut K: SessionKeyHash = [0u8; SESSION_KEY_HASH_LENGTH];
    for (i, h_Si) in even_half_of_S_hash
        .iter()
        .zip(odd_half_of_S_hash.iter())
        .enumerate()
    {
        K[2 * i] = *h_Si.0;
        K[2 * i + 1] = *h_Si.1;
    }
    K
}

/// Proof `M` common for server and client
pub(crate) fn calculate_proof_M<const KEYLEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
    I: UsernameRef,
    s: &Salt,
    A: &PublicKey,
    B: &PublicKey,
    K: &SessionKeyHash,
) -> Proof {
    let xor_hash: Hash = calculate_hash_N_xor_g::<KEYLEN>(N, g);
    let username_hash = HashFunc::new().chain(I.as_bytes()).finalize();
    let digest = HashFunc::new()
        .chain(xor_hash)
        .chain(username_hash)
        .chain(s)
        .chain(to_array_pad_zero(&A.num, KEYLEN))
        .chain(to_array_pad_zero(&B.num, KEYLEN))
        .chain(K)
        .finalize();
    digest.into()
}

/// Proof hash `M2`.
///
/// formula: `H(A | M | K)`
pub(crate) fn calculate_proof_M2<const KEYLEN: usize>(
    A: &PublicKey,
    M: &Proof,
    K: &SessionKeyHash,
) -> Proof {
    let digest = HashFunc::new()
        .chain(to_array_pad_zero(&A.num, KEYLEN))
        .chain(M)
        .chain(K)
        .finalize();
    digest.into()
}

/// Here we hash g and xor it with the hash of N
///
/// ```plain, ignore
/// M = H(H(N) xor H(g), H(I), s, A, B, K)
///       `````````````
///                    // this portion is calculated here
/// ```
fn calculate_hash_N_xor_g<const KEYLEN: usize>(N: &PrimeModulus, g: &Generator) -> Hash {
    let mut h = HashFunc::new()
        .chain(to_array_pad_zero(N, KEYLEN))
        .finalize();
    let h_g = HashFunc::new().chain(g.num.to_be_bytes()).finalize();
    for (i, v) in h.iter_mut().enumerate() {
        *v ^= h_g[i];
    }
    let H_n_g: Hash = h.into();
    H_n_g
}

/// here we calculate the `PasswordVerifier` called `v` based on `x` (derived from `p` ans `s`)
///
/// Formula: `v = g^x % N`
pub(crate) fn calculate_password_verifier_v(
    N: &PrimeModulus,
    g: &Generator,
    x: &PrivateKey,
) -> PasswordVerifier {
    let monty_g = BoxedMontyForm::new(g.num.clone(), BoxedMontyParams::new(N.clone()));
    let v = monty_g.pow(&x.num).retrieve();
    SerUint::new(v)
}

/// `u` is the hash of host's and client's [`PublicKey`].
///
/// Formula: `H(PAD(A) | PAD(B))`
pub(crate) fn calculate_u<const KEYLEN: usize>(A: &PublicKey, B: &PublicKey) -> BoxedUint {
    let digest = HashFunc::new()
        .chain(to_array_pad_zero(&A.num, KEYLEN))
        .chain(to_array_pad_zero(&B.num, KEYLEN))
        .finalize();
    from_hash(&digest) // u
}

/// `A` is the [`PublicKey`] of the client.
///
/// Formula: `A = g^a % N`
pub(crate) fn calculate_pubkey_A<const KEYLEN: usize>(
    g: &Generator,
    a: &PrivateKey,
    monty_N: &Arc<BoxedMontyParams>,
) -> PublicKey {
    let monty_g = g.get_monty::<KEYLEN>(monty_N);
    let A = monty_g.pow(&a.num).retrieve();
    SerUint::new(A)
}

/// `B` is the [`PublicKey`] of the host.
///
/// Formmula: `B = kv + g^b`
pub(crate) fn calculate_pubkey_B<const KEYLEN: usize>(
    monty_N: &Arc<BoxedMontyParams>,
    g: &Generator,
    v: &PasswordVerifier,
    b: &PrivateKey,
) -> PublicKey {
    let k = calculate_k::<KEYLEN>(monty_N.modulus(), g);
    let monty_k = k.get_monty::<KEYLEN>(monty_N);
    let monty_v = v.get_monty::<KEYLEN>(monty_N);
    let B1 = monty_v * monty_k;
    let monty_g = g.get_monty::<KEYLEN>(monty_N);
    let g_mod_N = monty_g.pow(&b.num);
    let monty_b2 = B1 + g_mod_N;
    let B = monty_b2.retrieve();
    SerUint::new(B)
}

/// `x` is a users private key.
///
/// I:  Username
/// p:  Cleartext Password
/// s:  User's salt
///
/// ```plain, ignore
/// ph = H(I, ':', p)           (':' is a string literal)
/// x = H(s, ph)                (s is chosen randomly)
/// ```
pub(crate) fn calculate_private_key_x<const KEYLEN: usize>(
    I: UsernameRef,
    p: &str,
    s: &Salt,
) -> PrivateKey {
    let ph = calculate_p_hash(I, p);
    let digest = HashFunc::new().chain(s).chain(ph).finalize();
    let x: PrivateKey = PrivateKey::new(from_hash(&digest));
    x
}

/// Hashes the user and the password
pub(crate) fn calculate_p_hash(I: UsernameRef, p: &str) -> Hash {
    HashFunc::new()
        .chain(I.as_bytes())
        .chain(":".as_bytes())
        .chain(p.as_bytes())
        .finalize()
        .into()
}

/// Multiplier `k = H(N | PAD(g))` (k was 3 for legacy SRP-6)
pub(crate) fn calculate_k<const KEYLEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
) -> MultiplierParameter {
    let digest = HashFunc::new()
        .chain(to_array_pad_zero(N, KEYLEN))
        .chain(to_array_pad_zero(&g.num, KEYLEN))
        .finalize();
    MultiplierParameter::new(from_hash(&digest))
}

/// [`PrivateKey`] `a` is a big random number
pub(crate) fn generate_private_key_a<const KEYLEN: usize>() -> PrivateKey {
    PrivateKey::new(new_rand(KEYLEN / 4))
}

/// [`PrivateKey`] `b` is a big random number
pub(crate) fn generate_private_key_b<const KEYLEN: usize>() -> PrivateKey {
    PrivateKey::new(new_rand(KEYLEN / 4))
}

/// [`Salt`] `s` is a random number
pub(crate) fn generate_salt() -> Salt {
    let res: Salt = new_rand(SALT_LENGTH)
        .to_be_bytes()
        .as_ref()
        .try_into()
        .unwrap();
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        OpenConstants,
        protocol_details::testdata::{self, *},
    };

    #[test]
    fn test_calculate_u() {
        let public_a = from_testdata(&testdata::A_PUBLIC);
        let public_b = from_testdata(&testdata::B_PUBLIC);
        let u = from_data_hash(&testdata::U);
        let calc_u = calculate_u::<128>(&SerUint::new(public_a), &SerUint::new(public_b));
        assert_eq!(calc_u, u);
    }

    #[test]
    fn test_private_x() {
        let salt = &testdata::SALT;
        let x = from_data_hash(&testdata::X);
        let x_calc = calculate_private_key_x::<128>(testdata::USERNAME, testdata::PASSWORD, salt);
        assert!(x_calc.num == x);
    }

    #[test]
    fn test_verifier_v() {
        let cst = OpenConstants::<128>::default();
        let verifier = from_testdata(&testdata::VERIFIER);
        let x = PrivateKey::new(from_data_hash(&testdata::X));
        let v_calc = calculate_password_verifier_v(&cst.module, &cst.generator, &x);
        assert!(v_calc.num == verifier);
    }

    #[test]
    fn test_multiplier_k() {
        let cst = OpenConstants::<128>::default();
        let k = MultiplierParameter::new(from_data_hash(&testdata::K_MULTIPLIER));
        let k_calc = calculate_k::<128>(&cst.module, &cst.generator);
        assert_eq!(k_calc, k);
    }

    #[test]
    fn test_calculate_pubkey_a() {
        let cst = OpenConstants::<128>::default();
        let private_a = PrivateKey::new(from_testdata_pk(&testdata::A_PRIVATE));
        let public_a = from_testdata(&testdata::A_PUBLIC);
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let a_calc = calculate_pubkey_A::<128>(&cst.generator, &private_a, &monty_n);
        assert_eq!(a_calc.num, public_a);
    }

    #[test]
    fn test_calculate_pubkey_b() {
        let cst = OpenConstants::<128>::default();
        let verifier = PasswordVerifier::new(from_testdata(&testdata::VERIFIER));
        let private_b = PrivateKey::new(from_testdata_pk(&testdata::B_PRIVATE));
        let public_b = from_testdata(&testdata::B_PUBLIC);
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let b_calc = calculate_pubkey_B::<128>(&monty_n, &cst.generator, &verifier, &private_b);
        assert_eq!(b_calc.num, public_b);
    }

    #[test]
    fn test_calculate_secret_host() {
        let cst = OpenConstants::<128>::default();
        let verifier = PasswordVerifier::new(from_testdata(&testdata::VERIFIER));
        let public_a = PublicKey::new(from_testdata(&testdata::A_PUBLIC));
        let private_b = PrivateKey::new(from_testdata_pk(&testdata::B_PRIVATE));
        let public_b = PublicKey::new(from_testdata(&testdata::B_PUBLIC));
        let secret = Zeroizing::new(from_testdata(&testdata::SECRET));
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let calc_secret = calculate_session_key_S_for_host::<128>(
            &monty_n, &public_a, &public_b, &private_b, &verifier,
        )
        .unwrap();
        assert_eq!(calc_secret, secret);
    }

    #[test]
    fn test_calculate_secret_client() {
        let cst = OpenConstants::<128>::default();
        let public_a = PublicKey::new(from_testdata(&testdata::A_PUBLIC));
        let private_a = PrivateKey::new(from_testdata_pk(&testdata::A_PRIVATE));
        let public_b = PublicKey::new(from_testdata(&testdata::B_PUBLIC));
        let x = PrivateKey::new(from_data_hash(&testdata::X));
        let secret = Zeroizing::new(from_testdata(&testdata::SECRET));
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let calc_secret = calculate_session_key_S_for_client::<128>(
            &monty_n,
            &cst.generator,
            &public_b,
            &public_a,
            &private_a,
            x,
        )
        .unwrap();
        assert_eq!(calc_secret, secret);
    }

    /// the real test is no overflow panic, not final asserts
    fn test_needed_precision<const KEYLEN: usize>()
    where
        OpenConstants<KEYLEN>: Default,
    {
        let needed = np::needed_precision::<KEYLEN>();
        println!("test prec for {KEYLEN}, needed {needed}");
        // hard : k*v + g^b, but now in Monty form passes easily
        let cst = OpenConstants::<KEYLEN>::default();
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let big_ser = SerUint::new(from_data::<KEYLEN>(&vec![255u8; KEYLEN]));
        let big_ser2 = SerUint::new(from_data::<KEYLEN>(&vec![255u8; KEYLEN]));
        let big_ser3 = SerUint::new(from_data::<KEYLEN>(&vec![255u8; KEYLEN]));
        let big_priv = MonUint::new(from_data_pk::<KEYLEN>(&vec![255u8; KEYLEN / 4]));
        let big_hash = MonUint::new(from_data_hash(&vec![255u8; HASH_LENGTH]));
        let b_calc = calculate_pubkey_B::<KEYLEN>(&monty_n, &cst.generator, &big_ser, &big_priv);
        assert!(b_calc.num.bits_precision() <= needed);
        println!("b_calc passed");
        let s_calc_client = calculate_session_key_S_for_client::<KEYLEN>(
            &monty_n,
            &cst.generator,
            &big_ser,
            &big_ser2,
            &big_priv,
            big_hash,
        )
        .unwrap();
        assert!(s_calc_client.bits_precision() <= needed);
        println!("big client passed");
        let s_calc_server = calculate_session_key_S_for_host::<KEYLEN>(
            &monty_n, &big_ser, &big_ser2, &big_priv, &big_ser3,
        )
        .unwrap();
        assert!(s_calc_server.bits_precision() <= needed);
        println!("big server passed");
    }

    #[test]
    fn test_needed_precisions() {
        test_needed_precision::<128>();
        test_needed_precision::<256>();
        test_needed_precision::<512>();
    }
}
