/*!
This module defines a list of all primitive types and functions
needed to express the meaning of certain variables better.

For instance in [RFC2945] the big prime number that acts
as the modulus in every mathematical power operation is called `N`.

In order to increase readability the type of `N` is
an alias to [`BigNumber`] that aims to express the meaning,
so [`PrimeModulus`] is same as `N` which is a [`BigNumber`].

This scheme is applied for all variables used in the calculus.

[RFC2945]: https://datatracker.ietf.org/doc/html/rfc2945
*/

use std::sync::Arc;

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, Odd,
};
use serde::{Deserialize, Serialize};

use crate::big_number::{needed_precision, new_rand, to_array_pad_zero, SerUint};
use crate::hash::{from_hash, hash, Digest, Hash, HashFunc, Update, HASH_LENGTH};
#[cfg(all(test, feature = "norand"))]
use crate::protocol_details::testdata;
use crate::{Result, Srp6Error};

const STRONG_SESSION_KEY_LENGTH: usize = HASH_LENGTH * 2;

/// Refers to a large safe prime called `N` (`N = 2q+1`, where `q` is prime)
#[doc(alias = "N")]
pub type PrimeModulus = Odd<BoxedUint>;

/// Refers to the modulus generator `g`
#[doc(alias = "g")]
pub type Generator = BoxedUint;

/// Refers to a User's salt called `s`
#[doc(alias = "s")]
pub type Salt = Vec<u8>;

/// Refers to a Public shared key called A (user), B (server)
#[doc(alias("A", "B"))]
pub type PublicKey = SerUint;

/// Refers to a private secret random number a (user), b (server)
#[doc(alias("a", "b"))]
pub type PrivateKey = BoxedUint;

/// Password Verifier is the users secret on the server side
#[doc(alias = "v")]
pub type PasswordVerifier = SerUint;

/// Refers to a multiplier parameter `k` (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
#[doc(alias = "k")]
pub type MultiplierParameter = BoxedUint;

/// Refers to the SessionKey `S`
#[doc(alias = "S")]
pub type SessionKey = BoxedUint;
/// Refers to the StrongSessionKey `K`
#[doc(alias = "K")]
pub type StrongSessionKey = BoxedUint;

/// Refers to `M` and `M1` Proof of server and client
#[doc(alias("M", "M1"))]
pub type Proof = SerUint;
/// Refers to `M2` the hash of Proof
#[doc(alias = "M2")]
pub type StrongProof = SerUint;

/// Username `I` as [`String`]
#[doc(alias = "I")]
pub type Username = String;
/// Username reference `I` as [`&str`]
pub type UsernameRef<'a> = &'a str;
/// Clear text password `p` as [`str`]
#[doc(alias = "p")]
pub type ClearTextPassword = str;

/// [`Username`] and [`ClearTextPassword`] used on the client side
#[derive(Debug, Clone)]
pub struct UserCredentials<'a> {
    pub username: UsernameRef<'a>,
    pub password: &'a ClearTextPassword,
}

/// User details composes [`Username`], [`Salt`] and [`PasswordVerifier`] in one struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDetails {
    pub username: Username,
    pub salt: Salt,
    pub verifier: PasswordVerifier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserHandshake {
    pub username: Username,
    pub user_publickey: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerHandshake {
    pub salt: Salt,
    pub server_publickey: PublicKey,
}

#[derive(Debug, Clone)]
pub struct OpenConstants<const LEN: usize> {
    pub module: PrimeModulus,
    pub generator: Generator,
}

/// host version of a session key for a given user
/// S: is the session key of a user
/// u: is the hash of user and server pub keys
///
/// u = H(A, B)
/// S = (Av^u) ^ b
pub(crate) fn calculate_session_key_S_for_host<const KEYLEN: usize>(
    monty_N: Arc<BoxedMontyParams>, // N: &PrimeModulus,
    A: &PublicKey,
    B: &PublicKey,
    b: &PrivateKey,
    monty_v: &BoxedMontyForm,
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
    let u = &calculate_u::<KEYLEN>(A, B);
    let monty_A = BoxedMontyForm::new_with_arc(A.num.clone(), monty_N);
    let base = monty_A * monty_v.pow(&u);
    let S = base.pow(&b).retrieve();
    Ok(S)
}

/// client version of the session key calculation, depends on
/// - the users [`PrivateKey`] `x`
/// - the users [`PublicKey`] `A`
/// - the servers [`PublicKey`] `B`
/// - formulas found so far:
///   - `S = (B - (k * g^x)) ^ (a + (u * x)) % N`
///   - `S = (B - (k * v)) ^ (a + (u * x)) % N`
#[allow(clippy::many_single_char_names)]
pub(crate) fn calculate_session_key_S_for_client<const KEYLEN: usize>(
    monty_N: Arc<BoxedMontyParams>,
    g: &Generator,
    monty_g: &BoxedMontyForm,
    B: &PublicKey,
    A: &PublicKey,
    a: &PrivateKey,
    x: &PrivateKey,
) -> Result<SessionKey> {
    // safeguard B % N == 0
    if bool::from((&B.num % monty_N.modulus().as_nz_ref()).is_zero()) {
        return Err(Srp6Error::InvalidPublicKey(B.clone()));
    }
    let u = &calculate_u::<KEYLEN>(A, B);
    let exp = a + &(u * x);
    let g_mod_x = &monty_g.pow(x);
    let k = calculate_k::<KEYLEN>(monty_N.modulus(), g);
    let monty_k = BoxedMontyForm::new_with_arc(k, Arc::clone(&monty_N));
    let to_sub = monty_k * g_mod_x;
    let monty_B = BoxedMontyForm::new_with_arc(B.num.clone(), monty_N);
    let base = monty_B - &to_sub;
    let S = base.pow(&exp).retrieve();
    Ok(S)
}

/// the hash of a session key `S` that is called `K`
/// S: is the session key of a user
/// K: is the hash of S, just not that straight
pub(crate) fn calculate_session_key_hash_interleave_K<const KEYLEN: usize>(
    S: &SessionKey,
) -> StrongSessionKey {
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
    let mut vK: Vec<u8> = Vec::with_capacity(STRONG_SESSION_KEY_LENGTH);
    for h_Si in even_half_of_S_hash.iter().zip(odd_half_of_S_hash.iter()) {
        vK.push(*h_Si.0);
        vK.push(*h_Si.1);
    }
    let K = BoxedUint::from_le_slice(vK.as_ref(), needed_precision(STRONG_SESSION_KEY_LENGTH))
        .expect("précision non respectée");
    K
}

pub(crate) fn calculate_proof_M<const KEYLEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
    I: UsernameRef,
    s: &Salt,
    A: &PublicKey,
    B: &PublicKey,
    K: &StrongSessionKey,
) -> Proof {
    let xor_hash: Hash = calculate_hash_N_xor_g::<KEYLEN>(N, g);
    let username_hash = HashFunc::new().chain(I.as_bytes()).finalize();
    let digest = HashFunc::new()
        .chain(xor_hash)
        .chain(username_hash)
        .chain(&s)
        .chain(to_array_pad_zero(&A.num, KEYLEN))
        .chain(to_array_pad_zero(&B.num, KEYLEN))
        .chain(to_array_pad_zero(&K, STRONG_SESSION_KEY_LENGTH))
        .finalize();

    let M: Proof = SerUint::from_be_bytes(&digest, needed_precision(HASH_LENGTH));
    M
}

/// todo(verify): check if padding is needed or not
/// formula: `H(A | M | K)`
pub(crate) fn calculate_strong_proof_M2<const KEYLEN: usize>(
    A: &PublicKey,
    M: &Proof,
    K: &StrongSessionKey,
) -> StrongProof {
    let digest = HashFunc::new()
        .chain(to_array_pad_zero(&A.num, KEYLEN))
        .chain(to_array_pad_zero(&M.num, HASH_LENGTH))
        .chain(to_array_pad_zero(&K, STRONG_SESSION_KEY_LENGTH))
        .finalize();
    let M2: StrongProof = SerUint::from_be_bytes(&digest, needed_precision(HASH_LENGTH));
    M2
}

/// here we hash g and xor it with the hash of N
///
/// ```plain
/// M = H(H(N) xor H(g), H(I), s, A, B, K)
///       `````````````
///                    // this portion is calculated here
/// ```
fn calculate_hash_N_xor_g<const KEYLEN: usize>(N: &PrimeModulus, g: &Generator) -> Hash {
    let mut h = HashFunc::new()
        .chain(to_array_pad_zero(N, KEYLEN))
        .finalize();
    let h_g = HashFunc::new().chain(g.to_be_bytes()).finalize();
    for (i, v) in h.iter_mut().enumerate() {
        *v ^= h_g[i];
    }
    let H_n_g: Hash = h.into();
    H_n_g
}

/// here we calculate the `PasswordVerifier` called `v` based on `x`
/// **Note**: something that only needs to be done on user pw change, or user creation
/// `x`:  Private key (derived from p and s)
/// `v`:  Password verifier
/// `g`:  A generator modulo N
/// `N`:  A large safe prime (N = 2q+1, where q is prime)
/// formula: `v = g^x % N`
pub(crate) fn calculate_password_verifier_v(
    N: &PrimeModulus,
    g: &Generator,
    x: &PrivateKey,
) -> PasswordVerifier {
    let monty_g = BoxedMontyForm::new(
        g.clone(),
        BoxedMontyParams::new(N.clone()),
    );
    let v = monty_g.pow(x).retrieve();
    SerUint::new(v)

}

/// `u` is the hash of host's and client's [`PublicKey`]
/// formula: `H(PAD(A) | PAD(B))`
pub(crate) fn calculate_u<const KEYLEN: usize>(A: &PublicKey, B: &PublicKey) -> BoxedUint {
    let u = hash(&A.num, &B.num, KEYLEN);
    u
}

/// `A` is the [`PublicKey`] of the client
/// formula: `A = g^a % N`
pub(crate) fn calculate_pubkey_A(monty_g: &BoxedMontyForm, a: &PrivateKey) -> PublicKey {
    let A = monty_g.pow(a).retrieve();
    SerUint::new(A)
}

/// [`PublicKey`][B] is the hosts public key
/// `B = kv + g^b`
pub(crate) fn calculate_pubkey_B<const KEYLEN: usize>(
    monty_N: Arc<BoxedMontyParams>,
    g: &Generator,
    v: &BoxedMontyForm,
    b: &PrivateKey,
) -> PublicKey {
    let k = calculate_k::<KEYLEN>(&monty_N.modulus(), g);
    let monty_k = BoxedMontyForm::new_with_arc(k, Arc::clone(&monty_N));
    let B1 = v * monty_k;
    let monty_g = BoxedMontyForm::new_with_arc(
        g.clone(),
        Arc::clone(&monty_N),
    );
    let g_mod_N = monty_g.pow(b);
    let monty_b2 = B1 + g_mod_N;
    let B = monty_b2.retrieve();
    SerUint::new(B)
}

/// `x` is the users private key (only they know)
///
/// I:  Username                (is uppercased for WoW)
/// p:  Cleartext Password      (is uppercased for WoW)
/// s:  User's salt
/// x:  Private key (derived from p and s)
/// ph = H(I, ':', p)           (':' is a string literal)
/// x = H(s, ph)                (s is chosen randomly)
pub(crate) fn calculate_private_key_x<const KEYLEN: usize>(
    I: UsernameRef,
    p: &ClearTextPassword,
    s: &Salt,
) -> PrivateKey {
    let ph = calculate_p_hash(I, p);
    let digest = HashFunc::new().chain(s).chain(ph).finalize();
    let x: PrivateKey = from_hash::<KEYLEN>(&digest);
    x
}

/// hashes the user and the password (used for client private key `x`)
pub(crate) fn calculate_p_hash(I: UsernameRef, p: &ClearTextPassword) -> Hash {
    HashFunc::new()
        .chain(I.as_bytes())
        .chain(":".as_bytes())
        .chain(p.as_bytes())
        .finalize()
        .into()
}

/// `k = H(N | PAD(g))` (k = 3 for legacy SRP-6)
pub(crate) fn calculate_k<const KEYLEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
) -> MultiplierParameter {
    let digest = HashFunc::new()
        .chain(to_array_pad_zero(N, KEYLEN))
        .chain(to_array_pad_zero(g, KEYLEN))
        .finalize();
    from_hash::<KEYLEN>(&digest)
}

/// [`PrivateKey`] `a` or `b` is in fact just a big (positive) random number
pub(crate) fn generate_private_key_a(key_len: usize) -> PrivateKey {
    #[cfg_attr(feature = "norand", allow(unused_variables))]
    let res = new_rand(key_len);
    #[cfg(all(test, feature = "norand"))]
    let res = PrivateKey::from_be_slice(&testdata::A_PRIVATE, needed_precision(key_len))
        .expect("A_PRIVATE utilisé avec mauvaise taille");
    res
}

/// [`PrivateKey`] `a` or `b` is in fact just a big (positive) random number
pub(crate) fn generate_private_key_b(key_len: usize) -> PrivateKey {
    #[cfg_attr(feature = "norand", allow(unused_variables))]
    let res = new_rand(key_len);
    #[cfg(all(test, feature = "norand"))]
    let res = PrivateKey::from_be_slice(&testdata::B_PRIVATE, needed_precision(key_len))
        .expect("B_PRIVATE utilisé avec mauvaise taille");
    res
}

/// [`Salt`] `s` is a random number
pub(crate) fn generate_salt(key_len: usize) -> Salt {
    #[cfg_attr(feature = "norand", allow(unused_variables))]
    let res = new_rand(key_len).to_be_bytes().to_vec();
    #[cfg(all(test, feature = "norand"))]
    let res = testdata::SALT.to_vec();
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{protocol_details::testdata::{self, from_testdata}, OpenConstants};

    #[test]
    fn test_private_x() {
        let salt = &testdata::SALT.to_vec();
        let x = from_testdata(&testdata::X);
        let x_calc =
            calculate_private_key_x::<128>(&testdata::USERNAME, &testdata::PASSWORD, &salt);
        assert!(x_calc == x);
    }

    #[test]
    fn test_verifier_v() {
        let cst = OpenConstants::<128>::default();
        let verifier = from_testdata(&testdata::VERIFIER);
        let x = &from_testdata(&testdata::X);
        let v_calc = calculate_password_verifier_v(&cst.module, &cst.generator, &x);
        assert!(v_calc.num == verifier);
    }

    #[test]
    fn test_multiplier_k() {
        let cst = OpenConstants::<128>::default();
        let k = from_testdata(&testdata::K_MULTIPLIER);
        let k_calc = calculate_k::<128>(&cst.module, &cst.generator);
        assert_eq!(k_calc, k);
    }

    #[test]
    fn test_calculate_pubkey_a() {
        let cst = OpenConstants::<128>::default();
        let private_a = from_testdata(&testdata::A_PRIVATE);
        let public_a = from_testdata(&testdata::A_PUBLIC);
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let monty_g = BoxedMontyForm::new_with_arc(cst.generator.clone(), Arc::clone(&monty_n));
        let a_calc = calculate_pubkey_A(&monty_g, &private_a);
        assert_eq!(a_calc.num, public_a);
    }

    #[test]
    fn test_calculate_pubkey_b() {
        let cst = OpenConstants::<128>::default();
        let verifier = from_testdata(&testdata::VERIFIER);
        let private_b = from_testdata(&testdata::B_PRIVATE);
        let public_b = from_testdata(&testdata::B_PUBLIC);
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let monty_v = BoxedMontyForm::new_with_arc(verifier, Arc::clone(&monty_n));
        let b_calc = calculate_pubkey_B::<128>(
            monty_n,
            &cst.generator,
            &monty_v,
            &private_b,
        );
        assert_eq!(b_calc.num, public_b);
    }

    #[test]
    fn test_calculate_secret_host() {
        let cst = OpenConstants::<128>::default();
        let verifier = from_testdata(&testdata::VERIFIER);
        let public_a = from_testdata(&testdata::A_PUBLIC);
        let private_b = from_testdata(&testdata::B_PRIVATE);
        let public_b = from_testdata(&testdata::B_PUBLIC);
        let secret = from_testdata(&testdata::SECRET);
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let monty_v = BoxedMontyForm::new_with_arc(verifier, Arc::clone(&monty_n));
        let calc_secret = calculate_session_key_S_for_host::<128>(
            monty_n,
            &SerUint::new(public_a),
            &SerUint::new(public_b),
            &private_b,
            &monty_v,
        )
        .unwrap();
        assert_eq!(calc_secret, secret);
    }

    #[test]
    fn test_calculate_secret_client() {
        let cst = OpenConstants::<128>::default();
        let public_a = from_testdata(&testdata::A_PUBLIC);
        let private_a = from_testdata(&testdata::A_PRIVATE);
        let public_b = from_testdata(&testdata::B_PUBLIC);
        let x = from_testdata(&testdata::X);
        let secret = from_testdata(&testdata::SECRET);
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let monty_g = BoxedMontyForm::new_with_arc(cst.generator.clone(), Arc::clone(&monty_n));
        let calc_secret = calculate_session_key_S_for_client::<128>(
            monty_n,
            &cst.generator,
            &monty_g,
            &SerUint::new(public_b),
            &SerUint::new(public_a),
            &private_a,
            &x,
        )
        .unwrap();
        assert_eq!(calc_secret, secret);
    }
}
