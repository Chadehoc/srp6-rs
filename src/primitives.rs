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

use log::debug;
use serde::{Deserialize, Serialize};

use crate::big_number::{modpow, needed_precision, new_rand, to_array_pad_zero, SerUint};
use crate::hash::{from_hash, hash, Digest, Hash, HashFunc, Update, HASH_LENGTH};
#[cfg(all(test, feature = "norand"))]
use crate::protocol_details::testdata;
use crate::{Result, Srp6Error};
use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint, Odd,
};

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
#[allow(non_snake_case)]
pub(crate) fn calculate_session_key_S_for_host<const KEYLEN: usize>(
    monty_N: Arc<BoxedMontyParams>, // N: &PrimeModulus,
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
    let u = &calculate_u::<KEYLEN>(A, B);
    // let base = &(A * &v.modpow(u, N));

    // let mparams = Arc::new(BoxedMontyParams::new(N.clone()));

    let monty_v = BoxedMontyForm::new_with_arc(v.num.clone(), Arc::clone(&monty_N));

    let monty_A = BoxedMontyForm::new_with_arc(A.num.clone(), Arc::clone(&monty_N));
    let base = monty_A * monty_v.pow(&u);

    let S = base.pow(&b).retrieve();

    debug!("S = {:?}", &S);

    Ok(S)
}

/*
ConstMontyForm<MOD: ConstMontyParams<LIMBS>, const LIMBS: usize>
*/
// TODO partout, chasser les clone() inutiles

/// client version of the session key calculation, depends on
/// - the users [`PrivateKey`] `x`
/// - the users [`PublicKey`] `A`
/// - the servers [`PublicKey`] `B`
/// - formulas found so far:
///   - `S = (B - (k * g^x)) ^ (a + (u * x)) % N`
///   - `S = (B - (k * v)) ^ (a + (u * x)) % N`
#[allow(non_snake_case)]
#[allow(clippy::many_single_char_names)]
pub(crate) fn calculate_session_key_S_for_client<const KEYLEN: usize>(
    //N: &PrimeModulus,
    monty_N: Arc<BoxedMontyParams>,
    g: &Generator,
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

    let monty_g = BoxedMontyForm::new_with_arc(g.clone(), Arc::clone(&monty_N));

    let g_mod_x = &monty_g.pow(x);
    let k = calculate_k::<KEYLEN>(monty_N.modulus(), g);
    let monty_k = BoxedMontyForm::new_with_arc(k, Arc::clone(&monty_N));

    let to_sub = monty_k * g_mod_x;
    let monty_B = BoxedMontyForm::new_with_arc(B.num.clone(), Arc::clone(&monty_N));
    // let base = B - ;
    let base = monty_B - &to_sub;
    /*
        if < 0

        {
        &(N - &to_sub) + B
    } else {
        B - &to_sub
    };
    */
    let S = base.pow(&exp).retrieve();
    debug!("S = {:?}", &S);

    Ok(S)
}

/// the hash of a session key `S` that is called `K`
/// S: is the session key of a user
/// K: is the hash of S, just not that straight
#[allow(non_snake_case)]
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
    debug!("K = {:?}", &K);

    K
}

#[allow(non_snake_case)]
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
    debug!("H(I) = {:?}", &username_hash);

    let digest = HashFunc::new()
        .chain(xor_hash)
        .chain(username_hash)
        .chain(&s)
        .chain(to_array_pad_zero(&A.num, KEYLEN))
        .chain(to_array_pad_zero(&B.num, KEYLEN))
        .chain(to_array_pad_zero(&K, STRONG_SESSION_KEY_LENGTH))
        .finalize();

    let M: Proof = SerUint::from_be_bytes(&digest, needed_precision(HASH_LENGTH));

    debug!("M = {:?}", &M);

    M
}

/// todo(verify): check if padding is needed or not
/// formula: `H(A | M | K)`
#[allow(non_snake_case)]
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
    debug!("M2 = {:?}", &M2);

    M2
}

/// here we hash g and xor it with the hash of N
///
/// ```plain
/// M = H(H(N) xor H(g), H(I), s, A, B, K)
///       `````````````
///                    // this portion is calculated here
/// ```
#[allow(non_snake_case)]
fn calculate_hash_N_xor_g<const KEYLEN: usize>(N: &PrimeModulus, g: &Generator) -> Hash {
    let mut h = HashFunc::new()
        .chain(to_array_pad_zero(N, KEYLEN))
        .finalize();
    let h_g = HashFunc::new().chain(g.to_be_bytes()).finalize();
    for (i, v) in h.iter_mut().enumerate() {
        *v ^= h_g[i];
    }

    let H_n_g: Hash = h.into();
    debug!("H(N) xor H(g) = {:X?}", &H_n_g);

    H_n_g
}

/// here we calculate the `PasswordVerifier` called `v` based on `x`
/// **Note**: something that only needs to be done on user pw change, or user creation
/// `x`:  Private key (derived from p and s)
/// `v`:  Password verifier
/// `g`:  A generator modulo N
/// `N`:  A large safe prime (N = 2q+1, where q is prime)
/// formula: `v = g^x % N`
#[allow(non_snake_case)]
pub(crate) fn calculate_password_verifier_v(
    N: &PrimeModulus,
    g: &Generator,
    x: &PrivateKey,
) -> PasswordVerifier {
    SerUint::new(modpow(g, x, N))
}

/// `u` is the hash of host's and client's [`PublicKey`]
/// formula: `H(PAD(A) | PAD(B))`
#[allow(non_snake_case)]
pub(crate) fn calculate_u<const KEYLEN: usize>(A: &PublicKey, B: &PublicKey) -> BoxedUint {
    let u = hash(&A.num, &B.num, KEYLEN);
    debug!("u = {:?}", &u);

    u
}

/// `A` is the [`PublicKey`] of the client
/// formula: `A = g^a % N`
#[allow(non_snake_case)]
pub(crate) fn calculate_pubkey_A(N: &PrimeModulus, g: &Generator, a: &PrivateKey) -> PublicKey {
    let A = modpow(g, a, N);
    debug!("A = {:?}", &A);

    SerUint::new(A)
}

/// [`PublicKey`][B] is the hosts public key
/// `B = kv + g^b`
#[allow(non_snake_case)]
pub(crate) fn calculate_pubkey_B<const KEYLEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
    v: &PasswordVerifier,
    b: &PrivateKey,
) -> PublicKey {
    let g_mod_N = modpow(g, b, N);
    let k = calculate_k::<KEYLEN>(N, g);
    // FIXME monty form améliore ?
    let B1 = &v.num * &k;
    let B2 = B1 + g_mod_N;
    let B = B2 % N.as_nz_ref();
    debug!("B = {:?}", &B);

    SerUint::new(B)
}

/*
---- tests::test_official_vectors_1024 stdout ----
pB g_mod_N C04234AFE80C155CF2FBB1873555D1EF9A934FA578712A3D47FE3C171B7C2F66079EA008DDFBD9D9F4DDFDD2CA52E28863FB492BB7B5F5943B6F62662B264B3FB0A82535FA7EE7A7DA7F9D07C641F61FECB37020F1BBB93F93C81959D84613CA858312FF46E9196FA42DDA5168FA59167F94E2CDE621C19CE8F842BF63BB8323
pB k 7556AA045AEF2CDD07ABAF0F665C3E818913186F
pB res BD0C61512C692C0CB6D041FA01BB152D4916A1E77AF46AE105393011BAF38964DC46A0670DD125B95A981652236F99D9B681CBF87837EC996C6DA04453728610D0C6DDB58B318885D7D82C7F8DEB75CE7BD4FBAA37089E6F9C6059F388838E7A00030B331EB76840910440B1B27AAEAEEB4012B7D7665238A8E3FB004B117B58
*/
/// `x` is the users private key (only they know)
///
/// I:  Username                (is uppercased for WoW)
/// p:  Cleartext Password      (is uppercased for WoW)
/// s:  User's salt
/// x:  Private key (derived from p and s)
/// ph = H(I, ':', p)           (':' is a string literal)
/// x = H(s, ph)                (s is chosen randomly)
#[allow(non_snake_case)]
pub(crate) fn calculate_private_key_x<const KEYLEN: usize>(
    I: UsernameRef,
    p: &ClearTextPassword,
    s: &Salt,
) -> PrivateKey {
    let ph = calculate_p_hash(I, p);
    let digest = HashFunc::new().chain(s).chain(ph).finalize();
    let x: PrivateKey = from_hash::<KEYLEN>(&digest);

    // debug!("x = {:?}", &x);

    x
}

/// hashes the user and the password (used for client private key `x`)
#[allow(non_snake_case)]
pub(crate) fn calculate_p_hash(I: UsernameRef, p: &ClearTextPassword) -> Hash {
    HashFunc::new()
        .chain(I.as_bytes())
        .chain(":".as_bytes())
        .chain(p.as_bytes())
        .finalize()
        .into()
}

/// `k = H(N | PAD(g))` (k = 3 for legacy SRP-6)
#[allow(non_snake_case)]
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
    use crate::{protocol_details::testdata, OpenConstants};

    fn testdata_fullprec(data: &impl AsRef<[u8]>) -> BoxedUint {
        BoxedUint::from_be_slice(data.as_ref(), needed_precision(128)).unwrap()
    }

    fn testdata_hashprec(data: &impl AsRef<[u8]>) -> BoxedUint {
        BoxedUint::from_be_slice(data.as_ref(), needed_precision(20)).unwrap()
    }

    #[test]
    fn test_private_x() {
        let salt = &testdata::SALT.to_vec();
        let x = testdata_fullprec(&testdata::X);
        let x_calc =
            calculate_private_key_x::<128>(&testdata::USERNAME, &testdata::PASSWORD, &salt);
        assert!(x_calc == x);
    }

    #[test]
    fn test_verifier_v() {
        let cst = OpenConstants::<128>::default();
        let verifier = testdata_fullprec(&testdata::VERIFIER);
        let x = &testdata_fullprec(&testdata::X);
        let v_calc = calculate_password_verifier_v(&cst.module, &cst.generator, &x);
        assert!(v_calc.num == verifier);
    }

    #[test]
    fn test_multiplier_k() {
        let cst = OpenConstants::<128>::default();
        let k = testdata_hashprec(&testdata::K_MULTIPLIER);
        let k_calc = calculate_k::<128>(&cst.module, &cst.generator);
        assert_eq!(k_calc, k);
    }

    #[test]
    fn test_calculate_pubkey_a() {
        let cst = OpenConstants::<128>::default();
        let private_a = testdata_fullprec(&testdata::A_PRIVATE);
        let public_a = testdata_fullprec(&testdata::A_PUBLIC);
        let a_calc = calculate_pubkey_A(&cst.module, &cst.generator, &private_a);
        assert_eq!(a_calc.num, public_a);
    }

    #[test]
    fn test_calculate_pubkey_b() {
        let cst = OpenConstants::<128>::default();
        let verifier = testdata_fullprec(&testdata::VERIFIER);
        let private_b = testdata_fullprec(&testdata::B_PRIVATE);
        let public_b = testdata_fullprec(&testdata::B_PUBLIC);
        let b_calc = calculate_pubkey_B::<128>(
            &cst.module,
            &cst.generator,
            &SerUint::new(verifier),
            &private_b,
        );
        assert_eq!(b_calc.num, public_b);
    }

    #[test]
    fn test_calculate_secret() {
        let cst = OpenConstants::<128>::default();
        let verifier = testdata_fullprec(&testdata::VERIFIER);
        let public_a = testdata_fullprec(&testdata::A_PUBLIC);
        let private_b = testdata_fullprec(&testdata::B_PRIVATE);
        let public_b = testdata_fullprec(&testdata::B_PUBLIC);
        let secret = testdata_fullprec(&testdata::SECRET);
        let monty_n = Arc::new(BoxedMontyParams::new(cst.module.clone()));
        let calc_secret = calculate_session_key_S_for_host::<128>(
            monty_n,
            &SerUint::new(public_a),
            &SerUint::new(public_b),
            &private_b,
            &SerUint::new(verifier),
        )
        .unwrap();
        assert_eq!(calc_secret, secret);
    }
}
