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
use log::debug;
use serde::{Deserialize, Serialize};

use crate::big_number::{BigNumber, Zero};
use crate::hash::{hash, Digest, Hash, HashFunc, Update, HASH_LENGTH};
#[cfg(feature = "norand")]
use crate::protocol_details::testdata;
use crate::{Result, Srp6Error};

const STRONG_SESSION_KEY_LENGTH: usize = HASH_LENGTH * 2;

/// Refers to a large safe prime called `N` (`N = 2q+1`, where `q` is prime)
#[doc(alias = "N")]
pub type PrimeModulus = BigNumber;

/// Refers to the modulus generator `g`
#[doc(alias = "g")]
pub type Generator = BigNumber;

/// Refers to a User's salt called `s`
#[doc(alias = "s")]
pub type Salt = BigNumber;

/// Refers to a Public shared key called A (user), B (server)
#[doc(alias("A", "B"))]
pub type PublicKey = BigNumber;

/// Refers to a private secret random number a (user), b (server)
#[doc(alias("a", "b"))]
pub type PrivateKey = BigNumber;

/// Password Verifier is the users secret on the server side
#[doc(alias = "v")]
pub type PasswordVerifier = BigNumber;

/// Refers to a multiplier parameter `k` (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
#[doc(alias = "k")]
pub type MultiplierParameter = BigNumber;

/// Refers to the SessionKey `S`
#[doc(alias = "S")]
pub type SessionKey = BigNumber;
/// Refers to the StrongSessionKey `K`
#[doc(alias = "K")]
pub type StrongSessionKey = BigNumber;

/// Refers to `M` and `M1` Proof of server and client
#[doc(alias("M", "M1"))]
pub type Proof = BigNumber;
/// Refers to `M2` the hash of Proof
#[doc(alias = "M2")]
pub type StrongProof = BigNumber;

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
pub(crate) fn calculate_session_key_S_for_host<const KEY_LENGTH: usize>(
    N: &PrimeModulus,
    A: &PublicKey,
    B: &PublicKey,
    b: &PrivateKey,
    v: &PasswordVerifier,
) -> Result<SessionKey> {
    // safeguard A % N == 0 should be checked
    if (A % N).is_zero() {
        return Err(Srp6Error::InvalidPublicKey(A.clone()));
    }

    let u = &calculate_u::<KEY_LENGTH>(A, B);
    let base = &(A * &v.modpow(u, N));
    let S: BigNumber = base.modpow(b, N);

    debug!("S = {:?}", &S);

    Ok(S)
}

/// client version of the session key calculation, depends on
/// - the users [`PrivateKey`] `x`
/// - the users [`PublicKey`] `A`
/// - the servers [`PublicKey`] `B`
/// - formulas found so far:
///   - `S = (B - (k * g^x)) ^ (a + (u * x)) % N`
///   - `S = (B - (k * v)) ^ (a + (u * x)) % N`
#[allow(non_snake_case)]
#[allow(clippy::many_single_char_names)]
pub(crate) fn calculate_session_key_S_for_client<const KEY_LENGTH: usize>(
    N: &PrimeModulus,
    g: &Generator,
    B: &PublicKey,
    A: &PublicKey,
    a: &PrivateKey,
    x: &PrivateKey,
) -> Result<SessionKey> {
    // safeguard B % N == 0
    if (B % N).is_zero() {
        return Err(Srp6Error::InvalidPublicKey(B.clone()));
    }

    let u = &calculate_u::<KEY_LENGTH>(A, B);
    let exp: BigNumber = a + &(u * x);
    let g_mod_x = &g.modpow(x, N);
    let to_sub = &(&calculate_k::<KEY_LENGTH>(N, g) * g_mod_x) % N;
    // let base = B - ;
    let base = if B < &to_sub {
        &(N - &to_sub) + B
    } else {
        B - &to_sub
    };
    let S = base.modpow(&exp, N);
    debug!("S = {:?}", &S);

    Ok(S)
}

/// the hash of a session key `S` that is called `K`
/// S: is the session key of a user
/// K: is the hash of S, just not that straight
#[allow(non_snake_case)]
pub(crate) fn calculate_session_key_hash_interleave_K<const KEY_LENGTH: usize>(
    S: &SessionKey,
) -> StrongSessionKey {
    let S = S.to_array_pad_zero::<KEY_LENGTH>();

    // take the even bytes out of S
    let mut half = [0_u8; KEY_LENGTH];
    for (i, Si) in S.iter().step_by(2).enumerate() {
        half[i] = *Si;
    }
    // hash the even portion of S
    let even_half_of_S_hash = HashFunc::new().chain(&half[..KEY_LENGTH / 2]).finalize();

    // take the odd bytes of S
    for (i, Si) in S.iter().skip(1).step_by(2).enumerate() {
        half[i] = *Si;
    }
    // hash the odd portion of S
    let odd_half_of_S_hash = HashFunc::new().chain(&half[..KEY_LENGTH / 2]).finalize();

    let mut vK = [0_u8; STRONG_SESSION_KEY_LENGTH];
    for (i, h_Si) in even_half_of_S_hash
        .iter()
        .zip(odd_half_of_S_hash.iter())
        .enumerate()
    {
        vK[i * 2] = *h_Si.0;
        vK[i * 2 + 1] = *h_Si.1;
    }

    let K = BigNumber::from_bytes_le(&vK);
    debug!("K = {:?}", &K);

    K
}

#[allow(non_snake_case)]
pub(crate) fn calculate_proof_M<const LEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
    I: UsernameRef,
    s: &Salt,
    A: &PublicKey,
    B: &PublicKey,
    K: &StrongSessionKey,
) -> Proof {
    let xor_hash: Hash = calculate_hash_N_xor_g::<LEN>(N, g);
    let username_hash = HashFunc::new().chain(I.as_bytes()).finalize();
    debug!("H(I) = {:?}", &username_hash);

    let M: Proof = HashFunc::new()
        .chain(xor_hash)
        .chain(username_hash)
        .chain(s.to_array_pad_zero::<LEN>())
        .chain(A.to_array_pad_zero::<LEN>())
        .chain(B.to_array_pad_zero::<LEN>())
        .chain(K.to_array_pad_zero::<STRONG_SESSION_KEY_LENGTH>())
        .into();

    debug!("M = {:?}", &M);

    M
}

/// todo(verify): check if padding is needed or not
/// formula: `H(A | M | K)`
#[allow(non_snake_case)]
pub(crate) fn calculate_strong_proof_M2<const LEN: usize>(
    A: &PublicKey,
    M: &Proof,
    K: &StrongSessionKey,
) -> StrongProof {
    let M2: StrongProof = HashFunc::new()
        .chain(A.to_array_pad_zero::<LEN>())
        .chain(M.to_array_pad_zero::<HASH_LENGTH>())
        .chain(K.to_array_pad_zero::<STRONG_SESSION_KEY_LENGTH>())
        .into();
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
fn calculate_hash_N_xor_g<const KEY_LENGTH: usize>(N: &PrimeModulus, g: &Generator) -> Hash {
    let mut h = HashFunc::new()
        .chain(N.to_array_pad_zero::<KEY_LENGTH>())
        .finalize();
    let h_g = HashFunc::new().chain(g.to_vec().as_slice()).finalize();
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
    g.modpow(x, N)
}

/// `u` is the hash of host's and client's [`PublicKey`]
/// formula: `H(PAD(A) | PAD(B))`
#[allow(non_snake_case)]
pub(crate) fn calculate_u<const KEY_LENGTH: usize>(A: &PublicKey, B: &PublicKey) -> BigNumber {
    let u = hash::<KEY_LENGTH>(A, B);
    debug!("u = {:?}", &u);

    u
}

/// `A` is the [`PublicKey`] of the client
/// formula: `A = g^a % N`
#[allow(non_snake_case)]
pub(crate) fn calculate_pubkey_A(N: &PrimeModulus, g: &Generator, a: &PrivateKey) -> PublicKey {
    let A = g.modpow(a, N);
    debug!("A = {:?}", &A);

    A
}

/// [`PublicKey`][B] is the hosts public key
/// `B = kv + g^b`
#[allow(non_snake_case)]
pub(crate) fn calculate_pubkey_B<const LEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
    v: &PasswordVerifier,
    b: &PrivateKey,
) -> PublicKey {
    let g_mod_N = g.modpow(b, N);
    let k = calculate_k::<LEN>(N, g);
    let B = &((&k * v) + g_mod_N) % N;

    dbg!(k);

    debug!("B = {:?}", &B);

    B
}

/// `x` is the users private key (only they know)
///
/// I:  Username                (is uppercased for WoW)
/// p:  Cleartext Password      (is uppercased for WoW)
/// s:  User's salt
/// x:  Private key (derived from p and s)
/// ph = H(I, ':', p)           (':' is a string literal)
/// x = H(s, ph)                (s is chosen randomly)
#[allow(non_snake_case)]
#[allow(dead_code)]
pub(crate) fn calculate_private_key_x(
    I: UsernameRef,
    p: &ClearTextPassword,
    s: &Salt,
) -> PrivateKey {
    let ph = calculate_p_hash(I, p);
    let x = HashFunc::new().chain(s.to_vec().as_slice()).chain(ph);
    let x: PrivateKey = x.into();
    debug!("x = {:?}", &x);

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
pub(crate) fn calculate_k<const LEN: usize>(
    N: &PrimeModulus,
    g: &Generator,
) -> MultiplierParameter {
    HashFunc::new()
        .chain(N.to_vec().as_slice())
        .chain(g.to_array_pad_zero::<LEN>())
        .into()
}

/// [`PrivateKey`] `a` or `b` is in fact just a big (positive) random number
pub(crate) fn generate_private_key_a<const KEY_LENGTH: usize>() -> PrivateKey {
    #[cfg(not(feature = "norand"))]
    return PrivateKey::new_rand(KEY_LENGTH);
    #[cfg(feature = "norand")]
    PrivateKey::from_bytes_be(&testdata::A_PRIVATE)
}

/// [`PrivateKey`] `a` or `b` is in fact just a big (positive) random number
pub(crate) fn generate_private_key_b<const KEY_LENGTH: usize>() -> PrivateKey {
    #[cfg(not(feature = "norand"))]
    return PrivateKey::new_rand(KEY_LENGTH);
    #[cfg(feature = "norand")]
    PrivateKey::from_bytes_be(&testdata::B_PRIVATE)
}

/// [`Salt`] `s` is a random number
pub(crate) fn generate_salt<const SALT_LENGTH: usize>() -> Salt {
    #[cfg(not(feature = "norand"))]
    return Salt::new_rand(SALT_LENGTH);
    #[cfg(feature = "norand")]
    PrivateKey::from_bytes_be(&testdata::SALT)
}
