//! Server-side handshake API.

use crate::bignum::num_effective_bytes;
use crate::primitives::*;
use crate::{Result, Srp6Error};

use std::sync::Arc;

use crypto_bigint::modular::BoxedMontyParams;

/// Client-side interaction API.
///
/// The generic size is expressed in bytes, not in bits. SRP-2048 is thus `Srp6User::<256>`.
///
/// Except for tests, only use the provided [`Srp6User2048`] or [`Srp6User4096`].
#[derive(Debug)]
pub struct Srp6User<const KEYLEN: usize> {
    pub A: PublicKey,
    a: PrivateKey,
    pub M: Proof,
    S: SessionKey,
    K: SessionKeyHash,
    /// Known once session started
    monty_N: Option<Arc<BoxedMontyParams>>,
}

impl<const KEYLEN: usize> Srp6User<KEYLEN> {
    /// Constructor, all defaults.
    pub fn new() -> Srp6User<KEYLEN> {
        Srp6User {
            A: Default::default(),
            a: Default::default(),
            M: Default::default(),
            S: Default::default(),
            K: [0u8; SESSION_KEY_HASH_LENGTH],
            monty_N: None,
        }
    }

    /// Creates a new [`Salt`] `s` and [`PasswordVerifier`] `v` for a new user
    pub fn generate_new_user_secrets(
        I: UsernameRef,
        p: &str,
        constants: &OpenConstants<KEYLEN>,
    ) -> UserDetails {
        let salt = generate_salt();
        Self::generate_new_user_secrets_with_salt(I, p, constants, salt)
    }

    fn generate_new_user_secrets_with_salt(
        I: UsernameRef,
        p: &str,
        constants: &OpenConstants<KEYLEN>,
        salt: Salt,
    ) -> UserDetails {
        let x = calculate_private_key_x::<KEYLEN>(I, p, &salt);
        let verifier = calculate_password_verifier_v(&constants.module, &constants.generator, &x);
        UserDetails {
            username: I.to_owned(),
            salt,
            verifier,
        }
    }

    /// Start the handshake, only the username is required.
    pub fn start_handshake(
        &mut self,
        username: UsernameRef,
        constants: &OpenConstants<KEYLEN>,
    ) -> UserHandshake {
        let a = generate_private_key_a::<KEYLEN>();
        self.start_handshake_with_a(username, constants, a)
    }

    fn start_handshake_with_a(
        &mut self,
        username: UsernameRef,
        constants: &OpenConstants<KEYLEN>,
        a: PrivateKey,
    ) -> UserHandshake {
        let monty_N = Arc::new(BoxedMontyParams::new(constants.module.clone()));
        let A = calculate_pubkey_A::<KEYLEN>(&constants.generator, &a, &monty_N);
        self.a = a;
        self.A = A.clone();
        self.monty_N = Some(monty_N);
        UserHandshake {
            username: username.to_owned(),
            user_publickey: A,
        }
    }

    /// Checks the server knew the correct details, only the issues a proof.
    pub fn update_handshake(
        &mut self,
        server_handshake: &ServerHandshake,
        constants: &OpenConstants<KEYLEN>,
        I: UsernameRef,
        p: &str,
    ) -> Result<Proof> {
        if num_effective_bytes(&server_handshake.server_publickey.num) > KEYLEN {
            return Err(Srp6Error::KeyLengthMismatch {
                given: num_effective_bytes(&server_handshake.server_publickey.num),
                expected: KEYLEN,
            });
        }
        // this clone could be avoided, but at the price of a &mut server_handshake
        // which would make the API heavier
        let B = server_handshake.server_publickey.clone();
        let x = calculate_private_key_x::<KEYLEN>(I, p, &server_handshake.salt);
        self.S = calculate_session_key_S_for_client::<KEYLEN>(
            self.monty_N.as_ref().unwrap(),
            &constants.generator,
            &B,
            &self.A,
            &self.a,
            &x,
        )?;
        self.K = calculate_session_key_hash_interleave_K::<KEYLEN>(&self.S);
        self.M = calculate_proof_M::<KEYLEN>(
            &constants.module,
            &constants.generator,
            I,
            &server_handshake.salt,
            &self.A,
            &B,
            &self.K,
        );
        Ok(self.M)
    }

    /// Verify the server proof, only then issue the share session key.
    pub fn verify_proof(self, servers_proof: &ProofHash) -> Option<SessionKey> {
        let proof_hash = calculate_proof_hash_M2::<KEYLEN>(&self.A, &self.M, &self.K);
        if servers_proof == &proof_hash {
            Some(self.S)
        } else {
            None
        }
    }
}

impl<const KEYLEN: usize> Default for Srp6User<KEYLEN> {
    fn default() -> Self {
        Srp6User::new()
    }
}

/// Allow a non-random `b` for tests
#[cfg(any(test, feature = "arbitrary"))]
pub fn start_handshake_with_a<const KEYLEN: usize>(
    this: &mut Srp6User<KEYLEN>,
    username: UsernameRef,
    constants: &OpenConstants<KEYLEN>,
    a: PrivateKey,
) -> UserHandshake {
    this.start_handshake_with_a(username, constants, a)
}

#[cfg(any(test, feature = "arbitrary"))]
pub fn generate_new_user_secrets_with_salt<const KEYLEN: usize>(
    I: UsernameRef,
    p: &str,
    constants: &OpenConstants<KEYLEN>,
    salt: Salt,
) -> UserDetails {
    Srp6User::<KEYLEN>::generate_new_user_secrets_with_salt(I, p, constants, salt)
}

/// Client-side, 4096 bits (512 bytes).
pub type Srp6User4096 = Srp6User<512>;
/// Client-side, 2048 bits (256 bytes).
pub type Srp6User2048 = Srp6User<256>;
