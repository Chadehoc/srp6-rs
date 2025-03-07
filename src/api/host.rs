//! Server-side handshake API.

use crate::Result;
use crate::Srp6Error;
use crate::bignum::num_effective_bytes;
use crate::primitives::*;

use std::sync::Arc;

use crypto_bigint::modular::BoxedMontyParams;

/// Server-side interaction API.
///
/// The generic size is expressed in bytes, not in bits. SRP-2048 is thus `Srp6Host::<256>`.
/// Except for tests, only use the provided [`Srp6Host2048`] or [`Srp6Host4096`].
///
/// There is no secret-"zeroizing" concern, as the server is considered safe.
#[derive(Debug)]
pub struct Srp6Host<const KEYLEN: usize> {
    pub A: PublicKey,
    S: SessionKey,
    M: Proof,
    K: SessionKeyHash,
}

impl<const KEYLEN: usize> Srp6Host<KEYLEN> {
    /// Constructor (all default).
    pub fn new() -> Srp6Host<KEYLEN> {
        Srp6Host {
            A: Default::default(),
            S: Default::default(),
            M: Default::default(),
            K: [0u8; SESSION_KEY_HASH_LENGTH],
        }
    }

    /// Process user_details reveived from the client.
    pub fn continue_handshake(
        &mut self,
        user_details: UserDetails,
        user_publickey: &PublicKey,
        constants: &OpenConstants<KEYLEN>,
    ) -> Result<ServerHandshake> {
        let b = generate_private_key_b::<KEYLEN>();
        self.continue_handshake_with_b(user_details, user_publickey, constants, b)
    }

    fn continue_handshake_with_b(
        &mut self,
        user_details: UserDetails,
        user_publickey: &PublicKey,
        constants: &OpenConstants<KEYLEN>,
        b: PrivateKey,
    ) -> Result<ServerHandshake> {
        if num_effective_bytes(&user_publickey.num) > KEYLEN {
            return Err(Srp6Error::KeyLengthMismatch {
                given: num_effective_bytes(&user_publickey.num),
                expected: KEYLEN,
            });
        }
        if user_publickey.num.bits_precision() != constants.module.bits_precision() {
            return Err(Srp6Error::KeyLengthMismatch {
                given: user_publickey.num.bits_precision() as usize,
                expected: constants.module.bits_precision() as usize,
            });
        }
        let monty_N = Arc::new(BoxedMontyParams::new(constants.module.clone()));
        let B = calculate_pubkey_B::<KEYLEN>(
            &monty_N,
            &constants.generator,
            &user_details.verifier,
            &b,
        );

        self.A = user_publickey.clone();

        self.S = calculate_session_key_S_for_host::<KEYLEN>(
            &monty_N,
            &self.A,
            &B,
            &b,
            &user_details.verifier,
        )?;
        self.K = calculate_session_key_hash_interleave_K::<KEYLEN>(&self.S);
        self.M = calculate_proof_M::<KEYLEN>(
            &constants.module,
            &constants.generator,
            &user_details.username,
            &user_details.salt,
            &self.A,
            &B,
            &self.K,
        );

        Ok(ServerHandshake {
            salt: user_details.salt,
            server_publickey: B,
        })
    }

    /// Verify the client is ok, only then issues a proof and the share session key.
    ///
    /// This last step consumes self.
    pub fn verify_proof(self, users_proof: &Proof) -> Result<(Proof, SessionKey)> {
        if self.M != *users_proof {
            // println!("srv {:?} != user {:?}", self.M, users_proof);
            // println!("{:?}", self);
            return Err(Srp6Error::InvalidProof(*users_proof));
        }
        let hamk = calculate_proof_M2::<KEYLEN>(&self.A, &self.M, &self.K);
        Ok((hamk, self.S))
    }
}

impl<const KEYLEN: usize> Default for Srp6Host<KEYLEN> {
    fn default() -> Self {
        Srp6Host::new()
    }
}

/// Allow a non-random `b` for tests
#[cfg(any(test, feature = "arbitrary"))]
pub fn continue_handshake_with_b<const KEYLEN: usize>(
    this: &mut Srp6Host<KEYLEN>,
    user_details: UserDetails,
    user_publickey: &PublicKey,
    constants: &OpenConstants<KEYLEN>,
    b: PrivateKey,
) -> Result<ServerHandshake> {
    this.continue_handshake_with_b(user_details, user_publickey, constants, b)
}

/// Server-side, 4096 bits (512 bytes).
pub type Srp6Host4096 = Srp6Host<512>;
/// Server-side, 2048 bits (256 bytes).
pub type Srp6Host2048 = Srp6Host<256>;
