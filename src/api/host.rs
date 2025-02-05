// use super::user::{HandshakeProof, StrongProofVerifier};
use crate::big_number::{SerUint, num_effective_bytes};
use crate::primitives::*;
use crate::Result;
use crate::Srp6Error;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use std::sync::Arc;

/// Main interaction point for the server
#[derive(Debug, Default)]
pub struct Srp6<const KEYLEN: usize> {
    pub A: PublicKey,
    pub B: PublicKey,
    b: PrivateKey,
    pub U: PublicKey,
    S: PrivateKey,
    K: SessionKey,
    M: Proof,
}

impl<const KEYLEN: usize> Srp6<KEYLEN> {
    pub fn continue_handshake(
        &mut self,
        user_details: &UserDetails,
        user_publickey: &PublicKey,
        constants: &OpenConstants<KEYLEN>,
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
        let monty_v = BoxedMontyForm::new_with_arc(user_details.verifier.num.clone(), Arc::clone(&monty_N));
        let b = generate_private_key_b(KEYLEN);
        let B = calculate_pubkey_B::<KEYLEN>(
            Arc::clone(&monty_N),
            &constants.generator,
            &monty_v,
            &b,
        );

        self.b = b;
        self.B = B.clone();
        self.A = user_publickey.clone();
        self.U = SerUint::new(calculate_u::<KEYLEN>(&self.A, &self.B));

        self.S = calculate_session_key_S_for_host::<KEYLEN>(
            Arc::clone(&monty_N),
            &self.A,
            &self.B,
            &self.b,
            &monty_v,
        )?;
        self.K = calculate_session_key_hash_interleave_K::<KEYLEN>(&self.S);
        self.M = calculate_proof_M::<KEYLEN>(
            &constants.module,
            &constants.generator,
            &user_details.username,
            &user_details.salt,
            &self.A,
            &self.B,
            &self.K,
        );

        Ok(ServerHandshake {
            salt: user_details.salt.clone(),
            server_publickey: B,
        })
    }

    pub fn verify_proof(self, users_proof: &Proof) -> Result<(Proof, PrivateKey)> {
        if self.M != *users_proof {
            // println!("{} != {}", self.M, users_proof);
            // println!("{:?}", self);
            return Err(Srp6Error::InvalidProof(users_proof.clone()));
        }
        let hamk = calculate_strong_proof_M2::<KEYLEN>(&self.A, &self.M, &self.K);
        Ok((hamk, self.S))
    }
}

pub type Srp6_4096 = Srp6<512>;
pub type Srp6_2048 = Srp6<256>;
