// use super::user::{HandshakeProof, StrongProofVerifier};
use crate::primitives::*;
use crate::Result;
use crate::Srp6Error;

use log::debug;

/// Main interaction point for the server
#[allow(non_snake_case)]
#[derive(Debug, Default)]
pub struct Srp6<const LEN: usize> {
    pub A: PublicKey,
    pub B: PublicKey,
    b: PrivateKey,
    pub U: PublicKey,
    S: PrivateKey,
    K: SessionKey,
    M: Proof,
}

impl<const LEN: usize> Srp6<LEN> {
    #[allow(non_snake_case)]
    pub fn continue_handshake(
        &mut self,
        user_details: &UserDetails,
        user_publickey: &PublicKey,
        constants: &OpenConstants<LEN>,
    ) -> Result<ServerHandshake> {
        if user_publickey.num_bytes() > LEN {
            return Err(Srp6Error::KeyLengthMismatch {
                given: user_publickey.num_bytes(),
                expected: LEN,
            });
        }
        let b = generate_private_key_b::<LEN>();
        debug!("b = {:?}", &b);

        let B = calculate_pubkey_B::<LEN>(
            &constants.module,
            &constants.generator,
            &user_details.verifier,
            &b,
        );

        self.b = b;
        self.B = B.clone();
        self.A = user_publickey.clone();
        self.U = calculate_u::<LEN>(&self.A, &self.B);

        self.S = calculate_session_key_S_for_host::<LEN>(
            &constants.module,
            &self.A,
            &self.B,
            &self.b,
            &user_details.verifier,
        )?;
        self.K = calculate_session_key_hash_interleave_K::<LEN>(&self.S);
        self.M = calculate_proof_M::<LEN>(
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
        let hamk = calculate_strong_proof_M2::<LEN>(&self.A, &self.M, &self.K);
        Ok((hamk, self.S))
    }
}

pub type Srp6_4096 = Srp6<512>;
pub type Srp6_2048 = Srp6<256>;
