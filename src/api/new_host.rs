// use super::user::{HandshakeProof, StrongProofVerifier};
use crate::primitives::*;
use crate::Result;
use crate::Srp6Error;

use log::debug;

/// this trait provides a higher level api
pub trait HostAPI<const KL: usize, const SL: usize> {
    /// starts the handshake with the client
    fn continue_handshake(
        &mut self,
        user_details: &UserDetails,
        user_publickey: &PublicKey,
        constants: &OpenConstants,
    ) -> Result<ServerHandshake>;

    fn verify_proof(&mut self, users_proof: &Proof) -> Result<(Proof, PrivateKey)>;
}

/// Main interaction point for the server
#[allow(non_snake_case)]
#[derive(Debug, Default)]
pub struct Srp6<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {
    pub A: PublicKey,
    pub B: PublicKey,
    b: PrivateKey,
    pub U: PublicKey,
    S: PrivateKey,
    K: SessionKey,
    M: Proof,
    verified: bool,
}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> HostAPI<KEY_LENGTH, SALT_LENGTH>
    for Srp6<KEY_LENGTH, SALT_LENGTH>
{
    #[allow(non_snake_case)]
    fn continue_handshake(
        &mut self,
        user_details: &UserDetails,
        user_publickey: &PublicKey,
        constants: &OpenConstants,
    ) -> Result<ServerHandshake> {
        let b = generate_private_key::<KEY_LENGTH>();
        debug!("b = {:?}", &b);

        let B = calculate_pubkey_B(
            &constants.module,
            &constants.generator,
            &user_details.verifier,
            &b,
        );

        self.b = b;
        self.B = B.clone();
        self.A = user_publickey.clone();
        self.U = calculate_u::<KEY_LENGTH>(&self.A, &self.B);

        self.S = calculate_session_key_S_for_host::<KEY_LENGTH>(
            &constants.module,
            &self.A,
            &self.B,
            &self.b,
            &user_details.verifier,
        )?;
        self.K = calculate_session_key_hash_interleave_K::<KEY_LENGTH>(&self.S);
        self.M = calculate_proof_M::<KEY_LENGTH, SALT_LENGTH>(
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

    fn verify_proof(&mut self, users_proof: &Proof) -> Result<(Proof, PrivateKey)> {
        if self.M != *users_proof {
            // println!("{} != {}", self.M, users_proof);
            // println!("{:?}", self);
            return Err(Srp6Error::InvalidProof(users_proof.clone()));
        }
        let hamk = calculate_strong_proof_M2::<KEY_LENGTH>(&self.A, &self.M, &self.K);
        self.verified = true;
        Ok((hamk, self.S.clone()))
    }
}

pub type Srp6_4096 = Srp6<512, 512>;
pub type Srp6_2048 = Srp6<256, 256>;
