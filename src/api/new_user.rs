// use super::host::Handshake;
use crate::primitives::*;
use crate::Result;

use log::debug;

pub trait UserTrait<const KL: usize, const SL: usize> {
    #[allow(non_snake_case)]
    fn start_handshake(
        &mut self,
        username: UsernameRef,
        constants: &OpenConstants,
    ) -> UserHandshake;

    #[allow(non_snake_case)]
    fn update_handshake(
        &mut self,
        server_handshake: &ServerHandshake,
        constants: &OpenConstants,
        I: UsernameRef,
        p: &ClearTextPassword,
    ) -> Result<Proof>;

    fn verify_proof(&mut self, servers_proof: &Proof) -> bool;
}

#[allow(non_snake_case)]
#[derive(Debug, Default)]
pub struct Srp6User<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {
    pub A: PublicKey,
    pub B: PublicKey,
    a: PrivateKey,
    pub U: PublicKey,
    pub salt: Salt,
    pub M: Proof,
    S: PrivateKey,
    K: SessionKey,
    verified: bool,
}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> UserTrait<KEY_LENGTH, SALT_LENGTH>
    for Srp6User<KEY_LENGTH, SALT_LENGTH>
{
    #[allow(non_snake_case)]
    fn start_handshake(
        &mut self,
        username: UsernameRef,
        constants: &OpenConstants,
    ) -> UserHandshake {
        let a = generate_private_key::<KEY_LENGTH>();
        debug!("a = {:?}", &a);

        let A = calculate_pubkey_A(&constants.module, &constants.generator, &a);
        self.a = a;
        self.A = A.clone();

        UserHandshake {
            username: username.to_owned(),
            user_publickey: A,
        }
    }

    #[allow(non_snake_case)]
    fn update_handshake(
        &mut self,
        server_handshake: &ServerHandshake,
        constants: &OpenConstants,
        I: UsernameRef,
        p: &ClearTextPassword,
    ) -> Result<Proof> {
        self.B = server_handshake.server_publickey.clone();
        self.salt = server_handshake.salt.clone();

        self.U = calculate_u::<KEY_LENGTH>(&self.A, &self.B);
        let x = calculate_private_key_x(I, p, &self.salt);
        self.S = calculate_session_key_S_for_client::<KEY_LENGTH>(
            &constants.module,
            &constants.generator,
            &self.B,
            &self.A,
            &self.a,
            &x,
        )?;
        self.K = calculate_session_key_hash_interleave_K::<KEY_LENGTH>(&self.S);
        self.M = calculate_proof_M::<KEY_LENGTH, SALT_LENGTH>(
            &constants.module,
            &constants.generator,
            I,
            &self.salt,
            &self.A,
            &self.B,
            &self.K,
        );
        Ok(self.M.clone())
    }

    fn verify_proof(&mut self, servers_proof: &Proof) -> bool {
        let my_strong_proof = calculate_strong_proof_M2::<KEY_LENGTH>(&self.A, &self.M, &self.K);

        if servers_proof != &my_strong_proof {
            false
        } else {
            self.verified = true;
            true
        }
    }
}

pub type Srp6user4096 = Srp6User<512, 512>;
