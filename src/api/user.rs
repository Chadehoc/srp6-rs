// use super::host::Handshake;
use crate::primitives::*;
use crate::{Result, Srp6Error};

use log::debug;

#[allow(non_snake_case)]
#[derive(Debug, Default)]
pub struct Srp6User<const LEN: usize> {
    pub A: PublicKey,
    pub B: PublicKey,
    a: PrivateKey,
    pub U: PublicKey,
    pub salt: Salt,
    pub M: Proof,
    S: PrivateKey,
    K: SessionKey,
}

impl<const LEN: usize> Srp6User<LEN> {
    /// creates a new [`Salt`] `s` and [`PasswordVerifier`] `v` for a new user
    #[allow(non_snake_case)]
    pub fn generate_new_user_secrets(
        I: UsernameRef,
        p: &ClearTextPassword,
        constants: &OpenConstants<LEN>,
    ) -> UserDetails {
        let salt = generate_salt::<LEN>();
        // let s = BigNumber::from_hex_str_be("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5290").unwrap();
        let x = calculate_private_key_x(I, p, &salt);
        let verifier = calculate_password_verifier_v(&constants.module, &constants.generator, &x);

        UserDetails {
            username: I.to_owned(),
            salt,
            verifier,
        }
    }

    #[allow(non_snake_case)]
    pub fn start_handshake(
        &mut self,
        username: UsernameRef,
        constants: &OpenConstants<LEN>,
    ) -> UserHandshake {
        let a = generate_private_key_a::<LEN>();
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
    pub fn update_handshake(
        &mut self,
        server_handshake: &ServerHandshake,
        constants: &OpenConstants<LEN>,
        I: UsernameRef,
        p: &ClearTextPassword,
    ) -> Result<Proof> {
        if server_handshake.server_publickey.num_bytes() > LEN {
            return Err(Srp6Error::KeyLengthMismatch {
                given: server_handshake.server_publickey.num_bytes(),
                expected: LEN,
            });
        }
        self.B = server_handshake.server_publickey.clone();
        self.salt = server_handshake.salt.clone();

        self.U = calculate_u::<LEN>(&self.A, &self.B);
        let x = calculate_private_key_x(I, p, &self.salt);
        self.S = calculate_session_key_S_for_client::<LEN>(
            &constants.module,
            &constants.generator,
            &self.B,
            &self.A,
            &self.a,
            &x,
        )?;
        self.K = calculate_session_key_hash_interleave_K::<LEN>(&self.S);
        self.M = calculate_proof_M::<LEN>(
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

    pub fn verify_proof(self, servers_proof: &Proof) -> Option<PrivateKey> {
        let my_strong_proof = calculate_strong_proof_M2::<LEN>(&self.A, &self.M, &self.K);
        if servers_proof == &my_strong_proof {
            Some(self.S)
        } else {
            None
        }
    }
}

pub type Srp6user4096 = Srp6User<512>;
pub type Srp6user2048 = Srp6User<256>;
