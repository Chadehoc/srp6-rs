// use super::host::Handshake;
use crate::big_number::num_effective_bytes;
use crate::primitives::*;
use crate::{Result, Srp6Error};

use crypto_bigint::modular::BoxedMontyParams;
use std::sync::Arc;

#[derive(Debug)]
pub struct Srp6User<const KEYLEN: usize> {
    pub A: PublicKey,
    a: PrivateKey,
    pub M: Proof,
    S: SessionKey,
    K: StrongSessionKey,
    /// Known once session started
    monty_N: Option<Arc<BoxedMontyParams>>,
}

impl<const KEYLEN: usize> Srp6User<KEYLEN> {
    pub fn new() -> Srp6User<KEYLEN> {
        Srp6User {
            A: Default::default(),
            a: Default::default(),
            M: Default::default(),
            S: Default::default(),
            K: [0u8; STRONG_SESSION_KEY_LENGTH],
            monty_N: None,
        }
    }

    /// creates a new [`Salt`] `s` and [`PasswordVerifier`] `v` for a new user
    pub fn generate_new_user_secrets(
        I: UsernameRef,
        p: &ClearTextPassword,
        constants: &OpenConstants<KEYLEN>,
    ) -> UserDetails {
        let salt = generate_salt(KEYLEN);
        // let s = BigNumber::from_hex_str_be("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5290").unwrap();
        let x = calculate_private_key_x::<KEYLEN>(I, p, &salt);
        let verifier = calculate_password_verifier_v(&constants.module, &constants.generator, &x);

        UserDetails {
            username: I.to_owned(),
            salt,
            verifier,
        }
    }

    pub fn start_handshake(
        &mut self,
        username: UsernameRef,
        constants: &mut OpenConstants<KEYLEN>,
    ) -> UserHandshake {
        let a = generate_private_key_a::<KEYLEN>();
        let monty_N = Arc::new(BoxedMontyParams::new(constants.module.clone()));
        let A = calculate_pubkey_A::<KEYLEN>(&mut constants.generator, &a, &monty_N);
        self.a = a;
        self.A = A.clone();
        self.monty_N = Some(monty_N);

        UserHandshake {
            username: username.to_owned(),
            user_publickey: A,
        }
    }

    pub fn update_handshake(
        &mut self,
        server_handshake: &ServerHandshake,
        constants: &mut OpenConstants<KEYLEN>,
        I: UsernameRef,
        p: &ClearTextPassword,
    ) -> Result<Proof> {
        if num_effective_bytes(&server_handshake.server_publickey.num) > KEYLEN {
            return Err(Srp6Error::KeyLengthMismatch {
                given: num_effective_bytes(&server_handshake.server_publickey.num),
                expected: KEYLEN,
            });
        }
        // this clone could be avoided, but at the price of a &mut server_handshake
        // which would make the API heavier
        let mut B = server_handshake.server_publickey.clone();

        let mut x = calculate_private_key_x::<KEYLEN>(I, p, &server_handshake.salt);

        self.S = calculate_session_key_S_for_client::<KEYLEN>(
            self.monty_N.as_ref().unwrap(),
            &mut constants.generator,
            &mut B,
            &self.A,
            &mut self.a,
            &mut x,
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

    pub fn verify_proof(self, servers_proof: &StrongProof) -> Option<SessionKey> {
        let my_strong_proof = calculate_strong_proof_M2::<KEYLEN>(&self.A, &self.M, &self.K);
        if servers_proof == &my_strong_proof {
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

/// Client-side, 4096 bits (512 bytes).
pub type Srp6User4096 = Srp6User<512>;
/// Client-side, 2048 bits (256 bytes).
pub type Srp6User2048 = Srp6User<256>;
