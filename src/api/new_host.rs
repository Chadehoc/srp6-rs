// use super::user::{HandshakeProof, StrongProofVerifier};
use crate::primitives::*;
use crate::{Result};
use serde::Serialize;
use crate::Srp6Error;
// use crate::big_number::BigNumber;

use log::debug;

/// this trait provides a higher level api
pub trait HostAPI<const KL: usize, const SL: usize> {
    /// for new users, or if they recover their password
    #[allow(non_snake_case)]
    fn generate_new_user_secrets(
        &mut self,
        I: UsernameRef,
        p: &ClearTextPassword,
        constants: &OpenConstants,
    ) -> UserDetails;

    /// starts the handshake with the client
    fn continue_handshake(
        &mut self, 
        user_details: &UserDetails, user_handshake: &UserHandshake, 
        constants: &OpenConstants)
        -> Result<ServerHandshake>;

    fn verify_proof(
        &mut self,
        users_proof: &Proof
    ) -> Result<Proof>;
}

/// Main interaction point for the server
#[allow(non_snake_case)]
#[derive(Debug, Serialize)]
pub struct Srp6<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {
    pub A: PublicKey,
    pub B: PublicKey,
    b: PrivateKey,
    pub U: PublicKey, 
    verifier: PrivateKey,
    pub salt: Salt,
    S: PrivateKey,
    K: SessionKey,
    M: Proof,
    verified: bool

}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> Srp6<KEY_LENGTH, SALT_LENGTH> {
    pub const KEY_LEN: usize = KEY_LENGTH;
    pub const SALT_LEN: usize = SALT_LENGTH;

    pub fn new() -> Self {
        Self{
            A: PublicKey::default(),
            B: PublicKey::default(),
            b: PrivateKey::default(),
            U: PublicKey::default(), 
            verifier: PrivateKey::default(),
            salt: Salt::default(),
            S: PrivateKey::default(),
            K: SessionKey::default(),
            M: Proof::default(),
            verified: false
        }
    }
}


impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> HostAPI<KEY_LENGTH, SALT_LENGTH>
    for Srp6<KEY_LENGTH, SALT_LENGTH>
{
    /// creates a new [`Salt`] `s` and [`PasswordVerifier`] `v` for a new user
    #[allow(non_snake_case)]
    fn generate_new_user_secrets(
        &mut self,
        I: UsernameRef,
        p: &ClearTextPassword,
        constants: &OpenConstants,
    ) -> UserDetails {
        self.salt = generate_salt::<SALT_LENGTH>();
        // let s = BigNumber::from_hex_str_be("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5290").unwrap();
        let x = calculate_private_key_x(I, p, &self.salt);
        self.verifier = calculate_password_verifier_v(&constants.module, &constants.generator, &x);
        // self.salt = s.clone();

        UserDetails{
            username: I.to_owned(),
            salt: self.salt.clone(),
            verifier: self.verifier.clone()
        }
    }

    #[allow(non_snake_case)]
    fn continue_handshake(
        &mut self, 
        user_details: &UserDetails,
        user_handshake: &UserHandshake,
        constants: &OpenConstants
    ) -> Result<ServerHandshake> {

        assert!(user_details.username == user_handshake.username, "wrong usernames");
        let b = generate_private_key::<KEY_LENGTH>();
        debug!("b = {:?}", &b);

        let B = calculate_pubkey_B(&constants.module, &constants.generator, &user_details.verifier, &b);

        self.b = b;
        self.B = B.clone();
        self.A = user_handshake.user_publickey.clone();
        self.U = calculate_u::<KEY_LENGTH>(&self.A, &self.B);
        
        self.S = calculate_session_key_S_for_host::<KEY_LENGTH>(&constants.module, &self.A, &self.B, &self.b, &self.verifier)?;
        self.K = calculate_session_key_hash_interleave_K::<KEY_LENGTH>(&self.S);
        self.M = calculate_proof_M::<KEY_LENGTH, SALT_LENGTH>(&constants.module, 
            &constants.generator, &user_details.username, &user_details.salt, &self.A, &self.B, &self.K);

        return Ok(ServerHandshake{
            salt: user_details.salt.clone(),
            server_publickey: B
        });
    }

    fn verify_proof(
        &mut self,
        users_proof: &Proof
    ) -> Result<Proof> {


        if self.M != *users_proof {
            // println!("{} != {}", self.M, users_proof);
            // println!("{:?}", self);
            return Err(Srp6Error::InvalidProof(users_proof.clone()));
        }
        let hamk = calculate_strong_proof_M2::<KEY_LENGTH>(&self.A, &self.M, &self.K);
        self.verified = true;
        return Ok(hamk);

    }


}

pub type Srp6_4096 = Srp6<512, 512>;

