// use super::user::{HandshakeProof, StrongProofVerifier};
use crate::primitives::*;
use crate::{Result, Srp6Error};
use serde::Serialize;

use log::debug;

/// this trait provides a higher level api
pub trait HostAPI<const KL: usize, const SL: usize> {
    /// for new users, or if they recover their password
    #[allow(non_snake_case)]
    fn generate_new_user_secrets(
        &self,
        I: UsernameRef,
        p: &ClearTextPassword,
    ) -> UserDetails;

    /// starts the handshake with the client
    fn continue_handshake(&self, 
        user_details: &UserDetails, user_handshake: &UserHandshake)
        -> (Salt, PublicKey) ;
}

/// Main interaction point for the server
#[allow(non_snake_case)]
#[derive(Debug, Serialize)]
pub struct Srp6<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {
    /// A large safe prime (N = 2q+1, where q is prime. AЦll arithmetic is done modulo N.
    /// `KEY_LENGTH` needs to match the bytes of [`PrimeModulus`] `N`  
    pub N: PrimeModulus,
    /// A generator modulo N
    pub g: Generator,
}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> HostAPI<KEY_LENGTH, SALT_LENGTH>
    for Srp6<KEY_LENGTH, SALT_LENGTH>
{
    /// creates a new [`Salt`] `s` and [`PasswordVerifier`] `v` for a new user
    #[allow(non_snake_case)]
    fn generate_new_user_secrets(
        &self,
        I: UsernameRef,
        p: &ClearTextPassword,
    ) -> UserDetails {
        let s = generate_salt::<SALT_LENGTH>();
        let x = calculate_private_key_x(I, p, &s);
        let v = calculate_password_verifier_v(&self.N, &self.g, &x);

        UserDetails{
            username: I.to_owned(),
            salt: s,
            verifier: v
        }
    }

    #[allow(non_snake_case)]
    fn continue_handshake(
        &self,
        user_details: &UserDetails,
        user_handshake: &UserHandshake,
    ) -> (Salt, PublicKey) {

        assert!(&user_details.username == user_handshake.username, "wrong usernames");
        let b = generate_private_key::<KEY_LENGTH>();
        debug!("b = {:?}", &b);

        let B = calculate_pubkey_B(&self.N, &self.g, &user_details.verifier, &b);

        return (user_details.salt.clone(), B);
    }
}