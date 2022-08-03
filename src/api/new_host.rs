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
        I: UsernameRef,
        p: &ClearTextPassword,
        constants: &OpenConstants,
    ) -> UserDetails;

    /// starts the handshake with the client
    fn continue_handshake(
        user_details: &UserDetails, user_handshake: &UserHandshake, 
        constants: &OpenConstants)
        -> (Salt, PublicKey) ;
}

/// Main interaction point for the server
#[allow(non_snake_case)]
#[derive(Debug, Serialize)]
pub struct Srp6<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> Srp6<KEY_LENGTH, SALT_LENGTH> {
    pub const KEY_LEN: usize = KEY_LENGTH;
    pub const SALT_LEN: usize = SALT_LENGTH;
}


impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> HostAPI<KEY_LENGTH, SALT_LENGTH>
    for Srp6<KEY_LENGTH, SALT_LENGTH>
{
    /// creates a new [`Salt`] `s` and [`PasswordVerifier`] `v` for a new user
    #[allow(non_snake_case)]
    fn generate_new_user_secrets(
        I: UsernameRef,
        p: &ClearTextPassword,
        constants: &OpenConstants,
    ) -> UserDetails {
        let s = generate_salt::<SALT_LENGTH>();
        let x = calculate_private_key_x(I, p, &s);
        println!("{}, {}", &s, &x);
        let v = calculate_password_verifier_v(&constants.module, &constants.generator, &x);

        UserDetails{
            username: I.to_owned(),
            salt: s,
            verifier: v
        }
    }

    #[allow(non_snake_case)]
    fn continue_handshake(
        user_details: &UserDetails,
        user_handshake: &UserHandshake,
        constants: &OpenConstants
    ) -> (Salt, PublicKey) {

        assert!(&user_details.username == user_handshake.username, "wrong usernames");
        let b = generate_private_key::<KEY_LENGTH>();
        debug!("b = {:?}", &b);

        let B = calculate_pubkey_B(&constants.module, &constants.generator, &user_details.verifier, &b);

        return (user_details.salt.clone(), B);
    }
}

pub type Srp6_4096 = Srp6<512, 512>;

