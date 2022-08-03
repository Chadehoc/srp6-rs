// use super::user::{HandshakeProof, StrongProofVerifier};
use crate::primitives::*;
use crate::{Result, Srp6Error};
use serde::Serialize;
use crate::big_number::BigNumber;

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
        // let s = generate_salt::<SALT_LENGTH>();
        let s = BigNumber::from_hex_str_be("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5290").unwrap();
        let x = calculate_private_key_x(I, p, &s);
        // println!("{}, {}", &s, &x);
        let v = calculate_password_verifier_v(&constants.module, &constants.generator, &x);
        println!("{}", x);

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

