// use super::host::Handshake;
use crate::primitives::*;
use crate::{Result, Srp6Error};

use log::debug;


pub trait UserTrait<const KL: usize, const SL: usize> {

    #[allow(non_snake_case)]
    fn start_handshake(
        username: UsernameRef,
        constants: &OpenConstants
    ) -> UserHandshake;
}

pub struct Srp6User<const KEY_LENGTH: usize, const SALT_LENGTH: usize> {}

impl<const KEY_LENGTH: usize, const SALT_LENGTH: usize> UserTrait<KEY_LENGTH, SALT_LENGTH>
    for Srp6User<KEY_LENGTH, SALT_LENGTH>
{

    #[allow(non_snake_case)]
    fn start_handshake(
        username: UsernameRef,
        constants: &OpenConstants
    ) -> UserHandshake {

        let a = generate_private_key::<KEY_LENGTH>();
        debug!("a = {:?}", &a);
        
        let A = calculate_pubkey_A(&constants.module, &constants.generator, &a);

        return UserHandshake{
            username: username.to_owned(),
            user_publickey: A
        }

    }
}


pub type Srp6User_4096 = Srp6User<512, 512>;