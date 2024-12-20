/*!
An implementation of Secure Remote Password (SRP6) authentication protocol.

**NOTE**: Please do only use key length >= 2048 bit in production. You can do so by using [`Srp6_2048`] or [`Srp6_4096`].

# Usage
See the examples.

# Note on key length
this crate provides some default keys (as [`OpenConstants`]).
The modulus prime and generator numbers are taken from [RFC5054].

# Further details and domain vocabolary
- You can find the documentation of SRP6 [variables in a dedicated module][`protocol_details`].
- [RFC2945](https://datatracker.ietf.org/doc/html/rfc2945) that describes in detail the Secure remote password protocol (SRP).
- [RFC5054] that describes SRP6 for TLS Authentication
- [check out the 2 examples](./examples) that illustrates the srp authentication flow as well

[RFC5054]: (https://datatracker.ietf.org/doc/html/rfc5054)
*/
use derive_more::{Display, Error};

#[cfg(doc)]
pub mod protocol_details;
#[cfg(not(doc))]
mod protocol_details;

pub(crate) mod primitives;

mod api;
mod big_number;
mod hash;

pub use api::{host::*, user::*};
pub use primitives::{
    ClearTextPassword, Generator, MultiplierParameter, OpenConstants, PasswordVerifier,
    PrimeModulus, PrivateKey, Proof, PublicKey, Salt, ServerHandshake, SessionKey, StrongProof,
    StrongSessionKey, UserCredentials, UserDetails, UserHandshake, Username, UsernameRef,
};
pub use std::convert::TryInto;

/// encapsulates a [`Srp6Error`]
pub type Result<T> = std::result::Result<T, Srp6Error>;

#[derive(Error, Display, Debug, PartialEq, serde::Serialize)]
pub enum Srp6Error {
    #[display(
        "The provided key length ({given} bytes) does not match the expected ({expected} byte)"
    )]
    KeyLengthMismatch { given: usize, expected: usize },

    #[display("The provided proof is invalid")]
    InvalidProof(#[error(not(source))] Proof),

    #[display("The provided strong proof is invalid")]
    InvalidStrongProof(#[error(not(source))] StrongProof),

    #[display("The provided public key is invalid")]
    InvalidPublicKey(#[error(not(source))] PublicKey),
}

#[cfg(test)]
mod tests {

    use super::*;

    #[cfg(feature = "norand")]
    use crate::protocol_details::testdata;

    /// Test similar to the example, full handshake but no data transfer.
    #[test]
    fn test_handshake_quick_4096() {
        let username = "Bob";
        let password: &ClearTextPassword = "secret-password";
        let constants = OpenConstants::default();
        // new user : those are sent to the server and stored there
        let user_details = Srp6user4096::generate_new_user_secrets(username, password, &constants);
        // user creates a handshake
        let mut srp6_user = Srp6user4096::default();
        let user_handshake = srp6_user.start_handshake(username, &constants);
        // server retrieves stored details and continues the handshake
        let mut srp6 = Srp6_4096::default();
        let server_handshake = srp6
            .continue_handshake(&user_details, &user_handshake.user_publickey, &constants)
            .unwrap();
        // client side
        let proof = srp6_user
            .update_handshake(&server_handshake, &constants, username, password)
            .unwrap();
        // server side
        let (hamk, secret) = srp6.verify_proof(&proof).unwrap();
        // client side
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
    }

    #[allow(unused_variables)]
    fn trace(title: &str, val: &str) {
        #[cfg(feature = "norand")]
        println!("{title} = {val:#}")
    }

    /// Test a handshake simulating data transfer (serialize/deserialize)
    #[test]
    fn test_handshake_serde_2048() {
        let username = "fred";
        let password: &ClearTextPassword = "password_fred";
        let constants = OpenConstants::default();
        // new user : those are sent to the server and stored there
        let user_details = Srp6user2048::generate_new_user_secrets(username, password, &constants);
        let transfer = serde_json::to_string(&user_details).unwrap();
        trace("details", &transfer);
        // server side (stores)
        let user_details = serde_json::from_str::<UserDetails>(&transfer).unwrap();
        // user creates a handshake
        let mut srp6_user = Srp6user2048::default();
        let user_handshake = srp6_user.start_handshake(username, &constants);
        let transfer = serde_json::to_string(&user_handshake).unwrap();
        trace("user_hs", &transfer);
        // server retrieves stored details and continues the handshake
        let user_handshake = serde_json::from_str::<UserHandshake>(&transfer).unwrap();
        let mut srp6 = Srp6_2048::default();
        let server_handshake = srp6
            .continue_handshake(&user_details, &user_handshake.user_publickey, &constants)
            .unwrap();
        let transfer = serde_json::to_string(&server_handshake).unwrap();
        trace("server_hs", &transfer);
        // client side
        let server_handshake = serde_json::from_str::<ServerHandshake>(&transfer).unwrap();
        let proof = srp6_user
            .update_handshake(&server_handshake, &constants, username, password)
            .unwrap();
        let transfer = serde_json::to_string(&proof).unwrap();
        trace("proof", &transfer);
        // server side
        let proof = serde_json::from_str::<Proof>(&transfer).unwrap();
        let (hamk, secret) = srp6.verify_proof(&proof).unwrap();
        let transfer = serde_json::to_string(&hamk).unwrap();
        trace("sproof", &transfer);
        // client side
        let hamk = serde_json::from_str::<Proof>(&transfer).unwrap();
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
    }

    /// Test the handshake against an official test data.
    #[cfg(feature = "norand")]
    #[test]
    fn test_official_vectors_1024() {
        type Srp6User1024 = Srp6User<128>;
        type Srp61024 = Srp6<128>;
        let username = testdata::USERNAME;
        let password: &ClearTextPassword = testdata::PASSWORD;
        let constants = OpenConstants::default();
        // new user : those are sent to the server and stored there
        let user_details = Srp6User1024::generate_new_user_secrets(username, password, &constants);
        let official_verifier = PublicKey::from_bytes_be(&testdata::VERIFIER);
        assert_eq!(official_verifier, user_details.verifier, "verifier nok");
        // user creates a handshake
        let mut srp6_user = Srp6User1024::default();
        let user_handshake = srp6_user.start_handshake(username, &constants);
        let official_user_publickey = PublicKey::from_bytes_be(&testdata::A_PUBLIC);
        assert_eq!(
            official_user_publickey, user_handshake.user_publickey,
            "A nok"
        );
        // server retrieves stored details and continues the handshake
        let mut srp6 = Srp61024::default();
        let server_handshake = srp6
            .continue_handshake(&user_details, &user_handshake.user_publickey, &constants)
            .unwrap();
        let official_server_publickey = PublicKey::from_bytes_be(&testdata::B_PUBLIC);
        assert_eq!(
            official_server_publickey, server_handshake.server_publickey,
            "B nok"
        );
        // client side
        let proof = srp6_user
            .update_handshake(&server_handshake, &constants, username, password)
            .unwrap();
        // server side
        let (hamk, secret) = srp6.verify_proof(&proof).unwrap();
        // client side
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
        // compare official numbers
        let expected_secret = PrivateKey::from_bytes_be(&testdata::SECRET);
        assert_eq!(expected_secret, secret, "S nok");
    }
}
