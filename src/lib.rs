#![allow(non_snake_case)]

/*!
An implementation of Secure Remote Password (SRP6) authentication protocol.

**NOTE**: Please do only use key length >= 2048 bit in production. You can do so by using [`Srp6Host2048`] or [`Srp6Host4096`].

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
#[cfg(all(test, not(doc)))]
mod protocol_details;

pub(crate) mod primitives;

mod api;
mod big_number;
mod hash;

pub use api::host::{Srp6Host, Srp6Host2048, Srp6Host4096};
pub use api::user::{Srp6User, Srp6User2048, Srp6User4096};
pub use primitives::{
    ClearTextPassword, Generator, MultiplierParameter, OpenConstants, PasswordVerifier,
    PrimeModulus, PrivateKey, Proof, PublicKey, Salt, ServerHandshake, SessionKey, StrongProof,
    StrongSessionKey, UserCredentials, UserDetails, UserHandshake, Username, UsernameRef,
};

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
    fn test_handshake_quick<const KEYLEN: usize>()
    where
        OpenConstants<KEYLEN>: Default,
    {
        let username = "Bob";
        let password: &ClearTextPassword = "secret-password";
        let mut constants = OpenConstants::<KEYLEN>::default();
        // new user : those are sent to the server and stored there
        let mut user_details =
            Srp6User::<KEYLEN>::generate_new_user_secrets(username, password, &constants);
        // user creates a handshake
        let mut srp6_user = Srp6User::<KEYLEN>::new();
        let user_handshake = srp6_user.start_handshake(username, &mut constants);
        // server retrieves stored details and continues the handshake
        let mut srp6 = Srp6Host::<KEYLEN>::new();
        let server_handshake = srp6
            .continue_handshake(
                &mut user_details,
                &user_handshake.user_publickey,
                &mut constants,
            )
            .unwrap();
        // client side
        let proof = srp6_user
            .update_handshake(&server_handshake, &mut constants, username, password)
            .unwrap();
        // server side
        let (hamk, secret) = srp6.verify_proof(&proof).unwrap();
        // client side
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
    }

    #[test]
    fn test_handshake_quick_512() {
        test_handshake_quick::<512>();
    }

    #[test]
    fn test_handshake_quick_256() {
        test_handshake_quick::<256>();
    }

    #[test]
    fn test_handshake_quick_128() {
        test_handshake_quick::<128>();
    }

    /// Test a handshake simulating data transfer (serialize/deserialize).
    ///
    /// Uncomment the `println!`'s to trace exchanged data.
    #[test]
    fn test_handshake_serde_2048() {
        let username = "fred";
        let password: &ClearTextPassword = "password_fred";
        let mut constants = OpenConstants::default();
        // new user : those are sent to the server and stored there
        let user_details_0 =
            Srp6User2048::generate_new_user_secrets(username, password, &constants);
        let transfer = serde_json::to_string(&user_details_0).unwrap();
        // println!("details {transfer}");
        // server side (stores)
        let mut user_details = serde_json::from_str::<UserDetails>(&transfer).unwrap();
        assert_eq!(user_details.salt, user_details_0.salt, "salt different");
        assert_eq!(
            user_details.verifier, user_details_0.verifier,
            "verifier different"
        );
        // user creates a handshake
        let mut srp6_user = Srp6User2048::new();
        let user_handshake_0 = srp6_user.start_handshake(username, &mut constants);
        let transfer = serde_json::to_string(&user_handshake_0).unwrap();
        // println!("user_handshake {transfer}");
        // server retrieves stored details and continues the handshake
        let user_handshake = serde_json::from_str::<UserHandshake>(&transfer).unwrap();
        assert_eq!(
            user_handshake.user_publickey.num, user_handshake_0.user_publickey.num,
            "public A different"
        );
        let mut srp6 = Srp6Host2048::new();
        let server_handshake_0 = srp6
            .continue_handshake(
                &mut user_details,
                &user_handshake.user_publickey,
                &mut constants,
            )
            .unwrap();
        let transfer = serde_json::to_string(&server_handshake_0).unwrap();
        // println!("server_handshake {transfer}");
        // client side
        let server_handshake = serde_json::from_str::<ServerHandshake>(&transfer).unwrap();
        assert_eq!(
            server_handshake.server_publickey, server_handshake_0.server_publickey,
            "public B different"
        );
        let proof_0 = srp6_user
            .update_handshake(&server_handshake, &mut constants, username, password)
            .expect("no proof 1");
        let transfer = serde_json::to_string(&proof_0).unwrap();
        // println!("client_proof {transfer}");
        // server side
        let proof = serde_json::from_str::<Proof>(&transfer).unwrap();
        assert_eq!(proof, proof_0, "proof different");
        let (hamk_0, secret) = srp6.verify_proof(&proof).expect("bad proof 2");
        let transfer = serde_json::to_string(&hamk_0).unwrap();
        // println!("server_proof {transfer}");
        // client side
        let hamk = serde_json::from_str::<Proof>(&transfer).unwrap();
        assert_eq!(hamk, hamk_0, "strong proof different");
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
    }

    /// Test the handshake against an official test data.
    #[cfg(feature = "norand")]
    #[test]
    fn test_official_vectors_1024() {
        type Srp6User1024 = Srp6User<128>;
        type Srp61024 = Srp6Host<128>;
        let username = testdata::USERNAME;
        let password: &ClearTextPassword = testdata::PASSWORD;
        let mut constants = OpenConstants::default();
        // new user : those are sent to the server and stored there
        let mut user_details =
            Srp6User1024::generate_new_user_secrets(username, password, &constants);
        let official_verifier = PublicKey::from_be_bytes(&testdata::VERIFIER, 1024);
        assert_eq!(official_verifier, user_details.verifier, "verifier nok");
        // user creates a handshake
        let mut srp6_user = Srp6User1024::new();
        let user_handshake = srp6_user.start_handshake(username, &mut constants);
        let official_user_publickey = PublicKey::from_be_bytes(&testdata::A_PUBLIC, 1024);
        assert_eq!(
            official_user_publickey, user_handshake.user_publickey,
            "A nok"
        );
        // server retrieves stored details and continues the handshake
        let mut srp6 = Srp61024::new();
        let server_handshake = srp6
            .continue_handshake(
                &mut user_details,
                &user_handshake.user_publickey,
                &mut constants,
            )
            .unwrap();
        let official_server_publickey = PublicKey::from_be_bytes(&testdata::B_PUBLIC, 1024);
        assert_eq!(
            official_server_publickey, server_handshake.server_publickey,
            "B nok"
        );
        // client side
        let proof = srp6_user
            .update_handshake(&server_handshake, &mut constants, username, password)
            .unwrap();
        // server side
        let (hamk, secret) = srp6.verify_proof(&proof).unwrap();
        // client side
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
        // compare official numbers
        let expected_secret = SessionKey::from_be_slice(&testdata::SECRET, 1024).unwrap();
        assert_eq!(expected_secret, secret, "S nok");
    }

    #[test]
    fn test_length_mismatch_1() {
        let username = "Bob";
        let password: &ClearTextPassword = "secret-password";
        // client is 4096
        let mut user_constants = OpenConstants::default();
        let mut user_details =
            Srp6User4096::generate_new_user_secrets(username, password, &user_constants);
        let mut srp6_user = Srp6User4096::new();
        let user_handshake = srp6_user.start_handshake(username, &mut user_constants);
        // server is 2048
        let mut server_constants = OpenConstants::default();
        let mut srp6 = Srp6Host2048::new();
        let err = srp6
            .continue_handshake(
                &mut user_details,
                &user_handshake.user_publickey,
                &mut server_constants,
            )
            .unwrap_err();
        assert!(matches!(err, Srp6Error::KeyLengthMismatch { .. }));
    }

    #[test]
    fn test_length_mismatch_2() {
        let username = "Bob";
        let password: &ClearTextPassword = "secret-password";
        // client is 2048
        let mut user_constants = OpenConstants::default();
        let mut user_details =
            Srp6User2048::generate_new_user_secrets(username, password, &user_constants);
        let mut srp6_user = Srp6User2048::new();
        let user_handshake = srp6_user.start_handshake(username, &mut user_constants);
        // server is 4096
        let mut server_constants = OpenConstants::default();
        let mut srp6 = Srp6Host4096::new();
        let err = srp6
            .continue_handshake(
                &mut user_details,
                &user_handshake.user_publickey,
                &mut server_constants,
            )
            .unwrap_err();
        // // client will detect
        // let err = srp6_user
        //     .update_handshake(&server_handshake, &user_constants, username, password)
        //     .unwrap_err();
        assert!(matches!(err, Srp6Error::KeyLengthMismatch { .. }));
    }
}
