// This allows to respect the official vocabulary.
#![allow(non_snake_case)]

//! This is the repository README.md file. License links are broken from the
//! generated documentation.

// License links are broken doing this, acceptable
#![allow(rustdoc::broken_intra_doc_links)]
#![doc =include_str!("../README.md")]

//! ## Example
//!
//! This is the examples/authentication.rs file.
//!
//! ```rust, ignore
#![doc =include_str!("../examples/authentication.rs")]
//! ```

#[warn(rustdoc::broken_intra_doc_links)]
use derive_more::{Display, Error};

mod api;
mod bignum;
mod hash;
pub(crate) mod primitives;
#[cfg(doc)]
pub mod protocol_details;
#[cfg(all(test, not(doc)))]
mod protocol_details;

pub use api::host;
pub use api::user;
pub use primitives::*;

/// Encapsulates a [`Srp6Error`]
pub type Result<T> = std::result::Result<T, Srp6Error>;

/// Authentication errors.
#[derive(Error, Display, Debug, PartialEq, serde::Serialize)]
pub enum Srp6Error {
    #[display(
        "The provided key length ({given} bytes) does not match the expected ({expected} byte)"
    )]
    KeyLengthMismatch { given: usize, expected: usize },

    #[display("The provided proof is invalid")]
    InvalidProof(#[error(not(source))] Proof),

    #[display("The provided public key is invalid")]
    InvalidPublicKey(#[error(not(source))] PublicKey),
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::bignum::np::needed_precision_pk;
    use host::*;
    use user::*;

    use crate::protocol_details::testdata;
    use crypto_bigint::BoxedUint;
    use zeroize::Zeroizing;

    /// Test similar to the example, full handshake but no data transfer.
    fn test_handshake_quick<const KEYLEN: usize>()
    where
        OpenConstants<KEYLEN>: Default,
    {
        let username = "Bob";
        let password = "secret-password";
        let constants = OpenConstants::<KEYLEN>::default();
        // new user : those are sent to the server and stored there
        let user_details =
            Srp6User::<KEYLEN>::generate_new_user_secrets(username, password, &constants);
        // user creates a handshake
        let mut srp6_user = Srp6User::<KEYLEN>::new();
        let user_handshake = srp6_user.start_handshake(username, &constants);
        // server retrieves stored details and continues the handshake
        let mut srp6 = Srp6Host::<KEYLEN>::new();
        let server_handshake = srp6
            .continue_handshake(user_details, &user_handshake.user_publickey, &constants)
            .unwrap();
        // client side
        let proof = srp6_user
            .update_handshake(server_handshake, &constants, username, password)
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
        let password = "password_fred";
        let constants = OpenConstants::default();
        // new user : those are sent to the server and stored there
        let user_details_0 =
            Srp6User2048::generate_new_user_secrets(username, password, &constants);
        let transfer = serde_json::to_string(&user_details_0).unwrap();
        // note that user details are zeroized on drop
        // println!("details {transfer}");
        // server side (stores)
        let user_details = serde_json::from_str::<UserDetails>(&transfer).unwrap();
        assert_eq!(user_details.salt, user_details_0.salt, "salt different");
        assert_eq!(
            user_details.verifier, user_details_0.verifier,
            "verifier different"
        );
        // user creates a handshake
        let mut srp6_user = Srp6User2048::new();
        let user_handshake_0 = srp6_user.start_handshake(username, &constants);
        let transfer = serde_json::to_string(&user_handshake_0).unwrap();
        // println!("user_handshake {transfer}");
        // server retrieves stored details (from username) and continues the handshake
        let user_handshake = serde_json::from_str::<UserHandshake>(&transfer).unwrap();
        assert_eq!(
            user_handshake.user_publickey.num, user_handshake_0.user_publickey.num,
            "public A different"
        );
        let mut srp6 = Srp6Host2048::new();
        let server_handshake_0 = srp6
            .continue_handshake(user_details, &user_handshake.user_publickey, &constants)
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
            .update_handshake(server_handshake, &constants, username, password)
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
        assert_eq!(hamk, hamk_0, "proof hash different");
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
    }

    /// Test the full handshake against an official test data
    #[test]
    fn test_official_vectors_1024() {
        type Srp6User1024 = Srp6User<128>;
        type Srp61024 = Srp6Host<128>;
        let username = testdata::USERNAME;
        let password = testdata::PASSWORD;
        let constants = OpenConstants::default();
        // new user : those are sent to the server and stored there
        let user_details =
            generate_new_user_secrets_with_salt(username, password, &constants, testdata::SALT);
        let official_verifier = PublicKey::from_be_bytes(&testdata::VERIFIER, 1024);
        assert_eq!(official_verifier, user_details.verifier, "verifier nok");
        // user creates a handshake with nominal values
        let mut srp6_user = Srp6User1024::new();
        let a = PrivateKey::from_be_bytes(&testdata::A_PRIVATE, needed_precision_pk::<128>());
        let b = PrivateKey::from_be_bytes(&testdata::B_PRIVATE, needed_precision_pk::<128>());
        let user_handshake =
            start_handshake_with_a::<128>(&mut srp6_user, username, &constants, Zeroizing::new(a));
        let official_user_publickey = PublicKey::from_be_bytes(&testdata::A_PUBLIC, 1024);
        assert_eq!(
            official_user_publickey, user_handshake.user_publickey,
            "A nok"
        );
        // server retrieves stored details and continues the handshake
        let mut srp6 = Srp61024::new();
        let server_handshake = continue_handshake_with_b::<128>(
            &mut srp6,
            user_details,
            &user_handshake.user_publickey,
            &constants,
            b,
        )
        .unwrap();
        let official_server_publickey = PublicKey::from_be_bytes(&testdata::B_PUBLIC, 1024);
        assert_eq!(
            official_server_publickey, server_handshake.server_publickey,
            "B nok"
        );
        // client side
        let proof = srp6_user
            .update_handshake(server_handshake, &constants, username, password)
            .unwrap();
        // server side
        let (hamk, secret) = srp6.verify_proof(&proof).unwrap();
        // client side
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // both secrets
        assert_eq!(secret2, secret, "not same secrets");
        // compare official numbers
        let expected_secret =
            SessionKey::new(BoxedUint::from_be_slice(&testdata::SECRET, 1024).unwrap());
        assert_eq!(expected_secret, secret, "S nok");
    }

    /// Client and server using different versions.
    #[test]
    fn test_length_mismatch_1() {
        let username = "Bob";
        let password = "secret-password";
        // client is 4096
        let user_constants = OpenConstants::default();
        let user_details =
            Srp6User4096::generate_new_user_secrets(username, password, &user_constants);
        let mut srp6_user = Srp6User4096::new();
        let user_handshake = srp6_user.start_handshake(username, &user_constants);
        // server is 2048
        let server_constants = OpenConstants::default();
        let mut srp6 = Srp6Host2048::new();
        let err = srp6
            .continue_handshake(
                user_details,
                &user_handshake.user_publickey,
                &server_constants,
            )
            .unwrap_err();
        assert!(matches!(err, Srp6Error::KeyLengthMismatch { .. }));
    }

    /// Client and server using different versions.
    #[test]
    fn test_length_mismatch_2() {
        let username = "Bob";
        let password = "secret-password";
        // client is 2048
        let user_constants = OpenConstants::default();
        let user_details =
            Srp6User2048::generate_new_user_secrets(username, password, &user_constants);
        let mut srp6_user = Srp6User2048::new();
        let user_handshake = srp6_user.start_handshake(username, &user_constants);
        // server is 4096
        let server_constants = OpenConstants::default();
        let mut srp6 = Srp6Host4096::new();
        let err = srp6
            .continue_handshake(
                user_details,
                &user_handshake.user_publickey,
                &server_constants,
            )
            .unwrap_err();
        assert!(matches!(err, Srp6Error::KeyLengthMismatch { .. }));
    }
}
