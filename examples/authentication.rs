//! This example demonstrates the full handshake.
//!
//! To also simulate serialization/deserialization between client and server,
//! see in `lib.rs` the test called `test_handshake_serde_2048`.

use chadehoc_srp6::host::Srp6Host2048;
use chadehoc_srp6::user::Srp6User2048;
use chadehoc_srp6::OpenConstants;

fn main() {
    // 1) Create new user, once

    // --- client side
    let username = "Bob";
    let password = "secret-password";
    let mut constants = OpenConstants::default();
    let mut user_details = Srp6User2048::generate_new_user_secrets(username, password, &constants);
    // --- server side
    // store the details sent by the client

    // 2) Authentication handshake, each call

    // --- client side - create a handshake
    let mut srp6_user = Srp6User2048::new();
    let user_handshake = srp6_user.start_handshake(username, &mut constants);
    // --- server side - retrieve stored details and continue the handshake
    let mut srp6 = Srp6Host2048::new();
    let server_handshake = srp6
        .continue_handshake(
            &mut user_details,
            &user_handshake.user_publickey,
            &mut constants,
        )
        .unwrap();
    // --- client side - compute a proof
    let proof = srp6_user
        .update_handshake(&server_handshake, &mut constants, username, password)
        .unwrap();
    // --- server side - verify client proof, compute its own proof
    let (hamk, secret) = srp6.verify_proof(&proof).expect("invalid client proof");
    // --- client side - verifiy server proof
    let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
    // --- Both sides - secrets are the same
    assert_eq!(secret2, secret, "not same secrets");
}
