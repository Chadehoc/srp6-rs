#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

extern crate chadehoc_srp6;
use chadehoc_srp6::host::Srp6Host2048;
use chadehoc_srp6::user::Srp6User2048;
use chadehoc_srp6::{
    OpenConstants,
    PrivateKey,
    Salt,
    Username,
    // under feature arbitrary
    user::generate_new_user_secrets_with_salt,
    host::continue_handshake_with_b,
    user::start_handshake_with_a,
};

#[derive(Debug, Arbitrary)]
struct Input {
    pub private_a: PrivateKey,
    pub private_b: PrivateKey,
    pub salt: Salt,
    pub username: Username,
    pub password: String,
}

fuzz_target!(|data: Input| full_handshake(data));

fn full_handshake(data: Input) {
    let constants = OpenConstants::default();
    let user_details = generate_new_user_secrets_with_salt(
        &data.username,
        &data.password,
        &constants,
        data.salt.clone(),
    );
    let mut srp6_user = Srp6User2048::new();
    let user_handshake = start_handshake_with_a(
        &mut srp6_user,
        &data.username,
        &constants,
        data.private_a.clone(),
    );
    let mut srp6 = Srp6Host2048::new();
    let server_handshake = continue_handshake_with_b(
        &mut srp6,
        &mut user_details,
        &user_handshake.user_publickey,
        &constants,
        data.private_b,
    )
    .unwrap();
    // --- client side - compute a proof
    let proof = srp6_user
        .update_handshake(
            &server_handshake,
            &mut constants,
            &data.username,
            &data.password,
        )
        .unwrap();
    // --- server side - verify client proof, compute its own proof
    let (hamk, secret) = srp6.verify_proof(&proof).expect("invalid client proof");
    // --- client side - verifiy server proof
    let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
    // --- Both sides - secrets are the same
    assert_eq!(secret2, secret, "not same secrets");
}
