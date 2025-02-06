//! This example is the same as authentication.rs,
//! but displays average durations (to run with `--release`).
//!
//! Change the `KEYLEN` to change the tested version.

use chadehoc_srp6::*;
use std::time::{Duration, Instant};

const KEYLEN: usize = 512;

fn main() {
    if cfg!(debug_assertions) {
        println!("This should run in --release mode");
        std::process::exit(1);
    }
    let username = "Bob";
    let password: &ClearTextPassword = "secret-password";
    let mut constants = OpenConstants::<KEYLEN>::default();
    let mut user_details =
        Srp6User::<KEYLEN>::generate_new_user_secrets(username, password, &constants);
    // durations are averaged in a loop
    const NLOOPS: u32 = 100;
    let mut durations = Duration::default();
    for _ in 0..NLOOPS {
        let start = Instant::now();
        let mut srp6_user = Srp6User::<KEYLEN>::new();
        let user_handshake = srp6_user.start_handshake(username, &mut constants);
        let mut srp6 = Srp6Host::<KEYLEN>::new();
        let server_handshake = srp6
            .continue_handshake(
                &mut user_details,
                &user_handshake.user_publickey,
                &mut constants,
            )
            .unwrap();
        let proof = srp6_user
            .update_handshake(&server_handshake, &mut constants, username, password)
            .unwrap();
        let (hamk, secret) = srp6.verify_proof(&proof).expect("invalid client proof");
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // end of processing
        durations = durations.checked_add(start.elapsed()).unwrap();
        // secrets are the same
        assert_eq!(secret2, secret, "not same secrets");
    }
    let avg: Duration = durations / NLOOPS;
    println!("Time elapsed in auth {KEYLEN} is: {avg:?} ({NLOOPS} loops)");
}
