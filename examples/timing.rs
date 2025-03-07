//! This example is the same as authentication.rs,
//! but displays average durations (to run with `--release`).
//!
//! Change the `KEYLEN` to change the tested version.

use chadehoc_srp6::OpenConstants;
use chadehoc_srp6::host::Srp6Host;
use chadehoc_srp6::user::Srp6User;

use std::time::{Duration, Instant};

const KEYLEN: usize = 256;

fn main() {
    if cfg!(debug_assertions) {
        println!("This should run in --release mode");
        std::process::exit(1);
    }
    let username = "Bob";
    let password = "secret-password";
    let constants = OpenConstants::<KEYLEN>::default();
    let user_details =
        Srp6User::<KEYLEN>::generate_new_user_secrets(username, password, &constants);
    // durations are averaged in a loop
    const NLOOPS: usize = 100;
    // pre-compute clones to let the artificial added durations mostly out
    let cloned_details = std::iter::repeat_with(|| user_details.clone())
        .take(NLOOPS)
        .collect::<Vec<_>>();
    let mut durations = Duration::default();
    for detail in cloned_details {
        let start = Instant::now();
        let mut srp6_user = Srp6User::<KEYLEN>::new();
        let user_handshake = srp6_user.start_handshake(username, &constants);
        let mut srp6 = Srp6Host::<KEYLEN>::new();
        let server_handshake = srp6
            .continue_handshake(detail, &user_handshake.user_publickey, &constants)
            .unwrap();
        let proof = srp6_user
            .update_handshake(server_handshake, &constants, username, password)
            .unwrap();
        let (hamk, secret) = srp6.verify_proof(&proof).expect("invalid client proof");
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // end of processing
        durations = durations.checked_add(start.elapsed()).unwrap();
        // secrets are the same
        assert_eq!(secret2, secret, "not same secrets");
    }
    let avg: Duration = durations / NLOOPS as u32;
    println!("Time elapsed in auth {KEYLEN} is: {avg:?} ({NLOOPS} loops)");
}
