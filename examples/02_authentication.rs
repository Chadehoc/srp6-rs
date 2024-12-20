use chadehoc_srp6::*;
use std::time::{Duration, Instant};

fn main() {
    let username = "Bob";
    let password: &ClearTextPassword = "secret-password";
    let constants = OpenConstants::default();
    let mut srp6_user = Srp6user4096::default();
    // new user : those are sent to the server and stored there
    let user_details = srp6_user.generate_new_user_secrets(username, password, &constants);
    // averaging durations
    let mut durations: Duration = Duration::default();
    #[cfg(debug_assertions)]
    const NLOOPS: u32 = 10;
    #[cfg(not(debug_assertions))]
    const NLOOPS: u32 = 100;
    for _ in 0..NLOOPS {
        let start = Instant::now();
        // user creates a handshake
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
        let (hamk, secret) = srp6.verify_proof(&proof).expect("invalid client proof");
        // client side
        let secret2 = srp6_user.verify_proof(&hamk).expect("invalid server proof");
        // end of processing
        let duration = start.elapsed();
        durations = durations.checked_add(duration).unwrap();
        // secrets are the same
        assert_eq!(secret2, secret, "not same secrets");
    }

    println!("Time elapsed in auth is: {:?}", durations / NLOOPS);
}
