use srp6::*;
use std::time::{Instant, Duration};
use std::str::FromStr;

const USER_PASSWORD: &ClearTextPassword = "secret-password";

fn main() {

    // let user = mocked::lookup_user_details("Bob");
    let username = String::from_str("Bob").unwrap();
    let constants = get_constants();
    let mut srp6 = Srp6_4096::default();
    let mut srp6_user = Srp6user4096::default();
    let user_details = srp6.generate_new_user_secrets(&username, USER_PASSWORD, &constants);
    let mut durations: Duration = Duration::default();
    for _ in 0..500 {
        let start = Instant::now();
        // user creates a handshake
        let user_handshake = srp6_user.start_handshake(&username, &constants);

        let server_handshake = srp6.continue_handshake(
            &user_details,
            &user_handshake,
            &constants
        ).unwrap();

        let proof = srp6_user.update_handshake(
            &server_handshake,
            &constants,
            &username,
            USER_PASSWORD,
        ).unwrap();

        let hamk = srp6.verify_proof(
            &proof
        ).unwrap_or_default();


        assert!(srp6_user.verify_proof(&hamk));


        let duration = start.elapsed();

        durations = durations.checked_add(duration).unwrap()
    }

    println!("Time elapsed in auth is: {:?}", durations/500);
}
