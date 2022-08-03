use srp6::*;
use std::time::{Duration, Instant};

fn main() {
    // this is what a user would enter in a form / terminal
    let start = Instant::now();
    let new_username: UsernameRef = "Bob";
    let user_password: &ClearTextPassword = "secret-password";

    // Reminder: choose always a Srp6_BITS type that is strong like 2048 or 4096
    let srp = Srp6_4096::default();
    let user_details = srp.generate_new_user_secrets(new_username, user_password);
    // assert_eq!(user_details.salt.num_bytes(), 4096 / 8);
    // assert_eq!(user_details.verifier.num_bytes(), 4096 / 8);

    // println!("Simulating a server and signup with user {}", new_username);
    // println!(" - User's username   [I] = {:?}", &user_details.username);
    // println!(" - Salt              [s] = {:?}", &user_details.salt);
    // println!(" - Password verifier [v] = {:?}", &user_details.verifier);
    // println!("This is a one time action, normally this data is stored in a user database");
    // println!();
    // println!("Next authentication process `cargo run --example 02_authentication`");
    let duration = start.elapsed();

    println!("Time elapsed in sign_up() is: {:?}", duration);
}
