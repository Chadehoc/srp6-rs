use chadehoc_srp6::*;

fn main() {
    // this is what a user would enter in a form / terminal
    let new_username: UsernameRef = "Bob";
    let user_password: &ClearTextPassword = "secret-password";

    let user_details = Srp6user4096::generate_new_user_secrets(
        new_username,
        user_password,
        &OpenConstants::default(),
    );
    assert_eq!(user_details.salt.num_bytes(), 4096 / 8);
    assert_eq!(user_details.verifier.num_bytes(), 4096 / 8);

    println!("Simulating a server and signup with user {}", new_username);
    println!(" - User's username   [I] = {:?}", &user_details.username);
    println!(" - Salt              [s] = {:?}", &user_details.salt);
    println!(" - Password verifier [v] = {:?}", &user_details.verifier);
    println!("This is a one time action, normally this data is stored in a user database");
    println!();
    println!("Next authentication process `cargo run --example 02_authentication`");
}
