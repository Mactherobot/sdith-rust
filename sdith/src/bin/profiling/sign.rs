//! Run time for profiling the signing functionality
//! Runs the signing functionality 100 times and prints the time it takes to run
//! the signing functionality
//!
//! Run it with samply
//!
//! ```sh
//! cargo build --bin profiling_sign
//! samply record target/debug/profiling_sign [iterations]
//! ```
//!

use rand::RngCore as _;
use sdith::constants::types::{Salt, Seed};
use std::env;

fn main() {
    // Fetch iterations
    let args = env::args_os();

    let iterations: usize = if args.len() > 1 {
        usize::from_str_radix(args.last().unwrap().into_string().unwrap().as_str(), 10).unwrap()
    } else {
        1000
    };

    let mut rng = rand::thread_rng();
    let mut seed = Seed::default();
    let mut salt = Salt::default();
    rng.fill_bytes(&mut seed);
    rng.fill_bytes(&mut salt);

    let (_, sk) = sdith::keygen::keygen(seed);

    let mut msg = vec![0u8; 100];

    eprintln!("Profiling - running sign message {} times...", iterations);

    (0..iterations).for_each(|_| {
        rng.fill_bytes(&mut msg);
        let _signature = sdith::signature::Signature::sign_message((seed, salt), &sk, &msg);
    });
}
