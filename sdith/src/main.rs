#![feature(generic_const_exprs)]
// TODO: Can we remove const generics. Currently used by `matrices.rs`

use constants::types::{Salt, Seed};
use keygen::keygen;
use signature::signature::Signature;

pub(crate) mod api;
pub(crate) mod arith;
pub(crate) mod constants;
pub(crate) mod keygen;
pub(crate) mod mpc;
pub(crate) mod signature;
pub(crate) mod spec_tests;
pub(crate) mod subroutines;
pub(crate) mod witness;

fn main() {
    println!("Hello, world!");
    let entropy = (Seed::default(), Salt::default());
    let (public_key, secret_key) = keygen(entropy.0);
    let signature = Signature::sign_message(entropy, secret_key, &b"Hello, world!".to_vec());
    let verification = Signature::verify_signature(public_key, &signature);
    if verification.is_ok() {
        println!("Signature is valid");
    } else {
        println!("Signature is invalid");
    }
}
