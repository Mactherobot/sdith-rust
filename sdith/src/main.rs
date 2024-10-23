#![feature(generic_const_exprs)]
// TODO: Can we remove const generics. Currently used by `matrices.rs`

mod api;
mod arith;
mod constants;
mod keygen;
mod mpc;
mod signature;
mod subroutines;
mod witness;
mod spec_tests;

fn main() {
    println!("Hello, world!");
}
