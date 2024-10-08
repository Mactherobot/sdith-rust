#![feature(generic_const_exprs)]
// TODO: Can we remove const generics. Currently used by `matrices.rs`

mod api;
mod arith;
mod constants;
mod keygen;
mod mpc;
mod subroutines;
mod witness;
mod signature;

fn main() {
    println!("Hello, world!");
}
