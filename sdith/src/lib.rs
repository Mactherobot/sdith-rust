#![feature(generic_const_exprs)]
#![allow(incomplete_features)] // TODO: remove when we create final version
#![allow(dead_code)] // TODO: remove when we create final version

pub mod api;
pub mod arith;
pub mod constants;
pub mod keygen;
pub mod mpc;
pub mod signature;
pub mod subroutines;
pub mod witness;

#[cfg(feature = "spec-tests")]
mod spec_tests;

#[cfg(test)]
mod tests {
    use crate::constants::params::COMPILED_CATEGORY;

    #[test]
    fn print_category() {
        println!("Running tests for the category: {:?}", COMPILED_CATEGORY);
    }
}