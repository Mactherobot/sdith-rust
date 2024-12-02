#![cfg_attr(feature = "simd", feature(portable_simd))]
#![allow(dead_code)] // TODO: remove when we create final version
#![warn(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! # Syndrome-Decoding in the Head (SDitH) Signature scheme
//!
//! The SD-in-the-Head signature scheme relies on an MPC protocol which efficiently checks whether
//! a given shared input corresponds to the solution of a syndrome decoding instance
//! By applying the MPC-in-the-Head paradigm, this protocol is turned into a zero-knowledge proof
//! of knowledge for the syndrome decoding problem that is then transformed into a signature scheme using the Fiat-Shamir heuristic.

pub mod api;
pub mod arith;
pub mod constants;
#[cfg(feature = "kat")]
mod kat;
pub mod keygen;
pub mod mpc;
pub mod signature;
pub mod subroutines;
pub mod utils;
pub mod witness;

#[cfg(test)]
mod tests {
    use crate::constants::params::COMPILED_CATEGORY;

    #[test]
    fn print_category() {
        println!("Running tests for the category: {:?}", COMPILED_CATEGORY);
    }
}
