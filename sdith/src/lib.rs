#![cfg_attr(feature = "simd", feature(portable_simd))]
#![warn(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

//! # Syndrome-Decoding in the Head (SDitH) Signature scheme
//!
//! The SD-in-the-Head signature scheme relies on an MPC protocol which efficiently checks whether
//! a given shared input corresponds to the solution of a syndrome decoding instance
//! By applying the MPC-in-the-Head paradigm, this protocol is turned into a zero-knowledge proof
//! of knowledge for the syndrome decoding problem that is then transformed into a signature scheme using the Fiat-Shamir heuristic.
//! 
//! Find information about
//! 
//! - The protocol endpoints in the [`keygen`] and [`signature`] modules.
//! - The [`subroutines`] module for the subroutines used in the SDitH protocol.
//! - The [`constants`] module for the constants used in the SDitH protocol.
//! - The [`utils`] module for utility functions.
//! - The [`witness`] module for the witness generation in itself a subroutine of the [`keygen`] module.

// Allocator features
#[cfg_attr(feature = "jemalloc", global_allocator)]
#[cfg(feature = "jemalloc")]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg_attr(feature = "mimalloc", global_allocator)]
#[cfg(feature = "mimalloc")]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod constants;
#[cfg(feature = "kat")]
mod kat;
pub mod keygen;
pub mod signature;
pub mod subroutines;
pub mod utils;

#[cfg(test)]
mod tests {
    use crate::constants::params::COMPILED_CATEGORY;

    #[test]
    fn print_category() {
        println!("Running tests for the category: {:?}", COMPILED_CATEGORY);
    }
}
