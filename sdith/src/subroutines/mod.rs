//! # Subroutines
//! 
//! This module contains the subroutines used in the SDitH protocol.
//! 
//! - [`commitments`]: Contains the functions for generating and verifying commitments.
//! - [`merkle_tree`]: Contains the functions for generating and verifying Merkle Trees Commitment Scheme.
//! - [`prg`]: Contains the functions for generating Pseudo Random Generators.
//! - [`marshalling`]: Contains the trait and test function for serializing and deserializing data.

pub mod commitments;
pub mod marshalling;
pub mod merkle_tree;
pub mod prg;
