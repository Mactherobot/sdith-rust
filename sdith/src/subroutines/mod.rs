//! # Subroutines
//!
//! This module contains the subroutines used in the SDitH protocol.
//!
//! - [`arithmetics`]: Contains the functions for arithmetic operations.
//! - [`commitments`]: Contains the functions for generating and verifying commitments.
//! - [`merkle_tree`]: Contains the functions for generating and verifying Merkle Trees Commitment Scheme.
//! - [`prg`]: Contains the functions for generating Pseudo Random Generators.
//! - [`mpc`]: Contains the functions for the Multi-Party Simulationl.

pub mod arithmetics;
pub mod commitments;
pub mod merkle_tree;
pub mod mpc;
pub mod prg;
pub mod challenge;
