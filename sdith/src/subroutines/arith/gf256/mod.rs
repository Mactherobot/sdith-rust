//! # Galois Field 256 and extension fields
//!
//! The field is an implementation of Rijndael's finite field with 256 elements.
//!
//! This module supplies [`crate::subroutines::arith::FieldArith`] trait implementations for the field elements in GF(256).
//!
//! See implementation for [`u8`](gf256_arith) and [`FPoint`](gf256_ext::FPoint)

pub mod gf256_arith;
pub mod gf256_ext;
pub mod gf256_matrices;
pub mod gf256_poly;
pub mod gf256_vector;

#[cfg(test)]
mod tests {
    #[test]
    fn test_param_q_constraint() {
        // Ensure that the parameter Q is equal to gf256 due to the current field size
        assert_eq!(crate::constants::params::PARAM_Q, 256, "Current implementation uses gf256, therefore we must have that PARAM_Q = 256");
    }
}
