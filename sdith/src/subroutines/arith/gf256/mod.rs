//! # Galois Field 256 and extension fields
//!
//! The field is an implementation of Rijndael's finite field with 256 elements.
//!
//! This module supplies [`crate::arith::FieldArith`] trait implementations for the field elements in GF(256).
//!
//! See implementation for [`u8`](gf256_arith) and [`FPoint`](gf256_ext::FPoint)

pub mod gf256_arith;
pub mod gf256_ext;
pub mod gf256_matrices;
pub mod gf256_poly;
pub mod gf256_vector;
