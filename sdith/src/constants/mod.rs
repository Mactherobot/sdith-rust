//! # Constants
//!
//! The SDitH Signature Scheme comes with three categories of parameters according to the NIST post-quantum cryptography standardization process.
//!
//! The constants are generated using the build.rs script and exposed through the [`params`] module.
//! Furthermore, the [`precomputed`] module contains precomputed values for the SDitH Signature Scheme.
//!
//! The [`types`] module contains the types used in the SDitH Signature Scheme like
//! [`crate::constants::types::Hash`] and [`crate::constants::types::Seed`].
//!

pub mod params;
pub mod precomputed;
pub mod types;
