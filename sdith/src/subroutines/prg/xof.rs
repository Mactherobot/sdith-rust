//! # Extendable output function (XOF).
//!
//! The pseudorandomness in SD-in-the-Head is generated through an extendable output hash function (XOF).
//! For example, we can easily generate an array of random values in [F_q](crate::arith::gf256::FieldArith) by
//! sampling a random hash `n` byte hash output and interpreting it as an array of field elements.

#[cfg(not(feature = "xof_blake3"))]
use crate::constants::{params::XOF_PRIMITIVE, types::XOFPrimitive};
#[cfg(not(feature = "xof_blake3"))]
use tiny_keccak::{Hasher, Shake, Xof};

use crate::constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE};

/// Trait for the extendable output function (XOF) implementation
///
/// The trait holds the necessary functions to initialize the XOF, update the XOF with data, and squeeze the XOF to get the output.
/// The trait is implemented for both the Shake and Blake3 XOFs.
pub trait SDitHXOFTrait<T> {
    /// Get the XOF instance
    ///
    /// Matches the [`XOF_PRIMITIVE`] to get the correct XOF based on Category configuration.
    fn get_xof() -> T;
    /// Initialize the XOF with a base value `x`
    fn init_base(x: &[u8]) -> Self;
    /// Initialize the XOF with a [`crate::constants::types::Seed`] and optional [`crate::constants::types::Salt`]
    fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self;
    /// Squeeze the XOF to get the output of size `output.len()`
    fn squeeze(&mut self, output: &mut [u8]);
}

/// SDitHXOF struct
///
/// Holds the generic XOF
pub struct SDitHXOF<T> {
    xof: T,
}

/// Consume the first output to ensure the XOF is initialized in the same way as the reference implementation `xof_final`
/// Technically, this is not necessary for the implementation to work, but it is necessary for the implementation to match outputs
/// of the reference implementation
#[cfg(not(feature = "xof_blake3"))]
fn _xof_final(xof: &mut Shake) {
    let mut tmp = [0u8; 0];
    xof.squeeze(&mut tmp);
}

#[cfg(not(feature = "xof_blake3"))]
impl SDitHXOFTrait<Shake> for SDitHXOF<Shake> {
    fn get_xof() -> Shake {
        match XOF_PRIMITIVE {
            XOFPrimitive::SHAKE128 => Shake::v128(),
            XOFPrimitive::SHAKE256 => Shake::v256(),
        }
    }

    fn init_base(x: &[u8]) -> Self {
        let mut xof = Self::get_xof();
        xof.update(x);
        // xof_final(&mut xof);
        SDitHXOF { xof }
    }

    fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self {
        let mut xof = Self::get_xof();

        if let Some(salt) = salt {
            xof.update(salt);
        }

        xof.update(seed);

        // xof_final(&mut xof);

        SDitHXOF { xof }
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        self.xof.squeeze(output);
    }
}

#[cfg(feature = "xof_blake3")]
impl SDitHXOFTrait<blake3::OutputReader> for SDitHXOF<blake3::OutputReader> {
    fn get_xof() -> blake3::OutputReader {
        blake3::Hasher::new().finalize_xof()
    }

    fn init_base(x: &[u8]) -> Self {
        let mut xof = blake3::Hasher::new();
        xof.update(x);
        SDitHXOF {
            xof: xof.finalize_xof(),
        }
    }

    fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self {
        let mut xof = blake3::Hasher::new();
        if let Some(salt) = salt {
            xof.update(salt);
        }
        xof.update(seed);
        SDitHXOF {
            xof: xof.finalize_xof(),
        }
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        self.xof.fill(output);
    }
}
