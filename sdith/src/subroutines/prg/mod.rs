//! # Pseudo Random Generator (PRG)
//! Pseudo-randomness used in the SDitH protocol
//!
//! ## Hashing
//! Hashing for Fiat-Shamir Heuristic, Commitments and [Merkle-Tree Commitment scheme](crate::subroutines::merkle_tree::MerkleTree) is 
//! implemented in the [`hashing`] module.
//! 
//! ## XOF
//! Extendable Output Functions (XOFs) are used to generate pseudorandom values in the fields [F_q](crate::arith::gf256::FieldArith) 
//! and [F_q^\eta](crate::arith::gf256::gf256_ext::FPoint).. The XOFs are implemented in the [`xof`] module.

pub mod hashing;
pub mod xof;

use xof::{SDitHXOF, SDitHXOFTrait as _};

use crate::{
    arith::gf256::gf256_ext::FPoint,
    constants::{
        params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        types::Seed,
    },
};

/// Pseudo Random Generator (PRG) struct
/// Generates random values in the fields F_q and F_q^\eta
///
/// The pseudorandomness is generated through extendable output functions (XOFs)
///
/// By default, the randomness is generated using Shake.
///
/// If the `xof_blake3` feature is enabled, the randomness is generated using Blake3 for category 1.
pub struct PRG {
    /// XOF instance for default Shake
    #[cfg(not(feature = "xof_blake3"))]
    xof: SDitHXOF<tiny_keccak::Shake>,
    #[cfg(feature = "xof_blake3")]
    /// XOF instance for Blake3
    xof: SDitHXOF<blake3::OutputReader>,
}

impl PRG {
    /// Initialize the PRG with a seed and optional salt
    pub fn init(seed: &[u8; PARAM_SEED_SIZE], salt: Option<&[u8; PARAM_SALT_SIZE]>) -> Self {
        PRG {
            xof: SDitHXOF::init(seed, salt),
        }
    }

    /// Initialize the PRG with a base value e.g for h1 in the spec `PRG::init_base(HASH_PREFIX_CHALLENGE_1)`
    pub fn init_base(x: &[u8]) -> Self {
        PRG {
            xof: SDitHXOF::init_base(x),
        }
    }

    /// Sample non-zero random values in the field [F_q](crate::arith::gf256::FieldArith)
    pub fn sample_field_fq_non_zero(&mut self, output: &mut [u8]) {
        for i in 0..output.len() {
            self.sample_field_fq_elements(&mut output[i..i + 1]);
            while output[i] == 0 {
                self.sample_field_fq_elements(&mut output[i..i + 1]);
            }
        }
    }

    /// Sample non-zero **distinct** random values in the field [F_q](crate::arith::gf256::FieldArith)
    ///
    /// The output length must be less than 256
    pub fn sample_field_fq_non_zero_set(&mut self, output: &mut [u8]) -> Result<(), String> {
        if output.len() >= 256 {
            return Err("Output length must be less than 256".to_string());
        };

        let mut i = 0;
        while i < output.len() {
            self.sample_field_fq_non_zero(&mut output[i..i + 1]);
            let is_redundant = (0..i).any(|j| output[j] == output[i]);
            if is_redundant {
                continue;
            }
            i += 1;
        }

        Ok(())
    }

    /// Sample a random [`Vec`] in the field [F_q](crate::arith::gf256::FieldArith)
    pub fn sample_field_fq_elements_vec(&mut self, n: usize) -> Vec<u8> {
        let mut f = vec![0u8; n];
        self.xof.squeeze(&mut f);

        f
    }

    /// Sample a random value in the field F_q = F_256
    /// The byte B_i is returned as the sampled field element. XOF is called to generate n bytes
    pub fn sample_field_fq_elements(&mut self, out: &mut [u8]) {
        self.xof.squeeze(out);
    }

    /// Sample a random value in the field F_q^η
    pub fn sample_field_fpoint_elements(&mut self, out: &mut [FPoint]) {
        for i in 0..out.len() {
            self.xof.squeeze(&mut out[i]);
        }
    }

    /// Sample a random value in the field F_q^η
    pub fn sample_field_fpoint_elements_vec(&mut self, n: usize) -> Vec<FPoint> {
        let mut f = vec![FPoint::default(); n];
        for i in 0..n {
            self.xof.squeeze(&mut f[i]);
        }
        f
    }

    /// Sample a random [`Seed`].
    pub fn sample_seed(&mut self) -> Seed {
        let mut seed = [0u8; PARAM_SEED_SIZE];
        self.xof.squeeze(&mut seed);
        seed
    }
}

#[cfg(test)]
mod tests {
    use crate::constants::params::PARAM_DIGEST_SIZE;

    use super::*;

    #[test]
    fn test_prg() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let mut output = [0u8; PARAM_DIGEST_SIZE];
        prg.sample_field_fq_elements(&mut output);
        assert_ne!(output, [0u8; PARAM_DIGEST_SIZE]);
    }

    #[test]
    fn test_prg_sample_field_elements_gf256_vec() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let f = prg.sample_field_fq_elements_vec(32);
        assert_ne!(f, vec![0u8; PARAM_DIGEST_SIZE]);
    }

    #[test]
    fn test_prg_sample_non_zero() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let mut f = [0u8; 256];
        prg.sample_field_fq_non_zero(&mut f);

        assert_ne!(f, [0u8; 256]);
        for i in f.iter() {
            assert_ne!(*i, 0);
        }
    }

    #[test]
    fn test_prg_sample_non_zero_set() {
        let seed = &[0u8; PARAM_SEED_SIZE];
        let mut prg = PRG::init(seed, None);

        let mut f = [0u8; 100];
        let _ = prg.sample_field_fq_non_zero_set(&mut f);
        for (i, fi) in f.iter().enumerate() {
            assert_ne!(*fi, 0);
            let is_redundant = (0..i).any(|j| f[j] == *fi);
            assert!(!is_redundant);
        }

        let mut f = [0u8; 256];
        assert!(prg.sample_field_fq_non_zero_set(&mut f).is_err());
    }
}
