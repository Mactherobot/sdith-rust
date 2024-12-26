//! # Key generation
//!
//! Public and Secret key structs for the signature protocol.
//!
//! Generating a keypair involves generating a random SD instance along with witness polynomials that
//! satisfy the relation
//!
//! `S * Q = P * F`.
//!
//! Actual generation functions are located in the [`crate::witness`] module.

use crate::{
    constants::{
        params::{PARAM_M_SUB_K, PARAM_SEED_SIZE},
        types::Seed,
    },
    utils::marshalling::Marshalling,
    witness::{generate_instance_with_solution, Solution, SOLUTION_PLAIN_SIZE},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Public key for the signature protocol
pub struct PublicKey {
    /// Seed for generating the matrix H' in the SD instance
    pub seed_h: Seed,
    /// The `y` value of the SD instance for `y = H' * x`
    pub y: [u8; PARAM_M_SUB_K],
}

impl Marshalling<Vec<u8>> for PublicKey {
    fn serialise(&self) -> Vec<u8> {
        let mut serialised = Vec::new();
        serialised.extend_from_slice(&self.seed_h);
        serialised.extend_from_slice(&self.y);

        serialised
    }

    fn parse(serialised: &Vec<u8>) -> Result<Self, String> {
        if serialised.len() != PARAM_SEED_SIZE + PARAM_M_SUB_K {
            return Err(format!(
                "Invalid public key length. Got {}, expected {}",
                serialised.len(),
                PARAM_SEED_SIZE + PARAM_M_SUB_K
            ));
        }
        let seed_h: Seed = serialised[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = serialised[PARAM_SEED_SIZE..].try_into().unwrap();
        Ok(PublicKey { seed_h, y })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Secret key for the signature protocol
pub struct SecretKey {
    /// [`Seed`] for generating the matrix H' in the SD instance
    pub seed_h: Seed,
    /// The `y` value of the SD instance for `y = H' * s`
    pub y: [u8; PARAM_M_SUB_K],
    /// [`Solution`] to the instance
    pub solution: Solution,
}

impl Marshalling<Vec<u8>> for SecretKey {
    fn serialise(&self) -> Vec<u8> {
        let mut serialised = Vec::new();
        serialised.extend_from_slice(&self.seed_h);
        serialised.extend_from_slice(&self.y);
        serialised.extend_from_slice(&self.solution.serialise());
        serialised
    }

    fn parse(serialised: &Vec<u8>) -> Result<Self, String> {
        if serialised.len() != PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE {
            return Err(format!(
                "Invalid secret key length. Got {}, expected {}",
                serialised.len(),
                PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE
            ));
        }
        let seed_h: Seed = serialised[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = serialised[PARAM_SEED_SIZE..PARAM_SEED_SIZE + PARAM_M_SUB_K]
            .try_into()
            .unwrap();
        let solution = Solution::parse(
            serialised[PARAM_SEED_SIZE + PARAM_M_SUB_K
                ..PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE]
                .try_into()
                .unwrap(),
        )?;

        Ok(SecretKey {
            seed_h,
            y,
            solution,
        })
    }
}

/// Generate a public and secret key pair given a root [`Seed`]
pub fn keygen(seed_root: Seed) -> (Box<PublicKey>, Box<SecretKey>) {
    let (instance, solution) = generate_instance_with_solution(seed_root);
    let pk = Box::new(PublicKey {
        seed_h: instance.seed_h,
        y: instance.y,
    });
    let sk = Box::new(SecretKey {
        seed_h: instance.seed_h,
        y: instance.y,
        solution,
    });

    (pk, sk)
}

#[cfg(test)]
mod keygen_tests {
    use crate::constants::params::PARAM_SEED_SIZE;

    #[test]
    fn test_marhalling_keygen() {
        let seed1 = [0u8; PARAM_SEED_SIZE];
        let seed2 = [1u8; PARAM_SEED_SIZE];
        let keys1 = super::keygen(seed1);
        let keys2 = super::keygen(seed2);

        // Test marshalling for PublicKey
        crate::utils::marshalling::test_marhalling(*keys1.0, *keys2.0);

        // Test marshalling for SecretKey
        crate::utils::marshalling::test_marhalling(*keys1.1, *keys2.1);
    }
}
