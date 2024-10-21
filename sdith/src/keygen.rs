use core::fmt;

use crate::{
    constants::{
        params::{PARAM_M_SUB_K, PARAM_SEED_SIZE},
        types::Seed,
    },
    witness::{generate_instance_with_solution, Solution, SOLUTION_PLAIN_SIZE},
};

pub(crate) struct PublicKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
}

impl PublicKey {
    pub(crate) fn parse_from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();
        assert!(
            bytes.len() == PARAM_SEED_SIZE + PARAM_M_SUB_K,
            "Invalid public key length. Got {}, expected {}",
            bytes.len(),
            PARAM_SEED_SIZE + PARAM_M_SUB_K
        );
        let seed_h: Seed = bytes[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = bytes[PARAM_SEED_SIZE..].try_into().unwrap();
        PublicKey { seed_h, y }
    }

    pub(crate) fn to_hex(&self) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed_h);
        bytes.extend_from_slice(&self.y);
        hex::encode(bytes)
    }
}

pub(crate) struct SecretKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
    /// Solution to the instance (s_a, Q', )
    pub(crate) solution: Solution,
}

impl SecretKey {
    pub(crate) fn parse_from_hex(hex: &str) -> Self {
        let bytes = hex::decode(hex).unwrap();

        assert!(
            bytes.len() == SOLUTION_PLAIN_SIZE + PARAM_SEED_SIZE + PARAM_M_SUB_K,
            "Invalid secret key length. Got {}, expected {}",
            bytes.len(),
            SOLUTION_PLAIN_SIZE + PARAM_SEED_SIZE + PARAM_M_SUB_K
        );

        let seed_h: Seed = bytes[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = bytes[PARAM_SEED_SIZE..PARAM_SEED_SIZE + PARAM_M_SUB_K]
            .try_into()
            .unwrap();
        let solution_plain = bytes[PARAM_SEED_SIZE + PARAM_M_SUB_K..].try_into().expect(
            format!(
                "Invalid secret key length. Got {}, expected {}",
                bytes.len(),
                SOLUTION_PLAIN_SIZE
            )
            .as_str(),
        );
        SecretKey {
            seed_h,
            y,
            solution: Solution::parse(solution_plain),
        }
    }

    pub(crate) fn to_hex(&self) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.seed_h);
        bytes.extend_from_slice(&self.y);
        bytes.extend_from_slice(&self.solution.serialise());
        hex::encode(bytes)
    }
}

pub(crate) fn keygen(seed_root: Seed) -> (PublicKey, SecretKey) {
    let (instance, solution) = generate_instance_with_solution(seed_root);
    let pk = PublicKey {
        seed_h: instance.seed_h,
        y: instance.y,
    };

    let sk = SecretKey {
        seed_h: instance.seed_h,
        y: instance.y,
        solution,
    };

    (pk, sk)
}
