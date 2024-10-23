use crate::{
    constants::{
        params::{PARAM_M_SUB_K, PARAM_SEED_SIZE},
        types::Seed,
    },
    witness::{generate_instance_with_solution, Solution, SOLUTION_PLAIN_SIZE},
};

#[derive(Debug)]
pub(crate) struct PublicKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
}

impl PublicKey {
    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut serialised = Vec::new();
        serialised.extend_from_slice(&self.seed_h);
        serialised.extend_from_slice(&self.y);
        serialised
    }

    pub(crate) fn parse(serialised: &[u8]) -> Self {
        assert!(
            serialised.len() == PARAM_SEED_SIZE + PARAM_M_SUB_K,
            "Invalid public key length. Got {}, expected {}",
            serialised.len(),
            PARAM_SEED_SIZE + PARAM_M_SUB_K
        );
        let seed_h: Seed = serialised[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = serialised[PARAM_SEED_SIZE..].try_into().unwrap();
        PublicKey { seed_h, y }
    }
}

pub(crate) struct SecretKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
    /// Solution to the instance (s_a, Q', )
    pub(crate) solution: Solution,
}

impl SecretKey {
    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut serialised = Vec::new();
        serialised.extend_from_slice(&self.seed_h);
        serialised.extend_from_slice(&self.y);
        serialised.extend_from_slice(&self.solution.serialise());
        serialised
    }

    pub(crate) fn parse(serialised: &[u8]) -> Self {
        assert!(
            serialised.len() == PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE,
            "Invalid secret key length. Got {}, expected {}",
            serialised.len(),
            PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE
        );
        let seed_h: Seed = serialised[..PARAM_SEED_SIZE].try_into().unwrap();
        let y = serialised[PARAM_SEED_SIZE..PARAM_SEED_SIZE + PARAM_M_SUB_K]
            .try_into()
            .unwrap();
        let solution = Solution::parse(
            serialised[PARAM_SEED_SIZE + PARAM_M_SUB_K
                ..PARAM_SEED_SIZE + PARAM_M_SUB_K + SOLUTION_PLAIN_SIZE]
                .try_into()
                .unwrap(),
        );
        SecretKey {
            seed_h,
            y,
            solution,
        }
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
