use crate::{
    constants::{
        params::{PARAM_M_SUB_K, PARAM_SEED_SIZE},
        types::Seed,
    },
    witness::{generate_instance_with_solution, Solution},
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

pub(crate) fn keygen(seed_root: Seed) -> (Box<PublicKey>, Box<SecretKey>) {
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

    (Box::new(pk), Box::new(sk))
}
