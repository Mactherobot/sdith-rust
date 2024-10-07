use crate::{
    constants::{params::PARAM_M_SUB_K, types::Seed},
    witness::{generate_instance_with_solution, Solution},
};

pub(crate) struct PublicKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
}

pub(crate) struct SecretKey {
    pub(crate) seed_h: Seed,
    pub(crate) y: [u8; PARAM_M_SUB_K],
    /// Solution to the instance (s_a, Q', )
    pub(crate) solution: Solution,
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
