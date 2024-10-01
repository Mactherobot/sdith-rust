use crate::{
    constants::{params::PARAM_M_SUB_K, types::Seed},
    witness::{generate_instance_with_solution, Solution},
};

struct PublicKey {
    seed_h: Seed,
    y: [u8; PARAM_M_SUB_K],
}

struct SecretKey {
    seed_h: Seed,
    y: [u8; PARAM_M_SUB_K],
    /// Solution to the instance (s_a, Q', )
    solution: Solution,
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
