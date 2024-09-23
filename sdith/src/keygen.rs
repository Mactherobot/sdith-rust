use crate::{
    constants::{params::PARAM_M_SUB_K, types::Seed},
    witness::{self, WitnessPlain},
};

struct PublicKey {
    seed_h: Seed,
    y: [u8; PARAM_M_SUB_K],
}

struct SecretKey {
    seed_h: Seed,
    y: [u8; PARAM_M_SUB_K],
    wit_plain: WitnessPlain,
}

pub(crate) fn keygen(seed_root: Seed) -> (PublicKey, SecretKey) {
    let (instance, _solution) = witness::generate_instance_with_solution(seed_root);
    let pk = PublicKey {
        seed_h: instance.seed_h,
        y: instance.y,
    };

    let sk = SecretKey {
        seed_h: instance.seed_h,
        y: instance.y,
        wit_plain: _solution.get_witness_plain(),
    };

    (pk, sk)
}
