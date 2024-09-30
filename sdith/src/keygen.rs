use crate::{
    constants::{params::PARAM_M_SUB_K, types::Seed},
    witness::{generate_instance_with_solution, WitnessPlain},
};

struct PublicKey {
    seed_h: Seed,
    y: [u8; PARAM_M_SUB_K],
}

struct SecretKey {
    seed_h: Seed,
    y: [u8; PARAM_M_SUB_K],
    /// The witness plain: serialize(s_a, Q', P)
    wit_plain: WitnessPlain,
}

pub(crate) fn keygen(seed_root: Seed) -> (PublicKey, SecretKey) {
    let (instance, _solution) = generate_instance_with_solution(seed_root);
    let pk = PublicKey {
        seed_h: instance.seed_h,
        y: instance.y,
    };

    let sk = SecretKey {
        seed_h: instance.seed_h,
        y: instance.y,
        wit_plain: _solution.get_witness_plain()
    };

    (pk, sk)
}
