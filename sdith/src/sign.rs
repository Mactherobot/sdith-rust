use crate::{
    arith::matrices::MatrixGF256,
    constants::types::{Salt, Seed},
    keygen::SecretKey,
    mpc::{
        beaver::{BeaverA, BeaverB, BeaverC},
        mpc::MPC,
    },
    subroutines::prg::prg::PRG,
    witness::{HPrimeMatrix, Solution},
};

struct Input {
    witness: Solution,
    beaver_ab: (BeaverA, BeaverB),
    beaver_c: BeaverC,
}

impl Input {
    // Turn the input into a byte array for mpc of `F_q^(k+2w+t(2d+1)η)`
    fn plain(&self) {}
}

pub(crate) fn sign_message(entropy: (Seed, Salt), secret_key: SecretKey, message: &[u8]) {
    // Expansion of the parity matrix H'
    let matrix_h_prime = HPrimeMatrix::gen_random(&mut PRG::init(&secret_key.seed_h, None));

    // Randomness generation for the Beaver triples and the shares
    let (mseed, salt) = entropy;
    let (a, b, c) = MPC::generate_beaver_triples(mseed, salt);

    let input = Input {
        witness: secret_key.solution,
        beaver_ab: (a, b),
        beaver_c: c,
    };
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::{constants::params::PARAM_DIGEST_SIZE, keygen::keygen};
}
