use crate::{
    arith::{
        gf256::{
            gf256_vector::{
                gf256_add_vector, gf256_add_vector_mul_scalar, gf256_mul_vector_by_scalar,
            },
            FieldArith,
        },
        matrices::MatrixGF256,
    },
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_N, PARAM_SALT_SIZE, PARAM_TAU},
        types::{CommitmentsArray, Hash, Salt, Seed},
    },
    keygen::SecretKey,
    mpc::{
        beaver::{Beaver, BeaverA, BeaverB, BeaverC, BEAVER_ABPLAIN_SIZE, BEAVER_CPLAIN_SIZE},
        challenge::Challenge,
        mpc::{BroadcastShare, MPC},
    },
    subroutines::{
        commitments::{self, commit_share},
        merkle_tree::MerkleTree,
        prg::{
            hashing::{hash_1, hash_2},
            prg::PRG,
        },
    },
    witness::{HPrimeMatrix, Solution, SOLUTION_PLAIN_SIZE},
};

struct Signature {
    salt: Salt,
    h1: Hash,
    broadcast_plain: [u8; PARAM_L],
    broadcast_shares_plain: [u8; PARAM_L],
    auth: Vec<Vec<Hash>>,
    wit_share: [[u8; PARAM_L - 1]; PARAM_TAU],
}

impl Signature {
    fn new(
        salt: Salt,
        h1: Hash,
        broadcast_plain: Vec<u8>,
        broadcast_shares_plain: Vec<u8>,
        view_opening_challenges: [[u16; PARAM_L]; PARAM_TAU],
        merkle_trees: Vec<MerkleTree>,
        input_share: [[u8; PARAM_L]; PARAM_TAU],
    ) -> Self {
        // Signature building
        let mut wit_share = [[0u8; PARAM_L - 1]; PARAM_TAU];
        let mut auth = vec![];
        for e in 0..PARAM_TAU {
            auth.push(merkle_trees[e].get_merkle_path(&view_opening_challenges[e]));
            wit_share[e] = input_share[e][..PARAM_L - 1].try_into().unwrap();
        }
        Signature {
            salt,
            h1,
            broadcast_plain,
            broadcast_shares_plain,
            auth,
            wit_share,
        }
    }
    pub(crate) fn serialise_signature(&self) -> Vec<u8> {
        let mut serialised = vec![];
        serialised.extend_from_slice(&self.salt);
        serialised.extend_from_slice(&self.h1);
        serialised.extend_from_slice(&self.broadcast_plain);
        serialised.extend_from_slice(&self.broadcast_shares_plain);
        for auth in &self.auth {
            serialised.extend_from_slice(&auth);
        }
        for wit_share in &self.wit_share {
            serialised.extend_from_slice(&wit_share);
        }
        serialised
    }
}

pub(crate) fn sign_message(entropy: (Seed, Salt), secret_key: SecretKey, message: &[u8]) {
    // Expansion of the parity matrix H'
    let h_prime = HPrimeMatrix::gen_random(&mut PRG::init(&secret_key.seed_h, None));

    // Randomness generation for the Beaver triples and the shares
    let (mseed, salt) = entropy;
    let mut prg = PRG::init(&mseed, Some(&salt));
    let (a, b, c) = MPC::generate_beaver_triples(&mut prg);

    let input = Input {
        solution: secret_key.solution,
        beaver_ab: (a, b),
        beaver_c: c,
    };

    // Compute input shares for the MPC
    // let mut input_shares
    let input_shares = input.compute_input_shares(&mut prg);
    let mut commitments: [CommitmentsArray; PARAM_TAU] = [[Hash::default(); PARAM_N]; PARAM_TAU];

    // Commit shares
    let mut merkle_trees: Vec<MerkleTree> = Vec::with_capacity(PARAM_TAU);
    for e in 0..PARAM_TAU {
        for i in 0..PARAM_N {
            // Commit to the shares
            commitments[e][i] = commit_share(&salt, e as u16, i as u16, &input_shares[e][i]);
        }
        merkle_trees.push(MerkleTree::new(commitments[e], Some(salt)));
    }

    // First challenge (MPC challenge)

    // h1 = Hash1 (seedH , y, salt, com[1], . . . , com[τ ])
    let mut h1_data: Vec<&[u8]> = vec![&secret_key.seed_h, &secret_key.y, &salt];
    for e in 0..PARAM_TAU {
        for i in 0..PARAM_N {
            h1_data.push(&commitments[e][i]);
        }
    }
    let h1 = hash_1(h1_data);
    let chal = Challenge::new(h1);

    // MPC Simulation
    let beaver_triples = (a, b, c);
    let broadcast = MPC::compute_broadcast(
        secret_key.solution,
        beaver_triples,
        chal.clone(),
        h_prime,
        secret_key.y,
    );

    // Run throuh Tau and l to compute the broadcast shares
    let broadcast_shares = MPC::party_computation(
        secret_key.solution,
        beaver_triples,
        chal,
        &broadcast,
        false,
        h_prime,
        secret_key.y,
    );

    let broadcast_plain = MPC::serialise_broadcast(broadcast);
    let broadcast_shares_plain = MPC::serialise_broadcast_shares(broadcast_shares);

    // Second challenge (view-opening challenge)
    // Create the hash data for h2, contains message, salt, h1, broadcast_plain, broadcast_shares_plain
    let h2_data: Vec<&[u8]> = vec![
        message,
        &salt,
        &h1,
        &broadcast_plain,
        &broadcast_shares_plain,
    ];

    let h2 = hash_2(h2_data);

    // Create the set of view-opening challenges
    let view_opening_challenges = MPC::expand_view_challenges_threshold(h2);
}

#[cfg(test)]
mod signature_tests {
    use super::*;
    use crate::{constants::params::PARAM_DIGEST_SIZE, keygen::keygen};
}

struct Input {
    solution: Solution,
    beaver_ab: (BeaverA, BeaverB),
    beaver_c: BeaverC,
}

/// k+2w+t(2d+1)η
const INPUT_SIZE: usize = SOLUTION_PLAIN_SIZE + BEAVER_ABPLAIN_SIZE + BEAVER_CPLAIN_SIZE;

impl Input {
    // Turn the input into a byte array for mpc of `F_q^(k+2w+t(2d+1)η)`
    fn serialise(&self) -> [u8; INPUT_SIZE] {
        let mut serialised = [0u8; INPUT_SIZE];
        serialised[..SOLUTION_PLAIN_SIZE].copy_from_slice(&self.solution.serialise());
        serialised[SOLUTION_PLAIN_SIZE..].copy_from_slice(&Beaver::serialise(
            self.beaver_ab.0,
            self.beaver_ab.1,
            self.beaver_c,
        ));
        serialised
    }

    fn deserialise(input: [u8; INPUT_SIZE]) -> Self {
        let witness = Solution::deserialise(input[..SOLUTION_PLAIN_SIZE].try_into().unwrap());
        let (a, b, c) = Beaver::deserialise(input[SOLUTION_PLAIN_SIZE..].try_into().unwrap());
        Input {
            solution: witness,
            beaver_ab: (a, b),
            beaver_c: c,
        }
    }

    /// Compute the input shares for Algorithm 12, p. 38
    ///
    /// ```
    /// for e in [1, τ] and i in [1, N]
    ///   input_share[e][i] = input_plain + sum^l_(j=1) fij · input coef[e][j]    if i != N
    ///                       input_coef[e][l]                                    if i == N
    /// ```
    fn compute_input_shares(&self, prg: &mut PRG) -> [[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU] {
        let input_plain = self.serialise();
        let mut input_shares = [[[0u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU];

        // Generate coefficients
        let mut input_coef = [[[0u8; INPUT_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                prg.sample_field_fq_elements(&mut input_coef[e][i]);
            }
        }

        for e in 0..PARAM_TAU {
            for i in 0..(PARAM_N - 1) {
                // We need to compute the following:
                // input_share[e][i] = input_plain + sum^ℓ_(j=1) fij · input coef[e][j]
                let f_i = u8::try_from(i).unwrap();
                let mut eval_sum = [0u8; INPUT_SIZE];

                // Compute the inner sum
                // sum^ℓ_(j=1) fij · input coef[e][j]
                for j in 0..PARAM_L {
                    gf256_add_vector_mul_scalar(
                        &mut eval_sum,
                        &input_coef[e][j],
                        f_i.field_pow((j + 1) as u8),
                    );
                }

                // Add the input_plain to the sum
                // input_plain + eval_sum
                gf256_add_vector(&mut eval_sum, &input_plain);

                // input_shares[e][i] = ...
                gf256_add_vector(&mut input_shares[e][i], &eval_sum);
            }

            // From line 13 in Algorithm 12
            // input[e][N-1] = input_coef[e][L-1]
            input_shares[e][PARAM_N - 1] = input_coef[e][PARAM_L - 1];
        }
        input_shares
    }
}

#[cfg(test)]
mod input_tests {
    use crate::{
        constants::params::{PARAM_SALT_SIZE, PARAM_SEED_SIZE},
        keygen::keygen,
    };

    use super::*;

    #[test]
    fn test_serialise_deserialise_input() {
        let (_pk, sk) = keygen([0u8; PARAM_SEED_SIZE]);
        let mut prg = PRG::init(&[0u8; PARAM_SEED_SIZE], Some(&[0u8; PARAM_SALT_SIZE]));
        let (a, b, c) = Beaver::generate_beaver_triples(&mut prg);

        let input = Input {
            solution: sk.solution,
            beaver_ab: (a, b),
            beaver_c: c,
        };

        let serialised = input.serialise();
        let deserialised = Input::deserialise(serialised);

        assert_eq!(input.solution.s_a, deserialised.solution.s_a);
        assert_eq!(input.solution.q_poly, deserialised.solution.q_poly);
        assert_eq!(input.solution.p_poly, deserialised.solution.p_poly);
        assert_eq!(input.beaver_ab, deserialised.beaver_ab);
        assert_eq!(input.beaver_c, deserialised.beaver_c);
    }
}
