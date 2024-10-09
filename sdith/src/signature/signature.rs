use num_traits::ToBytes;

use crate::{
    arith::{
        gf256::{
            gf256_vector::{
                gf256_add_vector, gf256_add_vector_mul_scalar, gf256_add_vector_with_padding,
            },
            FieldArith,
        },
        matrices::MatrixGF256,
    },
    constants::{
        params::{
            PARAM_DIGEST_SIZE, PARAM_L, PARAM_N, PARAM_SALT_SIZE, PARAM_SPLITTING_FACTOR, PARAM_T,
            PARAM_TAU,
        },
        types::{CommitmentsArray, Hash, Salt, Seed},
    },
    keygen::{PublicKey, SecretKey},
    mpc::{
        broadcast::{
            self, Broadcast, BroadcastShare, BROADCAST_PLAIN_SIZE, BROADCAST_SHARE_PLAIN_SIZE,
        },
        challenge::Challenge,
        mpc::MPC,
    },
    subroutines::{
        commitments::{self, commit_share},
        merkle_tree::{get_merkle_root_from_auth, MerkleTree},
        prg::{
            hashing::{hash_1, hash_2},
            prg::PRG,
        },
    },
    witness::{HPrimeMatrix, SOLUTION_PLAIN_SIZE},
};

use super::input::{Input, INPUT_SIZE};

struct Signature {
    salt: Salt,
    h1: Hash,
    broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
    broadcast_shares_plain: [u8; BROADCAST_SHARE_PLAIN_SIZE * PARAM_L * PARAM_TAU],
    // wit_share from spec
    solution_share: [[[u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    auth: [Vec<Hash>; PARAM_TAU],
}

impl Signature {
    /// Create a new signature
    ///
    /// # Arguments
    ///
    /// * `salt` - The salt used to generate the signature
    /// * `h1` - Fiat-Shamir hash from Hash_1
    /// * `broadcast_plain` - Serialised broadcast value
    /// * `broadcast_shares_plain` - Serialised broadcast shares
    /// * `view_opening_challenges` - The view opening challenges I[e] = {1.. / N} / *i
    /// * `merkle_trees` - The Merkle trees for each iteration
    /// * `input_shares` - The input shares for each party
    fn new(
        salt: Salt,
        h1: Hash,
        broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
        broadcast_shares_plain: [u8; BROADCAST_SHARE_PLAIN_SIZE * PARAM_L * PARAM_TAU],
        view_opening_challenges: [[u16; PARAM_L]; PARAM_TAU],
        merkle_trees: &Vec<MerkleTree>,
        // Shares of the input (s_a, Q', P) and the Beaver triples (a, b, c) for each party
        input_shares: [[[u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU],
    ) -> Self {
        // Signature building
        let mut solution_share = [[[0u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for e in 0..PARAM_TAU {
            // Fetch auth path for
            auth[e] = merkle_trees[e].get_merkle_path(&view_opening_challenges[e]);
            for (_i, i) in view_opening_challenges[e].iter().enumerate() {
                // Truncate witness share by removing beaver triples from the plain value
                solution_share[e][_i] =
                    Input::truncate_beaver_triples(input_shares[e][(*i - 1) as usize])
            }
        }

        Signature {
            salt,
            h1,
            broadcast_plain,
            broadcast_shares_plain,
            auth,
            solution_share,
        }
    }

    pub(crate) fn serialise(&self) -> Vec<u8> {
        let mut serialised = vec![];
        serialised.extend_from_slice(&self.salt);
        serialised.extend_from_slice(&self.h1);
        serialised.extend_from_slice(&self.broadcast_plain);
        serialised.extend_from_slice(&self.broadcast_shares_plain);

        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                serialised.extend_from_slice(&self.solution_share[e][i]);
            }
        }

        // Append auth sizes
        for auth in &self.auth {
            serialised.extend_from_slice(&(auth.len() as u16).to_le_bytes());
        }

        // Append auth
        for auth in &self.auth {
            for hash in auth {
                serialised.extend_from_slice(hash);
            }
        }

        serialised
    }

    pub(crate) fn parse(signature_plain: Vec<u8>) -> Signature {
        let mut offset = 0;
        let salt: Salt = signature_plain[offset..offset + PARAM_SALT_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_SALT_SIZE;

        let h1: Hash = signature_plain[offset..offset + PARAM_DIGEST_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_DIGEST_SIZE;

        let broadcast_plain: [u8; BROADCAST_PLAIN_SIZE] = signature_plain
            [offset..offset + BROADCAST_PLAIN_SIZE]
            .try_into()
            .unwrap();
        offset += BROADCAST_PLAIN_SIZE;

        let broadcast_shares_plain: [u8; BROADCAST_SHARE_PLAIN_SIZE * PARAM_TAU * PARAM_L] =
            signature_plain[offset..offset + BROADCAST_SHARE_PLAIN_SIZE * PARAM_TAU * PARAM_L]
                .try_into()
                .unwrap();
        offset += BROADCAST_SHARE_PLAIN_SIZE * PARAM_TAU * PARAM_L;

        let mut solution_share = [[[0u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                solution_share[e][i] = signature_plain[offset..offset + SOLUTION_PLAIN_SIZE]
                    .try_into()
                    .unwrap();
                offset += SOLUTION_PLAIN_SIZE;
            }
        }

        let auth_lengths = (0..PARAM_TAU)
            .map(|_| {
                let len =
                    u16::from_le_bytes(signature_plain[offset..offset + 2].try_into().unwrap());
                offset += 2;
                len
            })
            .collect::<Vec<u16>>();

        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for (e, auth_len) in auth_lengths.iter().enumerate() {
            let mut auth_path = Vec::with_capacity(*auth_len as usize);
            for _ in 0..*auth_len {
                auth_path.push(
                    signature_plain[offset..offset + PARAM_DIGEST_SIZE]
                        .try_into()
                        .unwrap(),
                );
                offset += PARAM_DIGEST_SIZE;
            }
            auth[e] = (auth_path);
        }

        Signature {
            salt,
            h1,
            broadcast_plain,
            broadcast_shares_plain,
            solution_share,
            auth,
        }
    }

    pub(crate) fn sign_message(
        entropy: (Seed, Salt),
        secret_key: SecretKey,
        message: &[u8],
    ) -> Signature {
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
        let input_plain = input.serialise();
        let mut input_shares = [[[0u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU];

        // Generate coefficients
        let mut input_coefs = [[[0u8; INPUT_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                prg.sample_field_fq_elements(&mut input_coefs[e][i]);
            }
        }

        for e in 0..PARAM_TAU {
            for i in 0..(PARAM_N - 1) {
                // We need to compute the following:
                // input_share[e][i] = input_plain + sum^ℓ_(j=1) fij · input coef[e][j]
                let f_i = u8::try_from(i + 1).unwrap();
                let mut eval_sum = [0u8; INPUT_SIZE];

                // Compute the inner sum
                // sum^ℓ_(j=1) fij · input coef[e][j]
                for j in 0..PARAM_L {
                    gf256_add_vector_mul_scalar(
                        &mut eval_sum,
                        &input_coefs[e][j],
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
            input_shares[e][PARAM_N - 1] = input_coefs[e][PARAM_L - 1];
        }
        let mut commitments: [Hash; PARAM_TAU] = [Hash::default(); PARAM_TAU];

        // Commit shares
        let mut merkle_trees: Vec<MerkleTree> = Vec::with_capacity(PARAM_TAU);
        for e in 0..PARAM_TAU {
            let mut commitments_prime = [Hash::default(); PARAM_N];
            for i in 0..PARAM_N {
                // Commit to the shares
                commitments_prime[i] = commit_share(&salt, e as u16, i as u16, &input_shares[e][i]);
            }
            let merkle_tree = MerkleTree::new(commitments_prime, Some(salt));
            commitments[e] = merkle_tree.get_root();
            merkle_trees.push(merkle_tree);
        }

        // First challenge (MPC challenge)

        // h1 = Hash1 (seedH , y, salt, com[1], . . . , com[τ ])
        let mut h1_data: Vec<&[u8]> = vec![&secret_key.seed_h, &secret_key.y, &salt];
        for e in 0..PARAM_TAU {
            h1_data.push(&commitments[e]);
        }
        let h1 = hash_1(h1_data);
        let chal = Challenge::new(h1);

        // MPC Simulation
        let broadcast = MPC::compute_broadcast(input, &chal, h_prime, secret_key.y);
        let mut broadcast_shares = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];

        // Run through Tau and l to compute the broadcast shares
        for e in 0..PARAM_TAU {
            for j in 0..PARAM_L {
                let broadcast_share = MPC::party_computation(
                    input_coefs[e][j],
                    &chal,
                    h_prime,
                    secret_key.y,
                    &broadcast,
                    false,
                );
                broadcast_shares[e][j] = broadcast_share.serialise();
            }
        }

        let broadcast_plain = broadcast.serialise();
        let mut broadcast_shares_plain = [0u8; BROADCAST_SHARE_PLAIN_SIZE * PARAM_L * PARAM_TAU];
        for e in 0..PARAM_TAU {
            for j in 0..PARAM_L {
                let offset = BROADCAST_SHARE_PLAIN_SIZE * (e * PARAM_L + j);
                broadcast_shares_plain[offset..offset + BROADCAST_SHARE_PLAIN_SIZE]
                    .copy_from_slice(&broadcast_shares[e][j]);
            }
        }

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

        // Build the signature
        let signature = Signature::new(
            salt,
            h1,
            broadcast_plain,
            broadcast_shares_plain,
            view_opening_challenges,
            &merkle_trees,
            input_shares,
        );

        signature
    }

    pub(crate) fn verify_signature(
        public_key: PublicKey,
        signature: Signature,
        message: &[u8],
    ) -> bool {
        // Expansion of parity-check matrix
        let h_prime = HPrimeMatrix::gen_random(&mut PRG::init(&public_key.seed_h, None));

        // Signature parsing
        let (salt, h1, broadcast_plain, broadcast_shares_plain, solution_share, mut auth) = (
            signature.salt,
            signature.h1,
            signature.broadcast_plain,
            signature.broadcast_shares_plain,
            signature.solution_share,
            signature.auth,
        );

        // First challenge (MPC challenge) Only generate one in the case of threshold variant
        let chal = Challenge::new(h1);

        // Second challenge (view-opening challenge)
        let h2_data: Vec<&[u8]> = vec![
            message,
            &salt,
            &h1,
            &broadcast_plain,
            &broadcast_shares_plain,
        ];
        let h2 = hash_2(h2_data);

        // Compute the view-opening challenges
        let view_opening_challenges = MPC::expand_view_challenges_threshold(h2);

        let broadcast = Broadcast::parse(broadcast_plain);
        let mut broadcast_shares = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for j in 0..PARAM_L {
                let offset = BROADCAST_SHARE_PLAIN_SIZE * (e * PARAM_L + j);
                broadcast_shares[e][j] = broadcast_shares_plain
                    [offset..offset + BROADCAST_SHARE_PLAIN_SIZE]
                    .try_into()
                    .unwrap();
            }
        }
        let mut sh_broadcast = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut commitments: [Hash; PARAM_TAU] = [Hash::default(); PARAM_TAU];
        // Party computation and regeneration of Merkle commitments
        for e in 0..PARAM_TAU {
            let mut commitments_prime = [Hash::default(); PARAM_L];
            for (li, i) in view_opening_challenges[e].iter().enumerate() {
                let mut with_offset = true;
                if *i as usize == PARAM_N {
                    sh_broadcast[e][li] = broadcast_shares[e][*i as usize];
                    with_offset = false;
                } else {
                    // We need to compute the following:
                    // input_share[e][i] = input_plain + sum^ℓ_(j=1) fij · input coef[e][j]
                    let f_i = i.to_le_bytes()[0];

                    let mut eval_sum = [0u8; BROADCAST_SHARE_PLAIN_SIZE];

                    // Compute the inner sum
                    // sum^ℓ_(j=1) fij · input coef[e][j]
                    for j in 0..PARAM_L {
                        gf256_add_vector_mul_scalar(
                            &mut eval_sum,
                            &broadcast_shares[e][j],
                            f_i.field_pow((j + 1) as u8),
                        );
                    }

                    // Add the input_plain to the sum
                    // broadcast_plain + eval_sum
                    gf256_add_vector_with_padding(&mut eval_sum, &broadcast_plain);

                    // input_shares[e][i] = ...
                    gf256_add_vector(&mut sh_broadcast[e][li], &eval_sum);
                }

                // Verify the Merkle path
                let beaver_triples = MPC::inverse_party_computation(
                    solution_share[e][li],
                    BroadcastShare::parse(sh_broadcast[e][li]),
                    &chal,
                    h_prime,
                    public_key.y,
                    &broadcast,
                    with_offset,
                );

                let input_share =
                    Input::append_beaver_triples(solution_share[e][li], beaver_triples);
                // Commit to the shares
                commitments_prime[li] = commit_share(&salt, e as u16, *i, &input_share);
            }
            let Ok(root) = get_merkle_root_from_auth(
                &mut auth[e],
                &commitments_prime,
                &view_opening_challenges[e],
                Some(salt),
            ) else {
                return false;
            };
            commitments[e] = root;
        }

        // h1 = Hash1 (seedH , y, salt, com[1], . . . , com[τ ])
        let mut h1_data: Vec<&[u8]> = vec![&public_key.seed_h, &public_key.y, &salt];
        for e in 0..PARAM_TAU {
            h1_data.push(&commitments[e]);
        }
        let h1_prime = hash_1(h1_data);

        h1 == h1_prime
    }
}

#[cfg(test)]
mod signature_tests {

    use super::*;
    use crate::constants::params::{PARAM_DIGEST_SIZE, PARAM_SEED_SIZE};

    #[test]
    fn test_serialise_deserialise_signature() {
        let auth_lengths: [usize; PARAM_TAU] = [5, 6, 7, 8, 9, 10];
        let auth_vec = auth_lengths
            .iter()
            .map(|&len| vec![Hash::default(); len])
            .collect::<Vec<Vec<Hash>>>();

        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for (i, vec) in auth_vec.into_iter().enumerate() {
            auth[i] = vec;
        }

        let sign = Signature {
            salt: [1u8; PARAM_SALT_SIZE],
            h1: [2u8; PARAM_DIGEST_SIZE],
            broadcast_plain: [3u8; BROADCAST_PLAIN_SIZE],
            broadcast_shares_plain: [4u8; BROADCAST_SHARE_PLAIN_SIZE * PARAM_L * PARAM_TAU],
            solution_share: [[[5u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
            auth,
        };

        let serialised = sign.serialise();
        let deserialised = Signature::parse(serialised);

        assert_eq!(sign.salt, deserialised.salt);
        assert_eq!(sign.h1, deserialised.h1);
        assert_eq!(sign.broadcast_plain, deserialised.broadcast_plain);
        assert_eq!(
            sign.broadcast_shares_plain,
            deserialised.broadcast_shares_plain
        );
        assert_eq!(sign.solution_share, deserialised.solution_share);

        for (i, auth_len) in auth_lengths.iter().enumerate() {
            assert_eq!(auth_len, &deserialised.auth[i].len());
        }
    }

    #[test]
    fn test_sign_verify_signature() {
        let seed_root = [0u8; PARAM_SEED_SIZE];
        let (pk, sk) = crate::keygen::keygen(seed_root);
        let message = b"Hello, World!";
        let entropy = (seed_root, [0u8; PARAM_SALT_SIZE]);
        let signature = Signature::sign_message(entropy, sk, message);
        let valid = Signature::verify_signature(pk, signature, message);
        assert!(valid);
    }

    #[test]
    fn test_auth_in_new() {
        let salt = [1u8; PARAM_SALT_SIZE];
        let h1 = [2u8; PARAM_DIGEST_SIZE];
        let broadcast_plain = [3u8; BROADCAST_PLAIN_SIZE];
        let broadcast_shares_plain = [4u8; BROADCAST_SHARE_PLAIN_SIZE * PARAM_L * PARAM_TAU];
        let view_opening_challenges = MPC::expand_view_challenges_threshold(Hash::default());
        let input_shares = [[[5u8; INPUT_SIZE]; PARAM_N]; PARAM_TAU];
        let mut merkle_trees: Vec<MerkleTree> = Vec::with_capacity(PARAM_TAU);
        let mut commitments = Vec::with_capacity(PARAM_TAU);

        for e in 0..PARAM_TAU {
            commitments.push(vec![]);
            for i in 0..PARAM_N {
                commitments[e].push(commit_share(
                    &salt,
                    e as u16,
                    i as u16,
                    &[i.try_into().unwrap(); INPUT_SIZE],
                ));
            }

            merkle_trees.push(MerkleTree::new(
                commitments[e].as_slice().try_into().unwrap(),
                Some(salt),
            ));
        }

        let mut signature = Signature::new(
            salt,
            h1,
            broadcast_plain,
            broadcast_shares_plain,
            view_opening_challenges,
            &merkle_trees,
            input_shares,
        );

        for e in 0..PARAM_TAU {
            let mut chosen_commitments = vec![];
            assert_eq!(
                signature.auth[e],
                merkle_trees[e].get_merkle_path(&view_opening_challenges[e])
            );
            for i_val in view_opening_challenges[e].iter() {
                chosen_commitments.push(commitments[e][*i_val as usize]);
            }
            assert_eq!(
                get_merkle_root_from_auth(
                    &mut signature.auth[e],
                    chosen_commitments.as_slice().try_into().unwrap(),
                    &view_opening_challenges[e],
                    Some(salt)
                )
                .unwrap(),
                merkle_trees[e].get_root()
            );
        }
    }
}
