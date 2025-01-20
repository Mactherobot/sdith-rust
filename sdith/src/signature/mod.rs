//! # Signature
//!
//! This module contains the implementation of the signature struct and its methods.
//! 
//! Contains the [`Signature`] struct which holds endpoints
//! - Signing: [`Signature::sign_message`] 
//! - Verifying: [`Signature::verify_signature`] functions.
//! 
//! Check out the [`crate::subroutines`] module for the subroutines used in the signature scheme.
//! Check out the [`crate::keygen`] module for the key generation.

mod sign;
mod verify;

use crate::{
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_M_SUB_K, PARAM_SALT_SIZE, PARAM_TAU},
        types::{Hash, Salt, Seed},
    },
    subroutines::{
        challenge::expand_view_challenge_hash,
        merkle_tree::{MerkleTree, MerkleTreeTrait},
        mpc::broadcast::{BROADCAST_PLAIN_SIZE, BROADCAST_SHARE_PLAIN_SIZE},
        prg::hashing::{hash_1, hash_2},
    },
    utils::marshalling::Marshalling,
    keygen::witness::SOLUTION_PLAIN_SIZE,
};

#[derive(Debug, PartialEq, Eq)]
/// Signature struct, containing all the parts of the signature
pub struct Signature {
    /// The message to be signed
    pub message: Vec<u8>,
    /// The salt used in the signature algorithm
    pub salt: Salt,
    /// The h1 hash value
    pub h1: Hash,
    /// The plain broadcast value
    pub broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
    /// The plain broadcast shares computed in the MPC protocol
    pub broadcast_shares: [[[u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    /// The collection of auth values from the merkle tree
    pub auth: [Vec<Hash>; PARAM_TAU],
    /// The solution share generated in the signing. 
    /// These are the inputs to the protocol (S, Q, P polynomials) with beaver triples truncated
    pub solution_share: [[[u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    /// MPC views opened to the verifier. Calculated in parsing
    pub view_opening_challenges: [[u16; PARAM_L]; PARAM_TAU],
}

impl Signature {
    /// Returns the length off the signature
    pub fn get_length(&self) -> [u8; 4] {
        let mut length = self.salt.len();
        length += self.h1.len();
        length += self.broadcast_plain.len();
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                length += self.broadcast_shares[e][i].len();
                length += self.solution_share[e][i].len();
            }
        }
        for auth in &self.auth {
            for hash in auth {
                length += hash.len();
            }
        }
        ((length) as u32).to_le_bytes()
    }

    /// Fiat-Shamir Hash1
    /// h1 = Hash (1, seedH , y, salt, com[1], . . . , com[τ ])
    pub(super) fn gen_h1(
        seed_h: &Seed,
        y: &[u8; PARAM_M_SUB_K],
        salt: Salt,
        commitments: [Hash; PARAM_TAU],
    ) -> Hash {
        let mut h1_data: Vec<&[u8]> = vec![seed_h, y, &salt];
        commitments
            .iter()
            .for_each(|commitment| h1_data.push(commitment));
        hash_1(h1_data)
    }

    /// Fiat-Shamir Hash2
    /// h2 = Hash (2, message, salt, h1, broadcast_plain, broadcast_shares)
    pub(super) fn gen_h2(
        message: &Vec<u8>,
        salt: &Salt,
        h1: &Hash,
        broadcast_plain: &[u8],
        broadcast_shares: &[[[u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU],
    ) -> Hash {
        let mut h2_data: Vec<&[u8]> = vec![message.as_slice(), salt, h1, broadcast_plain];
        broadcast_shares.iter().for_each(|broadcast_shares_e| {
            broadcast_shares_e
                .iter()
                .for_each(|broadcast_shares_e_i| h2_data.push(broadcast_shares_e_i))
        });

        hash_2(h2_data)
    }
}

impl Marshalling<Vec<u8>> for Signature {
    // Serialise message into (signature_len:[u8; 4] | msg | salt | h1 | broadcast_plain | broadcast_shares | auth)
    fn serialise(&self) -> Vec<u8> {
        let mut serialised = vec![];
        serialised.extend_from_slice(&self.get_length());
        serialised.extend_from_slice(&self.message);
        serialised.extend_from_slice(&self.salt);
        serialised.extend_from_slice(&self.h1);
        serialised.extend_from_slice(&self.broadcast_plain);

        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                serialised.extend_from_slice(&self.broadcast_shares[e][i]);
                serialised.extend_from_slice(&self.solution_share[e][i]);
            }
        }

        // Append auth
        for auth in &self.auth {
            for hash in auth {
                serialised.extend_from_slice(hash);
            }
        }

        serialised
    }

    /// Parse a signature from a byte array of form `(signature_len:[u8; 4] | msg | salt | h1 | broadcast_plain | broadcast_shares | auth)`
    /// 
    /// This function recomputes `h2` and the resulting View opening challenges from the signature.
    fn parse(signature_plain: &Vec<u8>) -> Result<Signature, String> {
        // Extract the signature length
        let signature_len = u32::from_le_bytes([
            signature_plain[0],
            signature_plain[1],
            signature_plain[2],
            signature_plain[3],
        ]);

        // Extract the message
        let message_length = signature_plain.len() - signature_len as usize;
        let mut message = Vec::with_capacity(message_length);
        message.extend_from_slice(&signature_plain[4usize..message_length]);

        // Create offset to be used for inserting into the sig byte array
        let mut offset = message_length;

        // Salt
        let salt: Salt = signature_plain[offset..offset + PARAM_SALT_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_SALT_SIZE;

        // H_1
        let h1: Hash = signature_plain[offset..offset + PARAM_DIGEST_SIZE]
            .try_into()
            .unwrap();
        offset += PARAM_DIGEST_SIZE;

        // Plain Broadcast
        let broadcast_plain: [u8; BROADCAST_PLAIN_SIZE] = signature_plain
            [offset..offset + BROADCAST_PLAIN_SIZE]
            .try_into()
            .unwrap();
        offset += BROADCAST_PLAIN_SIZE;

        let mut solution_share = [[[0u8; SOLUTION_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        let mut broadcast_shares = [[[0u8; BROADCAST_SHARE_PLAIN_SIZE]; PARAM_L]; PARAM_TAU];
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                // Broadcast shares
                broadcast_shares[e][i] = signature_plain
                    [offset..offset + BROADCAST_SHARE_PLAIN_SIZE]
                    .try_into()
                    .unwrap();
                offset += BROADCAST_SHARE_PLAIN_SIZE;

                // Witness shares
                solution_share[e][i] = signature_plain[offset..offset + SOLUTION_PLAIN_SIZE]
                    .try_into()
                    .unwrap();
                offset += SOLUTION_PLAIN_SIZE;
            }
        }

        // We need to create the view opening challenges in order to get the auth paths.
        // We can do this by computing the second hash
        // and then expanding the view opening challenges
        let h2 = Signature::gen_h2(&message, &salt, &h1, &broadcast_plain, &broadcast_shares);
        let view_opening_challenges = expand_view_challenge_hash(h2);

        // Expand the view opening challenges
        let mut auth_lengths = [0; PARAM_TAU];
        // Get the auth sizes
        for e in 0..PARAM_TAU {
            auth_lengths[e] = MerkleTree::get_auth_size(&view_opening_challenges[e]);
        }

        // Check if length is correct
        if signature_plain.len() != offset + auth_lengths.iter().sum::<usize>() {
            return Err("Signature length does not match calculated auth path lengths".to_string());
        }

        let mut auth: [Vec<Hash>; PARAM_TAU] = Default::default();
        for (e, auth_len) in auth_lengths.iter().enumerate() {
            auth[e] = signature_plain[offset..offset + *auth_len]
                .chunks_exact(PARAM_DIGEST_SIZE)
                .map(|chunk| chunk.try_into().unwrap())
                .collect();
            offset += *auth_len;
        }

        Ok(Signature {
            message,
            salt,
            h1,
            broadcast_plain,
            broadcast_shares,
            solution_share,
            auth,
            view_opening_challenges,
        })
    }
}

#[cfg(test)]
mod signature_tests {

    use super::*;
    use crate::{constants::params::PARAM_SEED_SIZE, keygen::keygen};

    #[test]
    fn test_marhalling_signature() {
        let message = vec![1u8, 2u8, 3u8, 4u8];
        let seed1 = [0u8; PARAM_SEED_SIZE];
        let seed2 = [1u8; PARAM_SEED_SIZE];
        let salt = [1u8; PARAM_SALT_SIZE];
        let entropy = (seed1, salt);

        let (_, sk1) = keygen(seed1);
        let (_, sk2) = keygen(seed2);

        let signature1 = Signature::sign_message(entropy, &sk1, &message).unwrap();
        let signature2 = Signature::sign_message(entropy, &sk2, &message).unwrap();

        crate::utils::marshalling::test_marhalling(signature1, signature2);
    }

    use crate::{
        constants::{
            params::{PARAM_K, PARAM_SALT_SIZE},
            types::Seed,
        },
        utils::marshalling::Marshalling,
    };

    #[test]
    fn test_sign_verify_signature() {
        let spec_master_seed: Seed = [0u8; PARAM_SEED_SIZE];
        let (pk, sk) = keygen(spec_master_seed);
        let message = b"Hello, World!".to_vec();
        let entropy = (spec_master_seed, [0u8; PARAM_SALT_SIZE]);

        let signature = Signature::sign_message(entropy, &sk, &message).unwrap();
        let valid = Signature::verify_signature(&pk, &signature.serialise());

        if valid.is_err() {
            println!("{:?}", valid);
        }
        assert!(valid.is_ok());
    }

    #[test]
    fn test_sign_failure() {
        let (_, mut sk1) = keygen([0u8; PARAM_SEED_SIZE]);

        let message = b"Hello, World!".to_vec();
        let entropy = ([0u8; PARAM_SEED_SIZE], [0u8; PARAM_SALT_SIZE]);

        sk1.solution.s_a = [0u8; PARAM_K]; // Invalid s_a
        let signature = Signature::sign_message(entropy, &sk1, &message);
        assert!(signature.is_err());
    }

    #[test]
    fn test_verify_failure() {
        let entropy1 = ([1u8; PARAM_SEED_SIZE], [1u8; PARAM_SALT_SIZE]);
        let (pk1, mut sk1) = keygen([1u8; PARAM_SEED_SIZE]);
        let (pk2, sk2) = keygen([2u8; PARAM_SEED_SIZE]);
        let message = b"Hello, World!".to_vec();

        let signature = Signature::sign_message(entropy1, &sk1, &message)
            .unwrap()
            .serialise();

        assert!(Signature::verify_signature(&pk1, &signature).is_ok());
        assert!(
            Signature::verify_signature(&pk2, &signature).is_err(),
            "Should not verify with different key"
        );

        let mut signature_bit_flip = signature.clone();
        signature_bit_flip[0] = signature_bit_flip[0] ^ 1u8;

        assert!(
            Signature::verify_signature(&pk1, &signature_bit_flip).is_err(),
            "Should not verify if signature is damaged"
        );

        sk1.y = sk2.y;
        let signature = Signature::sign_message(entropy1, &sk1, &message).unwrap();
        assert!(
            Signature::verify_signature(&pk1, &signature.serialise()).is_err(),
            "Should not verify if invalid key, i.e. y \neq Hx"
        );
    }
}
