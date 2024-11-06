use crate::{
    arith::arrays::{Array2D, Array2DTrait, Array3D, Array3DTrait},
    constants::{
        params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_M_SUB_K, PARAM_SALT_SIZE, PARAM_TAU},
        types::{Hash, Salt, Seed},
    },
    mpc::{
        broadcast::{BROADCAST_PLAIN_SIZE, BROADCAST_SHARE_PLAIN_SIZE},
        mpc::MPC,
    },
    subroutines::{
        marshalling::Marshalling,
        merkle_tree::get_auth_size,
        prg::hashing::{hash_1, hash_2},
    },
    witness::SOLUTION_PLAIN_SIZE,
};

#[derive(Debug, PartialEq)]
pub struct Signature {
    pub(crate) message: Vec<u8>,
    pub(crate) salt: Salt,
    pub(crate) h1: Hash,
    pub(crate) broadcast_plain: [u8; BROADCAST_PLAIN_SIZE],
    pub(crate) broadcast_shares: Array3D,
    // wit_share from spec
    pub(crate) solution_share: Array3D,
    pub(crate) auth: [Vec<Hash>; PARAM_TAU],
    // Calculated in parsing
    pub(crate) view_opening_challenges: Array2D<u16>,
}

impl Signature {
    pub(crate) fn get_length(&self) -> [u8; 4] {
        let mut length = self.salt.len();
        length += self.h1.len();
        length += self.broadcast_plain.len();
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                length += self.broadcast_shares.get_row_slice(e, i).len();
                length += self.solution_share.get_row_slice(e, i).len();
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
        y: &Vec<u8>, // Vector of size PARAM_M_SUB_K
        salt: Salt,
        commitments: [Hash; PARAM_TAU],
    ) -> Hash {
        let mut h1_data: Vec<&[u8]> = vec![seed_h, y, &salt];
        for e in 0..PARAM_TAU {
            h1_data.push(&commitments[e]);
        }
        hash_1(h1_data)
    }

    /// Fiat-Shamir Hash2
    /// h2 = Hash (2, message, salt, h1, broadcast_plain, broadcast_shares)
    pub(super) fn gen_h2(
        message: &Vec<u8>,
        salt: &Salt,
        h1: &Hash,
        broadcast_plain: &[u8],
        broadcast_shares: &Array3D,
    ) -> Hash {
        let mut h2_data: Vec<&[u8]> = vec![message.as_slice(), salt, h1, broadcast_plain];
        h2_data.push(broadcast_shares.to_bytes());

        hash_2(h2_data)
    }
}

impl Marshalling for Signature {
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
                serialised.extend_from_slice(&self.broadcast_shares.get_row_slice(e, i));
                serialised.extend_from_slice(&self.solution_share.get_row_slice(e, i));
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

    /// Parse a signature from a byte array of form (signature_len:[u8; 4] | msg | salt | h1 | broadcast_plain | broadcast_shares | auth)
    fn parse(signature_plain: &Vec<u8>) -> Result<Signature, String> {
        // TODO: Check if the signature is valid

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

        let mut solution_share = Array3D::new(SOLUTION_PLAIN_SIZE, PARAM_L, PARAM_TAU);
        let mut broadcast_shares = Array3D::new(BROADCAST_SHARE_PLAIN_SIZE, PARAM_L, PARAM_TAU);
        for e in 0..PARAM_TAU {
            for i in 0..PARAM_L {
                // Broadcast shares
                broadcast_shares.set_row_slice(
                    e,
                    i,
                    signature_plain[offset..offset + BROADCAST_SHARE_PLAIN_SIZE]
                        .try_into()
                        .unwrap(),
                );
                offset += BROADCAST_SHARE_PLAIN_SIZE;

                // Witness shares
                solution_share.set_row_slice(
                    e,
                    i,
                    signature_plain[offset..offset + SOLUTION_PLAIN_SIZE]
                        .try_into()
                        .unwrap(),
                );
                offset += SOLUTION_PLAIN_SIZE;
            }
        }

        // We need to create the view opening challenges in order to get the auth paths.
        // We can do this by computing the second hash
        // and then expanding the view opening challenges
        let h2 = Signature::gen_h2(&message, &salt, &h1, &broadcast_plain, &broadcast_shares);
        let view_opening_challenges = MPC::expand_view_challenge_hash(h2);

        // Expand the view opening challenges
        let mut auth_lengths = [0; PARAM_TAU];
        // Get the auth sizes
        for e in 0..PARAM_TAU {
            auth_lengths[e] = get_auth_size(&view_opening_challenges.get_row(e));
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
    fn test_serialise_parse_signature() {
        let message = vec![1u8, 2u8, 3u8, 4u8];
        let seed_root = [0u8; PARAM_SEED_SIZE];
        let salt = [1u8; PARAM_SALT_SIZE];
        let entropy = (seed_root, salt);
        let (_, sk) = keygen(seed_root);

        let signature = Signature::sign_message(entropy, sk, &message).unwrap();

        let deserialised = Signature::parse(&signature).unwrap();

        assert_eq!(message, deserialised.message);
        assert_eq!(salt, deserialised.salt);
        assert_eq!(signature, deserialised.serialise());
    }
}
