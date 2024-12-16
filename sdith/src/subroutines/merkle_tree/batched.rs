//! # Merkle Tree Commitment Scheme implemented using an batched approach for performance
//!
//! Nodes are stored in an array and the tree is constructed from the bottom up.
//!

use crate::{
    constants::{
        params::{HASH_PREFIX_MERKLE_TREE, PARAM_DIGEST_SIZE},
        types::{CommitmentsArray, Hash, Salt},
    },
    subroutines::prg::hashing::{SDitHHash, SDitHHashTrait as _},
};

use crate::constants::params::PARAM_MERKLE_TREE_NODES;

use super::{get_revealed_nodes, merkle_hash};

pub(self) fn merkle_hash_x4(
    parent_index: [usize; 4],
    left: [Hash; 4],
    right: [Option<Hash>; 4],
    salt: Option<Salt>,
) -> (Hash, Hash, Hash, Hash) {
    let mut hasher = SDitHHash::init_with_prefix(&[HASH_PREFIX_MERKLE_TREE]);
    let mut hasher_1 = SDitHHash::init_with_prefix(&[HASH_PREFIX_MERKLE_TREE]);
    let mut hasher_2 = SDitHHash::init_with_prefix(&[HASH_PREFIX_MERKLE_TREE]);
    let mut hasher_3 = SDitHHash::init_with_prefix(&[HASH_PREFIX_MERKLE_TREE]);

    if let Some(salt) = salt {
        hasher.update(&salt);
        hasher_1.update(&salt);
        hasher_2.update(&salt);
        hasher_3.update(&salt);
    }

    // Hash the parent_index
    hasher.update(&(parent_index[0] as u16).to_le_bytes());
    hasher_1.update(&(parent_index[1] as u16).to_le_bytes());
    hasher_2.update(&(parent_index[2] as u16).to_le_bytes());
    hasher_3.update(&(parent_index[3] as u16).to_le_bytes());

    // Hash the left and right children
    hasher.update(&left[0]);
    hasher_1.update(&left[1]);
    hasher_2.update(&left[2]);
    hasher_3.update(&left[3]);

    if let Some(right) = right[0] {
        hasher.update(&right);
    }
    if let Some(right) = right[1] {
        hasher_1.update(&right);
    }
    if let Some(right) = right[2] {
        hasher_2.update(&right);
    }
    if let Some(right) = right[3] {
        hasher_3.update(&right);
    }

    (
        hasher.finalize(),
        hasher_1.finalize(),
        hasher_2.finalize(),
        hasher_3.finalize(),
    )
}

pub fn new(
    nodes: &mut [Hash; PARAM_MERKLE_TREE_NODES],
    commitments: CommitmentsArray,
    salt: Option<Hash>,
) -> Hash {
    let nb_leaves = commitments.len();
    let height: u32 = nb_leaves.ilog2();

    let mut first_index = PARAM_MERKLE_TREE_NODES - 1 - nb_leaves + 1;
    let mut last_index = PARAM_MERKLE_TREE_NODES - 1;

    // Add leaves to the tree
    commitments.iter().enumerate().for_each(|(i, commitment)| {
        nodes[first_index + i] = *commitment;
    });

    for _h in (2..height).rev() {
        // Indicates if the last node is isolated
        first_index >>= 1;
        last_index >>= 1;

        let mut parent_index = first_index;
        while parent_index <= last_index {
            let parent_indexes = [
                parent_index,
                parent_index + 1,
                parent_index + 2,
                parent_index + 3,
            ];
            let left_child_hashes = [
                nodes[2 * parent_index],
                nodes[2 * parent_index + 2],
                nodes[2 * parent_index + 4],
                nodes[2 * parent_index + 6],
            ];

            let right_child_hashes = [
                Some(nodes[2 * parent_index + 1]),
                Some(nodes[2 * parent_index + 3]),
                Some(nodes[2 * parent_index + 5]),
                Some(nodes[2 * parent_index + 7]),
            ];
            // Finalize the hash and add it to the parent node
            (
                nodes[parent_index],
                nodes[parent_index + 1],
                nodes[parent_index + 2],
                nodes[parent_index + 3],
            ) = merkle_hash_x4(parent_indexes, left_child_hashes, right_child_hashes, salt);

            parent_index += 4;
        }
    }

    for _h in (0..2).rev() {
        // Indicates if the last node is isolated
        // let last_is_isolated = 1 - (last_index & 0x1);
        first_index >>= 1;
        last_index >>= 1;

        let mut parent_index = first_index;
        while parent_index <= last_index {
            // Calculate the indexes of the left and right children
            let left_child_index = 2 * parent_index;
            let right_child_index = 2 * parent_index + 1;

            // Finalize the hash and add it to the parent node
            nodes[parent_index] = merkle_hash(
                parent_index,
                &nodes[left_child_index],
                &nodes[right_child_index],
                salt,
            );

            parent_index += 1;
        }
    }
    nodes[1]
}

pub fn auth_path(nodes: [Hash; PARAM_MERKLE_TREE_NODES], selected_leaves: &[u16]) -> Vec<Hash> {
    let revealed_nodes = get_revealed_nodes(selected_leaves);
    revealed_nodes
        .iter()
        .map(|&idx| nodes[idx as usize])
        .collect()
}

pub fn get_auth_size(selected_leaves: &[u16]) -> usize {
    let get_revealed_nodes = get_revealed_nodes(selected_leaves);
    get_revealed_nodes.len() * PARAM_DIGEST_SIZE
}
