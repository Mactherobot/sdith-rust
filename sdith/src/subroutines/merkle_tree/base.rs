//! # Merkle Tree Commitment Scheme implemented using an array based approach
//!
//! Nodes are stored in an array and the tree is constructed from the bottom up.
//!

use crate::constants::{
    params::PARAM_DIGEST_SIZE,
    types::{CommitmentsArray, Hash},
};

use super::{merkle_hash, MerkleTreeTrait, PARAM_MERKLE_TREE_NODES};

/// Merkle tree struct
pub struct BaseMerkleTree {
    /// The height of the Merkle tree
    pub height: u32,
    /// The number of nodes in the Merkle tree
    pub n_nodes: usize,
    /// The number of leaves in the Merkle tree
    pub n_leaves: usize,
    /// The nodes of the Merkle tree as a flat array with the root at index 1 and the leaves at the end
    pub nodes: [Hash; PARAM_MERKLE_TREE_NODES],
}

impl MerkleTreeTrait for BaseMerkleTree {
    fn new(commitments: CommitmentsArray, salt: Option<Hash>) -> Self {
        let nb_leaves = commitments.len();
        let height: u32 = nb_leaves.ilog2();
        let mut tree = Self {
            height,
            n_nodes: (1 << (height)) + nb_leaves - 1,
            n_leaves: nb_leaves,
            nodes: [[0u8; PARAM_DIGEST_SIZE]; PARAM_MERKLE_TREE_NODES],
        };

        let mut first_index = tree.n_nodes - nb_leaves + 1;
        let mut last_index = tree.n_nodes;
        // Add leaves to the tree
        commitments.iter().enumerate().for_each(|(i, commitment)| {
            tree.nodes[first_index + i] = *commitment;
        });

        for _h in (0..height).rev() {
            first_index >>= 1;
            last_index >>= 1;

            let mut parent_index = first_index;
            while parent_index <= last_index {
                // Calculate the indexes of the left and right children
                let left_child_index = 2 * parent_index;
                let right_child_index = 2 * parent_index + 1;

                // Finalize the hash and add it to the parent node
                tree.nodes[parent_index] = merkle_hash(
                    parent_index,
                    &tree.nodes[left_child_index],
                    &tree.nodes[right_child_index],
                    salt,
                );

                parent_index += 1;
            }
        }
        tree
    }

    fn root(&self) -> Hash {
        self.nodes[1]
    }

    fn leaf(&self, n: usize) -> Hash {
        assert!(n <= self.n_leaves, "Invalid leaf index: {}", n);
        self.nodes[self.n_leaves + (n) as usize]
    }

    #[inline(always)]
    fn node(&self, index: usize) -> Hash {
        self.nodes[index]
    }

    fn auth_path(&self, selected_leaves: &[u16]) -> Vec<Hash> {
        let revealed_nodes = Self::get_revealed_nodes(selected_leaves);

        let mut auth = vec![];

        // Fetch the missing nodes
        revealed_nodes.iter().for_each(|index| {
            auth.push(self.nodes[*index as usize]);
        });

        auth
    }

    fn get_auth_size(selected_leaves: &[u16]) -> usize {
        let get_revealed_nodes = Self::get_revealed_nodes(selected_leaves);
        get_revealed_nodes.len() * PARAM_DIGEST_SIZE
    }

    fn n_leaves(&self) -> usize {
        self.n_leaves
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }

    fn height(&self) -> u32 {
        self.height
    }
}
