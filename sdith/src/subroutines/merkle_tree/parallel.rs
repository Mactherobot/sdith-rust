//! # Merkle Tree Commitment Scheme implemented using a parallel approach for performance
//!
//! Nodes are stored in an array and the tree is constructed from the bottom up.
//!

use std::{sync::Arc, time::Instant};

use rayon::prelude::*;

use crate::constants::{
    params::{PARAM_DIGEST_SIZE, PARAM_N},
    types::{CommitmentsArray, Hash},
};

use super::{merkle_hash, MerkleTreeTrait, PARAM_MERKLE_TREE_NODES};

type Tree = Vec<Vec<Arc<Hash>>>;

/// Merkle tree struct
#[derive(Debug)]
pub struct ParallelMerkleTree {
    pub tree: Tree,
    pub root: Arc<Hash>,
    pub height: u32,
    n_nodes: usize,
}
impl ParallelMerkleTree {
    fn get_node_height_index(index: usize) -> (usize, usize) {
        // Calculate height using logarithm
        let height = ((index + 1) as f64).log2().floor() as usize;

        // Calculate the starting index of this height
        let start_index_at_height = (1 << height) - 1;

        // Calculate the local index within the height
        let local_index = index - start_index_at_height;

        (height, local_index)
    }
}

impl MerkleTreeTrait for ParallelMerkleTree {
    fn new(commitments: CommitmentsArray, salt: Option<Hash>) -> Self {
        let height: u32 = commitments.len().ilog2() + 1;
        let mut tree: Tree = vec![];

        // Push the leaves to the tree from commitments
        let leaves = commitments
            .iter()
            .map(|c| Arc::new(*c))
            .collect::<Vec<Arc<Hash>>>();
        tree.push(leaves);

        // Build the tree from the bottom up
        for _h in 1..height {
            let current_level = tree.last().unwrap();
            let next_level = current_level
                .par_chunks(2)
                .enumerate()
                .map(|pair| {
                    let (i, [left, right]) = pair else {
                        unreachable!()
                    };
                    let parent_index = i * 4;
                    Arc::new(merkle_hash(parent_index, left, right, salt))
                })
                .collect::<Vec<Arc<Hash>>>();
            tree.push(next_level);
        }

        let n_nodes = if cfg!(test) {
            tree.iter()
                .map(|level| level.len())
                .reduce(|acc, level| acc + level)
                .unwrap()
        } else {
            PARAM_MERKLE_TREE_NODES - 1
        };

        Self {
            root: tree.last().unwrap()[0].clone(),
            tree,
            height,
            n_nodes,
        }
    }

    fn root(&self) -> Hash {
        *self.root
    }

    fn leaf(&self, n: usize) -> Hash {
        *self.tree[0][n]
    }

    fn node(&self, index: usize) -> Hash {
        let (height, index) = Self::get_node_height_index(index);

        // Get the node from the tree
        *self.tree[height][index as usize]
    }

    fn auth_path(&self, selected_leaves: &[u16]) -> Vec<Hash> {
        let revealed_nodes = Self::get_revealed_nodes(selected_leaves);

        let mut auth = vec![];

        // Fetch the missing nodes
        for h in (1..=self.height).rev() {
            for i in 1 << h..(1 << (h + 1)) {
                if revealed_nodes.contains(&i) {
                    auth.push(self.node(i as usize));
                }
            }
        }

        auth
    }

    fn get_auth_size(selected_leaves: &[u16]) -> usize {
        let get_revealed_nodes = Self::get_revealed_nodes(selected_leaves);
        get_revealed_nodes.len() * PARAM_DIGEST_SIZE
    }

    fn n_leaves(&self) -> usize {
        PARAM_N
    }

    fn n_nodes(&self) -> usize {
        self.n_nodes
    }

    fn height(&self) -> u32 {
        self.height
    }
}

#[cfg(test)]
mod tests {
    use crate::subroutines::merkle_tree::PARAM_MERKLE_TREE_HEIGHT;

    use super::*;

    #[test]
    fn test_new() {
        let commitments = super::super::test::setup_test_commitments();
        let tree = ParallelMerkleTree::new(commitments, None);

        // Check each level of the tree
        let mut length = PARAM_N;
        let mut height = 0;
        while length >= 1 {
            assert_eq!(tree.tree[height].len(), length);
            length >>= 1;
            height += 1;
        }

        // Check tree array lengths
        assert_eq!(tree.tree.len(), tree.height as usize);
    }

    #[test]
    fn test_get_node_by_index() {
        // Check that each left most node index is correctly calculated
        let leftmost_indexes = (0..PARAM_MERKLE_TREE_HEIGHT + 1)
            .map(|h| 2_usize.pow(h as u32) - 1)
            .collect::<Vec<usize>>();
        for i in 0..PARAM_MERKLE_TREE_HEIGHT {
            let res = ParallelMerkleTree::get_node_height_index(leftmost_indexes[i]);
            assert_eq!(res, (i, 0), "Failed at index {}", leftmost_indexes[i]);
        }

        // Check that each right most node index is correctly calculated
        let rightmost_indexes = (0..PARAM_MERKLE_TREE_HEIGHT + 1)
            .map(|h| (1 << (h + 1)) - 2)
            .collect::<Vec<usize>>();
        println!("{:?}", rightmost_indexes);
        for i in 0..PARAM_MERKLE_TREE_HEIGHT {
            let res = ParallelMerkleTree::get_node_height_index(rightmost_indexes[i]);
            // Get level width = 2^height
            let level_width = 1 << i;
            assert_eq!(
                res,
                (i, level_width - 1),
                "Failed at index {}",
                rightmost_indexes[i]
            );
        }
    }
}
