use std::error::Error;

use num_traits::ToPrimitive;
use queues::Queue;
use tiny_keccak::Hasher;

use crate::constants::{
    params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_LOG_N, PARAM_N, PARAM_TAU},
    types::{CommitmentsArray, Hash},
};

use queues::*;

use super::prg::hashing::{get_hasher, hash_finalize};

pub(crate) const PARAM_MERKLE_TREE_HEIGHT: usize = PARAM_LOG_N;
pub(crate) const PARAM_MERKLE_TREE_NODES: usize =
    2_usize.pow(PARAM_MERKLE_TREE_HEIGHT as u32) + (PARAM_N);

pub(crate) const HASH_PREFIX_MERKLE_TREE: u8 = 3;

pub(crate) struct MerkleTree {
    pub(crate) height: i32,
    pub(crate) n_nodes: usize,
    pub(crate) n_leaves: usize,
    pub(crate) nodes: [Hash; PARAM_MERKLE_TREE_NODES as usize],
}

impl MerkleTree {
    pub(crate) fn new(commitments: CommitmentsArray, salt: Option<Hash>) -> Self {
        let mut nodes: [Hash; PARAM_MERKLE_TREE_NODES] = [Hash::default(); PARAM_MERKLE_TREE_NODES];
        let nb_leaves = commitments.len();
        let height: i32 = nb_leaves
            .to_f32()
            .expect("could not convert to f32")
            .log2()
            .ceil() as i32;
        let nb_nodes = (1 << (height)) + nb_leaves - 1;

        let mut first_index = nb_nodes - nb_leaves + 1;
        let mut last_index = nb_nodes;

        // Add leaves to the tree
        (0..nb_leaves).for_each(|i| {
            nodes[first_index + i] = commitments[i];
        }); // TODO: Otimize the loop below with batch processing https://github.com/sdith/sdith/blob/main/Optimized_Implementation/Threshold_Variant/sdith_threshold_cat1_gf256/merkle-tree.c
        for _h in (0..height).rev() {
            // Indicates if the last node is isolated
            let last_is_isolated = 1 - (last_index & 0x1);

            first_index >>= 1;
            last_index >>= 1;

            let mut parent_index = first_index;
            while parent_index <= last_index {
                let mut hasher = get_hasher();

                let left_child_index = 2 * parent_index;
                let right_child_index = 2 * parent_index + 1;

                if let Some(salt) = salt {
                    hasher.update(&salt);
                }

                hasher.update(&[HASH_PREFIX_MERKLE_TREE]);
                hasher.update(&2_u16.to_le_bytes());
                hasher.update(&nodes[left_child_index]);
                if (parent_index < last_index) || last_is_isolated == 0 {
                    hasher.update(&nodes[right_child_index]);
                }
                nodes[parent_index] = hash_finalize(hasher);

                parent_index += 1;
            }
        }

        Self {
            height,
            n_nodes: nb_nodes,
            n_leaves: nb_leaves,
            nodes,
        }
    }

    /// Returns the root of the merkle tree
    pub(crate) fn get_root(&self) -> Hash {
        self.nodes[1]
    }

    /// Returns the nodes required to calculate the merkle root from the leaves.
    ///
    /// # Arguments
    /// - `selected_leaves`: A vector with the indexes of the selected leaves.
    ///
    /// # Returns
    /// A vector of node hash values that are required to calculate the merkle root from the selected leaves.
    ///
    /// If you supply all leaves or none, the auth path will be empty.
    pub(crate) fn get_merkle_path(&self, selected_leaves: &[u16]) -> Vec<Hash> {
        // Find the missing nodes
        let mut missing = vec![];
        for i in 0..=self.n_leaves {
            if !selected_leaves.contains(&((i) as u16)) {
                missing.push(i + self.n_leaves);
            }
        }

        // Remove the leaves from the missing list
        for i in (1..self.n_nodes - self.n_leaves + 1).rev() {
            if missing.contains(&(i * 2)) && missing.contains(&(i * 2 + 1)) {
                // Remove the 2 children from the missing list and add the parent instead
                missing.retain(|&x| x != i * 2);
                missing.retain(|&x| x != i * 2 + 1);
                missing.push(i);
            }
        }

        let mut auth = vec![];

        for h in (1..=self.height).rev() {
            for i in 1 << h..(1 << (h + 1)) {
                if missing.contains(&i) {
                    auth.push(self.nodes[i]);
                }
            }
        }

        auth
    }
}

/// Recalculates the merkle root from the commitments and the auth
pub(crate) fn get_merkle_root_from_auth(
    auth: &mut Vec<Hash>,
    commitments: [Hash; PARAM_L],
    selected_leaves: &[u16],
) -> Result<Hash, &'static str> {
    let mut q: Queue<(Hash, usize)> = queue![];
    for i in 0..PARAM_L {
        if selected_leaves.contains(&(i as u16)) {
            let index = (1 << PARAM_MERKLE_TREE_HEIGHT) + selected_leaves[i] as usize;
            let add = q.add((commitments[i], index));
            if add.is_err() {
                return Err("Could not add element to queue");
            }
        }
    }

    let (mut height, mut last_index) = (1 << PARAM_MERKLE_TREE_HEIGHT, PARAM_MERKLE_TREE_NODES - 1);
    // While the next element is not the root of the tree
    while q.peek().unwrap().1 != 1 {
        // Get the next element
        let (mut node, index) = q.remove().unwrap();

        // if the height is more than the index then divide the height and last_index by 2
        if index < height {
            height >>= 1;
            last_index >>= 1;
        }
        let mut next_node: Hash = Hash::default();
        let is_left_child = index % 2 == 0;
        if is_left_child && index == last_index {
            let add = q.add((node, index >> 1));
            if add.is_err() {
                return Err("Could not add element to queue");
            }
        } else {
            let mut next_index = 0;
            let ok = q.peek();
            if ok.is_ok() {
                next_index = ok.unwrap().1;
            }
            if index % 2 == 0 && next_index == index + 1 {
                (next_node, _) = q.remove().unwrap();
            } else {
                if auth[0].len() >= PARAM_DIGEST_SIZE {
                    // Extract and remove the first hash of the auth path
                    next_node = auth.remove(0);
                } else {
                    return Err("Auth path is too short");
                }
                if index % 2 == 1 {
                    // swap the next node with the current node
                    std::mem::swap(&mut node, &mut next_node);
                }
            }
            let mut hasher = get_hasher();
            hasher.update(&[HASH_PREFIX_MERKLE_TREE]);
            hasher.update(&2_u16.to_le_bytes());
            hasher.update(&node);
            if next_node != [0_u8; 32] {
                hasher.update(&next_node);
            }
            let parent = hash_finalize(hasher);
            let add = q.add((parent, index >> 1));
            if add.is_err() {
                return Err("Could not add element to queue");
            }
        }
    }
    let (root, _) = q.remove().unwrap();

    Ok(root)
}
#[cfg(test)]
mod test {
    use tiny_keccak::Hasher;

    use crate::constants::params::{PARAM_L, PARAM_N};

    use super::*;

    #[test]
    fn test_merkle_tree() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);
        assert_eq!(tree.height, PARAM_MERKLE_TREE_HEIGHT as i32);
        assert_eq!(tree.n_nodes, { PARAM_MERKLE_TREE_NODES - 1 });
        assert_eq!(tree.n_leaves, { PARAM_N });

        let mut hasher = get_hasher();
        hasher.update(&[HASH_PREFIX_MERKLE_TREE]);
        hasher.update(&2_u16.to_le_bytes());
        hasher.update(&tree.nodes[2]);
        hasher.update(&tree.nodes[3]);
        let root = hash_finalize(hasher);
        assert_eq!(tree.nodes[1], root);
    }

    #[test]
    fn test_merkle_zero_auth_path() {
        // When you have all leaves selected, you don't need any extra nodes to calculate the root. Therefore, if all leaves are selected, the auth path should be empty
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let mut selected_leaves = [0u16; PARAM_N];
        for i in 0..PARAM_N {
            selected_leaves[i] = i as u16;
        }
        let auth = tree.get_merkle_path(&selected_leaves);
        assert_eq!(auth.len(), 0);
        assert_eq!(auth.is_empty(), true);

        let auth = tree.get_merkle_path(&[]);
        assert_eq!(auth.len(), 0);
        assert!(auth.is_empty());
    }

    #[test]
    fn test_merkle_one_selected_leaf() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.get_merkle_path(&[1u16]);

        // The auth path should have 8 nodes (one from each level)
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT);
        assert!(!auth.is_empty());
    }

    #[test]
    fn test_merkle_root_from_auth() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let commitmens_tau = [[1_u8; 32]; PARAM_L];
        let mut auth = tree.get_merkle_path(&[233u16]);
        let Ok(root) = get_merkle_root_from_auth(&mut auth, commitmens_tau, &[233u16]) else {
            panic!("Could not get merkle root from auth")
        };
        assert_eq!(tree.nodes[1], root);
    }

    // TODO: Add more tests that are negative
}
