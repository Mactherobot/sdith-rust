use crate::{
    constants::{CommitmentsArray, PARAM_LOG_NB_PARTIES, PARAM_NB_PARTIES},
    helpers::modular_arithmetics::ceil_log2,
    subroutines::hashing::hash_finalize,
};

use super::{
    commitments::Hash,
    hashing::{get_hasher, get_hasher_with_prefix},
};

pub const PARAM_MERKLE_TREE_HEIGHT: usize = PARAM_LOG_NB_PARTIES;
pub const PARAM_MERKLE_TREE_NODES: usize =
    2_usize.pow(PARAM_MERKLE_TREE_HEIGHT as u32) + (PARAM_NB_PARTIES) - 1;

pub const HASH_PREFIX_MERKLE_TREE: u8 = 3;

struct MerkleTree {
    height: u8,
    n_nodes: usize,
    n_leaves: usize,
    nodes: [Hash; PARAM_MERKLE_TREE_NODES as usize],
}

impl MerkleTree {
    fn new(commitments: CommitmentsArray, salt: Option<Hash>) -> Self {
        let mut nodes: [Hash; PARAM_MERKLE_TREE_NODES as usize] =
            [Hash::default(); PARAM_MERKLE_TREE_NODES as usize];
        let nb_leaves = commitments.len();
        let height: u8 = ceil_log2(nb_leaves as u32).try_into().unwrap();
        let nb_nodes = (1 << (height)) + nb_leaves - 1;

        let mut first_index = nb_nodes - nb_leaves;
        let mut last_index = nb_nodes;

        // Add leaves to the tree
        for i in 0..nb_leaves {
            nodes[first_index + i] = commitments[i];
        }

        let mut hasher = get_hasher();

        for _h in 0..=height {
            first_index = first_index >> 1;
            last_index = last_index >> 1;

            let mut parent_index = first_index;
            while parent_index <= last_index {
                let left_child_index = 2 * parent_index;
                let right_child_index = 2 * parent_index + 1;

                if right_child_index >= nb_nodes {
                    nodes[parent_index] = nodes[left_child_index];
                    break;
                }

                hasher.reset();
                hasher.update(&[HASH_PREFIX_MERKLE_TREE]);

                if let Some(salt) = salt {
                    hasher.update(&salt);
                }
                hasher.update(&nodes[left_child_index]);
                hasher.update(&nodes[right_child_index]);

                nodes[parent_index] = hash_finalize(&mut *hasher);
                parent_index += 1;
            }
        }

        Self {
            height,
            n_nodes: nb_nodes as usize,
            n_leaves: nb_leaves,
            nodes,
        }
    }

    pub fn get_merkle_path() {
        todo!()
    }

    pub fn get_merkle_root_from_auth() {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::constants::PARAM_NB_PARTIES;

    #[test]
    fn test_merkle_tree() {
        let commitments = [[1_u8; 32]; PARAM_NB_PARTIES as usize];
        let tree = MerkleTree::new(commitments, None);
        assert_eq!(tree.height, PARAM_MERKLE_TREE_HEIGHT as u8);
        assert_eq!(tree.n_nodes, PARAM_MERKLE_TREE_NODES as usize);
        assert_eq!(tree.n_leaves, PARAM_NB_PARTIES as usize);

        let mut hasher = get_hasher();
        hasher.update(&[HASH_PREFIX_MERKLE_TREE]);
        hasher.update(&2_u16.to_le_bytes());
        hasher.update(&tree.nodes[1]);
        hasher.update(&tree.nodes[2]);
        let root = hash_finalize(&mut *hasher);
        assert_eq!(tree.nodes[0], root);

    }
}
