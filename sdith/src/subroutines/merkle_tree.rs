//! # Merkle Tree Commitment Scheme
//!
//! A commitment scheme that allows for efficient communication with partial opening.
//! This scheme is used by the signature scheme to commit to the shares of the parties.
//!
//! The tree is constructed from a list of commitments, where each leaf is a commitment.
//! Parents are calculated by hashing the concatenation of the left and right children along with a [prefix](HASH_PREFIX_MERKLE_TREE).
//! The root of the tree is then sent as the final commitment.
//!
//! To open a commitment, the prover sends the commitment along with the hashed path from the leaf to the root.
//!
//! The verifier can then recalculate the root from the commitment and the path and compare it to the previously received root.
//!
//! The structure allows for the Treshold variant of the signature scheme to only open the commitments to a subset of the parties.

#[cfg(not(feature = "merkle_batching"))]
pub mod base;
#[cfg(not(feature = "merkle_batching"))]
pub use base::BaseMerkleTree as MerkleTree;

#[cfg(feature = "merkle_batching")]
pub mod batched;
#[cfg(feature = "merkle_batching")]
pub use batched::BatchedMerkleTree as MerkleTree;

use crate::constants::{
    params::{PARAM_DIGEST_SIZE, PARAM_LOG_N, PARAM_N},
    types::{CommitmentsArray, Hash, Salt},
};

use queues::{queue, IsQueue as _, Queue};

use super::prg::hashing::{SDitHHash, SDitHHashTrait as _};

/// The height of the Merkle tree
pub(self) const PARAM_MERKLE_TREE_HEIGHT: usize = PARAM_LOG_N;
/// The number of nodes in the Merkle tree
pub(self) const PARAM_MERKLE_TREE_NODES: usize =
    2_usize.pow(PARAM_MERKLE_TREE_HEIGHT as u32) + (PARAM_N);
/// The prefix for the Merkle tree hash
pub(self) const HASH_PREFIX_MERKLE_TREE: u8 = 3;

/// Merkle tree trait
///
/// Adds methods to create new tree, get root, leaf or auth path
pub trait MerkleTreeTrait {
    /// Creates a new Merkle tree from a list of commitments (i.e. pre-hashed leaves in [`CommitmentsArray`]).
    ///
    /// The `salt` is optionally added to the hashing of parent nodes.
    fn new(commitments: CommitmentsArray, salt: Option<Hash>) -> Self;

    /// Returns the root of the Merkle tree.
    fn root(&self) -> Hash;

    /// Returns the leaf at the given index.
    fn leaf(&self, index: usize) -> Hash;

    /// Returns the path from the leaf at the given index to the root.
    fn auth_path(&self, selected_leaves: &[u16]) -> Vec<Hash>;

    /// Returns the size of the auth path in bytes.
    fn get_auth_size(selected_leaves: &[u16]) -> usize;

    /// Returns the number of leaves in the tree
    fn n_leaves(&self) -> usize;

    /// Returns the number of nodes in the tree
    fn n_nodes(&self) -> usize;

    /// Returns the height of the tree
    fn height(&self) -> u32;

    /// Recalculates the merkle root from the commitments and the authentication path
    fn get_root_from_auth_path(
        auth_path: &mut Vec<Hash>,
        commitments: &[Hash],
        selected_leaves: &[u16],
        salt: Option<Hash>,
    ) -> Result<Hash, &'static str> {
        if auth_path.is_empty() {
            return Err("No auth path");
        }
        if selected_leaves.len() != commitments.len() {
            return Err("The number of selected leaves and commitments should be of equal length");
        }

        // First, sort the selected leaves and the commitments
        let mut selected_leaves = selected_leaves.to_vec();
        selected_leaves.sort();

        let mut q: Queue<(Hash, usize)> = queue![];

        // Add the commitments to the queue but with the correct index in the tree
        for (i, selected_leaf) in selected_leaves.iter().enumerate() {
            let add = q.add((
                commitments[i],
                (1 << PARAM_MERKLE_TREE_HEIGHT) + *selected_leaf as usize,
            ));

            if add.is_err() {
                return Err("Could not add element to queue");
            }
        }

        let (mut height_index, mut last_index) =
            (1 << PARAM_MERKLE_TREE_HEIGHT, PARAM_MERKLE_TREE_NODES - 1);

        let mut _next_node: Hash = [0u8; PARAM_DIGEST_SIZE];

        // While the next element is not the root of the tree
        while q.peek().unwrap().1 != 1 {
            // Get the next element
            let (mut node, index) = q.remove().unwrap();

            // if the height is more than the index then divide the height and last_index by 2
            if index < height_index {
                height_index >>= 1;
                last_index >>= 1;
            }

            _next_node = [0u8; PARAM_DIGEST_SIZE];

            // Check if the current node is the left child of the parent
            let is_left_child = index % 2 == 0; // if the index is even then it is the left child

            if is_left_child && index == last_index {
                // If the node is isolated then add it to the queue
                let add = q.add((node, index >> 1));
                if add.is_err() {
                    return Err("Could not add element to queue");
                }
            } else {
                // Find the index of the next node
                let mut next_index = 0;
                let ok = q.peek();
                if ok.is_ok() {
                    next_index = ok.unwrap().1;
                }

                // Find out if the next node is the right child of the current node
                if is_left_child && next_index == index + 1 {
                    (_next_node, _) = q.remove().unwrap(); // Remove the next node from the queue
                } else {
                    if !auth_path.is_empty() {
                        // Extract and remove the first hash of the auth path
                        _next_node = auth_path.remove(0);
                    } else {
                        return Err("Auth path is too short");
                    }

                    // If the current node is the right child of the parent
                    if !is_left_child {
                        // swap the next node with the current node
                        std::mem::swap(&mut node, &mut _next_node);
                    }
                }

                let parent_index = index >> 1;

                // Generate the parent hash from current node and next node
                let parent = merkle_hash(
                    parent_index,
                    node,
                    if _next_node != [0_u8; PARAM_DIGEST_SIZE] {
                        Some(_next_node)
                    } else {
                        None
                    },
                    salt,
                );

                let add = q.add((parent, parent_index));
                if add.is_err() {
                    return Err("Could not add element to queue");
                }
            }
        }
        let (root, _) = q.remove().unwrap();

        Ok(root)
    }

    /// Gets the revealed nodes from the selected leaves in the tree. This is a bottom up approach to
    /// figuring out which nodes are needed to calculate the merkle root from the selected leaves.
    fn get_revealed_nodes(selected_leaves: &[u16]) -> Vec<u16> {
        if selected_leaves.is_empty() {
            return vec![];
        }

        // Initialize
        let mut revealed_nodes = vec![];
        let (mut height_index, mut last_index) =
            (1 << PARAM_MERKLE_TREE_HEIGHT, PARAM_MERKLE_TREE_NODES - 1);
        let mut q: Queue<usize> = queue![];

        // Add the commitments to the queue but with the correct index in the tree
        for selected_leaf in selected_leaves.iter() {
            let val = (1 << PARAM_MERKLE_TREE_HEIGHT) + *selected_leaf as usize;
            let add = q.add(val);

            if add.is_err() {
                panic!("Could not add element to queue");
            }
        }

        // While the next element is not the root of the tree
        while q.peek().unwrap() != 1 {
            // Get the first node from the queue
            let index = q.remove().unwrap();

            // if the height is more than the index then divide the height and last_index by 2
            if index < height_index {
                height_index >>= 1;
                last_index >>= 1;
            }

            // Check if the current node is the left child of the parent
            let is_left_child = index % 2 == 0; // if the index is even then it is the left child

            if is_left_child && index == last_index {
                // The node has no sibling node
            } else {
                // The node HAS a sibling node
                // Check if the queue is empty
                let queue_is_empty = q.peek().is_err();
                let mut candidate_index = 0;
                if !queue_is_empty {
                    candidate_index = q.peek().unwrap();
                }
                if is_left_child && (candidate_index == index + 1) {
                    // Remove the sibling node from the queue as we know it is not needed
                    q.remove().unwrap();
                } else if is_left_child {
                    // The sibling node is given in the authentication paths
                    revealed_nodes.push((index + 1) as u16);
                } else {
                    revealed_nodes.push((index - 1) as u16);
                }
            }
            let parent_index = index >> 1;
            let add = q.add(parent_index);
            if add.is_err() {
                panic!("Could not add element to queue");
            }
        }

        revealed_nodes
    }
}

/// Calculates the merkle hash from the left and right children and the parent index.
pub(self) fn merkle_hash(
    parent_index: usize,
    left: Hash,
    right: Option<Hash>,
    salt: Option<Salt>,
) -> Hash {
    let mut hasher = SDitHHash::init_with_prefix(&[HASH_PREFIX_MERKLE_TREE]);

    if let Some(salt) = salt {
        hasher.update(&salt);
    }

    // Hash the parent_index
    hasher.update(&(parent_index as u16).to_le_bytes());

    // Hash the left and right children
    hasher.update(&left);
    if let Some(right) = right {
        hasher.update(&right);
    }

    hasher.finalize()
}

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

#[cfg(test)]
mod test {
    use core::panic;

    use crate::{
        constants::{
            params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_N},
            types::hash_default,
        },
        subroutines::prg::PRG,
    };

    use super::*;

    fn setup_test_commitments() -> CommitmentsArray {
        let mut commitments = [[0_u8; PARAM_DIGEST_SIZE]; PARAM_N];
        for i in 0..PARAM_N {
            commitments[i] = [i as u8; PARAM_DIGEST_SIZE];
        }
        commitments
    }

    #[test]
    fn test_new_merkle_tree() {
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);
        assert_eq!(tree.height, PARAM_MERKLE_TREE_HEIGHT as u32);
        assert_eq!(tree.n_nodes, PARAM_MERKLE_TREE_NODES - 1);
        assert_eq!(tree.n_leaves, { PARAM_N });

        // First node is empty as the tree is not zero indexed
        assert_eq!(tree.nodes[0], hash_default());

        // Get the correct leaves.
        for i in 0..PARAM_N {
            assert_eq!(tree.leaf(i), commitments[i]);
        }

        assert_eq!(tree.nodes[256], commitments[0]);
        assert_eq!(tree.nodes.last(), Some(&commitments[255]));
        assert_eq!(tree.nodes.len(), PARAM_MERKLE_TREE_NODES);
        assert_eq!(tree.root(), tree.nodes[1]);

        // We are not zero index, so start from 1
        for i in 1..=255 {
            let left = tree.nodes[i * 2];
            let right = tree.nodes[i * 2 + 1];
            assert_eq!(tree.nodes[i], merkle_hash(i, left, Some(right), None));
        }
    }

    #[test]
    fn test_get_leaf() {
        let mut commitments = setup_test_commitments();
        for i in 1..=PARAM_N {
            commitments[i - 1] = [i as u8; PARAM_DIGEST_SIZE];
        }
        let tree = MerkleTree::new(commitments, None);

        for i in 0..PARAM_N {
            assert_eq!(tree.leaf(i), commitments[i]);
        }

        let result = std::panic::catch_unwind(|| tree.leaf(257));
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_zero_auth_path() {
        // When you have all leaves selected, you don't need any extra nodes to calculate the root. Therefore, if all leaves are selected, the auth path should be empty
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);

        let mut selected_leaves = [0u16; PARAM_N];
        for i in 0..PARAM_N {
            selected_leaves[i] = i as u16;
        }

        let auth = tree.auth_path(&selected_leaves);
        assert_eq!(auth.len(), 0);
        assert!(auth.is_empty());

        let auth = tree.auth_path(&[]);
        assert_eq!(auth.len(), 0);
        assert!(auth.is_empty());
    }

    #[test]
    fn test_merkle_one_selected_leaf() {
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.auth_path(&[1]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT);
        assert_eq!(
            auth,
            vec![
                tree.leaf(0),
                tree.nodes[129],
                tree.nodes[65],
                tree.nodes[33],
                tree.nodes[17],
                tree.nodes[9],
                tree.nodes[5],
                tree.nodes[3],
            ]
        );
    }

    #[test]
    fn test_merkle_two_selected_neighboring_leaves() {
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.auth_path(&[0, 1]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT - 1);
        assert_eq!(
            auth,
            vec![
                tree.nodes[129],
                tree.nodes[65],
                tree.nodes[33],
                tree.nodes[17],
                tree.nodes[9],
                tree.nodes[5],
                tree.nodes[3],
            ]
        );
    }

    #[test]
    fn test_merkle_two_selected_non_neighboring_leaves() {
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.auth_path(&[0, 255]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), (PARAM_MERKLE_TREE_HEIGHT - 1) * 2);
        assert_eq!(
            auth,
            vec![
                tree.leaf(1),
                tree.leaf(254),
                tree.nodes[129],
                tree.nodes[254],
                tree.nodes[65],
                tree.nodes[126],
                tree.nodes[33],
                tree.nodes[62],
                tree.nodes[17],
                tree.nodes[30],
                tree.nodes[9],
                tree.nodes[14],
                tree.nodes[5],
                tree.nodes[6],
            ]
        );

        let auth = tree.auth_path(&[1, 3]);
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT);
        assert_eq!(
            auth,
            vec![
                tree.leaf(0),
                tree.leaf(2),
                tree.nodes[65],
                tree.nodes[33],
                tree.nodes[17],
                tree.nodes[9],
                tree.nodes[5],
                tree.nodes[3],
            ]
        );
    }

    #[test]
    fn test_merkle_three_selected_leaves() {
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.auth_path(&[1, 2, 3]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT - 1);
        assert_eq!(
            auth,
            vec![
                tree.leaf(0),
                tree.nodes[65],
                tree.nodes[33],
                tree.nodes[17],
                tree.nodes[9],
                tree.nodes[5],
                tree.nodes[3],
            ]
        );
    }

    #[test]
    fn test_merkle_root_from_auth() {
        let mut commitments = setup_test_commitments();

        let mut prg = PRG::init_base(&[1]);
        (0..PARAM_N).for_each(|i| prg.sample_field_fq_non_zero(&mut commitments[i]));
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [1u16, 2u16, 235u16];
        for i in 0..2 {
            let _selected_leaves = &selected_leaves[..i + 1];

            // Get the commitments for the selected leaves
            let mut commitments_tau = vec![];
            for i in _selected_leaves {
                commitments_tau.push(commitments[*i as usize]);
            }

            // Get the auth path for the selected leaves
            let mut auth = tree.auth_path(_selected_leaves);

            // Get the merkle root from the auth path
            let Ok(root) = MerkleTree::get_root_from_auth_path(
                &mut auth,
                &commitments_tau,
                _selected_leaves,
                None,
            ) else {
                panic!("Could not get merkle root from auth")
            };

            assert_eq!(
                tree.root(),
                root,
                "Roots do not match for selected leaves {:?}",
                _selected_leaves
            );
        }
    }

    #[test]
    fn test_merkle_root_from_auth_wrong_commitments() {
        let mut commitments = setup_test_commitments();

        let mut prg = PRG::init_base(&[1]);
        (0..PARAM_N).for_each(|i| prg.sample_field_fq_non_zero(&mut commitments[i]));
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16, 235u16];
        let mut commitments_tau = [[1_u8; PARAM_DIGEST_SIZE]; PARAM_L];
        for i in selected_leaves {
            commitments_tau[(i - 233) as usize] = commitments[0];
        }

        let mut auth = tree.auth_path(&selected_leaves);
        let Ok(root) = MerkleTree::get_root_from_auth_path(
            &mut auth,
            &commitments_tau,
            &selected_leaves,
            None,
        ) else {
            panic!("Could not get merkle root from auth")
        };
        assert_ne!(tree.root(), root);
    }

    #[test]
    fn test_merkle_root_from_auth_remove_wrong() {
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16, 235u16];
        let commitments_tau = [[1_u8; PARAM_DIGEST_SIZE]; PARAM_L];
        let mut auth = tree.auth_path(&selected_leaves);
        auth.remove(0);
        let result = MerkleTree::get_root_from_auth_path(
            &mut auth,
            &commitments_tau,
            &selected_leaves,
            None,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Auth path is too short");
    }

    #[test]
    fn test_merkle_root_from_selected_leaves_too_short() {
        let commitments = setup_test_commitments();
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16];
        let commitments_tau = [[1_u8; PARAM_DIGEST_SIZE]; PARAM_L];
        let mut auth = tree.auth_path(&selected_leaves);
        auth.remove(0);
        let result = MerkleTree::get_root_from_auth_path(
            &mut auth,
            &commitments_tau,
            &selected_leaves,
            None,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "The number of selected leaves and commitments should be of equal length"
        );
    }

    #[test]
    fn test_merkle_root_from_auth_empty() {
        let commitments = setup_test_commitments();
        let _tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16];
        let commitments_tau = [[1_u8; PARAM_DIGEST_SIZE]; PARAM_L];
        let mut auth = vec![];

        let result = MerkleTree::get_root_from_auth_path(
            &mut auth,
            &commitments_tau,
            &selected_leaves,
            None,
        );
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No auth path");
    }

    #[test]
    fn test_edgecase_with_unsorted_selected_leaves() {
        let selected_leaves = [124, 245u16];

        let mut prg = PRG::init_base(&[1]);
        let mut commitments = setup_test_commitments();
        (0..PARAM_N).for_each(|i| {
            prg.sample_field_fq_non_zero(&mut commitments[i]);
        });

        let tree = MerkleTree::new(commitments, None);

        let mut commitments_tau = vec![];
        for i in &selected_leaves {
            commitments_tau.push(commitments[*i as usize]);
        }

        let mut auth = tree.auth_path(&selected_leaves);

        let result = MerkleTree::get_root_from_auth_path(
            &mut auth,
            &commitments_tau,
            &selected_leaves,
            None,
        );
        if result.is_err() {
            panic!("{}", result.unwrap_err());
        }

        assert_eq!(tree.root(), result.unwrap());
    }
}
