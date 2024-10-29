use std::{error::Error, fmt::Debug};

use num_traits::ToPrimitive;
use queues::Queue;
use tiny_keccak::Hasher;

use crate::constants::{
    params::{PARAM_DIGEST_SIZE, PARAM_L, PARAM_LOG_N, PARAM_N, PARAM_TAU},
    types::{CommitmentsArray, Hash, Salt},
};

use queues::*;

use super::prg::hashing::{hash_finalize, sha3};

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
        let nb_leaves = commitments.len();
        let height: i32 = nb_leaves
            .to_f32()
            .expect("could not convert to f32")
            .log2()
            .ceil() as i32;
        let mut tree = Self {
            height,
            n_nodes: (1 << (height)) + nb_leaves - 1,
            n_leaves: nb_leaves,
            nodes: [Hash::default(); PARAM_MERKLE_TREE_NODES],
        };

        let mut first_index = tree.n_nodes - nb_leaves + 1;
        let mut last_index = tree.n_nodes;

        // Add leaves to the tree
        (0..nb_leaves).for_each(|i| {
            tree.set_node(first_index + i, commitments[i]);
        }); // TODO: Optimize the loop below with batch processing https://github.com/sdith/sdith/blob/main/Optimized_Implementation/Threshold_Variant/sdith_threshold_cat1_gf256/merkle-tree.c

        for _h in (0..height).rev() {
            // Indicates if the last node is isolated
            let last_is_isolated = 1 - (last_index & 0x1);

            first_index >>= 1;
            last_index >>= 1;

            let mut parent_index = first_index;
            while parent_index <= last_index {
                // Calculate the indexes of the left and right children
                let left_child_index = 2 * parent_index;
                let right_child_index = 2 * parent_index + 1;

                // Finalize the hash and add it to the parent node
                tree.set_node(
                    parent_index,
                    merkle_hash(
                        parent_index as u16,
                        tree.get_node(left_child_index),
                        if last_is_isolated == 0 {
                            Some(tree.get_node(right_child_index))
                        } else {
                            None
                        },
                        salt,
                    ),
                );

                parent_index += 1;
            }
        }
        tree
    }

    /// Returns the root of the merkle tree
    pub(crate) fn get_root(&self) -> Hash {
        self.get_node(1)
    }

    pub(crate) fn get_leaf(&self, n: u16) -> Hash {
        assert!(n <= self.n_leaves as u16, "Invalid leaf index: {}", n);
        self.nodes[(self.n_leaves - 1 + (n as usize)).to_usize().unwrap()]
    }

    /// Return non-zero based index of the leaf in the tree
    fn get_leaf_index(&self, n: usize) -> u16 {
        assert!(
            n >= self.n_leaves && n <= self.n_nodes,
            "Invalid leaf index: {}",
            n
        );
        (n - (self.n_leaves - 1)).try_into().unwrap()
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
        let revealed_nodes = get_revealed_nodes(selected_leaves);

        let mut auth = vec![];

        // Fetch the missing nodes
        for h in (1..=self.height).rev() {
            for i in 1 << h..(1 << (h + 1)) {
                if revealed_nodes.contains(&i) {
                    auth.push(self.get_node(i as usize));
                }
            }
        }

        auth
    }
    /// Returns the node at the specified index
    pub(super) fn get_node(&self, index: usize) -> Hash {
        self.nodes[index - 1]
    }

    pub(super) fn set_node(&mut self, index: usize, hash: Hash) {
        self.nodes[index - 1] = hash;
    }
}

fn merkle_hash(parent_index: u16, left: Hash, right: Option<Hash>, salt: Option<Salt>) -> Hash {
    let mut hasher = sha3();

    // Hash the prefix
    hasher.update(&[HASH_PREFIX_MERKLE_TREE]);

    if let Some(salt) = salt {
        hasher.update(&salt);
    }

    // Hash the parent_index
    hasher.update(&parent_index.to_le_bytes());

    // Hash the left and right children
    hasher.update(&left);
    if let Some(right) = right {
        hasher.update(&right);
    }

    hash_finalize(hasher)
}

pub(crate) fn get_auth_size(selected_leaves: &[u16]) -> usize {
    let get_revealed_nodes = get_revealed_nodes(selected_leaves);
    get_revealed_nodes.len() * PARAM_DIGEST_SIZE
}

/// Gets the revealed nodes from the selected leaves in the tree. This is a bottom up approach to
/// figuring out which nodes are needed to calculate the merkle root from the selected leaves.
pub(crate) fn get_revealed_nodes(selected_leaves: &[u16]) -> Vec<u16> {
    if selected_leaves.is_empty() {
        return vec![];
    }

    let mut revealed_nodes = vec![];

    // Initialize
    let (mut height_index, mut last_index) =
        (1 << PARAM_MERKLE_TREE_HEIGHT, PARAM_MERKLE_TREE_NODES - 1);

    // We use "leaves" as a circular queue, so it destroys the input data.
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

/// Recalculates the merkle root from the commitments and the auth
pub(crate) fn get_merkle_root_from_auth(
    auth: &mut Vec<Hash>,
    commitments: &[Hash],
    selected_leaves: &[u16],
    salt: Option<Hash>,
) -> Result<Hash, &'static str> {
    if auth.is_empty() {
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

    let mut _next_node: Hash = Hash::default();

    // While the next element is not the root of the tree
    while q.peek().unwrap().1 != 1 {
        // Get the next element
        let (mut node, index) = q.remove().unwrap();

        // if the height is more than the index then divide the height and last_index by 2
        if index < height_index {
            height_index >>= 1;
            last_index >>= 1;
        }

        _next_node = Hash::default();

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
                if !auth.is_empty() {
                    // Extract and remove the first hash of the auth path
                    _next_node = auth.remove(0);
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
                parent_index as u16,
                node,
                if _next_node != [0_u8; 32] {
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

#[cfg(test)]
mod test {
    use core::panic;
    use std::panic::AssertUnwindSafe;

    use crate::{
        constants::params::{PARAM_L, PARAM_N},
        subroutines::{commitments, prg::prg::PRG},
    };

    use super::*;

    #[test]
    fn test_get_leaf() {
        let mut commitments = [[1_u8; 32]; PARAM_N];
        for i in 1..=PARAM_N {
            commitments[i - 1] = [i as u8; 32];
        }
        let tree = MerkleTree::new(commitments, None);

        for i in 1..=PARAM_N {
            assert_eq!(tree.get_leaf(i as u16), [i as u8; 32]);
        }

        let result = std::panic::catch_unwind(|| tree.get_leaf(257));
        assert!(result.is_err());
    }

    #[test]
    fn test_merkle_tree() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);
        assert_eq!(tree.height, PARAM_MERKLE_TREE_HEIGHT as i32);
        assert_eq!(tree.n_nodes, PARAM_MERKLE_TREE_NODES - 1);
        assert_eq!(tree.n_leaves, { PARAM_N });

        assert_eq!(tree.nodes[0], Hash::default());
        assert_eq!(
            tree.nodes[1],
            merkle_hash(1, tree.nodes[2], Some(tree.nodes[3]), None)
        );

        assert_eq!(tree.nodes[256], commitments[0]);
        assert_eq!(tree.nodes.last(), Some(&commitments[255]));
        assert_eq!(tree.nodes.len(), PARAM_MERKLE_TREE_NODES);

        // We are not zero index, so start from 1
        for i in 1..=255 {
            let left = tree.nodes[i * 2];
            let right = tree.nodes[i * 2 + 1];
            assert_eq!(
                tree.nodes[i],
                merkle_hash(i.try_into().unwrap(), left, Some(right), None)
            );
        }
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

        let auth = tree.get_merkle_path(&[1]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT);
        assert_eq!(
            auth,
            vec![
                tree.get_leaf(1),
                tree.get_node(129),
                tree.get_node(65),
                tree.get_node(33),
                tree.get_node(17),
                tree.get_node(9),
                tree.get_node(5),
                tree.get_node(3),
            ]
        );
    }

    #[test]
    fn test_merkle_two_selected_neighboring_leaves() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.get_merkle_path(&[0, 1]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT - 1);
        assert_eq!(
            auth,
            vec![
                tree.get_node(129),
                tree.get_node(65),
                tree.get_node(33),
                tree.get_node(17),
                tree.get_node(9),
                tree.get_node(5),
                tree.get_node(3),
            ]
        );
    }

    #[test]
    fn test_merkle_two_selected_non_neighboring_leaves() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.get_merkle_path(&[0, 255]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), (PARAM_MERKLE_TREE_HEIGHT - 1) * 2);
        assert_eq!(
            auth,
            vec![
                tree.nodes[257],
                tree.nodes[510],
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

        let auth = tree.get_merkle_path(&[1, 3]);
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT);
        assert_eq!(
            auth,
            vec![
                tree.nodes[257],
                tree.nodes[259],
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
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let auth = tree.get_merkle_path(&[1, 2, 3]);

        // The auth path should have 7 nodes (one from each level)
        assert_eq!(auth.len(), PARAM_MERKLE_TREE_HEIGHT - 1);
        assert_eq!(
            auth,
            vec![
                tree.nodes[259],
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
        let mut commitments = [[1_u8; 32]; PARAM_N];

        let mut prg = PRG::init_base(&[1]);
        for i in 0..PARAM_N {
            prg.sample_field_fq_non_zero(&mut commitments[i])
        }
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [1u16, 2u16, 235u16];
        for i in 0..2 {
            let _selected_leaves = &selected_leaves.clone()[..i + 1];

            // Get the commitments for the selected leaves
            let mut commitments_tau = vec![];
            for i in _selected_leaves {
                commitments_tau.push(commitments[*i as usize]);
            }

            // Get the auth path for the selected leaves
            let mut auth = tree.get_merkle_path(&_selected_leaves);

            // Get the merkle root from the auth path
            let Ok(root) =
                get_merkle_root_from_auth(&mut auth, &commitments_tau, &_selected_leaves, None)
            else {
                panic!("Could not get merkle root from auth")
            };

            assert_eq!(
                tree.get_root(),
                root,
                "Roots do not match for selected leaves {:?}",
                _selected_leaves
            );
        }
    }

    #[test]
    fn test_merkle_root_from_auth_wrong_commitments() {
        let mut commitments = [[1_u8; 32]; PARAM_N];

        let mut prg = PRG::init_base(&[1]);
        for i in 0..PARAM_N {
            prg.sample_field_fq_non_zero(&mut commitments[i])
        }
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16, 235u16];
        let mut commitments_tau = [[1_u8; 32]; PARAM_L];
        for i in selected_leaves {
            commitments_tau[(i - 233) as usize] = commitments[0];
        }

        let mut auth = tree.get_merkle_path(&selected_leaves);
        let Ok(root) =
            get_merkle_root_from_auth(&mut auth, &commitments_tau, &selected_leaves, None)
        else {
            panic!("Could not get merkle root from auth")
        };
        assert_ne!(tree.get_root(), root);
    }

    #[test]
    fn test_merkle_root_from_auth_remove_wrong() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16, 235u16];
        let commitments_tau = [[1_u8; 32]; PARAM_L];
        let mut auth = tree.get_merkle_path(&selected_leaves);
        auth.remove(0);
        let result = get_merkle_root_from_auth(&mut auth, &commitments_tau, &selected_leaves, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Auth path is too short");
    }

    #[test]
    fn test_merkle_root_from_selected_leaves_too_short() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16];
        let commitments_tau = [[1_u8; 32]; PARAM_L];
        let mut auth = tree.get_merkle_path(&selected_leaves);
        auth.remove(0);
        let result = get_merkle_root_from_auth(&mut auth, &commitments_tau, &selected_leaves, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "The number of selected leaves and commitments should be of equal length"
        );
    }

    #[test]
    fn test_merkle_root_from_auth_empty() {
        let commitments = [[1_u8; 32]; PARAM_N];
        let _tree = MerkleTree::new(commitments, None);

        let selected_leaves = [233u16, 234u16];
        let commitments_tau = [[1_u8; 32]; PARAM_L];
        let mut auth = vec![];

        let result = get_merkle_root_from_auth(&mut auth, &commitments_tau, &selected_leaves, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No auth path");
    }

    #[test]
    fn test_edgecase_with_unsorted_selected_leaves() {
        let selected_leaves = [124, 245u16];

        let mut prg = PRG::init_base(&[1]);
        let mut commitments = [[1_u8; 32]; PARAM_N];
        for i in 0..PARAM_N {
            prg.sample_field_fq_non_zero(&mut commitments[i]);
        }

        let tree = MerkleTree::new(commitments, None);

        let mut commitments_tau = vec![];
        for i in &selected_leaves {
            commitments_tau.push(commitments[*i as usize]);
        }

        let mut auth = tree.get_merkle_path(&selected_leaves);

        let result = get_merkle_root_from_auth(&mut auth, &commitments_tau, &selected_leaves, None);
        if result.is_err() {
            panic!("{}", result.unwrap_err());
        }

        assert_eq!(tree.get_root(), result.unwrap());
    }

    #[test]
    fn test_get_leaf_index() {
        let mut commitments = [[0_u8; 32]; PARAM_N];
        for i in 1..=PARAM_N {
            commitments[i - 1] = [i as u8; 32];
        }
        let tree = MerkleTree::new(commitments, None);

        assert_eq!(tree.get_leaf_index(256), 1);
        assert_eq!(tree.get_leaf_index(379), 124);
        assert_eq!(tree.get_leaf_index(tree.n_nodes), 256);
    }
}
