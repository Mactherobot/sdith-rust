use super::MerkleTreeTrait;
use crate::{constants::types::Hash, subroutines::merkle_tree::merkle_hash};
use std::rc::{Rc, Weak};

struct MerkleTreeNode {
    node_type: MerkleTreeNodeType,
    hash: Hash, // Adjust the type of hash as needed
    parent: Option<Weak<MerkleTreeNode>>,
    sibling: Option<Weak<MerkleTreeNode>>,
}

struct NodeBasedMerkleTree {
    pub root: MerkleTreeNode,
    pub leaves: Vec<Rc<MerkleTreeNode>>,
}

enum MerkleTreeNodeType {
    Leaf,
    Left,
    Right,
    Root,
}

impl MerkleTreeTrait for NodeBasedMerkleTree {
    fn new(commitments: crate::constants::types::CommitmentsArray, salt: Option<Hash>) -> Self {
        // Loop over the commitments and create the nodes

        let mut leaves: Vec<[Rc<MerkleTreeNode>; 2]> = commitments
            .chunks_exact(2)
            .map(|commitment| {
                let left_node = Rc::new(MerkleTreeNode {
                    node_type: MerkleTreeNodeType::Leaf,
                    hash: commitment[0],
                    parent: None,
                    sibling: None, // Placeholder for now
                });

                let right_node = Rc::new(MerkleTreeNode {
                    node_type: MerkleTreeNodeType::Leaf,
                    hash: commitment[1],
                    parent: None,
                    sibling: Some(Rc::downgrade(&left_node)), // Weak reference to left_node
                });

                // Update left_node's sibling to reference right_node
                if let Some(left_node_mut) = Rc::get_mut(&mut Rc::clone(&left_node)) {
                    left_node_mut.sibling = Some(Rc::downgrade(&right_node));
                }

                [left_node, right_node]
            })
            .collect();

        let mut parent_index = commitments.len();
        let mut root: Option<MerkleTreeNode> = None;
        let mut parents = leaves.clone();
        while root.is_none() {
            if (parents.len() > 1) {
                parents = parents
                    .chunks_exact(2)
                    .map(|node_pairs| {
                        let left = &node_pairs[0];
                        let right = &node_pairs[1];

                        let left_parent = Rc::new(MerkleTreeNode {
                            node_type: MerkleTreeNodeType::Left,
                            hash: merkle_hash(parent_index, left[0].hash, Some(left[1].hash), salt),
                            parent: None,
                            sibling: None,
                        });
                        let right_parent = Rc::new(MerkleTreeNode {
                            node_type: MerkleTreeNodeType::Right,
                            hash: merkle_hash(
                                parent_index + 1,
                                right[0].hash,
                                Some(right[1].hash),
                                salt,
                            ),
                            parent: None,
                            sibling: Some(Rc::downgrade(&left_parent)),
                        });

                        parent_index += 2;

                        // Update left_node's sibling to reference right_node
                        if let Some(left_parent_mut) = Rc::get_mut(&mut Rc::clone(&left_parent)) {
                            left_parent_mut.sibling = Some(Rc::downgrade(&right_parent));
                        }

                        return [left_parent, right_parent];
                    })
                    .collect();
            } else {
                // Calculate the root
                let left = &leaves[0];
                let right = &leaves[1];

                root = Some(MerkleTreeNode {
                    node_type: MerkleTreeNodeType::Root,
                    hash: merkle_hash(0, left[0].hash, Some(right[0].hash), salt),
                    parent: None,
                    sibling: None,
                });
            }
        }

        NodeBasedMerkleTree {
            root: root.expect("Root node is None"),
            leaves: leaves.into_iter().flatten().collect(),
        }
    }

    fn root(&self) -> Hash {
        self.root.hash
    }

    fn leaf(&self, index: usize) -> Hash {
        self.leaves[index].hash
    }

    fn auth_path(&self, selected_leaves: &[u16]) -> Vec<Hash> {
        let mut auth_path: Vec<Hash> = vec![];

        selected_leaves.iter().for_each(|selected_leaf| {
          let selected_leaf = &self.leaves[*selected_leaf as usize];
          auth_path.push(selected_leaf.hash);

          
        });


        auth_path
    }

    fn get_auth_size(selected_leaves: &[u16]) -> usize {
        todo!()
    }

    fn n_leaves(&self) -> usize {
        todo!()
    }

    fn n_nodes(&self) -> usize {
        todo!()
    }

    fn height(&self) -> u32 {
        todo!()
    }
}
