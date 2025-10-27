use std::collections::HashMap;

use commonware_cryptography::sha256::Digest;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ForkChoiceTreeError {
    #[error("invalid block parent hash")]
    InvalidBlockParentHash(Digest),
    #[error("invalid block parent height")]
    InvalidBlockHeight(u64),
    #[error("failed to solve fork")]
    UnsolvableFork(Digest),
}

pub struct ForkChoiceTree {
    nodes: HashMap<Digest, ForkChoiceTreeNode>,

    finalized_frame: u64,
    finalized_head: Digest,
}

impl ForkChoiceTree {
    pub fn new(genesis_block_hash: Digest) -> Self {
        let root = ForkChoiceTreeNode {
            block_frame: 0,
            block_height: 0,
            block_parent: [0; 32].into(),
            block_hash: genesis_block_hash,

            score: 0,
            children: Vec::new(),
        };

        let mut nodes = HashMap::<Digest, ForkChoiceTreeNode>::new();
        nodes.insert(genesis_block_hash, root);

        Self {
            nodes,

            finalized_frame: 1,
            finalized_head: genesis_block_hash,
        }
    }
    
    pub fn propose_block(&mut self, height: u64, parent: Digest, hash: Digest) -> Result<(), ForkChoiceTreeError> {
        if !self.nodes.contains_key(&hash) {
            self.create_node(height, parent, hash)
        } else {
            self.increment_node_score(hash);
            Ok(())
        }
    }

    fn create_node(&mut self, block_height: u64, block_parent: Digest, block_hash: Digest) -> Result<(), ForkChoiceTreeError> {
        // Check parent
        let parent = if let Some(parent) = self.nodes.get_mut(&block_parent) {
            parent
        } else {
            return Err(ForkChoiceTreeError::InvalidBlockParentHash(block_parent))
        };

        // Check parent height
        if block_height != parent.block_height + 1 {
            return Err(ForkChoiceTreeError::InvalidBlockHeight(block_height))
        };
        
        // Add node to tree
        parent.children.push(block_hash);
        let node = ForkChoiceTreeNode{
            block_frame: self.finalized_frame + 1,
            block_height: block_height,
            block_parent: block_parent,
            block_hash: block_hash,

            score: 0,
            children: Vec::new(),
        };
        self.nodes.insert(block_hash, node);
        self.increment_node_score(block_hash);

        Ok(())
    }

    fn increment_node_score(&mut self, block_hash: Digest) {
        let finalized_frame = self.finalized_frame;

        // Increment parent score until finalized frame is reached
        let mut current_block_hash = block_hash;
        loop {
            let node = self.node_mut(current_block_hash);
            if node.block_frame == finalized_frame {
                break;
            }
            node.score = node.score + 1;
            current_block_hash = node.block_parent;
        }
    }

    pub fn finalize_block_frame(&mut self) -> Result<(u64, Digest), ForkChoiceTreeError> {
        let mut current_block_hash = self.finalized_head;
        loop {
            // All forks are solved and leaf node is reached
            let node = &self.node(current_block_hash);
            if node.is_leaf() {
                self.finalized_frame += 1;
                self.finalized_head = current_block_hash;
                return Ok((self.finalized_frame, self.finalized_head));
            }

            // No fork at current node
            if node.children.len() == 1 {
                current_block_hash = node.children[0];
                continue;
            }

            let children = node.children.iter()
                .map(|block_hash| self.node(*block_hash))
                .collect::<Vec::<_>>();
            
            // Find "heaviest subtree" 
            let heaviest_subtree_rrot = children.iter()
                .max_by(|node_a, node_b| {
                    let score_a = node_a.score;
                    let score_b = node_b.score;
                    score_a.partial_cmp(&score_b).expect("failed to compare subtree scores")
                })
                .expect("tyring to solve fork for leaf node");
            
            // Check if fork is solvable (no other subtree doesn't have the same score as heaviest subtree)
            if children.iter()
                .filter(|child| child.score == heaviest_subtree_rrot.score)
                .count() > 1 {
                return Err(ForkChoiceTreeError::UnsolvableFork(current_block_hash))
            }

            current_block_hash = heaviest_subtree_rrot.block_hash;
        }
    }

    fn node(&self, block_hash: Digest) -> &ForkChoiceTreeNode {
        self.nodes.get(&block_hash).expect("node not found")
    }

    fn node_mut(&mut self, block_hash: Digest) -> &mut ForkChoiceTreeNode {
        self.nodes.get_mut(&block_hash).expect("node not found")
    }
}

struct ForkChoiceTreeNode {
    pub block_frame: u64,
    pub block_height: u64,
    pub block_parent: Digest,
    pub block_hash: Digest,
    
    pub score: u64,
    pub children: Vec<Digest>,
}

impl ForkChoiceTreeNode {
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }
}