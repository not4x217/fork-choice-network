use std::collections::{HashMap, BTreeMap};

use commonware_cryptography::{
    sha256::Digest,
    ed25519::PublicKey
};

use fcn_common::fork_choice_tree::ForkChoiceTree;

use crate::types::{BuilderAccount, Event, Frame, Instruction, Transaction};

pub struct State {
    pub builders: HashMap<PublicKey, BuilderAccount>,
    pub fork_tree: ForkChoiceTree,
    
    pub finalize_frame_block_proposal_min: u64,
    pub frame_block_proposal_count: u64,
}

impl State {
    pub fn new(genesis_block_hash: Digest, finalize_frame_block_proposal_min: u64) -> Self {
        Self {
            builders: HashMap::new(),
            fork_tree: ForkChoiceTree::new(genesis_block_hash),

            finalize_frame_block_proposal_min,
            frame_block_proposal_count: 0,
        }
    }
}

pub struct StateTransitionResult {
    pub processed_nonces: BTreeMap<PublicKey, u64>,
    pub invalid_txs: Vec<Transaction>,
    pub generated_events: Vec<Event>,
}

pub fn execute_state_transition( 
    state: &mut State,
    txs: Vec<Transaction>
) -> StateTransitionResult {
    let mut processed_nonces = BTreeMap::new();
    let mut invalid_txs = Vec::new();
    let mut generated_events = Vec::new();

    let mut valid_txs = Vec::new();
    for tx in txs {
        // Must be applied in order to ensure blocks with multiple transactions from same
        // account are handled properly.
        let sender = if let Some(account) = prepare_sender_account(state, &tx) {
            account
        } else {
            invalid_txs.push(tx);
            continue;
        };

        // Execute transaction
        if let Some(events) = apply_transaction(state, &tx) {
            generated_events.extend(events);
        } else {
            invalid_txs.push(tx);
            continue;
        };

        // Track the next nonce for this public key in case of valid transaction
        processed_nonces.insert(tx.public_key.clone(), tx.nonce.saturating_add(1));
        valid_txs.push(tx);
    }

    StateTransitionResult { 
        processed_nonces,
        invalid_txs,
        generated_events,
    }
}

fn prepare_sender_account(state: &mut State, tx: &Transaction) -> Option<BuilderAccount> {
    // Get account
    let mut account = if let Some(account) =
        state.builders.get(&tx.public_key)
    {
        account.clone()
    } else {
        return None;
    };

    // Ensure nonce is correct
    if account.nonce != tx.nonce {
        return None;
    }

    // Increment nonce
    account.nonce += 1;
    state.builders.insert(tx.public_key.clone(),account.clone());

    Some(account)
}

fn apply_transaction(
    state: &mut State,
    tx: &Transaction
) -> Option<Vec<Event>> {
    let mut events = Vec::<Event>::new();
    
    match &tx.instruction {
        Instruction::ProposeBlock(proposal) => {
            if let Ok(()) = state.fork_tree.propose_block(proposal.block_height, proposal.parent_hash, proposal.block_hash) {
                state.frame_block_proposal_count += 1;
            } else {
                return None
            }
        }
    }

    // Finalize frame max number of ProposeBlock txs has been received
    if state.frame_block_proposal_count >= state.finalize_frame_block_proposal_min {
        match state.fork_tree.finalize_block_frame() {
            Ok((frame_number, chain_head)) => {
                events.push(Event::FrameFinalized(Frame{
                    frame_number: frame_number,
                    chain_head: chain_head,
                }));
                state.frame_block_proposal_count = 0;
            },
            Err(err) => {
                todo!()
            },
        }
    }

    Some(events)
}