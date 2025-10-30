use std::{
    collections::BTreeMap,
};

use commonware_codec::Encode;
use commonware_cryptography::{
    ed25519::PublicKey,
    sha256::{Digest, Sha256},
    Hasher,
};
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    mmr::hasher::Standard,
    translator::Translator,
    adb::any::variable::Any
};

use crate::types::{
    Account, CommitMetadata, 
    Transaction, Instruction, TransferBread,
    Key, Value,
};


#[derive(Clone)]
pub enum StateOperation {
    Update(Value),
    Delete,
}

pub struct State<E, T>
where
    E: Spawner + Metrics + Clock + Storage,
    T: Translator,
{
    adb: Any<E, Digest, Value, Sha256, T>,
}

impl<E, T> State<E, T>
where
    E: Spawner + Metrics + Clock + Storage,
    T: Translator,
{
    pub async fn get(&self, key: &Key) -> Option<Value> {
        let key = Sha256::hash(&key.encode());
        self.adb.get(&key).await.unwrap()
    }

    pub async fn apply(
        &mut self, changes: Vec<(Key, StateOperation)>,
        commit_meta: CommitMetadata
    ) {
        for (key, op) in changes {
            match op {
                StateOperation::Update(value) => self.insert(key, value).await,
                StateOperation::Delete => self.delete(&key).await,
            }
        }
        self.adb.commit(Some(Value::CommitMetadata(commit_meta)))
            .await
            .unwrap();
    }

    async fn insert(&mut self, key: Key, value: Value) {
        let key = Sha256::hash(&key.encode());
        self.adb.update(key, value).await.unwrap();
    }

    async fn delete(&mut self, key: &Key) {
        let key = Sha256::hash(&key.encode());
        self.adb.delete(key).await.unwrap();
    }

    pub fn operation_count(&self) -> u64 {
        self.adb.op_count()
    }
    
    pub async fn commit_metadata(&self) -> CommitMetadata {
        let (state_height, state_start_op) = self.adb
            .get_metadata()
            .await
            .unwrap()
            .and_then(|(_, v)| match v {
                Some(Value::CommitMetadata(v)) => Some((v.height, v.start)),
                _ => None,
            })
            .unwrap_or((0, 0));
        CommitMetadata{
            height: state_height,
            start: state_start_op,
        }
    }

    pub fn root(&self, hasher: &mut Standard<Sha256>) ->  Digest{
        self.adb.root(hasher)
    }
}

pub struct StateTransitionResult {
    pub state_root: Digest,
    pub state_start_op: u64,
    pub state_end_op: u64,
    pub processed_nonces: BTreeMap<PublicKey, u64>,
    pub invalid_txs: Vec<Transaction>,
}

pub async fn execute_state_transition<E, T>( 
    state: &mut State<E, T>,
    txs: Vec<Transaction>,
    height: u64,
) -> StateTransitionResult
where 
    E: Spawner + Metrics + Clock + Storage,
    T: Translator,
{
    let state_commit = state.commit_metadata().await;
    assert!(
        height == state_commit.height || height == state_commit.height + 1,
        "state transition must be for next block or tip"
    );

    let mut state_start_op = state_commit.start;
    let mut processed_nonces = BTreeMap::new();
    let mut invalid_txs = Vec::new();
    
    // Only process if this is the next block
    if height == state_commit.height + 1 {
        state_start_op = state.operation_count();
        let mut layer = StateLayer::new(state);
        (processed_nonces, invalid_txs) = layer.execute(txs).await;
        state.apply(
            layer.commit(), 
            CommitMetadata { height, start: state_start_op }
        ).await;
    }

    // Compute roots
    let mut mmr_hasher = Standard::<Sha256>::new();
    let state_root = state.root(&mut mmr_hasher);
    let state_end_op = state.operation_count();

    StateTransitionResult{
        state_root,
        state_start_op,
        state_end_op,
        processed_nonces,
        invalid_txs,
    }
}

pub struct StateLayer<'a, E, T>
where
    E: Spawner + Metrics + Clock + Storage,
    T: Translator
{
    state: &'a State<E, T>,
    pending: BTreeMap<Key, StateOperation>,
}

impl<'a, E, T> StateLayer<'a, E, T>
where
    E: Spawner + Metrics + Clock + Storage,
    T: Translator,
{
    pub fn new(state: &'a State<E, T>) -> Self {
        Self {
            state,
            pending: BTreeMap::new(),
        }
    }

    pub fn commit(self) -> Vec<(Key, StateOperation)> {
        self.pending.into_iter().collect()
    }

    pub async fn execute(
        &mut self,
        txs: Vec<Transaction>
    ) -> (BTreeMap<PublicKey, u64>, Vec<Transaction>) {
        let mut processed_nonces = BTreeMap::new();
        let mut invalid_txs = Vec::new();
    
        for tx in txs {
            // Must be applied in order to ensure blocks with multiple transactions from same
            // account are handled properly.
            let sender= if let Some(account) = self.prepare_sender_account(&tx).await {
                account
            } else {
                invalid_txs.push(tx);
                continue;
            };

            // Execute transaction
            let valid_tx = match tx.instruction.clone() {
                Instruction::TransferBread(i) => 
                    self.apply_transfer_bread(tx.public_key.clone(), &sender, &i).await,
            };
            if !valid_tx {
                invalid_txs.push(tx);
                continue;
            }

            // Track the next nonce for this public key in case of valid transaction
            processed_nonces.insert(tx.public_key, tx.nonce.saturating_add(1));
        }

        (processed_nonces, invalid_txs)
    }

    async fn prepare_sender_account(&mut self, tx: &Transaction) -> Option<Account> {
        // Get account
        let mut account = if let Some(Value::Account(account)) =
            self.get(&Key::Account(tx.public_key.clone())).await
        {
            account
        } else {
           return None
        };

        // Ensure nonce is correct
        if account.nonce != tx.nonce {
            return None;
        }
        // Increment nonce
        account.nonce += 1;
        
        Some(account)
    }

    async fn apply_transfer_bread(
        &mut self, 
        sender_pk: PublicKey,
        sender: &Account,
        tx: &TransferBread
    ) -> bool {
        // Check sender balance
        if sender.bread < tx.amount {
            return false
        }

        // Create receiver acccount if necessary
        let mut receiver = if let Some(Value::Account(account)) =
            self.get(&Key::Account(tx.to.clone())).await
        {
            account
        } else {
            Account::default()
        };

        // Update sender balance
        let mut tx_sender = sender.clone();
        tx_sender.bread -= tx.amount;
        self.insert(Key::Account(sender_pk), Value::Account(tx_sender));

        // Update receiver balance
        receiver.bread += tx.amount;
        self.insert(Key::Account(tx.to.clone()), Value::Account(receiver));
    
        true
    }

    fn insert(&mut self, key: Key, value: Value) {
        self.pending.insert(key, StateOperation::Update(value));
    }

    fn delete(&mut self, key: Key) {
        self.pending.insert(key, StateOperation::Delete);
    }

    async fn get(&self, key: &Key) -> Option<Value> {
        match self.pending.get(key) {
            Some(StateOperation::Update(value)) => Some(value.clone()),
            Some(StateOperation::Delete) => None,
            None => self.state.get(key).await,
        }
    }

}