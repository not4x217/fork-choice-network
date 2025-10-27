use std::collections::{BTreeMap, HashMap, VecDeque};

use commonware_cryptography::{ed25519::PublicKey, Digestible};
use commonware_runtime::Metrics;

use prometheus_client::metrics::gauge::Gauge;

/// The maximum number of transactions a single account can have in the mempool.
const MAX_BACKLOG: usize = 16;

/// The maximum number of transactions in the mempool.
const MAX_TRANSACTIONS: usize = 32_768;

pub trait MempoolTransaction : Digestible {
    fn public_key(&self) -> PublicKey;
    fn nonce(&self) -> u64;
}

/// A mempool for transactions.
pub struct Mempool<T: MempoolTransaction> {
    transactions: HashMap<T::Digest, T>,
    tracked: HashMap<PublicKey, BTreeMap<u64, T::Digest>>,
    /// We store the public keys of the transactions to be processed next (rather than transactions
    /// received by digest) because we may receive transactions out-of-order (and/or some may have
    /// already been processed) and should just try return the transaction with the lowest nonce we
    /// are currently tracking.
    queue: VecDeque<PublicKey>,

    unique: Gauge,
    accounts: Gauge,
}

impl <T: MempoolTransaction> Mempool<T> {
    /// Create a new mempool.
    pub fn new(context: impl Metrics) -> Self {
        // Initialize metrics
        let unique = Gauge::default();
        let accounts = Gauge::default();
        context.register(
            "transactions",
            "Number of transactions in the mempool",
            unique.clone(),
        );
        context.register(
            "accounts",
            "Number of accounts in the mempool",
            accounts.clone(),
        );

        // Initialize mempool
        Self {
            transactions: HashMap::new(),
            tracked: HashMap::new(),
            queue: VecDeque::new(),

            unique,
            accounts,
        }
    }

    /// Add a transaction to the mempool.
    pub fn add(&mut self, tx: T) {
        // If there are too many transactions, ignore
        if self.transactions.len() >= MAX_TRANSACTIONS {
            return;
        }

        // Determine if duplicate
        let digest = tx.digest();
        if self.transactions.contains_key(&digest) {
            // If we already have a transaction with this digest, we don't need to track it
            return;
        }

        // Track the transaction
        let public = tx.public_key();
        let entry = self.tracked.entry(public.clone()).or_default();

        // If there already exists a transaction at some nonce, return
        if entry.contains_key(&tx.nonce()) {
            return;
        }

        // Insert the transaction into the mempool
        assert!(entry.insert(tx.nonce(), digest).is_none());
        self.transactions.insert(digest, tx);

        // If there are too many transactions, remove the furthest in the future
        let entries = entry.len();
        if entries > MAX_BACKLOG {
            let (_, future) = entry.pop_last().unwrap();
            self.transactions.remove(&future);
        }

        // Add to queue if this is the first entry (otherwise the public key will already be
        // in the queue)
        if entries == 1 {
            self.queue.push_back(public);
        }

        // Update metrics
        self.unique.set(self.transactions.len() as i64);
        self.accounts.set(self.tracked.len() as i64);
    }

    /// Retain transactions for a given account with a minimum nonce.
    pub fn retain(&mut self, public: &PublicKey, min: u64) {
        // Remove any items no longer present
        let Some(tracked) = self.tracked.get_mut(public) else {
            return;
        };
        let remove = loop {
            let Some((nonce, digest)) = tracked.first_key_value() else {
                break true;
            };
            if nonce >= &min {
                break false;
            }
            self.transactions.remove(digest);
            tracked.pop_first();
        };

        // If we removed a transaction, remove the address from the tracked map
        if remove {
            self.tracked.remove(public);
        }

        // Update metrics
        self.unique.set(self.transactions.len() as i64);
        self.accounts.set(self.tracked.len() as i64);
    }

    /// Get the next transaction to process from the mempool.
    pub fn next(&mut self) -> Option<T> {
        let tx = loop {
            // Get the transaction with the lowest nonce
            let address = self.queue.pop_front()?;
            let Some(tracked) = self.tracked.get_mut(&address) else {
                // We don't prune the queue when we drop a transaction, so we may need to
                // read through some untracked addresses.
                continue;
            };
            let Some((_, digest)) = tracked.pop_first() else {
                continue;
            };

            // If the address still has transactions, add it to the end of the queue (to
            // ensure everyone gets a chance to process their transactions)
            if !tracked.is_empty() {
                self.queue.push_back(address);
            } else {
                // If the address has no transactions, remove it from the tracked map
                self.tracked.remove(&address);
            }

            // Remove the transaction from the mempool
            let tx = self.transactions.remove(&digest).unwrap();
            break Some(tx);
        };

        // Update metrics
        self.unique.set(self.transactions.len() as i64);
        self.accounts.set(self.tracked.len() as i64);

        tx
    }
}