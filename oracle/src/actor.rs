use std::time::Duration;

use commonware_codec::Decode;
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey}, sha256::Digest, Signer
};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use commonware_p2p::{Sender, Receiver, Recipients};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_macros::select;

use rand::{CryptoRng, Rng};
use governor::clock::Clock as GClock;

use fcn_common::mempool::Mempool;
use crate::{
    execution::{State,  execute_state_transition},
    types::{Transaction, Event},
    wire::MessageEvent,
};

pub struct Config {    
    pub genesis_block_hash: Digest,

    pub block_period: Duration,
    pub finalize_frame_block_prosposal_min: u64,

    pub event_signer: PrivateKey,
}

pub struct Actor<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
> {
    context: E,

    buffer: buffered::Engine<E, PublicKey, MessageEvent>,
    buffer_mailbox: buffered::Mailbox<PublicKey, MessageEvent>,
    
    block_period: Duration,
    mempool: Mempool<Transaction>,
    
    state: State,
    block_number: u64,
}

impl<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
>Actor<E> {
    pub async fn new(context: E, config: Config) -> Self {
        let (buffer, buffer_mailbox) = buffered::Engine::new(
            context.with_label("buffer"),
            buffered::Config{
                public_key: config.event_signer.public_key(),
                mailbox_size: 1024,
                deque_size: 1024,
                priority: false,
                codec_config: (),
            }
        );
        
        let mempool = Mempool::<Transaction>::new(context.with_label("mempool"));
        
        let state = State::new(
            config.genesis_block_hash,
            config.finalize_frame_block_prosposal_min
        );
        
        Self {
            context,

            buffer,
            buffer_mailbox,
            
            block_period: config.block_period,
            mempool,

            state,
            block_number: 0,
        }
    }

    pub fn start(
        mut self,
        tx_receiver: impl Receiver<PublicKey = PublicKey>,
        event_network: (
            impl Receiver<PublicKey = PublicKey>,
            impl Sender<PublicKey = PublicKey>,
        )
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(tx_receiver))
    }

    async fn run(
        mut self,
        mut tx_receiver: impl Receiver<PublicKey = PublicKey>,
    ) {
        loop {
            select! {
                result = tx_receiver.recv() => {
                    match result {
                        Ok((_, msg)) => {
                            match Transaction::decode_cfg(msg, &()) {
                                Ok(tx) => self.mempool.add(tx),
                                Err(err) => {
                                    todo!();
                                    continue
                                }
                            };
                        },
                        Err(err) => {
                            todo!()
                        },
                    }
                },
                
                _ = self.context.sleep(self.block_period) => {
                    self.mint_block().await;
                }
            }
        }
    }

    async fn mint_block(&mut self) {
        // Get all pending transaction from mempool and execute them
        let mut txs = Vec::<Transaction>::new();
        while let Some(tx) = self.mempool.next() {
            txs.push(tx);
        }
        let result = execute_state_transition(&mut self.state, txs);
        self.block_number += 1;
        
        // Signal new block and finalized frame
        _ =self.buffer_mailbox.broadcast(
            Recipients::All,
            MessageEvent::BlockMinted(self.block_number),
        ).await;
        
        for event in result.generated_events {
            if let Event::FrameFinalized(frame) = event {
                _ = self.buffer_mailbox.broadcast(
                    Recipients::All,
                    MessageEvent::FrameFinalized(frame),
                ).await;
            }
        }

        // Clear mempool
        for (public, next_nonce) in &result.processed_nonces {
            self.mempool.retain(public, *next_nonce);
        }
    }
}