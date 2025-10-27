use commonware_cryptography::{
    Digestible, Hasher,
    ed25519::{PublicKey, Signature},
    sha256::{Digest, Sha256},
};
use commonware_codec::{
    Write, Read, EncodeSize, Error as CodecError,
    Encode, ReadExt, 
};

use bytes::{Buf, BufMut};

use fcn_common::mempool::MempoolTransaction;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub nonce: u64,
    pub instruction: Instruction,

    pub public_key: PublicKey,
    pub signature: Signature,
}

impl Write for Transaction {
    fn write(&self, buf: &mut impl BufMut) {
        self.nonce.write(buf);
        self.instruction.write(buf);
        self.public_key.write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        self.nonce.encode_size()
            + self.instruction.encode_size()
            + self.public_key.encode_size()
            + self.signature.encode_size()
    }
}

impl Read for Transaction {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let nonce = u64::read(buf)?;
        let instruction = Instruction::read(buf)?;
        let public_key = PublicKey::read(buf)?;
        let signature = Signature::read(buf)?;
        Ok(Self{
            nonce,
            instruction,
            public_key,
            signature,
        })
    }
}

impl MempoolTransaction for Transaction {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn nonce(&self) -> u64 {
        self.nonce
    }
}

impl Digestible for Transaction {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(self.nonce.to_be_bytes().as_ref());
        hasher.update(self.instruction.encode().as_ref());
        hasher.update(self.public_key.as_ref());
        // We don't include the signature as part of the digest (any valid
        // signature will be valid for the transaction)
        hasher.finalize()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    ProposeBlock(BlockProposal),
}

impl Write for Instruction {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Instruction::ProposeBlock(i) => {
                0u8.write(buf);
                i.write(buf);
            }
        }
    }
}

impl EncodeSize for Instruction {
    fn encode_size(&self) -> usize {
        1 + match self {
            Instruction::ProposeBlock(i) => i.encode_size()
        }
    }
}

impl Read for Instruction {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Instruction::ProposeBlock(BlockProposal::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockProposal {
    pub block_height: u64,
    pub parent_hash: Digest,
    pub block_hash: Digest,
}

impl Write for BlockProposal {
    fn write(&self, buf: &mut impl BufMut) {
        self.block_height.write(buf);
        self.parent_hash.write(buf);
        self.block_hash.write(buf);
    }
}

impl EncodeSize for BlockProposal {
    fn encode_size(&self) -> usize {
        self.block_height.encode_size()
            + self.parent_hash.encode_size()
            + self.block_hash.encode_size()
    }
}

impl Read for BlockProposal {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let height = u64::read_cfg(buf, &())?;
        let parent = Digest::read(buf)?;
        let hash = Digest::read(buf)?;
        Ok(Self{
            block_height: height,
            parent_hash: parent,
            block_hash: hash,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    FrameFinalized(Frame)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub frame_number: u64,
    pub chain_head: Digest,
}

impl Write for Frame {
    fn write(&self, buf: &mut impl BufMut) {
        self.frame_number.write(buf);
        self.chain_head.write(buf);
    }
}

impl EncodeSize for Frame {
    fn encode_size(&self) -> usize {
        self.frame_number.encode_size()
            + self.chain_head.encode_size()
    }
}

impl Read for Frame {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let frame = u64::read(buf)?;
        let head = Digest::read(buf)?;
        Ok(Self{
            frame_number: frame,
            chain_head: head,
        })
    }
}

#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct BuilderAccount {
    pub nonce: u64,
}