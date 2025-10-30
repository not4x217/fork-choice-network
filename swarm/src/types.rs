use commonware_cryptography::{
    Digestible, Hasher,
    Committable,
    ed25519::{PublicKey, Signature},
    sha256::{Digest, Sha256},
};
use commonware_codec::{
    Write, Read, EncodeSize, Error as CodecError,
    Encode, ReadExt, RangeCfg,
    varint::UInt,
};

use bytes::{Buf, BufMut};

use fcn_common::mempool::MempoolTransaction;

pub const MAX_BLOCK_TRANSACTIONS: usize = 10;

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
    TransferBread(TransferBread),
}

impl Write for Instruction {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Instruction::TransferBread(i) => {
                0u8.write(buf);
                i.write(buf);
            }
        }
    }
}

impl EncodeSize for Instruction {
    fn encode_size(&self) -> usize {
        1 + match self {
            Instruction::TransferBread(i) => i.encode_size()
        }
    }
}

impl Read for Instruction {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Instruction::TransferBread(TransferBread::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferBread {
    pub amount: u64,
    pub to: PublicKey,
}

impl Write for TransferBread {
    fn write(&self, buf: &mut impl BufMut) {
        self.amount.write(buf);
        self.to.write(buf);
    }
}

impl EncodeSize for TransferBread {
    fn encode_size(&self) -> usize {
        self.amount.encode_size()
            + self.to.encode_size()
    }
}

impl Read for TransferBread {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let amount = u64::read_cfg(buf, &())?;
        let to = PublicKey::read(buf)?;
        Ok(Self{
            amount,
            to,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub parent: Digest,
    pub height: u64,
    pub transactions: Vec<Transaction>,
    digest: Digest,
}

impl Block {
    pub fn new(parent: Digest, height: u64, transactions: Vec<Transaction>) -> Self {
        assert!(transactions.len() <= MAX_BLOCK_TRANSACTIONS);
        let digest = Self::compute_digest(&parent, height, &transactions);
        Self {
            parent,
            height,
            transactions,
            digest,
        }
    }

    fn compute_digest(
        parent: &Digest,
        height: u64,
        transactions: &[Transaction],
    ) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(parent);
        hasher.update(&height.to_be_bytes());
        for transaction in transactions {
            hasher.update(&transaction.digest());
        }
        hasher.finalize()
    }
}

impl Write for Block {
    fn write(&self, writer: &mut impl BufMut) {
        self.parent.write(writer);
        UInt(self.height).write(writer);
        self.transactions.write(writer);
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let parent = Digest::read(reader)?;
        let height = UInt::read(reader)?.into();
        let transactions = Vec::<Transaction>::read_cfg(
            reader,
            &(RangeCfg::from(0..=MAX_BLOCK_TRANSACTIONS), ()),
        )?;

        // Pre-compute the digest
        let digest = Self::compute_digest(&parent, height, &transactions);
        Ok(Self {
            parent,
            height,
            transactions,
            digest,
        })
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + UInt(self.height).encode_size()
            + self.transactions.encode_size()
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl Committable for Block {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Default, Eq, PartialEq, Debug)]
pub struct Account {
    pub nonce: u64,
    pub bread: u64,
}

impl Write for Account {
    fn write(&self, buf: &mut impl BufMut) {
        self.nonce.write(buf);
        self.bread.write(buf);
    }
}

impl EncodeSize for Account {
    fn encode_size(&self) -> usize {
        self.nonce.encode_size()
            + self.bread.encode_size()
    }
}

impl Read for Account {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let nonce = u64::read(buf)?;
        let bread = u64::read(buf)?;
        Ok(Self{
            nonce,
            bread,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct CommitMetadata {
    pub height: u64,
    pub start: u64,
}

impl Write for CommitMetadata {
    fn write(&self, buf: &mut impl BufMut) {
        self.height.write(buf);
        self.start.write(buf);
    }
}

impl EncodeSize for CommitMetadata {
    fn encode_size(&self) -> usize {
        self.height.encode_size()
            + self.start.encode_size()
    }
}

impl Read for CommitMetadata {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let height = u64::read(buf)?;
        let start = u64::read(buf)?;
        Ok(Self{
            height,
            start,
        })
    }
}

#[derive(Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub enum Key {
    Account(PublicKey),
}

impl Write for Key {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Key::Account(k) => {
                0u8.write(buf);
                k.write(buf);
            }
        }
    }
}

impl EncodeSize for Key {
    fn encode_size(&self) -> usize {
        1 + match self {
            Key::Account(k) => k.encode_size()
        }
    }
}

impl Read for Key {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Key::Account(PublicKey::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Value {
    Account(Account),
    CommitMetadata(CommitMetadata),
}

impl Write for Value {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Value::Account(v) => {
                0u8.write(buf);
                v.write(buf);
            },
            Value::CommitMetadata(v) => {
                1u8.write(buf);
                v.height.write(buf);
            },
        }
    }
}

impl EncodeSize for Value {
    fn encode_size(&self) -> usize {
        1 + match self {
            Value::Account(v) => v.encode_size(),
            Value::CommitMetadata(v) => v.encode_size(),
        }
    }
}

impl Read for Value {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(Value::Account(Account::read(buf)?)),
            1 => Ok(Value::CommitMetadata(CommitMetadata::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}