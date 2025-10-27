use commonware_cryptography::{
    sha256::{Digest, Sha256}, Committable, Digestible, Hasher
};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write 
};

use bytes::{Buf, BufMut};

use crate::types::Frame;

#[derive(Clone)]
pub enum MessageEvent {
    BlockMinted(u64),
    FrameFinalized(Frame),
}

impl Write for MessageEvent {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            MessageEvent::BlockMinted(block_number) => {
                0u8.write(buf);
                block_number.write(buf);
            }
            MessageEvent::FrameFinalized(frame) => {
                1u8.write(buf);
                frame.write(buf);
            },
        }
    }
}

impl EncodeSize for MessageEvent {
    fn encode_size(&self) -> usize {
        1 + match self {
            MessageEvent::BlockMinted(block_number) => block_number.encode_size(),
            MessageEvent::FrameFinalized(frame) => frame.encode_size(),
        }
    }
}

impl Read for MessageEvent {
    type Cfg = ();
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let tag = u8::read(buf)?;
        match tag {
            0 => Ok(MessageEvent::BlockMinted(u64::read(buf)?)),
            1 => Ok(MessageEvent::FrameFinalized(Frame::read(buf)?)),
            d => Err(CodecError::InvalidEnum(d)),
        }
    }
}

impl Digestible for MessageEvent {
    type Digest = Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&self.encode())
    }
}

impl Committable for MessageEvent {
    type Commitment = Digest;
    
    fn commitment(&self) -> Self::Commitment {
        self.digest()
    }
}