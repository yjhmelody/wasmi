use crate::merkle::MEMORY_LEAF_SIZE;
use codec::{Codec, Decode, Encode, Error, Input, Output};
use core::fmt::Debug;

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct TwoMemoryChunks {
    pub leaf: [u8; MEMORY_LEAF_SIZE],
    pub next_leaf: [u8; MEMORY_LEAF_SIZE],
}

impl TwoMemoryChunks {
    pub fn new(leaf: [u8; MEMORY_LEAF_SIZE], next_leaf: [u8; MEMORY_LEAF_SIZE]) -> Self {
        Self { leaf, next_leaf }
    }

    /// Two leaves are adjacent in memory
    fn leaves(&self) -> &[u8; MEMORY_LEAF_SIZE * 2] {
        unsafe { core::mem::transmute(&self.leaf) }
    }

    pub fn read(&self, address: usize, buffer: &mut [u8]) {
        let offset = address % MEMORY_LEAF_SIZE;
        buffer.copy_from_slice(&self.leaves()[offset..]);
    }
}
