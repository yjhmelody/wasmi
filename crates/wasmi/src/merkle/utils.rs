use crate::merkle::MEMORY_LEAF_SIZE;
use codec::{Decode, Encode};
use core::fmt::Debug;

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub(crate) struct TwoMemoryChunks {
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

    fn leaves_mut(&mut self) -> &mut [u8; MEMORY_LEAF_SIZE * 2] {
        unsafe { core::mem::transmute(&mut self.leaf) }
    }

    /// Read memory from an address.
    ///
    /// # Panics
    ///
    /// This function maybe will panic if the buffer length is great than `MEMORY_LEAF_SIZE`.
    pub fn read(&self, address: usize, buffer: &mut [u8]) {
        let offset = address % MEMORY_LEAF_SIZE;
        let end = offset + buffer.len();
        buffer.copy_from_slice(&self.leaves()[offset..end]);
    }

    /// Write memory to an address.
    ///
    /// # Panics
    ///
    /// This function maybe will panic if the buffer length is great than `MEMORY_LEAF_SIZE`.
    pub fn write(&mut self, address: usize, buffer: &[u8]) {
        let offset = address % MEMORY_LEAF_SIZE;
        let end = offset + buffer.len();
        self.leaves_mut()[offset..end].copy_from_slice(buffer);
    }
}
