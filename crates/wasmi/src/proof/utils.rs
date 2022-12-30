use crate::proof::{hash_memory_leaf, MEMORY_LEAF_SIZE};
use accel_merkle::MerkleHasher;
use codec::{Decode, Encode};
use core::fmt::Debug;

/// A util struct that contains two adjacent leaves.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub(crate) struct TwoMemoryChunks {
    leaf: [u8; MEMORY_LEAF_SIZE],
    next_leaf: [u8; MEMORY_LEAF_SIZE],
}

impl TwoMemoryChunks {
    /// Create two adjacent memory leaves.
    pub fn new(leaf: [u8; MEMORY_LEAF_SIZE], next_leaf: [u8; MEMORY_LEAF_SIZE]) -> Self {
        Self { leaf, next_leaf }
    }

    /// Returns the hash of current memory leaf.
    pub fn hash_leaf<Hasher: MerkleHasher>(&self) -> Hasher::Output {
        hash_memory_leaf::<Hasher>(self.leaf)
    }

    /// Returns the hash of next memory leaf.
    pub fn hash_next_leaf<Hasher: MerkleHasher>(&self) -> Hasher::Output {
        hash_memory_leaf::<Hasher>(self.next_leaf)
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
        let mut leaves = self.leaves();
        leaves[offset..end].copy_from_slice(buffer);
        self.leaf.copy_from_slice(&leaves[..MEMORY_LEAF_SIZE]);
        self.next_leaf.copy_from_slice(&leaves[MEMORY_LEAF_SIZE..]);
    }

    /// Return the adjacent two leaves in memory.
    fn leaves(&self) -> [u8; MEMORY_LEAF_SIZE * 2] {
        let mut res = [0; MEMORY_LEAF_SIZE * 2];
        res[..MEMORY_LEAF_SIZE].copy_from_slice(&self.leaf);
        res[MEMORY_LEAF_SIZE..].copy_from_slice(&self.next_leaf);

        res
    }
}
