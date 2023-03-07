use alloc::vec::Vec;
use core::fmt::Debug;

use codec::{Decode, Encode};

use crate::proof::hash_memory_leaf;
use accel_merkle::{memory_chunk_size, MerkleConfig, OutputOf};

/// A util struct that contains two adjacent leaves.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub(crate) struct TwoMemoryChunks<Config: MerkleConfig> {
    leaf: Config::MemoryChunk,
    next_leaf: Config::MemoryChunk,
}

impl<Config: MerkleConfig> TwoMemoryChunks<Config> {
    /// Create two adjacent memory leaves.
    pub fn new(leaf: Config::MemoryChunk, next_leaf: Config::MemoryChunk) -> Self {
        Self { leaf, next_leaf }
    }

    /// Returns the hash of current memory leaf.
    pub fn hash_leaf(&self) -> OutputOf<Config> {
        hash_memory_leaf::<Config::Hasher>(self.leaf.as_ref())
    }

    /// Returns the hash of next memory leaf.
    pub fn hash_next_leaf(&self) -> OutputOf<Config> {
        hash_memory_leaf::<Config::Hasher>(self.next_leaf.as_ref())
    }

    /// Read memory from an address.
    ///
    /// # Panics
    ///
    /// This function maybe will panic if the buffer length is great than `N`.
    pub fn read(&self, address: usize, buffer: &mut [u8]) {
        let offset = address % memory_chunk_size::<Config>();
        let end = offset + buffer.len();

        buffer.copy_from_slice(&self.leaves()[offset..end]);
    }

    /// Write memory to an address.
    ///
    /// # Panics
    ///
    /// This function maybe will panic if the buffer length is great than `N`.
    pub fn write(&mut self, address: usize, buffer: &[u8]) {
        let offset = address % memory_chunk_size::<Config>();
        let end = offset + buffer.len();
        let mut leaves = self.leaves();
        leaves[offset..end].copy_from_slice(buffer);

        self.leaf
            .as_mut()
            .copy_from_slice(&leaves[..memory_chunk_size::<Config>()]);
        self.next_leaf
            .as_mut()
            .copy_from_slice(&leaves[memory_chunk_size::<Config>()..]);
    }

    /// Return the adjacent two leaves in memory.
    fn leaves(&self) -> Vec<u8> {
        let mut leaves = vec![0; memory_chunk_size::<Config>() * 2];
        leaves[..memory_chunk_size::<Config>()].copy_from_slice(self.leaf.as_ref());
        leaves[memory_chunk_size::<Config>()..].copy_from_slice(self.next_leaf.as_ref());

        leaves
    }
}
