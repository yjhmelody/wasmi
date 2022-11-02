mod engine;
mod instance;
mod utils;

use crate::{snapshot::InstanceSnapshot, MemoryEntity};
use accel_merkle::Merkle;
use alloc::vec::Vec;
use core::cmp;
pub use engine::*;
pub use instance::*;

/// Get memory byte32 by leaf index. Returns a empty leaf if not exists.
pub fn get_memory_leaf(memory: &MemoryEntity, leaf_idx: usize) -> [u8; MEMORY_LEAF_SIZE] {
    let mut buf = [0u8; MEMORY_LEAF_SIZE];
    let idx = match leaf_idx.checked_mul(MEMORY_LEAF_SIZE) {
        Some(x) if x < memory.data().len() => x,
        _ => return buf,
    };
    let size = cmp::min(MEMORY_LEAF_SIZE, memory.data().len() - idx);
    buf[..size].copy_from_slice(&memory.data()[idx..(idx + size)]);
    buf
}

// TODO: consider functions type as merkle
#[derive(Debug)]
pub struct InstanceProof {
    pub globals: Merkle,
    pub memories: Vec<MemoryProof>,
    pub tables: Vec<TableProof>,
}

#[derive(Debug)]
pub struct MemoryProof {
    pub page: MemoryPage,
    pub merkle: Merkle,
}

#[derive(Debug)]
pub struct TableProof {
    pub initial: u32,
    pub maximum: Option<u32>,
    pub merkle: Merkle,
}

/// This contains some merkle trees whose data should never be changed during wasm execution.
#[derive(Debug)]
pub struct StaticMerkle {
    pub code: Merkle,
}

impl InstanceProof {
    pub fn create_by_snapshot(instance: InstanceSnapshot) -> Self {
        Self {
            globals: instance.globals_proof(),
            memories: instance.memory_proofs(),
            tables: instance.table_proofs(),
        }
    }
}
