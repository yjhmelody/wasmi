mod engine;
mod instance;
mod utils;

use crate::snapshot::InstanceSnapshot;
use accel_merkle::{GlobalMerkle, InstructionMerkle, MemoryMerkle, MerkleHasher, TableMerkle};
use alloc::vec::Vec;
pub use engine::*;
pub use instance::*;

// TODO: consider functions type as merkle

/// All proof data for an instance.
#[derive(Debug)]
pub struct InstanceProof<Hasher>
where
    Hasher: MerkleHasher,
{
    pub globals: Option<GlobalMerkle<Hasher>>,
    pub memories: Vec<MemoryProof<Hasher>>,
    pub tables: Vec<TableProof<Hasher>>,
}

#[derive(Debug)]
pub struct MemoryProof<Hasher>
where
    Hasher: MerkleHasher,
{
    pub page: MemoryPage,
    pub merkle: MemoryMerkle<Hasher>,
}

#[derive(Debug)]
pub struct TableProof<Hasher>
where
    Hasher: MerkleHasher,
{
    pub initial: u32,
    pub maximum: Option<u32>,
    pub merkle: TableMerkle<Hasher>,
}

/// This contains some merkle trees whose data should never be changed during wasm execution.
#[derive(Debug)]
pub struct StaticMerkle<Hasher>
where
    Hasher: MerkleHasher,
{
    pub(crate) code: InstructionMerkle<Hasher>,
}

impl<Hasher> InstanceProof<Hasher>
where
    Hasher: MerkleHasher,
{
    pub fn create_by_snapshot(instance: InstanceSnapshot) -> Self {
        Self {
            globals: instance.global_merkle(),
            memories: instance.memory_proofs(),
            tables: instance.table_proofs(),
        }
    }
}
