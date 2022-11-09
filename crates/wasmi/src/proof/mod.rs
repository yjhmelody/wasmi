mod engine;
mod inst;
mod instance;
mod utils;

pub use engine::*;
pub use inst::*;
pub use instance::*;

use crate::snapshot::{FuncType, InstanceSnapshot};
use accel_merkle::{
    FuncMerkle,
    GlobalMerkle,
    InstructionMerkle,
    MemoryMerkle,
    MerkleHasher,
    TableMerkle,
};
use codec::{Decode, Encode};

// TODO: consider functions type as merkle

/// All proof data for an instance at a checkpoint.
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

/// This contains some merkle trees whose data should
/// never be changed during wasm execution without code update.
#[derive(Debug)]
pub struct StaticMerkle<Hasher>
where
    Hasher: MerkleHasher,
{
    pub(crate) code: InstructionMerkle<Hasher>,
    pub(crate) func: FuncMerkle<Hasher>,
}

pub fn make_func_merkle<Hasher: MerkleHasher>(
    func_types: impl Iterator<Item = FuncType>,
) -> FuncMerkle<Hasher> {
    let hashes: Vec<_> = func_types.map(|f| f.to_hash::<Hasher>()).collect();
    assert!(hashes.len() > 0);
    FuncMerkle::new(hashes)
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
