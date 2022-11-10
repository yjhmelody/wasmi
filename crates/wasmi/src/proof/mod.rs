mod engine;
mod inst;
mod instance;
mod utils;

pub use engine::*;
pub use inst::*;
pub use instance::*;

use crate::{snapshot::InstanceSnapshot, AsContext, Engine, Func};
use accel_merkle::{
    FuncMerkle,
    GlobalMerkle,
    InstructionMerkle,
    MemoryMerkle,
    MerkleHasher,
    TableMerkle,
};

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
    code: InstructionMerkle<Hasher>,
    func: FuncMerkle<Hasher>,
}

impl<Hasher> StaticMerkle<Hasher>
where
    Hasher: MerkleHasher,
{
    /// Creates static merkle components.
    pub(crate) fn create(ctx: impl AsContext, funcs: &[Func], engine: Engine) -> Self {
        let code = engine.make_code_merkle();
        let func = make_func_merkle(ctx, funcs, engine);

        Self { code, func }
    }

    pub(crate) fn code(&self) -> &InstructionMerkle<Hasher> {
        &self.code
    }

    pub(crate) fn func(&self) -> &FuncMerkle<Hasher> {
        &self.func
    }
}

fn make_func_merkle<Hasher: MerkleHasher>(
    ctx: impl AsContext,
    funcs: &[Func],
    engine: Engine,
) -> FuncMerkle<Hasher> {
    let hashes = funcs
        .iter()
        .map(|f| FuncNode::from_func(ctx.as_context(), *f, engine.clone()))
        .map(|header| header.hash::<Hasher>())
        .collect();

    FuncMerkle::new(hashes)
}

impl<Hasher> InstanceProof<Hasher>
where
    Hasher: MerkleHasher,
{
    /// Creates an instance proof by snapshot.
    pub fn create_by_snapshot(instance: InstanceSnapshot) -> Self {
        Self {
            globals: instance.global_merkle(),
            memories: instance.memory_proofs(),
            tables: instance.table_proofs(),
        }
    }
}
