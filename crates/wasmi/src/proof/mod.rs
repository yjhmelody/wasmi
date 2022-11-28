mod engine;
mod inst;
mod instance;
mod utils;

pub use engine::*;
pub use inst::*;
pub use instance::*;

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::{AsContext, Engine, Func};
use accel_merkle::{FuncMerkle, InstructionMerkle, MerkleHasher};

/// Prefix versioned proof for osp.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum VersionedOspProof<Hasher: MerkleHasher> {
    V0(OspProof<Hasher>),
}

/// The complete osp proof data.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct OspProof<Hasher: MerkleHasher> {
    // instruction root and function root should always be same if wasm code not updated.
    pub(crate) inst_root: Hasher::Output,
    pub(crate) func_root: Hasher::Output,
    // wasm blob maybe not contain global value.
    pub(crate) globals_root: Option<Hasher::Output>,
    pub(crate) table_roots: Vec<Hasher::Output>,
    pub(crate) memory_roots: Vec<Hasher::Output>,

    pub(crate) inst_proof: InstructionProof<Hasher>,
    pub(crate) engine_proof: EngineProof<Hasher>,
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
