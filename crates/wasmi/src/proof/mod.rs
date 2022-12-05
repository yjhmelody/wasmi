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

// TODO: should encode more info/design an upgradable format.
/// The complete osp proof data.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct OspProof<Hasher: MerkleHasher> {
    // instruction root and function root should always be same if wasm code not updated.
    // TODO(design): should exist before prove
    pub inst_root: Hasher::Output,
    // TODO(design): should exist before prove
    pub func_root: Hasher::Output,
    // wasm blob maybe not contain global value.
    pub globals_root: Option<Hasher::Output>,
    pub table_roots: Vec<Hasher::Output>,
    pub memory_roots: Vec<Hasher::Output>,
    /// The inst special proof.
    pub inst_proof: InstructionProof<Hasher>,
    pub engine_proof: EngineProof<Hasher>,
}

impl<Hasher: MerkleHasher> OspProof<Hasher> {
    /// Compute the finally proof hash.
    pub fn hash(&self) -> Hasher::Output {
        let engine_proof = self.engine_proof.hash();
        Hasher::hash_of(&PostOspProof::<'_, Hasher> {
            inst_root: &self.inst_root,
            func_root: &self.func_root,
            globals_root: &self.globals_root,
            table_roots: &self.table_roots,
            memory_roots: &self.memory_roots,
            engine_proof: &engine_proof,
        })
    }
}

#[derive(Encode)]
struct PostOspProof<'a, T: MerkleHasher> {
    inst_root: &'a T::Output,
    func_root: &'a T::Output,
    globals_root: &'a Option<T::Output>,
    table_roots: &'a Vec<T::Output>,
    memory_roots: &'a Vec<T::Output>,
    engine_proof: &'a T::Output,
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
