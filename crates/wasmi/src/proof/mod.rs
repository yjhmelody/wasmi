mod engine;
mod inst;
mod instance;
mod store;
mod utils;

pub use self::{engine::*, inst::*, instance::*, store::*};

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::{AsContext, Engine, Func};
use accel_merkle::{
    FuncMerkle,
    InstructionMerkle,
    MerkleConfig,
    MerkleHasher,
    OutputOf,
    ProveData,
};

/// Prefix versioned proof for osp.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum VersionedCodeProof<Hasher: MerkleHasher> {
    V0(CodeProof<Hasher>),
}

/// The wasm code related proof.
///
/// If wasm code is not updated, this value should never be changed.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct CodeProof<Hasher: MerkleHasher> {
    /// The root of instructions.
    pub inst_root: Hasher::Output,
    /// The root of functions.
    pub func_root: Hasher::Output,
}

/// Prefix versioned proof for osp.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum VersionedOspProof<Config: MerkleConfig> {
    V0(OspProof<Config>),
}

/// The complete osp proof data to be input to osp executor.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct OspProof<Config: MerkleConfig> {
    /// The root of all wasm globals.
    ///
    /// Wasm blob maybe not contain global value.
    pub globals_root: Option<OutputOf<Config>>,
    /// The roots of wasm table.
    pub table_roots: Vec<OutputOf<Config>>,
    /// The roots of wasm memory.
    pub memory_roots: Vec<OutputOf<Config>>,
    /// The engine proof.
    pub engine_proof: EngineProof<Config::Hasher>,
    /// The inst special proof.
    pub inst_proof: InstructionProof<Config>,
}

impl<Config: MerkleConfig> OspProof<Config> {
    /// Compute the finally proof hash.
    pub fn hash(&self) -> OutputOf<Config> {
        let engine_proof = self.engine_proof.hash();
        Config::Hasher::hash_of(&OspProofRoots::<'_, Config::Hasher> {
            globals_root: &self.globals_root,
            table_roots: &self.table_roots,
            memory_roots: &self.memory_roots,
            engine_proof: &engine_proof,
        })
    }
}

/// The roots of different wasm part.
#[derive(Encode)]
struct OspProofRoots<'a, T: MerkleHasher> {
    globals_root: &'a Option<T::Output>,
    table_roots: &'a Vec<T::Output>,
    memory_roots: &'a Vec<T::Output>,
    engine_proof: &'a T::Output,
}

/// This contains some merkle trees which will never be changed if code is not updated.
#[derive(Debug)]
pub struct CodeMerkle<Hasher>
where
    Hasher: MerkleHasher,
{
    inst: InstructionMerkle<Hasher>,
    func: FuncMerkle<Hasher>,
}

impl<Hasher> CodeMerkle<Hasher>
where
    Hasher: MerkleHasher,
{
    /// Generate code related merkle.
    pub(crate) fn generate(ctx: impl AsContext, funcs: &[Func], engine: Engine) -> Self {
        let inst = engine.make_code_merkle();
        let func = make_func_merkle(ctx, funcs, engine);

        Self { inst, func }
    }

    /// Returns the instruction merkle.
    pub(crate) fn inst(&self) -> &InstructionMerkle<Hasher> {
        &self.inst
    }

    /// Returns the function merkle.
    pub(crate) fn func(&self) -> &FuncMerkle<Hasher> {
        &self.func
    }

    /// Creates code proof according to current merkle trees.
    pub fn code_proof(&self) -> CodeProof<Hasher> {
        CodeProof {
            inst_root: self.inst.root(),
            func_root: self.func.root(),
        }
    }

    /// Generate a proof for func at func index.
    pub fn prove_func_index(&self, func_index: usize) -> Option<ProveData<Hasher>> {
        self.func().prove(func_index)
    }

    /// Generate a proof for instruction at pc.
    pub fn prove_pc(&self, pc: usize) -> Option<ProveData<Hasher>> {
        self.inst().prove(pc)
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
