mod engine;
mod inst;
mod instance;
mod store;
mod utils;

pub use self::{engine::*, inst::*, instance::*, store::*};

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::{AsContext, Engine, Func};
use accel_merkle::{FuncMerkle, InstructionMerkle, MerkleHasher, ProveData};

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
pub enum VersionedOspProof<Hasher: MerkleHasher> {
    V0(OspProof<Hasher>),
}

// TODO: should encode more info/design an upgradable format.
/// The complete osp proof data.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct OspProof<Hasher: MerkleHasher> {
    /// wasm blob maybe not contain global value.
    pub globals_root: Option<Hasher::Output>,
    pub table_roots: Vec<Hasher::Output>,
    pub memory_roots: Vec<Hasher::Output>,
    pub engine_proof: EngineProof<Hasher>,
    /// The inst special proof.
    pub inst_proof: InstructionProof<Hasher>,
}

impl<Hasher: MerkleHasher> OspProof<Hasher> {
    /// Compute the finally proof hash.
    pub fn hash(&self) -> Hasher::Output {
        let engine_proof = self.engine_proof.hash();
        Hasher::hash_of(&OspProofRoots::<'_, Hasher> {
            globals_root: &self.globals_root,
            table_roots: &self.table_roots,
            memory_roots: &self.memory_roots,
            engine_proof: &engine_proof,
        })
    }
}

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

    pub(crate) fn inst(&self) -> &InstructionMerkle<Hasher> {
        &self.inst
    }

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

    /// Generate a proof for func index.
    pub fn prove_func_index(&self, func_index: usize) -> Option<ProveData<Hasher>> {
        self.func().prove(func_index)
    }

    /// Generate a proof for pc.
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
