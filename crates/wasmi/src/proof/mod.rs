mod engine;
mod inst;
mod instance;
mod store;
mod utils;

pub use self::{engine::*, inst::*, instance::*, store::*};

use alloc::vec::Vec;
use codec::{Decode, Encode};

use crate::{AsContext, Engine, Func, ProofError};
use accel_merkle::{
    FuncMerkle,
    InstructionMerkle,
    MerkleConfig,
    MerkleHasher,
    OutputOf,
    ProveData,
};

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

/// The complete wasm state proof designed for osp.
///
/// This is version 0.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct WasmStateProof<Config: MerkleConfig> {
    /// Current program status.
    pub status: Status,
    /// The current pc.
    pub current_pc: u32,
    /// The root of all wasm globals.
    pub globals_root: Option<OutputOf<Config>>,
    /// The roots of wasm table.
    pub table_roots: Vec<OutputOf<Config>>,
    /// The roots of wasm memory.
    pub memory_roots: Vec<OutputOf<Config>>,
    /// The engine proof.
    pub engine_proof: EngineProof<Config::Hasher>,
}

/// The status of program.
#[derive(Encode, Decode, Debug, Clone, Copy, Eq, PartialEq)]
pub enum Status {
    Running,
    Finished,
    Trapped,
}

/// The proof of wasm state.
#[derive(Encode)]
pub struct WasmState<'a, T: MerkleHasher> {
    status: Status,
    current_pc: u32,
    globals_root: &'a Option<T::Output>,
    table_roots: &'a Vec<T::Output>,
    memory_roots: &'a Vec<T::Output>,
    call_stack: T::Output,
    value_stack: T::Output,
}

impl<Config: MerkleConfig> WasmStateProof<Config> {
    /// Compute the finally proof hash.
    pub fn hash(&self) -> OutputOf<Config> {
        Config::Hasher::hash_of(&WasmState::<'_, Config::Hasher> {
            status: self.status,
            current_pc: self.current_pc,
            globals_root: &self.globals_root,
            table_roots: &self.table_roots,
            memory_roots: &self.memory_roots,
            call_stack: self.engine_proof.call_stack.hash(),
            value_stack: self.engine_proof.value_stack.hash(),
        })
    }
}

/// This contains some merkle trees which will never be changed if code is not updated.
#[derive(Debug)]
pub struct CodeMerkle<Hasher>
where
    Hasher: MerkleHasher,
{
    pub(crate) inst: InstructionMerkle<Hasher>,
    pub(crate) func: FuncMerkle<Hasher>,
}

impl<Hasher: MerkleHasher> CodeMerkle<Hasher> {
    // we need to generate proof for current instruction.
    pub(crate) fn get_inst_prove(&self, pc: usize) -> Result<ProveData<Hasher>, ProofError> {
        self.prove_pc(pc).ok_or(ProofError::IllegalPc)
    }
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
    #[inline]
    pub(crate) fn inst(&self) -> &InstructionMerkle<Hasher> {
        &self.inst
    }

    /// Returns the function merkle.
    #[inline]
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
