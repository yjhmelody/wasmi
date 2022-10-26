use super::{
    super::{Memory, Table},
    bytecode::{BranchParams, FuncIdx, GlobalIdx, Instruction, LocalDepth, Offset, SignatureIdx},
    cache::InstanceCache,
    code_map::InstructionPtr,
    stack::ValueStackRef,
    AsContextMut,
    CallOutcome,
    DropKeep,
    FuncFrame,
    ValueStack,
};
use crate::{
    core::{TrapCode, F32, F64},
    merkle::{
        value_hash,
        CallStackProof,
        EngineProof,
        ExtraProof,
        InstanceMerkle,
        InstructionProof,
        StaticMerkle,
        ValueStackProof,
    },
    snapshot::{EngineConfig, FuncFrameSnapshot, ValueStackSnapshot},
    AsContext,
    Func,
    StoreContextMut,
};
use accel_merkle::{sha3::Keccak256, Bytes32, ProveData};
use codec::{Decode, Encode};
use core::cmp;
use wasmi_core::{ExtendInto, LittleEndianConvert, UntypedValue, WrapInto};

#[derive(Clone, Copy, Encode, Decode, Debug, Eq, PartialEq)]
pub enum InstructionStatus {
    Running,
    Finished,
    Errored,
}

#[derive(Clone, Copy, Encode, Decode, Debug, Eq, PartialEq)]
pub enum ExecError {
    GlobalsRootNotMatch,
    EmptyValueStack,
    IllegalExtraProof,
    CallStackOverflow,
}

pub type Result<T> = core::result::Result<T, ExecError>;

/// One instruction executor used for OSP.
#[derive(Debug, Encode, Decode)]
pub struct InstExecutor {
    // TODO:
    // status: InstructionStatus,
    config: EngineConfig,
    call_stack: CallStackProof,
    value_stack: ValueStackProof,
    globals_root: Bytes32,

    current_pc: u32,
    inst: Instruction,
    /// The prove current instruction is legal.
    inst_prove: ProveData,
    extra: ExtraProof,
}

// TODO
impl InstExecutor {
    pub fn execute(&mut self) -> Result<()> {
        use Instruction as Instr;
        match self.inst {
            Instr::LocalGet { local_depth } => self.visit_local_get(local_depth),
            Instr::LocalSet { local_depth } => self.visit_local_set(local_depth),
            Instr::LocalTee { local_depth } => self.visit_local_tee(local_depth),

            Instr::Call(func) => self.visit_call(func),
            Instr::CallIndirect(signature) => self.visit_call_indirect(signature),
            Instr::BrTable { len_targets } => self.visit_br_table(len_targets),

            Instr::GlobalGet(global_idx) => self.visit_global_get(global_idx),
            Instr::GlobalSet(global_idx) => self.visit_global_set(global_idx),
            // TODO: Br insts
            _ => todo!(),
        }
    }

    fn next_instr(&mut self) {
        self.current_pc += 1;
    }

    fn pc(&self) -> u32 {
        self.current_pc
    }

    fn set_pc(&mut self, pc: u32) {
        self.current_pc = pc;
    }

    fn visit_local_get(&mut self, local_depth: LocalDepth) -> Result<()> {
        // TODO: we need to make sure local depth
        let value = *self
            .value_stack
            .peek(local_depth.into_inner())
            .ok_or(ExecError::EmptyValueStack)?;
        self.value_stack.push(value);
        self.next_instr();
        Ok(())
    }

    fn visit_local_set(&mut self, local_depth: LocalDepth) -> Result<()> {
        let new_value = self.value_stack.pop().ok_or(ExecError::EmptyValueStack)?;
        *self.value_stack.peek_mut(local_depth.into_inner()) = new_value;
        self.next_instr();
        Ok(())
    }

    fn visit_local_tee(&mut self, local_depth: LocalDepth) -> Result<()> {
        let new_value = self.value_stack.last().ok_or(ExecError::EmptyValueStack)?;
        *self.value_stack.peek_mut(local_depth.into_inner()) = *new_value;
        self.next_instr();
        Ok(())
    }

    fn visit_br_table(&mut self, len_targets: usize) -> Result<()> {
        let index: u32 = self
            .value_stack
            .pop_as()
            .ok_or(ExecError::EmptyValueStack)?;
        // The index of the default target which is the last target of the slice.
        let max_index = len_targets as u32 - 1;
        // A normalized index will always yield a target without panicking.
        let normalized_index = cmp::min(index, max_index);
        self.set_pc(self.pc() + normalized_index + 1);
        Ok(())
    }

    // TODO: Need to prove this index is valid
    fn visit_call(&mut self, _func_index: FuncIdx) -> Result<()> {
        // update current frame pc
        let pc = self.pc();
        self.call_stack
            .push(FuncFrameSnapshot::from(pc + 1))
            .ok_or(ExecError::CallStackOverflow)?;
        match &self.extra {
            ExtraProof::CallWasm(pc) => {
                self.set_pc(*pc);
                Ok(())
            }
            ExtraProof::CallHost => {
                self.next_instr();
                // nop
                Ok(())
            }
            _ => Err(ExecError::IllegalExtraProof),
        }
    }

    fn visit_call_indirect(&mut self, _signature_index: SignatureIdx) -> Result<()> {
        match &self.extra {
            ExtraProof::CallWasmIndirect(pc, func_type) => {
                // TODO:

                self.set_pc(*pc);
                Ok(())
            }
            ExtraProof::CallHostIndirect(func_type) => {
                // TODO:

                self.next_instr();
                Ok(())
            }
            _ => Err(ExecError::IllegalExtraProof),
        }
    }

    fn visit_global_get(&mut self, global_index: GlobalIdx) -> Result<()> {
        self.visit_global_set_get(global_index, false)
    }

    fn visit_global_set(&mut self, global_index: GlobalIdx) -> Result<()> {
        self.visit_global_set_get(global_index, true)
    }

    fn visit_global_set_get(&mut self, global_index: GlobalIdx, is_set: bool) -> Result<()> {
        match &self.extra {
            ExtraProof::GlobalGetSet(proof) => {
                let idx = global_index.into_inner() as usize;
                let global = proof.value.clone();
                let leaf_hash = value_hash(global);
                match proof.prove_data.compute_root(idx, leaf_hash) {
                    Some(root) => {
                        // TODO: it seems is not necessary to do it for global.set.
                        if root != self.globals_root {
                            return Err(ExecError::GlobalsRootNotMatch);
                        }
                    }
                    None => return Err(ExecError::IllegalExtraProof),
                };

                if is_set {
                    let global = self.value_stack.pop().expect("Must exist");
                    let leaf_hash = value_hash(global);
                    self.globals_root = proof
                        .prove_data
                        .compute_root(idx, leaf_hash)
                        .expect("idx have been checked; qed");
                    Ok(())
                } else {
                    self.value_stack.push(global);
                    Ok(())
                }
            }

            _ => Err(ExecError::IllegalExtraProof),
        }
    }
}
