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
    merkle::{CallStackProof, EngineProof, ExtraProof, InstructionProof, ValueStackProof},
    snapshot::{EngineConfig, FuncFrameSnapshot, ValueStackSnapshot},
    AsContext,
    Func,
    StoreContextMut,
};
use codec::{Decode, Encode};
use core::cmp;
use wasmi_core::{ExtendInto, LittleEndianConvert, UntypedValue, WrapInto};

#[derive(Clone, Copy, Encode, Decode, Debug, Eq, PartialEq)]
pub enum InstructionStatus {
    Running,
    Finished,
    Errored,
}

/// A one instruction executor used for OSP.
#[derive(Debug, Encode, Decode)]
pub struct InstExecutor {
    pub status: InstructionStatus,
    pub inst: InstructionProof,
}

// TODO
impl InstExecutor {
    pub fn execute(&mut self) {
        use Instruction as Instr;
        match self.inst.inst {
            Instr::LocalGet { local_depth } => self.visit_local_get(local_depth),
            Instr::LocalSet { local_depth } => self.visit_local_set(local_depth),
            Instr::LocalTee { local_depth } => self.visit_local_tee(local_depth),

            Instr::Call(func) => self.visit_call(func),
            Instr::CallIndirect(signature) => self.visit_call_indirect(signature),
            Instr::BrTable { len_targets } => self.visit_br_table(len_targets),

            Instr::GlobalGet(global_idx) => self.visit_global_get(global_idx),
            Instr::GlobalSet(global_idx) => self.visit_global_set(global_idx),

            _ => todo!(),
        }
    }

    fn next_instr(&mut self) {
        self.inst.current_pc += 1;
    }

    fn pc(&self) -> u32 {
        self.inst.current_pc
    }

    fn set_pc(&mut self, pc: u32) {
        self.inst.current_pc = pc;
    }

    fn value_stack(&mut self) -> &mut ValueStackProof {
        &mut self.inst.engine_proof.value_proof
    }

    fn call_stack(&mut self) -> &mut CallStackProof {
        &mut self.inst.engine_proof.call_proof
    }

    fn visit_local_get(&mut self, local_depth: LocalDepth) {
        if self.value_stack().is_emtpy() {
            self.status = InstructionStatus::Errored;
            return;
        }
        let value = *self.value_stack().peek(local_depth.into_inner());
        self.value_stack().push(value);
        self.next_instr()
    }

    fn visit_local_set(&mut self, local_depth: LocalDepth) {
        if self.value_stack().is_emtpy() {
            self.status = InstructionStatus::Errored;
            return;
        }
        let new_value = self.value_stack().pop();
        *self.value_stack().peek_mut(local_depth.into_inner()) = new_value;
        self.next_instr()
    }

    fn visit_local_tee(&mut self, local_depth: LocalDepth) {
        if self.value_stack().is_emtpy() {
            self.status = InstructionStatus::Errored;
            return;
        }
        let new_value = self.value_stack().last();
        *self.value_stack().peek_mut(local_depth.into_inner()) = *new_value;
        self.next_instr()
    }

    fn visit_br_table(&mut self, len_targets: usize) {
        if self.value_stack().is_emtpy() {
            self.status = InstructionStatus::Errored;
            return;
        }
        let index: u32 = self.value_stack().pop_as();
        // The index of the default target which is the last target of the slice.
        let max_index = len_targets as u32 - 1;
        // A normalized index will always yield a target without panicking.
        let normalized_index = cmp::min(index, max_index);

        self.set_pc(self.pc() + normalized_index + 1);
    }

    // TODO: Need to prove this index is valid
    fn visit_call(&mut self, _func_index: FuncIdx) {
        // update current frame pc
        let pc = self.pc();
        self.call_stack().push(FuncFrameSnapshot::from(pc + 1));
        match &self.inst.extra {
            ExtraProof::CallWasm(pc) => {
                self.set_pc(*pc);
            }
            ExtraProof::CallHost => {
                self.next_instr();
                // nop
            }
            _ => unreachable!(),
        }
    }

    fn visit_call_indirect(&mut self, _signature_index: SignatureIdx) {
        match &self.inst.extra {
            ExtraProof::CallWasmIndirect(pc, func_type) => {
                // TODO:

                self.set_pc(*pc);
            }
            ExtraProof::CallHostIndirect(func_type) => {
                // TODO:

                self.next_instr();
            }
            _ => unreachable!(),
        }
    }

    fn visit_global_get(&mut self, global_index: GlobalIdx) {
        match &self.inst.extra {
            ExtraProof::GlobalGetSet(proof) => {
                todo!()
            }

            _ => unreachable!(),
        }
        // let global_value = *self.global(global_index);
        // self.value_stack().push(global_value);
        // self.next_instr()
    }

    fn visit_global_set(&mut self, global_index: GlobalIdx) {
        // let new_value = self.value_stack.pop();
        // *self.global(global_index) = new_value;
        // self.next_instr()
    }
}
