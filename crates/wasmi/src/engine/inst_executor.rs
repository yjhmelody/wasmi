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
    merkle::{CallStackProof, ExtraProof, ValueStackProof},
    snapshot::{EngineConfig, FuncFrameSnapshot, ValueStackSnapshot},
    AsContext,
    Func,
    StoreContextMut,
};
use core::cmp;
use wasmi_core::{memory_units::Pages, ExtendInto, LittleEndianConvert, UntypedValue, WrapInto};

/// A one instruction executor used for proof.
pub struct InstExecutor {
    // TODO
    pub config: EngineConfig,
    inst: Instruction,
    value_stack: ValueStackProof,
    call_stack: CallStackProof,
    pc: u32,
    extra: ExtraProof,
}

impl InstExecutor {
    pub fn execute(&mut self) {
        use Instruction as Instr;
        match self.inst {
            Instr::LocalGet { local_depth } => self.visit_local_get(local_depth),
            Instr::LocalSet { local_depth } => self.visit_local_set(local_depth),
            Instr::LocalTee { local_depth } => self.visit_local_tee(local_depth),

            Instr::Call(func) => self.visit_call(func),
            Instr::CallIndirect(signature) => self.visit_call_indirect(signature),

            _ => todo!(),
        }
    }

    fn next_instr(&mut self) {
        self.pc += 1;
    }

    fn visit_local_get(&mut self, local_depth: LocalDepth) {
        let value = self.value_stack.peek(local_depth.into_inner());
        self.value_stack.push(*value);
        self.next_instr()
    }

    fn visit_local_set(&mut self, local_depth: LocalDepth) {
        let new_value = self.value_stack.pop();
        *self.value_stack.peek_mut(local_depth.into_inner()) = new_value;
        self.next_instr()
    }

    fn visit_local_tee(&mut self, local_depth: LocalDepth) {
        let new_value = self.value_stack.last();
        *self.value_stack.peek_mut(local_depth.into_inner()) = *new_value;
        self.next_instr()
    }

    fn visit_call(&mut self, func_index: FuncIdx) {
        // now it point to the next instruction after call.
        self.next_instr();
        let _ = self.call_stack.pop();
        // update current frame pc
        self.call_stack.push(FuncFrameSnapshot::from(self.pc));
    }

    fn visit_call_indirect(&mut self, signature_index: SignatureIdx) {
        match &self.extra {
            ExtraProof::Empty => unreachable!(),
            ExtraProof::CallIndirect(f) => {}
            _ => todo!(),
        }
    }
}
