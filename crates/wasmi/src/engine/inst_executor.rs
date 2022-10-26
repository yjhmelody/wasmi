use super::{
    bytecode::{BranchParams, FuncIdx, GlobalIdx, Instruction, LocalDepth, Offset, SignatureIdx},
    DropKeep,
};
use crate::{
    core::{TrapCode, F32, F64},
    merkle::{
        table_element_hash,
        value_hash,
        CallIndirectProof,
        CallStackProof,
        EngineProof,
        ExtraProof,
        InstanceMerkle,
        InstructionProof,
        StaticMerkle,
        ValueStackProof,
    },
    snapshot::{FuncFrameSnapshot, TableElementSnapshot, ValueStackSnapshot},
    Func,
};
use accel_merkle::{sha3::Keccak256, Bytes32, ProveData};
use codec::{Decode, Encode};
use core::cmp;
use wasmi_core::{ExtendInto, LittleEndianConvert, UntypedValue, WrapInto};

pub type Result<T> = core::result::Result<T, ExecError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecError {
    GlobalsRootNotMatch,
    TableRootsNotMatch,
    EmptyValueStack,
    ValueStackTooSmallForLocalDepth,
    EmptyCallStack,
    ValueStackTooShortForDropKeep,
    BranchToIllegalPc,
    IllegalExtraProof,
    CallStackOverflow,
    DefaultTableNotFound,

    /// Just a temporary error.
    /// Will be removed when all proof are completed
    TODO,
}

#[derive(Clone, Copy, Encode, Decode, Debug, Eq, PartialEq)]
pub enum InstructionStatus {
    /// This means there is still next instruction.
    Running,
    /// This means program has run the last instruction.
    Finished,
    /// Current instruction meet trap.
    Trapped,
}

/// One instruction executor used for OSP.
#[derive(Debug, Encode, Decode)]
pub struct InstExecutor {
    status: InstructionStatus,
    call_stack: CallStackProof,
    value_stack: ValueStackProof,
    globals_root: Bytes32,
    table_roots: Vec<Bytes32>,
    memory_roots: Vec<Bytes32>,

    current_pc: u32,
    inst: Instruction,
    /// The prove current instruction is legal.
    inst_prove: ProveData,
    // TODO: maybe not defined here.
    extra: ExtraProof,
}

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
            Instr::Br(target) => self.visit_br(target),
            Instr::BrIfEqz(target) => self.visit_br_if_eqz(target),
            Instr::BrIfNez(target) => self.visit_br_if_nez(target),
            Instr::ReturnIfNez(drop_keep) => self.visit_return_if_nez(drop_keep),
            Instr::Unreachable => self.visit_unreachable(),

            // TODO
            _ => Err(ExecError::TODO),
        }
    }

    #[inline]
    fn next_pc(&mut self) {
        self.current_pc += 1;
    }

    #[inline]
    fn pc(&self) -> u32 {
        self.current_pc
    }

    #[inline]
    fn set_pc(&mut self, pc: u32) {
        self.current_pc = pc;
    }

    fn visit_local_get(&mut self, local_depth: LocalDepth) -> Result<()> {
        let value = *self
            .value_stack
            .peek(local_depth.into_inner())
            .ok_or(ExecError::ValueStackTooSmallForLocalDepth)?;
        self.value_stack.push(value);
        self.next_pc();
        Ok(())
    }

    fn visit_local_set(&mut self, local_depth: LocalDepth) -> Result<()> {
        let new_value = self.value_stack.pop().ok_or(ExecError::EmptyValueStack)?;
        let local = self
            .value_stack
            .peek_mut(local_depth.into_inner())
            .ok_or(ExecError::ValueStackTooSmallForLocalDepth)?;
        *local = new_value;

        self.next_pc();
        Ok(())
    }

    fn visit_local_tee(&mut self, local_depth: LocalDepth) -> Result<()> {
        let new_value = self
            .value_stack
            .last()
            .ok_or(ExecError::EmptyValueStack)?
            .clone();
        let local = self
            .value_stack
            .peek_mut(local_depth.into_inner())
            .ok_or(ExecError::ValueStackTooSmallForLocalDepth)?;
        *local = new_value;

        self.next_pc();
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
                self.next_pc();
                // nop
                Ok(())
            }
            _ => Err(ExecError::IllegalExtraProof),
        }
    }

    fn _visit_call_indirect_proof(
        &self,
        func_index: u32,
        proof: &CallIndirectProof,
        _signature_index: SignatureIdx,
    ) -> Result<()> {
        let table_root = self
            .table_roots
            .first()
            .ok_or(ExecError::DefaultTableNotFound)?;
        let leaf_hash = table_element_hash(&TableElementSnapshot::FuncIndex(
            func_index,
            proof.func_type.clone(),
        ));
        // prove it before using it.
        proof
            .prove_data
            .compute_root(func_index as usize, leaf_hash)
            .map_or(Err(ExecError::IllegalExtraProof), |root| {
                if root != *table_root {
                    Err(ExecError::TableRootsNotMatch)
                } else {
                    Ok(())
                }
            })?;

        // TODO: need to design

        Ok(())
    }

    fn visit_call_indirect(&mut self, signature_index: SignatureIdx) -> Result<()> {
        let func_index = self.pop_value_stack_as::<u32>()?;
        match &self.extra {
            ExtraProof::CallWasmIndirect(pc, proof) => {
                self._visit_call_indirect_proof(func_index, proof, signature_index)?;

                self.set_pc(*pc);
                Ok(())
            }
            ExtraProof::CallHostIndirect(proof) => {
                self._visit_call_indirect_proof(func_index, proof, signature_index)?;

                self.next_pc();
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

                // prove it before using it.
                proof.prove_data.compute_root(idx, leaf_hash).map_or(
                    Err(ExecError::IllegalExtraProof),
                    |root| {
                        // TODO: it seems is not necessary to do it for global.set.
                        if root != self.globals_root {
                            Err(ExecError::GlobalsRootNotMatch)
                        } else {
                            Ok(())
                        }
                    },
                )?;

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

    #[inline]
    fn visit_br(&mut self, params: BranchParams) -> Result<()> {
        self.branch_to(params)
    }

    #[inline]
    fn pop_value_stack_as<T>(&mut self) -> Result<T>
    where
        T: From<UntypedValue>,
    {
        self.value_stack.pop_as().ok_or(ExecError::EmptyValueStack)
    }

    fn visit_br_if_eqz(&mut self, params: BranchParams) -> Result<()> {
        let condition = self.pop_value_stack_as()?;
        if condition {
            self.next_pc();
            Ok(())
        } else {
            self.branch_to(params)
        }
    }

    fn visit_br_if_nez(&mut self, params: BranchParams) -> Result<()> {
        let condition = self.pop_value_stack_as()?;
        if condition {
            self.branch_to(params)
        } else {
            self.next_pc();
            Ok(())
        }
    }

    fn branch_to(&mut self, params: BranchParams) -> Result<()> {
        self.drop_keep(params.drop_keep())?;
        let offset = params.offset().into_i32();
        let pc = self.pc();
        let new_pc = if offset < 0 {
            let new_pc = pc as i32 - offset;
            if new_pc < 0 {
                return Err(ExecError::BranchToIllegalPc);
            } else {
                new_pc as u32
            }
        } else {
            match pc.checked_add(offset as u32) {
                None => return Err(ExecError::BranchToIllegalPc),
                Some(new_pc) => new_pc,
            }
        };

        self.set_pc(new_pc);
        Ok(())
    }

    fn visit_return_if_nez(&mut self, drop_keep: DropKeep) -> Result<()> {
        let condition = self.pop_value_stack_as()?;
        if condition {
            self.ret(drop_keep)
        } else {
            self.next_pc();
            Ok(())
        }
    }

    #[inline]
    fn drop_keep(&mut self, drop_keep: DropKeep) -> Result<()> {
        self.value_stack
            .drop_keep(drop_keep)
            .ok_or(ExecError::ValueStackTooShortForDropKeep)
    }

    fn ret(&mut self, drop_keep: DropKeep) -> Result<()> {
        self.drop_keep(drop_keep)?;
        let frame = self.call_stack.pop().ok_or(ExecError::EmptyCallStack)?;
        self.set_pc(frame.pc);
        Ok(())
    }

    #[inline]
    fn visit_unreachable(&mut self) -> Result<()> {
        self.status = InstructionStatus::Trapped;
        // pc not changed
        Ok(())
    }
}
