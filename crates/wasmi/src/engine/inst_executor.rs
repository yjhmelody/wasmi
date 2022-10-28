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
        ExtraProof,
        ValueStackProof,
    },
    snapshot::{FuncFrameSnapshot, TableElementSnapshot},
};

use core::{cmp, result};

use accel_merkle::{Bytes32, ProveData};
use codec::{Decode, Encode};
use wasmi_core::{ExtendInto, LittleEndianConvert, UntypedValue, WrapInto};

pub type Result<T> = result::Result<T, ExecError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecError {
    GlobalsRootNotMatch,
    TableRootsNotMatch,
    EmptyValueStack,
    InsufficientValueStack,
    ValueStackTooSmallForLocalDepth,
    InsufficientCallStack,
    ValueStackTooShortForDropKeep,
    BranchToIllegalPc,
    IllegalExtraProof,
    CallStackOverflow,
    DefaultTableNotFound,
    UnsupportedOSP,
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
    /// The size of default memory.
    default_memory_size: u32,

    current_pc: u32,
    inst: Instruction,
    /// The prove current instruction is legal.
    inst_prove: ProveData,
    // TODO: maybe not defined here.
    extra: ExtraProof,
}

impl InstExecutor {
    #[allow(unused)]
    pub fn execute(&mut self) -> Result<()> {
        use Instruction as Instr;
        match self.inst {
            Instr::LocalGet { local_depth } => self.visit_local_get(local_depth),
            Instr::LocalSet { local_depth } => self.visit_local_set(local_depth),
            Instr::LocalTee { local_depth } => self.visit_local_tee(local_depth),
            Instr::Br(target) => self.visit_br(target),
            Instr::BrIfEqz(target) => self.visit_br_if_eqz(target),
            Instr::BrIfNez(target) => self.visit_br_if_nez(target),
            Instr::ReturnIfNez(drop_keep) => self.visit_return_if_nez(drop_keep),
            Instr::Unreachable => self.visit_unreachable(),
            Instr::BrTable { len_targets } => self.visit_br_table(len_targets),
            Instr::Return(drop_keep) => self.visit_ret(drop_keep),
            Instr::Call(func) => self.visit_call(func),
            Instr::CallIndirect(signature) => self.visit_call_indirect(signature),
            Instr::Drop => self.visit_drop(),
            Instr::Select => self.visit_select(),
            Instr::GlobalGet(global_idx) => self.visit_global_get(global_idx),
            Instr::GlobalSet(global_idx) => self.visit_global_set(global_idx),
            Instr::I32Load(offset) => self.visit_i32_load(offset),
            Instr::I64Load(offset) => self.visit_i64_load(offset),
            Instr::F32Load(offset) => self.visit_f32_load(offset),
            Instr::F64Load(offset) => self.visit_f64_load(offset),
            Instr::I32Load8S(offset) => self.visit_i32_load_i8(offset),
            Instr::I32Load8U(offset) => self.visit_i32_load_u8(offset),
            Instr::I32Load16S(offset) => self.visit_i32_load_i16(offset),
            Instr::I32Load16U(offset) => self.visit_i32_load_u16(offset),
            Instr::I64Load8S(offset) => self.visit_i64_load_i8(offset),
            Instr::I64Load8U(offset) => self.visit_i64_load_u8(offset),
            Instr::I64Load16S(offset) => self.visit_i64_load_i16(offset),
            Instr::I64Load16U(offset) => self.visit_i64_load_u16(offset),
            Instr::I64Load32S(offset) => self.visit_i64_load_i32(offset),
            Instr::I64Load32U(offset) => self.visit_i64_load_u32(offset),
            Instr::I32Store(offset) => self.visit_i32_store(offset),
            Instr::I64Store(offset) => self.visit_i64_store(offset),
            Instr::F32Store(offset) => self.visit_f32_store(offset),
            Instr::F64Store(offset) => self.visit_f64_store(offset),
            Instr::I32Store8(offset) => self.visit_i32_store_8(offset),
            Instr::I32Store16(offset) => self.visit_i32_store_16(offset),
            Instr::I64Store8(offset) => self.visit_i64_store_8(offset),
            Instr::I64Store16(offset) => self.visit_i64_store_16(offset),
            Instr::I64Store32(offset) => self.visit_i64_store_32(offset),
            Instr::MemorySize => self.visit_current_memory(),
            Instr::MemoryGrow => self.visit_grow_memory(),
            // TODO
            _ => Err(ExecError::UnsupportedOSP),
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

    // TODO: still need to design.
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
        let root = proof
            .prove_data
            .compute_root(func_index as usize, leaf_hash);

        if root != *table_root {
            Err(ExecError::TableRootsNotMatch)
        } else {
            Ok(())
        }
        // TODO: need to design
    }

    // TODO: still need to design.
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

                // prove old globals root before using global value.
                let globals_root = proof.prove_data.compute_root(idx, leaf_hash);
                if globals_root != self.globals_root {
                    return Err(ExecError::GlobalsRootNotMatch);
                }

                if is_set {
                    let global = self
                        .value_stack
                        .pop()
                        .ok_or(ExecError::InsufficientValueStack)?;
                    let leaf_hash = value_hash(global);
                    // update globals root
                    self.globals_root = proof.prove_data.compute_root(idx, leaf_hash)
                } else {
                    self.value_stack.push(global);
                }
                Ok(())
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
    fn visit_ret(&mut self, drop_keep: DropKeep) -> Result<()> {
        self.ret(drop_keep)
    }

    #[inline]
    fn drop_keep(&mut self, drop_keep: DropKeep) -> Result<()> {
        self.value_stack
            .drop_keep(drop_keep)
            .ok_or(ExecError::ValueStackTooShortForDropKeep)
    }

    fn ret(&mut self, drop_keep: DropKeep) -> Result<()> {
        self.drop_keep(drop_keep)?;
        let frame = self
            .call_stack
            .pop()
            .ok_or(ExecError::InsufficientCallStack)?;
        self.set_pc(frame.pc);
        Ok(())
    }

    fn visit_drop(&mut self) -> Result<()> {
        let _ = self.pop_value_stack_as::<UntypedValue>()?;
        self.next_pc();
        Ok(())
    }

    fn visit_select(&mut self) -> Result<()> {
        self.value_stack
            .pop2_eval(|e1, e2, e3| {
                let condition = <bool as From<UntypedValue>>::from(e3);
                let result = if condition { *e1 } else { e2 };
                *e1 = result;
            })
            .ok_or(ExecError::InsufficientValueStack)?;

        self.next_pc();
        Ok(())
    }

    #[inline]
    fn visit_unreachable(&mut self) -> Result<()> {
        self.status = InstructionStatus::Trapped;
        // pc not changed
        Ok(())
    }

    /// Calculates the effective address of a linear memory access.
    ///
    /// # Errors
    ///
    /// If the resulting effective address overflows.
    fn effective_address(offset: Offset, address: u32) -> result::Result<usize, TrapCode> {
        offset
            .into_inner()
            .checked_add(address)
            .map(|address| address as usize)
            .ok_or(TrapCode::MemoryAccessOutOfBounds)
    }

    fn ensure_same_memory(&self, memory_root: Bytes32) -> Result<()> {
        Self::ensure_same_root(self.memory_roots[0], memory_root)
    }

    fn ensure_same_root(root1: Bytes32, root2: Bytes32) -> Result<()> {
        if root1 != root2 {
            return Err(ExecError::IllegalExtraProof);
        }
        Ok(())
    }

    // TODO: reduce this code.
    /// Loads a value of type `T` from the default memory at the given address offset.
    ///
    /// # Note
    ///
    /// This can be used to emulate the following Wasm operands:
    ///
    /// - `i32.load`
    /// - `i64.load`
    /// - `f32.load`
    /// - `f64.load`
    fn execute_load<T>(&mut self, offset: Offset) -> Result<()>
    where
        UntypedValue: From<T>,
        T: LittleEndianConvert,
    {
        let address = self.pop_value_stack_as::<u32>()?;
        let address = match Self::effective_address(offset, address) {
            Ok(address) => address,
            Err(_trap) => {
                // TODO: redesign this style ?
                self.status = InstructionStatus::Trapped;
                return Ok(());
            }
        };

        let value = match &self.extra {
            ExtraProof::MemoryChunkNeighbor(proof) => {
                let root = proof
                    .compute_root(address)
                    .ok_or(ExecError::IllegalExtraProof)?;
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let mut bytes = <<T as LittleEndianConvert>::Bytes as Default>::default();
                proof.read(address, bytes.as_mut());
                let value = <T as LittleEndianConvert>::from_le_bytes(bytes);

                value
            }

            ExtraProof::MemoryChunkSibling(proof) => {
                let root = proof.compute_root(address);
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let mut bytes = <<T as LittleEndianConvert>::Bytes as Default>::default();
                proof.read(address, bytes.as_mut());
                let value = <T as LittleEndianConvert>::from_le_bytes(bytes);

                value
            }
            _ => return Err(ExecError::IllegalExtraProof),
        };

        self.value_stack.push(value);
        self.next_pc();

        Ok(())
    }

    /// Loads a value of type `U` from the default memory at the given address offset and extends it into `T`.
    ///
    /// # Note
    ///
    /// This can be used to emulate the following Wasm operands:
    ///
    /// - `i32.load_8s`
    /// - `i32.load_8u`
    /// - `i32.load_16s`
    /// - `i32.load_16u`
    /// - `i64.load_8s`
    /// - `i64.load_8u`
    /// - `i64.load_16s`
    /// - `i64.load_16u`
    /// - `i64.load_32s`
    /// - `i64.load_32u`
    fn execute_load_extend<T, U>(&mut self, offset: Offset) -> Result<()>
    where
        T: ExtendInto<U> + LittleEndianConvert,
        UntypedValue: From<U>,
    {
        let address = self.pop_value_stack_as::<u32>()?;
        let address = match Self::effective_address(offset, address) {
            Ok(address) => address,
            Err(_trap) => {
                self.status = InstructionStatus::Trapped;
                return Ok(());
            }
        };

        let value = match &self.extra {
            ExtraProof::MemoryChunkNeighbor(proof) => {
                let root = proof
                    .compute_root(address)
                    .ok_or(ExecError::IllegalExtraProof)?;
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let mut bytes = <<T as LittleEndianConvert>::Bytes as Default>::default();
                proof.read(address, bytes.as_mut());
                let value = <T as LittleEndianConvert>::from_le_bytes(bytes).extend_into();

                value
            }

            ExtraProof::MemoryChunkSibling(proof) => {
                let root = proof.compute_root(address);
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let mut bytes = <<T as LittleEndianConvert>::Bytes as Default>::default();
                proof.read(address, bytes.as_mut());
                let value = <T as LittleEndianConvert>::from_le_bytes(bytes).extend_into();

                value
            }
            _ => return Err(ExecError::IllegalExtraProof),
        };

        self.value_stack.push(value);
        self.next_pc();

        Ok(())
    }

    /// Stores a value of type `T` into the default memory at the given address offset.
    ///
    /// # Note
    ///
    /// This can be used to emulate the following Wasm operands:
    ///
    /// - `i32.store`
    /// - `i64.store`
    /// - `f32.store`
    /// - `f64.store`
    fn execute_store<T>(&mut self, offset: Offset) -> Result<()>
    where
        T: LittleEndianConvert + From<UntypedValue>,
    {
        let (address, value) = self
            .value_stack
            .pop2()
            .ok_or(ExecError::InsufficientValueStack)?;
        let value = T::from(value);
        let address = u32::from(address);
        let address = match Self::effective_address(offset, address) {
            Ok(address) => address,
            Err(_trap) => {
                self.status = InstructionStatus::Trapped;
                return Ok(());
            }
        };

        let memory_root = match &mut self.extra {
            ExtraProof::MemoryChunkNeighbor(proof) => {
                let memory_root = proof
                    .compute_root(address)
                    .ok_or(ExecError::IllegalExtraProof)?;
                // prove memory before use it.
                Self::ensure_same_root(self.memory_roots[0], memory_root)?;

                let bytes = <T as LittleEndianConvert>::into_le_bytes(value);
                proof.write(address, bytes.as_ref());

                proof.compute_root(address).expect("Checked before; qed")
            }

            ExtraProof::MemoryChunkSibling(proof) => {
                let memory_root = proof.compute_root(address);
                // prove memory before use it.
                Self::ensure_same_root(self.memory_roots[0], memory_root)?;

                let bytes = <T as LittleEndianConvert>::into_le_bytes(value);
                proof.write(address, bytes.as_ref());

                proof.compute_root(address)
            }
            _ => return Err(ExecError::IllegalExtraProof),
        };

        self.memory_roots[0] = memory_root;
        self.next_pc();

        Ok(())
    }

    /// Stores a value of type `T` wrapped to type `U` into the default memory at the given address offset.
    ///
    /// # Note
    ///
    /// This can be used to emulate the following Wasm operands:
    ///
    /// - `i32.store8`
    /// - `i32.store16`
    /// - `i64.store8`
    /// - `i64.store16`
    /// - `i64.store32`
    fn execute_store_wrap<T, U>(&mut self, offset: Offset) -> Result<()>
    where
        T: WrapInto<U> + From<UntypedValue>,
        U: LittleEndianConvert,
    {
        let (address, value) = self
            .value_stack
            .pop2()
            .ok_or(ExecError::InsufficientValueStack)?;
        let value = T::from(value).wrap_into();
        let address = u32::from(address);
        let address = match Self::effective_address(offset, address) {
            Ok(address) => address,
            Err(_trap) => {
                self.status = InstructionStatus::Trapped;
                return Ok(());
            }
        };

        let memory_root = match &mut self.extra {
            ExtraProof::MemoryChunkNeighbor(proof) => {
                let memory_root = proof
                    .compute_root(address)
                    .ok_or(ExecError::IllegalExtraProof)?;
                // prove memory before use it.
                Self::ensure_same_root(self.memory_roots[0], memory_root)?;

                let bytes = <U as LittleEndianConvert>::into_le_bytes(value);
                proof.write(address, bytes.as_ref());
                proof.compute_root(address).expect("Checked before; qed")
            }

            ExtraProof::MemoryChunkSibling(proof) => {
                let memory_root = proof.compute_root(address);
                // prove memory before use it.
                Self::ensure_same_root(self.memory_roots[0], memory_root)?;

                let bytes = <U as LittleEndianConvert>::into_le_bytes(value);
                proof.write(address, bytes.as_ref());

                proof.compute_root(address)
            }
            _ => return Err(ExecError::IllegalExtraProof),
        };

        self.memory_roots[0] = memory_root;
        self.next_pc();
        Ok(())
    }

    fn visit_i32_load(&mut self, offset: Offset) -> Result<()> {
        self.execute_load::<i32>(offset)
    }

    fn visit_i64_load(&mut self, offset: Offset) -> Result<()> {
        self.execute_load::<i64>(offset)
    }

    fn visit_f32_load(&mut self, offset: Offset) -> Result<()> {
        self.execute_load::<F32>(offset)
    }

    fn visit_f64_load(&mut self, offset: Offset) -> Result<()> {
        self.execute_load::<F64>(offset)
    }

    fn visit_i32_load_i8(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<i8, i32>(offset)
    }

    fn visit_i32_load_u8(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<u8, i32>(offset)
    }

    fn visit_i32_load_i16(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<i16, i32>(offset)
    }

    fn visit_i32_load_u16(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<u16, i32>(offset)
    }

    fn visit_i64_load_i8(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<i8, i64>(offset)
    }

    fn visit_i64_load_u8(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<u8, i64>(offset)
    }

    fn visit_i64_load_i16(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<i16, i64>(offset)
    }

    fn visit_i64_load_u16(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<u16, i64>(offset)
    }

    fn visit_i64_load_i32(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<i32, i64>(offset)
    }

    fn visit_i64_load_u32(&mut self, offset: Offset) -> Result<()> {
        self.execute_load_extend::<u32, i64>(offset)
    }

    fn visit_i32_store(&mut self, offset: Offset) -> Result<()> {
        self.execute_store::<i32>(offset)
    }

    fn visit_i64_store(&mut self, offset: Offset) -> Result<()> {
        self.execute_store::<i64>(offset)
    }

    fn visit_f32_store(&mut self, offset: Offset) -> Result<()> {
        self.execute_store::<F32>(offset)
    }

    fn visit_f64_store(&mut self, offset: Offset) -> Result<()> {
        self.execute_store::<F64>(offset)
    }

    fn visit_i32_store_8(&mut self, offset: Offset) -> Result<()> {
        self.execute_store_wrap::<i32, i8>(offset)
    }

    fn visit_i32_store_16(&mut self, offset: Offset) -> Result<()> {
        self.execute_store_wrap::<i32, i16>(offset)
    }

    fn visit_i64_store_8(&mut self, offset: Offset) -> Result<()> {
        self.execute_store_wrap::<i64, i8>(offset)
    }

    fn visit_i64_store_16(&mut self, offset: Offset) -> Result<()> {
        self.execute_store_wrap::<i64, i16>(offset)
    }

    fn visit_i64_store_32(&mut self, offset: Offset) -> Result<()> {
        self.execute_store_wrap::<i64, i32>(offset)
    }

    fn visit_current_memory(&mut self) -> Result<()> {
        let val = match &self.extra {
            ExtraProof::MemoryPage(page) => page.current_pages,
            _ => return Err(ExecError::IllegalExtraProof),
        };
        self.value_stack.push(val);
        self.next_pc();

        Ok(())
    }

    fn visit_grow_memory(&mut self) -> Result<()> {
        /// The WebAssembly spec demands to return `0xFFFF_FFFF`
        /// in case of failure for the `memory.grow` instruction.
        const ERR_VALUE: u32 = u32::MAX;

        let (current, max) = match &self.extra {
            ExtraProof::MemoryPage(page) => {
                (page.current_pages, page.maximum_pages.unwrap_or(u32::MAX))
            }
            _ => return Err(ExecError::IllegalExtraProof),
        };
        let additional = self.pop_value_stack_as()?;
        let result = if additional > MAX_PAGE_SIZE as u32 {
            ERR_VALUE
        } else {
            match current.checked_add(additional) {
                Some(new) if new <= max => new,
                _ => ERR_VALUE,
            }
        };

        self.value_stack.push(result);
        self.next_pc();

        Ok(())
    }
}

pub const MAX_PAGE_SIZE: usize = 65536;
