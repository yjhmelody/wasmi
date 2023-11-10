use core::{cmp, fmt, result};

use accel_merkle::{MerkleConfig, OutputOf, ProveData};
use wasmi_core::{ExtendInto, LittleEndianConvert, UntypedValue, WrapInto};

use super::super::{
    bytecode::{BranchParams, FuncIdx, GlobalIdx, Instruction, LocalDepth, Offset, SignatureIdx},
    DropKeep,
};
use crate::{
    core::{TrapCode, F32, F64},
    proof::{
        value_hash,
        CallProof,
        CallStackProof,
        CodeProof,
        ExtraProof,
        FuncNode,
        OspProof,
        Status,
        ValueStackProof,
        WasmFuncHeader,
    },
    snapshot::FuncFrameSnapshot,
};

/// As mandated by the WebAssembly specification every linear memory page
/// has exactly 2^16 (65536) bytes.
pub const MAX_PAGE_SIZE: u32 = 65536;

/// The result type of [`ExecError`].
pub type Result<T> = result::Result<T, ExecError>;

/// All execution error means this prove data is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecError {
    GlobalsRootNotExist,
    FuncRootNotMatch,
    GlobalsRootNotMatch,
    DefaultTableNotFound,
    MemoryRootNotMatch,
    MemoryRootsNotExist,
    EmptyValueStack,
    InsufficientValueStack,
    ValueStackTooShortForDropKeep,
    BranchToIllegalPc,
    IllegalInstruction,
    IllegalExtraProof,
    IllegalMemoryTwoChunks,
    IllegalMemoryChunk,
}

#[cfg(feature = "std")]
impl std::error::Error for ExecError {}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExecError::GlobalsRootNotExist => write!(f, "globals root not exist"),
            ExecError::FuncRootNotMatch => write!(f, "func root not match"),
            ExecError::GlobalsRootNotMatch => write!(f, "globals root not match"),
            ExecError::MemoryRootNotMatch => write!(f, "memory root not match"),
            ExecError::MemoryRootsNotExist => write!(f, "memory roots not match"),
            ExecError::EmptyValueStack => write!(f, "value stack is empty"),
            ExecError::InsufficientValueStack => write!(f, "value stack is insufficient"),
            ExecError::ValueStackTooShortForDropKeep => {
                write!(f, "value stack is insufficient for branch/return")
            }
            ExecError::BranchToIllegalPc => write!(f, "jump to an illegal pc"),
            ExecError::IllegalInstruction => write!(f, "meet illegal instruction"),
            ExecError::IllegalExtraProof => write!(f, "the extra proof is illegal"),
            ExecError::IllegalMemoryChunk => write!(f, "memory chunk extra proof is illegal"),
            ExecError::IllegalMemoryTwoChunks => {
                write!(f, "memory two chunks extra proof is illegal")
            }
            ExecError::DefaultTableNotFound => {
                write!(f, "default table not exist(for call_indirect)")
            }
        }
    }
}

impl<Config> OspProof<Config>
where
    Config: MerkleConfig,
{
    /// Creates an osp executor to run one step proof data.
    pub(crate) fn executor<'a>(
        &'a mut self,
        code_proof: &'a CodeProof<Config::Hasher>,
    ) -> OspExecutor<'a, Config> {
        OspExecutor::<Config> {
            call_stack: &mut self.engine_proof.call_stack,
            value_stack: &mut self.engine_proof.value_stack,

            inst_root: &code_proof.inst_root,
            func_root: &code_proof.func_root,
            globals_root: &mut self.globals_root,
            table_roots: &self.table_roots,
            memory_roots: &mut self.memory_roots,
            status: &mut self.status,

            current_pc: &mut self.inst_proof.current_pc,
            inst: self.inst_proof.inst,
            inst_prove: &self.inst_proof.inst_prove,
            extra: &self.inst_proof.extra,
        }
    }

    /// Run one step according to its proof state.
    ///
    /// This will transform proof state to a new state.
    ///
    /// # Error
    ///
    /// unexpected proof data or state.
    pub fn run(&mut self, code_proof: &CodeProof<Config::Hasher>) -> Result<()> {
        self.executor(code_proof).execute()
    }
}

/// One instruction executor used for OSP.
pub(crate) struct OspExecutor<'a, Config>
where
    Config: MerkleConfig,
{
    status: &'a mut Status,
    call_stack: &'a mut CallStackProof<Config::Hasher>,
    value_stack: &'a mut ValueStackProof<Config::Hasher>,

    inst_root: &'a OutputOf<Config>,
    func_root: &'a OutputOf<Config>,
    globals_root: &'a mut Option<OutputOf<Config>>,
    table_roots: &'a [OutputOf<Config>],
    memory_roots: &'a mut [OutputOf<Config>],

    current_pc: &'a mut u32,
    inst: Instruction,
    inst_prove: &'a ProveData<Config::Hasher>,
    extra: &'a ExtraProof<Config>,
}

impl<'a, Config: MerkleConfig> OspExecutor<'a, Config> {
    pub fn execute(&mut self) -> Result<()> {
        use Instruction as Instr;
        // pre-checks
        self.prove_inst()?;

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
            Instr::Const(bytes) => self.visit_const(bytes),
            Instr::I32Eqz => self.visit_i32_eqz(),
            Instr::I32Eq => self.visit_i32_eq(),
            Instr::I32Ne => self.visit_i32_ne(),
            Instr::I32LtS => self.visit_i32_lt_s(),
            Instr::I32LtU => self.visit_i32_lt_u(),
            Instr::I32GtS => self.visit_i32_gt_s(),
            Instr::I32GtU => self.visit_i32_gt_u(),
            Instr::I32LeS => self.visit_i32_le_s(),
            Instr::I32LeU => self.visit_i32_le_u(),
            Instr::I32GeS => self.visit_i32_ge_s(),
            Instr::I32GeU => self.visit_i32_ge_u(),
            Instr::I64Eqz => self.visit_i64_eqz(),
            Instr::I64Eq => self.visit_i64_eq(),
            Instr::I64Ne => self.visit_i64_ne(),
            Instr::I64LtS => self.visit_i64_lt_s(),
            Instr::I64LtU => self.visit_i64_lt_u(),
            Instr::I64GtS => self.visit_i64_gt_s(),
            Instr::I64GtU => self.visit_i64_gt_u(),
            Instr::I64LeS => self.visit_i64_le_s(),
            Instr::I64LeU => self.visit_i64_le_u(),
            Instr::I64GeS => self.visit_i64_ge_s(),
            Instr::I64GeU => self.visit_i64_ge_u(),
            Instr::F32Eq => self.visit_f32_eq(),
            Instr::F32Ne => self.visit_f32_ne(),
            Instr::F32Lt => self.visit_f32_lt(),
            Instr::F32Gt => self.visit_f32_gt(),
            Instr::F32Le => self.visit_f32_le(),
            Instr::F32Ge => self.visit_f32_ge(),
            Instr::F64Eq => self.visit_f64_eq(),
            Instr::F64Ne => self.visit_f64_ne(),
            Instr::F64Lt => self.visit_f64_lt(),
            Instr::F64Gt => self.visit_f64_gt(),
            Instr::F64Le => self.visit_f64_le(),
            Instr::F64Ge => self.visit_f64_ge(),
            Instr::I32Clz => self.visit_i32_clz(),
            Instr::I32Ctz => self.visit_i32_ctz(),
            Instr::I32Popcnt => self.visit_i32_popcnt(),
            Instr::I32Add => self.visit_i32_add(),
            Instr::I32Sub => self.visit_i32_sub(),
            Instr::I32Mul => self.visit_i32_mul(),
            Instr::I32DivS => self.visit_i32_div_s(),
            Instr::I32DivU => self.visit_i32_div_u(),
            Instr::I32RemS => self.visit_i32_rem_s(),
            Instr::I32RemU => self.visit_i32_rem_u(),
            Instr::I32And => self.visit_i32_and(),
            Instr::I32Or => self.visit_i32_or(),
            Instr::I32Xor => self.visit_i32_xor(),
            Instr::I32Shl => self.visit_i32_shl(),
            Instr::I32ShrS => self.visit_i32_shr_s(),
            Instr::I32ShrU => self.visit_i32_shr_u(),
            Instr::I32Rotl => self.visit_i32_rotl(),
            Instr::I32Rotr => self.visit_i32_rotr(),
            Instr::I64Clz => self.visit_i64_clz(),
            Instr::I64Ctz => self.visit_i64_ctz(),
            Instr::I64Popcnt => self.visit_i64_popcnt(),
            Instr::I64Add => self.visit_i64_add(),
            Instr::I64Sub => self.visit_i64_sub(),
            Instr::I64Mul => self.visit_i64_mul(),
            Instr::I64DivS => self.visit_i64_div_s(),
            Instr::I64DivU => self.visit_i64_div_u(),
            Instr::I64RemS => self.visit_i64_rem_s(),
            Instr::I64RemU => self.visit_i64_rem_u(),
            Instr::I64And => self.visit_i64_and(),
            Instr::I64Or => self.visit_i64_or(),
            Instr::I64Xor => self.visit_i64_xor(),
            Instr::I64Shl => self.visit_i64_shl(),
            Instr::I64ShrS => self.visit_i64_shr_s(),
            Instr::I64ShrU => self.visit_i64_shr_u(),
            Instr::I64Rotl => self.visit_i64_rotl(),
            Instr::I64Rotr => self.visit_i64_rotr(),
            Instr::F32Abs => self.visit_f32_abs(),
            Instr::F32Neg => self.visit_f32_neg(),
            Instr::F32Ceil => self.visit_f32_ceil(),
            Instr::F32Floor => self.visit_f32_floor(),
            Instr::F32Trunc => self.visit_f32_trunc(),
            Instr::F32Nearest => self.visit_f32_nearest(),
            Instr::F32Sqrt => self.visit_f32_sqrt(),
            Instr::F32Add => self.visit_f32_add(),
            Instr::F32Sub => self.visit_f32_sub(),
            Instr::F32Mul => self.visit_f32_mul(),
            Instr::F32Div => self.visit_f32_div(),
            Instr::F32Min => self.visit_f32_min(),
            Instr::F32Max => self.visit_f32_max(),
            Instr::F32Copysign => self.visit_f32_copysign(),
            Instr::F64Abs => self.visit_f64_abs(),
            Instr::F64Neg => self.visit_f64_neg(),
            Instr::F64Ceil => self.visit_f64_ceil(),
            Instr::F64Floor => self.visit_f64_floor(),
            Instr::F64Trunc => self.visit_f64_trunc(),
            Instr::F64Nearest => self.visit_f64_nearest(),
            Instr::F64Sqrt => self.visit_f64_sqrt(),
            Instr::F64Add => self.visit_f64_add(),
            Instr::F64Sub => self.visit_f64_sub(),
            Instr::F64Mul => self.visit_f64_mul(),
            Instr::F64Div => self.visit_f64_div(),
            Instr::F64Min => self.visit_f64_min(),
            Instr::F64Max => self.visit_f64_max(),
            Instr::F64Copysign => self.visit_f64_copysign(),
            Instr::I32WrapI64 => self.visit_i32_wrap_i64(),
            Instr::I32TruncF32S => self.visit_i32_trunc_f32(),
            Instr::I32TruncF32U => self.visit_u32_trunc_f32(),
            Instr::I32TruncF64S => self.visit_i32_trunc_f64(),
            Instr::I32TruncF64U => self.visit_u32_trunc_f64(),
            Instr::I64ExtendI32S => self.visit_i64_extend_i32(),
            Instr::I64ExtendI32U => self.visit_i64_extend_u32(),
            Instr::I64TruncF32S => self.visit_i64_trunc_f32(),
            Instr::I64TruncF32U => self.visit_u64_trunc_f32(),
            Instr::I64TruncF64S => self.visit_i64_trunc_f64(),
            Instr::I64TruncF64U => self.visit_u64_trunc_f64(),
            Instr::F32ConvertI32S => self.visit_f32_convert_i32(),
            Instr::F32ConvertI32U => self.visit_f32_convert_u32(),
            Instr::F32ConvertI64S => self.visit_f32_convert_i64(),
            Instr::F32ConvertI64U => self.visit_f32_convert_u64(),
            Instr::F32DemoteF64 => self.visit_f32_demote_f64(),
            Instr::F64ConvertI32S => self.visit_f64_convert_i32(),
            Instr::F64ConvertI32U => self.visit_f64_convert_u32(),
            Instr::F64ConvertI64S => self.visit_f64_convert_i64(),
            Instr::F64ConvertI64U => self.visit_f64_convert_u64(),
            Instr::F64PromoteF32 => self.visit_f64_promote_f32(),
            Instr::I32TruncSatF32S => self.visit_i32_trunc_sat_f32(),
            Instr::I32TruncSatF32U => self.visit_u32_trunc_sat_f32(),
            Instr::I32TruncSatF64S => self.visit_i32_trunc_sat_f64(),
            Instr::I32TruncSatF64U => self.visit_u32_trunc_sat_f64(),
            Instr::I64TruncSatF32S => self.visit_i64_trunc_sat_f32(),
            Instr::I64TruncSatF32U => self.visit_u64_trunc_sat_f32(),
            Instr::I64TruncSatF64S => self.visit_i64_trunc_sat_f64(),
            Instr::I64TruncSatF64U => self.visit_u64_trunc_sat_f64(),
            Instr::I32Extend8S => self.visit_i32_sign_extend8(),
            Instr::I32Extend16S => self.visit_i32_sign_extend16(),
            Instr::I64Extend8S => self.visit_i64_sign_extend8(),
            Instr::I64Extend16S => self.visit_i64_sign_extend16(),
            Instr::I64Extend32S => self.visit_i64_sign_extend32(),
        }
    }

    fn prove_inst(&mut self) -> Result<()> {
        let inst_hash = self.inst.hash::<Config::Hasher>();
        let inst_root = self.inst_prove.compute_root(self.pc() as usize, inst_hash);
        if inst_root != *self.inst_root {
            Err(ExecError::IllegalInstruction)
        } else {
            Ok(())
        }
    }

    #[inline]
    fn next_pc(&mut self) {
        *self.current_pc += 1;
    }

    #[inline]
    fn pc(&self) -> u32 {
        *self.current_pc
    }

    #[inline]
    fn set_trapped(&mut self) -> Result<()> {
        *self.status = Status::Trapped;
        Ok(())
    }

    #[inline]
    fn set_pc(&mut self, pc: u32) {
        *self.current_pc = pc;
    }

    fn visit_local_get(&mut self, local_depth: LocalDepth) -> Result<()> {
        let value = *self
            .value_stack
            .peek(local_depth.into_inner())
            .ok_or(ExecError::InsufficientValueStack)?;
        self.value_stack.push(value);
        self.next_pc();
        Ok(())
    }

    fn visit_local_set(&mut self, local_depth: LocalDepth) -> Result<()> {
        let new_value = self.value_stack.pop().ok_or(ExecError::EmptyValueStack)?;
        let local = self
            .value_stack
            .peek_mut(local_depth.into_inner())
            .ok_or(ExecError::InsufficientValueStack)?;
        *local = new_value;

        self.next_pc();
        Ok(())
    }

    fn visit_local_tee(&mut self, local_depth: LocalDepth) -> Result<()> {
        let new_value = *self.value_stack.last().ok_or(ExecError::EmptyValueStack)?;
        let local = self
            .value_stack
            .peek_mut(local_depth.into_inner())
            .ok_or(ExecError::InsufficientValueStack)?;
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
        let max_index = (len_targets as u32)
            .checked_sub(1)
            .ok_or(ExecError::IllegalInstruction)?;
        // A normalized index will always yield a target without panicking.
        let normalized_index = cmp::min(index, max_index);
        let new_pc = self
            .pc()
            .checked_add(normalized_index)
            .and_then(|pc| pc.checked_add(1))
            .ok_or(ExecError::BranchToIllegalPc)?;

        self.set_pc(new_pc);
        Ok(())
    }

    fn visit_call(&mut self, func_index: FuncIdx) -> Result<()> {
        let func_index = func_index.into_inner();
        let pc = self.pc();
        // push current frame pc
        self.call_stack.push(FuncFrameSnapshot::from(pc + 1));

        match &self.extra {
            ExtraProof::CallWasm(proof) => {
                let header = Self::get_func_header_from_call_proof(proof)?;
                self.ensure_call_proof(func_index, proof)?;
                // update the current frame pc.
                self.set_pc(header.pc);
                // fulfill local vars.
                self.value_stack.extend_zeros(header.len_locals as usize);
                Ok(())
            }
            _ => Err(ExecError::IllegalExtraProof),
        }
    }

    fn visit_call_indirect(&mut self, _signature_index: SignatureIdx) -> Result<()> {
        let func_index = self.pop_value_stack_as::<u32>()?;
        let pc = self.pc();
        // push current frame pc
        self.call_stack.push(FuncFrameSnapshot::from(pc + 1));

        match &self.extra {
            ExtraProof::CallIndirectWasm(proof) => {
                let header = Self::get_func_header_from_call_proof(proof)?;
                self.ensure_call_indirect_proof(func_index, proof)?;
                // update the current frame pc.
                self.set_pc(header.pc);
                // fulfill local vars.
                self.value_stack.extend_zeros(header.len_locals as usize);
                Ok(())
            }
            _ => Err(ExecError::IllegalExtraProof),
        }
    }

    fn ensure_call_proof(&self, func_index: u32, proof: &CallProof<Config::Hasher>) -> Result<()> {
        let leaf_hash = proof.func.hash::<Config::Hasher>();
        let root = proof
            .prove_data
            .compute_root(func_index as usize, leaf_hash);

        if root != *self.func_root {
            Err(ExecError::FuncRootNotMatch)
        } else {
            Ok(())
        }
    }

    // We do not allow indirect instruction meet trap here, since it's useless.
    fn ensure_call_indirect_proof(
        &self,
        _func_index: u32,
        _proof: &CallProof<Config::Hasher>,
    ) -> Result<()> {
        self.table_roots
            .first()
            .ok_or(ExecError::DefaultTableNotFound)?;

        Ok(())
    }

    fn get_func_header_from_call_proof(
        proof: &CallProof<Config::Hasher>,
    ) -> Result<&WasmFuncHeader> {
        match &proof.func {
            FuncNode::Host(..) => Err(ExecError::IllegalExtraProof),
            FuncNode::Wasm(header) => Ok(header),
        }
    }

    fn visit_global_get(&mut self, global_index: GlobalIdx) -> Result<()> {
        self.visit_global_set_get(global_index, false)?;

        self.next_pc();
        Ok(())
    }

    fn visit_global_set(&mut self, global_index: GlobalIdx) -> Result<()> {
        self.visit_global_set_get(global_index, true)?;

        self.next_pc();
        Ok(())
    }

    fn visit_global_set_get(&mut self, global_index: GlobalIdx, is_set: bool) -> Result<()> {
        let cur_globals_root = self
            .globals_root
            .as_mut()
            .ok_or(ExecError::GlobalsRootNotExist)?;
        match &self.extra {
            ExtraProof::GlobalGetSet(proof) => {
                let idx = global_index.into_inner() as usize;
                let global = proof.value;
                let leaf_hash = value_hash::<Config::Hasher>(global);

                let globals_root = proof.prove_data.compute_root(idx, leaf_hash);
                if globals_root != *cur_globals_root {
                    return Err(ExecError::GlobalsRootNotMatch);
                }

                if is_set {
                    let global = self
                        .value_stack
                        .pop()
                        .ok_or(ExecError::InsufficientValueStack)?;
                    let leaf_hash = value_hash::<Config::Hasher>(global);
                    // update globals root
                    *cur_globals_root = proof.prove_data.compute_root(idx, leaf_hash)
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
        let frame = self.call_stack.pop();

        // Note: when the last instruction is return opcode, there is no frame in call stack anymore.
        if let Some(frame) = frame {
            self.set_pc(frame.pc);
        }

        Ok(())
    }

    fn visit_drop(&mut self) -> Result<()> {
        let _ = self.pop_value_stack_as::<UntypedValue>()?;
        self.next_pc();
        Ok(())
    }

    fn visit_select(&mut self) -> Result<()> {
        self.value_stack
            .eval_top3(|e1, e2, e3| {
                let condition = <bool as From<UntypedValue>>::from(e3);
                if condition {
                    e1
                } else {
                    e2
                }
            })
            .ok_or(ExecError::InsufficientValueStack)?;

        self.next_pc();
        Ok(())
    }

    #[inline]
    fn visit_unreachable(&mut self) -> Result<()> {
        // pc not changed
        self.set_trapped()
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
            .ok_or(TrapCode::MemoryOutOfBounds)
    }

    #[inline]
    fn ensure_same_memory(&self, memory_root: OutputOf<Config>) -> Result<()> {
        Self::ensure_same_root(Self::default_memory_root(self.memory_roots)?, &memory_root)
            .map_err(|_e| ExecError::MemoryRootNotMatch)
    }

    #[inline]
    fn ensure_same_root(root1: &OutputOf<Config>, root2: &OutputOf<Config>) -> Result<()> {
        if root1 != root2 {
            return Err(ExecError::IllegalExtraProof);
        }
        Ok(())
    }

    fn default_memory_root(memory_roots: &[OutputOf<Config>]) -> Result<&OutputOf<Config>> {
        memory_roots.first().ok_or(ExecError::MemoryRootsNotExist)
    }

    /// # Note
    ///
    /// The first(default) memory root must exist.
    #[inline]
    fn update_default_memory(&mut self, memory_root: OutputOf<Config>) {
        self.memory_roots[0] = memory_root;
    }

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
    #[inline]
    fn execute_load<T>(&mut self, offset: Offset) -> Result<()>
    where
        T: ExtendInto<T> + LittleEndianConvert,
        UntypedValue: From<T>,
    {
        self.execute_load_extend::<T, T>(offset)
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
            Err(_trap) => return self.set_trapped(),
        };

        let value = match &self.extra {
            ExtraProof::MemoryTwoChunks(proof) => {
                let root = proof
                    .compute_root(address)
                    .ok_or(ExecError::IllegalMemoryTwoChunks)?;
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let mut bytes = <<T as LittleEndianConvert>::Bytes as Default>::default();
                proof.read(address, bytes.as_mut());

                <T as LittleEndianConvert>::from_le_bytes(bytes).extend_into()
            }

            ExtraProof::MemoryChunkSibling(proof) => {
                let root = proof.compute_root(address);
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let mut bytes = <<T as LittleEndianConvert>::Bytes as Default>::default();
                proof.read(address, bytes.as_mut());

                <T as LittleEndianConvert>::from_le_bytes(bytes).extend_into()
            }

            ExtraProof::MemoryChunk(proof) => {
                let root = proof.compute_root(address);
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let mut bytes = <<T as LittleEndianConvert>::Bytes as Default>::default();
                proof
                    .read(address, bytes.as_mut())
                    .ok_or(ExecError::IllegalMemoryChunk)?;

                <T as LittleEndianConvert>::from_le_bytes(bytes).extend_into()
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
    #[inline]
    fn execute_store<T>(&mut self, offset: Offset) -> Result<()>
    where
        T: LittleEndianConvert + WrapInto<T> + From<UntypedValue>,
    {
        self.execute_store_wrap::<T, T>(offset)
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
            Err(_trap) => return self.set_trapped(),
        };

        let memory_root = match &self.extra {
            ExtraProof::MemoryTwoChunks(proof) => {
                let root = proof
                    .compute_root(address)
                    .ok_or(ExecError::IllegalMemoryTwoChunks)?;
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let bytes = <U as LittleEndianConvert>::into_le_bytes(value);
                let mut proof = proof.clone();
                proof.write(address, bytes.as_ref());

                proof.recompute_root(address)
            }

            ExtraProof::MemoryChunkSibling(proof) => {
                let root = proof.compute_root(address);
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let bytes = <U as LittleEndianConvert>::into_le_bytes(value);
                let mut proof = proof.clone();
                proof.write(address, bytes.as_ref());

                proof.compute_root(address)
            }

            ExtraProof::MemoryChunk(proof) => {
                let root = proof.compute_root(address);
                // prove memory before use it.
                self.ensure_same_memory(root)?;

                let bytes = <U as LittleEndianConvert>::into_le_bytes(value);
                let mut proof = proof.clone();
                proof
                    .write(address, bytes.as_ref())
                    .ok_or(ExecError::IllegalMemoryChunk)?;

                proof.compute_root(address)
            }
            _ => return Err(ExecError::IllegalExtraProof),
        };

        self.update_default_memory(memory_root);
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
            ExtraProof::CurrentPage(page) => *page,
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

        let current = match &self.extra {
            ExtraProof::CurrentPage(page) => *page,
            _ => return Err(ExecError::IllegalExtraProof),
        };

        let additional = self.pop_value_stack_as()?;
        // return the origin page size if success
        let result = if additional > MAX_PAGE_SIZE {
            ERR_VALUE
        } else {
            match current.checked_add(additional) {
                Some(new) if new <= MAX_PAGE_SIZE => current,
                _ => ERR_VALUE,
            }
        };

        self.value_stack.push(result);
        self.next_pc();

        Ok(())
    }

    fn visit_const(&mut self, bytes: UntypedValue) -> Result<()> {
        self.value_stack.push(bytes);

        self.next_pc();
        Ok(())
    }

    fn execute_unary(&mut self, f: fn(UntypedValue) -> UntypedValue) -> Result<()> {
        self.value_stack
            .eval_top(f)
            .ok_or(ExecError::InsufficientValueStack)?;

        self.next_pc();
        Ok(())
    }

    fn try_execute_unary(
        &mut self,
        f: fn(UntypedValue) -> result::Result<UntypedValue, TrapCode>,
    ) -> Result<()> {
        let res = self
            .value_stack
            .try_eval_top(f)
            .ok_or(ExecError::InsufficientValueStack)?;

        if let Err(_trap) = res {
            return self.set_trapped();
        }

        self.next_pc();
        Ok(())
    }

    fn execute_binary(&mut self, f: fn(UntypedValue, UntypedValue) -> UntypedValue) -> Result<()> {
        self.value_stack.eval_top2(f);

        self.next_pc();
        Ok(())
    }

    fn try_execute_binary(
        &mut self,
        f: fn(UntypedValue, UntypedValue) -> result::Result<UntypedValue, TrapCode>,
    ) -> Result<()> {
        let res = self
            .value_stack
            .try_eval_top2(f)
            .ok_or(ExecError::InsufficientValueStack)?;

        if let Err(_trap) = res {
            return self.set_trapped();
        }

        self.next_pc();
        Ok(())
    }

    fn visit_i32_eqz(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_eqz)
    }

    fn visit_i32_eq(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_eq)
    }

    fn visit_i32_ne(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_ne)
    }

    fn visit_i32_lt_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_lt_s)
    }

    fn visit_i32_lt_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_lt_u)
    }

    fn visit_i32_gt_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_gt_s)
    }

    fn visit_i32_gt_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_gt_u)
    }

    fn visit_i32_le_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_le_s)
    }

    fn visit_i32_le_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_le_u)
    }

    fn visit_i32_ge_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_ge_s)
    }

    fn visit_i32_ge_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_ge_u)
    }

    fn visit_i64_eqz(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_eqz)
    }

    fn visit_i64_eq(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_eq)
    }

    fn visit_i64_ne(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_ne)
    }

    fn visit_i64_lt_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_lt_s)
    }

    fn visit_i64_lt_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_lt_u)
    }

    fn visit_i64_gt_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_gt_s)
    }

    fn visit_i64_gt_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_gt_u)
    }

    fn visit_i64_le_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_le_s)
    }

    fn visit_i64_le_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_le_u)
    }

    fn visit_i64_ge_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_ge_s)
    }

    fn visit_i64_ge_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_ge_u)
    }

    fn visit_f32_eq(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_eq)
    }

    fn visit_f32_ne(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_ne)
    }

    fn visit_f32_lt(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_lt)
    }

    fn visit_f32_gt(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_gt)
    }

    fn visit_f32_le(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_le)
    }

    fn visit_f32_ge(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_ge)
    }

    fn visit_f64_eq(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_eq)
    }

    fn visit_f64_ne(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_ne)
    }

    fn visit_f64_lt(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_lt)
    }

    fn visit_f64_gt(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_gt)
    }

    fn visit_f64_le(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_le)
    }

    fn visit_f64_ge(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_ge)
    }

    fn visit_i32_clz(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_clz)
    }

    fn visit_i32_ctz(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_ctz)
    }

    fn visit_i32_popcnt(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_popcnt)
    }

    fn visit_i32_add(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_add)
    }

    fn visit_i32_sub(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_sub)
    }

    fn visit_i32_mul(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_mul)
    }

    fn visit_i32_div_s(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i32_div_s)
    }

    fn visit_i32_div_u(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i32_div_u)
    }

    fn visit_i32_rem_s(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i32_rem_s)
    }

    fn visit_i32_rem_u(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i32_rem_u)
    }

    fn visit_i32_and(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_and)
    }

    fn visit_i32_or(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_or)
    }

    fn visit_i32_xor(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_xor)
    }

    fn visit_i32_shl(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_shl)
    }

    fn visit_i32_shr_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_shr_s)
    }

    fn visit_i32_shr_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_shr_u)
    }

    fn visit_i32_rotl(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_rotl)
    }

    fn visit_i32_rotr(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i32_rotr)
    }

    fn visit_i64_clz(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_clz)
    }

    fn visit_i64_ctz(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_ctz)
    }

    fn visit_i64_popcnt(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_popcnt)
    }

    fn visit_i64_add(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_add)
    }

    fn visit_i64_sub(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_sub)
    }

    fn visit_i64_mul(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_mul)
    }

    fn visit_i64_div_s(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i64_div_s)
    }

    fn visit_i64_div_u(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i64_div_u)
    }

    fn visit_i64_rem_s(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i64_rem_s)
    }

    fn visit_i64_rem_u(&mut self) -> Result<()> {
        self.try_execute_binary(UntypedValue::i64_rem_u)
    }

    fn visit_i64_and(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_and)
    }

    fn visit_i64_or(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_or)
    }

    fn visit_i64_xor(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_xor)
    }

    fn visit_i64_shl(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_shl)
    }

    fn visit_i64_shr_s(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_shr_s)
    }

    fn visit_i64_shr_u(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_shr_u)
    }

    fn visit_i64_rotl(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_rotl)
    }

    fn visit_i64_rotr(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::i64_rotr)
    }

    fn visit_f32_abs(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_abs)
    }

    fn visit_f32_neg(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_neg)
    }

    fn visit_f32_ceil(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_ceil)
    }

    fn visit_f32_floor(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_floor)
    }

    fn visit_f32_trunc(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_trunc)
    }

    fn visit_f32_nearest(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_nearest)
    }

    fn visit_f32_sqrt(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_sqrt)
    }

    fn visit_f32_add(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_add)
    }

    fn visit_f32_sub(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_sub)
    }

    fn visit_f32_mul(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_mul)
    }

    fn visit_f32_div(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_div)
    }

    fn visit_f32_min(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_min)
    }

    fn visit_f32_max(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_max)
    }

    fn visit_f32_copysign(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f32_copysign)
    }

    fn visit_f64_abs(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_abs)
    }

    fn visit_f64_neg(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_neg)
    }

    fn visit_f64_ceil(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_ceil)
    }

    fn visit_f64_floor(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_floor)
    }

    fn visit_f64_trunc(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_trunc)
    }

    fn visit_f64_nearest(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_nearest)
    }

    fn visit_f64_sqrt(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_sqrt)
    }

    fn visit_f64_add(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_add)
    }

    fn visit_f64_sub(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_sub)
    }

    fn visit_f64_mul(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_mul)
    }

    fn visit_f64_div(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_div)
    }

    fn visit_f64_min(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_min)
    }

    fn visit_f64_max(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_max)
    }

    fn visit_f64_copysign(&mut self) -> Result<()> {
        self.execute_binary(UntypedValue::f64_copysign)
    }

    fn visit_i32_wrap_i64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_wrap_i64)
    }

    fn visit_i32_trunc_f32(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i32_trunc_f32_s)
    }

    fn visit_u32_trunc_f32(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i32_trunc_f32_u)
    }

    fn visit_i32_trunc_f64(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i32_trunc_f64_s)
    }

    fn visit_u32_trunc_f64(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i32_trunc_f64_u)
    }

    fn visit_i64_extend_i32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_extend_i32_s)
    }

    fn visit_i64_extend_u32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_extend_i32_u)
    }

    fn visit_i64_trunc_f32(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i64_trunc_f32_s)
    }

    fn visit_u64_trunc_f32(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i64_trunc_f32_u)
    }

    fn visit_i64_trunc_f64(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i64_trunc_f64_s)
    }

    fn visit_u64_trunc_f64(&mut self) -> Result<()> {
        self.try_execute_unary(UntypedValue::i64_trunc_f64_u)
    }

    fn visit_f32_convert_i32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_convert_i32_s)
    }

    fn visit_f32_convert_u32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_convert_i32_u)
    }

    fn visit_f32_convert_i64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_convert_i64_s)
    }

    fn visit_f32_convert_u64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_convert_i64_u)
    }

    fn visit_f32_demote_f64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f32_demote_f64)
    }

    fn visit_f64_convert_i32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_convert_i32_s)
    }

    fn visit_f64_convert_u32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_convert_i32_u)
    }

    fn visit_f64_convert_i64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_convert_i64_s)
    }

    fn visit_f64_convert_u64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_convert_i64_u)
    }

    fn visit_f64_promote_f32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::f64_promote_f32)
    }

    fn visit_i32_sign_extend8(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_extend8_s)
    }

    fn visit_i32_sign_extend16(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_extend16_s)
    }

    fn visit_i64_sign_extend8(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_extend8_s)
    }

    fn visit_i64_sign_extend16(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_extend16_s)
    }

    fn visit_i64_sign_extend32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_extend32_s)
    }

    fn visit_i32_trunc_sat_f32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_trunc_sat_f32_s)
    }

    fn visit_u32_trunc_sat_f32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_trunc_sat_f32_u)
    }

    fn visit_i32_trunc_sat_f64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_trunc_sat_f64_s)
    }

    fn visit_u32_trunc_sat_f64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i32_trunc_sat_f64_u)
    }

    fn visit_i64_trunc_sat_f32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_trunc_sat_f32_s)
    }

    fn visit_u64_trunc_sat_f32(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_trunc_sat_f32_u)
    }

    fn visit_i64_trunc_sat_f64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_trunc_sat_f64_s)
    }

    fn visit_u64_trunc_sat_f64(&mut self) -> Result<()> {
        self.execute_unary(UntypedValue::i64_trunc_sat_f64_u)
    }
}
