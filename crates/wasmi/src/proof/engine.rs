use alloc::vec::Vec;
use core::fmt::Debug;
use std::marker::PhantomData;

use accel_merkle::{MerkleHasher, ProveData};
use wasmi_core::{TrapCode, UntypedValue};

use codec::{Codec, Decode, Encode};

use crate::{
    engine::{bytecode::Instruction, code_map::CodeMap, DropKeep},
    func::{FuncEntityInternal, WasmFuncEntity},
    proof::{utils::TwoMemoryChunks, value_hash, MEMORY_LEAF_SIZE},
    snapshot::{
        CallStackSnapshot,
        EngineConfig,
        EngineSnapshot,
        FuncFrameSnapshot,
        FuncType,
        ValueStackSnapshot,
    },
    AsContext,
    Engine,
    Func,
};

impl EngineSnapshot {
    /// Generate stack proofs for specific instruction.
    pub fn make_proof<Hasher: MerkleHasher>(
        &self,
        cur_inst: Instruction,
    ) -> Option<EngineProof<Hasher>> {
        let remain_size = match cur_inst {
            Instruction::LocalTee { local_depth }
            | Instruction::LocalSet { local_depth }
            | Instruction::LocalGet { local_depth } => local_depth.into_inner(),
            _ => 3,
        };
        let value_proof = self.values.make_proof(remain_size)?;
        let call_proof = self
            .frames
            .make_proof(1, self.config.maximum_recursion_depth);

        Some(EngineProof {
            config: self.config.clone(),
            value_proof,
            call_proof,
        })
    }
}

/// The contains engine level proof data used for instruction proof.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct EngineProof<Hasher: MerkleHasher> {
    pub config: EngineConfig,
    pub value_proof: ValueStackProof<Hasher>,
    pub call_proof: CallStackProof<Hasher>,
}

/// Instruction level proof.
///
/// It includes engine relate data proof.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct InstructionProof<Hasher: MerkleHasher> {
    pub(crate) engine_proof: EngineProof<Hasher>,
    pub(crate) current_pc: u32,
    pub(crate) inst: Instruction,
    /// The prove current instruction is legal.
    pub(crate) inst_prove: ProveData<Hasher>,
    pub(crate) extra: ExtraProof<Hasher>,
}

/// This struct contains extra proof data needed for some special instructions.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum ExtraProof<Hasher: MerkleHasher> {
    /// Most instructions do not need more proof.
    Empty,
    /// Proof data for global instructions.
    GlobalGetSet(GlobalProof<Hasher>),
    /// Proof data for `call`.
    CallWasm(CallProof<Hasher>),
    /// Proof data for `call_indirect`.
    CallIndirectWasm(CallProof<Hasher>),
    /// Proof data for memory.page.
    MemoryPage(MemoryPage),
    /// Proof data for some memory instructions.
    MemoryChunkNeighbor(MemoryChunkNeighbor<Hasher>),
    /// Proof data for some memory instructions.
    MemoryChunkSibling(MemoryChunkSibling<Hasher>),
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct GlobalProof<Hasher>
where
    Hasher: MerkleHasher,
{
    /// The global value.
    pub value: UntypedValue,
    /// The global value proof.
    pub prove_data: ProveData<Hasher>,
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub enum FuncNode {
    /// Contains a host function header.
    Host(HostFuncHeader),
    /// Contains a wasm function header.
    Wasm(WasmFuncHeader),
}

impl FuncNode {
    /// Cast a func ref to a proof representation.
    pub(crate) fn from_func(ctx: impl AsContext, f: Func, engine: Engine) -> Self {
        let sig = f.signature(ctx.as_context());
        // Note: lock/unlock
        let func_type = engine.resolve_func_type(sig, Clone::clone).into();
        // Note: lock again.
        let engine = engine.lock();
        let code_map = engine.code_map();
        match f.as_internal(ctx.as_context()) {
            FuncEntityInternal::Wasm(wasm_func) => {
                Self::from_wasm_func(wasm_func, code_map, func_type)
            }
            FuncEntityInternal::Host(_) => Self::Host(HostFuncHeader { func_type }),
        }
    }

    pub(crate) fn from_wasm_func(
        wasm_func: &WasmFuncEntity,
        code_map: &CodeMap,
        func_type: FuncType,
    ) -> Self {
        let header = code_map.header(wasm_func.func_body());
        let pc = header.start() as u32;

        Self::Wasm(WasmFuncHeader { pc, func_type })
    }
}

impl FuncNode {
    /// Creates a func hash for merkle node.
    pub fn hash<Hasher: MerkleHasher>(&self) -> Hasher::Output {
        Hasher::hash_of(self)
    }
}

impl From<WasmFuncHeader> for FuncNode {
    fn from(f: WasmFuncHeader) -> Self {
        FuncNode::Wasm(f)
    }
}

impl From<HostFuncHeader> for FuncNode {
    fn from(f: HostFuncHeader) -> Self {
        FuncNode::Host(f)
    }
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct HostFuncHeader {
    /// The function's signature
    pub func_type: FuncType,
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct WasmFuncHeader {
    /// The pc that call jump to.
    pub pc: u32,
    /// The function's signature
    pub func_type: FuncType,
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct CallProof<Hasher>
where
    Hasher: MerkleHasher,
{
    pub func: FuncNode,
    /// The func proof.
    pub prove_data: ProveData<Hasher>,
}

/// A linear memory page state.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct MemoryPage {
    pub initial_pages: u32,
    pub maximum_pages: Option<u32>,
    pub current_pages: u32,
}

/// The contains a proof that a memory store instruction touch two neighbor leaves which have `not` same parent.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct MemoryChunkNeighbor<Hasher>
where
    Hasher: MerkleHasher,
{
    prove_data: ProveData<Hasher>,
    chunks: TwoMemoryChunks,
    leaf_sibling: Hasher::Output,
    next_leaf_sibling: Hasher::Output,
}

impl<Hasher> MemoryChunkNeighbor<Hasher>
where
    Hasher: MerkleHasher,
{
    pub fn new(
        prove_data: ProveData<Hasher>,
        leaf: [u8; MEMORY_LEAF_SIZE],
        next_leaf: [u8; MEMORY_LEAF_SIZE],
        leaf_sibling: Hasher::Output,
        next_leaf_sibling: Hasher::Output,
    ) -> Self {
        Self {
            prove_data,
            chunks: TwoMemoryChunks::new(leaf, next_leaf),
            leaf_sibling,
            next_leaf_sibling,
        }
    }
    /// Compute root according to memory address.
    ///
    /// # Note
    ///
    /// Return None if index is not odd or root is invalid.
    pub fn compute_root(&self, address: usize) -> Option<Hasher::Output> {
        let mut index = address / MEMORY_LEAF_SIZE;
        if index & 1 == 0 {
            return None;
        }
        let mut next_index = index + 1;

        let mut parent_hash =
            Hasher::hash_node(&self.chunks.hash_leaf::<Hasher>(), &self.leaf_sibling);
        index >>= 1;
        let first_root = self.prove_data.compute_root(index, parent_hash);

        parent_hash = Hasher::hash_node(
            &self.chunks.hash_next_leaf::<Hasher>(),
            &self.next_leaf_sibling,
        );
        next_index >>= 1;
        let second_root = self.prove_data.compute_root(next_index, parent_hash);

        if first_root != second_root {
            None
        } else {
            Some(first_root)
        }
    }

    pub fn read(&self, address: usize, buffer: &mut [u8]) {
        self.chunks.read(address, buffer)
    }

    pub fn write(&mut self, address: usize, buffer: &[u8]) {
        self.chunks.write(address, buffer)
    }
}

/// The contains a proof that a memory store instruction touch two sibling leaves which have same parent.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct MemoryChunkSibling<Hasher>
where
    Hasher: MerkleHasher,
{
    chunks: TwoMemoryChunks,
    prove_data: ProveData<Hasher>,
}

impl<Hasher> MemoryChunkSibling<Hasher>
where
    Hasher: MerkleHasher,
{
    pub fn new(
        prove_data: ProveData<Hasher>,
        leaf: [u8; MEMORY_LEAF_SIZE],
        next_leaf: [u8; MEMORY_LEAF_SIZE],
    ) -> Self {
        Self {
            prove_data,
            chunks: TwoMemoryChunks::new(leaf, next_leaf),
        }
    }

    /// Compute root according to memory address.
    pub fn compute_root(&self, address: usize) -> Hasher::Output {
        let mut index = address / MEMORY_LEAF_SIZE;
        index >>= 1;

        let parent_hash = Hasher::hash_node(
            &self.chunks.hash_leaf::<Hasher>(),
            &self.chunks.hash_next_leaf::<Hasher>(),
        );

        self.prove_data.compute_root(index, parent_hash)
    }

    pub fn read(&self, address: usize, buffer: &mut [u8]) {
        self.chunks.read(address, buffer)
    }

    pub fn write(&mut self, address: usize, buffer: &[u8]) {
        self.chunks.write(address, buffer)
    }
}

fn hash_stack<Hasher, I>(stack: I, init_hash: Hasher::Output) -> Hasher::Output
where
    Hasher: MerkleHasher,
    I: IntoIterator<Item = Hasher::Output>,
{
    let mut hash = init_hash;
    // Note: do keccak N times recursively.
    for item in stack.into_iter() {
        hash = Hasher::hash_node(&item, &hash)
    }
    hash
}

/// The hashing rule for part of value stack.
fn hash_value_stack<Hasher: MerkleHasher>(
    stack: &[UntypedValue],
    init_hash: Hasher::Output,
) -> Hasher::Output {
    let iter = stack.iter().map(|v| value_hash::<Hasher>(*v));
    hash_stack::<Hasher, _>(iter, init_hash)
}

/// The hashing rule for part of call stack.
fn hash_call_stack<Hasher: MerkleHasher>(
    stack: &[FuncFrameSnapshot],
    init_hash: Hasher::Output,
) -> Hasher::Output {
    let iter = stack.iter().map(|f| Hasher::hash_of(f));
    hash_stack::<Hasher, _>(iter, init_hash)
}

impl ValueStackSnapshot {
    /// Make a value stack proof.
    ///
    /// Keep the top N stack value original and not be part of hash.
    pub fn make_proof<Hasher: MerkleHasher>(
        &self,
        keep_len: usize,
    ) -> Option<ValueStackProof<Hasher>> {
        if keep_len > self.entries.len() {
            return None;
        }
        let len = self.entries.len() - keep_len;
        let (bottoms, tops) = self.entries.split_at(len);
        let bottom_hash = hash_value_stack::<Hasher>(bottoms, Default::default());
        let entries = tops.to_vec();

        Some(ValueStackProof(StackProof::<_, Hasher>::new(
            entries,
            bottom_hash,
        )))
    }
}

#[derive(Encode, Decode, Debug)]
pub struct StackProof<T, Hasher: MerkleHasher> {
    /// The hash of entries excepting the top N.
    bottom_hash: Hasher::Output,
    /// The top N entries in value stack.
    ///
    /// These entries will be used when execute osp.
    entries: Vec<T>,
    /// The hasher.
    _hasher: core::marker::PhantomData<Hasher>,
}

impl<T: Clone, Hasher: MerkleHasher> Clone for StackProof<T, Hasher> {
    fn clone(&self) -> Self {
        Self {
            bottom_hash: self.bottom_hash.clone(),
            entries: self.entries.clone(),
            _hasher: PhantomData,
        }
    }
}

impl<T: PartialEq, Hasher: MerkleHasher> PartialEq for StackProof<T, Hasher> {
    fn eq(&self, other: &Self) -> bool {
        self.bottom_hash.eq(&other.bottom_hash) && self.entries.eq(&other.entries)
    }
}

impl<T: PartialEq, Hasher: MerkleHasher> Eq for StackProof<T, Hasher> {}

impl<T, Hasher> StackProof<T, Hasher>
where
    T: Codec,
    Hasher: MerkleHasher,
{
    pub fn new(entries: Vec<T>, bottom_hash: Hasher::Output) -> Self {
        Self {
            entries,
            bottom_hash,
            _hasher: PhantomData,
        }
    }

    /// Pop and return the last value.
    pub fn pop(&mut self) -> Option<T> {
        self.entries.pop()
    }

    /// Returns the last element of the slice, or `None` if it is empty.
    pub fn last(&self) -> Option<&T> {
        self.entries.last()
    }

    /// Returns a mutable pointer to the last item in the slice.
    pub fn last_mut(&mut self) -> Option<&mut T> {
        self.entries.last_mut()
    }

    /// Peek the value in depth
    ///
    /// # Note
    ///
    /// A `depth` of 0 is invalid.
    pub fn peek(&self, depth: usize) -> Option<&T> {
        let len = self.entries.len();
        if len > depth {
            Some(&self.entries[len - depth])
        } else {
            None
        }
    }

    /// Peek the value in depth
    ///
    /// # Note
    ///
    /// A `depth` of 0 is invalid.
    pub fn peek_mut(&mut self, depth: usize) -> Option<&mut T> {
        let len = self.entries.len();
        if len >= depth {
            Some(&mut self.entries[len - depth])
        } else {
            None
        }
    }

    /// Appends an element to the back of a collection.
    pub fn push(&mut self, val: T) {
        self.entries.push(val)
    }
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct ValueStackProof<Hasher: MerkleHasher>(pub(crate) StackProof<UntypedValue, Hasher>);

impl<Hasher: MerkleHasher> ValueStackProof<Hasher> {
    pub fn hash(&self) -> Hasher::Output {
        hash_value_stack::<Hasher>(&self.0.entries, self.0.bottom_hash.clone())
    }

    pub fn pop(&mut self) -> Option<UntypedValue> {
        self.0.pop()
    }

    pub fn push<T>(&mut self, val: T)
    where
        T: Into<UntypedValue>,
    {
        self.0.push(val.into())
    }

    pub fn is_emtpy(&self) -> bool {
        self.0.entries.is_empty()
    }

    pub fn pop_as<T>(&mut self) -> Option<T>
    where
        T: From<UntypedValue>,
    {
        self.pop().map(From::from)
    }

    pub fn peek(&self, depth: usize) -> Option<&UntypedValue> {
        self.0.peek(depth)
    }

    pub fn last(&self) -> Option<&UntypedValue> {
        self.0.last()
    }

    pub fn last_mut(&mut self) -> Option<&mut UntypedValue> {
        self.0.last_mut()
    }

    pub fn last_as<T>(&self) -> Option<T>
    where
        T: From<UntypedValue>,
    {
        self.last().copied().map(T::from)
    }

    /// Peek the depth value start from stack top.
    pub fn peek_mut(&mut self, depth: usize) -> Option<&mut UntypedValue> {
        if depth == 0 {
            return None;
        }
        self.0.peek_mut(depth)
    }

    /// Move `K` elements from the top of the stack `D` positions down the stack,
    /// and then pop `D` elements from the top of the stack.
    ///
    /// # Note
    ///
    /// For an amount of entries to keep `k` and an amount of entries to drop `d`
    /// this has the following effect on stack `s` and stack pointer `sp`.
    ///
    /// 1) Copy `k` elements from indices starting at `sp - k` to `sp - k - d`.
    /// 2) Adjust stack pointer: `sp -= d`
    ///
    /// After this operation the value stack will have `d` fewer entries and the
    /// top `k` entries are the top `k` entries before this operation.
    ///
    /// Note that `k + d` cannot be greater than the stack length.
    pub fn drop_keep(&mut self, drop_keep: DropKeep) -> Option<()> {
        let drop = drop_keep.drop();
        if drop == 0 {
            // Nothing to do in this case.
            return Some(());
        }
        let keep = drop_keep.keep();
        if keep == 0 {
            // Bail out early when there are no values to keep.
        } else if keep == 1 {
            let last = *self.0.last()?;
            let len = self.0.entries.len();
            if len < 1 + drop {
                // Illegal
                return None;
            }
            // Bail out early when there is only one value to copy.
            self.0.entries[len - 1 - drop] = last;
        } else {
            let len = self.0.entries.len();
            // Copy kept values over to their new place on the stack.
            if len < keep + drop {
                // Illegal
                return None;
            }
            let src = len - keep;
            let dst = len - keep - drop;
            for i in 0..keep {
                self.0.entries[dst + i] = self.0.entries[src + i];
            }
        }
        // Drop top values
        let len = self.0.entries.len();
        self.0.entries.truncate(len - drop);

        Some(())
    }

    /// Evaluates the given closure `f` for the top most stack value.
    #[inline]
    pub fn eval_top<F>(&mut self, f: F) -> Option<()>
    where
        F: FnOnce(UntypedValue) -> UntypedValue,
    {
        let top = *self.last()?;
        let last = self.last_mut()?;
        *last = f(top);

        Some(())
    }

    /// Evaluates the given closure `f` for the 2 top most stack values.
    #[inline]
    pub fn eval_top2<F>(&mut self, f: F) -> Option<()>
    where
        F: FnOnce(UntypedValue, UntypedValue) -> UntypedValue,
    {
        let rhs = self.pop()?;
        let lhs = *self.last()?;
        let last = self.last_mut()?;
        *last = f(lhs, rhs);

        Some(())
    }

    /// Evaluates the given closure `f` for the 3 top most stack values.
    #[inline]
    pub fn eval_top3<F>(&mut self, f: F) -> Option<()>
    where
        F: FnOnce(UntypedValue, UntypedValue, UntypedValue) -> UntypedValue,
    {
        let (e2, e3) = self.pop2()?;
        let e1 = *self.last()?;
        let last = self.last_mut()?;
        *last = f(e1, e2, e3);

        Some(())
    }

    /// Evaluates the given fallible closure `f` for the top most stack values.
    ///
    /// # Errors
    ///
    /// If the closure execution fails.
    #[inline]
    pub fn try_eval_top<F>(&mut self, f: F) -> Option<Result<(), TrapCode>>
    where
        F: FnOnce(UntypedValue) -> Result<UntypedValue, TrapCode>,
    {
        let val = *self.last()?;
        let res = f(val);

        match res {
            Ok(val) => {
                *self.last_mut()? = val;
                Some(Ok(()))
            }

            Err(trap) => Some(Err(trap)),
        }
    }

    /// Evaluates the given fallible closure `f` for the 2 top most stack values.
    ///
    /// # Errors
    ///
    /// If the closure execution fails.
    #[inline]
    pub fn try_eval_top2<F>(&mut self, f: F) -> Option<Result<(), TrapCode>>
    where
        F: FnOnce(UntypedValue, UntypedValue) -> Result<UntypedValue, TrapCode>,
    {
        let rhs = self.pop()?;
        let lhs = *self.last()?;
        let res = f(lhs, rhs);

        match res {
            Ok(val) => {
                *self.last_mut()? = val;
                Some(Ok(()))
            }

            Err(trap) => Some(Err(trap)),
        }
    }

    /// Pops the last pair of [`UntypedValue`] from the [`ValueStack`].
    pub fn pop2(&mut self) -> Option<(UntypedValue, UntypedValue)> {
        let b = self.pop()?;
        let a = self.pop()?;

        Some((a, b))
    }
}

impl CallStackSnapshot {
    // TODO: should consider current pc as part of proof ?
    pub fn make_proof<Hasher: MerkleHasher>(
        &self,
        keep_len: usize,
        recursion_depth: u32,
    ) -> CallStackProof<Hasher> {
        debug_assert!(keep_len > 0);
        let len = self.frames.len().saturating_sub(keep_len);
        let (bottoms, tops) = self.frames.split_at(len);
        let bottom_hash = hash_call_stack::<Hasher>(bottoms, Default::default());
        let entries = tops.to_vec();

        CallStackProof {
            remaining_depth: len as u32,
            stack: StackProof::<_, Hasher>::new(entries, bottom_hash),
            recursion_depth,
        }
    }
}

// TODO: need to consider more, maybe contain the current pc in it.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct CallStackProof<Hasher: MerkleHasher> {
    /// The maximum number of nested calls that the Wasm stack allows.
    recursion_depth: u32,
    /// The remaining depth of call stack excepting entries in `stack`.
    remaining_depth: u32,
    /// The underline stack.
    stack: StackProof<FuncFrameSnapshot, Hasher>,
}

impl<Hasher: MerkleHasher> CallStackProof<Hasher> {
    pub fn hash(&self) -> Hasher::Output {
        hash_call_stack::<Hasher>(&self.stack.entries, self.stack.bottom_hash.clone())
    }

    /// Returns None if stack overflow.
    pub fn push(&mut self, val: FuncFrameSnapshot) -> Option<()> {
        let cur_depth = (self.stack.entries.len() as u32).checked_add(self.remaining_depth)?;
        if self.recursion_depth == cur_depth {
            return None;
        }
        self.stack.push(val);
        Some(())
    }

    pub fn pop(&mut self) -> Option<FuncFrameSnapshot> {
        self.stack.pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use accel_merkle::MerkleKeccak256;

    #[test]
    fn test_value_stack_proof() {
        let snapshot = ValueStackSnapshot {
            entries: vec![
                UntypedValue::from(1i32),
                UntypedValue::from(2i32),
                UntypedValue::from(3i32),
                UntypedValue::from(4i32),
                UntypedValue::from(5i32),
                UntypedValue::from(6i32),
            ],
        };

        for i in 1..snapshot.entries.len() - 1 {
            let a = snapshot.make_proof::<MerkleKeccak256>(i).unwrap();
            let b = snapshot.make_proof::<MerkleKeccak256>(i + 1).unwrap();

            assert_eq!(a.hash(), b.hash(), "value stack finally hash must be equal")
        }
    }

    #[test]
    fn test_call_stack_proof() {
        let recursion_depth = 255;
        let snapshot = CallStackSnapshot {
            frames: vec![
                FuncFrameSnapshot::from(1u32),
                FuncFrameSnapshot::from(4u32),
                FuncFrameSnapshot::from(7u32),
            ],
        };

        for i in 1..snapshot.frames.len() - 1 {
            let a = snapshot.make_proof::<MerkleKeccak256>(i, recursion_depth);
            let b = snapshot.make_proof::<MerkleKeccak256>(i + 1, recursion_depth);

            assert_eq!(a.hash(), b.hash(), "call stack finally hash must be equal")
        }
    }
}
