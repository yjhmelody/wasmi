use alloc::vec::Vec;
use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use accel_merkle::{compute_root, MerkleHasher, ProveData};
use wasmi_core::{TrapCode, UntypedValue};

use codec::{Codec, Decode, Encode};

use crate::{
    engine::{bytecode::Instruction, code_map::CodeMap, DropKeep},
    func::{FuncEntityInternal, WasmFuncEntity},
    proof::{utils::TwoMemoryChunks, value_hash, MEMORY_LEAF_SIZE},
    snapshot::{
        CallStackSnapshot,
        EngineSnapshot,
        FuncFrameSnapshot,
        FuncType,
        ValueStackSnapshot,
    },
    AsContext,
    Engine,
    Func,
};

/// The contains engine level proof data used for instruction proof.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct EngineProof<Hasher: MerkleHasher> {
    /// The proof for value stack.
    pub value_stack: ValueStackProof<Hasher>,
    /// The proof for call stack.
    pub call_stack: CallStackProof<Hasher>,
}

/// The final engine proof data to be hashed.
#[derive(Encode)]
struct PostEngineProof<'a, T: MerkleHasher> {
    value_stack: &'a T::Output,
    call_stack: &'a T::Output,
}

impl<Hasher: MerkleHasher> EngineProof<Hasher> {
    /// Generate engine proof for specific instruction by snapshot.
    pub fn make(snapshot: &EngineSnapshot, cur_inst: Instruction) -> Option<Self> {
        let remain_size = match cur_inst {
            Instruction::LocalTee { local_depth } | Instruction::LocalGet { local_depth } => {
                local_depth.into_inner()
            }
            // local.set need pop top value first
            Instruction::LocalSet { local_depth } => local_depth.into_inner() + 1,

            Instruction::Return(drop_keep) => drop_keep.keep() + drop_keep.drop(),
            // TODO(opt): return 0 if equal to zero.
            Instruction::ReturnIfNez(drop_keep) => drop_keep.keep() + drop_keep.drop(),
            _ => 3,
        };
        let value_stack = ValueStackProof::make(&snapshot.values, remain_size)?;
        let call_stack =
            CallStackProof::make(&snapshot.frames, 1, snapshot.config.maximum_recursion_depth);
        Some(Self {
            value_stack,
            call_stack,
        })
    }

    /// Returns the hash of engine proof data.
    pub fn hash(&self) -> Hasher::Output {
        let value_stack = self.value_stack.hash();
        let call_stack = self.call_stack.hash();
        Hasher::hash_of(&PostEngineProof::<'_, Hasher> {
            value_stack: &value_stack,
            call_stack: &call_stack,
        })
    }
}

/// Instruction level proof.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct InstructionProof<Hasher: MerkleHasher> {
    /// The current pc.
    pub current_pc: u32,
    /// The current instruction.
    pub inst: Instruction,
    /// The prove current instruction is legal.
    pub inst_prove: ProveData<Hasher>,
    /// Extra proof data for some instructions.
    pub extra: ExtraProof<Hasher>,
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
    MemoryTwoChunks(MemoryTwoChunks<Hasher>),
    // MemoryChunkNeighbor(MemoryChunkNeighbor<Hasher>),
    /// Proof data for some memory instructions.
    MemoryChunkSibling(MemoryChunkSibling<Hasher>),
    /// Proof data for some memory instructions that will only access to one memory chunk.
    MemoryChunk(MemoryChunk<Hasher>),
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

    /// Creates Func node from wasm func entity and func header.
    pub(crate) fn from_wasm_func(
        wasm_func: &WasmFuncEntity,
        code_map: &CodeMap,
        func_type: FuncType,
    ) -> Self {
        let header = code_map.header(wasm_func.func_body());
        let pc = header.start() as u32;
        let len_locals = header.len_locals() as u32;

        Self::Wasm(WasmFuncHeader {
            pc,
            func_type,
            len_locals,
        })
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
    /// The amount of local variable of the function.
    pub len_locals: u32,
}

#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct CallProof<Hasher>
where
    Hasher: MerkleHasher,
{
    /// The function node info.
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

/// The contains a proof that a memory store instruction touch only one leaf.
#[derive(Encode, Decode, Debug, Eq, PartialEq)]
pub struct MemoryChunk<Hasher>
where
    Hasher: MerkleHasher,
{
    chunk: [u8; MEMORY_LEAF_SIZE],
    prove_data: ProveData<Hasher>,
}

impl<Hasher> Clone for MemoryChunk<Hasher>
where
    Hasher: MerkleHasher,
{
    fn clone(&self) -> Self {
        Self {
            chunk: self.chunk,
            prove_data: self.prove_data.clone(),
        }
    }
}

impl<Hasher> MemoryChunk<Hasher>
where
    Hasher: MerkleHasher,
{
    pub fn new(chunk: [u8; MEMORY_LEAF_SIZE], prove_data: ProveData<Hasher>) -> Self {
        Self { chunk, prove_data }
    }
    /// Compute root according to memory address.
    pub fn compute_root(&self, address: usize) -> Hasher::Output {
        let index = address / MEMORY_LEAF_SIZE;
        self.prove_data
            .compute_root(index, Hasher::hash_of(&self.chunk))
    }

    pub fn read(&self, address: usize, buffer: &mut [u8]) -> Option<()> {
        let offset = address % MEMORY_LEAF_SIZE;
        let len = buffer.len();
        buffer.copy_from_slice(self.chunk.get(offset..(offset + len))?);

        Some(())
    }

    pub fn write(&mut self, address: usize, buffer: &[u8]) -> Option<()> {
        let offset = address % MEMORY_LEAF_SIZE;
        let len = buffer.len();

        if len + offset > MEMORY_LEAF_SIZE {
            return None;
        }
        self.chunk[offset..(offset + len)].copy_from_slice(buffer);

        Some(())
    }
}

/// The contains a proof that a memory store instruction touch only two leaves which are neighbors.
#[derive(Encode, Decode, Debug, Eq, PartialEq)]
pub struct MemoryTwoChunks<Hasher>
where
    Hasher: MerkleHasher,
{
    chunks: TwoMemoryChunks,
    prove_data: ProveData<Hasher>,
    next_prove_data: ProveData<Hasher>,
}

impl<Hasher> Clone for MemoryTwoChunks<Hasher>
where
    Hasher: MerkleHasher,
{
    fn clone(&self) -> Self {
        Self {
            chunks: self.chunks.clone(),
            prove_data: self.prove_data.clone(),
            next_prove_data: self.next_prove_data.clone(),
        }
    }
}

impl<Hasher> MemoryTwoChunks<Hasher>
where
    Hasher: MerkleHasher,
{
    pub fn new(
        leaf: [u8; MEMORY_LEAF_SIZE],
        prove_data: ProveData<Hasher>,
        next_leaf: [u8; MEMORY_LEAF_SIZE],
        next_prove_data: ProveData<Hasher>,
    ) -> Self {
        Self {
            chunks: TwoMemoryChunks::new(leaf, next_leaf),
            prove_data,
            next_prove_data,
        }
    }
    /// Compute root according to memory address.
    ///
    /// # Note
    ///
    /// It's illegal to call this method after call `write` method but should call `recompute_root`.
    pub fn compute_root(&self, address: usize) -> Option<Hasher::Output> {
        let index = address / MEMORY_LEAF_SIZE;

        let root = self
            .prove_data
            .compute_root(index, self.chunks.hash_leaf::<Hasher>());
        let root2 = self
            .next_prove_data
            .compute_root(index + 1, self.chunks.hash_next_leaf::<Hasher>());
        debug_assert_eq!(root, root2);
        if root != root2 {
            None
        } else {
            Some(root)
        }
    }

    /// Recompute the root according to updated memory chunks.
    ///
    /// # Note
    ///
    /// If memory chunk is updated, user must call this method to calculate the new root.
    ///
    /// # Panic
    ///
    /// If prove data length is zero.
    pub fn recompute_root(&self, address: usize) -> Hasher::Output {
        let index = address / MEMORY_LEAF_SIZE;

        let common_ancestor = self.calculate_ancestor_hash(index);

        let (ancestor_prove_data_index, ancestor_prove_data) = self.prove_data_for_ancestor(index);

        let mut ancestor_node_index = index;
        let mut i = 0;
        while i < ancestor_prove_data_index {
            ancestor_node_index >>= 1;
            i += 1;
        }

        ancestor_prove_data.compute_root(ancestor_node_index, common_ancestor)
    }

    /// The two proof contains proof path could calculate the new ancestor.
    fn prove_data_from_leaf_to_ancestor(
        &self,
        index: usize,
    ) -> (ProveData<Hasher>, ProveData<Hasher>) {
        let common_index = Self::find_common_ancestor(index, index + 1);

        (
            ProveData::from(self.prove_data.inner()[..common_index].to_vec()),
            ProveData::from(self.next_prove_data.inner()[..common_index].to_vec()),
        )
    }

    fn prove_data_for_ancestor(&self, index: usize) -> (usize, ProveData<Hasher>) {
        let common_index = Self::find_common_ancestor(index, index + 1);

        (
            common_index,
            ProveData::from(self.prove_data.inner()[common_index..].to_vec()),
        )
    }

    fn calculate_ancestor_hash(&self, index: usize) -> Hasher::Output {
        let (prove_data, next_prove_data) = self.prove_data_from_leaf_to_ancestor(index);
        let len1 = prove_data.inner().len();
        let len2 = next_prove_data.inner().len();
        debug_assert_eq!(len1, len2);
        assert!(len1 >= 1);
        assert!(len2 >= 1);

        // The left child of ancestor
        let child_hash = compute_root::<Hasher>(
            &prove_data.inner()[..(len1 - 1)],
            index,
            self.chunks.hash_leaf::<Hasher>(),
        );
        // The right child of ancestor
        let next_child_hash = compute_root::<Hasher>(
            &next_prove_data.inner()[..(len2 - 1)],
            index + 1,
            self.chunks.hash_next_leaf::<Hasher>(),
        );

        Hasher::hash_node(&child_hash, &next_child_hash)
    }

    /// Return the index of common ancestor in prove data.
    ///
    /// # Note
    ///
    /// - The depth of leaves must be same.
    /// - Root is common ancestor if return the length of prove data.
    /// - The return value must be non-zero.
    fn find_common_ancestor(mut index: usize, mut next_index: usize) -> usize {
        let mut i = 0;
        loop {
            index >>= 1;
            next_index >>= 1;
            i += 1;
            if index == next_index {
                return i;
            }
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
#[derive(Encode, Decode, Debug, Eq, PartialEq)]
pub struct MemoryChunkSibling<Hasher>
where
    Hasher: MerkleHasher,
{
    /// a proof path but without leaf hash.
    prove_data: ProveData<Hasher>,
    /// Contains two memory leaves.
    chunks: TwoMemoryChunks,
}

impl<Hasher> Clone for MemoryChunkSibling<Hasher>
where
    Hasher: MerkleHasher,
{
    fn clone(&self) -> Self {
        Self {
            chunks: self.chunks.clone(),
            prove_data: self.prove_data.clone(),
        }
    }
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
        let index = address / MEMORY_LEAF_SIZE;

        let parent_hash = Hasher::hash_node(
            &self.chunks.hash_leaf::<Hasher>(),
            &self.chunks.hash_next_leaf::<Hasher>(),
        );

        self.prove_data.compute_root(index >> 1, parent_hash)
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

#[derive(Encode, Decode)]
pub(crate) struct StackProof<T, Hasher: MerkleHasher> {
    /// The hash of entries excepting the top N.
    bottom_hash: Hasher::Output,
    /// The top N entries in value stack.
    ///
    /// These entries will be used when execute osp.
    entries: Vec<T>,
    /// The hasher.
    _hasher: PhantomData<Hasher>,
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
    /// Creates a stack proof according to top entries and bottom hash.
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
        if len >= depth {
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

#[derive(Encode, Decode, Clone, Eq, PartialEq)]
pub struct ValueStackProof<Hasher: MerkleHasher>(pub(crate) StackProof<UntypedValue, Hasher>);

impl<Hasher: MerkleHasher> Debug for ValueStackProof<Hasher> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ValueStackProof")
            .field("bottom_hash", &self.0.bottom_hash)
            .field("top_values", &self.0.entries)
            .finish()
    }
}

impl<Hasher: MerkleHasher> ValueStackProof<Hasher> {
    /// Make a value stack proof by snapshot.
    ///
    /// Keep the top N stack value original and not be part of hash.
    pub fn make(snapshot: &ValueStackSnapshot, keep_len: usize) -> Option<Self> {
        if keep_len > snapshot.entries.len() {
            return None;
        }
        let len = snapshot.entries.len() - keep_len;
        let (bottoms, tops) = snapshot.entries.split_at(len);
        let bottom_hash = hash_value_stack::<Hasher>(bottoms, Default::default());
        let entries = tops.to_vec();

        Some(Self(StackProof::<_, Hasher>::new(entries, bottom_hash)))
    }

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

    /// Extends the value stack by the `additional` amount of zeros.
    pub fn extend_zeros(&mut self, additional: usize) {
        self.0
            .entries
            .extend(core::iter::repeat(UntypedValue::default()).take(additional))
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

// TODO: redesign some config
#[derive(Encode, Decode, Clone, Eq, PartialEq)]
pub struct CallStackProof<Hasher: MerkleHasher> {
    /// The maximum number of nested calls that the Wasm stack allows.
    recursion_depth: u32,
    /// The remaining depth of call stack excepting entries in `stack`.
    remaining_depth: u32,
    /// The underline stack.
    stack: StackProof<FuncFrameSnapshot, Hasher>,
}

impl<Hasher: MerkleHasher> Debug for CallStackProof<Hasher> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallStackProof")
            .field("bottom_hash", &self.stack.bottom_hash)
            .field("top_frames", &self.stack.entries)
            .finish()
    }
}

impl<Hasher: MerkleHasher> CallStackProof<Hasher> {
    /// Make a call stack proof by snapshot.
    ///
    /// Keep the top N stack value original and not be part of hash.
    ///
    /// # Note
    ///
    /// In our case, we only need the top 1 value to be kept.
    pub fn make(snapshot: &CallStackSnapshot, keep_len: usize, recursion_depth: u32) -> Self {
        debug_assert!(keep_len > 0);
        let len = snapshot.frames.len().saturating_sub(keep_len);
        let (bottoms, tops) = snapshot.frames.split_at(len);
        let bottom_hash = hash_call_stack::<Hasher>(bottoms, Default::default());
        let entries = tops.to_vec();

        Self {
            recursion_depth,
            remaining_depth: len as u32,
            stack: StackProof::<_, Hasher>::new(entries, bottom_hash),
        }
    }

    pub fn hash(&self) -> Hasher::Output {
        hash_call_stack::<Hasher>(&self.stack.entries, self.stack.bottom_hash.clone())
    }

    /// Push a frame to call stack.
    ///
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
    use crate::proof::hash_memory_leaf;
    use accel_merkle::{MemoryMerkle, MerkleKeccak256};

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
            let a = ValueStackProof::<MerkleKeccak256>::make(&snapshot, i).unwrap();
            let b = ValueStackProof::<MerkleKeccak256>::make(&snapshot, i + 1).unwrap();

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
            let a = CallStackProof::<MerkleKeccak256>::make(&snapshot, i, recursion_depth);
            let b = CallStackProof::<MerkleKeccak256>::make(&snapshot, i + 1, recursion_depth);

            assert_eq!(a.hash(), b.hash(), "call stack finally hash must be equal")
        }
    }

    fn new_chunk(val: usize) -> [u8; MEMORY_LEAF_SIZE] {
        let mut chunk = [0; MEMORY_LEAF_SIZE];
        let bytes = val.to_le_bytes().to_vec();
        chunk[..bytes.len()].copy_from_slice(&bytes);

        chunk
    }

    fn generate_memory_merkle_by<const CHUNK_NUM: usize>(
        f: impl Fn(usize) -> [u8; MEMORY_LEAF_SIZE],
        min_depth: usize,
    ) -> (MemoryMerkle<MerkleKeccak256>, Vec<[u8; MEMORY_LEAF_SIZE]>) {
        let chunks = (0..CHUNK_NUM).map(f).collect::<Vec<_>>();
        let leaf_hashes = chunks
            .iter()
            .map(|chunk| MerkleKeccak256::hash_of(&chunk))
            .collect::<Vec<_>>();

        let merkle = MemoryMerkle::<MerkleKeccak256>::new_advanced(
            leaf_hashes,
            hash_memory_leaf::<MerkleKeccak256>([0u8; MEMORY_LEAF_SIZE]),
            min_depth,
        );

        (merkle, chunks)
    }

    #[test]
    fn test_memory_chunk() {
        const CHUNK_NUM: usize = 16;
        let (merkle, chunks) = generate_memory_merkle_by::<CHUNK_NUM>(new_chunk, 4);
        let root = merkle.root();

        for (index, leaf) in chunks.iter().enumerate().take(CHUNK_NUM) {
            let prove_data = merkle.prove(index).unwrap();
            let memory_chunk = MemoryChunk::new(*leaf, prove_data);

            let root2 = memory_chunk.compute_root(index * MEMORY_LEAF_SIZE);
            assert_eq!(root, root2);
        }
    }

    #[test]
    fn test_memory_two_chunks() {
        const CHUNK_NUM: usize = 512;
        let (merkle, chunks) = generate_memory_merkle_by::<CHUNK_NUM>(new_chunk, 8);
        let root = merkle.root();

        for index in 0..(CHUNK_NUM - 1) {
            let leaf = chunks[index];
            let next_leaf = chunks[index + 1];

            let prove_data = merkle.prove(index).unwrap();
            let next_prove_data = merkle.prove(index + 1).unwrap();

            let memory_chunk = MemoryTwoChunks::new(leaf, prove_data, next_leaf, next_prove_data);

            let root2 = memory_chunk.compute_root(index * MEMORY_LEAF_SIZE).unwrap();
            assert_eq!(root, root2, "index({index})");
            // we actually not update root just use `recompute_root` here
            let new_root = memory_chunk.recompute_root(index * MEMORY_LEAF_SIZE);
            assert_eq!(root2, new_root, "index({index})");
        }
    }

    #[test]
    fn test_memory_two_chunks_recompute_root() {
        const CHUNK_NUM: usize = 512;
        const HALF_SIZE: usize = MEMORY_LEAF_SIZE / 2;

        let (merkle, chunks) = generate_memory_merkle_by::<CHUNK_NUM>(new_chunk, 8);
        let root = merkle.root();

        for index in 0..(CHUNK_NUM - 1) {
            let next_index = index + 1;
            let leaf = chunks[index];
            let next_leaf = chunks[next_index];

            let prove_data = merkle.prove(index).unwrap();
            let next_prove_data = merkle.prove(next_index).unwrap();

            let mut memory_chunk =
                MemoryTwoChunks::new(leaf, prove_data.clone(), next_leaf, next_prove_data.clone());

            let root2 = memory_chunk.compute_root(index * MEMORY_LEAF_SIZE).unwrap();
            assert_eq!(root, root2, "index({index})");

            let mut new_leaf = new_chunk(index);
            new_leaf[HALF_SIZE..].copy_from_slice(&[1; HALF_SIZE]);

            let mut new_next_leaf = new_chunk(next_index);
            new_next_leaf[..HALF_SIZE].copy_from_slice(&[1; HALF_SIZE]);

            let (new_merkle, _) = generate_memory_merkle_by::<CHUNK_NUM>(
                move |i| {
                    if i == index {
                        new_leaf
                    } else if i == next_index {
                        new_next_leaf
                    } else {
                        new_chunk(i)
                    }
                },
                8,
            );
            let new_root = new_merkle.root();
            memory_chunk.write(index * MEMORY_LEAF_SIZE + HALF_SIZE, &[1; MEMORY_LEAF_SIZE]);

            assert_eq!(
                memory_chunk,
                MemoryTwoChunks::new(new_leaf, prove_data, new_next_leaf, next_prove_data)
            );

            let new_root2 = memory_chunk.recompute_root(index * MEMORY_LEAF_SIZE);
            assert_eq!(new_root, new_root2, "index({index})");
        }
    }

    #[test]
    fn test_memory_two_chunks_recompute_root_by_all_same_memory_chunk() {
        const CHUNK_NUM: usize = 512;
        const HALF_SIZE: usize = MEMORY_LEAF_SIZE / 2;

        let template_chunk = [1; MEMORY_LEAF_SIZE];
        let (merkle, chunks) = generate_memory_merkle_by::<CHUNK_NUM>(|_i| template_chunk, 8);

        let root = merkle.root();

        for index in 0..(CHUNK_NUM - 1) {
            let next_index = index + 1;
            let leaf = chunks[index];
            let next_leaf = chunks[next_index];

            let prove_data = merkle.prove(index).unwrap();
            let next_prove_data = merkle.prove(next_index).unwrap();

            let mut memory_chunk =
                MemoryTwoChunks::new(leaf, prove_data.clone(), next_leaf, next_prove_data.clone());

            let root2 = memory_chunk.compute_root(index * MEMORY_LEAF_SIZE).unwrap();
            assert_eq!(root, root2, "index({index})");

            let mut new_leaf = template_chunk;
            new_leaf[HALF_SIZE..].copy_from_slice(&[255; HALF_SIZE]);

            let mut new_next_leaf = template_chunk;
            new_next_leaf[..HALF_SIZE].copy_from_slice(&[255; HALF_SIZE]);

            let (new_merkle, _) = generate_memory_merkle_by::<CHUNK_NUM>(
                move |i| {
                    if i == index {
                        new_leaf
                    } else if i == next_index {
                        new_next_leaf
                    } else {
                        template_chunk
                    }
                },
                8,
            );
            let new_root = new_merkle.root();
            memory_chunk.write(
                index * MEMORY_LEAF_SIZE + HALF_SIZE,
                &[255; MEMORY_LEAF_SIZE],
            );

            assert_eq!(
                memory_chunk,
                MemoryTwoChunks::new(new_leaf, prove_data, new_next_leaf, next_prove_data)
            );

            let new_root2 = memory_chunk.recompute_root(index * MEMORY_LEAF_SIZE);
            assert_eq!(new_root, new_root2, "index({index})");
        }
    }

    #[test]
    fn test_memory_chunk_sibling() {
        const CHUNK_NUM: usize = 16;
        let (merkle, chunks) = generate_memory_merkle_by::<CHUNK_NUM>(new_chunk, 4);
        let root = merkle.root();

        for index in (0..CHUNK_NUM).step_by(2) {
            // must be even
            let leaf = chunks[index];
            let next_leaf = chunks[index + 1];

            let prove_data = merkle.prove_without_leaf(index).unwrap();

            let chunk_sibling = MemoryChunkSibling::new(prove_data, leaf, next_leaf);

            let root2 = chunk_sibling.compute_root(index * MEMORY_LEAF_SIZE);
            assert_eq!(root, root2);
        }
    }
}
