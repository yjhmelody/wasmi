use super::{
    engine::DedupFuncType,
    AsContext,
    Extern,
    Func,
    Global,
    Index,
    Memory,
    StoreContext,
    Stored,
    Table,
};
use crate::{
    AsContextMut,
    FuncEntity,
    FuncType,
    GlobalEntity,
    MemoryEntity,
    MemoryType,
    TableEntity,
    TableType,
};
use alloc::{
    collections::{btree_map, BTreeMap},
    string::{String, ToString},
    vec::Vec,
};
use core::{iter::FusedIterator, ops::Deref};

/// A raw index to a module instance entity.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstanceIdx(pub u32);

impl Index for InstanceIdx {
    fn into_usize(self) -> usize {
        self.0 as usize
    }

    fn from_usize(value: usize) -> Self {
        let value = value.try_into().unwrap_or_else(|error| {
            panic!("index {value} is out of bounds as instance index: {error}")
        });
        Self(value)
    }
}

/// A module instance entity.
#[derive(Debug)]
pub struct InstanceEntity {
    initialized: bool,
    func_types: Vec<DedupFuncType>,
    tables: Vec<Table>,
    funcs: Vec<Func>,
    memories: Vec<Memory>,
    globals: Vec<Global>,
    exports: BTreeMap<String, Extern>,
}

use crate::memory::ByteBuffer;
use codec::{Decode, Encode, Output};
use wasmi_core::memory_units::Pages;

// TODO: support codec.
/// The state has two purpose:
/// 1. Generate merkle proof.
/// 2. Generate instruction level state.
///
/// The state will be used to execute a instruction in another one step executor.
/// And then diff the merkle root.
pub struct InstanceState<'a> {
    pub initialized: bool,
    // TODO: maybe we do not need this
    // pub func_types: Vec<FuncType>,
    // TODO: maybe we do not need this
    // pub funcs: Vec<&'a FuncEntity<T>>,
    pub tables: Vec<TableState>,
    pub memories: Vec<&'a MemoryEntity>,
    pub globals: Vec<&'a GlobalEntity>,
    // TODO:
    // pub exports: Vec<(&'a str, ExternState)>,
}

#[derive(Clone, Encode, Decode)]
pub struct InstanceSnapshot {
    pub initialized: bool,
    // pub func_types: Vec<FuncType>,
    // pub funcs: Vec<FuncEntity<T>>,
    pub tables: Vec<TableState>,
    // TODO: consider this data field's `instance`.
    pub memories: Vec<MemoryEntityState>,
    pub globals: Vec<GlobalEntity>,
    // pub exports: Vec<(String, ExternState)>,
}

#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct MemoryEntityState {
    pub memory_type: MemoryTypeState,
    pub current_pages: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct MemoryTypeState {
    pub initial_pages: u32,
    pub maximum_pages: Option<u32>,
}

impl From<MemoryTypeState> for MemoryType {
    fn from(t: MemoryTypeState) -> Self {
        Self::new(t.initial_pages, t.maximum_pages)
    }
}

impl From<MemoryEntityState> for MemoryEntity {
    fn from(t: MemoryEntityState) -> Self {
        Self {
            bytes: ByteBuffer { bytes: t.bytes },
            memory_type: t.memory_type.into(),
            current_pages: Pages(t.current_pages as usize),
        }
    }
}

impl From<MemoryEntity> for MemoryEntityState {
    fn from(mem: MemoryEntity) -> Self {
        Self {
            memory_type: MemoryTypeState {
                initial_pages: mem.memory_type().initial_pages().0 as u32,
                maximum_pages: mem.memory_type().maximum_pages().map(|x| x.0 as u32),
            },
            current_pages: mem.current_pages.0 as u32,
            bytes: mem.bytes.bytes,
        }
    }
}

impl<'a> Encode for InstanceState<'a> {
    fn encode_to<O: Output + ?Sized>(&self, dest: &mut O) {
        self.initialized.encode_to(dest);
        self.tables.encode_to(dest);
        // TODO: codec

        for mem in self.memories.iter() {
            // TODO: order
            (mem.memory_type.initial_pages().0 as u32).encode_to(dest);
            (mem.memory_type.maximum_pages().map(|page| page.0 as u32)).encode_to(dest);
            (mem.current_pages.0 as u32).encode_to(dest);
            mem.bytes.data().encode_to(dest);
        }

        for global in self.globals.iter() {
            global.encode_to(dest);
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TableState {
    /// Table type
    pub table_type: TableTypeState,
    /// Element index
    pub elements: Vec<Option<u32>>,
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TableTypeState {
    /// The initial size of the [`Table`].
    initial: u32,
    /// The optional maximum size fo the [`Table`].
    maximum: Option<u32>,
}

impl From<TableType> for TableTypeState {
    fn from(t: TableType) -> Self {
        Self {
            initial: t.initial() as u32,
            maximum: t.maximum().map(|x| x as u32),
        }
    }
}

/// An external reference to corresponding field in `InstanceState`.
#[derive(Debug, Copy, Clone, Encode, Decode)]
pub enum ExternState {
    /// An externally defined global variable.
    Global(u32),
    /// An externally defined table.
    Table(u32),
    /// An externally defined linear memory.
    Memory(u32),
    /// An externally defined Wasm or host function.
    Func(u32),
}

impl InstanceEntity {
    pub fn make_snapshot(&self, ctx: &impl AsContext) -> InstanceSnapshot {
        let store = ctx.as_context().store;
        let tables = self
            .tables
            .iter()
            .map(|table| {
                let table = store.resolve_table(table.clone());

                let mut elements_index = Vec::new();

                for elem in table.elements.iter() {
                    match elem {
                        None => elements_index.push(None),
                        Some(func) => {
                            let func_index = self
                                .funcs
                                .binary_search(func)
                                .expect("function ref in table must exist in funcs");
                            elements_index.push(Some(func_index as u32))
                        }
                    }
                }
                TableState {
                    table_type: table.table_type().into(),
                    elements: elements_index,
                }
            })
            .collect();

        let memories = self
            .memories
            .iter()
            .map(|mem| {
                let mem = store.resolve_memory(mem.clone()).clone();
                mem.into()
            })
            .collect();

        let globals = self
            .globals
            .iter()
            .map(|global| {
                let global = store.resolve_global(global.clone());
                global.clone()
            })
            .collect();

        InstanceSnapshot {
            initialized: self.initialized,
            tables,
            memories,
            globals,
        }
    }

    pub fn as_state<'a>(&'a self, ctx: &'a impl AsContext) -> InstanceState<'a> {
        let store = ctx.as_context().store;

        // let func_types = self
        //     .func_types
        //     .iter()
        //     .map(|func| store.resolve_func_type(func.clone()))
        //     .collect();

        // let funcs = self
        //     .funcs
        //     .iter()
        //     .map(|func| store.resolve_func(func.clone()))
        //     .collect();

        let globals = self
            .globals
            .iter()
            .map(|global| store.resolve_global(global.clone()))
            .collect();

        let memories = self
            .memories
            .iter()
            .map(|mem| store.resolve_memory(mem.clone()))
            .collect();

        let tables = self
            .tables
            .iter()
            .map(|table| {
                let table = store.resolve_table(table.clone());

                let mut elements_index = Vec::new();

                for elem in table.elements.iter() {
                    match elem {
                        None => elements_index.push(None),
                        Some(func) => {
                            let func_index = self
                                .funcs
                                .binary_search(func)
                                .expect("function ref in table must exist in funcs");
                            elements_index.push(Some(func_index as u32))
                        }
                    }
                }
                TableState {
                    table_type: table.table_type().into(),
                    elements: elements_index,
                }
            })
            .collect();

        // let exports = self
        //     .exports
        //     .iter()
        //     .map(|(name, ext)| {
        //         let index = match ext {
        //             Extern::Memory(mem) => ExternState::Memory(
        //                 self.memories
        //                     .binary_search(mem)
        //                     .expect("exported memory must exist; qed")
        //                     as u32,
        //             ),
        //             Extern::Func(func) => ExternState::Func(
        //                 self.funcs
        //                     .binary_search(func)
        //                     .expect("exported func must exist; qed") as u32,
        //             ),
        //             Extern::Table(table) => ExternState::Table(
        //                 self.tables
        //                     .binary_search(table)
        //                     .expect("exported table must exist; qed")
        //                     as u32,
        //             ),
        //             Extern::Global(global) => ExternState::Global(
        //                 self.globals
        //                     .binary_search(global)
        //                     .expect("exported global must exist; qed")
        //                     as u32,
        //             ),
        //         };
        //
        //         (name.as_str(), index)
        //     })
        //     .collect();

        InstanceState {
            initialized: self.initialized,
            // func_types,
            globals,
            memories,
            tables,
            // funcs,
            // exports,
        }
    }

    /// Creates an uninitialized [`InstanceEntity`].
    pub(crate) fn uninitialized() -> InstanceEntity {
        Self {
            initialized: false,
            func_types: Vec::new(),
            tables: Vec::new(),
            funcs: Vec::new(),
            memories: Vec::new(),
            globals: Vec::new(),
            exports: BTreeMap::new(),
        }
    }

    /// Creates a new [`InstanceEntityBuilder`].
    pub(crate) fn build() -> InstanceEntityBuilder {
        InstanceEntityBuilder {
            instance: Self {
                initialized: false,
                func_types: Vec::default(),
                tables: Vec::default(),
                funcs: Vec::default(),
                memories: Vec::default(),
                globals: Vec::default(),
                exports: BTreeMap::default(),
            },
        }
    }

    /// Returns `true` if the [`InstanceEntity`] has been fully initialized.
    pub(crate) fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the linear memory at the `index` if any.
    pub(crate) fn get_memory(&self, index: u32) -> Option<Memory> {
        self.memories.get(index as usize).copied()
    }

    /// Returns the table at the `index` if any.
    pub(crate) fn get_table(&self, index: u32) -> Option<Table> {
        self.tables.get(index as usize).copied()
    }

    /// Returns the global variable at the `index` if any.
    pub(crate) fn get_global(&self, index: u32) -> Option<Global> {
        self.globals.get(index as usize).copied()
    }

    /// Returns the function at the `index` if any.
    pub(crate) fn get_func(&self, index: u32) -> Option<Func> {
        self.funcs.get(index as usize).copied()
    }

    /// Returns the signature at the `index` if any.
    pub(crate) fn get_signature(&self, index: u32) -> Option<DedupFuncType> {
        self.func_types.get(index as usize).copied()
    }

    /// Returns the value exported to the given `name` if any.
    pub(crate) fn get_export(&self, name: &str) -> Option<Extern> {
        self.exports.get(name).copied()
    }

    /// Returns an iterator over the exports of the [`Instance`].
    ///
    /// The order of the yielded exports is not specified.
    pub fn exports(&self) -> ExportsIter {
        ExportsIter::new(self.exports.iter())
    }
}

/// An iterator over the [`Extern`] declarations of an [`Instance`].
#[derive(Debug)]
pub struct ExportsIter<'a> {
    iter: btree_map::Iter<'a, String, Extern>,
}

impl<'a> ExportsIter<'a> {
    /// Creates a new [`ExportsIter`].
    fn new(iter: btree_map::Iter<'a, String, Extern>) -> Self {
        Self { iter }
    }

    /// Prepares an item to match the expected iterator `Item` signature.
    fn convert_item((name, export): (&'a String, &'a Extern)) -> (&'a str, &'a Extern) {
        (name.as_str(), export)
    }
}

impl<'a> Iterator for ExportsIter<'a> {
    type Item = (&'a str, &'a Extern);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(Self::convert_item)
    }
}

impl DoubleEndedIterator for ExportsIter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.iter.next_back().map(Self::convert_item)
    }
}

impl ExactSizeIterator for ExportsIter<'_> {
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl FusedIterator for ExportsIter<'_> {}

/// A module instance entity builder.
#[derive(Debug)]
pub struct InstanceEntityBuilder {
    /// The [`InstanceEntity`] under construction.
    pub(crate) instance: InstanceEntity,
}

impl InstanceEntityBuilder {
    /// Pushes a new [`Memory`] to the [`InstanceEntity`] under construction.
    pub(crate) fn push_memory(&mut self, memory: Memory) {
        self.instance.memories.push(memory);
    }

    /// Pushes a new [`Table`] to the [`InstanceEntity`] under construction.
    pub(crate) fn push_table(&mut self, table: Table) {
        self.instance.tables.push(table);
    }

    /// Pushes a new [`Global`] to the [`InstanceEntity`] under construction.
    pub(crate) fn push_global(&mut self, global: Global) {
        self.instance.globals.push(global);
    }

    /// Pushes a new [`Func`] to the [`InstanceEntity`] under construction.
    pub(crate) fn push_func(&mut self, func: Func) {
        self.instance.funcs.push(func);
    }

    /// Pushes a new deduplicated [`FuncType`] to the [`InstanceEntity`]
    /// under construction.
    ///
    /// [`FuncType`]: [`crate::FuncType`]
    pub(crate) fn push_func_type(&mut self, func_type: DedupFuncType) {
        self.instance.func_types.push(func_type);
    }

    /// Pushes a new [`Extern`] under the given `name` to the [`InstanceEntity`] under construction.
    ///
    /// # Panics
    ///
    /// If the name has already been used by an already pushed [`Extern`].
    pub(crate) fn push_export(&mut self, name: &str, new_value: Extern) {
        if let Some(old_value) = self.instance.exports.get(name) {
            panic!(
                "tried to register {:?} for name {} but name is already used by {:?}",
                new_value, name, old_value,
            )
        }
        self.instance.exports.insert(name.to_string(), new_value);
    }

    /// Finishes constructing the [`InstanceEntity`].
    pub(crate) fn finish(mut self) -> InstanceEntity {
        self.instance.initialized = true;
        self.instance
    }
}

impl Deref for InstanceEntityBuilder {
    type Target = InstanceEntity;

    fn deref(&self) -> &Self::Target {
        &self.instance
    }
}

/// A Wasm module instance reference.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Instance(Stored<InstanceIdx>);

impl Instance {
    /// Creates a new stored instance reference.
    ///
    /// # Note
    ///
    /// This API is primarily used by the [`Store`] itself.
    ///
    /// [`Store`]: [`crate::v1::Store`]
    pub(super) fn from_inner(stored: Stored<InstanceIdx>) -> Self {
        Self(stored)
    }

    /// Returns the underlying stored representation.
    pub(super) fn into_inner(self) -> Stored<InstanceIdx> {
        self.0
    }

    /// Returns the linear memory at the `index` if any.
    ///
    /// # Panics
    ///
    /// Panics if `store` does not own this [`Instance`].
    pub(crate) fn get_memory(&self, store: impl AsContext, index: u32) -> Option<Memory> {
        store
            .as_context()
            .store
            .resolve_instance(*self)
            .get_memory(index)
    }

    /// Returns the table at the `index` if any.
    ///
    /// # Panics
    ///
    /// Panics if `store` does not own this [`Instance`].
    pub(crate) fn get_table(&self, store: impl AsContext, index: u32) -> Option<Table> {
        store
            .as_context()
            .store
            .resolve_instance(*self)
            .get_table(index)
    }

    /// Returns the global variable at the `index` if any.
    ///
    /// # Panics
    ///
    /// Panics if `store` does not own this [`Instance`].
    pub(crate) fn get_global(&self, store: impl AsContext, index: u32) -> Option<Global> {
        store
            .as_context()
            .store
            .resolve_instance(*self)
            .get_global(index)
    }

    /// Returns the function at the `index` if any.
    ///
    /// # Panics
    ///
    /// Panics if `store` does not own this [`Instance`].
    pub(crate) fn get_func(&self, store: impl AsContext, index: u32) -> Option<Func> {
        store
            .as_context()
            .store
            .resolve_instance(*self)
            .get_func(index)
    }

    /// Returns the signature at the `index` if any.
    ///
    /// # Panics
    ///
    /// Panics if `store` does not own this [`Instance`].
    pub(crate) fn get_signature(&self, store: impl AsContext, index: u32) -> Option<DedupFuncType> {
        store
            .as_context()
            .store
            .resolve_instance(*self)
            .get_signature(index)
    }

    /// Returns the value exported to the given `name` if any.
    ///
    /// # Panics
    ///
    /// Panics if `store` does not own this [`Instance`].
    pub fn get_export(&self, store: impl AsContext, name: &str) -> Option<Extern> {
        store
            .as_context()
            .store
            .resolve_instance(*self)
            .get_export(name)
    }

    /// Returns an iterator over the exports of the [`Instance`].
    ///
    /// The order of the yielded exports is not specified.
    ///
    /// # Panics
    ///
    /// Panics if `store` does not own this [`Instance`].
    pub fn exports<'a, T: 'a>(&self, store: impl Into<StoreContext<'a, T>>) -> ExportsIter<'a> {
        store.into().store.resolve_instance(*self).exports()
    }

    // TODO: docs
    pub fn make_snapshot(&self, store: &impl AsContext) -> InstanceSnapshot {
        let ctx = store.as_context();
        let instance = ctx.store.resolve_instance(*self);
        instance.clone().make_snapshot(store)
    }
}
