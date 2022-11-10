//! Module instance level snapshot.

use crate::{
    errors::MemoryError,
    memory::ByteBuffer,
    proof::FuncNode,
    GlobalEntity,
    MemoryEntity,
    MemoryType,
    TableType,
};
use alloc::vec::Vec;
use codec::{Decode, Encode};
use wasmi_core::{Pages, ValueType};

/// The wasm state snapshot of instance component.
#[derive(Clone, Encode, Decode)]
pub struct InstanceSnapshot {
    /// All global values.
    pub globals: Vec<GlobalEntity>,
    /// All memory states.
    pub memories: Vec<MemorySnapshot>,
    /// All table states.
    pub tables: Vec<TableSnapshot>,
}

/// A linear memory entity.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct MemorySnapshot {
    pub memory_type: MemoryTypeSnapshot,
    pub current_pages: u32,
    pub bytes: Vec<u8>,
}

/// The memory type of a linear memory.
#[derive(Clone, Eq, PartialEq, Encode, Decode)]
pub struct MemoryTypeSnapshot {
    pub initial_pages: u32,
    pub maximum_pages: Option<u32>,
}

impl TryFrom<MemoryTypeSnapshot> for MemoryType {
    type Error = MemoryError;

    fn try_from(t: MemoryTypeSnapshot) -> Result<Self, Self::Error> {
        Self::new(t.initial_pages, t.maximum_pages)
    }
}

impl TryFrom<MemorySnapshot> for MemoryEntity {
    type Error = MemoryError;

    fn try_from(mem: MemorySnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: ByteBuffer { bytes: mem.bytes },
            memory_type: MemoryType::new(
                mem.memory_type.initial_pages,
                mem.memory_type.maximum_pages,
            )?,
            current_pages: Pages(mem.current_pages),
        })
    }
}

impl From<MemoryEntity> for MemorySnapshot {
    fn from(mem: MemoryEntity) -> Self {
        Self {
            memory_type: MemoryTypeSnapshot {
                initial_pages: mem.memory_type().initial_pages().into_inner(),
                maximum_pages: mem.memory_type().maximum_pages().map(Pages::into_inner),
            },
            current_pages: mem.current_pages.into_inner(),
            bytes: mem.bytes.bytes,
        }
    }
}

/// A table snapshot.
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TableSnapshot {
    /// Table type.
    pub table_type: TableTypeSnapshot,
    /// Element index.
    pub elements: Vec<TableElementSnapshot>,
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub enum TableElementSnapshot {
    /// The table element is empty.
    Empty,
    /// The func index and its type.
    FuncIndex(u32, FuncNode),
}

/// The function type signature.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct FuncType {
    /// The params types.
    pub params: Vec<ValueType>,
    /// The return types.
    pub results: Vec<ValueType>,
}

impl From<crate::FuncType> for FuncType {
    fn from(value: crate::FuncType) -> Self {
        Self {
            params: value.params().to_vec(),
            results: value.results().to_vec(),
        }
    }
}

/// A descriptor for a Table.
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TableTypeSnapshot {
    /// The initial size of the [`Table`].
    pub initial: u32,
    /// The optional maximum size fo the [`Table`].
    pub maximum: Option<u32>,
}

impl From<TableType> for TableTypeSnapshot {
    fn from(t: TableType) -> Self {
        Self {
            initial: t.initial() as u32,
            maximum: t.maximum().map(|x| x as u32),
        }
    }
}
