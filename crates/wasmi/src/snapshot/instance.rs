//! Module instance level snapshot.

use crate::{
    memory::ByteBuffer,
    merkle::FuncType,
    GlobalEntity,
    MemoryEntity,
    MemoryType,
    TableType,
};
use codec::{Decode, Encode};
use wasmi_core::Pages;

/// The state has two purpose:
/// 1. Generate merkle proof.
/// 2. Generate instruction level state.
#[derive(Clone, Encode, Decode)]
pub struct InstanceSnapshot {
    pub globals: Vec<GlobalEntity>,
    pub memories: Vec<MemorySnapshot>,
    pub tables: Vec<TableSnapshot>,
}

// /// A global variable entity.
// #[derive(Clone, Eq, PartialEq, Encode, Decode)]
// pub struct GlobalSnapshot {
//     /// The current untyped value of the global variable.
//     pub value: u64,
//     /// The value type of the global variable.
//     pub value_type: ValueType,
//     /// The mutability of the global variable.
//     pub is_mutable: bool,
// }
//
// impl From<GlobalEntity> for GlobalSnapshot {
//     fn from(global: GlobalEntity) -> Self {
//         Self::from(&global)
//     }
// }
//
// impl From<&GlobalEntity> for GlobalSnapshot {
//     fn from(global: &GlobalEntity) -> Self {
//         Self {
//             value: global.get_untyped().to_bits(),
//             value_type: global.value_type(),
//             is_mutable: global.is_mutable(),
//         }
//     }
// }

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

// TODO: use TryFrom and define error type.
impl From<MemoryTypeSnapshot> for MemoryType {
    fn from(t: MemoryTypeSnapshot) -> Self {
        Self::new(t.initial_pages, t.maximum_pages).expect("Always be valid; qed")
    }
}

impl From<MemorySnapshot> for MemoryEntity {
    fn from(t: MemorySnapshot) -> Self {
        Self {
            bytes: ByteBuffer { bytes: t.bytes },
            memory_type: t.memory_type.into(),
            current_pages: Pages(t.current_pages),
        }
    }
}

impl From<MemoryEntity> for MemorySnapshot {
    fn from(mem: MemoryEntity) -> Self {
        Self {
            memory_type: MemoryTypeSnapshot {
                initial_pages: mem.memory_type().initial_pages().into_inner(),
                maximum_pages: mem.memory_type().maximum_pages().map(|x| x.into_inner()),
            },
            current_pages: mem.current_pages.into_inner(),
            bytes: mem.bytes.bytes,
        }
    }
}

// TODO: need to store type info for elements
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
    Empty,
    FuncIndex(u32, FuncType),
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
