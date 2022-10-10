pub mod engine;

use crate::{memory::ByteBuffer, GlobalEntity, MemoryEntity, MemoryType, TableType};
use codec::{Decode, Encode};
use wasmi_core::memory_units::Pages;

/// The state has two purpose:
/// 1. Generate merkle proof.
/// 2. Generate instruction level state.
///
/// The state will be used to execute a instruction in another one step executor.
/// And then diff the merkle hash.
#[derive(Clone, Encode, Decode)]
pub struct InstanceSnapshot {
    pub initialized: bool,
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

impl From<MemorySnapshot> for MemoryEntity {
    fn from(t: MemorySnapshot) -> Self {
        Self {
            bytes: ByteBuffer { bytes: t.bytes },
            memory_type: t.memory_type.into(),
            current_pages: Pages(t.current_pages as usize),
        }
    }
}

impl From<MemoryEntity> for MemorySnapshot {
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

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TableSnapshot {
    /// Table type.
    pub table_type: TableTypeState,
    /// Element index.
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
