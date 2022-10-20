mod engine;
mod instance;

use crate::MemoryEntity;
use core::cmp;
pub use engine::*;
pub use instance::*;

/// Get memory byte32 by leaf index. Returns a empty leaf if not exists.
pub fn get_memory_leaf(memory: &MemoryEntity, leaf_idx: usize) -> [u8; MEMORY_LEAF_SIZE] {
    let mut buf = [0u8; MEMORY_LEAF_SIZE];
    let idx = match leaf_idx.checked_mul(MEMORY_LEAF_SIZE) {
        Some(x) if x < memory.data().len() => x,
        _ => return buf,
    };
    let size = cmp::min(MEMORY_LEAF_SIZE, memory.data().len() - idx);
    buf[..size].copy_from_slice(&memory.data()[idx..(idx + size)]);
    buf
}
