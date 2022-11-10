use crate::{
    proof::{MemoryPage, MemoryProof, TableProof},
    snapshot::{InstanceSnapshot, MemorySnapshot, TableElementSnapshot, TableSnapshot},
    GlobalEntity,
};
use accel_merkle::{GlobalMerkle, MemoryMerkle, MerkleHasher, TableMerkle};
use alloc::vec::Vec;
use wasmi_core::UntypedValue;

pub const MEMORY_LEAF_SIZE: usize = 32;
// TODO: redesign this part
/// The number of layers in the memory merkle tree
/// 1 + log2(2^32 / LEAF_SIZE) = 1 + log2(2^(32 - log2(LEAF_SIZE))) = 1 + 32 - 5
const MEMORY_LAYERS: usize = 1 + 32 - 5;

/// hash the memory bytes.
pub fn hash_memory_leaf<Hasher: MerkleHasher>(bytes: [u8; MEMORY_LEAF_SIZE]) -> Hasher::Output {
    Hasher::hash(&bytes)
}

fn round_up_to_power_of_two(mut input: usize) -> usize {
    if input == 0 {
        return 1;
    }
    input -= 1;
    1usize
        .checked_shl(usize::BITS - input.leading_zeros())
        .expect("Can't round buffer up to power of two and fit in memory")
}

/// Overflow safe divide and round up
fn div_round_up(num: usize, denom: usize) -> usize {
    let mut res = num / denom;
    if num % denom > 0 {
        res += 1;
    }
    res
}

// TODO: design cache for some merkle nodes.

impl InstanceSnapshot {
    pub fn global_merkle<Hasher>(&self) -> Option<GlobalMerkle<Hasher>>
    where
        Hasher: MerkleHasher,
    {
        if self.globals.is_empty() {
            return None;
        }
        let globals = self
            .globals
            .iter()
            .map(|global| global_hash::<Hasher>(global))
            .collect();

        Some(GlobalMerkle::new(globals))
    }

    pub fn memory_proofs<Hasher>(&self) -> Vec<MemoryProof<Hasher>>
    where
        Hasher: MerkleHasher,
    {
        self.memories
            .iter()
            .map(|mem| {
                let merkle = mem.merkle::<Hasher>();
                MemoryProof {
                    page: MemoryPage {
                        initial_pages: mem.memory_type.initial_pages,
                        maximum_pages: mem.memory_type.maximum_pages,
                        current_pages: mem.current_pages,
                    },
                    merkle,
                }
            })
            .collect()
    }

    pub fn table_proofs<Hasher>(&self) -> Vec<TableProof<Hasher>>
    where
        Hasher: MerkleHasher,
    {
        self.tables
            .iter()
            .map(|table| TableProof::<Hasher> {
                merkle: table.merkle(),
                initial: table.table_type.initial,
                maximum: table.table_type.maximum,
            })
            .collect()
    }
}

impl MemorySnapshot {
    pub fn merkle<Hasher>(&self) -> MemoryMerkle<Hasher>
    where
        Hasher: MerkleHasher,
    {
        // Round the size up to 32 bytes size leaves, then round up to the next power of two number of leaves
        let leaves = round_up_to_power_of_two(div_round_up(self.bytes.len(), MEMORY_LEAF_SIZE));
        let mut leaf_hashes: Vec<Hasher::Output> = self
            .bytes
            .chunks(MEMORY_LEAF_SIZE)
            .map(|leaf| {
                let mut full_leaf = [0u8; MEMORY_LEAF_SIZE];
                full_leaf[..leaf.len()].copy_from_slice(leaf);
                hash_memory_leaf::<Hasher>(full_leaf)
            })
            .collect();
        if leaf_hashes.len() < leaves {
            let empty_hash = hash_memory_leaf::<Hasher>([0u8; MEMORY_LEAF_SIZE]);
            leaf_hashes.resize(leaves, empty_hash);
        }
        MemoryMerkle::new_advanced(
            leaf_hashes,
            hash_memory_leaf::<Hasher>([0u8; MEMORY_LEAF_SIZE]),
            MEMORY_LAYERS,
        )
    }
}

/// The hashing rule for wasm table element.
pub fn table_element_hash<Hasher>(elem: &TableElementSnapshot) -> Hasher::Output
where
    Hasher: MerkleHasher,
{
    Hasher::hash_of(elem)
}

/// The hashing rule for wasm value.
pub fn value_hash<Hasher>(val: UntypedValue) -> Hasher::Output
where
    Hasher: MerkleHasher,
{
    Hasher::hash_of(&val)
}

/// The hashing rule for wasm global value.
pub fn global_hash<Hasher>(global: &GlobalEntity) -> Hasher::Output
where
    Hasher: MerkleHasher,
{
    value_hash::<Hasher>(global.get_untyped())
}

impl TableSnapshot {
    pub fn merkle<Hasher>(&self) -> TableMerkle<Hasher>
    where
        Hasher: MerkleHasher,
    {
        let hashes = self
            .elements
            .iter()
            .map(table_element_hash::<Hasher>)
            .collect::<Vec<Hasher::Output>>();
        TableMerkle::<Hasher>::new(hashes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_round_up_power_of_two() {
        assert_eq!(round_up_to_power_of_two(0), 1);
        assert_eq!(round_up_to_power_of_two(1), 1);
        assert_eq!(round_up_to_power_of_two(2), 2);
        assert_eq!(round_up_to_power_of_two(3), 4);
        assert_eq!(round_up_to_power_of_two(4), 4);
        assert_eq!(round_up_to_power_of_two(5), 8);
        assert_eq!(round_up_to_power_of_two(6), 8);
        assert_eq!(round_up_to_power_of_two(7), 8);
        assert_eq!(round_up_to_power_of_two(8), 8);
    }
}
