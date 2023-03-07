use crate::{
    proof::MemoryPage,
    snapshot::{InstanceSnapshot, MemorySnapshot, TableElementSnapshot, TableSnapshot},
    GlobalEntity,
};
use accel_merkle::{
    empty_chunk,
    memory_chunk_size,
    memory_merkle_depth,
    GlobalMerkle,
    MemoryMerkle,
    MerkleConfig,
    MerkleHasher,
    OutputOf,
    TableMerkle,
};
use alloc::vec::Vec;
use wasmi_core::UntypedValue;

/// All proof data for an instance at a checkpoint.
#[derive(Debug)]
pub struct InstanceMerkle<Config>
where
    Config: MerkleConfig,
{
    pub globals: Option<GlobalMerkle<Config::Hasher>>,
    pub memories: Vec<MemoryProof<Config>>,
    pub tables: Vec<TableProof<Config::Hasher>>,
}

#[derive(Debug)]
pub struct MemoryProof<Config>
where
    Config: MerkleConfig,
{
    // TODO:
    pub page: MemoryPage,
    pub merkle: MemoryMerkle<Config>,
}

#[derive(Debug)]
pub struct TableProof<Hasher>
where
    Hasher: MerkleHasher,
{
    pub initial: u32,
    pub maximum: Option<u32>,
    pub merkle: TableMerkle<Hasher>,
}

impl<Config> InstanceMerkle<Config>
where
    Config: MerkleConfig,
{
    /// Generate an instance proof by snapshot.
    pub fn generate(instance: InstanceSnapshot) -> Self {
        Self {
            globals: instance.global_merkle(),
            memories: instance.memory_proofs(),
            tables: instance.table_proofs(),
        }
    }
}

// /// hash the memory bytes.
// pub fn hash_memory_leaf<T: MemoryMerkleConfig>(bytes: [u8; T::MEMORY_CHUNK_SIZE]) -> <T::Hasher as MerkleHasher>::Output {
//     <T::Hasher as MerkleHasher>::hash(&bytes)
// }

/// hash the memory bytes.
pub fn hash_memory_leaf<Hasher: MerkleHasher>(bytes: &[u8]) -> Hasher::Output {
    Hasher::hash(bytes)
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

    pub fn memory_proofs<Config>(&self) -> Vec<MemoryProof<Config>>
    where
        Config: MerkleConfig,
    {
        self.memories
            .iter()
            .map(|mem| {
                let merkle = mem.merkle::<Config>();
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
    // TODO: redesign this part.
    pub fn merkle<Config>(&self) -> MemoryMerkle<Config>
    where
        Config: MerkleConfig,
    {
        // Round the size up to 32 bytes size leaves, then round up to the next power of two number of leaves
        let leaves = round_up_to_power_of_two(div_round_up(
            self.bytes.len(),
            memory_chunk_size::<Config>(),
        ));

        let empty_leaf = empty_chunk::<Config>();
        let empty_hash = hash_memory_leaf::<Config::Hasher>(empty_leaf.as_ref());

        let mut leaf_hashes: Vec<OutputOf<Config>> = self
            .bytes
            .chunks(memory_chunk_size::<Config>())
            .map(|leaf| {
                let mut full_leaf = empty_chunk::<Config>();
                let full_leaf_mut = full_leaf.as_mut();
                full_leaf_mut[..leaf.len()].copy_from_slice(leaf);
                hash_memory_leaf::<Config::Hasher>(full_leaf.as_ref())
            })
            .collect();

        if leaf_hashes.len() < leaves {
            leaf_hashes.resize(leaves, empty_hash.clone());
        }

        MemoryMerkle::new_advanced(leaf_hashes, empty_hash, memory_merkle_depth::<Config>())
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
        assert_eq!(round_up_to_power_of_two(9), 16);
    }
}
