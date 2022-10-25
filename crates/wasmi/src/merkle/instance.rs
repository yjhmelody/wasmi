use crate::{
    snapshot::{InstanceSnapshot, MemorySnapshot, TableElementSnapshot, TableSnapshot},
    GlobalEntity,
};
use accel_merkle::{digest::Digest, sha3::Keccak256, Bytes32, Merkle, MerkleType};
use codec::Encode;

pub const MEMORY_LEAF_SIZE: usize = 32;
/// The number of layers in the memory merkle tree
/// 1 + log2(2^32 / LEAF_SIZE) = 1 + log2(2^(32 - log2(LEAF_SIZE))) = 1 + 32 - 5
const MEMORY_LAYERS: usize = 1 + 32 - 5;

/// hash the memory bytes.
fn hash_memory_leaf(bytes: [u8; MEMORY_LEAF_SIZE]) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
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
    // pub fn hash(&self) -> Bytes32 {
    //     let mut h = Keccak256::new();
    //     // TODO: should use this type?
    //     h.update([MerkleType::Module as u8]);
    //     // TODO: add func merkle root
    //
    //
    //     self.memories.iter().for_each(|mem| h.update(mem.hash()));
    //     self.tables.iter().for_each(|table| h.update(table.hash()));
    //
    //     h.finalize().into()
    // }
    //
    // /// Since one instance only have one module, so we use module instance hash as proof here.
    // pub fn generate_proof(&self) -> Vec<u8> {
    //     self.hash().to_vec()
    // }

    pub fn globals_merkle(&self) -> Merkle {
        let globals = self
            .globals
            .iter()
            .map(|global| global_hash(global))
            .collect();

        Merkle::new(MerkleType::Global, globals)
    }

    pub fn memories_merkle(&self) -> Vec<Merkle> {
        self.memories.iter().map(|mem| mem.merkle()).collect()
    }

    pub fn tables_merkle(&self) -> Vec<Merkle> {
        self.tables.iter().map(|table| table.merkle()).collect()
    }
}

impl MemorySnapshot {
    pub fn merkle(&self) -> Merkle {
        // TODO: maybe we do not need to hash byte32 leaf twice.
        // Round the size up to 32 bytes size leaves, then round up to the next power of two number of leaves
        let leaves = round_up_to_power_of_two(div_round_up(self.bytes.len(), MEMORY_LEAF_SIZE));
        let mut leaf_hashes: Vec<Bytes32> = self
            .bytes
            .chunks(MEMORY_LEAF_SIZE)
            .map(|leaf| {
                let mut full_leaf = [0u8; MEMORY_LEAF_SIZE];
                full_leaf[..leaf.len()].copy_from_slice(leaf);
                hash_memory_leaf(full_leaf)
            })
            .collect();
        if leaf_hashes.len() < leaves {
            let empty_hash = hash_memory_leaf([0u8; MEMORY_LEAF_SIZE]);
            leaf_hashes.resize(leaves, empty_hash);
        }
        Merkle::new_advanced(
            MerkleType::Memory,
            leaf_hashes,
            // TODO: should we relly use this as empty hash?
            hash_memory_leaf([0u8; MEMORY_LEAF_SIZE]),
            MEMORY_LAYERS,
        )
    }

    pub fn hash(&self) -> Bytes32 {
        let mut h = Keccak256::new();
        h.update([MerkleType::Memory as u8]);
        // TODO: add other memory data to hash.
        h.update(self.merkle().root());
        h.finalize().into()
    }
}

fn table_element_hash(elem: &TableElementSnapshot) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(elem.encode());
    h.finalize().into()
}

// TODO: define our own global state.
fn global_hash(global: &GlobalEntity) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(global.get_untyped().encode());
    h.finalize().into()
}

impl TableSnapshot {
    pub fn merkle(&self) -> Merkle {
        let hashes = self
            .elements
            .iter()
            .map(table_element_hash)
            .collect::<Vec<Bytes32>>();
        Merkle::new(MerkleType::Table, hashes)
    }

    pub fn hash(&self) -> Bytes32 {
        let mut h = Keccak256::new();
        let merkle = self.merkle();
        h.update([MerkleType::Table as u8]);
        // TODO: add other memory data to hash.
        h.update(merkle.root());
        h.finalize().into()
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
