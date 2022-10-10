use alloc::vec::Vec;

use codec::Encode;
use digest::Digest;
use sha3::Keccak256;

use crate::bytes32::Bytes32;

pub const LEAF_SIZE: usize = 32;
/// Only used when initializing a memory to determine its size
pub const PAGE_SIZE: u64 = 65536;
/// The number of layers in the memory merkle tree
/// 1 + log2(2^32 / LEAF_SIZE) = 1 + log2(2^(32 - log2(LEAF_SIZE))) = 1 + 32 - 5
const MEMORY_LAYERS: usize = 1 + 32 - 5;

#[derive(Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProofKind {
    Stack = 0,
    ValueStack = 1,
    CallStack = 2,
    Memory = 3,
    Global = 4,
}

// TODO: design the encode/decode spec.
pub trait ProofGenerator {
    /// Write the part of state proof of executor.
    fn write_proof(&self, proof_buf: &mut Vec<u8>);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MerkleType {
    Empty = 0,
    Value = 1,
    Function = 2,
    // TODO: maybe support instruction proof
    Instruction = 3,
    Memory = 4,
    Table = 5,
    TableElement = 6,
    Module = 7,
    Global = 8,
}

impl Default for MerkleType {
    fn default() -> Self {
        Self::Empty
    }
}

// TODO: it's altered from arb. Should be generalized to be a good crate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Merkle {
    ty: MerkleType,
    layers: Vec<Vec<Bytes32>>,
    empty_layers: Vec<Bytes32>,
}

fn hash_node(ty: MerkleType, a: Bytes32, b: Bytes32) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update([ty as u8]);
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// hash the memory bytes.
fn hash_memory_leaf(bytes: [u8; LEAF_SIZE]) -> Bytes32 {
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

impl Merkle {
    pub fn new(ty: MerkleType, hashes: Vec<Bytes32>) -> Self {
        Self::new_advanced(ty, hashes, Bytes32::default(), 0)
    }

    pub fn new_advanced(
        ty: MerkleType,
        hashes: Vec<Bytes32>,
        empty_hash: Bytes32,
        min_depth: usize,
    ) -> Self {
        if hashes.is_empty() {
            return Self::default();
        }
        let mut layers = vec![hashes];
        let mut empty_layers = vec![empty_hash];
        while layers.last().unwrap().len() > 1 || layers.len() < min_depth {
            let empty_layer = *empty_layers
                .last()
                .expect("empty layer size is not empty; qed");
            let layer = layers.last().expect("layers size is not empty; qed");
            let new_layer = layer
                .chunks(2)
                .map(|window| {
                    hash_node(ty, window[0], window.get(1).cloned().unwrap_or(empty_layer))
                })
                .collect();
            empty_layers.push(hash_node(ty, empty_layer, empty_layer));
            layers.push(new_layer);
        }
        Merkle {
            ty,
            layers,
            empty_layers,
        }
    }

    pub fn root(&self) -> Bytes32 {
        if let Some(layer) = self.layers.last() {
            assert_eq!(layer.len(), 1);
            layer[0]
        } else {
            Bytes32::default()
        }
    }

    pub fn leaves(&self) -> &[Bytes32] {
        if self.layers.is_empty() {
            &[]
        } else {
            &self.layers[0]
        }
    }

    pub fn prove(&self, mut idx: usize) -> Option<Vec<u8>> {
        if idx >= self.leaves().len() {
            return None;
        }
        let mut proof = vec![u8::try_from(self.layers.len() - 1).unwrap()];
        for (layer_i, layer) in self.layers.iter().enumerate() {
            if layer_i == self.layers.len() - 1 {
                break;
            }
            let counterpart = idx ^ 1;
            proof.extend(
                layer
                    .get(counterpart)
                    .cloned()
                    .unwrap_or_else(|| self.empty_layers[layer_i]),
            );
            idx >>= 1;
        }
        Some(proof)
    }

    pub fn set(&mut self, mut idx: usize, hash: Bytes32) {
        if self.layers[0][idx] == hash {
            return;
        }
        let mut next_hash = hash;
        let empty_layers = &self.empty_layers;
        let layers_len = self.layers.len();
        for (layer_i, layer) in self.layers.iter_mut().enumerate() {
            layer[idx] = next_hash;
            if layer_i == layers_len - 1 {
                // next_hash isn't needed
                break;
            }
            let counterpart = layer
                .get(idx ^ 1)
                .cloned()
                .unwrap_or_else(|| empty_layers[layer_i]);
            if idx % 2 == 0 {
                next_hash = hash_node(self.ty, next_hash, counterpart);
            } else {
                next_hash = hash_node(self.ty, counterpart, next_hash);
            }
            idx >>= 1;
        }
    }
}

// impl InstanceSnapshot {
//     pub fn hash(&self) -> Bytes32 {
//         let mut h = Keccak256::new();
//         // TODO: should use this type?
//         h.update([MerkleType::Module as u8]);
//         h.update([self.initialized as u8]);
//
//         self.globals
//             .iter()
//             .for_each(|global| h.update(global_hash(global)));
//         self.memories.iter().for_each(|mem| h.update(mem.hash()));
//         self.tables.iter().for_each(|table| h.update(table.hash()));
//
//         h.finalize().into()
//     }
// }
//
// impl MemorySnapshot {
//     pub fn merkle(&self) -> Merkle {
//         // Round the size up to 32 bytes size leaves, then round up to the next power of two number of leaves
//         let leaves = round_up_to_power_of_two(div_round_up(self.bytes.len(), LEAF_SIZE));
//         let mut leaf_hashes: Vec<Bytes32> = self
//             .bytes
//             .chunks(LEAF_SIZE)
//             .map(|leaf| {
//                 let mut full_leaf = [0u8; LEAF_SIZE];
//                 full_leaf[..leaf.len()].copy_from_slice(leaf);
//                 hash_memory_leaf(full_leaf)
//             })
//             .collect();
//         if leaf_hashes.len() < leaves {
//             let empty_hash = hash_memory_leaf([0u8; LEAF_SIZE]);
//             leaf_hashes.resize(leaves, empty_hash);
//         }
//         Merkle::new_advanced(
//             MerkleType::Memory,
//             leaf_hashes,
//             // TODO: should we relly use this as empty hash?
//             hash_memory_leaf([0u8; LEAF_SIZE]),
//             MEMORY_LAYERS,
//         )
//     }
//
//     pub fn hash(&self) -> Bytes32 {
//         let mut h = Keccak256::new();
//         h.update([MerkleType::Memory as u8]);
//         // TODO: add other memory data to hash.
//         h.update(self.merkle().root());
//         h.finalize().into()
//     }
// }
//
// fn table_element_hash(elem: &Option<u32>) -> Bytes32 {
//     let mut h = Keccak256::new();
//     h.update([MerkleType::TableElement as u8]);
//     h.update(elem.encode());
//     h.finalize().into()
// }
//
// // TODO: define our own global state.
// fn global_hash(global: &GlobalEntity) -> Bytes32 {
//     let mut h = Keccak256::new();
//     h.update([MerkleType::Global as u8]);
//     h.update(global.encode());
//     h.finalize().into()
// }
//
// impl TableSnapshot {
//     pub fn merkle(&self) -> Merkle {
//         let hashes = self
//             .elements
//             .iter()
//             .map(table_element_hash)
//             .collect::<Vec<Bytes32>>();
//         Merkle::new(MerkleType::Table, hashes)
//     }
//
//     pub fn hash(&self) -> Bytes32 {
//         let mut h = Keccak256::new();
//         h.update([MerkleType::Table as u8]);
//         // TODO: add other memory data to hash.
//         h.update(self.merkle().root());
//         h.finalize().into()
//     }
// }

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
