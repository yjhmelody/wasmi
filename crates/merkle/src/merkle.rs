use alloc::vec::Vec;

use digest::Digest;
use sha3::Keccak256;

use crate::bytes32::Bytes32;

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

/// The merkle node type for different wasm part state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MerkleType {
    // TODO: remove this type.
    Empty = 0,
    Value = 1,
    Function = 2,
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

impl Merkle {
    pub fn ty(&self) -> MerkleType {
        self.ty
    }

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
