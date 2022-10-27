use alloc::vec::Vec;

use digest::Digest;
use sha3::Keccak256;
use codec::{Encode, Decode};

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

// TODO: remove this enum. We should use generics merkle type.
/// The merkle node type for different wasm part state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum MerkleType {
    // TODO: I think these are useless, let's remove these.
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

pub fn hash_node(a: Bytes32, b: Bytes32) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// The struct contains a merkle proof for a leaf.
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct ProveData(Vec<Bytes32>);

impl ProveData {
    pub fn inner(&self) -> &[Bytes32] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<Bytes32> {
        self.0
    }

    pub fn compute_root(&self, index: usize, leaf_hash: Bytes32) -> Bytes32 {
        compute_root(self.inner(), index, leaf_hash)
    }
}

pub fn compute_root(prove_data: &[Bytes32], mut index: usize, leaf_hash: Bytes32) -> Bytes32 {
    let mut hash = leaf_hash;
    for sibling_hash in prove_data.iter() {
        if index & 1 == 0 {
            // even
            hash = hash_node(hash, sibling_hash.clone());
        } else {
            // odd
            hash = hash_node(sibling_hash.clone(), hash);
        }
        index >>= 1;
    }

    hash
}

// TODO: redesign this data structure.
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
                    hash_node(window[0], window.get(1).cloned().unwrap_or(empty_layer))
                })
                .collect();
            empty_layers.push(hash_node(empty_layer, empty_layer));
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

    pub fn prove(&self, mut idx: usize) -> Option<ProveData> {
        if idx >= self.leaves().len() {
            return None;
        }
        // TODO: redesign this codec
        let mut proof = ProveData(Vec::new());
        for (layer_i, layer) in self.layers.iter().enumerate() {
            if layer_i == self.layers.len() - 1 {
                break;
            }
            let counterpart = idx ^ 1;
            let hash = layer
                .get(counterpart)
                .cloned()
                .unwrap_or_else(|| self.empty_layers[layer_i]);
            idx >>= 1;
            proof.0.push(hash);
        }
        Some(proof)
    }

    /// A variant prove that not contains the leaf node.
    pub fn prove_without_leaf(&self, idx: usize) -> Option<ProveData> {
        // TODO: optimize this ops
        self.prove(idx).map(|mut proof| {
            proof.0.remove(0);
            proof
        })
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
                next_hash = hash_node(next_hash, counterpart);
            } else {
                next_hash = hash_node(counterpart, next_hash);
            }
            idx >>= 1;
        }
    }
}
