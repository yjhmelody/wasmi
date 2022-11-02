use alloc::vec::Vec;
use core::fmt::Debug;

use codec::{Decode, Encode};
use digest::Digest;
use sha3::Keccak256;

use crate::bytes32::Bytes32;

pub fn keccak256(bytes: &[u8]) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

pub fn hash_node(a: Bytes32, b: Bytes32) -> Bytes32 {
    let mut h = Keccak256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

// TODO: generalize
pub trait MerkleTrait: Debug {}

#[derive(Debug)]
pub struct MemoryType;
pub type MemoryMerkle = Merkle<MemoryType>;
impl MerkleTrait for MemoryType {}

#[derive(Debug)]
pub struct TableType;
pub type TableMerkle = Merkle<TableType>;
impl MerkleTrait for TableType {}

#[derive(Debug)]
pub struct GlobalType;
pub type GlobalMerkle = Merkle<GlobalType>;
impl MerkleTrait for GlobalType {}

#[derive(Debug)]
pub struct InstructionType;
pub type InstructionMerkle = Merkle<InstructionType>;
impl MerkleTrait for InstructionType {}

// TODO: it's altered from arb. Should be generalized to be a good crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merkle<T: MerkleTrait> {
    _type: core::marker::PhantomData<T>,
    layers: Vec<Vec<Bytes32>>,
    /// Keep the empty hash value of different layer.
    empty_layers: Vec<Bytes32>,
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

fn compute_root(prove_data: &[Bytes32], mut index: usize, leaf_hash: Bytes32) -> Bytes32 {
    let mut hash = leaf_hash;
    for sibling_hash in prove_data.iter() {
        if index & 1 == 0 {
            // even
            hash = hash_node(hash, *sibling_hash);
        } else {
            // odd
            hash = hash_node(*sibling_hash, hash);
        }
        index >>= 1;
    }

    hash
}

impl<T: MerkleTrait> Merkle<T> {
    /// Creates a merkle tree according to hashes.
    ///
    /// # Note
    ///
    /// Panic if hashes is empty.
    pub fn new(hashes: Vec<Bytes32>) -> Self {
        Self::new_advanced(hashes, Bytes32::default(), 0)
    }

    /// Creates a merkle tree according to hashes.
    ///
    /// # Note
    ///
    /// Panic if hashes is empty.
    pub fn new_advanced(hashes: Vec<Bytes32>, empty_hash: Bytes32, min_depth: usize) -> Self {
        assert!(hashes.len() > 0);
        let mut layers = vec![hashes];
        let mut empty_layers = vec![empty_hash];
        while layers.last().unwrap().len() > 1 || layers.len() < min_depth {
            let empty_layer = *empty_layers
                .last()
                .expect("empty layer size is not empty; qed");
            let layer = layers.last().expect("layers size is not empty; qed");
            let new_layer = layer
                .chunks(2)
                .map(|window| hash_node(window[0], window.get(1).cloned().unwrap_or(empty_layer)))
                .collect();
            empty_layers.push(hash_node(empty_layer, empty_layer));
            layers.push(new_layer);
        }
        Self {
            layers,
            empty_layers,
            _type: Default::default(),
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
        let len = self.layers.len();
        for (layer_i, layer) in self.layers[..len - 1].iter().enumerate() {
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
