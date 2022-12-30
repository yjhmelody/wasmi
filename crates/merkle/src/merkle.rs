use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};

use codec::{Decode, Encode};
use digest::Digest;
use sha3::Keccak256;

use crate::{bytes32::Bytes32, MerkleHasher, MerkleTrait};

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct MerkleKeccak256;

impl MerkleHasher for MerkleKeccak256 {
    type Output = Bytes32;

    fn hash(bytes: &[u8]) -> Self::Output {
        let mut h = Keccak256::new();
        h.update(bytes);
        h.finalize().into()
    }

    fn hash_node(a: &Self::Output, b: &Self::Output) -> Self::Output {
        let mut h = Keccak256::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    }
}

// TODO: move to other place
#[derive(Debug)]
pub struct MemoryType;
pub type MemoryMerkle<Hasher> = Merkle<MemoryType, Hasher>;
impl<Hasher: MerkleHasher> MerkleTrait<Hasher> for MemoryType {}

#[derive(Debug)]
pub struct TableType;
pub type TableMerkle<Hasher> = Merkle<TableType, Hasher>;
impl<Hasher: MerkleHasher> MerkleTrait<Hasher> for TableType {}

#[derive(Debug)]
pub struct GlobalType;
pub type GlobalMerkle<Hasher> = Merkle<GlobalType, Hasher>;
impl<Hasher: MerkleHasher> MerkleTrait<Hasher> for GlobalType {}

#[derive(Debug)]
pub struct InstructionType;
pub type InstructionMerkle<Hasher> = Merkle<InstructionType, Hasher>;
impl<Hasher: MerkleHasher> MerkleTrait<Hasher> for InstructionType {}

#[derive(Debug)]
pub struct FuncType;
pub type FuncMerkle<Hasher> = Merkle<FuncType, Hasher>;
impl<Hasher: MerkleHasher> MerkleTrait<Hasher> for FuncType {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merkle<T: MerkleTrait<Hasher>, Hasher: MerkleHasher> {
    _type: core::marker::PhantomData<T>,
    /// The node of different layers.
    layers: Vec<Vec<Hasher::Output>>,
    /// Keep the empty hash value of different layer.
    empty_layers: Vec<Hasher::Output>,
}

/// The struct contains a merkle proof for a leaf.
#[derive(Eq, PartialEq, Encode, Decode)]
pub struct ProveData<T: MerkleHasher>(Vec<T::Output>);

impl<T: MerkleHasher> Debug for ProveData<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<T: MerkleHasher> From<Vec<T::Output>> for ProveData<T> {
    fn from(value: Vec<T::Output>) -> Self {
        Self(value)
    }
}

impl<T: MerkleHasher> Clone for ProveData<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: MerkleHasher> ProveData<T> {
    /// Returns the ref of inner proof path.
    pub fn inner(&self) -> &[T::Output] {
        &self.0
    }

    /// Returns the inner proof path.
    pub fn into_inner(self) -> Vec<T::Output> {
        self.0
    }

    /// Compute the merkle root according to proof.
    pub fn compute_root(&self, index: usize, leaf_hash: T::Output) -> T::Output {
        compute_root::<T>(self.inner(), index, leaf_hash)
    }
}

/// Compute the merkle root according to prove data path and its leaf hash.
pub fn compute_root<T: MerkleHasher>(
    prove_data: &[T::Output],
    mut index: usize,
    leaf_hash: T::Output,
) -> T::Output {
    let mut hash = leaf_hash;
    for sibling_hash in prove_data.iter() {
        if index & 1 == 0 {
            // even
            hash = T::hash_node(&hash, sibling_hash);
        } else {
            // odd
            hash = T::hash_node(sibling_hash, &hash);
        }
        index >>= 1;
    }

    hash
}

impl<T: MerkleTrait<Hasher>, Hasher: MerkleHasher> Merkle<T, Hasher> {
    /// Creates a merkle tree according to hashes.
    ///
    /// # Note
    ///
    /// Panic if hashes is empty.
    pub fn new(hashes: Vec<Hasher::Output>) -> Self {
        Self::new_advanced(hashes, Hasher::Output::default(), 0)
    }

    /// Creates a merkle tree according to hashes iter.
    ///
    /// # Note
    ///
    /// Panic if hashes is empty.
    pub fn with_iter(hashes: impl Iterator<Item = Hasher::Output>) -> Self {
        let hashes: Vec<Hasher::Output> = hashes.into_iter().collect();
        Self::new(hashes)
    }

    /// Creates a merkle tree according to hashes.
    ///
    /// # Note
    ///
    /// Panic if hashes is empty.
    pub fn new_advanced(
        hashes: Vec<Hasher::Output>,
        empty_hash: Hasher::Output,
        min_depth: usize,
    ) -> Self {
        assert!(!hashes.is_empty());

        let mut layers = vec![hashes];
        let mut empty_layers = vec![empty_hash];
        while layers.last().unwrap().len() > 1 || layers.len() < min_depth {
            let empty_layer = empty_layers
                .last()
                .expect("empty layer size is not empty; qed");
            let layer = layers.last().expect("layers size is not empty; qed");
            let new_layer = layer
                .chunks(2)
                .map(|window| Hasher::hash_node(&window[0], window.get(1).unwrap_or(empty_layer)))
                .collect();
            empty_layers.push(Hasher::hash_node(empty_layer, empty_layer));
            layers.push(new_layer);
        }

        Self {
            layers,
            empty_layers,
            _type: Default::default(),
        }
    }

    /// Returns the merkle root.
    pub fn root(&self) -> Hasher::Output {
        if let Some(layer) = self.layers.last() {
            assert_eq!(layer.len(), 1);
            layer[0].clone()
        } else {
            Default::default()
        }
    }

    /// Returns the merkle leaves.
    pub fn leaves(&self) -> &[Hasher::Output] {
        if self.layers.is_empty() {
            &[]
        } else {
            &self.layers[0]
        }
    }

    /// Generate proof path for current leaf.
    ///
    /// # Notes
    ///
    /// Returns None if index is invalid.
    pub fn prove(&self, mut idx: usize) -> Option<ProveData<Hasher>> {
        if idx >= self.leaves().len() {
            return None;
        }
        let mut proof = Vec::new();
        let len = self.layers.len();
        for (layer_i, layer) in self.layers[..len - 1].iter().enumerate() {
            let counterpart = idx ^ 1;
            let hash = layer
                .get(counterpart)
                .cloned()
                .unwrap_or_else(|| self.empty_layers[layer_i].clone());
            idx >>= 1;
            proof.push(hash);
        }
        Some(ProveData(proof))
    }

    /// An variant prove that not contains the leaf node.
    pub fn prove_without_leaf(&self, idx: usize) -> Option<ProveData<Hasher>> {
        // TODO: optimize this ops
        self.prove(idx).map(|mut proof| {
            proof.0.remove(0);
            proof
        })
    }
}
