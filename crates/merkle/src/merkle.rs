use alloc::vec::Vec;
use core::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use codec::{Decode, Encode};

use crate::{empty_hash, MerkleConfig, MerkleHasher};

// TODO: move to other place
#[derive(Debug)]
pub struct MemoryType<Config: MerkleConfig>(PhantomData<Config>);

pub type MemoryMerkle<Config> = Merkle<MemoryType<Config>, <Config as MerkleConfig>::Hasher>;

#[derive(Debug)]
pub struct TableType;
pub type TableMerkle<Hasher> = Merkle<TableType, Hasher>;

#[derive(Debug)]
pub struct GlobalType;
pub type GlobalMerkle<Hasher> = Merkle<GlobalType, Hasher>;

#[derive(Debug)]
pub struct InstructionType;
pub type InstructionMerkle<Hasher> = Merkle<InstructionType, Hasher>;

#[derive(Debug)]
pub struct FuncType;
pub type FuncMerkle<Hasher> = Merkle<FuncType, Hasher>;

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

/// The generic merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Merkle<T, Hasher: MerkleHasher> {
    /// The node of different layers.
    layers: Vec<Vec<Hasher::Output>>,
    /// Keep the empty hash value of different layer.
    empty_layers: Vec<Hasher::Output>,
    /// The merkle tree kind.
    _kind: PhantomData<T>,
}

impl<T, Hasher: MerkleHasher> Merkle<T, Hasher> {
    /// Creates a merkle tree according to hashes.
    ///
    /// # Note
    ///
    /// Panic if hashes is empty.
    pub fn new(hashes: Vec<Hasher::Output>) -> Self {
        Self::new_advanced(hashes, empty_hash::<Hasher>(), 0)
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

    /// Clear all state inside `Merkle` for reusing this type.
    pub fn clear(&mut self) {
        self.layers.truncate(0);
        self.empty_layers.truncate(0);
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
            _kind: Default::default(),
        }
    }

    /// Returns the merkle root.
    pub fn root(&self) -> Hasher::Output {
        if let Some(layer) = self.layers.last() {
            assert_eq!(layer.len(), 1);
            layer[0].clone()
        } else {
            empty_hash::<Hasher>()
        }
    }

    /// Returns the merkle leaves.
    pub fn leaves(&self) -> &[Hasher::Output] {
        self.layers
            .first()
            .map(|leaves| leaves.as_slice())
            .unwrap_or(&[])
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
        let len = self.layers.len();
        let mut proof = Vec::with_capacity(len - 1);
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

    /// An variant `prove` that not contains the leaf node.
    pub fn prove_without_leaf(&self, idx: usize) -> Option<ProveData<Hasher>> {
        // TODO: optimize this ops
        self.prove(idx).map(|mut proof| {
            proof.0.remove(0);
            proof
        })
    }
}
