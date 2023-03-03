use blake2::{Blake2b, Blake2b512};
use digest::{consts::U32, Digest};
use sha3::{Keccak256, Keccak512};

use crate::MerkleHasher;

/// The Keccak256 Hasher used in merkle proof.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct MerkleKeccak256;

impl MerkleHasher for MerkleKeccak256 {
    type Output = [u8; 32];

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

/// The Keccak512 Hasher used in merkle proof.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct MerkleKeccak512;

impl MerkleHasher for MerkleKeccak512 {
    type Output = [u8; 64];

    fn hash(bytes: &[u8]) -> Self::Output {
        let mut h = Keccak512::new();
        h.update(bytes);
        h.finalize().into()
    }

    fn hash_node(a: &Self::Output, b: &Self::Output) -> Self::Output {
        let mut h = Keccak512::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    }
}

/// The BlakeTwo256 Hasher used in merkle proof.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct MerkleBlake2b256;

type Blake2b256 = Blake2b<U32>;

impl MerkleHasher for MerkleBlake2b256 {
    type Output = [u8; 32];

    fn hash(bytes: &[u8]) -> Self::Output {
        let mut h = Blake2b256::new();
        h.update(bytes);
        h.finalize().into()
    }

    fn hash_node(a: &Self::Output, b: &Self::Output) -> Self::Output {
        let mut h = Blake2b256::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    }
}

/// The BlakeTwo512 Hasher used in merkle proof.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Default)]
pub struct MerkleBlake2b512;

impl MerkleHasher for MerkleBlake2b512 {
    type Output = [u8; 64];

    fn hash(bytes: &[u8]) -> Self::Output {
        let mut h = Blake2b512::new();
        h.update(bytes);
        h.finalize().into()
    }

    fn hash_node(a: &Self::Output, b: &Self::Output) -> Self::Output {
        let mut h = Blake2b::new();
        h.update(a);
        h.update(b);
        h.finalize().into()
    }
}
