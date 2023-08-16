use core::fmt::Debug;

use codec::{Codec, Encode};

/// The total config for merkle tree details.
pub trait MerkleConfig: Clone + Debug + PartialEq + Eq {
    /// The hasher for memory chunk.
    type Hasher: MerkleHasher;

    /// The unit of handling wasm memory bytes.
    type MemoryChunk: MemoryChunk;
}

/// The Hasher type used in merkle proof.
pub trait MerkleHasher: Send + Sync + Clone + Debug + PartialEq + Eq {
    /// The output hash type.
    type Output: HashOutput;

    /// Creates a hash according to bytes.
    fn hash(bytes: &[u8]) -> Self::Output;

    /// Produce the hash of some codec-encodable value.
    fn hash_of<S: Encode + ?Sized>(s: &S) -> Self::Output {
        Encode::using_encoded(s, Self::hash)
    }

    /// Creates parent hash output by hashing two child output.
    fn hash_node(a: &Self::Output, b: &Self::Output) -> Self::Output;
}

/// Return the memory chunk size config.
pub const fn memory_chunk_size<T: MerkleConfig>() -> usize {
    <T::MemoryChunk as FixedBytes>::LENGTH
}

/// The default memory chunk fulfilled with zero.
pub const fn empty_chunk<T: MerkleConfig>() -> T::MemoryChunk {
    <T::MemoryChunk as FixedBytes>::ZERO
}

/// The default hash fulfilled with zero.
pub const fn empty_hash<T: MerkleHasher>() -> T::Output {
    <T::Output as FixedBytes>::ZERO
}

/// Return the max depth of memory merkle tree.
/// 1 + log2(2^32 / memory_chunk_size) = 1 + 32 - log2(memory_chunk_size)))
///
/// # Note
///
/// When a memory max memory is set in wasm code, it will be smaller depth than this in actually.
pub const fn memory_merkle_depth<T: MerkleConfig>() -> usize {
    32 + 1 - memory_chunk_size::<T>().ilog2() as usize
}

/// The output type of Hasher.
pub type OutputOf<T> = <<T as MerkleConfig>::Hasher as MerkleHasher>::Output;

/// The trait defines a zero value and length info for a fixed bytes.
pub trait FixedBytes:
    core::hash::Hash
    + Codec
    + Debug
    + Clone
    + PartialEq
    + Eq
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Send
    + Sync
    + Sized
{
    /// The length of bytes.
    const LENGTH: usize;

    /// The default bytes with zero.
    ///
    /// # Note
    ///
    /// We need this because Default is not implemented for `[u8; N]` where `N` > 32.
    const ZERO: Self;

    /// Cast bytes to `Self`.
    ///
    /// # Note
    ///
    /// The bytes len must equal to `Self::LENGTH`, otherwise it should panic.
    fn from_slice(bytes: &[u8]) -> Self;
}

/// The unit of handling wasm memory bytes.
pub trait MemoryChunk: FixedBytes {}

/// The output type of a hashing algorithm.
pub trait HashOutput: FixedBytes {}
