use core::fmt::{Debug, Display};

use codec::{Codec, Encode};

/// The trait for different proof of wasm state component.
///
/// User could choose custom hash algorithm.
pub trait MerkleTrait<Hasher: MerkleHasher>: Debug {}

/// The Hasher type used in merkle proof.
pub trait MerkleHasher: Send + Sync {
    /// The output hash type.
    type Output: HashOutput;

    /// Creates a hash according to bytes.
    fn hash(bytes: &[u8]) -> Self::Output;

    /// Produce the hash of some codec-encodable value.
    fn hash_of<S: Encode + ?Sized>(s: &S) -> Self::Output {
        Encode::using_encoded(s, Self::hash)
    }

    /// Creates parent hash by two child hash.
    fn hash_node(a: &Self::Output, b: &Self::Output) -> Self::Output;
}

/// The output type of a hash algorithm.
pub trait HashOutput:
    core::hash::Hash
    + Codec
    + Debug
    + Default
    + Clone
    + PartialEq
    + Eq
    + AsRef<[u8]>
    + AsMut<[u8]>
    + Send
    + Sync
    + Sized
    + Display
{
    /// The length of output hash bytes.
    const LENGTH: usize;

    /// Cast bytes to `Self`.
    ///
    /// # Note
    ///
    /// The bytes len must equal to `Self::LENGTH`, otherwise it should panic.
    fn from_slice(b: &[u8]) -> Self;
}
