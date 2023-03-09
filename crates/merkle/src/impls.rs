use core::{fmt::Debug, marker::PhantomData};

use crate::{FixedBytes, HashOutput, MemoryChunk, MerkleConfig, MerkleHasher};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefaultMemoryConfig<Hasher>(PhantomData<Hasher>);

impl<Hasher: MerkleHasher> MerkleConfig for DefaultMemoryConfig<Hasher> {
    type Hasher = Hasher;

    type MemoryChunk = [u8; 32];
}

impl FixedBytes for [u8; 32] {
    const LENGTH: usize = 32;
    const ZERO: Self = [0; 32];

    fn from_slice(bytes: &[u8]) -> Self {
        match bytes.try_into() {
            Ok(array) => array,
            Err(_) => panic!(
                "Expected a slice of length {} but it was {}",
                <Self as FixedBytes>::LENGTH,
                bytes.len()
            ),
        }
    }
}
impl FixedBytes for [u8; 64] {
    const LENGTH: usize = 64;
    const ZERO: Self = [0; 64];

    fn from_slice(bytes: &[u8]) -> Self {
        match bytes.try_into() {
            Ok(array) => array,
            Err(_) => panic!(
                "Expected a slice of length {} but it was {}",
                <Self as FixedBytes>::LENGTH,
                bytes.len()
            ),
        }
    }
}

impl FixedBytes for [u8; 128] {
    const LENGTH: usize = 128;
    const ZERO: Self = [0; 128];

    fn from_slice(bytes: &[u8]) -> Self {
        match bytes.try_into() {
            Ok(array) => array,
            Err(_) => panic!(
                "Expected a slice of length {} but it was {}",
                <Self as FixedBytes>::LENGTH,
                bytes.len()
            ),
        }
    }
}

impl FixedBytes for [u8; 256] {
    const LENGTH: usize = 256;
    const ZERO: Self = [0; 256];

    fn from_slice(bytes: &[u8]) -> Self {
        match bytes.try_into() {
            Ok(array) => array,
            Err(_) => panic!(
                "Expected a slice of length {} but it was {}",
                <Self as FixedBytes>::LENGTH,
                bytes.len()
            ),
        }
    }
}

impl MemoryChunk for [u8; 32] {}
impl MemoryChunk for [u8; 64] {}
impl MemoryChunk for [u8; 128] {}
impl MemoryChunk for [u8; 256] {}

impl HashOutput for [u8; 32] {}
impl HashOutput for [u8; 64] {}
