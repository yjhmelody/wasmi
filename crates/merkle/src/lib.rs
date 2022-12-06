#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std as alloc;

mod bytes32;
mod merkle;

pub use bytes32::*;
pub use merkle::*;

pub use digest;
pub use sha3;
