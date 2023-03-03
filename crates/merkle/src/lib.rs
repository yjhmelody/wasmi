#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std as alloc;

mod hasher;
mod merkle;
mod traits;

pub use hasher::*;
pub use merkle::*;
pub use traits::*;

pub use digest;
pub use sha3;
