pub mod engine;
pub mod instance;
pub use engine::*;
pub use instance::*;

use codec::{Decode, Encode};

#[derive(Clone, Encode, Decode)]
pub enum VersionedSnapshot {
    V0(SnapshotV0),
}

#[derive(Clone, Encode, Decode)]
pub struct SnapshotV0 {
    pub instance: InstanceSnapshot,
    pub engine: EngineSnapshot,
    pub pc: u32,
}
