//! Engine level snapshot.
use codec::{Decode, Encode};
use wasmi_core::UntypedValue;

/// The engine context snapshot.
///
/// Note: The snapshot lack of current pc data.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct EngineSnapshot {
    pub config: EngineConfig,
    /// The value stack.
    pub values: ValueStackSnapshot,
    /// The frame stack.
    pub frames: CallStackSnapshot,
}

// TODO: consider some inherent configs.
/// The configured limits of the engine.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct EngineConfig {
    /// The maximum number of nested calls that the Wasm stack allows.
    pub maximum_recursion_depth: u32,
}

/// The value stack that is used to execute Wasm bytecode.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct ValueStackSnapshot {
    /// All currently live stack entries.
    pub entries: Vec<UntypedValue>,
    // /// The maximum value stack height.
    // pub maximum_len: u32,
}

/// The live function call stack storing the live function activation frames.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct CallStackSnapshot {
    /// The call stack featuring the function frames in order.
    pub frames: Vec<FuncFrameSnapshot>,
    /// The maximum allowed depth of the `frames` stack.
    pub recursion_limit: u32,
}

/// A function frame of a function on the call stack.
#[derive(Encode, Decode, Debug, Clone, Eq, PartialEq)]
pub struct FuncFrameSnapshot {
    /// The current value of the program counter.
    pub pc: u32,
}
