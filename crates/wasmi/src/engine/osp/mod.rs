mod executor;

use codec::{Decode, Encode};

/// The current status of executor.
#[derive(Clone, Copy, Encode, Decode, Debug, Eq, PartialEq)]
pub enum OspStatus {
    /// This means there is still next instruction.
    Running,
    /// This means program has executed the last instruction.
    Finished,
    /// Current instruction meet trap.
    Trapped,
}
