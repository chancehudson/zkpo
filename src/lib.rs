/// An interface for programs and arguments of execution.
use anyhow::Result;

pub mod risczero;

/// A program to be argued to have been executed.
pub trait ZKProgram {
    /// Unique (per agent) identifier for the program.
    ///
    /// Although this is available, prefer statically
    /// analyzable program identification.
    fn id(&self) -> &[u8; 32];
    /// Optional human readable name.
    fn name(&self) -> Option<&str>;
    /// Executable linkable format data of the program.
    /// Arbitrary, defined by each agent implementation.
    fn elf(&self) -> &[u8];
    /// Optional, statically stable, agent implementation
    /// compatible with this program.
    fn agent(&self) -> Option<&dyn ZKAgent>;
}

/// An arithmetization agnostic argument of execution.
pub trait ZKExe {
    /// Opaque agent specific data necessary for verification.
    fn cipher_bytes(&self) -> &[u8];
    /// 32 byte program id that Self argues was executed.
    fn program_id(&self) -> &[u8; 32];
    /// Optional structure capable of creating and verifying Self.
    fn agent(&self) -> Option<&dyn ZKAgent>;
    /// Optional reference to program. For statically safe
    /// programs over the wire.
    fn program(&self) -> Option<&dyn ZKProgram>;
}

/// A structure that can
/// - execute, provided a ZKProgram
/// - verify, execution provided a ZKExe
///
/// Each agent can verify many different programs using
/// many different proving systems.
pub trait ZKAgent {
    /// Generate an argument of execution. Inputs are expected
    /// to be serialized arbitrarily outside of this implementation.
    fn execute(&self, input: &[u8], program: &dyn ZKProgram) -> Result<Box<dyn ZKExe>>;
    /// Verify an argument of execution and return the public output data.
    fn verify(&self, proof: &dyn ZKExe) -> Result<Vec<u8>>;
}
