/// An interface for programs and proofs of execution.
use anyhow::Result;

mod risczero;

/// A program to be proven to have been executed.
pub trait ZKProgram {
    /// The executable linkable format data of the program.
    /// This is arbitrary and defined by each ZKAgent
    /// implementation.
    fn elf(&self) -> &'static [u8];
    /// An optional, statically stable, agent implementation
    /// compatible with this program.
    fn agent(&self) -> Option<&dyn ZKAgent>;
    /// A unique identifier for the program.
    fn id(&self) -> &'static [u8; 32];
}

/// A prover/arithmetization agnostic argument of knowledge.
pub trait ZKProof {
    /// Opaque proving system data necessary for verification.
    fn cipher_bytes(&self) -> &[u8];
    /// Prover/Verifier implementation.
    fn agent(&self) -> Option<&dyn ZKAgent>;
    fn program_id(&self) -> &'static [u8; 32];
}

/// A structure that can
/// - create proofs provided a ZKProgram
/// - verify proofs provided a ZKProof
///
/// Each agent can verify many different programs using
/// many different proving systems.
pub trait ZKAgent {
    /// Generate a proof. Inputs are expected to be serialized outside
    /// of this implementation.
    fn execute(&self, input: &[u8], program: &dyn ZKProgram) -> Result<Box<dyn ZKProof>>;
    /// Verify a proof and return the public output data.
    fn verify(&self, proof: &dyn ZKProof) -> Result<Vec<u8>>;
}
