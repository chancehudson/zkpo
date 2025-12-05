//! An interface for zk programs and arguments of execution.
//!
//! With zk you compile (arithmetize) a program to a system
//! of equations. Then you prove/argue knowledge of a solution
//! to the system of equations, which implies execution.
use anyhow::Result;
use lettuce::*;

/// Exports all zkpo types, including concrete implementations
/// behind features.
pub mod prelude;

// #[cfg(feature = "risc0")]
// pub mod risc0;
// #[cfg(feature = "sp1")]
// pub mod sp1;

/// This trait forms the boundary between algebra and bits
pub trait ZKProgram<E: FieldScalar> {
    ///
    fn id(&self) -> Vector<E>;

    fn r1cs(&self, input_len: usize, static_args: &Vec<usize>) -> Result<R1CS<E>>;

    fn compute_wtns(&self, input: Vector<E>, static_args: &Vec<usize>) -> Result<Vector<E>>;
}

/// An arithmetization agnostic argument of execution.
pub trait ZKArg<E: FieldScalar>: Sized {
    /// Create an argument of knowldge for a program and some inputs.
    fn new(program: impl ZKProgram<E>, input: Vector<E>, static_args: &Vec<usize>) -> Result<Self>;

    /// Name the algebraic/oracle argument
    fn name() -> &'static str {
        "unnamed zk argument. i wouldn't trust it"
    }

    /// Does the argument hold water ?
    ///
    /// Returns public outputs.
    fn verify(self) -> Result<impl Iterator<Item = E>>;

    /// Retrieve the outputs of the program
    fn outputs(&self) -> impl Iterator<Item = E>;
}
