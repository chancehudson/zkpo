use std::sync::OnceLock;

use anyhow::Result;
use risc0_zkvm::Digest;
use risc0_zkvm::{ExecutorEnv, Receipt, default_prover};

use crate::prelude::*;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct ZKRiscZeroArg {
    pub receipt_bytes: Vec<u8>,
    pub program_id: [u8; 32],
}

impl ZKExe for ZKRiscZeroArg {
    fn agent(&self) -> Option<&dyn ZKAgent> {
        static DEFAULT: OnceLock<ZKRiscZeroAgent> = OnceLock::new();
        Some(DEFAULT.get_or_init(|| ZKRiscZeroAgent::default()))
    }

    fn cipher_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    fn program_id(&self) -> &[u8; 32] {
        &self.program_id
    }

    fn program(&self) -> Option<&dyn ZKProgram> {
        None
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Default, Debug)]
pub struct ZKRiscZeroAgent;

impl ZKAgent for ZKRiscZeroAgent {
    fn execute(&self, input: &[u8], program: &dyn ZKProgram) -> Result<Box<dyn ZKExe>> {
        // build an executor with the supplied input
        let env = ExecutorEnv::builder().write_slice(input).build()?;
        // use the default risc0 prover
        let prover = default_prover();
        // Produce a receipt by proving the specified ELF binary.
        let receipt = prover.prove(env, program.elf())?.receipt;
        Ok(Box::new(ZKRiscZeroArg {
            receipt_bytes: bincode::serialize(&receipt)?,
            program_id: program.id().clone(),
        }))
    }

    fn verify(&self, proof: &dyn ZKExe) -> Result<Vec<u8>> {
        let receipt = bincode::deserialize::<Receipt>(proof.cipher_bytes())?;
        let digest = Digest::from_bytes(*proof.program_id());
        receipt.verify(digest)?;
        Ok(receipt.journal.bytes)
    }
}
