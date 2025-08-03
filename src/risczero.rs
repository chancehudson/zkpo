use std::sync::OnceLock;

use anyhow::Result;
use risc0_zkvm::Digest;
use risc0_zkvm::{ExecutorEnv, Receipt, default_prover};

use crate::ZKAgent;
use crate::ZKProgram;
use crate::ZKProof;

#[derive(Clone, Debug)]
pub struct ZKRiscZeroProof {
    pub receipt_bytes: Vec<u8>,
    pub program_id: &'static [u8; 32],
}

impl ZKProof for ZKRiscZeroProof {
    fn agent(&self) -> Option<&dyn ZKAgent> {
        static DEFAULT: OnceLock<ZKRiscZeroAgent> = OnceLock::new();
        Some(DEFAULT.get_or_init(|| ZKRiscZeroAgent::default()))
    }

    fn cipher_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }

    fn program_id(&self) -> &'static [u8; 32] {
        self.program_id
    }
}

/// TODO: serialize as well, so provers can be embedded in network data
/// for declarative zk proofs. related: typetag
#[derive(Clone, Default, Debug)]
pub struct ZKRiscZeroAgent;

impl ZKAgent for ZKRiscZeroAgent {
    fn execute(&self, input: &[u8], program: &dyn ZKProgram) -> Result<Box<dyn ZKProof>> {
        // build an executor with the supplied input
        let env = ExecutorEnv::builder().write_slice(input).build()?;
        // use the default risc0 prover
        let prover = default_prover();
        // Produce a receipt by proving the specified ELF binary.
        let receipt = prover.prove(env, program.elf())?.receipt;
        Ok(Box::new(ZKRiscZeroProof {
            receipt_bytes: bincode::serialize(&receipt)?,
            program_id: program.id(),
        }))
    }

    fn verify(&self, proof: &dyn ZKProof) -> Result<Vec<u8>> {
        let receipt = bincode::deserialize::<Receipt>(proof.cipher_bytes())?;
        let digest = Digest::from_bytes(*proof.program_id());
        receipt.verify(digest)?;
        Ok(receipt.journal.bytes)
    }
}

mod tests {
    #[test]
    fn build_prove() {}
}
