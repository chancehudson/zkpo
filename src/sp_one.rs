use anyhow::Result;
use sp1_sdk::HashableKey;
use sp1_sdk::ProverClient;
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_sdk::SP1Stdin;
use sp1_sdk::SP1VerifyingKey;

use crate::prelude::*;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct ZKSPOneExe {
    pub proof: Vec<u8>,
    pub program_id: [u8; 32],
}

impl ZKExe for ZKSPOneExe {
    fn program_id(&self) -> &[u8; 32] {
        &self.program_id
    }

    fn cipher_bytes(&self) -> &[u8] {
        &self.proof
    }

    fn agent(&self) -> Option<&dyn ZKAgent> {
        None
    }

    fn program(&self) -> Option<&dyn ZKProgram> {
        None
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug)]
pub struct ZKSPOneAgent;

impl ZKAgent for ZKSPOneAgent {
    fn execute(&self, input: &[u8], program: &dyn ZKProgram) -> Result<Box<dyn ZKExe>> {
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);
        // I don't much care for taking env vars from the host program...
        let client = ProverClient::from_env();

        // executing without generating a proof
        let (public_values, report) = client.execute(program.elf(), &stdin).run()?;

        #[cfg(debug_assertions)]
        println!("sp1 report: {report:?}");
        #[cfg(debug_assertions)]
        println!("sp1 public values: {public_values:?}");

        let (pk, vk) = client.setup(program.elf());
        assert_eq!(
            vk.hash_bytes(),
            *program.id(),
            "prover vkey mismatched program vkey, claude said this wouldn't happen :("
        );
        // prove recursive stark by default
        let proof = client.prove(&pk, &stdin).compressed().run()?;
        Ok(Box::new(ZKSPOneExe {
            // TODO: convert this tuple to a proper struct
            proof: bincode::serialize(&(proof, vk))?,
            program_id: program.id().clone(),
        }))
    }

    fn verify(&self, exe: &dyn ZKExe) -> Result<Vec<u8>> {
        let client = ProverClient::from_env();
        let (proof, vk): (SP1ProofWithPublicValues, SP1VerifyingKey) =
            bincode::deserialize(exe.cipher_bytes())?;

        client.verify(&proof, &vk)?;
        assert_eq!(
            vk.hash_bytes(),
            *exe.program_id(),
            "mismatch between exe program_id and cryptographically verified program id"
        );

        // No idea if this passthrough will work as i expect
        Ok(proof.public_values.to_vec())
    }
}
