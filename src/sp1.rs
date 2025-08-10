//! A `ZKAgent` implementation for the sp1@4
//! prover implementation.
//!
//! By default produces recursively verified STARK proofs.
//!
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

use anyhow::Result;
use sp1_build::BuildArgs;
use sp1_sdk::HashableKey;
use sp1_sdk::ProverClient;
use sp1_sdk::SP1ProofWithPublicValues;
use sp1_sdk::SP1Stdin;
use sp1_sdk::SP1VerifyingKey;

use crate::prelude::*;

static DEFAULT_AGENT: OnceLock<ZKSPOneAgent> = OnceLock::new();

/// Build the specified binaries and put the output
/// elf files somewhere.
///
/// This is meant to be used in a `build.rs` in a
/// dependent project. Files will NOT be built if the
/// `CI` env variable is set, or if the target OS is `zkvm`.
///
/// Arguments:
/// * `binaries`: names of binary targets to be built
/// * `features`: names of features to enable in the build
/// * `no_default_features`: whether to disable default features
/// * `output_dir`: (optional) path relative to manifest directory to store compiled binaries. By
/// default binaries will be stored in `target/`
///
/// See also: https://docs.rs/sp1-build/latest/sp1_build/fn.execute_build_program.html
pub fn build(
    binaries: &[&str],
    features: &[&str],
    no_default_features: bool,
    output_dir: Option<&Path>,
) -> Result<()> {
    // if we're in a CI don't rebuild the elf files
    // use the committed ones
    let is_ci = std::env::var("CI").is_ok();
    let target = std::env::var("CARGO_CFG_TARGET_OS")?;
    if target == "zkvm" || is_ci {
        return Ok(());
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let build_args = BuildArgs {
        docker: false,
        binaries: binaries.iter().map(|v| (*v).into()).collect(),
        features: features.iter().map(|v| (*v).into()).collect(),
        no_default_features,
        output_directory: output_dir.map(|path| {
            PathBuf::from(manifest_dir)
                .join(path)
                .to_string_lossy()
                .to_string()
        }),
        ..Default::default()
    };
    sp1_build::execute_build_program(&build_args, None)?;

    Ok(())
}

/// An argument of execution containing an SP1 compressed
/// STARK proof. The program in question is broken into "shards"
/// and each shard is proven and then recursively verified
/// into the final compressed STARK proof.
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

    fn agent(&self) -> &dyn ZKAgent {
        ZKSPOneAgent::singleton()
    }

    fn program(&self) -> Option<&dyn ZKProgram> {
        None
    }
}

/// A succinct SP1 prover agent. Produces compressed STARK arguments of
/// knowledge.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Default, Debug)]
pub struct ZKSPOneAgent;

impl ZKSPOneAgent {
    /// Get a reference to a global shared instance of the agent.
    pub fn singleton() -> &'static Self {
        DEFAULT_AGENT.get_or_init(|| ZKSPOneAgent::default())
    }
}

impl ZKAgent for ZKSPOneAgent {
    fn execute(&self, input: &[u8], program: &dyn ZKProgram) -> Result<Box<dyn ZKExe>> {
        let mut stdin = SP1Stdin::new();

        stdin.write_slice(&input);
        // I don't much care for taking env vars from the host program...
        //
        // TODO: store this client on the instance to avoid initialization cost
        // in execution/proving?
        let client = ProverClient::from_env();

        // executing without generating a proof
        //
        // this execute call is redundant, prove calls execute internally.
        // TODO: remove
        let (_public_values, report) = client.execute(program.elf(), &stdin).run()?;

        println!("sp1 report: {report}");

        let (pk, vk) = client.setup(program.elf());
        assert_eq!(
            vk.hash_bytes(),
            *program.id(),
            "prover vkey mismatched program vkey"
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
