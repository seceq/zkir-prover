//! ZK IR Prover CLI

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use zkir_prover::{ExecutionTrace, Proof, Prover, ProverConfig, Verifier};

#[derive(Parser)]
#[command(name = "zkir-prover")]
#[command(about = "STARK prover for ZK IR", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a STARK proof from an execution trace
    Prove {
        /// Path to the execution trace file
        #[arg(short, long)]
        trace: PathBuf,

        /// Output path for the proof (defaults to <trace>.zkproof)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Security level: fast, default, or high
        #[arg(long, default_value = "default")]
        security: String,
    },

    /// Verify a STARK proof
    Verify {
        /// Path to the proof file
        proof: PathBuf,
    },

    /// Show information about a proof
    Info {
        /// Path to the proof file
        proof: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Commands::Prove {
            trace,
            output,
            security,
        } => {
            cmd_prove(trace, output, security)?;
        }
        Commands::Verify { proof } => {
            cmd_verify(proof)?;
        }
        Commands::Info { proof } => {
            cmd_info(proof)?;
        }
    }

    Ok(())
}

fn cmd_prove(trace_path: PathBuf, output: Option<PathBuf>, security: String) -> Result<()> {
    info!("Loading execution trace from {:?}", trace_path);

    let config = match security.as_str() {
        "fast" => ProverConfig::fast(),
        "default" => ProverConfig::default(),
        "high" => ProverConfig::high(),
        _ => {
            anyhow::bail!("Unknown security level: {}. Use fast, default, or high", security);
        }
    };

    info!("Using security level: {} ({:?})", security, config);

    // Load execution trace
    let trace = ExecutionTrace::load(&trace_path)?;
    info!("Loaded trace with {} cycles", trace.num_cycles());

    // Generate proof
    let prover = Prover::new(config);
    info!("Generating proof...");

    let proof = prover.prove(&trace)?;

    // Determine output path
    let output_path = output.unwrap_or_else(|| {
        let mut p = trace_path.clone();
        p.set_extension("zkproof");
        p
    });

    // Save proof
    proof.save(&output_path)?;
    info!("Proof saved to {:?}", output_path);
    info!("Proof size: {} bytes", proof.size_bytes());

    Ok(())
}

fn cmd_verify(proof_path: PathBuf) -> Result<()> {
    info!("Loading proof from {:?}", proof_path);

    let proof = Proof::load(&proof_path)?;
    let verifier = Verifier::new();

    info!("Verifying proof...");
    match verifier.verify(&proof) {
        Ok(()) => {
            info!("Proof is VALID");
            println!("Verification: PASSED");
        }
        Err(e) => {
            info!("Proof is INVALID: {}", e);
            println!("Verification: FAILED - {}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_info(proof_path: PathBuf) -> Result<()> {
    let proof = Proof::load(&proof_path)?;

    println!("Proof Information");
    println!("=================");
    println!("Size: {} bytes", proof.size_bytes());
    println!();
    println!("Public Inputs:");
    println!("  Program hash: {}", hex::encode(&proof.public_inputs.program_hash));
    println!("  Num cycles: {}", proof.public_inputs.num_cycles);
    println!("  Inputs: {:?}", proof.public_inputs.inputs);
    println!("  Outputs: {:?}", proof.public_inputs.outputs);

    Ok(())
}
