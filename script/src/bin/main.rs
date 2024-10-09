//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use std::{fs::File, io::Write};

// use alloy_sol_types::SolType;
use clap::Parser;
// use fibonacci_lib::PublicValuesStruct;
use hex::ToHex;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::time::Instant;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../../../elf/riscv32im-succinct-zkvm-elf");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    execute: bool,

    #[clap(long)]
    generate: bool,

    #[clap(long)]
    verify: bool,

    #[clap(short, default_value = "20")]
    n: u32,

    #[clap(long, default_value = "0")]
    offset: u32,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Parse the command line arguments.
    let args = Args::parse();

    if !args.execute && !args.generate && !args.verify {
        eprintln!("Error: You must specify either --execute, --generate or --verify");
        std::process::exit(1);
    }

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&args.n);
    stdin.write(&args.offset);

    println!("n: {}", args.n);

    if args.execute {
        // Execute the program
        let start_time = Instant::now();
        let (_output, report) = client.execute(FIBONACCI_ELF, stdin).run().unwrap();
        println!("Program executed successfully.");
        println!("Time elapsed: {:?}", start_time.elapsed());

        // // Read the output.
        // let decoded = PublicValuesStruct::abi_decode(output.as_slice(), true).unwrap();
        // let PublicValuesStruct { n, a, b, root } = decoded;
        // println!("n: {}", n);
        // println!("a: {}", a);
        // println!("b: {}", b);
        // println!("root: {:?}", root);
        // println!("offset: {}", args.offset);

        // let (expected_a, expected_b) = fibonacci_lib::fibonacci(n);
        // assert_eq!(a, expected_a + args.offset);
        // assert_eq!(b, expected_b + args.offset);
        // println!("Values are correct!");

        // Record the number of cycles executed.
        println!("Number of cycles: {}", report.total_instruction_count());
    } else if args.generate {
        // Setup the program for proving.
        let (pk, _) = client.setup(FIBONACCI_ELF);

        // Generate the proof
        let proof = client
            .prove(&pk, stdin)
            .groth16()
            .run()
            .expect("failed to generate proof");

        println!("Successfully generated proof! {:#?}", proof);

        save_proof_to_json(&proof).expect("failed to save proof to disk");
    } else if args.verify {
        // Setup the program for proving.
        let (_, vk) = client.setup(FIBONACCI_ELF);

        let proof = load_proof_from_json();

        println!("loaded proof.json from disk: {:#?}", proof);

        let mut proof = proof;
        proof.stdin = sp1_sdk::SP1Stdin::default();
        println!("mutated proof, now is: {:#?}", proof);

        // Verify the proof.
        client.verify(&proof, &vk).expect("failed to verify proof");
        println!("Successfully verified proof!");
        println!(
            "I don't know which offset was used:
            on the proof.public_values i can see n, a, b but not the offset,
            yet i know the proof is valid"
        );

        println!(
            "public_values slice is {}",
            proof.public_values.encode_hex::<String>()
        );

        // let decoded = PublicValuesStruct::abi_decode(proof.public_values.as_slice(), true).unwrap();
        // let PublicValuesStruct { n, a, b, root } = decoded;
        // println!(
        //     "so in public_values i see n={}, a={}, b={}, root={:?}",
        //     n, a, b, root
        // );
    }
}

// save `proof` to disk
fn save_proof_to_json(proof: &sp1_sdk::SP1ProofWithPublicValues) -> std::io::Result<()> {
    // Open the file in write mode
    let mut file = File::create("proof.json")?;

    // Serialize the proof to a JSON string
    let proof_json = serde_json::to_string(&proof).expect("Failed to serialize proof");

    // Write the serialized JSON to the file
    file.write_all(proof_json.as_bytes())?;

    println!("Proof saved to proof.json");
    Ok(())
}

fn load_proof_from_json() -> sp1_sdk::SP1ProofWithPublicValues {
    let file = File::open("proof.json").expect("Failed to open proof file");
    let proof: sp1_sdk::SP1ProofWithPublicValues =
        serde_json::from_reader(file).expect("Failed to deserialize proof");
    proof
}
