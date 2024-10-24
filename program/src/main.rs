// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use smtverifier::MerkleProof;

fn main() {
    println!("start");

    let proof = sp1_zkvm::io::read::<MerkleProof>();

    for n in 1..10 {
        println!("dummy loop {}", n);
        smtverifier::verify(
            &(proof.root),
            &(proof.key),
            &(proof.value),
            proof.siblings.clone(),
        );
    }

    smtverifier::verify(&(proof.root), &(proof.key), &(proof.value), proof.siblings);

    println!("done");
}
