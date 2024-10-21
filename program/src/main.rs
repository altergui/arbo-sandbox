// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use smtverifier::MerkleProof;

fn main() {
    println!("start");

    let proof = sp1_zkvm::io::read::<MerkleProof>();

    smtverifier::verify(&(proof.root), &(proof.key), &(proof.value), proof.siblings);

    println!("done");
}
