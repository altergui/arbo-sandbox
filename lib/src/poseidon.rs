use ark_bn254::Fr;
// use ark_ff::fields::Field;

use num_bigint::BigUint;
use poseidon_ark::Poseidon;

pub(crate) fn poseidon_hash(inputs: &[&Vec<u8>]) -> Vec<u8> {
    let mut fr_array = Vec::new();
    for input in inputs {
        let bi = BigUint::from_bytes_le(input);
        fr_array.push(Fr::from(bi));
    }
    let h = Poseidon::new().hash(fr_array).unwrap();
    field_to_biguint(h).to_bytes_le()
}

fn field_to_biguint(f: Fr) -> num_bigint::BigUint {
    let bi: num_bigint::BigUint = f.into();
    bi
}
