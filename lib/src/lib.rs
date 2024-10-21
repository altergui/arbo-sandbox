use alloy_sol_types::sol;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

pub mod smtverifier;

sol! {
    /// Sub-struct for Merkle proof details
    struct MerkleProofSol {
        uint256 root;
        uint256 key;
        uint256 value;
        uint256[] siblings; // Dynamic array of uint256 for siblings
    }

    /// The public values encoded as a struct that can be easily deserialized inside Solidity.
    struct PublicValuesStruct {
        MerkleProofSol proof;  // Nested struct
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub root: BigUint,
    pub key: BigUint,
    pub value: BigUint,
    pub siblings: Vec<BigUint>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleProofFromFile {
    #[serde(deserialize_with = "string_to_biguint")]
    pub root: BigUint,
    #[serde(deserialize_with = "string_to_biguint")]
    pub key: BigUint,
    #[serde(deserialize_with = "string_to_biguint")]
    pub value: BigUint,
    #[serde(deserialize_with = "vec_string_to_biguint")]
    pub siblings: Vec<BigUint>,
}

fn string_to_biguint<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    BigUint::from_str(&s).map_err(serde::de::Error::custom)
}

fn vec_string_to_biguint<'de, D>(deserializer: D) -> Result<Vec<BigUint>, D::Error>
where
    D: Deserializer<'de>,
{
    let vec_of_strings: Vec<String> = Deserialize::deserialize(deserializer)?;
    vec_of_strings
        .into_iter()
        .map(|s| BigUint::from_str(&s).map_err(serde::de::Error::custom))
        .collect()
}

pub fn verify(expected_root: &BigUint, key: &BigUint, value: &BigUint, siblings: Vec<BigUint>) {
    smtverifier::verify_extended(
        &BigUint::one(),
        expected_root,
        &BigUint::zero(),
        &BigUint::zero(),
        &BigUint::zero(),
        key,
        value,
        &BigUint::zero(),
        siblings,
    );
}
