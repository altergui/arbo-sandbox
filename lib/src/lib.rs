use alloy_sol_types::sol;
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

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

/// Compute the n'th fibonacci number (wrapping around on overflows), using normal Rust code.
pub fn fibonacci(n: u32) -> (u32, u32) {
    let mut a = 0u32;
    let mut b = 1u32;
    for _ in 0..n {
        let c = a.wrapping_add(b);
        a = b;
        b = c;
    }
    (a, b)
}
