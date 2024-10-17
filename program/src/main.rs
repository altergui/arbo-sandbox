// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use std::str::FromStr;

use arbo_lib::MerkleProof;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use num_traits::{One, Zero};

fn verify(expected_root: &BigUint, key: &BigUint, value: &BigUint, siblings: Vec<BigUint>) {
    verify_extended(
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

fn verify_extended(
    enabled: &BigUint,
    expected_root: &BigUint,
    old_key: &BigUint,
    old_value: &BigUint,
    is_old_0: &BigUint,
    key: &BigUint,
    value: &BigUint,
    fnc: &BigUint,
    siblings: Vec<BigUint>,
) {
    let n_levels = siblings.len();
    let hash1_old = end_leaf_value(old_key, old_value);
    let hash1_new = end_leaf_value(key, value);

    let lev_ins = level_ins(&siblings, enabled.is_one());

    let mut st_tops = vec![BigUint::zero(); siblings.len()];
    let mut st_iolds = vec![BigUint::zero(); siblings.len()];
    let mut st_i0s = vec![BigUint::zero(); siblings.len()];
    let mut st_inews = vec![BigUint::zero(); siblings.len()];
    let mut st_nas = vec![BigUint::zero(); siblings.len()];

    for i in 0..n_levels {
        let (st_top, st_inew, st_iold, st_i0, st_na) = if i == 0 {
            sm_verifier(
                is_old_0,
                &lev_ins[0],
                fnc,
                enabled,
                &BigUint::zero(),
                &BigUint::zero(),
                &BigUint::zero(),
                &(BigUint::one() - enabled),
            )
        } else {
            sm_verifier(
                is_old_0,
                &lev_ins[i],
                fnc,
                &st_tops[i - 1],
                &st_i0s[i - 1],
                &st_iolds[i - 1],
                &st_inews[i - 1],
                &st_nas[i - 1],
            )
        };
        st_tops[i] = st_top;
        st_inews[i] = st_inew;
        st_iolds[i] = st_iold;
        st_i0s[i] = st_i0;
        st_nas[i] = st_na;
    }

    assert!(
        st_nas[n_levels - 1].clone()
            + st_iolds[n_levels - 1].clone()
            + st_inews[n_levels - 1].clone()
            + st_i0s[n_levels - 1].clone()
            == BigUint::one()
    );

    let mut levels = vec![BigUint::zero(); siblings.len()];
    let mut i = n_levels - 1;
    for n in 0..n_levels {
        let child = if n != 0 {
            levels[i + 1].clone()
        } else {
            BigUint::zero()
        };
        // let child = levels[i].clone();

        let lrbit = if key.bit(i.try_into().unwrap()) {
            1u8
        } else {
            0u8
        };
        println!("n:{} i:{} child:{}", n, i, child);
        levels[i] = level_verifier(
            &st_tops[i],
            &st_inews[i],
            &st_iolds[i],
            &siblings[i],
            &hash1_old,
            &hash1_new,
            lrbit,
            &child,
        );
        if i > 0 {
            i -= 1;
        }
    }

    println!(
        "Expected root: {:x} (base10: {:?})",
        expected_root, expected_root
    );
    println!(
        "Computed root: {:x} (base10: {:?})",
        (levels[0]),
        (levels[0])
    );
    assert!(expected_root == &levels[0]);

    let are_keys_equal = if old_key == key {
        BigUint::one()
    } else {
        BigUint::zero()
    };
    assert!(
        multi_and(&[
            fnc.clone(),
            (BigUint::one() - is_old_0),
            are_keys_equal,
            enabled.clone()
        ]) == BigUint::zero()
    );
}

fn level_ins(siblings: &[BigUint], enabled: bool) -> Vec<BigUint> {
    println!("level_ins {:?} {}", siblings, enabled);
    let mut lev_ins = vec![BigUint::zero(); siblings.len()];
    if enabled {
        assert!(siblings[siblings.len() - 1].is_zero());
    }

    let is_zero: Vec<BigUint> = siblings
        .iter()
        .map(|i| {
            if i.is_zero() {
                BigUint::one()
            } else {
                BigUint::zero()
            }
        })
        .collect();
    let mut is_done = vec![BigUint::zero(); siblings.len()];

    let last = BigUint::one() - &is_zero[siblings.len() - 2];
    lev_ins[siblings.len() - 1] = last.clone();
    is_done[siblings.len() - 2] = last.clone();

    for n in 2..siblings.len() {
        let i = siblings.len() - n;
        lev_ins[i] = (BigUint::one() - &is_done[i]) * (BigUint::one() - &is_zero[i - 1]);
        is_done[i - 1] = lev_ins[i].clone() + &is_done[i];
    }
    lev_ins[0] = BigUint::one() - &is_done[0];
    lev_ins
}

fn sm_verifier(
    is_0: &BigUint,
    lev_ins: &BigUint,
    fnc: &BigUint,
    prev_top: &BigUint,
    prev_i0: &BigUint,
    prev_iold: &BigUint,
    prev_inew: &BigUint,
    prev_na: &BigUint,
) -> (BigUint, BigUint, BigUint, BigUint, BigUint) {
    let prev_top_lev_ins = prev_top * lev_ins;
    let prev_top_lev_ins_fnc = &prev_top_lev_ins * fnc;
    let st_top = prev_top - &prev_top_lev_ins;
    let st_inew = &prev_top_lev_ins - &prev_top_lev_ins_fnc;
    let st_iold = &prev_top_lev_ins_fnc * &(BigUint::one() - is_0);
    let st_i0 = &prev_top_lev_ins * is_0;
    let st_na = prev_na + prev_inew + prev_iold + prev_i0;
    (st_top, st_inew, st_iold, st_i0, st_na)
}

fn level_verifier(
    st_top: &BigUint,
    st_inew: &BigUint,
    st_iold: &BigUint,
    sibling: &BigUint,
    old1leaf: &BigUint,
    new1leaf: &BigUint,
    lrbit: u8,
    child: &BigUint,
) -> BigUint {
    println!("level_verifier {} {:x} {:x}", lrbit, child, sibling);
    let (l, r) = switcher(lrbit, child, sibling);
    (intermediate_leaf_value(l, r) * st_top) + (old1leaf * st_iold) + (new1leaf * st_inew)
}

fn switcher(lrbit: u8, l: &BigUint, r: &BigUint) -> (BigUint, BigUint) {
    if lrbit == 0 {
        (l.clone(), r.clone())
    } else {
        (r.clone(), l.clone())
    }
}

// Perform bitwise AND over an array of BigUint elements
fn multi_and(arr: &[BigUint]) -> BigUint {
    arr.iter().cloned().reduce(|a, b| a & b).unwrap()
}

fn blake3_hash(inputs: &[BigUint]) -> BigUint {
    let mut hasher = blake3::Hasher::new();

    // Iterate over each field, serialize it, and pass it to the hasher
    for input in inputs {
        println!("input {:x} (base10: {:?})", input, input.to_string());
        hasher.update(&input.to_bytes_be()); // Vec<u8> gets converted to &[u8] automatically
    }

    // Finalize the hash and take the first 32 bytes
    let hash = hasher.finalize();
    println!(
        "hash {:?} (base10: {})",
        &hash.to_hex(),
        BigUint::from_bytes_be(hash.as_bytes())
    );
    println!("hash(bytes) {:?}", &hash.as_bytes());
    println!("");
    BigUint::from_bytes_be(hash.as_bytes())
}

// endLeafValue using Blake3 hash
pub(crate) fn end_leaf_value(k: &BigUint, v: &BigUint) -> BigUint {
    blake3_hash(&[k.clone(), v.clone(), BigUint::one()]) // Hash key, value, and 1
}

// intermediateLeafValue using Blake3 hash
pub(crate) fn intermediate_leaf_value(l: BigUint, r: BigUint) -> BigUint {
    blake3_hash(&[l, r]) // Hash left and right children
}

fn main() {
    println!("start");

    let mut proof = sp1_zkvm::io::read::<MerkleProof>();

    // Ensure the last sibling is zero
    proof.siblings.push(BigUint::zero());

    verify(&(proof.root), &(proof.key), &(proof.value), proof.siblings);

    println!("done");
}

fn test_multi_and() {
    let zero = BigUint::zero;
    let one = BigUint::one;

    assert!(multi_and(&{ [one()] }) == one());
    assert!(multi_and(&{ [zero()] }) == zero());
    assert!(multi_and(&{ [one(), one(), zero(), zero(),] }) == zero());
    assert!(multi_and(&{ [one(), one(), one(), one(),] }) == one());
    assert!(multi_and(&{ [zero(), zero(), zero(), zero(),] }) == zero());
    assert!(
        multi_and(&{
            [
                BigUint::from(11u32),
                BigUint::from(13u32),
                BigUint::from(1u32),
            ]
        }) == BigUint::from(9u32)
    );
}
