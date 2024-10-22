use blake3;
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn siblings_biguints_to_bytes(siblings: Vec<BigUint>) -> Vec<Vec<u8>> {
    let hash_len = ((siblings.len() - 1) + 7) / 8; // Calculate the ceil value of (n_levels-1)/8

    println!("{} {}", siblings.len(), hash_len); // debug

    let to_bytes = |i: &BigUint| -> Vec<u8> {
        let mut b = i.to_bytes_le();
        b.resize(hash_len, 0u8);
        b
    };

    let mut siblings: Vec<Vec<u8>> = siblings
        .into_iter()
        .map(|biguint| to_bytes(&biguint))
        .collect();

    for sibling in siblings.iter_mut() {
        // if the sibling is empty or zero, pad with zeroes
        if sibling.is_empty() || sibling.iter().all(|&byte| byte == 0) {
            *sibling = vec![0u8; hash_len];
        }
    }

    siblings
}

pub(crate) fn verify_extended(
    enabled: &BigUint,
    expected_root: &BigUint,
    old_key: &BigUint,
    old_value: &BigUint,
    is_old_0: &BigUint,
    key: &BigUint,
    value: &BigUint,
    fnc: &BigUint,
    siblings_biguint: Vec<BigUint>,
) {
    let mut siblings = siblings_biguints_to_bytes(siblings_biguint);
    let required_len = ((siblings.len() - 1) + 7) / 8; // Calculate the ceil value of (n_levels-1)/8

    let to_bytes = |i: &BigUint| -> Vec<u8> {
        let mut b = i.to_bytes_le();
        b.resize(required_len, 0u8);
        b
    };

    // Ensure the last sibling is zero
    siblings.push(vec![0u8; 32]);

    let n_levels = siblings.len();
    let hash1_old = end_leaf_hash(&to_bytes(old_key), &to_bytes(old_value));
    let hash1_new = end_leaf_hash(&to_bytes(key), &to_bytes(value));

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
                lev_ins[0],
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
                lev_ins[i],
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
            levels[i + 1].to_bytes_le()
        } else {
            BigUint::zero().to_bytes_le()
        };
        let lrbit = if key.bit(i.try_into().unwrap()) {
            1u8
        } else {
            0u8
        };

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

fn level_ins(siblings: &Vec<Vec<u8>>, enabled: bool) -> Vec<bool> {
    println!("level_ins {:?} {}", siblings, enabled); // debug
    let mut lev_ins = vec![false; siblings.len()];
    if enabled {
        assert!(*siblings[siblings.len() - 1] == vec![0u8; 32]);
    }

    let is_zero: Vec<bool> = siblings.iter().map(|i| **i == vec![0u8; 32]).collect();
    println!("is_zero: {:?}", is_zero); // debug

    let mut is_done = vec![false; siblings.len()];

    let last = !is_zero[siblings.len() - 2];
    lev_ins[siblings.len() - 1] = last;
    is_done[siblings.len() - 2] = last;

    for n in 2..siblings.len() {
        let i = siblings.len() - n;
        lev_ins[i] = !is_done[i] && !is_zero[i - 1];
        is_done[i - 1] = lev_ins[i] || is_done[i];
    }
    lev_ins[0] = !is_done[0];
    println!("lev_ins {:?}", lev_ins); // debug

    lev_ins
}

fn sm_verifier(
    is_0: &BigUint,
    lev_ins: bool,
    fnc: &BigUint,
    prev_top: &BigUint,
    prev_i0: &BigUint,
    prev_iold: &BigUint,
    prev_inew: &BigUint,
    prev_na: &BigUint,
) -> (BigUint, BigUint, BigUint, BigUint, BigUint) {
    let prev_top_lev_ins = prev_top
        * if lev_ins {
            BigUint::one()
        } else {
            BigUint::zero()
        };
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
    sibling: &Vec<u8>,
    old1leaf: &Vec<u8>,
    new1leaf: &Vec<u8>,
    lrbit: u8,
    child: &Vec<u8>,
) -> BigUint {
    let (l, r) = switcher(lrbit, &child, &sibling);
    let hash = intermediate_leaf_hash(l, r);
    println!(
        "level_verifier {} {} {}",
        lrbit,
        hex::encode(child),
        hex::encode(sibling)
    ); // debug
    (BigUint::from_bytes_le(&hash) * st_top)
        + (BigUint::from_bytes_le(old1leaf) * st_iold)
        + (BigUint::from_bytes_le(new1leaf) * st_inew)
}

fn switcher<'a>(lrbit: u8, l: &'a Vec<u8>, r: &'a Vec<u8>) -> (&'a Vec<u8>, &'a Vec<u8>) {
    if lrbit == 0 {
        (l, r)
    } else {
        (r, l)
    }
}

// Perform bitwise AND over an array of BigUint elements
fn multi_and(arr: &[BigUint]) -> BigUint {
    arr.iter().cloned().reduce(|a, b| a & b).unwrap()
}

// intermediate_leaf_value using Blake3 hash
pub(crate) fn end_leaf_hash(k: &Vec<u8>, v: &Vec<u8>) -> Vec<u8> {
    blake3_hash(&[k, v, &BigUint::one().to_bytes_le()])
}

// intermediate_leaf_value using Blake3 hash
pub(crate) fn intermediate_leaf_hash(l: &Vec<u8>, r: &Vec<u8>) -> Vec<u8> {
    blake3_hash(&[l, r])
}

// fn blake3_hash_from_le_biguints(inputs: &[&BigUint]) -> BigUint {
//     // circomlib uses little-endian when converting bigints to bytes
//     let hash = blake3_hash(&inputs.iter().map(|x| x.to_bytes_le()).collect::<Vec<_>>());
//     BigUint::from_bytes_le(&hash)
// }

fn blake3_hash(inputs: &[&Vec<u8>]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();

    // Iterate over each input byte slice and pass it to the hasher
    for input in inputs {
        println!("input (hex): {}", hex::encode(input)); // debug
        hasher.update(input); // Pass the byte slice directly to the hasher
    }

    // Finalize the hash and return the resulting hash as a Vec<u8>
    let hash = hasher.finalize();

    println!("hash (hex): {:?}", hash.to_hex()); // debug

    hash.as_bytes().to_vec()
}

#[test]
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
                BigUint::from(25u32),
            ]
        }) == BigUint::from(9u32)
    );
}
