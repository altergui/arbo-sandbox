use crate::poseidon::poseidon_hash;
use blake3;
use num_bigint::BigUint;
use num_traits::{One, Zero};

fn siblings_biguints_to_bytes(siblings: Vec<BigUint>) -> Vec<Vec<u8>> {
    let hash_len = 32; // for BLAKE3

    println!(
        "got {} siblings, using {} bytes as hash_len",
        siblings.len(),
        hash_len
    ); // debug

    let to_bytes = |i: &BigUint| -> Vec<u8> {
        let mut b = i.to_bytes_le();
        b.resize(hash_len, 0u8); // pad with zeroes
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
    enabled: bool,
    expected_root: &BigUint,
    old_key: &BigUint,
    old_value: &BigUint,
    is_old_0: bool,
    key: &BigUint,
    value: &BigUint,
    fnc: bool,
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

    let lev_ins = level_ins(&siblings, enabled);

    let mut st_tops = vec![false; siblings.len()];
    let mut st_iolds = vec![false; siblings.len()];
    let mut st_i0s = vec![false; siblings.len()];
    let mut st_inews = vec![false; siblings.len()];
    let mut st_nas = vec![false; siblings.len()];

    for i in 0..n_levels {
        let (st_top, st_inew, st_iold, st_i0, st_na) = if i == 0 {
            sm_verifier(
                is_old_0, lev_ins[0], fnc, enabled, false, false, false, !enabled,
            )
        } else {
            sm_verifier(
                is_old_0,
                lev_ins[i],
                fnc,
                st_tops[i - 1],
                st_i0s[i - 1],
                st_iolds[i - 1],
                st_inews[i - 1],
                st_nas[i - 1],
            )
        };
        st_tops[i] = st_top;
        st_inews[i] = st_inew;
        st_iolds[i] = st_iold;
        st_i0s[i] = st_i0;
        st_nas[i] = st_na;
    }

    assert!(
        st_nas[n_levels - 1] as u8
            + st_iolds[n_levels - 1] as u8
            + st_inews[n_levels - 1] as u8
            + st_i0s[n_levels - 1] as u8
            == 1
    );

    let mut levels = vec![Vec::new(); siblings.len()];
    let mut i = n_levels - 1;
    for n in 0..n_levels {
        let child = if n != 0 {
            levels[i + 1].clone()
        } else {
            BigUint::zero().to_bytes_le()
        };
        let lrbit = if key.bit(i.try_into().unwrap()) {
            1u8
        } else {
            0u8
        };

        levels[i] = if st_tops[i] {
            let (l, r) = switcher(lrbit, &child, &siblings[i]);
            let hash = intermediate_leaf_hash(l, r);
            println!(
                "level_verifier {} {} + {} = {}",
                lrbit,
                pretty_hash(&child),
                pretty_hash(&siblings[i]),
                pretty_hash(&hash.clone()),
            ); // debug
            hash
        } else if st_inews[i] {
            println!("level_verifier new = {}", pretty_hash(&hash1_new.clone()),); // debug
            hash1_new.clone()
        } else if st_iolds[i] {
            println!("level_verifier old = {}", pretty_hash(&hash1_old.clone()),); // debug
            hash1_old.clone()
        } else {
            Vec::new()
        };

        if i > 0 {
            i -= 1;
        }
    }

    println!(
        "Expected root: {} (base10: {:?})",
        hex::encode(expected_root.to_bytes_le()),
        expected_root
    );
    println!(
        "Computed root: {} (base10: {})",
        (hex::encode(levels[0].clone())),
        (BigUint::from_bytes_le(&levels[0]).to_string())
    );

    assert!(expected_root.to_bytes_le() == levels[0]);

    assert!((fnc && (!is_old_0) && (old_key == key) && enabled) == false);
}

fn level_ins(siblings: &Vec<Vec<u8>>, enabled: bool) -> Vec<bool> {
    // println!(
    //     "level_ins {:?} {}",
    //     siblings
    //         .iter()
    //         .map(|x| pretty_hash(x))
    //         .collect::<Vec<String>>(),
    //     enabled
    // ); // debug
    let mut lev_ins = vec![false; siblings.len()];
    if enabled {
        assert!(*siblings[siblings.len() - 1] == vec![0u8; 32]);
    }

    let is_zero: Vec<bool> = siblings.iter().map(|i| **i == vec![0u8; 32]).collect();
    // println!("is_zero: {:?}", is_zero); // debug

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
    // println!("lev_ins {:?}", lev_ins); // debug

    lev_ins
}

fn sm_verifier(
    is_0: bool,
    lev_ins: bool,
    fnc: bool,
    prev_top: bool,
    prev_i0: bool,
    prev_iold: bool,
    prev_inew: bool,
    prev_na: bool,
) -> (bool, bool, bool, bool, bool) {
    let prev_top_lev_ins = prev_top && lev_ins;
    let prev_top_lev_ins_fnc = prev_top_lev_ins && fnc;
    let st_top = prev_top && !prev_top_lev_ins;
    let st_inew = prev_top_lev_ins && !prev_top_lev_ins_fnc;
    let st_iold = prev_top_lev_ins_fnc && !is_0;
    let st_i0 = prev_top_lev_ins && is_0;
    let st_na = prev_na || prev_inew || prev_iold || prev_i0;
    // println!(
    //     "sm_verifier gave: {} {} {} {} {}",
    //     st_top, st_inew, st_iold, st_i0, st_na
    // );
    (st_top, st_inew, st_iold, st_i0, st_na)
}

fn pretty_hash(bytes: &Vec<u8>) -> String {
    if bytes.len() < 6 {
        return hex::encode(bytes);
    }

    format!(
        "{}...{}",
        hex::encode(&bytes[0..3]),
        hex::encode(&bytes[bytes.len() - 3..])
    )
}
fn switcher<'a>(lrbit: u8, l: &'a Vec<u8>, r: &'a Vec<u8>) -> (&'a Vec<u8>, &'a Vec<u8>) {
    if lrbit == 0 {
        (l, r)
    } else {
        (r, l)
    }
}

// intermediate_leaf_value using Blake3 hash
pub(crate) fn end_leaf_hash(k: &Vec<u8>, v: &Vec<u8>) -> Vec<u8> {
    // blake3_hash(&[k, v, &BigUint::one().to_bytes_le()])
    poseidon_hash(&[k, v, &BigUint::one().to_bytes_le()])
}

// intermediate_leaf_value using Blake3 hash
pub(crate) fn intermediate_leaf_hash(l: &Vec<u8>, r: &Vec<u8>) -> Vec<u8> {
    // blake3_hash(&[l, r])
    poseidon_hash(&[l, r])
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
        // println!("input (hex): {}", hex::encode(input)); // debug
        hasher.update(input); // Pass the byte slice directly to the hasher
    }

    // Finalize the hash and return the resulting hash as a Vec<u8>
    let hash = hasher.finalize();

    // println!("hash (hex): {:?}", hash.to_hex()); // debug

    hash.as_bytes().to_vec()
}
