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
    let n2b_new = key.clone();

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
        levels[i] = level_verifier(
            &st_tops[i],
            &st_inews[i],
            &st_iolds[i],
            &siblings[i],
            &hash1_old,
            &hash1_new,
            n2b_new.bit(i.try_into().unwrap()),
            &child,
        );
        if i > 0 {
            i -= 1;
        }
    }

    println!("Expected root: {:?}", expected_root);
    println!("Expected root(hex): {:x}", (*expected_root));
    println!("Computed root: {:?}", (levels[0]));
    println!("Computed root(hex): {:x}", (levels[0]));
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
    // if enabled {
    //     assert!(siblings[siblings.len() - 1].is_zero());
    // }

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
    lrbit: bool,
    child: &BigUint,
) -> BigUint {
    let (l, r) = switcher(lrbit, child, sibling);
    (intermediate_leaf_value(l, r) * st_top) + (old1leaf * st_iold) + (new1leaf * st_inew)
}

fn switcher(sel: bool, l: &BigUint, r: &BigUint) -> (BigUint, BigUint) {
    if sel {
        (l.clone(), r.clone())
    } else {
        (r.clone(), l.clone())
    }
}

// Bitwise AND for BigUint elements
// TODO: can't we do simply `a&b`?
fn field_and(a: BigUint, b: BigUint) -> BigUint {
    // Create byte buffers
    let a_bytes = a.to_bytes_be();
    let b_bytes = b.to_bytes_be();

    let mut c = [0u8; 32]; // Create a 32-byte array to store the result
                           // Perform byte-wise AND between a_bytes and b_bytes
    for i in 0..32 {
        c[i] = a_bytes[i] & b_bytes[i];
    }

    // Convert the resulting byte array back into a biguint
    BigUint::from_bytes_be(&c)
}

// Perform bitwise AND over an array of BigUint elements
fn multi_and(arr: &[BigUint]) -> BigUint {
    arr.iter().cloned().reduce(|a, b| field_and(a, b)).unwrap()
}

fn blake3_hash(inputs: &[BigUint]) -> BigUint {
    let mut hasher = blake3::Hasher::new();

    // Iterate over each field, serialize it, and pass it to the hasher
    for field in inputs {
        println!("input {:?}", (*field).to_string());
        println!("input(hex) {:x}", (*field));
        hasher.update(&field.to_bytes_be()); // Vec<u8> gets converted to &[u8] automatically
    }

    // Finalize the hash and take the first 32 bytes
    let hash = hasher.finalize();
    println!("hash {:?}", &hash.to_hex());
    println!("hash(bytes) {:?}", &hash.as_bytes());
    println!("hash(base10BE) {}", BigUint::from_bytes_be(hash.as_bytes()));
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
    let proof = sp1_zkvm::io::read::<MerkleProof>();
    // test_blake3_hash();
    // // let hash: '
    // println!("hash {:?}", &hash.to_hex());
    // println!("hash(bytes) {:?}", &hash.as_bytes());
    // println!(
    //     "hash(base10) {:?}",
    //     field_to_biguint(BigUint::from_be_bytes_mod_order(hash.as_bytes()))
    // );
    let m = BigUint::from(5_u32);
    println!("{} {} {}", m.bit(0), m.bit(1), m.bit(2));
    verify(&(proof.root), &(proof.key), &(proof.value), proof.siblings);

    println!("done");
}

fn test_blake3_hash() {
    let mut hasher = blake3::Hasher::new();

    hasher.update(&[{ 0x01u8 }]); //

    // Finalize the hash and take the first 32 bytes
    let hash = hasher.finalize();
    println!("hash {:?}", &hash.as_bytes()[..32]); // Use only the first 32 bytes (256 bits)
    println!("hash {:?}", &hash.to_hex()[..32]); // Use only the first 32 bytes (256 bits)
}

fn _hardcoded_blake3_test1() {
    // Example usage with big integers
    // let root =
    //     to_field("21135506078746510573119705753579567335835726524098367527812922933644667691006"); // this is the resulting hash using Poseidon

    let root = BigUint::from_str(
        "10768433685903779808492645729755013812360352060157252115590238143087516437857",
    )
    .unwrap(); // this is the resulting hash using Blake3

    let key = BigUint::from_str("500400244448261235194511589700085192056257072811").unwrap();
    let value = BigUint::from_str("10").unwrap();
    let mut siblings = vec![
        BigUint::from_str(
            "13175438946403099127785287940793227584022396513432127658229341995655669945927",
        )
        .unwrap(),
        BigUint::from_str(
            "8906855681626013805208515602420790146700990181185755277830603493975762067087",
        )
        .unwrap(),
        BigUint::from_str(
            "9457781280074316365191154663065840032069867769247887694941521931147573919101",
        )
        .unwrap(),
        BigUint::from_str(
            "3886003602968045687040541715852317767887615077999207197223340281752527813105",
        )
        .unwrap(),
        BigUint::from_str(
            "5615297718669932502221460377065820025799135258753150375139282337562917282190",
        )
        .unwrap(),
        BigUint::from_str(
            "8028805327216345358010190706209509799652032446863364094962139617192615346584",
        )
        .unwrap(),
        BigUint::from_str(
            "572541247728029242828004565014369314635015057986897745288271497923406188177",
        )
        .unwrap(),
        BigUint::from_str(
            "9738042754594087795123752255236264962836518315799343893748681096434196901468",
        )
        .unwrap(),
    ];

    // Ensure the last sibling is zero
    siblings.push(BigUint::zero());

    verify(&root, &key, &value, siblings);
}

// fn _hardcoded_test2() {
//     // Example usage with big integers
//     let root = string_to_field(
//         "13558168455220559042747853958949063046226645447188878859760119761585093422436",
//     );
//     let key = string_to_field("2");
//     let value = string_to_field("22");
//     let mut siblings = vec![
//         string_to_field(
//             "11620130507635441932056895853942898236773847390796721536119314875877874016518",
//         ),
//         string_to_field(
//             "5158240518874928563648144881543092238925265313977134167935552944620041388700",
//         ),
//         string_to_field("0"),
//         string_to_field("0"),
//     ];

//     // Ensure the last sibling is zero
//     siblings.push(BigUint::zero());

//     verify(&root, &key, &value, siblings);
// }
