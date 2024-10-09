// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use ark_bn254::Fr as Field; // Use BN254 scalar field
use ark_ff::{One, PrimeField, Zero}; // For field arithmetic and conversions
use ark_serialize::CanonicalSerialize; // Import serialization traits
use poseidon_ark::Poseidon; // Import Poseidon from the repository

// Helper function to convert a string into a Field element
fn to_field(val: &str) -> Field {
    let int_val = num_bigint::BigUint::parse_bytes(val.as_bytes(), 10).unwrap(); // Convert string to BigUint
    Field::from_le_bytes_mod_order(&int_val.to_bytes_le()) // Convert BigUint to Field
}

fn verify(expected_root: &Field, key: &Field, value: &Field, siblings: Vec<Field>) {
    verify_extended(
        &Field::one(),
        expected_root,
        &Field::zero(),
        &Field::zero(),
        &Field::zero(),
        key,
        value,
        &Field::zero(),
        siblings,
    );
}

fn verify_extended(
    enabled: &Field,
    expected_root: &Field,
    old_key: &Field,
    old_value: &Field,
    is_old_0: &Field,
    key: &Field,
    value: &Field,
    fnc: &Field,
    siblings: Vec<Field>,
) {
    let n_levels = siblings.len();
    let hash1_old = end_leaf_value(*old_key, *old_value);
    let hash1_new = end_leaf_value(*key, *value);
    let n2b_new = to_le_bits_254(key);

    let lev_ins = level_ins(&siblings, enabled.is_one());

    let mut st_tops = vec![Field::zero(); siblings.len()];
    let mut st_iolds = vec![Field::zero(); siblings.len()];
    let mut st_i0s = vec![Field::zero(); siblings.len()];
    let mut st_inews = vec![Field::zero(); siblings.len()];
    let mut st_nas = vec![Field::zero(); siblings.len()];

    for i in 0..n_levels {
        let (st_top, st_inew, st_iold, st_i0, st_na) = if i == 0 {
            sm_verifier(
                is_old_0,
                &lev_ins[0],
                fnc,
                enabled,
                &Field::zero(),
                &Field::zero(),
                &Field::zero(),
                &(Field::one() - enabled),
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
        st_nas[n_levels - 1]
            + st_iolds[n_levels - 1]
            + st_inews[n_levels - 1]
            + st_i0s[n_levels - 1]
            == Field::one()
    );

    let mut levels = vec![Field::zero(); siblings.len()];
    let mut i = n_levels - 1;
    for n in 0..n_levels {
        let child = if n != 0 { levels[i + 1] } else { Field::zero() };
        levels[i] = level_verifier(
            &st_tops[i],
            &st_inews[i],
            &st_iolds[i],
            &siblings[i],
            &hash1_old,
            &hash1_new,
            n2b_new[i],
            &child,
        );
        if i > 0 {
            i -= 1;
        }
    }

    println!("Expected root: {:?}", expected_root);
    println!("Computed root: {:?}", levels[0]);
    assert!(expected_root == &levels[0]);

    let are_keys_equal = if old_key == key {
        Field::one()
    } else {
        Field::zero()
    };
    assert!(
        multi_and(&[*fnc, (Field::one() - is_old_0), are_keys_equal, *enabled]) == Field::zero()
    );
}

fn level_ins(siblings: &[Field], enabled: bool) -> Vec<Field> {
    let mut lev_ins = vec![Field::zero(); siblings.len()];
    if enabled {
        assert!(siblings[siblings.len() - 1].is_zero());
    }

    let is_zero: Vec<Field> = siblings
        .iter()
        .map(|i| {
            if i.is_zero() {
                Field::one()
            } else {
                Field::zero()
            }
        })
        .collect();
    let mut is_done = vec![Field::zero(); siblings.len()];

    let last = Field::one() - &is_zero[siblings.len() - 2];
    lev_ins[siblings.len() - 1] = last.clone();
    is_done[siblings.len() - 2] = last.clone();

    for n in 2..siblings.len() {
        let i = siblings.len() - n;
        lev_ins[i] = (Field::one() - &is_done[i]) * (Field::one() - &is_zero[i - 1]);
        is_done[i - 1] = lev_ins[i].clone() + &is_done[i];
    }
    lev_ins[0] = Field::one() - &is_done[0];
    lev_ins
}

fn sm_verifier(
    is_0: &Field,
    lev_ins: &Field,
    fnc: &Field,
    prev_top: &Field,
    prev_i0: &Field,
    prev_iold: &Field,
    prev_inew: &Field,
    prev_na: &Field,
) -> (Field, Field, Field, Field, Field) {
    let prev_top_lev_ins = prev_top * lev_ins;
    let prev_top_lev_ins_fnc = &prev_top_lev_ins * fnc;
    let st_top = prev_top - &prev_top_lev_ins;
    let st_inew = &prev_top_lev_ins - &prev_top_lev_ins_fnc;
    let st_iold = &prev_top_lev_ins_fnc * &(Field::one() - is_0);
    let st_i0 = &prev_top_lev_ins * is_0;
    let st_na = prev_na + prev_inew + prev_iold + prev_i0;
    (st_top, st_inew, st_iold, st_i0, st_na)
}

fn level_verifier(
    st_top: &Field,
    st_inew: &Field,
    st_iold: &Field,
    sibling: &Field,
    old1leaf: &Field,
    new1leaf: &Field,
    lrbit: u8,
    child: &Field,
) -> Field {
    let (l, r) = switcher(lrbit, child, sibling);
    (intermediate_leaf_value(l, r) * st_top) + (old1leaf * st_iold) + (new1leaf * st_inew)
}

fn switcher(sel: u8, l: &Field, r: &Field) -> (Field, Field) {
    if sel == 0 {
        (l.clone(), r.clone())
    } else {
        (r.clone(), l.clone())
    }
}

// Bitwise AND for Field elements
fn field_and(a: Field, b: Field) -> Field {
    // Create byte buffers for serialized field elements
    let mut a_bytes = Vec::new();
    let mut b_bytes = Vec::new();

    // Convert field elements to 32-byte arrays (big-endian representation)
    CanonicalSerialize::serialize_uncompressed(&a, &mut a_bytes).unwrap();
    CanonicalSerialize::serialize_uncompressed(&b, &mut b_bytes).unwrap();

    let mut c = [0u8; 32]; // Create a 32-byte array to store the result

    // Perform byte-wise AND between a_bytes and b_bytes
    for i in 0..32 {
        c[i] = a_bytes[i] & b_bytes[i];
    }

    // Convert the resulting byte array back into a field element
    Field::from_le_bytes_mod_order(&c)
}

// Perform bitwise AND over an array of Field elements
fn multi_and(arr: &[Field]) -> Field {
    arr.iter().cloned().reduce(|a, b| field_and(a, b)).unwrap()
}

// Poseidon hash function example (ensure correct Poseidon parameters are used)
fn poseidon_hash(inputs: &[Field]) -> Field {
    Poseidon::new().hash(inputs.to_vec()).expect("hash failed") // This will hash the input array using Poseidon
}

// endLeafValue using Poseidon hash
pub(crate) fn end_leaf_value(k: Field, v: Field) -> Field {
    poseidon_hash(&[k, v, Field::from(1u64)]) // Hash key, value, and 1
}

// intermediateLeafValue using Poseidon hash
pub(crate) fn intermediate_leaf_value(l: Field, r: Field) -> Field {
    poseidon_hash(&[l, r]) // Hash left and right children
}

// Function to get the least significant 254 bits of a Field element
fn to_le_bits_254(value: &Field) -> Vec<u8> {
    let mut serialized_bytes = Vec::new();

    // Serialize the field element into the byte vector
    value.serialize_uncompressed(&mut serialized_bytes).unwrap();

    // Take the first 254 bits (32 bytes = 256 bits, so we trim the last 2 bits)
    let mut bits = Vec::new();
    for byte in serialized_bytes.iter().take(32) {
        // We take the first 32 bytes
        for bit_index in 0..8 {
            let bit = (byte >> bit_index) & 1; // Extract each bit
            bits.push(bit);
        }
    }

    // Return the first 254 bits
    bits.truncate(254);
    bits
}

fn main() {
    println!("start");
    main1();
    // main2();
    println!("done");
}

fn main1() {
    // Example usage with big integers
    let root =
        to_field("21135506078746510573119705753579567335835726524098367527812922933644667691006");
    let key = to_field("500400244448261235194511589700085192056257072811");
    let value = to_field("10");
    let mut siblings = vec![
        to_field("13175438946403099127785287940793227584022396513432127658229341995655669945927"),
        to_field("8906855681626013805208515602420790146700990181185755277830603493975762067087"),
        to_field("9457781280074316365191154663065840032069867769247887694941521931147573919101"),
        to_field("3886003602968045687040541715852317767887615077999207197223340281752527813105"),
        to_field("5615297718669932502221460377065820025799135258753150375139282337562917282190"),
        to_field("8028805327216345358010190706209509799652032446863364094962139617192615346584"),
        to_field("572541247728029242828004565014369314635015057986897745288271497923406188177"),
        to_field("9738042754594087795123752255236264962836518315799343893748681096434196901468"),
    ];

    // Ensure the last sibling is zero
    siblings.push(Field::zero());

    verify(&root, &key, &value, siblings);
}

fn main2() {
    // Example usage with big integers
    let root =
        to_field("13558168455220559042747853958949063046226645447188878859760119761585093422436");
    let key = to_field("2");
    let value = to_field("22");
    let mut siblings = vec![
        to_field("11620130507635441932056895853942898236773847390796721536119314875877874016518"),
        to_field("5158240518874928563648144881543092238925265313977134167935552944620041388700"),
        to_field("0"),
        to_field("0"),
    ];

    // Ensure the last sibling is zero
    siblings.push(Field::zero());

    verify(&root, &key, &value, siblings);
}
