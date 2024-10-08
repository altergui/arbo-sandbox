use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::{One, Zero};
use std::ops::BitAnd;
use std::ops::Shr;

// Helper function to convert large integer literals into BigUint
fn to_biguint(val: &str) -> BigUint {
    BigUint::parse_bytes(val.as_bytes(), 10).unwrap()
}

fn verify(root: &BigUint, key: &BigUint, value: &BigUint, siblings: Vec<BigUint>) {
    verify_extended(
        &BigUint::one(),
        root,
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
    root: &BigUint,
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
    let n2b_new = to_le_bits_254(key);

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
            &levels[i + 1]
        } else {
            &BigUint::zero()
        };
        levels[i] = level_verifier(
            &st_tops[i],
            &st_inews[i],
            &st_iolds[i],
            &siblings[i],
            &hash1_old,
            &hash1_new,
            n2b_new[i],
            child,
        );
        if i > 0 {
            i -= 1;
        }
    }

    println!("Expected root: {:?}", root);
    println!("Computed root: {:?}", levels[0]);
    assert!(root == &levels[0]);

    let are_keys_equal = if old_key == key {
        BigUint::one()
    } else {
        BigUint::zero()
    };
    assert!(
        multi_and(&[fnc, &(BigUint::one() - is_old_0), &are_keys_equal, enabled])
            == BigUint::zero()
    );
}

fn level_ins(siblings: &[BigUint], enabled: bool) -> Vec<BigUint> {
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
    let (l, r) = switcher(lrbit, child, sibling);
    (intermediate_leaf_value(&l, &r) * st_top) + (old1leaf * st_iold) + (new1leaf * st_inew)
}

fn switcher(sel: u8, l: &BigUint, r: &BigUint) -> (BigUint, BigUint) {
    if sel == 0 {
        (l.clone(), r.clone())
    } else {
        (r.clone(), l.clone())
    }
}

fn multi_and(arr: &[&BigUint]) -> BigUint {
    arr.iter().fold(BigUint::one(), |acc, x| acc.bitand(&**x))
}

fn end_leaf_value(k: &BigUint, v: &BigUint) -> BigUint {
    // Placeholder for hash function, replace with actual cryptographic hash
    k ^ v ^ BigUint::one()
}

fn intermediate_leaf_value(l: &BigUint, r: &BigUint) -> BigUint {
    // Placeholder for hash function, replace with actual cryptographic hash
    l ^ r
}

fn to_le_bits_254(value: &BigUint) -> Vec<u8> {
    (0..254)
        .map(|i| {
            (value.shr(i as u32).bitand(BigUint::one()))
                .to_u8()
                .unwrap_or(0)
        })
        .collect()
}

fn main() {
    // Example usage with big integers
    // let root =
    //     to_biguint("21135506078746510573119705753579567335835726524098367527812922933644667691006");
    // let key = to_biguint("500400244448261235194511589700085192056257072811");
    // let value = to_biguint("10");
    // let mut siblings = vec![
    //     to_biguint("13175438946403099127785287940793227584022396513432127658229341995655669945927"),
    //     to_biguint("8906855681626013805208515602420790146700990181185755277830603493975762067087"),
    //     to_biguint("9457781280074316365191154663065840032069867769247887694941521931147573919101"),
    //     to_biguint("3886003602968045687040541715852317767887615077999207197223340281752527813105"),
    //     to_biguint("5615297718669932502221460377065820025799135258753150375139282337562917282190"),
    //     to_biguint("8028805327216345358010190706209509799652032446863364094962139617192615346584"),
    //     to_biguint("572541247728029242828004565014369314635015057986897745288271497923406188177"),
    //     to_biguint("9738042754594087795123752255236264962836518315799343893748681096434196901468"),
    // ];

    // // Ensure the last sibling is zero
    // siblings.push(BigUint::zero());

    let root = to_biguint("1");
    let key = to_biguint("1");
    let value = to_biguint("1");
    let siblings = vec![to_biguint("0"), to_biguint("1"), to_biguint("0")];
    verify(&root, &key, &value, siblings);
}
