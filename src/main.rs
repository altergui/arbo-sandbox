use std::ops::BitAnd;

fn verify<N: Copy + Into<usize>>(root: u128, key: u128, value: u128, siblings: [u128; N]) {
    verify_extended(1, root, 0, 0, 0, key, value, 0, siblings);
}

fn verify_extended<N: Copy + Into<usize>>(
    enabled: u128,
    root: u128,
    old_key: u128,
    old_value: u128,
    is_old_0: u128,
    key: u128,
    value: u128,
    fnc: u128,
    siblings: [u128; N],
) {
    let n_levels = siblings.len() as u128;
    let hash1_old = end_leaf_value(old_key, old_value);
    let hash1_new = end_leaf_value(key, value);

    // Placeholder for converting key to bits (left as integer array for simplicity)
    let n2b_new: [u8; 254] = to_le_bits_254(key);

    let lev_ins = level_ins(&siblings, enabled == 1);

    let mut st_tops: Vec<u128> = vec![0; siblings.len()];
    let mut st_iolds: Vec<u128> = vec![0; siblings.len()];
    let mut st_i0s: Vec<u128> = vec![0; siblings.len()];
    let mut st_inews: Vec<u128> = vec![0; siblings.len()];
    let mut st_nas: Vec<u128> = vec![0; siblings.len()];

    for i in 0..n_levels as usize {
        let (st_top, st_inew, st_iold, st_i0, st_na) = if i == 0 {
            sm_verifier(is_old_0, lev_ins[0], fnc, enabled, 0, 0, 0, 1 - enabled)
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
        st_nas[n_levels as usize - 1]
            + st_iolds[n_levels as usize - 1]
            + st_inews[n_levels as usize - 1]
            + st_i0s[n_levels as usize - 1]
            == 1
    );

    let mut levels = vec![0; siblings.len()];
    let mut i = n_levels as usize - 1;
    for n in 0..n_levels as usize {
        levels[i] = level_verifier(
            st_tops[i],
            st_inews[i],
            st_iolds[i],
            siblings[i],
            hash1_old,
            hash1_new,
            n2b_new[i] as u8,
            if n != 0 { levels[i + 1] } else { 0 },
        );
        if i > 0 {
            i -= 1;
        }
    }

    let are_key_equals = if old_key == key { 1 } else { 0 };
    assert!(multi_and(&[fnc, 1 - is_old_0, are_key_equals, enabled]) == 0);
    assert!(root == levels[0]);
}

fn level_ins<N: Copy + Into<usize>>(siblings: &[u128; N], enabled: bool) -> Vec<u128> {
    let mut lev_ins: Vec<u128> = vec![0; siblings.len()];
    if enabled {
        assert!(siblings[siblings.len() - 1] == 0);
    }

    let is_zero: Vec<u128> = siblings
        .iter()
        .map(|&i| if i == 0 { 1 } else { 0 })
        .collect();
    let mut is_done: Vec<u128> = vec![0; siblings.len()];

    let last = 1 - is_zero[siblings.len() - 2];
    lev_ins[siblings.len() - 1] = last;
    is_done[siblings.len() - 2] = last;

    for n in 2..siblings.len() {
        let i = siblings.len() - n;
        lev_ins[i] = (1 - is_done[i]) * (1 - is_zero[i - 1]);
        is_done[i - 1] = lev_ins[i] + is_done[i];
    }
    lev_ins[0] = 1 - is_done[0];
    lev_ins
}

fn sm_verifier(
    is_0: u128,
    lev_ins: u128,
    fnc: u128,
    prev_top: u128,
    prev_i0: u128,
    prev_iold: u128,
    prev_inew: u128,
    prev_na: u128,
) -> (u128, u128, u128, u128, u128) {
    let prev_top_lev_ins = prev_top * lev_ins;
    let prev_top_lev_ins_fnc = prev_top_lev_ins * fnc;
    let st_top = prev_top - prev_top_lev_ins;
    let st_inew = prev_top_lev_ins - prev_top_lev_ins_fnc;
    let st_iold = prev_top_lev_ins_fnc * (1 - is_0);
    let st_i0 = prev_top_lev_ins * is_0;
    let st_na = prev_na + prev_inew + prev_iold + prev_i0;
    (st_top, st_inew, st_iold, st_i0, st_na)
}

fn level_verifier(
    st_top: u128,
    st_inew: u128,
    st_iold: u128,
    sibling: u128,
    old1leaf: u128,
    new1leaf: u128,
    lrbit: u8,
    child: u128,
) -> u128 {
    let (l, r) = switcher(lrbit, child, sibling);
    (intermediate_leaf_value(l, r) * st_top) + (old1leaf * st_iold) + (new1leaf * st_inew)
}

fn switcher(sel: u8, l: u128, r: u128) -> (u128, u128) {
    if sel == 0 {
        (l, r)
    } else {
        (r, l)
    }
}

fn multi_and(arr: &[u128]) -> u128 {
    arr.iter().fold(u128::MAX, |acc, &x| acc.bitand(x))
}

fn end_leaf_value(k: u128, v: u128) -> u128 {
    // Placeholder for hash function, replace with actual cryptographic hash
    k ^ v ^ 1
}

fn intermediate_leaf_value(l: u128, r: u128) -> u128 {
    // Placeholder for hash function, replace with actual cryptographic hash
    l ^ r
}

fn to_le_bits_254(value: u128) -> [u8; 254] {
    // Placeholder for converting a value to a bit array of length 254
    let mut bits = [0; 254];
    for i in 0..254 {
        bits[i] = ((value >> i) & 1) as u8;
    }
    bits
}

fn main() {
    // Example usage of verify function
    let root = 21135506078746510573119705753579567335835726524098367527812922933644667691006u128;
    let key = 500400244448261235194511589700085192056257072811u128;
    let value = 10u128;
    let siblings: [u128; 8] = [
        13175438946403099127785287940793227584022396513432127658229341995655669945927u128,
        8906855681626013805208515602420790146700990181185755277830603493975762067087u128,
        9457781280074316365191154663065840032069867769247887694941521931147573919101u128,
        3886003602968045687040541715852317767887615077999207197223340281752527813105u128,
        5615297718669932502221460377065820025799135258753150375139282337562917282190u128,
        8028805327216345358010190706209509799652032446863364094962139617192615346584u128,
        572541247728029242828004565014369314635015057986897745288271497923406188177u128,
        9738042754594087795123752255236264962836518315799343893748681096434196901468u128,
    ];
    let mut total_siblings: [u128; 160] = [0; 160];
    for i in 0..siblings.len() {
        total_siblings[i] = siblings[i];
    }
    verify(root, key, value, total_siblings);
}
