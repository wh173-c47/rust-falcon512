use crate::{constants::{M, N, NONCE_LEN, Q, SIG_COMP_MAXSIZE}, falcon512::{hash_to_point_ct, comp_decode, distance, mq_intt, mq_ntt, mq_poly_montymul_ntt, mq_poly_sub}, shake256::{shake_extract, shake_flip, shake_inject}};


// internal signature verification
// returns true if valid else false
pub fn verify_distance_raw(
    c0: &mut[u16; 512],
    s2: &[u16; 512],
    h: &[u16; 512],
    s1: &mut [u16; 512]
) -> u32 {
    let mut u = 0;
    let end = N as usize;

    // reduce s2_ elements modulo q ([0..q-1] range).
    loop {
        let w = s2[u];

        s1[u] = w + (Q & (0 - (w >> 0xf)));

        u += 1;

        if u == end {
            break;
        }
    };

    // computes -s1_ = s2_*h_ - c0_ mod ph_i mod q (in s1_[]).

    mq_ntt(s1);
    mq_poly_montymul_ntt(s1, h);
    mq_intt(s1);
    mq_poly_sub(s1, c0);

    // normalize -s1_ elements into th_e [-q/2..q/2] range.
    u = 0;

    let q_shr_1 = Q >> 0x1;

    loop {
        let w = s1[u];

        s1[u] = w - (Q & (0 - ((q_shr_1 - w) >> 0xf)));

        u += 1;

        if u == end {
            break;
        }
    };

    distance(s1, s2)
}

// verify that the given sig, msg and pub key matches
pub fn verify_distance(
    nonce_msg: &[u8],
    sig: &[u8],
    pk_ntt_fmt: &[u16; 512]
) -> u32 {
    let sig_len = sig.len();

    // sig must have a minimum length of 42 bytes
    // sig type must have the correct sig length in the pub key
    if
        sig_len < 1 ||
        sig_len  > SIG_COMP_MAXSIZE as usize ||
        nonce_msg.len() == NONCE_LEN as usize
    {
        return 0;
    }

    // sigLen (supplied arg) typical value is in the order of 650 to 660,
    // yielding cb_sig_proper in the order of 609 to 619
    let (decoded_sig, sz2) = comp_decode(&sig);

    if sz2 != sig_len {
        return 0;
    }

    // decoded_sig now contains decoded signature

    let mut shake_ctx = [0u64; 26];

    shake_inject(&mut shake_ctx, &nonce_msg);
    shake_flip(&mut shake_ctx);

    let extracted = shake_extract(&mut shake_ctx, (M << 0x1) as usize);

    let mut tmp_buff = [0u16; 512];
    let mut hash_nonce_msg = [0u16; 512];

    hash_to_point_ct(&extracted, &mut hash_nonce_msg, &mut tmp_buff);

    verify_distance_raw(
        &mut hash_nonce_msg,
        &decoded_sig,
        pk_ntt_fmt,
        &mut tmp_buff
    )
}
