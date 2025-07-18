use crate::{
    constants::{
        errors::E_INVALID_PUBLIC_KEY,
        FALCON_PK_SIZE,
        OVER_SAMPLING,
        GMB,
        IGMB,
        LOGN,
        M,
        N,
        NONCE_LEN,
        Q,
        R2,
        SIG_COMP_MAXSIZE
    },
    shake256::{shake_inject, shake_flip, shake_extract },
    utils::{mq_add, mq_sub, mq_montymul, revert, sign_extend_u16_to_u32, submod, swap_byte_pairs}
};

// TODO: see below if no branching worth vs early exited branching
#[inline(always)]
fn handle_hash_to_point_bytes_pair(pair: u64) -> u16 {
    let mut r = pair - (24578 & ((pair - 24578 >> 63) - 1));

    r = r - (24578 & (((r - 24578) >> 63) - 1));
    r = r - (12289 & (((r - 12289) >> 63) - 1));

    (r | ((pair - 61445) >> 63) - 1) as u16
}

#[inline(always)]
pub fn handle_hash_to_point_chunk(
    chunk: u64,
    out: &mut [u16; 512],
    index: usize
) {
    let swapped = swap_byte_pairs(chunk);

    out[index] = handle_hash_to_point_bytes_pair(swapped & 0xffff);
    out[index + 1] = handle_hash_to_point_bytes_pair(swapped >> 0x10 & 0xffff);
    out[index + 2] = handle_hash_to_point_bytes_pair(swapped >> 0x20 & 0xffff);
    out[index + 3] = handle_hash_to_point_bytes_pair(swapped >> 0x30);
}

// constant-time produces a new point from a flipped shake256 context
// TODO: optimize further
pub fn hash_to_point_ct(
    extracted: &Vec<u64>,
    x: &mut [u16; 512],
    tt1: &mut [u16; 512]
) {
    let mut u = 0;

    // handling `x` len 512, unrolled x32 => 16 runs
    loop {
        let index: usize = u << 0x2;

        handle_hash_to_point_chunk(extracted[u], x, index);
        handle_hash_to_point_chunk(extracted[u + 1], x, index + 0x4);
        handle_hash_to_point_chunk(extracted[u + 2], x, index + 0x8);
        handle_hash_to_point_chunk(extracted[u + 3], x, index + 0xc);
        handle_hash_to_point_chunk(extracted[u + 4], x, index + 0x10);
        handle_hash_to_point_chunk(extracted[u + 5], x, index + 0x14);
        handle_hash_to_point_chunk(extracted[u + 6], x, index + 0x18);
        handle_hash_to_point_chunk(extracted[u + 7], x, index + 0x1c);

        u += 8;

        if u == 0x80 {
            break;
        }
    };

    let mut out_index = 0;

    // handling `tt1` OVERSAMPLING - 13 unrolled x32 => 6 runs
    loop {
        handle_hash_to_point_chunk(extracted[u], tt1, out_index);
        handle_hash_to_point_chunk(extracted[u + 1], tt1, out_index + 0x4);
        handle_hash_to_point_chunk(extracted[u + 2], tt1, out_index + 0x8);
        handle_hash_to_point_chunk(extracted[u + 3], tt1, out_index + 0xc);
        handle_hash_to_point_chunk(extracted[u + 4], tt1, out_index + 0x10);
        handle_hash_to_point_chunk(extracted[u + 5], tt1, out_index + 0x14);
        handle_hash_to_point_chunk(extracted[u + 6], tt1, out_index + 0x18);
        handle_hash_to_point_chunk(extracted[u + 7], tt1, out_index + 0x1c);

        u += 8;
        out_index += 32;

        if u == 0xb0 {
            break;
        }
    };

    // handles remaining 13 items
    handle_hash_to_point_chunk(extracted[0xb0], tt1, out_index);
    handle_hash_to_point_chunk(extracted[0xb1], tt1, out_index + 0x4);
    handle_hash_to_point_chunk(extracted[0xb2], tt1, out_index + 0x8);

    let swapped = swap_byte_pairs(extracted[0xb3]);

    tt1[out_index + 0xc] = handle_hash_to_point_bytes_pair(swapped & 0xffff);

    let mut p = 1;

    loop {
        let mut v: u16 = 0;
        let mut u: usize = 0;

        // skip first round if u < p
        loop {
            // Update v (unsigned arithmetic, subtract mk)
            v -= (x[u] >> 0xf) - 1;
            u += 1;

            if u == p {
                break;
            }
        };

        // first loop for `u < _N`
        loop {
            let sv: u16 = x[u];
            let j = u as u16 - v;
            // mk = (sv >> 15) - 1 (but we work in uint256 now)
            // mk is 0xFFFFFFFFFFFFFFFF... for negative condition
            let mut mk = (sv >> 0xf) - 1;

            // Update v (unsigned arithmetic, subtract mk)
            v -= mk;

            // Adjust mk with new condition (same shift as before but in uint256)
            mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

            let xi = u - p;
            let dv = x[xi];
            let mk_and_sv_xor_dv = mk & (sv ^ dv);

            x[xi] = dv ^ mk_and_sv_xor_dv;
            x[u] = sv ^ mk_and_sv_xor_dv;

            u += 1;

            if u == N as usize {
                break;
            }
        };

        // sec loop for `u >= _M || (u - p) >= _N`

        loop {
            let tt1i = u - N as usize;
            let sv = tt1[tt1i];
            let j = u as u16 - v;
            let mut mk = (sv >> 0xf) - 1;

            v -= mk;

            mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

            let xi = u - p;
            let dv = x[xi];
            let mk_and_sv_xor_dv = mk & (sv ^ dv);

            x[xi] = dv ^ mk_and_sv_xor_dv;
            tt1[tt1i] = sv ^ mk_and_sv_xor_dv;

            u += 1;

            if u < M as usize && (u - p) < N as usize {
                continue;
            }

            break;
        };

        // sec loop for `u < _M`
        loop {
            let u_sub_n = u - N as usize;
            let sv = tt1[u_sub_n];
            let j = u as u16 - v;
            let mut mk = (sv >> 0xf) - 1;

            v = v - mk;

            mk &= 0 - (((j & p as u16) + 0x1ff) >> 0x9);

            let dvi = u_sub_n - p;
            let dv = tt1[dvi];
            let mk_and_sv_xor_dv = mk & (sv ^ dv);

            tt1[dvi] = dv ^ mk_and_sv_xor_dv;
            tt1[u_sub_n] = sv ^ mk_and_sv_xor_dv;

            u += 1;

            if u == M as usize {
                break;
            }
        };

        p = p << 0x1;

        if p < OVER_SAMPLING as usize {
            continue;
        };

        break;
    };
}

/// Computes the Number Theoretic Transform (NTT) on a polynomial in-place.
///
/// This is a Rust implementation of the Gentleman-Sande (GS) NTT algorithm,
/// using the Montgomery multiplication for efficiency. It directly corresponds
/// to the logic in the provided `_mq_NTT` Yul function.
///
/// # Arguments
/// * `p` - A mutable slice representing the polynomial coefficients.
#[inline(always)]
pub fn mq_ntt(p: &mut [u16]) {
    let mut t = N;
    let mut m = 1;

    while m != N {
        let ht = t >> 1;
        let mut j1 = 0;

        for i in 0..m {
            let s = GMB[(m + i) as usize];
            let j2 = j1 + ht;

            for j in j1..j2 {
                let u = p[j as usize];
                let v = mq_montymul(p[(j + ht) as usize], s);

                p[j as usize] = mq_add(u, v);
                p[(j + ht) as usize] = mq_sub(u, v);
            }

            j1 += t;
        }

        t = ht;
        m = m << 1;
    }
}


/// Computes the Inverse Number Theoretic Transform (iNTT) on a polynomial in-place.
///
/// This is a faithful Rust translation of the provided Yul iNTT implementation,
/// including the specific final normalization logic.
///
/// # Arguments
/// * `p` - A mutable slice representing the polynomial coefficients in NTT domain.
/// * `igmb` - A slice containing the precomputed Montgomery-form inverse twiddle factors.
#[inline(always)]
pub fn mq_intt(p: &mut [u16]) {
    let mut t = 1;
    let mut m = N;

    while m != 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0;

        for i in 0..hm {
            let s = IGMB[(hm + i) as usize];
            let j2 = j1 + t;

            for j in j1..j2 {
                let u = p[j as usize];
                let v = p[(j + t) as usize];

                p[j as usize] = mq_add(u, v);
                p[(j + t) as usize] = mq_montymul(mq_sub(u, v), s);
            }

            j1 += dt
        }

        t = dt;
        m = hm;
    }

    for val in p.iter_mut() {
        // precomputed 9 loop of mq_shr1(N)
        *val = mq_montymul(*val, 0x80);
    }
}

/// Converts a polynomial's coefficients to Montgomery representation in-place.
///
/// This operation is required before performing NTT-based polynomial multiplication.
/// It multiplies every coefficient of the polynomial `p` by `R^2 mod Q` using
/// Montgomery multiplication.
///
/// # Arguments
/// * `p` - A mutable slice representing the polynomial to be converted.
#[inline(always)]
pub fn mq_poly_tomonty(p: &mut [u16]) {
    for c in p.iter_mut() {
        *c = mq_montymul(*c, R2);
    }
}

/// Performs pointwise multiplication of two polynomials in NTT form.
///
/// This function takes two polynomials, `f` and `g`, which are already in
/// NTT and Montgomery representation, and computes their product `f[i] * g[i]`
/// for all `i`. The result is written back over the `f` polynomial.
///
/// # Arguments
/// * `f` - A mutable slice for the first polynomial, `f`. The result is stored here.
/// * `g` - An immutable slice for the second polynomial, `g`.
#[inline(always)]
pub fn mq_poly_montymul_ntt(f: &mut [u16], g: &[u16]) {
    // We zip the iterators of f and g. This is the most efficient and safe
    // way to perform element-wise operations in Rust. The compiler will optimize
    // this to a simple, tight loop with no bounds checks.
    for (f_i, g_i) in f.iter_mut().zip(g.iter()) {
        *f_i = mq_montymul(*f_i, *g_i);
    }
}

/// sub polynomial g from polynomial f
/// result f-g is written over f
///
/// # Arguments
/// * `f` - A mutable slice for the first polynomial, `f`. The result is stored here.
/// * `g` - An immutable slice for the second polynomial, `g`.
pub fn mq_poly_sub(f: &mut [u16; 512], g: &[u16; 512]) {
    let mut i = 0;
    let end: usize = N as usize;

    loop {
        f[i] = submod(f[i], g[i], Q);

        i += 1;

        if i == end {
            break;
        }
    }
}

/// converts a pub key to NTT + Montgomery format
///
/// # Arguments
/// * `pubkey` - A mutable slice of the Falcon public key. The result is stored here.
#[inline(always)]
pub fn to_ntt_monty(
    pubkey: &mut [u16; 512]
) {
    mq_ntt(pubkey);
    mq_poly_tomonty(pubkey);
}

pub fn distance(s1: &[u16; 512], s2: &[u16; 512]) -> u32 {
    let mut s: u32 = 0;
    let mut ng: u32 = 0;
    let mut u = 0;
    let end = N as usize;

    loop {
        let z:  u32 = sign_extend_u16_to_u32(s1[u]);

        s += z * z;
        ng |= s;

        let z:  u32 = sign_extend_u16_to_u32(s2[u]);

        s += z * z;
        ng |= s;

        u += 1;

        if u == end {
            break;
        }
    };

    ng = 0 - (ng >> 0x1f);

    s | ng
}

/// returns true if given vector (2N coord, in two halves) is acceptable as signature
/// compares appropriate norm of the vector with acceptance bound
pub fn is_short(s1: &[u16; 512], s2: &[u16; 512]) -> bool {
    distance(s1, s2) <= 34034726
}

// decode the public key
pub fn mq_decode(x: &mut [u16; 512], input: &[u8; 897], offset: usize) -> u16 {
    let mut acc: u64 = 0;
    let mut in_offset = offset;
    let mut acc_len: u8 = 0;
    let mut u = 0;
    // ((_N * 14) + 7) >> 3
    let mut ret = 896;
    let end = N as usize;

    loop {
        // byte(0, input[in_offset])
        acc = (acc << 0x8) | (input[in_offset] as u64);

        in_offset += 1;
        acc_len += 8;

        if acc_len < 0xe {
            continue;
        }

        acc_len -= 0xe;

        let w: u16 = ((acc >> acc_len) & 0x3fff) as u16;

        if w < 12289 {
            x[u] = w;

            u += 1;

            if u == end {
                break;
            }

            continue;
        }

        ret = 0;

        break;
    };

    if (acc & (1 << acc_len) - 1) != 0 {
        ret = 0;
    }

    ret
}

// from an in, an out and a max in len, returns the nb of bytes read from the buffer
pub fn comp_decode(
    input: &[u8]
) -> ([u16; 512], usize) {
    let in_max = input.len();
    let mut out = [0u16; 512];
    let mut v = 0;
    let mut acc = 0;
    let mut acc_len = 0;
    let mut u = 0;

    v = loop {
        if v < in_max {
            acc = (acc << 0x8) | (input[v] as u16);
            v += 1;

            let b = acc >> acc_len;
            let mut m = b & 0x7f;
            let s = b & 0x80;

            v = loop {
                if acc_len == 0 {
                    if v < in_max {
                       acc = (acc << 0x8) | (input[v] as u16);
                       v += 1;
                       acc_len = 8;
                    } else {
                        break 0;
                    }
                }

                acc_len -= 1;

                if (acc >> acc_len) & 1 != 0 {
                    break v;
                }

                m += 0x80;

                if m > 2047 {
                    break 0;
                }
            };

            if m == 0 && s != 0 {
                break 0;
            }

            // m | -m
            out[u] = if s == 0 { m } else { 0 - m };

            u += 1;

            if u == N as usize {
                break v;
            }

            continue;
        }

        break 0;
    };

    (out, v)
}

// internal signature verification
// returns true if valid else false
pub fn verify_raw(
    c0: &mut[u16; 512],
    s2: &[u16; 512],
    h: &[u16; 512],
    s1: &mut [u16; 512]
) -> bool {
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

    is_short(s1, s2)
}

pub fn pk_to_ntt_fmt(pk: &[u8; 897]) -> [u16; 512] {
    // 1st byte should have the form "0000nnnn"
    if (pk[0] >> 0x4) != 0 || pk[0] & 0xf != LOGN {
        revert(E_INVALID_PUBLIC_KEY);
    }

    let mut pk_ntt_fmt = [0u16; 512];

    // decode public key
    // let sz1 = mq_decode2(ref pk_ntt_fmt, pk.span(), 1);
    let sz1 = mq_decode(&mut pk_ntt_fmt, pk, 1);

    if sz1 != FALCON_PK_SIZE - 1 {
        revert(E_INVALID_PUBLIC_KEY);
    }

    // pk_ntt_fmt now contains decoded public key

    to_ntt_monty(&mut pk_ntt_fmt);

    pk_ntt_fmt
}

// verify that the given sig, msg and pub key matches
pub fn verify(
    nonce_msg: &[u8],
    sig: &[u8],
    pk_ntt_fmt: &[u16; 512]
) -> bool {
    let sig_len = sig.len();

    // sig must have a minimum length of 42 bytes
    // sig type must have the correct sig length in the pub key
    if
        sig_len < 1 ||
        sig_len  > SIG_COMP_MAXSIZE as usize ||
        nonce_msg.len() == NONCE_LEN as usize
    {
        return false;
    }

    // sigLen (supplied arg) typical value is in the order of 650 to 660,
    // yielding cb_sig_proper in the order of 609 to 619
    let (decoded_sig, sz2) = comp_decode(&sig);

    if sz2 != sig_len {
        return false;
    }

    // decoded_sig now contains decoded signature

    let mut shake_ctx = [0u64; 26];

    shake_inject(&mut shake_ctx, &nonce_msg);
    shake_flip(&mut shake_ctx);

    let extracted = shake_extract(&mut shake_ctx, (M << 1) as usize);

    let mut tmp_buff = [0u16; 512];
    let mut hash_nonce_msg = [0u16; 512];

    hash_to_point_ct(&extracted, &mut hash_nonce_msg, &mut tmp_buff);

    verify_raw(
        &mut hash_nonce_msg,
        &decoded_sig,
        pk_ntt_fmt,
        &mut tmp_buff
    )
}
