//! Heavy on-demand forgery-resistance check (millions of single-bit-flip / byte-swap mutations of a
//! valid signature). It asserts the security property the fast fuzz tests assert in miniature: a
//! mutation may verify only if it decodes to the **same** coefficient vector (a benign re-encoding of
//! unused bits); a verifying **distinct** vector would be a forgery. Run with:
//!   cargo test --release capture_accepts -- --ignored --nocapture
#[cfg(test)]
mod tests {
    use crate::{
        falcon512::{comp_decode, pk_to_ntt_fmt, verify},
        tests::test_utils::get_valid_test_vector,
    };
    use rand::prelude::*;

    #[test]
    #[ignore = "heavy (~minutes); run on demand"]
    fn capture_accepts() {
        let (msg, pk, sig) = get_valid_test_vector();
        let pk_ntt = pk_to_ntt_fmt(pk.as_slice().try_into().unwrap());
        let (orig_dec, _) = comp_decode(&sig);
        let mut rng = rand::rng();

        let mut flip_same = 0u64;
        let mut flip_diff = 0u64;
        let mut swap_same = 0u64;
        let mut swap_diff = 0u64;
        let trials = 5_000_000u64;

        for _ in 0..trials {
            // single bit flip
            let mut m = sig.clone();
            let idx = rng.random_range(0..m.len());
            m[idx] ^= 1 << rng.random_range(0..8u8);
            if m != sig && verify(&msg, &m, &pk_ntt) {
                let (d, _) = comp_decode(&m);
                if d == orig_dec {
                    flip_same += 1;
                } else {
                    flip_diff += 1;
                    if flip_diff <= 3 {
                        println!("FLIP -> DISTINCT vector accepted (byte {idx})");
                    }
                }
            }

            // single byte swap
            let mut m = sig.clone();
            let i = rng.random_range(0..m.len());
            let mut j = rng.random_range(0..m.len());
            while i == j {
                j = rng.random_range(0..m.len());
            }
            m.swap(i, j);
            if m != sig && verify(&msg, &m, &pk_ntt) {
                let (d, _) = comp_decode(&m);
                if d == orig_dec {
                    swap_same += 1;
                } else {
                    swap_diff += 1;
                    if swap_diff <= 3 {
                        println!("SWAP -> DISTINCT vector accepted (bytes {i},{j})");
                    }
                }
            }
        }

        println!("== {trials} trials each ==");
        println!("bit-flip  accepted: same-vector(re-encoding)={flip_same}  distinct-vector={flip_diff}");
        println!("byte-swap accepted: same-vector(re-encoding)={swap_same}  distinct-vector={swap_diff}");
        // A benign re-encoding is fine; a DISTINCT vector that verifies would be the thing to scrutinize.
        assert_eq!(flip_diff, 0, "a bit-flip produced a DISTINCT verifying vector");
        assert_eq!(swap_diff, 0, "a byte-swap produced a DISTINCT verifying vector");
    }
}
