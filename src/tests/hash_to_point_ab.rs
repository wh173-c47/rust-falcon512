#[cfg(test)]
mod tests {
    use crate::{
        constants::N,
        falcon512::{hash_to_point_ct, hash_to_point_vartime, verify},
        shake256::{shake_extract, shake_flip, shake_inject},
        tests::test_utils::get_valid_test_vector,
    };

    /// Squeeze the SHAKE stream for `nonce_msg` exactly as `verify` does.
    fn extract_for(nonce_msg: &[u8]) -> Vec<u64> {
        let mut shake_ctx = [0u64; 26];
        shake_inject(&mut shake_ctx, nonce_msg);
        shake_flip(&mut shake_ctx);
        shake_extract(&mut shake_ctx).to_vec()
    }

    #[test]
    fn ct_and_vartime_produce_identical_challenge() {
        let (msg, _pk, _sig) = get_valid_test_vector();
        let extracted = extract_for(&msg);

        let mut x_ct = [0u16; N];
        let mut tt1 = [0u16; N];
        hash_to_point_ct(&extracted, &mut x_ct, &mut tt1);

        let mut x_vt = [0u16; N];
        hash_to_point_vartime(&extracted, &mut x_vt);

        assert_eq!(
            x_ct.as_slice(),
            x_vt.as_slice(),
            "vartime hash-to-point must equal the constant-time challenge coefficient-for-coefficient"
        );
    }

    #[test]
    fn vartime_challenge_is_well_formed() {
        // Every accepted coefficient must be a valid field element in [0, q); none may be the
        // 0xffff rejection sentinel.
        let (msg, _pk, _sig) = get_valid_test_vector();
        let extracted = extract_for(&msg);

        let mut x_vt = [0u16; N];
        hash_to_point_vartime(&extracted, &mut x_vt);

        assert!(
            x_vt.iter().all(|&c| c < crate::constants::Q),
            "all challenge coefficients must be reduced into [0, q)"
        );
    }

    #[test]
    fn production_verify_accepts_valid_vector() {
        let (msg, pk, sig) = get_valid_test_vector();
        let pk_ntt = crate::falcon512::pk_to_ntt_fmt(pk.as_slice().try_into().unwrap());
        assert!(
            verify(&msg, &sig, &pk_ntt),
            "valid NIST vector must verify through the vartime production path"
        );
    }
}
