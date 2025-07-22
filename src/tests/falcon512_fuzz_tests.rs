#[cfg(test)]
pub mod tests {
    use crate::{
        falcon512::{pk_to_ntt_fmt, verify},
        tests::test_utils::{mutation_utils::*, get_valid_test_vector},
    };

    // Helper to ensure mutation really changed the data
    fn assert_mutated<T: PartialEq + std::fmt::Debug>(orig: &[T], mutated: &[T]) {
        assert_ne!(orig, mutated, "Mutation did not change the data!");
    }

    #[test]
    fn fuzz_randomize_sig() {
        let (msg, pk, sig) = get_valid_test_vector();

        for _ in 0..32 {
            let mut mutated = sig.clone();

            randomize_sig(&mut mutated);
            assert_mutated(&sig, &mutated);
            assert!(
                !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                "Randomized sig should not verify"
            );
        }
    }

    #[test]
    fn fuzz_flip_sig_bits() {
        let (msg, pk, sig) = get_valid_test_vector();

        for n in [1, 3, 8, 16, 32, 64, 128, 256, 512] {
            let mut mutated = sig.clone();

            flip_sig_bit(&mut mutated, n);

            assert_mutated(&sig, &mutated);
            assert!(
                !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                "Bit-flipped sig ({}x) should not verify",
                n
            );
        }
    }

    #[test]
    fn fuzz_swap_sig_bytes() {
        let (msg, pk, sig) = get_valid_test_vector();

        for n in [1, 4, 10, 16, 32, 64, 128, 256, 512] {
            let mut mutated = sig.clone();

            swap_sig_bytes(&mut mutated, n);
            assert_mutated(&sig, &mutated);

            assert!(
                !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                "Swapped sig bytes ({}x) should not verify",
                n
            );
        }
    }

    #[test]
    fn fuzz_zero_sig() {
        let (msg, pk, sig) = get_valid_test_vector();
        let mut mutated = sig.clone();

        zero_sig(&mut mutated);
        assert!(mutated.iter().all(|&b| b == 0));

        assert!(
            !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
            "Zero sig should not verify"
        );
    }

    #[test]
    fn fuzz_ff_sig() {
        let (msg, pk, sig) = get_valid_test_vector();
        let mut mutated = sig.clone();

        ff_sig(&mut mutated);
        assert!(mutated.iter().all(|&b| b == 0xFF));
        assert!(
            !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
            "All-0xFF sig should not verify"
        );
    }

    #[test]
    fn fuzz_truncate_sig() {
        let (msg, pk, sig) = get_valid_test_vector();

        for n in [1, 3, 10, 16, 32, 64, 128, 256, 512] {
            if sig.len() > n {
                let mutated = truncate_sig(&sig, n);

                assert_eq!(mutated.len(), sig.len() - n);
                assert!(
                    !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                    "Truncated sig ({} bytes) should not verify",
                    n
                );
            }
        }
    }

    #[test]
    fn fuzz_extend_sig_random() {
        let (msg, pk, sig) = get_valid_test_vector();

        for n in [1, 2, 8, 16, 32, 64] {
            let mutated = extend_sig_random(&sig, n);

            assert_eq!(mutated.len(), sig.len() + n);
            assert!(
                !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                "Randomly extended sig ({} bytes) should not verify",
                n
            );
        }
    }

    #[test]
    fn fuzz_extend_sig_zero() {
        let (msg, pk, sig) = get_valid_test_vector();

        for n in [1, 2, 8, 16, 32, 64] {
            let mutated = extend_sig_zero(&sig, n);

            assert_eq!(mutated.len(), sig.len() + n);
            assert!(
                !verify(&msg, &mutated, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                "Zero extended sig ({} bytes) should not verify",
                n
            );
        }
    }

    #[test]
    fn fuzz_randomize_nonce() {
        let (msg, pk, sig) = get_valid_test_vector();

        for _ in 0..32 {
            let mut mutated = msg.clone();

            randomize_nonce(&mut mutated);
            assert_mutated(&msg[..40], &mutated[..40]);
            assert!(
                !verify(&mutated, &sig, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                "Randomized nonce should not verify"
            );
        }
    }

    #[test]
    fn fuzz_zero_nonce() {
        let (msg, pk, sig) = get_valid_test_vector();
        let mut mutated = msg.clone();

        zero_nonce(&mut mutated);
        assert!(mutated[..40].iter().all(|&b| b == 0));
        assert!(
            !verify(&mutated, &sig, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
            "Zero nonce should not verify"
        );
    }

    #[test]
    fn fuzz_ff_nonce() {
        let (msg, pk, sig) = get_valid_test_vector();
        let mut mutated = msg.clone();

        ff_nonce(&mut mutated);
        assert!(mutated[..40].iter().all(|&b| b == 0xFF));
        assert!(
            !verify(&mutated, &sig, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
            "0xFF nonce should not verify"
        );
    }

    #[test]
    fn fuzz_swap_nonce_bytes() {
        let (msg, pk, sig) = get_valid_test_vector();

        for n in [1, 3, 10, 20, 30, 40] {
            let mut mutated = msg.clone();

            swap_nonce_bytes(&mut mutated, n);
            assert_mutated(&msg[..40], &mutated[..40]);
            assert!(
                !verify(&mutated, &sig, &pk_to_ntt_fmt(pk.as_slice().try_into().unwrap())),
                "Swapped nonce bytes ({}x) should not verify",
                n
            );
        }
    }
}
