use crate::constants::{M, SHAKE256_RATE, SHAKE_EXTRACT_OUT_CAPACITY_WORDS, SHAKE_ROUND_CONSTANTS};

/// Performs the Theta and Rho steps (step 1) of the Keccak permutation.
///
/// # Parameters
/// - `p`: A mutable pointer to the state array (expected to be 25 `u64` words).
///
/// # Safety
/// This function operates on a raw pointer. The caller must ensure that
/// `p` points to a valid and properly aligned state array.
#[inline(always)]
fn theta_rho_step_1(p: *mut u64) {
    unsafe {
        let xor_0_1 = *p.add(1) ^ *p.add(6) ^ *p.add(11) ^ *p.add(16) ^ *p.add(21);
        let xor_2_3 = *p.add(4) ^ *p.add(9) ^ *p.add(14) ^ *p.add(19) ^ *p.add(24);
        let xor_4_5 = *p.add(3) ^ *p.add(8) ^ *p.add(13) ^ *p.add(18) ^ *p.add(23);
        let xor_6_7 = *p.add(0) ^ *p.add(5) ^ *p.add(10) ^ *p.add(15) ^ *p.add(20);
        let xor_8_9 = *p.add(2) ^ *p.add(7) ^ *p.add(12) ^ *p.add(17) ^ *p.add(22);

        let t_0 = xor_0_1.rotate_left(1) ^ xor_2_3;
        let t_1 = xor_8_9.rotate_left(1) ^ xor_6_7;
        let t_2 = xor_4_5.rotate_left(1) ^ xor_0_1;
        let t_3 = xor_2_3.rotate_left(1) ^ xor_8_9;
        let t_4 = xor_6_7.rotate_left(1) ^ xor_4_5;

        // Apply theta and rho
        *p.add(0) ^= t_0;
        *p.add(1) = (*p.add(1) ^ t_1).rotate_left(1);
        *p.add(2) = (*p.add(2) ^ t_2).rotate_left(62);
        *p.add(3) = (*p.add(3) ^ t_3).rotate_left(28);
        *p.add(4) = (*p.add(4) ^ t_4).rotate_left(27);
        *p.add(5) = (*p.add(5) ^ t_0).rotate_left(36);
        *p.add(6) = (*p.add(6) ^ t_1).rotate_left(44);
        *p.add(7) = (*p.add(7) ^ t_2).rotate_left(6);
        *p.add(8) = (*p.add(8) ^ t_3).rotate_left(55);
        *p.add(9) = (*p.add(9) ^ t_4).rotate_left(20);
        *p.add(10) = (*p.add(10) ^ t_0).rotate_left(3);
        *p.add(11) = (*p.add(11) ^ t_1).rotate_left(10);
        *p.add(12) = (*p.add(12) ^ t_2).rotate_left(43);
        *p.add(13) = (*p.add(13) ^ t_3).rotate_left(25);
        *p.add(14) = (*p.add(14) ^ t_4).rotate_left(39);
        *p.add(15) = (*p.add(15) ^ t_0).rotate_left(41);
        *p.add(16) = (*p.add(16) ^ t_1).rotate_left(45);
        *p.add(17) = (*p.add(17) ^ t_2).rotate_left(15);
        *p.add(18) = (*p.add(18) ^ t_3).rotate_left(21);
        *p.add(19) = (*p.add(19) ^ t_4).rotate_left(8);
        *p.add(20) = (*p.add(20) ^ t_0).rotate_left(18);
        *p.add(21) = (*p.add(21) ^ t_1).rotate_left(2);
        *p.add(22) = (*p.add(22) ^ t_2).rotate_left(61);
        *p.add(23) = (*p.add(23) ^ t_3).rotate_left(56);
        *p.add(24) = (*p.add(24) ^ t_4).rotate_left(14);
    }
}

/// Performs the Chi and Iota steps (step 1) of the Keccak permutation for the given round.
///
/// # Parameters
/// - `p`: A mutable pointer to the state array (expected to be 25 `u64` words).
/// - `round_constant`: The round constant for the current permutation round.
///
/// # Safety
/// This function operates on a raw pointer. The caller must ensure that
/// `p` points to a valid and properly aligned state array.
#[inline(always)]
fn chi_iota_step_1(p: *mut u64, round_constant: u64) {
    unsafe {
        let mut c_0 = *p.add(0) ^ (*p.add(6) | *p.add(12));
        let mut c_1 = *p.add(6) ^ (!*p.add(12) | *p.add(18));
        let mut c_2 = *p.add(12) ^ (*p.add(18) & *p.add(24));
        let mut c_3 = *p.add(18) ^ (*p.add(24) | *p.add(0));
        let mut c_4 = *p.add(24) ^ (*p.add(0) & *p.add(6));

        *p.add(0) = c_0;
        *p.add(6) = c_1;
        *p.add(12) = c_2;
        *p.add(18) = c_3;
        *p.add(24) = c_4;

        c_0 = *p.add(3) ^ (*p.add(9) | *p.add(10));
        c_1 = *p.add(9) ^ (*p.add(10) & *p.add(16));
        c_2 = *p.add(10) ^ (*p.add(16) | !*p.add(22));
        c_3 = *p.add(16) ^ (*p.add(22) | *p.add(3));
        c_4 = *p.add(22) ^ (*p.add(3) & *p.add(9));
        *p.add(3) = c_0;
        *p.add(9) = c_1;
        *p.add(10) = c_2;
        *p.add(16) = c_3;
        *p.add(22) = c_4;

        let tmp = !*p.add(19);

        c_0 = *p.add(1) ^ (*p.add(7) | *p.add(13));
        c_1 = *p.add(7) ^ (*p.add(13) & *p.add(19));
        c_2 = *p.add(13) ^ (tmp & *p.add(20));
        c_3 = tmp ^ (*p.add(20) | *p.add(1));
        c_4 = *p.add(20) ^ (*p.add(1) & *p.add(7));
        *p.add(1) = c_0;
        *p.add(7) = c_1;
        *p.add(13) = c_2;
        *p.add(19) = c_3;
        *p.add(20) = c_4;

        let tmp = !*p.add(17);

        c_0 = *p.add(4) ^ (*p.add(5) & *p.add(11));
        c_1 = *p.add(5) ^ (*p.add(11) | *p.add(17));
        c_2 = *p.add(11) ^ (tmp | *p.add(23));
        c_3 = tmp ^ (*p.add(23) & *p.add(4));
        c_4 = *p.add(23) ^ (*p.add(4) | *p.add(5));
        *p.add(4) = c_0;
        *p.add(5) = c_1;
        *p.add(11) = c_2;
        *p.add(17) = c_3;
        *p.add(23) = c_4;

        let tmp = !*p.add(8);

        c_0 = *p.add(2) ^ (tmp & *p.add(14));
        c_1 = tmp ^ (*p.add(14) | *p.add(15));
        c_2 = *p.add(14) ^ (*p.add(15) & *p.add(21));
        c_3 = *p.add(15) ^ (*p.add(21) | *p.add(2));
        c_4 = *p.add(21) ^ (*p.add(2) & *p.add(8));
        *p.add(2) = c_0;
        *p.add(8) = c_1;
        *p.add(14) = c_2;
        *p.add(15) = c_3;
        *p.add(21) = c_4;

        *p.add(0) ^= round_constant;
    }
}

/// Performs the Theta and Rho steps (step 2) of the Keccak permutation.
///
/// # Parameters
/// - `p`: A mutable pointer to the state array (expected to be 25 `u64` words).
///
/// # Safety
/// This function operates on a raw pointer. The caller must ensure that
/// `p` points to a valid and properly aligned state array.
#[inline(always)]
fn theta_rho_step_2(p: *mut u64) {
    unsafe {
        let xor_0_1 = *p.add(6) ^ *p.add(9) ^ *p.add(7) ^ *p.add(5) ^ *p.add(8);
        let xor_2_3 = *p.add(24) ^ *p.add(22) ^ *p.add(20) ^ *p.add(23) ^ *p.add(21);
        let xor_4_5 = *p.add(18) ^ *p.add(16) ^ *p.add(19) ^ *p.add(17) ^ *p.add(15);
        let xor_6_7 = *p.add(0) ^ *p.add(3) ^ *p.add(1) ^ *p.add(4) ^ *p.add(2);
        let xor_8_9 = *p.add(12) ^ *p.add(10) ^ *p.add(13) ^ *p.add(11) ^ *p.add(14);

        let t_0 = xor_0_1.rotate_left(1) ^ xor_2_3;
        let t_1 = xor_8_9.rotate_left(1) ^ xor_6_7;
        let t_2 = xor_4_5.rotate_left(1) ^ xor_0_1;
        let t_3 = xor_2_3.rotate_left(1) ^ xor_8_9;
        let t_4 = xor_6_7.rotate_left(1) ^ xor_4_5;

        *p.add(0) ^= t_0;

        *p.add(3) = (*p.add(3) ^ t_0).rotate_left(36);
        *p.add(1) = (*p.add(1) ^ t_0).rotate_left(3);
        *p.add(4) = (*p.add(4) ^ t_0).rotate_left(41);
        *p.add(2) = (*p.add(2) ^ t_0).rotate_left(18);
        *p.add(6) = (*p.add(6) ^ t_1).rotate_left(1);
        *p.add(9) = (*p.add(9) ^ t_1).rotate_left(44);
        *p.add(7) = (*p.add(7) ^ t_1).rotate_left(10);
        *p.add(5) = (*p.add(5) ^ t_1).rotate_left(45);
        *p.add(8) = (*p.add(8) ^ t_1).rotate_left(2);
        *p.add(12) = (*p.add(12) ^ t_2).rotate_left(62);
        *p.add(10) = (*p.add(10) ^ t_2).rotate_left(6);
        *p.add(13) = (*p.add(13) ^ t_2).rotate_left(43);
        *p.add(11) = (*p.add(11) ^ t_2).rotate_left(15);
        *p.add(14) = (*p.add(14) ^ t_2).rotate_left(61);
        *p.add(18) = (*p.add(18) ^ t_3).rotate_left(28);
        *p.add(16) = (*p.add(16) ^ t_3).rotate_left(55);
        *p.add(19) = (*p.add(19) ^ t_3).rotate_left(25);
        *p.add(17) = (*p.add(17) ^ t_3).rotate_left(21);
        *p.add(15) = (*p.add(15) ^ t_3).rotate_left(56);
        *p.add(24) = (*p.add(24) ^ t_4).rotate_left(27);
        *p.add(22) = (*p.add(22) ^ t_4).rotate_left(20);
        *p.add(20) = (*p.add(20) ^ t_4).rotate_left(39);
        *p.add(23) = (*p.add(23) ^ t_4).rotate_left(8);
        *p.add(21) = (*p.add(21) ^ t_4).rotate_left(14);
    }
}

/// Performs the Chi, Iota, and Pi steps (step 2) of the Keccak permutation for the given round.
///
/// # Parameters
/// - `p`: A mutable pointer to the state array (expected to be 25 `u64` words).
/// - `round_constant`: The round constant for the current permutation round.
///
/// # Safety
/// This function operates on a raw pointer. The caller must ensure that
/// `p` points to a valid and properly aligned state array.
#[inline(always)]
fn chi_iota_pi_step_2(p: *mut u64, round_constant: u64) {
    unsafe {
        let mut c_0 = *p.add(0) ^ (*p.add(9) | *p.add(13));
        let mut c_1 = *p.add(9) ^ (!*p.add(13) | *p.add(17));
        let mut c_2 = *p.add(13) ^ (*p.add(17) & *p.add(21));
        let mut c_3 = *p.add(17) ^ (*p.add(21) | *p.add(0));
        let mut c_4 = *p.add(21) ^ (*p.add(0) & *p.add(9));

        *p.add(0) = c_0;
        *p.add(9) = c_1;
        *p.add(13) = c_2;
        *p.add(17) = c_3;
        *p.add(21) = c_4;

        c_0 = *p.add(18) ^ (*p.add(22) | *p.add(1));
        c_1 = *p.add(22) ^ (*p.add(1) & *p.add(5));
        c_2 = *p.add(1) ^ (*p.add(5) | !*p.add(14));
        c_3 = *p.add(5) ^ (*p.add(14) | *p.add(18));
        c_4 = *p.add(14) ^ (*p.add(18) & *p.add(22));
        *p.add(18) = c_0;
        *p.add(22) = c_1;
        *p.add(1) = c_2;
        *p.add(5) = c_3;
        *p.add(14) = c_4;

        let tmp = !*p.add(23);

        c_0 = *p.add(6) ^ (*p.add(10) | *p.add(19));
        c_1 = *p.add(10) ^ (*p.add(19) & *p.add(23));
        c_2 = *p.add(19) ^ (tmp & *p.add(2));
        c_3 = tmp ^ (*p.add(2) | *p.add(6));
        c_4 = *p.add(2) ^ (*p.add(6) & *p.add(10));
        *p.add(6) = c_0;
        *p.add(10) = c_1;
        *p.add(19) = c_2;
        *p.add(23) = c_3;
        *p.add(2) = c_4;

        let tmp = !*p.add(11);

        c_0 = *p.add(24) ^ (*p.add(3) & *p.add(7));
        c_1 = *p.add(3) ^ (*p.add(7) | *p.add(11));
        c_2 = *p.add(7) ^ (tmp | *p.add(15));
        c_3 = tmp ^ (*p.add(15) & *p.add(24));
        c_4 = *p.add(15) ^ (*p.add(24) | *p.add(3));
        *p.add(24) = c_0;
        *p.add(3) = c_1;
        *p.add(7) = c_2;
        *p.add(11) = c_3;
        *p.add(15) = c_4;

        let tmp = !*p.add(16);

        c_0 = *p.add(12) ^ (tmp & *p.add(20));
        c_1 = tmp ^ (*p.add(20) | *p.add(4));
        c_2 = *p.add(20) ^ (*p.add(4) & *p.add(8));
        c_3 = *p.add(4) ^ (*p.add(8) | *p.add(12));
        c_4 = *p.add(8) ^ (*p.add(12) & *p.add(16));
        *p.add(12) = c_0;
        *p.add(16) = c_1;
        *p.add(20) = c_2;
        *p.add(4) = c_3;
        *p.add(8) = c_4;

        *p.add(0) ^= round_constant;

        let tmp = *p.add(5);

        *p.add(5) = *p.add(18);
        *p.add(18) = *p.add(11);
        *p.add(11) = *p.add(10);
        *p.add(10) = *p.add(6);
        *p.add(6) = *p.add(22);
        *p.add(22) = *p.add(20);
        *p.add(20) = *p.add(12);
        *p.add(12) = *p.add(19);
        *p.add(19) = *p.add(15);
        *p.add(15) = *p.add(24);
        *p.add(24) = *p.add(8);
        *p.add(8) = tmp;

        let tmp = *p.add(1);

        *p.add(1) = *p.add(9);
        *p.add(9) = *p.add(14);
        *p.add(14) = *p.add(2);
        *p.add(2) = *p.add(13);
        *p.add(13) = *p.add(23);
        *p.add(23) = *p.add(4);
        *p.add(4) = *p.add(21);
        *p.add(21) = *p.add(16);
        *p.add(16) = *p.add(3);
        *p.add(3) = *p.add(17);
        *p.add(17) = *p.add(7);
        *p.add(7) = tmp;
    }
}

/// Processes the provided SHAKE256 state in-place.
///
/// This function performs the Keccak permutation over the provided `shake_ctx` state.
/// The result is written back into the same context.
///
/// # Parameters
/// - `shake_ctx`: The mutable SHAKE256 state array (26 `u64` words) to be permuted.
#[inline(always)]
pub fn process_block(shake_ctx: &mut [u64; 26]) {
    let shake_ptr = shake_ctx.as_mut_ptr();
    let shake_constants_ptr = SHAKE_ROUND_CONSTANTS.as_ptr();

    unsafe {
        *shake_ptr.add(1) = !*shake_ptr.add(1);
        *shake_ptr.add(2) = !*shake_ptr.add(2);
        *shake_ptr.add(8) = !*shake_ptr.add(8);
        *shake_ptr.add(12) = !*shake_ptr.add(12);
        *shake_ptr.add(17) = !*shake_ptr.add(17);
        *shake_ptr.add(20) = !*shake_ptr.add(20);

        // unrolling rounds
        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x0));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x1));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x2));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x3));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x4));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x5));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x6));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x7));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x8));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x9));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0xa));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0xb));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0xc));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0xd));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0xe));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0xf));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x10));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x11));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x12));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x13));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x14));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x15));

        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr.add(0x16));
        theta_rho_step_2(shake_ptr);
        chi_iota_pi_step_2(shake_ptr, *shake_constants_ptr.add(0x17));

        *shake_ptr.add(1) = !*shake_ptr.add(1);
        *shake_ptr.add(2) = !*shake_ptr.add(2);
        *shake_ptr.add(8) = !*shake_ptr.add(8);
        *shake_ptr.add(12) = !*shake_ptr.add(12);
        *shake_ptr.add(17) = !*shake_ptr.add(17);
        *shake_ptr.add(20) = !*shake_ptr.add(20);
    }
}

/// Absorbs one full 136-byte block into the Keccak state using direct field access.
///
/// # Parameters
/// - `shake_ctx`: The mutable SHAKE256 state array (26 `u64` words).
/// - `input_block`: The input data block to absorb (must be exactly 136 bytes).
///
/// # Panics
/// Panics if `input_block.len()` is not equal to 136.
#[inline(always)]
fn absorb_full_block(shake_ctx: &mut [u64; 26], input_ptr: *const u8) {
    // fn absorb_full_block(shake_ctx: &mut [u64; 26], input_block: &[u8]) {
    unsafe {
        let shake_ptr = shake_ctx.as_mut_ptr();

        *shake_ptr.add(0) ^=
            u64::from_le_bytes(input_ptr.add(0x00).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(1) ^=
            u64::from_le_bytes(input_ptr.add(0x08).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(2) ^=
            u64::from_le_bytes(input_ptr.add(0x10).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(3) ^=
            u64::from_le_bytes(input_ptr.add(0x18).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(4) ^=
            u64::from_le_bytes(input_ptr.add(0x20).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(5) ^=
            u64::from_le_bytes(input_ptr.add(0x28).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(6) ^=
            u64::from_le_bytes(input_ptr.add(0x30).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(7) ^=
            u64::from_le_bytes(input_ptr.add(0x38).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(8) ^=
            u64::from_le_bytes(input_ptr.add(0x40).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(9) ^=
            u64::from_le_bytes(input_ptr.add(0x48).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(10) ^=
            u64::from_le_bytes(input_ptr.add(0x50).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(11) ^=
            u64::from_le_bytes(input_ptr.add(0x58).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(12) ^=
            u64::from_le_bytes(input_ptr.add(0x60).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(13) ^=
            u64::from_le_bytes(input_ptr.add(0x68).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(14) ^=
            u64::from_le_bytes(input_ptr.add(0x70).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(15) ^=
            u64::from_le_bytes(input_ptr.add(0x78).cast::<[u8; 8]>().read_unaligned());
        *shake_ptr.add(16) ^=
            u64::from_le_bytes(input_ptr.add(0x80).cast::<[u8; 8]>().read_unaligned());
    }
}

/// Injects byte data into the SHAKE256 context.
///
/// After this call, consecutive calls are not supported.
///
/// # Parameters
/// - `shake_ctx`: The mutable SHAKE256 state array (26 `u64` words).
/// - `input`: The input bytes to inject into the state.
///
/// # Note
/// This function does not support consecutive calls; call `shake_flip()` before further extraction or other injection.
pub fn shake_inject(shake_ctx: &mut [u64; 26], input: &[u8]) {
    let mut in_len = input.len();
    let mut offset: usize = 0;
    let rate_usize = SHAKE256_RATE as usize;
    let full_runs = in_len / rate_usize;
    let loop_end = full_runs * rate_usize;
    let mut input_ptr = input.as_ptr();

    // processes full blocks using the fast, unrolled path
    while offset != loop_end {
        absorb_full_block(shake_ctx, input_ptr);
        process_block(shake_ctx);

        offset += rate_usize;

        unsafe {
            input_ptr = input_ptr.add(rate_usize);
        }
    }

    in_len -= loop_end;

    if in_len != 0 {
        let full_words_in_remainder = in_len >> 0x3;
        let final_bytes = in_len & 0x7;

        let mut i = 0;

        while i != full_words_in_remainder {
            unsafe {
                let data_chunk = u64::from_le_bytes(input_ptr.cast::<[u8; 8]>().read_unaligned());
                let shake_ptr = shake_ctx.as_mut_ptr();

                *shake_ptr.add(i) ^= data_chunk;

                i += 1;

                input_ptr = input_ptr.add(0x8);
            }
        }

        let remainder_offset = offset + (full_words_in_remainder << 0x3);
        let mut acc: u64 = 0;

        for i in 0..final_bytes {
            acc |= (input[remainder_offset + i] as u64) << (i << 0x3);
        }

        shake_ctx[full_words_in_remainder] ^= acc;
    }

    shake_ctx[25] = in_len as u64;
}

/// Flips the SHAKE256 state to output (squeeze) mode.
///
/// After this call:
/// - `shake256_inject()` must not be called on the context.
/// - `shake256_extract()` can be called to extract output.
///
/// # Parameters
/// - `shake_ctx`: The mutable SHAKE256 state array (26 `u64` words) to be flipped.
pub fn shake_flip(shake_ctx: &mut [u64; 26]) {
    let last: u16 = shake_ctx[25] as u16;
    let o1: usize = (last >> 0x3) as usize;

    shake_ctx[o1] ^= 0x1f << ((last & 0x7) << 0x3);

    let rate_sub_1 = SHAKE256_RATE - 1;
    let o2: usize = (rate_sub_1 >> 0x3) as usize;

    shake_ctx[o2] ^= 0x80 << ((rate_sub_1 & 0x7) << 0x3);
    shake_ctx[25] = SHAKE256_RATE as u64;
}

/// Extracts bytes from the SHAKE256 context ("squeeze" operation, 8-byte chunks).
///
/// The context must have been flipped to output mode using [`shake_flip()`].
/// Usecase is tied to Falcon512 as output will be enforced to 1434 bytes.
///
/// # Parameters
/// - `shake_ctx`: The SHAKE256 state array (26 `u64` words) to extract from.
///
/// # Returns
/// An array of `u64` words, with a length of `SHAKE_EXTRACT_OUT_CAPACITY_WORDS`, containing the extracted output.
/// Extracts bytes from the SHAKE256 context ("squeeze" operation).
///
/// The context must have been flipped to output mode using [`shake_flip()`].
/// Usecase is tied to Falcon512 as output will be enforced to 1434 bytes.
///
/// # Parameters
/// - `shake_ctx`: The SHAKE256 state array (26 `u64` words) to extract from.
///
/// # Returns
/// An array of `u64` words, with a length of `SHAKE_EXTRACT_OUT_CAPACITY_WORDS`, containing the extracted output.
pub fn shake_extract(shake_ctx: &mut [u64; 26]) -> [u64; SHAKE_EXTRACT_OUT_CAPACITY_WORDS] {
    const SHAKE256_RATE_WORDS: usize = 17;

    let mut out = [0u64; SHAKE_EXTRACT_OUT_CAPACITY_WORDS];
    let mut out_ptr = out.as_mut_ptr();
    let mut bytes_to_extract = (M << 1) as usize;

    while bytes_to_extract != 0 {
        process_block(shake_ctx);

        let rate_part = &shake_ctx[..SHAKE256_RATE_WORDS];
        let bytes_this_run = bytes_to_extract.min(SHAKE256_RATE.into());

        unsafe {
            core::ptr::copy_nonoverlapping(
                rate_part.as_ptr() as *const u8,
                out_ptr as *mut u8,
                bytes_this_run,
            );

            out_ptr = (out_ptr as *mut u8).add(bytes_this_run) as *mut u64;
        }

        bytes_to_extract -= bytes_this_run;
    }

    shake_ctx[25] = 0x0;

    out
}
