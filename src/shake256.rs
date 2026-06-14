use crate::constants::{
    M, SHAKE256_RATE, SHAKE256_RATE_WORDS, SHAKE_EXTRACT_OUT_CAPACITY_WORDS, SHAKE_ROUND_CONSTANTS,
    SHAKE_VARTIME_BLOCKS, SHAKE_VARTIME_WORDS,
};

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
        let p1 = p.add(1);
        let p2 = p.add(2);
        let p3 = p.add(3);
        let p4 = p.add(4);
        let p5 = p.add(5);
        let p6 = p.add(6);
        let p7 = p.add(7);
        let p8 = p.add(8);
        let p9 = p.add(9);
        let p10 = p.add(10);
        let p11 = p.add(11);
        let p12 = p.add(12);
        let p13 = p.add(13);
        let p14 = p.add(14);
        let p15 = p.add(15);
        let p16 = p.add(16);
        let p17 = p.add(17);
        let p18 = p.add(18);
        let p19 = p.add(19);
        let p20 = p.add(20);
        let p21 = p.add(21);
        let p22 = p.add(22);
        let p23 = p.add(23);
        let p24 = p.add(24);

        let xor_0_1 = *p1 ^ *p6 ^ *p11 ^ *p16 ^ *p21;
        let xor_2_3 = *p4 ^ *p9 ^ *p14 ^ *p19 ^ *p24;
        let xor_4_5 = *p3 ^ *p8 ^ *p13 ^ *p18 ^ *p23;
        let xor_6_7 = *p ^ *p5 ^ *p10 ^ *p15 ^ *p20;
        let xor_8_9 = *p2 ^ *p7 ^ *p12 ^ *p17 ^ *p22;

        let t_0 = xor_0_1.rotate_left(1) ^ xor_2_3;
        let t_1 = xor_8_9.rotate_left(1) ^ xor_6_7;
        let t_2 = xor_4_5.rotate_left(1) ^ xor_0_1;
        let t_3 = xor_2_3.rotate_left(1) ^ xor_8_9;
        let t_4 = xor_6_7.rotate_left(1) ^ xor_4_5;

        // Apply theta and rho
        *p ^= t_0;
        *p1 = (*p1 ^ t_1).rotate_left(1);
        *p2 = (*p2 ^ t_2).rotate_left(62);
        *p3 = (*p3 ^ t_3).rotate_left(28);
        *p4 = (*p4 ^ t_4).rotate_left(27);
        *p5 = (*p5 ^ t_0).rotate_left(36);
        *p6 = (*p6 ^ t_1).rotate_left(44);
        *p7 = (*p7 ^ t_2).rotate_left(6);
        *p8 = (*p8 ^ t_3).rotate_left(55);
        *p9 = (*p9 ^ t_4).rotate_left(20);
        *p10 = (*p10 ^ t_0).rotate_left(3);
        *p11 = (*p11 ^ t_1).rotate_left(10);
        *p12 = (*p12 ^ t_2).rotate_left(43);
        *p13 = (*p13 ^ t_3).rotate_left(25);
        *p14 = (*p14 ^ t_4).rotate_left(39);
        *p15 = (*p15 ^ t_0).rotate_left(41);
        *p16 = (*p16 ^ t_1).rotate_left(45);
        *p17 = (*p17 ^ t_2).rotate_left(15);
        *p18 = (*p18 ^ t_3).rotate_left(21);
        *p19 = (*p19 ^ t_4).rotate_left(8);
        *p20 = (*p20 ^ t_0).rotate_left(18);
        *p21 = (*p21 ^ t_1).rotate_left(2);
        *p22 = (*p22 ^ t_2).rotate_left(61);
        *p23 = (*p23 ^ t_3).rotate_left(56);
        *p24 = (*p24 ^ t_4).rotate_left(14);
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
        let p6 = p.add(6);
        let p12 = p.add(12);
        let p18 = p.add(18);
        let p24 = p.add(24);

        let mut c_0 = *p ^ (*p6 | *p12);
        let mut c_1 = *p6 ^ (!*p12 | *p18);
        let mut c_2 = *p12 ^ (*p18 & *p24);
        let mut c_3 = *p18 ^ (*p24 | *p);
        let mut c_4 = *p24 ^ (*p & *p6);

        *p = c_0;
        *p6 = c_1;
        *p12 = c_2;
        *p18 = c_3;
        *p24 = c_4;

        let p3 = p.add(3);
        let p9 = p.add(9);
        let p10 = p.add(10);
        let p16 = p.add(16);
        let p22 = p.add(22);

        c_0 = *p3 ^ (*p9 | *p10);
        c_1 = *p9 ^ (*p10 & *p16);
        c_2 = *p10 ^ (*p16 | !*p22);
        c_3 = *p16 ^ (*p22 | *p3);
        c_4 = *p22 ^ (*p3 & *p9);

        *p3 = c_0;
        *p9 = c_1;
        *p10 = c_2;
        *p16 = c_3;
        *p22 = c_4;

        let p1 = p.add(1);
        let p7 = p.add(7);
        let p13 = p.add(13);
        let p19 = p.add(19);
        let p20 = p.add(20);

        let tmp = !*p19;

        c_0 = *p1 ^ (*p7 | *p13);
        c_1 = *p7 ^ (*p13 & *p19);
        c_2 = *p13 ^ (tmp & *p20);
        c_3 = tmp ^ (*p20 | *p1);
        c_4 = *p20 ^ (*p1 & *p7);

        *p1 = c_0;
        *p7 = c_1;
        *p13 = c_2;
        *p19 = c_3;
        *p20 = c_4;

        let p4 = p.add(4);
        let p5 = p.add(5);
        let p11 = p.add(11);
        let p17 = p.add(17);
        let p23 = p.add(23);

        let tmp = !*p17;

        c_0 = *p4 ^ (*p5 & *p11);
        c_1 = *p5 ^ (*p11 | *p17);
        c_2 = *p11 ^ (tmp | *p23);
        c_3 = tmp ^ (*p23 & *p4);
        c_4 = *p23 ^ (*p4 | *p5);

        *p4 = c_0;
        *p5 = c_1;
        *p11 = c_2;
        *p17 = c_3;
        *p23 = c_4;

        let p2 = p.add(2);
        let p8 = p.add(8);
        let p14 = p.add(14);
        let p15 = p.add(15);
        let p21 = p.add(21);

        let tmp = !*p8;

        c_0 = *p2 ^ (tmp & *p14);
        c_1 = tmp ^ (*p14 | *p15);
        c_2 = *p14 ^ (*p15 & *p21);
        c_3 = *p15 ^ (*p21 | *p2);
        c_4 = *p21 ^ (*p2 & *p8);

        *p2 = c_0;
        *p8 = c_1;
        *p14 = c_2;
        *p15 = c_3;
        *p21 = c_4;

        *p ^= round_constant;
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
        let p1 = p.add(1);
        let p2 = p.add(2);
        let p3 = p.add(3);
        let p4 = p.add(4);
        let p5 = p.add(5);
        let p6 = p.add(6);
        let p7 = p.add(7);
        let p8 = p.add(8);
        let p9 = p.add(9);
        let p10 = p.add(10);
        let p11 = p.add(11);
        let p12 = p.add(12);
        let p13 = p.add(13);
        let p14 = p.add(14);
        let p15 = p.add(15);
        let p16 = p.add(16);
        let p17 = p.add(17);
        let p18 = p.add(18);
        let p19 = p.add(19);
        let p20 = p.add(20);
        let p21 = p.add(21);
        let p22 = p.add(22);
        let p23 = p.add(23);
        let p24 = p.add(24);

        let xor_0_1 = *p6 ^ *p9 ^ *p7 ^ *p5 ^ *p8;
        let xor_2_3 = *p24 ^ *p22 ^ *p20 ^ *p23 ^ *p21;
        let xor_4_5 = *p18 ^ *p16 ^ *p19 ^ *p17 ^ *p15;
        let xor_6_7 = *p ^ *p3 ^ *p1 ^ *p4 ^ *p2;
        let xor_8_9 = *p12 ^ *p10 ^ *p13 ^ *p11 ^ *p14;

        let t_0 = xor_0_1.rotate_left(1) ^ xor_2_3;
        let t_1 = xor_8_9.rotate_left(1) ^ xor_6_7;
        let t_2 = xor_4_5.rotate_left(1) ^ xor_0_1;
        let t_3 = xor_2_3.rotate_left(1) ^ xor_8_9;
        let t_4 = xor_6_7.rotate_left(1) ^ xor_4_5;

        *p ^= t_0;

        *p3 = (*p3 ^ t_0).rotate_left(36);
        *p1 = (*p1 ^ t_0).rotate_left(3);
        *p4 = (*p4 ^ t_0).rotate_left(41);
        *p2 = (*p2 ^ t_0).rotate_left(18);
        *p6 = (*p6 ^ t_1).rotate_left(1);
        *p9 = (*p9 ^ t_1).rotate_left(44);
        *p7 = (*p7 ^ t_1).rotate_left(10);
        *p5 = (*p5 ^ t_1).rotate_left(45);
        *p8 = (*p8 ^ t_1).rotate_left(2);
        *p12 = (*p12 ^ t_2).rotate_left(62);
        *p10 = (*p10 ^ t_2).rotate_left(6);
        *p13 = (*p13 ^ t_2).rotate_left(43);
        *p11 = (*p11 ^ t_2).rotate_left(15);
        *p14 = (*p14 ^ t_2).rotate_left(61);
        *p18 = (*p18 ^ t_3).rotate_left(28);
        *p16 = (*p16 ^ t_3).rotate_left(55);
        *p19 = (*p19 ^ t_3).rotate_left(25);
        *p17 = (*p17 ^ t_3).rotate_left(21);
        *p15 = (*p15 ^ t_3).rotate_left(56);
        *p24 = (*p24 ^ t_4).rotate_left(27);
        *p22 = (*p22 ^ t_4).rotate_left(20);
        *p20 = (*p20 ^ t_4).rotate_left(39);
        *p23 = (*p23 ^ t_4).rotate_left(8);
        *p21 = (*p21 ^ t_4).rotate_left(14);
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
        let p9 = p.add(9);
        let p13 = p.add(13);
        let p17 = p.add(17);
        let p21 = p.add(21);

        let mut c_0 = *p ^ (*p9 | *p13);
        let mut c_1 = *p9 ^ (!*p13 | *p17);
        let mut c_2 = *p13 ^ (*p17 & *p21);
        let mut c_3 = *p17 ^ (*p21 | *p);
        let mut c_4 = *p21 ^ (*p & *p9);

        *p = c_0;
        *p9 = c_1;
        *p13 = c_2;
        *p17 = c_3;
        *p21 = c_4;

        let p1 = p.add(1);
        let p5 = p.add(5);
        let p14 = p.add(14);
        let p18 = p.add(18);
        let p22 = p.add(22);

        c_0 = *p18 ^ (*p22 | *p1);
        c_1 = *p22 ^ (*p1 & *p5);
        c_2 = *p1 ^ (*p5 | !*p14);
        c_3 = *p5 ^ (*p14 | *p18);
        c_4 = *p14 ^ (*p18 & *p22);

        *p18 = c_0;
        *p22 = c_1;
        *p1 = c_2;
        *p5 = c_3;
        *p14 = c_4;

        let p2 = p.add(2);
        let p6 = p.add(6);
        let p10 = p.add(10);
        let p19 = p.add(19);
        let p23 = p.add(23);

        let tmp = !*p23;

        c_0 = *p6 ^ (*p10 | *p19);
        c_1 = *p10 ^ (*p19 & *p23);
        c_2 = *p19 ^ (tmp & *p2);
        c_3 = tmp ^ (*p2 | *p6);
        c_4 = *p2 ^ (*p6 & *p10);

        *p6 = c_0;
        *p10 = c_1;
        *p19 = c_2;
        *p23 = c_3;
        *p2 = c_4;

        let p3 = p.add(3);
        let p7 = p.add(7);
        let p11 = p.add(11);
        let p15 = p.add(15);
        let p24 = p.add(24);

        let tmp = !*p11;

        c_0 = *p24 ^ (*p3 & *p7);
        c_1 = *p3 ^ (*p7 | *p11);
        c_2 = *p7 ^ (tmp | *p15);
        c_3 = tmp ^ (*p15 & *p24);
        c_4 = *p15 ^ (*p24 | *p3);

        *p24 = c_0;
        *p3 = c_1;
        *p7 = c_2;
        *p11 = c_3;
        *p15 = c_4;

        let p4 = p.add(4);
        let p8 = p.add(8);
        let p12 = p.add(12);
        let p16 = p.add(16);
        let p20 = p.add(20);

        let tmp = !*p16;

        c_0 = *p12 ^ (tmp & *p20);
        c_1 = tmp ^ (*p20 | *p4);
        c_2 = *p20 ^ (*p4 & *p8);
        c_3 = *p4 ^ (*p8 | *p12);
        c_4 = *p8 ^ (*p12 & *p16);

        *p12 = c_0;
        *p16 = c_1;
        *p20 = c_2;
        *p4 = c_3;
        *p8 = c_4;

        *p ^= round_constant;

        let tmp = *p5;

        *p5 = *p18;
        *p18 = *p11;
        *p11 = *p10;
        *p10 = *p6;
        *p6 = *p22;
        *p22 = *p20;
        *p20 = *p12;
        *p12 = *p19;
        *p19 = *p15;
        *p15 = *p24;
        *p24 = *p8;
        *p8 = tmp;

        let tmp = *p1;

        *p1 = *p9;
        *p9 = *p14;
        *p14 = *p2;
        *p2 = *p13;
        *p13 = *p23;
        *p23 = *p4;
        *p4 = *p21;
        *p21 = *p16;
        *p16 = *p3;
        *p3 = *p17;
        *p17 = *p7;
        *p7 = tmp;
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
        let p1 = shake_ptr.add(1);
        let p2 = shake_ptr.add(2);
        let p8 = shake_ptr.add(8);
        let p12 = shake_ptr.add(12);
        let p17 = shake_ptr.add(17);
        let p20 = shake_ptr.add(20);

        *p1 = !*p1;
        *p2 = !*p2;
        *p8 = !*p8;
        *p12 = !*p12;
        *p17 = !*p17;
        *p20 = !*p20;

        // unrolling rounds
        theta_rho_step_1(shake_ptr);
        chi_iota_step_1(shake_ptr, *shake_constants_ptr);
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

        *p1 = !*p1;
        *p2 = !*p2;
        *p8 = !*p8;
        *p12 = !*p12;
        *p17 = !*p17;
        *p20 = !*p20;
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
        let shake_ptr_u128 = shake_ptr as *mut u128;
        let input_ptr_u128 = input_ptr as *const u128;

        // Process first 16 lanes (8 u128 values = 128 bytes) in pairs using u128 XOR
        // This reduces operations from 17 u64 XORs (16 + 1) to 8 u128 XORs + 1 u64 XOR
        *shake_ptr_u128 ^= input_ptr_u128.read_unaligned();
        *shake_ptr_u128.add(1) ^= input_ptr_u128.add(1).read_unaligned();
        *shake_ptr_u128.add(2) ^= input_ptr_u128.add(2).read_unaligned();
        *shake_ptr_u128.add(3) ^= input_ptr_u128.add(3).read_unaligned();
        *shake_ptr_u128.add(4) ^= input_ptr_u128.add(4).read_unaligned();
        *shake_ptr_u128.add(5) ^= input_ptr_u128.add(5).read_unaligned();
        *shake_ptr_u128.add(6) ^= input_ptr_u128.add(6).read_unaligned();
        *shake_ptr_u128.add(7) ^= input_ptr_u128.add(7).read_unaligned();

        // Handle the last u64 (lane 16, bytes 128-135)
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

/// Variable-time squeeze (Finding B): extracts exactly [`SHAKE_VARTIME_BLOCKS`] (9) full Keccak
/// rate blocks - enough draws for the variable-time rejection sampler to accept all `N` challenge
/// coefficients with an overwhelming safety margin - instead of the 11 permutations the
/// constant-time oversample required.
///
/// Every block is a full 17-word rate (9 × 17 = [`SHAKE_VARTIME_WORDS`] = 153 words, exactly
/// 1224 bytes), so the rate is copied whole-word - no trailing partial word like [`shake_extract`].
///
/// The context must have been flipped to output mode using [`shake_flip()`].
///
/// # Parameters
/// - `shake_ctx`: The SHAKE256 state array (26 `u64` words) to extract from.
///
/// # Returns
/// `SHAKE_VARTIME_WORDS` (153) squeezed `u64` words = 612 big-endian draws.
pub fn shake_extract_vartime(shake_ctx: &mut [u64; 26]) -> [u64; SHAKE_VARTIME_WORDS] {
    let mut out = [0u64; SHAKE_VARTIME_WORDS];
    let out_ptr = out.as_mut_ptr();

    unsafe {
        let state_ptr = shake_ctx.as_ptr();
        let mut block = 0usize;
        let mut word = 0usize;

        while block != SHAKE_VARTIME_BLOCKS {
            process_block(shake_ctx);

            // Copy the full 17-word (136-byte) rate block.
            core::ptr::copy_nonoverlapping(state_ptr, out_ptr.add(word), SHAKE256_RATE_WORDS);

            word += SHAKE256_RATE_WORDS;
            block += 1;
        }
    }

    shake_ctx[25] = 0x0;

    out
}
