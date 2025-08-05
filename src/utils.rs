use crate::constants::{M8, Q, Q0I, R_M8};

/// Performs Montgomery modular multiplication for the modulus `Q`.
///
/// Computes `(a * b) * Q0I mod Q`, using 16-bit arithmetic with precomputed Montgomery constants.
///
/// # Parameters
/// - `a`: The first operand (`u16`).
/// - `b`: The second operand (`u16`).
///
/// # Returns
/// The Montgomery product of `a` and `b` as a `u16`, reduced modulo `Q`.
///
/// # Details
/// Assumes `Q`, `Q0I` are modular arithmetic constants suitable for the Montgomery domain.
///
#[inline(always)]
pub fn mq_montymul(a: u16, b: u16) -> u16 {
    let res: u32 = (a as u32) * (b as u32);
    let m = res as u16 * Q0I;
    let t = ((res + m as u32 * Q as u32) >> 0x10) as u16;

    t - (t >= Q) as u16 * Q
}

/// Performs modular addition: `(a + b) mod Q`.
///
/// # Parameters
/// - `a`: The first operand (`u16`).
/// - `b`: The second operand (`u16`).
///
/// # Returns
/// The sum of `a` and `b`, reduced modulo `Q`.
#[inline(always)]
pub fn mq_add(a: u16, b: u16) -> u16 {
    let c = a + b - Q;

    c + (Q & 0 - (c >> 0xf))
}

/// Performs modular subtraction: `(a - b) mod Q`.
///
/// # Parameters
/// - `a`: The minuend (`u16`).
/// - `b`: The subtrahend (`u16`).
///
/// # Returns
/// The result of `a - b`, wrapped mod `Q` if negative.
#[inline(always)]
pub fn mq_sub(a: u16, b: u16) -> u16 {
    let c = a - b;

    c + (Q & 0 - (c >> 0xf))
}

/// Swaps byte pairs in a 64-bit value using the provided masks.
///
/// Each pair of bytes within the 64-bit word `x` is swapped using bitmasks.
///
/// # Parameters
/// - `x`: The input value (`u64`).
///
/// # Returns
/// The value with each byte pair swapped.
///
#[inline(always)]
pub fn swap_byte_pairs(x: u64) -> u64 {
    (x & R_M8) >> 0x8 | (x & M8) << 0x8
}

/// Returns the sign-extended value of a 16-bit integer, up to 32 bits.
///
/// The input `x` (interpreted as `i16`) is sign-extended to `i32`, then cast to `u32`.
///
/// # Parameters
/// - `x`: The input value (`u16`).
///
/// # Returns
/// The sign-extended value as a `u32`.#[inline(always)]
pub fn sign_extend_u16_to_u32(x: u16) -> u32 {
    (x as i16) as i32 as u32
}

/// Panics with a revert message.
///
/// # Parameters
/// - `reason`: The reason for reverting (displayed in the panic message).
///
/// # Panics
/// Always panics with the message `"Reverted: {reason}"`.
pub fn revert(reason: &str) {
    panic!("Reverted: {}", reason);
}
