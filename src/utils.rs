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
#[inline(always)]
pub fn mq_montymul(a: u16, b: u16) -> u16 {
    let res: u32 = (a as u32) * (b as u32);
    let m = res as u16 * Q0I;
    let t = ((res + m as u32 * Q as u32) >> 0x10) as u16;

    t - ((((t - Q) >> 15) - 1) & Q)
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

/// SWAR (SIMD-within-a-register) utilities for **exactly 7× u16** packed into a `u128`
/// using 17-bit lanes (16 data bits + 1 reserved MSB per lane, 119 bits used).
///
/// All operations are fully constant-time / branchless and never produce carry/borrow
/// across lanes thanks to the reserved MSB.
///
/// Only the u128 / 7-lane part from the original Solidity `SIMDLibU16` is kept.
/// Constants are private, API is minimal and Rust-idiomatic.

const MSB_MASK: u128 = 0x400020001000080004000200010000u128;
const PACK_MASK: u128 = 0x40002000100008000400020001u128;
const MSB_NEG_MASK: u128 = 0x3fffdfffeffff7fffbfffdfffeffffu128;
const MAGIC_LOW: u128 = 0x480c205ba04f0840dc400a4019400440u128;
const SHIFT: u32 = 118;

#[inline(always)]
fn lt_raw(p: u128, pc: u128) -> u128 {
    let mask = MSB_MASK;
    let inv = MSB_NEG_MASK;
    let tmp = (p | mask).wrapping_sub(pc & inv);
    let flg = (p ^ !pc) & mask;
    (tmp ^ flg) & mask
}

#[inline(always)]
fn aggregate(raw: u128) -> u128 {
    (raw.wrapping_mul(MAGIC_LOW) >> SHIFT) & 0x7f
}

#[inline(always)]
fn add_raw(a: u128, b: u128) -> u128 {
    a.wrapping_add(b) & MSB_NEG_MASK
}

#[inline(always)]
fn sub_raw(a: u128, b: u128) -> u128 {
    let mask = MSB_MASK;
    let inv = MSB_NEG_MASK;
    let tmp = (a | mask).wrapping_sub(b & inv);
    let flg = (a ^ !b) & mask;
    (tmp ^ flg) & inv
}

/// Pack 7 × `u16` into a `u128` (MSB of every 17-bit lane = 0).
#[inline(always)]
pub fn pack(ns: [u16; 7]) -> u128 {
    let [n0, n1, n2, n3, n4, n5, n6] = ns;
    (n0 as u128)
        | ((n1 as u128) << 17)
        | ((n2 as u128) << 34)
        | ((n3 as u128) << 51)
        | ((n4 as u128) << 68)
        | ((n5 as u128) << 85)
        | ((n6 as u128) << 102)
}

/// Broadcast a single `u16` into all 7 lanes (pre-computed compare value).
#[inline(always)]
pub fn broadcast(c: u16) -> u128 {
    (c as u128).wrapping_mul(PACK_MASK)
}

/// Lane-wise `<` → 7-bit flag mask (bit k = 1 iff lane k < `c`).
#[inline(always)]
pub fn lt(packed: u128, c: u16) -> u128 {
    lt_packed(packed, broadcast(c))
}

/// Same as `lt` but with a pre-broadcasted compare value (slightly faster in hot loops).
#[inline(always)]
pub fn lt_packed(packed: u128, packed_cmp: u128) -> u128 {
    aggregate(lt_raw(packed, packed_cmp))
}

/// Lane-wise `>` → 7-bit flag mask.
#[inline(always)]
pub fn gt(packed: u128, c: u16) -> u128 {
    lt_packed(broadcast(c), packed)
}

/// Same as `gt` but with pre-broadcasted compare value.
#[inline(always)]
pub fn gt_packed(packed: u128, packed_cmp: u128) -> u128 {
    lt_packed(packed_cmp, packed)
}

/// Lane-wise add (assumes result stays ≤ 0xffff per lane – as required by the original lib).
#[inline(always)]
pub fn add(a: u128, b: u128) -> u128 {
    add_raw(a, b)
}

/// Lane-wise subtract (constant-time, no borrow propagation across lanes).
#[inline(always)]
pub fn sub(a: u128, b: u128) -> u128 {
    sub_raw(a, b)
}
