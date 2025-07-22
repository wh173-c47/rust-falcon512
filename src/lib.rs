pub mod constants;
pub mod falcon512;
pub mod shake256;
pub mod utils;

#[cfg(any(test, feature = "bench"))]
pub mod tests {
    pub mod falcon512_fuzz_tests;
    pub mod falcon512_tests_0;
    pub mod falcon512_tests_1;
    pub mod falcon512_tests_2;
    pub mod falcon512_tests_3;
    pub mod falcon512_tests_4;
    pub mod falcon512_tests_5;
    pub mod falcon512_tests_6;
    pub mod falcon512_tests_7;
    pub mod falcon512_tests_8;
    pub mod falcon512_tests_9;
    pub mod test_utils;
}
