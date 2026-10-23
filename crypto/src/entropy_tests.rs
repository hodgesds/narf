use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_entropy_partial_source_never_publishes_a_seed() -> TestResult {
    for fail_at in 0..4 {
        let mut calls = 0;
        let mut seed = [0xa5; 32];
        if seed_words(&mut seed, || {
            let index = calls;
            calls += 1;
            (index != fail_at).then_some(0x8070605040302010)
        }) || calls != fail_at + 1
            || seed != [0; 32]
        {
            return TestResult::Fail(
                "short entropy source retained partial seed or retried unboundedly",
            );
        }
    }
    let mut seed = [0; 32];
    let mut word = 0u64;
    if !seed_words(&mut seed, || {
        word += 1;
        Some(word)
    }) || word != 4
        || seed[..8] != 1u64.to_le_bytes()
        || seed[24..] != 4u64.to_le_bytes()
    {
        return TestResult::Fail("complete hardware seed changed word order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/entropy",
    smoke_entropy_partial_source_never_publishes_a_seed
);

fn smoke_entropy_failure_zeroizes_complete_output() -> TestResult {
    for len in [1, 31, 32, 64, 129] {
        let mut out = [0xa5; 129];
        let mut calls = 0;
        let result = fill_with(&mut out[..len], |seed| {
            calls += 1;
            seed[..16].fill(0x7b);
            Err(CryptoError::EntropyUnavailable)
        });
        if result != Err(CryptoError::EntropyUnavailable)
            || calls != 1
            || out[..len].iter().any(|b| *b != 0)
            || out[len..].iter().any(|b| *b != 0xa5)
        {
            return TestResult::Fail(
                "failed RNG produced partial bytes or overwrote caller extent",
            );
        }
    }
    if fill_with(&mut [], |_| panic!("empty output requested entropy")).is_err() {
        return TestResult::Fail("empty entropy fill failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/entropy",
    smoke_entropy_failure_zeroizes_complete_output
);

fn smoke_entropy_seed_expansion_matches_chacha_vector() -> TestResult {
    // ChaCha20 all-zero key/nonce first block (RFC 8439), independent of RNG state.
    let expected = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
        0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
        0x0d, 0xc7,
    ];
    let mut out = [0xa5; 32];
    if fill_with(&mut out, |seed| {
        seed.fill(0);
        Ok(())
    }) != Ok(())
        || out != expected
    {
        return TestResult::Fail("hardware seed adapter changed ChaCha20 stream expansion");
    }
    let mut other = [0; 32];
    if fill_with(&mut other, |seed| {
        seed.fill(0x93);
        Ok(())
    })
    .is_err()
        || other == out
    {
        return TestResult::Fail("fresh seed ignored or stream was shared");
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/entropy",
    smoke_entropy_seed_expansion_matches_chacha_vector
);

fn smoke_entropy_native_source_is_fallible() -> TestResult {
    let mut out = [0xa5; 32];
    match try_fill_random_bytes(&mut out) {
        Ok(()) => (), // No probabilistic nonzero/difference assertion about random output.
        Err(CryptoError::EntropyUnavailable) if out == [0; 32] => (),
        _ => return TestResult::Fail("native entropy result violated error/output contract"),
    }
    TestResult::Pass
}
kernel_test_in!("crypto/entropy", smoke_entropy_native_source_is_fallible);
