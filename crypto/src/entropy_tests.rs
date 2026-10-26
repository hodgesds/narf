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

// ── Key-material surface (issue #996) ────────────────────────────────
//
// Deterministic by construction: every test drives the source seam
// with a synthetic word stream and a fresh EntropyHealth, so no
// verdict depends on the host CPU, the QEMU CPU model, or global
// health state left by another smoke.

/// Stand-in for a healthy source: the byte stream 0,1,...,255,0,1,...
/// — no repeated-byte run and no dominant byte in any 512-byte window,
/// so it passes the SP 800-90B tests by construction. `calls` counts
/// the words drawn, pinning the startup test's exact cost.
struct CycleSource {
    pos: u64,
    calls: usize,
}

impl CycleSource {
    fn new() -> Self {
        Self { pos: 0, calls: 0 }
    }

    fn next(&mut self) -> Option<u64> {
        self.calls += 1;
        let mut bytes = [0u8; 8];
        for byte in &mut bytes {
            *byte = (self.pos % 256) as u8;
            self.pos += 1;
        }
        Some(u64::from_le_bytes(bytes))
    }
}

fn smoke_key_material_refuses_without_source_and_does_not_latch() -> TestResult {
    let health = EntropyHealth::new();
    let mut out = [0xa5; 48];
    if fill_key_material_with(&mut out, &health, || None) != Err(CryptoError::EntropyUnavailable)
        || out.iter().any(|b| *b != 0)
    {
        return TestResult::Fail("entropy-less key fill published bytes or kept caller data");
    }
    if key_rng_with(&health, || None).is_ok() {
        return TestResult::Fail("entropy-less key stream was constructed");
    }
    if health.failed() {
        return TestResult::Fail("source starvation latched the health state");
    }
    // Starvation is not a health failure: the startup test simply
    // retries, and the same monitor accepts a healthy source after it.
    let mut source = CycleSource::new();
    if fill_key_material_with(&mut out, &health, || source.next()) != Ok(()) || out == [0; 48] {
        return TestResult::Fail("healthy source refused after transient starvation");
    }
    if fill_key_material_with(&mut [], &health, || {
        panic!("empty fill consulted the source")
    })
    .is_err()
    {
        return TestResult::Fail("empty key fill failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/entropy",
    smoke_key_material_refuses_without_source_and_does_not_latch
);

fn smoke_key_material_health_test_cutoffs() -> TestResult {
    // RCT: 32 identical bytes pass; the 33rd fails, permanently.
    let mut tests = HealthTests::new();
    if tests.feed_all(&[0x07; 32]).is_err()
        || tests.feed(0x07) != Err(CryptoError::EntropyUnavailable)
        || !tests.failed
    {
        return TestResult::Fail("repetition count test did not trip at its cutoff");
    }
    if tests.feed(0x09).is_ok() {
        return TestResult::Fail("failed health state accepted more input");
    }
    // A varied stream restarts the run and passes both tests for
    // multiple whole APT windows.
    let mut tests = HealthTests::new();
    for i in 0..1024 {
        if tests.feed((i % 251) as u8).is_err() {
            return TestResult::Fail("varied stream tripped the health tests");
        }
    }
    // APT: "AAB" repeated makes the window's reference byte dominant
    // (341 of 512) and must trip before the window closes; "ABAB" sits
    // at the assumed min-entropy distribution (256 of 512) and passes.
    let mut tests = HealthTests::new();
    let mut tripped = false;
    for i in 0..APT_WINDOW {
        if tests.feed([0x41, 0x41, 0x42][i % 3]).is_err() {
            tripped = true;
            break;
        }
    }
    if !tripped {
        return TestResult::Fail("adaptive proportion test ignored a dominant byte");
    }
    let mut tests = HealthTests::new();
    for i in 0..APT_WINDOW {
        if tests.feed(if i % 2 == 0 { 0x41 } else { 0x42 }).is_err() {
            return TestResult::Fail("balanced stream tripped the adaptive proportion test");
        }
    }
    TestResult::Pass
}
kernel_test_in!("crypto/entropy", smoke_key_material_health_test_cutoffs);

fn smoke_key_material_startup_rejects_degenerate_sources() -> TestResult {
    // A stuck-at word and an "AAB"-biased word both fail the startup
    // test — one through the RCT, one through the APT — and the latch
    // then refuses even a healthy source.
    for word in [
        0u64,
        u64::from_le_bytes([0x41, 0x41, 0x42, 0x41, 0x41, 0x42, 0x41, 0x41]),
    ] {
        let health = EntropyHealth::new();
        if key_rng_with(&health, || Some(word)).is_ok() || !health.failed() {
            return TestResult::Fail("startup health test admitted a degenerate source");
        }
        let mut source = CycleSource::new();
        if key_rng_with(&health, || source.next()).is_ok() {
            return TestResult::Fail("health failure did not latch the source off");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/entropy",
    smoke_key_material_startup_rejects_degenerate_sources
);

fn smoke_key_material_draws_after_single_startup() -> TestResult {
    let health = EntropyHealth::new();
    let mut source = CycleSource::new();
    let mut out = [0u8; 32];
    if fill_key_material_with(&mut out, &health, || source.next()) != Ok(()) {
        return TestResult::Fail("healthy source refused key material");
    }
    // The startup test costs exactly 1024 bytes = 128 words, once,
    // before the first 4 seed words.
    if source.calls != STARTUP_BYTES / 8 + 4 {
        return TestResult::Fail("startup test did not run exactly once before the first draw");
    }
    let first = out;
    if fill_key_material_with(&mut out, &health, || source.next()) != Ok(()) || out == first {
        return TestResult::Fail("second key fill failed or repeated the first stream");
    }
    if source.calls != STARTUP_BYTES / 8 + 8 {
        return TestResult::Fail("startup test re-ran on a later draw");
    }
    if key_rng_with(&health, || source.next()).is_err() || source.calls != STARTUP_BYTES / 8 + 12 {
        return TestResult::Fail("key stream draw failed or re-ran the startup test");
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/entropy",
    smoke_key_material_draws_after_single_startup
);

fn smoke_key_material_continuous_failure_latches_and_zeroizes() -> TestResult {
    let health = EntropyHealth::new();
    let mut source = CycleSource::new();
    let mut out = [0u8; 32];
    if fill_key_material_with(&mut out, &health, || source.next()) != Ok(()) {
        return TestResult::Fail("healthy source refused key material");
    }
    // The source degrades to a single repeated byte. The first degraded
    // seed only extends the repetition run to 32 — one short of the
    // cutoff — so it is still released.
    if fill_key_material_with(&mut out, &health, || Some(0xabab_abab_abab_abab)) != Ok(()) {
        return TestResult::Fail("first degraded seed was rejected before the cutoff");
    }
    // The next seed's first byte is the 33rd identical byte in a row:
    // the continuous test trips while observing the seed, the fill
    // refuses, the caller's buffer is zeroized rather than left holding
    // the previous fill, and the latch closes behind it.
    out.fill(0x5a);
    if fill_key_material_with(&mut out, &health, || Some(0xabab_abab_abab_abab))
        != Err(CryptoError::EntropyUnavailable)
        || out.iter().any(|b| *b != 0)
        || !health.failed()
    {
        return TestResult::Fail("continuous health failure did not refuse and zeroize");
    }
    let mut source = CycleSource::new();
    if fill_key_material_with(&mut out, &health, || source.next()).is_ok() {
        return TestResult::Fail("latched-off source served key material again");
    }
    TestResult::Pass
}
kernel_test_in!(
    "crypto/entropy",
    smoke_key_material_continuous_failure_latches_and_zeroizes
);

fn smoke_key_material_native_contract() -> TestResult {
    let mut out = [0xa5; 32];
    if has_hw_entropy() {
        // Present and healthy (the startup test just passed inside
        // has_hw_entropy): generation may not refuse.
        if try_fill_key_material(&mut out) != Ok(()) {
            return TestResult::Fail("healthy native source refused key material");
        }
        if key_material_rng().is_err() {
            return TestResult::Fail("healthy native source refused a key stream");
        }
    } else if !seed_source_present() || KEY_MATERIAL_HEALTH.failed() {
        // Absent source, or a source the startup test latched off:
        // the refusal contract is stable — typed error, zeroized out.
        if try_fill_key_material(&mut out) != Err(CryptoError::EntropyUnavailable) || out != [0; 32]
        {
            return TestResult::Fail("unavailable native source published key material");
        }
        if key_material_rng().is_ok() {
            return TestResult::Fail("unavailable native source produced a key stream");
        }
    }
    // The remaining case — source present but the startup draw starved
    // transiently — has no stable contract to assert either way.
    TestResult::Pass
}
kernel_test_in!("crypto/entropy", smoke_key_material_native_contract);
