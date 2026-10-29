//! Source-selection fixtures for the userspace CSPRNG floor (#1026).
//!
//! The matrix under test is seed-grade present / absent /
//! health-latched × consumer class. The deterministic fixtures drive
//! the pool through scripted draws ([`super::fill_pool`] /
//! [`super::obtain_seed`]) so every cell of the matrix runs on any
//! CPU; the native fixture at the end pins the contract against the
//! real `narf-crypto` surface on whatever machine executes it.
//!
//! The properties pinned here:
//!
//! - No source at all ⇒ refusal, and neither draw is even attempted.
//! - Seed-grade present ⇒ the key-material draw seeds the pool and
//!   the conditioned draw is never consulted.
//! - Seed-grade present but refusing (starved or SP 800-90B
//!   health-latched) ⇒ refusal, and the conditioned draw is STILL
//!   never consulted — the latch is not a routing hint.
//! - No seed-grade source + RDRAND present ⇒ the conditioned class
//!   seeds the pool, labelled `SeedClass::Conditioned`.
//! - A reseed never changes the pool's class and never downgrades: a
//!   failed reseed leaves the pool serving from its existing key,
//!   counted, with the retry deferred — never silently, never from
//!   the other class's draw.
//! - There is no scripted draw that models a cycle counter: the
//!   ladder's third rung is a registered virtio-rng device, not a
//!   timing source, so no fixture (and no machine) can make timing
//!   output reach a cryptographic consumer.
//! - The virtio rung seeds only when no architectural source exists
//!   at all, is never consulted around a refusing higher rung, is
//!   labelled `SeedClass::VirtioRng` (never architectural), and a
//!   virtio-seeded pool reseeds from the virtio draw only.

use core::cell::Cell;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::*;

/// Deterministic stand-in for a healthy seed-grade draw: fills with a
/// non-constant pattern so seeded output is recognisably keyed.
fn healthy_draw(tag: u8) -> impl FnMut(&mut [u8; 32]) -> Result<(), CsprngError> {
    move |buf: &mut [u8; 32]| {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(tag);
        }
        Ok(())
    }
}

fn refusing_draw(_buf: &mut [u8; 32]) -> Result<(), CsprngError> {
    Err(CsprngError::EntropyUnavailable)
}

/// A healthy draw that counts its invocations, so a fixture can
/// prove a rung was (or was not) consulted.
fn counting_draw<'a>(
    tag: u8,
    calls: &'a Cell<usize>,
) -> impl FnMut(&mut [u8; 32]) -> Result<(), CsprngError> + 'a {
    move |buf: &mut [u8; 32]| {
        calls.set(calls.get() + 1);
        healthy_draw(tag)(buf)
    }
}

/// Stand-in for a probed virtio-rng device's registered draw, for
/// the registration-visibility smoke: a plain fn item, as the
/// production adapter is.
fn fake_virtio_fill(buf: &mut [u8; 32]) -> Result<(), CsprngError> {
    healthy_draw(0x5A)(buf)
}

fn non_constant(buf: &[u8]) -> bool {
    buf.iter().any(|&b| b != buf[0])
}

// ── No source: refusal, and no draw is even attempted ────────────────────────

fn csprng_floor_no_source_refuses() -> TestResult {
    // Entropy-less machine: no seed-grade source, no conditioned
    // source. The pool must refuse, and the refusal must happen
    // on presence alone — neither draw may be attempted.
    let km_calls = Cell::new(0usize);
    let cd_calls = Cell::new(0usize);
    let vt_calls = Cell::new(0usize);
    let mut km = |buf: &mut [u8; 32]| {
        km_calls.set(km_calls.get() + 1);
        healthy_draw(0x11)(buf)
    };
    let mut cd = |buf: &mut [u8; 32]| {
        cd_calls.set(cd_calls.get() + 1);
        healthy_draw(0x22)(buf)
    };
    let mut vt = counting_draw(0x33, &vt_calls);
    let mut state = PoolState::uninit();
    let mut buf = [0xCDu8; 32];
    match fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: false,
            virtio_present: false,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    ) {
        Err(CsprngError::EntropyUnavailable) => {}
        Ok(()) => return TestResult::Fail("fill_pool succeeded with no entropy source"),
    }
    if km_calls.get() != 0 || cd_calls.get() != 0 || vt_calls.get() != 0 {
        return TestResult::Fail("a draw was attempted despite no source being present");
    }
    if state.class.is_some() {
        return TestResult::Fail("pool claims a seed class after refusing");
    }
    if buf != [0xCDu8; 32] {
        return TestResult::Fail("refused fill wrote into the caller's buffer");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/csprng", csprng_floor_no_source_refuses);

// ── Seed-grade present: it seeds, conditioned never consulted ────────────────

fn csprng_floor_seed_grade_preferred() -> TestResult {
    // Both sources present: the key-material draw seeds the pool
    // at SeedGrade and the conditioned draw is never consulted.
    let cd_calls = Cell::new(0usize);
    let vt_calls = Cell::new(0usize);
    let mut km = healthy_draw(0x33);
    let mut cd = |buf: &mut [u8; 32]| {
        cd_calls.set(cd_calls.get() + 1);
        healthy_draw(0x44)(buf)
    };
    let mut vt = counting_draw(0x5A, &vt_calls);
    let mut state = PoolState::uninit();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: true,
            conditioned_present: true,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut a,
    )
    .is_err()
    {
        return TestResult::Fail("seed-grade fill refused");
    }
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: true,
            conditioned_present: true,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut b,
    )
    .is_err()
    {
        return TestResult::Fail("second seed-grade fill refused");
    }
    if state.class != Some(SeedClass::SeedGrade) {
        return TestResult::Fail("pool is not SeedGrade with a seed-grade source present");
    }
    if cd_calls.get() != 0 {
        return TestResult::Fail("conditioned draw consulted despite seed-grade source");
    }
    if vt_calls.get() != 0 {
        return TestResult::Fail("virtio draw consulted despite seed-grade source");
    }
    if a == b {
        return TestResult::Fail("successive fills are identical");
    }
    if !non_constant(&a) || !non_constant(&b) {
        return TestResult::Fail("pool output is constant");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/csprng", csprng_floor_seed_grade_preferred);

// ── Seed-grade present but refusing: refusal, never a bypass ─────────────────

fn csprng_floor_latched_seed_grade_never_bypassed() -> TestResult {
    // The anti-bypass cell: a seed-grade source is PRESENT but
    // its draw refuses — the SP 800-90B health latch or starvation
    // in narf-crypto. The pool must refuse too. Consulting the
    // conditioned draw here would route around the latch (on
    // aarch64 it draws the very instructions that latched), so
    // the fixture asserts it is never called.
    let cd_calls = Cell::new(0usize);
    let vt_calls = Cell::new(0usize);
    let mut km = refusing_draw;
    let mut cd = |buf: &mut [u8; 32]| {
        cd_calls.set(cd_calls.get() + 1);
        healthy_draw(0x55)(buf)
    };
    let mut vt = counting_draw(0x5A, &vt_calls);
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 16];
    match fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: true,
            conditioned_present: true,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    ) {
        Err(CsprngError::EntropyUnavailable) => {}
        Ok(()) => return TestResult::Fail("pool served bytes around a refused seed-grade draw"),
    }
    if cd_calls.get() != 0 {
        return TestResult::Fail("conditioned draw consulted after seed-grade refusal");
    }
    if vt_calls.get() != 0 {
        return TestResult::Fail("virtio draw consulted after seed-grade refusal");
    }
    if state.class.is_some() {
        return TestResult::Fail("pool claims a seed class after the latch refusal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_latched_seed_grade_never_bypassed
);

// ── No seed-grade source + RDRAND: the labelled Conditioned class ────────────

fn csprng_floor_conditioned_only_without_seed_grade() -> TestResult {
    // The RDRAND-only x86_64 shape: no seed-grade source, RDRAND
    // present. The pool seeds at the Conditioned class — served,
    // but labelled degraded, never SeedGrade.
    let km_calls = Cell::new(0usize);
    let vt_calls = Cell::new(0usize);
    let mut km = |buf: &mut [u8; 32]| {
        km_calls.set(km_calls.get() + 1);
        healthy_draw(0x66)(buf)
    };
    let mut cd = healthy_draw(0x77);
    let mut vt = counting_draw(0x5A, &vt_calls);
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 32];
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: true,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("conditioned-class fill refused");
    }
    if state.class != Some(SeedClass::Conditioned) {
        return TestResult::Fail("RDRAND-only pool is not labelled Conditioned");
    }
    if km_calls.get() != 0 {
        return TestResult::Fail("key-material draw attempted with no seed-grade source");
    }
    if vt_calls.get() != 0 {
        return TestResult::Fail("virtio draw consulted despite conditioned source");
    }
    if !non_constant(&buf) {
        return TestResult::Fail("conditioned-class output is constant");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_conditioned_only_without_seed_grade
);

// ── Reseed discipline: class-preserving, failure-tolerant, no downgrade ──────

fn csprng_floor_reseed_preserves_class_and_tolerates_failure() -> TestResult {
    // Seed a pool at SeedGrade.
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 16];
    let mut vt = refusing_draw;
    {
        let mut km = healthy_draw(0x88);
        let mut cd = healthy_draw(0x99);
        if fill_pool(
            &mut state,
            SeedDraws {
                seed_grade_present: true,
                conditioned_present: true,
                virtio_present: false,
                key_material: &mut km,
                conditioned: &mut cd,
                virtio: &mut vt,
            },
            &mut buf,
        )
        .is_err()
        {
            return TestResult::Fail("initial seed-grade fill refused");
        }
    }
    if state.class != Some(SeedClass::SeedGrade) {
        return TestResult::Fail("pool did not seed at SeedGrade");
    }

    // Drive the pool to its reseed threshold and make the
    // seed-grade draw fail. The fill must still succeed — the
    // pool serves from its existing, properly seeded key — the
    // class must not move, the failure must be counted, and the
    // conditioned draw must not be used as a downgrade path.
    state.inner.bytes_since_reseed = RESEED_THRESHOLD;
    let km_calls = Cell::new(0usize);
    let cd_calls = Cell::new(0usize);
    let mut km_fail = |_buf: &mut [u8; 32]| {
        km_calls.set(km_calls.get() + 1);
        Err(CsprngError::EntropyUnavailable)
    };
    let mut cd = |buf: &mut [u8; 32]| {
        cd_calls.set(cd_calls.get() + 1);
        healthy_draw(0xAA)(buf)
    };
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: true,
            conditioned_present: true,
            virtio_present: false,
            key_material: &mut km_fail,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("fill failed on a reseed draw failure against a live pool");
    }
    if state.class != Some(SeedClass::SeedGrade) {
        return TestResult::Fail("reseed failure changed the pool's class");
    }
    if state.reseed_failures != 1 {
        return TestResult::Fail("reseed failure was not counted");
    }
    if cd_calls.get() != 0 {
        return TestResult::Fail("reseed downgraded to the conditioned draw");
    }
    if km_calls.get() != 1 {
        return TestResult::Fail("reseed draw was not attempted exactly once");
    }

    // Inside the retry slice, further fills do not spin the draw.
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: true,
            conditioned_present: true,
            virtio_present: false,
            key_material: &mut km_fail,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("fill inside the retry slice refused");
    }
    if km_calls.get() != 1 {
        return TestResult::Fail("reseed draw retried inside its deferral slice");
    }

    // Past the slice, a healthy draw reseeds and clears the count.
    state.inner.bytes_since_reseed = state.reseed_blocked_until;
    let mut km_ok = healthy_draw(0xBB);
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: true,
            conditioned_present: true,
            virtio_present: false,
            key_material: &mut km_ok,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("deferred reseed refused");
    }
    if state.reseed_failures != 0 {
        return TestResult::Fail("successful reseed did not clear the failure count");
    }
    if cd_calls.get() != 0 {
        return TestResult::Fail("conditioned draw used for a seed-grade pool");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_reseed_preserves_class_and_tolerates_failure
);

fn csprng_floor_conditioned_reseed_stays_conditioned() -> TestResult {
    // A Conditioned pool reseeds from the conditioned draw only:
    // the key-material draw is never attempted for it (there is
    // no seed-grade source on the machine that produced it).
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 16];
    let km_calls = Cell::new(0usize);
    let mut km = |buf: &mut [u8; 32]| {
        km_calls.set(km_calls.get() + 1);
        healthy_draw(0xCC)(buf)
    };
    let mut cd = healthy_draw(0xDD);
    let mut vt = refusing_draw;
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: true,
            virtio_present: false,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("conditioned seed refused");
    }
    state.inner.bytes_since_reseed = RESEED_THRESHOLD;
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: true,
            virtio_present: false,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("conditioned reseed refused");
    }
    if state.class != Some(SeedClass::Conditioned) {
        return TestResult::Fail("conditioned pool changed class on reseed");
    }
    if km_calls.get() != 0 {
        return TestResult::Fail("key-material draw attempted for a conditioned pool");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_conditioned_reseed_stays_conditioned
);

// ── VirtioRng rung: seeds only without an architectural source ───────────────

fn csprng_floor_virtio_seeds_when_no_arch_source() -> TestResult {
    // The RNG-less shape with a virtio-rng device: no seed-grade
    // source, no conditioned source, virtio present. The pool seeds
    // at the labelled VirtioRng class — served, but never
    // architectural.
    let vt_calls = Cell::new(0usize);
    let mut km = refusing_draw;
    let mut cd = refusing_draw;
    let mut vt = counting_draw(0x5A, &vt_calls);
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 64];
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: false,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("virtio-class fill refused");
    }
    if state.class != Some(SeedClass::VirtioRng) {
        return TestResult::Fail("virtio-seeded pool is not labelled VirtioRng");
    }
    if vt_calls.get() != 1 {
        return TestResult::Fail("virtio draw was not attempted exactly once for the seed");
    }
    if !non_constant(&buf) {
        return TestResult::Fail("virtio-class output is constant");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_virtio_seeds_when_no_arch_source
);

fn csprng_floor_virtio_not_consulted_when_conditioned_refuses() -> TestResult {
    // The new terminal rule for the conditioned rung: a conditioned
    // source is PRESENT but its draw refuses, and a healthy virtio
    // draw is available. The pool must refuse too — the virtio rung
    // exists only for hardware with no architectural source, not as
    // a route around a refusing one.
    let vt_calls = Cell::new(0usize);
    let mut km = refusing_draw;
    let mut cd = refusing_draw;
    let mut vt = counting_draw(0x5A, &vt_calls);
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 16];
    match fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: true,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    ) {
        Err(CsprngError::EntropyUnavailable) => {}
        Ok(()) => return TestResult::Fail("pool served bytes around a refused conditioned draw"),
    }
    if vt_calls.get() != 0 {
        return TestResult::Fail("virtio draw consulted after conditioned refusal");
    }
    if state.class.is_some() {
        return TestResult::Fail("pool claims a seed class after the conditioned refusal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_virtio_not_consulted_when_conditioned_refuses
);

fn csprng_floor_virtio_reseed_stays_virtio() -> TestResult {
    // A VirtioRng pool reseeds from the virtio draw only: neither
    // architectural draw is attempted for it (there is no
    // architectural source on the machine that produced it).
    let vt_calls = Cell::new(0usize);
    let km_calls = Cell::new(0usize);
    let cd_calls = Cell::new(0usize);
    let mut km = |buf: &mut [u8; 32]| {
        km_calls.set(km_calls.get() + 1);
        healthy_draw(0x66)(buf)
    };
    let mut cd = |buf: &mut [u8; 32]| {
        cd_calls.set(cd_calls.get() + 1);
        healthy_draw(0x77)(buf)
    };
    let mut vt = counting_draw(0x5A, &vt_calls);
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 16];
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: false,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("virtio seed refused");
    }
    state.inner.bytes_since_reseed = RESEED_THRESHOLD;
    if fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: false,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    )
    .is_err()
    {
        return TestResult::Fail("virtio reseed refused");
    }
    if state.class != Some(SeedClass::VirtioRng) {
        return TestResult::Fail("virtio pool changed class on reseed");
    }
    if vt_calls.get() != 2 {
        return TestResult::Fail("virtio draw was not attempted exactly once per (re)seed");
    }
    if km_calls.get() != 0 || cd_calls.get() != 0 {
        return TestResult::Fail("architectural draw attempted for a virtio pool");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem/csprng", csprng_floor_virtio_reseed_stays_virtio);

fn csprng_floor_virtio_refusal_when_device_fails() -> TestResult {
    // Virtio present but its draw fails: the pool refuses, exactly
    // as it would with no source at all.
    let mut km = refusing_draw;
    let mut cd = refusing_draw;
    let mut vt = refusing_draw;
    let mut state = PoolState::uninit();
    let mut buf = [0u8; 16];
    match fill_pool(
        &mut state,
        SeedDraws {
            seed_grade_present: false,
            conditioned_present: false,
            virtio_present: true,
            key_material: &mut km,
            conditioned: &mut cd,
            virtio: &mut vt,
        },
        &mut buf,
    ) {
        Err(CsprngError::EntropyUnavailable) => {}
        Ok(()) => return TestResult::Fail("pool served bytes from a failing virtio draw"),
    }
    if state.class.is_some() {
        return TestResult::Fail("pool claims a seed class after the virtio refusal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_virtio_refusal_when_device_fails
);

fn csprng_floor_virtio_registration_visible() -> TestResult {
    // The global registration slot itself: install a fake draw,
    // observe presence, clear it, observe absence — restoring the
    // slot to exactly the state this smoke found it in. If a real
    // device already registered (or an earlier smoke left one),
    // first-wins registration means this smoke cannot install its
    // fake without clobbering it, so it skips: the ladder fixtures
    // above still prove the class logic, and the probe smoke proves
    // the device path.
    if virtio_rng_source_present() {
        return TestResult::Skip("virtio source already registered");
    }
    __test_set_virtio_rng_source(Some(fake_virtio_fill));
    if !virtio_rng_source_present() {
        return TestResult::Fail("fake virtio source not visible after install");
    }
    __test_set_virtio_rng_source(None);
    if virtio_rng_source_present() {
        return TestResult::Fail("virtio source still visible after clear");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/csprng",
    csprng_floor_virtio_registration_visible
);

// ── Native contract: the real surface on the executing machine ───────────────

fn csprng_native_contract() -> TestResult {
    // Whichever class the hardware offers, the observable state
    // must agree with what fills do.
    init_csprng();
    match seed_class() {
        Some(_) => {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            if try_fill(&mut a).is_err() || try_fill(&mut b).is_err() {
                return TestResult::Fail("try_fill refused on a seeded pool");
            }
            if a == b {
                return TestResult::Fail("successive native fills are identical");
            }
            if entropy_avail_bits() != 4096 {
                return TestResult::Fail("seeded pool does not report full entropy_avail");
            }
            if last_entropy_source().is_none() {
                return TestResult::Fail("seeded pool records no entropy source");
            }
            if !is_seeded() || !CSPRNG_SEEDED.load(Ordering::Acquire) {
                return TestResult::Fail("seeded pool does not report seeded");
            }
            TestResult::Pass
        }
        None => {
            let mut buf = [0u8; 16];
            if try_fill(&mut buf).is_ok() {
                return TestResult::Fail("try_fill served bytes from an unseeded pool");
            }
            if entropy_avail_bits() != 0 {
                return TestResult::Fail("unseeded pool reports entropy available");
            }
            if last_entropy_source().is_some() {
                return TestResult::Fail("unseeded pool records an entropy source");
            }
            // The infallible in-kernel fill must leave the buffer
            // untouched rather than writing predictable bytes.
            let mut sentinel = [0xCDu8; 16];
            fill(&mut sentinel);
            if sentinel != [0xCDu8; 16] {
                return TestResult::Fail("fill() wrote bytes on an entropy-less machine");
            }
            TestResult::Pass
        }
    }
}
kernel_test_in!("filesystem/csprng", csprng_native_contract);
