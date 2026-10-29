//! ChaCha20-based CSPRNG for `/dev/random` and `/dev/urandom`.
//!
//! Replaces the non-cryptographic Park-Miller LCG that Wave-13 and
//! Wave-35 audits flagged as a security gap.
//!
//! # Design
//!
//! ```text
//! Csprng {
//!     state: [u32; 16],          // ChaCha20 key-stream state (key + nonce + counter)
//!     key:   [u8; 32],           // Current 256-bit ChaCha20 key
//!     nonce: [u8; 12],           // 96-bit nonce (bytes 0..8 = boot entropy, 8..12 = 0)
//!     counter: u64,              // 64-bit block counter (split across state[12..13])
//!     bytes_since_reseed: usize, // bytes generated since last reseed
//! }
//! ```
//!
//! The pool is seeded from hardware entropy through `narf-crypto`'s
//! entropy surface — the tree has exactly one entropy truth, and it is
//! not probed privately here (issue #1026). Reseeding occurs
//! automatically after every `RESEED_THRESHOLD` bytes; on each reseed
//! another 32 bytes of hardware entropy are mixed in via XOR into the
//! key material.
//!
//! # Seed discipline — the floor (issue #1026)
//!
//! This module used to gather its own entropy: RDSEED → RDRAND →
//! cycle-counter TSC on x86_64, RNDRRS → RNDR → TSC on aarch64. The
//! cycle-counter tail was a silent security downgrade: on a machine
//! (or VM) without the RNG instructions, every userspace key — SSH/TLS
//! keys, tokens, nonces — drew from a predictable source, with one
//! warning log line as the only signal. The TSC gather is **deleted**;
//! no path in this module can seed the pool from a timing counter.
//!
//! A seed is now drawn by a three-class ladder — two architectural
//! rungs over `narf-crypto`, plus a host-provided rung for hardware
//! with no architectural source at all (issue #1074):
//!
//! 1. **Seed-grade** — `narf_crypto::try_fill_key_material`: RDSEED on
//!    x86_64, RNDR/RNDRRS on aarch64, every released byte covered by
//!    the SP 800-90B health tests of issue #996, fail-closed. This is
//!    the only class that can seed the pool when a seed-grade source
//!    is present: if the key-material surface refuses (source starved
//!    or health-latched off), the pool refuses too. The weaker draws
//!    are never consulted as a route around the health latch — on
//!    aarch64 the conditioned draw uses the very same instructions.
//! 2. **Conditioned** (x86_64 only) — when no seed-grade source exists
//!    but RDRAND does, the pool seeds through the protocol adapter
//!    `narf_crypto::try_fill_random_bytes`. RDRAND is a conditioned
//!    DRBG output, not an entropy source (crypto specification §6),
//!    and the crypto specification's own protocol adapter trusts it
//!    for protocol secrets (§3.2); the pool accepts it as a degraded
//!    class rather than bricking userspace randomness on RDRAND-only
//!    hardware. The class is never silent: it is recorded in
//!    [`seed_class`], announced on the kernel log when installed, and
//!    printed by the boot console line.
//! 3. **VirtioRng** — when no architectural source exists at all, but
//!    a virtio-rng device has been probed and registered a seed draw
//!    (see [`register_virtio_rng_source`]), the pool seeds from the
//!    host-provided bytes. This is a degraded class with a different
//!    trust story from either architectural rung: the host is in the
//!    entropy path, so the class is explicitly labelled everywhere
//!    the other classes are — [`seed_class`], the kernel log, the
//!    boot console line — and it is never permitted to seed key
//!    generation, which stays seed-grade-only. A present-but-refusing
//!    higher rung is terminal, exactly as for seed-grade: the virtio
//!    draw is never consulted to route around a starved or latched
//!    architectural source. It exists only for hardware with no
//!    architectural source, and only once the device has probed — a
//!    fill attempted before probe still refuses, and the next fill
//!    after probe seeds, because [`try_fill`] re-attempts seeding
//!    while unseeded.
//!
//! When no class is available the pool **stays unseeded** and
//! every cryptographic fill refuses (see "Blocking semantics"). A
//! failed *reseed* is different: the pool keeps serving from its
//! existing, properly seeded key — output never degrades — and the
//! failure is counted (see `PoolState::reseed_failures`) and retried
//! after a further slice of output.
//!
//! # Blocking semantics
//!
//! [`try_fill`] is the cryptographic fill. While the pool is unseeded
//! it returns `Err(CsprngError::EntropyUnavailable)`, and the ABI
//! consumers translate that to Linux's not-ready signal:
//!
//! - `getrandom(2)` returns `-EAGAIN`. Linux would park a blocking
//!   call until the CRNG initialises and `-EAGAIN` only a
//!   `GRND_NONBLOCK` one; NARF syscall handlers have no readiness
//!   source to park on, so both take `-EAGAIN` (the same failure mode
//!   the compat read paths use). `GRND_INSECURE` waives blocking, not
//!   provenance: it is served from the seeded pool like any other
//!   request and takes the same `-EAGAIN` while unseeded — there is
//!   no partial-entropy pool state to honour it with. On any machine
//!   with a hardware RNG the pool seeds at `Stage::Subsys` init, long
//!   before userspace runs, so the refusal window is "hardware with
//!   no RNG source", not "early boot".
//! - `/dev/random` and `/dev/urandom` reads fail with
//!   `FsError::WouldBlock` (`EAGAIN`), and `RNDGETENTCNT` plus
//!   `/proc/sys/kernel/random/entropy_avail` report the real pool
//!   state via [`entropy_avail_bits`] — 0 while unseeded — so
//!   userspace can observe readiness instead of guessing.
//!
//! `/dev/random` and `/dev/urandom` are **identical** post-5.18 Linux
//! semantics: both deliver CSPRNG bytes; neither blocks once the pool
//! is seeded.
//!
//! The legacy infallible [`fill`] remains for in-kernel,
//! non-cryptographic consumers whose contract cannot fail (the net
//! stack's IP-ID hook is installed as a bare `fn(&mut [u8])`). On
//! refusal it leaves the caller's buffer **unchanged** — visibly
//! absent output rather than silently predictable output. It must
//! never serve a cryptographic consumer; they all use [`try_fill`].
//!
//! # Thread safety
//!
//! The global pool is protected by an `IrqSafeSpinLock`. Each `fill`
//! call locks, generates bytes, and unlocks. Entropy draws (which may
//! spin in the RDSEED bounded-retry loop, and run the 90B startup
//! test on first use) are performed with the pool lock **dropped**,
//! exactly as the previous gather path did. This is safe from IRQ
//! context because ChaCha20 is pure computation.
//!
//! # Linux refs
//!
//! - `linux/drivers/char/random.c::extract_crng` — output path
//! - `linux/drivers/char/random.c::crng_reseed` — reseed discipline
//! - `linux/drivers/char/random.c::crng_init_one` — per-CPU init
//! - `linux/lib/crypto/chacha20.c` — ChaCha20 block function
//!
//! GPL-2.0-or-later — NARF is GPL-2.0-or-later as of 2026-05-20.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Reseed threshold ─────────────────────────────────────────────────────────
//
// Linux uses 32 MiB (CHACHA_KEY_SIZE * 1024 * 1024) before reseeding.
// NARF uses 1 MiB — conservative for an embedded/microkernel context where
// boot sessions are short and hardware entropy is abundant.
const RESEED_THRESHOLD: usize = 1024 * 1024; // 1 MiB

/// After a failed reseed the pool keeps serving from its current key
/// and does not retry until this much further output has been drawn —
/// a starved or latched source must not turn every fill into a
/// bounded-retry spin, but a transient failure must not brick
/// reseeding for the rest of the boot either.
const RESEED_RETRY_SLICE: usize = RESEED_THRESHOLD / 8;

// ── ChaCha20 constants ───────────────────────────────────────────────────────

/// "expand 32-byte k" — RFC 8439 §2.3
const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

// ── Inner CSPRNG state ───────────────────────────────────────────────────────

struct CsprngInner {
    /// ChaCha20 state: [constants(4), key(8), counter_lo, counter_hi, nonce(2)]
    /// Layout: state[12] = counter_lo u32, state[13] = counter_hi u32,
    ///         state[14..16] = nonce[0..8] as 2× u32.
    state: [u32; 16],
    /// Raw key bytes; kept so we can XOR in new entropy on reseed.
    key: [u8; 32],
    /// Raw nonce bytes (first 8 bytes from initial seed, last 4 = 0).
    nonce: [u8; 12],
    /// 64-bit block counter (spans state[12] + state[13]).
    counter: u64,
    /// Bytes generated since last (re)seed.
    bytes_since_reseed: usize,
    /// Keystream block buffer (one 64-byte ChaCha20 block).
    block_buf: [u8; 64],
    /// How many bytes of `block_buf` have been consumed already.
    block_pos: usize,
}

impl CsprngInner {
    /// Construct an un-seeded inner state.  `seed` must be called before
    /// any `fill` call produces meaningful output.
    const fn uninit() -> Self {
        Self {
            state: [0u32; 16],
            key: [0u8; 32],
            nonce: [0u8; 12],
            counter: 0,
            bytes_since_reseed: 0,
            block_buf: [0u8; 64],
            block_pos: 64, // force a block generation on first fill
        }
    }

    /// (Re)seed from a 32-byte entropy buffer.
    ///
    /// On initial seeding:  install key, derive nonce from the last 8 bytes
    /// of the entropy buffer. The counter starts at 0 (from `uninit`).
    ///
    /// On reseed: XOR the new entropy into the existing key (same discipline
    /// as Linux's `crng_reseed` — mix, don't replace) and re-derive nonce from
    /// the high 8 bytes.
    ///
    /// The block counter is **never reset here** — it only advances (via
    /// `advance_counter`) and wraps at 2^64. Resetting it on reseed would, if
    /// a reseed's fresh entropy happened to net no change to the key/nonce
    /// (e.g. a hardware source that momentarily returns zeros), replay the
    /// exact `(key, nonce, counter)` of a prior block and reproduce its
    /// keystream — a keystream-reuse flaw. Keeping the counter monotonic means
    /// post-reseed output can never collide with anything already emitted,
    /// regardless of entropy quality.
    fn seed(&mut self, entropy: &[u8; 32]) {
        // Mix new entropy into key via XOR.
        for (k, &e) in self.key.iter_mut().zip(entropy.iter()) {
            *k ^= e;
        }
        // Derive a fresh nonce from the last 8 bytes of the entropy buffer,
        // XOR'd with the existing nonce (mix rather than replace).
        for i in 0..8 {
            self.nonce[i] ^= entropy[24 + i];
        }
        // Bytes 8..12 of nonce stay 0 (the ChaCha20 RFC nonce model uses
        // a 96-bit nonce; we use the lower 64 bits for boot entropy and
        // leave the upper 32 bits as 0 to keep counter-in-state clean).
        self.bytes_since_reseed = 0;
        self.block_pos = 64; // invalidate buffer
        self.rebuild_state();
    }

    /// Rebuild the ChaCha20 state from key/nonce/counter.
    fn rebuild_state(&mut self) {
        // Constants.
        self.state[0] = SIGMA[0];
        self.state[1] = SIGMA[1];
        self.state[2] = SIGMA[2];
        self.state[3] = SIGMA[3];
        // Key (8 × u32 little-endian).
        for i in 0..8 {
            self.state[4 + i] = u32::from_le_bytes([
                self.key[i * 4],
                self.key[i * 4 + 1],
                self.key[i * 4 + 2],
                self.key[i * 4 + 3],
            ]);
        }
        // Counter (64-bit split across words 12 + 13, little-endian).
        self.state[12] = self.counter as u32;
        self.state[13] = (self.counter >> 32) as u32;
        // Nonce (words 14 + 15, 8 bytes total; last 4 bytes of nonce are 0).
        self.state[14] =
            u32::from_le_bytes([self.nonce[0], self.nonce[1], self.nonce[2], self.nonce[3]]);
        self.state[15] =
            u32::from_le_bytes([self.nonce[4], self.nonce[5], self.nonce[6], self.nonce[7]]);
    }

    /// Advance the counter and re-sync state words 12 + 13.
    fn advance_counter(&mut self) {
        self.counter = self.counter.wrapping_add(1);
        self.state[12] = self.counter as u32;
        self.state[13] = (self.counter >> 32) as u32;
    }

    /// Fill `buf` with CSPRNG bytes.
    fn fill(&mut self, buf: &mut [u8]) {
        let mut pos = 0;
        while pos < buf.len() {
            if self.block_pos >= 64 {
                chacha20_block(&self.state, &mut self.block_buf);
                self.advance_counter();
                self.block_pos = 0;
            }
            let avail = 64 - self.block_pos;
            let want = buf.len() - pos;
            let n = avail.min(want);
            buf[pos..pos + n].copy_from_slice(&self.block_buf[self.block_pos..self.block_pos + n]);
            pos += n;
            self.block_pos += n;
        }
        self.bytes_since_reseed += buf.len();
    }

    /// True iff the pool needs a reseed.
    fn needs_reseed(&self) -> bool {
        self.bytes_since_reseed >= RESEED_THRESHOLD
    }
}

// ── ChaCha20 block function ──────────────────────────────────────────────────
//
// Cleanroom implementation from RFC 8439. This remains a private copy
// rather than a re-export from narf-crypto: the pool is a persistent
// key + monotonic-counter stream with XOR-mix reseeding — a different
// state model from narf-crypto's fresh-seed-per-fill streams — and
// coupling the pool's state semantics to that API would blur both.
// The algorithm is identical to narf_crypto::chacha20::chacha20_block,
// verified by the same RFC 8439 test vectors in Wave 31.
//
// Reference: https://datatracker.ietf.org/doc/html/rfc8439#section-2.3

#[inline(always)]
fn qr(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

fn chacha20_block(state: &[u32; 16], out: &mut [u8; 64]) {
    let mut x = *state;
    for _ in 0..10 {
        // Column rounds.
        let (mut a, mut b, mut c, mut d) = (x[0], x[4], x[8], x[12]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[0] = a;
        x[4] = b;
        x[8] = c;
        x[12] = d;
        let (mut a, mut b, mut c, mut d) = (x[1], x[5], x[9], x[13]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[1] = a;
        x[5] = b;
        x[9] = c;
        x[13] = d;
        let (mut a, mut b, mut c, mut d) = (x[2], x[6], x[10], x[14]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[2] = a;
        x[6] = b;
        x[10] = c;
        x[14] = d;
        let (mut a, mut b, mut c, mut d) = (x[3], x[7], x[11], x[15]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[3] = a;
        x[7] = b;
        x[11] = c;
        x[15] = d;
        // Diagonal rounds.
        let (mut a, mut b, mut c, mut d) = (x[0], x[5], x[10], x[15]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[0] = a;
        x[5] = b;
        x[10] = c;
        x[15] = d;
        let (mut a, mut b, mut c, mut d) = (x[1], x[6], x[11], x[12]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[1] = a;
        x[6] = b;
        x[11] = c;
        x[12] = d;
        let (mut a, mut b, mut c, mut d) = (x[2], x[7], x[8], x[13]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[2] = a;
        x[7] = b;
        x[8] = c;
        x[13] = d;
        let (mut a, mut b, mut c, mut d) = (x[3], x[4], x[9], x[14]);
        qr(&mut a, &mut b, &mut c, &mut d);
        x[3] = a;
        x[4] = b;
        x[9] = c;
        x[14] = d;
    }
    for i in 0..16 {
        let val = x[i].wrapping_add(state[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
}

// ── Seed classes and the draw discipline ─────────────────────────────────────

/// The class of entropy the pool was seeded from.
///
/// The class is part of the pool's observable state ([`seed_class`]):
/// degradation is a fact userspace tooling and operators can query,
/// never a silent property of the bytes served.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SeedClass {
    /// Seeded from the seed-grade architectural source through
    /// `narf_crypto::try_fill_key_material` — RDSEED on x86_64,
    /// RNDR/RNDRRS on aarch64 — under the SP 800-90B health discipline
    /// of issue #996. The only class permitted to seed key generation
    /// anywhere in the tree.
    SeedGrade,
    /// x86_64 only: no seed-grade source exists, so the pool seeded
    /// from RDRAND through the protocol adapter
    /// `narf_crypto::try_fill_random_bytes`. RDRAND output is
    /// conditioned (crypto specification §6), not raw entropy; the
    /// class exists so RDRAND-only hardware still gets a real CSPRNG
    /// instead of a predictable one, and it is announced — kernel log
    /// at install, boot console line, and this queryable state — every
    /// time. A `SeedGrade` pool can never become `Conditioned`, and a
    /// `Conditioned` pool never claims to be `SeedGrade`.
    Conditioned,
    /// No architectural source exists, so the pool seeded from a
    /// registered virtio-rng device (VirtIO 1.2 §5.4, issue #1074).
    /// The bytes are host-provided: the host is in the entropy path,
    /// so the class is announced — kernel log at install, boot
    /// console line, and this queryable state — every time, and it
    /// is never permitted to seed key generation. A higher-class pool
    /// never downgrades to `VirtioRng`, and a `VirtioRng` pool never
    /// claims to be architectural.
    VirtioRng,
}

/// The pool could not produce bytes: it is unseeded and no seed could
/// be drawn (no hardware source, or the source starved, or the 90B
/// health tests latched it off). ABI consumers map this to `EAGAIN`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CsprngError {
    /// No seed-grade, conditioned, or registered virtio-rng entropy
    /// is available.
    EntropyUnavailable,
}

/// Whether the seed-grade architectural source is present on this CPU:
/// RDSEED on x86_64, the FEAT_RNG instructions (RNDR/RNDRRS) on
/// aarch64. Probed from the same `narf-arch` feature surface the
/// crypto crate's key-material path consults — presence only; the
/// seed-grade *trust* decision (startup test, continuous health
/// tests, latching) lives in `narf-crypto` and is not duplicated here.
fn seed_grade_present() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: CPUID is legal at CPL=0 for any leaf, and unsupported
        // leaves return zeros rather than faulting (the arch cpuid
        // contract); this probe runs in kernel context only.
        unsafe { narf_arch::x86_64::cpuid::Features::probe() }.rdseed
    }
    #[cfg(target_arch = "aarch64")]
    {
        narf_arch::aarch64::rndr::supported()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Whether the conditioned architectural source is present. Only
/// x86_64 has one distinct from its seed-grade source: RDRAND. On
/// aarch64 the protocol adapter draws RNDR/RNDRRS themselves, so
/// there is no separate conditioned class to fall back to.
fn conditioned_present() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: as for `seed_grade_present` — CPUID at CPL=0, kernel
        // context only.
        unsafe { narf_arch::x86_64::cpuid::Features::probe() }.rdrand
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// Draw one 32-byte seed under the class discipline.
///
/// - `current == Some(class)`: a reseed. The draw uses the SAME class
///   the pool was seeded with — reseeds preserve class and can never
///   downgrade (a seed-grade pool whose RDSEED latched off refuses
///   the reseed rather than quietly continuing on RDRAND).
/// - `current == None`: an initial seed. Seed-grade wins whenever it
///   is present, and its refusal is terminal: when a seed-grade
///   source exists but `try_fill_key_material` refuses (starved or
///   health-latched), the conditioned draw is NOT consulted — on
///   aarch64 it would draw the same latched instructions without the
///   health tests, and on x86_64 routing around a latched-off RDSEED
///   with RDRAND would defeat the latch. Only when no seed-grade
///   source exists at all may the conditioned draw seed the pool.
///   Only when no architectural source exists at all may the
///   registered virtio-rng draw seed the pool (issue #1074), as the
///   labelled `VirtioRng` class — never as a route around a refusing
///   higher rung.
fn obtain_seed(
    draws: SeedDraws<'_>,
    current: Option<SeedClass>,
) -> Result<([u8; 32], SeedClass), CsprngError> {
    let mut seed = [0u8; 32];
    let class = match current {
        Some(SeedClass::SeedGrade) => {
            (draws.key_material)(&mut seed)?;
            SeedClass::SeedGrade
        }
        Some(SeedClass::Conditioned) => {
            (draws.conditioned)(&mut seed)?;
            SeedClass::Conditioned
        }
        Some(SeedClass::VirtioRng) => {
            (draws.virtio)(&mut seed)?;
            SeedClass::VirtioRng
        }
        None => {
            if draws.seed_grade_present {
                (draws.key_material)(&mut seed)?;
                SeedClass::SeedGrade
            } else if draws.conditioned_present {
                (draws.conditioned)(&mut seed)?;
                SeedClass::Conditioned
            } else if draws.virtio_present {
                (draws.virtio)(&mut seed)?;
                SeedClass::VirtioRng
            } else {
                return Err(CsprngError::EntropyUnavailable);
            }
        }
    };
    Ok((seed, class))
}

/// Best-effort wipe of a local seed buffer once it has been installed
/// into the pool (volatile writes so the compiler cannot elide them).
fn wipe(seed: &mut [u8; 32]) {
    for byte in seed.iter_mut() {
        // SAFETY: `byte` points into the caller's live `[u8; 32]`
        // array; a volatile byte write to it is valid and cannot
        // race (the array is stack-local to the seed path).
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
}

/// The draws a seed attempt may consult, bundled so the seed path
/// stays under clippy's argument-count limit. Presence is separate
/// from the draw itself: a present-but-refusing source is terminal,
/// and an absent source's draw is never consulted.
struct SeedDraws<'a> {
    seed_grade_present: bool,
    conditioned_present: bool,
    virtio_present: bool,
    key_material: &'a mut dyn FnMut(&mut [u8; 32]) -> Result<(), CsprngError>,
    conditioned: &'a mut dyn FnMut(&mut [u8; 32]) -> Result<(), CsprngError>,
    virtio: &'a mut dyn FnMut(&mut [u8; 32]) -> Result<(), CsprngError>,
}

// ── Pool state ───────────────────────────────────────────────────────────────

/// The userspace CSPRNG pool: the ChaCha20 stream plus the seed-class
/// bookkeeping the floor discipline needs.
struct PoolState {
    inner: CsprngInner,
    /// Class of the installed seed; `None` while the pool has never
    /// been seeded this boot.
    class: Option<SeedClass>,
    /// Reseed draws that failed since the last successful (re)seed.
    /// Non-zero means "serving from an older key than the reseed
    /// schedule wants" — counted, never silent (the first failure is
    /// also kernel-logged).
    reseed_failures: u32,
    /// `inner.bytes_since_reseed` value at which a failed reseed may
    /// be retried.
    reseed_blocked_until: usize,
}

impl PoolState {
    const fn uninit() -> Self {
        Self {
            inner: CsprngInner::uninit(),
            class: None,
            reseed_failures: 0,
            reseed_blocked_until: 0,
        }
    }

    /// A reseed is due when the byte threshold is reached and a
    /// previously failed attempt's retry slice has elapsed.
    fn reseed_due(&self) -> bool {
        self.inner.needs_reseed() && self.inner.bytes_since_reseed >= self.reseed_blocked_until
    }

    /// Install a freshly drawn seed (initial seed or reseed mix).
    fn install(&mut self, seed: &[u8; 32], class: SeedClass) {
        self.inner.seed(seed);
        self.class = Some(class);
        self.reseed_failures = 0;
        self.reseed_blocked_until = 0;
    }

    /// Record a failed reseed draw against a live pool: the pool
    /// keeps serving from its existing key, and the next attempt is
    /// deferred by one retry slice.
    fn note_reseed_failure(&mut self) {
        self.reseed_failures = self.reseed_failures.saturating_add(1);
        self.reseed_blocked_until = self
            .inner
            .bytes_since_reseed
            .saturating_add(RESEED_RETRY_SLICE);
    }
}

/// Seed (or reseed) a pool from scripted draws — the deterministic
/// seam the source-selection fixtures drive. Returns the pool's class
/// after the attempt. A failed draw against an already-seeded pool is
/// NOT an error: the pool keeps its class and its key, the failure is
/// counted, and `Ok(class)` reports that the pool remains serviceable.
/// A failed draw against an unseeded pool is `Err`.
fn seed_pool(state: &mut PoolState, draws: SeedDraws<'_>) -> Result<SeedClass, CsprngError> {
    match obtain_seed(draws, state.class) {
        Ok((mut seed, class)) => {
            state.install(&seed, class);
            wipe(&mut seed);
            Ok(class)
        }
        Err(e) => match state.class {
            Some(class) => {
                state.note_reseed_failure();
                Ok(class)
            }
            None => Err(e),
        },
    }
}

/// Fill `buf` from a pool, seeding/reseeding from scripted draws as
/// needed. Mirrors the global [`try_fill`] discipline exactly.
fn fill_pool(
    state: &mut PoolState,
    draws: SeedDraws<'_>,
    buf: &mut [u8],
) -> Result<(), CsprngError> {
    if buf.is_empty() {
        return Ok(());
    }
    if state.class.is_none() || state.reseed_due() {
        seed_pool(state, draws)?;
    }
    state.inner.fill(buf);
    Ok(())
}

// ── Global pool ──────────────────────────────────────────────────────────────

static POOL: IrqSafeSpinLock<PoolState> = IrqSafeSpinLock::new(PoolState::uninit());

/// `true` after the pool's first seed; part of filesystem's public
/// contract (kernel-test assertions read it directly). The pool never
/// un-seeds: once set, the flag stays set for the boot.
pub static CSPRNG_SEEDED: AtomicBool = AtomicBool::new(false);

/// Encoding of the pool's [`SeedClass`] for lock-free readers:
/// 0 = unseeded, 1 = seed-grade, 2 = conditioned, 3 = virtio-rng.
static SEED_CLASS_CODE: AtomicU8 = AtomicU8::new(0);

/// One-shot guard for the unseeded-refusal kernel-log line: the
/// refusal is logged once per boot (plus once after each successful
/// seed that a later latch could follow), not once per failed fill.
static REFUSAL_LOGGED: AtomicBool = AtomicBool::new(false);

/// One-shot guard for the reseed-failure kernel-log line.
static RESEED_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);

// ── Entropy source tracking ──────────────────────────────────────────────────

/// Which hardware entropy instruction the pool's seed class draws
/// from — retained for boot diagnostics and kernel tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntropySource {
    /// x86_64 RDSEED instruction.
    Rdseed,
    /// x86_64 RDRAND instruction.
    Rdrand,
    /// aarch64 FEAT_RNG RNDRRS instruction.
    Rndrrs,
    /// aarch64 FEAT_RNG RNDR instruction.
    Rndr,
    /// Host-provided entropy via a registered virtio-rng device
    /// (VirtIO 1.2 §5.4). Not an architectural instruction: the
    /// host is in the entropy path.
    VirtioRng,
}

/// Atomic encoding of the last entropy source used (255 = none yet).
static LAST_SOURCE: AtomicU8 = AtomicU8::new(255);

/// The instruction a seed class draws on this architecture. The
/// crypto surface deliberately does not say WHICH of RNDR/RNDRRS a
/// draw used, so the seed-grade class records `Rndrrs` on aarch64 —
/// the reseeding variant #996 prefers — as representative.
fn source_of(class: SeedClass) -> EntropySource {
    match class {
        SeedClass::SeedGrade => {
            if cfg!(target_arch = "x86_64") {
                EntropySource::Rdseed
            } else {
                EntropySource::Rndrrs
            }
        }
        SeedClass::Conditioned => EntropySource::Rdrand,
        SeedClass::VirtioRng => EntropySource::VirtioRng,
    }
}

fn record_source(src: EntropySource) {
    let val: u8 = match src {
        EntropySource::Rdseed => 0,
        EntropySource::Rdrand => 1,
        EntropySource::Rndrrs => 2,
        EntropySource::Rndr => 3,
        EntropySource::VirtioRng => 4,
    };
    LAST_SOURCE.store(val, Ordering::Release);
}

/// The entropy source the pool's seed came from, or `None` if the
/// pool has not been seeded yet this boot.
pub fn last_entropy_source() -> Option<EntropySource> {
    match LAST_SOURCE.load(Ordering::Acquire) {
        0 => Some(EntropySource::Rdseed),
        1 => Some(EntropySource::Rdrand),
        2 => Some(EntropySource::Rndrrs),
        3 => Some(EntropySource::Rndr),
        4 => Some(EntropySource::VirtioRng),
        _ => None,
    }
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Whether the pool has been seeded this boot.
pub fn is_seeded() -> bool {
    CSPRNG_SEEDED.load(Ordering::Acquire)
}

/// The class of the pool's seed, or `None` while unseeded. This is
/// the userspace-observable distinction the #1026 floor requires:
/// degraded service is a queryable fact, not a silent property.
pub fn seed_class() -> Option<SeedClass> {
    match SEED_CLASS_CODE.load(Ordering::Acquire) {
        1 => Some(SeedClass::SeedGrade),
        2 => Some(SeedClass::Conditioned),
        3 => Some(SeedClass::VirtioRng),
        _ => None,
    }
}

/// Bits of entropy userspace readiness queries report
/// (`RNDGETENTCNT`, `/proc/sys/kernel/random/entropy_avail`): the
/// full 4096-bit pool size once seeded, 0 while unseeded — the real
/// pool state, replacing the constants those interfaces used to
/// fabricate.
pub fn entropy_avail_bits() -> u32 {
    if is_seeded() {
        4096
    } else {
        0
    }
}

fn log_refusal_once() {
    if !REFUSAL_LOGGED.swap(true, Ordering::AcqRel) {
        narf_console::klog::record(
            "csprng: no usable hardware entropy source - pool NOT seeded; \
             getrandom(2) and /dev/random reads will fail EAGAIN (#1026)",
        );
    }
}

fn log_reseed_failure_once() {
    if !RESEED_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        narf_console::klog::record(
            "csprng: entropy reseed draw failed - continuing on the existing \
             pool key (#1026)",
        );
    }
}

/// Publish a successfully installed seed class to the lock-free
/// observers, announcing a first-time degraded seed on the kernel
/// log (conditioned or virtio-rng).
fn publish_class(class: SeedClass) {
    let code = match class {
        SeedClass::SeedGrade => 1,
        SeedClass::Conditioned => 2,
        SeedClass::VirtioRng => 3,
    };
    let previous = SEED_CLASS_CODE.swap(code, Ordering::AcqRel);
    CSPRNG_SEEDED.store(true, Ordering::Release);
    record_source(source_of(class));
    if class == SeedClass::Conditioned && previous == 0 {
        narf_console::klog::record(
            "csprng: WARNING - no seed-grade entropy source; pool seeded from \
             RDRAND conditioned output (DEGRADED class, #1026)",
        );
    }
    if class == SeedClass::VirtioRng && previous == 0 {
        narf_console::klog::record(
            "csprng: WARNING - no architectural entropy source; pool seeded \
             from host-provided virtio-rng entropy (DEGRADED class, #1074)",
        );
    }
}

// ── Virtio-rng seed draw registration ────────────────────────────────────────

/// A seed draw supplied by a probed virtio-rng device: fills a full
/// 32-byte seed or fails. The driver registers exactly one draw (its
/// controller is a singleton); the fill runs with no pool lock held,
/// so the device conversation cannot deadlock against the pool.
pub type VirtioRngFill = fn(&mut [u8; 32]) -> Result<(), CsprngError>;

/// The registered virtio-rng draw, if any device has probed.
static VIRTIO_SOURCE: IrqSafeSpinLock<Option<VirtioRngFill>> = IrqSafeSpinLock::new(None);

/// Register a virtio-rng seed draw. First-wins: a second device (the
/// driver probes at most one controller) must not silently replace
/// the source the pool may already have seeded from.
pub fn register_virtio_rng_source(fill: VirtioRngFill) {
    let mut slot = VIRTIO_SOURCE.lock();
    if slot.is_none() {
        *slot = Some(fill);
    }
}

/// Whether a virtio-rng device has registered a seed draw. Presence
/// is what the ladder consults — the draw itself runs only when the
/// ladder reaches the virtio rung.
pub fn virtio_rng_source_present() -> bool {
    VIRTIO_SOURCE.lock().is_some()
}

/// Test-only setter for the registered virtio-rng draw, mirroring
/// [`__test_unseed`]: kernel-test smokes install a fake draw and
/// clear it at the end of the test. Production code never calls this.
#[doc(hidden)]
pub fn __test_set_virtio_rng_source(source: Option<VirtioRngFill>) {
    *VIRTIO_SOURCE.lock() = source;
}

/// One seed attempt against the global pool, drawing through
/// `narf-crypto` with the pool lock dropped (the draw may spin in the
/// RDSEED bounded-retry loop and runs the 90B startup test on first
/// use). Mirrors [`seed_pool`]'s discipline: `Err` only when the pool
/// is unseeded and unseedable.
fn global_seed_attempt() -> Result<SeedClass, CsprngError> {
    let current = POOL.lock().class;
    let mut key_material = |buf: &mut [u8; 32]| {
        narf_crypto::try_fill_key_material(buf).map_err(|_| CsprngError::EntropyUnavailable)
    };
    let mut conditioned = |buf: &mut [u8; 32]| {
        narf_crypto::try_fill_random_bytes(buf).map_err(|_| CsprngError::EntropyUnavailable)
    };
    // The registered draw is read out of its lock before the draw
    // runs, so no lock is held across the device conversation.
    let registered = *VIRTIO_SOURCE.lock();
    let mut virtio = |buf: &mut [u8; 32]| match registered {
        Some(fill) => fill(buf),
        None => Err(CsprngError::EntropyUnavailable),
    };
    let draws = SeedDraws {
        seed_grade_present: seed_grade_present(),
        conditioned_present: conditioned_present(),
        virtio_present: virtio_rng_source_present(),
        key_material: &mut key_material,
        conditioned: &mut conditioned,
        virtio: &mut virtio,
    };
    match obtain_seed(draws, current) {
        Ok((mut seed, class)) => {
            POOL.lock().install(&seed, class);
            wipe(&mut seed);
            publish_class(class);
            Ok(class)
        }
        Err(e) => {
            let mut pool = POOL.lock();
            match pool.class {
                Some(class) => {
                    pool.note_reseed_failure();
                    drop(pool);
                    log_reseed_failure_once();
                    Ok(class)
                }
                None => {
                    drop(pool);
                    log_refusal_once();
                    Err(e)
                }
            }
        }
    }
}

/// Attempt to (re-)seed the pool, called once per boot from
/// `frame`'s Stage::Subsys initcall and again by kernel tests.
///
/// The outcome is observable via [`seed_class`] /
/// [`last_entropy_source`] and is announced by the seed path itself
/// (kernel log + the boot console line): on entropy-less hardware the
/// pool stays unseeded and fills refuse with `EAGAIN` semantics
/// rather than serving predictable bytes.
pub fn init_csprng() {
    let _ = global_seed_attempt();
}

/// Seed the pool (synchronously) if it is not already seeded, then
/// fill `buf` with CSPRNG bytes.
///
/// This is the ONLY fill cryptographic consumers may use:
/// `getrandom(2)`, `/dev/random`, `/dev/urandom`, and the ELF
/// `AT_RANDOM` aux vector. Returns
/// `Err(CsprngError::EntropyUnavailable)` — writing nothing — while
/// the pool is unseeded. See the module docs for the seed-class
/// discipline and the per-ABI refusal mapping.
pub fn try_fill(buf: &mut [u8]) -> Result<(), CsprngError> {
    if buf.is_empty() {
        return Ok(());
    }
    if !is_seeded() || POOL.lock().reseed_due() {
        global_seed_attempt()?;
    }
    POOL.lock().inner.fill(buf);
    Ok(())
}

/// Fill `buf` with CSPRNG bytes, for in-kernel **non-cryptographic**
/// consumers whose contract cannot fail — today the net stack's IP-ID
/// random hook, installed as a bare `fn(&mut [u8])`.
///
/// If the pool is unseeded and cannot be seeded, `buf` is left
/// **unchanged** (the refusal itself is kernel-logged once by the
/// seed path). Callers that need bytes with any provenance guarantee
/// must use [`try_fill`] and handle its refusal.
pub fn fill(buf: &mut [u8]) {
    let _ = try_fill(buf);
}

/// Reset the pool to the un-seeded state — test support only, used by
/// the kernel-test end-to-end smokes to exercise the seed-on-demand
/// and refusal paths from a known state.
#[doc(hidden)]
pub fn __test_unseed() {
    *POOL.lock() = PoolState::uninit();
    CSPRNG_SEEDED.store(false, Ordering::Release);
    SEED_CLASS_CODE.store(0, Ordering::Release);
    LAST_SOURCE.store(255, Ordering::Release);
    REFUSAL_LOGGED.store(false, Ordering::Release);
    RESEED_FAILURE_LOGGED.store(false, Ordering::Release);
}

// ── Tests ────────────────────────────────────────────────────────────

#[path = "csprng_tests.rs"]
mod tests;
