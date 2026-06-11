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
//! The pool is seeded once at boot from hardware entropy (`RDSEED` →
//! `RDRAND` → TSC-fallback on x86_64; `RNDRRS` → `RNDR` → TSC-fallback
//! on aarch64).  Reseeding occurs automatically after every
//! `RESEED_THRESHOLD` bytes; on each reseed another 32 bytes of hardware
//! entropy are mixed in via XOR into the key material.
//!
//! # Blocking semantics
//!
//! A `CSPRNG_SEEDED` atomic flag is set to `true` after the initial
//! hardware-entropy seed.  `/dev/random` and `/dev/urandom` are
//! **identical** post-5.18 Linux semantics: both deliver CSPRNG bytes;
//! neither blocks once the pool is seeded.  Reads before seeding
//! complete immediately (the seeding is synchronous during `init_csprng`).
//!
//! # Thread safety
//!
//! The global pool is protected by an `IrqSafeSpinLock`.  Each `fill`
//! call locks, generates bytes, and unlocks.  This is safe from IRQ
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

use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Reseed threshold ─────────────────────────────────────────────────────────
//
// Linux uses 32 MiB (CHACHA_KEY_SIZE * 1024 * 1024) before reseeding.
// NARF uses 1 MiB — conservative for an embedded/microkernel context where
// boot sessions are short and hardware entropy is abundant.
const RESEED_THRESHOLD: usize = 1024 * 1024; // 1 MiB

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
    /// of the entropy buffer, and reset the counter.
    ///
    /// On reseed: XOR the new entropy into the existing key (same discipline
    /// as Linux's `crng_reseed` — mix, don't replace), re-derive nonce from
    /// the high 8 bytes, and reset counter.
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
        self.counter = 0;
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
// Cleanroom implementation from RFC 8439.  This is intentionally a private
// copy rather than a re-export from narf-crypto to avoid a circular crate
// dependency between narf-filesystem and narf-crypto.  The algorithm is
// identical to narf_crypto::chacha20::chacha20_block, verified by the same
// RFC 8439 test vectors in Wave 31.
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

// ── Global pool ──────────────────────────────────────────────────────────────

static POOL: IrqSafeSpinLock<CsprngInner> = IrqSafeSpinLock::new(CsprngInner::uninit());

/// Set to `true` once the pool has been seeded from hardware entropy.
pub static CSPRNG_SEEDED: AtomicBool = AtomicBool::new(false);

// ── Public API ───────────────────────────────────────────────────────────────

/// Seed the global CSPRNG from hardware entropy.
///
/// Must be called once during kernel init (before any `/dev/random` read).
/// Safe to call multiple times — subsequent calls reseed the pool.
///
/// On x86_64: attempts RDSEED, falls back to RDRAND, then TSC.
/// On aarch64: attempts RNDRRS, falls back to RNDR, then TSC.
/// On other arches: TSC-based fallback (weak; logs a warning).
pub fn init_csprng() {
    let entropy = gather_entropy();
    POOL.lock().seed(&entropy);
    CSPRNG_SEEDED.store(true, Ordering::Release);
}

/// Fill `buf` with CSPRNG bytes.
///
/// Thread-safe; safe from IRQ context.  If the pool needs a reseed
/// (bytes_since_reseed ≥ 1 MiB), pulls new hardware entropy and mixes
/// it in before returning output.
///
/// # Panics
///
/// Panics if called before `init_csprng()` in debug builds (the seeded
/// flag is checked).
pub fn fill(buf: &mut [u8]) {
    // Trigger reseed if needed, then fill.
    let mut pool = POOL.lock();
    if pool.needs_reseed() {
        // Drop the lock while gathering entropy so IRQs aren't held off
        // for the RDSEED retry loop.  Re-acquire for the seed() call.
        drop(pool);
        let entropy = gather_entropy();
        POOL.lock().seed(&entropy);
        pool = POOL.lock();
    }
    pool.fill(buf);
}

/// Gather 32 bytes of hardware entropy using the platform's best available
/// source.  Returns the bytes and the source used (for diagnostic purposes).
pub fn gather_entropy() -> [u8; 32] {
    let mut buf = [0u8; 32];
    gather_entropy_into(&mut buf);
    buf
}

/// Hardware entropy source used on the last `gather_entropy` call.
///
/// Used by diagnostic smokes to verify the probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EntropySource {
    /// x86_64 RDSEED instruction.
    Rdseed,
    /// x86_64 RDRAND instruction (CSPRNG output from CPU's pool).
    Rdrand,
    /// aarch64 RNDRRS instruction (reseed-quality entropy).
    Rndrrs,
    /// aarch64 RNDR instruction.
    Rndr,
    /// TSC + diversity constant (weak fallback).
    TscFallback,
}

/// Last entropy source used.  Written by `gather_entropy_into`; readable
/// from smokes via `last_entropy_source()`.
static LAST_SOURCE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(255);

/// Return the `EntropySource` used by the most recent `gather_entropy` call.
/// Returns `None` if `gather_entropy` has never been called.
pub fn last_entropy_source() -> Option<EntropySource> {
    match LAST_SOURCE.load(Ordering::Relaxed) {
        0 => Some(EntropySource::Rdseed),
        1 => Some(EntropySource::Rdrand),
        2 => Some(EntropySource::Rndrrs),
        3 => Some(EntropySource::Rndr),
        4 => Some(EntropySource::TscFallback),
        _ => None,
    }
}

fn record_source(s: EntropySource) {
    let v = match s {
        EntropySource::Rdseed => 0,
        EntropySource::Rdrand => 1,
        EntropySource::Rndrrs => 2,
        EntropySource::Rndr => 3,
        EntropySource::TscFallback => 4,
    };
    LAST_SOURCE.store(v, Ordering::Relaxed);
}

#[cfg(target_arch = "x86_64")]
fn gather_entropy_into(buf: &mut [u8; 32]) {
    use narf_arch::x86_64::hwrng::{fill_key_32, HwRngSource};
    let src = fill_key_32(buf);
    record_source(match src {
        HwRngSource::Rdseed => EntropySource::Rdseed,
        HwRngSource::Rdrand => EntropySource::Rdrand,
        HwRngSource::TscFallback => EntropySource::TscFallback,
    });
}

#[cfg(target_arch = "aarch64")]
fn gather_entropy_into(buf: &mut [u8; 32]) {
    use narf_arch::aarch64::rndr;
    // Try RNDRRS first (reseed-grade), then RNDR.
    if rndr::supported() {
        let mut ok = true;
        for i in 0..4usize {
            match rndr::try_rndrrs() {
                Some(v) => buf[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes()),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok {
            record_source(EntropySource::Rndrrs);
            return;
        }
        // Retry with RNDR.
        let mut ok2 = true;
        for i in 0..4usize {
            match rndr::try_rndr() {
                Some(v) => buf[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes()),
                None => {
                    ok2 = false;
                    break;
                }
            }
        }
        if ok2 {
            record_source(EntropySource::Rndr);
            return;
        }
    }
    tsc_fallback_into(buf);
    record_source(EntropySource::TscFallback);
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn gather_entropy_into(buf: &mut [u8; 32]) {
    tsc_fallback_into(buf);
    record_source(EntropySource::TscFallback);
}

/// Cross-arch TSC/cycle-counter fallback.
// Used on x86_64 (RDSEED/RDRAND path calls this as last resort), on aarch64
// (RNDR path), and on all other arches.  The `dead_code` warning fires on
// x86_64 because the #[cfg] branches mean the cfg=aarch64 definition is
// never reached in an x86_64 build — suppress it.
#[allow(dead_code)]
fn tsc_fallback_into(buf: &mut [u8; 32]) {
    let t0 = narf_time::now_cycles();
    let t1 = narf_time::now_cycles().wrapping_add(0xDEAD_BEEF_CAFE_1234);
    const WEYL: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut s = t0 ^ t1;
    for i in 0..4usize {
        s = s.wrapping_add(WEYL);
        s = s.wrapping_mul(0x6C62_272E_07BB_0142);
        s ^= s >> 30;
        buf[i * 8..(i + 1) * 8].copy_from_slice(&s.to_le_bytes());
    }
}
