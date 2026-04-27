//! Per-arch IRQ vector allocator.
//!
//! x86_64: hands out IDT vectors in `48..=240` (32–47 are reserved
//!   for legacy IRQ-stub layout, 0xFE/0xFF for spurious + self-IPI
//!   conventions). The returned u8 is the LAPIC delivery vector,
//!   which doubles as the dispatch-table slot index.
//! aarch64: hands out logical-IRQ slots in `0..=240` that the ITS
//!   layer multiplexes onto LPI INTIDs (INTID = LPI_BASE + slot).
//!   Stage-3 caps total at 240 — well above any plausible Stage-3
//!   driver count.
//!
//! Backed by a 256-bit bitmap (4 × `AtomicU64`). `alloc` does a
//! linear scan with `compare_exchange`; collisions are rare in
//! practice (driver-bring-up is sequenced).

use core::sync::atomic::{AtomicU64, Ordering};

/// First allocatable vector. Below this, vectors are reserved by
/// per-arch convention (legacy IRQ stubs, spurious vector, IPIs).
#[cfg(target_arch = "x86_64")]
pub const ALLOC_BASE: u8 = 48;
#[cfg(not(target_arch = "x86_64"))]
pub const ALLOC_BASE: u8 = 0;

/// Last allocatable vector (inclusive).
pub const ALLOC_MAX: u8 = 240;

/// Why an alloc failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VectorError {
    Exhausted,
    OutOfRange,
    AlreadyFree,
}

/// 256-bit bitmap, one word per 64 vectors. Bit set = allocated.
static USED: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[inline]
fn split(vector: u8) -> (usize, u64) {
    let word = (vector as usize) >> 6;
    let bit  = 1u64 << (vector & 0x3F);
    (word, bit)
}

/// Reserve and return a free vector in `ALLOC_BASE..=ALLOC_MAX`.
/// Linear scan; collisions are CAS-resolved.
pub fn alloc() -> Result<u8, VectorError> {
    for v in ALLOC_BASE..=ALLOC_MAX {
        let (w, bit) = split(v);
        // Try to flip 0 → 1 atomically.
        let mut cur = USED[w].load(Ordering::Relaxed);
        loop {
            if cur & bit != 0 { break; }
            match USED[w].compare_exchange_weak(
                cur, cur | bit, Ordering::AcqRel, Ordering::Relaxed,
            ) {
                Ok(_)   => return Ok(v),
                Err(actual) => cur = actual,
            }
        }
    }
    Err(VectorError::Exhausted)
}

/// Reserve `n` *contiguous* vectors. Useful for MSI / per-CPU MSI-X
/// where the device fires consecutive vectors. Returns the base
/// vector; the reserved range is `[base, base + n)`. All-or-nothing
/// — partial reservations are rolled back on failure.
pub fn alloc_block(n: u8) -> Result<u8, VectorError> {
    if n == 0 { return Err(VectorError::OutOfRange); }
    let last_start = ALLOC_MAX.saturating_sub(n - 1);
    'outer: for base in ALLOC_BASE..=last_start {
        // Speculatively flip every bit in [base, base+n). If any
        // flip fails (already allocated), roll back the prior ones
        // and try the next base.
        let mut owned: u8 = 0;
        for i in 0..n {
            let v = base + i;
            let (w, bit) = split(v);
            let mut cur = USED[w].load(Ordering::Relaxed);
            let mut acquired = false;
            loop {
                if cur & bit != 0 { break; }
                match USED[w].compare_exchange_weak(
                    cur, cur | bit, Ordering::AcqRel, Ordering::Relaxed,
                ) {
                    Ok(_)       => { acquired = true; break; }
                    Err(actual) => cur = actual,
                }
            }
            if !acquired {
                // Rollback the prior i acquisitions.
                for j in 0..owned {
                    let (rw, rbit) = split(base + j);
                    USED[rw].fetch_and(!rbit, Ordering::AcqRel);
                }
                continue 'outer;
            }
            owned += 1;
        }
        return Ok(base);
    }
    Err(VectorError::Exhausted)
}

/// Release a previously-allocated vector. `AlreadyFree` if the bit
/// wasn't set — points at a double-free in caller code.
pub fn free(vector: u8) -> Result<(), VectorError> {
    if vector < ALLOC_BASE || vector > ALLOC_MAX {
        return Err(VectorError::OutOfRange);
    }
    let (w, bit) = split(vector);
    let prev = USED[w].fetch_and(!bit, Ordering::AcqRel);
    if prev & bit == 0 { Err(VectorError::AlreadyFree) } else { Ok(()) }
}

/// `true` if `vector` is currently allocated. Test-only helper; production
/// code holds its allocator state in driver structs and shouldn't poll
/// the bitmap directly.
#[doc(hidden)]
pub fn is_allocated(vector: u8) -> bool {
    let (w, bit) = split(vector);
    USED[w].load(Ordering::Acquire) & bit != 0
}
