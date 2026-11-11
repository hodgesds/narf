//! Per-arch IRQ vector allocator.
//!
//! x86_64: hands out IDT vectors in `48..=239`, except 128 (32–47 are
//!   reserved for legacy IRQ-stub layout, 128 is the `int 0x80` gate,
//!   0xF0 and up are fixed IPI / error / spurious vectors). The
//!   returned u8 is the LAPIC delivery vector, which doubles as the
//!   dispatch-table slot index.
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
#[cfg(target_arch = "x86_64")]
pub const ALLOC_MAX: u8 = 239;
#[cfg(not(target_arch = "x86_64"))]
pub const ALLOC_MAX: u8 = 240;

/// The x86 `int 0x80` gate. The trap path treats this vector as a system
/// call before it looks at interrupts, so a device interrupt delivered on
/// it would run a bogus syscall and never be acknowledged.
#[cfg(target_arch = "x86_64")]
pub const SYSCALL_VECTOR: u8 = 128;

/// `true` for vectors the allocator may hand to a device. On x86_64 the
/// range stops below the fixed IPI vectors (`VECTOR_TLB_SHOOTDOWN` = 0xF0
/// and up) and excludes the `int 0x80` gate.
pub const fn allocatable(vector: u8) -> bool {
    #[cfg(target_arch = "x86_64")]
    if vector == SYSCALL_VECTOR {
        return false;
    }
    // On aarch64 ALLOC_BASE is 0 (the u8 minimum), so the lower bound is
    // vacuous there — keep it x86-only instead of comparing against the
    // type minimum, which clippy rightly flags as always true.
    #[cfg(target_arch = "x86_64")]
    if vector < ALLOC_BASE {
        return false;
    }
    vector <= ALLOC_MAX
}

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
    let bit = 1u64 << (vector & 0x3F);
    (word, bit)
}

/// A newly allocated vector starts enabled, whatever its previous owner left.
/// Linux's `irq_startup` resets `desc->depth` to 0 when a new owner requests
/// the line, so a `disable_irq` before `free_irq` never reaches the next
/// owner. Here a teardown that soft-masks its vector and then frees it would
/// otherwise hand the next owner a vector `on_irq` silently drops.
fn start_enabled(vector: u8) {
    crate::dispatch::enable_irq(vector);
}

/// Reserve and return a free vector in `ALLOC_BASE..=ALLOC_MAX`.
/// Linear scan; collisions are CAS-resolved.
pub fn alloc() -> Result<u8, VectorError> {
    for v in ALLOC_BASE..=ALLOC_MAX {
        if !allocatable(v) {
            continue;
        }
        let (w, bit) = split(v);
        // Try to flip 0 → 1 atomically.
        let mut cur = USED[w].load(Ordering::Relaxed);
        loop {
            if cur & bit != 0 {
                break;
            }
            match USED[w].compare_exchange_weak(cur, cur | bit, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    start_enabled(v);
                    return Ok(v);
                }
                Err(actual) => cur = actual,
            }
        }
    }
    Err(VectorError::Exhausted)
}

/// Reserve one specific vector — the dispatch slot of a fixed-INTID
/// interrupt (an aarch64 SPI dispatches on `intid & 0xFF`), so no
/// [`alloc`] caller (MSI / LPI) can be handed the same slot.
/// `AlreadyFree` is never returned; a taken vector is `Exhausted`.
pub fn reserve(vector: u8) -> Result<(), VectorError> {
    if !allocatable(vector) {
        return Err(VectorError::OutOfRange);
    }
    let (w, bit) = split(vector);
    let prev = USED[w].fetch_or(bit, Ordering::AcqRel);
    if prev & bit != 0 {
        return Err(VectorError::Exhausted);
    }
    start_enabled(vector);
    Ok(())
}

/// Reserve `n` *contiguous* vectors. Useful for MSI / per-CPU MSI-X
/// where the device fires consecutive vectors. Returns the base
/// vector; the reserved range is `[base, base + n)`. All-or-nothing
/// — partial reservations are rolled back on failure.
pub fn alloc_block(n: u8) -> Result<u8, VectorError> {
    alloc_block_aligned(n, 1)
}

/// Reserve `n` contiguous vectors whose base is a multiple of `align`
/// (a power of two). Multi-message MSI needs this: the function
/// substitutes the vector index into the low `log2(n)` bits of the
/// Message Data (PCIe base 5.0 §6.1.4.3), so the base vector's low
/// bits must be zero — Linux's x86 vector domain enforces the same
/// for multi-MSI. `OutOfRange` for `n == 0` or a non-power-of-two
/// `align`; `Exhausted` when no aligned run is free.
pub fn alloc_block_aligned(n: u8, align: u8) -> Result<u8, VectorError> {
    if n == 0 || align == 0 || !align.is_power_of_two() {
        return Err(VectorError::OutOfRange);
    }
    let align = align as u16;
    let first = (ALLOC_BASE as u16).div_ceil(align) * align;
    let Some(last_start) = (ALLOC_MAX as u16 + 1).checked_sub(n as u16) else {
        return Err(VectorError::Exhausted);
    };
    let mut base16 = first;
    'outer: while base16 <= last_start {
        let base = base16 as u8;
        base16 += align;
        // Speculatively flip every bit in [base, base+n). If any
        // flip fails (already allocated), roll back the prior ones
        // and try the next base.
        let mut owned: u8 = 0;
        for i in 0..n {
            let v = base + i;
            if !allocatable(v) {
                for j in 0..owned {
                    let (rw, rbit) = split(base + j);
                    USED[rw].fetch_and(!rbit, Ordering::AcqRel);
                }
                continue 'outer;
            }
            let (w, bit) = split(v);
            let mut cur = USED[w].load(Ordering::Relaxed);
            let mut acquired = false;
            loop {
                if cur & bit != 0 {
                    break;
                }
                match USED[w].compare_exchange_weak(
                    cur,
                    cur | bit,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        acquired = true;
                        break;
                    }
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
        for i in 0..n {
            start_enabled(base + i);
        }
        return Ok(base);
    }
    Err(VectorError::Exhausted)
}

/// Release a previously-allocated vector. `AlreadyFree` if the bit
/// wasn't set — points at a double-free in caller code.
pub fn free(vector: u8) -> Result<(), VectorError> {
    if !allocatable(vector) {
        return Err(VectorError::OutOfRange);
    }
    let (w, bit) = split(vector);
    let prev = USED[w].fetch_and(!bit, Ordering::AcqRel);
    if prev & bit == 0 {
        Err(VectorError::AlreadyFree)
    } else {
        Ok(())
    }
}

/// `true` if `vector` is currently allocated. Test-only helper; production
/// code holds its allocator state in driver structs and shouldn't poll
/// the bitmap directly.
#[doc(hidden)]
pub fn is_allocated(vector: u8) -> bool {
    let (w, bit) = split(vector);
    USED[w].load(Ordering::Acquire) & bit != 0
}
