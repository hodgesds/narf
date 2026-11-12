//! Allocation-site attribution for live heap memory (`/proc/narf/slab_sites`).
//!
//! The per-class counters say *which size* holds the heap; this says *who*.
//! Off by default; `echo 1 > /proc/narf/slab_sites` arms it, after which every
//! large (buddy-backed) allocation and one in [`SMALL_SAMPLE`] allocations of
//! the classes from [`SMALL_MIN_CLASS`] up record a call-site key, and their
//! frees retire it. Reading the file lists live bytes per site, largest first,
//! as `.text` offsets for `addr2line` (the same offsets the crash printer
//! uses).
//!
//! Release kernels omit frame pointers, so a site is the first
//! [`SITE_DEPTH`] stack words that land in kernel `.text`, scanned upward
//! from the allocator's stack pointer. That is the crash printer's heuristic:
//! the leading words are the allocator's own frames, the rest the caller's.
//! A stale word can split one caller into several sites; the reader merges
//! them offline by symbol.
//!
//! Everything here is allocation-free and runs under one IRQ-safe spinlock,
//! so it is safe from every context the allocator itself runs in. When
//! disarmed the hooks cost one relaxed load.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

/// Text words that make up one site key.
pub const SITE_DEPTH: usize = 8;
/// Stack words scanned for them.
const SCAN_WORDS: usize = 160;
/// Distinct sites tracked; the rest pool in site 0 ("other").
const MAX_SITES: usize = 2048;
/// Live tracked allocations (open addressing, power of two).
const TABLE: usize = 1 << 17;
/// Classes `>= SMALL_MIN_CLASS` (512 B and up) are sampled.
pub const SMALL_MIN_CLASS: usize = 5;
/// One in this many small-class allocations is tracked.
pub const SMALL_SAMPLE: u64 = 8;

static ARMED: AtomicBool = AtomicBool::new(false);
static SAMPLE: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct Site {
    words: [u64; SITE_DEPTH],
    /// Size class (block bytes) or, for large blocks, the page count; the
    /// key includes it so one caller's sizes stay apart.
    kind: u32,
    live: u64,
    bytes: u64,
}

impl Site {
    const EMPTY: Self = Self {
        words: [0; SITE_DEPTH],
        kind: 0,
        live: 0,
        bytes: 0,
    };
}

#[derive(Clone, Copy)]
struct Slot {
    /// Object address; 0 is empty.
    ptr: u64,
    site: u16,
    bytes: u32,
}

/// Site hash index slots (power of two, twice `MAX_SITES`).
const SITE_INDEX: usize = 2 * MAX_SITES;

struct State {
    sites: [Site; MAX_SITES],
    /// Sites in use, site 0 ("other") included once any record exists.
    nsites: usize,
    /// Hash of (kind, words) -> site + 1; 0 is empty.
    index: [u16; SITE_INDEX],
    table: [Slot; TABLE],
}

// All-zero initial state, so the 2 MiB table lives in .bss.
static STATE: IrqSafeSpinLock<State> = IrqSafeSpinLock::new(State {
    sites: [Site::EMPTY; MAX_SITES],
    nsites: 0,
    index: [0; SITE_INDEX],
    table: [Slot {
        ptr: 0,
        site: 0,
        bytes: 0,
    }; TABLE],
});

/// Arm or disarm. Disarming clears every record.
pub fn set_armed(on: bool) {
    if !on {
        ARMED.store(false, Ordering::Release);
        let mut g = STATE.lock();
        g.nsites = 0;
        g.sites[0] = Site::EMPTY;
        g.index = [0; SITE_INDEX];
        for s in g.table.iter_mut() {
            s.ptr = 0;
        }
        return;
    }
    ARMED.store(true, Ordering::Release);
}

pub fn armed() -> bool {
    ARMED.load(Ordering::Relaxed)
}

/// Whether to track this small-class allocation.
#[inline]
pub fn sample_small(class: usize) -> bool {
    class >= SMALL_MIN_CLASS
        && ARMED.load(Ordering::Relaxed)
        && SAMPLE.fetch_add(1, Ordering::Relaxed) % SMALL_SAMPLE == 0
}

fn slot_of(ptr: u64) -> usize {
    ((ptr >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - 17)) as usize & (TABLE - 1)
}

#[cfg(target_arch = "x86_64")]
fn scan(out: &mut [u64; SITE_DEPTH]) {
    extern "C" {
        static __text_start: u8;
        static __text_end: u8;
    }
    let tstart = core::ptr::addr_of!(__text_start) as u64;
    let tend = core::ptr::addr_of!(__text_end) as u64;
    let rsp: u64;
    // SAFETY: reads the stack pointer; no memory or flags are touched.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags))
    };
    let mut n = 0;
    for i in 0..SCAN_WORDS as u64 {
        // SAFETY: words just above the live stack pointer belong to this
        // task's kernel stack or, for a shallow stack, to the mapped memory
        // right above it (heap-allocated stacks, static boot/IRQ stacks);
        // the panic backtrace scans the same window. Read-only, volatile.
        let w = unsafe { ((rsp + i * 8) as *const u64).read_volatile() };
        if w > tstart && w < tend {
            out[n] = w - tstart;
            n += 1;
            if n == SITE_DEPTH {
                break;
            }
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn scan(_out: &mut [u64; SITE_DEPTH]) {}

/// Record a live allocation of `bytes` at `ptr`; `kind` as in [`Site`].
pub fn record(ptr: usize, bytes: usize, kind: u32) {
    let mut words = [0u64; SITE_DEPTH];
    scan(&mut words);
    let mut h = u64::from(kind).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    for w in words {
        h = (h ^ w).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
    let mut g = STATE.lock();
    let g = &mut *g;
    if g.nsites == 0 {
        g.nsites = 1;
        g.sites[0] = Site::EMPTY;
    }
    let mut k = (h >> 32) as usize & (SITE_INDEX - 1);
    let site = loop {
        let e = g.index[k] as usize;
        if e == 0 {
            if g.nsites == MAX_SITES {
                break 0;
            }
            let i = g.nsites;
            g.nsites += 1;
            g.sites[i] = Site {
                words,
                kind,
                live: 0,
                bytes: 0,
            };
            g.index[k] = i as u16 + 1;
            break i;
        }
        let i = e - 1;
        if g.sites[i].kind == kind && g.sites[i].words == words {
            break i;
        }
        k = (k + 1) & (SITE_INDEX - 1);
    };
    let ptr = ptr as u64;
    let mut i = slot_of(ptr);
    for _ in 0..TABLE {
        let s = g.table[i];
        if s.ptr == 0 || s.ptr == ptr {
            if s.ptr == ptr {
                // A free this audit never saw (atomic path): retire it.
                let old = &mut g.sites[s.site as usize];
                old.live = old.live.saturating_sub(1);
                old.bytes = old.bytes.saturating_sub(u64::from(s.bytes));
            }
            g.table[i] = Slot {
                ptr,
                site: site as u16,
                bytes: bytes.min(u32::MAX as usize) as u32,
            };
            g.sites[site].live += 1;
            g.sites[site].bytes += bytes as u64;
            return;
        }
        i = (i + 1) & (TABLE - 1);
    }
    DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Retire `ptr` if it is tracked. Backward-shift deletion keeps probes short.
pub fn forget(ptr: usize) {
    let ptr = ptr as u64;
    let mut g = STATE.lock();
    let g = &mut *g;
    let mut i = slot_of(ptr);
    loop {
        let s = g.table[i];
        if s.ptr == 0 {
            return;
        }
        if s.ptr == ptr {
            break;
        }
        i = (i + 1) & (TABLE - 1);
    }
    let s = g.table[i];
    let site = &mut g.sites[s.site as usize];
    site.live = site.live.saturating_sub(1);
    site.bytes = site.bytes.saturating_sub(u64::from(s.bytes));
    let mut hole = i;
    let mut j = (i + 1) & (TABLE - 1);
    loop {
        let s = g.table[j];
        if s.ptr == 0 {
            break;
        }
        let home = slot_of(s.ptr);
        // Move `s` into the hole unless its home lies cyclically in (hole, j].
        let in_range = if hole <= j {
            home > hole && home <= j
        } else {
            home > hole || home <= j
        };
        if !in_range {
            g.table[hole] = s;
            hole = j;
        }
        j = (j + 1) & (TABLE - 1);
    }
    g.table[hole].ptr = 0;
}

/// One reported site.
#[derive(Clone, Copy, Debug, Default)]
pub struct SiteRow {
    pub words: [u64; SITE_DEPTH],
    pub kind: u32,
    pub live: u64,
    pub bytes: u64,
}

/// Copy the sites with the most live bytes into `out` (largest first);
/// returns how many were written and the count of untracked allocations
/// (table full). Small-class figures are samples: multiply by
/// [`SMALL_SAMPLE`].
pub fn snapshot(out: &mut [SiteRow]) -> (usize, u64) {
    let mut n = 0usize;
    {
        let g = STATE.lock();
        for s in g.sites[..g.nsites].iter().filter(|s| s.live != 0) {
            let row = SiteRow {
                words: s.words,
                kind: s.kind,
                live: s.live,
                bytes: s.bytes,
            };
            if n < out.len() {
                out[n] = row;
                n += 1;
            } else if let Some(min) = (0..n).min_by_key(|&k| out[k].bytes) {
                if out[min].bytes < row.bytes {
                    out[min] = row;
                }
            }
        }
    }
    out[..n].sort_unstable_by(|a, b| b.bytes.cmp(&a.bytes));
    (n, DROPPED.load(Ordering::Relaxed))
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use core::alloc::Layout;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Armed, a burst of large allocations from one caller shows up as live
    /// bytes at a site of their size; freeing them retires every record.
    fn smoke_slab_site_audit_tracks_and_retires() -> TestResult {
        const N: usize = 16;
        const PAGES: usize = 3; // an unusual size: its own `kind`
        let Ok(layout) = Layout::from_size_align(PAGES * 4096, 16) else {
            return TestResult::Fail("layout");
        };
        let kind = 0x8000_0000 | PAGES as u32;
        let count = |rows: &[SiteRow]| -> u64 {
            rows.iter().filter(|r| r.kind == kind).map(|r| r.live).sum()
        };
        let was = armed();
        set_armed(true);
        let mut ptrs = [None; N];
        for slot in ptrs.iter_mut() {
            *slot = crate::slab::alloc(layout).ok();
        }
        let mut rows = [SiteRow::default(); 64];
        let (n, _) = snapshot(&mut rows);
        let live = count(&rows[..n]);
        let keyed = rows[..n]
            .iter()
            .filter(|r| r.kind == kind)
            .all(|r| r.words[0] != 0 || cfg!(not(target_arch = "x86_64")));
        for p in ptrs.iter().flatten() {
            // SAFETY: allocated above with `layout`, freed exactly once.
            unsafe { crate::slab::dealloc(*p, layout) };
        }
        let (n2, _) = snapshot(&mut rows);
        let after = count(&rows[..n2]);
        set_armed(was);
        if ptrs.iter().any(Option::is_none) {
            return TestResult::Skip("large allocation failed");
        }
        if live < N as u64 {
            return TestResult::Fail("armed audit missed live large allocations");
        }
        if !keyed {
            return TestResult::Fail("site key has no .text words");
        }
        if after != 0 {
            return TestResult::Fail("freed allocations still counted live");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/slab_sites",
        smoke_slab_site_audit_tracks_and_retires
    );
}
