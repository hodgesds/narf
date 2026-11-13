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
pub const SITE_DEPTH: usize = 12;
/// Stack words scanned for them (x86_64 kernel `scan()` only; the other
/// targets' stub `scan()` never reads the stack, so the const is gated to
/// match its sole use site instead of tripping dead-code there).
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
const SCAN_WORDS: usize = 160;
/// Distinct sites tracked; the rest pool in site 0 ("other").
const MAX_SITES: usize = 4096;
/// Sites 0..OTHER_SITES pool records once every site is taken, one per
/// category, so a full table never mixes sampled and unsampled bytes:
/// small-class, large heap, order-0 frame, higher-order frame.
const OTHER_SITES: usize = 4;
/// Live tracked allocations (open addressing, power of two).
const TABLE: usize = 1 << TABLE_BITS;
const TABLE_BITS: u32 = 18;
/// Classes `>= SMALL_MIN_CLASS` (512 B and up) are sampled.
pub const SMALL_MIN_CLASS: usize = 5;
/// One in this many small-class allocations is tracked.
pub const SMALL_SAMPLE: u64 = 8;

static ARMED: AtomicBool = AtomicBool::new(false);
/// Also attribute buddy frames (`echo 2`): every block of order >= 1 and the
/// order-0 frames whose frame number is a multiple of [`FRAME_SAMPLE`].
static FRAMES_ARMED: AtomicBool = AtomicBool::new(false);
/// One in this many order-0 frames is tracked (chosen by frame number, so
/// the same frames are sampled on allocation and on free).
pub const FRAME_SAMPLE: u64 = 8;
/// `kind` tag of a buddy-frame record; the low bits are the order.
pub const KIND_FRAME: u32 = 0x4000_0000;
/// `kind` tag of a large heap block; the low bits are its page count.
pub const KIND_LARGE: u32 = 0x8000_0000;
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

/// Arm (`heap`, and `frames` for buddy frames) or disarm. Disarming clears
/// every record.
pub fn set_armed_frames(heap: bool, frames: bool) {
    FRAMES_ARMED.store(heap && frames, Ordering::Release);
    set_armed(heap);
}

/// Whether buddy frames are being attributed.
pub fn frames_armed() -> bool {
    FRAMES_ARMED.load(Ordering::Relaxed)
}

#[inline]
fn frame_sampled(frame: u64, order: u8) -> bool {
    order != 0 || frame % FRAME_SAMPLE == 0
}

/// Buddy hand-out of `2^order` frames at frame number `frame`.
#[inline]
pub fn frame_alloc(frame: u64, order: u8) {
    if FRAMES_ARMED.load(Ordering::Relaxed) && frame_sampled(frame, order) {
        // Frame numbers are far below any kernel virtual address, so they
        // share the table with heap pointers without colliding.
        record(
            frame as usize,
            4096usize << order,
            KIND_FRAME | u32::from(order),
        );
    }
}

/// Buddy return of the block [`frame_alloc`] recorded.
#[inline]
pub fn frame_free(frame: u64, order: u8) {
    if FRAMES_ARMED.load(Ordering::Relaxed) && frame_sampled(frame, order) {
        forget(frame as usize);
    }
}

/// Arm or disarm. Disarming clears every record.
pub fn set_armed(on: bool) {
    if !on {
        FRAMES_ARMED.store(false, Ordering::Release);
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
    ((ptr >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - TABLE_BITS)) as usize & (TABLE - 1)
}

// Hosted builds (the btrfs host harness) have no kernel text symbols.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
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
    // Never past the page `rsp` is in: the word above a shallow stack's top
    // can be an unmapped guard page (vmapped kernel stacks, and a soak hit
    // a #PF 155 words above rsp on one). The live stack page is mapped.
    let to_page_end = (4096 - (rsp & 4095)) / 8;
    let words = (SCAN_WORDS as u64).min(to_page_end);
    for i in 0..words {
        // SAFETY: every address read lies in the 4 KiB page that holds the
        // current stack pointer, which is mapped and readable while this
        // code runs on it. Read-only, volatile.
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

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
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
        for (i, other) in [0, KIND_LARGE, KIND_FRAME, KIND_FRAME | 0xfe]
            .into_iter()
            .enumerate()
        {
            g.sites[i] = Site {
                kind: other,
                ..Site::EMPTY
            };
        }
        g.nsites = OTHER_SITES;
    }
    let other = if kind & KIND_FRAME != 0 {
        if kind & 0xff == 0 {
            2
        } else {
            3
        }
    } else if kind & KIND_LARGE != 0 {
        1
    } else {
        0
    };
    let mut k = (h >> 32) as usize & (SITE_INDEX - 1);
    let site = loop {
        let e = g.index[k] as usize;
        if e == 0 {
            if g.nsites == MAX_SITES {
                break other;
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
/// `frames` selects buddy-frame sites instead of heap sites. Returns how
/// many were written and the count of untracked allocations
/// (table full). Small-class figures are samples: multiply by
/// [`SMALL_SAMPLE`].
pub fn snapshot(out: &mut [SiteRow], frames: bool) -> (usize, u64) {
    let mut n = 0usize;
    {
        let g = STATE.lock();
        for s in g.sites[..g.nsites]
            .iter()
            .filter(|s| s.live != 0 && (s.kind & KIND_FRAME != 0) == frames)
        {
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

/// Live bytes over every site, scaled up by the sampling rates:
/// `(heap, frames)`. Tells how much of the attributed memory the top rows of
/// [`snapshot`] leave out.
pub fn totals() -> (u64, u64) {
    let g = STATE.lock();
    let (mut heap, mut frames) = (0u64, 0u64);
    for s in g.sites[..g.nsites].iter() {
        if s.kind & KIND_FRAME != 0 {
            let scale = if s.kind & 0xff == 0 { FRAME_SAMPLE } else { 1 };
            frames = frames.saturating_add(s.bytes.saturating_mul(scale));
        } else if s.kind & KIND_LARGE != 0 {
            heap = heap.saturating_add(s.bytes);
        } else {
            heap = heap.saturating_add(s.bytes.saturating_mul(SMALL_SAMPLE));
        }
    }
    (heap, frames)
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
        let kind = KIND_LARGE | PAGES as u32;
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
        let (n, _) = snapshot(&mut rows, false);
        let live = count(&rows[..n]);
        let keyed = rows[..n]
            .iter()
            .filter(|r| r.kind == kind)
            .all(|r| r.words[0] != 0 || cfg!(not(target_arch = "x86_64")));
        for p in ptrs.iter().flatten() {
            // SAFETY: allocated above with `layout`, freed exactly once.
            unsafe { crate::slab::dealloc(*p, layout) };
        }
        let (n2, _) = snapshot(&mut rows, false);
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

    /// A buffer grown by repeated reallocation through the large sizes, then
    /// dropped, leaves the heap estimate where it was: every realloc retires
    /// the old block's record, and nothing is scaled by the wrong rate.
    fn smoke_slab_site_audit_estimate_follows_realloc() -> TestResult {
        const NOISE: u64 = 4 << 20; // other CPUs allocate meanwhile
        let was = armed();
        set_armed(true);
        let (before, _) = totals();
        let mut grown: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        for _ in 0..(1 << 20) / 4096 {
            grown.extend_from_slice(&[0u8; 4096]);
        }
        let (during, _) = totals();
        drop(grown);
        let (after, _) = totals();
        set_armed(was);
        if during < before + (1 << 20) - NOISE.min(1 << 19) {
            return TestResult::Fail("a live 1 MiB buffer is missing from the estimate");
        }
        if after > before + NOISE {
            return TestResult::Fail("reallocated or freed blocks stayed in the estimate");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/slab_sites",
        smoke_slab_site_audit_estimate_follows_realloc
    );
}
