//! Physical frames + per-NUMA-node frame allocator.
//!
//! Wave-2 subset of `memory/` spec §3 with Wave-3 NUMA awareness:
//! per-node buddy allocators classified by SRAT memory-range attribution.
//!
//! Layout:
//! - One cache-line-aligned buddy-zone lock per NUMA node
//!   (`MAX_NUMA_NODES`). Boot inits flat (everything goes to zone 0);
//!   `rebalance_to_topology` redistributes the remaining frames once SRAT
//!   data is available.
//! - `alloc_frame()` consults the current CPU's NUMA node first
//!   (looked up via the weak-link `narf_cpu_to_node` hook), then falls back
//!   nearest-node-first. Order-0 traffic is batched through per-CPU/per-node
//!   caches sized from the node and its CPUs (see "Per-CPU frame caches"),
//!   published once buddy metadata capacity is frozen and every boot frame
//!   has a free-state word.
//! - `alloc_frame_on(node)` is the explicit-node entry point.
//! - `free_frame(f)` uses `narf_phys_to_node` to return the frame
//!   to its rightful node bin.
//!
//! Cycle avoidance: this crate cannot depend on `narf-acpi`
//! (narf-acpi pulls in `narf_memory::PhysAddr`). The hooks below are
//! the standard weakly-linked surface — narf-frame provides
//! `#[no_mangle]` definitions calling into narf-acpi at boot.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::percpu::current_cpu;
use narf_lib::sync::IrqSafeSpinLock;

use crate::buddy::{self, BuddyZone, MAX_ORDER};
use crate::PhysAddr;

/// Page size in bytes. x86_64 / aarch64 both use 4 KiB as the base size.
pub const PAGE_SIZE: u64 = 4096;
/// Log2 of the page size; handy for shifts.
pub const PAGE_SHIFT: u32 = 12;

/// Maximum NUMA nodes we track. Mirrors `narf_acpi::MAX_NUMA_NODES`
/// — kept independent so this crate doesn't pull in narf-acpi.
pub const MAX_NUMA_NODES: usize = 16;
/// Number of buddy orders exposed by `/proc/buddyinfo` (orders 0..=10).
pub const BUDDY_ORDER_COUNT: usize = MAX_ORDER as usize + 1;

/// Linux-compatible per-node NUMA allocation event counters.
///
/// Values count base pages, not allocation calls.  `numa_foreign` is
/// attributed to the intended node; all other fields are attributed to
/// the node that supplied the page.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NumaNodeStats {
    pub numa_hit: u64,
    pub numa_miss: u64,
    pub numa_foreign: u64,
    pub interleave_hit: u64,
    pub local_node: u64,
    pub other_node: u64,
}

struct AtomicNumaNodeStats {
    numa_hit: AtomicU64,
    numa_miss: AtomicU64,
    numa_foreign: AtomicU64,
    interleave_hit: AtomicU64,
    local_node: AtomicU64,
    other_node: AtomicU64,
}

impl AtomicNumaNodeStats {
    const fn new() -> Self {
        Self {
            numa_hit: AtomicU64::new(0),
            numa_miss: AtomicU64::new(0),
            numa_foreign: AtomicU64::new(0),
            interleave_hit: AtomicU64::new(0),
            local_node: AtomicU64::new(0),
            other_node: AtomicU64::new(0),
        }
    }
}

static NUMA_STATS: [AtomicNumaNodeStats; MAX_NUMA_NODES] =
    [const { AtomicNumaNodeStats::new() }; MAX_NUMA_NODES];

/// Return a coherent-enough lock-free snapshot of one node's monotonic
/// allocation counters. Individual fields may advance during the read.
pub fn numa_node_stats(node: usize) -> NumaNodeStats {
    let Some(s) = NUMA_STATS.get(node) else {
        return NumaNodeStats::default();
    };
    NumaNodeStats {
        numa_hit: s.numa_hit.load(Ordering::Relaxed),
        numa_miss: s.numa_miss.load(Ordering::Relaxed),
        numa_foreign: s.numa_foreign.load(Ordering::Relaxed),
        interleave_hit: s.interleave_hit.load(Ordering::Relaxed),
        local_node: s.local_node.load(Ordering::Relaxed),
        other_node: s.other_node.load(Ordering::Relaxed),
    }
}

pub(crate) fn account_numa_allocation(preferred: usize, actual: usize, pages: u64) {
    let preferred = preferred.min(MAX_NUMA_NODES - 1);
    let actual = actual.min(MAX_NUMA_NODES - 1);
    if actual == preferred {
        NUMA_STATS[actual]
            .numa_hit
            .fetch_add(pages, Ordering::Relaxed);
    } else {
        NUMA_STATS[actual]
            .numa_miss
            .fetch_add(pages, Ordering::Relaxed);
        NUMA_STATS[preferred]
            .numa_foreign
            .fetch_add(pages, Ordering::Relaxed);
    }
    if actual == current_cpu_node().min(MAX_NUMA_NODES - 1) {
        NUMA_STATS[actual]
            .local_node
            .fetch_add(pages, Ordering::Relaxed);
    } else {
        NUMA_STATS[actual]
            .other_node
            .fetch_add(pages, Ordering::Relaxed);
    }
}

/// Record an interleave selection that was satisfied by its intended node.
pub(crate) fn account_interleave_hit(node: usize, pages: u64) {
    NUMA_STATS[node.min(MAX_NUMA_NODES - 1)]
        .interleave_hit
        .fetch_add(pages, Ordering::Relaxed);
}

/// A 4 KiB physical frame, identified by its starting physical address.
///
/// The wrapper enforces page alignment at construction time and is
/// `#[repr(transparent)]` so conversion to/from `PhysAddr` is free.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysFrame(PhysAddr);

impl PhysFrame {
    /// Wrap an already-aligned `PhysAddr`. Panics on misaligned input in
    /// debug; truncates in release (callers should use `containing`).
    pub const fn new(addr: PhysAddr) -> Self {
        debug_assert!(
            addr.raw() & (PAGE_SIZE - 1) == 0,
            "PhysFrame::new requires a page-aligned PhysAddr"
        );
        Self(addr)
    }

    /// Round `addr` down to a page boundary and wrap.
    pub const fn containing(addr: PhysAddr) -> Self {
        Self(PhysAddr::new(addr.raw() & !(PAGE_SIZE - 1)))
    }

    /// Starting physical address of this frame.
    #[inline]
    pub const fn start_address(self) -> PhysAddr {
        self.0
    }

    /// Frame number (phys >> PAGE_SHIFT).
    #[inline]
    pub const fn number(self) -> u64 {
        self.0.raw() >> PAGE_SHIFT
    }
}

impl fmt::Debug for PhysFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysFrame({:#018x})", self.0.raw())
    }
}

/// Reasons a frame-alloc call can fail.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FrameAllocError {
    /// No free frames remain in any usable region.
    Exhausted,
    /// A user-backing allocation was refused to preserve the kernel's
    /// protected minimum free-memory reserve.
    ReservePressure(crate::reclaim::ReclaimTicket),
    /// Allocator not initialised yet (`init_from_map` hasn't run).
    Uninitialised,
    /// The currently-installed `FrameAlloc` impl does not support
    /// this operation (e.g. `BumpFrameAlloc::free_frame`).
    NotSupported,
    /// `install_frame_alloc` was called with an authority cap whose
    /// epoch has been revoked.
    AuthorityRevoked,
}

impl From<CapError> for FrameAllocError {
    fn from(_: CapError) -> Self {
        FrameAllocError::AuthorityRevoked
    }
}

/// Global frame-accounting metadata. Buddy free lists are deliberately kept
/// out of this object: each NUMA node has an independent cache-line-aligned
/// lock, so allocations on unrelated nodes do not serialize.
#[derive(Debug)]
pub struct FrameAllocator {
    /// Managed base pages per node, frozen when topology rebalance
    /// completes. Unlike the zone free counts this does not decrease on
    /// allocation, so it is suitable for sysfs MemTotal reporting.
    node_total_frames: [AtomicUsize; MAX_NUMA_NODES],
    /// Free base pages per node, including frames held in per-CPU caches.
    /// Successful ownership handoff updates this once per allocation/free, so
    /// watermark checks do not have to lock and walk every buddy zone.
    node_free_frames: [AtomicUsize; MAX_NUMA_NODES],
    initialised: AtomicBool,
    total_frames: AtomicUsize,
    reserved_frames: AtomicUsize,
    /// Set after `rebalance_to_topology` completes; alloc + free
    /// honour per-node zones from this point on. Pre-flag, every
    /// allocation comes out of zones[0].
    numa_aware: AtomicBool,
}

static ALLOC: FrameAllocator = FrameAllocator {
    node_total_frames: [const { AtomicUsize::new(0) }; MAX_NUMA_NODES],
    node_free_frames: [const { AtomicUsize::new(0) }; MAX_NUMA_NODES],
    initialised: AtomicBool::new(false),
    total_frames: AtomicUsize::new(0),
    reserved_frames: AtomicUsize::new(0),
    numa_aware: AtomicBool::new(false),
};

#[inline]
fn account_allocated_frames(node: usize, pages: usize) {
    let previous = ALLOC.node_free_frames[node].fetch_sub(pages, Ordering::Relaxed);
    debug_assert!(
        previous >= pages,
        "free-frame accounting underflow on node {node}: {previous} < {pages}"
    );
}

#[inline]
fn account_freed_frames(node: usize, pages: usize) {
    ALLOC.node_free_frames[node].fetch_add(pages, Ordering::Relaxed);
}

#[repr(align(64))]
struct BuddyZoneLock(IrqSafeSpinLock<BuddyZone>);

impl BuddyZoneLock {
    const fn new() -> Self {
        Self(IrqSafeSpinLock::new(BuddyZone::new()))
    }
}

/// One independently locked buddy free-list per NUMA node. The alignment
/// prevents the lock words for adjacent nodes from sharing a cache line.
static ZONES: [BuddyZoneLock; MAX_NUMA_NODES] = [const { BuddyZoneLock::new() }; MAX_NUMA_NODES];
static REBALANCE_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// One hold of a node's zone lock on an allocation or free path.
///
/// In the kernel-test build the guard measures what its hold did — blocks
/// freed, blocks allocated and buddy-lookup steps, read from the zone's own
/// counters under the lock — and folds that into per-node maxima on release, so
/// the scale tests can state how much work one interrupts-off section of the
/// allocator is allowed to do. Everywhere else it is the bare lock guard.
struct ZoneGuard {
    zone: narf_lib::sync::IrqSafeSpinLockGuard<'static, BuddyZone>,
    #[cfg(feature = "kernel-test")]
    node: usize,
    #[cfg(feature = "kernel-test")]
    entry: buddy::ZoneOpStats,
}

impl core::ops::Deref for ZoneGuard {
    type Target = BuddyZone;
    #[inline]
    fn deref(&self) -> &BuddyZone {
        &self.zone
    }
}

impl core::ops::DerefMut for ZoneGuard {
    #[inline]
    fn deref_mut(&mut self) -> &mut BuddyZone {
        &mut self.zone
    }
}

#[cfg(feature = "kernel-test")]
impl Drop for ZoneGuard {
    fn drop(&mut self) {
        // Runs before the field drop that releases the lock, so the deltas
        // belong to this hold alone.
        let now = self.zone.op_stats();
        let stats = &ZONE_HOLD_STATS[self.node];
        stats.acquisitions.fetch_add(1, Ordering::Relaxed);
        stats
            .max_frees
            .fetch_max(now.frees - self.entry.frees, Ordering::Relaxed);
        stats
            .max_allocs
            .fetch_max(now.allocs - self.entry.allocs, Ordering::Relaxed);
        stats
            .max_find_steps
            .fetch_max(now.find_steps - self.entry.find_steps, Ordering::Relaxed);
    }
}

/// Take `node`'s zone lock for an allocation or free.
#[inline]
fn lock_zone(node: usize) -> ZoneGuard {
    let zone = ZONES[node].0.lock();
    ZoneGuard {
        #[cfg(feature = "kernel-test")]
        entry: zone.op_stats(),
        #[cfg(feature = "kernel-test")]
        node,
        zone,
    }
}

/// Per-node record of zone-lock holds taken through [`lock_zone`].
#[cfg(feature = "kernel-test")]
struct ZoneHoldStats {
    acquisitions: AtomicU64,
    max_frees: AtomicU64,
    max_allocs: AtomicU64,
    max_find_steps: AtomicU64,
}

#[cfg(feature = "kernel-test")]
static ZONE_HOLD_STATS: [ZoneHoldStats; MAX_NUMA_NODES] = [const {
    ZoneHoldStats {
        acquisitions: AtomicU64::new(0),
        max_frees: AtomicU64::new(0),
        max_allocs: AtomicU64::new(0),
        max_find_steps: AtomicU64::new(0),
    }
}; MAX_NUMA_NODES];

/// Per-frame free-state words for every frame the allocator manages: the
/// buddy zones mirror their free lists into it, and the per-CPU frame caches
/// link their frames through it. See "Per-frame free state" in `buddy.rs`.
static FRAME_INDEX: buddy::FrameStateIndex = buddy::FrameStateIndex::new();

/// Frees refused because the frame's state word said it was already free (the
/// head of a free buddy block, or resident in a per-CPU cache): a double free.
/// The second free is dropped — accepting it would hand the same frame to two
/// owners, or loop a cache's list back on itself. Stays 0 in a correct kernel.
static DOUBLE_FREES_REFUSED: AtomicU64 = AtomicU64::new(0);

/// Number of frees the allocator has refused as double frees since boot.
pub fn double_frees_refused() -> u64 {
    DOUBLE_FREES_REFUSED.load(Ordering::Relaxed)
}

/// Fixed-size text sink: the failure report below runs when memory is
/// exhausted, so it must not allocate.
struct ReportBuf {
    bytes: [u8; 1536],
    len: usize,
}

impl fmt::Write for ReportBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.bytes.len() - self.len;
        let take = s.len().min(room);
        self.bytes[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

/// Write the allocator's free state for every online node: free and cached
/// page totals, free blocks per order and migratetype as the zone lists hold
/// them, and refused double frees. Takes each zone lock with `try_lock` only,
/// so it is safe from any context, including one that already holds a zone
/// lock (that zone is then reported as busy). Allocates nothing.
pub fn write_free_state(out: &mut impl fmt::Write) -> fmt::Result {
    #[cfg(feature = "cgroup")]
    let (denials, denied_pid) = crate::cgroup_charge::denials();
    #[cfg(not(feature = "cgroup"))]
    let (denials, denied_pid) = (0usize, 0usize);
    write!(
        out,
        "frame: free state, double frees refused {}, cgroup charges refused {denials} \
         (last pid {denied_pid}), early ceiling {:#x}",
        double_frees_refused(),
        EARLY_PHYS_CEILING.load(Ordering::Relaxed),
    )?;
    let last = LAST_BLOCK_FAILURE.load(Ordering::Relaxed);
    if last != 0 {
        let reason = match last >> 8 {
            BLOCK_FAIL_CHARGE => "cgroup charge refused",
            _ => "no block in any zone",
        };
        write!(
            out,
            "\nframe: last block allocation failure: order {}, {reason}",
            last & 0xff
        )?;
    }
    let mut nodes = online_node_mask() | 1;
    while nodes != 0 {
        let node = nodes.trailing_zeros() as usize;
        nodes &= nodes - 1;
        if node >= MAX_NUMA_NODES {
            break;
        }
        write!(
            out,
            "\nframe: node {node}: total {} free {} cached {} pairs {}",
            ALLOC.node_total_frames[node].load(Ordering::Relaxed),
            ALLOC.node_free_frames[node].load(Ordering::Relaxed),
            FRAME_CACHE_FREE[node].load(Ordering::Relaxed),
            PAIR_CACHE_FREE[node].load(Ordering::Relaxed),
        )?;
        let Some(zone) = ZONES[node].0.try_lock() else {
            write!(out, "; zone busy")?;
            continue;
        };
        write!(out, "; listed {}", zone.free_frame_count())?;
        for mt in 0..buddy::NUM_MIGRATE_TYPES {
            let kind = buddy::MigrateType::from_index(mt);
            write!(out, "\nframe: node {node} {kind:?} blocks/order:")?;
            for order in 0..=MAX_ORDER {
                write!(out, " {}", zone.free_block_count_mt(order, kind))?;
            }
        }
    }
    Ok(())
}

/// Report a failed heap allocation on the console, once per `REPORT_LIMIT`
/// failures since boot, with the allocator's free state, so the next
/// "memory allocation failed" panic says where the memory was.
pub(crate) fn report_allocation_failure(size: usize, align: usize) {
    const REPORT_LIMIT: u64 = 4;
    static REPORTS: AtomicU64 = AtomicU64::new(0);
    if REPORTS.fetch_add(1, Ordering::Relaxed) >= REPORT_LIMIT {
        return;
    }
    let mut buf = ReportBuf {
        bytes: [0; 1536],
        len: 0,
    };
    let _ = fmt::Write::write_fmt(
        &mut buf,
        format_args!("frame: heap allocation of {size} bytes (align {align}) failed\n"),
    );
    let _ = write_free_state(&mut buf);
    let _ = fmt::Write::write_str(&mut buf, "\n");
    console_write(&buf.bytes[..buf.len]);
}

#[cfg(target_os = "none")]
fn console_write(bytes: &[u8]) {
    extern "C" {
        /// The kernel's console write export (`modules/src/kabi.rs`), linked
        /// into every kernel image.
        fn narf_printk(ptr: *const u8, len: usize) -> i32;
    }
    if bytes.is_empty() {
        return;
    }
    // SAFETY: `bytes` is a live slice for the duration of the call, and
    // `narf_printk` only reads `len` bytes from `ptr`. The text is UTF-8
    // except possibly a final code point cut by the buffer bound, which
    // `narf_printk` rejects as a whole rather than misreading.
    let _ = unsafe { narf_printk(bytes.as_ptr(), bytes.len()) };
}

#[cfg(not(target_os = "none"))]
fn console_write(_bytes: &[u8]) {}

#[cold]
fn note_double_free() {
    DOUBLE_FREES_REFUSED.fetch_add(1, Ordering::Relaxed);
}

/// A free refused because the frame's state says it cannot be freed as asked
/// (Linux `bad_page`): count it, and report the first few on the console with
/// the frame, the order and the reason. The memory stays with whoever holds
/// it — never on a free list twice.
#[cold]
fn note_refused_free(frame: u64, order: u8, refusal: buddy::FreeRefusal) {
    note_double_free();
    const REPORT_LIMIT: u64 = 16;
    static REPORTS: AtomicU64 = AtomicU64::new(0);
    if REPORTS.fetch_add(1, Ordering::Relaxed) >= REPORT_LIMIT {
        return;
    }
    let mut buf = ReportBuf {
        bytes: [0; 1536],
        len: 0,
    };
    let held = match refusal {
        buddy::FreeRefusal::OrderMismatch(held) => held,
        _ => order,
    };
    let _ = fmt::Write::write_fmt(
        &mut buf,
        format_args!(
            "frame: refused free of phys {:#x} order {order}: {} (held order {held})\n",
            frame << PAGE_SHIFT,
            refusal.describe(),
        ),
    );
    #[cfg(feature = "frame-alloc-audit")]
    {
        if let Some((allocated, alloc_site, free_site)) =
            buddy::frame_audit_state(PhysAddr::new(frame << PAGE_SHIFT))
        {
            let _ = fmt::Write::write_fmt(
                &mut buf,
                format_args!(
                    "frame:   audit: allocated {allocated}, alloc site {}:{}, last free {}:{}\n",
                    alloc_site.0, alloc_site.1, free_site.0, free_site.1,
                ),
            );
        }
    }
    console_write(&buf.bytes[..buf.len]);
}

/// Turn a live order-`order` block into `2^order` order-0 frames that may be
/// freed one at a time (Linux `split_page`). `false`, changing nothing, when
/// `frame` does not head a live block of that order.
pub fn split_block(frame: PhysFrame, order: u8) -> bool {
    FRAME_INDEX.split_allocated(buddy::frame_no(frame), order)
}

// ── Per-CPU frame caches ────────────────────────────────────────────────
//
// Each CPU keeps, per NUMA node, a list of free order-0 frames and a list of
// free UNMOVABLE order-1 blocks in front of that node's buddy zone, so the
// common allocation and free touch only the CPU's own lock. The shape is
// Linux's per-CPU pagesets (`struct per_cpu_pages`, mm/page_alloc.c):
//
// * The lists are intrusive — each cached frame's state word links to the
//   next — so a cache has no capacity of its own; how much it may hold is a
//   number (`high`), not an array size.
// * `batch`, the unit of every exchange with the zone, comes from the zone's
//   size (`zone_cache_batch`, Linux `zone_batchsize`).
// * `high`, the page count at which a cache starts giving frames back, floats
//   between `high_min` (the node's low watermark shared out over its CPUs)
//   and `high_max` (an eighth of the node shared out the same way) — Linux
//   `zone_highsize` and the `pcp->high` auto-tuning in `nr_pcp_alloc` /
//   `nr_pcp_high`: it grows while a CPU keeps refilling or keeps freeing more
//   than it holds, and shrinks back while the node is short of memory.
// * A refill takes `batch << alloc_factor` frames under ONE zone-lock hold,
//   the factor doubling per consecutive refill up to `CACHE_BATCH_SCALE_MAX`
//   (Linux `nr_pcp_alloc`, `rmqueue_bulk`). A trim returns up to
//   `free_count` frames, `batch` per zone-lock hold (Linux `nr_pcp_free`,
//   `free_pcppages_bulk`).
//
// So under fork/exit churn a CPU takes the zone lock about once per `batch`
// frames it moves through the zone, and not at all for churn that fits under
// `high`. The cache this replaces held 16 frames and refilled 8 at a time on
// every machine, which is one zone-lock acquisition per 8 frames from every
// CPU — on a one-node machine, all through one lock.
//
// Interrupts-off bounds. The zone, cache and drain locks all mask
// interrupts, so each bound below is also a bound on one interrupts-off
// section of the allocator's own making, in frames, every frame O(orders):
//
// * a zone-lock hold that frees: at most `FRAME_RETURN_CHUNK` (64) blocks;
// * a zone-lock hold that refills: at most `batch << CACHE_BATCH_SCALE_MAX`
//   frames (63 << 5 = 2016 at most);
// * a cache-lock hold on a free: one chunk linked (64 frames) plus one trim,
//   which returns at most `free_count` frames — again `batch <<
//   CACHE_BATCH_SCALE_MAX` plus a chunk — across several zone-lock holds;
// * a coordinated drain (`with_node_frame_caches_drained`,
//   `with_node_cache_bypassed`): the drain lock is held from the first cache
//   to the last, so its section covers whatever the node's caches still hold.
//   `predrain_node_caches` empties them first in slices with every lock
//   dropped in between, which leaves the coordinated pass only what was
//   freed in the meantime; the ceiling on that, if every CPU refilled its
//   cache to `high` in the gap, is the caches' whole budget (an eighth of
//   the node).
//
// A caller that frees a large region while holding its own interrupts-off
// lock is outside these bounds: the allocator releases every lock of its own
// between batches, but cannot unmask interrupts on the caller's behalf.
//
// Not taken from Linux: per-migratetype lists (NARF's order-0 frames are all
// served from the UNMOVABLE partition, as before), orders 2-3 and THP on the
// lists, trimming from the cold end (the lists are singly linked, so a trim
// takes the most recently cached frames that are not the ones just freed),
// and the periodic `decay_pcp_high` — nothing in this crate runs on a timer.
// Frames an idle CPU leaves in its cache stay counted as free and are
// recovered by the drain a failed allocation performs (`alloc_order0_on`,
// `alloc_pages_on_inner`).

/// Refill and trim batches scale up to `batch << CACHE_BATCH_SCALE_MAX`
/// (Linux `CONFIG_PCP_BATCH_SCALE_MAX`, default 5). It is the knob that
/// bounds the work of one refill's zone-lock hold.
const CACHE_BATCH_SCALE_MAX: u32 = 5;
/// A node's caches may together hold at most this fraction of the node
/// (Linux `MIN_PERCPU_PAGELIST_HIGH_FRACTION`).
const CACHE_HIGH_FRACTION: usize = 8;
/// Maximum final-owner returns published during one cache/zone transaction,
/// and the most blocks one zone-lock hold gives back to the buddy.
/// The fixed bound keeps IRQ-masked work finite and permits stack-backed spill
/// storage: freeing memory must not allocate memory after ownership reaches 0.
const FRAME_RETURN_CHUNK: usize = 64;

/// Order-0 frames one per-CPU cache refill or trim moves, from the size of
/// the zone it fronts: about 0.025% of the zone, at most 256 KiB, clamped to a
/// `2^n - 1` value (Linux `zone_batchsize`). 63 for any zone of 1 GiB or more;
/// 1 — no caching to speak of — for a zone under 32 MiB.
fn zone_cache_batch(managed_frames: usize) -> usize {
    let batch = (managed_frames >> 12).min((256usize << 10) / PAGE_SIZE as usize);
    if batch <= 1 {
        return 1;
    }
    let scaled = batch + batch / 2;
    (1usize << (usize::BITS - 1 - scaled.leading_zeros())) - 1
}

/// Page count at which one CPU's cache starts returning frames, when
/// `pool_frames` is the amount the node's caches may hold between them and
/// `cpus` CPUs share it; never less than four batches (Linux `zone_highsize`).
fn zone_cache_high(pool_frames: usize, cpus: usize, batch: usize) -> usize {
    (pool_frames / cpus.max(1)).max(batch << 2)
}

/// One node's cache sizing, shared by every CPU's cache for that node.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct CacheTuning {
    batch: usize,
    high_min: usize,
    high_max: usize,
}

/// A node's published [`CacheTuning`] with the inputs it was derived from, so
/// a slow path notices when the node's size, its low watermark or the CPU
/// count has changed and derives it again. Linux recomputes at the events
/// themselves (`zone_pcp_update` on memory and CPU hotplug, on watermark
/// changes); this crate is not told about CPU bring-up, so it compares.
struct NodeCacheTuning {
    batch: AtomicUsize,
    high_min: AtomicUsize,
    high_max: AtomicUsize,
    managed: AtomicUsize,
    low_watermark: AtomicUsize,
    cpus: AtomicUsize,
}

impl NodeCacheTuning {
    const fn new() -> Self {
        Self {
            batch: AtomicUsize::new(0),
            high_min: AtomicUsize::new(0),
            high_max: AtomicUsize::new(0),
            managed: AtomicUsize::new(usize::MAX),
            low_watermark: AtomicUsize::new(0),
            cpus: AtomicUsize::new(0),
        }
    }
}

static FRAME_CACHE_TUNING: [NodeCacheTuning; MAX_NUMA_NODES] =
    [const { NodeCacheTuning::new() }; MAX_NUMA_NODES];

/// CPUs that share `node`'s cache budget: the CPUs on the node, or every CPU
/// when the node has none of its own (Linux `zone_highsize`'s
/// `nr_split_cpus`).
fn node_cache_cpus(node: usize, cpus: usize) -> usize {
    let local = (0..cpus as u32)
        .filter(|&cpu| {
            // SAFETY: narf-frame provides the `#[no_mangle]` definition.
            unsafe { narf_cpu_to_node(cpu) as usize == node }
        })
        .count();
    if local == 0 {
        cpus.max(1)
    } else {
        local
    }
}

/// Pure sizing: the tuning for a node of `managed` frames whose share of the
/// low watermark is `low_watermark` pages, split over `cpus` CPUs.
fn derive_cache_tuning(managed: usize, low_watermark: usize, cpus: usize) -> CacheTuning {
    let batch = zone_cache_batch(managed);
    let high_min = zone_cache_high(low_watermark, cpus, batch);
    let high_max = zone_cache_high(managed / CACHE_HIGH_FRACTION, cpus, batch).max(high_min);
    CacheTuning {
        batch,
        high_min,
        high_max,
    }
}

/// `node`'s current cache sizing. Called on the slow paths only (a refill or
/// a trim, which are about to take the zone lock anyway); a few loads when
/// nothing has changed. Two CPUs re-deriving at once store the same values.
fn cache_tuning(node: usize) -> CacheTuning {
    let published = &FRAME_CACHE_TUNING[node];
    let managed = ALLOC.node_total_frames[node].load(Ordering::Relaxed);
    let low_watermark = crate::reclaim::watermark_low_node(node) as usize;
    let cpus = narf_lib::smp::cpu_count().max(1) as usize;
    if published.managed.load(Ordering::Relaxed) != managed
        || published.low_watermark.load(Ordering::Relaxed) != low_watermark
        || published.cpus.load(Ordering::Relaxed) != cpus
    {
        let tuning = derive_cache_tuning(managed, low_watermark, node_cache_cpus(node, cpus));
        published.batch.store(tuning.batch, Ordering::Relaxed);
        published.high_min.store(tuning.high_min, Ordering::Relaxed);
        published.high_max.store(tuning.high_max, Ordering::Relaxed);
        published.managed.store(managed, Ordering::Relaxed);
        published
            .low_watermark
            .store(low_watermark, Ordering::Relaxed);
        published.cpus.store(cpus, Ordering::Relaxed);
        return tuning;
    }
    // A reader racing a re-derivation may combine fields of two tunings.
    // Every use clamps (`high` into `[high_min, high_max]`, batches to at
    // least 1), so a mixed triple costs at most one oddly sized batch.
    let batch = published.batch.load(Ordering::Relaxed).max(1);
    let high_min = published.high_min.load(Ordering::Relaxed);
    CacheTuning {
        batch,
        high_min,
        high_max: published.high_max.load(Ordering::Relaxed).max(high_min),
    }
}

/// One CPU's cache of one node's free frames (Linux `struct per_cpu_pages`).
/// Guarded by the owning CPU's `FRAME_CACHES` lock.
#[derive(Copy, Clone)]
struct NodeFrameCache {
    /// Order-0 frames, most recently freed first, each frame's state word
    /// naming the next (`buddy::cached_state`).
    frames: u64,
    /// Complete UNMOVABLE order-1 blocks, linked the same way through each
    /// block's first frame. Small kernel buffers above the slab's 4 KiB limit
    /// repeatedly allocate and free these.
    pairs: u64,
    /// Blocks on `pairs`.
    pair_count: usize,
    /// Base pages on both lists: frames plus two per pair (`pcp->count`).
    count: usize,
    /// Auto-tuned ceiling for `count` (`pcp->high`); clamped into the node's
    /// `[high_min, high_max]` on every slow path.
    high: usize,
    /// `count` at which the next free takes the slow path: `high`, or less
    /// while the node is short of memory. 0 until the first free computes it.
    trim_at: usize,
    /// Pages freed in the current streak — halved by every allocation, and
    /// no longer counted up once it reaches `free_cap` (`pcp->free_count`).
    /// It is the number of pages a trim returns.
    free_count: usize,
    /// `batch << CACHE_BATCH_SCALE_MAX` as of the last slow path, kept here so
    /// the fast path need not read the node's sizing.
    free_cap: usize,
    /// log2 of the refill multiplier; grows per refill, halves per free
    /// (`pcp->alloc_factor`).
    alloc_factor: u8,
}

impl NodeFrameCache {
    const fn new() -> Self {
        Self {
            frames: buddy::NO_FRAME,
            pairs: buddy::NO_FRAME,
            pair_count: 0,
            count: 0,
            high: 0,
            trim_at: 0,
            free_count: 0,
            free_cap: 0,
            alloc_factor: 0,
        }
    }

    /// Order-0 frames on the `frames` list.
    #[inline]
    fn frame_count(&self) -> usize {
        self.count - 2 * self.pair_count
    }
}

/// Link `frame` onto a cache list through its state word. `false`, leaving
/// the list untouched, when the word is not 0: the frame is already free.
#[inline]
fn cache_list_push(head: &mut u64, frame: u64, word: &AtomicU64) -> bool {
    if word.load(Ordering::Relaxed) != 0 {
        return false;
    }
    word.store(buddy::cached_state(*head), Ordering::Relaxed);
    *head = frame;
    true
}

/// Unlink and return the first frame of a cache list, clearing its state
/// word (the frame is about to be owned by a caller, or handed to the zone).
#[inline]
fn cache_list_pop(head: &mut u64) -> Option<u64> {
    let frame = *head;
    if frame == buddy::NO_FRAME {
        return None;
    }
    // A frame only gets onto a list through `cache_list_push`, which needs
    // its state word, and words are never removed. Anything else in the word
    // means allocator metadata was overwritten; following the link would hand
    // out an arbitrary frame.
    let word = FRAME_INDEX.slot(frame);
    let next = word.and_then(|word| buddy::cached_next(word.load(Ordering::Relaxed)));
    let (Some(word), Some(next)) = (word, next) else {
        panic!("frame cache list corrupted at frame {frame:#x}");
    };
    word.store(0, Ordering::Relaxed);
    *head = next;
    Some(frame)
}

struct CpuFrameCache {
    nodes: [NodeFrameCache; MAX_NUMA_NODES],
}

impl CpuFrameCache {
    const fn new() -> Self {
        Self {
            nodes: [NodeFrameCache::new(); MAX_NUMA_NODES],
        }
    }
}

#[repr(align(64))]
struct CpuFrameCacheLock(IrqSafeSpinLock<CpuFrameCache>);

impl CpuFrameCacheLock {
    const fn new() -> Self {
        Self(IrqSafeSpinLock::new(CpuFrameCache::new()))
    }
}

static FRAME_CACHES: [CpuFrameCacheLock; narf_lib::percpu::MAX_CPUS] =
    [const { CpuFrameCacheLock::new() }; narf_lib::percpu::MAX_CPUS];
// Order-0 frames held in per-CPU caches, per node. The ordinary per-node
// free-page totals already include them.
static FRAME_CACHE_FREE: [AtomicUsize; MAX_NUMA_NODES] =
    [const { AtomicUsize::new(0) }; MAX_NUMA_NODES];
// Counts free order-1 blocks, not base pages. The ordinary per-node free-page
// totals already include both frames in every cached pair.
static PAIR_CACHE_FREE: [AtomicUsize; MAX_NUMA_NODES] =
    [const { AtomicUsize::new(0) }; MAX_NUMA_NODES];
#[cfg(feature = "kernel-test")]
static PAIR_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_REFILLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_SPILLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "kernel-test")]
static FRAME_CACHE_BATCH_FREE_LOCKS: AtomicU64 = AtomicU64::new(0);
static FRAME_CACHE_ENABLED: AtomicBool = AtomicBool::new(false);

#[repr(align(64))]
struct FrameCacheDrain {
    lock: IrqSafeSpinLock<()>,
    bypass: AtomicBool,
    /// CPU holding `lock`, plus one; 0 when free. Lets a re-entrant drain on
    /// the same CPU be caught instead of spinning forever with interrupts
    /// off (the lock is IRQ-safe and not re-entrant).
    owner: AtomicUsize,
}

impl FrameCacheDrain {
    const fn new() -> Self {
        Self {
            lock: IrqSafeSpinLock::new(()),
            bypass: AtomicBool::new(false),
            owner: AtomicUsize::new(0),
        }
    }

    /// Whether the calling CPU holds this drain lock. Exact while it does:
    /// the lock masks interrupts, so the holder cannot migrate.
    fn held_by_this_cpu(&self) -> bool {
        self.owner.load(Ordering::Relaxed) == narf_lib::percpu::current_cpu() + 1
    }

    /// Take the drain lock. Lock order: drain -> per-CPU cache -> zone. A
    /// drain is never nested inside another drain of the same node: code
    /// running under one (the closure of `with_node_cache_bypassed`) sees the
    /// node's `bypass` set and must not start a second (see
    /// `with_node_frame_caches_drained`).
    fn lock(&self) -> FrameCacheDrainGuard<'_> {
        assert!(
            !self.held_by_this_cpu(),
            "re-entrant frame-cache drain on one node would self-deadlock"
        );
        let guard = self.lock.lock();
        self.owner
            .store(narf_lib::percpu::current_cpu() + 1, Ordering::Relaxed);
        FrameCacheDrainGuard {
            drain: self,
            _guard: guard,
        }
    }
}

struct FrameCacheDrainGuard<'a> {
    drain: &'a FrameCacheDrain,
    _guard: narf_lib::sync::IrqSafeSpinLockGuard<'a, ()>,
}

impl Drop for FrameCacheDrainGuard<'_> {
    fn drop(&mut self) {
        // Cleared before the lock guard field drops and releases the lock.
        self.drain.owner.store(0, Ordering::Relaxed);
    }
}

static FRAME_CACHE_DRAIN: [FrameCacheDrain; MAX_NUMA_NODES] =
    [const { FrameCacheDrain::new() }; MAX_NUMA_NODES];
static FRAME_CACHE_HOTPLUG_BYPASS: [AtomicBool; MAX_NUMA_NODES] =
    [const { AtomicBool::new(false) }; MAX_NUMA_NODES];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct HotplugRange {
    start: u64,
    len: u64,
    node: usize,
    online: bool,
}

static HOTPLUG_RANGES: IrqSafeSpinLock<Vec<HotplugRange>> = IrqSafeSpinLock::new(Vec::new());
static BOOT_MEMORY_RANGES: IrqSafeSpinLock<Vec<(u64, u64)>> = IrqSafeSpinLock::new(Vec::new());
/// Known RAM, including kernel/ACPI ranges never donated to the allocator.
static BOOT_KNOWN_RAM: IrqSafeSpinLock<Vec<(u64, u64)>> = IrqSafeSpinLock::new(Vec::new());
static BOOT_KNOWN_RAM_SET: AtomicBool = AtomicBool::new(false);
static ONLINE_NODE_MASK: AtomicU64 = AtomicU64::new(1);
static MEMORY_HOTPLUG_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install a post-commit observer for memory-block topology changes.
///
/// The callback runs after allocator and hotplug-registry locks are released,
/// so it may safely query [`memory_blocks`]. Installation is expected once
/// during sysfs initialisation.
pub fn install_memory_hotplug_hook(hook: fn()) {
    MEMORY_HOTPLUG_HOOK.store(hook as usize, Ordering::Release);
}

fn notify_memory_hotplug() {
    let raw = MEMORY_HOTPLUG_HOOK.load(Ordering::Acquire);
    if raw != 0 {
        // SAFETY: only `install_memory_hotplug_hook` stores a function pointer.
        let hook: fn() = unsafe { core::mem::transmute(raw) };
        hook();
    }
}

/// Linux-compatible logical memory-block size. Linux's generic default is
/// 128 MiB; keeping this fixed makes block ids stable across hotplug events.
pub const MEMORY_BLOCK_SIZE: u64 = 128 * 1024 * 1024;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MemoryBlock {
    pub id: u64,
    pub start: u64,
    pub node: usize,
    pub online: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MemoryHotplugError {
    Uninitialised,
    InvalidRange,
    InvalidNode,
    Overlap,
    MetadataCapacity,
    Busy,
    NotOnline,
}

/// A subset of the bootloader memory map: just what the allocator needs.
/// Consumers typically pass `BootInfo::memory_map` via `narf_boot`.
#[derive(Copy, Clone, Debug)]
pub struct UsableRegion {
    pub start: PhysAddr,
    pub len: u64,
}

/// Physical range carved out of the memory map for the bootstrap arena, as
/// `(phys, len)`; `(0, 0)` when the fixed `.bss` array is big enough.
static CARVE_PHYS: AtomicU64 = AtomicU64::new(0);
static CARVE_LEN: AtomicUsize = AtomicUsize::new(0);

/// Bytes the pre-slab buddy reservation will want, from the frame count alone.
///
/// Mirrors `BuddyZone::reservation_bytes` summed over zones, which is possible
/// before the zones exist because the total is distribution-independent:
/// `Σ over orders (frames >> order)` is ~2·frames however the frames are split,
/// and each entry costs 8 bytes in each of the `NUM_MIGRATE_TYPES` partitions.
/// So ~32 bytes per 4 KiB frame, plus the same 25% margin and slack
/// `ensure_bootstrap_headroom` applies.
fn projected_reservation_bytes(total_frames: usize) -> usize {
    let per_frame = 2 * core::mem::size_of::<u64>() * crate::buddy::NUM_MIGRATE_TYPES;
    let need = total_frames.saturating_mul(per_frame);
    // The same margin `ensure_bootstrap_headroom` applies, and no more: this
    // number decides WHETHER to carve, so padding it here would make small
    // machines reserve a range they never needed. A 1 GiB boot projects ~11 MiB
    // against a 12 MiB `.bss` array and must come out with no carve at all,
    // exactly as before this existed.
    need.saturating_add(need / 4).saturating_add(1 << 20)
}

/// Pick a contiguous physical range to host the bootstrap arena, or `None` when
/// the fixed `.bss` array already covers the projected reservation.
///
/// Why a carve-out and not more buddy donations: the arena is a bump allocator,
/// so a single allocation has to fit inside ONE region. The largest free-list
/// Vec is `(zone_frames + 64) * 8` bytes — 32 MiB + 512 for a 16 GiB zone — and
/// a buddy donation can never exceed `1 << MAX_ORDER` frames, i.e. 32 MiB. So a
/// 32 GiB machine failed with "memory allocation of 33554944 bytes failed" no
/// matter how many donations were allowed: the request was 512 bytes larger than
/// the biggest block the buddy can ever hand out. Taking the range before the
/// buddy is populated is what makes an arbitrarily large contiguous arena
/// possible, and is how Linux sources per-page metadata (memblock, pre-buddy).
///
/// Carves from the END of the largest usable region: the low addresses hold the
/// kernel image, the initrd and the firmware tables, and every exclude the
/// caller passed is honoured anyway.
fn plan_bootstrap_carve(
    usable: &[UsableRegion],
    exclude: &[(u64, u64)],
    total_frames: usize,
) -> Option<(u64, usize)> {
    let target = projected_reservation_bytes(total_frames);
    if target <= crate::heap::HEAP_CAPACITY {
        // Small machine: the `.bss` array covers it, so change nothing.
        return None;
    }
    // Slack is added to the SIZE, not to the decision above: once a carve is
    // happening, leave room for the per-zone per-order constants and the other
    // pre-slab bump users (per-CPU init, driver probe).
    let want = (target - crate::heap::HEAP_CAPACITY + (32 << 20)).next_multiple_of(2 << 20);

    let mut best: Option<(u64, usize)> = None;
    for r in usable {
        let start = (r.start.raw() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = (r.start.raw() + r.len) & !(PAGE_SIZE - 1);
        if end <= start || (end - start) as usize <= want {
            continue;
        }
        // Take the tail, 2 MiB aligned.
        let base = (end - want as u64) & !((2 << 20) - 1);
        if base < start {
            continue;
        }
        // Reject if it meets anything the caller already reserved. Checked per
        // page because an exclude may sit anywhere inside the tail.
        let mut clear = true;
        let mut a = base;
        while a < base + want as u64 {
            if is_excluded(a, exclude) {
                clear = false;
                break;
            }
            a += PAGE_SIZE;
        }
        if !clear {
            continue;
        }
        if best.is_none_or(|(_, len)| want > len) {
            best = Some((base, want));
        }
    }
    best
}

/// The carved bootstrap-arena range, if one was reserved by `init_from_map`.
pub fn bootstrap_carve() -> Option<(u64, usize)> {
    let len = CARVE_LEN.load(Ordering::Acquire);
    (len != 0).then(|| (CARVE_PHYS.load(Ordering::Acquire), len))
}

/// Initialise the frame allocator from a slice of usable regions. `exclude`
/// is a list of half-open byte ranges that must NOT be handed out — the
/// kernel image itself, the boot-info structure, the PVH hvm_start_info,
/// and so on.
///
/// Frames go into bin 0 unconditionally — NUMA topology is not yet
/// known at this point in boot. Call `rebalance_to_topology` after
/// SRAT has been parsed to redistribute.
///
/// # Safety
/// - Must be called exactly once, before any `alloc_frame` / `free_frame`.
/// - Each `UsableRegion` must be real, kernel-reachable physical RAM;
///   violating this hands out bogus frames that will fault on first
///   touch.
pub unsafe fn init_from_map(usable: &[UsableRegion], exclude: &[(u64, u64)]) {
    {
        let mut ranges = BOOT_MEMORY_RANGES.lock();
        ranges.clear();
        ranges.extend(usable.iter().filter_map(|region| {
            let start = region.start.raw() & !(PAGE_SIZE - 1);
            let end = region.start.raw().checked_add(region.len)?;
            (start < end).then_some((start, end - start))
        }));
    }
    // Count the frames first so the arena carve-out can be sized from them, then
    // treat the carve as one more excluded range: it must never reach the buddy,
    // because the bump arena hands out pointers into it that are never freed.
    // Counted arithmetically, not by walking every page: this runs before the
    // two passes below, which are already O(frames), and a 1 TiB machine has
    // 268M of them — no reason to add a third walk just to get a total.
    let frame_count: usize = usable
        .iter()
        .map(|r| {
            let first = (r.start.raw() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            let last = (r.start.raw() + r.len) & !(PAGE_SIZE - 1);
            last.checked_sub(first)
                .map_or(0, |span| (span / PAGE_SIZE) as usize)
        })
        .sum();
    let carve = plan_bootstrap_carve(usable, exclude, frame_count);
    let mut eff_exclude: Vec<(u64, u64)> = exclude.to_vec();
    if let Some((base, len)) = carve {
        CARVE_PHYS.store(base, Ordering::Release);
        CARVE_LEN.store(len, Ordering::Release);
        eff_exclude.push((base, base + len as u64));
    }
    let exclude: &[(u64, u64)] = &eff_exclude;

    let mut total = 0usize;
    let mut reserved = 0usize;
    let mut zone0 = ZONES[0].0.lock();
    // First pass: count total + reserved frames for stats.
    for r in usable {
        let start = r.start.raw();
        let end = start + r.len;
        let first = (start + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let last = end & !(PAGE_SIZE - 1);
        let mut a = first;
        while a + PAGE_SIZE <= last {
            total += 1;
            if is_excluded(a, exclude) {
                reserved += 1;
            }
            a += PAGE_SIZE;
        }
    }
    // Second pass: donate sub-ranges that don't overlap any
    // excluded range. Each exclude is (lo_byte, hi_byte) — a
    // half-open byte range. Sub-divide each region accordingly
    // so the buddy gets contiguous sub-ranges to coalesce.
    for r in usable {
        let region_start = (r.start.raw() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let region_end = (r.start.raw() + r.len) & !(PAGE_SIZE - 1);
        if region_start >= region_end {
            continue;
        }
        donate_around_excludes(&mut zone0, region_start, region_end, exclude);
    }
    for node in 0..MAX_NUMA_NODES {
        ALLOC.node_total_frames[node].store(0, Ordering::Relaxed);
        ALLOC.node_free_frames[node].store(0, Ordering::Relaxed);
    }
    let free = zone0.free_frame_count();
    ALLOC.node_total_frames[0].store(free, Ordering::Relaxed);
    ALLOC.node_free_frames[0].store(free, Ordering::Relaxed);
    ALLOC.total_frames.store(total, Ordering::Relaxed);
    ALLOC.reserved_frames.store(reserved, Ordering::Relaxed);
    ALLOC.numa_aware.store(false, Ordering::Relaxed);
    drop(zone0);
    // Opt the LIVE allocator's zones into frame-alloc-audit (no-op unless
    // the feature is set). Standalone unit-test `BuddyZone`s never call
    // this, so their synthetic frame numbers stay out of the global audit
    // bitmap (which would otherwise false-positive on their fabricated
    // 0x100-style frames).
    #[cfg(feature = "frame-alloc-audit")]
    for zone in &ZONES {
        zone.0.lock().enable_audit();
    }
    // Publish only after every free list and accounting field is complete.
    ALLOC.initialised.store(true, Ordering::Release);
    // Zone locks are released before installing the default `FrameAlloc` —
    // `install_frame_alloc_default` takes its own lock and we don't want to
    // risk an unrelated future reentrancy regression.
    install_frame_alloc_default();
    // NOTE: we deliberately do NOT promote the global allocator to
    // the slab here, and we do not pre-reserve buddy Vec capacity
    // until after `rebalance_to_topology` has redistributed frames
    // to their proper NUMA zones. `reserve_for_slab_promotion()`
    // does the per-zone reservation just before promote_to_slab —
    // sized to the actual zone contents, not the worst-case
    // total. Both are called from bare_main once ACPI is up.
}

/// Pre-reserve buddy Vec capacity in every populated zone so that
/// split / coalesce pushes never realloc-grow at runtime. Critical
/// for deadlock-avoidance once the slab is the global allocator:
/// a Vec growth would route through slab → buddy → the same zone lock
/// (already held by the buddy) → recursive deadlock.
///
/// Call this once, AFTER `rebalance_to_topology` has populated
/// each zone, and BEFORE `crate::heap::promote_to_slab()` flips
/// the global allocator. While we're still on bump, the
/// reservation allocations themselves don't recurse.
pub fn reserve_for_slab_promotion() {
    // The reservation below runs one zone at a time and, on a large
    // machine, wants far more than the fixed 12 MiB `.bss` bootstrap
    // arena holds — ~32 bytes/frame, so ~1.5 GiB was the hard ceiling
    // before this path existed and an 8 GiB boot died right here. Buddy
    // frames are already live, so top the bootstrap arena up from the
    // buddy FIRST, without holding the lock, then reserve.
    //
    // (This comment said 16 bytes/frame, halving the real cost: the
    // per-order capacity is reserved once per migratetype and there are
    // two. The same error in `heap.rs` is what sized the spill capacity
    // for ~25 GiB while claiming 64.)
    // Hand the arena its carved-out range first, if there is one. Done here
    // rather than in `init_from_map` because the arena needs a mapped VA and the
    // direct map only exists after `init_mmu`; the range is already excluded
    // from the buddy, so nothing else can have taken it in between.
    if let Some((base, len)) = bootstrap_carve() {
        let vbase = PhysAddr::new(base).kernel_mut_ptr::<u8>();
        // SAFETY: excluded from every donation in `init_from_map`, so it is RAM
        // owned by nobody else, and reachable through the live direct map. The
        // bump arena never frees, which matches the carve being permanent.
        unsafe {
            crate::heap::add_bootstrap_spill(vbase, len);
        }
    }
    let need: usize = ZONES
        .iter()
        .map(|zone| zone.0.lock().reservation_bytes())
        .sum();
    ensure_bootstrap_headroom(need);

    for zone in &ZONES {
        zone.0.lock().reserve_growth_capacity();
    }
    // Give every boot frame a state word, then have each zone mirror its free
    // lists into them: from here a buddy lookup is one load instead of a scan
    // of the free list. The sections come out of the buddy (8 bytes per frame
    // of RAM, in 128 MiB granules), so they are taken before any zone is
    // indexed and need nothing from the bootstrap arena beyond one small
    // table per 512 GiB. A section that cannot be allocated just leaves its
    // frames on the scanning path.
    let boot_ranges = BOOT_MEMORY_RANGES.lock().clone();
    for &(start, len) in &boot_ranges {
        let first = start >> PAGE_SHIFT;
        let end = start.saturating_add(len).saturating_add(PAGE_SIZE - 1) >> PAGE_SHIFT;
        cover_frames_with_state(first, end.saturating_sub(first), None);
    }
    // Every frame not on a free list now is allocated with an order nobody
    // recorded: mark them all, then let each zone write its free blocks'
    // words (and clear their interiors) over that.
    FRAME_INDEX.fill(buddy::STATE_LEGACY);
    for (node, zone) in ZONES.iter().enumerate() {
        zone.0.lock().enable_index(&FRAME_INDEX, node);
    }
    // Free-list Vecs can no longer grow recursively through the slab, and
    // cached frames have state words to be linked through. This is the safe
    // publication point for the per-CPU caches even on UMA machines that
    // never publish `numa_aware`.
    FRAME_CACHE_ENABLED.store(true, Ordering::Release);
}

/// Give every frame of `[first_frame, first_frame + count)` a state word,
/// installing whichever index sections are missing. Returns
/// `(covered, installed)`: whether the whole range now has words, and whether
/// any section was newly installed (a zone that might already list frames of
/// it then needs [`BuddyZone::sync_index`]).
///
/// Each section's words are allocated on `node` when the caller names one (a
/// hot-plugged range, whose node the topology tables do not know yet), else
/// on the node the section's own first frame belongs to.
///
/// Allocates from the buddy and from the heap: never call it under a zone or
/// frame-cache lock.
fn cover_frames_with_state(first_frame: u64, count: u64, node: Option<usize>) -> (bool, bool) {
    if count == 0 {
        return (true, false);
    }
    let mut covered = true;
    let mut installed = false;
    let last = (first_frame + (count - 1)) >> buddy::STATE_SECTION_SHIFT;
    for section in (first_frame >> buddy::STATE_SECTION_SHIFT)..=last {
        if FRAME_INDEX.has_section(section) {
            continue;
        }
        let home = node
            .unwrap_or_else(|| phys_to_node(section << (buddy::STATE_SECTION_SHIFT + PAGE_SHIFT)));
        let Some((block, words)) = alloc_state_section(home) else {
            covered = false;
            continue;
        };
        // When the index declines `words` it keeps no copy of the reference,
        // and this function does not use it again: freeing the block below
        // leaves nothing that can reach its memory.
        if FRAME_INDEX.install_section(section, words) {
            installed = true;
        } else {
            // Out of table memory, or a racing caller installed the section
            // first (`has_section` tells which). The frames go back.
            free_block(block, STATE_SECTION_ORDER, buddy::MigrateType::Unmovable);
            covered &= FRAME_INDEX.has_section(section);
        }
    }
    (covered, installed)
}

/// Bytes of state words in one index section, and the buddy order that
/// holds exactly that many.
const STATE_SECTION_BYTES: usize = buddy::STATE_SECTION_FRAMES * core::mem::size_of::<AtomicU64>();
const STATE_SECTION_ORDER: u8 = (STATE_SECTION_BYTES / PAGE_SIZE as usize).trailing_zeros() as u8;
const _: () = assert!(STATE_SECTION_BYTES == (PAGE_SIZE as usize) << STATE_SECTION_ORDER);
const _: () = assert!(STATE_SECTION_ORDER <= MAX_ORDER);

/// One section's worth of zeroed state words, in frames taken from the buddy
/// (preferring `node`), together with the block that backs them.
fn alloc_state_section(node: usize) -> Option<(PhysFrame, &'static [AtomicU64])> {
    let block =
        alloc_pages_on_inner(node, STATE_SECTION_ORDER, buddy::MigrateType::Unmovable).ok()?;
    let words = block.start_address().kernel_mut_ptr::<AtomicU64>();
    // SAFETY: `block` is `1 << STATE_SECTION_ORDER` contiguous frames the
    // buddy just handed out, so this code is their only owner; `words` is
    // their direct-map (or boot identity-map) address, valid and writable
    // for the kernel's lifetime — the same footing as the bootstrap-arena
    // donation in `ensure_bootstrap_headroom`. The block is exactly
    // `STATE_SECTION_BYTES` long (asserted above) and page-aligned, which
    // satisfies `AtomicU64`'s alignment; an all-zero `AtomicU64` is a valid
    // value. The slice is created only after the bytes are initialised and is
    // only ever shared (never `&mut`). `'static` holds because the block is
    // freed in exactly one case — `cover_frames_with_state`, when
    // `install_section` declined the slice and so kept no reference to it —
    // and the slice is not touched again after that.
    let words = unsafe {
        core::ptr::write_bytes(words, 0, buddy::STATE_SECTION_FRAMES);
        core::slice::from_raw_parts(words.cast_const(), buddy::STATE_SECTION_FRAMES)
    };
    Some((block, words))
}

/// Make sure the bootstrap bump arena can satisfy `need` more bytes,
/// donating buddy-allocated RAM to it when the `.bss` array falls short.
///
/// Runs while the global allocator is still the bump arena (pre
/// `promote_to_slab`), so the donated frames' bookkeeping doesn't
/// recurse into the slab. Each donation is one buddy allocation of up
/// to `1 << MAX_ORDER` frames; a handful covers a very large machine.
fn ensure_bootstrap_headroom(need: usize) {
    // A margin over the bare reservation: `reserve_exact` strands the
    // free lists' pre-existing (doubling-grown) buffers, and boot has
    // other bump users still to come (per-CPU init, driver probe).
    let target = need.saturating_add(need / 4).saturating_add(1 << 20);
    let mut have = crate::heap::bootstrap_remaining();
    if have >= target {
        return;
    }

    const MAX_CHUNK_ORDER: u8 = MAX_ORDER; // 1 << 13 frames = 32 MiB
    let mut guard = 0;
    while have < target {
        let deficit = target - have;
        // Smallest order whose block covers the remaining deficit,
        // capped at the buddy's largest allocation.
        let want_frames = deficit.div_ceil(PAGE_SIZE as usize).max(1);
        let mut order = 0u8;
        while order < MAX_CHUNK_ORDER && (1usize << order) < want_frames {
            order += 1;
        }
        // `alloc_pages_on` already falls back across NUMA nodes when
        // node 0 can't satisfy the order.
        let Ok(base) = alloc_pages_on(0, order) else {
            // Can't grow the arena. The reservation may still fit what
            // we already have; if not, the existing OOM panic reports it
            // — no worse than before this path existed.
            crate::heap::set_bootstrap_shortfall(target.saturating_sub(have));
            return;
        };
        let bytes = (1usize << order) * PAGE_SIZE as usize;
        let vbase = base.start_address().kernel_mut_ptr::<u8>();
        // SAFETY: `base` is `1<<order` contiguous frames just handed out
        // by the buddy (so owned by us, mapped, writable), and `vbase` is
        // its identity or direct-map VA, valid for the kernel's lifetime.
        // The bump arena never frees, matching the donation's
        // leak-forever contract.
        let donated = unsafe { crate::heap::add_bootstrap_spill(vbase, bytes) };
        if !donated {
            // All spill slots full — we've donated as much as the arena can
            // track. Record the shortfall before giving up: this used to return
            // silently, and the boot then died in `handle_alloc_error` with
            // nothing pointing at MAX_SPILL_REGIONS as the limit. That is how a
            // 32 GiB machine failed to boot while the sizing comment claimed 64.
            crate::heap::set_bootstrap_shortfall(target.saturating_sub(have));
            return;
        }
        have += bytes;
        guard += 1;
        if guard > crate::heap::MAX_SPILL_REGIONS + 4 {
            // Defensive: never spin. Tied to the slot count, which is the real
            // limit — a bare 64 here silently capped donations below the slot
            // capacity once that count was raised past it.
            crate::heap::set_bootstrap_shortfall(target.saturating_sub(have));
            break;
        }
    }
}

/// Donate the byte range `[start, end)` to `zone`, splitting around
/// any excluded sub-ranges. Aligns each sub-range to page boundaries
/// before donating.
fn donate_around_excludes(zone: &mut BuddyZone, start: u64, end: u64, exclude: &[(u64, u64)]) {
    // Walk left to right, emitting sub-ranges between excludes.
    let mut cursor = start;
    // Collect overlapping excludes, sorted by start.
    let mut hits: Vec<(u64, u64)> = exclude
        .iter()
        .copied()
        .filter(|&(lo, hi)| hi > start && lo < end)
        .map(|(lo, hi)| (lo.max(start), hi.min(end)))
        .collect();
    hits.sort_by_key(|&(lo, _)| lo);
    for (lo, hi) in hits {
        // Round excluded range OUT to page boundaries (anything
        // touching an excluded byte is fully reserved).
        let lo_page = lo & !(PAGE_SIZE - 1);
        let hi_page = (hi + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if cursor < lo_page {
            donate_range(zone, cursor, lo_page);
        }
        cursor = hi_page.max(cursor);
    }
    if cursor < end {
        donate_range(zone, cursor, end);
    }
}

/// Lowest phys address the buddy is allowed to hand out. The first
/// MiB of physical RAM is conventionally reserved on x86 — it
/// contains the BIOS data area, the IVT (real-mode), the EBDA,
/// the SMP AP trampoline (0x8000), VGA framebuffer remnants, and
/// other firmware-owned regions. Even though the bootloader
/// memory map sometimes marks it "Available", handing it out as
/// a real allocation collides with these uses (most painfully:
/// the AP trampoline at 0x8000).
///
/// The previous Vec-based frame allocator masked this because
/// `Vec::pop` returned high frames first; the buddy, splitting
/// from any order, can return low frames early. Skip the first
/// MiB unconditionally.
pub(crate) const LOW_RESERVED_BYTES: u64 = 0x100000;

/// Donate `[start, end)` (page-aligned) to `zone` as a single contiguous run.
/// Skips the first MiB of phys (BIOS / SMP trampoline territory).
fn donate_range(zone: &mut BuddyZone, start: u64, end: u64) {
    debug_assert_eq!(start & (PAGE_SIZE - 1), 0);
    debug_assert_eq!(end & (PAGE_SIZE - 1), 0);
    if end <= start {
        return;
    }
    let start = start.max(LOW_RESERVED_BYTES);
    if end <= start {
        return;
    }
    let first_frame = start >> PAGE_SHIFT;
    let frame_count = (end - start) >> PAGE_SHIFT;
    zone.donate(first_frame, frame_count);
}

fn is_excluded(addr: u64, exclude: &[(u64, u64)]) -> bool {
    exclude.iter().any(|&(lo, hi)| addr >= lo && addr < hi)
}

/// Redistribute frames currently in zones[0] across per-NUMA-node
/// zones according to `narf_phys_to_node`. Call this once after ACPI
/// SRAT has been parsed (`narf_acpi::parse_srat`). Idempotent —
/// repeated calls are no-ops.
///
/// The buddy is per-zone; we move whole free blocks based on the
/// node of their starting frame. (A multi-frame block crossing a
/// node boundary stays with its starting node — rare in practice
/// since SRAT memory ranges are typically aligned to large
/// boundaries.)
pub fn rebalance_to_topology() {
    let _transition = REBALANCE_LOCK.lock();
    debug_assert!(
        !FRAME_CACHE_ENABLED.load(Ordering::Acquire),
        "NUMA rebalance must precede frame-cache publication"
    );
    if ALLOC.numa_aware.load(Ordering::Acquire) || !ALLOC.initialised.load(Ordering::Acquire) {
        return;
    }
    // Move blocks from zones[0] to their proper node zones.
    // Always lock the lower node first. Rebalance is a boot-time,
    // pre-SMP transition; publishing `numa_aware` after every move makes
    // the completed topology visible atomically to later hot paths.
    for (target, target_zone) in ZONES.iter().enumerate().skip(1) {
        let mut src = ZONES[0].0.lock();
        let mut dst = target_zone.0.lock();
        src.drain_into(&mut dst, |frame_no| {
            let phys = frame_no << PAGE_SHIFT;
            phys_to_node(phys) == target
        });
    }
    for (node, zone) in ZONES.iter().enumerate() {
        let total = zone.0.lock().free_frame_count();
        ALLOC.node_total_frames[node].store(total, Ordering::Relaxed);
        ALLOC.node_free_frames[node].store(total, Ordering::Relaxed);
    }
    let mut online = 0u64;
    for node in 0..MAX_NUMA_NODES {
        if ALLOC.node_total_frames[node].load(Ordering::Relaxed) != 0 {
            online |= 1u64 << node;
        }
    }
    ONLINE_NODE_MASK.store(online.max(1), Ordering::Release);
    ALLOC.numa_aware.store(true, Ordering::Release);
}

/// Dynamically add a real, kernel-addressable RAM range to one NUMA node.
///
/// # Safety
/// The caller must prove the range is RAM, is mapped in the kernel direct
/// map, and does not overlap boot RAM, MMIO, or any previously managed range.
pub unsafe fn online_memory_range(
    start: PhysAddr,
    len: u64,
    node: usize,
) -> Result<(), MemoryHotplugError> {
    if node >= MAX_NUMA_NODES {
        return Err(MemoryHotplugError::InvalidNode);
    }
    if len == 0
        || start.raw() & (PAGE_SIZE - 1) != 0
        || len & (PAGE_SIZE - 1) != 0
        || start.raw().checked_add(len).is_none()
    {
        return Err(MemoryHotplugError::InvalidRange);
    }
    let first_frame = start.raw() >> PAGE_SHIFT;
    let frame_count = len >> PAGE_SHIFT;
    // The new frames need state words before the buddy can list them in O(1).
    // Installing a section allocates (buddy frames, possibly a heap table) and
    // may free again, and a free can consult the hot-plug registry for the
    // frame's node — so it happens here, before that registry is locked. A
    // range refused further down keeps its words; they describe no free frame
    // and cost nothing but their memory.
    let mut new_sections = false;
    if ALLOC.initialised.load(Ordering::Acquire) {
        let (covered, installed) = cover_frames_with_state(first_frame, frame_count, Some(node));
        if !covered {
            return Err(MemoryHotplugError::MetadataCapacity);
        }
        new_sections = installed;
    }
    let mut ranges = HOTPLUG_RANGES.lock();
    let end = start.raw() + len;
    let existing = ranges
        .iter()
        .position(|range| range.start < end && start.raw() < range.start + range.len);
    let reused = if let Some(index) = existing {
        let range = ranges[index];
        if range.start != start.raw() || range.len != len || range.node != node || range.online {
            return Err(MemoryHotplugError::Overlap);
        }
        ranges[index].online = true;
        true
    } else {
        ranges.push(HotplugRange {
            start: start.raw(),
            len,
            node,
            online: true,
        });
        false
    };
    // Runtime ranges must remain wholly visible to `remove_free_range`.
    // Disable page caching on this node before the new frames are donated;
    // an in-flight cache operation that began earlier can only see pre-existing
    // boot frames because the range is not in the buddy yet. The node's
    // caches are emptied in the same pass: with caching off, frames left in
    // them would never be allocated again.
    FRAME_CACHE_HOTPLUG_BYPASS[node].store(true, Ordering::Release);
    drain_bypassed_node_caches(node);

    if !ALLOC.initialised.load(Ordering::Acquire) {
        if reused {
            if let Some(range) = ranges
                .iter_mut()
                .find(|range| range.start == start.raw() && range.len == len)
            {
                range.online = false;
            }
        } else {
            ranges.pop();
        }
        let still_online = ranges
            .iter()
            .any(|range| range.node == node && range.online);
        FRAME_CACHE_HOTPLUG_BYPASS[node].store(still_online, Ordering::Release);
        return Err(MemoryHotplugError::Uninitialised);
    }
    let mut zone = ZONES[node].0.lock();
    if !zone.can_donate_without_growth(first_frame, frame_count) {
        if reused {
            if let Some(range) = ranges
                .iter_mut()
                .find(|range| range.start == start.raw() && range.len == len)
            {
                range.online = false;
            }
        } else {
            ranges.pop();
        }
        let still_online = ranges
            .iter()
            .any(|range| range.node == node && range.online);
        FRAME_CACHE_HOTPLUG_BYPASS[node].store(still_online, Ordering::Release);
        return Err(MemoryHotplugError::MetadataCapacity);
    }
    zone.donate(first_frame, frame_count);
    if new_sections {
        // Nothing should already list a frame of a section that had no words
        // until now; if something does, bring it into the index rather than
        // leave it on the scanning path. O(free blocks), once per new section.
        zone.sync_index();
    }
    account_freed_frames(node, frame_count as usize);
    ALLOC.node_total_frames[node].fetch_add(frame_count as usize, Ordering::Relaxed);
    ALLOC
        .total_frames
        .fetch_add(frame_count as usize, Ordering::Relaxed);
    ONLINE_NODE_MASK.fetch_or(1u64 << node, Ordering::AcqRel);
    drop(zone);
    drop(ranges);
    notify_memory_hotplug();
    Ok(())
}

/// Remove an exact hotplug range after proving every frame is free.
///
/// A busy range is left online and returns [`MemoryHotplugError::Busy`].
pub fn offline_memory_range(start: PhysAddr, len: u64) -> Result<usize, MemoryHotplugError> {
    if len == 0 || start.raw() & (PAGE_SIZE - 1) != 0 || len & (PAGE_SIZE - 1) != 0 {
        return Err(MemoryHotplugError::InvalidRange);
    }
    let mut ranges = HOTPLUG_RANGES.lock();
    let Some(index) = ranges
        .iter()
        .position(|range| range.start == start.raw() && range.len == len && range.online)
    else {
        return Err(MemoryHotplugError::NotOnline);
    };
    let range = ranges[index];
    let first_frame = start.raw() >> PAGE_SHIFT;
    let frame_count = len >> PAGE_SHIFT;
    let mut zone = ZONES[range.node].0.lock();
    if !zone.remove_free_range(first_frame, frame_count) {
        return Err(MemoryHotplugError::Busy);
    }
    account_allocated_frames(range.node, frame_count as usize);
    let remaining = ALLOC.node_total_frames[range.node]
        .fetch_sub(frame_count as usize, Ordering::Relaxed)
        - frame_count as usize;
    ALLOC
        .total_frames
        .fetch_sub(frame_count as usize, Ordering::Relaxed);
    ranges[index].online = false;
    let still_online = ranges
        .iter()
        .any(|candidate| candidate.node == range.node && candidate.online);
    FRAME_CACHE_HOTPLUG_BYPASS[range.node].store(still_online, Ordering::Release);
    if remaining == 0 {
        ONLINE_NODE_MASK.fetch_and(!(1u64 << range.node), Ordering::AcqRel);
    }
    drop(zone);
    drop(ranges);
    notify_memory_hotplug();
    Ok(range.node)
}

pub fn online_node_mask() -> u64 {
    ONLINE_NODE_MASK.load(Ordering::Acquire)
}

pub fn online_node_count() -> u32 {
    let mask = online_node_mask();
    if mask == 0 {
        1
    } else {
        64 - mask.leading_zeros()
    }
}

/// Allocate one 4 KiB frame. NUMA-aware: prefers the current CPU's
/// node, falls back round-robin to other nodes when the local bin
/// is empty. Dispatches through the installed `FrameAlloc`.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn alloc_frame() -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    let preferred = current_cpu_node();
    alloc_frame_on_inner(preferred)
}

/// Whether an allocation is servicing the kernel or a userspace mapping.
///
/// The `min` watermark is a reserve the kernel must always be able to draw on:
/// a `Kernel` allocation may take the pool down into it so kernel/atomic work
/// (page tables, slab, fork/teardown metadata) never fails under memory
/// pressure. A `User` allocation (demand fault, COW, stack growth, brk,
/// mmap-populate, page migration) is refused — surfacing as `-ENOMEM` to
/// userspace — once granting it would breach the reserve, so userspace cannot
/// starve the kernel. This is NARF's analogue of Linux's `ALLOC_WMARK_MIN`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AllocContext {
    /// Kernel/atomic allocation — may consume the `min` reserve.
    Kernel,
    /// Userspace-backing allocation — must leave the `min` reserve intact.
    User,
    /// Userspace-backing allocation that MUST succeed to keep a running
    /// process correct, and so may consume the `min` reserve like `Kernel`
    /// while staying `Movable` like `User`. The sole user is a copy-on-write
    /// break (`cow_split_on_write`): the faulting task already owns the shared
    /// page and is performing a legitimate write; refusing the private-copy
    /// frame at the watermark would deliver a spurious SIGSEGV on writable
    /// memory. Linux likewise lets a CoW break dip into reserves rather than
    /// fail the fault. Not a general escape hatch — ordinary demand/mmap/brk
    /// faults stay `User` so userspace still cannot drain the reserve.
    UserReserve,
}

impl AllocContext {
    /// Mobility class for anti-fragmentation grouping. Kernel allocations
    /// are UNMOVABLE (page tables, slab, DMA hold raw physical pointers);
    /// user-backing allocations are MOVABLE (the pages that WOULD be
    /// migratable and that free back in bulk on process teardown). See the
    /// migratetype design note in `buddy.rs`.
    #[inline]
    pub fn migrate_type(self) -> buddy::MigrateType {
        match self {
            AllocContext::Kernel => buddy::MigrateType::Unmovable,
            AllocContext::User | AllocContext::UserReserve => buddy::MigrateType::Movable,
        }
    }
}

/// Central reserve gate. Returns `ReservePressure` (and wakes the reclaimer)
/// when a `User` allocation would breach the `min` watermark reserve; `Kernel`
/// and `UserReserve` allocations always pass (the latter is a CoW break that
/// must not fault a writable page — see [`AllocContext::UserReserve`]).
/// Enforced once, here, so every allocation entry inherits the same policy —
/// an ordinary user path cannot silently drain the reserve.
#[inline]
fn reserve_permits(ctx: AllocContext, node: usize) -> Result<(), FrameAllocError> {
    let node = node.min(MAX_NUMA_NODES - 1);
    // Start background balancing at the low watermark for both kernel and user
    // allocations rather than waiting for either to collide with the protected
    // minimum. Kernel allocations may consume the reserve but must still wake
    // the task-context reclaimer proactively.
    if crate::reclaim::under_low_watermark_node(node) {
        crate::reclaim::wake_kswapd(node);
    }
    if ctx == AllocContext::User {
        if !crate::reclaim::user_alloc_would_breach_reserve() {
            return Ok(());
        }
        // Wake the local node's reclaimer so it can shed clean cache and let
        // the retry succeed. Under an overcommit policy that permits it
        // (Heuristic / Always), also arm the OOM killer so sustained user
        // pressure reclaims a hog rather than only failing the faulting task.
        // Under `Never` (the default) this stays a graceful ENOMEM — no
        // process is killed.
        let ticket = if crate::reclaim::user_pressure_arms_oom() {
            crate::reclaim::request_reclaim_ticket(node, 1, true)
        } else {
            crate::reclaim::request_reclaim_ticket(node, 1, false)
        };
        return ticket.map_or(Err(FrameAllocError::Exhausted), |ticket| {
            Err(FrameAllocError::ReservePressure(ticket))
        });
    }
    Ok(())
}

/// Allocate one CPU-local frame for a userspace mapping, honouring the `min`
/// watermark reserve. Mirrors [`alloc_frame`] but with `User` context.
pub fn alloc_user_frame() -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner_ctx(current_cpu_node(), AllocContext::User)
}

/// Allocate one CPU-local `Movable` frame for a copy-on-write break, permitted
/// to dip into the `min` reserve. See [`AllocContext::UserReserve`]: a CoW split
/// is a legitimate write to a page the process already owns, so it must not be
/// refused at the watermark and turned into a spurious SIGSEGV. Only
/// `cow_split_on_write` uses this; every other user-backing fault stays on the
/// reserve-respecting [`alloc_user_frame`].
pub fn alloc_user_frame_urgent() -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner_ctx(current_cpu_node(), AllocContext::UserReserve)
}

/// Reserve-respecting `User`-context variant of [`alloc_frame_on`].
pub fn alloc_frame_on_ctx(node: usize, ctx: AllocContext) -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner_ctx(node, ctx)
}

/// Reserve-respecting variant of [`alloc_frame_anywhere`].
pub fn alloc_frame_anywhere_ctx(ctx: AllocContext) -> Result<PhysFrame, FrameAllocError> {
    let node = current_cpu_node();
    reserve_permits(ctx, node)?;
    let charge = charge_user_alloc(ctx, node, PAGE_SIZE)?;
    let r = with_installed(|a| a.alloc_frame_anywhere());
    commit_user_charge(charge, &r, PAGE_SIZE);
    r
}

/// `User`-context strict per-node allocation of a page-migration destination.
///
/// Not charged to any memory cgroup: the page being migrated already is, and
/// the caller moves that charge to the new frame with
/// [`transfer_frame_memcg`] (Linux `mem_cgroup_migrate`). Charging the
/// destination to whoever runs the migration — compaction, NUMA balancing,
/// `move_pages` — would bill a cgroup for a page it does not own.
pub fn alloc_user_frame_on_strict(node: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_strict_inner(node, node, AllocContext::User, false)
}

/// Move the memory-cgroup charge of a migrating page from `old` to `new`.
/// Call once the destination exists; the old frame's final free then
/// uncharges nothing, and the new frame's uncharges the original cgroup.
/// No-op without the `cgroup` feature.
pub fn transfer_frame_memcg(old: PhysAddr, new: PhysAddr) {
    #[cfg(feature = "cgroup")]
    cow::transfer_frame_memcg(old, new);
    #[cfg(not(feature = "cgroup"))]
    let _ = (old, new);
}

/// A memory-cgroup charge taken for an allocation that has not happened yet;
/// the charged cgroup, 0 for nothing charged.
#[derive(Copy, Clone)]
#[cfg_attr(not(feature = "cgroup"), allow(dead_code))]
struct UserCharge(u32);

/// Charge a user allocation of `bytes` to the current task's memory cgroup
/// before it is made (Linux charges at fault time, `mem_cgroup_charge`).
/// Kernel allocations are never charged — Linux charges kernel memory only
/// for `__GFP_ACCOUNT` allocations, and nothing here asks for that — so no
/// kernel allocation, the heap's included, can be refused by a cgroup.
///
/// A refused user charge queues an OOM kill inside the cgroup that hit its
/// `memory.max` (run by the OOM reaper, with no lock held) and returns
/// `ReservePressure`, so a faulting task waits for a reclaim cycle and
/// retries instead of taking SIGSEGV. A copy-on-write break (`UserReserve`)
/// is force-charged past the limit, as Linux does for allocations that must
/// not fail.
#[cfg(feature = "cgroup")]
fn charge_user_alloc(
    ctx: AllocContext,
    node: usize,
    bytes: u64,
) -> Result<UserCharge, FrameAllocError> {
    if ctx == AllocContext::Kernel {
        return Ok(UserCharge(0));
    }
    let force = ctx == AllocContext::UserReserve;
    match crate::cgroup_charge::charge_current(bytes, force) {
        Ok((id, _)) => Ok(UserCharge(id)),
        Err((id, pid)) => {
            crate::cgroup_charge::request_memcg_oom(id, pid);
            let node = node.min(MAX_NUMA_NODES - 1);
            Err(crate::reclaim::request_reclaim_ticket(node, 1, false)
                .map_or(FrameAllocError::Exhausted, FrameAllocError::ReservePressure))
        }
    }
}

#[cfg(not(feature = "cgroup"))]
#[inline]
fn charge_user_alloc(
    _ctx: AllocContext,
    _node: usize,
    _bytes: u64,
) -> Result<UserCharge, FrameAllocError> {
    Ok(UserCharge(0))
}

/// Finish a charge taken by [`charge_user_alloc`]: record it on the block's
/// head frame when the allocation succeeded, refund it when it failed.
#[inline]
fn commit_user_charge(charge: UserCharge, result: &Result<PhysFrame, FrameAllocError>, bytes: u64) {
    #[cfg(feature = "cgroup")]
    match result {
        Ok(frame) => cow::set_frame_memcg(frame.start_address(), charge.0),
        Err(_) => crate::cgroup_charge::uncharge_memcg(charge.0, bytes),
    }
    #[cfg(not(feature = "cgroup"))]
    let _ = (charge, result, bytes);
}

/// Charge a `1 << order` block the caller has just allocated with kernel
/// context to the current task's memory cgroup, as user memory: a page-cache
/// folio a task reads or faults in, a shmem/tmpfs page (Linux
/// `mem_cgroup_charge` on the new folio). On `Err` nothing was charged and
/// the caller must free the block and fail its operation (ENOMEM); a refusal
/// also queues an OOM kill inside the cgroup at its limit. The block's final
/// free (`free_frame` / `free_pages`) uncharges the same cgroup. A task with
/// no memory cgroup, and kernel threads, charge nothing. No-op without the
/// `cgroup` feature.
pub fn charge_frame_to_current(frame: PhysFrame, order: u8) -> Result<(), FrameAllocError> {
    #[cfg(feature = "cgroup")]
    {
        let bytes = PAGE_SIZE << order;
        let charge = charge_user_alloc(AllocContext::User, current_cpu_node(), bytes)?;
        cow::set_frame_memcg(frame.start_address(), charge.0);
    }
    #[cfg(not(feature = "cgroup"))]
    let _ = (frame, order);
    Ok(())
}

/// Return the memory-cgroup charge recorded on `head` for a `bytes` block
/// that is being freed. Allocation-free.
#[inline]
fn uncharge_freed_block(head: PhysAddr, bytes: u64) {
    #[cfg(feature = "cgroup")]
    crate::cgroup_charge::uncharge_memcg(cow::take_frame_memcg(head), bytes);
    #[cfg(not(feature = "cgroup"))]
    let _ = (head, bytes);
}

/// Phys-address ceiling for early boot. While set, alloc_frame*
/// returns only frames whose physical address is strictly below
/// this value. Reason: pre-MMU-init code (per-domain PML4 setup,
/// init_mmu's own page tables, anything that writes through
/// `phys.kernel_mut_ptr::<T>()`) only works when phys is in the
/// boot.S identity map (currently 0..4 GiB). On systems with
/// the q35 PCI-hole RAM split (real Zen2 laptops with 16 GiB,
/// QEMU q35 with -m ≥ 4G) usable RAM straddles 4 GiB; an
/// unconstrained allocator would hand out high frames and
/// trigger a #PF on first access.
///
/// Default 4 GiB. Cleared (set to 0 = unlimited) by
/// `release_early_ceiling()` once a kernel direct map covers
/// all RAM — typically after MMU init + a high-mem ioremap pass.
pub(crate) static EARLY_PHYS_CEILING: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(4u64 << 30);

/// Upper bound a physical address handed out by the frame allocator must stay
/// under, for the CURRENT stage of boot.
///
/// [`EARLY_PHYS_CEILING`] while it is in force, and the top of boot-donated RAM
/// once [`release_early_ceiling`] has lifted it. Both answer the same question —
/// "is this address one the kernel can actually reach?" — and which one applies
/// changes when the direct map comes up.
///
/// Exists because several tests hardcoded `4 GiB`, which was only ever the
/// ceiling's DEFAULT value. Once the direct map covers all RAM the ceiling is
/// deliberately cleared and frames above 4 GiB are both legal and reachable, so
/// those tests failed on any host with more than 4 GiB of RAM while the code was
/// behaving correctly. A count-derived bound (`total_frames * PAGE_SIZE`) is not
/// a substitute: RAM is not contiguous from 0, so a frame legitimately above
/// that size still sits in usable RAM.
pub fn phys_alloc_ceiling() -> u64 {
    let early = EARLY_PHYS_CEILING.load(core::sync::atomic::Ordering::Acquire);
    if early != 0 {
        return early;
    }
    managed_phys_end()
}

/// End of the physical window the kernel can actually reach through
/// [`PhysAddr::kernel_ptr`], for the CURRENT stage of boot — the bound the
/// SEC-F2 ACPI table-window check (`acpi::check_table_window`) validates
/// firmware table pointers against.
///
/// This is deliberately NOT [`phys_alloc_ceiling`]. That is the top of
/// boot-donated *Usable* RAM, which the frame allocator may hand out — but
/// firmware tables live in ACPI-reclaimable RAM above it, and the high-half
/// direct map covers them anyway: on x86_64 `init_mmu` fills every chunk's
/// PDPT with all 512 x 1-GiB entries, so the map spans `[0, dmap_chunks *
/// 512 GiB)` regardless of installed RAM. Bounding the check by the
/// allocator ceiling therefore rejects every table deterministically (all
/// of SRAT/MADT/MCFG/FADT/... skipped with `OutOfMappedWindow`, 0 PCIe
/// devices bound — main b59be050, CI run 42309866130); the direct-map
/// extent is the correct bound.
///
/// Stages, x86_64: direct-map extent once `init_mmu` publishes it, else
/// [`EARLY_PHYS_CEILING`] (4 GiB — the pre-`init_mmu` identity map covers
/// `[0, 4 GiB)`). Other arches: [`phys_alloc_ceiling`] unchanged — there is
/// no ACPI production consumer there (aarch64 uses DT for PCIe) and the
/// TTBR1 window covers installed RAM.
///
/// Fail-closed: 0 (nothing published yet — direct map not live and the
/// early ceiling already released) rejects every table.
pub fn mapped_window_end() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        let end = crate::addr::direct_map_phys_end();
        if end != 0 {
            return end;
        }
        EARLY_PHYS_CEILING.load(core::sync::atomic::Ordering::Acquire)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        phys_alloc_ceiling()
    }
}

/// Allow the allocator to return frames at any physical address.
/// Call once a kernel direct map covers all installed RAM.
pub fn release_early_ceiling() {
    EARLY_PHYS_CEILING.store(0, core::sync::atomic::Ordering::Release);
}

/// Pop a frame from `zone` whose phys address is below the early
/// ceiling. Returns None if no qualifying block is available at
/// order 0. Uses the buddy zone's `alloc_below` which honors the
/// ceiling at the frame-number level.
fn alloc_below_ceiling(zone: &mut BuddyZone) -> Option<PhysFrame> {
    let ceil_frame = buddy::early_ceiling_frame();
    let frame_no = if ceil_frame == u64::MAX {
        zone.alloc(0)?
    } else {
        zone.alloc_below(0, ceil_frame)?
    };
    Some(buddy::frame_from_no(frame_no))
}

#[inline]
fn frame_cache_bypassed(node: usize) -> bool {
    FRAME_CACHE_DRAIN[node].bypass.load(Ordering::Acquire)
        || FRAME_CACHE_HOTPLUG_BYPASS[node].load(Ordering::Acquire)
}

/// Take one order-0 frame straight from `node`'s zone: the path while the
/// caches are unpublished or bypassed for the node.
fn alloc_order0_from_zone(node: usize) -> Option<PhysFrame> {
    let frame = alloc_below_ceiling(&mut lock_zone(node))?;
    account_allocated_frames(node, 1);
    Some(frame)
}

/// `node` is below its share of the high watermark (Linux `ZONE_BELOW_HIGH`):
/// its caches stop growing and start handing their ceiling back.
#[inline]
fn node_below_high(node: usize) -> bool {
    crate::reclaim::reclaim_goal_node(node) != 0
}

/// `node` is below its share of the low watermark, where its reclaimer runs
/// (the condition Linux tracks as `ZONE_RECLAIM_ACTIVE`): its caches keep
/// only a few batches.
#[inline]
fn node_reclaiming(node: usize) -> bool {
    crate::reclaim::under_low_watermark_node(node)
}

/// Frames to take from the zone to refill an empty cache, the one the caller
/// is waiting for included (Linux `nr_pcp_alloc`). Each consecutive refill
/// doubles the batch, up to `batch << CACHE_BATCH_SCALE_MAX` and never past
/// what fits under `high`; `high` itself grows by the batch, since a larger
/// cache would have saved this trip to the zone — unless the node is short.
fn cache_refill_count(local: &mut NodeFrameCache, tuning: CacheTuning, node: usize) -> usize {
    local.high = local.high.clamp(tuning.high_min, tuning.high_max);
    // The node's sizing may have shrunk since the last free computed its
    // trigger (a CPU count learned later in boot, memory taken offline).
    local.trim_at = local.trim_at.min(local.high);
    if local.high < tuning.batch {
        return 1;
    }
    let batch = tuning.batch << local.alloc_factor;
    if tuning.high_min != tuning.high_max && !node_below_high(node) {
        local.high = (local.high + batch).min(tuning.high_max);
    }
    let room = local
        .high
        .saturating_sub(local.count)
        .saturating_sub(tuning.batch)
        .max(tuning.batch);
    if batch <= room && u32::from(local.alloc_factor) < CACHE_BATCH_SCALE_MAX {
        local.alloc_factor += 1;
    }
    batch.min(room)
}

/// Order-0 allocator front-end. Once the frame-state index is live, each CPU
/// keeps a list of free frames per node and refills it with a whole batch
/// under one zone-lock acquisition. The per-CPU lock also masks local IRQs,
/// preventing same-CPU re-entry from duplicating a frame.
fn alloc_order0_on(node: usize) -> Option<PhysFrame> {
    let node = node.min(MAX_NUMA_NODES - 1);
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        return alloc_order0_from_zone(node);
    }

    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    // A drain may have begun between the optimistic check and taking this
    // CPU's lock. Bypass under that transition so the drainer cannot miss a
    // newly cached frame.
    if frame_cache_bypassed(node) {
        drop(cache);
        return alloc_order0_from_zone(node);
    }
    let local = &mut cache.nodes[node];
    // An allocation interrupts a streak of frees (Linux `rmqueue_pcplist`).
    local.free_count >>= 1;
    if let Some(frame) = cache_list_pop(&mut local.frames) {
        FRAME_INDEX.mark_allocated(frame, 0);
        local.count -= 1;
        FRAME_CACHE_FREE[node].fetch_sub(1, Ordering::Relaxed);
        account_allocated_frames(node, 1);
        #[cfg(feature = "kernel-test")]
        FRAME_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        buddy::audit_cached_alloc(frame);
        return Some(buddy::frame_from_no(frame));
    }

    #[cfg(feature = "kernel-test")]
    FRAME_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    let want = cache_refill_count(local, cache_tuning(node), node);
    let mut zone = lock_zone(node);
    let Some(first) = alloc_below_ceiling(&mut zone) else {
        drop(zone);
        drop(cache);
        return alloc_order0_after_drain(node);
    };
    let mut refilled = 0usize;
    for _ in 1..want {
        let Some(extra) = alloc_below_ceiling(&mut zone) else {
            break;
        };
        let frame = buddy::frame_no(extra);
        // The zone marked it allocated; it is free again, in this cache.
        let linked = FRAME_INDEX.slot(frame).is_some_and(|word| {
            word.store(0, Ordering::Relaxed);
            cache_list_push(&mut local.frames, frame, word)
        });
        if !linked {
            // No state word to link it through (no index section covers the
            // frame), so it cannot be cached: hand it straight back and
            // settle for what the refill has.
            zone.free(frame, 0);
            break;
        }
        buddy::audit_cached_free(frame);
        refilled += 1;
    }
    drop(zone);
    local.count += refilled;
    FRAME_CACHE_FREE[node].fetch_add(refilled, Ordering::Relaxed);
    #[cfg(feature = "kernel-test")]
    FRAME_CACHE_REFILLS.fetch_add(1, Ordering::Relaxed);
    account_allocated_frames(node, 1);
    Some(first)
}

/// `node`'s zone has no order-0 frame. Before the node is reported exhausted,
/// return to the zone whatever its per-CPU caches hold — every CPU's, an idle
/// CPU's included — and try once more. Linux drains the per-CPU lists the same
/// way before an allocation fails (`drain_all_pages` on the direct-reclaim
/// retry). Without this, memory parked in other CPUs' caches would turn into
/// allocation failures while still being counted free.
///
/// The caller holds no allocator lock. Skipped, with no lock taken, when the
/// node's caches are empty.
#[cold]
fn alloc_order0_after_drain(node: usize) -> Option<PhysFrame> {
    if FRAME_CACHE_FREE[node].load(Ordering::Relaxed) == 0
        && PAIR_CACHE_FREE[node].load(Ordering::Relaxed) == 0
    {
        return None;
    }
    let frame = with_node_frame_caches_drained(node, alloc_below_ceiling)?;
    account_allocated_frames(node, 1);
    Some(frame)
}

/// What became of a block offered to the calling CPU's cache.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CacheFree {
    /// The cache holds it now.
    Cached,
    /// Not cacheable — caching is off for the node, or the frame has no
    /// state word. The caller returns it directly to the node's zone.
    Declined,
    /// The free was refused (already free, a tail, not allocated, wrong
    /// order): dropped, counted and reported.
    AlreadyFree,
}

/// The page count at or above which `local` must give frames back right now,
/// after adjusting its ceiling (Linux `nr_pcp_high`); `held` is what the cache
/// will hold once the frames being freed are linked. Also sets `trim_at`, the
/// count at which a later free re-evaluates.
fn cache_high_mark(
    local: &mut NodeFrameCache,
    tuning: CacheTuning,
    node: usize,
    held: usize,
) -> usize {
    local.high = local.high.clamp(tuning.high_min, tuning.high_max);
    let high = local.high;
    let streak = local.free_count.max(tuning.batch);
    if node_reclaiming(node) {
        // The node's reclaimer is running: keep only a few batches here.
        local.high = high.saturating_sub(streak).max(tuning.high_min);
        local.trim_at = (tuning.batch << 2).min(local.high);
        return local.trim_at;
    }
    if tuning.high_min == tuning.high_max {
        local.trim_at = high;
        return high;
    }
    if node_below_high(node) {
        // Short of memory but not reclaiming yet: lower the ceiling a streak
        // at a time and trim down towards the floor.
        local.high = high.saturating_sub(streak).max(tuning.high_min);
        local.trim_at = tuning.high_min;
        return held.max(tuning.high_min);
    }
    if held >= high {
        // The streak being freed did not fit; make room for the next one.
        let need = local.free_count + tuning.batch;
        if local.high < need {
            local.high = need.clamp(tuning.high_min, tuning.high_max);
        }
    }
    local.trim_at = local.high;
    high
}

/// Book `incoming` base pages about to be linked onto `local`, trimming the
/// cache first if they would take it to its mark. Caller holds the CPU's
/// cache lock and links the frames afterwards.
///
/// The trim comes BEFORE the link so that what a free just put in the cache
/// is still there for the next allocation — the lists are singly linked and a
/// trim takes from the front. (Linux links first and trims from the back;
/// either way the frames just freed are the ones that stay.)
#[inline]
fn cache_make_room(local: &mut NodeFrameCache, node: usize, incoming: usize, pairs_first: bool) {
    // A free interrupts a run of refills (Linux `free_frozen_page_commit`).
    local.alloc_factor >>= 1;
    if local.free_count < local.free_cap {
        local.free_count += incoming;
    }
    if local.count + incoming >= local.trim_at {
        cache_trim(local, node, incoming, pairs_first);
    }
}

/// Slow half of [`cache_make_room`]: re-read the node's sizing and its memory
/// pressure, and if the cache would be over its mark return a streak's worth
/// of pages — between one batch and all but one batch (Linux `nr_pcp_free`).
fn cache_trim(local: &mut NodeFrameCache, node: usize, incoming: usize, pairs_first: bool) {
    let tuning = cache_tuning(node);
    local.free_cap = tuning.batch << CACHE_BATCH_SCALE_MAX;
    let held = local.count + incoming;
    let high = cache_high_mark(local, tuning, node, held);
    if held < high {
        return;
    }
    let pages = if high < tuning.batch {
        1
    } else {
        local
            .free_count
            .clamp(tuning.batch, (high - tuning.batch).max(tuning.batch))
    };
    cache_spill(local, node, pages, tuning.batch, pairs_first);
}

/// Return up to `pages` base pages from `local` to `node`'s zone, at most
/// `batch` pages — and never more than `FRAME_RETURN_CHUNK` blocks — per
/// zone-lock hold (Linux `free_pcppages_bulk`, called once per batch).
/// `pairs_first` picks the list to start on; the other is used once it is
/// empty.
///
/// Caller holds the CPU's cache lock and keeps it until this returns, so a
/// frame taken off a list is in the zone before any drainer can look: the
/// drain/hot-remove protocol relies on a free frame never being in neither
/// place. The zone lock, though, is released between batches, so other CPUs
/// get a turn at it however much is being returned.
fn cache_spill(
    local: &mut NodeFrameCache,
    node: usize,
    pages: usize,
    batch: usize,
    pairs_first: bool,
) {
    let per_hold = batch.clamp(1, FRAME_RETURN_CHUNK);
    let mut left = pages.min(local.count);
    while left != 0 {
        let mut zone = lock_zone(node);
        let mut budget = per_hold.min(left);
        let mut frames = 0usize;
        let mut pairs = 0usize;
        while budget != 0 {
            if local.pair_count != 0 && (pairs_first || local.frame_count() == 0) {
                let Some(block) = cache_list_pop(&mut local.pairs) else {
                    break;
                };
                local.pair_count -= 1;
                local.count -= 2;
                zone.free_cached(block, 1);
                pairs += 1;
                budget = budget.saturating_sub(2);
            } else {
                let Some(frame) = cache_list_pop(&mut local.frames) else {
                    break;
                };
                local.count -= 1;
                zone.free_cached(frame, 0);
                frames += 1;
                budget -= 1;
            }
        }
        drop(zone);
        FRAME_CACHE_FREE[node].fetch_sub(frames, Ordering::Relaxed);
        PAIR_CACHE_FREE[node].fetch_sub(pairs, Ordering::Relaxed);
        #[cfg(feature = "kernel-test")]
        FRAME_CACHE_SPILLS.fetch_add(1, Ordering::Relaxed);
        let moved = frames + 2 * pairs;
        if moved == 0 {
            break;
        }
        left = left.saturating_sub(moved);
    }
}

/// Cache an order-0 free on the calling CPU.
fn free_order0_to_cache(node: usize, frame: u64) -> CacheFree {
    let node = node.min(MAX_NUMA_NODES - 1);
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        return CacheFree::Declined;
    }
    let Some(word) = FRAME_INDEX.slot(frame) else {
        return CacheFree::Declined;
    };
    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    if frame_cache_bypassed(node) {
        return CacheFree::Declined;
    }
    let local = &mut cache.nodes[node];
    // The audit (when compiled in) names a double free at its source before
    // the refusal below can hide it.
    buddy::audit_cached_free(frame);
    // Checked before any trim: a trim could move the earlier copy of a
    // doubly-freed frame out of this cache and make it unrecognisable.
    if let Err(refusal) = FRAME_INDEX.claim_free(frame, 0) {
        note_refused_free(frame, 0, refusal);
        return CacheFree::AlreadyFree;
    }
    cache_make_room(local, node, 1, false);
    let linked = cache_list_push(&mut local.frames, frame, word);
    debug_assert!(linked);
    local.count += 1;
    FRAME_CACHE_FREE[node].fetch_add(1, Ordering::Relaxed);
    CacheFree::Cached
}

/// Claim a complete UNMOVABLE order-1 block. Misses retain the ordinary buddy
/// path; this cache only holds blocks returned by their previous owners.
fn alloc_cached_pair(node: usize) -> Option<PhysFrame> {
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        return None;
    }
    let cpu = current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    if frame_cache_bypassed(node) {
        return None;
    }
    let local = &mut cache.nodes[node];
    let frame = cache_list_pop(&mut local.pairs)?;
    FRAME_INDEX.mark_allocated(frame, 1);
    local.pair_count -= 1;
    local.count -= 2;
    local.free_count >>= 1;
    PAIR_CACHE_FREE[node].fetch_sub(1, Ordering::Relaxed);
    account_allocated_frames(node, 2);
    buddy::audit_cached_alloc(frame);
    buddy::audit_cached_alloc(frame + 1);
    #[cfg(feature = "kernel-test")]
    PAIR_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
    Some(buddy::frame_from_no(frame))
}

/// Return a complete UNMOVABLE order-1 block. The CPU cache stays locked
/// until every pair a trim displaces is visible in the buddy, matching the
/// base-page drain and hot-remove exclusion protocol. No allocation occurs
/// after owner release.
fn free_pair_to_cache(node: usize, frame: u64) -> CacheFree {
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        return CacheFree::Declined;
    }
    let (Some(word), Some(_)) = (FRAME_INDEX.slot(frame), FRAME_INDEX.slot(frame + 1)) else {
        return CacheFree::Declined;
    };
    let cpu = current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    if frame_cache_bypassed(node) {
        return CacheFree::Declined;
    }
    let local = &mut cache.nodes[node];
    buddy::audit_cached_free(frame);
    buddy::audit_cached_free(frame + 1);
    // The block must be a live order-1 block, freed by its head; claiming it
    // clears both words. Checked before any trim, as for a base page.
    if let Err(refusal) = FRAME_INDEX.claim_free(frame, 1) {
        note_refused_free(frame, 1, refusal);
        return CacheFree::AlreadyFree;
    }
    cache_make_room(local, node, 2, true);
    let linked = cache_list_push(&mut local.pairs, frame, word);
    debug_assert!(linked);
    local.pair_count += 1;
    local.count += 2;
    PAIR_CACHE_FREE[node].fetch_add(1, Ordering::Relaxed);
    CacheFree::Cached
}

/// Caller holds this CPU's cache lock, with the node's bypass already
/// published. Both lists go back to the zone, cache -> zone as always, in
/// zone-lock holds of at most `FRAME_RETURN_CHUNK` blocks.
fn drain_cpu_node_cache(cache: &mut CpuFrameCache, node: usize) {
    let local = &mut cache.nodes[node];
    if local.count == 0 {
        return;
    }
    cache_spill(local, node, usize::MAX, FRAME_RETURN_CHUNK, false);
    local.free_count = 0;
    local.alloc_factor = 0;
}

/// One zone-lock hold returning up to `FRAME_RETURN_CHUNK` final-owner
/// order-0 frames directly to `node`'s zone. Returns how many it took.
fn free_order0_chunk_direct(node: usize, frames: &[u64]) -> usize {
    debug_assert!(frames.len() <= FRAME_RETURN_CHUNK);
    if frames.is_empty() {
        return 0;
    }
    let mut zone = lock_zone(node);
    let mut freed = 0usize;
    for &frame in frames {
        match zone.try_free_checked(frame, 0, buddy::MigrateType::Unmovable) {
            Ok(()) => freed += 1,
            Err(refusal) => note_refused_free(frame, 0, refusal),
        }
    }
    freed
}

/// Publish a bounded set of final-owner order-0 frames for one NUMA node, and
/// return how many were taken (a frame that is already free is dropped).
///
/// No allocation is permitted here: callers have already removed the final
/// ownership reference, so allocator progress must not depend on obtaining a
/// fresh frame. The frames are linked onto the calling CPU's cache in one
/// cache-lock transaction; if they would take the cache to its mark, a trim
/// makes room first in the same transaction, a batch per zone-lock hold, and
/// the cache lock is kept until the displaced frames are installed in the
/// buddy zone. That cache -> zone lock coupling is required so a concurrent
/// drain/hot-remove transaction cannot observe the frames in neither
/// location.
fn free_order0_chunk_to_zone(node: usize, frames: &[u64]) -> usize {
    debug_assert!(frames.len() <= FRAME_RETURN_CHUNK);
    if frames.is_empty() {
        return 0;
    }
    let node = node.min(MAX_NUMA_NODES - 1);
    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) || frame_cache_bypassed(node) {
        return free_order0_chunk_direct(node, frames);
    }

    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let mut cache = FRAME_CACHES[cpu].0.lock();
    #[cfg(feature = "kernel-test")]
    FRAME_CACHE_BATCH_FREE_LOCKS.fetch_add(1, Ordering::Relaxed);
    // A coordinated drain may have published bypass after the optimistic
    // check. Match the scalar path by publishing directly to the zone.
    if frame_cache_bypassed(node) {
        drop(cache);
        return free_order0_chunk_direct(node, frames);
    }

    let local = &mut cache.nodes[node];
    // Room for the whole chunk first (see `cache_make_room`); a chunk that
    // turns out to hold uncacheable frames merely trimmed a little early.
    cache_make_room(local, node, frames.len(), false);
    // Frames no index section covers cannot be linked; they go to the zone.
    let mut direct = [0u64; FRAME_RETURN_CHUNK];
    let mut direct_len = 0usize;
    let mut cached = 0usize;
    for &frame in frames {
        let Some(word) = FRAME_INDEX.slot(frame) else {
            direct[direct_len] = frame;
            direct_len += 1;
            continue;
        };
        buddy::audit_cached_free(frame);
        match FRAME_INDEX.claim_free(frame, 0) {
            Ok(()) => {
                let linked = cache_list_push(&mut local.frames, frame, word);
                debug_assert!(linked);
                cached += 1;
            }
            Err(refusal) => note_refused_free(frame, 0, refusal),
        }
    }
    local.count += cached;
    FRAME_CACHE_FREE[node].fetch_add(cached, Ordering::Relaxed);
    drop(cache);
    cached + free_order0_chunk_direct(node, &direct[..direct_len])
}

/// Best-effort first pass of a coordinated drain: move what `node`'s caches
/// hold into the zone in bounded slices, with every lock dropped between
/// slices. The coordinated drain proper runs with interrupts off from its
/// first lock to its last (the drain lock is IRQ-safe and held throughout),
/// so the work it has to do there should be what was cached since this pass
/// rather than everything the caches could hold.
///
/// Takes no drain lock and publishes no bypass: it is an ordinary cache ->
/// zone trim performed on each CPU's cache in turn, which any CPU may do.
/// Frames freed concurrently simply stay for the coordinated pass.
fn predrain_node_caches(node: usize) {
    if FRAME_CACHE_FREE[node].load(Ordering::Relaxed) == 0
        && PAIR_CACHE_FREE[node].load(Ordering::Relaxed) == 0
    {
        return;
    }
    let tuning = cache_tuning(node);
    let slice = tuning.batch << CACHE_BATCH_SCALE_MAX;
    // Enough slices to empty a cache at its ceiling; a CPU refilling its cache
    // faster than that is left to the coordinated pass.
    let passes = tuning.high_max / slice + 2;
    for cpu_cache in &FRAME_CACHES {
        for _ in 0..passes {
            let mut cache = cpu_cache.0.lock();
            let local = &mut cache.nodes[node];
            if local.count == 0 {
                break;
            }
            cache_spill(local, node, slice, FRAME_RETURN_CHUNK, false);
        }
    }
}

/// Drain every CPU's cache for one node and run `f` while new cache entries
/// are bypassed. Lock order is drain -> per-CPU cache -> zone; ordinary paths
/// take at most one per-CPU cache before the zone and never take a drain lock.
///
/// When this CPU already holds the node's drain lock — inside the closure of
/// [`with_node_cache_bypassed`], which keeps the lock while that closure
/// allocates — the caches have just been emptied and, bypassed, receive
/// nothing new, so there is nothing to drain: `f` runs on the zone directly.
/// Taking the drain lock again there would spin forever with interrupts off
/// on a node whose zone cannot satisfy the allocation. A drain held by
/// another CPU is waited for as before.
fn with_node_frame_caches_drained<R>(node: usize, f: impl FnOnce(&mut BuddyZone) -> R) -> R {
    let node = node.min(MAX_NUMA_NODES - 1);
    let drain = &FRAME_CACHE_DRAIN[node];
    if drain.held_by_this_cpu() {
        debug_assert!(drain.bypass.load(Ordering::Acquire));
        return f(&mut lock_zone(node));
    }
    predrain_node_caches(node);
    let _drain_guard = drain.lock();
    drain.bypass.store(true, Ordering::Release);
    for cpu_cache in &FRAME_CACHES {
        let mut cache = cpu_cache.0.lock();
        drain_cpu_node_cache(&mut cache, node);
    }
    let result = f(&mut lock_zone(node));
    drain.bypass.store(false, Ordering::Release);
    result
}

/// Drain every CPU's cache for `node` into the zone and run `f` with the
/// per-CPU cache BYPASSED — but WITHOUT holding the zone lock across `f`, so `f`
/// may itself allocate / free / reserve frames (which take the zone lock).
///
/// This is what memory compaction needs: draining makes every currently-free
/// frame visible in the zone free lists (so `reserve_frame_range` can hold it),
/// and the bypass routes `f`'s own allocs/frees straight to the zone (so a
/// just-migrated frame is immediately reservable and a destination allocation
/// never comes from the cache). The node's allocations run cache-cold for the
/// duration; keep `f` bounded.
pub fn with_node_cache_bypassed<R>(node: usize, f: impl FnOnce() -> R) -> R {
    let node = node.min(MAX_NUMA_NODES - 1);
    predrain_node_caches(node);
    let drain = &FRAME_CACHE_DRAIN[node];
    let _drain_guard = drain.lock();
    drain.bypass.store(true, Ordering::Release);
    for cpu_cache in &FRAME_CACHES {
        let mut cache = cpu_cache.0.lock();
        drain_cpu_node_cache(&mut cache, node);
    }
    // The zone lock is released here; `f` takes it per operation as needed.
    let result = f();
    drain.bypass.store(false, Ordering::Release);
    result
}

/// Second half of publishing a PERSISTENT (hot-plug) bypass for `node`: wait
/// for every cache operation that may have observed the old bypass value, and
/// return what the node's caches hold to the zone. With caching off for the
/// node nothing would ever take those frames out again, so leaving them would
/// strand up to a cache's `high` per CPU for as long as the node has a
/// hot-plugged range online. The caller publishes the bypass first, then
/// calls this before making newly hot-plugged frames visible in the buddy.
fn drain_bypassed_node_caches(node: usize) {
    debug_assert!(frame_cache_bypassed(node));
    for cpu_cache in &FRAME_CACHES {
        let mut cache = cpu_cache.0.lock();
        drain_cpu_node_cache(&mut cache, node);
    }
}

/// Allocate one 4 KiB frame, preferring `node`'s zone. Dispatches
/// through the installed `FrameAlloc` impl — see `install_frame_alloc`.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn alloc_frame_on(node: usize) -> Result<PhysFrame, FrameAllocError> {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_alloc_caller(core::panic::Location::caller());
    alloc_frame_on_inner(node)
}

/// Allocate one frame from `node`'s zone ONLY — no cross-node
/// fallback. Returns `Exhausted` if `node` has no free frame.
/// Used by `MPOL_BIND` enforcement, which must never spill outside
/// the bound nodemask. Still applies the cgroup charge.
pub fn alloc_frame_on_strict(node: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_strict_for(node, node)
}

/// Strict allocation from `node` while attributing hit/miss against
/// `preferred`. Mempolicy uses this when a hard allowed mask requires
/// explicit fallback attempts.
pub(crate) fn alloc_frame_on_strict_for(
    node: usize,
    preferred: usize,
) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_strict_for_ctx(node, preferred, AllocContext::Kernel)
}

/// Reserve-aware core of the strict per-node path. `User` allocations are
/// refused once they would breach the `min` watermark reserve.
pub(crate) fn alloc_frame_on_strict_for_ctx(
    node: usize,
    preferred: usize,
    ctx: AllocContext,
) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_strict_inner(node, preferred, ctx, true)
}

/// [`alloc_frame_on_strict_for_ctx`], with the memory-cgroup charge of a user
/// allocation made only when `charge` is set (a migration destination
/// inherits its source's charge instead).
fn alloc_frame_on_strict_inner(
    node: usize,
    preferred: usize,
    ctx: AllocContext,
    charge: bool,
) -> Result<PhysFrame, FrameAllocError> {
    reserve_permits(ctx, node)?;
    let charge_ctx = if charge { ctx } else { AllocContext::Kernel };
    let charged = charge_user_alloc(charge_ctx, node, PAGE_SIZE)?;
    let r = buddy_alloc_frame_on_strict(node, preferred);
    commit_user_charge(charged, &r, PAGE_SIZE);
    if r.is_err() {
        // A strict-node miss may be local fragmentation rather than global
        // exhaustion, so request a background pass without arming OOM.
        crate::reclaim::request_reclaim(node.min(MAX_NUMA_NODES - 1), 1);
    }
    r
}

/// Strict per-node buddy allocation: only `node`'s zone is consulted.
fn buddy_alloc_frame_on_strict(
    node: usize,
    preferred: usize,
) -> Result<PhysFrame, FrameAllocError> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }
    let zone = if ALLOC.numa_aware.load(Ordering::Acquire) {
        node.min(MAX_NUMA_NODES - 1)
    } else if node == 0 {
        0
    } else {
        return Err(FrameAllocError::Exhausted);
    };
    let frame = alloc_order0_on(zone).ok_or(FrameAllocError::Exhausted)?;
    account_numa_allocation(preferred, zone, 1);
    Ok(frame)
}

/// Core of `alloc_frame` / `alloc_frame_on` — does the cgroup charge +
/// buddy dispatch. Kept separate (and NOT `#[track_caller]`) so the two
/// public entry points each capture their OWN caller's source location
/// for the `frame-alloc-audit` alloc-site map, instead of one shadowing
/// the other.
fn alloc_frame_on_inner(node: usize) -> Result<PhysFrame, FrameAllocError> {
    alloc_frame_on_inner_ctx(node, AllocContext::Kernel)
}

/// How many empty slab frames to reclaim back to the buddy when a frame
/// allocation fails, before retrying. One frame would unstick the immediate
/// allocation, but reclaiming a small batch amortises the (rare, failure-path)
/// shrink across the next allocations and gives the buddy contiguous runs to
/// coalesce for higher-order retries.
const SLAB_DIRECT_RECLAIM_PAGES: usize = 512;

/// Reserve-aware core of `alloc_frame` / `alloc_frame_on`. `User` allocations
/// are refused (and the reclaimer woken) once they would breach the `min`
/// watermark reserve; `Kernel` allocations may consume it.
fn alloc_frame_on_inner_ctx(node: usize, ctx: AllocContext) -> Result<PhysFrame, FrameAllocError> {
    reserve_permits(ctx, node)?;
    // Memory-cgroup accounting: a user page is charged to the current task's
    // cgroup before the allocation commits, and the charge is recorded on
    // the frame so its final free uncharges the same cgroup. Kernel
    // allocations (`alloc_frame`, the heap) are not charged.
    let charge = charge_user_alloc(ctx, node, PAGE_SIZE)?;
    let mut r = with_installed(|a| a.alloc_frame_on(node));
    if r.is_err() {
        // The slab grows one size-class at a time and parks emptied frames in
        // that class's own central free list instead of returning them to the
        // buddy. A churny workload (e.g. a fork storm's COW/rmap/page-table
        // allocations) can sequester most of RAM in one class, so this buddy
        // allocation fails although the memory is free — just trapped in the
        // slab. Pull empty slab frames back to the buddy and retry once before
        // surfacing the failure. Slab-only (never the anon/address-space
        // shrinkers), so it is safe from any context, including a page fault
        // holding the region lock or an IRQ-masked slab-grow. Linux does the
        // analogous direct reclaim of slab caches before failing an allocation.
        if crate::slab::reclaim_empty_frames_to_buddy(SLAB_DIRECT_RECLAIM_PAGES) > 0 {
            r = with_installed(|a| a.alloc_frame_on(node));
        }
    }
    commit_user_charge(charge, &r, PAGE_SIZE);
    if r.is_err() {
        if ctx == AllocContext::Kernel {
            // A generic kernel allocation can be fallible (`try_reserve`, zram
            // metadata growth, cache population). Its caller may handle the
            // failure, so an asynchronous OOM authorization would outlive the
            // operation and later kill an unrelated process. Request reclaim
            // only. User demand faults carry a live request ticket before they
            // authorize OOM; cgroup limits use their explicit scoped policy.
            let reclaim_node = node.min(MAX_NUMA_NODES - 1);
            crate::reclaim::request_reclaim(reclaim_node, 1);
        } else {
            // The reserve check passed but the selected buddy/cpuset could not
            // satisfy the allocation (for example fragmentation or strict-node
            // pressure). Give kswapd an opportunity to make progress before a
            // later user fault retries.
            crate::reclaim::request_reclaim(node.min(MAX_NUMA_NODES - 1), 1);
        }
    }
    r
}

/// Allocate a frame from any node. Useful for boot-time allocations
/// that don't care about locality. Dispatches through the installed
/// `FrameAlloc` impl.
pub fn alloc_frame_anywhere() -> Result<PhysFrame, FrameAllocError> {
    // Kernel memory: not charged to any cgroup.
    with_installed(|a| a.alloc_frame_anywhere())
}

/// Buddy-backed implementation of `alloc_frame_on`. The default
/// `BuddyFrameAlloc::alloc_frame_on` delegates here; alternative
/// `FrameAlloc` impls (e.g. `BumpFrameAlloc`) own their own paths
/// and never touch the buddy.
fn buddy_alloc_frame_on(node: usize) -> Result<PhysFrame, FrameAllocError> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }

    if !ALLOC.numa_aware.load(Ordering::Acquire) {
        // Pre-rebalance: everything's in zones[0].
        let frame = alloc_order0_on(0).ok_or(FrameAllocError::Exhausted)?;
        account_numa_allocation(node, 0, 1);
        return Ok(frame);
    }

    let preferred = node.min(MAX_NUMA_NODES - 1);
    if let Some(f) = alloc_order0_on(preferred) {
        account_numa_allocation(preferred, preferred, 1);
        return Ok(f);
    }

    // Fallback: try the remaining nodes nearest-first by NUMA distance
    // (Linux's local-then-nearest policy) instead of a blind
    // round-robin. On a single node (or no-topology stub) the order is
    // still all other zones, just deterministically index-ordered.
    let mut order = [0usize; MAX_NUMA_NODES];
    let n = fallback_order(preferred, &mut order);
    for &i in &order[..n] {
        if let Some(f) = alloc_order0_on(i) {
            account_numa_allocation(preferred, i, 1);
            return Ok(f);
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Buddy-backed implementation of `alloc_frame_anywhere`.
fn buddy_alloc_frame_anywhere() -> Result<PhysFrame, FrameAllocError> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }
    let preferred = current_cpu_node().min(MAX_NUMA_NODES - 1);
    for node in 0..MAX_NUMA_NODES {
        if let Some(f) = alloc_order0_on(node) {
            account_numa_allocation(preferred, node, 1);
            return Ok(f);
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate a contiguous block of `1 << order` frames. `order=0`
/// is one frame (same as `alloc_frame_on`); `order=10` is 4 MiB.
/// Phase-1 buddy allocator entry point.
pub fn alloc_pages_on(node: usize, order: u8) -> Result<PhysFrame, FrameAllocError> {
    // Default higher-order allocations to the kernel/UNMOVABLE class.
    alloc_pages_on_ctx(node, order, AllocContext::Kernel)
}

/// Allocate a contiguous `1 << order` block, classified for
/// anti-fragmentation grouping by `ctx` (Kernel → UNMOVABLE, User →
/// MOVABLE). The multi-frame buddy path files the block — and any
/// split-off buddies — into the matching migratetype partition so
/// unmovable and movable contiguous regions don't fragment each other.
pub fn alloc_pages_on_ctx(
    node: usize,
    order: u8,
    ctx: AllocContext,
) -> Result<PhysFrame, FrameAllocError> {
    if order > MAX_ORDER {
        return Err(FrameAllocError::Exhausted);
    }
    // Memory-cgroup accounting: a user block is charged whole before it is
    // allocated and the charge is recorded on its head frame; a kernel block
    // is not charged.
    let charge_bytes = PAGE_SIZE << order;
    let charge = match charge_user_alloc(ctx, node, charge_bytes) {
        Ok(charge) => charge,
        Err(error) => {
            note_block_failure(order, BLOCK_FAIL_CHARGE);
            return Err(error);
        }
    };
    let r = alloc_pages_on_inner(node, order, ctx.migrate_type());
    // Return empty slab frames to the buddy before trying anything more
    // expensive: the slab hoards emptied frames per size-class rather than
    // freeing them to the buddy (see `slab::reclaim_empty_frames_to_buddy`), so
    // a higher-order allocation can fail on a system that is mostly free. Unlike
    // `direct_compact` below, this is safe under an IRQ mask, so it also unsticks
    // the IRQ-masked slab-grow path. The freed frames additionally give
    // compaction more room to coalesce.
    let r = if r.is_err()
        && crate::slab::reclaim_empty_frames_to_buddy(SLAB_DIRECT_RECLAIM_PAGES) > 0
    {
        alloc_pages_on_inner(node, order, ctx.migrate_type())
    } else {
        r
    };
    // Direct compaction: a higher-order allocation that ran out of contiguous
    // blocks may succeed after migrating movable pages together. Compact this
    // node once and retry before giving up. `direct_compact` itself rejects
    // IRQ-masked callers, so allocations made under an IRQ-safe metadata lock
    // fall through to their caller's non-contiguous/failure path rather than
    // recursively entering migration while that metadata is locked.
    let r = retry_after_direct_compaction(r, node, order, ctx.migrate_type());
    if r.is_err() {
        note_block_failure(order, BLOCK_FAIL_BUDDY);
    }
    commit_user_charge(charge, &r, charge_bytes);
    r
}

/// Why the most recent `alloc_pages_on_ctx` failed: the cgroup charge was
/// refused, or no zone had a block after drain, slab reclaim and compaction.
const BLOCK_FAIL_CHARGE: u64 = 1;
const BLOCK_FAIL_BUDDY: u64 = 2;
/// `reason << 8 | order` of the last failed block allocation; 0 = none yet.
static LAST_BLOCK_FAILURE: AtomicU64 = AtomicU64::new(0);

#[cold]
fn note_block_failure(order: u8, reason: u64) {
    LAST_BLOCK_FAILURE.store(reason << 8 | u64::from(order), Ordering::Relaxed);
}

/// If a higher-order allocation failed, run synchronous direct compaction on
/// `node` and retry the allocation once. x86_64 only — migration needs the rmap
/// and accessed-bit machinery that aarch64 lacks; other arches pass the result
/// through unchanged.
#[cfg(target_arch = "x86_64")]
fn retry_after_direct_compaction(
    r: Result<PhysFrame, FrameAllocError>,
    node: usize,
    order: u8,
    mt: buddy::MigrateType,
) -> Result<PhysFrame, FrameAllocError> {
    if r.is_err()
        && order > 0
        && crate::migrate::direct_compact(node.min(MAX_NUMA_NODES - 1), order as usize) > 0
    {
        return alloc_pages_on_inner(node, order, mt);
    }
    r
}

#[cfg(not(target_arch = "x86_64"))]
fn retry_after_direct_compaction(
    r: Result<PhysFrame, FrameAllocError>,
    _node: usize,
    _order: u8,
    _mt: buddy::MigrateType,
) -> Result<PhysFrame, FrameAllocError> {
    r
}

fn alloc_pages_on_inner(
    node: usize,
    order: u8,
    mt: buddy::MigrateType,
) -> Result<PhysFrame, FrameAllocError> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }
    let preferred = node.min(MAX_NUMA_NODES - 1);
    let numa_aware = ALLOC.numa_aware.load(Ordering::Acquire);
    let zone_idx = if numa_aware { preferred } else { 0 };
    if order == 0 {
        if let Some(frame) = alloc_order0_on(zone_idx) {
            account_numa_allocation(preferred, zone_idx, 1);
            return Ok(frame);
        }
        if !numa_aware {
            return Err(FrameAllocError::Exhausted);
        }
        let mut fallback_nodes = [0usize; MAX_NUMA_NODES];
        let n = fallback_order(preferred, &mut fallback_nodes);
        for &i in &fallback_nodes[..n] {
            if let Some(frame) = alloc_order0_on(i) {
                account_numa_allocation(preferred, i, 1);
                return Ok(frame);
            }
        }
        return Err(FrameAllocError::Exhausted);
    }
    let ceil = buddy::early_ceiling_frame();
    let try_alloc = |z: &mut BuddyZone| -> Option<u64> {
        if ceil == u64::MAX {
            z.alloc_mt(order, mt)
        } else {
            z.alloc_below_mt(order, ceil, mt)
        }
    };
    if order == 1 && mt == buddy::MigrateType::Unmovable {
        if let Some(frame) = alloc_cached_pair(zone_idx) {
            account_numa_allocation(preferred, zone_idx, 2);
            return Ok(frame);
        }
    }
    let first_try = {
        let mut zone = lock_zone(zone_idx);
        try_alloc(&mut zone)
    };
    if let Some(no) =
        first_try.or_else(|| with_node_frame_caches_drained(zone_idx, |zone| try_alloc(zone)))
    {
        account_allocated_frames(zone_idx, 1usize << order);
        account_numa_allocation(preferred, zone_idx, 1u64 << order);
        return Ok(buddy::frame_from_no(no));
    }
    if !numa_aware {
        return Err(FrameAllocError::Exhausted);
    }
    // Nearest-first cross-node fallback (see buddy_alloc_frame_on).
    let mut fallback_nodes = [0usize; MAX_NUMA_NODES];
    let n = fallback_order(preferred, &mut fallback_nodes);
    for &i in &fallback_nodes[..n] {
        if order == 1 && mt == buddy::MigrateType::Unmovable {
            if let Some(frame) = alloc_cached_pair(i) {
                account_numa_allocation(preferred, i, 2);
                return Ok(frame);
            }
        }
        let first_try = {
            let mut zone = lock_zone(i);
            try_alloc(&mut zone)
        };
        if let Some(no) =
            first_try.or_else(|| with_node_frame_caches_drained(i, |zone| try_alloc(zone)))
        {
            account_allocated_frames(i, 1usize << order);
            account_numa_allocation(preferred, i, 1u64 << order);
            return Ok(buddy::frame_from_no(no));
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Allocate a contiguous kernel (UNMOVABLE) block of `1 << order`
/// frames lying entirely at or below physical address `limit_phys`
/// (inclusive: every byte of the block is `<= limit_phys`), searching
/// every online node's zone. This is the frame-level half of Linux's
/// `dma_set_coherent_mask` + `dma_alloc_coherent` contract for a
/// device whose coherent DMA mask is `limit_phys` (e.g. 32-bit masks:
/// `limit_phys = 0xffff_ffff`).
///
/// Returns `Exhausted` — never a frame above the limit — when no block
/// fits, including when `limit_phys` lies below all managed RAM. The
/// early boot ceiling, if still in force, is honoured too. Free with
/// [`free_pages`].
pub fn alloc_pages_below(order: u8, limit_phys: u64) -> Result<PhysFrame, FrameAllocError> {
    if order > MAX_ORDER {
        return Err(FrameAllocError::Exhausted);
    }
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return Err(FrameAllocError::Uninitialised);
    }
    // One past the last frame number whose final byte is <= limit_phys.
    let mut ceil = (limit_phys >> PAGE_SHIFT).saturating_add(1);
    if limit_phys & (PAGE_SIZE - 1) != PAGE_SIZE - 1 {
        // A partial last page cannot hold a whole frame.
        ceil -= 1;
    }
    ceil = ceil.min(buddy::early_ceiling_frame());
    if ceil == 0 {
        return Err(FrameAllocError::Exhausted);
    }
    // Kernel (DMA) memory: not charged to any cgroup.
    let preferred = current_cpu_node().min(MAX_NUMA_NODES - 1);
    let mt = AllocContext::Kernel.migrate_type();
    let try_alloc = |z: &mut BuddyZone| z.alloc_below_mt(order, ceil, mt);
    // Zone 0 holds everything until `rebalance_to_topology` runs.
    let mut nodes = online_node_mask() | 1;
    while nodes != 0 {
        let node = nodes.trailing_zeros() as usize;
        nodes &= nodes - 1;
        if node >= MAX_NUMA_NODES {
            break;
        }
        let first_try = try_alloc(&mut lock_zone(node));
        if let Some(no) =
            first_try.or_else(|| with_node_frame_caches_drained(node, |zone| try_alloc(zone)))
        {
            account_allocated_frames(node, 1usize << order);
            account_numa_allocation(preferred, node, 1u64 << order);
            return Ok(buddy::frame_from_no(no));
        }
    }
    Err(FrameAllocError::Exhausted)
}

/// Free a contiguous block of `1 << order` frames previously returned
/// from `alloc_pages_on` (the kernel/UNMOVABLE default).
pub fn free_pages(frame: PhysFrame, order: u8) {
    free_pages_ctx(frame, order, AllocContext::Kernel);
}

/// Free a contiguous block classified by `ctx`, so the block returns to
/// the migratetype partition it was allocated from. A block allocated via
/// [`alloc_pages_on_ctx`] MUST be freed with the matching `ctx`: NARF has
/// no per-frame migratetype record (no pageblock bitmap yet), so the
/// caller supplies the mobility, and a mismatch would misfile the block
/// into the wrong partition (harmless for correctness — the free lists
/// only group, they don't gate reuse — but it would blur the grouping).
pub fn free_pages_ctx(frame: PhysFrame, order: u8, ctx: AllocContext) {
    if order > MAX_ORDER {
        return;
    }
    free_block(frame, order, ctx.migrate_type());
}

/// Return a `1 << order` block to its node: the body of [`free_pages_ctx`],
/// and the release for blocks taken with `alloc_pages_on_inner` and so never
/// charged to a memory cgroup (their record is empty, so nothing is
/// uncharged).
fn free_block(frame: PhysFrame, order: u8, mt: buddy::MigrateType) {
    let phys = frame.start_address().raw();
    if phys >= LOW_RESERVED_BYTES {
        // Return whatever memory-cgroup charge the block's allocation
        // recorded (none for kernel memory) to the cgroup it was charged to.
        uncharge_freed_block(frame.start_address(), PAGE_SIZE << order);
    }
    if phys < LOW_RESERVED_BYTES {
        // Refusing the free is safer than corrupting the buddy by
        // pushing a frame that was never legitimately donated.
        // (donate_range masks below 1 MiB at boot; any lower phys
        // here came from a stale page-table addr or bad pointer.)
        return;
    }
    let node = phys_to_node(phys);
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return;
    }
    let zone_idx = if ALLOC.numa_aware.load(Ordering::Acquire) {
        node
    } else {
        0
    };
    let frame_no = buddy::frame_no(frame);
    let cached = match order {
        0 => free_order0_to_cache(zone_idx, frame_no),
        1 if mt == buddy::MigrateType::Unmovable => free_pair_to_cache(zone_idx, frame_no),
        _ => CacheFree::Declined,
    };
    match cached {
        CacheFree::Cached => account_freed_frames(zone_idx, 1usize << order),
        // Dropped and counted by the cache.
        CacheFree::AlreadyFree => {}
        CacheFree::Declined => match lock_zone(zone_idx).try_free_checked(frame_no, order, mt) {
            Ok(()) => account_freed_frames(zone_idx, 1usize << order),
            Err(refusal) => note_refused_free(frame_no, order, refusal),
        },
    }
}

/// Return a previously-allocated frame to the pool. Dispatches
/// through the installed `FrameAlloc`. The default buddy impl
/// routes the frame to its NUMA node's zone; alternative impls
/// (e.g. `BumpFrameAlloc`) may treat this as a no-op or return
/// `NotSupported` via their `try_*` variant.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn free_frame(f: PhysFrame) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if let Some(a) = current_alloc() {
        a.free_frame(f);
    }
}

/// Reserve a fully-free physical frame range: pull it out of the buddy free
/// lists so a later allocation can't hand it out. Returns `false` WITHOUT
/// mutation if any frame in the range is already allocated. The range must lie
/// within a single NUMA node's zone (a buddy block always does).
///
/// Memory compaction uses this to hold migration destinations OUTSIDE the block
/// it is evacuating (and to re-hold each just-migrated frame), so migration
/// never lands a page back in the block being freed. Balance with
/// [`free_movable_range`].
pub fn reserve_frame_range(base: PhysAddr, count: u64) -> bool {
    if count == 0 {
        return false;
    }
    let node = node_for_phys(base.raw());
    let first_frame = base.raw() >> 12;
    let removed = lock_zone(node).remove_free_range(first_frame, count);
    if removed {
        // Handed out like allocations, one order-0 frame each: compaction
        // frees them that way (`free_movable_range`).
        for offset in 0..count {
            FRAME_INDEX.mark_allocated(first_frame + offset, 0);
        }
        // Exact-range reservation claims free pages just like allocation.
        // Compaction may publish them as live migration destinations; leaving
        // their audit bits free makes that owner's eventual release look like
        // a double free. Hot-remove uses remove_free_range directly instead.
        #[cfg(feature = "frame-alloc-audit")]
        for offset in 0..count {
            buddy::audit_cached_alloc(first_frame + offset);
        }
        account_allocated_frames(node, count as usize);
    }
    removed
}

/// Return a range previously taken with [`reserve_frame_range`] (or a run of
/// freshly-evacuated frames) to the buddy as MOVABLE order-0 frames, coalescing
/// with free buddies. Compaction releases a fully-evacuated block this way so it
/// coalesces up to a higher order. The whole run must lie in one node's zone.
pub fn free_movable_range(base: PhysAddr, count: u64) {
    if count == 0 {
        return;
    }
    let node = node_for_phys(base.raw());
    let first_frame = base.raw() >> 12;
    // A frame leaving here must not keep a memory-cgroup record: the next
    // owner would otherwise uncharge a cgroup it was never charged to.
    for i in 0..count {
        uncharge_freed_block(PhysAddr::new(base.raw() + i * PAGE_SIZE), PAGE_SIZE);
    }
    let end = first_frame + count;
    let mut freed = 0usize;
    let mut next = first_frame;
    // `FRAME_RETURN_CHUNK` frames per zone-lock hold, like every other free.
    // Compaction's own runs are a few frames and stay one hold, as before.
    while next < end {
        let stop = end.min(next + FRAME_RETURN_CHUNK as u64);
        let mut zone = lock_zone(node);
        for frame in next..stop {
            match zone.try_free_checked(frame, 0, buddy::MigrateType::Movable) {
                Ok(()) => freed += 1,
                Err(refusal) => note_refused_free(frame, 0, refusal),
            }
        }
        drop(zone);
        next = stop;
    }
    account_freed_frames(node, freed);
}

/// Return a vector of independently owned base frames through the installed
/// allocator. Alternative allocators inherit the scalar default; the buddy
/// implementation batches COW-refcount shard acquisition before returning
/// only last-owner frames to its NUMA caches/free lists.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn free_frame_batch(frames: &[PhysFrame]) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if let Some(allocator) = current_alloc() {
        allocator.free_frame_batch(frames);
    }
}

/// Free base frames addressed directly as `PhysAddr`, without first collecting
/// a region-sized `Vec<PhysFrame>`. Semantically identical to
/// [`free_frame_batch`] but allocation-free, so address-space teardown can hand
/// its backing list straight in even when memory is exhausted. Zero and
/// low-reserved entries are skipped, matching the `PhysFrame` path.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub fn free_phys_batch(phys_list: &[PhysAddr]) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if current_alloc().is_some() {
        buddy_free_phys_batch(phys_list);
    }
}

/// Return a batch whose frames are known to have exactly one owner and are not
/// present in the COW registry. Page-table teardown uses this after detaching
/// the final inactive root and removing every table ownership registration.
///
/// # Safety
/// Every input frame must be exclusively owned by the caller. In particular,
/// it must have no COW reference-count entry and no live page-table registry
/// entry. Violating this contract can make a still-owned frame reusable.
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub(crate) unsafe fn free_unique_frame_batch(frames: &[PhysFrame]) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if let Some(allocator) = current_alloc() {
        // SAFETY: forwarded from this function's caller contract.
        unsafe { allocator.free_unique_frame_batch(frames) };
    }
}

/// Allocation-free physical-address counterpart to
/// [`free_unique_frame_batch`]. Address-space teardown uses this for private
/// regions that have never acquired the `COW` provenance bit, so consulting
/// and sorting through the COW registry cannot change the ownership verdict.
///
/// # Safety
/// Every non-zero, non-reserved input frame must be exclusively owned by the
/// caller and absent from the COW and page-table ownership registries.
// Only caller today is `smoke_free_unique_phys_batch_spans_windows_without_leak`
// below, so this is dead outside the kernel-test build. The doc above says
// address-space teardown uses it; no such call site exists yet, so the `allow`
// is deliberately scoped to the non-test configs — the kernel-test build still
// dead-code-checks it, and wiring the documented teardown user will not need
// the attribute touched.
#[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
#[cfg_attr(feature = "frame-alloc-audit", track_caller)]
pub(crate) unsafe fn free_unique_phys_batch(phys_list: &[PhysAddr]) {
    #[cfg(feature = "frame-alloc-audit")]
    crate::buddy::audit_note_free_caller(core::panic::Location::caller());
    if current_alloc().is_some() {
        // SAFETY: forwarded from this function's caller contract.
        unsafe { buddy_free_unique_phys_batch(phys_list) };
    }
}

/// Buddy-backed implementation of `free_frame`.
///
/// COW interaction: if the frame has a refcount > 1 (multiple
/// `Arc<AddressSpace>`s share it via `clone_for_fork`), this call
/// only decrements — the actual return-to-bin happens when the
/// last reference drops. Frames that were never refcounted
/// (default for everything outside the COW path) are returned
/// immediately as before.
fn buddy_free_frame(f: PhysFrame) {
    // Refuse low-mem phys before any state mutation. Frames below
    // `LOW_RESERVED_BYTES` are never legitimately donated to the
    // buddy (see `donate_range`), so any caller handing one to
    // `free_frame` has a bad source phys — typically a page-table
    // entry whose `addr()` mask resolved to a sentinel.
    if f.start_address().raw() < LOW_RESERVED_BYTES {
        return;
    }
    if cow::dec_ref(f.start_address()) > 0 {
        // Other ASes still reference this frame; don't return it.
        return;
    }
    buddy_return_unreferenced_frame(f);
}

/// Return a frame after the caller has established that no COW owner remains.
/// This is the common accounting/scrub/NUMA path for scalar and batched free.
fn buddy_return_unreferenced_frame(f: PhysFrame) {
    buddy_prepare_unreferenced_frame(f.start_address());
    let Some((zone_idx, frame_no)) = buddy_unreferenced_route(f) else {
        return;
    };
    match free_order0_to_cache(zone_idx, frame_no) {
        CacheFree::Cached => account_freed_frames(zone_idx, 1),
        // Dropped and counted by the cache.
        CacheFree::AlreadyFree => {}
        CacheFree::Declined => {
            match lock_zone(zone_idx).try_free_checked(frame_no, 0, buddy::MigrateType::Unmovable) {
                Ok(()) => account_freed_frames(zone_idx, 1),
                Err(refusal) => note_refused_free(frame_no, 0, refusal),
            }
        }
    }
}

/// Complete work that must precede publication of a final-owner frame.
fn buddy_prepare_unreferenced_frame(phys: PhysAddr) {
    // DEBUG_VM analogue of Linux `free_pages_prepare`'s "nonzero mapcount"
    // `bad_page` check (mm/page_alloc.c): a frame genuinely returning to the
    // buddy (COW refcount just reached 0) must have no reverse-map owners. A
    // surviving owner means some unmap/teardown path returned the frame without
    // a paired `rmap::remove`, so the next allocation of this frame inherits a
    // stale (root, va) owner and corrupts every reverse-map-driven decision
    // (TLB shootdown, page migration, COW split) — and, in the test suite,
    // makes any rmap-sensitive test later handed the frame flake (the
    // long-standing shared-alias/mremap test flakiness).
    //
    // Perf: this takes the frame's rmap shard lock on every buddy free, so it
    // must NOT run in release. Gated exactly like Linux's DEBUG_VM: on under
    // `debug_assertions` (debug builds) and compiled out of release so
    // production pays nothing. `rmap-free-audit` additionally force-enables it
    // in a release-mode build (the default kernel-test suite runs release) for a
    // targeted hunt. Every teardown/reclaim path now retires its rmap owners
    // before returning a frame, so the whole memory suite runs clean under this
    // check — it stands as the permanent regression guard for the class.
    #[cfg(any(debug_assertions, feature = "rmap-free-audit"))]
    {
        let owners = crate::rmap::owner_count(phys);
        if owners != 0 {
            let mut first_va = u64::MAX;
            let mut first_root = 0u64;
            crate::rmap::for_each_owner(phys, |o| {
                if first_va == u64::MAX {
                    first_va = o.va.as_u64();
                    first_root = o.root.raw();
                }
            });
            // Capture the free-path return-address chain into the panic
            // message BEFORE panic! runs — the panic/format machinery would
            // otherwise bury the culprit under its own frames (the generic
            // stack-word scan only saw fmt/unwind frames). Walk our own stack
            // upward and collect words that look like kernel return addresses;
            // symbolize offline: static = runtime - kaslr_slide, then
            // `addr2line -e narf-frame`.
            let mut chain = alloc::string::String::new();
            {
                use core::fmt::Write as _;
                // Address of a stack local ≈ current rsp — portable, no asm.
                let anchor = 0u64;
                let sp = core::ptr::addr_of!(anchor) as u64;
                let mut hits = 0u32;
                for i in 0..256u64 {
                    if hits >= 40 {
                        break;
                    }
                    // SAFETY: reads our own stack within a bounded window.
                    let w = unsafe { core::ptr::read_volatile((sp + i * 8) as *const u64) };
                    if (0xffff_ffff_8000_0000..0xffff_ffff_ffff_0000).contains(&w) {
                        let _ = write!(chain, " {w:#x}");
                        hits += 1;
                    }
                }
            }
            panic!(
                "buddy free of {phys:?} with {owners} live rmap owner(s) \
                 (first root={first_root:#x} va={first_va:#x}): a teardown/free \
                 path returned this frame without rmap::remove (Linux bad_page: \
                 nonzero mapcount) chain:{chain}"
            );
        }
    }
    // Memory-cgroup uncharge: only here, where the frame is genuinely
    // returned to the buddy — i.e. the COW refcount has reached 0 — does
    // it balance the single charge taken when the page was allocated. The
    // intermediate `dec_ref > 0` frees above (fork-shared pages) take no
    // uncharge, matching the fact that `clone_for_fork` `inc_ref`s
    // rather than re-allocating (no second charge was ever taken). The
    // charge goes back to the cgroup recorded on the frame, whichever task
    // is running now; a kernel frame recorded none.
    uncharge_freed_block(phys, PAGE_SIZE);
    // Optional scrub of the frame's contents on its way back to the
    // buddy. The frame's COW refcount just hit 0 and it is NOT yet on
    // any free list, so we hold exclusive access — no lock needed and
    // no allocator can hand it out mid-scrub.
    scrub_freed_frame(phys);
}

/// Resolve the allocator destination after final-owner accounting/scrub.
fn buddy_unreferenced_route(f: PhysFrame) -> Option<(usize, u64)> {
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return None;
    }
    let zone_idx = if ALLOC.numa_aware.load(Ordering::Acquire) {
        phys_to_node(f.start_address().raw())
    } else {
        0
    };
    Some((zone_idx, buddy::frame_no(f)))
}

/// Window size for the allocation-free batched free path. A whole
/// address-space teardown is processed in fixed windows of this many frames
/// so the transient stack storage is bounded regardless of the region size —
/// freeing memory must never allocate memory proportional to the amount being
/// freed. Each window still amortises COW-shard lock acquisition (one lock per
/// touched shard per window) and publishes through `FRAME_RETURN_CHUNK` spills.
const FREE_BATCH_WINDOW: usize = 256;

/// Return one window (`<= FREE_BATCH_WINDOW`) of already-filtered final-owner
/// candidates. No heap allocation occurs: released frames are collected into a
/// stack buffer, scrubbed, then published through fixed-size cache/zone chunks.
fn free_final_owner_window(valid: &[PhysAddr]) {
    debug_assert!(valid.len() <= FREE_BATCH_WINDOW);
    let mut released = [PhysAddr::new(0); FREE_BATCH_WINDOW];
    let mut released_len = 0usize;
    cow::dec_ref_batch_each(valid, |phys| {
        released[released_len] = phys;
        released_len += 1;
    });
    free_released_window(&released[..released_len]);
}

/// Prepare and publish one bounded window whose unique ownership is already
/// established. No COW registry lookup or allocation occurs here.
fn free_released_window(released: &[PhysAddr]) {
    debug_assert!(released.len() <= FREE_BATCH_WINDOW);
    // From here no allocation is permitted: every entry has already lost its
    // final owner. Complete scalar-equivalent accounting/scrub with the COW
    // shard locks dropped, then publish through fixed-size stack chunks.
    for &phys in released {
        buddy_prepare_unreferenced_frame(phys);
    }
    if !ALLOC.initialised.load(Ordering::Acquire) {
        return;
    }

    // Resolve each frame's node once (this used to be redone for every one of
    // the `MAX_NUMA_NODES` passes), and visit only the nodes that occur: a
    // window nearly always belongs to a single node.
    const _: () = assert!(MAX_NUMA_NODES <= u64::BITS as usize);
    let mut nodes = [0u8; FREE_BATCH_WINDOW];
    let mut present = 1u64;
    if ALLOC.numa_aware.load(Ordering::Acquire) {
        present = 0;
        for (slot, phys) in nodes.iter_mut().zip(released) {
            let node = phys_to_node(phys.raw());
            *slot = node as u8;
            present |= 1u64 << node;
        }
    }
    while present != 0 {
        let node = present.trailing_zeros() as usize;
        present &= present - 1;
        let mut chunk = [0u64; FRAME_RETURN_CHUNK];
        let mut chunk_len = 0usize;
        for (&phys, &frame_node) in released.iter().zip(&nodes) {
            if usize::from(frame_node) != node {
                continue;
            }
            chunk[chunk_len] = buddy::frame_no(PhysFrame::new(phys));
            chunk_len += 1;
            if chunk_len == FRAME_RETURN_CHUNK {
                let freed = free_order0_chunk_to_zone(node, &chunk);
                account_freed_frames(node, freed);
                chunk_len = 0;
            }
        }
        let freed = free_order0_chunk_to_zone(node, &chunk[..chunk_len]);
        account_freed_frames(node, freed);
    }
}

fn buddy_free_frame_batch(frames: &[PhysFrame]) {
    let mut valid = [PhysAddr::new(0); FREE_BATCH_WINDOW];
    let mut valid_len = 0usize;
    for frame in frames {
        let phys = frame.start_address();
        if phys.raw() < LOW_RESERVED_BYTES {
            continue;
        }
        valid[valid_len] = phys;
        valid_len += 1;
        if valid_len == FREE_BATCH_WINDOW {
            free_final_owner_window(&valid[..valid_len]);
            valid_len = 0;
        }
    }
    if valid_len != 0 {
        free_final_owner_window(&valid[..valid_len]);
    }
}

/// Free a batch of physical frames addressed directly (no `PhysFrame`
/// wrapper). Shares the allocation-free window machinery so an address-space
/// teardown can hand its backing list straight in without first collecting a
/// region-sized `Vec<PhysFrame>` — that intermediate allocation is exactly
/// what failed under memory pressure.
pub(crate) fn buddy_free_phys_batch(phys_list: &[PhysAddr]) {
    let mut valid = [PhysAddr::new(0); FREE_BATCH_WINDOW];
    let mut valid_len = 0usize;
    for &phys in phys_list {
        if phys.raw() < LOW_RESERVED_BYTES {
            continue;
        }
        valid[valid_len] = phys;
        valid_len += 1;
        if valid_len == FREE_BATCH_WINDOW {
            free_final_owner_window(&valid[..valid_len]);
            valid_len = 0;
        }
    }
    if valid_len != 0 {
        free_final_owner_window(&valid[..valid_len]);
    }
}

/// Batch unique physical frames without consulting the COW registry.
///
/// # Safety
/// Forwarded from [`free_unique_phys_batch`].
#[cfg_attr(not(feature = "kernel-test"), allow(dead_code))]
unsafe fn buddy_free_unique_phys_batch(phys_list: &[PhysAddr]) {
    let mut valid = [PhysAddr::new(0); FREE_BATCH_WINDOW];
    let mut valid_len = 0usize;
    for &phys in phys_list {
        if phys.raw() < LOW_RESERVED_BYTES {
            continue;
        }
        valid[valid_len] = phys;
        valid_len += 1;
        if valid_len == FREE_BATCH_WINDOW {
            free_released_window(&valid);
            valid_len = 0;
        }
    }
    if valid_len != 0 {
        free_released_window(&valid[..valid_len]);
    }
}

/// Optionally overwrite a frame's bytes as it returns to the buddy
/// allocator. Compiled out (zero cost) unless a scrub feature is set:
///
/// - `frame-zero-on-free`: fill with zeros. Info-leak hardening — a
///   freed frame's stale data (which may be another task's user memory
///   or kernel heap) can't be observed by the next owner of the frame.
/// - `frame-poison-on-free`: fill with a recognizable non-canonical
///   poison word (`0xDEAD_BEEF_DEAD_BEEF`). A use-after-free or
///   uninitialised-pointer read of a recycled frame then faults on an
///   obviously-diagnostic value (`cr2`/registers spell `deadbeef`)
///   instead of whatever stale bytes happened to land there — the
///   "marginal-buddy" execve `#PF` that reads the freed `tcp_congestion`
///   name ("cubic") as a pointer is exactly this class. Poison takes
///   precedence when both features are enabled.
///
/// Both add a 4 KiB write to the genuine-free path (after the COW
/// refcount reaches 0), so they are opt-in debug/hardening aids rather
/// than always-on.
#[inline]
fn scrub_freed_frame(phys: PhysAddr) {
    #[cfg(any(feature = "frame-poison-on-free", feature = "frame-zero-on-free"))]
    {
        #[cfg(feature = "frame-poison-on-free")]
        const FILL: u64 = 0xDEAD_BEEF_DEAD_BEEF;
        #[cfg(all(feature = "frame-zero-on-free", not(feature = "frame-poison-on-free")))]
        const FILL: u64 = 0;
        let dst = phys.kernel_mut_ptr::<u64>();
        // SAFETY: exclusive access per the caller's contract (refcount 0,
        // not yet on a free list). `kernel_mut_ptr` resolves through the
        // kernel direct map (identity low-4-GiB + high-half RAM window),
        // valid for any donated RAM frame. Writes stay within the 4 KiB
        // frame. `write_volatile` keeps the fill from being elided as a
        // dead store into about-to-be-freed memory.
        unsafe {
            for i in 0..(PAGE_SIZE as usize / 8) {
                core::ptr::write_volatile(dst.add(i), FILL);
            }
        }
    }
    let _ = phys;
}

/// Page-table-frame registry. Every PT / PD / PDPT / PML4 page allocated for a
/// user `AddressSpace` is recorded here and unregistered when reclaimed.
/// `free_user_pml4_tree` uses membership to distinguish AS-private tables from
/// kernel-shared entries copied into a fresh root; it must never free the
/// latter.
///
/// Sized for the LIVE page-table-frame working set across all
/// concurrently-mapped user address spaces — NOT the cumulative count.
/// Entries are cleared on each AS's teardown (`__pagetable_unregister`
/// via `free_user_pml4_tree`), so a correctly-drained registry only ever
/// holds the page-table pages of currently-live ASes (a handful of
/// processes × their sparse user mappings). For every frame with a flat
/// per-frame slot the registration is a bit in that slot (Linux `PG_table`):
/// register, unregister and lookup are one atomic each and leave nothing
/// behind. The fixed open-addressed atomic hash table below serves only the
/// frames without a slot (hot-plugged RAM, and boot before the flat table
/// exists); its unregistrations leave tombstones, which is why it must not be
/// the path for every page table — under process churn each frame that was
/// ever a page table left one, the vacant slots ran out, and each operation
/// probed up to the whole table. A flat linear scan made sparse MAP_FIXED/mremap table
/// construction quadratic and overflowed after 16 K live tables.
const PT_REGISTRY_LEN: usize = 131072;
const PT_REGISTRY_TOMBSTONE: u64 = 1;
static PT_REGISTRY: [core::sync::atomic::AtomicU64; PT_REGISTRY_LEN] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; PT_REGISTRY_LEN]
};

/// Hash-registry slots examined by register/unregister/is_registered
/// (kernel-test builds), for the registry scale test.
#[cfg(feature = "kernel-test")]
static PT_REGISTRY_PROBES: AtomicU64 = AtomicU64::new(0);

#[inline]
fn note_pt_probe() {
    #[cfg(feature = "kernel-test")]
    PT_REGISTRY_PROBES.fetch_add(1, Ordering::Relaxed);
}

#[inline]
fn pagetable_registry_start(phys: u64) -> usize {
    debug_assert!(PT_REGISTRY_LEN.is_power_of_two());
    (((phys >> PAGE_SHIFT).wrapping_mul(0x9E37_79B9_7F4A_7C15)) as usize) & (PT_REGISTRY_LEN - 1)
}

#[doc(hidden)]
pub fn __pagetable_register(phys: u64) {
    use core::sync::atomic::Ordering;
    debug_assert!(phys > PT_REGISTRY_TOMBSTONE && phys & (PAGE_SIZE - 1) == 0);
    // O(1) mark in the frame's own slot (Linux `PG_table`); the hash table
    // below serves only frames without one.
    if cow::set_page_table_mark(phys, true) {
        return;
    }
    let start = pagetable_registry_start(phys);
    'retry: loop {
        let mut first_tombstone = None;
        for distance in 0..PT_REGISTRY_LEN {
            let index = (start + distance) & (PT_REGISTRY_LEN - 1);
            let value = PT_REGISTRY[index].load(Ordering::Acquire);
            note_pt_probe();
            if value == phys {
                return;
            }
            if value == PT_REGISTRY_TOMBSTONE {
                first_tombstone.get_or_insert(index);
                continue;
            }
            if value != 0 {
                continue;
            }
            let target = first_tombstone.unwrap_or(index);
            let expected = if target == index {
                0
            } else {
                PT_REGISTRY_TOMBSTONE
            };
            if PT_REGISTRY[target]
                .compare_exchange(expected, phys, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
            continue 'retry;
        }
        if let Some(target) = first_tombstone {
            if PT_REGISTRY[target]
                .compare_exchange(
                    PT_REGISTRY_TOMBSTONE,
                    phys,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return;
            }
            continue;
        }
        // Full of live entries. Never evict another root's ownership marker.
        PT_REGISTRY_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
        return;
    }
}

/// Move every hash-registry entry that now has a flat slot into that slot's
/// page-table mark, and clear the table if nothing else is left in it. Runs
/// once, as the flat table is published during boot, before any user address
/// space exists.
fn move_pagetable_registry_into_marks() {
    let mut remaining = 0usize;
    for slot in &PT_REGISTRY {
        let value = slot.load(Ordering::Acquire);
        if value <= PT_REGISTRY_TOMBSTONE {
            continue;
        }
        if cow::set_page_table_mark(value, true) {
            slot.store(PT_REGISTRY_TOMBSTONE, Ordering::Release);
        } else {
            remaining += 1;
        }
    }
    if remaining == 0 {
        // Only tombstones left: an empty table probes nothing.
        for slot in &PT_REGISTRY {
            slot.store(0, Ordering::Release);
        }
    }
}

/// Count of `__pagetable_register` calls that found no free slot. Stays
/// 0 in healthy operation; a non-zero value means address spaces are
/// leaking page tables faster than they're reclaimed.
pub static PT_REGISTRY_OVERFLOWS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[doc(hidden)]
pub fn __pagetable_unregister(phys: u64) {
    use core::sync::atomic::Ordering;
    if cow::set_page_table_mark(phys, false) {
        return;
    }
    let start = pagetable_registry_start(phys);
    for distance in 0..PT_REGISTRY_LEN {
        let slot = &PT_REGISTRY[(start + distance) & (PT_REGISTRY_LEN - 1)];
        let value = slot.load(Ordering::Acquire);
        note_pt_probe();
        if value == 0 {
            return;
        }
        if value == phys {
            let _ = slot.compare_exchange(
                phys,
                PT_REGISTRY_TOMBSTONE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return;
        }
    }
}

#[doc(hidden)]
pub fn __pagetable_is_registered(phys: u64) -> bool {
    use core::sync::atomic::Ordering;
    if let Some(marked) = cow::page_table_mark(phys) {
        return marked;
    }
    let start = pagetable_registry_start(phys);
    for distance in 0..PT_REGISTRY_LEN {
        let value = PT_REGISTRY[(start + distance) & (PT_REGISTRY_LEN - 1)].load(Ordering::Acquire);
        note_pt_probe();
        if value == phys {
            return true;
        }
        if value == 0 {
            return false;
        }
    }
    false
}

/// Registering and unregistering page tables must cost the same however many
/// distinct frames have been page tables before, and must leave the registry
/// as it found it. Process churn makes every page-table frame ever used pass
/// through here once; a registry that keeps a trace of each one (a tombstone
/// in an open-addressed table) slows down for good. Linux keeps the
/// page-table mark in the page itself (`PG_table`).
#[cfg(feature = "kernel-test")]
fn smoke_pagetable_registry_churn_is_constant() -> narf_kernel_test::TestResult {
    use alloc::format;
    use narf_kernel_test::TestResult;

    const FRAMES: usize = 4096;
    const ROUNDS: usize = 4;
    let occupancy = || {
        PT_REGISTRY
            .iter()
            .filter(|slot| slot.load(Ordering::Relaxed) != 0)
            .count()
    };
    let mut frames = Vec::new();
    if frames.try_reserve_exact(FRAMES).is_err() {
        return TestResult::Skip("no memory for the frame list");
    }
    for _ in 0..FRAMES {
        match alloc_frame() {
            Ok(frame) => frames.push(frame),
            Err(_) => break,
        }
    }
    if frames.len() != FRAMES {
        free_frame_batch(&frames);
        return TestResult::Skip("not enough frames");
    }
    let before = occupancy();
    let probes_before = PT_REGISTRY_PROBES.load(Ordering::Relaxed);
    let mut lost = false;
    for _ in 0..ROUNDS {
        for frame in &frames {
            __pagetable_register(frame.start_address().raw());
        }
        lost |= frames
            .iter()
            .any(|frame| !__pagetable_is_registered(frame.start_address().raw()));
        for frame in &frames {
            __pagetable_unregister(frame.start_address().raw());
        }
        lost |= frames
            .iter()
            .any(|frame| __pagetable_is_registered(frame.start_address().raw()));
    }
    let probes = PT_REGISTRY_PROBES.load(Ordering::Relaxed) - probes_before;
    let after = occupancy();
    free_frame_batch(&frames);
    let operations = (ROUNDS * FRAMES * 4) as u64;
    if lost {
        return TestResult::Fail("a registered page table was not found, or stayed found");
    }
    if after != before || probes > operations {
        return TestResult::Fail(alloc::boxed::Box::leak(
            format!(
                "registry churn of {FRAMES} frames x {ROUNDS}: occupied slots {before} -> {after}; \
                 {probes} slot probes for {operations} operations"
            )
            .into_boxed_str(),
        ));
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("memory/frame", smoke_pagetable_registry_churn_is_constant);

/// Per-frame reference counting for the COW-fork path.
///
/// `clone_for_fork` shares the parent's frames with the child by
/// `inc_ref`-ing every frame and marking the PTEs read-only on
/// both sides. The first user-mode write to such a page faults;
/// the page-fault handler invokes `cow_split_on_write` which
/// allocates a fresh frame, memcpys the bytes, repoints the
/// faulting AS's PTE at the new frame, and `dec_ref`s the old
/// shared frame. When the count drops back to 1, the surviving
/// AS is the sole owner and subsequent writes don't fault.
///
/// Frames not registered here behave as if their refcount is 0:
/// `free_frame` returns them immediately, matching the
/// pre-existing single-owner semantics. The map is populated
/// only for frames that go through `inc_ref`.
pub mod cow {
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};

    use narf_lib::sync::IrqSafeSpinLock;

    use crate::PhysAddr;

    // COW refcounts are consulted on EVERY frame free (`dec_ref`) and every
    // fork'd shared page (`inc_ref`), so a single global lock bounced one cache
    // line between every CPU freeing memory. Shard 64-way by phys page number
    // (same transform as the signal / futex tables); a frame always maps to one
    // shard, but unrelated frames on other CPUs no longer contend.
    const REFCOUNT_SHARDS: usize = 64;

    #[repr(align(64))]
    struct RefShard {
        map: IrqSafeSpinLock<Option<RefTable>>,
    }

    enum RefSlot {
        Vacant,
        Tombstone,
        Occupied {
            key: u64,
            count: u32,
            transition_epoch: u32,
        },
    }

    /// Open-addressed physical-frame refcount index.
    ///
    /// COW retains already serialize on the frame's shard. A B-tree therefore
    /// bought no concurrency while making every page retain/drop logarithmic.
    /// Linux keeps the refcount directly beside each `struct page`; this sparse
    /// table gives NARF the same average O(1) lookup without allocating metadata
    /// proportional to the machine's highest physical address.
    struct RefTable {
        slots: Vec<RefSlot>,
        len: usize,
        tombstones: usize,
        batch_epoch: u32,
    }

    impl RefTable {
        fn new() -> Self {
            Self {
                slots: Vec::new(),
                len: 0,
                tombstones: 0,
                batch_epoch: 0,
            }
        }

        #[inline]
        fn hash(key: u64) -> usize {
            // SplitMix64 finalizer over the frame number. Low frame-number
            // bits selected the shard, so mix before indexing the table.
            let mut value = key >> super::PAGE_SHIFT;
            value ^= value >> 30;
            value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value ^= value >> 27;
            value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
            (value ^ (value >> 31)) as usize
        }

        fn find(&self, key: u64) -> Option<usize> {
            if self.slots.is_empty() {
                return None;
            }
            let mask = self.slots.len() - 1;
            let mut index = Self::hash(key) & mask;
            for _ in 0..self.slots.len() {
                match &self.slots[index] {
                    RefSlot::Vacant => return None,
                    RefSlot::Occupied { key: existing, .. } if *existing == key => {
                        return Some(index);
                    }
                    RefSlot::Tombstone | RefSlot::Occupied { .. } => {}
                }
                index = (index + 1) & mask;
            }
            None
        }

        fn insertion_slot(&self, key: u64) -> usize {
            let mask = self.slots.len() - 1;
            let mut index = Self::hash(key) & mask;
            let mut first_tombstone = None;
            for _ in 0..self.slots.len() {
                match &self.slots[index] {
                    RefSlot::Vacant => return first_tombstone.unwrap_or(index),
                    RefSlot::Tombstone => {
                        first_tombstone.get_or_insert(index);
                    }
                    RefSlot::Occupied { key: existing, .. } => {
                        assert_ne!(*existing, key, "duplicate COW refcount insertion");
                    }
                }
                index = (index + 1) & mask;
            }
            first_tombstone.expect("COW refcount table has no insertion slot")
        }

        fn rehash(&mut self, capacity: usize) {
            debug_assert!(capacity.is_power_of_two());
            let mut slots = Vec::with_capacity(capacity);
            slots.resize_with(capacity, || RefSlot::Vacant);
            let old = core::mem::replace(&mut self.slots, slots);
            self.len = 0;
            self.tombstones = 0;
            for slot in old {
                if let RefSlot::Occupied {
                    key,
                    count,
                    transition_epoch,
                } = slot
                {
                    self.insert_rehashed(key, count, transition_epoch);
                }
            }
        }

        fn insert_rehashed(&mut self, key: u64, count: u32, transition_epoch: u32) {
            let index = self.insertion_slot(key);
            self.slots[index] = RefSlot::Occupied {
                key,
                count,
                transition_epoch,
            };
            self.len += 1;
        }

        fn prepare_insert(&mut self) {
            const INITIAL_CAPACITY: usize = 16;
            if self.slots.is_empty() {
                self.rehash(INITIAL_CAPACITY);
                return;
            }
            // Keep one quarter of the table genuinely vacant so a missing-key
            // probe terminates quickly. Rebuild in place if tombstones alone
            // crossed the ceiling.
            let occupied_after_insert = self.len + self.tombstones + 1;
            let load_ceiling = self.slots.len() - self.slots.len() / 4;
            if occupied_after_insert >= load_ceiling {
                let capacity = if self.len + 1 < self.slots.len() / 2 {
                    self.slots.len()
                } else {
                    self.slots
                        .len()
                        .checked_mul(2)
                        .expect("COW refcount table capacity overflow")
                };
                self.rehash(capacity);
            }
        }

        fn count(&self, key: u64) -> u32 {
            let Some(index) = self.find(key) else {
                return 0;
            };
            match &self.slots[index] {
                RefSlot::Occupied { count, .. } => *count,
                RefSlot::Vacant | RefSlot::Tombstone => unreachable!(),
            }
        }

        /// Add one owner and return the count before the addition. A missing
        /// row has one implicit original owner, matching the old map contract.
        fn increment(&mut self, key: u64) -> u32 {
            if let Some(index) = self.find(key) {
                let RefSlot::Occupied { count, .. } = &mut self.slots[index] else {
                    unreachable!();
                };
                let previous = *count;
                *count = (*count).wrapping_add(1);
                return previous;
            }
            self.prepare_insert();
            let index = self.insertion_slot(key);
            if matches!(self.slots[index], RefSlot::Tombstone) {
                self.tombstones -= 1;
            }
            self.slots[index] = RefSlot::Occupied {
                key,
                count: 2,
                transition_epoch: 0,
            };
            self.len += 1;
            1
        }

        /// Begin one locked batch. The epoch lets duplicate aliases observe a
        /// sole-to-shared transition made by an earlier occurrence without a
        /// second allocation or a linear search through transitioned keys.
        fn begin_batch(&mut self) -> u32 {
            self.batch_epoch = self.batch_epoch.wrapping_add(1);
            if self.batch_epoch == 0 {
                for slot in &mut self.slots {
                    if let RefSlot::Occupied {
                        transition_epoch, ..
                    } = slot
                    {
                        *transition_epoch = 0;
                    }
                }
                self.batch_epoch = 1;
            }
            self.batch_epoch
        }

        /// Add one batch owner and return whether this key transitioned from
        /// sole-owned in the current batch. Every duplicate occurrence sees
        /// the same answer so every writable parent alias is write-protected.
        fn increment_batch(&mut self, key: u64, epoch: u32) -> bool {
            if let Some(index) = self.find(key) {
                let RefSlot::Occupied {
                    count,
                    transition_epoch,
                    ..
                } = &mut self.slots[index]
                else {
                    unreachable!();
                };
                if *count <= 1 {
                    *transition_epoch = epoch;
                }
                *count = (*count).wrapping_add(1);
                return *transition_epoch == epoch;
            }
            self.prepare_insert();
            let index = self.insertion_slot(key);
            if matches!(self.slots[index], RefSlot::Tombstone) {
                self.tombstones -= 1;
            }
            self.slots[index] = RefSlot::Occupied {
                key,
                count: 2,
                transition_epoch: epoch,
            };
            self.len += 1;
            true
        }

        /// Drop one explicit owner. `rollback` removes a `2 -> 1` row because
        /// the speculative child never became an owner; ordinary teardown
        /// retains count 1 until the original owner itself is freed.
        fn decrement(&mut self, key: u64, rollback: bool) -> Option<(u32, u32)> {
            let index = self.find(key)?;
            let previous = match &self.slots[index] {
                RefSlot::Occupied { count, .. } => *count,
                RefSlot::Vacant | RefSlot::Tombstone => unreachable!(),
            };
            let next = previous.saturating_sub(1);
            if previous <= 1 || (rollback && previous == 2) {
                self.slots[index] = RefSlot::Tombstone;
                self.len -= 1;
                self.tombstones += 1;
            } else if let RefSlot::Occupied { count, .. } = &mut self.slots[index] {
                *count = next;
            } else {
                unreachable!();
            }
            Some((previous, next))
        }
    }

    impl RefShard {
        const fn new() -> Self {
            Self {
                map: IrqSafeSpinLock::new(None),
            }
        }
    }

    static REFCOUNTS: [RefShard; REFCOUNT_SHARDS] = [const { RefShard::new() }; REFCOUNT_SHARDS];

    #[inline]
    fn ref_shard(phys: u64) -> usize {
        // Frames are page-aligned; the low 12 bits are always zero.
        ((phys >> 12) as usize) & (REFCOUNT_SHARDS - 1)
    }

    // ── Flat PFN-indexed fast path ─────────────────────────────────────
    //
    // Linux keeps the COW share count directly in `struct page`; the
    // sharded hash above makes every fork and every teardown pay
    // hash+probe+shard-lock per resident page — the dominant cost of a
    // fork+exit cycle. `init_flat_table` (boot, after the slab heap is
    // live) backs one cache-line-isolated slot per boot-managed frame via
    // `valloc` (64 bytes per 4 KiB page, 1.6% of RAM, comparable to Linux's
    // `struct page`). Fork/exit updates refcounts from many CPUs at once;
    // packing eight unrelated frames into one cache line made independent
    // address spaces serialize through false sharing. After publication every
    // in-range key still uses a single lock-free atomic. Keys outside the boot
    // RAM range (memory hotplug) and pre-init callers keep the sharded-hash
    // path; a key is in exactly one of the two structures, decided solely by
    // its address.
    //
    // Entry layout: low 32 bits = owner count (0 = unregistered, i.e.
    // one implicit sole owner; 1 is stored after a share drops back to a
    // sole owner, matching the hash table's retained count-1 row), high
    // 32 bits = the `inc_ref_batch` epoch that observed the frame's most
    // recent sole→shared transition, so a duplicate alias in the same
    // batch also reports "newly shared" and every parent alias gets
    // write-protected.
    #[repr(align(64))]
    struct FlatCowSlot {
        state: AtomicU64,
        // Lifetime holds such as vmsplice do not write-protect the original
        // mapping. Fork must distinguish them from existing COW mappings.
        pins: AtomicU32,
        // Physical provenance is independent of COW/pin ownership and survives
        // reuse. Zero means unknown; registered RAM stores node + 1. This fits
        // in the existing padding, keeping the 64-byte descriptor unchanged.
        // The top bit is the frame's page-table mark (`PAGE_TABLE_BIT`, Linux
        // `PG_table`); the node lives in the bits below it.
        node_plus_one: AtomicU32,
        // Independent slab bookkeeping. Zeroed before publication, protected
        // exclusively by the owning slab size-class lock, never by COW locks.
        slab: core::cell::UnsafeCell<crate::slab::FrameState>,
    }
    // SAFETY: ownership/pins/provenance use their original atomics. Only slab
    // accesses `slab`, under the frame's owning class lock; an allocated frame
    // cannot change classes until every object is central and it is detached.
    unsafe impl Sync for FlatCowSlot {}
    const _: () = assert!(core::mem::size_of::<FlatCowSlot>() == 64);
    const _: () = assert!(core::mem::align_of::<FlatCowSlot>() == 64);

    static FLAT: AtomicPtr<FlatCowSlot> = AtomicPtr::new(core::ptr::null_mut());
    static FLAT_FRAMES: AtomicUsize = AtomicUsize::new(0);
    static FLAT_EPOCH: AtomicU32 = AtomicU32::new(0);

    // ── Charged memory cgroup per frame (Linux `folio->memcg_data`) ────────
    //
    // One `MemcgId` word per boot-managed frame, beside the flat COW table and
    // published with it: the memory cgroup a user page was charged to, so its
    // final free uncharges that cgroup rather than whoever is running then.
    // 0 = not charged (kernel memory, or no memory cgroup). Frames outside
    // the flat range (hot-plugged RAM) use the sharded `SPILL_MEMCG` maps.
    // A word is written when its frame is charged, right after allocation and
    // before the frame is published to anyone else, and cleared by the single
    // final free; both are plain atomic swaps.
    #[cfg(feature = "cgroup")]
    static MEMCG_WORDS: AtomicPtr<AtomicU32> = AtomicPtr::new(core::ptr::null_mut());
    #[cfg(feature = "cgroup")]
    static MEMCG_FRAMES: AtomicUsize = AtomicUsize::new(0);
    #[cfg(feature = "cgroup")]
    type MemcgMap = alloc::collections::BTreeMap<u64, u32>;
    #[cfg(feature = "cgroup")]
    static SPILL_MEMCG: [IrqSafeSpinLock<Option<MemcgMap>>; REFCOUNT_SHARDS] =
        [const { IrqSafeSpinLock::new(None) }; REFCOUNT_SHARDS];

    #[cfg(feature = "cgroup")]
    fn memcg_word(key: u64) -> Option<&'static AtomicU32> {
        let ptr = MEMCG_WORDS.load(Ordering::Acquire);
        let index = (key >> super::PAGE_SHIFT) as usize;
        if ptr.is_null() || index >= MEMCG_FRAMES.load(Ordering::Relaxed) {
            return None;
        }
        // SAFETY: the published array is permanent and holds `MEMCG_FRAMES`
        // initialized words; `index` is bounds-checked above.
        Some(unsafe { &*ptr.add(index) })
    }

    /// Record that `phys` (the head of a charged block) was charged to memory
    /// cgroup `id`. The frame must be freshly allocated and not yet visible to
    /// any other owner.
    #[cfg(feature = "cgroup")]
    pub(crate) fn set_frame_memcg(phys: PhysAddr, id: u32) {
        if id == 0 {
            return;
        }
        if let Some(word) = memcg_word(phys.raw()) {
            word.store(id, Ordering::Release);
            return;
        }
        SPILL_MEMCG[ref_shard(phys.raw())]
            .lock()
            .get_or_insert_with(MemcgMap::new)
            .insert(phys.raw(), id);
    }

    /// Take (and clear) the memory cgroup `phys` was charged to; 0 if none.
    /// Allocation-free.
    #[cfg(feature = "cgroup")]
    pub(crate) fn take_frame_memcg(phys: PhysAddr) -> u32 {
        if let Some(word) = memcg_word(phys.raw()) {
            return word.swap(0, Ordering::AcqRel);
        }
        SPILL_MEMCG[ref_shard(phys.raw())]
            .lock()
            .as_mut()
            .and_then(|map| map.remove(&phys.raw()))
            .unwrap_or(0)
    }

    /// The memory cgroup `phys` is charged to, without changing it; 0 if none.
    #[cfg(feature = "cgroup")]
    pub fn frame_memcg(phys: PhysAddr) -> u32 {
        if let Some(word) = memcg_word(phys.raw()) {
            return word.load(Ordering::Acquire);
        }
        SPILL_MEMCG[ref_shard(phys.raw())]
            .lock()
            .as_ref()
            .and_then(|map| map.get(&phys.raw()).copied())
            .unwrap_or(0)
    }

    /// Move a charge from `old` to `new` (page migration: Linux
    /// `mem_cgroup_migrate`). The new frame inherits the old one's cgroup and
    /// the old frame's final free then uncharges nothing.
    #[cfg(feature = "cgroup")]
    pub(crate) fn transfer_frame_memcg(old: PhysAddr, new: PhysAddr) {
        let id = take_frame_memcg(old);
        set_frame_memcg(new, id);
    }

    /// Allocate the per-frame memcg words for `frames` boot frames. Same
    /// timing contract as [`init_flat_table`]: before any user page exists.
    #[cfg(feature = "cgroup")]
    fn init_memcg_words(frames: usize) {
        if !MEMCG_WORDS.load(Ordering::Acquire).is_null() {
            return;
        }
        let bytes = frames * core::mem::size_of::<AtomicU32>();
        let Some(ptr) = crate::vmalloc::valloc(bytes) else {
            return;
        };
        // SAFETY: `valloc` returned `bytes` of exclusively owned, mapped
        // kernel memory; zero it before publication (all-zero is a valid
        // `AtomicU32`).
        unsafe { core::ptr::write_bytes(ptr.as_ptr(), 0, bytes) };
        MEMCG_FRAMES.store(frames, Ordering::Relaxed);
        MEMCG_WORDS.store(ptr.as_ptr() as *mut AtomicU32, Ordering::Release);
    }

    const FLAT_COUNT_MASK: u64 = 0xFFFF_FFFF;

    type PinMap = alloc::collections::BTreeMap<u64, u32>;
    static SPILL_PINS: [IrqSafeSpinLock<Option<PinMap>>; REFCOUNT_SHARDS] =
        [const { IrqSafeSpinLock::new(None) }; REFCOUNT_SHARDS];

    #[inline]
    fn flat_entry(key: u64) -> Option<&'static FlatCowSlot> {
        let ptr = FLAT.load(Ordering::Acquire);
        let index = (key >> super::PAGE_SHIFT) as usize;
        if ptr.is_null() || index >= FLAT_FRAMES.load(Ordering::Relaxed) {
            return None;
        }
        // SAFETY: the published PFN array is permanent and bounds-checked.
        Some(unsafe { &*ptr.add(index) })
    }

    fn flat_pins(key: u64) -> Option<&'static AtomicU32> {
        flat_entry(key).map(|slot| &slot.pins)
    }

    /// Permanent metadata only; callers require their slab class lock before
    /// dereferencing the interior-mutability cell. Early/out-of-range frames
    /// return None and keep the legacy slab central path.
    pub(crate) fn slab_frame_state(
        phys: PhysAddr,
    ) -> Option<&'static core::cell::UnsafeCell<crate::slab::FrameState>> {
        flat_entry(phys.raw()).map(|slot| &slot.slab)
    }

    /// Constant-time lookup for registered boot RAM. No ownership counter changes,
    /// topology locks, or heap allocation occur on this path.
    #[inline]
    pub(super) fn cached_node_for_phys(key: u64) -> Option<usize> {
        (flat_entry(key)?.node_plus_one.load(Ordering::Relaxed) & !PAGE_TABLE_BIT)
            .checked_sub(1)
            .map(|node| node as usize)
    }

    /// Page-table mark in `FlatCowSlot::node_plus_one` (Linux `PG_table`).
    const PAGE_TABLE_BIT: u32 = 1 << 31;

    /// Mark or unmark `key` as a page-table frame in its flat slot, in O(1).
    /// `false` when the frame has no flat slot (hot-plugged RAM, or before
    /// the table is published); the caller then uses the hash registry.
    pub(super) fn set_page_table_mark(key: u64, on: bool) -> bool {
        let Some(slot) = flat_entry(key) else {
            return false;
        };
        if on {
            slot.node_plus_one
                .fetch_or(PAGE_TABLE_BIT, Ordering::AcqRel);
        } else {
            slot.node_plus_one
                .fetch_and(!PAGE_TABLE_BIT, Ordering::AcqRel);
        }
        true
    }

    /// The page-table mark of `key`; `None` when it has no flat slot.
    pub(super) fn page_table_mark(key: u64) -> Option<bool> {
        flat_entry(key).map(|slot| slot.node_plus_one.load(Ordering::Acquire) & PAGE_TABLE_BIT != 0)
    }

    /// Retain RAM independently of its mappings. The caller holds the mapping
    /// lock so fork cannot observe the count increment before pin publication.
    pub(crate) fn pin_ref(phys: PhysAddr) {
        inc_ref(phys);
        if let Some(pins) = flat_pins(phys.raw()) {
            pins.fetch_add(1, Ordering::Release);
        } else {
            let mut guard = SPILL_PINS[ref_shard(phys.raw())].lock();
            *guard
                .get_or_insert_with(PinMap::new)
                .entry(phys.raw())
                .or_default() += 1;
        }
    }

    /// Release the physical owner before withdrawing the pin marker. A fork
    /// which sees no marker must also see the completed owner decrement;
    /// otherwise it could mistake a remaining pin for an already-COW mapping.
    pub(crate) fn unpin_ref(phys: PhysAddr) {
        super::free_frame(super::PhysFrame::new(phys));
        if let Some(pins) = flat_pins(phys.raw()) {
            let previous = pins.fetch_sub(1, Ordering::AcqRel);
            assert_ne!(previous, 0, "unbalanced user-page pin");
        } else {
            let mut guard = SPILL_PINS[ref_shard(phys.raw())].lock();
            let map = guard.as_mut().expect("registered user-page pin");
            let count = map.get_mut(&phys.raw()).expect("registered user-page pin");
            *count -= 1;
            if *count == 0 {
                map.remove(&phys.raw());
            }
        }
    }

    pub(crate) fn is_pinned(phys: PhysAddr) -> bool {
        match flat_pins(phys.raw()) {
            Some(pins) => pins.load(Ordering::Acquire) != 0,
            None => SPILL_PINS[ref_shard(phys.raw())]
                .lock()
                .as_ref()
                .is_some_and(|map| map.contains_key(&phys.raw())),
        }
    }

    #[inline]
    fn flat_slot(key: u64) -> Option<&'static AtomicU64> {
        flat_entry(key).map(|slot| &slot.state)
    }

    /// Reserve a batch epoch. Epoch 0 is reserved for non-batch
    /// increments so a fresh slot can never alias a live batch.
    /// Wraparound can only turn "already shared" into a spurious "newly
    /// shared" for a duplicate alias — one redundant write-protect,
    /// never a missed one.
    fn flat_next_epoch() -> u32 {
        let mut epoch = FLAT_EPOCH.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if epoch == 0 {
            epoch = FLAT_EPOCH.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        }
        epoch
    }

    /// Add one owner. Returns `(previous_count, newly_shared)` where a
    /// missing registration reports the implicit sole owner `1`, exactly
    /// like `RefTable::increment` / `increment_batch`.
    fn flat_increment(slot: &AtomicU64, epoch: u32) -> (u32, bool) {
        let mut cur = slot.load(Ordering::Relaxed);
        loop {
            let count = cur as u32;
            let (next, previous, newly) = if count <= 1 {
                ((u64::from(epoch) << 32) | 2, count.max(1), true)
            } else {
                let stored_epoch = (cur >> 32) as u32;
                (
                    (cur & !FLAT_COUNT_MASK) | u64::from(count.wrapping_add(1)),
                    count,
                    epoch != 0 && stored_epoch == epoch,
                )
            };
            match slot.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return (previous, newly),
                Err(seen) => cur = seen,
            }
        }
    }

    /// Drop one owner. `None` when the frame was never registered.
    /// Mirrors `RefTable::decrement`: an ordinary drop from 1 (and a
    /// rollback drop from 2) returns the slot to the implicit
    /// sole-owner representation. The stored epoch is cleared — it only
    /// carries meaning within the `inc_ref_batch` call that wrote it,
    /// and the VMA transaction serializes that batch against any
    /// decrement of the same frames.
    fn flat_decrement(slot: &AtomicU64, rollback: bool) -> Option<(u32, u32)> {
        let mut cur = slot.load(Ordering::Relaxed);
        loop {
            let count = cur as u32;
            if count == 0 {
                return None;
            }
            let next_count = count.saturating_sub(1);
            let next = if count <= 1 || (rollback && count == 2) {
                0
            } else {
                u64::from(next_count)
            };
            match slot.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some((count, next_count)),
                Err(seen) => cur = seen,
            }
        }
    }

    /// One-time boot initialisation of the flat PFN-indexed table.
    ///
    /// Must run after the slab heap and `init_from_map` are live and
    /// BEFORE the first user address space exists: any refcount already
    /// registered for an in-range key is migrated under its shard lock,
    /// but concurrent COW traffic during the migration itself is not
    /// supported (there is none — user tasks spawn much later in boot).
    /// A failed `valloc` leaves the sharded hash serving everything.
    pub fn init_flat_table() {
        if !FLAT.load(Ordering::Acquire).is_null() {
            return;
        }
        let limit = super::managed_phys_end();
        if limit == 0 {
            return;
        }
        let frames = (limit >> super::PAGE_SHIFT) as usize;
        let bytes = frames * core::mem::size_of::<FlatCowSlot>();
        let Some(ptr) = crate::vmalloc::valloc(bytes) else {
            return;
        };
        // SAFETY: `valloc` returned `bytes` of exclusively-owned,
        // frame-backed kernel memory; zero it before publication.
        unsafe { core::ptr::write_bytes(ptr.as_ptr(), 0, bytes) };
        let base = ptr.as_ptr() as *mut FlatCowSlot;
        // Only known boot RAM gets a cached node. PFN holes stay unknown so
        // later hotplug cannot inherit a fabricated node-0 classification.
        // Resolve before publication, while boot topology is authoritative;
        // no user address space exists yet. A byte address within a frame has
        // the same node as its page-aligned start.
        // Rebalance publishes numa_aware only after boot node membership is
        // fixed. An earlier initialization leaves nodes unknown, preserving
        // authoritative lookup if topology is installed later. Hotplug RAM
        // cannot overlap these boot ranges and keeps its existing fallback.
        let boot_ranges = if super::ALLOC.numa_aware.load(Ordering::Acquire) {
            super::BOOT_MEMORY_RANGES.lock().clone()
        } else {
            Vec::new()
        };
        for (start, len) in boot_ranges {
            let first = (start.saturating_add(super::PAGE_SIZE - 1) >> super::PAGE_SHIFT) as usize;
            let end = ((start.saturating_add(len) >> super::PAGE_SHIFT) as usize).min(frames);
            for index in first..end {
                // SAFETY: frame provides the topology hook; this is a known
                // boot-RAM frame and the table is not yet published.
                let node = unsafe { super::narf_phys_to_node((index as u64) << super::PAGE_SHIFT) };
                if node < super::MAX_NUMA_NODES as u32 {
                    // SAFETY: valloc owns `frames` initialized entries.
                    unsafe { &*base.add(index) }
                        .node_plus_one
                        .store(node + 1, Ordering::Relaxed);
                }
            }
        }
        for shard in &REFCOUNTS {
            let mut guard = shard.map.lock();
            if let Some(table) = guard.as_mut() {
                for slot in &mut table.slots {
                    if let RefSlot::Occupied { key, count, .. } = *slot {
                        let index = (key >> super::PAGE_SHIFT) as usize;
                        if index < frames {
                            // SAFETY: `base` holds `frames` entries.
                            unsafe { &*base.add(index) }
                                .state
                                .store(u64::from(count), Ordering::Relaxed);
                            *slot = RefSlot::Tombstone;
                            table.len -= 1;
                            table.tombstones += 1;
                        }
                    }
                }
            }
        }
        #[cfg(feature = "cgroup")]
        init_memcg_words(frames);
        FLAT_FRAMES.store(frames, Ordering::Relaxed);
        FLAT.store(base, Ordering::Release);
        // Page tables registered before the table existed (kernel tables
        // built during boot) move from the hash registry to their marks.
        super::move_pagetable_registry_into_marks();
    }

    /// Increment the refcount on `phys`. Returns the new count.
    /// First call (frame previously had count 0 / unregistered)
    /// inserts a count of 2 — the implicit "1" for the original
    /// owner plus the "1" for the new sharer. Subsequent
    /// `inc_ref`s add one each.
    pub fn inc_ref(phys: PhysAddr) -> u32 {
        let key = phys.raw();
        if let Some(slot) = flat_slot(key) {
            let (previous, _) = flat_increment(slot, 0);
            return previous.wrapping_add(1);
        }
        let mut g = REFCOUNTS[ref_shard(key)].map.lock();
        let map = g.get_or_insert_with(RefTable::new);
        // Bump from N to N+1; "first share" promotes the implicit
        // owner from `1` (representing the original sole owner) to
        // `2` (original + new sharer).
        map.increment(key).wrapping_add(1)
    }

    /// Increment the COW reference for every non-zero frame in `frames`.
    ///
    /// Frames are grouped by refcount shard before any lock is taken, so a
    /// fork of an N-page address space acquires each touched shard once rather
    /// than disabling IRQs around N independent lock acquisitions. The return
    /// bitmap preserves input order and marks every occurrence of a frame that
    /// transitioned from sole-owned to shared during this batch. Fork uses it
    /// to write-protect only newly shared parent leaves.
    ///
    /// Duplicate addresses are intentional: each occurrence represents
    /// another owner and therefore contributes one reference. If a sole-owned
    /// frame occurs more than once, every occurrence is marked so every parent
    /// alias loses WRITE before the child can observe it.
    pub fn inc_ref_batch(frames: &[PhysAddr]) -> Vec<bool> {
        if !FLAT.load(Ordering::Acquire).is_null() {
            let epoch = flat_next_epoch();
            let mut newly_shared = alloc::vec![false; frames.len()];
            // Out-of-range (hotplug) keys fall back to the sharded hash;
            // they still need the hash's own batch-epoch machinery so
            // duplicate aliases are all marked.
            let mut spill: Vec<(u64, usize)> = Vec::new();
            for (index, phys) in frames.iter().enumerate() {
                let key = phys.raw();
                if key == 0 {
                    continue;
                }
                if let Some(slot) = flat_slot(key) {
                    let (_, newly) = flat_increment(slot, epoch);
                    newly_shared[index] = newly;
                } else {
                    spill.push((key, index));
                }
            }
            for (shard, refcounts) in REFCOUNTS.iter().enumerate() {
                let mut guard = None;
                let mut hash_epoch = 0;
                for &(key, index) in &spill {
                    if ref_shard(key) != shard {
                        continue;
                    }
                    let g = guard.get_or_insert_with(|| refcounts.map.lock());
                    let map = g.get_or_insert_with(RefTable::new);
                    if hash_epoch == 0 {
                        hash_epoch = map.begin_batch();
                    }
                    if map.increment_batch(key, hash_epoch) {
                        newly_shared[index] = true;
                    }
                }
            }
            return newly_shared;
        }
        let mut newly_shared = alloc::vec![false; frames.len()];
        let mut counts = [0usize; REFCOUNT_SHARDS];
        for phys in frames {
            let key = phys.raw();
            if key != 0 {
                counts[ref_shard(key)] += 1;
            }
        }
        let nonzero = counts.iter().sum();
        let mut next = [0usize; REFCOUNT_SHARDS];
        let mut offset = 0usize;
        for (shard, count) in counts.iter().copied().enumerate() {
            next[shard] = offset;
            offset += count;
        }
        let mut entries = alloc::vec![(0u64, 0usize); nonzero];
        for (index, phys) in frames.iter().enumerate() {
            let key = phys.raw();
            if key == 0 {
                continue;
            }
            let shard = ref_shard(key);
            entries[next[shard]] = (key, index);
            next[shard] += 1;
        }

        let mut start = 0usize;
        for (shard, count) in counts.into_iter().enumerate() {
            if count == 0 {
                continue;
            }
            let shard_entries = &entries[start..start + count];
            let mut guard = REFCOUNTS[shard].map.lock();
            let map = guard.get_or_insert_with(RefTable::new);
            // Keep the counting-partition's input order. Sorting every shard
            // made a repeated fork pay O(pages log pages) even though the
            // common case contains no aliases and every refcount row already
            // exists. Linux increments each struct-page refcount directly;
            // doing the same ordered walk here leaves the operation linear.
            //
            // The table's batch epoch remembers a transition made by an
            // earlier alias without allocating or searching a second vector.
            // Every occurrence still gets its own reference and bitmap bit.
            let epoch = map.begin_batch();
            for &(key, input_index) in shard_entries {
                if map.increment_batch(key, epoch) {
                    newly_shared[input_index] = true;
                }
            }
            start += count;
        }
        debug_assert_eq!(start, nonzero);
        newly_shared
    }

    /// One fork's incremental COW retain pass.
    ///
    /// [`inc_ref_batch`]'s slice shape forces the caller to materialize
    /// every resident private frame in a side vector before any retain
    /// happens; this cursor gives the same batch semantics one frame at a
    /// time so fork can retain while it walks its regions. The flat-table
    /// epoch is reserved lazily on the first retain, and duplicate aliases
    /// of a frame whose sole→shared transition happened in this pass all
    /// report newly-shared, exactly like [`inc_ref_batch`]'s bitmap. Keys
    /// outside the flat table (memory hotplug, pre-init callers) take
    /// their shard lock per call and track this pass's transitions in a
    /// linear spill list — both are cold by construction, so the common
    /// fork never leaves the lock-free flat path.
    pub(crate) struct ForkRetain {
        flat_epoch: u32,
        spill_transitioned: Vec<u64>,
    }

    pub(crate) fn begin_fork_retain() -> ForkRetain {
        ForkRetain {
            flat_epoch: 0,
            spill_transitioned: Vec::new(),
        }
    }

    impl ForkRetain {
        /// Add one COW owner for the resident frame `phys` and report
        /// whether the frame is newly shared — its sole→shared transition
        /// happened during this pass (every duplicate alias of such a frame
        /// also reports true, so each writable parent alias gets
        /// write-protected). Failed forks undo these retains with
        /// [`rollback_inc_ref_batch`] over the frames retained so far.
        pub(crate) fn retain(&mut self, phys: PhysAddr) -> bool {
            let key = phys.raw();
            debug_assert_ne!(key, 0, "COW retain requires a resident frame");
            if let Some(slot) = flat_slot(key) {
                if self.flat_epoch == 0 {
                    self.flat_epoch = flat_next_epoch();
                }
                return flat_increment(slot, self.flat_epoch).1;
            }
            let previous = {
                let mut guard = REFCOUNTS[ref_shard(key)].map.lock();
                guard.get_or_insert_with(RefTable::new).increment(key)
            };
            if previous <= 1 {
                self.spill_transitioned.push(key);
                true
            } else {
                self.spill_transitioned.contains(&key)
            }
        }
    }

    /// Undo speculative retains previously added by [`inc_ref_batch`] or
    /// [`ForkRetain::retain`].
    ///
    /// Fork uses this only for private frames whose child VMAs
    /// were never published.  The original owner is therefore still live: a
    /// count that falls from two to one is removed from the table, restoring
    /// the implicit sole-owner representation, and no frame is released.
    /// Duplicate inputs remain distinct retains and are rolled back in full.
    /// This path allocates nothing and takes each touched shard at most once.
    pub(crate) fn rollback_inc_ref_batch(frames: &[PhysAddr]) {
        for (shard, refcounts) in REFCOUNTS.iter().enumerate() {
            let mut guard = None;
            for &phys in frames {
                let key = phys.raw();
                if key == 0 || ref_shard(key) != shard {
                    continue;
                }
                if let Some(slot) = flat_slot(key) {
                    let (previous, _) = flat_decrement(slot, true)
                        .expect("speculative COW retain must remain registered");
                    assert!(previous > 1, "cannot roll back the original COW owner");
                    continue;
                }
                let g = guard.get_or_insert_with(|| refcounts.map.lock());
                let map = g
                    .as_mut()
                    .expect("speculative COW retain must have a refcount table");
                let (previous, _) = map
                    .decrement(key, true)
                    .expect("speculative COW retain must remain registered");
                assert!(previous > 1, "cannot roll back the original COW owner");
            }
        }
    }

    /// Decrement the refcount on `phys`. Returns the new count
    /// (post-decrement). If `phys` was never `inc_ref`'d, returns
    /// 0 — `free_frame` then returns the frame to the bin
    /// directly, matching pre-COW semantics.
    pub fn dec_ref(phys: PhysAddr) -> u32 {
        let key = phys.raw();
        if let Some(slot) = flat_slot(key) {
            return flat_decrement(slot, false).map_or(0, |(_, next)| next);
        }
        let mut g = REFCOUNTS[ref_shard(key)].map.lock();
        let map = match g.as_mut() {
            Some(m) => m,
            None => return 0,
        };
        // We want the post-decrement value. If the count is
        // already 1, drop the entry entirely so an unregistered
        // frame's next `free_frame` doesn't have to look it up.
        map.decrement(key, false).map_or(0, |(_, next)| next)
    }

    /// Drop one owner for every non-zero input and return exactly the frames
    /// whose final COW owner was removed (or which were never registered).
    ///
    /// Results preserve input order within each shard only; callers must treat
    /// them as an ownership set, not as a positional mask. Duplicate inputs
    /// are processed as distinct owner drops. Each touched shard is locked
    /// once, eliminating per-page IRQ disable/restore cycles during teardown.
    pub fn dec_ref_batch(frames: &[PhysAddr]) -> Vec<PhysAddr> {
        if !FLAT.load(Ordering::Acquire).is_null() {
            let mut releasable = Vec::with_capacity(frames.len());
            for &phys in frames {
                let key = phys.raw();
                if key == 0 {
                    continue;
                }
                match flat_slot(key) {
                    Some(slot) => match flat_decrement(slot, false) {
                        Some((previous, _)) if previous > 1 => {}
                        _ => releasable.push(phys),
                    },
                    None => {
                        // Hotplug key: sharded-hash drop (rare path).
                        let mut guard = REFCOUNTS[ref_shard(key)].map.lock();
                        match guard.as_mut().and_then(|map| map.decrement(key, false)) {
                            Some((previous, _)) if previous > 1 => {}
                            _ => releasable.push(phys),
                        }
                    }
                }
            }
            return releasable;
        }
        let mut by_shard: [Vec<usize>; REFCOUNT_SHARDS] = core::array::from_fn(|_| Vec::new());
        for (index, phys) in frames.iter().enumerate() {
            let key = phys.raw();
            if key != 0 {
                by_shard[ref_shard(key)].push(index);
            }
        }

        // Reserve before any refcount reaches zero. Growing this vector while
        // holding a COW shard after final-owner removal would make teardown's
        // forward progress depend on a recursive frame allocation.
        let mut releasable = Vec::with_capacity(frames.len());
        for (shard, indices) in by_shard.into_iter().enumerate() {
            if indices.is_empty() {
                continue;
            }
            let mut guard = REFCOUNTS[shard].map.lock();
            for index in indices {
                let phys = frames[index];
                let Some(map) = guard.as_mut() else {
                    releasable.push(phys);
                    continue;
                };
                let key = phys.raw();
                let Some((previous, _)) = map.decrement(key, false) else {
                    releasable.push(phys);
                    continue;
                };
                if previous <= 1 {
                    releasable.push(phys);
                }
            }
        }
        releasable
    }

    /// Drop one owner for every non-zero input, invoking `on_release(phys)`
    /// for each frame whose final COW owner was removed (or which was never
    /// registered). Unlike [`dec_ref_batch`] this allocates nothing: the
    /// caller supplies the sink, so freeing memory never depends on a
    /// recursive allocation. That is a hard requirement for the teardown and
    /// OOM-reaper paths, which run precisely when memory is exhausted.
    ///
    /// The caller supplies at most one allocator teardown window. A fixed-size
    /// counting sort groups that window by shard in O(frames + shards), then
    /// each touched shard is locked exactly once. `on_release` runs while the
    /// shard lock is held, so it must only record the address (e.g. into a
    /// stack buffer) — it must not take the zone/cache locks, which would
    /// invert the established lock order.
    /// Callers scrub/publish released frames after this returns.
    pub(super) fn dec_ref_batch_each(frames: &[PhysAddr], mut on_release: impl FnMut(PhysAddr)) {
        assert!(
            frames.len() <= super::FREE_BATCH_WINDOW,
            "COW decrement batch exceeds allocator teardown window"
        );
        if !FLAT.load(Ordering::Acquire).is_null() {
            // Allocation-free by construction: one lock-free atomic per
            // in-range frame, a single transient shard lock per hotplug
            // frame.
            for &phys in frames {
                let key = phys.raw();
                if key == 0 {
                    continue;
                }
                match flat_slot(key) {
                    Some(slot) => match flat_decrement(slot, false) {
                        Some((previous, _)) if previous > 1 => {}
                        _ => on_release(phys),
                    },
                    None => {
                        let mut guard = REFCOUNTS[ref_shard(key)].map.lock();
                        match guard.as_mut().and_then(|map| map.decrement(key, false)) {
                            Some((previous, _)) if previous > 1 => {}
                            _ => on_release(phys),
                        }
                    }
                }
            }
            return;
        }
        let mut counts = [0usize; REFCOUNT_SHARDS];
        for &phys in frames {
            if phys.raw() != 0 {
                counts[ref_shard(phys.raw())] += 1;
            }
        }
        let mut next = [0usize; REFCOUNT_SHARDS];
        let mut total = 0usize;
        for (shard, count) in counts.iter().copied().enumerate() {
            next[shard] = total;
            total += count;
        }
        let mut ordered = [PhysAddr::new(0); super::FREE_BATCH_WINDOW];
        for &phys in frames {
            if phys.raw() == 0 {
                continue;
            }
            let shard = ref_shard(phys.raw());
            ordered[next[shard]] = phys;
            next[shard] += 1;
        }

        let mut start = 0usize;
        for (shard, count) in counts.into_iter().enumerate() {
            if count == 0 {
                continue;
            }
            let mut guard = REFCOUNTS[shard].map.lock();
            for &phys in &ordered[start..start + count] {
                let Some(map) = guard.as_mut() else {
                    on_release(phys);
                    continue;
                };
                let key = phys.raw();
                let Some((previous, _)) = map.decrement(key, false) else {
                    on_release(phys);
                    continue;
                };
                if previous <= 1 {
                    on_release(phys);
                }
            }
            start += count;
        }
        debug_assert_eq!(start, total);
    }

    /// Read-only peek at a frame's refcount. Returns 0 if the
    /// frame was never registered; otherwise the current count.
    pub fn count(phys: PhysAddr) -> u32 {
        let key = phys.raw();
        if let Some(slot) = flat_slot(key) {
            return slot.load(Ordering::Acquire) as u32;
        }
        REFCOUNTS[ref_shard(key)]
            .map
            .lock()
            .as_ref()
            .map_or(0, |map| map.count(key))
    }

    /// Snapshot COW counts in the same order as `frames`.
    ///
    /// Each touched shard is locked once, so page-table construction can
    /// derive permissions for a complete region without one IRQ-disabling
    /// lock acquisition per leaf. Zero/unregistered frames report zero and
    /// duplicate inputs receive identical snapshots.
    pub fn count_batch(frames: &[PhysAddr]) -> Vec<u32> {
        if !FLAT.load(Ordering::Acquire).is_null() {
            let mut counts = alloc::vec![0; frames.len()];
            for (index, phys) in frames.iter().enumerate() {
                let key = phys.raw();
                if key == 0 {
                    continue;
                }
                counts[index] = match flat_slot(key) {
                    Some(slot) => slot.load(Ordering::Acquire) as u32,
                    None => REFCOUNTS[ref_shard(key)]
                        .map
                        .lock()
                        .as_ref()
                        .map_or(0, |map| map.count(key)),
                };
            }
            return counts;
        }
        let mut counts = alloc::vec![0; frames.len()];
        let mut by_shard: [Vec<usize>; REFCOUNT_SHARDS] = core::array::from_fn(|_| Vec::new());
        for (index, phys) in frames.iter().enumerate() {
            let key = phys.raw();
            if key != 0 {
                by_shard[ref_shard(key)].push(index);
            }
        }

        for (shard, indices) in by_shard.into_iter().enumerate() {
            if indices.is_empty() {
                continue;
            }
            let guard = REFCOUNTS[shard].map.lock();
            let Some(map) = guard.as_ref() else {
                continue;
            };
            for index in indices {
                let key = frames[index].raw();
                counts[index] = map.count(key);
            }
        }
        counts
    }

    /// Test hook — drop every recorded refcount. Tests that
    /// exercise inc/dec sequences should call this to start from
    /// a clean slate.
    #[doc(hidden)]
    pub fn __test_clear() {
        let ptr = FLAT.load(Ordering::Acquire);
        if !ptr.is_null() {
            let frames = FLAT_FRAMES.load(Ordering::Relaxed);
            for index in 0..frames {
                // SAFETY: `ptr` holds `frames` published entries.
                unsafe { &*ptr.add(index) }
                    .state
                    .store(0, Ordering::Relaxed);
            }
        }
        for s in &REFCOUNTS {
            *s.map.lock() = None;
        }
    }

    // Always compiled so this exercises the same table implementation used by
    // the in-kernel test image rather than a hosted-only substitute.
    mod tests {
        use super::RefTable;
        use narf_kernel_test::{kernel_test_in, TestResult};

        /// smaps and allocator return paths must not take the hotplug registry
        /// lock for a registered frame. Compare with the firmware bridge, then
        /// hold that registry while checking both whole-frame and byte lookups.
        fn smoke_frame_node_metadata_bypasses_topology_locks() -> TestResult {
            let Ok(frame) = super::super::alloc_frame() else {
                return TestResult::Fail("no frame for NUMA metadata smoke");
            };
            let phys = frame.start_address().raw();
            let cached = super::cached_node_for_phys(phys);
            // SAFETY: the linked frame bridge is the uncached topology oracle.
            let expected = unsafe { super::super::narf_phys_to_node(phys) } as usize;
            let result = match cached {
                None if super::FLAT
                    .load(core::sync::atomic::Ordering::Acquire)
                    .is_null()
                    || !super::super::ALLOC
                        .numa_aware
                        .load(core::sync::atomic::Ordering::Acquire) =>
                {
                    TestResult::Skip("boot node metadata is unavailable")
                }
                None => TestResult::Fail("allocated boot frame lacks NUMA provenance"),
                Some(node) if node != expected => {
                    TestResult::Fail("cached NUMA node differs from the topology bridge")
                }
                Some(node) => {
                    if super::cached_node_for_phys(u64::MAX).is_some() {
                        super::super::free_frame(frame);
                        return TestResult::Fail("unknown PFN acquired fabricated provenance");
                    }
                    let _ranges = super::super::HOTPLUG_RANGES.lock();
                    if [0, 1, super::super::PAGE_SIZE - 1]
                        .into_iter()
                        .all(|offset| {
                            super::super::node_for_phys(phys + offset) == node
                            // SAFETY: the allocated frame stays live.
                            && unsafe { super::super::narf_phys_node(phys + offset) } == node
                        })
                    {
                        TestResult::Pass
                    } else {
                        TestResult::Fail("frame-node lookup lost registered provenance")
                    }
                }
            };
            super::super::free_frame(frame);
            result
        }
        kernel_test_in!(
            "memory/numa",
            smoke_frame_node_metadata_bypasses_topology_locks
        );

        fn smoke_cow_refcount_hash_index_grows_through_tombstones() -> TestResult {
            let mut table = RefTable::new();
            for page in 1..=192u64 {
                if table.increment(page << super::super::PAGE_SHIFT) != 1 {
                    return TestResult::Fail("fresh COW hash entry was not implicit owner 1");
                }
            }
            for page in (2..=192u64).step_by(2) {
                let key = page << super::super::PAGE_SHIFT;
                if table.decrement(key, false) != Some((2, 1))
                    || table.decrement(key, false) != Some((1, 0))
                {
                    return TestResult::Fail("COW hash decrement lost owner cardinality");
                }
            }
            for page in 193..=320u64 {
                table.increment(page << super::super::PAGE_SHIFT);
            }
            let old_survived = (1..=192u64).all(|page| {
                table.count(page << super::super::PAGE_SHIFT) == if page & 1 == 0 { 0 } else { 2 }
            });
            let new_visible =
                (193..=320u64).all(|page| table.count(page << super::super::PAGE_SHIFT) == 2);
            if !old_survived || !new_visible || table.len != 224 {
                return TestResult::Fail("COW hash growth lost a live key across tombstones");
            }

            // Rollback of the only speculative share returns to the implicit
            // owner representation and must preserve neighboring probe chains.
            let rollback_key = 256u64 << super::super::PAGE_SHIFT;
            if table.decrement(rollback_key, true) != Some((2, 1))
                || table.count(rollback_key) != 0
                || table.count(255u64 << super::super::PAGE_SHIFT) != 2
                || table.count(257u64 << super::super::PAGE_SHIFT) != 2
            {
                return TestResult::Fail("COW rollback broke the hash probe chain");
            }
            TestResult::Pass
        }
        kernel_test_in!(
            "memory/cow",
            smoke_cow_refcount_hash_index_grows_through_tombstones
        );

        /// End-to-end owner-count transitions through the PUBLIC cow API
        /// on a real allocated frame. In the boot kernel this exercises
        /// the flat PFN-indexed fast path (`init_flat_table` ran); when
        /// the flat table is absent it exercises the sharded hash — the
        /// contract is identical either way.
        fn smoke_cow_public_api_owner_transitions() -> TestResult {
            let Ok(frame) = super::super::alloc_frame() else {
                return TestResult::Fail("no frame available for COW smoke");
            };
            let phys = frame.start_address();
            let result = (|| {
                if super::count(phys) != 0 {
                    return TestResult::Fail("fresh frame already had a COW count");
                }
                if super::inc_ref(phys) != 2 {
                    return TestResult::Fail("first share must report two owners");
                }
                if super::dec_ref(phys) != 1 {
                    return TestResult::Fail("share drop must report the sole owner");
                }
                if super::count(phys) != 1 {
                    return TestResult::Fail("retained sole-owner row lost");
                }
                // Duplicate aliases in one batch: both occurrences must
                // report the sole→shared transition.
                let newly = super::inc_ref_batch(&[phys, phys]);
                if newly != alloc::vec![true, true] {
                    return TestResult::Fail("batch duplicate missed a newly-shared mark");
                }
                if super::count(phys) != 3 {
                    return TestResult::Fail("batch owners not all recorded");
                }
                // An already-shared frame in a later batch is NOT newly
                // shared.
                if super::inc_ref_batch(&[phys]) != alloc::vec![false] {
                    return TestResult::Fail("already-shared frame reported a transition");
                }
                if !super::dec_ref_batch(&[phys, phys]).is_empty() {
                    return TestResult::Fail("non-final owner drop reported releasable");
                }
                if super::count_batch(&[phys]) != alloc::vec![2] {
                    return TestResult::Fail("count_batch disagrees after batch drops");
                }
                // Drop to a single explicit share, then roll it back:
                // a 2 -> 1 rollback restores the implicit sole-owner
                // representation (count reads 0 = unregistered).
                if super::dec_ref(phys) != 1 || super::count(phys) != 1 {
                    return TestResult::Fail("owner drop to retained sole owner failed");
                }
                if super::inc_ref(phys) != 2 {
                    return TestResult::Fail("re-share of retained sole owner failed");
                }
                super::rollback_inc_ref_batch(&[phys]);
                if super::count(phys) != 0 {
                    return TestResult::Fail("rollback did not restore the implicit owner");
                }
                TestResult::Pass
            })();
            // The frame's count is back to unregistered on every path
            // above that reaches a verdict late; free unconditionally.
            super::super::free_frame(super::super::PhysFrame::new(phys));
            result
        }
        kernel_test_in!("memory/cow", smoke_cow_public_api_owner_transitions);
    }
}

/// Snapshot of allocator usage. Dispatches through the installed
/// `FrameAlloc`. Returns a zeroed `FrameStats` if no allocator
/// has been installed yet (pre-init).
pub fn stats() -> FrameStats {
    current_alloc().map(|a| a.stats()).unwrap_or(FrameStats {
        total: 0,
        free: 0,
        reserved: 0,
    })
}

/// One-past-the-end of the highest boot-donated RAM byte, or 0 before
/// `init_from_map`. Sizes the flat COW refcount table: every frame the
/// buddy can hand out lies below this bound (memory hotplug can later
/// donate above it; those frames use the sharded-hash COW path).
pub(crate) fn managed_phys_end() -> u64 {
    BOOT_MEMORY_RANGES
        .lock()
        .iter()
        .map(|&(start, len)| start.saturating_add(len))
        .max()
        .unwrap_or(0)
}

/// Buddy-backed implementation of `stats`.
fn buddy_stats() -> FrameStats {
    // The online mask is published after each node's counters and cleared
    // only after its final range has left the allocator. Sparse iteration
    // therefore preserves the aggregate while avoiding 16 cache-line reads
    // on the overwhelmingly common one-node system.
    let mut nodes = online_node_mask();
    let mut free = 0usize;
    while nodes != 0 {
        let node = nodes.trailing_zeros() as usize;
        free = free.saturating_add(ALLOC.node_free_frames[node].load(Ordering::Relaxed));
        nodes &= nodes - 1;
    }
    FrameStats {
        total: ALLOC.total_frames.load(Ordering::Relaxed),
        free,
        reserved: ALLOC.reserved_frames.load(Ordering::Relaxed),
    }
}

/// Per-node free-frame count. Returns 0 when `node` is out of range
/// or the allocator hasn't been initialised.
pub fn node_free(node: usize) -> usize {
    if node >= MAX_NUMA_NODES {
        return 0;
    }
    ALLOC.node_free_frames[node].load(Ordering::Relaxed)
}

/// Stable number of allocator-managed base pages assigned to `node`.
///
/// The snapshot is established at SRAT-driven rebalance, after early
/// reserved/boot allocations have been removed from the buddy pool.
pub fn node_total(node: usize) -> usize {
    if node >= MAX_NUMA_NODES {
        return 0;
    }
    ALLOC.node_total_frames[node].load(Ordering::Relaxed)
}

/// Snapshot the number of free buddy blocks at every order for `node`.
pub fn node_free_blocks(node: usize) -> [usize; BUDDY_ORDER_COUNT] {
    let mut counts = [0usize; BUDDY_ORDER_COUNT];
    if node >= MAX_NUMA_NODES {
        return counts;
    }
    let zone = ZONES[node].0.lock();
    for (order, count) in counts.iter_mut().enumerate() {
        *count = zone.free_block_count(order as u8);
    }
    counts[0] += FRAME_CACHE_FREE[node].load(Ordering::Relaxed);
    counts[1] += PAIR_CACHE_FREE[node].load(Ordering::Relaxed);
    counts
}

/// True once `rebalance_to_topology` has run.
pub fn is_numa_aware() -> bool {
    ALLOC.numa_aware.load(Ordering::Acquire)
}

/// Diagnostic: walk every zone's free lists and confirm no frame
/// appears in more than one block. Returns `Ok(())` on success or
/// `Err((zone, frame_no, order_a, order_b))` describing the first
/// overlap found. Intended for smoke-test instrumentation, not hot
/// paths — O(N log N) per zone in total free-block count.
pub fn validate_no_overlap() -> Result<(), (usize, u64, u8, u8)> {
    for (i, zone) in ZONES.iter().enumerate() {
        if let Err((f, oa, ob)) = zone.0.lock().validate_no_overlap() {
            return Err((i, f, oa, ob));
        }
    }
    Ok(())
}

fn smoke_buddy_zone_locks_are_independent() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    let first = core::ptr::addr_of!(ZONES[0]) as usize;
    let second = core::ptr::addr_of!(ZONES[1]) as usize;
    if first & 63 != 0 || second.saturating_sub(first) < 64 {
        return TestResult::Fail("buddy zone locks share a cache line");
    }
    let _held = ZONES[0].0.lock();
    if ZONES[1].0.try_lock().is_none() {
        return TestResult::Fail("locking one buddy zone blocks another zone");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("memory/frame", smoke_buddy_zone_locks_are_independent);

/// `alloc_pages_below` (Linux `dma_set_coherent_mask` semantics): every
/// byte of the block is <= the limit, and a limit no RAM satisfies is an
/// error rather than a high frame.
fn smoke_alloc_pages_below_honours_mask() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !ALLOC.initialised.load(Ordering::Acquire) {
        return TestResult::Skip("buddy allocator not initialised");
    }
    const DMA32: u64 = 0xffff_ffff;
    for order in [0u8, 1, 4, 7] {
        let frame = match alloc_pages_below(order, DMA32) {
            Ok(f) => f,
            Err(_) => return TestResult::Fail("no DMA32 block although RAM starts below 4 GiB"),
        };
        let start = frame.start_address().raw();
        let last = start + (PAGE_SIZE << order) - 1;
        free_pages(frame, order);
        if last > DMA32 {
            return TestResult::Fail("alloc_pages_below returned bytes above the mask");
        }
        if start & ((PAGE_SIZE << order) - 1) != 0 {
            return TestResult::Fail("alloc_pages_below block not naturally aligned");
        }
    }
    // A limit inside the 1 MiB the buddy never manages: no frame can
    // satisfy it, so the call must fail instead of handing out RAM
    // above the mask.
    for limit in [0u64, 0xfff, 0x1000, LOW_RESERVED_BYTES - 1] {
        if alloc_pages_below(0, limit).is_ok() {
            return TestResult::Fail("alloc_pages_below satisfied a mask below managed RAM");
        }
    }
    // A mask ending mid-page cannot hold that page.
    let lowest = match alloc_pages_below(0, DMA32) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("DMA32 order-0 allocation failed"),
    };
    let lo = lowest.start_address().raw();
    free_pages(lowest, 0);
    if let Ok(f) = alloc_pages_below(0, lo + 0x7ff) {
        let end = f.start_address().raw() + PAGE_SIZE - 1;
        free_pages(f, 0);
        if end > lo + 0x7ff {
            return TestResult::Fail("partial last page counted as allocatable");
        }
    }
    if alloc_pages_below(MAX_ORDER + 1, DMA32).is_ok() {
        return TestResult::Fail("order above MAX_ORDER accepted");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("memory/frame", smoke_alloc_pages_below_honours_mask);

/// The node the frame-cache tests allocate on: this CPU's node when it has
/// memory, else the first node that does. A node can have none at all — in
/// the kernel-test VM the kernel image covers every frame of node 0 — and an
/// allocation "on" it then comes from another node, which is not what these
/// tests measure.
#[cfg(feature = "kernel-test")]
fn test_node_with_memory() -> usize {
    if !ALLOC.numa_aware.load(Ordering::Acquire) {
        return 0;
    }
    let local = current_cpu_node();
    if node_total(local) != 0 {
        return local;
    }
    (0..MAX_NUMA_NODES)
        .find(|&node| node_total(node) != 0)
        .unwrap_or(local)
}

#[cfg(feature = "kernel-test")]
fn smoke_order0_frame_cache_round_trip() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) {
        return TestResult::Skip("frame caches not published");
    }
    let node = test_node_with_memory();
    if FRAME_CACHE_HOTPLUG_BYPASS[node].load(Ordering::Acquire) {
        return TestResult::Skip("runtime hotplug intentionally bypasses frame cache");
    }
    let free_before = node_free(node);
    let hits_before = FRAME_CACHE_HITS.load(Ordering::Relaxed);
    let first = match alloc_pages_on(node, 0) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Skip("no order-0 frame available"),
    };
    if node_free(node).saturating_add(1) != free_before {
        free_pages(first, 0);
        return TestResult::Fail("order-0 allocation did not decrement free accounting");
    }
    free_pages(first, 0);
    let second = match alloc_pages_on(node, 0) {
        Ok(frame) => frame,
        Err(_) => return TestResult::Fail("cached order-0 frame was not reusable"),
    };
    free_pages(second, 0);
    if FRAME_CACHE_HITS.load(Ordering::Relaxed) <= hits_before {
        return TestResult::Fail("order-0 round trip missed the per-CPU cache");
    }
    if node_free(node) != free_before {
        return TestResult::Fail("frame cache changed free-page accounting");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("memory/frame", smoke_order0_frame_cache_round_trip);

#[cfg(feature = "kernel-test")]
fn smoke_order1_frame_cache_ownership_and_accounting() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) {
        return TestResult::Skip("frame caches not published");
    }
    narf_lib::sync::without_interrupts(|| {
        let node = if ALLOC.numa_aware.load(Ordering::Acquire) {
            current_cpu_node()
        } else {
            0
        };
        if frame_cache_bypassed(node) {
            return TestResult::Skip("frame cache bypass is active");
        }
        let before = node_free(node);
        let first = match alloc_pages_on(node, 1) {
            Ok(frame) => frame,
            Err(_) => return TestResult::Fail("cannot allocate an order-1 block"),
        };
        let address = first.start_address().raw();
        if ALLOC.numa_aware.load(Ordering::Acquire) && phys_to_node(address) != node {
            free_pages(first, 1);
            return TestResult::Skip("order-1 allocation used a fallback node");
        }
        let charged = node_free(node).saturating_add(2) == before;
        free_pages(first, 1);
        let hits = PAIR_CACHE_HITS.load(Ordering::Relaxed);
        let second = match alloc_pages_on(node, 1) {
            Ok(frame) => frame,
            Err(_) => return TestResult::Fail("cached order-1 block was not reusable"),
        };
        let reused = second.start_address().raw() == address
            && PAIR_CACHE_HITS.load(Ordering::Relaxed) > hits;
        let other = match alloc_pages_on(node, 1) {
            Ok(frame) => frame,
            Err(_) => {
                free_pages(second, 1);
                return TestResult::Fail("cannot allocate a second live pair");
            }
        };
        let distinct = other.start_address().raw() != second.start_address().raw();
        let pair_mask = PAGE_SIZE * 2 - 1;
        let aligned = address & pair_mask == 0 && other.start_address().raw() & pair_mask == 0;
        free_pages(other, 1);
        free_pages(second, 1);
        if !charged || node_free(node) != before {
            return TestResult::Fail("pair cache changed free-page accounting");
        }
        if !reused || !distinct || !aligned {
            return TestResult::Fail("pair cache lost alignment or exclusive ownership");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "memory/frame",
    smoke_order1_frame_cache_ownership_and_accounting
);

#[cfg(feature = "kernel-test")]
fn smoke_order1_frame_cache_spill_and_drain() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) {
        return TestResult::Skip("frame caches not published");
    }
    narf_lib::sync::without_interrupts(|| {
        let node = test_node_with_memory();
        if frame_cache_bypassed(node) {
            return TestResult::Skip("frame cache bypass is active");
        }
        // Enough pairs that freeing them all must take this CPU's cache past
        // its ceiling, wherever `high` has floated to.
        let tuning = cache_tuning(node);
        let wanted = tuning.high_max / 2 + 2 * tuning.batch + 1;
        let mut held: Vec<u64> = Vec::new();
        if node_free(node) / 4 < 2 * wanted || held.try_reserve_exact(wanted).is_err() {
            return TestResult::Skip("not enough free memory to overfill the pair cache");
        }
        let before = node_free(node);
        for _ in 0..wanted {
            match alloc_pages_on(node, 1) {
                Ok(frame) => held.push(frame.start_address().raw()),
                Err(_) => break,
            }
        }
        for &physical in &held {
            free_pages(PhysFrame::new(PhysAddr::new(physical)), 1);
        }
        if held.len() != wanted {
            return TestResult::Fail("cannot allocate enough pairs to exercise spill");
        }
        let cpu = current_cpu();
        let cached_pages = FRAME_CACHES[cpu].0.lock().nodes[node].count;
        let bounded = cached_pages <= tuning.high_max && cached_pages < 2 * wanted;
        let cached_before = PAIR_CACHE_FREE[node].load(Ordering::Relaxed);
        let drained = with_node_frame_caches_drained(node, |zone| {
            PAIR_CACHE_FREE[node].load(Ordering::Relaxed) == 0
                && FRAME_CACHE_FREE[node].load(Ordering::Relaxed) == 0
                && zone.validate_no_overlap().is_ok()
        });
        let bypassed = with_node_cache_bypassed(node, || {
            let frame = match alloc_pages_on(node, 1) {
                Ok(frame) => frame,
                Err(_) => return false,
            };
            free_pages(frame, 1);
            PAIR_CACHE_FREE[node].load(Ordering::Relaxed) == 0
        });
        if !bounded || cached_before == 0 || !drained || !bypassed {
            return TestResult::Fail("pair spill/drain did not preserve the bypass protocol");
        }
        if node_free(node) != before {
            return TestResult::Fail("pair spill/drain changed free-page accounting");
        }
        TestResult::Pass
    })
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("memory/frame", smoke_order1_frame_cache_spill_and_drain);

/// A higher-order allocation made inside `with_node_cache_bypassed` on a node
/// whose zone has no block of that order must return — from another node or
/// as `Exhausted` — instead of re-taking the node's drain lock its caller
/// holds. That re-entry spun forever with interrupts off whenever NUMA node 0
/// started with no free frames (the kernel-test VM's kernel image can cover
/// all of node 0). A node with no memory at all is the zone that is sure to
/// have no block.
#[cfg(feature = "kernel-test")]
fn smoke_bypassed_node_high_order_alloc_returns() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !ALLOC.numa_aware.load(Ordering::Acquire) {
        return TestResult::Skip("allocator is not NUMA-aware; every node maps to zone 0");
    }
    let Some(empty) = (0..MAX_NUMA_NODES)
        .rev()
        .find(|&node| node_total(node) == 0)
    else {
        return TestResult::Skip("every NUMA slot has memory");
    };
    let free_before: usize = (0..MAX_NUMA_NODES).map(node_free).sum();
    for order in [1u8, 4, MAX_ORDER] {
        let result = with_node_cache_bypassed(empty, || alloc_pages_on(empty, order));
        if let Ok(block) = result {
            if phys_to_node(block.start_address().raw()) == empty {
                free_pages(block, order);
                return TestResult::Fail("a node with no memory supplied a block");
            }
            free_pages(block, order);
        }
    }
    let free_after: usize = (0..MAX_NUMA_NODES).map(node_free).sum();
    if free_after != free_before {
        return TestResult::Fail("bypassed allocation changed free-page accounting");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("memory/frame", smoke_bypassed_node_high_order_alloc_returns);

#[cfg(feature = "kernel-test")]
fn smoke_order0_frame_cache_batch_free_is_bounded() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) {
        return TestResult::Skip("frame caches not published");
    }
    let node = if ALLOC.numa_aware.load(Ordering::Acquire) {
        current_cpu_node().min(MAX_NUMA_NODES - 1)
    } else {
        0
    };
    if frame_cache_bypassed(node) {
        return TestResult::Skip("frame cache drain/hotplug bypass is active");
    }

    const FRAMES: usize = FRAME_RETURN_CHUNK + 1;
    let free_before = node_free(node);
    let mut frames = Vec::with_capacity(FRAMES);
    for _ in 0..FRAMES {
        let frame = match alloc_pages_on(node, 0) {
            Ok(frame) => frame,
            Err(_) => {
                buddy_free_frame_batch(&frames);
                return TestResult::Skip("not enough order-0 frames for batch-free smoke");
            }
        };
        let release_node = if ALLOC.numa_aware.load(Ordering::Acquire) {
            phys_to_node(frame.start_address().raw())
        } else {
            0
        };
        if release_node != node {
            frames.push(frame);
            buddy_free_frame_batch(&frames);
            return TestResult::Skip("allocation fell back to another NUMA node");
        }
        frames.push(frame);
    }

    let locks_before = FRAME_CACHE_BATCH_FREE_LOCKS.load(Ordering::Relaxed);
    buddy_free_frame_batch(&frames);
    let locks = FRAME_CACHE_BATCH_FREE_LOCKS
        .load(Ordering::Relaxed)
        .saturating_sub(locks_before);
    if locks != 2 {
        return TestResult::Fail("batch free did not use bounded cache transactions");
    }
    if node_free(node) != free_before {
        return TestResult::Fail("batch free changed free-page accounting");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "memory/frame",
    smoke_order0_frame_cache_batch_free_is_bounded
);

/// A teardown larger than one `FREE_BATCH_WINDOW` must free every frame with
/// no allocation proportional to the batch size (the region-sized `Vec` that
/// used to sit on this path panicked the kernel under memory pressure). This
/// exercises the multi-window `free_phys_batch` entry across the window
/// boundary and asserts free-page accounting is fully restored and the frames
/// are reusable — a leak or a stranded window would fail both.
#[cfg(feature = "kernel-test")]
fn smoke_free_phys_batch_spans_windows_without_leak() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !ALLOC.initialised.load(Ordering::Acquire) {
        return TestResult::Skip("allocator not initialised");
    }
    let node = if ALLOC.numa_aware.load(Ordering::Acquire) {
        current_cpu_node().min(MAX_NUMA_NODES - 1)
    } else {
        0
    };

    const FRAMES: usize = FREE_BATCH_WINDOW + 8;
    let free_before = node_free(node);
    let mut phys = Vec::with_capacity(FRAMES);
    for _ in 0..FRAMES {
        match alloc_pages_on(node, 0) {
            Ok(frame) => {
                if ALLOC.numa_aware.load(Ordering::Acquire)
                    && phys_to_node(frame.start_address().raw()) != node
                {
                    phys.push(frame.start_address());
                    free_phys_batch(&phys);
                    return TestResult::Skip("allocation fell back to another NUMA node");
                }
                phys.push(frame.start_address());
            }
            Err(_) => {
                free_phys_batch(&phys);
                return TestResult::Skip("not enough order-0 frames for windowed free smoke");
            }
        }
    }

    free_phys_batch(&phys);
    if node_free(node) != free_before {
        return TestResult::Fail("windowed free_phys_batch changed free-page accounting");
    }
    // A stranded window would leak frames; confirm the pool handed them back.
    match alloc_pages_on(node, 0) {
        Ok(frame) => free_pages(frame, 0),
        Err(_) => return TestResult::Fail("frames not reusable after windowed free"),
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "memory/frame",
    smoke_free_phys_batch_spans_windows_without_leak
);

/// Private non-COW teardown may bypass the COW registry, but it must retain
/// the ordinary batch path's filtering, windowing, accounting, and reuse
/// behavior. Cross a window boundary so a dropped tail cannot hide.
#[cfg(feature = "kernel-test")]
fn smoke_free_unique_phys_batch_spans_windows_without_leak() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    if !ALLOC.initialised.load(Ordering::Acquire) {
        return TestResult::Skip("allocator not initialised");
    }
    let node = if ALLOC.numa_aware.load(Ordering::Acquire) {
        current_cpu_node().min(MAX_NUMA_NODES - 1)
    } else {
        0
    };

    const FRAMES: usize = FREE_BATCH_WINDOW + 8;
    let free_before = node_free(node);
    let mut phys = Vec::with_capacity(FRAMES);
    for _ in 0..FRAMES {
        match alloc_pages_on(node, 0) {
            Ok(frame) => {
                let address = frame.start_address();
                if ALLOC.numa_aware.load(Ordering::Acquire) && phys_to_node(address.raw()) != node {
                    phys.push(address);
                    // SAFETY: every collected frame is a fresh, unique
                    // allocation with no COW or page-table owner.
                    unsafe { free_unique_phys_batch(&phys) };
                    return TestResult::Skip("allocation fell back to another NUMA node");
                }
                if cow::count(address) != 0 {
                    free_phys_batch(&phys);
                    free_pages(frame, 0);
                    return TestResult::Fail("fresh unique frame had COW ownership");
                }
                phys.push(address);
            }
            Err(_) => {
                // SAFETY: every collected frame is a fresh, unique allocation.
                unsafe { free_unique_phys_batch(&phys) };
                return TestResult::Skip("not enough order-0 frames for unique free smoke");
            }
        }
    }

    // SAFETY: no frame was aliased, registered in a page table, or retained
    // in the COW registry after allocation above.
    unsafe { free_unique_phys_batch(&phys) };
    if node_free(node) != free_before {
        return TestResult::Fail("windowed unique free changed free-page accounting");
    }
    match alloc_pages_on(node, 0) {
        Ok(frame) => free_pages(frame, 0),
        Err(_) => return TestResult::Fail("frames not reusable after windowed unique free"),
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!(
    "memory/frame",
    smoke_free_unique_phys_batch_spans_windows_without_leak
);

/// Scale tests: how much zone-lock traffic and how much work per zone-lock hold
/// the allocator costs as the machine and the workload grow.
///
/// Everything here is a counter read from the allocator's own bookkeeping
/// (`ZoneOpStats`, `ZONE_HOLD_STATS`), never a clock: the tests assert shapes —
/// constant work per frame, a bounded hold, one lock acquisition per batch —
/// that hold on any host speed. A failure carries the measured counters in its
/// reason, and `scale_counter_report` prints the same counters when the
/// assertions pass (the memory crate has no console of its own; a harness
/// reason string is the only output channel a test here has).
#[cfg(feature = "kernel-test")]
mod scale_tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::format;
    use alloc::string::String;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A zone-lock hold may return at most this many blocks to the buddy.
    const HOLD_FREE_LIMIT: u64 = FRAME_RETURN_CHUNK as u64;
    /// Buddy-lookup steps one freed block may cost: one probe per order it can
    /// coalesce through, with a factor of two of slack.
    const STEPS_PER_FREE_LIMIT: u64 = 2 * (MAX_ORDER as u64 + 1);
    /// Buddy-lookup steps one zone-lock hold may cost.
    const HOLD_STEP_LIMIT: u64 = HOLD_FREE_LIMIT * (MAX_ORDER as u64 + 1);

    const UNMEASURED: u64 = u64::MAX;
    static LIST_STEPS: [AtomicU64; 2] = [const { AtomicU64::new(UNMEASURED) }; 2];
    static LARGE_FREE: [[AtomicU64; 4]; 4] =
        [const { [const { AtomicU64::new(UNMEASURED) }; 4] }; 4];
    static CHURN: [AtomicU64; 3] = [const { AtomicU64::new(UNMEASURED) }; 3];

    fn fail(reason: String) -> TestResult {
        TestResult::Fail(Box::leak(reason.into_boxed_str()))
    }

    /// The node the calling CPU allocates from, provided its frame cache is in
    /// use (a drain or a hot-plugged range turns caching off for a node).
    fn scale_node() -> Result<usize, TestResult> {
        if !FRAME_CACHE_ENABLED.load(Ordering::Acquire) {
            return Err(TestResult::Skip("frame caches not published"));
        }
        // This CPU's node, or the first node with memory when it has none
        // (node 0 can be all kernel image in the test VM).
        let node = test_node_with_memory().min(MAX_NUMA_NODES - 1);
        if frame_cache_bypassed(node) {
            return Err(TestResult::Skip("frame cache bypass is active"));
        }
        Ok(node)
    }

    fn release(frames: &[PhysAddr]) {
        free_phys_batch(frames);
    }

    /// Take `count` order-0 frames that all belong to `node`. `None` (with
    /// everything handed back) when the node cannot supply them.
    fn take_frames(node: usize, count: usize) -> Option<Vec<PhysAddr>> {
        let mut frames = Vec::new();
        frames.try_reserve_exact(count).ok()?;
        let numa = ALLOC.numa_aware.load(Ordering::Acquire);
        for _ in 0..count {
            let Ok(frame) = alloc_pages_on(node, 0) else {
                release(&frames);
                return None;
            };
            let phys = frame.start_address();
            if numa && phys_to_node(phys.raw()) != node {
                free_pages(frame, 0);
                release(&frames);
                return None;
            }
            frames.push(phys);
        }
        Some(frames)
    }

    /// Leave a quarter of the node's free memory alone: the suite shares it.
    fn affordable(node: usize, count: usize) -> bool {
        node_free(node) / 4 >= count
    }

    fn drain(node: usize) {
        with_node_frame_caches_drained(node, |_| ());
    }

    fn op_stats(node: usize) -> buddy::ZoneOpStats {
        ZONES[node].0.lock().op_stats()
    }

    fn reset_holds(node: usize) {
        let stats = &ZONE_HOLD_STATS[node];
        stats.acquisitions.store(0, Ordering::Relaxed);
        stats.max_frees.store(0, Ordering::Relaxed);
        stats.max_allocs.store(0, Ordering::Relaxed);
        stats.max_find_steps.store(0, Ordering::Relaxed);
    }

    /// Deterministic Fisher-Yates over a xorshift stream.
    fn shuffle(frames: &mut [PhysAddr]) {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        for i in (1..frames.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            frames.swap(i, (state % (i as u64 + 1)) as usize);
        }
    }

    /// Buddy-lookup steps per freed frame with `count / 2` order-0 blocks
    /// already on the free list: free one frame of every buddy pair (its
    /// partner is still held, so it cannot coalesce and stays listed), then
    /// free the partners and count what finding each buddy cost.
    fn measure_list_steps(node: usize, count: usize) -> Option<u64> {
        let mut frames = take_frames(node, count)?;
        frames.sort_unstable();
        for phys in frames
            .iter()
            .filter(|phys| (phys.raw() >> PAGE_SHIFT) & 1 == 0)
        {
            free_pages(PhysFrame::new(*phys), 0);
        }
        drain(node);
        let before = op_stats(node);
        for phys in frames
            .iter()
            .filter(|phys| (phys.raw() >> PAGE_SHIFT) & 1 == 1)
        {
            free_pages(PhysFrame::new(*phys), 0);
        }
        drain(node);
        let after = op_stats(node);
        let frees = (after.frees - before.frees).max(1);
        Some((after.find_steps - before.find_steps) / frees)
    }

    const LIST_SIZES: [usize; 2] = [4096, 16384];

    fn list_steps(node: usize) -> Option<[u64; 2]> {
        let mut out = [0u64; 2];
        for (index, &count) in LIST_SIZES.iter().enumerate() {
            let cached = LIST_STEPS[index].load(Ordering::Relaxed);
            out[index] = if cached != UNMEASURED {
                cached
            } else {
                if !affordable(node, count) {
                    return None;
                }
                let steps = measure_list_steps(node, count)?;
                LIST_STEPS[index].store(steps, Ordering::Relaxed);
                steps
            };
        }
        Some(out)
    }

    /// Returning a block to the buddy must cost the same however long the
    /// free lists are. The soak's interrupts-off lockups sat in
    /// `BuddyZone::free_inner`, not spinning on a lock: every free searched its
    /// order's free list for the buddy, so a large free was quadratic.
    fn scale_buddy_free_cost_is_independent_of_list_length() -> TestResult {
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let Some(steps) = list_steps(node) else {
            return TestResult::Skip("not enough free order-0 frames on this node");
        };
        if steps
            .iter()
            .any(|&per_free| per_free > STEPS_PER_FREE_LIMIT)
        {
            return fail(format!(
                "buddy lookup steps per freed frame: {} with {} order-0 blocks listed, {} with {} \
                 (limit {STEPS_PER_FREE_LIMIT})",
                steps[0],
                LIST_SIZES[0] / 2,
                steps[1],
                LIST_SIZES[1] / 2,
            ));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/frame/scale",
        scale_buddy_free_cost_is_independent_of_list_length
    );

    /// `(frames, max blocks freed in one zone-lock hold, max lookup steps in
    /// one hold, lookup steps per freed block)` for one batched free of `count`
    /// order-0 frames, in address order or shuffled.
    fn measure_large_free(node: usize, count: usize, shuffled: bool) -> Option<[u64; 4]> {
        let mut frames = take_frames(node, count)?;
        frames.sort_unstable();
        if shuffled {
            shuffle(&mut frames);
        }
        // Whatever the allocations above left in the caches goes back first,
        // so the holds measured below are this free's own.
        drain(node);
        reset_holds(node);
        let before = op_stats(node);
        release(&frames);
        drain(node);
        let after = op_stats(node);
        let holds = &ZONE_HOLD_STATS[node];
        let frees = (after.frees - before.frees).max(1);
        Some([
            count as u64,
            holds.max_frees.load(Ordering::Relaxed),
            holds.max_find_steps.load(Ordering::Relaxed),
            (after.find_steps - before.find_steps) / frees,
        ])
    }

    /// 64 MiB, and 1 GiB or as much of it as a quarter of the node's free
    /// memory allows, each in address order and shuffled.
    const LARGE_FREE_LABELS: [&str; 4] = [
        "64 MiB ascending",
        "64 MiB shuffled",
        "large ascending",
        "large shuffled",
    ];

    fn large_free(node: usize) -> Option<[[u64; 4]; 4]> {
        const SMALL: usize = (64 << 20) >> PAGE_SHIFT;
        const LARGE: usize = (1 << 30) >> PAGE_SHIFT;
        let mut out = [[0u64; 4]; 4];
        for (index, row) in out.iter_mut().enumerate() {
            if LARGE_FREE[index][0].load(Ordering::Relaxed) != UNMEASURED {
                for (slot, cached) in row.iter_mut().zip(&LARGE_FREE[index]) {
                    *slot = cached.load(Ordering::Relaxed);
                }
                continue;
            }
            let count = if index < 2 {
                SMALL
            } else {
                LARGE.min(node_free(node) / 4)
            };
            if !affordable(node, count) {
                return None;
            }
            *row = measure_large_free(node, count, index % 2 == 1)?;
            for (cached, value) in LARGE_FREE[index].iter().zip(row.iter()) {
                cached.store(*value, Ordering::Relaxed);
            }
        }
        Some(out)
    }

    /// A large region freed in one call — what `munmap` and exit hand to
    /// `free_phys_batch` — must reach the buddy in bounded pieces: each
    /// zone-lock hold (interrupts off) returns a bounded number of blocks and
    /// costs a bounded number of buddy-lookup steps, in either address order.
    fn scale_large_free_is_bounded_per_zone_lock_hold() -> TestResult {
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let Some(rows) = large_free(node) else {
            return TestResult::Skip("not enough free order-0 frames on this node");
        };
        for (label, row) in LARGE_FREE_LABELS.iter().zip(rows.iter()) {
            let [frames, max_frees, max_steps, steps_per_free] = *row;
            if max_frees > HOLD_FREE_LIMIT
                || max_steps > HOLD_STEP_LIMIT
                || steps_per_free > STEPS_PER_FREE_LIMIT
            {
                return fail(format!(
                    "{label} free of {frames} frames: one zone-lock hold freed up to {max_frees} \
                     blocks (limit {HOLD_FREE_LIMIT}) in up to {max_steps} lookup steps (limit \
                     {HOLD_STEP_LIMIT}); {steps_per_free} steps per freed block (limit \
                     {STEPS_PER_FREE_LIMIT})"
                ));
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/frame/scale",
        scale_large_free_is_bounded_per_zone_lock_hold
    );

    const CHURN_FRAMES: usize = 1024;
    const CHURN_ROUNDS: usize = 64;

    /// `(frame operations, zone-lock acquisitions, largest refill)` for a
    /// fork+exit shaped churn: a process's worth of frames taken one at a time
    /// and handed back, half the rounds as one batch (exit) and half one frame
    /// at a time (COW breaks, page-table frees).
    fn measure_churn(node: usize) -> Option<[u64; 3]> {
        if CHURN[0].load(Ordering::Relaxed) != UNMEASURED {
            return Some([
                CHURN[0].load(Ordering::Relaxed),
                CHURN[1].load(Ordering::Relaxed),
                CHURN[2].load(Ordering::Relaxed),
            ]);
        }
        if !affordable(node, CHURN_FRAMES) {
            return None;
        }
        drain(node);
        reset_holds(node);
        for round in 0..CHURN_ROUNDS {
            let frames = take_frames(node, CHURN_FRAMES)?;
            if round % 2 == 0 {
                release(&frames);
            } else {
                for phys in &frames {
                    free_pages(PhysFrame::new(*phys), 0);
                }
            }
        }
        let holds = &ZONE_HOLD_STATS[node];
        let out = [
            (2 * CHURN_FRAMES * CHURN_ROUNDS) as u64,
            holds.acquisitions.load(Ordering::Relaxed),
            holds.max_allocs.load(Ordering::Relaxed),
        ];
        for (cached, value) in CHURN.iter().zip(out.iter()) {
            cached.store(*value, Ordering::Relaxed);
        }
        Some(out)
    }

    /// Under fork/exit churn a CPU may take its node's zone lock at most once
    /// per batch of frames, where the batch is sized from the zone the way
    /// Linux sizes `pcp->batch`. The soak spent 65% of its vCPU samples
    /// spinning for this lock: a 16-frame cache refilled 8 at a time takes it
    /// every 8 frames whatever the machine.
    fn scale_zone_lock_traffic_follows_the_zone_batch() -> TestResult {
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let batch = zone_cache_batch(node_total(node)) as u64;
        let Some([operations, acquisitions, max_refill]) = measure_churn(node) else {
            return TestResult::Skip("not enough free order-0 frames on this node");
        };
        let limit = operations / batch;
        if acquisitions > limit {
            return fail(format!(
                "{acquisitions} zone-lock acquisitions for {operations} frame allocations and \
                 frees ({} per 1000); the zone's batch is {batch}, so the limit is {limit} ({} \
                 per 1000); largest refill {max_refill} frames",
                acquisitions * 1000 / operations,
                limit * 1000 / operations,
            ));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/frame/scale",
        scale_zone_lock_traffic_follows_the_zone_batch
    );

    /// Frames parked in per-CPU caches must stay reachable for a higher-order
    /// allocation: a drain has to put every one of them back in the buddy,
    /// coalesced. Split an order-10 block into its 1024 frames, free them one
    /// at a time (which parks them in the cache), then require the whole block
    /// to be free in the buddy once the node's caches are bypassed — the same
    /// step a failed higher-order allocation takes before it retries.
    fn scale_cached_frames_drain_back_to_a_high_order_block() -> TestResult {
        const ORDER: u8 = 10;
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let free_before = node_free(node);
        let Ok(block) = alloc_pages_on(node, ORDER) else {
            return TestResult::Skip("no order-10 block available");
        };
        let base = block.start_address();
        if ALLOC.numa_aware.load(Ordering::Acquire) && phys_to_node(base.raw()) != node {
            free_pages(block, ORDER);
            return TestResult::Skip("order-10 allocation fell back to another node");
        }
        let frames = 1u64 << ORDER;
        if !split_block(block, ORDER) {
            free_pages(block, ORDER);
            return TestResult::Fail("a live order-10 block could not be split");
        }
        for index in 0..frames {
            free_pages(
                PhysFrame::new(PhysAddr::new(base.raw() + index * PAGE_SIZE)),
                0,
            );
        }
        if node_free(node) != free_before {
            return TestResult::Fail("freeing a split block changed free-page accounting");
        }
        let whole = with_node_cache_bypassed(node, || {
            let reserved = reserve_frame_range(base, frames);
            if reserved {
                free_movable_range(base, frames);
            }
            reserved
        });
        if !whole {
            return TestResult::Fail(
                "frames freed into the per-CPU cache did not all return to the buddy on drain",
            );
        }
        if node_free(node) != free_before {
            return TestResult::Fail("drain and reserve changed free-page accounting");
        }
        match alloc_pages_on(node, ORDER) {
            Ok(again) => free_pages(again, ORDER),
            Err(_) => return TestResult::Fail("order-10 allocation failed after the drain"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/frame/scale",
        scale_cached_frames_drain_back_to_a_high_order_block
    );

    /// The cache sizing is a function of the zone, its low watermark and the
    /// CPUs sharing it — Linux's `zone_batchsize` / `zone_highsize` numbers —
    /// and the live tuning is that function of the live machine.
    fn scale_frame_cache_sizing_follows_the_zone_and_cpu_count() -> TestResult {
        use narf_kernel_test::kt_assert;
        let tuning = |batch, high_min, high_max| CacheTuning {
            batch,
            high_min,
            high_max,
        };
        // The 4 GiB / 12-CPU soak guest: batch 63, 428..10922 pages per CPU.
        kt_assert!(derive_cache_tuning(1 << 20, 5144, 12) == tuning(63, 428, 10922));
        // A 512 MiB node shared by 8 CPUs.
        kt_assert!(derive_cache_tuning(1 << 17, 1280, 8) == tuning(31, 160, 2048));
        // More CPUs on the same node: the floor becomes four batches.
        kt_assert!(derive_cache_tuning(1 << 20, 5144, 64) == tuning(63, 252, 2048));
        // A 16 MiB zone does not batch at all.
        kt_assert!(derive_cache_tuning(4096, 64, 4) == tuning(1, 16, 128));
        // The ceiling never drops below the floor, whatever the watermark.
        kt_assert!(derive_cache_tuning(1 << 20, 1 << 19, 1) == tuning(63, 1 << 19, 1 << 19));
        kt_assert!(zone_cache_batch(usize::MAX) == 63 && zone_cache_batch(0) == 1);

        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let cpus = narf_lib::smp::cpu_count().max(1) as usize;
        let expected = derive_cache_tuning(
            node_total(node),
            crate::reclaim::watermark_low_node(node) as usize,
            node_cache_cpus(node, cpus),
        );
        let live = cache_tuning(node);
        if live != expected {
            return fail(format!(
                "node {node} cache tuning {live:?} is not {expected:?} ({} frames, {cpus} CPUs)",
                node_total(node),
            ));
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/frame/scale",
        scale_frame_cache_sizing_follows_the_zone_and_cpu_count
    );

    /// A frame's state word follows it: empty while allocated, a cache link
    /// while a per-CPU cache holds it, never a cache link once the cache has
    /// been drained — and every zone's words agree with its free lists.
    fn scale_free_state_words_follow_the_frame() -> TestResult {
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let lists_agree = || {
            ZONES
                .iter()
                .all(|zone| zone.0.lock().validate_index().is_ok())
        };
        if !lists_agree() {
            return TestResult::Fail("a zone's state words disagree with its free lists");
        }
        let Ok(frame) = alloc_pages_on(node, 0) else {
            return TestResult::Skip("no order-0 frame available");
        };
        let Some(word) = FRAME_INDEX.slot(buddy::frame_no(frame)) else {
            free_pages(frame, 0);
            return TestResult::Fail("a boot-RAM frame has no state word");
        };
        let allocated = word.load(Ordering::Relaxed);
        if ALLOC.numa_aware.load(Ordering::Acquire)
            && phys_to_node(frame.start_address().raw()) != node
        {
            free_pages(frame, 0);
            return TestResult::Skip("allocation fell back to another NUMA node");
        }
        // Interrupts off so the CPU, and with it the cache, cannot change
        // between the free and the look at the word.
        let (freed, bypassed) = narf_lib::sync::without_interrupts(|| {
            free_pages(frame, 0);
            (word.load(Ordering::Relaxed), frame_cache_bypassed(node))
        });
        drain(node);
        let drained = word.load(Ordering::Relaxed);
        if allocated != buddy::alloc_head_state(0) {
            return TestResult::Fail("an allocated frame's state word does not say order-0 head");
        }
        if bypassed {
            return TestResult::Skip("a drain bypassed the frame cache during the test");
        }
        if buddy::cached_next(freed).is_none() {
            return TestResult::Fail("a frame freed into the per-CPU cache is not marked cached");
        }
        if buddy::cached_next(drained).is_some() {
            return TestResult::Fail("a frame is still marked cached after the cache was drained");
        }
        if !lists_agree() {
            return TestResult::Fail("state words disagree with the free lists after a drain");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/frame/scale",
        scale_free_state_words_follow_the_frame
    );

    /// The step an order-0 allocation takes when its zone has nothing left:
    /// the node's per-CPU caches are drained into the zone and the allocation
    /// is retried there, so memory parked in caches cannot turn into an
    /// allocation failure. Emptying a zone for real would starve the rest of
    /// the suite, so the step is driven directly.
    fn scale_empty_zone_allocation_reaches_cached_frames() -> TestResult {
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let Some(frames) = take_frames(node, FRAME_RETURN_CHUNK) else {
            return TestResult::Skip("not enough free order-0 frames on this node");
        };
        // Read once the vector holding the frames exists, so its own backing
        // allocation is not mistaken for a leak.
        let free_before = node_free(node) + frames.len();
        let outcome = narf_lib::sync::without_interrupts(|| {
            release(&frames);
            let cpu = current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
            let parked = FRAME_CACHES[cpu].0.lock().nodes[node].count;
            let frame = alloc_order0_after_drain(node);
            let left = FRAME_CACHES[cpu].0.lock().nodes[node].count;
            (parked, frame, left)
        });
        let (parked, frame, left) = outcome;
        if let Some(frame) = frame {
            free_pages(frame, 0);
        }
        if parked == 0 {
            return TestResult::Skip("freed frames did not stay in the per-CPU cache");
        }
        if frame.is_none() {
            return TestResult::Fail("no frame although the per-CPU cache held some");
        }
        if left != 0 {
            return TestResult::Fail("the drain left frames in the calling CPU's cache");
        }
        if node_free(node) != free_before {
            return TestResult::Fail("drain-and-retry changed free-page accounting");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "memory/frame/scale",
        scale_empty_zone_allocation_reaches_cached_frames
    );

    /// A frame that is already free must not be accepted again, whether a
    /// per-CPU cache or a buddy free list holds it: the second free is dropped
    /// and counted, and free-page accounting does not move. (With
    /// `frame-alloc-audit` the audit panics at the offending free instead, so
    /// the refusal is not reachable there.)
    #[cfg(not(feature = "frame-alloc-audit"))]
    fn scale_double_free_is_refused_and_counted() -> TestResult {
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let numa = ALLOC.numa_aware.load(Ordering::Acquire);
        let free_before = node_free(node);
        let Ok(frame) = alloc_pages_on(node, 0) else {
            return TestResult::Skip("no order-0 frame available");
        };
        if numa && phys_to_node(frame.start_address().raw()) != node {
            free_pages(frame, 0);
            return TestResult::Skip("allocation fell back to another NUMA node");
        }
        let number = buddy::frame_no(frame);
        free_pages(frame, 0);
        // A per-CPU cache holds it now, unless a drain on another CPU got in
        // between — then it is in the buddy, possibly coalesced beyond
        // recognition, and offering it again would be a real double free.
        let held = FRAME_INDEX
            .slot(number)
            .is_some_and(|word| buddy::cached_next(word.load(Ordering::Relaxed)).is_some());
        if !held {
            return TestResult::Skip("the freed frame did not stay in a per-CPU cache");
        }
        // Offer it again, both ways a second free could arrive.
        let refused = double_frees_refused();
        if free_order0_to_cache(node, number) != CacheFree::AlreadyFree
            || double_frees_refused() != refused + 1
        {
            return TestResult::Fail("the per-CPU cache accepted a frame it already held");
        }
        if lock_zone(node).try_free_mt(number, 0, buddy::MigrateType::Unmovable) {
            return TestResult::Fail("the zone accepted a frame a per-CPU cache holds");
        }

        // A frame on a buddy free list. Free the first half of an order-1
        // block with the cache bypassed: its buddy is still held, so it stays
        // the head of an order-0 block until the second half follows.
        let Ok(pair) = alloc_pages_on(node, 1) else {
            return TestResult::Skip("no order-1 block available on this node");
        };
        let base = pair.start_address();
        if numa && phys_to_node(base.raw()) != node {
            free_pages(pair, 1);
            return TestResult::Skip("order-1 allocation fell back to another NUMA node");
        }
        let second = PhysFrame::new(PhysAddr::new(base.raw() + PAGE_SIZE));
        if !split_block(pair, 1) {
            free_pages(pair, 1);
            return TestResult::Fail("a live order-1 block could not be split");
        }
        let accepted_again = with_node_cache_bypassed(node, || {
            free_pages(pair, 0);
            let accepted = lock_zone(node).try_free_mt(
                buddy::frame_no(pair),
                0,
                buddy::MigrateType::Unmovable,
            );
            free_pages(second, 0);
            accepted
        });
        if accepted_again {
            return TestResult::Fail("the zone accepted a frame already on its free list");
        }
        if node_free(node) != free_before {
            return TestResult::Fail("a refused double free changed free-page accounting");
        }
        TestResult::Pass
    }
    #[cfg(not(feature = "frame-alloc-audit"))]
    kernel_test_in!(
        "memory/frame/scale",
        scale_double_free_is_refused_and_counted
    );

    /// Print the counters the tests above assert on. Always a `Skip`: it
    /// asserts nothing, and a reason string is the only way a test in this
    /// crate can put numbers in the harness log.
    fn scale_counter_report() -> TestResult {
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let tuning = cache_tuning(node);
        let mut report = format!(
            "harness counters, node {node} ({} frames, {} CPUs, batch {}, high {}..{}):",
            node_total(node),
            narf_lib::smp::cpu_count(),
            tuning.batch,
            tuning.high_min,
            tuning.high_max,
        );
        if let Some(steps) = list_steps(node) {
            report.push_str(&format!(
                " lookup steps/free {} @{} listed, {} @{} listed;",
                steps[0],
                LIST_SIZES[0] / 2,
                steps[1],
                LIST_SIZES[1] / 2,
            ));
        }
        if let Some(rows) = large_free(node) {
            for (label, row) in LARGE_FREE_LABELS.iter().zip(rows.iter()) {
                report.push_str(&format!(
                    " {label} {} frames: max {} frees/hold, max {} steps/hold, {} steps/free;",
                    row[0], row[1], row[2], row[3],
                ));
            }
        }
        if let Some([operations, acquisitions, max_refill]) = measure_churn(node) {
            report.push_str(&format!(
                " churn {operations} frame ops: {acquisitions} zone-lock acquisitions ({} per \
                 1000), largest refill {max_refill}",
                acquisitions * 1000 / operations,
            ));
        }
        TestResult::Skip(Box::leak(report.into_boxed_str()))
    }
    kernel_test_in!("memory/frame/scale", scale_counter_report);

    /// The allocator's free state as a test failure reason.
    fn fail_with_state(what: &str) -> TestResult {
        let mut state = String::new();
        let _ = write_free_state(&mut state);
        fail(format!("{what}; {state}"))
    }

    /// Unmovable order-2, -4 and -8 blocks must be available whenever free
    /// memory is ample, both straight away and after order-0 churn has gone
    /// through the per-CPU caches and back in shuffled order. A soak of the
    /// cache rework failed a 16 KiB (order-2) heap allocation with 15 GiB
    /// free, 17 s after boot.
    fn scale_high_orders_survive_order0_churn() -> TestResult {
        const ORDERS: [u8; 3] = [2, 4, 8];
        let node = match scale_node() {
            Ok(node) => node,
            Err(skip) => return skip,
        };
        let try_orders = |label: &str| -> Option<TestResult> {
            for round in 0..64 {
                for order in ORDERS {
                    // Leave a quarter of the node alone, as everywhere here.
                    if node_free(node) / 4 < (1 << order) * 64 {
                        return Some(TestResult::Skip("not enough free memory on this node"));
                    }
                    match alloc_pages_on(node, order) {
                        Ok(block) => free_pages(block, order),
                        Err(_) => {
                            return Some(fail_with_state(&format!(
                                "{label}: order-{order} unmovable allocation failed in round \
                                 {round} with {} frames free",
                                node_free(node)
                            )))
                        }
                    }
                }
            }
            None
        };
        if let Some(result) = try_orders("before churn") {
            return result;
        }
        let count = (node_free(node) / 8).min(1 << 18);
        let Some(mut frames) = take_frames(node, count) else {
            return TestResult::Skip("not enough free order-0 frames on this node");
        };
        shuffle(&mut frames);
        // Half back one at a time (through this CPU's cache), half batched.
        let half = frames.len() / 2;
        for phys in &frames[..half] {
            free_pages(PhysFrame::new(*phys), 0);
        }
        release(&frames[half..]);
        drop(frames);
        if let Some(result) = try_orders("after churn") {
            return result;
        }
        TestResult::Pass
    }
    kernel_test_in!("memory/frame/scale", scale_high_orders_survive_order0_churn);
}

#[derive(Copy, Clone, Debug)]
pub struct FrameStats {
    pub total: usize,
    pub free: usize,
    pub reserved: usize,
}

// ── Weak-link hooks for NUMA topology lookup ────────────────────────
//
// narf-memory cannot depend on narf-acpi (would form a cycle —
// narf-acpi already uses narf_memory::PhysAddr). The kernel binary
// (narf-frame) provides `#[no_mangle]` definitions that call into
// narf-acpi; tests and other binaries that don't care about NUMA
// can provide stubs returning 0.

#[cfg(target_os = "none")]
extern "Rust" {
    /// Look up the NUMA node a physical address belongs to. Returns
    /// `0` when topology is unknown or the address is outside any
    /// SRAT memory range.
    fn narf_phys_to_node(addr: u64) -> u32;
    /// Look up the NUMA node hosting a logical CPU. Returns `0`
    /// when topology is unknown.
    fn narf_cpu_to_node(cpu: u32) -> u32;
    /// NUMA distance from node `from` to node `to` (Linux's
    /// `node_distance`, scaled so local == 10). Returns the SLIT
    /// matrix entry when available, else 10 (same node) / 20
    /// (cross-node). Used to order the allocator's cross-node
    /// fallback nearest-first.
    fn narf_node_distance(from: u32, to: u32) -> u32;
    /// Number of NUMA nodes in the firmware-described topology
    /// (frame's bridge over the SRAT parse). Independent of the
    /// allocator's rebalance state; the bridge floors the result
    /// at 1 (no SRAT described → single node).
    fn narf_numa_node_count() -> u32;
}

// Host-side crate tests do not link the kernel binary that owns the ACPI
// bridge above. Give them the documented no-topology behavior so every crate
// that transitively links narf-memory gets the same deterministic fallback.
// These definitions are excluded from kernel targets, where silently
// replacing firmware topology would be incorrect.
#[cfg(not(target_os = "none"))]
unsafe fn narf_phys_to_node(_addr: u64) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe fn narf_cpu_to_node(_cpu: u32) -> u32 {
    0
}

#[cfg(not(target_os = "none"))]
unsafe fn narf_node_distance(from: u32, to: u32) -> u32 {
    if from == to {
        10
    } else {
        20
    }
}

#[cfg(not(target_os = "none"))]
unsafe fn narf_numa_node_count() -> u32 {
    1
}

/// Number of NUMA nodes in the firmware-described topology, via the
/// weak ACPI bridge. Unlike [`online_node_count`], this reflects
/// what firmware described whether or not the allocator has
/// rebalanced onto it, so callers can distinguish "no multi-node
/// topology exists" from "rebalance did not happen". Returns `1`
/// when topology is unknown (no SRAT parsed, or the host stub).
pub fn firmware_node_count() -> u32 {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    unsafe { narf_numa_node_count() }.max(1)
}

/// Resolve a physical address to an allocator NUMA-node index.
///
/// Kept crate-visible for address-space page migration; external consumers
/// should use higher-level allocation and policy APIs.
#[inline]
pub(crate) unsafe fn narf_phys_node(addr: u64) -> usize {
    if let Some(node) = cow::cached_node_for_phys(addr) {
        return node;
    }
    // SAFETY: narf-frame provides the topology hook in kernel binaries.
    unsafe { narf_phys_to_node(addr) as usize }.min(MAX_NUMA_NODES - 1)
}

/// Distance from node `from` to node `to`, via the weak ACPI hook.
/// Clamps to a sane non-zero default (10 local / 20 remote) when the
/// hook is the no-topology stub.
#[inline]
pub(crate) fn node_distance(from: usize, to: usize) -> u32 {
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let d = unsafe { narf_node_distance(from as u32, to as u32) };
    if d == 0 {
        if from == to {
            10
        } else {
            20
        }
    } else {
        d
    }
}

/// Build the cross-node fallback search order for `preferred`: every
/// *other* node, sorted nearest-first by NUMA distance, ties broken by
/// ascending node index for determinism. Returns the count written into
/// `out` (always `MAX_NUMA_NODES - 1`).
fn fallback_order(preferred: usize, out: &mut [usize; MAX_NUMA_NODES]) -> usize {
    let mut n = 0;
    for i in 0..MAX_NUMA_NODES {
        if i != preferred {
            out[n] = i;
            n += 1;
        }
    }
    // Insertion sort by (distance, index); n <= 15 so this is cheap and
    // avoids any alloc on the hot path.
    for a in 1..n {
        let mut b = a;
        while b > 0 {
            let cur = out[b];
            let prev = out[b - 1];
            let dc = node_distance(preferred, cur);
            let dp = node_distance(preferred, prev);
            if dc < dp || (dc == dp && cur < prev) {
                out.swap(b, b - 1);
                b -= 1;
            } else {
                break;
            }
        }
    }
    n
}

#[inline]
fn phys_to_node(addr: u64) -> usize {
    if let Some(node) = cow::cached_node_for_phys(addr) {
        return node;
    }
    if let Some(node) = hotplug_node_for_phys(addr) {
        return node;
    }
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_phys_to_node(addr) } as usize;
    if n < MAX_NUMA_NODES {
        n
    } else {
        0
    }
}

pub fn node_for_phys(addr: u64) -> usize {
    phys_to_node(addr)
}

/// Register boot-identified RAM independently of allocator donation.
///
/// # Safety
/// Once on the BSP, before `init_from_map`; every supplied range must be
/// known RAM (usable, kernel, ACPI reclaimable or NVS), never a generic
/// Reserved range that could be MMIO. Registration does not free any page.
pub unsafe fn register_boot_ram(regions: &[UsableRegion]) {
    assert!(!ALLOC.initialised.load(Ordering::Acquire));
    assert!(!BOOT_KNOWN_RAM_SET.swap(true, Ordering::AcqRel));
    let mut ranges = BOOT_KNOWN_RAM.lock();
    ranges.extend(regions.iter().filter_map(|region| {
        let start = region.start.raw() & !(PAGE_SIZE - 1);
        let end = region.start.raw().checked_add(region.len)?;
        (start < end).then_some((start, end - start))
    }));
}

#[cfg(feature = "kernel-test")]
pub(crate) fn known_boot_ram_for_test() -> Vec<(u64, u64)> {
    BOOT_KNOWN_RAM.lock().clone()
}

/// Whether the page containing `phys` is known System RAM: usable boot
/// ranges, kernel/ACPI RAM registered by `register_boot_ram`, or any hotplug
/// range ever registered, online or not. An offlined block stays RAM because
/// its direct-map alias outlives the offline. Ambiguous Reserved boot entries
/// are not classified as RAM: they may be device MMIO.
///
/// This is the authority [`crate::memtype`] uses to refuse non-WB user aliases
/// of known RAM. Registry locks are taken separately, with no allocation,
/// so it is callable under a page-table root lock.
pub fn is_system_ram(phys: PhysAddr) -> bool {
    let page = phys.raw() & !(PAGE_SIZE - 1);
    let in_range = |start: u64, len: u64| page >= start && page - start < len;
    if BOOT_KNOWN_RAM
        .lock()
        .iter()
        .any(|&(start, len)| in_range(start, len))
    {
        return true;
    }
    if BOOT_MEMORY_RANGES
        .lock()
        .iter()
        .any(|&(start, len)| in_range(start, len))
    {
        return true;
    }
    HOTPLUG_RANGES
        .lock()
        .iter()
        .any(|range| in_range(range.start, range.len))
}

/// Whether any known System RAM intersects `[start, start + len)`.
/// Large ioremap leaves use this conservative range test so a 2 MiB leaf
/// never changes the cache type of even one RAM page within the leaf.
#[cfg(target_arch = "x86_64")]
pub(crate) fn system_ram_intersects(start: u64, len: u64) -> bool {
    let Some(end) = start.checked_add(len) else {
        return true;
    };
    let overlaps = |range_start: u64, range_len: u64| {
        range_start < end && start < range_start.saturating_add(range_len)
    };
    if BOOT_KNOWN_RAM.lock().iter().any(|&(s, n)| overlaps(s, n))
        || BOOT_MEMORY_RANGES
            .lock()
            .iter()
            .any(|&(s, n)| overlaps(s, n))
    {
        return true;
    }
    HOTPLUG_RANGES
        .lock()
        .iter()
        .any(|r| overlaps(r.start, r.len))
}

pub fn hotplug_node_for_phys(addr: u64) -> Option<usize> {
    HOTPLUG_RANGES
        .lock()
        .iter()
        .find(|range| addr >= range.start && addr < range.start + range.len)
        .map(|range| range.node)
}

/// Inclusive `[lo, hi]` frame-number span containing all of `node`'s managed
/// frames, or `None` if the node has none. This is the physical range the
/// compaction dual-scanner sweeps between.
///
/// The span is an OUTER bound, not an exact membership test: where firmware /
/// hotplug ranges interleave nodes it may include holes or foreign-node frames.
/// Callers step frame-by-frame and re-check [`node_for_phys`] (and free /
/// movable state), so an over-approximate span only costs a few skipped frames.
pub fn node_frame_bounds(node: usize) -> Option<(u64, u64)> {
    // Snapshot the range registries first: `phys_to_node` locks `HOTPLUG_RANGES`,
    // so we must not hold it (or `BOOT_MEMORY_RANGES`) across the sample.
    let boot = BOOT_MEMORY_RANGES.lock().clone();
    let hotplug = HOTPLUG_RANGES.lock().clone();

    let mut lo = u64::MAX;
    let mut hi = 0u64;
    let mut seen = false;
    let mut consider = |start: u64, len: u64| {
        if len == 0 {
            return;
        }
        let end = start.saturating_add(len);
        // SRAT- and hotplug-derived ranges are node-homogeneous; sample the node
        // at the range start rather than per frame.
        if phys_to_node(start) != node {
            return;
        }
        let first = (start + PAGE_SIZE - 1) >> 12; // first fully-contained frame
        let last = (end >> 12).saturating_sub(1); // last fully-contained frame
        if last < first {
            return;
        }
        lo = lo.min(first);
        hi = hi.max(last);
        seen = true;
    };

    for (start, len) in &boot {
        consider(*start, *len);
    }
    for range in &hotplug {
        if range.online {
            consider(range.start, range.len);
        }
    }
    seen.then_some((lo, hi))
}

/// Snapshot Linux-style logical memory blocks from authoritative boot RAM and
/// currently-online hotplug ranges. A block is listed once even when adjacent
/// firmware ranges overlap it.
pub fn memory_blocks() -> Vec<MemoryBlock> {
    let boot = BOOT_MEMORY_RANGES.lock().clone();
    let hotplug = HOTPLUG_RANGES.lock().clone();
    memory_blocks_from_ranges(&boot, &hotplug)
}

fn memory_blocks_from_ranges(boot: &[(u64, u64)], hotplug: &[HotplugRange]) -> Vec<MemoryBlock> {
    let mut ids = Vec::new();
    for &(start, len) in boot {
        let first = start / MEMORY_BLOCK_SIZE;
        let last = start.saturating_add(len).saturating_sub(1) / MEMORY_BLOCK_SIZE;
        for id in first..=last {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    for range in hotplug {
        let first = range.start / MEMORY_BLOCK_SIZE;
        let last = range.start.saturating_add(range.len).saturating_sub(1) / MEMORY_BLOCK_SIZE;
        for id in first..=last {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.into_iter()
        .map(|id| {
            let start = id * MEMORY_BLOCK_SIZE;
            let sample = boot
                .iter()
                .filter_map(|&(base, len)| {
                    (start < base + len && base < start + MEMORY_BLOCK_SIZE)
                        .then_some(start.max(base))
                })
                .chain(hotplug.iter().filter_map(|range| {
                    (start < range.start + range.len && range.start < start + MEMORY_BLOCK_SIZE)
                        .then_some(start.max(range.start))
                }))
                .min()
                .unwrap_or(start);
            let node = hotplug
                .iter()
                .find(|range| {
                    start < range.start + range.len && range.start < start + MEMORY_BLOCK_SIZE
                })
                .map(|range| range.node)
                .unwrap_or_else(|| phys_to_node(sample));
            MemoryBlock {
                id,
                start,
                node,
                online: boot
                    .iter()
                    .any(|&(base, len)| start < base + len && base < start + MEMORY_BLOCK_SIZE)
                    || hotplug.iter().any(|range| {
                        range.online
                            && start < range.start + range.len
                            && range.start < start + MEMORY_BLOCK_SIZE
                    }),
            }
        })
        .collect()
}

fn smoke_memory_blocks_persist_offline_topology() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;

    let base = 8 * MEMORY_BLOCK_SIZE;
    let ranges = [
        HotplugRange {
            start: base,
            len: MEMORY_BLOCK_SIZE / 2,
            node: 3,
            online: false,
        },
        HotplugRange {
            start: base + MEMORY_BLOCK_SIZE,
            len: MEMORY_BLOCK_SIZE,
            node: 4,
            online: true,
        },
    ];
    let blocks = memory_blocks_from_ranges(&[], &ranges);
    let offline = blocks.iter().find(|block| block.id == 8);
    let online = blocks.iter().find(|block| block.id == 9);
    if offline.is_none_or(|block| block.online || block.node != 3)
        || online.is_none_or(|block| !block.online || block.node != 4)
    {
        TestResult::Fail("offline identity or live state was not preserved")
    } else {
        TestResult::Pass
    }
}
narf_kernel_test::kernel_test_in!("memory/numa", smoke_memory_blocks_persist_offline_topology);

#[inline]
pub fn current_cpu_node() -> usize {
    let cpu = narf_lib::percpu::current_cpu() as u32;
    // SAFETY: narf-frame provides the `#[no_mangle]` definition.
    let n = unsafe { narf_cpu_to_node(cpu) } as usize;
    if n < MAX_NUMA_NODES {
        n
    } else {
        0
    }
}

/// The NUMA node hosting the current CPU (the "local" node for
/// locality-first allocation). Public wrapper over `current_cpu_node`
/// so the mempolicy + fault paths can resolve their `local` argument.
#[inline]
pub fn local_node() -> usize {
    current_cpu_node()
}

// ── Pluggable FrameAlloc framework ─────────────────────────────────
//
// Wave-A of the pluggable-policy pass. Mirrors `power::install_governor`
// (`power/src/lib.rs::538`) shape-for-shape, with one principled
// deviation: the frame allocator lives *below* the heap on some
// boot paths (the bootstrap-bump arena is in `.bss`, but a future
// no-bootstrap-heap build would init frames before `Box`). The slot
// therefore stores a `&'static dyn FrameAlloc` rather than a
// `Box<dyn FrameAlloc>`. Installation is cap-gated on
// `Cap<MemAlloc, Grant>`.

/// A pluggable frame allocator. Owns the single-frame allocation
/// surface; multi-frame buddy ops (`alloc_pages_on`, `free_pages`)
/// stay on the concrete buddy and are not part of the trait.
pub trait FrameAlloc: Send + Sync {
    /// Stable identifier (e.g. `"buddy"`, `"bump"`).
    fn name(&self) -> &'static str;
    /// Allocate one 4 KiB frame, preferring `node`'s zone.
    fn alloc_frame_on(&self, node: usize) -> Result<PhysFrame, FrameAllocError>;
    /// Allocate one 4 KiB frame from any node.
    fn alloc_frame_anywhere(&self) -> Result<PhysFrame, FrameAllocError>;
    /// Return a frame to the pool. Impls that don't support freeing
    /// (e.g. `BumpFrameAlloc`) may treat this as a no-op.
    fn free_frame(&self, frame: PhysFrame);
    /// Return multiple independently owned base frames. The default preserves
    /// compatibility for simple allocators; implementations may coalesce
    /// metadata locking while retaining scalar ownership semantics.
    fn free_frame_batch(&self, frames: &[PhysFrame]) {
        for frame in frames {
            self.free_frame(*frame);
        }
    }
    /// Return frames for which the caller has already proved unique ownership.
    /// Simple allocators retain their ordinary batch semantics; allocators with
    /// separate shared-owner metadata may bypass those lookups.
    ///
    /// # Safety
    /// Every frame must be exclusively owned by the caller and absent from any
    /// allocator-specific shared-owner registry.
    unsafe fn free_unique_frame_batch(&self, frames: &[PhysFrame]) {
        self.free_frame_batch(frames);
    }
    /// Snapshot of allocator usage.
    fn stats(&self) -> FrameStats;
}

/// Cap-marker for `install_frame_alloc`. The runtime kind variant
/// is reserved at `CapKind::MemAlloc = 0x0200` (see Wave 0).
#[derive(Copy, Clone, Debug)]
pub struct MemAlloc;
impl CapType for MemAlloc {
    const KIND: CapKind = CapKind::MemAlloc;
}

/// The default, today's per-NUMA buddy allocator wrapped behind the
/// `FrameAlloc` seam. Zero-sized: the actual state lives in the
/// module-private cache-line-aligned per-zone `BuddyZone` locks.
#[derive(Copy, Clone, Debug, Default)]
pub struct BuddyFrameAlloc;

impl FrameAlloc for BuddyFrameAlloc {
    fn name(&self) -> &'static str {
        "buddy"
    }
    fn alloc_frame_on(&self, node: usize) -> Result<PhysFrame, FrameAllocError> {
        buddy_alloc_frame_on(node)
    }
    fn alloc_frame_anywhere(&self) -> Result<PhysFrame, FrameAllocError> {
        buddy_alloc_frame_anywhere()
    }
    fn free_frame(&self, frame: PhysFrame) {
        buddy_free_frame(frame);
    }
    fn free_frame_batch(&self, frames: &[PhysFrame]) {
        buddy_free_frame_batch(frames);
    }
    unsafe fn free_unique_frame_batch(&self, frames: &[PhysFrame]) {
        for frame in frames {
            buddy_return_unreferenced_frame(*frame);
        }
    }
    fn stats(&self) -> FrameStats {
        buddy_stats()
    }
}

/// The shipped `FrameAlloc` default. Installed by
/// `install_frame_alloc_default` during `init_from_map`.
pub static BUDDY_FRAME_ALLOC: BuddyFrameAlloc = BuddyFrameAlloc;

/// Linear-cursor frame allocator over a pre-reserved region. Useful
/// for early-boot diagnostics and as the seam-exercising alternative
/// to `BuddyFrameAlloc`. `free_frame` is unsupported; the cursor
/// advances and never rewinds.
#[derive(Debug)]
pub struct BumpFrameAlloc {
    start: u64,
    end: u64,
    next: AtomicU64,
}

impl BumpFrameAlloc {
    /// Const-construct a bump allocator over `[start, end)`. The
    /// caller is responsible for ensuring the region is genuinely
    /// reserved (e.g. excluded from the buddy donation list) — this
    /// type performs no overlap check with the buddy zones.
    pub const fn new_const(start: PhysAddr, end: PhysAddr) -> Self {
        Self {
            start: start.raw(),
            end: end.raw(),
            next: AtomicU64::new(start.raw()),
        }
    }

    /// Total bytes managed by this bump (`end - start`).
    pub const fn capacity_bytes(&self) -> u64 {
        self.end - self.start
    }

    /// Reset the cursor to `start`. Test/diagnostic hook — there's
    /// no safe way to reset a bump allocator whose frames are still
    /// referenced, so callers must guarantee no live frames exist.
    #[doc(hidden)]
    pub fn __test_reset(&self) {
        self.next.store(self.start, Ordering::SeqCst);
    }
}

impl FrameAlloc for BumpFrameAlloc {
    fn name(&self) -> &'static str {
        "bump"
    }
    fn alloc_frame_on(&self, _node: usize) -> Result<PhysFrame, FrameAllocError> {
        self.alloc_frame_anywhere()
    }
    fn alloc_frame_anywhere(&self) -> Result<PhysFrame, FrameAllocError> {
        // Bump cursor by PAGE_SIZE, fail when we'd cross `end`.
        let mut cur = self.next.load(Ordering::Acquire);
        loop {
            if cur >= self.end || self.end - cur < PAGE_SIZE {
                return Err(FrameAllocError::Exhausted);
            }
            let next = cur + PAGE_SIZE;
            match self
                .next
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(PhysFrame::new(PhysAddr::new(cur))),
                Err(observed) => cur = observed,
            }
        }
    }
    fn free_frame(&self, _frame: PhysFrame) {
        // Bump allocators don't free. No-op; explicit-failure callers
        // should use a typed wrapper that returns `NotSupported`.
    }
    fn stats(&self) -> FrameStats {
        let used = self.next.load(Ordering::Acquire).saturating_sub(self.start);
        let total = (self.end - self.start) / PAGE_SIZE;
        let used_frames = used / PAGE_SIZE;
        FrameStats {
            total: total as usize,
            free: (total - used_frames) as usize,
            reserved: 0,
        }
    }
}

// `&'static dyn FrameAlloc` is a fat pointer (data + vtable), so an AtomicPtr
// cannot publish an arbitrary implementation. Keep the authoritative object
// behind the lock, but bypass that globally shared cache line for the shipped
// buddy: its static identity needs no pointer load. Custom implementations are
// deliberately cold and retain the locked fallback.
static FRAME_ALLOC_SLOT: IrqSafeSpinLock<Option<&'static dyn FrameAlloc>> =
    IrqSafeSpinLock::new(None);

const FRAME_ALLOC_NONE: u8 = 0;
const FRAME_ALLOC_BUDDY: u8 = 1;
const FRAME_ALLOC_CUSTOM: u8 = 2;
static FRAME_ALLOC_KIND: AtomicU8 = AtomicU8::new(FRAME_ALLOC_NONE);

#[inline]
fn is_default_buddy(alloc: &'static dyn FrameAlloc) -> bool {
    core::ptr::eq(alloc, &BUDDY_FRAME_ALLOC as &dyn FrameAlloc)
}

/// Install a `FrameAlloc` impl. Cap-gated on `Cap<MemAlloc, Grant>`.
/// The previous installed allocator is replaced; callers are
/// responsible for ensuring no frames allocated under the old impl
/// will be freed under the new one (the buddy and the bump don't
/// share a free-list).
pub fn install_frame_alloc(
    cap: &Cap<MemAlloc, Grant>,
    alloc: &'static dyn FrameAlloc,
) -> Result<(), FrameAllocError> {
    cap.check_live()?;
    let mut slot = FRAME_ALLOC_SLOT.lock();
    if is_default_buddy(alloc) {
        *slot = Some(alloc);
        // Publish the lock-free identity only after the authoritative slot.
        FRAME_ALLOC_KIND.store(FRAME_ALLOC_BUDDY, Ordering::Release);
    } else {
        // Divert new readers through the lock before changing the fat pointer.
        // A reader that observed BUDDY earlier linearizes before this install;
        // a reader that observes CUSTOM waits for `slot` and sees `alloc`.
        FRAME_ALLOC_KIND.store(FRAME_ALLOC_CUSTOM, Ordering::Release);
        *slot = Some(alloc);
    }
    Ok(())
}

/// Internal: install `BUDDY_FRAME_ALLOC` without a cap check. Called
/// once at the end of `init_from_map` to plant the default before
/// any allocation. There is no public uncap'd install.
fn install_frame_alloc_default() {
    let mut slot = FRAME_ALLOC_SLOT.lock();
    if slot.is_none() {
        *slot = Some(&BUDDY_FRAME_ALLOC);
        FRAME_ALLOC_KIND.store(FRAME_ALLOC_BUDDY, Ordering::Release);
    }
}

/// Snapshot the active `FrameAlloc`'s `name()`. Returns `"none"`
/// when no allocator has been installed yet (`init_from_map`
/// hasn't run).
pub fn current_frame_alloc_name() -> &'static str {
    current_alloc().map(|a| a.name()).unwrap_or("none")
}

/// Snapshot the currently-installed `FrameAlloc`. Returns `None`
/// pre-init.
#[inline]
fn current_alloc() -> Option<&'static dyn FrameAlloc> {
    match FRAME_ALLOC_KIND.load(Ordering::Acquire) {
        FRAME_ALLOC_BUDDY => Some(&BUDDY_FRAME_ALLOC),
        FRAME_ALLOC_CUSTOM => *FRAME_ALLOC_SLOT.lock(),
        FRAME_ALLOC_NONE => None,
        _ => unreachable!("invalid frame allocator kind"),
    }
}

/// Dispatch helper: thread the installed allocator into `f` or
/// return `Uninitialised` if none is live.
#[inline]
fn with_installed<R, F>(f: F) -> Result<R, FrameAllocError>
where
    F: FnOnce(&'static dyn FrameAlloc) -> Result<R, FrameAllocError>,
{
    match current_alloc() {
        Some(a) => f(a),
        None => Err(FrameAllocError::Uninitialised),
    }
}
