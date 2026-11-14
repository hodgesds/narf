//! Where a card's GPU buffer memory is, and who holds it.
//!
//! Linux answers this in three places, all read-only walks of TTM's state:
//! `mem_info_*` under the PCI device (amdgpu_vram_mgr.c, amdgpu_gtt_mgr.c),
//! `/proc/<pid>/fdinfo/<fd>` (drm_show_fdinfo, amdgpu_show_fdinfo), and the
//! kernel log when an allocation fails. Nothing here runs on an allocation
//! or submission path: the hot paths keep only what they already had (the
//! pools' own ranges, `GTT_USED`, each buffer's pin count) plus the
//! process id an open's handle insertion records; every figure below is
//! computed by walking the card's buffers when someone asks.
use super::*;
use alloc::string::String;
use core::fmt::Write;

/// The open a handle table belongs to: `struct drm_file`'s identity.
#[derive(Debug)]
pub(crate) struct Client {
    /// `drm-client-id`: unique per open, never reused.
    id: u64,
    /// The process last seen putting a buffer in the table
    /// (drm_file_update_pid: an fd handed to another process — logind's
    /// TakeDevice — is that process's from then on). 0: not known.
    pid: AtomicU64,
}
static NEXT_CLIENT: AtomicU64 = AtomicU64::new(1);
impl Client {
    pub(super) fn new() -> Self {
        Self {
            id: NEXT_CLIENT.fetch_add(1, Ordering::Relaxed),
            pid: AtomicU64::new(0),
        }
    }
    /// Record the calling process as the open's user.
    pub(super) fn touch(&self) {
        let pid = narf_filesystem::procfs::current_process_id();
        if pid != 0 {
            self.pid.store(pid, Ordering::Relaxed);
        }
    }
    pub(crate) fn id(&self) -> u64 {
        self.id
    }
    pub(crate) fn pid(&self) -> u64 {
        self.pid.load(Ordering::Relaxed)
    }
}

/// What one open's handle table holds, each buffer once, in bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OpenUsage {
    pub client: u64,
    pub pid: u64,
    /// Resident in VRAM (visible or past the BAR).
    pub vram: u64,
    /// Resident in system pages: GTT buffers, and VRAM-preferred ones that
    /// fell back or were evicted. The frames this open keeps out of the
    /// page allocator.
    pub system: u64,
    /// User pages (GEM_USERPTR) and imported foreign pages: pinned or
    /// leased, not allocated here.
    pub borrowed: u64,
    /// Asked for VRAM, resident elsewhere (amd-evicted-vram).
    pub evicted: u64,
    /// Preferred domains include VRAM / only GTT or CPU.
    pub requested_vram: u64,
    pub requested_gtt: u64,
    pub buffers: usize,
}

/// Test probe run between a walk's snapshot of an open's handles and its
/// accounting of them.
#[cfg(feature = "kernel-test")]
pub(crate) static WALK_PROBE: IrqSafeSpinLock<Option<Arc<dyn Fn() + Send + Sync>>> =
    IrqSafeSpinLock::new(None);

/// One open's usage. The open's handle table is locked only for
/// `table_objects`' snapshot; everything counted here is counted with it
/// free, so a reader of fdinfo or a failure report never holds up the
/// open's own handle lookups.
fn open_usage(table: &Arc<GemTable>) -> OpenUsage {
    let objects = table_objects(core::slice::from_ref(table));
    #[cfg(feature = "kernel-test")]
    {
        let probe = WALK_PROBE.lock().clone();
        if let Some(probe) = probe {
            probe();
        }
    }
    let mut usage = OpenUsage {
        client: table.client.id(),
        pid: table.client.pid(),
        buffers: objects.len(),
        ..Default::default()
    };
    let vram = u64::from(uapi::AMDGPU_GEM_DOMAIN_VRAM);
    for object in &objects {
        let (system, borrowed) = object.peek(|p| {
            (
                p.system,
                matches!(p.backing, Backing::User(_) | Backing::Foreign { .. }),
            )
        });
        let wants_vram = object.preferred_domains() & vram != 0;
        if wants_vram {
            usage.requested_vram += object.byte_len;
        } else {
            usage.requested_gtt += object.byte_len;
        }
        if borrowed {
            usage.borrowed += object.byte_len;
        } else if system {
            usage.system += object.byte_len;
            if wants_vram {
                usage.evicted += object.byte_len;
            }
        } else {
            usage.vram += object.byte_len;
        }
    }
    usage
}

/// Every open of `card` that holds a handle table, largest holder first.
pub(crate) fn opens(card: u32) -> Vec<OpenUsage> {
    let tables: Vec<Arc<GemTable>> = GEM_TABLES
        .lock()
        .iter()
        .filter(|(c, _)| *c == card)
        .filter_map(|(_, table)| table.upgrade())
        .collect();
    let mut opens: Vec<OpenUsage> = tables.iter().map(open_usage).collect();
    opens.sort_by_key(|o| core::cmp::Reverse(o.vram + o.system));
    opens
}

/// A card's GPU memory at one instant, in bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CardUsage {
    /// The CPU-visible client heap: size, used, largest free range.
    pub visible: (u64, u64, u64),
    /// The heap past the BAR: size, used.
    pub hidden: (u64, u64),
    /// System pages GEM buffers hold (all cards share the budget): limit,
    /// used.
    pub system: (u64, u64),
    /// Live buffers created on the card.
    pub buffers: usize,
    /// VRAM held by scanout pins (amdgpu_bo_pin): bytes, buffers.
    pub pinned: (u64, usize),
    /// VRAM an allocation could reclaim: unpinned buffers allowed to live
    /// in system memory.
    pub evictable: u64,
}

pub(crate) fn card_usage(card: u32) -> CardUsage {
    let heap = vram_heap(card);
    let objects = card_objects(card);
    let mut usage = CardUsage {
        visible: heap.as_ref().map_or((0, 0, 0), |h| {
            let size = h.pool.size();
            (size, size - h.pool.available(), h.pool.largest_free())
        }),
        hidden: heap
            .as_ref()
            .and_then(|h| h.unmapped.as_ref())
            .map_or((0, 0), |u| {
                (u.pool.size(), u.pool.size() - u.pool.available())
            }),
        system: (gtt_limit(), gtt_used()),
        buffers: objects.len(),
        ..Default::default()
    };
    for object in &objects {
        if object.system() {
            continue;
        }
        if object.pinned() {
            usage.pinned.0 += object.byte_len;
            usage.pinned.1 += 1;
        } else if object.allows_system() && !moves_by_engine(object) {
            usage.evictable += object.byte_len;
        }
    }
    usage
}

/// `amdgpu_vram_mgr`'s and `amdgpu_gtt_mgr`'s sysfs attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemInfo {
    VramTotal,
    VramUsed,
    VisVramTotal,
    VisVramUsed,
    GttTotal,
    GttUsed,
}
impl MemInfo {
    pub const ALL: [(Self, &'static str); 6] = [
        (Self::VramTotal, "mem_info_vram_total"),
        (Self::VramUsed, "mem_info_vram_used"),
        (Self::VisVramTotal, "mem_info_vis_vram_total"),
        (Self::VisVramUsed, "mem_info_vis_vram_used"),
        (Self::GttTotal, "mem_info_gtt_total"),
        (Self::GttUsed, "mem_info_gtt_used"),
    ];
}

/// One `mem_info_*` value in bytes for DRM card `card`. The totals are the
/// VRAM clients can be given (the card's client heap: the driver's own
/// VRAM is not in it, where Linux counts its kernel buffers as used), so
/// `total - used` is what an allocation can still get; 0 while the card
/// has no heap.
pub fn mem_info(card: u32, which: MemInfo) -> u64 {
    let heap = vram_heap_usage(card);
    let (visible, hidden) = heap.map_or(((0, 0), (0, 0)), |h| (h.visible, h.unmapped));
    match which {
        MemInfo::VramTotal => visible.0 + hidden.0,
        MemInfo::VramUsed => visible.1 + hidden.1,
        MemInfo::VisVramTotal => visible.0,
        MemInfo::VisVramUsed => visible.1,
        MemInfo::GttTotal => gtt_limit(),
        MemInfo::GttUsed => gtt_used(),
    }
}

/// `/proc/<pid>/fdinfo/<fd>` of the open owning `state`
/// (drm-usage-stats.rst): drm_show_fdinfo's `drm-driver`, `drm-client-id`
/// and `drm-pdev` (`pdev` is the card's PCI address, where it has one),
/// then amdgpu_show_fdinfo's memory keys. `drm-memory-gtt` is the system
/// pages the open's buffers hold.
pub(crate) fn fdinfo(state: &GemState, pdev: Option<&str>, out: &mut String) {
    let usage = open_usage(&state.table());
    let kib = |bytes: u64| bytes / 1024;
    let _ = writeln!(out, "drm-driver:\tamdgpu");
    let _ = writeln!(out, "drm-client-id:\t{}", usage.client);
    if let Some(pdev) = pdev {
        let _ = writeln!(out, "drm-pdev:\t{pdev}");
    }
    for (region, bytes) in [("vram", usage.vram), ("gtt", usage.system)] {
        let _ = writeln!(out, "drm-total-{region}:\t{} KiB", kib(bytes));
        let _ = writeln!(out, "drm-resident-{region}:\t{} KiB", kib(bytes));
    }
    // Legacy amdgpu keys, alias to drm-resident-memory-.
    let _ = writeln!(out, "drm-memory-vram:\t{} KiB", kib(usage.vram));
    let _ = writeln!(out, "drm-memory-gtt: \t{} KiB", kib(usage.system));
    let _ = writeln!(out, "drm-memory-cpu: \t0 KiB");
    let _ = writeln!(out, "amd-evicted-vram:\t{} KiB", kib(usage.evicted));
    let _ = writeln!(
        out,
        "amd-requested-vram:\t{} KiB",
        kib(usage.requested_vram)
    );
    let _ = writeln!(out, "amd-requested-gtt:\t{} KiB", kib(usage.requested_gtt));
}

/// The framebuffers DRM card `card` holds: all, and those a file closed
/// while a plane still shows them. None when the card's KMS state is busy
/// (the report never waits for it).
fn framebuffers(card: u32) -> Option<(usize, usize)> {
    let mode = crate::drm_registry::mode_state(card)?;
    let card = mode.try_lock()?;
    let closed = card
        .framebuffers
        .iter()
        .filter(|fb| fb.owner() == Some(crate::drm::card::CLOSED_FB_OWNER))
        .count();
    Some((card.framebuffers.len(), closed))
}

/// The state report of a failed allocation: what was asked, the heap, the
/// system-page budget and the page allocator behind it, and the largest
/// holders. Sizes in KiB. `count` is which failure of the card this is and
/// how many since the last report were not reported.
pub(crate) fn failure_report(
    card: u32,
    what: &str,
    bytes: u64,
    domains: u64,
    flags: u64,
    error: FsError,
    count: (u64, u64),
) -> String {
    let (nth, earlier) = count;
    let kib = |bytes: u64| bytes / 1024;
    let pid = narf_filesystem::procfs::current_process_id();
    let name =
        |pid: u64| narf_filesystem::procfs::process_comm(pid).unwrap_or_else(|| String::from("?"));
    let usage = card_usage(card);
    let frames = narf_memory::frame::stats();
    let mut out = String::new();
    let _ = write!(
        out,
        "amdgpu: gem: card{card} {what} of {} KiB (domains {domains:#x} flags {flags:#x}) failed {error:?} for pid {pid} ({}); failure {nth} on this card",
        kib(bytes),
        name(pid),
    );
    if earlier != 0 {
        let _ = write!(out, ", {earlier} since the last report not reported");
    }
    let _ = write!(
        out,
        "\namdgpu: gem: card{card} vram {} KiB: used {} free {} largest-free {} pinned {} ({} buffers) evictable {}; past-BAR {} KiB used {}; system pages {} KiB of {} allowed; RAM free {} KiB of {}; {} buffers",
        kib(usage.visible.0),
        kib(usage.visible.1),
        kib(usage.visible.0 - usage.visible.1),
        kib(usage.visible.2),
        kib(usage.pinned.0),
        usage.pinned.1,
        kib(usage.evictable),
        kib(usage.hidden.0),
        kib(usage.hidden.1),
        kib(usage.system.1),
        kib(usage.system.0),
        frames.free as u64 * 4,
        frames.total as u64 * 4,
        usage.buffers,
    );
    match framebuffers(card) {
        Some((all, closed)) => {
            let _ = write!(out, ", {all} framebuffers ({closed} closed, still shown)");
        }
        None => {
            let _ = write!(out, ", framebuffers busy");
        }
    }
    let _ = write!(out, "\namdgpu: gem: card{card} opens:");
    for open in opens(card).iter().take(TOP_OPENS) {
        let _ = write!(
            out,
            " [client {} pid {} ({}) vram {} KiB system {} KiB borrowed {} KiB, {} buffers]",
            open.client,
            open.pid,
            name(open.pid),
            kib(open.vram),
            kib(open.system),
            kib(open.borrowed),
            open.buffers,
        );
    }
    out
}

/// How many opens a failure report names.
const TOP_OPENS: usize = 5;
/// At most one failure report per card in this long.
const REPORT_INTERVAL_NS: u64 = 5_000_000_000;

#[derive(Debug, Default)]
pub(super) struct Failures {
    /// Failures since the card registered.
    total: AtomicU64,
    /// monotonic_ns of the last report (0: none yet).
    reported_ns: AtomicU64,
    /// Failures since the last report.
    unreported: AtomicU64,
}

/// Failure reports made while the card's placement gate was held.
#[cfg(feature = "kernel-test")]
pub(crate) static REPORTS_UNDER_GATE: AtomicU64 = AtomicU64::new(0);

/// A GEM allocation or placement for DRM card `card` failed for lack of
/// memory: count it, and log the state report unless one was logged within
/// `REPORT_INTERVAL_NS` (the next report says how many it stood for). Only
/// ever called on a failure. Any other error is the caller's own.
///
/// Callers release the card's placement gate first: the report walks every
/// buffer and open of the card, resolves process names and writes the log,
/// and every job, VA edit and commit of the card waits on that gate —
/// most of all when VRAM is exhausted, which is when this runs.
pub(crate) fn note_failure(
    card: Option<u32>,
    what: &str,
    bytes: u64,
    domains: u64,
    flags: u64,
    error: FsError,
) {
    if !matches!(error, FsError::NoSpace | FsError::OutOfMemory) {
        return;
    }
    let Some(card) = card else {
        return;
    };
    let Some(stats) = stats::for_card(Some(card)) else {
        return;
    };
    #[cfg(feature = "kernel-test")]
    if try_placement(card).is_none() {
        REPORTS_UNDER_GATE.fetch_add(1, Ordering::Relaxed);
    }
    let failures = stats.failures();
    let nth = failures.total.fetch_add(1, Ordering::Relaxed) + 1;
    let now = narf_time::monotonic_ns().max(1);
    let last = failures.reported_ns.load(Ordering::Acquire);
    if (last != 0 && now.saturating_sub(last) < REPORT_INTERVAL_NS)
        || failures
            .reported_ns
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        failures.unreported.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let earlier = failures.unreported.swap(0, Ordering::AcqRel);
    let report = failure_report(card, what, bytes, domains, flags, error, (nth, earlier));
    let _ = writeln!(narf_console::Writer, "{report}");
}

/// VRAM pressure (or suspend) moved a buffer of `card` out of the heap for
/// the first time: say so once, so a log shows when a card started
/// evicting. AMDGPU_INFO_NUM_EVICTIONS and NUM_BYTES_MOVED count the rest.
pub(super) fn note_first_eviction(card: Option<u32>, bytes: u64) {
    let Some(card) = card else {
        return;
    };
    let (size, used) = vram_heap_usage(card).map_or((0, 0), |h| h.visible);
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: gem: card{card} first eviction: a {} KiB buffer left VRAM for system pages (heap {} of {} KiB used after it)",
        bytes / 1024,
        used / 1024,
        size / 1024,
    );
}

/// GEM allocation failures on DRM card `card` since it registered.
#[cfg(feature = "kernel-test")]
pub(crate) fn failures(card: u32) -> u64 {
    stats::for_card(Some(card)).map_or(0, |s| s.failures().total.load(Ordering::Relaxed))
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_gem_accounting_tests.rs"]
mod tests;
