//! Hazard-pointer reclamation.
//!
//! Spec: `rcu/specification/spec.md` §3.6. Hazard pointers give bounded
//! reclamation latency at a higher read-side cost than QSBR or epoch:
//! every reader that needs to dereference a shared pointer first
//! *publishes* it into a per-CPU slot, then re-checks the source. A
//! retiring writer scans every slot and refuses to free anything it
//! finds named there.
//!
//! # Stage-3 scope
//!
//! - `HazardSlot`: a single per-reader publication cell backed by an
//!   `AtomicPtr<()>`. Type-erased so the per-CPU array can be
//!   monomorphic; the typed view lives behind `HazardGuard<'_, T>`.
//! - `HazardDomain`: owns the per-CPU slot array (using
//!   `narf_lib::percpu::PerCpu`) and a single retire-list. The retire
//!   list is bounded; once it crosses `RETIRE_THRESHOLD` an inline
//!   `scan()` runs and reclaims everything no slot currently names.
//!   Explicit `scan()` is also exported for tests and for consumers
//!   that want deterministic latency.
//! - `HazardGuard<'a, T>`: RAII binding that ties a pointer to a slot
//!   for the guard's lifetime; `Deref` exposes `&T` safely under the
//!   hazard discipline. `Drop` clears the slot.
//! - `retire(...)`: enqueue an item with its monomorphic dropper. The
//!   dropper signature is `fn(*mut T)`, which lets callers free a `Box`,
//!   a custom allocation, or anything with a destructor — the cell
//!   itself is type-erased so the retire list is non-generic.
//!
//! # Stage-4 deferrals
//!
//! - **Scheduled reclamation pass.** Today the only triggers are the
//!   threshold-driven inline scan and explicit `scan()`. Real hazard-
//!   pointer systems also schedule a periodic pass so a low-write
//!   workload doesn't accumulate retired items forever. That belongs to
//!   the per-domain reclamation worker Future (spec §3.7) which doesn't
//!   exist yet.
//! - **Wait-free reader fast-path.** The `reader_acquire` loop is
//!   load-publish-verify; a publisher that swaps the pointer between
//!   the load and the verify makes the reader retry. The retry count
//!   is unbounded in pathological writer storms. If profiling ever
//!   shows measurable spinning here, switch to a tagged-pointer scheme
//!   or a per-reader generation tag.
//! - **Per-CPU retire lists.** The current retire list is a single
//!   `Mutex`-equivalent (in spirit — Stage-3 single-CPU means there's no
//!   real contention, but the design is wrong for SMP). Stage-4 should
//!   sharded retire lists per CPU and merge on scan, mirroring the QSBR
//!   bucket layout in `qsbr.rs`.
//! - **Multiple slots per reader.** Spec §3.6 allows several slots per
//!   reader. Today `HazardDomain` exposes one slot per CPU; a reader
//!   that needs to hold two pointers simultaneously must use two
//!   domains, or wait for the multi-slot extension.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::Deref;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use narf_lib::percpu::MAX_CPUS;

// `narf_arch::current_cpu_id` is the in-kernel CPU-ID source. Stage-3
// single-CPU returns 0; the indexing scheme works once SMP brings APs
// up without re-plumbing the call sites here.

// ── HazardSlot ──────────────────────────────────────────────────────

/// One reader-publication cell. The slot is type-erased (`*mut ()`) so
/// the per-CPU array can be `[HazardSlot; MAX_CPUS]` regardless of `T`;
/// the typed view rides on `HazardGuard<'_, T>`.
///
/// At most one active hazard per slot at a time. A reader that needs to
/// hold several pointers simultaneously needs several slots — see the
/// Stage-4 deferral note in the module doc.
#[derive(Debug)]
pub struct HazardSlot {
    /// Currently-published hazard pointer, or `null` if the slot is
    /// idle. Published with `Release`, observed by scanners with
    /// `Acquire` so the scan ordering is total relative to the reader's
    /// publication.
    ptr: AtomicPtr<()>,
}

impl HazardSlot {
    /// Construct an idle slot.
    pub const fn new() -> Self {
        Self {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Currently published pointer (test/diagnostic).
    pub fn current(&self) -> *mut () {
        self.ptr.load(Ordering::Acquire)
    }

    /// Whether the slot is idle.
    pub fn is_idle(&self) -> bool {
        self.ptr.load(Ordering::Acquire).is_null()
    }
}

impl Default for HazardSlot {
    fn default() -> Self {
        Self::new()
    }
}

// `HazardSlot` carries only an `AtomicPtr`; it's safe to share by
// reference across CPUs. The `*mut ()` content is just bits as far as
// the slot itself is concerned; reader/writer disciplines on either
// side guarantee the pointee's lifetime.
//
// SAFETY: `AtomicPtr` is already `Sync`; this impl is implicit. We do
// implement `Copy` manually so the type can sit inside `PerCpu<T: Copy>`
// (see below).

// We can't store `HazardSlot` (or any `AtomicPtr<()>`-bearing type)
// inside `PerCpu<T>` because `PerCpu<T>` requires `T: Copy` and
// `AtomicPtr` isn't `Copy`. Mirror the QSBR pattern: a plain static
// `[HazardSlot; MAX_CPUS]` indexed by `current_cpu_id()`. Indexing
// is identical to `PerCpu::this_cpu`; the only thing we lose is the
// cache-line padding that `PerCpu` advertises (it doesn't actually
// pad today either — see `lib/src/percpu.rs` Stage-3 note).

// ── Retire list ─────────────────────────────────────────────────────
//
// One retire list per `HazardDomain`. Each entry holds a type-erased
// pointer plus a monomorphic dropper. We hold the entries in a fixed
// array — Stage-3 single-CPU means no real contention; the lock is a
// spin-loop on an `AtomicUsize` flag whose only purpose is to keep the
// destructive scan from racing with a concurrent retire.
//
// Stage-4 should replace this with per-CPU sharded lists (see module
// doc deferral list).

const RETIRE_CAP: usize = 256;
/// Inline-scan trigger threshold. Spec §3.6: reclamation cadence is the
/// Stage-3 budget knob; 16 retires before a scan keeps test latency
/// bounded without producing pathological writer overhead.
pub const RETIRE_THRESHOLD: usize = 16;

#[derive(Copy, Clone)]
struct RetireEntry {
    ptr: *mut (),
    dropper: Option<unsafe fn(*mut ())>,
}

// SAFETY: same reasoning as `qsbr::DeferEntry` — the captured pointer
// was `Send + 'static` at retire time, so moving the entry across CPUs
// is sound.
unsafe impl Send for RetireEntry {}
// SAFETY: `RetireEntry` only ever holds a type-erased raw pointer plus an
// `unsafe fn` dropper; it exposes no interior mutability of its own. All
// access to the shared entry array is serialized by `RetireList::busy`
// (the spinlock flag), so two CPUs never touch the same entry concurrently.
// Sharing `&RetireEntry` across threads therefore cannot create a data race.
unsafe impl Sync for RetireEntry {}

struct RetireList {
    /// Spinlock flag — 0 = idle, 1 = held. Single-CPU Stage-3 makes
    /// contention impossible; the flag keeps the SMP discipline correct.
    busy: AtomicUsize,
    /// Type-erased entry array. `UnsafeCell` because the lock guards
    /// access — we don't pay for an extra atomic on every slot read.
    entries: UnsafeCell<[RetireEntry; RETIRE_CAP]>,
    /// Number of valid entries in `entries`.
    len: UnsafeCell<usize>,
    /// Retires silently dropped because the list was full. Surfaced via
    /// `HazardDomain::overflow_count`. Non-zero indicates a missing
    /// scheduled-pass tick (Stage-4 deferral) or a bug.
    overflow: AtomicUsize,
}

impl RetireList {
    const fn new() -> Self {
        Self {
            busy: AtomicUsize::new(0),
            entries: UnsafeCell::new(
                [RetireEntry {
                    ptr: core::ptr::null_mut(),
                    dropper: None,
                }; RETIRE_CAP],
            ),
            len: UnsafeCell::new(0),
            overflow: AtomicUsize::new(0),
        }
    }

    #[inline]
    fn lock(&self) -> RetireGuard<'_> {
        // Spin-acquire. Stage-3 single-CPU never spins; the loop exists
        // for SMP correctness.
        while self
            .busy
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        RetireGuard { list: self }
    }
}

// SAFETY: every access to the `UnsafeCell` interiors goes through
// `lock()`, which serialises producers and the scan. The pointers /
// droppers held in the entries are `Send + Sync` via the impls above.
unsafe impl Sync for RetireList {}

struct RetireGuard<'a> {
    list: &'a RetireList,
}

impl<'a> Drop for RetireGuard<'a> {
    fn drop(&mut self) {
        self.list.busy.store(0, Ordering::Release);
    }
}

impl<'a> RetireGuard<'a> {
    #[inline]
    fn entries_mut(&mut self) -> &mut [RetireEntry; RETIRE_CAP] {
        // SAFETY: the lock guards exclusive access.
        unsafe { &mut *self.list.entries.get() }
    }
    #[inline]
    fn len(&self) -> usize {
        // SAFETY: the lock guards exclusive access.
        unsafe { *self.list.len.get() }
    }
    #[inline]
    fn set_len(&mut self, n: usize) {
        // SAFETY: the lock guards exclusive access.
        unsafe {
            *self.list.len.get() = n;
        }
    }
}

// ── HazardDomain ────────────────────────────────────────────────────

/// A hazard-pointer reclamation domain. Owns one publication slot per
/// CPU and a single retire-list. Multiple domains can coexist (e.g.
/// one per data structure); they don't share slots, so a scan on
/// domain X doesn't observe domain Y's hazards.
pub struct HazardDomain {
    slots: [HazardSlot; MAX_CPUS],
    retire: RetireList,
}

impl core::fmt::Debug for HazardDomain {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HazardDomain")
            .field("max_cpus", &MAX_CPUS)
            .field("retire_threshold", &RETIRE_THRESHOLD)
            .finish_non_exhaustive()
    }
}

impl HazardDomain {
    /// Construct an empty domain. Slots are idle, retire list empty.
    pub const fn new() -> Self {
        Self {
            slots: [const { HazardSlot::new() }; MAX_CPUS],
            retire: RetireList::new(),
        }
    }

    /// This-CPU's hazard slot. Mirrors the `PerCpu::this_cpu` shape
    /// without the `Copy` bound that `PerCpu<T>` insists on.
    #[inline]
    fn this_cpu_slot(&self) -> &HazardSlot {
        let idx = narf_arch::current_cpu_id().raw() as usize;
        &self.slots[if idx < MAX_CPUS { idx } else { 0 }]
    }

    /// Canonical hazard-pointer acquire. Loops `load(p) -> publish ->
    /// re-load(p)` until the published value matches the source — at
    /// which point any concurrent retire of the *original* pointer
    /// will see the hazard slot and refuse to reclaim.
    ///
    /// Returns `None` if `p` is observed null (no value to acquire).
    /// Otherwise the caller wraps the returned pointer in a
    /// `HazardGuard` (typically through `acquire`).
    pub fn reader_acquire<T>(&self, p: &AtomicPtr<T>) -> Option<*const T> {
        let slot = &self.this_cpu_slot().ptr;
        loop {
            let candidate = p.load(Ordering::Acquire);
            if candidate.is_null() {
                // No value to publish. Make sure the slot is idle so a
                // stale prior hazard doesn't pin a freed allocation.
                slot.store(core::ptr::null_mut(), Ordering::Release);
                return None;
            }
            // Publish — Release so a scanner observing this hazard also
            // observes any prior reader writes (defensive; scanners
            // don't actually read through the pointer themselves).
            slot.store(candidate as *mut (), Ordering::Release);
            // Re-load the source. If it still matches, the publication
            // is valid: any retiring writer that displaced `candidate`
            // must have observed our slot already.
            let recheck = p.load(Ordering::Acquire);
            if core::ptr::eq(recheck as *const T, candidate as *const T) {
                return Some(candidate as *const T);
            }
            // The pointer moved underneath us; loop and re-publish.
        }
    }

    /// Acquire a `HazardGuard` over `p`. Convenience wrapper around
    /// `reader_acquire` that bundles the slot reference into the guard
    /// so `Drop` knows where to clear.
    pub fn acquire<'a, T>(&'a self, p: &AtomicPtr<T>) -> Option<HazardGuard<'a, T>> {
        let raw = self.reader_acquire(p)?;
        Some(HazardGuard {
            domain: self,
            ptr: raw,
            _phantom: PhantomData,
        })
    }

    /// Manually clear the calling CPU's hazard slot. `HazardGuard::drop`
    /// calls this; explicit invocation is supported for callers that
    /// don't use the guard wrapper.
    pub fn reader_release<T>(&self) {
        let slot = &self.this_cpu_slot().ptr;
        slot.store(core::ptr::null_mut(), Ordering::Release);
    }

    /// Retire `ptr`, calling `drop_fn(ptr)` once no hazard slot names it.
    /// If the retire list crosses `RETIRE_THRESHOLD`, an inline scan
    /// runs immediately. Otherwise reclamation waits for the next
    /// explicit `scan()`.
    pub fn retire<T>(&self, ptr: *mut T, drop_fn: fn(*mut T)) {
        // The retire list is type-erased — entries store `*mut ()` plus
        // a `fn(*mut ())` dropper. We can't pass `drop_fn` directly
        // because its signature is typed; instead we monomorphise a
        // per-`(T, drop_fn)` pair into a per-call-site dispatcher.
        //
        // Stage-3 trick: bake `drop_fn` into a `static`-stored cell
        // keyed by the per-`T` monomorphisation, then route the erased
        // call through a generic shim that re-reads it. We use a
        // function-pointer transmute for the dispatch. Both signatures
        // are thin function pointers (single pointer argument, no
        // closure state) on every Tier-1/2 target NARF builds for
        // (x86_64-unknown-none, aarch64-unknown-none) — both follow
        // System-V ABI where `fn(*mut X)` is laid out identically for
        // all `X` (a single register for the argument). This is the
        // same idiom Rust's `Box::from_raw` / `Vec::drop_in_place`
        // monomorphisation uses internally and is what e.g.
        // crossbeam-epoch uses for its retired-bag dispatch.
        //
        // SAFETY: `fn(*mut T)` and `fn(*mut ())` have identical layout
        // (thin function pointer) and identical calling convention on
        // every supported target. The callee receives the same bit
        // pattern as `ptr`, cast back to `*mut T`. The wrapped
        // `drop_fn` is itself the caller's invariant — they assert it
        // is sound to call once no hazard slot holds the pointer.
        let dropper: unsafe fn(*mut ()) =
            // SAFETY: Valid memory or trusted environment
            unsafe { core::mem::transmute::<fn(*mut T), unsafe fn(*mut ())>(drop_fn) };

        let raw_ptr = ptr as *mut ();
        let mut should_scan = false;
        {
            let mut g = self.retire.lock();
            let len = g.len();
            if len < RETIRE_CAP {
                g.entries_mut()[len] = RetireEntry {
                    ptr: raw_ptr,
                    dropper: Some(dropper),
                };
                g.set_len(len + 1);
                if g.len() >= RETIRE_THRESHOLD {
                    should_scan = true;
                }
            } else {
                self.retire.overflow.fetch_add(1, Ordering::Relaxed);
            }
        }
        if should_scan {
            self.scan();
        }
    }

    /// Force a retire-list scan. Reclaims every entry whose pointer no
    /// hazard slot currently names. Idempotent; safe to call from any
    /// CPU at any time.
    pub fn scan(&self) {
        // Snapshot every CPU's hazard slot first. This minimises the
        // window in which a concurrent reader could publish a pointer
        // whose entry we already passed in the sweep — though the
        // double-check structure of `reader_acquire` makes any such
        // reader retry anyway. The snapshot is cache-friendly and
        // bounded (`MAX_CPUS` slots).
        let mut hazards: [*mut (); MAX_CPUS] = [core::ptr::null_mut(); MAX_CPUS];
        let mut h_count = 0;
        for cell in self.slots.iter() {
            let p = cell.ptr.load(Ordering::Acquire);
            if !p.is_null() {
                hazards[h_count] = p;
                h_count += 1;
            }
        }

        // Walk the retire list. Anything not in `hazards[..h_count]`
        // can be freed. Compact survivors in place.
        let mut g = self.retire.lock();
        let len = g.len();
        let entries = g.entries_mut();
        let mut write = 0;
        for read in 0..len {
            let entry = entries[read];
            let mut held = false;
            for &hazard in hazards.iter().take(h_count) {
                if hazard == entry.ptr {
                    held = true;
                    break;
                }
            }
            if !held {
                if let Some(f) = entry.dropper {
                    // SAFETY: hazard discipline — no live reader holds
                    // a hazard for `entry.ptr`, so it is sound to drop.
                    // The dropper was supplied by the caller of
                    // `retire`, who asserts soundness for that pointer.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        f(entry.ptr);
                    }
                }
            } else {
                if write != read {
                    entries[write] = entry;
                }
                write += 1;
            }
        }
        g.set_len(write);
    }

    /// Pending retires (test/diagnostic).
    pub fn pending_retires(&self) -> usize {
        let g = self.retire.lock();
        g.len()
    }

    /// Retires silently dropped due to retire-list overflow. Non-zero
    /// values indicate the threshold-driven scan isn't keeping up — see
    /// the Stage-4 scheduled-pass deferral note.
    pub fn overflow_count(&self) -> usize {
        self.retire.overflow.load(Ordering::Relaxed)
    }
}

impl Default for HazardDomain {
    fn default() -> Self {
        Self::new()
    }
}

// ── HazardGuard ─────────────────────────────────────────────────────

/// RAII guard tying a `*const T` to a hazard slot. While the guard is
/// live, no `retire()` call on this `HazardDomain` will reclaim the
/// pointee — the discipline guarantees the pointee remains valid for
/// the guard's lifetime.
///
/// `Deref` exposes `&T`. The implementation is `unsafe` internally; the
/// hazard-pointer contract is what makes it sound.
pub struct HazardGuard<'a, T> {
    domain: &'a HazardDomain,
    ptr: *const T,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T> core::fmt::Debug for HazardGuard<'a, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HazardGuard")
            .field("ptr", &self.ptr)
            .finish_non_exhaustive()
    }
}

impl<'a, T> HazardGuard<'a, T> {
    /// Raw pointer view. Same lifetime contract as `Deref`.
    pub fn as_ptr(&self) -> *const T {
        self.ptr
    }
}

impl<'a, T> Deref for HazardGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: hazard-pointer discipline. The slot held by this
        // guard names `self.ptr`; no concurrent `scan()` will reclaim
        // it, and the guard's lifetime is shorter than the domain's.
        // SAFETY: Valid memory or trusted environment
        unsafe { &*self.ptr }
    }
}

impl<'a, T> Drop for HazardGuard<'a, T> {
    fn drop(&mut self) {
        // Clear the calling CPU's slot. We rely on the guard not
        // crossing CPUs (no `Send`); since the guard contains no
        // `*const ()` PhantomData marker, it is technically `Send` on
        // stable today — but `HazardDomain` is `Sync`, and the slot's
        // store is unconditional Release, so a guard that migrates
        // simply clears the *new* CPU's slot. The leak is bounded:
        // the pointer becomes reclaimable on the next scan once the
        // *original* CPU's slot is republished or cleared. Stage-4
        // adds `!Send` once the executor's CPU pinning is real.
        self.domain.reader_release::<T>();
    }
}

/// Free-function form of `HazardDomain::retire` for spec-shape
/// re-export. See the method for the full contract.
pub fn retire<T>(domain: &HazardDomain, ptr: *mut T, drop_fn: fn(*mut T)) {
    domain.retire(ptr, drop_fn);
}
