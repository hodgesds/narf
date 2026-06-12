//! Wave-C of the pluggable-policy pass: the `Pager` policy seam.
//!
//! NARF has historically had no swap path. The only way a page leaves
//! a tracked LRU slot is for the owner's `ReclaimFn` to report
//! `Freed` — i.e. the owner itself decided the page was disposable
//! (clean cache page, unreferenced anonymous mapping it can fault
//! back in from a known source, etc.).
//!
//! Wave C does *not* ship a real pager either. What it ships is the
//! **seam**: a `Pager` trait, two implementations (`NoopPager`,
//! `ZpoolPager`), an install function gated on
//! `Cap<PagerAuthority, Grant>`, and a single new
//! `ReclaimOutcome::DeferToPager` variant that lets a reclaim handler
//! say "I can't free this page myself but the kernel may stash it
//! somewhere if it has somewhere to stash it." The reclaim loop in
//! `reclaim.rs` calls `page_out` on the installed pager; the default
//! `NoopPager` always declines (`Err(NoBacking)`), which preserves
//! exactly today's behaviour (no swap).
//!
//! The trait API uses an opaque `SwapSlot(u64)` as the round-trip
//! token. After a successful `page_out`, the *kernel-level* reclaim
//! integration is intentionally minimal for Wave C: the page-out
//! result is logged but the physical frame is not yet freed, and no
//! reverse-mapping side-table is maintained. Full integration with
//! the page-table walker + owner notification is a Wave C+1 follow-up
//! (see TODOs in `reclaim.rs`). The deliverable here is the *seam* —
//! installing a real pager later is a trait swap, not a redesign.
//!
//! # Slot type
//!
//! `Box<dyn Pager>` behind `IrqSafeSpinLock<Option<...>>`, mirroring
//! `power::GOVERNOR`. The pager is consulted from the reclaim path,
//! which already runs without the heap on the critical line — taking
//! one extra uncontended spinlock per *deferred* page is well under
//! the noise floor, and the swap-time `Box` allocation only happens
//! at `install_pager` time (cold path).
//!
//! # Cap kind
//!
//! Reserved at `CapKind::Pager = 0x0202` (Wave 0). The cap marker is
//! `PagerAuthority` to avoid colliding with the `Pager` trait name.

extern crate alloc as alloc_crate;

use alloc_crate::boxed::Box;
use core::fmt;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::reclaim::PageFlags;
use crate::PhysAddr;

/// Stable opaque handle to a page that's been paged out. Owners
/// store this in place of the physical address; `page_in` exchanges
/// it back for a fresh `PhysAddr` carrying the same bytes.
///
/// The wire format is implementation-defined; callers must not
/// assume any structure beyond `Copy + Eq`. The `NoopPager` never
/// mints slots; `ZpoolPager`'s encoding is a monotonic counter that
/// indexes its internal table.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SwapSlot(pub u64);

/// Reasons `Pager` operations can fail.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PagerError {
    /// Pager refused — no room in the backing store, or this pager
    /// implementation does not provide backing at all (`NoopPager`).
    NoBacking,
    /// `page_in` (or `discard`) given a handle that this pager did
    /// not mint, or that has already been paged in / discarded.
    SlotNotFound,
    /// `page_out` was requested for a page whose flags forbid it
    /// (e.g. `PageFlags::LOCKED`).
    BadFlags,
    /// `install_pager` was called with a cap whose epoch has been
    /// revoked between mint and call.
    AuthorityRevoked,
    /// `current_pager_*` was consulted before
    /// `install_default_if_unset` had a chance to land `NoopPager`.
    /// Should never escape into a steady-state kernel; flagged for
    /// completeness so the slot type can express "empty".
    NotInstalled,
}

impl From<CapError> for PagerError {
    fn from(_: CapError) -> Self {
        PagerError::AuthorityRevoked
    }
}

impl fmt::Display for PagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PagerError::NoBacking => "pager has no backing store available",
            PagerError::SlotNotFound => "swap slot is unknown to this pager",
            PagerError::BadFlags => "page flags forbid page-out (locked / pinned)",
            PagerError::AuthorityRevoked => "pager-authority cap was revoked",
            PagerError::NotInstalled => "no pager installed",
        };
        f.write_str(s)
    }
}

/// A pluggable swap / page-out policy.
///
/// Implementations are responsible for *bytes*: stash the contents
/// of a 4 KiB physical page somewhere (compressed RAM, a disk-backed
/// swap area, a network-backed page-store, …) and hand back an
/// opaque `SwapSlot` token. The kernel reclaim path is responsible
/// for *frames* (freeing the physical page after a successful
/// `page_out`) and for *page tables* (replacing PTEs that referenced
/// the now-evicted page with a fault-on-touch encoding) — see
/// `reclaim.rs` for the integration point and the Wave C scope note
/// re: full frame-free / side-table wiring.
pub trait Pager: Send + Sync + 'static {
    /// Stable identifier (`"noop"`, `"zpool"`, …). Surfaces in
    /// `current_pager_name()` for diagnostics and tests.
    fn name(&self) -> &'static str;

    /// Page out `phys`. On `Ok`, the kernel may free the underlying
    /// frame; the bytes are preserved in the pager's backing store
    /// and recoverable through `page_in(slot)`.
    ///
    /// Implementations must reject pages flagged `LOCKED` with
    /// `BadFlags`: a pinned page cannot be safely paged out.
    fn page_out(&self, phys: PhysAddr, flags: PageFlags) -> Result<SwapSlot, PagerError>;

    /// Page in `slot`. Allocates a fresh physical frame (the new
    /// frame is *not* the same one originally paged out), populates
    /// it with the saved bytes, returns the new `PhysAddr`. The
    /// owner is responsible for re-mapping any PTE that referenced
    /// the original page to point at the returned frame.
    fn page_in(&self, slot: SwapSlot) -> Result<PhysAddr, PagerError>;

    /// Drop `slot` without paging it in. The owner has decided the
    /// page was no longer needed (the mapping was torn down before
    /// touch, the process exited, …) and the pager may reclaim the
    /// backing.
    ///
    /// Idempotent on already-unknown slots — callers may race a
    /// stale handle in.
    fn discard(&self, slot: SwapSlot);
}

/// Cap-marker type for `install_pager`. Reserved at
/// `CapKind::Pager = 0x0202` (Wave 0).
///
/// Named `PagerAuthority` rather than `Pager` so the cap marker
/// does not collide with the trait of the same conceptual name.
/// The trait is the policy contract; this type is the installation
/// right.
#[derive(Copy, Clone, Debug)]
pub struct PagerAuthority;
impl CapType for PagerAuthority {
    const KIND: CapKind = CapKind::Pager;
}

/// The default pager: refuses everything. Equivalent to today's
/// behaviour (no swap at all).
///
/// Installing `NoopPager` is the install-time signal "I do not want
/// the reclaim path to attempt any paging-out — owner callbacks
/// only." Wave C ships with `NoopPager` as the default to preserve
/// pre-Wave-C semantics bit-for-bit.
#[derive(Copy, Clone, Debug, Default)]
pub struct NoopPager;

impl Pager for NoopPager {
    fn name(&self) -> &'static str {
        "noop"
    }
    fn page_out(&self, _phys: PhysAddr, _flags: PageFlags) -> Result<SwapSlot, PagerError> {
        Err(PagerError::NoBacking)
    }
    fn page_in(&self, _slot: SwapSlot) -> Result<PhysAddr, PagerError> {
        Err(PagerError::SlotNotFound)
    }
    fn discard(&self, _slot: SwapSlot) {
        // No backing to release.
    }
}

/// A compressed-RAM pager — stub for Wave C.
///
/// The intent: `page_out` compresses the page via `crate::zpool` and
/// stores the result, returning a `SwapSlot` keyed by an internal
/// handle table; `page_in` decompresses back into a fresh frame
/// from `alloc_frame_anywhere`; `discard` releases the zpool entry.
///
/// What's actually shipped here is a *stub*: every call returns
/// `Err(PagerError::NoBacking)` (or `SlotNotFound` on the `page_in`
/// side). The reason is scope:
///
///   * The `Zpool` type in `crate::zpool` is per-instance (no global
///     swap pool exists, and the existing consumer
///     `CompressedRamDisk` owns its own private `Zpool`).
///   * Standing up a *kernel-wide* swap pool — global instance, GC
///     policy under low-memory pressure, integration with the
///     reclaim watermark, reverse-mapping side-table for handle →
///     owner — is a Wave C+1 effort, far larger than the trait seam.
///
/// Wave C ships `ZpoolPager` as a stub so the dispatch surface
/// (`install_pager(ZpoolPager)` → `current_pager_name() == "zpool"`
/// → `page_out → Err(NoBacking)`) is testable. The real
/// implementation lands when the kernel-wide zpool instance does.
///
/// TODO(wave-C+1): wire to a global `Zpool` instance, an internal
/// `BTreeMap<u64, ZpoolHandle>` for slot decoding, and
/// `alloc_frame_anywhere` on `page_in`.
#[derive(Copy, Clone, Debug, Default)]
pub struct ZpoolPager;

impl Pager for ZpoolPager {
    fn name(&self) -> &'static str {
        "zpool"
    }
    fn page_out(&self, _phys: PhysAddr, flags: PageFlags) -> Result<SwapSlot, PagerError> {
        if flags.contains(PageFlags::LOCKED) {
            return Err(PagerError::BadFlags);
        }
        // TODO(wave-C+1): compress via `crate::zpool::Zpool::store`
        // on a kernel-global pool instance + mint a slot keyed off
        // the returned `ZpoolHandle`. Until the global pool exists,
        // refuse paging-out so the reclaim loop falls through to
        // owner callbacks (pre-Wave-C behaviour).
        Err(PagerError::NoBacking)
    }
    fn page_in(&self, _slot: SwapSlot) -> Result<PhysAddr, PagerError> {
        // TODO(wave-C+1): decode the slot, decompress into a fresh
        // frame from `alloc_frame_anywhere`, return its `PhysAddr`.
        Err(PagerError::SlotNotFound)
    }
    fn discard(&self, _slot: SwapSlot) {
        // TODO(wave-C+1): free the corresponding zpool slot.
    }
}

// `Box<dyn Pager>` slot. `IrqSafeSpinLock<Option<...>>` so
// `install_default_if_unset` can land `NoopPager` and
// `install_pager` can swap it without an extra allocation per
// dispatched call. Mirrors `power::GOVERNOR`.
static PAGER: IrqSafeSpinLock<Option<Box<dyn Pager>>> = IrqSafeSpinLock::new(None);

/// Install a `Pager` impl. Cap-gated on `Cap<PagerAuthority, Grant>`.
///
/// The previous installed pager is dropped. Any `SwapSlot` minted
/// by the displaced pager becomes unrecoverable — installs are
/// expected to happen at well-defined boundaries (boot, test setup
/// / teardown), not as a hot-path policy switch. Callers that need
/// a live swap migration are out of scope for Wave C.
pub fn install_pager<P: Pager>(cap: &Cap<PagerAuthority, Grant>, p: P) -> Result<(), PagerError> {
    cap.check_live()?;
    *PAGER.lock() = Some(Box::new(p));
    Ok(())
}

/// Install `NoopPager` if no pager has been installed yet. Called
/// from the reclaim path's `DeferToPager` branch on first miss so
/// the lookup always succeeds, and from `current_pager_name()` for
/// the diagnostic path. Idempotent: a slot already holding `Some(_)`
/// is left alone, which is what makes a later `install_pager`
/// installation stick.
pub(crate) fn install_default_if_unset() {
    let mut slot = PAGER.lock();
    if slot.is_none() {
        *slot = Some(Box::new(NoopPager));
    }
}

/// Snapshot the active pager's `name()`. Returns `Some("noop")`
/// after `install_default_if_unset` has run; in steady-state kernel
/// boot this is always non-`None`.
pub fn current_pager_name() -> Option<&'static str> {
    install_default_if_unset();
    PAGER.lock().as_ref().map(|p| p.name())
}

/// Crate-internal hook called by the reclaim loop when an owner's
/// `ReclaimFn` returns `ReclaimOutcome::DeferToPager`. Forwards to
/// the installed pager's `page_out`. Ensures the default `NoopPager`
/// is installed if no pager has been set yet, so the reclaim loop
/// never has to special-case a missing pager.
///
/// # Wave C scope
///
/// The caller (`reclaim_target_pages`) currently **logs the result
/// and does not free the physical frame** even on success, and does
/// not maintain a side-table of `(owner, phys) → SwapSlot`. Full
/// integration is Wave C+1. See the long-form note in
/// `reclaim.rs::reclaim_target_pages`.
pub(crate) fn page_out_via_installed(
    phys: PhysAddr,
    flags: PageFlags,
) -> Result<SwapSlot, PagerError> {
    install_default_if_unset();
    let slot = PAGER.lock();
    let pager = slot.as_ref().ok_or(PagerError::NotInstalled)?;
    pager.page_out(phys, flags)
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn reset_for_test() {
    *PAGER.lock() = None;
    install_default_if_unset();
}
