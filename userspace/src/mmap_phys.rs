//! Allowlist for `sys_mmap_phys` — kernel-vetted physical regions
//! that userspace processes are allowed to map into their VA space.
//!
//! Without an allowlist a userspace caller could map arbitrary
//! physical memory (the kernel image, MMIO from an unrelated
//! driver) and read or scribble through. With one, only pages the
//! kernel has explicitly published — typically a fresh DrawRing
//! frame minted for the calling process — are mappable.
//!
//! Entries are (phys, len, perms) tuples. `len` is page-rounded;
//! the entry covers the half-open interval `[phys, phys + len)`.
//! Lookup is linear; the table is small (a few rings + future
//! shared regions). Insert / remove are atomic via an internal
//! spinlock.
//!
//! No fancy revocation yet — `revoke(phys)` removes the entry but
//! does not invalidate already-mapped userspace VAs. Future work:
//! tear down user mappings on revoke + IPI-driven TLB shootdown
//! of the affected userspace ASIDs.

use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MapPerms {
    /// Read + write. The common case for shared rings.
    ReadWrite,
    /// Read-only. Used for query-style shared regions.
    ReadOnly,
}

#[derive(Copy, Clone, Debug)]
pub struct AllowedRange {
    pub phys:  u64,
    pub len:   u64,
    pub perms: MapPerms,
}

static ALLOWLIST: IrqSafeSpinLock<Vec<AllowedRange>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register `(phys, len, perms)` as user-mappable. Subsequent
/// `sys_mmap_phys` calls naming this range succeed. `len` is
/// rounded up to a page boundary.
pub fn allow(phys: u64, len: u64, perms: MapPerms) {
    let len_pg = (len + 0xFFF) & !0xFFFu64;
    if phys & 0xFFF != 0 || len_pg == 0 { return; }
    let mut g = ALLOWLIST.lock();
    // De-dupe — re-registering the same range is idempotent.
    if g.iter().any(|e| e.phys == phys && e.len == len_pg) { return; }
    g.push(AllowedRange { phys, len: len_pg, perms });
}

/// Look up a `(phys, len)` request. Returns the matching entry or
/// `None`. Match means the request is *fully contained* by an
/// allowed entry — partial overlaps are rejected.
pub fn lookup(phys: u64, len: u64) -> Option<AllowedRange> {
    let len_pg = (len + 0xFFF) & !0xFFFu64;
    if phys & 0xFFF != 0 || len_pg == 0 { return None; }
    ALLOWLIST.lock().iter().copied().find(|e| {
        phys >= e.phys && phys.saturating_add(len_pg) <= e.phys.saturating_add(e.len)
    })
}

/// Remove an entry by exact (phys, len) match. No-op if absent.
pub fn revoke(phys: u64, len: u64) {
    let len_pg = (len + 0xFFF) & !0xFFFu64;
    let mut g = ALLOWLIST.lock();
    g.retain(|e| !(e.phys == phys && e.len == len_pg));
}

/// Test helper: clear the allowlist.
#[doc(hidden)]
pub fn __reset_for_test() {
    ALLOWLIST.lock().clear();
}

/// Test helper: snapshot the current entries.
#[doc(hidden)]
pub fn snapshot_for_test() -> Vec<AllowedRange> {
    ALLOWLIST.lock().clone()
}
