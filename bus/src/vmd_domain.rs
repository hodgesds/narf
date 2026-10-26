//! VMD domains — the MEMBAR resource windows behind an Intel VMD
//! bridge (issue #933 item 3).
//!
//! A VMD bridge hides its children behind two MMIO apertures: the
//! bridge's BAR2 (`VMD_MEMBAR1`) and BAR4 (`VMD_MEMBAR2`). The
//! firmware programs *host* addresses into those bridge BARs, and
//! every child BAR that decodes at all must decode *inside* one of
//! the two apertures — that containment is the whole contract. There
//! is no address translation on the path (Linux `vmd.c` hands the
//! apertures to the child bus as plain resource windows with offset
//! 0 on bare metal), so a child BAR value is already a host address;
//! what was missing in NARF is the bookkeeping that
//!
//! 1. records the apertures when the VMD driver probes the bridge,
//! 2. assigns *unprogrammed* child BARs from the owning bridge's
//!    aperture instead of the global host MMIO pool (an address
//!    from the host pool would never route through the bridge), and
//! 3. refuses to map a child BAR that points outside its bridge's
//!    apertures (a stale host-domain address left by firmware in a
//!    non-VMD configuration).
//!
//! MEMBAR2's head is not allocatable: the bridge's own MSI-X table
//! lives there. Linux reserves `0x2000` bytes (`0x2010` on the
//! MEMBAR-shadow server parts, whose shadow registers sit at
//! `0x2000..0x2010`), so child allocations from MEMBAR2 start at
//! `base + reserve_head`.
//!
//! Spec: `bus/specification/spec.md` §3.7. The MSI half of a VMD
//! domain (bridge entry allocation + demux) lives in
//! [`crate::vmd_irq`]; the two registries are keyed by the same
//! synthetic segment the VMD driver allocates per bridge.

use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::device::{BusDevice, BusKind};

/// Head bytes of MEMBAR2 reserved for the bridge's MSI-X table on
/// parts without the MEMBAR-shadow register block (Linux's default
/// `membar2_offset`).
pub const VMD_MEMBAR2_RESERVE_DEFAULT: u64 = 0x2000;

/// Head bytes reserved on MEMBAR-shadow parts (0x28C0): the shadow
/// register block occupies `0x2000..0x2010` on top of the table
/// reserve (Linux `MB2_SHADOW_OFFSET + MB2_SHADOW_SIZE`).
pub const VMD_MEMBAR2_RESERVE_SHADOW: u64 = 0x2010;

/// One MEMBAR aperture: a host-address window `[base, base + size)`
/// whose first `reserve_head` bytes belong to the bridge itself.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MembarWindow {
    /// Host physical base of the aperture (the bridge's BAR value).
    pub base: u64,
    /// Aperture size in bytes (the bridge BAR's decoded size).
    pub size: u64,
    /// Bytes at the head reserved for the bridge (MSI-X table /
    /// shadow registers); child allocations start past this.
    pub reserve_head: u64,
}

impl MembarWindow {
    pub const fn new(base: u64, size: u64, reserve_head: u64) -> Self {
        Self {
            base,
            size,
            reserve_head,
        }
    }

    /// First address a child BAR may be assigned at.
    pub fn usable_start(&self) -> u64 {
        self.base.saturating_add(self.reserve_head)
    }

    /// End of the aperture (exclusive).
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    /// `true` when `[phys, phys + len)` lies entirely inside the
    /// aperture. A zero-length range at the aperture base counts as
    /// contained; callers pass real BAR sizes.
    pub fn contains(&self, phys: u64, len: u64) -> bool {
        if phys < self.base {
            return false;
        }
        match phys.checked_add(len) {
            Some(end) => end <= self.end(),
            None => false,
        }
    }
}

/// Static description of one VMD domain, registered by the VMD
/// driver at probe time and read by the BAR / MSI paths.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VmdDomainInfo {
    /// Synthetic segment the bridge's children are tagged with.
    pub segment: u16,
    /// Registry address of the bridge device itself (host domain).
    pub bridge: crate::BusAddr,
    /// BAR2 aperture, when the bridge decoded one.
    pub membar1: Option<MembarWindow>,
    /// BAR4 aperture, when the bridge decoded one.
    pub membar2: Option<MembarWindow>,
    /// Bridge MSI-X table entries owned by the remap domain
    /// (0 = no MSI remapping on this bridge).
    pub msix_entries: u16,
    /// First bridge MSI-X entry children may be assigned (Linux
    /// `VMD_FEAT_OFFSET_FIRST_VECTOR`: 1 on client parts, where
    /// entry 0 is kept free; 0 elsewhere).
    pub first_vec: u16,
}

/// Runtime state behind one registered domain: the immutable info
/// plus the aperture ranges already spoken for. Programmed child
/// BARs are noted here as they are observed (BAR assignment and
/// mapping both note — see [`note_occupied`]), and allocations are
/// first-fit over the gaps, so a fresh assignment can never land
/// on top of a range firmware or an earlier probe already claimed.
struct DomainState {
    info: VmdDomainInfo,
    /// `(base, size)` ranges inside the apertures that are taken:
    /// the bridges' reserved heads (seeded at registration) plus
    /// every noted child BAR.
    occupied: Vec<(u64, u64)>,
}

static DOMAINS: IrqSafeSpinLock<Vec<DomainState>> = IrqSafeSpinLock::new(Vec::new());

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmdDomainError {
    /// A domain is already registered for this segment.
    DuplicateSegment,
    /// The bridge decoded no MEMBAR window at all.
    NoWindow,
}

/// Register a VMD domain. Called by the VMD driver once per bridge,
/// after the apertures are decoded and *before* the children are
/// installed into the device registry, so a child probe can never
/// observe the segment without its domain.
pub fn register_domain(info: VmdDomainInfo) -> Result<(), VmdDomainError> {
    if info.membar1.is_none() && info.membar2.is_none() {
        return Err(VmdDomainError::NoWindow);
    }
    let mut g = DOMAINS.lock();
    if g.iter().any(|d| d.info.segment == info.segment) {
        return Err(VmdDomainError::DuplicateSegment);
    }
    let mut occupied = Vec::new();
    for w in [info.membar1, info.membar2].into_iter().flatten() {
        if w.reserve_head > 0 {
            occupied.push((w.base, w.reserve_head));
        }
    }
    g.push(DomainState { info, occupied });
    Ok(())
}

/// Remove a domain (bridge detach). Returns the registered info so
/// the caller can tear down the matching IRQ domain.
pub fn unregister_domain(segment: u16) -> Option<VmdDomainInfo> {
    let mut g = DOMAINS.lock();
    let pos = g.iter().position(|d| d.info.segment == segment)?;
    Some(g.remove(pos).info)
}

/// Snapshot of the domain registered for `segment`, if any.
pub fn domain_info(segment: u16) -> Option<VmdDomainInfo> {
    DOMAINS
        .lock()
        .iter()
        .find(|d| d.info.segment == segment)
        .map(|d| d.info)
}

/// The domain owning `device`, if the device is a PCIe function on
/// a registered VMD segment. The bridge itself lives on the host
/// segment, so it never matches its own domain.
pub fn domain_for_device(device: &BusDevice) -> Option<VmdDomainInfo> {
    match device.kind {
        BusKind::Pcie { addr, .. } => domain_info(addr.segment),
        BusKind::VirtioMmio { .. } => None,
    }
}

/// The domain whose bridge is the device at `addr`, if any. Used by
/// the bridge's remove hook, which knows the bridge's registry
/// address but not the synthetic segment it was assigned.
pub fn domain_for_bridge(addr: crate::BusAddr) -> Option<VmdDomainInfo> {
    DOMAINS
        .lock()
        .iter()
        .find(|d| d.info.bridge == addr)
        .map(|d| d.info)
}

/// Which MEMBAR window of `segment`'s domain fully contains
/// `[phys, phys + len)`: `Some(1)` for MEMBAR1, `Some(2)` for
/// MEMBAR2, `None` when no domain is registered or the range falls
/// outside both apertures (or straddles one).
pub fn membar_window_of(segment: u16, phys: u64, len: u64) -> Option<u8> {
    let info = domain_info(segment)?;
    if let Some(w) = info.membar1 {
        if w.contains(phys, len) {
            return Some(1);
        }
    }
    if let Some(w) = info.membar2 {
        if w.contains(phys, len) {
            return Some(2);
        }
    }
    None
}

/// Allocate a `size`-byte, `align`-aligned window from the domain's
/// apertures — first-fit over the unoccupied gaps, MEMBAR1 before
/// MEMBAR2. Mirrors the host pool's alignment rules (power of two,
/// minimum one page). Returns `None` when the domain is unknown or
/// no gap in either aperture fits.
pub fn allocate_domain_mmio(segment: u16, size: u64, align: u64) -> Option<u64> {
    if size == 0 {
        return None;
    }
    let align = align.max(0x1000).next_power_of_two();
    let mut g = DOMAINS.lock();
    let d = g.iter_mut().find(|d| d.info.segment == segment)?;
    for w in [d.info.membar1, d.info.membar2].into_iter().flatten() {
        let mut cand = (w.usable_start() + align - 1) & !(align - 1);
        // First-fit: hop over every occupied range that overlaps
        // the candidate. Occupied ranges are few (one per child
        // BAR), so the rescan is cheap and keeps this deterministic.
        'scan: while cand.checked_add(size).is_some_and(|end| end <= w.end()) {
            for &(base, len) in &d.occupied {
                let occ_end = base.saturating_add(len);
                if cand < occ_end && base < cand + size {
                    cand = (occ_end + align - 1) & !(align - 1);
                    continue 'scan;
                }
            }
            d.occupied.push((cand, size));
            return Some(cand);
        }
    }
    None
}

/// Record `[phys, phys + len)` as spoken for inside `segment`'s
/// domain, when it lies inside one of the apertures. Called as BARs
/// are observed in use — a programmed BAR skipped by assignment, or
/// a BAR being mapped — so later allocations route around it.
/// Ranges outside the apertures and ranges already covered are
/// ignored.
pub fn note_occupied(segment: u16, phys: u64, len: u64) {
    if len == 0 {
        return;
    }
    let mut g = DOMAINS.lock();
    let Some(d) = g.iter_mut().find(|d| d.info.segment == segment) else {
        return;
    };
    let in_window = [d.info.membar1, d.info.membar2]
        .into_iter()
        .flatten()
        .any(|w| w.contains(phys, len));
    if !in_window {
        return;
    }
    let covered = d
        .occupied
        .iter()
        .any(|&(b, l)| phys >= b && phys + len <= b.saturating_add(l));
    if !covered {
        d.occupied.push((phys, len));
    }
}

/// Number of registered domains. Diagnostic / test signal.
pub fn domain_count() -> usize {
    DOMAINS.lock().len()
}

#[doc(hidden)]
/// Test-only: drop every registered domain between smokes.
pub fn __reset_for_test() {
    DOMAINS.lock().clear();
}
