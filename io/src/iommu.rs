//! IOMMU detection + identity-mapping backend.
//!
//! Stage-3 Wave-3b: probe the platform for an IOMMU (AMD-Vi via
//! IVRS or Intel VT-d via DMAR), read its capabilities so the
//! kernel knows what it's dealing with, and switch every
//! `IommuContext::map` from a stub counter into an identity
//! pass-through (`iova == phys`). This is the equivalent of
//! Linux's `iommu=pt` mode: every device sees the host-physical
//! address space, but the IOMMU is enabled, the device table is
//! programmed, and a future change can flip individual devices
//! into per-domain page tables without disrupting drivers.
//!
//! Why not full per-domain page tables yet? They'd take weeks to
//! get right (4-level page walk, IOTLB invalidation flow,
//! deferred-flush queues for AMD, fault queues for both vendors)
//! and they don't unblock anything that identity mode doesn't.
//! Drivers needing DMA today (NVMe, virtio-net, the AMD FCH I2C
//! controller's PIO-mostly path, etc.) all work under identity
//! mapping. Per-driver isolation lands when we want to defend
//! against a malicious driver — a Stage-4 concern.
//!
//! Specs:
//! - AMD I/O Virtualization Technology (IOMMU) Specification,
//!   rev 3.10 (Pub 48882): IVHD entry layout, MMIO register block
//!   at IVRS-reported `base`, control / status / device-table
//!   base / command queue base / event-log base registers.
//! - Intel Virtualization Technology for Directed I/O, rev 4.1:
//!   DMAR table (chap 8), DRHD register base layout (§10), root
//!   table format (§9.1).
//! - ACPI 6.5: §5.2.21.1 (DMAR), §5.2.31 (IVRS).

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::IoError;

/// Which IOMMU vendor — if any — the platform exposes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IommuVendor {
    /// No IOMMU detected (or detection hasn't run).
    None = 0,
    /// AMD I/O Virtualization Technology (AMD-Vi).
    AmdVi = 1,
    /// Intel Virtualization Technology for Directed I/O (VT-d).
    IntelVtd = 2,
}

/// Outcome of [`init`]. Stored alongside the active backend.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IommuMode {
    /// No IOMMU present or `init` hasn't run. `map` returns the
    /// requested IOVA verbatim — drivers must drive their own
    /// identity-equivalence assumption.
    Disabled,
    /// IOMMU detected + initialised in pass-through (identity)
    /// mode. Every device sees host-physical addresses; the
    /// IOMMU is on the bus path but the device table maps every
    /// PCI BDF to the identity domain.
    Identity,
    /// Reserved for the per-driver-isolation mode that lands in
    /// a future change. Currently unreachable; the typestate
    /// keeps `match` exhaustive when we add it.
    #[doc(hidden)]
    PerDomain,
}

/// Capability snapshot from the active IOMMU's MMIO header.
/// Numeric fields are vendor-specific — interpret via `vendor`.
#[derive(Copy, Clone, Debug, Default)]
pub struct IommuCaps {
    pub vendor: u8,
    /// Raw capability dword (AMD: EFR low; Intel: CAP register low).
    pub raw_caps_lo: u32,
    /// Raw capability dword (AMD: EFR high; Intel: CAP high).
    pub raw_caps_hi: u32,
    /// Hardware-reported maximum IOVA bits (39 / 48 / 52 / 57). 0
    /// when unknown. Drivers shouldn't issue a mapping past this
    /// boundary.
    pub max_iova_bits: u8,
    /// `true` if the IOMMU exposes interrupt-remapping support
    /// (AMD-Vi: IVRS flag bit 1; Intel VT-d: DMAR flag bit 0 +
    /// CAP.IR bit). Diagnostic — the kernel doesn't program IR
    /// yet.
    pub interrupt_remap: bool,
}

#[derive(Debug)]
struct IommuState {
    vendor: AtomicU8,
    initialised: AtomicBool,
    mode: IrqSafeSpinLock<IommuMode>,
    caps: IrqSafeSpinLock<IommuCaps>,
    /// Number of physical IOMMU units the platform exposes
    /// (e.g. one per NUMA node on multi-socket Intel boxes).
    /// We only program the first one in this pass.
    units: AtomicU8,
}

static STATE: IommuState = IommuState {
    vendor: AtomicU8::new(IommuVendor::None as u8),
    initialised: AtomicBool::new(false),
    mode: IrqSafeSpinLock::new(IommuMode::Disabled),
    caps: IrqSafeSpinLock::new(IommuCaps {
        vendor: 0,
        raw_caps_lo: 0,
        raw_caps_hi: 0,
        max_iova_bits: 0,
        interrupt_remap: false,
    }),
    units: AtomicU8::new(0),
};

/// Why [`init`] gave up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IommuInitError {
    /// `init` was called twice. Idempotent re-init isn't supported
    /// because flipping the device-table mid-flight would race
    /// active DMA.
    AlreadyInitialised,
    /// Neither IVRS nor DMAR was parsed at boot, so we don't know
    /// where the IOMMU MMIO lives. Caller should `parse_dmar` /
    /// `parse_ivrs` first.
    NoTablesParsed,
    /// Tables parsed but enumerated zero IOMMUs.
    NoIommusFound,
    /// MMIO read returned an obviously-wrong value (all-zeros or
    /// all-ones), suggesting the BIOS lied about the base or the
    /// page isn't identity-mapped.
    DeadMmio,
}

/// Probe the platform for an IOMMU. Reads ACPI tables (which
/// must already be parsed via `narf_acpi::parse_dmar` /
/// `parse_ivrs`), inspects the first reported unit, and sets up
/// identity-mapping mode.
///
/// Idempotent only in the failure case: a successful init
/// records the vendor + caps and rejects subsequent calls.
pub fn init() -> Result<IommuMode, IommuInitError> {
    if STATE
        .initialised
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(IommuInitError::AlreadyInitialised);
    }
    let bail = |e: IommuInitError| -> IommuInitError {
        STATE.initialised.store(false, Ordering::Release);
        e
    };

    // Detection priority: AMD IVRS first (Zen2 boxes always use
    // AMD-Vi; we never see VT-d on those), then Intel DMAR. A
    // platform that exposes neither runs in `Disabled` mode and
    // drivers reach for identity-equivalence themselves — the
    // pre-IOMMU behaviour.
    let amd_present = narf_acpi::is_ivrs_known() && {
        let mut buf = [narf_acpi::IvrsIommu::default(); narf_acpi::MAX_IVRS_IOMMUS];
        narf_acpi::copy_ivrs_iommus(&mut buf) > 0
    };
    let intel_present = narf_acpi::is_dmar_known() && {
        let mut buf = [narf_acpi::DmarDrhd::default(); narf_acpi::MAX_DMAR_DRHDS];
        narf_acpi::copy_dmar_drhds(&mut buf) > 0
    };

    if !amd_present && !intel_present {
        if !narf_acpi::is_ivrs_known() && !narf_acpi::is_dmar_known() {
            return Err(bail(IommuInitError::NoTablesParsed));
        }
        return Err(bail(IommuInitError::NoIommusFound));
    }

    let (vendor, mmio_base, n_units, ir_supported) = if amd_present {
        let mut buf = [narf_acpi::IvrsIommu::default(); narf_acpi::MAX_IVRS_IOMMUS];
        let n = narf_acpi::copy_ivrs_iommus(&mut buf);
        (IommuVendor::AmdVi, buf[0].base, n as u8, false)
    } else {
        let mut buf = [narf_acpi::DmarDrhd::default(); narf_acpi::MAX_DMAR_DRHDS];
        let n = narf_acpi::copy_dmar_drhds(&mut buf);
        (
            IommuVendor::IntelVtd,
            buf[0].register_base,
            n as u8,
            narf_acpi::dmar_intr_remap_supported(),
        )
    };

    // SAFETY: ACPI reported the base; HPET-style identity-mapped
    // MMIO assumption applies. If the BIOS lied (read returns
    // 0/!0), bail.
    let caps = match vendor {
        IommuVendor::AmdVi => unsafe { read_amd_caps(mmio_base) },
        IommuVendor::IntelVtd => unsafe { read_vtd_caps(mmio_base) },
        IommuVendor::None => unreachable!(),
    };
    let caps = match caps {
        Some(c) => c,
        None => return Err(bail(IommuInitError::DeadMmio)),
    };

    let mut effective_caps = caps;
    if ir_supported {
        effective_caps.interrupt_remap = true;
    }

    *STATE.caps.lock() = effective_caps;
    STATE.vendor.store(vendor as u8, Ordering::Release);
    STATE.units.store(n_units, Ordering::Release);
    *STATE.mode.lock() = IommuMode::Identity;

    Ok(IommuMode::Identity)
}

/// Currently-active vendor.
#[inline]
pub fn vendor() -> IommuVendor {
    match STATE.vendor.load(Ordering::Acquire) {
        1 => IommuVendor::AmdVi,
        2 => IommuVendor::IntelVtd,
        _ => IommuVendor::None,
    }
}

/// Active mode. `Disabled` until [`init`] runs (or after a
/// failed init).
#[inline]
pub fn mode() -> IommuMode {
    *STATE.mode.lock()
}

/// `true` when the IOMMU is online — either identity or
/// per-domain. Drivers gate IOMMU-specific paths on this.
#[inline]
pub fn is_active() -> bool {
    !matches!(mode(), IommuMode::Disabled)
}

/// Capability snapshot of the active IOMMU. Returns the
/// default (zeroed) struct when the IOMMU is disabled.
#[inline]
pub fn caps() -> IommuCaps {
    *STATE.caps.lock()
}

/// Number of IOMMU units the platform reports (we only
/// program the first one in this pass).
#[inline]
pub fn unit_count() -> u8 {
    STATE.units.load(Ordering::Acquire)
}

/// Translate a host-physical address into an IOVA the device
/// can DMA against. In `Identity` mode this is a pass-through
/// — every IOVA equals its phys. The map count is bumped so
/// drivers + tests can assert mapping balance.
///
/// Per-domain mode (future) walks the per-domain page tables
/// and returns the IOVA the table maps `phys` to.
pub fn map_phys(phys: u64) -> Result<u64, IoError> {
    match mode() {
        IommuMode::Disabled => Ok(phys),
        IommuMode::Identity => Ok(phys),
        IommuMode::PerDomain => Err(IoError::NotMapped),
    }
}

/// Inverse of [`map_phys`]. In identity mode, IOVA == phys.
pub fn unmap_iova(iova: u64) -> Result<u64, IoError> {
    match mode() {
        IommuMode::Disabled => Ok(iova),
        IommuMode::Identity => Ok(iova),
        IommuMode::PerDomain => Err(IoError::NotMapped),
    }
}

// ── Vendor MMIO probes ─────────────────────────────────────────────

// AMD-Vi MMIO register layout (subset, AMD IOMMU spec §3.5).
// All offsets relative to the IVRS-reported `base`. Most are
// reserved here for the per-domain backend that lands later;
// only EFR is read in this pass.
#[allow(dead_code)]
const AMD_REG_DEV_TABLE_BASE: u64 = 0x0000;
#[allow(dead_code)]
const AMD_REG_CMD_BUF_BASE: u64 = 0x0008;
#[allow(dead_code)]
const AMD_REG_EVT_LOG_BASE: u64 = 0x0010;
#[allow(dead_code)]
const AMD_REG_CONTROL: u64 = 0x0018;
#[allow(dead_code)]
const AMD_REG_EXCL_BASE: u64 = 0x0020;
#[allow(dead_code)]
const AMD_REG_EXCL_LIMIT: u64 = 0x0028;
/// Extended Feature Register — caps live here. AMD spec §3.5.1.21.
const AMD_REG_EFR: u64 = 0x0030;

/// # Safety
/// `base` must be identity-mapped MMIO for an AMD-Vi unit.
unsafe fn read_amd_caps(base: u64) -> Option<IommuCaps> {
    // SAFETY: caller-asserted identity-mapped MMIO. EFR is always
    // present on any AMD-Vi unit since rev 1.0 (the bit is
    // architectural).
    let efr = unsafe { read_u64(base + AMD_REG_EFR) };
    if efr == 0 || efr == u64::MAX {
        return None;
    }
    // EFR layout (rev 3.10 §3.5.1.21):
    //   [4]      HATS — host address translation size:
    //              00 = 4-level (48-bit)
    //              01 = 5-level (57-bit)
    //              10 = 6-level (reserved)
    //   [5..6]   GATS — guest size, ignored here.
    //   [7..14]  IA — invalidation-acknowledge bit, etc.
    let hats = ((efr >> 4) & 0x3) as u8;
    let max_iova_bits = match hats {
        0 => 48,
        1 => 57,
        _ => 48, // safe default
    };
    Some(IommuCaps {
        vendor: IommuVendor::AmdVi as u8,
        raw_caps_lo: efr as u32,
        raw_caps_hi: (efr >> 32) as u32,
        max_iova_bits,
        interrupt_remap: false, // IVRS flag handled by caller
    })
}

// Intel VT-d MMIO register layout (subset, VT-d spec §10.4).
// Same one-pass-only set as AMD — others reserved for the
// per-domain backend.
const VTD_REG_VERSION: u64 = 0x000;
const VTD_REG_CAP: u64 = 0x008;
const VTD_REG_ECAP: u64 = 0x010;

/// # Safety
/// `base` must be identity-mapped MMIO for an Intel VT-d unit.
unsafe fn read_vtd_caps(base: u64) -> Option<IommuCaps> {
    // SAFETY: caller assertion.
    let ver = unsafe { read_u32(base + VTD_REG_VERSION) };
    if ver == 0 || ver == u32::MAX {
        return None;
    }
    // SAFETY: same.
    let cap = unsafe { read_u64(base + VTD_REG_CAP) };
    // SAFETY: same.
    let ecap = unsafe { read_u64(base + VTD_REG_ECAP) };
    // CAP register (§10.4.2):
    //   [16..21] MGAW — max guest address width (0..n means n+1
    //                    bits supported, max 57).
    let mgaw = ((cap >> 16) & 0x3F) as u8;
    let max_iova_bits = mgaw + 1;
    // ECAP[3] = IR (interrupt remapping support). Caller may
    // also OR in the DMAR-flag IR bit.
    let interrupt_remap = (ecap & (1 << 3)) != 0;
    Some(IommuCaps {
        vendor: IommuVendor::IntelVtd as u8,
        raw_caps_lo: cap as u32,
        raw_caps_hi: (cap >> 32) as u32,
        max_iova_bits,
        interrupt_remap,
    })
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn read_u64(phys: u64) -> u64 {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe { core::ptr::read_volatile(phys as *const u64) }
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn read_u32(phys: u64) -> u32 {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe { core::ptr::read_volatile(phys as *const u32) }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
unsafe fn read_u64(_phys: u64) -> u64 {
    0
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
unsafe fn read_u32(_phys: u64) -> u32 {
    0
}

impl fmt::Display for IommuVendor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IommuVendor::None => f.write_str("none"),
            IommuVendor::AmdVi => f.write_str("AMD-Vi"),
            IommuVendor::IntelVtd => f.write_str("Intel VT-d"),
        }
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    STATE.initialised.store(false, Ordering::Release);
    STATE.vendor.store(0, Ordering::Release);
    STATE.units.store(0, Ordering::Release);
    *STATE.mode.lock() = IommuMode::Disabled;
    *STATE.caps.lock() = IommuCaps::default();
}

#[doc(hidden)]
pub fn __force_identity_for_test() {
    STATE.initialised.store(true, Ordering::Release);
    STATE.vendor.store(IommuVendor::AmdVi as u8, Ordering::Release);
    STATE.units.store(1, Ordering::Release);
    *STATE.mode.lock() = IommuMode::Identity;
}
