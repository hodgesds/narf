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
//! Per-domain translation ([`IommuMode::PerDomain`]): a registered
//! hardware backend ([`IommuHw`], via [`enable_per_domain`]) plus
//! NARF-owned 4-level page tables in the backend's format
//! ([`PageTableFormat`]: AMD-Vi v1 or VT-d second-stage, Linux
//! `generic_pt/fmt/{amdv1,vtdss}.h`) and a per-domain IOVA allocator
//! ([`crate::iova`], Linux `iova.c`). Unmap is strict, as Linux
//! `iommu.strict=1`: clear PTEs → backend IOTLB invalidation +
//! completion wait → free IOVA → caller frees frames. `init` selects
//! `Identity` unless the boot command line opts in with
//! `iommu.passthrough=0`; then an AMD-Vi platform brings up the
//! [`crate::amd_vi`] silicon backend and enters `PerDomain`. VT-d and
//! SMMUv3 backends do not exist.
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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

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
    /// Per-device translation through [`IommuDomain`] page tables,
    /// entered only by [`enable_per_domain`] with a hardware backend.
    /// DMA addresses are IOVAs from the device's domain; device-less
    /// [`map_phys`] / [`unmap_iova`] fail (`NotMapped`).
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
    /// Primary IOMMU unit's MMIO base address (from the first
    /// IVRS/DMAR entry). 0 until [`init`] succeeds.
    primary_mmio_base: AtomicU64,
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
    primary_mmio_base: AtomicU64::new(0),
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
/// Opt-in only: with `iommu.passthrough=0` on the kernel command line, an
/// AMD-Vi platform whose devices have not yet been handed any DMA address
/// brings up the [`crate::amd_vi`] backend and enters
/// [`IommuMode::PerDomain`]; [`per_domain_opt_in`] reports the outcome.
/// Without the switch nothing changes: identity mode, hardware untouched.
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

    let caps = match vendor {
        // SAFETY: `mmio_base` is `buf[0].base` copied from the IVRS
        // table parsed by `narf_acpi`, and this arm only runs when
        // `amd_present` selected the AMD-Vi vendor, so the base
        // belongs to an AMD-Vi unit. IOMMU MMIO is identity-mapped
        // (HPET-style); `read_amd_caps` validates the read and
        // returns `None` if the BIOS-reported base is dead (0/!0).
        // SAFETY: Valid memory or trusted environment
        IommuVendor::AmdVi => unsafe { read_amd_caps(mmio_base) },
        // SAFETY: `mmio_base` is `buf[0].register_base` copied from
        // the DMAR table parsed by `narf_acpi`, reached only on the
        // Intel branch where `amd_present` was false and DMAR DRHDs
        // were found, so the base belongs to a VT-d unit. The VT-d
        // register window is identity-mapped MMIO; `read_vtd_caps`
        // validates the version register and returns `None` on a
        // dead window.
        // SAFETY: Valid memory or trusted environment
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
    STATE.primary_mmio_base.store(mmio_base, Ordering::Release);
    *STATE.mode.lock() = IommuMode::Identity;

    if !per_domain_requested_in(narf_boot::cmdline()) {
        // Identity is the software address contract; this branch does not
        // program the units. Record firmware's actual translation state so
        // a DMA failure cannot mistake detection for verified passthrough.
        if vendor == IommuVendor::AmdVi {
            use crate::amd_vi::{AmdViRegs, MmioRegs, MMIO_CONTROL, MMIO_DEV_TABLE};
            use core::fmt::Write;
            let mut units = [narf_acpi::IvrsIommu::default(); narf_acpi::MAX_IVRS_IOMMUS];
            let count = narf_acpi::copy_ivrs_iommus(&mut units);
            for (index, unit) in units[..count].iter().enumerate() {
                // IVRS reports device MMIO, which need not be covered by the
                // RAM direct map. Use the backend's checked Device mapping;
                // a failed diagnostic map must not prevent normal boot.
                // SAFETY: this is an IVRS-reported AMD-Vi register window;
                // the boot path owns it and these accesses perform no writes.
                let Some(regs) = (unsafe { MmioRegs::map(unit.base) }) else {
                    let _ = writeln!(narf_console::Writer,
                        "[iommu] AMD-Vi inherited unit{index} base={:#x}: diagnostic mapping unavailable (hardware unchanged)",
                        unit.base);
                    continue;
                };
                let control = regs.read64(MMIO_CONTROL);
                let table = regs.read64(MMIO_DEV_TABLE);
                let _ = writeln!(narf_console::Writer,
                    "[iommu] AMD-Vi inherited unit{index} base={:#x} control={control:#x} dev_table={table:#x} (hardware unchanged)",
                    unit.base);
            }
        }
        *OPT_IN.lock() = PerDomainOptIn::NotRequested;
        return Ok(IommuMode::Identity);
    }
    let outcome = if vendor != IommuVendor::AmdVi {
        PerDomainOptIn::NoBackend
    } else if IDENTITY_DMA_ISSUED.load(Ordering::Acquire) {
        // A device already holds a physical DMA address; attaching it
        // later would make that address fault. Linux decides the default
        // domain type before any driver probes.
        PerDomainOptIn::DmaAlreadyHandedOut
    } else {
        match crate::amd_vi::boot_enable() {
            Ok(hw) => match enable_per_domain(hw) {
                Ok(()) => PerDomainOptIn::Enabled,
                Err(_) => PerDomainOptIn::AlreadyPerDomain,
            },
            Err(e) => PerDomainOptIn::Failed(e),
        }
    };
    *OPT_IN.lock() = outcome;
    Ok(mode())
}

/// Boot switch for per-domain translation: Linux `iommu.passthrough=0`
/// (default DMA domains instead of identity). Absent ⇒ [`IommuMode::Identity`].
pub const PER_DOMAIN_CMDLINE_KEY: &str = "iommu.passthrough";

/// Whether `cmdline` asks for per-domain translation (`iommu.passthrough=`
/// `0` / `n` / `N` / `off`, the false spellings of Linux `kstrtobool`).
pub fn per_domain_requested_in(cmdline: &str) -> bool {
    narf_boot::args::KernelCmdline::new(cmdline)
        .value(PER_DOMAIN_CMDLINE_KEY)
        .is_some_and(|v| matches!(v, "0" | "n" | "N" | "off"))
}

/// Outcome of the `iommu.passthrough=0` opt-in, for boot diagnostics.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PerDomainOptIn {
    /// [`init`] has not run.
    Unknown,
    /// Switch absent: identity mode, IOMMU hardware untouched.
    NotRequested,
    /// AMD-Vi backend up, [`IommuMode::PerDomain`] active.
    Enabled,
    /// Requested on a platform without a silicon backend (VT-d).
    NoBackend,
    /// Requested, but [`init`] ran after a DMA buffer was already handed
    /// out with a physical address; mode stays identity.
    DmaAlreadyHandedOut,
    /// Per-domain mode was already active (test harness).
    AlreadyPerDomain,
    /// AMD-Vi bring-up failed; mode stays identity.
    Failed(crate::amd_vi::EnableError),
}

static OPT_IN: IrqSafeSpinLock<PerDomainOptIn> = IrqSafeSpinLock::new(PerDomainOptIn::Unknown);

/// Set once any DMA address is handed out before per-domain mode.
static IDENTITY_DMA_ISSUED: AtomicBool = AtomicBool::new(false);

/// What the per-domain opt-in did.
pub fn per_domain_opt_in() -> PerDomainOptIn {
    *OPT_IN.lock()
}

/// Record that a device received a DMA address outside per-domain mode.
#[inline]
pub(crate) fn note_dma_issued() {
    if !IDENTITY_DMA_ISSUED.load(Ordering::Relaxed) {
        IDENTITY_DMA_ISSUED.store(true, Ordering::Release);
    }
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

/// MMIO base of the primary (first-enumerated) IOMMU unit. Returns
/// 0 when [`init`] hasn't run, the IOMMU isn't present, or `init`
/// failed. Boot diagnostics use this to print where the IOMMU
/// register block lives.
#[inline]
pub fn primary_mmio_base() -> u64 {
    STATE.primary_mmio_base.load(Ordering::Acquire)
}

/// Translate a host-physical address into an IOVA the device
/// can DMA against. In `Identity` mode this is a pass-through
/// — every IOVA equals its phys. The map count is bumped so
/// drivers + tests can assert mapping balance.
///
/// Per-domain mode has no device to pick a domain from, so it
/// fails (`NotMapped`); use [`IommuDomain::map_below`] /
/// `alloc_coherent_for` with a domain-carrying `DmaDevice`.
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
    // SAFETY: Valid memory or trusted environment
    let efr = unsafe { read_u64(base + AMD_REG_EFR) };
    if efr == 0 || efr == u64::MAX {
        return None;
    }
    // EFR[11:10] HATS (Linux `FEATURE_HATS`): max host levels = HATS + 4
    // (`amd_iommu_hpt_level`); 3 is reserved.
    let hats = ((efr >> crate::amd_vi::FEATURE_HATS_SHIFT) & 0x3) as u8;
    let max_iova_bits = match hats {
        0 => 48,
        1 | 2 => 57,
        _ => 48, // reserved: safe default
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
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(phys).kernel_ptr::<u64>()) }
}

#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn read_u32(phys: u64) -> u32 {
    // SAFETY: caller-asserted identity-mapped MMIO.
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(phys).kernel_ptr::<u32>()) }
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
    STATE.primary_mmio_base.store(0, Ordering::Release);
    *STATE.mode.lock() = IommuMode::Disabled;
    *STATE.caps.lock() = IommuCaps::default();
    *BACKEND.lock() = None;
    let defaults = core::mem::take(&mut *DEFAULT_DOMAINS.lock());
    for (bdf, domain) in defaults {
        let _ = domain.detach(bdf);
    }
    ATTACHED.lock().clear();
}

#[doc(hidden)]
pub fn __force_identity_for_test() {
    STATE.initialised.store(true, Ordering::Release);
    STATE
        .vendor
        .store(IommuVendor::AmdVi as u8, Ordering::Release);
    STATE.units.store(1, Ordering::Release);
    *STATE.mode.lock() = IommuMode::Identity;
}

// ── Per-device IOVA mapping API ──────────────────────────────────
//
// `IommuDomain` is the per-driver / per-device abstraction over the
// IOMMU's page tables. In Identity mode every domain resolves
// `iova == phys`; in PerDomain mode `domain.map` returns an IOVA
// from the domain's own page table, with no driver change.
//
// `iommu_map(bdf, iova, phys, len, perms)` is the free-function form
// for drivers that don't construct their own domain: identity mode
// passes through, per-domain mode uses the device's default domain.

/// Permission bits on an `iommu_map`. Backed by AMD-Vi DTE IR/IW
/// and Intel VT-d SL_PTE READ/WRITE. The bit values are the same
/// across both vendors and they are also identical to
/// `arch::x86_64::amd_vi::PERM_*`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IommuPerms(u8);

impl IommuPerms {
    pub const NONE: IommuPerms = IommuPerms(0);
    pub const READ: IommuPerms = IommuPerms(0b01);
    pub const WRITE: IommuPerms = IommuPerms(0b10);
    pub const READ_WRITE: IommuPerms = IommuPerms(0b11);

    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        IommuPerms(bits & 0b11)
    }

    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[inline]
    pub const fn read(self) -> bool {
        self.0 & 0b01 != 0
    }

    #[inline]
    pub const fn write(self) -> bool {
        self.0 & 0b10 != 0
    }
}

impl core::ops::BitOr for IommuPerms {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        IommuPerms(self.0 | rhs.0)
    }
}

/// PCI Bus/Device/Function identifier, packed as `bus<<8 | dev<<3
/// | func`. Indexes both AMD-Vi device tables and Intel VT-d
/// root/context lookup.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bdf(pub u16);

impl Bdf {
    #[inline]
    pub const fn new(bus: u8, dev: u8, func: u8) -> Self {
        Bdf(((bus as u16) << 8) | (((dev & 0x1F) as u16) << 3) | ((func & 0x7) as u16))
    }

    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    #[inline]
    pub const fn bus(self) -> u8 {
        (self.0 >> 8) as u8
    }

    #[inline]
    pub const fn devfn(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
}

// ── Per-domain translation (IommuMode::PerDomain) ────────────────
//
// Linux splits this across `drivers/iommu/iommu.c` (domains, attach),
// the vendor page-table code (`generic_pt/fmt/amdv1.h`,
// `generic_pt/fmt/vtdss.h`), `dma-iommu.c` (IOVA allocation + the strict
// unmap ordering) and the vendor drivers' invalidation queues. NARF keeps
// the page tables and IOVA space here and asks a registered hardware
// backend ([`IommuHw`]) for the three things only silicon can do:
// pointing a requester ID at a page-table root, removing it again, and
// invalidating cached translations with a completion wait.

/// In-memory page-table format the hardware walks.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageTableFormat {
    /// AMD-Vi host page table v1 (Linux `generic_pt/fmt/amdv1.h`).
    AmdV1,
    /// Intel VT-d second-stage table (Linux `generic_pt/fmt/vtdss.h`).
    VtdSecondStage,
}

/// Levels of every NARF per-domain table: 4 × 9 index bits + 12-bit
/// page offset = 48-bit IOVA (AMD DTE `Mode = 4`, VT-d `AW = 2`).
pub const PT_LEVELS: u8 = 4;
/// IOVA width translated by a [`PT_LEVELS`]-level table.
pub const PT_IOVA_BITS: u8 = 48;

// AMD v1 bits (Linux `generic_pt/fmt/amdv1.h`).
const AMDV1_PR: u64 = 1 << 0;
const AMDV1_NEXT_LEVEL_SHIFT: u32 = 9;
const AMDV1_FC: u64 = 1 << 60;
const AMDV1_IR: u64 = 1 << 61;
const AMDV1_IW: u64 = 1 << 62;
// VT-d second-stage bits (Linux `generic_pt/fmt/vtdss.h`).
const VTDSS_R: u64 = 1 << 0;
const VTDSS_W: u64 = 1 << 1;
/// Output-address field shared by both formats (bits 51:12).
const PTE_OA_MASK: u64 = 0x000F_FFFF_FFFF_F000;

impl PageTableFormat {
    /// Whether `pte` is a live entry (AMD `PR`; VT-d `R|W`, Linux
    /// `dma_pte_present`).
    #[inline]
    pub const fn present(self, pte: u64) -> bool {
        match self {
            PageTableFormat::AmdV1 => pte & AMDV1_PR != 0,
            PageTableFormat::VtdSecondStage => pte & (VTDSS_R | VTDSS_W) != 0,
        }
    }

    /// Non-leaf entry in a table of 1-based `level` pointing at the next
    /// table (Linux `amdv1pt_install_table`: `NextLevel = level - 1`,
    /// IR|IW always set because permissions are ANDed down the walk;
    /// `vtdss_pt_install_table`: R|W).
    #[inline]
    pub const fn table_entry(self, level: u8, table_phys: u64) -> u64 {
        let oa = table_phys & PTE_OA_MASK;
        match self {
            PageTableFormat::AmdV1 => {
                AMDV1_PR
                    | (((level - 1) as u64) << AMDV1_NEXT_LEVEL_SHIFT)
                    | oa
                    | AMDV1_IR
                    | AMDV1_IW
            }
            PageTableFormat::VtdSecondStage => VTDSS_R | VTDSS_W | oa,
        }
    }

    /// 4 KiB leaf (Linux `amdv1pt_install_leaf_entry` with
    /// `NextLevel = AMDV1PT_FMT_NL_DEFAULT` and the `IOMMU_CACHE` → FC
    /// descriptor bit of `amdv1pt_iommu_set_prot`;
    /// `vtdss_pt_install_leaf_entry` at level 0).
    #[inline]
    pub const fn leaf_entry(self, phys: u64, perms: IommuPerms) -> u64 {
        let oa = phys & PTE_OA_MASK;
        match self {
            PageTableFormat::AmdV1 => {
                let mut e = AMDV1_PR | AMDV1_FC | oa;
                if perms.read() {
                    e |= AMDV1_IR;
                }
                if perms.write() {
                    e |= AMDV1_IW;
                }
                e
            }
            PageTableFormat::VtdSecondStage => {
                let mut e = oa;
                if perms.read() {
                    e |= VTDSS_R;
                }
                if perms.write() {
                    e |= VTDSS_W;
                }
                e
            }
        }
    }

    /// Permissions of a leaf entry.
    #[inline]
    pub const fn leaf_perms(self, pte: u64) -> IommuPerms {
        match self {
            PageTableFormat::AmdV1 => IommuPerms::from_bits(
                ((pte & AMDV1_IR != 0) as u8) | (((pte & AMDV1_IW != 0) as u8) << 1),
            ),
            PageTableFormat::VtdSecondStage => IommuPerms::from_bits((pte & 0b11) as u8),
        }
    }
}

/// Hardware half of per-domain translation: one implementation per
/// IOMMU unit type. Every method must complete on the hardware before
/// returning (Linux pairs each invalidation with `COMPLETION_WAIT` /
/// an invalidation-wait descriptor); `flush_iotlb` returning `Ok`
/// is the proof that no IOTLB or device-TLB entry for the range
/// survives, which is what lets the IOVA be reused.
pub trait IommuHw: Send + Sync {
    /// Diagnostic name.
    fn name(&self) -> &'static str;
    /// Page-table format the unit walks.
    fn format(&self) -> PageTableFormat;
    /// Whether the table walker snoops CPU caches (AMD-Vi: always;
    /// VT-d: `ECAP.C`). When `false` every PTE store is cleaned to the
    /// point of coherency (Linux `domain_flush_cache` / `clflush_cache_range`).
    fn coherent_walk(&self) -> bool;
    /// Point `bdf` at `root` for `domain_id` and invalidate the cached
    /// device entry (AMD: DTE + `INVALIDATE_DEVTAB_ENTRY`; VT-d:
    /// context entry + context-cache invalidation).
    fn attach(&self, bdf: Bdf, domain_id: u16, root: u64, levels: u8) -> Result<(), IoError>;
    /// Block `bdf` (DTE/context entry cleared or set to a blocking
    /// domain), then invalidate its device entry and its domain's IOTLB.
    fn detach(&self, bdf: Bdf, domain_id: u16) -> Result<(), IoError>;
    /// Invalidate `[iova, iova + len)` for `domain_id` and wait for the
    /// invalidation to complete (AMD `INVALIDATE_IOMMU_PAGES` +
    /// `COMPLETION_WAIT`; VT-d `iotlb_inv_dsc` + `inv_wait_dsc`).
    fn flush_iotlb(&self, domain_id: u16, iova: u64, len: u64) -> Result<(), IoError>;
    /// Called after new PTEs become visible (VT-d caching mode needs an
    /// invalidation even for non-present → present, Linux
    /// `intel_iommu_iotlb_sync_map`). Default: nothing to do.
    fn sync_map(&self, _domain_id: u16, _iova: u64, _len: u64) -> Result<(), IoError> {
        Ok(())
    }
    /// Firmware-mandated identity ranges for `bdf` (AMD IVMD unity /
    /// exclusion ranges, VT-d RMRR; Linux `IOMMU_RESV_DIRECT` from
    /// `get_resv_regions`). [`IommuDomain::attach`] reserves each range in
    /// the domain's IOVA space and maps it 1:1 before pointing the device
    /// at the table (Linux `iommu_create_device_direct_mappings`).
    /// Default: none.
    fn direct_mappings(&self, _bdf: Bdf) -> alloc::vec::Vec<DirectMapping> {
        alloc::vec::Vec::new()
    }
}

/// One identity-mapped range `[start, end)` (page aligned) a device must
/// keep reaching after it is attached to a translating domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DirectMapping {
    pub start: u64,
    pub end: u64,
    pub perms: IommuPerms,
}

static BACKEND: IrqSafeSpinLock<Option<&'static dyn IommuHw>> = IrqSafeSpinLock::new(None);

/// Domain IDs handed to default domains. 0 is reserved (AMD-Vi and
/// VT-d with caching mode treat domain 0 specially). IDs are never
/// recycled, so a stale IOTLB entry tagged with a freed ID cannot hit a
/// new domain.
static NEXT_DOMAIN_ID: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1);

/// BDFs currently pointed at a page table, with their domain ID.
static ATTACHED: IrqSafeSpinLock<alloc::vec::Vec<(Bdf, u16)>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Default DMA domain per device (Linux `iommu_group::default_domain`).
static DEFAULT_DOMAINS: IrqSafeSpinLock<alloc::vec::Vec<(Bdf, alloc::sync::Arc<IommuDomain>)>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// Switch to [`IommuMode::PerDomain`] with `hw` as the translation
/// backend. Must run before any device is handed a DMA address: buffers
/// allocated earlier keep their physical (identity) DMA address.
///
/// Errors: `DomainMismatch` if per-domain mode is already active.
pub fn enable_per_domain(hw: &'static dyn IommuHw) -> Result<(), IoError> {
    let mut mode = STATE.mode.lock();
    if *mode == IommuMode::PerDomain {
        return Err(IoError::DomainMismatch);
    }
    *BACKEND.lock() = Some(hw);
    *mode = IommuMode::PerDomain;
    Ok(())
}

/// The registered per-domain backend, if any.
pub fn backend() -> Option<&'static dyn IommuHw> {
    *BACKEND.lock()
}

fn alloc_domain_id() -> Result<u16, IoError> {
    let id = NEXT_DOMAIN_ID.fetch_add(1, Ordering::Relaxed);
    u16::try_from(id).map_err(|_| IoError::NoMemory)
}

/// Linux `iommu_get_dma_domain`: the device's default DMA domain,
/// created and attached on first use. Only valid in
/// [`IommuMode::PerDomain`] (`NotMapped` otherwise).
pub fn default_domain(bdf: Bdf) -> Result<alloc::sync::Arc<IommuDomain>, IoError> {
    if mode() != IommuMode::PerDomain {
        return Err(IoError::NotMapped);
    }
    let mut defaults = DEFAULT_DOMAINS.lock();
    if let Some((_, d)) = defaults.iter().find(|(b, _)| *b == bdf) {
        return Ok(d.clone());
    }
    let domain = alloc::sync::Arc::new(IommuDomain::new(alloc_domain_id()?));
    domain.attach(bdf)?;
    defaults.push((bdf, domain.clone()));
    Ok(domain)
}

/// Detach `bdf` from its default domain and forget it. Buffers still
/// holding the domain keep it (and its page table) alive until they are
/// freed; the device can no longer reach them.
pub fn release_default_domain(bdf: Bdf) -> Result<(), IoError> {
    let domain = {
        let mut defaults = DEFAULT_DOMAINS.lock();
        let pos = defaults
            .iter()
            .position(|(b, _)| *b == bdf)
            .ok_or(IoError::NotMapped)?;
        defaults.swap_remove(pos).1
    };
    domain.detach(bdf)
}

/// Outcome of [`block_device_dma`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DmaBlock {
    /// Not [`IommuMode::PerDomain`]: DMA addresses are physical and the
    /// IOMMU cannot stop the device, so DMA quiescence rests on
    /// device-side evidence alone (bus-master clear, device handshakes).
    Untranslated,
    /// The device's requester ID is blocked ([`IommuHw::detach`]: blocking
    /// DTE / context entry, device-entry and domain IOTLB invalidation,
    /// completion wait). Its default domain stays recorded, so buffers
    /// still mapped there unmap (and invalidate) normally.
    Blocked,
}

fn attached_domain_id(bdf: Bdf) -> Option<u16> {
    ATTACHED
        .lock()
        .iter()
        .find(|(b, _)| *b == bdf)
        .map(|(_, d)| *d)
}

/// Driver-neutral DMA quiescence through the IOMMU (Linux
/// `pci_dev_reset_iommu_prepare`: attach the requester to the group's
/// blocking domain while `group->domain` stays intact; on removal
/// `iommu_deinit_device` → `release_domain`/blocked domain). In
/// `PerDomain` the device is detached from its default domain, which per
/// the [`IommuHw::detach`] contract returns only after the blocking entry
/// and its invalidations completed: from then on no device transaction
/// translates, so memory previously mapped for it may be released (each
/// [`crate::DmaBuffer`] still runs its own strict unmap → invalidate →
/// wait before its frames are freed).
///
/// Idempotent: a device whose default domain exists but is not attached
/// was detached by an earlier call and is reported `Blocked` (a device
/// gets a default domain only through a successful attach, and an
/// AMD-Vi requester that was never attached passes through untranslated,
/// so "no default domain" is never reported as blocked).
///
/// Errors: `NotMapped` (PerDomain, no default domain), `DomainMismatch`
/// (attached to some other domain), or the backend's detach error
/// (`Timeout`): the device must then be treated as still able to DMA.
pub fn block_device_dma(bdf: Bdf) -> Result<DmaBlock, IoError> {
    if mode() != IommuMode::PerDomain {
        return Ok(DmaBlock::Untranslated);
    }
    let domain = default_domain_of(bdf).ok_or(IoError::NotMapped)?;
    match attached_domain_id(bdf) {
        None => Ok(DmaBlock::Blocked),
        Some(id) if id == domain.domain_id() => {
            domain.detach(bdf)?;
            Ok(DmaBlock::Blocked)
        }
        Some(_) => Err(IoError::DomainMismatch),
    }
}

/// Inverse of [`block_device_dma`] (Linux `pci_dev_reset_iommu_done`):
/// re-attach the device to its retained default domain so a fresh
/// generation's buffers translate. A no-op outside `PerDomain` or when
/// already attached to that domain. Callers must only restore a device
/// whose own reset/stop proof they hold: restoring re-opens every IOVA
/// still mapped in the domain to the device.
pub fn restore_device_dma(bdf: Bdf) -> Result<(), IoError> {
    if mode() != IommuMode::PerDomain {
        return Ok(());
    }
    let domain = default_domain_of(bdf).ok_or(IoError::NotMapped)?;
    match attached_domain_id(bdf) {
        Some(id) if id == domain.domain_id() => Ok(()),
        Some(_) => Err(IoError::DomainMismatch),
        None => domain.attach(bdf),
    }
}

/// Whether [`block_device_dma`] currently holds `bdf` blocked (always
/// `false` outside `PerDomain`).
pub fn device_dma_blocked(bdf: Bdf) -> bool {
    mode() == IommuMode::PerDomain
        && default_domain_of(bdf).is_some()
        && attached_domain_id(bdf).is_none()
}

fn default_domain_of(bdf: Bdf) -> Option<alloc::sync::Arc<IommuDomain>> {
    DEFAULT_DOMAINS
        .lock()
        .iter()
        .find(|(b, _)| *b == bdf)
        .map(|(_, d)| d.clone())
}

#[inline]
fn pt_ptr(phys: u64) -> *mut u64 {
    narf_memory::PhysAddr::new(phys).kernel_mut_ptr::<u64>()
}

#[inline]
fn pt_index(iova: u64, level: u8) -> usize {
    ((iova >> (12 + 9 * (level as u32 - 1))) & 0x1FF) as usize
}

/// Software walk of a [`PT_LEVELS`]-level table rooted at `root`:
/// the leaf PTE translating `iova`, if present. Lock-free read of
/// hardware-visible memory (what the IOMMU would see), for backends
/// and tests.
pub fn walk(format: PageTableFormat, root: u64, iova: u64) -> Option<u64> {
    let mut table = root;
    let mut level = PT_LEVELS;
    loop {
        // SAFETY: `table` is a page-table frame owned by a live
        // `IoPageTable` (callers pass a root they hold), reached
        // through the kernel direct map; index < 512.
        let pte = unsafe { core::ptr::read_volatile(pt_ptr(table).add(pt_index(iova, level))) };
        if !format.present(pte) {
            return None;
        }
        if level == 1 {
            return Some(pte);
        }
        table = pte & PTE_OA_MASK;
        level -= 1;
    }
}

/// One domain's page table: frames owned here, freed on drop.
#[derive(Debug)]
struct IoPageTable {
    format: PageTableFormat,
    coherent: bool,
    root: u64,
    /// Every table frame including `root`, for teardown.
    frames: alloc::vec::Vec<u64>,
}

impl IoPageTable {
    fn new(format: PageTableFormat, coherent: bool) -> Result<Self, IoError> {
        let mut pt = Self {
            format,
            coherent,
            root: 0,
            frames: alloc::vec::Vec::new(),
        };
        pt.root = pt.alloc_table()?;
        Ok(pt)
    }

    fn alloc_table(&mut self) -> Result<u64, IoError> {
        let frame = narf_memory::alloc_pages_on(0, 0)?;
        let phys = frame.start_address().raw();
        let ptr = pt_ptr(phys);
        // SAFETY: freshly allocated, exclusively owned 4 KiB frame.
        unsafe { core::ptr::write_bytes(ptr as *mut u8, 0, 4096) };
        if !self.coherent {
            crate::cache_clean(ptr as usize, ptr as usize + 4096);
        }
        self.frames.push(phys);
        Ok(phys)
    }

    fn store(&self, table: u64, index: usize, pte: u64) {
        // SAFETY: `table` is one of `self.frames`; index < 512.
        let slot = unsafe { pt_ptr(table).add(index) };
        // SAFETY: as above; a single aligned 64-bit store is atomic to
        // the walker (Linux `WRITE_ONCE`).
        unsafe { core::ptr::write_volatile(slot, pte) };
        if !self.coherent {
            crate::cache_clean(slot as usize, slot as usize + 8);
        }
    }

    fn load(table: u64, index: usize) -> u64 {
        // SAFETY: `table` is an owned table frame; index < 512.
        unsafe { core::ptr::read_volatile(pt_ptr(table).add(index)) }
    }

    /// Install one 4 KiB leaf. `NotMapped` if a leaf already exists.
    fn map_page(&mut self, iova: u64, phys: u64, perms: IommuPerms) -> Result<(), IoError> {
        let mut table = self.root;
        let mut level = PT_LEVELS;
        while level > 1 {
            let idx = pt_index(iova, level);
            let pte = Self::load(table, idx);
            table = if self.format.present(pte) {
                pte & PTE_OA_MASK
            } else {
                let next = self.alloc_table()?;
                // The zeroed child is visible before the parent points
                // at it (store ordering + clean above).
                core::sync::atomic::fence(Ordering::Release);
                self.store(table, idx, self.format.table_entry(level, next));
                next
            };
            level -= 1;
        }
        let idx = pt_index(iova, 1);
        if self.format.present(Self::load(table, idx)) {
            return Err(IoError::NotMapped);
        }
        self.store(table, idx, self.format.leaf_entry(phys, perms));
        Ok(())
    }

    /// Clear one leaf; `true` if it was present. Intermediate tables are
    /// kept until the domain is destroyed, so a concurrent walk never
    /// follows a freed table (Linux frees them only through the gather
    /// freelist after the IOTLB sync).
    fn unmap_page(&mut self, iova: u64) -> bool {
        let mut table = self.root;
        let mut level = PT_LEVELS;
        while level > 1 {
            let pte = Self::load(table, pt_index(iova, level));
            if !self.format.present(pte) {
                return false;
            }
            table = pte & PTE_OA_MASK;
            level -= 1;
        }
        let idx = pt_index(iova, 1);
        let present = self.format.present(Self::load(table, idx));
        if present {
            self.store(table, idx, 0);
        }
        present
    }
}

impl Drop for IoPageTable {
    fn drop(&mut self) {
        for &phys in &self.frames {
            narf_memory::free_pages(
                narf_memory::PhysFrame::new(narf_memory::PhysAddr::new(phys)),
                0,
            );
        }
    }
}

/// Live per-domain translation state.
#[derive(Debug)]
struct Paging {
    hw: HwRef,
    pt: IoPageTable,
    iova: crate::iova::IovaAllocator,
    attached: alloc::vec::Vec<Bdf>,
}

#[derive(Clone, Copy)]
struct HwRef(&'static dyn IommuHw);

impl fmt::Debug for HwRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.name())
    }
}

impl Paging {
    fn new(hw: &'static dyn IommuHw) -> Result<Self, IoError> {
        let pt = IoPageTable::new(hw.format(), hw.coherent_walk())?;
        let mut iova = crate::iova::IovaAllocator::new(1, 1u64 << (PT_IOVA_BITS - 12));
        // Linux `iommu_dma_get_resv_regions` / vendor `get_resv_regions`:
        // the x86 interrupt window 0xfee0_0000..=0xfeef_ffff is never DMA
        // (AMD `MSI_RANGE_START/END`, Intel `IOAPIC_RANGE_START/END`).
        iova.reserve(0xfee0_0000 >> 12, 0xfeef_ffff >> 12);
        if hw.format() == PageTableFormat::AmdV1 {
            // AMD `HT_RANGE_START/END`: HyperTransport reserved window.
            iova.reserve(0xfd_0000_0000 >> 12, 0xff_ffff_ffff >> 12);
        }
        Ok(Self {
            hw: HwRef(hw),
            pt,
            iova,
            attached: alloc::vec::Vec::new(),
        })
    }

    /// Reserve `m` in the IOVA space and map it 1:1 (pages already mapped
    /// identically are kept). Ranges above [`crate::amd_vi::MAX_DIRECT_MAP_BYTES`]
    /// or outside the table's IOVA width are refused (`NoMemory` /
    /// `OutOfIova`).
    fn map_direct(&mut self, m: DirectMapping) -> Result<(), IoError> {
        if m.end <= m.start || m.perms == IommuPerms::NONE {
            return Ok(());
        }
        let (lo, hi) = (m.start >> 12, (m.end - 1) >> 12);
        if hi >= 1u64 << (PT_IOVA_BITS - 12) {
            return Err(IoError::OutOfIova);
        }
        if m.end - m.start > crate::amd_vi::MAX_DIRECT_MAP_BYTES {
            return Err(IoError::NoMemory);
        }
        self.iova.reserve(lo, hi);
        for pfn in lo..=hi {
            let iova = pfn << 12;
            if let Some(pte) = walk(self.pt.format, self.pt.root, iova) {
                if pte & PTE_OA_MASK == iova {
                    continue;
                }
                return Err(IoError::DomainMismatch);
            }
            self.pt.map_page(iova, iova, m.perms)?;
        }
        Ok(())
    }

    /// Clear `pages` leaves at `pfn`, invalidate, then free the IOVA.
    /// Linux `__iommu_dma_unmap` (strict): `iommu_unmap_fast` →
    /// `iommu_iotlb_sync` → `iommu_dma_free_iova`. A failed flush
    /// quarantines the IOVA instead of freeing it.
    fn teardown(&mut self, domain_id: u16, pfn: u64, pages: u64) -> Result<(), IoError> {
        for i in 0..pages {
            self.pt.unmap_page((pfn + i) << 12);
        }
        // PTE stores are globally visible before the invalidation command
        // is queued (invariant #4 style ordering on the CPU side).
        core::sync::atomic::fence(Ordering::SeqCst);
        match self.hw.0.flush_iotlb(domain_id, pfn << 12, pages << 12) {
            Ok(()) => {
                self.iova.free(pfn);
                Ok(())
            }
            Err(e) => {
                self.iova.quarantine(pfn);
                Err(e)
            }
        }
    }
}

/// Per-domain IOVA → phys page-table state.
///
/// In `Disabled` / `Identity` mode the domain is a thin counter — every
/// `map` returns `iova == phys`. In [`IommuMode::PerDomain`] the first
/// `map`/`attach` builds a page table in the registered backend's
/// [`PageTableFormat`] and an [`crate::iova::IovaAllocator`]; `map`
/// then returns a real IOVA and `unmap` runs
/// unmap → invalidate → wait → free IOVA.
#[derive(Debug)]
pub struct IommuDomain {
    /// Per-IOMMU domain ID (16-bit AMD-Vi / Intel VT-d field).
    domain_id: u16,
    /// Number of live `map` operations. Tests assert balance.
    mappings: core::sync::atomic::AtomicUsize,
    /// Attached device count.
    devices: core::sync::atomic::AtomicU32,
    /// Per-domain translation, built lazily in `PerDomain` mode.
    paging: IrqSafeSpinLock<Option<Paging>>,
}

impl IommuDomain {
    /// Build a fresh domain with the given 16-bit ID. Per-domain
    /// callers normally use [`default_domain`], which allocates a
    /// never-recycled ID.
    pub const fn new(domain_id: u16) -> Self {
        IommuDomain {
            domain_id,
            mappings: core::sync::atomic::AtomicUsize::new(0),
            devices: core::sync::atomic::AtomicU32::new(0),
            paging: IrqSafeSpinLock::new(None),
        }
    }

    #[inline]
    pub fn domain_id(&self) -> u16 {
        self.domain_id
    }

    #[inline]
    pub fn mapping_count(&self) -> usize {
        self.mappings.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn device_count(&self) -> u32 {
        self.devices.load(Ordering::Relaxed)
    }

    /// Physical address of this domain's top-level table, once
    /// per-domain translation is live.
    pub fn page_table_root(&self) -> Option<(PageTableFormat, u64)> {
        self.paging
            .lock()
            .as_ref()
            .map(|p| (p.pt.format, p.pt.root))
    }

    /// Software translation of `iova` through this domain's table
    /// (`None` when not present). Page offset is preserved.
    pub fn translate(&self, iova: u64) -> Option<(u64, IommuPerms)> {
        let guard = self.paging.lock();
        let p = guard.as_ref()?;
        let pte = walk(p.pt.format, p.pt.root, iova)?;
        Some((
            (pte & PTE_OA_MASK) | (iova & 0xFFF),
            p.pt.format.leaf_perms(pte),
        ))
    }

    /// IOVA pages parked because their invalidation did not complete.
    pub fn quarantined_pages(&self) -> u64 {
        self.paging
            .lock()
            .as_ref()
            .map_or(0, |p| p.iova.quarantined_pages())
    }

    fn with_paging<T>(
        &self,
        f: impl FnOnce(&mut Paging) -> Result<T, IoError>,
    ) -> Result<T, IoError> {
        let mut guard = self.paging.lock();
        if guard.is_none() {
            if self.domain_id == 0 {
                return Err(IoError::DomainMismatch);
            }
            let hw = backend().ok_or(IoError::NotMapped)?;
            *guard = Some(Paging::new(hw)?);
        }
        match guard.as_mut() {
            Some(p) => f(p),
            None => Err(IoError::NotMapped),
        }
    }

    /// Attach a device to this domain. In identity mode this is
    /// bookkeeping. In per-domain mode the backend points the device's
    /// DTE / context entry at this domain's page-table root and
    /// invalidates its cached entry before this returns (Linux
    /// `amd_iommu_attach_device` / `intel_iommu_attach_device`). A
    /// device already attached to any domain is `DomainMismatch`.
    pub fn attach(&self, bdf: Bdf) -> Result<(), IoError> {
        if mode() == IommuMode::PerDomain {
            self.with_paging(|p| {
                let mut attached = ATTACHED.lock();
                if attached.iter().any(|(b, _)| *b == bdf) {
                    return Err(IoError::DomainMismatch);
                }
                for m in p.hw.0.direct_mappings(bdf) {
                    p.map_direct(m)?;
                }
                core::sync::atomic::fence(Ordering::SeqCst);
                p.hw.0.attach(bdf, self.domain_id, p.pt.root, PT_LEVELS)?;
                attached.push((bdf, self.domain_id));
                p.attached.push(bdf);
                Ok(())
            })?;
        }
        self.devices.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Inverse of [`Self::attach`]. In per-domain mode the backend
    /// blocks the device and flushes its device entry + IOTLB before the
    /// device is forgotten.
    pub fn detach(&self, bdf: Bdf) -> Result<(), IoError> {
        {
            let mut guard = self.paging.lock();
            if let Some(p) = guard.as_mut() {
                let pos = p
                    .attached
                    .iter()
                    .position(|b| *b == bdf)
                    .ok_or(IoError::NotMapped)?;
                p.hw.0.detach(bdf, self.domain_id)?;
                p.attached.swap_remove(pos);
                ATTACHED.lock().retain(|(b, _)| *b != bdf);
            }
        }
        let prev = self.devices.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            self.devices.fetch_add(1, Ordering::Relaxed);
            return Err(IoError::NotMapped);
        }
        Ok(())
    }

    /// Map `len` bytes at host-physical `phys` into IOVA `iova`
    /// with the given perms. Identity mode requires
    /// `iova == phys` (or `iova == 0` meaning "let the IOMMU pick"
    /// — we resolve that to `phys` too). Per-domain mode: `iova == 0`
    /// allocates an IOVA (see [`Self::map_below`]); a non-zero `iova`
    /// must be free and page-aligned with the same page offset as
    /// `phys`. Returns the actual IOVA the caller should hand to the
    /// device.
    pub fn map(&self, iova: u64, phys: u64, len: u64, perms: IommuPerms) -> Result<u64, IoError> {
        if len == 0 {
            return Err(IoError::NotMapped);
        }
        if perms == IommuPerms::NONE {
            return Err(IoError::NotMapped);
        }
        let resolved = match mode() {
            IommuMode::Disabled => phys,
            IommuMode::Identity => {
                // In identity mode the IOVA *is* the physical
                // address. `iova == 0` means "let the IOMMU pick".
                if iova != 0 && iova != phys {
                    return Err(IoError::NotMapped);
                }
                phys
            }
            IommuMode::PerDomain => return self.map_paged(iova, phys, len, perms, u64::MAX, false),
        };
        self.mappings.fetch_add(1, Ordering::Relaxed);
        Ok(resolved)
    }

    /// Per-domain `map` with an IOVA allocated so the whole range lies at
    /// or below `dma_mask` (Linux `iommu_dma_alloc_iova`). For PCI
    /// devices (`pci = true`) a 32-bit IOVA is tried first, as Linux does
    /// unless `iommu.forcedac`. Outside `PerDomain` this is
    /// [`Self::map`] with `iova = 0`.
    pub fn map_below(
        &self,
        phys: u64,
        len: u64,
        perms: IommuPerms,
        dma_mask: u64,
        pci: bool,
    ) -> Result<u64, IoError> {
        if mode() != IommuMode::PerDomain {
            return self.map(0, phys, len, perms);
        }
        if len == 0 || perms == IommuPerms::NONE {
            return Err(IoError::NotMapped);
        }
        self.map_paged(0, phys, len, perms, dma_mask, pci)
    }

    fn map_paged(
        &self,
        iova: u64,
        phys: u64,
        len: u64,
        perms: IommuPerms,
        dma_mask: u64,
        pci: bool,
    ) -> Result<u64, IoError> {
        let offset = phys & 0xFFF;
        let pages = (offset.checked_add(len).ok_or(IoError::OutOfIova)?).div_ceil(4096);
        let phys_base = phys & !0xFFF;
        let out = self.with_paging(|p| {
            let pfn = if iova != 0 {
                if iova & 0xFFF != offset || !p.iova.alloc_fixed(iova >> 12, pages) {
                    return Err(IoError::OutOfIova);
                }
                iova >> 12
            } else {
                let limit = dma_mask >> 12;
                let low = if pci && limit > (u32::MAX as u64 >> 12) {
                    p.iova.alloc(pages, u32::MAX as u64 >> 12, true)
                } else {
                    None
                };
                low.or_else(|| p.iova.alloc(pages, limit, true))
                    .ok_or(IoError::OutOfIova)?
            };
            for i in 0..pages {
                if let Err(e) = p.pt.map_page((pfn + i) << 12, phys_base + (i << 12), perms) {
                    // Undo the pages already made visible: clear,
                    // invalidate, then release (or quarantine) the IOVA.
                    let _ = p.teardown(self.domain_id, pfn, pages);
                    return Err(e);
                }
            }
            core::sync::atomic::fence(Ordering::SeqCst);
            if let Err(e) = p.hw.0.sync_map(self.domain_id, pfn << 12, pages << 12) {
                let _ = p.teardown(self.domain_id, pfn, pages);
                return Err(e);
            }
            Ok((pfn << 12) | offset)
        })?;
        self.mappings.fetch_add(1, Ordering::Relaxed);
        Ok(out)
    }

    /// Unmap the mapping that starts at IOVA `iova`. Identity mode
    /// just decrements the counter. Per-domain mode clears the PTEs,
    /// invalidates the IOTLB and waits for completion, and only then
    /// frees the IOVA; if the invalidation fails the IOVA is quarantined
    /// and the error returned — the caller must then also keep the
    /// backing frames out of reuse. `len` is ignored in per-domain mode:
    /// the allocator records the mapping's size (Linux `iova_size`).
    pub fn unmap(&self, iova: u64, _len: u64) -> Result<(), IoError> {
        if mode() == IommuMode::PerDomain {
            let mut guard = self.paging.lock();
            let p = guard.as_mut().ok_or(IoError::NotMapped)?;
            let pfn = iova >> 12;
            let pages = p.iova.range_pages(pfn).ok_or(IoError::NotMapped)?;
            p.teardown(self.domain_id, pfn, pages)?;
        }
        let prev = self.mappings.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            self.mappings.fetch_add(1, Ordering::Relaxed);
            return Err(IoError::NotMapped);
        }
        Ok(())
    }
}

impl Drop for IommuDomain {
    fn drop(&mut self) {
        // A domain with attached devices must not lose its tables: the
        // hardware may still walk them. Leak instead (fail closed).
        let paging = self.paging.lock().take();
        if let Some(p) = paging {
            if !p.attached.is_empty() {
                core::mem::forget(p);
            }
        }
    }
}

/// Free-function map for code that doesn't yet hold an
/// `IommuDomain`. Identity mode: returns `phys`. Per-domain mode maps
/// through `bdf`'s default domain ([`default_domain`]); `NotMapped` if
/// the device has none.
pub fn iommu_map(
    bdf: Bdf,
    iova: u64,
    phys: u64,
    len: u64,
    perms: IommuPerms,
) -> Result<u64, IoError> {
    if len == 0 {
        return Err(IoError::NotMapped);
    }
    match mode() {
        IommuMode::Disabled => Ok(phys),
        IommuMode::Identity => {
            if iova != 0 && iova != phys {
                return Err(IoError::NotMapped);
            }
            Ok(phys)
        }
        IommuMode::PerDomain => default_domain_of(bdf)
            .ok_or(IoError::NotMapped)?
            .map(iova, phys, len, perms),
    }
}

/// Free-function unmap. In identity mode this is a no-op; in
/// per-domain mode it unmaps from `bdf`'s default domain with the
/// unmap → invalidate → wait → free-IOVA ordering.
pub fn iommu_unmap(bdf: Bdf, iova: u64, len: u64) -> Result<(), IoError> {
    match mode() {
        IommuMode::Disabled | IommuMode::Identity => Ok(()),
        IommuMode::PerDomain => default_domain_of(bdf)
            .ok_or(IoError::NotMapped)?
            .unmap(iova, len),
    }
}

/// Attach `device` (PCI BDF) to `domain` — mirrors
/// `iommu::attach(domain, device)` in the brief. Forwards to
/// [`IommuDomain::attach`]; the free-function form is the
/// shape drivers see when they get a domain handle from the
/// kernel allocator.
pub fn attach(domain: &IommuDomain, device: Bdf) -> Result<(), IoError> {
    domain.attach(device)
}

/// Inverse of [`attach`].
pub fn detach(domain: &IommuDomain, device: Bdf) -> Result<(), IoError> {
    domain.detach(device)
}
