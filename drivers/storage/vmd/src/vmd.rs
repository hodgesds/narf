//! Intel VMD (Volume Management Device) bridge enumeration.
//!
//! Stage-0 cut: identify the VMD bridge by Intel device-ID, map BAR0
//! (the VMD-private config-space window), and walk it as if it were
//! a standard PCIe ECAM region. Every discovered function gets pushed
//! into the global `narf-bus` registry tagged with a synthetic
//! `segment` so its (B, D, F) key cannot collide with the host
//! PCIe domain. From there, existing drivers (NVMe, etc.) can be
//! bound by a later `probe_all_pci` pass — but Stage-0 stops at
//! enumerate + log; no child probe is triggered from here.
//!
//! Spec / reference: Linux `drivers/pci/controller/vmd.c`. The pieces
//! we reproduce are the PCI ID table (vmd_ids[]), the `VMD_CFGBAR`
//! BAR0 mapping convention, and `vmd_cfg_addr`'s
//! `PCIE_ECAM_OFFSET(bus, devfn, reg)` math — identical to the
//! standard ECAM `(bus << 20) | (devfn << 12) | reg` layout used by
//! `narf_bus::pcie::enumerate_segment`.
//!
//! Hardware shape (from Linux `vmd.c` + Intel docs):
//! - PCI class = 0x010400 (mass storage / RAID-class shell — the real
//!   device behind it is the bridge, not a RAID controller, but the
//!   class code makes VMD discoverable to OSes that filter by class).
//! - BAR0 = `VMD_CFGBAR`, a config-space window for the children
//!   (`resource_size(BAR0) >> 20` gives the bus count covered).
//! - BAR2 = `VMD_MEMBAR1`, BAR4 = `VMD_MEMBAR2` — MMIO windows for
//!   the children's BAR resources. Stage-0 doesn't touch these; the
//!   children's BARs are still readable through the cfg window and
//!   the BIOS / UEFI firmware will have programmed them already on
//!   real silicon. (Stage-1 / NVMe binding deals with them.)
//!
//! What Stage-0 does NOT do (deferred):
//! - MSI remapping / IRQ domain setup. VMD owns its own MSI and
//!   forwards children's MSI through it; this is the gnarly bit.
//!   Wired in a follow-up that touches `interrupts/` for the
//!   MSI-remap shape.
//! - Resource offsets (`VMD_FEAT_HAS_MEMBAR_SHADOW`,
//!   `VMD_FEAT_HAS_MEMBAR_SHADOW_VSCAP`) — only matter when the host
//!   wants to address children's MMIO from outside; Stage-0's
//!   enumerate-only path doesn't need them.
//! - Bus-number restrictions (`VMD_FEAT_HAS_BUS_RESTRICTIONS`) —
//!   restricts to 0-127 / 128-255 / 224-255 on certain SKUs. The
//!   BAR0 walk on Stage-0 simply scans every bus the BAR size
//!   accounts for, so it's tolerant of the restriction.
//! - Child probe re-trigger. The user wants Stage-0 to stop at
//!   "log how many children we found"; binding NVMe to them is the
//!   next stage and needs VMD-domain addressing in `read_bar` etc.

use core::sync::atomic::{AtomicU32, Ordering};

use narf_bus::{
    append_devices, map_bar, register_pci_driver, BusDevice, BusDeviceCap, MatchKind, MmioRegion,
    PciMatch, ProbeError,
};
use narf_capabilities::{Cap, Write};

/// Intel PCI vendor ID.
pub const INTEL_VENDOR: u16 = 0x8086;

/// VMD device-ID table — every PCI ID Intel ships VMD bridges under.
/// Sourced from `vmd_pci_tbl[]` in Linux `drivers/pci/controller/vmd.c`.
pub const VMD_DEVICE_IDS: &[(u16, &str)] = &[
    (0x201D, "vmd-original"), // VMD (older)
    (0x28C0, "vmd-skylake-x"),
    (0x467F, "vmd-comet-lake"),
    (0x4C3D, "vmd-rocket-alder-lake-p"),
    (0x7D0B, "vmd-raptor-lake"),
    (0x9A0B, "vmd-tiger-lake"),
    (0xA77F, "vmd-meteor-lake"),
    (0xAD0B, "vmd-tiger-lake-h"),
];

/// BAR index conventions per Linux `vmd.c` §25-27.
pub const VMD_CFGBAR: u8 = 0;
#[allow(dead_code)]
pub const VMD_MEMBAR1: u8 = 2;
#[allow(dead_code)]
pub const VMD_MEMBAR2: u8 = 4;

/// VMD-domain segment numbers start here. Real ACPI _SEG values are
/// `0..0xFFFF` per ACPI 6.5 §6.5.6, but in practice they're tiny
/// (single digits on every laptop we care about); reserving the high
/// half keeps VMD synthetic segments from colliding. Mirrors Linux's
/// `pci_bus_find_emul_domain_nr(0, 0x10000, INT_MAX)` choice.
pub const VMD_SEGMENT_BASE: u16 = 0x8000;

/// Counter of detected VMD bridges. Used to allocate a unique segment
/// per bridge so a multi-VMD system (workstations) keeps each domain
/// distinct in the registry.
static VMD_INSTANCE_COUNT: AtomicU32 = AtomicU32::new(0);

/// Counter of successfully enumerated child devices — diagnostic +
/// test-observable signal that the walk ran.
static VMD_CHILDREN_FOUND: AtomicU32 = AtomicU32::new(0);

/// Errors from VMD bring-up. Kept minimal at Stage-0 — every variant
/// folds to `ProbeError::BadDevice` in `probe`, but the typed surface
/// makes the smoke tests' assertions readable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmdError {
    /// BAR0 wasn't mappable — typically means the bridge is in legacy
    /// (non-VMD) mode and the BIOS didn't expose the config window.
    BarMapFailed,
    /// BAR0 size doesn't make sense (< 1 MiB so doesn't even cover one
    /// child bus, or > 256 MiB which is the full PCIe range).
    BarSizeOutOfRange,
}

/// One discovered VMD bridge + its enumeration state.
#[derive(Debug)]
pub struct Vmd {
    /// PCI device-ID of the bridge itself (one of `VMD_DEVICE_IDS`).
    pub device_id: u16,
    /// The CFGBAR mapping — children's config space lives here.
    pub cfgbar: MmioRegion,
    /// Synthetic PCI segment we allocated for this bridge's children.
    pub segment: u16,
    /// Number of buses the CFGBAR covers: `size / 0x10_0000`.
    pub n_buses: u16,
    /// Children we enumerated + injected into the global registry.
    pub children: alloc::vec::Vec<BusDevice>,
}

impl Vmd {
    /// Bring up the VMD bridge: map BAR0, walk it, append discovered
    /// children to the bus registry.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 exclusively. `map_bar` enforces
    /// the standard PCIe sizing dance which writes briefly to cfg
    /// space.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VmdError> {
        // Map BAR0 (CFGBAR). SAFETY: caller-authority over the device.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cfgbar = unsafe { map_bar(device, VMD_CFGBAR) }.map_err(|_| VmdError::BarMapFailed)?;

        // BAR size determines how many child buses we can cover.
        // Linux `vmd.c` uses `resource_size(BAR0) >> 20` for the
        // same calculation (1 MiB per bus, the standard ECAM stride).
        let size = cfgbar.len;
        let n_buses_full = (size >> 20) as u64;
        if n_buses_full == 0 || n_buses_full > 256 {
            return Err(VmdError::BarSizeOutOfRange);
        }
        let n_buses = n_buses_full as u16;

        // Allocate a unique segment for this bridge.
        let inst = VMD_INSTANCE_COUNT.fetch_add(1, Ordering::AcqRel);
        let segment = VMD_SEGMENT_BASE.wrapping_add(inst as u16);

        // Walk the CFGBAR as if it were a standard ECAM region. The
        // shared `enumerate_segment` does exactly this — same per-
        // function 4 KiB stride, same vendor-ID sentinel checks.
        // SAFETY: cfgbar.phys is identity-mapped (Stage-3 invariant)
        // and we promised it's a real config window above.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let children = unsafe { narf_bus::pcie::enumerate_segment(cfgbar.phys, n_buses, segment) };

        Ok(Self {
            device_id: device.id.device,
            cfgbar,
            segment,
            n_buses,
            children,
        })
    }

    /// Inject this bridge's discovered children into the global
    /// `narf-bus` registry so the next `probe_all_pci` pass (or a
    /// targeted lookup) can find them.
    pub fn install_children(&self) {
        if !self.children.is_empty() {
            append_devices(self.children.clone());
            VMD_CHILDREN_FOUND.fetch_add(self.children.len() as u32, Ordering::AcqRel);
        }
    }

    /// Number of children this bridge has — useful for tests +
    /// post-probe logging.
    pub fn child_count(&self) -> usize {
        self.children.len()
    }
}

/// Per-driver `probe` invoked by the bus driver-match dispatcher
/// once a matching device is discovered.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), ProbeError> {
    // Defensive double-check: the match table only registers exact
    // VendorDevice entries for the eight Intel VMD IDs, but a future
    // edit might add a class backstop (VMD exposes class 0x010400
    // which is shared by some Intel RAID controllers). Filtering
    // again here keeps the probe behaviour stable across that kind
    // of registry edit.
    if device.id.vendor != INTEL_VENDOR {
        return Err(ProbeError::NotForThisDriver);
    }
    if !VMD_DEVICE_IDS.iter().any(|(d, _)| *d == device.id.device) {
        return Err(ProbeError::NotForThisDriver);
    }

    // Enable MEM_SPACE + BUS_MASTER so the bridge's BARs decode and
    // the children behind them can DMA. Same shape as the AHCI / NVMe
    // probes.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::BUS_MASTER,
    )
    .map_err(|_| ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let vmd = match unsafe { Vmd::bring_up(&device, &cap) } {
        Ok(v) => v,
        Err(_) => return Err(ProbeError::BadDevice),
    };
    vmd.install_children();

    // Stage-0 announce. Mirrors the i915 / nvme probe announce lines.
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "vmd: detected DID={:#06x} BAR0={:#018x} {} child devices found (segment={:#06x}, buses={})",
            vmd.device_id,
            vmd.cfgbar.phys.raw(),
            vmd.child_count(),
            vmd.segment,
            vmd.n_buses,
        );
    }

    // VMD is a PCIe bridge, not a Block / Net / etc. device — it
    // discovers children but doesn't itself terminate I/O. Use the
    // `Other` bucket; a follow-up may grow `BoundKind` with a
    // `BusBridge` variant once VMD + Thunderbolt + USB-bridge
    // controllers share enough behaviour to deserve it.
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-vmd"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });
    Ok(())
}

/// Register the VMD driver with the bus-level match table. Trusted
/// in-tree drivers call this from a Stage::Device initcall.
///
/// Registration shape:
/// - Explicit `(0x8086, DID)` matches for every known VMD device ID,
///   so the bus tie-breaker prefers them at full specificity even
///   against the NVMe-class backstop.
pub fn register_pci_driver_vmd() {
    for (did, name) in VMD_DEVICE_IDS.iter().copied() {
        register_pci_driver(PciMatch {
            name,
            kind: MatchKind::VendorDevice {
                vendor: INTEL_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// Number of children injected by every VMD bridge that has been
/// probed so far. Test-observable signal that the walk ran.
pub fn children_found() -> u32 {
    VMD_CHILDREN_FOUND.load(Ordering::Acquire)
}

/// Number of VMD bridges detected. Diagnostic — Stage-1 wiring will
/// want this to fan out per-bridge IRQ / resource setup.
pub fn instance_count() -> u32 {
    VMD_INSTANCE_COUNT.load(Ordering::Acquire)
}

#[doc(hidden)]
/// Test-only: reset counters between smokes. Boot path never calls
/// this — the smokes pile up otherwise.
pub fn __reset_for_test() {
    VMD_INSTANCE_COUNT.store(0, Ordering::Release);
    VMD_CHILDREN_FOUND.store(0, Ordering::Release);
}
