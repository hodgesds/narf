//! Intel VMD (Volume Management Device) bridge enumeration, MEMBAR
//! resource windows, and MSI remapping.
//!
//! The driver identifies the VMD bridge by Intel device-ID, maps
//! BAR0 (the VMD-private config-space window), and walks it as if
//! it were a standard PCIe ECAM region. Every discovered function
//! gets pushed into the global `narf-bus` registry tagged with a
//! synthetic `segment` so its (B, D, F) key cannot collide with
//! the host PCIe domain. From there, existing drivers (NVMe, etc.)
//! bind to the children through the same `probe_all_pci` walk that
//! probed this bridge: the walk observes mid-walk appends
//! (bus spec §9.5, issue #933).
//!
//! Spec / reference: Linux `drivers/pci/controller/vmd.c`. The
//! pieces reproduced here are the PCI ID table (`vmd_ids[]`), the
//! `VMD_CFGBAR` mapping convention, `vmd_cfg_addr`'s
//! `PCIE_ECAM_OFFSET(bus, devfn, reg)` math — identical to the
//! standard ECAM `(bus << 20) | (devfn << 12) | reg` layout used by
//! `narf_bus::pcie::enumerate_segment` — plus the two pieces that
//! make children actually usable behind the bridge (issue #933
//! items 3 and 4):
//!
//! - **MEMBAR windows.** BAR2 (`VMD_MEMBAR1`) and BAR4
//!   (`VMD_MEMBAR2`) are the apertures child BARs must decode
//!   inside. Probe decodes both and registers them with
//!   `narf_bus::vmd_domain` before the children are installed, so
//!   BAR assignment draws from the aperture (never the host pool)
//!   and BAR mapping refuses addresses outside it. The programmed
//!   values are already host addresses — Linux hands the apertures
//!   to the child bus with offset 0 on bare metal — so there is no
//!   translation on the path, only containment + allocation.
//!   MEMBAR2's first `0x2000` bytes (the bridge's MSI-X table) are
//!   reserved from child allocation; `0x2010` on the MEMBAR-shadow
//!   server part.
//! - **MSI remapping.** The bridge's own MSI-X table is programmed
//!   with one host vector per entry (capped at
//!   [`VMD_MAX_BRIDGE_VECTORS`]), the demux domain is registered
//!   with `narf_bus::vmd_irq`, and the VMCONFIG `MSI_RMP_DIS` bit
//!   is cleared so remapping is on. Child drivers then program
//!   their MSI/MSI-X exactly as usual — `bus` interposes the
//!   bridge-entry message and the demux re-dispatches to the child
//!   vector when a bridge entry fires. As in current Linux for
//!   every ID in the table below, remapping is always on; the
//!   bypass mode (`VMD_FEAT_CAN_BYPASS_MSI_REMAP`) is a performance
//!   option, never a correctness requirement, and is not used.
//!
//! Child config addressing is *not* deferred: config-space access
//! resolves through each child's `cfg_phys`, which the enumeration
//! captured inside this CFGBAR window, so `set_command` /
//! `read_bar` on a child already land in VMD-domain config space.
//!
//! What remains deferred (none of it blocks children binding and
//! receiving interrupts on bare metal):
//! - Guest resource offsets (`VMD_FEAT_HAS_MEMBAR_SHADOW*` in its
//!   nonzero-offset form): only matter when a hypervisor guest
//!   addresses child MMIO from outside the domain.
//! - Bus-number restrictions (`VMD_FEAT_HAS_BUS_RESTRICTIONS`):
//!   the CFGBAR walk scans every bus the BAR size accounts for,
//!   which is tolerant of the restriction; the VMCONFIG field is
//!   left exactly as firmware programmed it.
//! - The interrupt-ordering erratum on 0x7D0B / 0xAD0B (Linux
//!   `VMD_FEAT_INTERRUPT_QUIRK`): the demux should issue a dummy
//!   config read of the interrupting child before dispatch, lest
//!   posted writes still be in flight. Tracked as a follow-up.

use core::sync::atomic::{AtomicU32, Ordering};

use narf_bus::{
    append_devices, enable_msix, map_bar, read_bar, register_pci_driver, register_pci_remove,
    BarKind, BusDevice, BusDeviceCap, MatchKind, MembarWindow, MmioRegion, PciMatch, ProbeError,
    VmdDomainInfo,
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
pub const VMD_MEMBAR1: u8 = 2;
pub const VMD_MEMBAR2: u8 = 4;

/// Vendor capability header (VMCAP) offset in the bridge's config
/// space; VMCONFIG immediately follows it.
pub const VMD_VMCAP_OFFSET: u16 = 0x40;
/// VMCONFIG register offset.
pub const VMD_VMCONFIG_OFFSET: u16 = 0x44;
/// VMCONFIG bit 1 — MSI_RMP_DIS. When set, child MSIs bypass the
/// remap indexing; remapping (this driver's only mode) keeps it
/// clear. Default after reset is clear, but a previous OS can leave
/// it set across a soft reboot, so probe writes it explicitly.
pub const VMD_VMCONFIG_MSI_REMAP_DISABLE: u32 = 1 << 1;

/// Cap on the host vectors one bridge's remap domain owns. A client
/// bridge's table can advertise far more entries than the host has
/// vectors to give (the pool spans 48..=240); entries past the cap
/// are simply never assigned to a child.
pub const VMD_MAX_BRIDGE_VECTORS: u16 = 64;

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

/// Errors from VMD bring-up. Every variant folds to
/// `ProbeError::BadDevice` in `probe`, but the typed surface makes
/// the smoke tests' assertions readable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VmdError {
    /// BAR0 wasn't mappable — typically means the bridge is in legacy
    /// (non-VMD) mode and the BIOS didn't expose the config window.
    BarMapFailed,
    /// BAR0 size doesn't make sense (< 1 MiB so doesn't even cover one
    /// child bus, or > 256 MiB which is the full PCIe range).
    BarSizeOutOfRange,
    /// Neither MEMBAR window decoded — without an aperture there is
    /// no domain to register, and children could not DMA anyway.
    NoMembar,
    /// Bridge IRQ-domain setup failed (host vectors exhausted, the
    /// bridge's MSI-X table refused programming, or the remap
    /// domain was already registered for the segment).
    IrqSetupFailed,
    /// A VMCONFIG read/write through the cap-gated config path
    /// failed.
    ConfigAccessFailed,
    /// The MEMBAR domain was already registered for the segment.
    DomainRegistrationFailed,
}

/// The Linux `vmd_ids[]` `driver_data` feature bits this driver
/// acts on, distilled per device ID.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct VmdFeatures {
    /// `VMD_FEAT_OFFSET_FIRST_VECTOR` (all client parts): bridge
    /// entry 0 stays unassigned, so child entries start at 1.
    offset_first_vector: bool,
    /// `VMD_FEAT_HAS_MEMBAR_SHADOW` (0x28C0): the shadow register
    /// block extends MEMBAR2's reserved head to `0x2010`.
    membar_shadow: bool,
}

fn features_for(device_id: u16) -> VmdFeatures {
    match device_id {
        0x28C0 => VmdFeatures {
            offset_first_vector: false,
            membar_shadow: true,
        },
        0x467F | 0x4C3D | 0x7D0B | 0x9A0B | 0xA77F | 0xAD0B => VmdFeatures {
            offset_first_vector: true,
            membar_shadow: false,
        },
        // 0x201D (VMD_FEAT_HAS_MEMBAR_SHADOW_VSCAP only) and any
        // future ID the table grows.
        _ => VmdFeatures {
            offset_first_vector: false,
            membar_shadow: false,
        },
    }
}

impl VmdFeatures {
    /// Bytes of MEMBAR2 reserved for the bridge (MSI-X table, plus
    /// the shadow register block on shadow parts).
    fn membar2_reserve(&self) -> u64 {
        if self.membar_shadow {
            narf_bus::vmd_domain::VMD_MEMBAR2_RESERVE_SHADOW
        } else {
            narf_bus::vmd_domain::VMD_MEMBAR2_RESERVE_DEFAULT
        }
    }

    /// First bridge MSI-X entry children may be assigned.
    fn first_vec(&self) -> u16 {
        if self.offset_first_vector {
            1
        } else {
            0
        }
    }
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
    /// BAR2 aperture registered for the children, if decoded.
    pub membar1: Option<MembarWindow>,
    /// BAR4 aperture registered for the children, if decoded.
    pub membar2: Option<MembarWindow>,
    /// Bridge MSI-X entries owned by the remap domain
    /// (0 = bridge exposed no MSI-X; children bind but cannot be
    /// remapped onto a bridge entry).
    pub msix_entries: u16,
}

impl Vmd {
    /// Bring up the VMD bridge: map BAR0, decode the MEMBAR
    /// windows, walk the CFGBAR, set up the MSI remap domain, and
    /// register the resource domain — in that order, so by the time
    /// [`install_children`](Self::install_children) runs, every
    /// child probe observes the full domain.
    ///
    /// # Safety
    /// Caller owns the device's BARs exclusively. `map_bar` enforces
    /// the standard PCIe sizing dance which writes briefly to cfg
    /// space.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, VmdError> {
        // Map BAR0 (CFGBAR). SAFETY: caller-authority over the device.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let cfgbar = unsafe { map_bar(device, VMD_CFGBAR) }.map_err(|_| VmdError::BarMapFailed)?;

        let features = features_for(device.id.device);
        // SAFETY: caller owns the device's cfg space; read_bar only
        // performs the standard sizing dance on the BAR slots.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let membar1 = unsafe { decode_membar(device, VMD_MEMBAR1, 0) };
        // SAFETY: same.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let membar2 = unsafe { decode_membar(device, VMD_MEMBAR2, features.membar2_reserve()) };

        // SAFETY: forwarded exclusivity; `cfgbar` is the mapping
        // this call just made.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { Self::assemble_domain(device, cap, cfgbar, membar1, membar2) }
    }

    /// The assembly half of bring-up, split out so kernel-test
    /// fixtures can drive it with pre-decoded windows: RAM-backed
    /// fake config space cannot emulate the BAR sizing dance
    /// `read_bar` performs (a RAM cell reads back the all-ones probe
    /// value verbatim), so fixtures supply the decoded BAR values
    /// and exercise everything downstream — enumeration, IRQ-domain
    /// setup against the bridge's config/MSI-X table, and domain
    /// registration — through this production code.
    ///
    /// # Safety
    /// Same contract as [`bring_up`](Self::bring_up); `cfgbar` must
    /// be a live mapping of the bridge's CFGBAR window.
    #[doc(hidden)]
    pub unsafe fn assemble_domain(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
        cfgbar: MmioRegion,
        membar1: Option<MembarWindow>,
        membar2: Option<MembarWindow>,
    ) -> Result<Self, VmdError> {
        if membar1.is_none() && membar2.is_none() {
            return Err(VmdError::NoMembar);
        }

        // BAR size determines how many child buses we can cover.
        // Linux `vmd.c` uses `resource_size(BAR0) >> 20` for the
        // same calculation (1 MiB per bus, the standard ECAM stride).
        let size = cfgbar.len;
        let n_buses_full = size >> 20;
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
        // SAFETY: cfgbar.phys is a real config window per the
        // caller's contract above.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let children = unsafe { narf_bus::pcie::enumerate_segment(cfgbar.phys, n_buses, segment) };

        // MSI remap domain next, MEMBAR domain registration last:
        // registration is the point of no return after which child
        // probes may observe the segment, so everything they need
        // must already exist.
        let features = features_for(device.id.device);
        let first_vec = features.first_vec();
        // SAFETY: caller owns the bridge exclusively.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let msix_entries = unsafe { setup_irq_domain(device, cap, segment, first_vec) }?;

        if narf_bus::register_vmd_domain(VmdDomainInfo {
            segment,
            bridge: device.addr,
            membar1,
            membar2,
            msix_entries,
            first_vec,
        })
        .is_err()
        {
            // Roll the IRQ domain back out so a failed registration
            // leaks neither host vectors nor demux handlers.
            narf_bus::unregister_vmd_irq_domain(segment);
            return Err(VmdError::DomainRegistrationFailed);
        }

        Ok(Self {
            device_id: device.id.device,
            cfgbar,
            segment,
            n_buses,
            children,
            membar1,
            membar2,
            msix_entries,
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

/// Decode one bridge MEMBAR into a resource window. A BAR that is
/// unprogrammed, I/O-typed, or fails the sizing dance yields
/// `None` — the domain simply has one fewer aperture.
///
/// # Safety
/// Caller owns the device's cfg space for the sizing dance.
unsafe fn decode_membar(device: &BusDevice, idx: u8, reserve_head: u64) -> Option<MembarWindow> {
    // SAFETY: forwarded by caller.
    // SAFETY: Valid memory or trusted environment
    let bar = unsafe { read_bar(device, idx) }.ok()?;
    match bar.kind {
        BarKind::Mmio32 { .. } | BarKind::Mmio64 { .. } => {
            if bar.phys.raw() == 0 || bar.size == 0 {
                None
            } else {
                Some(MembarWindow::new(bar.phys.raw(), bar.size, reserve_head))
            }
        }
        BarKind::Io => None,
    }
}

/// Set or clear VMCONFIG's MSI_RMP_DIS bit. Read-modify-write: the
/// register also carries the BIOS-owned DID_ASSIGN and
/// BUS_RESTRICTIONS fields, which must survive untouched.
///
/// # Safety
/// Caller owns the bridge's cfg space.
unsafe fn set_msi_remapping(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
    enable: bool,
) -> Result<(), VmdError> {
    let cur = narf_bus::pci::read_config32(cap, device, VMD_VMCONFIG_OFFSET)
        .map_err(|_| VmdError::ConfigAccessFailed)?;
    let new = if enable {
        cur & !VMD_VMCONFIG_MSI_REMAP_DISABLE
    } else {
        cur | VMD_VMCONFIG_MSI_REMAP_DISABLE
    };
    if new != cur {
        narf_bus::pci::write_config32(cap, device, VMD_VMCONFIG_OFFSET, new)
            .map_err(|_| VmdError::ConfigAccessFailed)?;
    }
    Ok(())
}

/// Program the bridge's own MSI-X table with one host vector per
/// entry, enable remapping in VMCONFIG, and register the demux
/// domain. Returns the number of bridge entries the domain owns.
///
/// A bridge without an MSI-X capability is not an error: the
/// domain enumerates and binds children, but no child interrupt can
/// be remapped — reported upward as an entry count of 0.
///
/// # Safety
/// Caller owns the bridge exclusively.
unsafe fn setup_irq_domain(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
    segment: u16,
    first_vec: u16,
) -> Result<u16, VmdError> {
    let mut table = match enable_msix(cap, device) {
        Ok(t) => t,
        Err(_) => return Ok(0),
    };
    let entries = table.size().min(VMD_MAX_BRIDGE_VECTORS);
    if entries == 0 {
        return Ok(0);
    }

    let mut vectors = alloc::vec::Vec::with_capacity(entries as usize);
    for _ in 0..entries {
        match narf_interrupts::vector::alloc() {
            Ok(v) => vectors.push(v),
            Err(_) => {
                for v in &vectors {
                    let _ = narf_interrupts::vector::free(*v);
                }
                return Err(VmdError::IrqSetupFailed);
            }
        }
    }

    // From here on, any failure must hand the vectors back. The IRQ
    // domain takes ownership of them at registration; before that
    // they are this function's to free.
    let mut registered = false;
    let outcome = (|| -> Result<(), VmdError> {
        for (i, &v) in vectors.iter().enumerate() {
            // SAFETY: this probe owns the bridge's MSI-X table; the
            // bridge lives on the host segment, so program_vector
            // takes the native path (no remap interposition).
            // SAFETY: Valid memory or trusted environment
            unsafe { table.program_vector(i as u16, 0, v) }
                .map_err(|_| VmdError::IrqSetupFailed)?;
        }
        // SAFETY: caller owns the bridge's cfg space.
        // SAFETY: Valid memory or trusted environment
        unsafe { set_msi_remapping(cap, device, true) }?;
        narf_bus::register_vmd_irq_domain(segment, first_vec, &vectors)
            .map_err(|_| VmdError::IrqSetupFailed)?;
        registered = true;
        // SAFETY: table entries are programmed and the demux is
        // installed; flipping the MSI-X enable bit is the last step.
        // SAFETY: Valid memory or trusted environment
        unsafe { table.enable() }.map_err(|_| VmdError::IrqSetupFailed)?;
        Ok(())
    })();
    if outcome.is_err() {
        if registered {
            narf_bus::unregister_vmd_irq_domain(segment);
        } else {
            for v in &vectors {
                let _ = narf_interrupts::vector::free(*v);
            }
        }
        return Err(VmdError::IrqSetupFailed);
    }
    Ok(entries)
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

    // Stage-0 announce, extended with the domain shape. Mirrors
    // the i915 / nvme probe announce lines.
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "vmd: detected DID={:#06x} BAR0={:#018x} {} child devices found (segment={:#06x}, buses={}, msix_entries={})",
            vmd.device_id,
            vmd.cfgbar.phys.raw(),
            vmd.child_count(),
            vmd.segment,
            vmd.n_buses,
            vmd.msix_entries,
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

/// Remove hook for a detached bridge: unregister the resource
/// domain and tear down the remap domain (demux handlers removed,
/// host vectors freed). Children keep their own bindings; their
/// remap mappings are released individually by the bus detach path.
fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    if let Some(info) = narf_bus::vmd_domain::domain_for_bridge(device.addr) {
        narf_bus::unregister_vmd_domain(info.segment);
        narf_bus::unregister_vmd_irq_domain(info.segment);
    }
}

/// Register the VMD driver with the bus-level match table. Trusted
/// in-tree drivers call this from a Stage::Device initcall.
///
/// Registration shape:
/// - Explicit `(0x8086, DID)` matches for every known VMD device ID,
///   so the bus tie-breaker prefers them at full specificity even
///   against the NVMe-class backstop.
/// - A remove hook under each match name, so a hot-detach of the
///   bridge tears its domains down (see `remove`).
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
        register_pci_remove(name, remove);
    }
}

/// Number of children injected by every VMD bridge that has been
/// probed so far. Test-observable signal that the walk ran.
pub fn children_found() -> u32 {
    VMD_CHILDREN_FOUND.load(Ordering::Acquire)
}

/// Number of VMD bridges detected. Diagnostic — per-bridge IRQ /
/// resource state lives in the `narf-bus` domain registries.
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
