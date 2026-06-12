//! PCI probe + BAR map + chip family detection.
//!
//! ## References
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nouveau_drm.c`**
//!   `nouveau_drm_probe()` — Nouveau's PCI bring-up entry: claim
//!   the device, map BARs, read PMC_BOOT_0 to detect family.
//! - **`drivers/gpu/drm/nouveau/nvkm/device/pci.c`** —
//!   `nvkm_device_pci_func` (BAR mapping helpers).
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mc/base.c`** — the
//!   PMC_BOOT_0 read in `nvkm_mc_oneinit` / `nvkm_device_ctor`.
//!
//! NARF's `narf-driver-runtime` provides `map_bar()` that produces
//! a kernel-mapped `MmioRegion` from a PCI BAR index, mirroring
//! Nouveau's `pci_resource_*` / `ioremap` pair.
//!
//! ## BAR layout
//!
//! Per `nvkm_device_ctor`:
//!
//! - **BAR0** — 16 MiB MMIO register window. Holds every register
//!   block (PMC, PFIFO, PDISP, PGRAPH, PMU, GSP, …).
//! - **BAR1** — GPU-visible system aperture. Variable size; up to
//!   VRAM total on discrete cards. The host CPU writes pushbuffers
//!   here; the GPU reads them out.
//! - **BAR3** — instance-memory window. Used for indirect access
//!   to PRAMIN; on Turing+ the GSP/Falcons use it as their
//!   firmware DMA target.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, AtomicU32, Ordering};

use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

use crate::chip::{chip_info_for_pci_id, ChipFamily, ChipInfo, NVIDIA_VENDOR, PCI_CLASS_DISPLAY};
use crate::mc::Boot0;

// ── BAR indices (per nvkm_device_pci/pci.c) ─────────────────────

/// BAR0 — register window. Cited
/// `drivers/gpu/drm/nouveau/nvkm/device/pci.c::nvkm_device_pci_map`.
pub const BAR_REGS: u8 = 0;
/// BAR1 — GPU-visible aperture into system memory.
pub const BAR_BAR1: u8 = 1;
/// BAR3 — instance-memory window (sometimes BAR2 on older parts).
pub const BAR_BAR3: u8 = 3;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// The vendor field on the BusDevice wasn't NVIDIA.
    NotNvidia,
    /// Vendor was NVIDIA but the device id isn't in `KNOWN_DEVICES`.
    UnknownAsic,
    /// `map_bar` failed for one of the required BARs.
    BarMapFailed,
    /// `PMC_BOOT_0` read as all-ones / zero — device gone.
    DeviceGone,
    /// `PMC_BOOT_0[24:20]` doesn't match a family the driver
    /// supports (we target Maxwell+; pre-Maxwell rejected here).
    UnsupportedFamily(u8),
}

/// Mapped-and-detected per-device state after a successful probe.
#[derive(Debug)]
pub struct NvidiaDevice {
    pub chip: ChipInfo,
    /// Decoded `PMC_BOOT_0`.
    pub boot0: Boot0,
    pub regs: MmioRegion,
    pub bar1: MmioRegion,
    pub bar3: Option<MmioRegion>,
    /// Stable per-card index. Assigned monotonically by `probe`; used
    /// by upper layers to refer to a specific card without holding a
    /// raw `Arc<NvidiaCard>`. Mirrors Nouveau's `drm_dev_register`
    /// dev->primary->index.
    pub card_index: u32,
    /// PCI device descriptor — needed by tear-down + AER recovery so
    /// `bus::pcie_recovery::register_error_callback` can be re-called
    /// after a slot reset.
    pub bus_device: BusDevice,
}

impl NvidiaDevice {
    /// Map the three BARs, sample `PMC_BOOT_0`, and verify the
    /// silicon-reported family matches a generation the driver
    /// can drive.
    ///
    /// # Safety
    /// Caller owns the BARs exclusively for the lifetime of the
    /// returned device. `cap` is the bus-device write capability;
    /// it gates `pci_cfg_write` if the driver chooses to flip
    /// PCI command bits, but the BAR mapping itself happens via
    /// `map_bar` which is the kernel-side identity-mapping path.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
        card_index: u32,
    ) -> Result<Self, ProbeError> {
        if device.id.vendor != NVIDIA_VENDOR {
            return Err(ProbeError::NotNvidia);
        }
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(ProbeError::UnknownAsic)?;

        // SAFETY: per this fn's `# Safety`, the caller owns `device`'s BARs
        // exclusively for the device lifetime, so mapping BAR_REGS is sound.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let regs = unsafe { map_bar(device, BAR_REGS) }.map_err(|_| ProbeError::BarMapFailed)?;
        // SAFETY: same caller-asserted exclusive BAR ownership; BAR_BAR1 is a
        // distinct BAR of the same `device` and is mapped at most once here.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let bar1 = unsafe { map_bar(device, BAR_BAR1) }.map_err(|_| ProbeError::BarMapFailed)?;
        // BAR3 is best-effort — older Maxwell/Pascal parts don't
        // expose a separate instance window via BAR3.
        // SAFETY: same.
        let bar3 = unsafe { map_bar(device, BAR_BAR3) }.ok();

        // Sample PMC_BOOT_0. Read-only.
        // SAFETY: regs is an identity-mapped MMIO window we just
        // captured; offset 0 is the universal PMC_BOOT_0 register.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let boot0_raw = unsafe { regs.read32(crate::mc::PMC_BOOT_0) };
        compiler_fence(Ordering::SeqCst);
        if !Boot0::looks_present(boot0_raw) {
            return Err(ProbeError::DeviceGone);
        }
        let boot0 = Boot0::decode(boot0_raw);

        // Maxwell+ is the supported range. Reject anything older or
        // unrecognised so the driver can't mis-program a pre-Maxwell
        // chip whose registers don't match.
        match boot0.family {
            ChipFamily::Maxwell
            | ChipFamily::Pascal
            | ChipFamily::Volta
            | ChipFamily::Turing
            | ChipFamily::Ampere
            | ChipFamily::Ada => {}
            ChipFamily::Unknown(n) => return Err(ProbeError::UnsupportedFamily(n)),
            ChipFamily::Fermi | ChipFamily::Kepler => {
                return Err(ProbeError::UnsupportedFamily(boot0.family.arch_version()));
            }
        }

        Ok(Self {
            chip,
            boot0,
            regs,
            bar1,
            bar3,
            card_index,
            bus_device: *device,
        })
    }
}

// ── One-controller-per-board (multi-card) ───────────────────────
//
// NARF's bus layer drives `probe()` per matched device. Each call
// to `probe` allocates a fresh card and pushes it onto the global
// list. Upper layers reach into the list by card index.
//
// Cited Nouveau: `drm_dev_register` allocates a fresh dev per
// matched PCI function, and `nouveau_drm_device_init` keys all
// per-card state off `drm->dev->primary->index`.

/// One owned card. `Arc` so callers can keep a handle independent
/// of the list mutex.
pub type NvidiaCard = NvidiaDevice;

static CONTROLLER: IrqSafeSpinLock<Vec<Arc<NvidiaCard>>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_CARD_INDEX: AtomicU32 = AtomicU32::new(0);

/// `nvkm_device_pci_new` analogue. Called once per PCI match.
/// Multi-card: every successful probe pushes a fresh card onto the
/// global list.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != NVIDIA_VENDOR {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    // Refuse duplicate enumeration of the same PCI function (the
    // bus layer can hit a vendor match and a class match for the
    // same device). Keyed by BusAddr.
    {
        let list = CONTROLLER.lock();
        if list.iter().any(|c| c.bus_device.addr == device.addr) {
            return Ok(());
        }
    }
    // Turn on memory + bus-mastering. Nouveau does this in
    // `pci_enable_device`; we set the bits explicitly through the
    // bus-cap interface.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let card_index = NEXT_CARD_INDEX.fetch_add(1, Ordering::SeqCst);
    // SAFETY: caller-authority on the BusDevice + cap.
    let dev = match unsafe { NvidiaDevice::bring_up(&device, &cap, card_index) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    let card = Arc::new(dev);

    // Register PCIe-AER recovery for this card. Stage 1 callback;
    // pieces of the driver flesh it out further down.
    crate::pcie_recovery::register_for_card(&card);

    CONTROLLER.lock().push(card);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("nvidia"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

/// Register the driver with the bus match table — one entry per
/// known device id, plus a class-match backstop. The probe body
/// filters by vendor so AMD/Intel VGA controllers are rejected.
pub fn register_pci_driver() {
    for (name, did) in crate::chip::KNOWN_DEVICES.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: NVIDIA_VENDOR,
                device: did,
            },
            probe,
        });
    }
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "nvidia-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_DISPLAY,
            mask: 0xFF,
        },
        probe,
    });
}

/// `true` if at least one board has been mounted by the driver.
pub fn is_probed() -> bool {
    !CONTROLLER.lock().is_empty()
}

/// Number of bound cards.
pub fn card_count() -> usize {
    CONTROLLER.lock().len()
}

/// Borrow the first bound card, if any. Convenience that mirrors the
/// pre-Stage-6 single-controller API; new code should prefer
/// `with_card`.
pub fn with_controller<R>(f: impl FnOnce(&NvidiaDevice) -> R) -> Option<R> {
    CONTROLLER.lock().first().map(|c| f(c.as_ref()))
}

/// Borrow a specific bound card by index. `None` if no card with
/// that index exists (either out-of-range or unbound).
pub fn with_card<R>(index: u32, f: impl FnOnce(&NvidiaDevice) -> R) -> Option<R> {
    let list = CONTROLLER.lock();
    list.iter()
        .find(|c| c.card_index == index)
        .map(|c| f(c.as_ref()))
}

/// Clone an `Arc<NvidiaCard>` so the caller can keep a handle past
/// the list mutex (e.g. for an IRQ handler or AER callback).
pub fn card_arc(index: u32) -> Option<Arc<NvidiaCard>> {
    let list = CONTROLLER.lock();
    list.iter().find(|c| c.card_index == index).cloned()
}

/// Snapshot the list of currently bound card indices.
pub fn card_indices() -> Vec<u32> {
    CONTROLLER.lock().iter().map(|c| c.card_index).collect()
}

/// Test helper — wipe the bound-cards list. Production driver code
/// never calls this; the unit tests build the list, then peel it
/// down to keep hermetic per-test state.
#[doc(hidden)]
pub fn __reset_for_test() {
    CONTROLLER.lock().clear();
    NEXT_CARD_INDEX.store(0, Ordering::SeqCst);
}
