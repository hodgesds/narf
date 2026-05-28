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

use core::sync::atomic::{compiler_fence, Ordering};

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
    ) -> Result<Self, ProbeError> {
        if device.id.vendor != NVIDIA_VENDOR {
            return Err(ProbeError::NotNvidia);
        }
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(ProbeError::UnknownAsic)?;

        // SAFETY: caller-asserted exclusive ownership of these BARs.
        let regs = unsafe { map_bar(device, BAR_REGS) }
            .map_err(|_| ProbeError::BarMapFailed)?;
        let bar1 = unsafe { map_bar(device, BAR_BAR1) }
            .map_err(|_| ProbeError::BarMapFailed)?;
        // BAR3 is best-effort — older Maxwell/Pascal parts don't
        // expose a separate instance window via BAR3.
        // SAFETY: same.
        let bar3 = unsafe { map_bar(device, BAR_BAR3) }.ok();

        // Sample PMC_BOOT_0. Read-only.
        // SAFETY: regs is an identity-mapped MMIO window we just
        // captured; offset 0 is the universal PMC_BOOT_0 register.
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
        })
    }
}

// ── One-controller-per-board ────────────────────────────────────
//
// NARF's bus layer drives `probe()` per matched device. The
// driver state goes into a global to mirror the singleton shape
// most of the kernel's bound drivers use. Multi-GPU systems will
// want a Vec<NvidiaDevice> here; that's a follow-up.

static CONTROLLER: IrqSafeSpinLock<Option<NvidiaDevice>> = IrqSafeSpinLock::new(None);

/// `nvkm_device_pci_new` analogue. Called once per PCI match.
pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        // Single-GPU singleton today.
        return Ok(());
    }
    if device.id.vendor != NVIDIA_VENDOR {
        return Err(narf_bus::ProbeError::BadDevice);
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
    // SAFETY: caller-authority on the BusDevice + cap.
    let dev = match unsafe { NvidiaDevice::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
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

/// `true` if a board has been mounted by the driver.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Borrow the controller state.
pub fn with_controller<R>(f: impl FnOnce(&NvidiaDevice) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
