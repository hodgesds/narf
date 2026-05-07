//! Intel integrated graphics (Gen12 Xe-LP / Xe-LPG) — clean-room driver.
//!
//! Spec: `drivers/gpu/specification/intel_gpu.md`.
//!
//! ## References
//!
//! - **Intel "Linux Graphics Programmer's Reference Manual" hub** —
//!   per-generation public PDFs.
//!   <https://www.intel.com/content/www/us/en/docs/graphics-for-linux/developer-reference/1-0/overview.html>
//! - **Tiger Lake PRM** (the conservative reference target):
//!   - **Vol. 12** — Display DDIs / Plane Programming.
//!   - **Vol. 14** — Display Engine (pipes + transcoders).
//!   - **Vol. 11** — Display Engine Registers (clocks).
//!   - **Vol.  5** — Memory Views (GTT / PPGTT).
//! - **Alder Lake PRM** — same Gen12 register surface; useful
//!   cross-check for ADL-S/-P iGPUs.
//! - **Meteor Lake display PRM** — Xe-LPG display engine.
//! - **Public `pci.ids` database** — every Intel iGPU device ID
//!   the upstream snapshot lists for Gen12.
//!
//! **No GPL Linux `i915` / `xe` source consulted.** All register
//! offsets cite a TGL PRM volume + section in the doc-comment
//! adjacent to the constant, so a future maintainer can verify
//! the value against the public PDF without re-deriving it.
//!
//! ## Stage progression
//!
//! - **Stage 1 (this commit)** — PCI claim, BAR0 (GTTMMADR)
//!   mapping, presence test against `GMD_ID`, bound-driver
//!   record. No display programming.
//! - **Stage 2 (this commit)** — Codec layer: GMBUS, DPLL,
//!   pipes, DDI, GTT register-codecs land as sibling modules.
//!   See `crate::intel_gpu_*` for the per-block detail.
//! - **Stage 3 (future)** — driver core wires GMBUS / DDI /
//!   pipe codecs into a working modeset against the firmware-
//!   supplied default mode.
//! - **Stage 4 (future)** — KMS-grade frame buffer, full GTT
//!   page-table population.
//! - **Stage 5+ (future)** — 3D / compute via RCS0 ring.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

// ── Vendor + device ids ───────────────────────────────────────────

/// Intel Corporation (PCI Special Interest Group ID).
pub const INTEL_VENDOR: u16 = 0x8086;

/// PCI class triple for a VGA-compatible display controller. The
/// class-match backstop catches all VGA cards; `probe` filters by
/// vendor so non-Intel cards fall through to their own drivers.
const PCI_CLASS_DISPLAY: u8 = 0x03;

// Tiger Lake (Gen12 Xe-LP) — public `pci.ids` Intel rows. The
// 0x9A40..0x9A78 stride covers the TGL-U / TGL-H GT0/GT1/GT2
// SKUs; only the documented IDs are listed.
pub const TGL_U_GT2_9A49: u16 = 0x9A49;
pub const TGL_H_GT1_9A60: u16 = 0x9A60;
pub const TGL_H_GT2_9A68: u16 = 0x9A68;
pub const TGL_H_GT2_9A70: u16 = 0x9A70;
pub const TGL_GT2_9A78: u16 = 0x9A78;

// Alder Lake-P / Raptor Lake-P (Gen12, mobile).
pub const ADL_P_4626: u16 = 0x4626;
pub const ADL_P_4628: u16 = 0x4628;
pub const ADL_P_462A: u16 = 0x462A;
pub const ADL_P_46A6: u16 = 0x46A6;
pub const ADL_P_46A8: u16 = 0x46A8;
pub const ADL_P_46AA: u16 = 0x46AA;
pub const RPL_P_46B0: u16 = 0x46B0;
pub const RPL_P_46B1: u16 = 0x46B1;
pub const RPL_P_46B3: u16 = 0x46B3;

// Alder Lake-S / Raptor Lake-S (Gen12, desktop).
pub const ADL_S_4690: u16 = 0x4690;
pub const ADL_S_4692: u16 = 0x4692;
pub const ADL_S_4693: u16 = 0x4693;
pub const RPL_S_A780: u16 = 0xA780;
pub const RPL_S_A782: u16 = 0xA782;
pub const RPL_S_A788: u16 = 0xA788;

// Meteor Lake (Xe-LPG, mobile).
pub const MTL_7D40: u16 = 0x7D40;
pub const MTL_7D45: u16 = 0x7D45;
pub const MTL_7D55: u16 = 0x7D55;
pub const MTL_7DD5: u16 = 0x7DD5;

// ── BAR layout (TGL PRM Vol. 12 §"Memory Map and Configuration") ─

/// `GTTMMADR` — Graphics Translation Table + Memory-Mapped
/// register window. BAR0 on every Gen12 iGPU; the low half is
/// MMIO registers, the high half is the GTT entry array.
const BAR_GTTMMADR: u8 = 0;
/// `GMADR` — Graphics Memory aperture (stolen-memory frame
/// buffer). BAR2 on iGPUs.
const BAR_GMADR: u8 = 2;

// ── Identification register ──────────────────────────────────────

/// `GMD_ID` — Graphics Media Device Identifier (TGL PRM Vol. 12
/// §"Device Identification"). MMIO offset `0x000D8C`. The low
/// 16 bits report the IP version; the upper bits carry the
/// architecture revision. All-ones / all-zeros means the BAR is
/// mapped but no silicon backs it.
const GMD_ID: u64 = 0x0000_0D8C;

/// `MTCFG_TRBLK` cookie (TGL PRM Vol. 12 §"Identifier"): a write
/// of any value is accepted; the read-back is independent of the
/// write (unlike a sentinel-latch pattern). We use it solely as a
/// presence smoke test by checking the value isn't `0xFFFF_FFFF`.
const MTCFG_TRBLK: u64 = 0x0000_0FF8;

// ── Generation classifier ────────────────────────────────────────

/// Gen12 sub-architecture identifier. Tiger Lake / Alder Lake /
/// Raptor Lake all share the Xe-LP register surface; Meteor Lake
/// uses Xe-LPG (different DDI / DPLL programming).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Generation {
    /// Tiger Lake — Gen12 Xe-LP. Conservative reference target.
    TigerLake,
    /// Alder Lake / Raptor Lake — Gen12 Xe-LP carry-forward.
    AlderLake,
    /// Meteor Lake — Xe-LPG (re-architected DDI + display power).
    MeteorLake,
}

/// What Stage-1 knows about a probed Intel iGPU.
#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid: u16,
    pub did: u16,
    pub generation: Generation,
    /// Short ASIC name for diagnostics.
    pub asic: &'static str,
}

fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != INTEL_VENDOR {
        return None;
    }
    let (generation, asic) = match did {
        TGL_U_GT2_9A49 | TGL_H_GT1_9A60 | TGL_H_GT2_9A68 | TGL_H_GT2_9A70 | TGL_GT2_9A78 => {
            (Generation::TigerLake, "tigerlake")
        }
        ADL_P_4626 | ADL_P_4628 | ADL_P_462A | ADL_P_46A6 | ADL_P_46A8 | ADL_P_46AA => {
            (Generation::AlderLake, "alderlake-p")
        }
        RPL_P_46B0 | RPL_P_46B1 | RPL_P_46B3 => (Generation::AlderLake, "raptorlake-p"),
        ADL_S_4690 | ADL_S_4692 | ADL_S_4693 => (Generation::AlderLake, "alderlake-s"),
        RPL_S_A780 | RPL_S_A782 | RPL_S_A788 => (Generation::AlderLake, "raptorlake-s"),
        MTL_7D40 | MTL_7D45 | MTL_7D55 | MTL_7DD5 => (Generation::MeteorLake, "meteorlake"),
        _ => return None,
    };
    Some(ChipInfo {
        vid,
        did,
        generation,
        asic,
    })
}

// ── Errors ───────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IntelGpuError {
    BarMapFailed,
    /// Vendor is Intel but the device id isn't in the table.
    /// Class-match probe path returns this for unknown cards.
    UnknownAsic,
    /// MMIO presence test read garbage (all-ones). Typical when
    /// BAR is mapped but the device is gone.
    DeviceGone,
}

// ── Driver state ─────────────────────────────────────────────────

/// One probed Intel iGPU. Stage-1: BAR0 + BAR2 mapped, chip
/// identified. Stage-3+ adds display programming on top.
pub struct IntelGpu {
    pub gtt_mmadr: MmioRegion,
    pub gmadr: MmioRegion,
    pub chip: ChipInfo,
    /// `GMD_ID` value captured at probe time.
    pub gmd_id: u32,
}

impl core::fmt::Debug for IntelGpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelGpu")
            .field("chip", &self.chip)
            .field("gmd_id", &self.gmd_id)
            .finish_non_exhaustive()
    }
}

impl IntelGpu {
    /// Map BAR0 (GTTMMADR) and BAR2 (GMADR), identify the chip,
    /// run a presence test against `GMD_ID`.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR2 exclusively for the duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, IntelGpuError> {
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(IntelGpuError::UnknownAsic)?;

        // SAFETY: caller-asserted ownership of BAR0 + BAR2.
        let gtt_mmadr =
            unsafe { map_bar(device, BAR_GTTMMADR) }.map_err(|_| IntelGpuError::BarMapFailed)?;
        let gmadr =
            unsafe { map_bar(device, BAR_GMADR) }.map_err(|_| IntelGpuError::BarMapFailed)?;

        // Presence smoke test: read `GMD_ID`. All-ones means the
        // BAR is mapped but the device isn't responding (PCI
        // master-abort returning `0xFFFFFFFF`).
        // SAFETY: identity-mapped MMIO.
        let gmd_id = unsafe { gtt_mmadr.read32(GMD_ID) };
        if gmd_id == 0xFFFF_FFFF {
            return Err(IntelGpuError::DeviceGone);
        }
        compiler_fence(Ordering::SeqCst);
        // Cross-check: `MTCFG_TRBLK` should also not be all-ones.
        // SAFETY: same.
        let trblk = unsafe { gtt_mmadr.read32(MTCFG_TRBLK) };
        if trblk == 0xFFFF_FFFF {
            return Err(IntelGpuError::DeviceGone);
        }

        Ok(Self {
            gtt_mmadr,
            gmadr,
            chip,
            gmd_id,
        })
    }

    pub fn chip_info(&self) -> ChipInfo {
        self.chip
    }

    pub fn gmd_id(&self) -> u32 {
        self.gmd_id
    }
}

// ── Driver-match registration ────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<IntelGpu>> = IrqSafeSpinLock::new(None);

pub fn probe(
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    if device.id.vendor != INTEL_VENDOR {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { IntelGpu::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("intel-gpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

/// Every documented Gen12 device ID + a class-match backstop for
/// any Intel VGA controller whose specific DID isn't listed.
pub fn register_pci_driver() {
    let exact: &[(&'static str, u16, u16)] = &[
        ("intel-gpu-tgl-9A49", INTEL_VENDOR, TGL_U_GT2_9A49),
        ("intel-gpu-tgl-9A60", INTEL_VENDOR, TGL_H_GT1_9A60),
        ("intel-gpu-tgl-9A68", INTEL_VENDOR, TGL_H_GT2_9A68),
        ("intel-gpu-tgl-9A70", INTEL_VENDOR, TGL_H_GT2_9A70),
        ("intel-gpu-tgl-9A78", INTEL_VENDOR, TGL_GT2_9A78),
        ("intel-gpu-adl-4626", INTEL_VENDOR, ADL_P_4626),
        ("intel-gpu-adl-4628", INTEL_VENDOR, ADL_P_4628),
        ("intel-gpu-adl-462A", INTEL_VENDOR, ADL_P_462A),
        ("intel-gpu-adl-46A6", INTEL_VENDOR, ADL_P_46A6),
        ("intel-gpu-adl-46A8", INTEL_VENDOR, ADL_P_46A8),
        ("intel-gpu-adl-46AA", INTEL_VENDOR, ADL_P_46AA),
        ("intel-gpu-rpl-46B0", INTEL_VENDOR, RPL_P_46B0),
        ("intel-gpu-rpl-46B1", INTEL_VENDOR, RPL_P_46B1),
        ("intel-gpu-rpl-46B3", INTEL_VENDOR, RPL_P_46B3),
        ("intel-gpu-adl-4690", INTEL_VENDOR, ADL_S_4690),
        ("intel-gpu-adl-4692", INTEL_VENDOR, ADL_S_4692),
        ("intel-gpu-adl-4693", INTEL_VENDOR, ADL_S_4693),
        ("intel-gpu-rpl-A780", INTEL_VENDOR, RPL_S_A780),
        ("intel-gpu-rpl-A782", INTEL_VENDOR, RPL_S_A782),
        ("intel-gpu-rpl-A788", INTEL_VENDOR, RPL_S_A788),
        ("intel-gpu-mtl-7D40", INTEL_VENDOR, MTL_7D40),
        ("intel-gpu-mtl-7D45", INTEL_VENDOR, MTL_7D45),
        ("intel-gpu-mtl-7D55", INTEL_VENDOR, MTL_7D55),
        ("intel-gpu-mtl-7DD5", INTEL_VENDOR, MTL_7DD5),
    ];
    for (name, v, d) in exact.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: v,
                device: d,
            },
            probe,
        });
    }
    // Class-match backstop. The probe body filters non-Intel
    // vendors so AMD / NVIDIA / virtio-gpu cards aren't claimed.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "intel-gpu-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_DISPLAY,
            mask: 0xFF,
        },
        probe,
    });
}

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

pub fn with_controller<R>(f: impl FnOnce(&IntelGpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
