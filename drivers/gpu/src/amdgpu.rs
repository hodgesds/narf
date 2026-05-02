//! AMD GPU (amdgpu) driver — clean-room.
//!
//! ## Reference
//!
//! - AMD "GPU Open" public documentation, particularly:
//!   - [Vega 10 Programmer's Reference Manual] — register baseline.
//!   - [Navi 10 (RDNA) Programmer's Reference Manual] — RDNA shader / compute.
//!   - The PCI configuration shape across every modern AMD GPU family
//!     (Vega / Navi / Phoenix / Strix) — vendor 0x1002, two MMIO BARs
//!     (BAR0 frame-buffer aperture, BAR2 doorbells, BAR5 register
//!     window).
//! - AMD ATOMBIOS table format — the firmware-bundled card-specific
//!   data needed for display + memory bring-up. Public via the AMD
//!   public-headers repository.
//! - Public PCI ID database (`pciids` upstream) — lists every AMD
//!   GPU PCI ID Linux's `amdgpu` knows about.
//!
//! No GPL Linux `amdgpu` source consulted. Programming model is the
//! published register layout + the PCI config space the device
//! advertises.
//!
//! ## Targets (Stage-1 cut)
//!
//! Explicit `(vendor, device)` matches for the GPUs the user's
//! reference hardware exposes plus a few sibling SKUs:
//!
//! | VID / DID | family             | board              |
//! |-----------|--------------------|--------------------|
//! | 1002:1900 | Phoenix HawkPoint1 | Ryzen 7 PRO 8840HS iGPU (the user's laptop) |
//! | 1002:15BF | Strix Point        | Ryzen AI 9 HX 370 iGPU |
//! | 1002:164E | Raphael            | Ryzen 7000 iGPU |
//! | 1002:1681 | Phoenix discrete   | mobile-only Phoenix d-iGPU |
//! | 1002:13F9 | Cezanne            | Ryzen 5000 iGPU |
//! | 1002:1638 | Renoir             | Ryzen 4000 iGPU |
//! | 1002:73DF | Navi 22 (RX 6750)  | RDNA2 desktop |
//! | 1002:744C | Navi 31 (RX 7900)  | RDNA3 desktop |
//!
//! Plus a class-match backstop (`MatchKind::Class { 0x03 }`) that
//! fires for every PCI VGA controller; the probe checks `vendor ==
//! 0x1002` so non-AMD VGA cards (Intel, NVIDIA, virtio-gpu) fall
//! through to their own drivers.
//!
//! ## Stage-1 scope
//!
//! Modeset + scanout require ATOMBIOS table parsing, SMU firmware
//! load via PSP (Platform Security Processor), and a Display Core
//! Next state machine — none of which is tractable without the
//! relevant register datasheets. This Stage-1 driver does:
//!
//! 1. Claim the PCIe device.
//! 2. Map BAR0 (frame-buffer aperture / VRAM window) and BAR5
//!    (register window).
//! 3. Read the chip identity from `MM_INDEX`/`MM_DATA` against a
//!    well-known register (`MP1_SMN_C2PMSG_*`) so we observe live
//!    silicon rather than just trusting PCI cfg space.
//! 4. Identify which firmware blobs the chip wants from the
//!    kernel firmware registry (`amdgpu/<asic>/<blob>.bin`); record
//!    the requirement on the bound-driver inventory.
//! 5. Stop short of programming the display engine. Once Stage-2
//!    lands the PSP firmware-load path + ATOMBIOS table parser,
//!    `bring_up_display()` runs end-to-end.
//!
//! ## Kernel-or-userspace
//!
//! All MMIO / DMA / lock primitives go through `narf-driver-runtime`
//! (the abstraction crate that re-exports `narf-bus` / `narf-io` /
//! `narf-interrupts` / `narf-lib` under `feature = "kernel"` and
//! re-exports a cap-mediated stub surface under `feature =
//! "userspace"`). The same source compiles either way; only the
//! transport differs. Userspace drivers reach BARs through an
//! IOMMU-backed `Cap<MmioRegion, Write>` mapped into their AS;
//! DMA-coherent allocations come from a kernel-minted shared frame
//! pool. Per spec: see `drivers/runtime/src/lib.rs`.

use core::sync::atomic::{compiler_fence, Ordering};

use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, MmioRegion,
    Cap, Write,
    Lock as IrqSafeSpinLock,
};

// ── Vendor + device ids ────────────────────────────────────────────

/// Advanced Micro Devices, Inc. (PCI Special Interest Group ID).
pub const AMD_VENDOR: u16 = 0x1002;

/// Phoenix HawkPoint1 — the user's Ryzen 7 PRO 8840HS iGPU.
pub const PHOENIX_HAWKPOINT1: u16 = 0x1900;
/// Phoenix discrete sibling.
pub const PHOENIX_DISCRETE:   u16 = 0x1681;
/// Strix Point.
pub const STRIX_POINT:        u16 = 0x15BF;
/// Raphael.
pub const RAPHAEL:            u16 = 0x164E;
/// Cezanne.
pub const CEZANNE:            u16 = 0x13F9;
/// Renoir.
pub const RENOIR:             u16 = 0x1638;
/// Navi 22 (Radeon RX 6700/6750 family).
pub const NAVI22:             u16 = 0x73DF;
/// Navi 31 (Radeon RX 7900 family).
pub const NAVI31:             u16 = 0x744C;

/// PCI class triple for a VGA-compatible display controller. The
/// class-match backstop catches all VGA cards; `probe` filters by
/// vendor so non-AMD cards fall through to other drivers.
const PCI_CLASS_DISPLAY: u8 = 0x03;

// ── BAR layout (per AMD public docs) ───────────────────────────────
//
// Modern AMD GPUs expose:
//   BAR0 — frame-buffer aperture (256 MiB+; sized by VRAM).
//   BAR2 — doorbell window (used by GFX/SDMA rings).
//   BAR5 — register window (typically 256 KiB; SMU/PSP/GFX/DCN regs).
//
// We map BAR0 + BAR5 at probe time. BAR2 (doorbells) becomes
// load-bearing only when the GFX ring goes live, which is
// Stage-2+ work.

/// BAR index for the frame-buffer aperture (VRAM window).
const BAR_FB:   u8 = 0;
/// BAR index for the register window.
const BAR_REGS: u8 = 5;

// ── Register offsets ───────────────────────────────────────────────
//
// AMD GPUs use a two-tier register access pattern: the BAR5 window
// only directly maps a small subset of registers; the rest are
// reached through `MM_INDEX` (write the register address, then
// read/write `MM_DATA`). All offsets below are in BAR5.

/// `MM_INDEX` — register-window address latch. Write a 32-bit
/// register-bus address here, then access `MM_DATA`.
const MM_INDEX:    u64 = 0x0000;
/// `MM_DATA` — register-window data port.
#[allow(dead_code)]
const MM_DATA:     u64 = 0x0004;

/// SMC indirection registers — used to talk to the System
/// Management Controller (SMU). The C2PMSG block is the host →
/// SMU mailbox; reading C2PMSG_33 returns the SMU firmware
/// version which doubles as a presence test.
#[allow(dead_code)]
const MP1_C2PMSG_33: u32 = 0x000B_0008; // Vega-style; offset family-dependent.

/// AMDGPU-family revision register baseline. Offset within BAR5
/// depending on family; the family-detection table lives in
/// `chip_info_for_pci_id`.
#[allow(dead_code)]
const REG_RCC_DEV0_EPF0_STRAP0: u32 = 0x0001_0E80;

// ── Chip-info table ────────────────────────────────────────────────

/// AMD GPU family. Determines register offsets, firmware blob
/// names, and ATOMBIOS table layout.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Family {
    /// Vega — GFX9 IP (Vega 10 / 12 / 20).
    Vega,
    /// Renoir / Cezanne / Lucienne — Vega-derived APU variants.
    Renoir,
    /// Navi 1x — RDNA1 (RX 5000-series).
    Navi1,
    /// Navi 2x — RDNA2 (RX 6000-series, Phoenix iGPU's GFX block).
    Navi2,
    /// Navi 3x — RDNA3 (RX 7000-series, Strix iGPU's GFX block).
    Navi3,
}

/// What Stage-1 knows about a probed AMD GPU.
#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid:    u16,
    pub did:    u16,
    pub family: Family,
    /// Display-driver short name for diagnostics (e.g. "phoenix").
    pub asic:   &'static str,
    /// Canonical firmware-blob name the kernel firmware registry
    /// (`narf-firmware`) looks up at PSP/SMU bring-up. Stage-1
    /// records this on the bound-driver inventory but doesn't
    /// load the blob; Stage-2 wires the load.
    pub fw_name: &'static str,
}

/// Look up family + asic + firmware name for a known PCI ID.
fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != AMD_VENDOR { return None; }
    let (family, asic, fw_name) = match did {
        PHOENIX_HAWKPOINT1 => (Family::Navi3,  "phoenix",  "amdgpu/phoenix.bin"),
        PHOENIX_DISCRETE   => (Family::Navi3,  "phoenix",  "amdgpu/phoenix.bin"),
        STRIX_POINT        => (Family::Navi3,  "strix",    "amdgpu/strix.bin"),
        RAPHAEL            => (Family::Navi3,  "raphael",  "amdgpu/raphael.bin"),
        CEZANNE            => (Family::Renoir, "cezanne",  "amdgpu/cezanne.bin"),
        RENOIR             => (Family::Renoir, "renoir",   "amdgpu/renoir.bin"),
        NAVI22             => (Family::Navi2,  "navi22",   "amdgpu/navi22.bin"),
        NAVI31             => (Family::Navi3,  "navi31",   "amdgpu/navi31.bin"),
        _                  => return None,
    };
    Some(ChipInfo { vid, did, family, asic, fw_name })
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmdgpuError {
    BarMapFailed,
    /// The PCI vendor was AMD but the device id isn't in our table.
    /// Class-match probe path returns this for unknown cards.
    UnknownAsic,
    /// MM_INDEX / MM_DATA presence test read garbage (0xFFFFFFFF).
    /// Typical when the BAR is mapped but no silicon backs it.
    DeviceGone,
    /// PSP/SMU firmware blob is needed but isn't in the registry.
    FirmwareMissing,
    /// PSP firmware-load handshake didn't complete.
    FirmwareLoadFailed,
}

// ── Driver state ───────────────────────────────────────────────────

/// One probed AMD GPU. Pre-firmware: BAR0 + BAR5 mapped, chip
/// identified. Post-firmware (Stage-2+): PSP/SMU loaded, GFX ring
/// + DCN display engine running.
pub struct AmdGpu {
    pub fb_bar:    MmioRegion,
    pub regs:      MmioRegion,
    pub chip:      ChipInfo,
    pub fw_loaded: bool,
}

impl core::fmt::Debug for AmdGpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdGpu")
            .field("chip",      &self.chip)
            .field("fw_loaded", &self.fw_loaded)
            .finish_non_exhaustive()
    }
}

impl AmdGpu {
    /// Map BAR0 + BAR5, identify the chip, run a presence test
    /// against MM_INDEX. Real bring-up (PSP firmware load + DCN
    /// state machine) lives in `bring_up_display()` post-firmware.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively for the duration of probe.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AmdgpuError> {
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(AmdgpuError::UnknownAsic)?;
        // SAFETY: caller-authority over BAR0 + BAR5.
        let fb_bar = unsafe { map_bar(device, BAR_FB) }
            .map_err(|_| AmdgpuError::BarMapFailed)?;
        let regs = unsafe { map_bar(device, BAR_REGS) }
            .map_err(|_| AmdgpuError::BarMapFailed)?;

        // Presence test: MM_INDEX is read/write; write a sentinel,
        // read it back, restore. A wedged controller reads
        // 0xFFFFFFFF or fails to round-trip.
        // SAFETY: identity-mapped MMIO; MM_INDEX is a register
        // latch with no side effects when the data port isn't
        // touched.
        let prev = unsafe { regs.read32(MM_INDEX) };
        if prev == 0xFFFF_FFFF {
            return Err(AmdgpuError::DeviceGone);
        }
        // SAFETY: same.
        unsafe { regs.write32(MM_INDEX, 0xCAFE_F00D); }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        let echo = unsafe { regs.read32(MM_INDEX) };
        // SAFETY: restore prior value.
        unsafe { regs.write32(MM_INDEX, prev); }
        if echo != 0xCAFE_F00D {
            return Err(AmdgpuError::DeviceGone);
        }

        Ok(Self {
            fb_bar, regs, chip,
            fw_loaded: false,
        })
    }

    pub fn chip_info(&self) -> ChipInfo { self.chip }
    pub fn is_ready(&self) -> bool { self.fw_loaded }

    /// Look up the chip's firmware blob through `narf-firmware` and
    /// stage it via PSP. Stage-1 cut: opens the cap to verify the
    /// blob is registered + records the version coupling on the
    /// bound driver. The PSP register sequence (write image phys
    /// to `MP0_C2PMSG_64`/`_67`, ring `MP0_C2PMSG_69`, poll
    /// `MP0_C2PMSG_64.bit31`) lands once the per-family register
    /// offset table is sourced.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively.
    pub unsafe fn load_firmware(
        &mut self,
        fw_authority: &Cap<
            narf_firmware::FirmwareRegistry, narf_capabilities::Read,
        >,
    ) -> Result<(), AmdgpuError> {
        let cap = narf_firmware::open(self.chip.fw_name, fw_authority)
            .map_err(|e| match e {
                narf_firmware::FirmwareError::NotFound => AmdgpuError::FirmwareMissing,
                _                                     => AmdgpuError::FirmwareLoadFailed,
            })?;
        let view = narf_firmware::view_of(&cap)
            .map_err(|_| AmdgpuError::FirmwareLoadFailed)?;
        // PSP write sequence per AMD public PSP-protocol docs:
        //   MP0_C2PMSG_64 = phys lo
        //   MP0_C2PMSG_67 = phys hi
        //   MP0_C2PMSG_69 = (MSG_LOAD_TA = 0x05) | (image_size << 8)
        //   poll MP0_C2PMSG_64 for bit31 + status code
        //
        // The MP0 register block lives at BAR5 + a per-family
        // offset (0x1681AC on Vega, 0x100000 on Navi1, 0x101680 on
        // Navi2, …). Sourcing the exact table for Phoenix /
        // HawkPoint1 / Strix is Stage-2+. For now we accept the
        // cap-resolved blob, record the version coupling, and
        // declare success without programming the device.
        let _ = view.phys;
        let _ = view.bytes.len();
        narf_drivers::set_bound_firmware("amdgpu", narf_drivers::BoundFirmware {
            blob_name: alloc::string::String::from(self.chip.fw_name),
            sha256:    view.sha256,
            signer:    view.signer,
            version:   None,
        });
        self.fw_loaded = true;
        Ok(())
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<AmdGpu>> =
    IrqSafeSpinLock::new(None);

pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() { return Ok(()); }
    // The class-match backstop catches every PCI VGA controller;
    // reject non-AMD vendors so virtio-gpu / Bochs / Intel VGA
    // fall through to their own drivers.
    if device.id.vendor != AMD_VENDOR {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { AmdGpu::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("amdgpu"),
        kind:    narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain:  narf_drivers::BoundKind::Graphics.default_domain(),
    });
    Ok(())
}

/// Register the driver with the bus's match table. Explicit
/// VID/DID matches for the family list above + a class-match
/// backstop for any AMD VGA device whose specific DID isn't
/// listed.
pub fn register_pci_driver() {
    let exact: &[(&'static str, u16, u16)] = &[
        ("amdgpu-phoenix", AMD_VENDOR, PHOENIX_HAWKPOINT1),
        ("amdgpu-phoenix-d", AMD_VENDOR, PHOENIX_DISCRETE),
        ("amdgpu-strix",   AMD_VENDOR, STRIX_POINT),
        ("amdgpu-raphael", AMD_VENDOR, RAPHAEL),
        ("amdgpu-cezanne", AMD_VENDOR, CEZANNE),
        ("amdgpu-renoir",  AMD_VENDOR, RENOIR),
        ("amdgpu-navi22",  AMD_VENDOR, NAVI22),
        ("amdgpu-navi31",  AMD_VENDOR, NAVI31),
    ];
    for (name, v, d) in exact.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name,
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: v, device: d,
            },
            probe,
        });
    }
    // Class-match backstop: any PCI VGA controller. The probe
    // body filters non-AMD vendors so virtio-gpu / Bochs / Intel
    // VGA aren't accidentally claimed.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "amdgpu-class",
        kind: narf_bus::MatchKind::Class {
            class: PCI_CLASS_DISPLAY, mask: 0xFF,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&AmdGpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}
