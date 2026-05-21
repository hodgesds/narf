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

use alloc::vec::Vec;
use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

use crate::amdgpu_discovery::{self, IpBlock};

// ── Vendor + device ids ────────────────────────────────────────────

/// Advanced Micro Devices, Inc. (PCI Special Interest Group ID).
pub const AMD_VENDOR: u16 = 0x1002;

/// Phoenix HawkPoint1 — the user's Ryzen 7 PRO 8840HS iGPU.
pub const PHOENIX_HAWKPOINT1: u16 = 0x1900;
/// Phoenix discrete sibling.
pub const PHOENIX_DISCRETE: u16 = 0x1681;
/// Strix Point.
pub const STRIX_POINT: u16 = 0x15BF;
/// Raphael.
pub const RAPHAEL: u16 = 0x164E;
/// Cezanne.
pub const CEZANNE: u16 = 0x13F9;
/// Renoir.
pub const RENOIR: u16 = 0x1638;
/// Navi 22 (Radeon RX 6700/6750 family).
pub const NAVI22: u16 = 0x73DF;
/// Navi 31 (Radeon RX 7900 family).
pub const NAVI31: u16 = 0x744C;

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
const BAR_FB: u8 = 0;
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
const MM_INDEX: u64 = 0x0000;
/// `MM_DATA` — register-window data port.
const MM_DATA: u64 = 0x0004;

/// MC (Memory Controller) framebuffer-location registers in the
/// register-bus address space. Read through MM_INDEX/MM_DATA to
/// learn the visible-VRAM phys range. Same offsets across Vega +
/// Navi families per the public AMD MC IP block docs.
const MC_VM_FB_LOCATION_BASE: u32 = 0x0000_6B0F;
const MC_VM_FB_LOCATION_TOP: u32 = 0x0000_6B10;

// ── PSP (Platform Security Processor) MP0 mailbox protocol ────────
//
// Firmware-load handshake per AMD public PSP-protocol docs:
//
//   MP0_C2PMSG_64 = phys lo  (image base, low 32 bits)
//   MP0_C2PMSG_67 = phys hi  (image base, high 32 bits)
//   MP0_C2PMSG_69 = (CMD_LOAD_TA = 5) | (image_size << 8)
//   poll MP0_C2PMSG_64 — bit31 set → done; bits[30:0] = status code.
//   status == 0 → success.
//
// All three message slots are register-bus addresses computed
// against the per-family `Family::mp0_base()` offset.
//
// `MP0_C2PMSG_N = mp0_base + 0x29C + N*4`. The 0x29C offset is
// constant; only the `mp0_base` shifts per family.

// PSP MP0 register / command / status constants live in
// `amdgpu_psp` (canonically named LOAD_IP_FW for the value 0x05
// that pre-relicense scaffold mislabelled LOAD_TA). Re-export
// the names load_firmware uses inline below.
use crate::amdgpu_psp::{
    MP0_C2PMSG_64_REL, MP0_C2PMSG_67_REL, MP0_C2PMSG_69_REL,
    PSP_CMD_LOAD_IP_FW, PSP_STATUS_CODE_MASK, PSP_STATUS_DONE_BIT,
};

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
    /// Navi 2x — RDNA2 (RX 6000-series).
    Navi2,
    /// Navi 3x — RDNA3 (RX 7000-series desktop, Navi31/32/33).
    Navi3,
    /// Phoenix / HawkPoint / Strix-Point — Zen4/Zen5 APUs whose
    /// display IP is DCN 3.5 (RDNA 3.5 iGPU). Kept distinct from
    /// `Navi3` because the DCN 3.5 modeset register layout differs
    /// from DCN 3.2 (Navi31): OTG block has shifted V_BLANK /
    /// V_SYNC / OTG_CONTROL / INTERRUPT_CONTROL offsets per
    /// `drivers/gpu/drm/amd/include/asic_reg/dcn/dcn_3_5_0_offset.h`.
    Phoenix,
}

impl Family {
    /// MP0 (PSP) register block base, in BAR5 register-bus
    /// address space. Resolution order:
    ///
    /// 1. Runtime registration via
    ///    `crate::amdgpu_offsets::register_family_offsets`. The
    ///    trusted bootstrap plugs in offsets sourced from the
    ///    AMD PPR for the family.
    /// 2. Compile-time fallbacks for families whose offsets are
    ///    in publicly-documented AMD GPUOpen IP tables (Vega +
    ///    Navi 1).
    /// 3. `None` for families whose offsets need datasheet
    ///    sourcing — `load_firmware` fails closed rather than
    ///    poking the wrong register window.
    pub fn mp0_base(self) -> Option<u32> {
        // Runtime override wins.
        let runtime = crate::amdgpu_offsets::offsets_of(self);
        if let Some(base) = runtime.mp0_base {
            return Some(base);
        }
        // Compile-time fallback for documented families.
        match self {
            Family::Vega => Some(0x000B_0000),
            Family::Navi1 => Some(0x000B_0000),
            Family::Navi2 => None,
            Family::Navi3 => None,
            Family::Renoir => None,
            Family::Phoenix => None,
        }
    }
}

/// What Stage-1 knows about a probed AMD GPU.
#[derive(Copy, Clone, Debug)]
pub struct ChipInfo {
    pub vid: u16,
    pub did: u16,
    pub family: Family,
    /// Display-driver short name for diagnostics (e.g. "phoenix").
    pub asic: &'static str,
    /// Canonical firmware-blob name the kernel firmware registry
    /// (`narf-firmware`) looks up at PSP/SMU bring-up. Stage-1
    /// records this on the bound-driver inventory but doesn't
    /// load the blob; Stage-2 wires the load.
    pub fw_name: &'static str,
}

/// Look up family + asic + firmware name for a known PCI ID.
fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != AMD_VENDOR {
        return None;
    }
    let (family, asic, fw_name) = match did {
        // Phoenix / HawkPoint / Strix all carry RDNA3.5 iGPU →
        // DCN 3.5 display IP; they take the DCN 3.5 modeset path.
        PHOENIX_HAWKPOINT1 => (Family::Phoenix, "phoenix", "amdgpu/phoenix.bin"),
        PHOENIX_DISCRETE => (Family::Phoenix, "phoenix", "amdgpu/phoenix.bin"),
        STRIX_POINT => (Family::Phoenix, "strix", "amdgpu/strix.bin"),
        RAPHAEL => (Family::Navi3, "raphael", "amdgpu/raphael.bin"),
        CEZANNE => (Family::Renoir, "cezanne", "amdgpu/cezanne.bin"),
        RENOIR => (Family::Renoir, "renoir", "amdgpu/renoir.bin"),
        NAVI22 => (Family::Navi2, "navi22", "amdgpu/navi22.bin"),
        NAVI31 => (Family::Navi3, "navi31", "amdgpu/navi31.bin"),
        _ => return None,
    };
    Some(ChipInfo {
        vid,
        did,
        family,
        asic,
        fw_name,
    })
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
    /// SMU bring-up failed — TestMessage echo mismatch, driver-IF
    /// schema mismatch, or mailbox timeout. The MP1 base may be
    /// wrong (IP discovery missing MP1) or SMU firmware never
    /// loaded (PSP issue upstream).
    SmuBringUpFailed,
}

// ── Driver state ───────────────────────────────────────────────────

/// VRAM aperture parameters read from MC_VM_FB_LOCATION_BASE/TOP.
#[derive(Copy, Clone, Debug, Default)]
pub struct VramInfo {
    /// Phys base of the visible VRAM aperture.
    pub base: u64,
    /// Aperture size in bytes (TOP - BASE + 1, scaled by the
    /// MC's natural granularity of 4 KiB).
    pub size: u64,
}

/// Scanout mode the driver programs into DCN.
#[derive(Copy, Clone, Debug)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
}

/// One probed AMD GPU. Pre-firmware: BAR0 + BAR5 mapped, chip
/// identified, VRAM aperture sized. Post-firmware: PSP loaded,
/// DCN bring-up + scanout registration possible.
pub struct AmdGpu {
    pub fb_bar: MmioRegion,
    pub regs: MmioRegion,
    pub chip: ChipInfo,
    /// VRAM aperture read from the MC at probe time.
    pub vram: VramInfo,
    /// Currently-programmed mode, if `set_mode` has run.
    pub mode: Option<Mode>,
    pub fw_loaded: bool,
    /// IP blocks enumerated from the on-die discovery table (top
    /// of VRAM, parsed at probe time). Empty when the silicon
    /// doesn't publish a discovery blob or the read yielded
    /// garbage (typical on QEMU / older chips); callers fall
    /// back to the hardcoded `Family::mp0_base()` table.
    pub ip_blocks: Vec<IpBlock>,
}

impl core::fmt::Debug for AmdGpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdGpu")
            .field("chip", &self.chip)
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
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AmdgpuError> {
        let chip = chip_info_for_pci_id(device.id.vendor, device.id.device)
            .ok_or(AmdgpuError::UnknownAsic)?;
        // SAFETY: caller-authority over BAR0 + BAR5.
        let fb_bar = unsafe { map_bar(device, BAR_FB) }.map_err(|_| AmdgpuError::BarMapFailed)?;
        let regs = unsafe { map_bar(device, BAR_REGS) }.map_err(|_| AmdgpuError::BarMapFailed)?;

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
        unsafe {
            regs.write32(MM_INDEX, 0xCAFE_F00D);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        let echo = unsafe { regs.read32(MM_INDEX) };
        // SAFETY: restore prior value.
        unsafe {
            regs.write32(MM_INDEX, prev);
        }
        if echo != 0xCAFE_F00D {
            return Err(AmdgpuError::DeviceGone);
        }

        // Read the VRAM aperture through MM_INDEX/MM_DATA. Both
        // base and top live in the MC IP block at register-bus
        // offsets 0x6B0F / 0x6B10. Each value is in 24-byte-shifted
        // units (the MC's natural granularity); the visible
        // aperture is `[base << 24, ((top + 1) << 24))`.
        // SAFETY: identity-mapped MMIO; MM_INDEX/MM_DATA are a
        // sequential pair with no side effects beyond the access.
        let vram = unsafe { read_vram_info(&regs) };

        // Try to parse the on-die IP discovery table. Lives in
        // the top `DISCOVERY_TMR_OFFSET` bytes of the VRAM
        // aperture; reachable through the BAR0 framebuffer
        // window. On QEMU the read yields all-ones / garbage and
        // discovery fails closed with `BadSignature` — log and
        // continue using the hardcoded `Family::mp0_base()`
        // table.
        //
        // SAFETY: BAR0 mapped, exclusive owner; the discovery
        // blob is read-only from the host side.
        let ip_blocks = unsafe { read_ip_discovery(&fb_bar, &vram) };

        Ok(Self {
            fb_bar,
            regs,
            chip,
            vram,
            mode: None,
            fw_loaded: false,
            ip_blocks,
        })
    }

    /// MP0 (PSP) register-window base for this device. Prefers
    /// the on-die discovery table (`HW_ID_MP0` instance 0),
    /// falls back to the static `Family::mp0_base()` table for
    /// chips that don't publish discovery (Vega, Navi1, QEMU).
    pub fn mp0_base(&self) -> Option<u32> {
        if let Some(b) = self.ip_block_base(amdgpu_discovery::HW_ID_MP0, 0) {
            return Some(b);
        }
        self.chip.family.mp0_base()
    }

    /// Look up the canonical (index-0) MMIO base for an IP block
    /// enumerated in the discovery table. Returns `None` when
    /// discovery is empty (older silicon, QEMU) or the requested
    /// `(hw_id, instance)` isn't present.
    pub fn ip_block_base(&self, hw_id: u16, instance: u8) -> Option<u32> {
        amdgpu_discovery::find_ip(&self.ip_blocks, hw_id, instance)
            .map(|b| b.base_addrs[0])
    }

    pub fn chip_info(&self) -> ChipInfo {
        self.chip
    }
    pub fn vram_info(&self) -> VramInfo {
        self.vram
    }
    pub fn is_ready(&self) -> bool {
        self.fw_loaded
    }
    pub fn current_mode(&self) -> Option<Mode> {
        // If `set_mode` has run, return what it programmed.
        // Otherwise, fall back to whatever the firmware left
        // configured at boot — the UEFI GOP / pre-OS POST path
        // typically programs DCN at the panel's preferred mode
        // and we can scan out without re-programming. This
        // mirrors Linux's `simpledrm` fallback.
        if self.mode.is_some() {
            return self.mode;
        }
        // SAFETY: BAR5 mapped, exclusive owner.
        unsafe { self.passive_mode() }
    }

    /// Read the firmware-programmed scanout mode through the OTG
    /// timing registers. Returns `None` when DCN isn't running
    /// (HUBP_BLANK = 1) or when the timing registers read garbage.
    ///
    /// This relies on register offsets being identical across
    /// Vega/Navi — the HUBP/OTG register-bus offsets are stable in
    /// the public AMD docs even though MP0 (PSP) offsets shift
    /// per family. When that assumption stops holding the function
    /// returns `None` for the unsupported family.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively.
    unsafe fn passive_mode(&self) -> Option<Mode> {
        // OTG H_TOTAL / V_TOTAL register-bus offsets per the
        // public DCN1+ register map. Both encode `total - 1`.
        const OTG_H_TOTAL: u32 = 0x0000_5C00;
        const OTG_V_TOTAL: u32 = 0x0000_5C04;
        const OTG_H_BLANK_START_END: u32 = 0x0000_5C08;
        const OTG_V_BLANK_START_END: u32 = 0x0000_5C0C;

        // SAFETY: caller-asserted exclusive ownership of BAR5.
        let h_total = unsafe { mm_read(&self.regs, OTG_H_TOTAL) };
        if h_total == 0 || h_total == 0xFFFF_FFFF {
            return None;
        }
        let v_total = unsafe { mm_read(&self.regs, OTG_V_TOTAL) };
        if v_total == 0 || v_total == 0xFFFF_FFFF {
            return None;
        }
        // SAFETY: same.
        let h_blank = unsafe { mm_read(&self.regs, OTG_H_BLANK_START_END) };
        let v_blank = unsafe { mm_read(&self.regs, OTG_V_BLANK_START_END) };

        // OTG_H_TOTAL is `total - 1`; bits[15:0] are the value.
        // H/V_BLANK_START_END pack `(end << 16) | start`.
        let h_total_val = (h_total & 0xFFFF) + 1;
        let v_total_val = (v_total & 0xFFFF) + 1;
        let h_blank_start = h_blank & 0xFFFF;
        let h_blank_end = (h_blank >> 16) & 0xFFFF;
        let v_blank_start = v_blank & 0xFFFF;
        let v_blank_end = (v_blank >> 16) & 0xFFFF;
        // Active = total - blanking_width.
        let h_blank_w = h_blank_end.saturating_sub(h_blank_start);
        let v_blank_w = v_blank_end.saturating_sub(v_blank_start);
        let h_active = h_total_val.saturating_sub(h_blank_w);
        let v_active = v_total_val.saturating_sub(v_blank_w);
        if h_active < 64 || v_active < 64 || h_active > 16384 || v_active > 16384 {
            // Sanity-bound: 64..16384 covers 720p..16K.
            return None;
        }
        Some(Mode {
            width: h_active,
            height: v_active,
            // Linear scanout: stride = width (no row padding).
            stride: h_active,
        })
    }

    /// Stage the chip's firmware blob through `narf-firmware` and
    /// drive the PSP MP0 mailbox handshake to load it.
    ///
    /// Sequence per `drivers/gpu/specification/amdgpu.md` §4
    /// step 2:
    ///   1. open the blob from the registry
    ///   2. write `view.phys` (lo / hi) to MP0_C2PMSG_64 / _67
    ///   3. write `(LOAD_TA = 5) | (size << 8)` to MP0_C2PMSG_69
    ///   4. poll MP0_C2PMSG_64 until bit 31 is set
    ///   5. status code in bits[30:0]; 0 = success
    ///   6. record `BoundFirmware` on the bound driver
    ///
    /// Families whose `Family::mp0_base()` returns `None` fail
    /// closed with `FirmwareLoadFailed` rather than poking the
    /// wrong register window.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively. The blob's
    /// `view().phys` must remain valid for the duration of the
    /// PSP handshake (the cap stays alive until this function
    /// returns).
    pub unsafe fn load_firmware(
        &mut self,
        fw_authority: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<(), AmdgpuError> {
        // Prefer the discovery-driven MP0 base (true for every
        // Navi2+ / Phoenix / Strix chip); fall back to the
        // hardcoded per-family table for Vega / Navi1.
        let mp0_base = self.mp0_base().ok_or(AmdgpuError::FirmwareLoadFailed)?;

        let cap = narf_firmware::open(self.chip.fw_name, fw_authority).map_err(|e| match e {
            narf_firmware::FirmwareError::NotFound => AmdgpuError::FirmwareMissing,
            _ => AmdgpuError::FirmwareLoadFailed,
        })?;
        let view = narf_firmware::view_of(&cap).map_err(|_| AmdgpuError::FirmwareLoadFailed)?;

        let phys = view.phys;
        let size = view.bytes.len() as u32;
        if size == 0 || size & 0xFF00_0000 != 0 {
            // PSP `LOAD_TA` packs size into bits[31:8] of the
            // command word; image > 16 MiB doesn't fit. Real
            // images are at most a few MiB.
            return Err(AmdgpuError::FirmwareLoadFailed);
        }

        // Step 2-3: program phys + size + command.
        // SAFETY: BAR5 mapped, exclusive owner; mp0_base + offsets
        // are valid register-bus addresses for this family.
        unsafe {
            mm_write(&self.regs, mp0_base + MP0_C2PMSG_64_REL, phys as u32);
            mm_write(
                &self.regs,
                mp0_base + MP0_C2PMSG_67_REL,
                (phys >> 32) as u32,
            );
        }
        compiler_fence(Ordering::SeqCst);
        let cmd = PSP_CMD_LOAD_IP_FW | (size << 8);
        // SAFETY: same.
        unsafe {
            mm_write(&self.regs, mp0_base + MP0_C2PMSG_69_REL, cmd);
        }

        // Step 4-5: poll MP0_C2PMSG_64 for the done bit. PSP
        // typically responds within ~50 ms; bound the spin so a
        // wedged controller surfaces as FirmwareLoadFailed.
        // responsive_spin_until ticks sleep_pumps so cursor/FB stay
        // alive during this multi-millisecond wait. 500 ms wedge
        // threshold (10x typical PSP TA-load latency).
        let _ = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mm_read(&self.regs, mp0_base + MP0_C2PMSG_64_REL) } & PSP_STATUS_DONE_BIT != 0,
            narf_time::Deadline::after_ms(500),
        );
        // SAFETY: identity-mapped MMIO.
        let last = unsafe { mm_read(&self.regs, mp0_base + MP0_C2PMSG_64_REL) };
        if last & PSP_STATUS_DONE_BIT == 0 {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        if last & PSP_STATUS_CODE_MASK != 0 {
            // PSP rejected the image. Status codes are
            // ASIC-specific; surface them so callers can log.
            return Err(AmdgpuError::FirmwareLoadFailed);
        }

        // Step 6: record the version coupling.
        narf_drivers::set_bound_firmware(
            "amdgpu",
            narf_drivers::BoundFirmware {
                blob_name: alloc::string::String::from(self.chip.fw_name),
                sha256: view.sha256,
                signer: view.signer,
                version: None,
            },
        );
        self.fw_loaded = true;
        Ok(())
    }

    /// Program a scanout mode through DCN 2.0.
    ///
    /// Path:
    ///   1. Look up the DCN register window from the IP
    ///      discovery table (`HW_ID_DCN` instance 0). Bail if
    ///      discovery didn't land a DCN block — the older
    ///      `amdgpu_offsets` registry path is reserved for
    ///      pre-discovery silicon (Vega / Navi1) which doesn't
    ///      ship DCN 2.0 anyway.
    ///   2. Translate `mode.width × mode.height @ 60 Hz` to a
    ///      `ModeTiming` via the VESA / CEA-861 table in
    ///      `amdgpu_dcn::timing_for_mode`.
    ///   3. Build the full DCN 2.0 modeset write sequence
    ///      (prologue + body + epilogue) via
    ///      `dcn20_modeset_sequence`.
    ///   4. Execute through `execute_modeset` against BAR5's
    ///      `MM_INDEX / MM_DATA` indexed access pair.
    ///   5. Stash the programmed mode so the `FbScanout` impl
    ///      reports it.
    ///
    /// Mirrors Linux `drivers/gpu/drm/amd/display/dc/dcn20/
    /// dcn20_hwseq.c::dcn20_enable_crtc` +
    /// `dcn20_program_pipe`. Link training / DP-AUX wakeup are
    /// out of scope for Stage-3; the panel is expected to be in
    /// the firmware-programmed link state already.
    ///
    /// Returns `FirmwareLoadFailed` if PSP firmware hasn't been
    /// loaded yet (DCN registers shadow against the SMU and can
    /// glitch the display if poked pre-firmware) or
    /// `UnknownAsic` if the requested mode isn't in the timing
    /// table.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively.
    pub unsafe fn set_mode(&mut self, mode: Mode) -> Result<(), AmdgpuError> {
        if !self.fw_loaded {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }

        // Resolve DCN base via discovery. Stage-3 only programs
        // discovery-capable silicon (Renoir+).
        let dcn_base = self
            .ip_block_base(amdgpu_discovery::HW_ID_DCN, 0)
            .ok_or(AmdgpuError::FirmwareLoadFailed)?;

        // Translate the requested mode to a full timing. We
        // currently honour 1920x1080 / 1366x768 / 1280x720, all
        // @60 Hz. Anything else: bail rather than program a mode
        // we don't have timings for.
        let timing = crate::amdgpu_dcn::timing_for_mode(mode.width, mode.height, 60)
            .ok_or(AmdgpuError::UnknownAsic)?;

        // Build the sequence. `mode.stride` is in pixels — DCN's
        // DCSURF_SURFACE_PITCH field also expects pixels.
        //
        // Branch by family: Phoenix / HawkPoint / Strix run DCN 3.5
        // (different OTG register layout — see `amdgpu_dcn` module
        // header for the per-register shifts). Everything else with
        // a discoverable DCN block today is DCN 2.0 (Renoir,
        // Cezanne, Lucienne).
        let seq = match self.chip.family {
            Family::Phoenix => crate::amdgpu_dcn::dcn35_modeset_sequence(
                &timing,
                self.vram.base,
                mode.stride,
                dcn_base,
            ),
            _ => crate::amdgpu_dcn::dcn20_modeset_sequence(
                &timing,
                self.vram.base,
                mode.stride,
                dcn_base,
            ),
        };

        // Drive the sequencer.
        // SAFETY: caller-asserted exclusive ownership of BAR5.
        unsafe {
            crate::amdgpu_dcn::execute_modeset(&self.regs, &seq);
        }

        self.mode = Some(mode);
        Ok(())
    }

    /// Program the panel backlight to `percent` (0–100). Caller's
    /// 0 typically lands at the panel's hardware minimum (the panel
    /// usually won't fully extinguish even with USER_LEVEL = 0 —
    /// the SMU brightness-floor calibration table sits between).
    ///
    /// Requires `set_mode` to have run first (DCN must be brought
    /// up so PANEL_CNTL is reachable). On chips without a
    /// discovery-resolvable DCN base, returns `UnknownAsic`.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively.
    pub unsafe fn set_backlight(&mut self, percent: u8) -> Result<(), AmdgpuError> {
        if self.mode.is_none() {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        let dcn_base = self
            .ip_block_base(amdgpu_discovery::HW_ID_DCN, 0)
            .ok_or(AmdgpuError::UnknownAsic)?;
        let user_level = crate::amdgpu_backlight::user_level_for_percent(percent);
        let writes = crate::amdgpu_backlight::build_set_user_level(dcn_base, user_level);
        // SAFETY: caller-asserted BAR5 ownership.
        unsafe {
            for w in &writes {
                mm_write(&self.regs, w.addr, w.value);
            }
        }
        Ok(())
    }

    /// MP1 (SMU) register-window base. Reads IP discovery first;
    /// pre-discovery silicon doesn't expose SMU bring-up here.
    pub fn mp1_base(&self) -> Option<u32> {
        self.ip_block_base(amdgpu_discovery::HW_ID_MP1, 0)
    }

    /// SMU driver-interface schema version this driver was
    /// compiled to talk to, per family. Renoir = SMU 12.0,
    /// Phoenix = SMU 13.0.4. Other families don't have an SMU
    /// bring-up path in this scaffold.
    pub fn expected_smu_driver_if_version(&self) -> Option<u32> {
        use crate::amdgpu_smu::{SMU12_DRIVER_IF_VERSION, SMU_13_0_4_DRIVER_IF_VERSION};
        match self.chip.family {
            Family::Renoir => Some(SMU12_DRIVER_IF_VERSION),
            Family::Phoenix => Some(SMU_13_0_4_DRIVER_IF_VERSION),
            _ => None,
        }
    }

    /// End-to-end post-probe init: PSP firmware load, then SMU
    /// bring-up handshake. After this returns Ok, the chip is
    /// "warm" — engines can be brought up and a mode set. Ring /
    /// IH / SDMA bring-up are deferred to caller; they need DMA
    /// buffer allocation outside this method's scope.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively. The firmware blob's phys
    /// stays valid through the PSP handshake.
    pub unsafe fn initialize(
        &mut self,
        fw_authority: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<InitializeReport, AmdgpuError> {
        // 1. PSP-driven firmware load (existing path — handles
        //    SMU / GFX / SDMA / DCN microcode in one shot).
        // SAFETY: caller-asserted BAR5 ownership.
        unsafe { self.load_firmware(fw_authority)? };

        // 2. SMU bring-up handshake. The MP1 base + expected
        //    driver-IF version are family-specific; both must
        //    resolve or we can't safely talk to the SMU.
        let mp1_base = self.mp1_base().ok_or(AmdgpuError::SmuBringUpFailed)?;
        let expected_ifv = self
            .expected_smu_driver_if_version()
            .ok_or(AmdgpuError::SmuBringUpFailed)?;
        // SAFETY: SmuRegsAdapter borrows &self.regs which is uniquely
        // held through `&mut self`. mm_read/mm_write are unsafe
        // because they touch MM_INDEX/MM_DATA; the adapter promises
        // exclusivity for the duration of bring_up.
        let smu_info = {
            let mut adapter = SmuRegsAdapter { regs: &self.regs };
            crate::amdgpu_smu::bring_up(&mut adapter, mp1_base, expected_ifv)
                .map_err(|_| AmdgpuError::SmuBringUpFailed)?
        };

        Ok(InitializeReport { smu_info })
    }
}

/// Per-initialize report — what the host learned about the chip
/// after `AmdGpu::initialize`. The caller stashes this on the
/// driver state for later reference (logging, ABI exposure).
#[derive(Copy, Clone, Debug)]
pub struct InitializeReport {
    pub smu_info: crate::amdgpu_smu::SmuInfo,
}

/// Adapter that implements `SmuMmio` over the driver's BAR5
/// region. Lives in the function frame of `initialize` — never
/// outlives the &mut borrow of AmdGpu, so the unsafe MMIO
/// access in the `read` / `write` methods is sound.
struct SmuRegsAdapter<'a> {
    regs: &'a MmioRegion,
}

impl<'a> crate::amdgpu_smu::SmuMmio for SmuRegsAdapter<'a> {
    fn read(&mut self, addr: u32) -> u32 {
        // SAFETY: adapter constructed inside `initialize` which
        // holds &mut AmdGpu — `self.regs` is exclusively owned for
        // the duration of the bring-up sequence.
        unsafe { mm_read(self.regs, addr) }
    }
    fn write(&mut self, addr: u32, value: u32) {
        // SAFETY: same.
        unsafe { mm_write(self.regs, addr, value) }
    }
}

/// Indexed register read through MM_INDEX / MM_DATA.
///
/// # Safety
/// `regs` must map BAR5 of an AMD GPU; the caller must hold
/// exclusive ownership of the register window for the duration
/// of the read (MM_INDEX is a shared latch).
unsafe fn mm_read(regs: &MmioRegion, addr: u32) -> u32 {
    // SAFETY: caller-asserted ownership.
    unsafe {
        regs.write32(MM_INDEX, addr);
    }
    compiler_fence(Ordering::SeqCst);
    // SAFETY: same.
    unsafe { regs.read32(MM_DATA) }
}

/// Indexed register write.
///
/// # Safety
/// Same as `mm_read`.
pub(crate) unsafe fn mm_write(regs: &MmioRegion, addr: u32, value: u32) {
    // SAFETY: caller-asserted ownership.
    unsafe {
        regs.write32(MM_INDEX, addr);
    }
    compiler_fence(Ordering::SeqCst);
    // SAFETY: same.
    unsafe {
        regs.write32(MM_DATA, value);
    }
}

/// Read the visible-VRAM aperture from the MC IP block.
///
/// MC_VM_FB_LOCATION_BASE / TOP are both in 16-MiB units (low 24
/// bits of the address are implicit zero). The visible aperture
/// is `[base, top + 16 MiB)`.
///
/// On Phoenix / Strix iGPUs (UMA), VRAM is carved from system
/// DRAM and the aperture covers the whole carve-out. On discrete
/// cards, it's the GPU's local memory.
///
/// # Safety
/// Caller owns BAR5 exclusively.
unsafe fn read_vram_info(regs: &MmioRegion) -> VramInfo {
    // SAFETY: caller-asserted ownership; MM_INDEX/MM_DATA pair.
    let base_field = unsafe { mm_read(regs, MC_VM_FB_LOCATION_BASE) };
    let top_field = unsafe { mm_read(regs, MC_VM_FB_LOCATION_TOP) };
    // Bits[23:0] are the FB location; high bits are reserved.
    let base = (base_field as u64 & 0x00FF_FFFF) << 24;
    let top = (top_field as u64 & 0x00FF_FFFF) << 24;
    let size = if top >= base {
        top - base + (1u64 << 24) // top is inclusive, last 16 MiB unit
    } else {
        0
    };
    VramInfo { base, size }
}

/// Read the on-die IP discovery blob from the top of the VRAM
/// aperture and parse it into a flat `Vec<IpBlock>`. Returns an
/// empty Vec on any failure (signature mismatch from QEMU
/// garbage, truncated blob, checksum fail) — discovery is an
/// optimisation, not a load-bearing path, so we fail soft.
///
/// The blob lives at `vram_size - DISCOVERY_TMR_OFFSET` per
/// `amdgpu_discovery.c` line 332. We slurp `DISCOVERY_TMR_SIZE`
/// bytes (or whatever fits inside the aperture, whichever is
/// smaller) into a heap buffer so the parser sees a contiguous
/// byte slice independent of the MMIO access width.
///
/// # Safety
/// `fb_bar` must map BAR0 of an AMD GPU; the caller must hold
/// exclusive ownership of the framebuffer aperture for the
/// duration of the read.
unsafe fn read_ip_discovery(fb_bar: &MmioRegion, vram: &VramInfo) -> Vec<IpBlock> {
    // No aperture → no discovery.
    if vram.size < amdgpu_discovery::DISCOVERY_TMR_OFFSET {
        return Vec::new();
    }
    let off_in_vram = vram.size - amdgpu_discovery::DISCOVERY_TMR_OFFSET;
    // Cap the read at whatever the aperture actually exposes
    // (BAR0 may be smaller than the visible VRAM on systems with
    // a resizable BAR turned off).
    let max = amdgpu_discovery::DISCOVERY_TMR_SIZE.min(
        amdgpu_discovery::DISCOVERY_TMR_OFFSET as usize,
    );
    let mut buf = alloc::vec![0u8; max];
    // Read in 4-byte chunks via the MMIO accessor. The BAR's
    // size guard is enforced by `MmioRegion::read32` (returns
    // garbage / panics on out-of-bounds depending on the
    // runtime); we conservatively walk only `max` bytes here.
    let mut i = 0;
    while i + 4 <= max {
        // SAFETY: caller-asserted ownership of BAR0; the
        // aperture covers `[0, vram.size)` and we've bounded
        // `off_in_vram + i` against `vram.size`.
        let word = unsafe { fb_bar.read32(off_in_vram + i as u64) };
        let bytes = word.to_le_bytes();
        buf[i] = bytes[0];
        buf[i + 1] = bytes[1];
        buf[i + 2] = bytes[2];
        buf[i + 3] = bytes[3];
        i += 4;
    }
    match amdgpu_discovery::parse_discovery(&buf) {
        Ok(blocks) => blocks,
        Err(_) => Vec::new(),
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<AmdGpu>> = IrqSafeSpinLock::new(None);

pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    // The class-match backstop catches every PCI VGA controller;
    // reject non-AMD vendors so virtio-gpu / Bochs / Intel VGA
    // fall through to their own drivers.
    if device.id.vendor != AMD_VENDOR {
        return Err(narf_bus::ProbeError::NotForThisDriver);
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
    let dev = match unsafe { AmdGpu::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("amdgpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    // Register against the device PM registry. AMDGPU suspend
    // saves the current Mode so set_mode can re-program it on
    // resume; full S3 also needs PSP TMR teardown + SMU
    // PowerDownGfx, which the current scaffold doesn't do —
    // registered as best-effort.
    narf_power::device_pm::register_device_pm(
        "amdgpu",
        amdgpu_suspend_handler,
        amdgpu_resume_handler,
    );
    Ok(())
}

/// Stash so the resume handler can re-program the same Mode the
/// suspend handler saw. None when no mode has been programmed
/// yet (e.g. pre-firmware-load).
static SAVED_MODE: narf_lib::sync::IrqSafeSpinLock<Option<Mode>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

fn amdgpu_suspend_handler() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if !is_probed() {
        return Ok(());
    }
    // 1. Snapshot the current Mode so resume re-programs it.
    let mode = with_controller(|d| d.current_mode());
    if let Some(Some(m)) = mode {
        *SAVED_MODE.lock() = Some(m);
    }
    // 2. Tell the SMU to power-gate GFX. PPSMC_MSG_PowerDownGfx is
    //    stable across Renoir (SMU 12.0) and Phoenix (SMU 13.0.4)
    //    per crate::amdgpu_smu — no-op return value, void wrapper.
    //
    //    The PSP TMR is intentionally NOT torn down here: it
    //    survives S3, and tearing it down would force a full
    //    PSP-firmware-reload on resume (which needs the cap we
    //    haven't stashed). Modern AMI BIOSes preserve TMR across
    //    S3 so this is the right shape for the bring-up targets.
    let _ = with_controller(|d| {
        let mp1_base = match d.mp1_base() {
            Some(b) => b,
            None => return,
        };
        let mut adapter = SmuRegsAdapter { regs: &d.regs };
        let _ = crate::amdgpu_smu::send_message_void(
            &mut adapter,
            mp1_base,
            crate::amdgpu_smu::PPSMC_MSG_POWER_DOWN_GFX,
            0,
        );
    });
    Ok(())
}

fn amdgpu_resume_handler() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if !is_probed() {
        return Ok(());
    }
    // 1. Re-arm SMU mailbox with a TEST_MESSAGE echo. The PSP
    //    TMR survived S3 so SMU firmware is still loaded; we
    //    just need to confirm the mailbox is alive before the
    //    next bring-up step issues real commands.
    let _ = with_controller(|d| {
        let mp1_base = d.mp1_base()?;
        let mut adapter = SmuRegsAdapter { regs: &d.regs };
        crate::amdgpu_smu::send_message_get(
            &mut adapter,
            mp1_base,
            crate::amdgpu_smu::PPSMC_MSG_TEST_MESSAGE,
            0xDEAD_BEEF,
        )
        .ok()
    });
    // 2. Tell SMU to power-up GFX before DCN re-init touches
    //    display clocks. Inverse of the PowerDownGfx above.
    let _ = with_controller(|d| {
        let mp1_base = d.mp1_base()?;
        let mut adapter = SmuRegsAdapter { regs: &d.regs };
        crate::amdgpu_smu::send_message_void(
            &mut adapter,
            mp1_base,
            crate::amdgpu_smu::PPSMC_MSG_POWER_UP_GFX,
            0,
        )
        .ok()
    });
    // 3. Re-program the saved Mode. fw_loaded survived S3 (TMR
    //    intact). Failures fall through — the next user-driven
    //    modeset re-tries.
    let saved = *SAVED_MODE.lock();
    if let Some(mode) = saved {
        let _ = with_controller_mut(|d| {
            // SAFETY: probe gave us BAR ownership, still held.
            unsafe { d.set_mode(mode) }
        });
    }
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
        ("amdgpu-strix", AMD_VENDOR, STRIX_POINT),
        ("amdgpu-raphael", AMD_VENDOR, RAPHAEL),
        ("amdgpu-cezanne", AMD_VENDOR, CEZANNE),
        ("amdgpu-renoir", AMD_VENDOR, RENOIR),
        ("amdgpu-navi22", AMD_VENDOR, NAVI22),
        ("amdgpu-navi31", AMD_VENDOR, NAVI31),
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
    // Class-match backstop: any PCI VGA controller. The probe
    // body filters non-AMD vendors so virtio-gpu / Bochs / Intel
    // VGA aren't accidentally claimed.
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "amdgpu-class",
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

pub fn with_controller<R>(f: impl FnOnce(&AmdGpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

/// `&mut` variant of `with_controller`. Used by `set_mode` and other
/// state-mutating bring-up paths.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut AmdGpu) -> R) -> Option<R> {
    CONTROLLER.lock().as_mut().map(f)
}
