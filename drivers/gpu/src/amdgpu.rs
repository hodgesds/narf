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
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

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

const MP0_C2PMSG_REL: u32 = 0x0000_029C;
const MP0_C2PMSG_64_REL: u32 = MP0_C2PMSG_REL + 64 * 4;
const MP0_C2PMSG_67_REL: u32 = MP0_C2PMSG_REL + 67 * 4;
const MP0_C2PMSG_69_REL: u32 = MP0_C2PMSG_REL + 69 * 4;

/// PSP `LOAD_TA` (Trusted Application) command code. Other codes
/// (`UNLOAD_TA`, `INVOKE_CMD`) aren't load-bearing for Stage-2.
const PSP_CMD_LOAD_TA: u32 = 0x05;

/// MP0_C2PMSG_64 status fields after LOAD_TA polling completes.
const PSP_STATUS_DONE_BIT: u32 = 1 << 31;
const PSP_STATUS_CODE_MASK: u32 = 0x7FFF_FFFF;

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
        PHOENIX_HAWKPOINT1 => (Family::Navi3, "phoenix", "amdgpu/phoenix.bin"),
        PHOENIX_DISCRETE => (Family::Navi3, "phoenix", "amdgpu/phoenix.bin"),
        STRIX_POINT => (Family::Navi3, "strix", "amdgpu/strix.bin"),
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

        Ok(Self {
            fb_bar,
            regs,
            chip,
            vram,
            mode: None,
            fw_loaded: false,
        })
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
        let mp0_base = self
            .chip
            .family
            .mp0_base()
            .ok_or(AmdgpuError::FirmwareLoadFailed)?;

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
        let cmd = PSP_CMD_LOAD_TA | (size << 8);
        // SAFETY: same.
        unsafe {
            mm_write(&self.regs, mp0_base + MP0_C2PMSG_69_REL, cmd);
        }

        // Step 4-5: poll MP0_C2PMSG_64 for the done bit. PSP
        // typically responds within ~50 ms; bound the spin so a
        // wedged controller surfaces as FirmwareLoadFailed.
        // responsive_spin ticks sleep_pumps so cursor/FB stay alive
        // during this multi-millisecond wait.
        let _ = narf_scheduler::responsive_spin(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mm_read(&self.regs, mp0_base + MP0_C2PMSG_64_REL) } & PSP_STATUS_DONE_BIT != 0,
            10_000_000,
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

    /// Program a scanout mode through DCN.
    ///
    /// Stage-2 ships only the linear-scanout path: one primary
    /// plane covering the full VRAM aperture at the requested
    /// `Mode`. Cursor / overlay / DCC compression / multi-plane
    /// land in Phase B (`drivers/gpu/spec.md` §1).
    ///
    /// Returns `FirmwareLoadFailed` until firmware is loaded;
    /// otherwise stashes the mode in `self.mode` for the
    /// `AmdgpuScanout: FbScanout` impl to expose. The actual
    /// HUBP / OPP / OTG register sequence requires per-family
    /// DCN offsets that aren't yet sourced — this stub records
    /// the intent so the picker integration can light up the
    /// moment the offset tables land.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively.
    pub unsafe fn set_mode(&mut self, mode: Mode) -> Result<(), AmdgpuError> {
        if !self.fw_loaded {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        // TODO(stage-3): DCN HUBP/OPP/OTG programming.
        //   1. Disable scanout (HUBP_BLANK = 1).
        //   2. Program HUBP_PRIMARY_SURFACE_ADDR = self.vram.base.
        //   3. Program HUBP_PRIMARY_SURFACE_PITCH = mode.stride.
        //   4. Program OPP gamma passthrough.
        //   5. Program OTG_H_TOTAL / OTG_V_TOTAL from mode timing.
        //   6. HUBP_BLANK = 0; assert OTG_MASTER_EN.
        self.mode = Some(mode);
        Ok(())
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
unsafe fn mm_write(regs: &MmioRegion, addr: u32, value: u32) {
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
