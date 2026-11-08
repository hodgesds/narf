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
//! | 1002:7550 | Navi 48 (RX 9070 / 9070 XT / 9070 GRE) | RDNA4 desktop |
//! | 1002:7551 | Navi 48 (Radeon AI PRO R9700) | RDNA4 workstation |
//! | 1002:7590 | Navi 44 (RX 9060 XT) | RDNA4 desktop |
//!
//! The RDNA4 rows come from `amdgpu_rdna4::KNOWN_DEVICES`; any other AMD
//! display function whose discovery reports GC 12.0.x (RX 9060, OEM ids) is
//! bound too, as Linux's `CHIP_IP_DISCOVERY` class entries bind it.
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

use alloc::vec::Vec;
use narf_capabilities::{CapError, CapOp};
use narf_driver_runtime::{
    map_bar, BusDevice, BusDeviceCap, Cap, Lock as IrqSafeSpinLock, MmioRegion, Write,
};

use crate::amdgpu_discovery::{self, IpBlock};

#[path = "amdgpu_index.rs"]
mod index;

// ── Vendor + device ids ────────────────────────────────────────────

/// Advanced Micro Devices, Inc. (PCI Special Interest Group ID).
pub const AMD_VENDOR: u16 = 0x1002;

// The APU device ids below are checked against the PCI SIG id database
// (`/usr/share/hwdata/pci.ids`, vendor 1002), not against amdgpu — modern
// amdgpu matches APUs by IP-discovery version and carries no id table for
// them, so a wrong constant here cannot be caught by reading the driver.
//
// Three of these were wrong and each sent a real machine down a path built
// for different silicon; the comments record what they were.

/// Phoenix HawkPoint1 (Ryzen 8040 series iGPU). GFX 11.0.1.
pub const PHOENIX_HAWKPOINT1: u16 = 0x1900;
/// Phoenix1 — **Radeon 780M**, Ryzen 7040 series. GFX 11.0.1, DCN 3.1.4.
///
/// Was labelled `STRIX_POINT` and mapped to the Strix firmware bundle. Strix
/// is 0x150E; 0x15BF is Phoenix, so every 780M laptop asked the PSP for
/// `psp_14_0_4_toc.bin` and failed firmware open before reaching DCN.
pub const PHOENIX1: u16 = 0x15BF;
/// Phoenix2 — the cut-down Phoenix die (Ryzen 7x40U low end). Same IP set.
pub const PHOENIX2: u16 = 0x15C8;
/// Strix Point (Radeon 880M / 890M). GFX **11.5.0**, DCN **3.5**,
/// PSP 14.0.1 — a different IP stack from Phoenix, not a Phoenix variant.
pub const STRIX_POINT: u16 = 0x150E;
/// Rembrandt (Radeon 680M, Ryzen 6000 series). GFX **10.3.6**, DCN 3.1.2 —
/// RDNA2, one whole architecture before Phoenix.
///
/// Was labelled `PHOENIX_DISCRETE` and mapped to the Phoenix family and
/// firmware. It is neither discrete nor Phoenix.
pub const REMBRANDT: u16 = 0x1681;
/// Raphael.
pub const RAPHAEL: u16 = 0x164E;
/// Lucienne — Renoir refresh / low-cost variant (Ryzen 5000U some
/// SKUs). Same GFX9 + DCN 2.0 IP set as Renoir; uses the same
/// firmware bundle.
pub const LUCIENNE: u16 = 0x164C;
/// Barcelo — Cezanne refresh (Ryzen 5xx5U / 5xx5H series).
/// Identical IP version stack to Cezanne; green_sardine firmware.
pub const BARCELO: u16 = 0x15E7;
/// Cezanne — Ryzen 5000/6000 mobile APUs. GFX9 + DCN 2.1
/// (one step up from Renoir's DCN 2.0). PCI ID 0x1638 per
/// Linux's amdgpu.
pub const CEZANNE: u16 = 0x1638;
/// Renoir — Ryzen 4000 mobile APUs (original Vega8/9 iGPU).
/// GFX9 + DCN 2.0. PCI ID 0x1636 per Linux. The pre-audit
/// constant was 0x1638 which is actually Cezanne — fixed.
pub const RENOIR: u16 = 0x1636;
/// Navi 22 (Radeon RX 6700/6750 family).
pub const NAVI22: u16 = 0x73DF;
/// Navi 31 (Radeon RX 7900 family).
pub const NAVI31: u16 = 0x744C;
/// Navi 48 (RX 9070 / 9070 XT / 9070 GRE). The PCI ID does not identify
/// the SKU's enabled topology; discovery supplies maximum geometry, while
/// enabled CU counts require GFX12's harvested-WGP register inventory.
///
/// Not an RDNA4 gate: `amdgpu_rdna4::Rdna4Chip::of` identifies the die from
/// discovery, and `amdgpu_rdna4::KNOWN_DEVICES` lists every RDNA4 board id.
pub const NAVI48: u16 = 0x7550;

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

/// `mmRCC_CONFIG_MEMSIZE` — the VRAM size in MiB, as an ABSOLUTE dword
/// address with no IP base.
///
/// `amdgpu_discovery.c:142` defines it alongside `mmIP_DISCOVERY_VERSION` and
/// `mmMP0_SMN_C2PMSG_33` under the comment "Note: These registers are
/// consistent across all the SOCs" — they are the handful that must be
/// readable before the discovery blob has been parsed and so before any IP
/// base exists.
pub(crate) const RCC_CONFIG_MEMSIZE: u32 = 0x0de3;

/// `MM_DATA` — register-window data port.
const MM_DATA: u64 = 0x0004;

// Pre-discovery VRAM sizing. This is the most load-bearing read in the
// driver: `vram.size` locates the IP-discovery blob at
// `vram.size - DISCOVERY_TMR_OFFSET`, and every IP base — the firmware load,
// the DCN bring-up, the SMU handshake — comes out of that blob.
//
// It used to read framebuffer-location registers, and got three things wrong
// in sequence. First a duplicate pair at 0x6B0F / 0x6B10, which appear in no
// AMD header for any `MC_VM_FB_LOCATION_BASE` variant. Then the right ids for
// the family — GFX9's `mmMC_VM_FB_LOCATION_BASE` 0x0980 and GFX11's
// `regGCMC_VM_FB_LOCATION_BASE` 0x1678, which are different registers rather
// than one register at two offsets (`gfxhub_v1_0.c` against `gfxhub_v3_0.c`) —
// but still with no IP base added, because there was none to add: resolving a
// base needs the discovery blob this read is trying to locate.
//
// That circularity was recorded as the remaining gap, and this is its answer.
// Linux does not break the cycle, it avoids it: `amdgpu_discovery.c:142`
// defines `mmRCC_CONFIG_MEMSIZE` as the absolute dword 0xde3, under the
// comment "Note: These registers are consistent across all the SOCs", and
// reads the VRAM size in MiB from it with a bare `RREG32` at line 312. The
// aperture BASE is not a register read at all — `gmc_v11_0_mc_init` takes
// `pci_resource_start(adev->pdev, 0)`, BAR0's physical address.
//
// So `read_vram_info` needs no IP base and the FB-location registers are not
// part of this path. They remain correct in `amdgpu_gmc` for the
// post-discovery aperture reads that can address them properly.

// ── PSP (Platform Security Processor) MP0 mailbox protocol ────────
//
// LINUX-GAP: a firmware-load handshake was described here —
//
//   MP0_C2PMSG_64 = phys lo, _67 = phys hi,
//   MP0_C2PMSG_69 = cmd | (image_size << 8), poll _64 for bit 31
//
// — "per AMD public PSP-protocol docs". It appears in no `psp_v*.c`; see the
// gap note on `amdgpu_psp::send_command`. The real mailbox loads a bootloader
// component through C2PMSG_36/_35 and creates a ring through C2PMSG_69..71 and
// _64; IP firmware travels in the GPCOM ring that `amdgpu_psp_ring` builds.
//
// `MP0_C2PMSG_N` is at `mp0_base + 0x100 + N * 4` —
// `regMP0_SMN_C2PMSG_0` is dword 0x0040 at BASE_IDX 1. The stale `0x29C` that
// stood here is corrected in `amdgpu_psp::MP0_C2PMSG_REL`; only `mp0_base`
// shifts per family.

// PSP MP0 register / command / status constants live in
// `amdgpu_psp` (canonically named LOAD_IP_FW for the value 0x05
// that pre-relicense scaffold mislabelled LOAD_TA). Re-export
// the names load_firmware uses inline below.
use crate::amdgpu_psp::{
    PSP_CMD_AUTOLOAD_RLC, PSP_CMD_LOAD_ASD, PSP_CMD_LOAD_IP_FW, PSP_CMD_LOAD_TA, PSP_CMD_LOAD_TOC,
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
    /// Navi 4x — RDNA4. Separate from both the RDNA3 APUs and Navi3.
    Navi4,
}

/// Whether a part is an APU, keyed on its **GC IP version**.
///
/// This is `amdgpu_discovery.c`'s own switch, transcribed. Modern Linux does
/// not take APU-ness from the PCI id: the `AMD_IS_APU` flag in the PCI table
/// survives only for pre-discovery parts, and every discovery part gets the
/// flag from this list instead.
///
/// The list is the authority on a question that changes real behaviour:
///
/// * VRAM. An APU's is carved from system memory and entirely CPU-visible;
///   a discrete card's sits behind a BAR aperture that is normally much
///   smaller than the card. See [`VramInfo::visible_size`].
/// * `AMDGPU_IDS_FLAGS_FUSION`, which userspace reads to decide whether the
///   GPU shares the CPU's memory.
/// * The MEC count — a discrete part has two, an APU one.
///
/// GC 10.3.2, the RX 6700/6750's Navi 22, is **absent**: discrete. GC 11.0.1,
/// Phoenix, is present.
pub const APU_GC_VERSIONS: &[(u8, u8, u8)] = &[
    (9, 1, 0),
    (9, 2, 2),
    (9, 3, 0),
    (10, 1, 3),
    (10, 1, 4),
    (10, 3, 1),
    (10, 3, 3),
    (10, 3, 6),
    (10, 3, 7),
    (11, 0, 1),
    (11, 0, 4),
    (11, 5, 0),
    (11, 5, 1),
    (11, 5, 2),
    (11, 5, 3),
    (11, 5, 4),
    (11, 5, 6),
    (11, 7, 0),
    (11, 7, 1),
];

/// Is `(major, minor, revision)` a GC version that belongs to an APU?
///
/// Absence means discrete, as it does in Linux: the switch has no `default`
/// that sets the flag. So an unknown future part reads as discrete, which is
/// the conservative answer — a discrete misread as an APU would claim the
/// whole of VRAM is CPU-visible.
pub const fn gc_version_is_apu(major: u8, minor: u8, revision: u8) -> bool {
    let mut i = 0;
    while i < APU_GC_VERSIONS.len() {
        let (a, b, c) = APU_GC_VERSIONS[i];
        if a == major && b == minor && c == revision {
            return true;
        }
        i += 1;
    }
    false
}

impl Family {
    /// Coarse family default. Use `ChipInfo::is_apu` for the PCI fallback:
    /// some APU IDs share the Navi register-family buckets. Once discovery
    /// is available, `AmdGpu::is_apu` uses the exact GC version instead.
    pub const fn is_apu(self) -> bool {
        match self {
            Family::Renoir | Family::Phoenix => true,
            Family::Vega | Family::Navi1 | Family::Navi2 | Family::Navi3 | Family::Navi4 => false,
        }
    }
}

/// APU identity is independent of BAR sizing, including Resizable BAR.
pub(crate) fn device_is_apu(chip: &ChipInfo, blocks: &[IpBlock]) -> bool {
    amdgpu_discovery::find_ip(blocks, amdgpu_discovery::HW_ID_GC, 0)
        .map(|gc| gc_version_is_apu(gc.major, gc.minor, gc.revision))
        .unwrap_or_else(|| chip.is_apu())
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
            Family::Navi4 => None,
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
    /// Legacy single-blob firmware name. Pre-multi-IP code paths
    /// (e.g. `load_firmware` on test mocks) still open this name.
    /// Real silicon goes through [`fw_list`] instead.
    pub fw_name: &'static str,
    /// Per-IP firmware enumeration. Walked in order during
    /// `load_firmware_multi` — each entry names a registry blob plus
    /// the PSP command used to dispatch it. List comes from the
    /// Linux amdgpu driver's `MODULE_FIRMWARE` declarations for
    /// the matching `gc_*`, `dcn_*`, `psp_*`, `sdma_*`, `vcn_*`,
    /// `smu_*` IP versions.
    pub fw_list: &'static [FwEntry],
    /// PCI revision ID (`pdev->revision`, config offset 0x08), read at
    /// probe. Linux keys the kicker firmware list on it and reports it as
    /// DEV_INFO `pci_rev`; 0 until the probe reads it.
    pub revision: u8,
    /// `adev->rev_id`: the NBIO `STRAP_ATI_REV_ID` strap
    /// (`amdgpu_device_get_rev_id`), the base of `external_rev_id`. Read
    /// by the probe on RDNA4 only; 0 elsewhere.
    pub rev_id: u8,
    /// `adev->gmc.mall_size` from the discovery MALL_INFO table
    /// (`amdgpu_discovery_get_mall_info`). Read by the probe on RDNA4 only;
    /// 0 elsewhere.
    pub mall_size: u64,
}

impl ChipInfo {
    /// Pre-discovery identity. Rembrandt and Raphael are APUs even though
    /// their coarse register families also contain discrete Navi parts.
    pub fn is_apu(&self) -> bool {
        matches!(self.did, REMBRANDT | RAPHAEL) || self.family.is_apu()
    }
}

/// One firmware blob in a chip's bring-up sequence: its canonical
/// registry name (matches what the kernel asks
/// `narf_firmware::open` for) and the PSP command that delivers it.
///
/// `optional = true` means the firmware-load path treats `NotFound`
/// as a warning and continues. APUs that have their SOS / SMU
/// PMFW resident in BIOS use this so an absent blob doesn't fail
/// bring-up.
#[derive(Copy, Clone, Debug)]
pub struct FwEntry {
    pub name: &'static str,
    pub cmd: u32,
    pub optional: bool,
}

/// Sentinel `cmd` value flagging an entry that goes through the
/// **SMU MP1** mailbox, not the PSP MP0 mailbox. The driver
/// checks for this value in `load_firmware_multi` and routes the
/// blob through `amdgpu_smu::load_pmfw` instead of
/// `psp_dispatch_one`. Hex chosen to be visually distinct from
/// any real PSP cmd id (which all sit ≤ 0x22).
pub const SMU_LOAD_PMFW_MP1: u32 = 0xFF00_0001;

impl FwEntry {
    const fn ip_fw(name: &'static str) -> Self {
        Self {
            name,
            cmd: PSP_CMD_LOAD_IP_FW,
            optional: false,
        }
    }
    const fn ta(name: &'static str) -> Self {
        Self {
            name,
            cmd: PSP_CMD_LOAD_TA,
            optional: false,
        }
    }
    const fn asd(name: &'static str) -> Self {
        Self {
            name,
            cmd: PSP_CMD_LOAD_ASD,
            optional: false,
        }
    }
    const fn toc(name: &'static str) -> Self {
        Self {
            name,
            cmd: PSP_CMD_LOAD_TOC,
            optional: false,
        }
    }
    /// SMU PMFW via MP1 mailbox (Phoenix-class). The `cmd` field
    /// here is the SMU sentinel, NOT a PSP cmd id — the dispatch
    /// loop routes accordingly.
    // Unused while the only audited families are APUs, whose PMFW is
    // BIOS-resident. Kept because a discrete bring-up needs it and because
    // deleting it would invite the next table to reach for `ip_fw` instead,
    // which loads at a different point in the PSP sequence.
    #[allow(dead_code)]
    const fn smu_pmfw(name: &'static str) -> Self {
        Self {
            name,
            cmd: SMU_LOAD_PMFW_MP1,
            optional: false,
        }
    }
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
}

// ── Per-chip firmware enumerations ─────────────────────────────────
//
// Sourced from Linux `drivers/gpu/drm/amd/amdgpu/*_v*.c`
// `MODULE_FIRMWARE` declarations + the load ordering in
// `psp_load_non_psp_fw` and `psp_hw_start` (kernel 6.10+).
//
// Load order (both families): TOC (gfx11+) → ASD (gfx9) → SMU
// (gfx11+; gfx9 APU SMU lives in BIOS) → IP firmwares (SDMA →
// CP → MES → RLC → IMU → VCN → DMCUB) → TAs.

/// Phoenix1 / Phoenix2 / HawkPoint — GFX **11.0.1**, DCN **3.1.4**,
/// PSP **13.0.4**, SDMA 6.0.1, VCN 4.0.2.
///
/// Every name here is the one Linux declares for this IP set:
/// `psp_v13_0_4.c`, `imu_v11_0.c`, `gfx_v11_0.c`, `mes_v11_0.c`,
/// `sdma_v6_0.c`, `amdgpu_vcn.c` (`FIRMWARE_VCN4_0_2`) and
/// `amdgpu_dm_dmub.h` (`FIRMWARE_DCN_314_DMUB`).
///
/// This table previously held the **Strix** bundle — GFX 11.5, DCN 3.5,
/// PSP 14.0.1 — under a doc comment that said so. Phoenix is RDNA3 and
/// Strix is RDNA3.5; they share no firmware file.
///
/// There is deliberately **no SMU entry**. Phoenix is an APU and its PMFW
/// is BIOS-resident, loaded by the PSP — exactly as `RENOIR_FW` notes for
/// GFX9 APUs. linux-firmware ships `smu_*.bin` only for discrete parts
/// (13_0_0, 13_0_6, 13_0_7, 13_0_10, 13_0_14, 14_0_2, 14_0_3); neither
/// `smu_13_0_4.bin` nor `smu_14_0_1.bin` exists anywhere, so the entry this
/// table used to carry could never have opened.
/// The ORDER is Linux's, and it is a hardware contract rather than a
/// preference. `psp_load_non_psp_fw` walks `adev->firmware.ucode[]`, which is
/// indexed by `enum AMDGPU_UCODE_ID`, so the enum's order IS the load order:
/// SDMA, then the CP engines (PFP, ME, MEC), then MES, then IMU, then RLC,
/// and only then the non-graphics blobs (VCN, DMCUB).
///
/// This table was in a different order — IMU first, SDMA near the end, RLC
/// before MES — which is one more variable between here and a GPU that comes
/// up. The PSP processes each load against state the previous ones left.
static PHOENIX_FW: &[FwEntry] = &[
    FwEntry::toc("amdgpu/psp_13_0_4_toc.bin"),
    FwEntry::ip_fw("amdgpu/sdma_6_0_1.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_0_1_pfp.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_0_1_me.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_0_1_mec.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_0_1_mes.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_0_1_mes_2.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_0_1_mes1.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_0_1_imu.bin"),
    // RLC last of the graphics firmwares: the PSP's autoload state machine
    // starts the moment this one lands, and it expects every other graphics
    // blob to have been received already.
    FwEntry::ip_fw("amdgpu/gc_11_0_1_rlc.bin"),
    FwEntry::ip_fw("amdgpu/vcn_4_0_2.bin"),
    FwEntry::ip_fw("amdgpu/dcn_3_1_4_dmcub.bin"),
    FwEntry::ta("amdgpu/psp_13_0_4_ta.bin"),
];

/// Whether `name` is the RLC blob, which is what triggers the PSP's autoload.
///
/// Matched by name because `FwEntry` carries no ucode id — the names are
/// Linux's own `MODULE_FIRMWARE` strings and a `_rlc.bin` suffix identifies
/// the blob across every family in this file.
fn is_rlc_blob(name: &str) -> bool {
    name.ends_with("_rlc.bin")
}

/// Strix Point — GFX **11.5.0**, DCN **3.5**, PSP **14.0.1**, SDMA 6.1.0,
/// VCN 4.0.5. This is the bundle that used to sit in `PHOENIX_FW`.
///
/// No SMU entry, for the same reason Phoenix has none: Strix is an APU and
/// `smu_14_0_1.bin` does not exist in linux-firmware.
///
/// Reaching this table does not mean Strix is supported — see the mapping,
/// which routes Strix to `UNAUDITED_FW`. Its DCN 3.5 display path, SMU 14
/// interface and GFX 11.5 differences have had no bring-up. The table is
/// kept correct so that work starts from facts rather than from this file.
// Unused: the mapping routes Strix to `UNAUDITED_FW` until it has a real
// bring-up. Kept correct so that work does not start by re-deriving it.
#[allow(dead_code)]
static STRIX_FW: &[FwEntry] = &[
    FwEntry::toc("amdgpu/psp_14_0_1_toc.bin"),
    FwEntry::ip_fw("amdgpu/sdma_6_1_0.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_5_0_pfp.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_5_0_me.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_5_0_mec.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_5_0_mes_2.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_5_0_mes1.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_5_0_imu.bin"),
    FwEntry::ip_fw("amdgpu/gc_11_5_0_rlc.bin"),
    FwEntry::ip_fw("amdgpu/vcn_4_0_5.bin"),
    FwEntry::ip_fw("amdgpu/dcn_3_5_dmcub.bin"),
    FwEntry::ta("amdgpu/psp_14_0_1_ta.bin"),
];

/// Renoir — GFX9, DCN 2.0, PSP 12.0. APU; SMU PMFW is BIOS-
/// resident (no smu blob on disk). MEC carries CP_MEC1_JT in the
/// same blob; jump-table extraction happens at parse time.
static RENOIR_FW: &[FwEntry] = &[
    FwEntry::asd("amdgpu/renoir_asd.bin"),
    FwEntry::ip_fw("amdgpu/renoir_pfp.bin"),
    FwEntry::ip_fw("amdgpu/renoir_me.bin"),
    FwEntry::ip_fw("amdgpu/renoir_ce.bin"),
    FwEntry::ip_fw("amdgpu/renoir_mec.bin"),
    FwEntry::ip_fw("amdgpu/renoir_rlc.bin"),
    FwEntry::ip_fw("amdgpu/renoir_sdma.bin"),
    FwEntry::ip_fw("amdgpu/renoir_vcn.bin"),
    FwEntry::ip_fw("amdgpu/renoir_dmcub.bin"),
    FwEntry::ta("amdgpu/renoir_ta.bin"),
];

/// Cezanne / Lucienne / Barcelo — "green_sardine" upstream
/// prefix. GFX9, DCN 2.1, PSP 12.0. Adds `green_sardine_mec2`
/// (second MEC pipe) absent from Renoir proper.
static GREEN_SARDINE_FW: &[FwEntry] = &[
    FwEntry::asd("amdgpu/green_sardine_asd.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_pfp.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_me.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_ce.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_mec.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_mec2.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_rlc.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_sdma.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_vcn.bin"),
    FwEntry::ip_fw("amdgpu/green_sardine_dmcub.bin"),
    FwEntry::ta("amdgpu/green_sardine_ta.bin"),
];

/// Empty list — placeholder for chips whose per-IP enumeration
/// hasn't been audited yet. `load_firmware_multi` short-circuits
/// to a single `fw_name` load when the list is empty, preserving
/// the pre-multi-IP behaviour for those chips.
static UNAUDITED_FW: &[FwEntry] = &[];

/// Test hook for [`chip_info_for_pci_id`] — the id-to-firmware mapping is
/// the one thing here that cannot be checked by reading amdgpu, so it is
/// checked against `pci.ids` and `MODULE_FIRMWARE` by a kernel test instead.
#[doc(hidden)]
pub fn __test_chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    chip_info_for_pci_id(vid, did)
}

/// The register family of a known AMD PCI id.
pub(crate) fn family_for_pci_id(vid: u16, did: u16) -> Option<Family> {
    chip_info_for_pci_id(vid, did).map(|c| c.family)
}

/// Look up family + asic + firmware name for a known PCI ID.
fn chip_info_for_pci_id(vid: u16, did: u16) -> Option<ChipInfo> {
    if vid != AMD_VENDOR {
        return None;
    }
    if let Some(profile) = crate::amdgpu_rdna2::for_pci_id(vid, did) {
        return Some(ChipInfo {
            vid,
            did,
            family: Family::Navi2,
            asic: profile.asic,
            fw_name: profile.firmware.sos,
            fw_list: UNAUDITED_FW,
            revision: 0,
            rev_id: 0,
            mall_size: 0,
        });
    }
    if let Some(known) = crate::amdgpu_rdna4::known_device(did) {
        return Some(rdna4_chip_info(did, known.chip));
    }
    let (family, asic, fw_name, fw_list) = match did {
        // Phoenix1 / Phoenix2 / HawkPoint are RDNA3: GFX 11.0.1 with
        // **DCN 3.1.4**. The comment that used to stand here said all three
        // of these plus Strix "carry RDNA3.5 iGPU → DCN 3.5", which is the
        // error the firmware tables were built on. Strix is RDNA3.5; these
        // are not, and the live display path (`amdgpu_platform::start` →
        // DCN314) has always agreed with that.
        PHOENIX_HAWKPOINT1 => (
            Family::Phoenix,
            "hawkpoint",
            "amdgpu/phoenix.bin",
            PHOENIX_FW,
        ),
        PHOENIX1 => (Family::Phoenix, "phoenix", "amdgpu/phoenix.bin", PHOENIX_FW),
        PHOENIX2 => (
            Family::Phoenix,
            "phoenix2",
            "amdgpu/phoenix.bin",
            PHOENIX_FW,
        ),
        // Strix is a different IP stack (GFX 11.5 / DCN 3.5 / PSP 14.0.1)
        // and has had no bring-up. Claiming it by handing it the Phoenix
        // family would put DCN 3.1.4 register sequences on DCN 3.5 silicon.
        STRIX_POINT => (Family::Phoenix, "strix", "amdgpu/strix.bin", UNAUDITED_FW),
        // Rembrandt is RDNA2 (GFX 10.3.6 / DCN 3.1.2) — not Phoenix, and
        // not a generation this driver has any path for.
        REMBRANDT => (
            Family::Navi2,
            "rembrandt",
            "amdgpu/rembrandt.bin",
            UNAUDITED_FW,
        ),
        RAPHAEL => (Family::Navi3, "raphael", "amdgpu/raphael.bin", UNAUDITED_FW),
        CEZANNE => (
            Family::Renoir,
            "cezanne",
            "amdgpu/cezanne.bin",
            GREEN_SARDINE_FW,
        ),
        // Lucienne shares Renoir's GFX9 + DCN 2.0 IP set; same blobs.
        LUCIENNE => (Family::Renoir, "lucienne", "amdgpu/renoir.bin", RENOIR_FW),
        // Barcelo is Cezanne-refresh; green_sardine firmware.
        BARCELO => (
            Family::Renoir,
            "barcelo",
            "amdgpu/green_sardine.bin",
            GREEN_SARDINE_FW,
        ),
        RENOIR => (Family::Renoir, "renoir", "amdgpu/renoir.bin", RENOIR_FW),
        NAVI31 => (Family::Navi3, "navi31", "amdgpu/navi31.bin", UNAUDITED_FW),
        _ => return None,
    };
    Some(ChipInfo {
        vid,
        did,
        family,
        asic,
        fw_name,
        fw_list,
        revision: 0,
        rev_id: 0,
        mall_size: 0,
    })
}

/// An RDNA4 board, listed or found by discovery alone. PSP14 selects its SOS
/// container by the discovered MP0 revision, so no single legacy image/load
/// command describes it.
fn rdna4_chip_info(did: u16, chip: crate::amdgpu_rdna4::Rdna4Chip) -> ChipInfo {
    ChipInfo {
        vid: AMD_VENDOR,
        did,
        family: Family::Navi4,
        asic: chip.asic(),
        fw_name: "",
        fw_list: UNAUDITED_FW,
        revision: 0,
        rev_id: 0,
        mall_size: 0,
    }
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
    /// This device requires the PSP command-ring loader, not the legacy helper.
    UnsupportedFirmwareLoad,
    /// SMU bring-up failed — TestMessage echo mismatch, driver-IF
    /// schema mismatch, or mailbox timeout. The MP1 base may be
    /// wrong (IP discovery missing MP1) or SMU firmware never
    /// loaded (PSP issue upstream).
    SmuBringUpFailed,
    /// The native Type-C runtime owns the live DMUB mailbox.
    DisplayFirmwareBusy,
}

// ── Driver state ───────────────────────────────────────────────────

/// The CPU-visible VRAM carve-out: BAR0's base and the size
/// `RCC_CONFIG_MEMSIZE` reports. See [`read_vram_info`].
#[derive(Copy, Clone, Debug, Default)]
pub struct VramInfo {
    /// Phys base of the CPU-visible VRAM aperture — `gmc.aper_base`.
    pub base: u64,
    /// **Real** VRAM size: `gmc.real_vram_size`, every byte the memory
    /// controller has, whether the CPU can see it or not.
    pub size: u64,
    /// **Visible** VRAM size: `gmc.visible_vram_size`, the part reachable
    /// through the aperture at [`VramInfo::base`].
    ///
    /// Bounded by both real VRAM and the mapped BAR0 length, including on
    /// APUs under passthrough. On a **discrete** card without Resizable BAR
    /// this is commonly 256 MiB against
    /// however many gigabytes the card has: a 12 GiB RX 6750 XT shows 256
    /// MiB here. Reporting the two as one number tells userspace it may CPU
    /// map all 12 GiB, and the mapping that results is of nothing.
    pub visible_size: u64,
}

impl VramInfo {
    /// Does the CPU aperture cover the whole of VRAM?
    ///
    /// Requires nonzero VRAM and a mapping covering it all; this is not an
    /// APU identity test. A discrete card with Resizable BAR can also qualify.
    pub fn fully_visible(&self) -> bool {
        self.size != 0 && self.visible_size >= self.size
    }
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
    /// Panel backlight level in percent (0–100), stored on the
    /// modeset state. `None` until the first successful `set_mode`
    /// on an APU initialises it from the period/readback state;
    /// every modeset then (re-)applies it via `set_backlight`, and
    /// every successful `set_backlight` refreshes it — so the
    /// stored level is always the last level actually programmed.
    /// Discrete GPUs have no panel and leave this `None`.
    pub backlight_percent: Option<u8>,
    pub fw_loaded: bool,
    /// IP blocks enumerated from the on-die discovery table (top
    /// of VRAM, parsed at probe time). Empty when the silicon
    /// doesn't publish a discovery blob or the read yielded
    /// garbage (typical on QEMU / older chips); callers fall
    /// back to the hardcoded `Family::mp0_base()` table.
    pub ip_blocks: Vec<IpBlock>,
    /// Graphics-core topology from the same discovery binary's
    /// `table_list[GC]`. `None` when the silicon publishes no GC table
    /// (pre-discovery parts, and QEMU), or when it failed its checksum —
    /// a wrong CU count is wrong shader code generation, so this fails
    /// closed rather than defaulting.
    ///
    /// `AMDGPU_INFO_DEV_INFO` reports most of it to userspace verbatim.
    pub gc_info: Option<crate::amdgpu_discovery::GcInfo>,
    /// Immutable platform VBIOS captured at probe, when available.
    pub vbios: Option<crate::amdgpu_vbios::Vbios>,
}

impl core::fmt::Debug for AmdGpu {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdGpu")
            .field("chip", &self.chip)
            .field("fw_loaded", &self.fw_loaded)
            .finish_non_exhaustive()
    }
}

/// Execute synchronous probe I/O only after the PCI epoch check.
struct ProbeOp<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for ProbeOp<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
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
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, AmdgpuError> {
        // Linux binds an unlisted AMD display function as CHIP_IP_DISCOVERY
        // and identifies it from the discovery blob; only RDNA4 is admitted
        // that way here (see `amdgpu_rdna4`). Everything else stays listed.
        let listed = chip_info_for_pci_id(device.id.vendor, device.id.device);
        if listed.is_none() && device.id.vendor != AMD_VENDOR {
            return Err(AmdgpuError::UnknownAsic);
        }
        // SAFETY: caller-authority over BAR0 + BAR5.
        let fb_bar = unsafe { map_bar(device, BAR_FB) }.map_err(|error| {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: {:04x}:{:04x} BAR{BAR_FB} mapping failed: {error:?}",
                device.id.vendor,
                device.id.device,
            );
            AmdgpuError::BarMapFailed
        })?;
        // SAFETY: caller-authority over BAR0 + BAR5 (the `bring_up` contract);
        // `BAR_REGS` selects the MMIO register BAR which the caller owns
        // exclusively for the duration of probe.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let regs = unsafe { map_bar(device, BAR_REGS) }.map_err(|error| {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: {:04x}:{:04x} BAR{BAR_REGS} mapping failed: {error:?}",
                device.id.vendor,
                device.id.device,
            );
            AmdgpuError::BarMapFailed
        })?;

        if regs.len < MM_DATA + 4 {
            return Err(AmdgpuError::BarMapFailed);
        }
        cap.invoke(ProbeOp(|| {
            // SAFETY: probe exclusively owns a live BAR5 mapping of at
            // least eight bytes, under the current PCI capability.
            if let Err(error) = unsafe { index::probe(&regs) } {
                use core::fmt::Write as _;
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: {:04x}:{:04x} MM_INDEX probe failed: {error:x?}; expected={:#010x} (BAR{BAR_REGS} phys={:#x} virt={:#x} len={:#x})",
                    device.id.vendor,
                    device.id.device,
                    index::PROBE_ADDRESS,
                    regs.phys.raw(),
                    regs.virt,
                    regs.len,
                );
                return Err(AmdgpuError::DeviceGone);
            }
            Ok(())
        }))
        .map_err(|_| AmdgpuError::DeviceGone)??;

        // RCC_CONFIG_MEMSIZE is absolute and needs no discovered IP base.
        // SAFETY: both mappings belong to this exclusively owned device;
        // the operation runs under live PCI authority.
        let vram = cap
            .invoke(ProbeOp(|| unsafe { read_vram_info(&regs, &fb_bar) }))
            .map_err(|_| AmdgpuError::DeviceGone)?;

        // Try to parse the on-die IP discovery table. Lives in
        // last `DISCOVERY_TMR_OFFSET` bytes of VRAM. A discrete card's
        // discovery table usually lies outside BAR0; the reader uses the
        // BAR5 memory index/data ports for that range.
        // On QEMU the read yields all-ones / garbage and
        // discovery fails closed with `BadSignature` — log and
        // continue using the hardcoded `Family::mp0_base()`
        // table.
        //
        let (ip_blocks, gc_info, mall_size) = cap
            .invoke(ProbeOp(|| {
                // SAFETY: current PCI authority; probe exclusively owns both
                // mappings and the shared index latch for the whole read.
                let mut reader =
                    unsafe { crate::amdgpu_vram_access::MmioReader::new(&fb_bar, &regs) };
                read_discovery(&mut reader, vram.size)
            }))
            .map_err(|_| AmdgpuError::DeviceGone)?;

        let die = crate::amdgpu_rdna4::Rdna4Chip::from_ip_blocks(&ip_blocks);
        let mut chip = match (listed, die) {
            // A listed RDNA4 id is named by its discovered die, not its id.
            (Some(c), Some(die)) if c.family == Family::Navi4 => ChipInfo {
                asic: die.asic(),
                ..c
            },
            (Some(c), _) => c,
            (None, Some(die)) => rdna4_chip_info(device.id.device, die),
            (None, None) => return Err(AmdgpuError::UnknownAsic),
        };
        let rdna4 = chip.family == Family::Navi4 && die.is_some();
        // pdev->revision, the kicker-firmware key and DEV_INFO `pci_rev`.
        // Linux caches it in `pci_setup_device`, and a function whose config
        // header cannot be read is never enumerated, so never probed: RDNA4
        // fails closed. Other families keep their historical 0 fallback.
        chip.revision = match narf_bus::pci::read_config32(cap, device, 0x08) {
            Ok(v) => v as u8,
            Err(_) if rdna4 => return Err(AmdgpuError::DeviceGone),
            Err(_) => 0,
        };
        if rdna4 {
            // soc24_common_early_init: `adev->rev_id =
            // amdgpu_device_get_rev_id(adev)`, NBIO's ATI_REV_ID strap,
            // which DEV_INFO publishes as `chip_rev` and offsets into
            // `external_rev`. It is not the PCI revision.
            let at = crate::amdgpu_rdna4::rev_id_strap(&ip_blocks)
                .filter(|at| at.checked_add(4).is_some_and(|end| end <= regs.len))
                .ok_or(AmdgpuError::UnknownAsic)?;
            // SAFETY: bounded above inside the exclusively owned BAR5
            // mapping; a strap register read has no side effects.
            let strap = cap
                .invoke(ProbeOp(|| unsafe { regs.read32(at) }))
                .map_err(|_| AmdgpuError::DeviceGone)?;
            if strap == 0xFFFF_FFFF {
                return Err(AmdgpuError::DeviceGone);
            }
            chip.rev_id = crate::amdgpu_rdna4::rev_id(strap);
            chip.mall_size = mall_size;
        }

        // Cross-check the pre-discovery identity. The actual BAR mapping,
        // rather than APU identity, always bounds CPU-visible VRAM.
        let mut apu_disagreement = None;
        if let Some(gc) = ip_blocks
            .iter()
            .find(|b| b.hw_id == amdgpu_discovery::HW_ID_GC && b.instance == 0)
        {
            let from_gc = gc_version_is_apu(gc.major, gc.minor, gc.revision);
            if from_gc != chip.is_apu() {
                apu_disagreement = Some((gc.major, gc.minor, gc.revision));
            }
        }
        if let Some((a, b, c)) = apu_disagreement {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: {}: GC {}.{}.{} says {} but the PCI table says {}; \
                 trusting the GC version",
                chip.asic,
                a,
                b,
                c,
                if gc_version_is_apu(a, b, c) {
                    "APU"
                } else {
                    "discrete"
                },
                if chip.is_apu() { "APU" } else { "discrete" },
            );
        }

        Ok(Self {
            fb_bar,
            regs,
            chip,
            vram,
            mode: None,
            backlight_percent: None,
            fw_loaded: false,
            gc_info,
            ip_blocks,
            vbios: None,
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
        self.ip_block_base_idx(hw_id, instance, 0)
    }

    /// An IP block's base address in window `base_idx`.
    ///
    /// A SOC15 register is addressed as `reg_offset[IP][inst][BASE_IDX] +
    /// dword_id`, and `BASE_IDX` is a property of the REGISTER, not of the
    /// block: within GC, `CP_RB0_BASE` is window 0 while `GRBM_GFX_INDEX`,
    /// `CP_GFX_CNTL` and `GRBM_GFX_CNTL` are window 1, and the whole MP1
    /// mailbox is window 1 on Phoenix.
    ///
    /// Everything here used `base_addrs[0]` unconditionally, so a window-1
    /// register was addressed from window 0 — a different base entirely, so
    /// the write landed on whatever register sits at that offset there. The
    /// offsets were right and the window was not.
    ///
    /// `None` when the block was not discovered or declares fewer bases than
    /// asked for: a caller must not silently fall back to window 0, which is
    /// the behaviour being fixed.
    pub fn ip_block_base_idx(&self, hw_id: u16, instance: u8, base_idx: usize) -> Option<u32> {
        let block = amdgpu_discovery::find_ip(&self.ip_blocks, hw_id, instance)?;
        if base_idx >= block.num_bases as usize {
            return None;
        }
        block.base_addrs.get(base_idx).copied()
    }

    pub fn chip_info(&self) -> ChipInfo {
        self.chip
    }
    pub fn vram_info(&self) -> VramInfo {
        self.vram
    }
    /// Discovered GC identity, or the PCI fallback when discovery is absent.
    pub fn is_apu(&self) -> bool {
        device_is_apu(&self.chip, &self.ip_blocks)
    }
    pub fn is_ready(&self) -> bool {
        self.fw_loaded
    }

    // ── Foundations-wave register surfaces ─────────────────────────
    //
    // GFX (GRBM_STATUS / GRBM_GFX_INDEX / CP_VERSION) and GMC
    // (system aperture) read paths used by chip-identification +
    // subsequent ring/scheduler bring-up. Pure reads — no engine
    // programming. See `amdgpu_gfx.rs` and `amdgpu_gmc.rs` for the
    // register-offset constants and pure decoders.

    /// Per-family GFX `mmGRBM_STATUS` byte offset within the GC IP
    /// block window. GFX9 (Renoir) and GFX11 (Phoenix) place the
    /// register at distinct offsets.
    /// This chip's GFX generation, for the per-generation register tables.
    fn gfx_generation(&self) -> Option<crate::amdgpu_gfx::GfxGeneration> {
        Some(match self.chip.family {
            Family::Navi4 => return None,
            Family::Phoenix | Family::Navi3 => crate::amdgpu_gfx::GfxGeneration::Gfx11,
            _ => crate::amdgpu_gfx::GfxGeneration::Gfx9,
        })
    }

    /// Resolve a `(byte offset, GC window)` register location to the dword
    /// register ID the indexed helpers accept.
    ///
    /// Two conversions happen here and nowhere else. `amdgpu_gfx`'s `*_REL`
    /// constants are BYTE offsets — that module's own callers reach registers
    /// through a directly mapped window and scale with `<< 2` — while
    /// [`mm_read`] and [`mm_write`] accept DWORD register IDs and scale them
    /// for the byte-addressed MM_INDEX port. The register selects its window
    /// in `base_addrs` rather than always using window 0.
    ///
    /// `None` when discovery did not publish that window: a caller must not
    /// fall back to window 0.
    fn gc_reg(&self, location: (u32, usize)) -> Option<u32> {
        let (rel, base_idx) = location;
        let base = self.ip_block_base_idx(amdgpu_discovery::HW_ID_GC, 0, base_idx)?;
        Some(base + mm_dword(rel))
    }

    /// Resolve the GC IP block base from discovery. None on
    /// pre-discovery silicon or when the discovery blob didn't
    /// land a GC entry.
    pub fn gc_base(&self) -> Option<u32> {
        self.ip_block_base(amdgpu_discovery::HW_ID_GC, 0)
    }

    /// GC base window 1 — where `GRBM_GFX_INDEX`, `CP_GFX_CNTL` and
    /// `GRBM_GFX_CNTL` live. See [`AmdGpu::ip_block_base_idx`].
    pub fn gc_base_1(&self) -> Option<u32> {
        self.ip_block_base_idx(amdgpu_discovery::HW_ID_GC, 0, 1)
    }

    /// Read `mmGRBM_STATUS`. Returns None when the GC base isn't
    /// resolvable (discovery missing) so the caller can fall back
    /// to a chip-presence heuristic. On real silicon the value
    /// is non-sentinel (not 0xFFFF_FFFF); QEMU returns 0 (idle).
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively (MM_INDEX / MM_DATA latch).
    pub unsafe fn read_grbm_status(&self) -> Option<crate::amdgpu_gfx::GrbmStatus> {
        let off = self.gc_reg(self.gfx_generation()?.grbm_status_rel())?;
        // SAFETY: caller-asserted BAR5 ownership; mm_read uses the
        // MM_INDEX/MM_DATA pair which is a r/w latch with no side
        // effect on the addressed register.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let raw = unsafe { mm_read(&self.regs, off) };
        Some(crate::amdgpu_gfx::GrbmStatus { raw })
    }

    /// Write `mmGRBM_GFX_INDEX` to target a specific SE/SH/instance
    /// (or broadcast). Subsequent indexed register reads against
    /// the GC block hit the selected lane. Foundations wave
    /// exposes the write so the scheduler bring-up wave can drive
    /// it without re-deriving the offset.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively. The value SHOULD be one
    /// produced by `grbm_gfx_index_broadcast()` /
    /// `grbm_gfx_index_for()`; raw values that name nonexistent
    /// SE/SH lanes leave the chip in a misconfigured indexing
    /// state until the next broadcast write.
    pub unsafe fn write_grbm_gfx_index(&self, value: u32) -> Option<()> {
        // `GRBM_GFX_INDEX` is **BASE_IDX 1**, so it is addressed from the GC
        // block's second window — not `gc_base()`, which is window 0.
        //
        // LINUX-GAP: this used `gc_base()` and added `GRBM_GFX_INDEX_REL`
        // directly. Two errors compounding: the wrong window, and a byte
        // offset (0x2200 * 4) added to a dword base, so the write went to
        // dword 0x8800 of window 0. `gc_base_1()` existed and nothing called
        // it; `GC_BASE_IDX_1` named this register as one that needed it.
        let off = self.gc_reg(self.gfx_generation()?.grbm_gfx_index_rel())?;
        // SAFETY: caller-asserted BAR5 ownership.
        unsafe {
            mm_write(&self.regs, off, value);
        }
        Some(())
    }

    /// Load the GFX CP's three firmware images and un-halt the engines.
    ///
    /// This is the glue `amdgpu_cp_fw` documented and did not have. Nothing
    /// implemented `CpFwMmio` outside that module's test mock, and the IC
    /// registers are all BASE_IDX 1 while `CP_STAT` is BASE_IDX 0, so neither
    /// window was reachable from a caller holding one `gc_base`.
    ///
    /// `None` when discovery did not publish both GC windows — never a
    /// fallback to window 0, which would address an unrelated register.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively (MM_INDEX / MM_DATA latch), and the three
    /// GPU addresses must each name a 64 KiB-aligned, GPU-visible firmware
    /// image that stays mapped for as long as the CP runs.
    pub unsafe fn start_gfx_cp(
        &self,
        pfp_gpu_addr: u64,
        me_gpu_addr: u64,
        mec_gpu_addr: u64,
    ) -> Option<Result<(), crate::amdgpu_cp_fw::CpFwError>> {
        let idx0 = self.gc_base()?;
        let idx1 = self.gc_base_1()?;
        let generation = self.gfx_generation()?;
        // SAFETY: caller-asserted BAR5 ownership, held for the adapter's whole
        // lifetime — it borrows `self.regs` and never outlives this frame.
        let mut mmio = CpRegsAdapter { regs: &self.regs };
        Some(
            crate::amdgpu_cp_fw::load_all_cp_fw(
                &mut mmio,
                idx1,
                pfp_gpu_addr,
                me_gpu_addr,
                mec_gpu_addr,
            )
            .and_then(|()| crate::amdgpu_cp_fw::cp_enable(&mut mmio, generation, idx0, idx1)),
        )
    }

    /// Apply a GFX11 ring-init sequence: perform its writes and its waits.
    ///
    /// [`crate::amdgpu_gfx::build_gfx11_ring_init`] returns a value rather
    /// than touching hardware, so the whole sequence is inspectable without a
    /// GPU. Nothing executed it. This does, through the same `CpFwMmio`
    /// adapter the firmware load uses — which is where the sequence's **byte**
    /// offsets become the DWORD register IDs the indexed helpers accept.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively for the whole sequence: MM_INDEX is a
    /// shared latch, and a concurrent reader between the index and the data
    /// write lands on a different register.
    pub unsafe fn apply_gfx11_sequence(&self, seq: &crate::amdgpu_gfx::Gfx11Sequence) {
        if self.gfx_generation() != Some(crate::amdgpu_gfx::GfxGeneration::Gfx11) {
            return;
        }
        // SAFETY: caller-asserted BAR5 ownership, held for the adapter's
        // whole lifetime — it borrows `self.regs` and never outlives this
        // frame.
        let mut mmio = CpRegsAdapter { regs: &self.regs };
        crate::amdgpu_gfx::apply_gfx11_sequence(&mut mmio, seq, &mut delay_us);
    }

    /// `mes_v11_0_get_fw_version` — read each MES pipe's firmware version.
    ///
    /// Returns `(scheduler, kiq)`. A read cannot be part of a
    /// [`crate::amdgpu_gfx::Gfx11Sequence`], so this is the one bring-up step
    /// that has to be a function: select me 3 / the pipe, read
    /// `CP_MES_GP3_LO`, and restore the selection.
    ///
    /// **Restoring the selection is not optional.** `GRBM_GFX_CNTL` is a
    /// latch; leaving the MES selected sends the next block's register writes
    /// to it. `mes_v11_0_get_fw_version` restores it to all-zero and so does
    /// this, including on the error path.
    ///
    /// Both reads go through the same two registers, so the pipe selection is
    /// the only thing distinguishing them — which is why a version read that
    /// forgot to re-select would return the scheduler's version twice and look
    /// entirely plausible.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively: `GRBM_GFX_CNTL` and MM_INDEX are both
    /// shared latches, and a concurrent accessor between the select and the
    /// read lands on another engine's register.
    pub unsafe fn read_mes_fw_versions(
        &self,
    ) -> Option<(
        crate::amdgpu_mes_hw::MesVersion,
        crate::amdgpu_mes_hw::MesVersion,
    )> {
        use crate::amdgpu_mes_hw as hw;
        if self.gfx_generation() != Some(crate::amdgpu_gfx::GfxGeneration::Gfx11) {
            return None;
        }
        let idx1 = self.gc_base_1()?;
        let cntl = idx1 + hw::GRBM_GFX_CNTL;
        let gp3 = idx1 + hw::CP_MES_GP3_LO;

        // SAFETY: caller-asserted exclusive BAR5 ownership. Each read is
        // bracketed by the selection it needs, and the selection is restored
        // below before anything else can use the latch.
        let read_pipe = |pipe: u32| unsafe {
            mm_write(&self.regs, cntl, hw::fw_version_select(pipe));
            let raw = mm_read(&self.regs, gp3);
            hw::MesVersion::decode(raw)
        };
        let sched = read_pipe(hw::MES_SCHED_PIPE);
        let kiq = read_pipe(hw::MES_KIQ_PIPE);
        // SAFETY: as above.
        unsafe { mm_write(&self.regs, cntl, hw::grbm_select(0, 0, 0, 0)) };
        Some((sched, kiq))
    }

    /// Read the full `ApertureLayout` (VRAM + system aperture)
    /// through the MC register block. VRAM aperture mirrors what
    /// `vram_info()` returns; system aperture is fresh from the
    /// MC each call.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively.
    pub unsafe fn read_aperture_layout(&self) -> Option<crate::amdgpu_gmc::ApertureLayout> {
        // LINUX-GAP: this read GFX9's `mmMC_VM_SYSTEM_APERTURE_LOW_ADDR`
        // (0x0985) on every family, with no IP base added. Two errors: Phoenix
        // uses `regGCMC_VM_SYSTEM_APERTURE_LOW_ADDR` (0x167d), a different
        // register — and both are SOC15 registers addressed as
        // `reg_offset[GC][0][0] + dword_id`, so a bare id names something
        // else. Unlike `read_vram_info` this runs after discovery, so the
        // base is available; the function returns `None` rather than reading
        // an unbased address when it is not.
        let (low, high) = match self.gfx_generation()? {
            crate::amdgpu_gfx::GfxGeneration::Gfx11 => (
                crate::amdgpu_gmc::GCMC_VM_SYSTEM_APERTURE_LOW_ADDR_GFX11,
                crate::amdgpu_gmc::GCMC_VM_SYSTEM_APERTURE_HIGH_ADDR_GFX11,
            ),
            crate::amdgpu_gfx::GfxGeneration::Gfx9 => (
                crate::amdgpu_gmc::MC_VM_SYSTEM_APERTURE_LOW_ADDR,
                crate::amdgpu_gmc::MC_VM_SYSTEM_APERTURE_HIGH_ADDR,
            ),
        };
        let base = self.ip_block_base(amdgpu_discovery::HW_ID_GC, 0)?;
        // VRAM comes from the cached probe-time read; only the system
        // aperture is re-read here.
        // SAFETY: caller-asserted BAR5 ownership.
        let sys_low_field = unsafe { mm_read(&self.regs, base + low) };
        // SAFETY: same.
        let sys_high_field = unsafe { mm_read(&self.regs, base + high) };
        let (sys_low, sys_high) =
            crate::amdgpu_gmc::decode_system_aperture(sys_low_field, sys_high_field);
        Some(crate::amdgpu_gmc::ApertureLayout {
            vram_base: self.vram.base,
            vram_size: self.vram.size,
            system_low: sys_low,
            system_high: sys_high,
        })
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

    /// Is a display connected on `connector`?
    ///
    /// Reads `DC_HPD_INT_STATUS.DC_HPD_SENSE_DELAYED`, the debounced sense
    /// bit `dal_hw_hpd_get_value` returns in interrupt mode
    /// (`gpio/hw_hpd.c:65-81`). This is the read `amdgpu_hpd` needs for
    /// `HpdEvent::from_ih_cookie`'s `asserted` argument: the interrupt cookie
    /// says which connector fired and whether it was a plug event or a sink
    /// IRQ, but not whether the result is connected or disconnected — Linux
    /// calls `dc_link_detect` to go and look, and this is that look.
    ///
    /// `None` when DCN was not discovered or `connector` is past the HPD
    /// blocks this ASIC has. Note the cookie space is wider than the register
    /// space: see [`crate::amdgpu_dcn::HPD_BLOCKS`].
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively.
    pub unsafe fn hpd_asserted(&self, connector: u8) -> Option<bool> {
        use crate::amdgpu_dcn as dcn;
        if self.chip.family == Family::Navi4 || connector >= dcn::HPD_BLOCKS {
            return None;
        }
        let base = self.ip_block_base_idx(amdgpu_discovery::HW_ID_DCN, 0, 2)?;
        let reg = base + dcn::for_pipe(dcn::HPD0_DC_HPD_INT_STATUS, connector, dcn::HPD_STRIDE);
        // SAFETY: caller-asserted BAR5 ownership; a read-only status register
        // reached through the MM_INDEX/MM_DATA pair.
        let status = unsafe { mm_read(&self.regs, reg) };
        if status == u32::MAX {
            return None;
        }
        Some(status & dcn::DC_HPD_SENSE_DELAYED != 0)
    }

    /// Read the firmware-programmed scanout geometry out of DCN.
    ///
    /// Returns `None` when no pipe is fetching, when DCN was not discovered,
    /// or when the registers read back as a vanished device.
    ///
    /// LINUX-GAP: this read four constants — 0x5C00, 0x5C04, 0x5C08, 0x5C0C —
    /// described as "OTG H_TOTAL / V_TOTAL register-bus offsets per the public
    /// DCN1+ register map". No DCN header defines anything in that range;
    /// `regOTG0_OTG_H_TOTAL` is dword 0x1b2a. They were also used with no DCN
    /// base and the indexed helpers, which accept DWORD register IDs, so the reads
    /// landed on four unrelated registers. The derivation on top was wrong
    /// too: `h_active` came out as `h_total - (blank_end - blank_start)`, but
    /// `optc1_program_timing` writes `OTG_H_BLANK_END` BELOW
    /// `OTG_H_BLANK_START` (end = start - h_active), so that subtraction
    /// saturated to zero and the function would have reported
    /// `h_active == h_total`. `stride` was assumed equal to the width.
    ///
    /// None of that is needed. The HUBP's own viewport and pitch registers say
    /// what the pipe is fetching, which is the question being asked —
    /// `amdgpu_platform::scan_surfaces` reads the same ones to inventory an
    /// inherited scanout.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively.
    unsafe fn passive_mode(&self) -> Option<Mode> {
        if self.chip.family == Family::Navi4 {
            return None;
        }
        use crate::amdgpu_dcn as dcn;
        // Every HUBP / HUBPREQ register is BASE_IDX 2.
        let base = self.ip_block_base_idx(amdgpu_discovery::HW_ID_DCN, 0, 2)?;
        for pipe in 0..dcn::DCN_PIPES {
            let at = |reg: u32| base + dcn::for_pipe(reg, pipe, dcn::HUBP_PIPE_STRIDE);
            // SAFETY: caller-asserted BAR5 ownership; MM_INDEX/MM_DATA pair,
            // and these are read-only hub status registers.
            let cntl = unsafe { mm_read(&self.regs, at(dcn::HUBP0_DCHUBP_CNTL)) };
            if cntl == u32::MAX {
                return None;
            }
            // `HUBP_BLANK_EN` set means this pipe is not fetching.
            if cntl & dcn::HUBP_BLANK_FORCE != 0 {
                continue;
            }
            // SAFETY: same bank, same contract.
            let viewport =
                unsafe { mm_read(&self.regs, at(dcn::HUBP0_DCSURF_PRI_VIEWPORT_DIMENSION)) };
            // SAFETY: same.
            let pitch = unsafe { mm_read(&self.regs, at(dcn::HUBPREQ0_DCSURF_SURFACE_PITCH)) };
            if viewport == u32::MAX || pitch == u32::MAX {
                return None;
            }
            let width = viewport & dcn::SURFACE_DIMENSION_MASK;
            let height = (viewport >> 16) & dcn::SURFACE_DIMENSION_MASK;
            // The pitch register holds one less than the pitch.
            let stride = (pitch & dcn::SURFACE_DIMENSION_MASK) + 1;
            if width == 0 || height == 0 || stride < width {
                return None;
            }
            return Some(Mode {
                width,
                height,
                stride,
            });
        }
        None
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
        if matches!(self.chip.family, Family::Phoenix | Family::Navi4)
            || crate::amdgpu_rdna2::for_pci_id(self.chip.vid, self.chip.did).is_some()
        {
            // Navi22 SOS uses amdgpu_psp_boot and an owned GPU VRAM staging
            // buffer; this legacy entry point cannot satisfy that contract.
            return Err(AmdgpuError::UnsupportedFirmwareLoad);
        }
        if crate::amdgpu_usbc::firmware_busy() {
            return Err(AmdgpuError::DisplayFirmwareBusy);
        }
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

        // LINUX-GAP: there is no MP0 mailbox command that loads a firmware
        // image. What stood here wrote `phys` lo/hi to C2PMSG_64 and _67, a
        // `cmd | size << 8` trigger to C2PMSG_69, and polled C2PMSG_64 for a
        // completion — a sequence that appears in no `psp_v*.c`. C2PMSG_67 is
        // never addressed by the driver, no command word packs a size, and
        // the register polled for completion is always the one the command
        // was written to. `GFX_CMD_ID_LOAD_IP_FW` is the `cmd_id` of a
        // `psp_gfx_cmd_resp` placed in the GPCOM ring buffer, which
        // `amdgpu_psp_ring` builds and the live bring-up path uses.
        //
        // Fail closed rather than write that to live registers. Rewiring this
        // scaffold onto the ring, and recording `BoundFirmware` when it
        // succeeds, is the follow-up.
        let _ = (mp0_base, phys, size, view.sha256, view.signer);
        Err(AmdgpuError::UnsupportedFirmwareLoad)
    }

    /// Dispatch one firmware blob through the PSP mailbox using
    /// the requested command. Used by both `load_firmware_multi`
    /// (real bring-up) and other future TA-invocation paths.
    /// Returns `Ok(true)` when the blob loaded, `Ok(false)` when
    /// it was absent but the entry was marked `optional`, and `Err`
    /// on any hard failure.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively (regs MMIO) and `mp0_base` is
    /// the live MP0 register window for this chip.
    unsafe fn psp_dispatch_one(
        &mut self,
        entry: &FwEntry,
        mp0_base: u32,
        fw_authority: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<bool, AmdgpuError> {
        // SMU PMFW gets routed through MP1, not MP0. The cmd
        // sentinel `SMU_LOAD_PMFW_MP1` flags this — Phoenix-class
        // SMU firmware lives on disk and uploads via the SMU
        // mailbox's `LoadMicrocode` message (smu_v14_0.c in
        // Linux). Renoir-class lists never carry this entry.
        if entry.cmd == SMU_LOAD_PMFW_MP1 {
            // SAFETY: caller-asserted exclusive BAR5; same MMIO
            // discipline as the PSP path.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            return unsafe { self.smu_dispatch_pmfw(entry, fw_authority) };
        }

        let cap = match narf_firmware::open(entry.name, fw_authority) {
            Ok(c) => c,
            Err(narf_firmware::FirmwareError::NotFound) => {
                if entry.optional {
                    return Ok(false);
                }
                return Err(AmdgpuError::FirmwareMissing);
            }
            Err(_) => return Err(AmdgpuError::FirmwareLoadFailed),
        };
        let view = narf_firmware::view_of(&cap).map_err(|_| AmdgpuError::FirmwareLoadFailed)?;
        let phys = view.phys;
        let size = view.bytes.len() as u32;
        if size == 0 || size & 0xFF00_0000 != 0 {
            // PSP_CMD trigger word packs size into bits[31:8]; > 16 MiB
            // doesn't fit. Real blobs cap at a few MiB so this is a
            // guard, not a real limit.
            return Err(AmdgpuError::FirmwareLoadFailed);
        }

        // LINUX-GAP: as in `load_firmware` — the mailbox carries no image
        // load, so there is nothing correct to write here. Every `FwEntry`
        // command in `chip.fw_list` (`LOAD_IP_FW`, `LOAD_TA`, `LOAD_ASD`,
        // `LOAD_TOC`) is a GPCOM ring `cmd_id`, which `amdgpu_psp_ring`
        // submits. Fail closed until this is rewired onto that ring.
        let _ = (mp0_base, phys, size, entry.cmd, view.sha256, view.signer);
        Err(AmdgpuError::UnsupportedFirmwareLoad)
    }

    /// Dispatch an SMU PMFW blob via the MP1 mailbox. Phoenix-class
    /// only — `smu_v14_0.c::smu_v14_0_load_microcode` in Linux.
    /// The blob is opened from the registry, the raw payload is
    /// programmed into the SMU's PMFW slots, and
    /// `PPSMC_MSG_LoadMicrocode` kicks the SMU's loader.
    ///
    /// Returns `Ok(true)` when the SMU acks the load, `Ok(false)`
    /// for an absent optional blob, `Err` on hard failure. Same
    /// surface as `psp_dispatch_one` so the multi-load loop can
    /// call either without branching.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively. The firmware blob phys stays
    /// valid through the SMU mailbox handshake.
    unsafe fn smu_dispatch_pmfw(
        &mut self,
        entry: &FwEntry,
        fw_authority: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<bool, AmdgpuError> {
        let cap = match narf_firmware::open(entry.name, fw_authority) {
            Ok(c) => c,
            Err(narf_firmware::FirmwareError::NotFound) => {
                if entry.optional {
                    return Ok(false);
                }
                return Err(AmdgpuError::FirmwareMissing);
            }
            Err(_) => return Err(AmdgpuError::FirmwareLoadFailed),
        };
        let view = narf_firmware::view_of(&cap).map_err(|_| AmdgpuError::FirmwareLoadFailed)?;
        let mp1_base = self
            .mp1_mailbox_base()
            .ok_or(AmdgpuError::SmuBringUpFailed)?;
        let phys = view.phys;
        let size = view.bytes.len() as u32;

        let mut adapter = SmuRegsAdapter { regs: &self.regs };
        match crate::amdgpu_smu::load_pmfw(&mut adapter, mp1_base, phys, size) {
            Ok(()) => {
                narf_drivers::set_bound_firmware(
                    "amdgpu",
                    narf_drivers::BoundFirmware {
                        blob_name: alloc::string::String::from(entry.name),
                        sha256: view.sha256,
                        signer: view.signer,
                        version: None,
                    },
                );
                Ok(true)
            }
            Err(_) => Err(AmdgpuError::FirmwareLoadFailed),
        }
    }

    /// Walk the chip's per-IP firmware list (`chip.fw_list`) and
    /// dispatch each entry through the PSP mailbox in declaration
    /// order. Falls through to the single-blob `load_firmware` when
    /// the chip's list is empty (unaudited chips). Sets
    /// `self.fw_loaded` only after the entire required set lands.
    ///
    /// Per-entry semantics:
    ///   - `optional = true`  → NotFound is a warning, continue.
    ///   - `optional = false` → NotFound bails with FirmwareMissing.
    ///   - PSP reject / timeout always bails with FirmwareLoadFailed.
    ///
    /// Returns the `MultiFwReport` for diagnostics — how many
    /// blobs loaded vs skipped, and which (if any) was the last
    /// optional skip so an operator can correlate with what's
    /// missing from the initramfs.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively. The firmware blob phys stays
    /// valid through the entire PSP handshake (the cap stays alive
    /// in scope while the per-blob mailbox sequence runs).
    pub unsafe fn load_firmware_multi(
        &mut self,
        fw_authority: &Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<MultiFwReport, AmdgpuError> {
        if matches!(self.chip.family, Family::Phoenix | Family::Navi4)
            || crate::amdgpu_rdna2::for_pci_id(self.chip.vid, self.chip.did).is_some()
        {
            return Err(AmdgpuError::UnsupportedFirmwareLoad);
        }
        if crate::amdgpu_usbc::firmware_busy() {
            return Err(AmdgpuError::DisplayFirmwareBusy);
        }
        // Fall through to the single-blob path for chips whose IP
        // enumeration we haven't audited yet. Preserves the
        // pre-multi-IP behaviour without forcing every PCI ID to
        // have a populated list.
        if self.chip.fw_list.is_empty() {
            // SAFETY: same precondition.
            return unsafe { self.load_firmware(fw_authority) }.map(|_| MultiFwReport {
                loaded: 1,
                skipped_optional: 0,
                last_optional_skip: None,
            });
        }
        let mp0_base = self.mp0_base().ok_or(AmdgpuError::FirmwareLoadFailed)?;

        let mut loaded = 0usize;
        let mut skipped_optional = 0usize;
        let mut last_optional_skip: Option<alloc::string::String> = None;

        let autoload = matches!(self.chip.family, Family::Phoenix);
        for entry in self.chip.fw_list {
            // SAFETY: caller-asserted exclusive BAR5; mp0_base
            // is resolved live (not stale).
            // SAFETY: Valid MMIO bounds or trusted driver environment
            match unsafe { self.psp_dispatch_one(entry, mp0_base, fw_authority) } {
                Ok(true) => loaded += 1,
                Ok(false) => {
                    skipped_optional += 1;
                    last_optional_skip = Some(alloc::string::String::from(entry.name));
                }
                Err(e) => {
                    // Name the blob. A family's list is a dozen entries and
                    // "firmware load failed" says nothing about which one, nor
                    // whether the file was missing, malformed, or rejected by
                    // the PSP — three problems with three different fixes.
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: firmware load failed at {} (cmd {:#x}): {e:?}",
                        entry.name,
                        entry.cmd
                    );
                    return Err(e);
                }
            }

            // `psp_load_non_psp_fw`: "Start rlc autoload after psp received
            // all the gfx firmware" — fired the moment RLC lands, which is
            // why RLC is last among the graphics blobs in the table. This
            // used to run after the WHOLE list, so VCN and DMCUB had been
            // sent first; the PSP's state machine expects otherwise.
            //
            // GFX9 (the Renoir family) starts RLC by MMIO kick instead, so it
            // is skipped there.
            if autoload && is_rlc_blob(entry.name) {
                // SAFETY: caller-asserted exclusive BAR5.
                let r =
                    unsafe { psp_send_control_command(&self.regs, mp0_base, PSP_CMD_AUTOLOAD_RLC) };
                if let Err(e) = r {
                    // Fatal, as it is in Linux: `psp_rlc_autoload_start`
                    // failing returns the error from `psp_load_non_psp_fw`.
                    // A comment here used to call it non-fatal while the code
                    // returned an error — the code was right.
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "amdgpu: PSP RLC autoload failed: {e:?}; the GFX ring will not come up"
                    );
                    return Err(AmdgpuError::FirmwareLoadFailed);
                }
            }
        }

        self.fw_loaded = true;
        Ok(MultiFwReport {
            loaded,
            skipped_optional,
            last_optional_skip,
        })
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
        if self.chip.family == Family::Navi4 {
            return Err(AmdgpuError::UnknownAsic);
        }
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
        // LINUX-GAP: this selected `dcn35_modeset_sequence` for Phoenix.
        // Phoenix is DCN **3.1.4**, which agrees with DCN 2.0 on all nine OTG
        // registers; DCN 3.5 moves four of them. `amdgpu_modeset` was
        // corrected to the 2.0 sequence in an earlier pass and this call site
        // was not, so the two modeset paths disagreed — and this is the one
        // `set_mode` uses, which is what the PM resume path re-runs.
        let seq = crate::amdgpu_dcn::dcn20_modeset_sequence(
            &timing,
            self.vram.base,
            mode.stride,
            dcn_base,
        );

        // Drive the sequencer.
        // SAFETY: caller-asserted exclusive ownership of BAR5.
        unsafe {
            crate::amdgpu_dcn::execute_modeset(&self.regs, &seq);
        }

        // Display-audio resume: re-run the saved enable writes for
        // the last applied external plan when this modeset
        // re-programs the same timing (the PM-resume re-run — the
        // resume handler calls `set_mode`, which takes the non-KMS
        // path). A different timing means the mode changed since
        // the plan was applied — drop the stale audio instead of
        // programming a DTO built for another pixel clock. Empty
        // snapshot: no external audio was ever applied, no-op.
        // The video sequence above ends with OTG_MASTER_EN, so
        // scanout is live before audio starts.
        let replay = {
            let mut saved = SAVED_DISPLAY_AUDIO.lock();
            match saved.as_ref() {
                Some(s) if s.timing == timing => Some(s.writes.clone()),
                Some(_) => {
                    *saved = None;
                    None
                }
                None => None,
            }
        };
        if let Some(audio) = replay {
            // SAFETY: caller-asserted exclusive ownership of BAR5.
            unsafe {
                crate::amdgpu_dcn::execute_modeset(&self.regs, &audio);
            }
        }

        self.mode = Some(mode);
        // Panel brightness (#948): the mode is programmed, so the
        // panel must leave modeset at a defined brightness instead
        // of VBIOS residue. On an APU the first modeset
        // initialises the stored level from the period/readback
        // state (full brightness when no trustworthy readback
        // exists) and every modeset (re-)applies it via
        // `set_backlight` — which also covers the PM resume path,
        // the only other `set_mode` caller. Discrete GPUs have no
        // panel: the level stays unset and nothing is programmed.
        if self.is_apu() {
            let pct = match self.backlight_percent {
                Some(pct) => pct,
                None => {
                    // SAFETY: `set_mode`'s caller owns BAR0 + BAR5
                    // exclusively, discharging
                    // `readback_brightness_percent`'s BAR5 requirement;
                    // the readback only reads the DCN BL_PWM registers
                    // inside the window `ip_block_base` resolves.
                    let pct = unsafe { self.readback_brightness_percent() }.unwrap_or(100);
                    self.backlight_percent = Some(pct);
                    pct
                }
            };
            // Best-effort: the mode is programmed regardless, so a
            // failed apply must not misreport the modeset. The
            // level stays stored, so the next modeset or
            // `set_brightness` retries it.
            // SAFETY: caller-asserted exclusive ownership of BAR5.
            let _ = unsafe { self.set_backlight(pct) };
        }
        Ok(())
    }

    /// Execute a KMS modeset plan against live MMIO — the
    /// production caller the plan layer lacked. The video writes
    /// run first, then the plan's display-audio writes, through
    /// `amdgpu_dcn::execute_modeset_chained`: audio starts only
    /// once scanout is live (the video sequence ends with
    /// OTG_MASTER_EN). KMS bookkeeping follows
    /// (`commit_modeset_full` + `mark_active`), and the audio
    /// half is snapshotted so `set_mode` (including the PM-resume
    /// re-run) restores it after re-programming video for the
    /// same timing.
    ///
    /// The caller owns the plan: it was built by
    /// `amdgpu_modeset::plan_modeset` against this GPU's KMS
    /// state, with the DCN BASE_IDX 2 segment resolved, so the
    /// write addresses are absolute and no base resolution
    /// happens here. A plan built for another family or another
    /// device is a caller bug — the plan carries no family tag
    /// to check.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively.
    pub unsafe fn apply_modeset_plan(
        &mut self,
        kms: &mut crate::amdgpu_modeset::KmsState,
        plan: &crate::amdgpu_modeset::ModesetPlan,
        stride_pixels: u32,
        surface_phys: u64,
    ) -> Result<(), AmdgpuError> {
        if self.chip.family == Family::Navi4 {
            return Err(AmdgpuError::UnknownAsic);
        }
        if !self.fw_loaded {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        // SAFETY: caller-asserted exclusive ownership of BAR5.
        unsafe {
            crate::amdgpu_dcn::execute_modeset_chained(
                &self.regs,
                &plan.writes,
                &plan.audio_writes,
            );
        }
        crate::amdgpu_modeset::commit_modeset_full(kms, plan, stride_pixels, surface_phys);
        crate::amdgpu_modeset::mark_active(kms, plan.crtc_idx);
        // Snapshot the audio half (only when the plan carries
        // one — an internal-panel plan must not clear another
        // connector's live audio).
        if !plan.audio_writes.is_empty() {
            *SAVED_DISPLAY_AUDIO.lock() = Some(SavedDisplayAudio {
                timing: plan.timing,
                connector_idx: plan.connector_idx,
                writes: plan.audio_writes.clone(),
            });
        }
        Ok(())
    }

    /// Execute the display-audio teardown writes for a connector.
    /// Call this BEFORE the video teardown's OTG master-enable
    /// clear: the sequence mutes and disables the endpoint while
    /// scanout is still live, the mirror of
    /// `apply_modeset_plan` starting audio after it.
    ///
    /// Returns `Ok(true)` when disable writes executed,
    /// `Ok(false)` when the connector has no audio endpoint on
    /// this path or the DCN BASE_IDX 2 segment is undiscoverable
    /// (audio cannot be live without it — the enable sequence
    /// needs the same segment). The saved audio for this
    /// connector is cleared whenever the segment resolves,
    /// whether or not disable writes execute — a binding that is
    /// already gone has nothing left to tear down, but its
    /// snapshot must not survive to resurrect on a later
    /// `set_mode`.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively.
    pub unsafe fn disable_display_audio(
        &mut self,
        kms: &crate::amdgpu_modeset::KmsState,
        connector_idx: u8,
    ) -> Result<bool, AmdgpuError> {
        if self.chip.family == Family::Navi4 {
            return Err(AmdgpuError::UnknownAsic);
        }
        if !self.fw_loaded {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        let Some(dcn_base) = self.ip_block_base(amdgpu_discovery::HW_ID_DCN, 0) else {
            return Ok(false);
        };
        let Some(dcn_base2) = self.ip_block_base_idx(amdgpu_discovery::HW_ID_DCN, 0, 2) else {
            return Ok(false);
        };
        clear_saved_display_audio(connector_idx);
        let Some(writes) =
            crate::amdgpu_modeset::plan_audio_disable(kms, connector_idx, dcn_base, dcn_base2)
        else {
            return Ok(false);
        };
        if writes.is_empty() {
            return Ok(false);
        }
        // SAFETY: caller-asserted exclusive ownership of BAR5.
        unsafe {
            crate::amdgpu_dcn::execute_modeset(&self.regs, &writes);
        }
        Ok(true)
    }

    /// The audio half of an HPD disconnect for one connector.
    /// Computes the audio action from the PRE-transition state,
    /// applies the status change (which drops the CRTC binding),
    /// then executes the disable writes — the mute/disable lands
    /// while scanout is still live; the caller's video teardown
    /// (OTG master-enable clear) follows. Returns the action
    /// applied (`DisableAudio` when teardown writes ran, `None`
    /// otherwise).
    ///
    /// The IH dispatch calls this (not bare
    /// `HpdEngine::apply_to_kms`) for disconnects, so the status
    /// transition and the audio teardown stay ordered. Connects
    /// need a mode before a plan can be built, so the connect
    /// half stays with the caller: `hotplug_audio_action` →
    /// `plan_modeset` → `apply_modeset_plan`.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively.
    pub unsafe fn apply_hotplug_disconnect(
        &mut self,
        kms: &mut crate::amdgpu_modeset::KmsState,
        connector_idx: u8,
    ) -> Result<crate::amdgpu_modeset::HotplugAudioAction, AmdgpuError> {
        if self.chip.family == Family::Navi4 {
            return Err(AmdgpuError::UnknownAsic);
        }
        if !self.fw_loaded {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        // Undiscoverable bases mean no audio was ever programmed
        // through this GPU; the action still computes (it degrades
        // to `None`) and the status transition still applies.
        let dcn_base = self
            .ip_block_base(amdgpu_discovery::HW_ID_DCN, 0)
            .unwrap_or(0);
        let dcn_base2 = self
            .ip_block_base_idx(amdgpu_discovery::HW_ID_DCN, 0, 2)
            .unwrap_or(0);
        let action = crate::amdgpu_modeset::hotplug_audio_action(
            kms,
            connector_idx,
            crate::amdgpu_modeset::ConnectorStatus::Disconnected,
            dcn_base,
            dcn_base2,
        );
        // Status transition AFTER computing the action (disconnect
        // drops the CRTC binding, so a disable computed after the
        // transition would find nothing to tear down). The saved
        // audio for this connector is cleared on every disconnect
        // application, whether or not disable writes execute.
        kms.set_status(
            connector_idx,
            crate::amdgpu_modeset::ConnectorStatus::Disconnected,
        );
        clear_saved_display_audio(connector_idx);
        if let crate::amdgpu_modeset::HotplugAudioAction::DisableAudio { writes } = &action {
            // SAFETY: caller-asserted exclusive ownership of BAR5.
            unsafe {
                crate::amdgpu_dcn::execute_modeset(&self.regs, writes);
            }
        }
        Ok(action)
    }

    /// Re-execute the display-audio enable writes for every
    /// still-Connected external connector with a programmed mode,
    /// for the PM resume handler to run AFTER `set_mode`
    /// re-programs video (audio starts only once scanout is
    /// live). This is the multi-connector resume path; the
    /// `set_mode` snapshot re-run covers the last applied plan
    /// when no KMS state is at hand. Returns `Ok(true)` when
    /// writes executed, `Ok(false)` when nothing was live or the
    /// DCN bases are undiscoverable.
    ///
    /// # Safety
    /// Caller owns BAR0 + BAR5 exclusively.
    pub unsafe fn resume_display_audio(
        &mut self,
        kms: &crate::amdgpu_modeset::KmsState,
    ) -> Result<bool, AmdgpuError> {
        if self.chip.family == Family::Navi4 {
            return Err(AmdgpuError::UnknownAsic);
        }
        if !self.fw_loaded {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        let Some(dcn_base) = self.ip_block_base(amdgpu_discovery::HW_ID_DCN, 0) else {
            return Ok(false);
        };
        let Some(dcn_base2) = self.ip_block_base_idx(amdgpu_discovery::HW_ID_DCN, 0, 2) else {
            return Ok(false);
        };
        let writes = crate::amdgpu_modeset::resume_display_audio_writes(kms, dcn_base, dcn_base2);
        if writes.is_empty() {
            return Ok(false);
        }
        // SAFETY: caller-asserted exclusive ownership of BAR5.
        unsafe {
            crate::amdgpu_dcn::execute_modeset(&self.regs, &writes);
        }
        Ok(true)
    }

    /// Encoder kind for a connector kind, for probe-time encoder
    /// binding. `None` for an unrecognised connector object — the
    /// connector still mints in KMS, it just gets no encoder.
    fn encoder_kind_for_connector(
        kind: crate::amdgpu_atom_displayobj::ConnectorKind,
    ) -> Option<crate::amdgpu_modeset::EncoderKind> {
        use crate::amdgpu_atom_displayobj::ConnectorKind;
        use crate::amdgpu_modeset::EncoderKind;
        match kind {
            ConnectorKind::Dp | ConnectorKind::Edp | ConnectorKind::Usbc => {
                Some(EncoderKind::DigitalPort)
            }
            ConnectorKind::HdmiA | ConnectorKind::HdmiB => Some(EncoderKind::Hdmi),
            ConnectorKind::DviI | ConnectorKind::DviD => Some(EncoderKind::Dvi),
            ConnectorKind::Vga => Some(EncoderKind::Dac),
            ConnectorKind::Lvds => Some(EncoderKind::Panel),
            ConnectorKind::Unknown(_) => None,
        }
    }

    /// Build the probe-time KMS topology from a VBIOS image (#1712).
    ///
    /// Pure over the image bytes: parse the ATOM display-object
    /// table (data table 0x05), mint one connector per path and one
    /// CRTC per pipe, then bind each path's first chain encoder to
    /// its connector. The encoder's DIG comes from the chain link
    /// via `translate_encoder_to_transmitter`; a non-UNIPHY encoder
    /// (no DIG) keeps its enum id as the instance, which the audio
    /// path never reads for those kinds. Connectors sharing one
    /// transmitter share one encoder entry (the possible-connectors
    /// mask gains each connector's bit).
    ///
    /// Any parse failure yields an empty topology (no connectors)
    /// instead of an error: probe must not fail because the display
    /// table is unreadable — the panel path (`set_mode`) works
    /// without KMS, and the caller logs the empty result.
    pub(crate) fn kms_from_vbios(
        vbios: &[u8],
        family: Family,
    ) -> (
        crate::amdgpu_modeset::KmsState,
        crate::amdgpu_hpd::HpdMachine,
    ) {
        use crate::amdgpu_atom_displayobj::DisplayObjectTable;
        use crate::amdgpu_modeset::KmsState;
        // Desktop Navi3 needs 6 pipes; everything else ships 4
        // (KmsState::new's own doc).
        let n_pipes = if family == Family::Navi3 { 6 } else { 4 };
        let mut kms = KmsState::new(n_pipes);
        let hpd = crate::amdgpu_hpd::HpdMachine::new();
        let Ok(atom) = crate::amdgpu_atombios::Atombios::parse(vbios) else {
            return (kms, hpd);
        };
        let Ok(raw) = atom.data_table(0x05) else {
            return (kms, hpd);
        };
        let Ok(mut table) = DisplayObjectTable::parse(raw) else {
            return (kms, hpd);
        };
        // Walk once, collecting (path, first encoder link): ingest
        // needs the paths in order, and encoder binding needs the
        // connector index each path becomes.
        let mut paths = Vec::new();
        while let Some((path, mut chain)) = table.next_with_chain() {
            let encoder = chain.find(|link| link.is_encoder());
            paths.push((path, encoder));
        }
        kms.ingest_atom_paths(paths.iter().map(|(path, _)| *path));
        for (connector_idx, (path, encoder)) in paths.iter().enumerate() {
            let Some(link) = encoder else { continue };
            let Some(kind) = Self::encoder_kind_for_connector(path.connector_kind) else {
                continue;
            };
            // The possible-connectors mask is a u32; a connector past
            // bit 31 cannot be represented there, so it stays
            // encoder-less (still modesettable — the plan layer falls
            // back to the connector's own instance for the DIG).
            if connector_idx >= 32 {
                continue;
            }
            let connector_idx = connector_idx as u8;
            // The DIG is the transmitter the encoder object maps to
            // (Linux `translate_encoder_to_transmitter`); a
            // non-UNIPHY encoder has no DIG, so its enum id stands
            // in as the instance (audio never reads it there).
            let raw =
                ((link.kind as u16) << 12) | ((link.enum_id as u16) << 8) | (link.instance as u16);
            let instance = crate::amdgpu_dcn_inventory::transmitter(raw).unwrap_or(link.enum_id);
            // Share one encoder entry per transmitter.
            let encoder_idx = match kms.encoders.iter().position(|enc| enc.instance == instance) {
                Some(idx) => {
                    kms.encoders[idx].possible_connectors |= 1u32 << connector_idx;
                    idx as u8
                }
                None => {
                    kms.push_encoder(kind, instance, 1u32 << connector_idx);
                    (kms.encoders.len() - 1) as u8
                }
            };
            let _ = kms.bind_encoder(connector_idx, encoder_idx);
        }
        (kms, hpd)
    }

    /// Bind HPD sources to KMS connectors from the inventory's
    /// per-path HPD selectors (#1712). The match key is the ATOM
    /// `usDeviceTag`, which both the display-object table and the
    /// inventory's display-object-info table carry for a path. A
    /// selector of 0 means the board declares no HPD pin for that
    /// connector; a tag with no KMS connector, or a selector past
    /// HPD6, binds nothing.
    pub(crate) fn bind_hpd_from_inventory(
        kms: &crate::amdgpu_modeset::KmsState,
        hpd: &mut crate::amdgpu_hpd::HpdMachine,
        paths: &[crate::amdgpu_dcn_inventory::Path],
    ) {
        use crate::amdgpu_hpd::HpdSource;
        for path in paths {
            if path.hpd == 0 {
                continue;
            }
            let Some(src) = HpdSource::from_index(path.hpd - 1) else {
                continue;
            };
            let Some((connector_idx, _)) = kms
                .connectors
                .iter()
                .enumerate()
                .find(|(_, conn)| conn.device_tag == path.device_tag)
            else {
                continue;
            };
            hpd.bind(src, connector_idx as u8);
        }
    }

    /// Probe-time KMS ownership (#1712). Builds the topology from
    /// the captured VBIOS, binds HPD sources from the inventory's
    /// per-path selectors when that parse succeeds, and publishes
    /// both statics. Best-effort throughout: a missing VBIOS or an
    /// unreadable table leaves KMS empty (the panel path does not
    /// need it) and logs one line; probe never fails here.
    fn init_kms_from_vbios(&self) {
        use core::fmt::Write as _;
        let Some(vbios) = self.vbios.as_ref() else {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: no VBIOS image; KMS topology stays empty",
            );
            return;
        };
        let (kms, mut hpd) = Self::kms_from_vbios(vbios.bytes(), self.chip.family);
        match crate::amdgpu_dcn_inventory::display_paths(self, vbios.bytes()) {
            Ok(paths) => Self::bind_hpd_from_inventory(&kms, &mut hpd, &paths),
            Err(_) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: inventory HPD parse failed; hotplug sources stay unbound",
                );
            }
        }
        let n_connectors = kms.connectors.len();
        let n_encoders = kms.encoders.len();
        if n_connectors == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: ATOM display-object table unreadable; KMS topology stays empty",
            );
        } else {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: KMS topology: {n_connectors} connectors, {n_encoders} encoders",
            );
        }
        *KMS_STATE.lock() = Some(kms);
        *HPD_STATE.lock() = Some(hpd);
    }

    /// Modeset one KMS connector with display audio (#1712) — the
    /// connect-half production caller the plan layer was waiting
    /// for. Picks a CRTC, builds the plan (video + the DCN audio
    /// enable sequence for external HDMI/DP when the BASE_IDX 2
    /// segment resolves), and applies it. The caller supplies the
    /// mode — on a hotplug connect that is the sink's EDID
    /// preferred mode; there is no safe default to invent for an
    /// unknown sink. Internal panels modeset through here too (the
    /// plan layer carries no audio for them). Returns
    /// `ConnectorDisconnected` for a connector HPD has not marked
    /// `Connected` yet.
    pub fn modeset_connector(
        &mut self,
        connector_idx: u8,
        mode: Mode,
        refresh_hz: u32,
        surface_phys: u64,
    ) -> Result<(), crate::amdgpu_modeset::KmsError> {
        use crate::amdgpu_modeset::{plan_modeset, KmsError};
        if self.chip.family == Family::Navi4 {
            return Err(KmsError::UnsupportedMode);
        }
        if !self.fw_loaded {
            return Err(KmsError::NotReady);
        }
        let dcn_base = self
            .ip_block_base(amdgpu_discovery::HW_ID_DCN, 0)
            .ok_or(KmsError::NotReady)?;
        let dcn_base2 = self
            .ip_block_base_idx(amdgpu_discovery::HW_ID_DCN, 0, 2)
            .unwrap_or(0);
        let mut guard = KMS_STATE.lock();
        let kms = guard.as_mut().ok_or(KmsError::NotReady)?;
        kms.pick_crtc(connector_idx)?;
        let plan = plan_modeset(
            kms,
            self.chip.family,
            connector_idx,
            mode.width,
            mode.height,
            refresh_hz,
            mode.stride,
            surface_phys,
            dcn_base,
            dcn_base2,
        )?;
        // SAFETY: probe gave us BAR ownership, still held.
        unsafe { self.apply_modeset_plan(kms, &plan, mode.stride, surface_phys) }
            .map_err(|_| KmsError::NotReady)?;
        Ok(())
    }

    /// Feed one connector's audio caps from a full EDID blob (#1712).
    /// Scans the extension blocks for the CEA-861 block (tag 0x02),
    /// parses its audio blocks, and feeds the result into the KMS
    /// connector. The live DDC/AUX read that produces the blob per
    /// connector is follow-up work; this is the feed call the issue
    /// names as missing. A missing speaker block falls back to the
    /// FL/FR baseline (0x01) every HDMI sink must accept. Returns
    /// `true` when a CEA block was found and fed — even when it
    /// carries no audio blocks (known-empty caps, not unknown) —
    /// `false` when there is no CEA block, no KMS state, or the
    /// connector index is out of range.
    pub fn feed_connector_edid(&self, connector_idx: u8, edid: &[u8]) -> bool {
        use crate::amdgpu_hdmi_audio::parse_cea_audio_blocks;
        use crate::amdgpu_modeset::feed_connector_audio_caps;
        // Base block is 128 bytes; byte 126 is the extension count.
        if edid.len() < 128 {
            return false;
        }
        let count = edid[126] as usize;
        let mut guard = KMS_STATE.lock();
        let Some(kms) = guard.as_mut() else {
            return false;
        };
        for index in 0..count {
            let off = 128 * (index + 1);
            let Some(block) = edid.get(off..off + 128) else {
                break;
            };
            if block[0] != 0x02 {
                continue;
            }
            let caps = parse_cea_audio_blocks(block);
            let speakers = caps.speakers.unwrap_or(0x01);
            return feed_connector_audio_caps(kms, connector_idx, caps.sads, speakers);
        }
        false
    }

    /// Feed one IH HPD cookie into the driver-owned HPD state
    /// machine (#1712) — the seam the IH ring drainer calls. The
    /// pin level comes from the caller (`hpd_asserted` readback at
    /// drain time); the cookie alone cannot say connect vs
    /// disconnect. A disconnect on a stable-connected pin runs the
    /// audio teardown through `apply_hotplug_disconnect` (never a
    /// bare status flip — the disable writes must execute while
    /// scanout is still live). Returns `None` for a context id
    /// that is not an HPD event; `Some(UnmappedSource)` when the
    /// machine is not initialised or the source has no bound
    /// connector.
    pub fn handle_hotplug_event(
        &mut self,
        ctxid: u8,
        asserted: bool,
        tsc: u64,
    ) -> Option<crate::amdgpu_hpd::HpdOutcome> {
        use crate::amdgpu_hpd::{HpdEvent, HpdOutcome};
        use crate::amdgpu_modeset::ConnectorStatus;
        let event = HpdEvent::from_ih_cookie(ctxid, asserted, tsc)?;
        let outcome = {
            let mut guard = HPD_STATE.lock();
            let Some(hpd) = guard.as_mut() else {
                return Some(HpdOutcome::UnmappedSource);
            };
            hpd.handle(event)
        };
        if let HpdOutcome::Disconnected { connector_idx } = outcome {
            let mut guard = KMS_STATE.lock();
            if let Some(kms) = guard.as_mut() {
                // SAFETY: probe gave us BAR ownership, still held.
                let applied = unsafe { self.apply_hotplug_disconnect(kms, connector_idx) };
                if applied.is_err() {
                    // Firmware not loaded (or Navi4): the teardown
                    // never ran, but the pin is gone either way —
                    // drop the connector's CRTC binding so a later
                    // modeset does not reuse a dead pipe.
                    kms.set_status(connector_idx, ConnectorStatus::Disconnected);
                }
            }
        }
        Some(outcome)
    }

    /// Sample the HPD debounce timers at `tsc` (#1712). Call from
    /// the driver's main loop or a scheduled wakeup — a connect
    /// only becomes `Connected` here, after the debounce window,
    /// never at event time. Returns the connector indices that
    /// stabilised as connected in this poll, marked `Connected` in
    /// KMS; the caller modesets each with its mode (EDID preferred
    /// mode) via `modeset_connector`.
    pub fn poll_hotplug(&mut self, tsc: u64) -> Vec<u8> {
        use crate::amdgpu_hpd::{HpdMachine, HpdOutcome, HpdSource};
        let mut connected = Vec::new();
        {
            let mut guard = HPD_STATE.lock();
            let Some(hpd) = guard.as_mut() else {
                return connected;
            };
            for index in 0..6u8 {
                let Some(src) = HpdSource::from_index(index) else {
                    continue;
                };
                if let HpdOutcome::Connected { connector_idx } = hpd.sample_at(src, tsc) {
                    connected.push(connector_idx);
                }
            }
        }
        if !connected.is_empty() {
            let mut guard = KMS_STATE.lock();
            if let Some(kms) = guard.as_mut() {
                for &connector_idx in &connected {
                    HpdMachine::apply_to_kms(kms, HpdOutcome::Connected { connector_idx });
                }
            }
        }
        connected
    }

    /// Drain one batch of decoded IH ring entries into the HPD state
    /// machine (#1785) — the live IH ring drainer. Each entry's HPD
    /// context id is decoded, the pin level is read back with
    /// `hpd_asserted` at drain time, and the cookie is fed to
    /// `handle_hotplug_event`. Non-HPD entries are counted and
    /// skipped; a plug cookie whose pin cannot be read back is
    /// dropped rather than guessed at.
    ///
    /// The readback and the feed cannot share one borrow — the
    /// readback needs `&self`, the feed needs `&mut self` — so the
    /// pin level is read once per plug cookie, in ring order, into a
    /// staged table before the feed pass runs. Both passes happen in
    /// this same drain call, so the level a cookie is fed with is the
    /// level read for that cookie moments earlier; a cable yanked
    /// between the passes is corrected by the disconnect cookie the
    /// falling edge raises on the next drain, exactly as it would be
    /// for a read done inline. The staged entry also carries its
    /// pin index, and the feed pass fails a cookie closed if the
    /// staging ever disagrees with the ring order.
    pub fn drain_ih_hotplug(
        &mut self,
        ivs: &[crate::amdgpu_ih_navi22::Iv],
        tsc: u64,
    ) -> crate::amdgpu_ih_drainer::IhHpdDrain {
        use crate::amdgpu_ih_drainer::drain_ih_hpd_ivs;
        // Stage 1: one pin readback per plug cookie, in ring order.
        // Sink IRQs need no level; non-HPD entries need nothing.
        let mut staged: Vec<(u8, Option<bool>)> = Vec::new();
        for iv in ivs {
            let Some(hpd) = iv.hpd() else {
                continue;
            };
            if hpd.rx {
                continue;
            }
            // SAFETY: probe gave us BAR ownership, still held; a
            // read-only status register through the MM_INDEX/MM_DATA
            // pair.
            let level = unsafe { self.hpd_asserted(hpd.instance) };
            staged.push((hpd.instance, level));
        }
        // Stage 2: feed the batch. The pin closure consumes the
        // staged levels in the same ring order the drainer consults
        // them; a staging/ring disagreement fails closed.
        let mut next = 0usize;
        drain_ih_hpd_ivs(
            ivs,
            tsc,
            |instance| {
                let (staged_instance, level) = staged.get(next).copied().unwrap_or((u8::MAX, None));
                next += 1;
                if staged_instance == instance {
                    level
                } else {
                    None
                }
            },
            |ctxid, asserted, tsc| self.handle_hotplug_event(ctxid, asserted, tsc),
        )
    }

    /// Drain one batch and sample the HPD debounce timers (#1785) —
    /// the scheduled-wakeup entry point. A connect only becomes
    /// `Connected` in the `poll_hotplug` half, so a driver loop must
    /// call this on a tick (see `serve_ih_hpd` in
    /// `amdgpu_ih_drainer`, which ticks every [`IH_HPD_POLL_MS`])
    /// even when no cookie arrived since the last call. Returns the
    /// drain report plus the connector indices that stabilised as
    /// connected in this poll, marked `Connected` in KMS; the caller
    /// modesets each with its mode (EDID preferred mode) via
    /// `modeset_connector`.
    ///
    /// [`IH_HPD_POLL_MS`]: crate::amdgpu_ih_drainer::IH_HPD_POLL_MS
    pub fn service_hotplug(
        &mut self,
        ivs: &[crate::amdgpu_ih_navi22::Iv],
        tsc: u64,
    ) -> (crate::amdgpu_ih_drainer::IhHpdDrain, Vec<u8>) {
        let report = self.drain_ih_hotplug(ivs, tsc);
        let connected = self.poll_hotplug(tsc);
        (report, connected)
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
        if self.chip.family == Family::Navi4 {
            return Err(AmdgpuError::UnknownAsic);
        }
        if self.mode.is_none() {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        let dcn_base = self
            .ip_block_base(amdgpu_discovery::HW_ID_DCN, 0)
            .ok_or(AmdgpuError::UnknownAsic)?;
        let brightness = crate::amdgpu_backlight::user_level_for_percent(percent);
        // The duty count is the brightness scaled against the period VBIOS
        // programmed, so the period has to be read back first — it is not a
        // value this driver chooses.
        // SAFETY: caller-asserted BAR5 ownership; the register is inside the
        // DCN window `ip_block_base` resolved.
        // `mm_read`/`mm_write` drive the helpers, which accept a **dword**
        // register address — `reg_offset[IP][inst][BASE_IDX] + dword_id`, the
        // same sum `SOC15_REG_OFFSET` forms. `ip_block_base` returns that
        // dword base straight out of the discovery blob, so the dword id is
        // added to it unshifted.
        let period_cntl = unsafe {
            mm_read(
                &self.regs,
                dcn_base + crate::amdgpu_backlight::BL_PWM_PERIOD_CNTL,
            )
        };
        let writes = crate::amdgpu_backlight::build_set_user_level(0, brightness, period_cntl)
            .map_err(|_| AmdgpuError::UnknownAsic)?;
        // SAFETY: caller-asserted BAR5 ownership.
        unsafe {
            for w in &writes {
                mm_write(&self.regs, dcn_base + w.addr, w.value);
            }
        }
        // Record the programmed level on the modeset state, so a
        // later modeset (including the PM resume re-modeset)
        // re-applies the level the user last set instead of the
        // level the first modeset read back (#948).
        self.backlight_percent = Some(percent);
        Ok(())
    }

    /// Read the panel's current brightness back out of the DCN
    /// BL_PWM registers, as a percentage (0–100) — the inverse of
    /// what `set_backlight` programs, via
    /// [`crate::amdgpu_backlight::percent_for_active_count`].
    ///
    /// Returns `None` when the PWM is not enabled (`BL_PWM_EN`
    /// clear, so the duty field holds no live level), when no DCN
    /// base resolves, or when the period carries no duty to scale
    /// against. Callers fall back to full brightness rather than
    /// inventing a level from a dead register.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively.
    pub unsafe fn readback_brightness_percent(&self) -> Option<u8> {
        if self.chip.family == Family::Navi4 {
            return None;
        }
        let dcn_base = self.ip_block_base(amdgpu_discovery::HW_ID_DCN, 0)?;
        // The duty count is scaled against the period VBIOS
        // programmed, so both registers have to be read back —
        // neither value is one this driver chooses.
        // SAFETY: caller-asserted BAR5 ownership; the registers
        // are inside the DCN window `ip_block_base` resolved.
        let period_cntl = unsafe {
            mm_read(
                &self.regs,
                dcn_base + crate::amdgpu_backlight::BL_PWM_PERIOD_CNTL,
            )
        };
        // SAFETY: caller-asserted BAR5 ownership; the register is
        // inside the DCN window `ip_block_base` resolved.
        let cntl = unsafe { mm_read(&self.regs, dcn_base + crate::amdgpu_backlight::BL_PWM_CNTL) };
        if cntl & crate::amdgpu_backlight::BL_PWM_EN == 0 {
            return None;
        }
        crate::amdgpu_backlight::percent_for_active_count(
            cntl & crate::amdgpu_backlight::BL_ACTIVE_INT_FRAC_CNT_MASK,
            period_cntl,
        )
    }

    /// Program the panel backlight PWM to a raw `USER_LEVEL`
    /// (0 = full off, 0xFFFF = full on) — the sequencer-facing
    /// form of [`AmdGpu::set_backlight`], without the percent
    /// conversion. The eDP panel-power sequencer's production
    /// `EdpPanelHw` drives this so suspend/resume relight goes
    /// through the sequencer's T4/T5 ordering and `last_pwm_level`
    /// cache instead of bypassing it.
    ///
    /// Same guards as `set_backlight`: requires a programmed mode
    /// (DCN up) and a discovery-resolvable DCN base; Navi4 has
    /// neither and refuses.
    ///
    /// Deliberately a small duplication of `set_backlight`'s
    /// read-period → build → write body rather than a refactor of
    /// it: #948 (AMD DC `set_backlight`) is a separate running
    /// lane — consolidate the two once it lands.
    ///
    /// # Safety
    /// Caller owns BAR5 exclusively.
    pub(crate) unsafe fn set_pwm_user_level(&mut self, level: u16) -> Result<(), AmdgpuError> {
        if self.chip.family == Family::Navi4 {
            return Err(AmdgpuError::UnknownAsic);
        }
        if self.mode.is_none() {
            return Err(AmdgpuError::FirmwareLoadFailed);
        }
        let dcn_base = self
            .ip_block_base(amdgpu_discovery::HW_ID_DCN, 0)
            .ok_or(AmdgpuError::UnknownAsic)?;
        // SAFETY: caller-asserted BAR5 ownership; the register is inside the
        // DCN window `ip_block_base` resolved.
        let period_cntl = unsafe {
            mm_read(
                &self.regs,
                dcn_base + crate::amdgpu_backlight::BL_PWM_PERIOD_CNTL,
            )
        };
        let writes = crate::amdgpu_backlight::build_set_user_level(0, level, period_cntl)
            .map_err(|_| AmdgpuError::UnknownAsic)?;
        // SAFETY: caller-asserted BAR5 ownership.
        unsafe {
            for w in &writes {
                mm_write(&self.regs, dcn_base + w.addr, w.value);
            }
        }
        Ok(())
    }

    /// MP1 (SMU) register-window base. Reads IP discovery first;
    /// pre-discovery silicon doesn't expose SMU bring-up here.
    pub fn mp1_base(&self) -> Option<u32> {
        self.ip_block_base(amdgpu_discovery::HW_ID_MP1, 0)
    }

    /// MP1 base window 1 — where the SMU mailbox registers live on Phoenix
    /// (`mp_13_0_4_offset.h` gives `regMP1_SMN_C2PMSG_66_BASE_IDX` as 1).
    ///
    /// Every `amdgpu_smu` call takes an `mp1_base`; they were being handed
    /// window 0, so the mailbox writes went to the wrong window even once the
    /// offsets were corrected.
    pub fn mp1_mailbox_base(&self) -> Option<u32> {
        // Discrete SMU11 has its own message map and owner. Never hand its
        // register window to the APU PowerUp/PowerDownGfx helpers.
        if self.chip.family == Family::Navi4 || !self.is_apu() {
            return None;
        }
        self.ip_block_base_idx(amdgpu_discovery::HW_ID_MP1, 0, 1)
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
        // 1. PSP-driven firmware load. `load_firmware_multi`
        //    walks `chip.fw_list` — TOC, ASD, IP firmwares, TAs
        //    in declaration order matching Linux's psp_load_non_
        //    psp_fw + psp_hw_start. Falls through to the legacy
        //    single-blob path on chips whose IP enumeration we
        //    haven't audited yet.
        // SAFETY: caller-asserted BAR5 ownership.
        let multi_fw = unsafe { self.load_firmware_multi(fw_authority) }?;

        // 2. SMU bring-up handshake. The MP1 base + expected
        //    driver-IF version are family-specific; both must
        //    resolve or we can't safely talk to the SMU.
        let mp1_base = self
            .mp1_mailbox_base()
            .ok_or(AmdgpuError::SmuBringUpFailed)?;
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

        Ok(InitializeReport {
            smu_info,
            multi_fw: Some(multi_fw),
        })
    }
}

/// Send a control-only PSP command (no firmware image — used by
/// AUTOLOAD_RLC, BOOT_CFG queries, etc.). Same MP0 mailbox
/// protocol as `psp_dispatch_one` but with `phys = 0`, `size = 0`,
/// and the cmd alone in the trigger word.
///
/// # Safety
/// Caller owns BAR5 exclusively (regs MMIO). `mp0_base` is the
/// live MP0 register window for this chip.
unsafe fn psp_send_control_command(
    regs: &MmioRegion,
    mp0_base: u32,
    cmd: u32,
) -> Result<(), AmdgpuError> {
    // LINUX-GAP: `AUTOLOAD_RLC`, `BOOT_CFG` and the rest of `psp_gfx_cmd_id`
    // are GPCOM ring commands, not mailbox commands. The MP0 mailbox accepts
    // only `psp_bootloader_cmd` values on C2PMSG_35 and `psp_gfx_ctrl_cmd_id`
    // values on C2PMSG_64; `amdgpu_psp::ring_control` is the entry point for
    // the latter, and `amdgpu_psp_ring` carries the former kind.
    let _ = (regs, mp0_base, cmd);
    Err(AmdgpuError::UnsupportedFirmwareLoad)
}

/// Per-initialize report — what the host learned about the chip
/// after `AmdGpu::initialize`. The caller stashes this on the
/// driver state for later reference (logging, ABI exposure).
#[derive(Clone, Debug)]
pub struct InitializeReport {
    pub smu_info: crate::amdgpu_smu::SmuInfo,
    /// Per-IP firmware-load summary from `load_firmware_multi`.
    /// `None` on chips that fell back to the single-blob path.
    pub multi_fw: Option<MultiFwReport>,
}

/// Summary returned by `AmdGpu::load_firmware_multi`. The driver
/// records this so operators can correlate boot-time logging with
/// what actually loaded vs what was skipped because the blob
/// wasn't in the initramfs.
#[derive(Clone, Debug)]
pub struct MultiFwReport {
    /// How many blobs from `chip.fw_list` loaded successfully.
    pub loaded: usize,
    /// How many entries were `optional` and not present in the
    /// firmware registry. Non-zero usually means "build a more
    /// complete initramfs" — the chip will function but some IPs
    /// (typically optional TAs / boot-cfg) skipped.
    pub skipped_optional: usize,
    /// The most recent optional blob that was skipped, for log
    /// breadcrumbs.
    pub last_optional_skip: Option<alloc::string::String>,
}

/// Adapter that implements `CpFwMmio` over MM_INDEX / MM_DATA.
///
/// `CpFwMmio` hands out `(base + dword_id) << 2`, a byte offset into a
/// directly mapped window. The helper API accepts DWORD IDs, so this shifts back —
/// the one place in the driver where the two conventions meet, rather than at
/// every call site.
struct CpRegsAdapter<'a> {
    regs: &'a MmioRegion,
}

impl<'a> crate::amdgpu_cp_fw::CpFwMmio for CpRegsAdapter<'a> {
    fn read(&mut self, byte_off: u32) -> u32 {
        // SAFETY: the adapter is built inside `start_gfx_cp`, whose caller
        // asserts exclusive BAR5 ownership, and it cannot outlive that frame.
        unsafe { mm_read(self.regs, byte_off >> 2) }
    }
    fn write(&mut self, byte_off: u32, value: u32) {
        // SAFETY: same.
        unsafe { mm_write(self.regs, byte_off >> 2, value) }
    }
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
    // SAFETY: caller owns the live >=8-byte BAR5 mapping and its index
    // latch under PCI authority. The helper converts DWORD IDs to bytes.
    unsafe { index::read(regs, addr) }
}

/// Convert one of `amdgpu_gfx`/`amdgpu_cp_fw`'s byte-offset `*_REL` constants
/// into the dword register ID the indexed helpers accept.
///
/// The driver carries both conventions on purpose: a module that owns a
/// directly mapped register window indexes it in bytes, while the indexed
/// helpers accept DWORD register IDs. Mixing them addresses a register four
/// times further in, which is what [`AmdGpu::write_grbm_gfx_index`] and
/// [`AmdGpu::read_grbm_status`] were doing.
pub(crate) const fn mm_dword(rel_bytes: u32) -> u32 {
    rel_bytes / 4
}

/// Establish wall-time conversions before the discrete firmware handoff.
/// Its initcall precedes frame's HPET/timer setup; using the identity scale
/// there makes both minimum delays and timeouts too short on a >1 GHz TSC.
pub(crate) fn boot_clock_ready() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let (mut hz, mut source) = narf_time::calibrate_clocks_with_source();
        if hz == 0 && !narf_time::hpet::is_present() {
            // KVM can mask CPUID frequency leaves and AMD P-state MSRs.
            // This handoff precedes frame's HPET/IRQ timer setup. Borrow
            // only the counter for calibration; do not publish a virtual
            // base as the physical address frame must map later.
            let phys = narf_time::hpet::base_phys_for_ioremap();
            // SAFETY: exclusive boot-time clock setup; this is the same
            // platform HPET window used by frame's later timer installation.
            if let Ok(mapping) = unsafe {
                narf_memory::ioremap::ioremap(phys, 0x1000, narf_memory::ioremap::MmioAttrs::Device)
            } {
                // SAFETY: permanent device mapping, before IRQ timer setup;
                // no other CPU or HPET owner accesses the counter here.
                if let Some(measured) = unsafe { narf_time::hpet::calibrate_tsc_at(mapping.virt) }
                    .filter(|hz| (1_000_000_000..=6_500_000_000).contains(hz))
                {
                    narf_arch::x86_64::tsc::set_hz_via_hpet(measured);
                    // Installs both wall-time conversion directions from
                    // the measured cache, before any firmware delay.
                    hz = narf_time::calibrate_clocks_with_source().0;
                    source = narf_time::CalibrationSource::HpetXcheck;
                }
            }
        }
        if hz == 0 {
            return false;
        }
        // Stamp the existing per-stage checkpoints only after their clock
        // reports real ns. Frame's later installation uses the same scale.
        narf_console::klog::set_clock(narf_time::monotonic_ns);
        use core::fmt::Write;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: boot clock calibrated to {hz} Hz via {}",
            source.name()
        );
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        true
    }
}

/// Busy-wait `us` microseconds of wall-clock time.
///
/// `narf_time::calibrate_clocks` returns the TSC frequency, or 0 when every
/// calibration path failed. The spin fallback is the same shape `ixgbe`'s
/// reset handshake uses, and it is a fallback rather than the primary path
/// because a spin count's duration is whatever the CPU clock makes it, while
/// the hardware waits this stands in for are specified in time.
pub(crate) fn delay_us(us: u32) {
    let hz = narf_time::calibrate_clocks();
    if hz > 0 {
        narf_time::busy_wait_cycles((hz / 1_000_000).max(1) * u64::from(us));
    } else {
        for _ in 0..(u64::from(us) * 1000) {
            core::hint::spin_loop();
        }
    }
}

/// Indexed register write of a DWORD register ID.
///
/// # Safety
/// Same mapping, latch ownership and PCI authority contract as `mm_read`.
pub(crate) unsafe fn mm_write(regs: &MmioRegion, addr: u32, value: u32) {
    // SAFETY: same mapping, latch ownership and PCI authority as mm_read.
    unsafe { index::write(regs, addr, value) }
}

/// Read the absolute VRAM-size register through BAR5's direct register window.
/// # Safety
/// `regs` is a live, exclusively owned AMD GPU BAR5 mapping.
unsafe fn read_config_memsize(regs: &MmioRegion) -> u32 {
    let offset = u64::from(RCC_CONFIG_MEMSIZE) * 4;
    if regs.len < offset + 4 {
        return u32::MAX;
    }
    // SAFETY: validated DWORD bounds; caller owns the mapping.
    unsafe { regs.read32(offset) }
}

/// Post-reset liveness: the ASIC must answer beyond PCI configuration space.
/// # Safety
/// Same live BAR5 mapping contract as `read_config_memsize`.
pub(crate) unsafe fn config_memsize_alive(regs: &MmioRegion) -> bool {
    // SAFETY: caller supplies the live, exclusively owned register mapping.
    unsafe { read_config_memsize(regs) != u32::MAX }
}

/// Total VRAM from RCC_CONFIG_MEMSIZE; CPU visibility from the mapped BAR0.
/// # Safety
/// Caller owns both live mappings of the same GPU.
pub(crate) unsafe fn read_vram_info(regs: &MmioRegion, fb_bar: &MmioRegion) -> VramInfo {
    // RCC_CONFIG_MEMSIZE is an absolute DWORD register ID. It is within
    // BAR5's directly mapped window, which is addressed in BYTES.
    // SAFETY: caller owns the live BAR5 mapping.
    let memsize_mb = unsafe { read_config_memsize(regs) };
    let size = if memsize_mb == u32::MAX {
        0
    } else {
        u64::from(memsize_mb) << 20
    };
    // Use only the aperture actually mapped. This also covers APUs behind
    // passthrough and ReBAR apertures rounded up beyond physical VRAM.
    // LINUX-GAP: bare-metal APU expansion via get_mc_fb_offset is not mapped
    // here; until it is, advertising more than BAR0 would promise invalid CPU
    // mappings. Indexed discovery does not require that expansion.
    VramInfo {
        base: fb_bar.phys.raw(),
        size,
        visible_size: fb_bar.len.min(size),
    }
}

/// Read the default 10 KiB discovery table 64 KiB below the end of real VRAM.
/// BAR0 reads stop at its mapped extent; BAR5 indexed memory reads cover the
/// remainder. Missing/corrupt discovery leaves the IP inventory unavailable.
/// LINUX-GAP: newer firmware's relocated/system-memory TMR is not handled.
pub(crate) fn read_discovery(
    io: &mut impl crate::amdgpu_vram_access::ReadIo,
    vram_size: u64,
) -> (Vec<IpBlock>, Option<crate::amdgpu_discovery::GcInfo>, u64) {
    let Some(offset) = vram_size.checked_sub(amdgpu_discovery::DISCOVERY_TMR_OFFSET) else {
        return (Vec::new(), None, 0);
    };
    let mut buf = alloc::vec![0u8; amdgpu_discovery::DISCOVERY_TMR_SIZE];
    if crate::amdgpu_vram_access::read(io, vram_size, offset, &mut buf).is_err() {
        return (Vec::new(), None, 0);
    }
    // The GC table is parsed from the same bytes. Its absence is ordinary
    // (QEMU, pre-discovery silicon) and is not worth reporting; a blob that
    // parsed but whose GC table is corrupt is worth reporting, because the
    // topology it would have carried is not guessable.
    let gc_info = match amdgpu_discovery::parse_gc_info(&buf) {
        Ok(info) => Some(info),
        Err(amdgpu_discovery::DiscoveryError::NoGcTable) => None,
        Err(error) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: discovery GC table unusable ({error:?}); shader topology unknown"
            );
            None
        }
    };
    let ip_blocks = amdgpu_discovery::parse_discovery(&buf).unwrap_or_default();
    // amdgpu_discovery_get_mall_info, after harvest_ip has trimmed num_umc.
    let mall_size = amdgpu_discovery::mall_size(&buf, &ip_blocks);
    (ip_blocks, gc_info, mall_size)
}

// ── VBIOS image acquisition ────────────────────────────────────────────────
//
// AMD GPUs expose their VBIOS through the PCI expansion ROM BAR (cfg+0x30).
// Protocol (per AMD amdgpu_bios.c::amdgpu_read_bios, lines 101-140):
//   1. Read ROM BAR address from cfg+0x30 (bits[31:11] = phys base).
//   2. Probe the ROM header for presence / size field.
//   3. Slurp bytes into a heap Vec<u8>.
//   4. Parse ATOMBIOS header, extract version string.
//
// On any failure, returns None without affecting probe.
// Linux ref: drivers/gpu/drm/amd/amdgpu/amdgpu_bios.c::amdgpu_read_bios.

/// Try to read the VBIOS from the PCI expansion ROM BAR and parse the
/// ATOMBIOS version string.  Returns `None` on any failure.
///
/// # Safety
/// Caller holds `cap` (authority over the PCI device). Reads are
/// performed through the identity-mapped MMIO path; garbage reads
/// are safe (we check for the 0xFF sentinel before proceeding).
unsafe fn read_vbios_version_from_rom(
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Option<alloc::string::String> {
    use narf_bus::bar::{BarKind, MmioRegion};
    use narf_memory::PhysAddr;

    // Get the expansion ROM BAR address from the PCI config snapshot.
    let saved = narf_bus::pci::save_config(cap, device).ok()?;
    let rom_bar_reg = saved.expansion_rom_bar;

    // Bits[31:11] are the phys base; bit 0 = ROM_ENABLE.
    let rom_phys_base = rom_bar_reg & !0x1u32;
    if rom_phys_base == 0 {
        return None;
    }
    let rom_phys = rom_phys_base as u64;

    // Map a small probe window to read the PCI ROM header (first 3 bytes).
    // Identity-mapped ROM window, so virt == phys.
    let probe_region = MmioRegion {
        phys: PhysAddr::new(rom_phys),
        virt: rom_phys,
        len: 512,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };

    // Guard against unmapped / absent ROM (reads back 0xFF 0xFF).
    // SAFETY: identity-mapped MMIO in NARF's kernel context.
    let b0 = unsafe { probe_region.read8(0) };
    // SAFETY: identity-mapped MMIO in NARF's kernel context; offset 1 is the
    // second byte of the 512-byte `probe_region` mapped at the PCI ROM base,
    // well within bounds.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let b1 = unsafe { probe_region.read8(1) };
    if b0 == 0xFF && b1 == 0xFF {
        return None;
    }

    // PCI ROM header byte 2: image size in 512-byte blocks.
    // SAFETY: identity-mapped MMIO in NARF's kernel context; offset 2 is the
    // third byte of the 512-byte `probe_region` mapped at the PCI ROM base,
    // well within bounds.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let blocks = unsafe { probe_region.read8(2) };
    let rom_size: u64 = if blocks == 0 {
        65536 // fallback: 64 KiB
    } else {
        (blocks as u64).saturating_mul(512)
    }
    // Hard cap: real AMD VBIOSes are <= 256 KiB.
    .min(256 * 1024);

    // Re-map with the full ROM size. Identity-mapped, so virt == phys.
    let region = MmioRegion {
        phys: PhysAddr::new(rom_phys),
        virt: rom_phys,
        len: rom_size,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };

    // Slurp ROM bytes via 32-bit reads.
    let n_bytes = rom_size as usize;
    let mut buf = alloc::vec![0u8; n_bytes];
    let n4 = n_bytes / 4;
    for i in 0..n4 {
        // SAFETY: offset i*4 is within [0, rom_size).
        let word = unsafe { region.read32(i as u64 * 4) };
        let bytes = word.to_le_bytes();
        buf[i * 4] = bytes[0];
        buf[i * 4 + 1] = bytes[1];
        buf[i * 4 + 2] = bytes[2];
        buf[i * 4 + 3] = bytes[3];
    }

    // Parse the ATOMBIOS header and extract the version string.
    match crate::atombios::parse(&buf) {
        Ok(atom) => atom.version,
        Err(_) => None,
    }
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<AmdGpu>> = IrqSafeSpinLock::new(None);
// Set under CONTROLLER before the boot owner leaves that lock. It stays set
// through success, failure and cancellation: only that owner may access MMIO.
static DISCRETE_OWNED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static PCI_AUTHORITY: IrqSafeSpinLock<Option<Cap<BusDeviceCap, Write>>> =
    IrqSafeSpinLock::new(None);
static PCI_DEVICE: IrqSafeSpinLock<Option<BusDevice>> = IrqSafeSpinLock::new(None);
/// Probe-owned KMS topology (#1712): the connectors/encoders/CRTCs
/// built from the VBIOS ATOM display-object table, plus the HPD
/// source bindings. `None` until `probe()` runs
/// `init_kms_from_vbios`; the panel path (`set_mode`) does not need
/// it. Lock order is CONTROLLER → KMS_STATE and CONTROLLER →
/// HPD_STATE; HPD_STATE and KMS_STATE are never held at once (each
/// is dropped before the other is taken).
static KMS_STATE: IrqSafeSpinLock<Option<crate::amdgpu_modeset::KmsState>> =
    IrqSafeSpinLock::new(None);
static HPD_STATE: IrqSafeSpinLock<Option<crate::amdgpu_hpd::HpdMachine>> =
    IrqSafeSpinLock::new(None);
pub(crate) fn pci_device() -> Option<BusDevice> {
    *PCI_DEVICE.lock()
}
pub(crate) fn pci_authority() -> Option<Cap<BusDeviceCap, Write>> {
    *PCI_AUTHORITY.lock()
}

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
    .map_err(|error| {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: {:04x}:{:04x} enabling PCI command failed: {error:?}",
            device.id.vendor,
            device.id.device,
        );
        narf_bus::ProbeError::BadDevice
    })?;
    // SAFETY: caller-authority.
    let mut dev = match unsafe { AmdGpu::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(error) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: {:04x}:{:04x} bring-up failed: {error:?}",
                device.id.vendor,
                device.id.device,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    // SAFETY: probe owns the GPU mappings; boot ACPI tables remain mapped.
    let vbios = unsafe { crate::amdgpu_vbios::discover(&dev, &device, &cap) };
    let rdna4 = crate::amdgpu_rdna4::Rdna4Chip::of(&dev);
    if crate::amdgpu_rdna2::for_pci_id(device.id.vendor, device.id.device).is_some()
        || rdna4.is_some()
    {
        use core::fmt::Write as _;
        match &vbios {
            Ok(image) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: {} VBIOS {:?}, {} bytes",
                    dev.chip.asic,
                    image.source(),
                    image.bytes().len()
                );
            }
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "amdgpu: {} VBIOS unavailable: {error:?}",
                    dev.chip.asic,
                );
            }
        }
    }
    dev.vbios = vbios.ok();
    // Probe-time KMS ownership (#1712): build the topology from the
    // VBIOS ATOM display-object table so the modeset/display-audio
    // apply path has a state to act on. Best-effort — failure leaves
    // KMS empty and the panel path (`set_mode`) is unaffected.
    dev.init_kms_from_vbios();
    let vbios_version = dev.vbios.as_ref().and_then(|bios| bios.version());
    let is_apu = dev.is_apu();
    // Captured before the move into CONTROLLER; both are Copy.
    let (bound_asic, bound_family, revision, rev_id) = (
        dev.chip.asic,
        dev.chip.family,
        dev.chip.revision,
        dev.chip.rev_id,
    );
    crate::amdgpu_rdna4::publish(rdna4);
    if rdna4.is_some() {
        crate::amdgpu_info::publish_rdna4_identity(crate::amdgpu_info::Rdna4Identity {
            rev_id,
            pci_rev: revision,
            mall_size: dev.chip.mall_size,
        });
    }
    *PCI_AUTHORITY.lock() = Some(cap);
    *PCI_DEVICE.lock() = Some(device);
    *CONTROLLER.lock() = Some(dev);
    // One identity line, before anything can fail. On a machine that gets no
    // picture this is what says whether the driver bound at all, which ASIC
    // table it chose, and therefore which firmware bundle it is about to ask
    // the PSP for — the question a wrong PCI-id constant makes unanswerable.
    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: bound {:04x}:{:04x} asic={} family={:?} vbios={}",
            device.id.vendor,
            device.id.device,
            bound_asic,
            bound_family,
            vbios_version.as_deref().unwrap_or("<none>"),
        );
        if let Some(die) = rdna4 {
            let name = crate::amdgpu_rdna4::known_device(device.id.device)
                .map_or("unlisted board id", |d| d.name);
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: RDNA4 {} GC {:?} pci_rev {revision:#04x} rev_id {rev_id:#x} \
                 external_rev {:#04x}: {name}",
                die.asic(),
                die.gc_version(),
                die.external_rev(rev_id),
            );
        }
    }
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("amdgpu"),
        kind: narf_drivers::BoundKind::Graphics,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Graphics.default_domain(),
    });
    // APUs and audited discrete probes use their retained, capability-checked image. The legacy
    // ROM-version-only path remains for other discrete GPUs.
    let vbios_version: Option<alloc::string::String> = if vbios_version.is_some()
        || is_apu
        || (crate::amdgpu_rdna2::for_pci_id(device.id.vendor, device.id.device).is_some()
            || rdna4.is_some())
    {
        vbios_version
    } else {
        // SAFETY: caller-authority over the device. ROM BAR is read-only
        // from the CPU side once the phys address is known.
        // Linux ref: amdgpu_bios.c::amdgpu_read_bios (lines 101-140).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { read_vbios_version_from_rom(&cap, &device) }
    };

    // Register with the DRM card registry so /sys/class/drm/card<N>/
    // and /dev/dri/card<N> appear after Stage::Late.
    // Linux ref: drm_dev_register (drivers/gpu/drm/drm_drv.c).
    {
        let drm_count = crate::drm_registry::count() as u32;
        let card_name = alloc::format!("card{}", drm_count);
        let amdgpu_card = crate::drm_devfs_bridge::AmdgpuCard::new(
            card_name,
            device.id.vendor,
            device.id.device,
            device.id.subsystem_vendor, // cfg offset 0x2C, populated at ECAM probe
            device.id.subsystem_id,     // cfg offset 0x2E, populated at ECAM probe
            vbios_version,
        );
        crate::drm_registry::register_drm_card(alloc::sync::Arc::new(amdgpu_card));
    }
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
    // Panel backlight: an APU drives the internal panel, so register
    // the production backlight owner through the backlight
    // subsystem's single-owner arbitration (Raw priority — an ACPI
    // firmware candidate defers to it). Discrete cards have no
    // internal panel and register nothing. This is bookkeeping
    // only; `set_backlight` still refuses until a mode is set.
    if is_apu {
        crate::amdgpu_panel_backlight::register_panel_owner();
    }
    Ok(())
}

/// Stash so the resume handler can re-program the same Mode the
/// suspend handler saw. None when no mode has been programmed
/// yet (e.g. pre-firmware-load).
static SAVED_MODE: narf_lib::sync::IrqSafeSpinLock<Option<Mode>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Display-audio enable writes of the last applied external plan
/// (`AmdGpu::apply_modeset_plan`), keyed by the plan's timing and
/// connector. `set_mode` re-executes them after re-programming
/// video when the timing matches — the PM-resume re-run — and
/// drops them when the mode changed since the plan was applied
/// (stale audio must never resurrect on a different pixel clock)
/// or the connector is torn down (`disable_display_audio` /
/// `apply_hotplug_disconnect` clear their own connector's entry).
///
/// The snapshot covers the last applied plan only. A
/// multi-connector resume rebuilds every connector's writes
/// through `AmdGpu::resume_display_audio` instead; the snapshot
/// is the single-plan path for when no KMS state is at hand.
struct SavedDisplayAudio {
    timing: crate::amdgpu_dcn::ModeTiming,
    connector_idx: u8,
    writes: Vec<crate::amdgpu_dcn::DcnWrite>,
}

static SAVED_DISPLAY_AUDIO: narf_lib::sync::IrqSafeSpinLock<Option<SavedDisplayAudio>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);

/// Drop the saved audio for one connector, leaving other
/// connectors' snapshots alone. Teardown paths call this when
/// tearing a connector down, whether or not disable writes
/// execute, so a later `set_mode` cannot resurrect audio for a
/// disconnected output.
fn clear_saved_display_audio(connector_idx: u8) {
    let mut saved = SAVED_DISPLAY_AUDIO.lock();
    if let Some(s) = saved.as_ref() {
        if s.connector_idx == connector_idx {
            *saved = None;
        }
    }
}

/// Test-only reset for the saved display-audio snapshot. The
/// snapshot is kernel-global, so fixtures that share it reset it
/// up front instead of depending on run order. Only the
/// x86_64-only `e2e_tests` fixtures call it, so it is gated to
/// that arch.
#[cfg(feature = "kernel-test")]
#[cfg(target_arch = "x86_64")]
pub(crate) fn reset_saved_display_audio_for_test() {
    *SAVED_DISPLAY_AUDIO.lock() = None;
}

/// Test-only probe for the saved display-audio snapshot: whether
/// one is held for `connector_idx`. The e2e snapshot-lifecycle
/// tests assert on this instead of the last-write latch after
/// `set_mode`: on an APU the modeset tail applies the panel
/// backlight last (#948), so the latch holds a BL_PWM write and
/// cannot show whether audio replayed or stayed silent. The
/// snapshot state is the contract itself — retained on a
/// same-timing modeset (the match arm runs, and it executes the
/// replay writes unconditionally), dropped on a stale timing or a
/// teardown — so observing it proves the lifecycle directly.
/// Same gating as `reset_saved_display_audio_for_test`.
#[cfg(feature = "kernel-test")]
#[cfg(target_arch = "x86_64")]
pub(crate) fn has_saved_display_audio_for_test(connector_idx: u8) -> bool {
    SAVED_DISPLAY_AUDIO
        .lock()
        .as_ref()
        .is_some_and(|s| s.connector_idx == connector_idx)
}
static PM_SUSPENDED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn amdgpu_suspend_handler() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    if CONTROLLER
        .lock()
        .as_ref()
        .is_some_and(|gpu| gpu.chip.family == Family::Navi4)
    {
        // Navi48 suspends in the async system-PM phase (evict, quiesce, save
        // PCI state); nothing is left for the interrupt-gated fan-out.
        return if crate::amdgpu_navi48_platform::system_suspended() {
            Ok(())
        } else {
            Err(narf_power::device_pm::DeviceSuspendError::NotImplemented)
        };
    }
    if CONTROLLER.lock().as_ref().is_some_and(|gpu| !gpu.is_apu()) {
        // No discrete TMR teardown, training-cache restore or SMU resume yet.
        // Refuse before modifying PM state or sending an APU mailbox command.
        return Err(narf_power::device_pm::DeviceSuspendError::NotImplemented);
    }
    if !is_probed() {
        return Ok(());
    }
    if !crate::amdgpu_usbc::suspend() {
        return Err(narf_power::device_pm::DeviceSuspendError::Busy);
    }
    PM_SUSPENDED.store(true, core::sync::atomic::Ordering::Release);
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
        let mp1_base = match d.mp1_mailbox_base() {
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
    if !is_probed() || !PM_SUSPENDED.swap(false, core::sync::atomic::Ordering::AcqRel) {
        return Ok(());
    }
    // 1. Re-arm SMU mailbox with a TEST_MESSAGE echo. The PSP
    //    TMR survived S3 so SMU firmware is still loaded; we
    //    just need to confirm the mailbox is alive before the
    //    next bring-up step issues real commands.
    let _ = with_controller(|d| {
        let mp1_base = d.mp1_mailbox_base()?;
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
        let mp1_base = d.mp1_mailbox_base()?;
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
    // Multi-connector display-audio resume (#1712): re-execute the
    // audio enable writes for every still-Connected external
    // connector with a programmed mode, after `set_mode` above
    // re-programmed video. The `set_mode` snapshot re-run covers
    // the last applied plan only; this is the multi-connector path.
    // A missing KMS state (probe never built one) is a silent
    // no-op — the snapshot path above already handled that case.
    let _ = with_controller_mut(|d| {
        let mut guard = KMS_STATE.lock();
        let Some(kms) = guard.as_mut() else {
            return;
        };
        // SAFETY: probe gave us BAR ownership, still held.
        let _ = unsafe { d.resume_display_audio(kms) };
    });
    if !crate::amdgpu_usbc::resume() {
        PM_SUSPENDED.store(true, core::sync::atomic::Ordering::Release);
        return Err(narf_power::device_pm::DeviceSuspendError::DriverError);
    }
    Ok(())
}

/// Register the driver with the bus's match table. Explicit
/// VID/DID matches for the family list above + a class-match
/// backstop for any AMD VGA device whose specific DID isn't
/// listed.
pub fn register_pci_driver() {
    let exact: &[(&'static str, u16, u16)] = &[
        ("amdgpu-hawkpoint", AMD_VENDOR, PHOENIX_HAWKPOINT1),
        ("amdgpu-phoenix1", AMD_VENDOR, PHOENIX1),
        ("amdgpu-phoenix2", AMD_VENDOR, PHOENIX2),
        ("amdgpu-strix", AMD_VENDOR, STRIX_POINT),
        ("amdgpu-rembrandt", AMD_VENDOR, REMBRANDT),
        ("amdgpu-raphael", AMD_VENDOR, RAPHAEL),
        ("amdgpu-cezanne", AMD_VENDOR, CEZANNE),
        ("amdgpu-renoir", AMD_VENDOR, RENOIR),
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
    // Listed RDNA4 boards; unlisted ones reach `probe` through the class match
    // and are identified by discovery.
    for known in crate::amdgpu_rdna4::KNOWN_DEVICES {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: match known.chip {
                crate::amdgpu_rdna4::Rdna4Chip::Navi48 => "amdgpu-navi48",
                crate::amdgpu_rdna4::Rdna4Chip::Navi44 => "amdgpu-navi44",
            },
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: AMD_VENDOR,
                device: known.did,
            },
            probe,
        });
    }
    for profile in crate::amdgpu_rdna2::PROFILES {
        for &device in profile.pci_ids {
            narf_bus::register_pci_driver(narf_bus::PciMatch {
                name: profile.asic,
                kind: narf_bus::MatchKind::VendorDevice {
                    vendor: AMD_VENDOR,
                    device,
                },
                probe,
            });
        }
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

pub(crate) fn is_navi22() -> bool {
    CONTROLLER
        .lock()
        .as_ref()
        .is_some_and(|gpu| crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did).is_some())
}

/// Synchronous preparation under the controller lock, followed by permanent
/// transfer of MMIO ownership on success. Errors leave the controller usable.
pub(crate) fn claim_navi22<R, E>(
    prepare: impl FnOnce(&AmdGpu) -> Result<R, E>,
) -> Option<Result<R, E>> {
    claim_matching(
        |gpu| crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did).is_some(),
        prepare,
    )
}

/// Whether the bound GPU is an RDNA4 die (Navi48 or Navi44, by discovered
/// GC). The `navi48` names predate Navi44 and cover the whole family.
pub(crate) fn is_navi48() -> bool {
    CONTROLLER
        .lock()
        .as_ref()
        .is_some_and(|gpu| crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_some())
}
/// `claim_navi22`'s counterpart for any RDNA4 die.
pub(crate) fn claim_navi48<R, E>(
    prepare: impl FnOnce(&AmdGpu) -> Result<R, E>,
) -> Option<Result<R, E>> {
    claim_matching(
        |gpu| crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_some(),
        prepare,
    )
}
fn claim_matching<R, E>(
    matches: impl FnOnce(&AmdGpu) -> bool,
    prepare: impl FnOnce(&AmdGpu) -> Result<R, E>,
) -> Option<Result<R, E>> {
    let controller = CONTROLLER.lock();
    let gpu = controller.as_ref()?;
    if !matches(gpu) || DISCRETE_OWNED.load(core::sync::atomic::Ordering::Acquire) {
        return None;
    }
    let result = prepare(gpu);
    if result.is_ok() {
        DISCRETE_OWNED.store(true, core::sync::atomic::Ordering::Release);
    }
    Some(result)
}

/// Immutable discovery data only; deliberately does not expose GPU registers.
pub(crate) fn info_snapshot() -> Option<crate::amdgpu_info::Snapshot> {
    CONTROLLER
        .lock()
        .as_ref()
        .map(crate::amdgpu_info::Snapshot::from_gpu)
}

/// Returns None after a discrete GPU boot owner claims the hardware. Its immutable
/// DRM discovery snapshot remains available independently of this MMIO access.
pub fn with_controller<R>(f: impl FnOnce(&AmdGpu) -> R) -> Option<R> {
    let controller = CONTROLLER.lock();
    if DISCRETE_OWNED.load(core::sync::atomic::Ordering::Acquire) {
        return None;
    }
    controller.as_ref().map(f)
}

/// `&mut` variant of `with_controller`. Used by `set_mode` and other
/// state-mutating bring-up paths.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut AmdGpu) -> R) -> Option<R> {
    let mut controller = CONTROLLER.lock();
    if DISCRETE_OWNED.load(core::sync::atomic::Ordering::Acquire) {
        return None;
    }
    controller.as_mut().map(f)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_memory_info_tests.rs"]
mod memory_info_tests;

#[cfg(feature = "kernel-test")]
mod navi22_ownership_tests {
    use super::*;
    use core::sync::atomic::Ordering;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn navi48_boot_claim_excludes_legacy_access_and_wrong_owner() -> TestResult {
        if is_probed() {
            return TestResult::Skip("real controller owns the global slot");
        }
        // Every RDNA4 board takes the same exclusive cold-boot claim.
        for profile in crate::amdgpu_rdna4::tests::Profile::ALL {
            let mut gpu = crate::amdgpu_navi48_firmware::tests::gpu();
            profile.apply(&mut gpu);
            let did = gpu.chip.did;
            *CONTROLLER.lock() = Some(gpu);
            let claimed = is_navi48()
                && claim_navi22(|_| Ok::<_, ()>(())).is_none()
                && claim_navi48(|_| Ok::<_, ()>(())) == Some(Ok(()))
                && info_snapshot().is_some_and(|info| info.did == u32::from(did));
            *CONTROLLER.lock() = None;
            DISCRETE_OWNED.store(false, Ordering::Release);
            if !claimed {
                return TestResult::Fail("RDNA4 profile cold-boot claim");
            }
        }
        *CONTROLLER.lock() = Some(crate::amdgpu_navi48_firmware::tests::gpu());
        let prior_pm = PM_SUSPENDED.swap(false, Ordering::AcqRel);
        let wrong = claim_navi22(|_| Ok::<_, ()>(())).is_none();
        let failed: Option<Result<(), ()>> = claim_navi48(|_| Err(()));
        let released = failed == Some(Err(())) && with_controller(|_| true) == Some(true);
        let claimed = claim_navi48(|_| Ok::<_, ()>(())) == Some(Ok(()));
        let exclusive = with_controller(|_| true).is_none()
            && with_controller_mut(|_| true).is_none()
            && claim_navi48(|_| Ok::<_, ()>(())).is_none()
            && info_snapshot().is_some_and(|info| info.did == u32::from(NAVI48))
            && is_navi48()
            && amdgpu_suspend_handler()
                == Err(narf_power::device_pm::DeviceSuspendError::NotImplemented)
            && !PM_SUSPENDED.load(Ordering::Acquire);
        *CONTROLLER.lock() = None;
        DISCRETE_OWNED.store(false, Ordering::Release);
        PM_SUSPENDED.store(prior_pm, Ordering::Release);
        if wrong && released && claimed && exclusive {
            TestResult::Pass
        } else {
            TestResult::Fail("Navi48 ownership rollback, exclusivity or PM gating")
        }
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi48",
        navi48_boot_claim_excludes_legacy_access_and_wrong_owner
    );

    fn navi22_boot_claim_excludes_legacy_access_and_suspend() -> TestResult {
        if is_probed() {
            return TestResult::Skip("real controller owns the global slot");
        }
        // Fake metadata uses null MMIO: any accidental legacy suspend access
        // faults rather than making this test appear to pass through zeros.
        let gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let mailbox_blocked = gpu.mp1_mailbox_base().is_none();
        *CONTROLLER.lock() = Some(gpu);
        let prior_pm = PM_SUSPENDED.swap(false, Ordering::AcqRel);
        let failed_prepare: Option<Result<(), ()>> = claim_navi22(|_| Err(()));
        let failure_released =
            failed_prepare == Some(Err(())) && with_controller(|_| true) == Some(true);
        let pm_refused = amdgpu_suspend_handler()
            == Err(narf_power::device_pm::DeviceSuspendError::NotImplemented)
            && !PM_SUSPENDED.load(Ordering::Acquire);
        let claimed: Option<Result<(), ()>> = claim_navi22(|_| Ok(()));
        let exclusive = claimed == Some(Ok(()))
            && with_controller(|_| true).is_none()
            && with_controller_mut(|_| true).is_none()
            && claim_navi22(|_| Ok::<_, ()>(())).is_none()
            && info_snapshot().is_some_and(|info| info.did == u32::from(NAVI22))
            && is_probed()
            && amdgpu_suspend_handler()
                == Err(narf_power::device_pm::DeviceSuspendError::NotImplemented);
        *CONTROLLER.lock() = None;
        DISCRETE_OWNED.store(false, Ordering::Release);
        PM_SUSPENDED.store(prior_pm, Ordering::Release);
        if !(mailbox_blocked && failure_released && pm_refused && exclusive) {
            return TestResult::Fail("Navi22 owner/PM exclusion or failed-preflight rollback");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/navi22",
        navi22_boot_claim_excludes_legacy_access_and_suspend
    );
}

// ── HDMI/DP audio KMS apply fixtures (#1712) ─────────────────────

#[cfg(feature = "kernel-test")]
mod hdmi_dp_audio_kms_tests {
    use super::*;
    use crate::amdgpu_atom_displayobj::{ConnectorKind, DisplayPath};
    use crate::amdgpu_dcn::DC_HPD_SENSE_DELAYED;
    use crate::amdgpu_dcn20_audio::{AFMT_AUDIO_PACKET_CONTROL, DCCG_AUDIO_DTO_SOURCE, DIG_STRIDE};
    use crate::amdgpu_hdmi_audio::AudioFormat;
    use crate::amdgpu_hpd::{HpdMachine, HpdOutcome, HpdSource};
    use crate::amdgpu_ih_drainer::IhHpdDrain;
    use crate::amdgpu_ih_navi22::Iv;
    use crate::amdgpu_modeset::{plan_modeset, ConnectorStatus, CrtcState, EncoderKind, KmsState};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Words-backed fixture GPU (Phoenix APU) with DCN bases
    /// resolved: base 0x5000, BASE_IDX 2 segment 0x9000 when
    /// `base2` — the same bases the modeset plan tests use.
    fn fixture_gpu(words: &mut [u32; 16], base2: bool) -> AmdGpu {
        let mut gpu = crate::amdgpu_gfx_navi22::tests::gpu();
        gpu.regs.virt = words.as_mut_ptr() as u64;
        gpu.regs.len = (words.len() * 4) as u64;
        gpu.fw_loaded = true;
        gpu.chip = __test_chip_info_for_pci_id(AMD_VENDOR, PHOENIX_HAWKPOINT1).unwrap();
        for block in gpu.ip_blocks.iter_mut() {
            if block.hw_id == crate::amdgpu_discovery::HW_ID_GC {
                (block.major, block.minor, block.revision) = (11, 0, 1);
            }
            if block.hw_id == crate::amdgpu_discovery::HW_ID_DCN {
                block.num_bases = if base2 { 3 } else { 1 };
                block.base_addrs[0] = 0x5000;
                block.base_addrs[2] = 0x9000;
            }
        }
        gpu
    }

    /// KMS with one HDMI connector (index 0, DIG 2, initially
    /// Disconnected) and one eDP connector (index 1, Connected,
    /// chain-less). Mirrors the fake-VBIOS topology.
    fn kms_hdmi_edp() -> KmsState {
        let mut kms = KmsState::new(4);
        kms.ingest_atom_paths(
            [
                DisplayPath {
                    device_tag: 0x0002,
                    connector_kind: ConnectorKind::HdmiA,
                    connector_index: 2,
                    gpu_object_id: 0x1101,
                },
                DisplayPath {
                    device_tag: 0x0004,
                    connector_kind: ConnectorKind::Edp,
                    connector_index: 1,
                    gpu_object_id: 0x1102,
                },
            ]
            .iter()
            .copied(),
        );
        kms.push_encoder(EncoderKind::Hdmi, 2, 0b0001);
        kms.bind_encoder(0, 0).expect("bind HDMI encoder");
        kms
    }

    /// Installs the test KMS/HPD state into the driver statics and
    /// clears both on drop — the statics are process-global, like
    /// CONTROLLER, so a test must not leak them into the next one.
    /// Also clears the saved display-audio snapshot, which
    /// `apply_modeset_plan` writes: a later `set_mode` test with
    /// matching timing would otherwise replay this test's audio
    /// writes into its own fixture.
    struct KmsGuard;
    impl Drop for KmsGuard {
        fn drop(&mut self) {
            *KMS_STATE.lock() = None;
            *HPD_STATE.lock() = None;
            *SAVED_DISPLAY_AUDIO.lock() = None;
        }
    }

    fn mode_1080p() -> Mode {
        Mode {
            width: 1920,
            height: 1080,
            stride: 1920,
        }
    }

    /// HDMI modeset executes the audio enable sequence after video:
    /// the last INDEX/DATA pair is the AFMT sample-send un-mute on
    /// DIG 2's block, and KMS records the modeset.
    fn smoke_amdgpu_kms_modeset_hdmi_audio_executes() -> TestResult {
        let _guard = KmsGuard;
        let mut words = [0u32; 16];
        let mut gpu = fixture_gpu(&mut words, true);
        if gpu.ip_block_base(crate::amdgpu_discovery::HW_ID_DCN, 0) != Some(0x5000) {
            return TestResult::Fail("fixture DCN base not resolved");
        }
        let mut kms = kms_hdmi_edp();
        kms.set_status(0, ConnectorStatus::Connected);
        *KMS_STATE.lock() = Some(kms);
        *HPD_STATE.lock() = Some(HpdMachine::new());
        if gpu
            .modeset_connector(0, mode_1080p(), 60, 0x8000_0000)
            .is_err()
        {
            return TestResult::Fail("HDMI modeset_connector failed");
        }
        // AFMT_AUDIO_PACKET_CONTROL on DIG 2, sample-send bit set.
        let afmt = 0x9000 + AFMT_AUDIO_PACKET_CONTROL + 2 * DIG_STRIDE;
        if words[0] != afmt || words[1] != 1 {
            return TestResult::Fail("HDMI modeset did not end with the AFMT enable");
        }
        let guard = KMS_STATE.lock();
        let Some(kms) = guard.as_ref() else {
            return TestResult::Fail("KMS state missing after modeset");
        };
        let conn = &kms.connectors[0];
        let Some(crtc_idx) = conn.bound_crtc else {
            return TestResult::Fail("HDMI connector has no bound CRTC after modeset");
        };
        let crtc = &kms.crtcs[crtc_idx as usize];
        if crtc.state != CrtcState::Active {
            return TestResult::Fail("HDMI CRTC not Active after modeset");
        }
        if crtc
            .mode
            .is_none_or(|m| m.width != 1920 || m.height != 1080)
        {
            return TestResult::Fail("HDMI CRTC mode wrong after modeset");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amdgpu_kms_modeset_hdmi_audio_executes);

    /// The internal panel modesets video-only: the plan carries no
    /// audio writes and the latch holds the plan's last video write.
    fn smoke_amdgpu_kms_modeset_edp_video_only() -> TestResult {
        let _guard = KmsGuard;
        let mut words = [0u32; 16];
        let mut gpu = fixture_gpu(&mut words, true);
        *KMS_STATE.lock() = Some(kms_hdmi_edp());
        *HPD_STATE.lock() = Some(HpdMachine::new());
        if gpu
            .modeset_connector(1, mode_1080p(), 60, 0x8000_0000)
            .is_err()
        {
            return TestResult::Fail("eDP modeset_connector failed");
        }
        let guard = KMS_STATE.lock();
        let Some(kms) = guard.as_ref() else {
            return TestResult::Fail("KMS state missing after modeset");
        };
        let plan = match plan_modeset(
            kms,
            Family::Phoenix,
            1,
            1920,
            1080,
            60,
            1920,
            0x8000_0000,
            0x5000,
            0x9000,
        ) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("eDP plan rebuild failed"),
        };
        if !plan.audio_writes.is_empty() {
            return TestResult::Fail("eDP plan must carry no audio writes");
        }
        let Some(last) = plan.writes.last() else {
            return TestResult::Fail("eDP plan has no video writes");
        };
        if words[0] != last.addr || words[1] != last.value {
            return TestResult::Fail("eDP modeset latch is not the last video write");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amdgpu_kms_modeset_edp_video_only);

    /// Without the BASE_IDX 2 segment an HDMI modeset still
    /// succeeds but programs video only — no spurious audio enable.
    fn smoke_amdgpu_kms_modeset_no_base2_video_only() -> TestResult {
        let _guard = KmsGuard;
        let mut words = [0u32; 16];
        let mut gpu = fixture_gpu(&mut words, false);
        let mut kms = kms_hdmi_edp();
        kms.set_status(0, ConnectorStatus::Connected);
        *KMS_STATE.lock() = Some(kms);
        *HPD_STATE.lock() = Some(HpdMachine::new());
        if gpu
            .modeset_connector(0, mode_1080p(), 60, 0x8000_0000)
            .is_err()
        {
            return TestResult::Fail("HDMI modeset without base2 failed");
        }
        let guard = KMS_STATE.lock();
        let Some(kms) = guard.as_ref() else {
            return TestResult::Fail("KMS state missing after modeset");
        };
        let plan = match plan_modeset(
            kms,
            Family::Phoenix,
            0,
            1920,
            1080,
            60,
            1920,
            0x8000_0000,
            0x5000,
            0,
        ) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("no-base2 plan rebuild failed"),
        };
        if !plan.audio_writes.is_empty() {
            return TestResult::Fail("plan without base2 must carry no audio writes");
        }
        let Some(last) = plan.writes.last() else {
            return TestResult::Fail("no-base2 plan has no video writes");
        };
        if words[0] != last.addr || words[1] != last.value {
            return TestResult::Fail("no-base2 modeset latch is not the last video write");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amdgpu_kms_modeset_no_base2_video_only);

    /// Full hotplug round trip: unmapped source drops, connect
    /// debounces and then marks the connector Connected, modeset
    /// programs audio, disconnect tears audio down (latch ends on
    /// the DTO release) and frees the CRTC, and a second disconnect
    /// on the idle pin writes nothing.
    fn smoke_amdgpu_kms_hotplug_connect_disconnect_audio() -> TestResult {
        let _guard = KmsGuard;
        let mut words = [0u32; 16];
        let mut gpu = fixture_gpu(&mut words, true);
        *KMS_STATE.lock() = Some(kms_hdmi_edp());
        let mut hpd = HpdMachine::with_debounce(100);
        hpd.bind(HpdSource::Hpd1, 0);
        *HPD_STATE.lock() = Some(hpd);
        // HPD2 has no binding.
        if gpu.handle_hotplug_event(1, true, 1000) != Some(HpdOutcome::UnmappedSource) {
            return TestResult::Fail("unbound HPD source must be UnmappedSource");
        }
        // Connect on HPD1: debounce pending.
        if gpu.handle_hotplug_event(0, true, 1000) != Some(HpdOutcome::NoChange) {
            return TestResult::Fail("connect must debounce (NoChange)");
        }
        if !gpu.poll_hotplug(1050).is_empty() {
            return TestResult::Fail("poll before the window must emit nothing");
        }
        if gpu.poll_hotplug(1200) != alloc::vec![0] {
            return TestResult::Fail("poll after the window must emit connector 0");
        }
        {
            let guard = KMS_STATE.lock();
            let Some(kms) = guard.as_ref() else {
                return TestResult::Fail("KMS state missing after poll");
            };
            if kms.connectors[0].status != ConnectorStatus::Connected {
                return TestResult::Fail("poll must mark the connector Connected");
            }
        }
        if gpu
            .modeset_connector(0, mode_1080p(), 60, 0x8000_0000)
            .is_err()
        {
            return TestResult::Fail("modeset after connect failed");
        }
        let afmt = 0x9000 + AFMT_AUDIO_PACKET_CONTROL + 2 * DIG_STRIDE;
        if words[0] != afmt || words[1] != 1 {
            return TestResult::Fail("modeset after connect did not enable audio");
        }
        if gpu.handle_hotplug_event(0, false, 2000)
            != Some(HpdOutcome::Disconnected { connector_idx: 0 })
        {
            return TestResult::Fail("disconnect must emit Disconnected");
        }
        // DTO source released last, value 0.
        if words[0] != 0x5000 + DCCG_AUDIO_DTO_SOURCE || words[1] != 0 {
            return TestResult::Fail("disconnect must end with the DTO release");
        }
        {
            let guard = KMS_STATE.lock();
            let Some(kms) = guard.as_ref() else {
                return TestResult::Fail("KMS state missing after disconnect");
            };
            if kms.connectors[0].status != ConnectorStatus::Disconnected {
                return TestResult::Fail("disconnect must mark the connector Disconnected");
            }
            if kms.connectors[0].bound_crtc.is_some() {
                return TestResult::Fail("disconnect must drop the CRTC binding");
            }
        }
        let (w0, w1) = (words[0], words[1]);
        if gpu.handle_hotplug_event(0, false, 3000) != Some(HpdOutcome::NoChange) {
            return TestResult::Fail("second disconnect must be NoChange");
        }
        if words[0] != w0 || words[1] != w1 {
            return TestResult::Fail("spurious disconnect wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amdgpu_kms_hotplug_connect_disconnect_audio
    );

    /// Live IH ring drainer (#1785): a fake IH ring — raw 32-byte
    /// cookies decoded by `Iv::decode` — plus pin levels staged in
    /// the fixture latch drives the full connect/disconnect round
    /// trip through `drain_ih_hotplug` + `service_hotplug`: a vblank
    /// cookie and an out-of-range context id are skipped, an unbound
    /// HPD2 cookie is unmapped, an HPD6 cookie has no sense register
    /// and is dropped, the HPD1 plug debounces and then marks the
    /// connector Connected, modeset programs audio (AFMT enable
    /// last), a sink-IRQ cookie passes through without a pin read,
    /// and the disconnect tears audio down (DTO release last) and
    /// frees the CRTC.
    fn smoke_amdgpu_kms_ih_drainer_connect_disconnect_audio() -> TestResult {
        let _guard = KmsGuard;
        let mut words = [0u32; 16];
        let mut gpu = fixture_gpu(&mut words, true);
        *KMS_STATE.lock() = Some(kms_hdmi_edp());
        let mut hpd = HpdMachine::with_debounce(100);
        hpd.bind(HpdSource::Hpd1, 0);
        *HPD_STATE.lock() = Some(hpd);

        /// One raw 32-byte ring cookie: DCE client, the given
        /// source id, `src_data[0]` = the HPD context id.
        fn cookie(src: u8, ctxid: u32) -> Iv {
            Iv::decode([0x04 | (u32::from(src) << 8), 0, 0, 0, ctxid, 0, 0, 0])
        }
        // Pin levels are staged in the latch: `hpd_asserted` reads
        // the DATA word (words[1]) through the MM_INDEX/MM_DATA
        // pair, so staging words[1] stages the pin level the next
        // read returns. (The AFMT/DTO assertions below read the same
        // latch as the last INDEX/DATA pair, so the level is
        // re-staged before every drain that needs one.)
        words[1] = DC_HPD_SENSE_DELAYED;
        let ring = [
            cookie(0x3c, 0), // pipe 0 vblank: not HPD
            cookie(9, 1),    // plug, HPD2: no binding
            cookie(9, 5),    // plug, HPD6: no sense register
            cookie(9, 0),    // plug, HPD1, pin high
            cookie(9, 12),   // context id past 11: not an HPD event
        ];
        let report = gpu.drain_ih_hotplug(&ring, 1000);
        if report
            != (IhHpdDrain {
                fed: 2,
                skipped_non_hpd: 2,
                skipped_pin_unreadable: 1,
                unmapped: 1,
                short_pulse: 0,
            })
        {
            return TestResult::Fail("drainer counts wrong on the connect batch");
        }
        {
            let guard = KMS_STATE.lock();
            let Some(kms) = guard.as_ref() else {
                return TestResult::Fail("KMS state missing after drain");
            };
            if kms.connectors[0].status != ConnectorStatus::Disconnected {
                return TestResult::Fail("connect cookie must debounce, not connect");
            }
        }
        // No cookies: the scheduled poll samples the debounce timers.
        let (report, connected) = gpu.service_hotplug(&[], 1050);
        if report != IhHpdDrain::default() || !connected.is_empty() {
            return TestResult::Fail("poll before the window must emit nothing");
        }
        let (report, connected) = gpu.service_hotplug(&[], 1200);
        if report != IhHpdDrain::default() || connected != alloc::vec![0] {
            return TestResult::Fail("poll after the window must emit connector 0");
        }
        {
            let guard = KMS_STATE.lock();
            let Some(kms) = guard.as_ref() else {
                return TestResult::Fail("KMS state missing after poll");
            };
            if kms.connectors[0].status != ConnectorStatus::Connected {
                return TestResult::Fail("poll must mark the connector Connected");
            }
        }
        if gpu
            .modeset_connector(0, mode_1080p(), 60, 0x8000_0000)
            .is_err()
        {
            return TestResult::Fail("modeset after connect failed");
        }
        let afmt = 0x9000 + AFMT_AUDIO_PACKET_CONTROL + 2 * DIG_STRIDE;
        if words[0] != afmt || words[1] != 1 {
            return TestResult::Fail("modeset after connect did not enable audio");
        }
        // Disconnect batch: a sink IRQ first (no pin read — the
        // staged level is irrelevant to it), then the plug with the
        // pin low.
        words[1] = 0;
        let ring = [cookie(9, 6), cookie(9, 0)];
        let report = gpu.drain_ih_hotplug(&ring, 2000);
        if report.fed != 2 || report.short_pulse != 1 {
            return TestResult::Fail("drainer counts wrong on the disconnect batch");
        }
        // DTO source released last, value 0.
        if words[0] != 0x5000 + DCCG_AUDIO_DTO_SOURCE || words[1] != 0 {
            return TestResult::Fail("disconnect must end with the DTO release");
        }
        {
            let guard = KMS_STATE.lock();
            let Some(kms) = guard.as_ref() else {
                return TestResult::Fail("KMS state missing after disconnect");
            };
            if kms.connectors[0].status != ConnectorStatus::Disconnected {
                return TestResult::Fail("disconnect must mark the connector Disconnected");
            }
            if kms.connectors[0].bound_crtc.is_some() {
                return TestResult::Fail("disconnect must drop the CRTC binding");
            }
        }
        // A second disconnect on the idle pin: the drain still reads
        // the pin back (the INDEX latch takes the HPD status
        // register's byte address) but no teardown writes execute.
        words[1] = 0;
        let report = gpu.drain_ih_hotplug(&[cookie(9, 0)], 3000);
        if report.fed != 1 {
            return TestResult::Fail("second disconnect must still feed");
        }
        let hpd_index = (0x9000
            + crate::amdgpu_dcn::for_pipe(
                crate::amdgpu_dcn::HPD0_DC_HPD_INT_STATUS,
                0,
                crate::amdgpu_dcn::HPD_STRIDE,
            ))
            * 4;
        if words[0] != hpd_index || words[1] != 0 {
            return TestResult::Fail("spurious disconnect wrote registers");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amdgpu_kms_ih_drainer_connect_disconnect_audio
    );

    /// EDID feed: a CEA block with one LPCM stereo 48 kHz SAD and
    /// an FL/FR speaker block lands in the connector's caps; an
    /// EDID with no extensions and an out-of-range connector both
    /// return false.
    fn smoke_amdgpu_kms_feed_connector_edid() -> TestResult {
        let _guard = KmsGuard;
        let mut words = [0u32; 16];
        let gpu = fixture_gpu(&mut words, true);
        *KMS_STATE.lock() = Some(kms_hdmi_edp());
        *HPD_STATE.lock() = Some(HpdMachine::new());
        let mut edid = [0u8; 256];
        edid[126] = 1;
        let cea = &mut edid[128..256];
        cea[0] = 0x02; // CEA-861 tag
        cea[1] = 0x03; // revision
        cea[2] = 10; // DTD offset: collection is bytes 4..10
        cea[4] = 0x23; // audio data block, tag 1, length 3
        cea[5] = 0x09; // LPCM (1), stereo (channels - 1 = 1)
        cea[6] = 0x04; // sample rates: 48 kHz
        cea[7] = 0x00; // 16-bit
        cea[8] = 0x81; // speaker allocation block, tag 4, length 1
        cea[9] = 0x01; // FL/FR
        if !gpu.feed_connector_edid(0, &edid) {
            return TestResult::Fail("CEA feed must succeed");
        }
        {
            let guard = KMS_STATE.lock();
            let Some(kms) = guard.as_ref() else {
                return TestResult::Fail("KMS state missing after feed");
            };
            let Some(caps) = &kms.connectors[0].audio_caps else {
                return TestResult::Fail("feed left no audio caps");
            };
            if caps.sads.len() != 1 || caps.sads[0].format != AudioFormat::LinearPcm {
                return TestResult::Fail("fed SAD wrong");
            }
            if caps.speakers != 0x01 {
                return TestResult::Fail("fed speaker mask wrong");
            }
        }
        let mut edid0 = [0u8; 128];
        edid0[126] = 0;
        if gpu.feed_connector_edid(0, &edid0) {
            return TestResult::Fail("feed without extensions must fail");
        }
        if gpu.feed_connector_edid(9, &edid) {
            return TestResult::Fail("feed to a missing connector must fail");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amdgpu_kms_feed_connector_edid);

    /// Resume re-executes the audio enable writes for the
    /// still-Connected connector after video is re-programmed:
    /// wipe the latch, run `resume_display_audio`, and the AFMT
    /// enable is rewritten.
    fn smoke_amdgpu_kms_resume_reenables_audio() -> TestResult {
        let _guard = KmsGuard;
        let mut words = [0u32; 16];
        let mut gpu = fixture_gpu(&mut words, true);
        let mut kms = kms_hdmi_edp();
        kms.set_status(0, ConnectorStatus::Connected);
        *KMS_STATE.lock() = Some(kms);
        *HPD_STATE.lock() = Some(HpdMachine::new());
        if gpu
            .modeset_connector(0, mode_1080p(), 60, 0x8000_0000)
            .is_err()
        {
            return TestResult::Fail("modeset for resume setup failed");
        }
        // Wipe the latch: resume must rewrite the enable itself.
        words = [0u32; 16];
        let resumed = {
            let guard = KMS_STATE.lock();
            let Some(kms) = guard.as_ref() else {
                return TestResult::Fail("KMS state missing for resume");
            };
            // SAFETY: fixture owns the words-backed BAR5.
            unsafe { gpu.resume_display_audio(kms) }
        };
        match resumed {
            Ok(true) => {}
            _ => return TestResult::Fail("resume_display_audio must execute writes"),
        }
        let afmt = 0x9000 + AFMT_AUDIO_PACKET_CONTROL + 2 * DIG_STRIDE;
        if words[0] != afmt || words[1] != 1 {
            return TestResult::Fail("resume did not rewrite the AFMT enable");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amdgpu_kms_resume_reenables_audio);
}
