//! Master Controller (PMC) — the top-level engine reset/enable +
//! interrupt routing block.
//!
//! ## References
//!
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mc/base.c`** —
//!   `nvkm_mc_enable/disable/reset/enabled`: per-engine
//!   `PMC_ENABLE` mask-set / mask-clear / readback-check against
//!   BAR0+0x200 (via the `nv04_mc_device` ops in `nv04.c`).
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mc/nv50.c`** —
//!   `nv50_mc_init`: the discrete-Pascal MC bring-up, the
//!   `.init` hook `gp100_mc` uses — a single
//!   `nvkm_wr32(device, 0x000200, 0xffffffff)` ("everything on").
//!   No per-engine order, no delay, no poll after the write.
//!   `gp10b.c` adds a second all-ones write at 0x20c (ELPG) —
//!   Tegra-only, not the discrete path.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mc/ga100.c`** —
//!   Ampere+ MC (`ga100_mc_init`: all-ones at 0x200 *and* 0x600).
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/mc/gp100.c`** &
//!   **`gk104.c`** — Pascal/Kepler MC functables; `gp100_mc_intrs[]`
//!   / `gk104_mc_intrs[]` are the top-level INTR_0 bit tables
//!   (PMU = `0x01000000`, DISP = `0x04000000`, FIFO = `0x100`).
//! - **envytools `hw/bus/pmc.html`** — independent second source
//!   for the GF100+ `PMC_ENABLE` bit list and the GF100+
//!   `INTR_HOST` bit list (used where Nouveau carries the bits
//!   only in runtime-parsed PTOP data, e.g. the copy/video
//!   engines and PSEC).
//! - **PMC_BOOT_0** at BAR0 offset 0x000000 — universal chip-id
//!   register. Used here as the presence + family detect.
//!
//! ## Register offsets (BAR0)
//!
//! | offset       | name                                       |
//! |--------------|--------------------------------------------|
//! | `0x000000`   | `NV_PMC_BOOT_0` — chip identifier          |
//! | `0x000100`   | `NV_PMC_INTR_0` — top-level IRQ status     |
//! | `0x000104`   | `NV_PMC_INTR_1` — secondary IRQ status     |
//! | `0x000140`   | `NV_PMC_INTR_EN_0` — IRQ mask, group 0     |
//! | `0x000144`   | `NV_PMC_INTR_EN_1` — IRQ mask, group 1     |
//! | `0x000200`   | `NV_PMC_ENABLE` — per-engine enable        |
//! | `0x000204`   | `NV_PMC_ENABLE_UNK0` — Ampere+ alt bank    |

#![allow(dead_code)]

extern crate alloc;

use crate::chip::ChipFamily;

// ── Register offsets ─────────────────────────────────────────────

/// `NV_PMC_BOOT_0` — chip identifier. Read-only. Stable since Fermi.
pub const PMC_BOOT_0: u64 = 0x0000_0000;

/// `NV_PMC_INTR_0` — top-level interrupt status, host group.
pub const PMC_INTR_0: u64 = 0x0000_0100;
/// `NV_PMC_INTR_1` — secondary interrupt status.
pub const PMC_INTR_1: u64 = 0x0000_0104;
/// `NV_PMC_INTR_EN_0` — interrupt enable, host group.
pub const PMC_INTR_EN_0: u64 = 0x0000_0140;
/// `NV_PMC_INTR_EN_1` — interrupt enable, secondary group.
pub const PMC_INTR_EN_1: u64 = 0x0000_0144;

/// `NV_PMC_ENABLE` — per-engine reset/enable. Bit set = engine
/// out of reset; cleared = engine held in reset.
pub const PMC_ENABLE: u64 = 0x0000_0200;
/// `NV_PMC_ENABLE_UNK0` — alternate enable bank on some parts.
pub const PMC_ENABLE_UNK0: u64 = 0x0000_0204;

// ── PMC_ENABLE engine-bit assignments ────────────────────────────
//
// Grounded (G3, 2026-11-11) against upstream Nouveau
// (`torvalds/linux` master `067c5c24`) and envytools
// (`hw/bus/pmc.html`, GF100+ lists) — NOT `dev_pmc.ref.txt`,
// which does not exist in open-gpu-doc (see §5 of the Nvidia
// driver programme record). Two earlier values were wrong and
// are corrected here:
//
// - `PMSPDEC` was `1 << 17`: that is the Fermi `MSPDEC` bit
//   (`gf100_mc_reset[]`: `{ 0x00020000, NVKM_ENGINE_MSPDEC }`).
//   On GM107+ the video-decoder enable is bit 15 (envytools
//   GF100+ ENABLE: "15: PVDEC [GM107:]"; bit 17 is the
//   decoder's *interrupt* line on GM107+, and the pre-GM107
//   PPDEC enable).
// - `PCE0` was `1 << 15`: that is the GM107+ PVDEC enable bit.
//   The copy engines are PCOPY[0..2] = bits 6, 7, 21 on GF100+
//   (envytools GF100+ ENABLE list). GP107 has four copy engines
//   (`nv137_chipset`: `.ce = { 0xf, gp102_ce_new }`); the
//   PCOPY[3] enable bit is unresolved in both sources, so only
//   PCOPY[0] is named here — CE bring-up (G10) must re-verify
//   the per-instance bits before enabling engines individually.
//
// The remaining bits are pinned by both sources: PFIFO 8 and
// PGRAPH 12 also appear in `nv04_mc_reset[]`
// (`{ 0x1000, NVKM_ENGINE_GR }, { 0x100, NVKM_ENGINE_FIFO }`);
// PMU 13 in `gk104_mc_reset[]`; PSEC 14, PVENC 18 and PDISP 30
// in the envytools GF100+ ENABLE list. Note the ENABLE and
// INTR_0 bit numbers for one engine often differ (PSEC: enable
// 14, interrupt 15; PVDEC: enable 15, interrupt 17) — the old
// table copied several INTR positions into ENABLE slots and
// vice versa; both tables below are now sourced independently.

/// `NV_PMC_ENABLE.PFIFO` — host FIFO engine.
pub const PMC_ENABLE_PFIFO: u32 = 1 << 8;
/// `NV_PMC_ENABLE.PGRAPH` — graphics engine.
pub const PMC_ENABLE_PGRAPH: u32 = 1 << 12;
/// `NV_PMC_ENABLE.PMSPDEC` — video decoder (PVDEC on GM107+).
pub const PMC_ENABLE_PMSPDEC: u32 = 1 << 15;
/// `NV_PMC_ENABLE.PMSENC` — video encoder (PVENC).
pub const PMC_ENABLE_PMSENC: u32 = 1 << 18;
/// `NV_PMC_ENABLE.PSEC` — security engine (SEC2).
pub const PMC_ENABLE_PSEC: u32 = 1 << 14;
/// `NV_PMC_ENABLE.PCE0` — copy engine 0 (PCOPY[0]).
pub const PMC_ENABLE_PCE0: u32 = 1 << 6;
/// `NV_PMC_ENABLE.PMU` — power-management microcontroller.
///
/// Grounded against upstream Nouveau, NOT `dev_pmc.ref.txt` (which
/// does not exist — see the `PMC_ENABLE` note above): the PMU's
/// reset mask is `0x00002000` in `nvkm/subdev/mc/gk104.c`
/// (`gk104_mc_reset[]`: `{ 0x00002000, NVKM_SUBDEV_PMU, 0, true }`),
/// the reset map `gp100_mc` uses (`.reset = gk104_mc_reset` in
/// `nvkm/subdev/mc/gp100.c`), and `nvkm_mc_enabled` tests it via
/// `nv04_mc_device_enabled`, which reads `PMC_ENABLE` (BAR0+0x200)
/// and checks `(value & mask) == mask`
/// (`nvkm/subdev/mc/nv04.c`). Bit set = PMU engine out of reset.
/// Envytools agrees independently (falcon parameters: PMU
/// "PMC enable bit: v2+: 13").
pub const PMC_ENABLE_PMU: u32 = 1 << 13;
/// `NV_PMC_ENABLE.PDISP` — display engine.
pub const PMC_ENABLE_PDISP: u32 = 1 << 30;

/// Engines `gk104_mc_reset[]` proves present on Pascal (FIFO +
/// PMU). Used as the post-enable sanity check: after the
/// all-ones write, both bits must read back set. Other engines
/// (GR, DISP, …) are enabled by the same write but are not part
/// of the check — their presence is a per-chip property the
/// readback alone cannot prove.
pub const PMC_ENABLE_CORE_MASK: u32 = PMC_ENABLE_PFIFO | PMC_ENABLE_PMU;

/// "Everything on" — the discrete-Pascal MC bring-up write.
/// Cite `nvkm/subdev/mc/nv50.c::nv50_mc_init`
/// (`nvkm_wr32(device, 0x000200, 0xffffffff)`, the `.init` hook
/// `gp100_mc` uses for GP107) and `nv04.c::nv04_mc_init`
/// (same write, "everything enabled").
pub const PMC_ENABLE_ALL: u32 = 0xFFFF_FFFF;

// ── PMC_BOOT_0 field layout ──────────────────────────────────────
//
// The architecture is a 6-bit field SPLIT across the register:
//
//   bits[3:0]    minor revision
//   bits[7:4]    major revision
//   bit  8       architecture_1 — MSB of the architecture
//   bits[23:20]  implementation (chip variant within an arch)
//   bits[28:24]  architecture_0 — low 5 bits of the architecture
//
//   architecture = ((raw >> 8) & 1) << 5 | ((raw >> 24) & 0x1F)
//
// Grounded against the upstream Linux Nova driver
// (`drivers/gpu/nova-core/regs.rs`, commit
// 1b155edcab0832a887387dd77e209e37beb7b49c — the commit that
// converted the open-gpu-doc register macros into Nova's
// register definitions; NVIDIA-authored, derived from
// open-gpu-doc/manuals):
//
//   NV_PMC_BOOT_0: minor 3:0, major 7:4, architecture_1 bit 8
//     ("MSB of the architecture"), implementation 23:20,
//     architecture_0 bits 28:24 ("Lower bits of the architecture")
//
// Nova's `Architecture` enum pins the resulting values:
// GF100 = 0x0c, Turing = 0x16, Ampere = 0x17, Ada = 0x19.
// The remaining family values in `chip::ChipFamily` follow the
// same rule from the NVxx codes (arch = NV-code >> 4).
//
// Two earlier readings of this register were wrong and are
// corrected here: (1) treating bits[28:20] as one 9-bit
// architecture tag folds the implementation nibble into the tag
// (a Turing TU102 with implementation 0x2 decodes as 0x162,
// not 0x160); (2) treating bits[19:8] as a 12-bit implementation
// field overlaps architecture_1. Both the gpu copy's
// `nvidia_gpu_pmc::Boot0` and this crate's previous decoder
// made those mistakes (self-consistent fixtures masked them —
// see the crate-split step-3 PR body). The cited
// `dev_pmc.ref.txt` does not exist in open-gpu-doc/manuals
// (tu102/ and ga102/ carry only `dev_display_withoffset.ref.txt`),
// so the Nova register definitions are the authority here.

/// Mask for `PMC_BOOT_0[3:0]` — minor revision.
pub const PMC_BOOT_0_MINOR_MASK: u32 = 0x0000_000F;
/// Mask for `PMC_BOOT_0[7:4]` — major revision.
pub const PMC_BOOT_0_MAJOR_MASK: u32 = 0x0000_00F0;
/// Mask for `PMC_BOOT_0[23:20]` — implementation (chip variant).
pub const PMC_BOOT_0_IMPL_MASK: u32 = 0x00F0_0000;
/// Shift to recover the implementation nibble.
pub const PMC_BOOT_0_IMPL_SHIFT: u32 = 20;
/// Mask for `PMC_BOOT_0[28:24]` — architecture_0, the low 5 bits
/// of the architecture value.
pub const PMC_BOOT_0_ARCH0_MASK: u32 = 0x1F00_0000;
/// Shift to recover architecture_0.
pub const PMC_BOOT_0_ARCH0_SHIFT: u32 = 24;
/// Mask for `PMC_BOOT_0[8]` — architecture_1, the MSB of the
/// architecture value.
pub const PMC_BOOT_0_ARCH1_MASK: u32 = 0x0000_0100;

/// Decoded `PMC_BOOT_0`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Boot0 {
    pub family: ChipFamily,
    /// Implementation (chip variant within an architecture) — the
    /// 4-bit nibble at bits[23:20].
    pub implementation: u16,
    pub major_rev: u8,
    pub minor_rev: u8,
}

impl Boot0 {
    /// Sanity-check that the value plausibly came from silicon
    /// rather than from a torn PCI bus / unmapped BAR.
    pub const fn looks_present(raw: u32) -> bool {
        // All-ones is the typical "BAR not mapped / device gone"
        // pattern; all-zeros is the second-typical case.
        raw != 0xFFFF_FFFF && raw != 0x0000_0000
    }

    /// Decode a raw PMC_BOOT_0 sample.
    pub const fn decode(raw: u32) -> Self {
        let minor_rev = (raw & PMC_BOOT_0_MINOR_MASK) as u8;
        let major_rev = ((raw & PMC_BOOT_0_MAJOR_MASK) >> 4) as u8;
        let implementation = ((raw & PMC_BOOT_0_IMPL_MASK) >> PMC_BOOT_0_IMPL_SHIFT) as u16;
        let arch0 = ((raw & PMC_BOOT_0_ARCH0_MASK) >> PMC_BOOT_0_ARCH0_SHIFT) as u8;
        let arch1 = ((raw & PMC_BOOT_0_ARCH1_MASK) >> 8) as u8;
        let arch = (arch1 << 5) | arch0;
        let family = ChipFamily::from_arch_version(arch);
        Self {
            family,
            implementation,
            major_rev,
            minor_rev,
        }
    }
}

// ── Top-level interrupt mask vectors ─────────────────────────────
//
// Top-level `PMC_INTR_0` bits, grounded on Nouveau's per-chip MC
// intr tables — NOT `dev_pmc.ref.txt`, which does not exist in
// open-gpu-doc (see §5 of the programme record). The tables agree
// where they overlap:
//
// - `gp100_mc_intr[]` (`nvkm/subdev/mc/gp100.c`, Pascal — the target
//   family): DISP `0x04000000`, FIFO `0x00000100`, FAULT `0x00000200`,
//   IBUS `0x40000000`, BUS `0x10000000`, FB `0x08000000`, LTC
//   `0x02000000`, **PMU `0x01000000` (bit 24)**, GPIO/I2C
//   `0x00200000` (bit 21), TIMER `0x00100000`, THERM `0x00040000`,
//   FB `0x00002000`.
// - `gk104_mc_intr[]` (`nvkm/subdev/mc/gk104.c`) and
//   `gf100_mc_intr[]` (`nvkm/subdev/mc/gf100.c`) agree on PMU
//   `0x01000000`; `gf100` additionally lists GR `0x00001000` (bit
//   12) and CE0/CE1/CE2 `0x20/0x40/0x80` (bits 5/6/7).
//
// Corrections this implies (G4 lane, G13 item):
//
// - `Pmu` is bit **24** (`0x01000000`), not bit 21. The old value
//   was wrong; bit 21 is GPIO/I2C in all three tables, so the
//   "Pmu/Sec swapped" reading is refuted — there is no swap, the PMU
//   bit was simply wrong and SEC has no top-level bit at all.
// - `Sec` (SEC2) has **no** `PMC_INTR_0` bit in any Nouveau MC table:
//   SEC2 registers its interrupt through the `nvkm_intr` vector tree
//   (`nvkm/engine/sec2/base.c::nvkm_sec2_oneinit`, via the
//   `intr_vector` hook — e.g. `ga102_sec2_intr_vector` reads the TOP
//   vector from `0x8403e0`), not through the PMC map. Its
//   `intr0_bit` is therefore `0`, and the walker skips it.
// - `Gsp` likewise has no PMC bit (GSP is Turing+; its interrupts
//   route via GIN/TOP, not `PMC_INTR_0` — see the Nova core
//   interrupts doc, `Documentation/gpu/nova/core/interrupts.rst`).
//   Bit 28 (`0x10000000`) in the tables is BUS, not GSP.
// - `Graphics` bit 12 is grounded on `gf100_mc_intr[]` (GR
//   `0x00001000`); the Pascal table omits engines (they route via
//   the intr tree in the modern model), but the hardware bit is the
//   same register.
// - `CopyEngine0/1/2` bits 13/14/15 are **UNVERIFIED**: they collide
//   with the tables (bit 13 is FB `0x00002000`, bit 15 is MSVLD
//   `0x00008000` in `gf100`), while `gf100` puts CE0/CE1/CE2 at bits
//   5/6/7. Do NOT "fix" them to 5/6/7 without a Pascal-era engine-bit
//   source — the Fermi table may not apply to Pascal engine routing.
//   G13 remainder; the handler never masks unknown bits.
// - `NVKM_SUBDEV_FAULT` (`0x00000200`, bit 9, `gp100`) has no
//   `IntrSource` variant yet; the handler counts it as unrecognized.
//   G13 remainder.
//
// We model the interrupt-source bits as a typed enum so the routing
// code can be exhaustive. A bit of `0` means "no top-level
// `PMC_INTR_0` bit" — the walker skips such sources, and
// mask/unmask with bit `0` is a no-op.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IntrSource {
    Fifo,
    Graphics,
    CopyEngine0,
    CopyEngine1,
    CopyEngine2,
    Display,
    Sec,
    Pmu,
    // Kept (G4): no top-level `PMC_INTR_0` bit (`intr0_bit` is 0);
    // G3 removed this variant, but the G4 IRQ design keeps it so
    // the walker can enumerate it and skip it, and the G4 test
    // pins the 0 bit. Restored during the G3 rebase onto main.
    Gsp,
}

impl IntrSource {
    /// Bit mask in `PMC_INTR_0`, or `0` when the source has no
    /// top-level `PMC_INTR_0` bit (`Sec`, `Gsp` — see the table
    /// comment above). Grounded per source on the Nouveau MC intr
    /// tables (`gp100`/`gk104`/`gf100`); the `dev_pmc.ref.txt`
    /// citation this previously carried does not exist.
    pub const fn intr0_bit(self) -> u32 {
        match self {
            IntrSource::Fifo => 1 << 8,
            IntrSource::Graphics => 1 << 12,
            // UNVERIFIED (see the table comment): collides with the
            // `gf100` table, which puts CE0/CE1/CE2 at bits 5/6/7.
            IntrSource::CopyEngine0 => 1 << 13,
            IntrSource::CopyEngine1 => 1 << 14,
            IntrSource::CopyEngine2 => 1 << 15,
            IntrSource::Display => 1 << 26,
            // No top-level bit: SEC2 routes via the intr-vector tree.
            IntrSource::Sec => 0,
            // `gp100_mc_intr[]` / `gk104` / `gf100`: PMU 0x01000000.
            IntrSource::Pmu => 1 << 24,
            // No top-level bit: GSP routes via GIN/TOP (Turing+).
            // Bit 28 in the tables is BUS, not GSP.
            IntrSource::Gsp => 0,
        }
    }

    /// All sources, in canonical walk order. Cite gk104.c's
    /// `gk104_mc_intrs[]` for the same ordering — high-priority
    /// (DISP, FIFO) first, then per-engine, then subsystems.
    pub const fn all() -> &'static [IntrSource] {
        &[
            IntrSource::Display,
            IntrSource::Fifo,
            IntrSource::Graphics,
            IntrSource::CopyEngine0,
            IntrSource::CopyEngine1,
            IntrSource::CopyEngine2,
            IntrSource::Sec,
            IntrSource::Pmu,
            IntrSource::Gsp,
        ]
    }

    /// Per-engine interrupt-status register inside BAR0 for this
    /// source. This is the second-level register the IH walker
    /// touches after PMC_INTR_0 reports the top-level bit. Cite
    /// per-engine `dev_*.ref.txt`.
    pub const fn engine_status_offset(self) -> Option<u64> {
        match self {
            IntrSource::Fifo => Some(crate::fifo::PFIFO_INTR_0),
            IntrSource::Graphics => Some(crate::gr::PGRAPH_INTR),
            IntrSource::Display => Some(0x0061_0024),
            IntrSource::CopyEngine0 => Some(0x0010_4140),
            IntrSource::CopyEngine1 => Some(0x0010_4540),
            IntrSource::CopyEngine2 => Some(0x0010_4940),
            IntrSource::Pmu => Some(0x0010_A008),
            IntrSource::Sec => Some(0x0084_0008),
            IntrSource::Gsp => Some(0x0011_0008),
        }
    }

    /// Per-engine interrupt-enable register. Same offset table as
    /// `engine_status_offset` but with a +4 displacement, matching
    /// every NV register pair convention (status + 0, enable + 4).
    pub const fn engine_enable_offset(self) -> Option<u64> {
        match self.engine_status_offset() {
            Some(off) => Some(off + 4),
            None => None,
        }
    }
}

// ── IH cookie decode walker ──────────────────────────────────────
//
// Cite `nvkm/subdev/mc/base.c` + `nv04_mc_intr_pending` +
// `gk104_mc_intrs[]` for the walking shape: read PMC_INTR_0,
// produce one cookie per asserted bit, route to per-engine
// `engine_status_offset()` for the sub-tree decode.

/// One decoded interrupt cookie — the IH walker produces a vector
/// of these per PMC_INTR_0 sample.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IntrCookie {
    /// Which top-level source asserted.
    pub source: IntrSource,
    /// The raw PMC_INTR_0 bit that fired.
    pub intr0_bit: u32,
    /// Per-engine sub-tree status value (read from the
    /// `engine_status_offset` register). 0 = none observed; the
    /// walker stores the live value so the per-engine bottom-half
    /// can inspect it without re-reading.
    pub engine_status: u32,
}

impl IntrCookie {
    /// Construct a cookie for a single source.
    pub const fn new(source: IntrSource, engine_status: u32) -> Self {
        Self {
            source,
            intr0_bit: source.intr0_bit(),
            engine_status,
        }
    }
}

/// Walk a synthetic `PMC_INTR_0` + per-engine status table. Produces
/// one cookie per asserted source bit, in declaration order. The
/// caller supplies the per-engine status pre-read (so the walker is
/// hermetic / live-MMIO-free for tests). Mirrors `nvkm_mc_intr`'s
/// bit-walk; the `intr_pending` reader populates `intr->stat[]` for
/// us in real silicon.
pub fn walk_intr0(
    pmc_intr_0: u32,
    engine_status: impl Fn(IntrSource) -> u32,
) -> alloc::vec::Vec<IntrCookie> {
    let mut out = alloc::vec::Vec::new();
    for s in IntrSource::all().iter().copied() {
        if pmc_intr_0 & s.intr0_bit() != 0 {
            out.push(IntrCookie::new(s, engine_status(s)));
        }
    }
    out
}

/// Top-level intr-walker, live MMIO variant. Reads PMC_INTR_0 then
/// each per-engine status register, packs them into cookies.
///
/// # Safety
/// `bar0` is the kernel-mapped BAR0 view of the card. Caller has
/// exclusive access (typically an IRQ top-half).
pub unsafe fn read_live_intr0(
    bar0: &narf_driver_runtime::MmioRegion,
) -> alloc::vec::Vec<IntrCookie> {
    // SAFETY: caller's responsibility.
    let top = unsafe { bar0.read32(PMC_INTR_0) };
    walk_intr0(top, |src| {
        match src.engine_status_offset() {
            // SAFETY: per this fn's `# Safety`, `bar0` is the kernel-mapped
            // BAR0 view with caller-exclusive access. `off` is the per-engine
            // status register offset returned by `engine_status_offset()` for
            // `src`, a fixed valid 32-bit register within BAR0.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            Some(off) => unsafe { bar0.read32(off) },
            None => 0,
        }
    })
}

/// Read the raw `PMC_INTR_0` status word. Non-allocating single MMIO
/// read, for the hard-IRQ top half (`irq::IrqState::handle_top_half`),
/// which cannot allocate — cf. [`read_live_intr0`], which allocates
/// a cookie vector and is reserved for the bottom half.
///
/// # Safety
/// `bar0` is the kernel-mapped BAR0 view of the card. Caller has
/// exclusive access (typically an IRQ top-half).
pub unsafe fn read_intr0_status(bar0: &narf_driver_runtime::MmioRegion) -> u32 {
    // SAFETY: caller's responsibility.
    unsafe { bar0.read32(PMC_INTR_0) }
}

/// Mask a single interrupt source at the top level. Cite
/// `nv04_mc_intr_unarm`'s write to `0x000140` (= PMC_INTR_EN_0).
///
/// # Safety
/// `bar0` is the kernel-mapped BAR0 view; caller has exclusive
/// access to the intr-enable register.
pub unsafe fn mask_intr_source(bar0: &narf_driver_runtime::MmioRegion, source: IntrSource) {
    // SAFETY: caller's responsibility.
    unsafe {
        let cur = bar0.read32(PMC_INTR_EN_0);
        bar0.write32(PMC_INTR_EN_0, cur & !source.intr0_bit());
    }
}

/// Unmask a single interrupt source.
///
/// # Safety
/// Same.
pub unsafe fn unmask_intr_source(bar0: &narf_driver_runtime::MmioRegion, source: IntrSource) {
    // SAFETY: caller's responsibility.
    unsafe {
        let cur = bar0.read32(PMC_INTR_EN_0);
        bar0.write32(PMC_INTR_EN_0, cur | source.intr0_bit());
    }
}

// ── PMC_ENABLE writer (G3) ───────────────────────────────────────
//
// The bring-up sequence, grounded on upstream Nouveau (see the
// module header): there is NO per-engine enable order. The MC
// subdev's `.init` hook writes all-ones to `PMC_ENABLE` in one
// shot — `nv50_mc_init` on discrete Pascal (`gp100_mc`), and
// the same write in `nv04_mc_init` and `ga100_mc_init` — and
// individual engines are only ever toggled afterwards, around
// their own init/fini (`nvkm_mc_enable/disable`, via the
// `nv04_mc_device` ops: mask-set + posting read / mask-clear).
// Nouveau performs no delay and no poll after the all-ones
// write; the posting read below is our own addition (same shape
// as `nv04_mc_device_enable`'s), so probe can verify the write
// landed instead of assuming it.

/// Take every engine out of reset in one write, then read
/// `PMC_ENABLE` back. Returns the readback value; the caller
/// checks it with [`engines_enabled`].
///
/// This is `nv50_mc_init` (`nvkm_wr32(device, 0x000200,
/// 0xffffffff) /* everything on */`) plus a readback. It
/// enables engines whose bring-up does not exist yet (GR, CE,
/// NVDEC/NVENC, …) as well as the ones probe needs — that is
/// what Nouveau does at MC init, and an engine in reset cannot
/// be programmed by its later bring-up lane. The write does not
/// start any engine's firmware; it only releases reset.
///
/// # Safety
/// `bar0` is the kernel-mapped BAR0 view; caller has exclusive
/// access to `PMC_ENABLE` for the duration of the call.
pub unsafe fn enable_all_engines(bar0: &narf_driver_runtime::MmioRegion) -> u32 {
    // SAFETY: caller's responsibility.
    unsafe {
        bar0.write32(PMC_ENABLE, PMC_ENABLE_ALL);
        // Posting read: flushes the write and gives the caller a
        // value to verify (cf. `nv04_mc_device_enable`).
        bar0.read32(PMC_ENABLE)
    }
}

/// Enable one engine (or engine set) by mask: set exactly the
/// masked bits in `PMC_ENABLE`, then a posting read. Mirrors
/// `nvkm_mc_enable` / `nv04_mc_device_enable` (`nvkm_mask(dev,
/// 0x200, mask, mask); nvkm_rd32(dev, 0x200)`). The mask must
/// come from the `PMC_ENABLE_*` constants above; per-engine
/// masks Nouveau derives from runtime-parsed PTOP data are not
/// re-derived here.
///
/// # Safety
/// Same as [`enable_all_engines`].
pub unsafe fn enable_engine(bar0: &narf_driver_runtime::MmioRegion, mask: u32) {
    // SAFETY: caller's responsibility.
    unsafe {
        let cur = bar0.read32(PMC_ENABLE);
        bar0.write32(PMC_ENABLE, cur | mask);
        let _ = bar0.read32(PMC_ENABLE);
    }
}

/// Disable one engine (or engine set) by mask: clear exactly the
/// masked bits in `PMC_ENABLE`. Mirrors `nvkm_mc_disable` /
/// `nv04_mc_device_disable` (`nvkm_mask(dev, 0x200, mask, 0)`);
/// Nouveau performs no posting read on the disable path.
///
/// # Safety
/// Same as [`enable_all_engines`].
pub unsafe fn disable_engine(bar0: &narf_driver_runtime::MmioRegion, mask: u32) {
    // SAFETY: caller's responsibility.
    unsafe {
        let cur = bar0.read32(PMC_ENABLE);
        bar0.write32(PMC_ENABLE, cur & !mask);
    }
}

/// Pure readback check: true iff every bit in `mask` is set in
/// the `PMC_ENABLE` sample. Mirrors `nvkm_mc_enabled` /
/// `nv04_mc_device_enabled` (`(rd32(0x200) & mask) == mask`).
pub fn engines_enabled(readback: u32, mask: u32) -> bool {
    mask != 0 && (readback & mask) == mask
}
