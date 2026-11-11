//! BAR1 / BAR3 windowing into VRAM.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/bar/base.c`**
//!   — generic BAR-window entry points (`nvkm_bar_bar1_*`,
//!   `nvkm_bar_bar2_*`).
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/bar/gf100.c`** /
//!   **`gm107.c`** / **`gp100.c`** / **`tu102.c`** — per-ASIC
//!   BAR1/BAR2 vmm setup; each maps a `nvkm_vmm` ("BAR1 vmm") that
//!   the host CPU writes via the BAR aperture and the GPU reads
//!   back through its own MMU.
//!
//! ## What a BAR window does
//!
//! BAR1 is a PCI BAR (i.e. CPU-visible) but pointed at GPU VRAM
//! via the GPU's MMU. The host driver allocates an "instance" in
//! VRAM, maps it into the BAR1 vmm, and writes to it from the CPU
//! at `bar1_base + bar1_offset`. The GPU sees the same memory at
//! whatever GPU VA the BAR1 vmm assigned it.
//!
//! BAR3 (sometimes BAR2 on older parts) carries a smaller window
//! used for instance-memory PRAMIN access — the host CPU reads
//! USERD / dispclass / channel-state out of VRAM through it.

#![allow(dead_code)]

use narf_driver_runtime::MmioRegion;

/// A windowed view over GPU VRAM exposed via a PCI BAR.
///
/// `region` is the kernel-mapped MMIO view of the BAR; reads /
/// writes hit GPU memory via the GPU's MMU. The driver caches the
/// reported physical size so range checks don't trust caller-
/// supplied offsets.
#[derive(Debug)]
pub struct BarWindow {
    pub region: MmioRegion,
    pub size_bytes: u64,
}

impl BarWindow {
    pub const fn new(region: MmioRegion, size_bytes: u64) -> Self {
        Self { region, size_bytes }
    }

    /// 32-bit window read at `offset` (in bytes from window base).
    /// # Safety
    /// `offset + 4 <= size_bytes`, naturally aligned.
    pub unsafe fn read32(&self, offset: u64) -> u32 {
        debug_assert!(offset + 4 <= self.size_bytes);
        // SAFETY: caller's responsibility.
        unsafe { self.region.read32(offset) }
    }

    /// 32-bit window write at `offset`.
    /// # Safety
    /// Same.
    pub unsafe fn write32(&self, offset: u64, value: u32) {
        debug_assert!(offset + 4 <= self.size_bytes);
        // SAFETY: caller's responsibility.
        unsafe { self.region.write32(offset, value) }
    }
}

// ── PRAMIN window indirection (BAR3 / older parts) ───────────────
//
// Pre-Volta parts expose instance memory through a 1 MiB "PRAMIN"
// window at BAR0 0x700000 that the driver retargets by writing
// `BUS_BAR0_WINDOW` (BAR0 0x001700) — the high 16 bits of the
// physical instance-memory address. Read/write within the window
// then hits the targeted page.
//
// Cite `nvkm/subdev/bar/gf100.c::gf100_bar_init` for the equivalent
// programming sequence.

/// `NV_PBUS_BAR0_WINDOW` — selects the page that the PRAMIN
/// window at BAR0 0x700000 points at. Lower 12 bits are zero
/// (4 KiB granularity). Cited
/// `nvkm/subdev/bar/gf100.c::gf100_bar_pramin_init`.
pub const PBUS_BAR0_WINDOW: u64 = 0x0000_1700;
/// Base of the 1 MiB PRAMIN window inside BAR0.
pub const PRAMIN_WINDOW_BASE: u64 = 0x0070_0000;
/// Size of the PRAMIN window (1 MiB).
pub const PRAMIN_WINDOW_SIZE: u64 = 0x0010_0000;

/// Helpers for the `BAR0_WINDOW` indirection. The driver targets
/// the window at a 4 KiB-aligned VRAM page, then accesses up to
/// 1 MiB through the BAR0 PRAMIN window.
pub fn bar0_window_target(vram_page_phys: u64) -> u32 {
    // Hardware stores the upper 20 bits of the VRAM page, shifted
    // right by 16 (4 KiB granularity). Cite gf100_bar_pramin_init.
    debug_assert_eq!(vram_page_phys & 0xFFF, 0, "must be 4 KiB-aligned");
    ((vram_page_phys >> 16) & 0xFFFF_FFFF) as u32
}
