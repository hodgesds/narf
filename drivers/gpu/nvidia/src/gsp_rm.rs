//! GSP boot step 3 — GSP-RM VRAM layout: WPR2 framebuffer map, the
//! `GspFwWprMeta` descriptor, and the RADIX3 page table (Turing).
//!
//! ## Where this sits
//!
//! [`crate::gsp_boot`] (GSP-2) stages the booter; the booter reads the
//! [`WprMeta`] this module builds (its physical address goes in SEC2
//! MAILBOX0/1) to find the GSP-RM ELF image — mapped by a RADIX3 page
//! table — and copy it into the WPR2 framebuffer window it carves.
//! [`crate::gsp`] (GSP-4) then speaks RPCs to the running firmware.
//!
//! ## Scope — what GSP-3 lands
//!
//! The pure, unit-testable layout logic, grounded against
//! `/usr/src/linux`:
//!
//! - [`fb_layout`] — the WPR2 region map (`nvkm/subdev/gsp/tu102.c::
//!   tu102_gsp_oneinit`).
//! - [`WprMeta`] + [`WprMeta::to_bytes`] — the exact 256-byte
//!   `GspFwWprMeta` wire struct (`rm/r535/nvrm/gsp.h:418`,
//!   filled per `tu102_gsp_wpr_meta_init`).
//! - RADIX3 sizing ([`radix3_lvl2_entries`] / [`radix3_lvl2_bytes`] /
//!   [`radix3_max_image_size`]) — the 3-level table from
//!   `rm/r535/gsp.c::nvkm_gsp_radix3_sg`.
//!
//! Allocating the VRAM/sysmem pages, writing the tables, and DMA-
//! syncing the descriptor need a VRAM allocator and real silicon
//! (QEMU has no NVIDIA GPU); those are a later lane.

#![allow(dead_code)]

/// GSP page size (the RADIX3 / WPR granularity). Cite `GSP_PAGE_SIZE`.
pub const GSP_PAGE_SIZE: u64 = 4096;

/// `sizeof(GspFwWprMeta)` — the struct is padded to exactly 256 bytes.
pub const WPR_META_SIZE: usize = 256;

/// `GSP_FW_WPR_META_MAGIC` — the booter verifies this. Cite
/// `rm/r535/nvrm/gsp.h`.
pub const GSP_FW_WPR_META_MAGIC: u64 = 0xdc3a_ae21_371a_60b3;
/// `GSP_FW_WPR_META_REVISION` — Booter/BL/Sequencer handoff revision.
pub const GSP_FW_WPR_META_REVISION: u64 = 1;
/// `verified` sentinel the booter writes back on success (the host
/// initialises the field to 0).
pub const GSP_FW_WPR_META_VERIFIED: u64 = 0xa0a0_a0a0_a0a0_a0a0;

/// `x` rounded down to a multiple of power-of-two `align`.
pub const fn align_down(x: u64, align: u64) -> u64 {
    x & !(align - 1)
}

/// `x` rounded up to a multiple of power-of-two `align`.
pub const fn align_up(x: u64, align: u64) -> u64 {
    (x + align - 1) & !(align - 1)
}

// ── FB / WPR2 layout ─────────────────────────────────────────────

/// A `{addr, size}` framebuffer region.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FbRegion {
    pub addr: u64,
    pub size: u64,
}

impl FbRegion {
    pub const fn new(addr: u64, size: u64) -> Self {
        Self { addr, size }
    }

    /// Exclusive end address.
    pub const fn end(&self) -> u64 {
        self.addr + self.size
    }
}

/// The computed framebuffer layout for GSP boot. All regions are
/// carved from the top of VRAM downward. Cite
/// `nvkm/subdev/gsp/tu102.c::tu102_gsp_oneinit`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FbLayout {
    pub fb_size: u64,
    /// VBIOS VGA workspace at the very top of VRAM.
    pub vga_workspace: FbRegion,
    /// FWSEC-FRTS region (fixed 1 MiB).
    pub frts: FbRegion,
    /// GSP-RM RISC-V bootloader image.
    pub boot: FbRegion,
    /// GSP-RM ELF image (RADIX3-mapped).
    pub elf: FbRegion,
    /// WPR2 heap.
    pub wpr2_heap: FbRegion,
    /// The WPR2 window itself (meta + heap … frts).
    pub wpr2: FbRegion,
    /// Non-WPR heap below WPR2.
    pub heap: FbRegion,
}

/// Compute the WPR2 framebuffer layout. Mirrors `tu102_gsp_oneinit`'s
/// top-down carve exactly:
///
/// - `frts`  : 1 MiB, just below the (0x20000-aligned) VBIOS area.
/// - `boot`  : `boot_size`, 0x1000-aligned below `frts`.
/// - `elf`   : `elf_size`, 0x10000-aligned below `boot`.
/// - `heap`  : `wpr_heap_size` (then grown to fill up to `elf`),
///   0x100000-aligned below `elf`.
/// - `wpr2`  : starts 0x100000-aligned below `heap - sizeof(meta)`;
///   spans up to `frts.end()`.
/// - non-WPR `heap`: 1 MiB below `wpr2`.
///
/// `bios_addr` is the VBIOS/VGA-workspace base (`fb_size - 0x100000`
/// absent a display override); `wpr_heap_size` comes from
/// `tu102_gsp_wpr_heap_size` (a later lane) and is taken as input to
/// keep this pure.
pub fn fb_layout(
    fb_size: u64,
    bios_addr: u64,
    boot_size: u64,
    elf_size: u64,
    wpr_heap_size: u64,
) -> FbLayout {
    let vga_workspace = FbRegion::new(bios_addr, fb_size - bios_addr);

    let frts_size = 0x10_0000;
    let frts_addr = align_down(bios_addr, 0x2_0000) - frts_size;

    let boot_addr = align_down(frts_addr - boot_size, 0x1000);
    let elf_addr = align_down(boot_addr - elf_size, 0x1_0000);

    let heap_addr = align_down(elf_addr - wpr_heap_size, 0x10_0000);
    // Grow the heap to fill the gap up to the ELF exactly.
    let heap_size = align_down(elf_addr - heap_addr, 0x10_0000);

    let wpr2_addr = align_down(heap_addr - WPR_META_SIZE as u64, 0x10_0000);
    let wpr2_size = (frts_addr + frts_size) - wpr2_addr;

    let nonwpr_heap_size = 0x10_0000;
    let nonwpr_heap_addr = wpr2_addr - nonwpr_heap_size;

    FbLayout {
        fb_size,
        vga_workspace,
        frts: FbRegion::new(frts_addr, frts_size),
        boot: FbRegion::new(boot_addr, boot_size),
        elf: FbRegion::new(elf_addr, elf_size),
        wpr2_heap: FbRegion::new(heap_addr, heap_size),
        wpr2: FbRegion::new(wpr2_addr, wpr2_size),
        heap: FbRegion::new(nonwpr_heap_addr, nonwpr_heap_size),
    }
}

// ── RADIX3 page table sizing ─────────────────────────────────────
//
// The GSP maps its firmware ELF through a 3-level page table
// ("radix3"): lvl0 = one page with a single u64 pointing at lvl1;
// lvl1 = one page of up to 512 u64 pointers to lvl2 pages; lvl2 = up
// to 512 pages of u64 pointers to the image's own pages. Each entry
// is a 64-bit bus address. Cite `rm/r535/gsp.c::nvkm_gsp_radix3_sg`.

/// u64 entries per page.
pub const RADIX3_PTES_PER_PAGE: u64 = GSP_PAGE_SIZE / 8;

/// Largest firmware image radix3 can map: `512 * 512 * GSP_PAGE_SIZE`
/// (= 1 GiB).
pub const fn radix3_max_image_size() -> u64 {
    RADIX3_PTES_PER_PAGE * RADIX3_PTES_PER_PAGE * GSP_PAGE_SIZE
}

/// Number of level-2 entries = number of pages in the image.
pub const fn radix3_lvl2_entries(image_size: u64) -> u64 {
    image_size.div_ceil(GSP_PAGE_SIZE)
}

/// Byte size of the level-2 table, page-aligned. Cite
/// `ALIGN((size / GSP_PAGE_SIZE) * sizeof(u64), GSP_PAGE_SIZE)`.
pub const fn radix3_lvl2_bytes(image_size: u64) -> u64 {
    align_up(radix3_lvl2_entries(image_size) * 8, GSP_PAGE_SIZE)
}

/// True if `image_size` is within radix3's addressing reach.
pub const fn radix3_fits(image_size: u64) -> bool {
    image_size <= radix3_max_image_size()
}

/// Fill the three radix3 levels in place, given the DMA page addresses.
/// Each level is the `u64` view of its DMA-coherent page(s):
///
/// - `lvl0[0] = lvl1_pa` (single pointer to level 1),
/// - `lvl1[i] = lvl2_page_pas[i]` (one pointer per level-2 page),
/// - `lvl2[i] = image_page_pas[i]` (one pointer per firmware page).
///
/// Cite `rm/r535/gsp.c::nvkm_gsp_radix3_sg`. Returns `false` if the
/// provided tables are too small for the page lists.
pub fn build_radix3(
    lvl0: &mut [u64],
    lvl1: &mut [u64],
    lvl2: &mut [u64],
    lvl1_pa: u64,
    lvl2_page_pas: &[u64],
    image_page_pas: &[u64],
) -> bool {
    if lvl0.is_empty() || lvl1.len() < lvl2_page_pas.len() || lvl2.len() < image_page_pas.len() {
        return false;
    }
    lvl0[0] = lvl1_pa;
    for (dst, &pa) in lvl1.iter_mut().zip(lvl2_page_pas) {
        *dst = pa;
    }
    for (dst, &pa) in lvl2.iter_mut().zip(image_page_pas) {
        *dst = pa;
    }
    true
}

// ── GspFwWprMeta (256-byte wire struct) ──────────────────────────

/// The fields of `GspFwWprMeta` the host fills for a fresh Turing
/// boot (`tu102_gsp_wpr_meta_init`). Suspend/resume, partition-RPC,
/// and crash-report fields are left zero. [`Self::to_bytes`] packs
/// this into the exact 256-byte layout the booter reads.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WprMeta {
    /// `sysmemAddrOfRadix3Elf` = radix3 level-0 page bus address.
    pub sysmem_radix3_elf: u64,
    /// `sizeOfRadix3Elf` = ELF image size.
    pub size_radix3_elf: u64,
    pub sysmem_bootloader: u64,
    pub size_bootloader: u64,
    pub bootloader_code_offset: u64,
    pub bootloader_data_offset: u64,
    pub bootloader_manifest_offset: u64,
    pub sysmem_signature: u64,
    pub size_signature: u64,
    pub gsp_fw_rsvd_start: u64,
    pub non_wpr_heap_offset: u64,
    pub non_wpr_heap_size: u64,
    pub gsp_fw_wpr_start: u64,
    pub gsp_fw_heap_offset: u64,
    pub gsp_fw_heap_size: u64,
    pub gsp_fw_offset: u64,
    pub boot_bin_offset: u64,
    pub frts_offset: u64,
    pub frts_size: u64,
    pub gsp_fw_wpr_end: u64,
    pub fb_size: u64,
    pub vga_workspace_offset: u64,
    pub vga_workspace_size: u64,
}

impl WprMeta {
    /// Build the metadata from the computed [`FbLayout`] plus the
    /// bootloader / signature / radix3 placements. Mirrors
    /// `tu102_gsp_wpr_meta_init` field-for-field.
    #[allow(clippy::too_many_arguments)]
    pub fn from_layout(
        fb: &FbLayout,
        radix3_lvl0_addr: u64,
        bootloader_sysmem_addr: u64,
        bootloader_size: u64,
        bootloader_code_offset: u64,
        bootloader_data_offset: u64,
        bootloader_manifest_offset: u64,
        signature_addr: u64,
        signature_size: u64,
    ) -> Self {
        Self {
            sysmem_radix3_elf: radix3_lvl0_addr,
            size_radix3_elf: fb.elf.size,
            sysmem_bootloader: bootloader_sysmem_addr,
            size_bootloader: bootloader_size,
            bootloader_code_offset,
            bootloader_data_offset,
            bootloader_manifest_offset,
            sysmem_signature: signature_addr,
            size_signature: signature_size,
            gsp_fw_rsvd_start: fb.heap.addr,
            non_wpr_heap_offset: fb.heap.addr,
            non_wpr_heap_size: fb.heap.size,
            gsp_fw_wpr_start: fb.wpr2.addr,
            gsp_fw_heap_offset: fb.wpr2_heap.addr,
            gsp_fw_heap_size: fb.wpr2_heap.size,
            gsp_fw_offset: fb.elf.addr,
            boot_bin_offset: fb.boot.addr,
            frts_offset: fb.frts.addr,
            frts_size: fb.frts.size,
            gsp_fw_wpr_end: align_down(fb.vga_workspace.addr, 0x2_0000),
            fb_size: fb.fb_size,
            vga_workspace_offset: fb.vga_workspace.addr,
            vga_workspace_size: fb.vga_workspace.size,
        }
    }

    /// Pack into the exact 256-byte `GspFwWprMeta` layout (little-
    /// endian). Field offsets follow the struct in
    /// `rm/r535/nvrm/gsp.h`; unset regions (suspend/resume,
    /// partition-RPC, crash-report) stay zero and `verified` is 0.
    pub fn to_bytes(&self) -> [u8; WPR_META_SIZE] {
        let mut b = [0u8; WPR_META_SIZE];
        let mut put = |off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put(0x00, GSP_FW_WPR_META_MAGIC);
        put(0x08, GSP_FW_WPR_META_REVISION);
        put(0x10, self.sysmem_radix3_elf);
        put(0x18, self.size_radix3_elf);
        put(0x20, self.sysmem_bootloader);
        put(0x28, self.size_bootloader);
        put(0x30, self.bootloader_code_offset);
        put(0x38, self.bootloader_data_offset);
        put(0x40, self.bootloader_manifest_offset);
        put(0x48, self.sysmem_signature);
        put(0x50, self.size_signature);
        put(0x58, self.gsp_fw_rsvd_start);
        put(0x60, self.non_wpr_heap_offset);
        put(0x68, self.non_wpr_heap_size);
        put(0x70, self.gsp_fw_wpr_start);
        put(0x78, self.gsp_fw_heap_offset);
        put(0x80, self.gsp_fw_heap_size);
        put(0x88, self.gsp_fw_offset);
        put(0x90, self.boot_bin_offset);
        put(0x98, self.frts_offset);
        put(0xA0, self.frts_size);
        put(0xA8, self.gsp_fw_wpr_end);
        put(0xB0, self.fb_size);
        put(0xB8, self.vga_workspace_offset);
        put(0xC0, self.vga_workspace_size);
        // 0xC8 bootCount, 0xD0..0xF0 partition/crash union, 0xF0
        // vfPartitionCount + padding — all zero. 0xF8 verified = 0.
        b
    }
}
