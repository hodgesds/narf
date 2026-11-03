//! Display-14 data stolen memory (DSM): discovery, reserved-range
//! exclusion, a read-only exclusivity proof against the page allocator,
//! and bounded first-fit placement of display-owned ranges (the FBC
//! compressed framebuffer).
//!
//! Pinned source: Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad.
//!
//! - `xe/xe_ttm_stolen_mgr.c::detect_bar2_integrated` (graphics >= 12.70,
//!   Meteor/Arrow Lake): GGC (0x108040) must report GGMS = 3 (8 MiB GTT);
//!   DSM begins 8 MiB above GSMBASE (`io_base` = BAR2 + 8 MiB); GMS 0..4
//!   gives 32 MiB units, 0xF0..0xFE 4 MiB units; the WOPCM at the top is
//!   carved off by `STOLEN_RESERVED` (0x1082C0) bits 9:7
//!   (`get_wopcm_size`); and when the BIOS applied Wa_14019821291
//!   (`MEDIA_VERSION_RANGE(1300, 2000)`, MTL media 13.00), everything from
//!   the media GT's `GSCPSMI_BASE` (0x880C + GSI offset 0x380000, low six
//!   bits masked) up is carved off too. `xe_stolen_insert_node_in_range`
//!   never places below 4 KiB.
//! - `arch/x86/kernel/early-quirks.c::gen11_stolen_base` and
//!   `include/drm/intel/i915_drm.h`: the DSM physical base is PCI config
//!   `INTEL_GEN11_BSM_DW0/1` (0xC0/0xC4), DW0 masked to 1 MiB.
//! - `xe/regs/xe_gtt_defs.h`: a GGTT PTE maps DSM when `XE_GGTT_PTE_DM`
//!   (bit 1) is set; its address field (bits 51:12) is then an offset from
//!   GSMBASE.
//! - `i915/display/intel_fbc.c::intel_fbc_cfb_base_max`: the CFB must lie
//!   below 2^28.
//!
//! What this driver adds, and why. The boot GOP framebuffer lives in DSM
//! behind the BAR2 aperture, and its CPU writers (boot console, panic
//! sinks in `graphics/` and `fb/`) are not proven retired. Every route by
//! which a CPU reaches DSM through the aperture is a present DM PTE inside
//! the CPU-mappable GGTT range `[0, BAR2 length)`, so every DSM page such a
//! PTE maps is excluded (this driver never writes a DM PTE). And before a
//! range is handed out, every one of its physical pages is checked against
//! `narf_memory::frame::is_system_ram`: the buddy allocator is seeded only
//! from Usable boot RAM (plus hotplug), so a page that is not system RAM
//! can never be owned by the page allocator. No memory/ change is needed.

use alloc::vec::Vec;

/// `GGC` (xe_regs.h).
pub const GGC: u64 = 0x108040;
/// `GGMS_MASK`, bits 7:6; must equal the mask (8 MiB GTT).
pub const GGMS_MASK: u32 = 0x3 << 6;
/// `GMS_MASK`, bits 15:8.
pub const GMS_SHIFT: u32 = 8;
/// `STOLEN_RESERVED` low dword (64-bit register read as 2x32).
pub const STOLEN_RESERVED: u64 = 0x1082C0;
/// `WOPCM_SIZE_MASK`, bits 9:7.
pub const WOPCM_SIZE_SHIFT: u32 = 7;
/// `MEDIA_GT_GSI_OFFSET`.
pub const MEDIA_GT_GSI_OFFSET: u64 = 0x380000;
/// `GSCPSMI_BASE` as the media GT addresses it (0x880C + GSI offset).
pub const MEDIA_GSCPSMI_BASE: u64 = MEDIA_GT_GSI_OFFSET + 0x880C;
/// DSMBASE = GSMBASE + 8 MiB.
pub const DSM_GSM_OFFSET: u64 = 8 << 20;
/// `INTEL_GEN11_BSM_DW0` / `DW1` (PCI config).
pub const PCI_BSM_DW0: u16 = 0xC0;
pub const PCI_BSM_DW1: u16 = 0xC4;
/// `INTEL_BSM_MASK` for DW0.
pub const BSM_MASK: u32 = !((1 << 20) - 1);
/// `XE_GGTT_PTE_DM`.
pub const GGTT_PTE_DM: u64 = 1 << 1;
/// `XE_PAGE_PRESENT`.
pub const GGTT_PTE_PRESENT: u64 = 1 << 0;
/// `XE_PTE_ADDR_MASK`, bits 51:12.
pub const GGTT_PTE_ADDR_MASK: u64 = ((1 << 52) - 1) & !0xFFF;
/// `intel_fbc_cfb_base_max` for display >= 5.
pub const CFB_BASE_MAX: u64 = 1 << 28;
/// Lowest placeable DSM offset (`xe_stolen_insert_node_in_range`).
pub const MIN_OFFSET: u64 = 4096;
/// Page size.
pub const PAGE: u64 = 4096;
/// Bounded placements per function (the FBC CFB needs one).
pub const MAX_PLACEMENTS: usize = 2;

/// Why DSM cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StolenError {
    /// A discovery register read all-ones.
    Unavailable,
    /// GGC's GGMS is not the 8 MiB encoding.
    BadGgms(u32),
    /// GGC's GMS encoding is reserved.
    BadGms(u32),
    /// `STOLEN_RESERVED` reports no WOPCM size this tree decodes.
    BadWopcm(u32),
    /// DSM plus the GTT does not fit the BAR2 aperture.
    ApertureTooSmall,
    /// No excluded-range-free window fits the request.
    NoSpace,
    /// A page of the candidate is known system RAM: never hand it out.
    SystemRam(u64),
    /// Placement capacity is exhausted.
    Exhausted,
}

/// GMS decode (`detect_bar2_integrated`).
pub fn gms_bytes(ggc: u32) -> Result<u64, StolenError> {
    if ggc & GGMS_MASK != GGMS_MASK {
        return Err(StolenError::BadGgms(ggc));
    }
    let gms = (ggc >> GMS_SHIFT) & 0xFF;
    match gms {
        0x00..=0x04 => Ok(u64::from(gms) * (32 << 20)),
        0xF0..=0xFE => Ok(u64::from(gms - 0xF0 + 1) * (4 << 20)),
        _ => Err(StolenError::BadGms(gms)),
    }
}

/// WOPCM decode (`get_wopcm_size`): 0..3 -> 2^v MiB, 5..6 -> 2^(v-1) MiB.
pub fn wopcm_bytes(stolen_reserved_lo: u32) -> Result<u64, StolenError> {
    let v = (stolen_reserved_lo >> WOPCM_SIZE_SHIFT) & 0x7;
    match v {
        0..=3 => Ok((1u64 << v) << 20),
        5..=6 => Ok((1u64 << (v - 1)) << 20),
        _ => Err(StolenError::BadWopcm(v)),
    }
}

/// The register facts discovery consumes (all read by the caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub ggc: u32,
    pub stolen_reserved_lo: u32,
    /// `GSCPSMI_BASE`, 64-bit, as read through the media GT window.
    pub gscpsmi_base: u64,
    /// BAR2 (GMADR) bus base and length.
    pub gmadr_base: u64,
    pub gmadr_len: u64,
    /// PCI BSM DW0/DW1.
    pub bsm_dw0: u32,
    pub bsm_dw1: u32,
}

/// Usable DSM: offsets `[0, usable)` relative to DSM base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// DSM physical base (BSM).
    pub base_phys: u64,
    /// GMS-reported DSM size.
    pub total: u64,
    /// Bytes below the WOPCM / GSC carve-outs.
    pub usable: u64,
    pub wopcm: u64,
    /// Bytes carved for Wa_14019821291, if the BIOS applied it.
    pub gsc: u64,
}

/// `detect_bar2_integrated`, as a pure decode.
pub fn layout(facts: Facts) -> Result<Layout, StolenError> {
    if facts.ggc == u32::MAX || facts.stolen_reserved_lo == u32::MAX || facts.bsm_dw0 == u32::MAX {
        return Err(StolenError::Unavailable);
    }
    let total = gms_bytes(facts.ggc)?;
    let wopcm = wopcm_bytes(facts.stolen_reserved_lo)?;
    let mut usable = total.checked_sub(wopcm).ok_or(StolenError::NoSpace)?;
    let io_base = facts.gmadr_base + DSM_GSM_OFFSET;
    let gsc_base = facts.gscpsmi_base & !0x3F;
    let mut gsc = 0;
    if gsc_base >= io_base && gsc_base < io_base + usable {
        gsc = io_base + usable - gsc_base;
        usable = gsc_base - io_base;
    }
    if usable + DSM_GSM_OFFSET > facts.gmadr_len {
        return Err(StolenError::ApertureTooSmall);
    }
    Ok(Layout {
        base_phys: u64::from(facts.bsm_dw0 & BSM_MASK) | (u64::from(facts.bsm_dw1) << 32),
        total,
        usable,
        wopcm,
        gsc,
    })
}

/// DSM pages reachable through the CPU aperture: the DSM-relative page
/// offset of every present DM PTE among `ptes` (GGTT entries
/// `[0, BAR2 length / 4 KiB)`).
pub fn aperture_dsm_pages(ptes: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut pages: Vec<u64> = ptes
        .into_iter()
        .filter(|pte| pte & (GGTT_PTE_PRESENT | GGTT_PTE_DM) == GGTT_PTE_PRESENT | GGTT_PTE_DM)
        .filter_map(|pte| (pte & GGTT_PTE_ADDR_MASK).checked_sub(DSM_GSM_OFFSET))
        .collect();
    pages.sort_unstable();
    pages.dedup();
    pages
}

/// A function's DSM: layout, excluded aperture pages and the bounded
/// list of ranges this driver placed (retained for the card lifetime).
#[derive(Clone, Debug)]
pub struct Dsm {
    layout: Layout,
    excluded_pages: Vec<u64>,
    placed: Vec<(u64, u64)>,
}

impl Dsm {
    pub fn new(layout: Layout, excluded_pages: Vec<u64>) -> Self {
        Self {
            layout,
            excluded_pages,
            placed: Vec::new(),
        }
    }
    pub fn layout(&self) -> Layout {
        self.layout
    }
    pub fn placed(&self) -> &[(u64, u64)] {
        &self.placed
    }

    fn conflict(&self, start: u64, len: u64) -> Option<u64> {
        let end = start + len;
        // Lowest blocking end at or above `start`, to skip past it.
        let page = self
            .excluded_pages
            .iter()
            .find(|&&p| p + PAGE > start && p < end)
            .map(|p| p + PAGE);
        let range = self
            .placed
            .iter()
            .find(|&&(s, l)| s < end && start < s + l)
            .map(|&(s, l)| s + l);
        match (page, range) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }

    /// First-fit a `len`-byte, `align`-aligned range in
    /// `[MIN_OFFSET, min(usable, limit))` that avoids every excluded
    /// aperture page and earlier placement, then prove every physical
    /// page of it is not system RAM before recording it. Returns the
    /// DSM-relative offset.
    pub fn place(
        &mut self,
        len: u64,
        align: u64,
        limit: u64,
        is_system_ram: impl Fn(u64) -> bool,
    ) -> Result<u64, StolenError> {
        if self.placed.len() >= MAX_PLACEMENTS {
            return Err(StolenError::Exhausted);
        }
        let align = align.max(PAGE);
        let len = len.div_ceil(PAGE) * PAGE;
        let end_limit = self.layout.usable.min(limit);
        if len == 0 {
            return Err(StolenError::NoSpace);
        }
        let mut start = MIN_OFFSET.div_ceil(align) * align;
        loop {
            if start.checked_add(len).is_none_or(|end| end > end_limit) {
                return Err(StolenError::NoSpace);
            }
            match self.conflict(start, len) {
                Some(past) => start = past.div_ceil(align) * align,
                None => break,
            }
        }
        for page in (start..start + len).step_by(PAGE as usize) {
            let phys = self.layout.base_phys + page;
            if is_system_ram(phys) {
                return Err(StolenError::SystemRam(phys));
            }
        }
        self.placed.push((start, len));
        Ok(start)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_stolen_tests.rs"]
mod tests;
