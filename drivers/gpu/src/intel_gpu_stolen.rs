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
//!   (`get_wopcm_size`); and when the BIOS applied Wa_14019821291,
//!   everything from the media GT's `GSCPSMI_BASE` (0x880C + GSI offset
//!   0x380000, low six bits masked) up is carved off too. Linux checks the
//!   workaround as `media_gt && XE_GT_WA(media_gt, 14019821291)`
//!   (`xe_wa_oob.rules`: `MEDIA_VERSION_RANGE(1300, 2000)`, inclusive per
//!   `xe_rtp.h`): `xe_pci.c::handle_gmdid` / `alloc_media_gt` create a
//!   media GT only for a non-zero media `GMD_ID` (read at 0xD8C + GSI
//!   offset) whose version is a known `media_ips` entry, so the carve
//!   applies exactly for media 13.00, 13.01 and 20.00 ([`wa_14019821291`]);
//!   otherwise `GSCPSMI_BASE` is never read or used.
//!   `xe_stolen_insert_node_in_range` never places below 4 KiB.
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
//!
//! The aperture survey reads one GGTT PTE per CPU-mappable 4 KiB page (64Ki
//! entries for a 256 MiB BAR2). It never runs on the present path: a
//! [`Carve`] reads at most [`CARVE_CHUNK_PTES`] entries per step and its
//! driver yields between steps; the present path only polls a
//! [`CarveSlot`], and FBC stays off until the carve has finished. A
//! finished survey stays valid: the only DM PTEs this driver writes map the
//! GSC private object at [`GSC_GGTT`], above every CPU-mappable GGTT entry,
//! so the set of aperture-reachable DSM pages can only shrink, and a stale
//! survey only over-excludes.
//!
//! Two owners place DSM ranges for one function: display FBC (the CFB) and
//! the media GT's GSC (the 4 MiB private object of
//! `xe/xe_gsc.c::xe_gsc_init_post_hwconfig`, `XE_BO_FLAG_STOLEN |
//! XE_BO_FLAG_GGTT`). A device-lifetime claim registry keyed by the DSM base
//! keeps them apart: every CFB placement avoids the GSC claim, and the GSC
//! placement avoids every recent CFB claim. The GSC claim is made once and
//! never released or moved: the GSC may keep using that memory until an FLR
//! (Linux sets `xe->needs_flr_on_fini`), and NARF performs none, so every
//! later GT0 incarnation and resume gets the same range back.

use alloc::vec::Vec;
use core::task::Poll;

use narf_lib::sync::IrqSafeSpinLock;

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
/// The media GT's `GMD_ID` (0xD8C + GSI offset, `read_gmdid`).
pub const MEDIA_GMD_ID: u64 = MEDIA_GT_GSI_OFFSET + 0xD8C;
/// `xe_pci.c::media_ips` versions (verx100).
const MEDIA_IPS: [u16; 7] = [1300, 1301, 2000, 3000, 3002, 3500, 3503];
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
/// `xe_gsc_init_post_hwconfig`'s SZ_4M GSC private object.
pub const GSC_BYTES: u64 = 4 << 20;
/// The GGTT window of the GSC private object's DM PTEs: directly above the
/// GT arena (`GGTT_ARENA_BASE` + 32 MiB), owned by the function's GGTT
/// ledger for its lifetime and never handed to any arena.
pub const GSC_GGTT: u64 = 288 << 20;
/// Recent CFB claims the GSC placement avoids (FBC uses its newest carve;
/// an earlier one may still be scanned until FBC re-activates).
pub const MAX_CFB_CLAIMS: usize = 4;

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

/// `media_gt && XE_GT_WA(media_gt, 14019821291)` from the media
/// `GMD_ID`: a media GT exists for a non-zero, known media IP version
/// (`handle_gmdid`, `alloc_media_gt`), and the workaround matches media
/// 13.00..=20.00. An all-ones read is `Unavailable`.
pub fn wa_14019821291(media_gmd_id: u32) -> Result<bool, StolenError> {
    if media_gmd_id == u32::MAX {
        return Err(StolenError::Unavailable);
    }
    let version = crate::intel_gpu_gt::media::MediaIp::decode(media_gmd_id).version;
    Ok(MEDIA_IPS.contains(&version) && (1300..=2000).contains(&version))
}

/// The register facts discovery consumes (all read by the caller).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub ggc: u32,
    pub stolen_reserved_lo: u32,
    /// The media GT's `GMD_ID` ([`MEDIA_GMD_ID`]); 0 when media is fused
    /// off.
    pub media_gmd_id: u32,
    /// `GSCPSMI_BASE`, 64-bit, as read through the media GT window; only
    /// consulted when [`wa_14019821291`] applies.
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
    let mut gsc = 0;
    if wa_14019821291(facts.media_gmd_id)? {
        let gsc_base = facts.gscpsmi_base & !0x3F;
        if gsc_base >= io_base && gsc_base < io_base + usable {
            gsc = io_base + usable - gsc_base;
            usable = gsc_base - io_base;
        }
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

/// The DSM-relative page offset a present DM PTE maps, if `pte` is one.
fn dm_page(pte: u64) -> Option<u64> {
    if pte & (GGTT_PTE_PRESENT | GGTT_PTE_DM) != GGTT_PTE_PRESENT | GGTT_PTE_DM {
        return None;
    }
    (pte & GGTT_PTE_ADDR_MASK).checked_sub(DSM_GSM_OFFSET)
}

/// DSM pages reachable through the CPU aperture: the DSM-relative page
/// offset of every present DM PTE among `ptes` (GGTT entries
/// `[0, BAR2 length / 4 KiB)`).
pub fn aperture_dsm_pages(ptes: impl IntoIterator<Item = u64>) -> Vec<u64> {
    let mut pages: Vec<u64> = ptes.into_iter().filter_map(dm_page).collect();
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
    /// Ranges another DSM owner of this function holds (not counted against
    /// [`MAX_PLACEMENTS`]).
    reserved: Vec<(u64, u64)>,
}

impl Dsm {
    pub fn new(layout: Layout, excluded_pages: Vec<u64>) -> Self {
        Self {
            layout,
            excluded_pages,
            placed: Vec::new(),
            reserved: Vec::new(),
        }
    }
    /// Exclude `[start, start + len)`, held by another owner of this DSM.
    pub fn reserve(&mut self, start: u64, len: u64) {
        self.reserved.push((start, len));
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
            .chain(&self.reserved)
            .filter(|&&(s, l)| s < end && start < s + l)
            .map(|&(s, l)| s + l)
            .max();
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

/// GGTT entries one [`Carve::survey`] step reads (two MMIO reads each)
/// before its driver yields.
pub const CARVE_CHUNK_PTES: u64 = 1024;

/// A placed FBC CFB: (DSM offset, placed bytes, compression limit).
pub type Placed = (u32, u64, u32);

/// A resumable DSM survey and FBC CFB placement for one function.
#[derive(Clone, Debug)]
pub struct Carve {
    layout: Layout,
    entries: u64,
    next: u64,
    pages: Vec<u64>,
}

impl Carve {
    /// A survey of GGTT entries `[0, entries)` over `layout`.
    pub fn new(layout: Layout, entries: u64) -> Self {
        Self {
            layout,
            entries,
            next: 0,
            pages: Vec::new(),
        }
    }

    /// Read at most `budget` further GGTT entries through
    /// `read_pte(index)`, keeping every present DM page. Returns whether
    /// every entry has been read.
    pub fn survey(&mut self, budget: u64, mut read_pte: impl FnMut(u64) -> u64) -> bool {
        let end = self.next.saturating_add(budget).min(self.entries);
        for index in self.next..end {
            if let Some(page) = dm_page(read_pte(index)) {
                self.pages.push(page);
            }
        }
        self.next = end;
        self.done()
    }

    /// Every entry has been read.
    pub fn done(&self) -> bool {
        self.next >= self.entries
    }

    /// GGTT entries read so far.
    pub fn read(&self) -> u64 {
        self.next
    }

    /// After a complete survey: `find_compression_limit` over first-fit
    /// placements below `intel_fbc_cfb_base_max`, each proved free of
    /// system RAM and of this function's GSC claim, then recorded as a CFB
    /// claim. `None` before the survey completes or when nothing fits.
    pub fn place(
        self,
        size: u64,
        min_limit: u32,
        is_system_ram: impl Fn(u64) -> bool,
    ) -> Option<Placed> {
        if !self.done() {
            return None;
        }
        let mut pages = self.pages;
        pages.sort_unstable();
        pages.dedup();
        // A GSC claim committed between the snapshot and the commit forces
        // one more placement over the new snapshot.
        loop {
            let (generation, gsc, _) = claims(self.layout);
            let mut stolen = Dsm::new(self.layout, pages.clone());
            if let Some((start, len)) = gsc {
                stolen.reserve(start, len);
            }
            let mut offset = None;
            let (limit, bytes) = crate::intel_gpu_fbc::find_compression_limit(
                size,
                min_limit,
                |bytes| match stolen.place(bytes, PAGE, CFB_BASE_MAX, &is_system_ram) {
                    Ok(placed) => {
                        offset = Some(placed);
                        true
                    }
                    Err(_) => false,
                },
            )?;
            let offset = offset?;
            if commit(self.layout, generation, Claim::Cfb(offset, bytes)) {
                return Some((u32::try_from(offset).ok()?, bytes, limit));
            }
        }
    }

    /// After a complete survey: the GSC private object's DSM range,
    /// `GSC_BYTES` placed first-fit in usable DSM away from every excluded
    /// aperture page and recent CFB claim, each page proved free of system
    /// RAM. A function that already holds a GSC claim gets that range back
    /// without a placement (`gsc_claim`). `None` before the survey completes.
    pub fn place_gsc(
        &self,
        is_system_ram: impl Fn(u64) -> bool,
    ) -> Option<Result<(u64, u64), StolenError>> {
        if let Some(claim) = gsc_claim(self.layout) {
            return Some(Ok(claim));
        }
        if !self.done() {
            return None;
        }
        let mut pages = self.pages.clone();
        pages.sort_unstable();
        pages.dedup();
        loop {
            let (generation, gsc, cfb) = claims(self.layout);
            if let Some(claim) = gsc {
                return Some(Ok(claim));
            }
            let mut stolen = Dsm::new(self.layout, pages.clone());
            for (start, len) in cfb {
                stolen.reserve(start, len);
            }
            let offset = match stolen.place(GSC_BYTES, PAGE, u64::MAX, &is_system_ram) {
                Ok(offset) => offset,
                Err(error) => return Some(Err(error)),
            };
            if commit(self.layout, generation, Claim::Gsc(offset, GSC_BYTES)) {
                return Some(Ok((offset, GSC_BYTES)));
            }
        }
    }
}

/// One function's device-lifetime DSM claims.
#[derive(Clone, Debug, Default)]
struct Claims {
    /// Bumped by every commit (optimistic placement outside the lock).
    generation: u64,
    /// The GSC private object: placed once, never released.
    gsc: Option<(u64, u64)>,
    /// The newest CFB placements, oldest first.
    cfb: Vec<(u64, u64)>,
}

enum Claim {
    Cfb(u64, u64),
    Gsc(u64, u64),
}

/// Claims per DSM base (`Layout::base_phys`, the function's BSM).
static CLAIMS: IrqSafeSpinLock<Vec<(u64, Claims)>> = IrqSafeSpinLock::new(Vec::new());

/// A snapshot: (generation, GSC claim, recent CFB claims).
fn claims(layout: Layout) -> (u64, Option<(u64, u64)>, Vec<(u64, u64)>) {
    CLAIMS
        .lock()
        .iter()
        .find(|(base, _)| *base == layout.base_phys)
        .map_or((0, None, Vec::new()), |(_, c)| {
            (c.generation, c.gsc, c.cfb.clone())
        })
}

/// Record `claim` if no other claim of this DSM landed since `generation`.
fn commit(layout: Layout, generation: u64, claim: Claim) -> bool {
    let mut all = CLAIMS.lock();
    let at = match all.iter().position(|(base, _)| *base == layout.base_phys) {
        Some(at) => at,
        None => {
            all.push((layout.base_phys, Claims::default()));
            all.len() - 1
        }
    };
    let claims = &mut all[at].1;
    if claims.generation != generation {
        return false;
    }
    match claim {
        Claim::Cfb(start, len) => {
            if claims.cfb.len() == MAX_CFB_CLAIMS {
                claims.cfb.remove(0);
            }
            claims.cfb.push((start, len));
        }
        Claim::Gsc(start, len) => {
            if claims.gsc.is_some() {
                return false;
            }
            claims.gsc = Some((start, len));
        }
    }
    claims.generation += 1;
    true
}

/// This function's GSC private object, if one was ever claimed: the GSC
/// owns it until an FLR, so it is never released or reused.
pub fn gsc_claim(layout: Layout) -> Option<(u64, u64)> {
    claims(layout).1
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum SlotState {
    #[default]
    Idle,
    Running {
        size: u64,
        min_limit: u32,
    },
    Done {
        size: u64,
        min_limit: u32,
        result: Option<Placed>,
    },
}

/// One function's off-path CFB carve as the present path sees it: polled,
/// never waited for.
#[derive(Debug)]
pub struct CarveSlot(IrqSafeSpinLock<SlotState>);

impl Default for CarveSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl CarveSlot {
    pub const fn new() -> Self {
        Self(IrqSafeSpinLock::new(SlotState::Idle))
    }

    /// The finished carve for exactly `size`/`min_limit` (`Ready(None)`:
    /// nothing fits), or `Pending`. When no carve for these parameters is
    /// running or finished, the slot records one as running and calls
    /// `start` (outside its lock) to launch it; `start` must not block.
    pub fn poll(&self, size: u64, min_limit: u32, start: impl FnOnce()) -> Poll<Option<Placed>> {
        let mut state = self.0.lock();
        match *state {
            SlotState::Done {
                size: s,
                min_limit: m,
                result,
            } if (s, m) == (size, min_limit) => Poll::Ready(result),
            SlotState::Running { .. } => Poll::Pending,
            _ => {
                *state = SlotState::Running { size, min_limit };
                drop(state);
                start();
                Poll::Pending
            }
        }
    }

    /// The running carve for `size`/`min_limit` finished.
    pub fn finish(&self, size: u64, min_limit: u32, result: Option<Placed>) {
        let mut state = self.0.lock();
        if *state == (SlotState::Running { size, min_limit }) {
            *state = SlotState::Done {
                size,
                min_limit,
                result,
            };
        }
    }

    /// The running carve could not complete (access lost): the next poll
    /// starts another.
    pub fn abandon(&self) {
        let mut state = self.0.lock();
        if matches!(*state, SlotState::Running { .. }) {
            *state = SlotState::Idle;
        }
    }
}

/// The function's BAR2 (GMADR) as the CPU reaches DSM on graphics >= 12.70:
/// GSM, then DSM at [`DSM_GSM_OFFSET`] (`detect_bar2_integrated`'s
/// `io_base`). Accesses outside the BAR or unaligned read as all ones and
/// write nothing.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "kernel-test"), allow(dead_code))] // GSC runtime wiring follows.
pub(crate) struct Bar2Window(pub(crate) narf_bus::MmioRegion);

impl crate::intel_gpu_aux::MmioWindow for Bar2Window {
    fn read32(&self, offset: u64) -> u32 {
        if offset % 4 != 0 || offset.checked_add(4).is_none_or(|end| end > self.0.len) {
            return u32::MAX;
        }
        // SAFETY: the probe-mapped BAR2 this driver owns; the dword is
        // aligned and inside the BAR. DSM is memory and tolerates any read.
        unsafe { self.0.read32(offset) }
    }
    fn write32(&self, offset: u64, value: u32) {
        if offset % 4 != 0 || offset.checked_add(4).is_none_or(|end| end > self.0.len) {
            return;
        }
        // SAFETY: as `read32`; callers write only a DSM range they claimed.
        unsafe { self.0.write32(offset, value) }
    }
}

/// The GSC private object: its claimed DSM range, which the CPU writes
/// through BAR2 at `io_base + offset` as `xe_ttm_stolen_io_offset` does on
/// graphics >= 12.70 (no GGTT detour), and which the GSC reaches through its
/// fixed GGTT DM window. Dropping it releases nothing: the claim and the
/// GGTT window stay the function's for its lifetime.
#[derive(Debug)]
#[cfg_attr(not(feature = "kernel-test"), allow(dead_code))] // GSC runtime wiring follows.
pub(crate) struct StolenObject<W> {
    cpu: W,
    offset: u64,
    ggtt: u32,
}

impl<W: crate::intel_gpu_aux::MmioWindow> StolenObject<W> {
    /// The claimed `GSC_BYTES` range at `claim` within usable DSM of
    /// `layout`, mapped at the GGTT window base `ggtt`.
    #[cfg_attr(not(feature = "kernel-test"), allow(dead_code))] // GSC runtime wiring follows.
    pub(crate) fn gsc(cpu: W, layout: Layout, claim: (u64, u64), ggtt: u32) -> Option<Self> {
        let (offset, len) = claim;
        (len == GSC_BYTES
            && offset % PAGE == 0
            && offset >= MIN_OFFSET
            && offset
                .checked_add(len)
                .is_some_and(|end| end <= layout.usable)
            && gsc_claim(layout) == Some(claim)
            && u64::from(ggtt) == GSC_GGTT)
            .then_some(Self { cpu, offset, ggtt })
    }
}

impl<W: crate::intel_gpu_aux::MmioWindow> crate::intel_gpu_rcs::GpuBacking for StolenObject<W> {
    fn ggtt_offset(&self) -> u32 {
        self.ggtt
    }
    fn size_pages(&self) -> u32 {
        (GSC_BYTES / PAGE) as u32
    }
    fn read32(&self, byte_off: u64) -> u32 {
        if byte_off >= GSC_BYTES {
            return u32::MAX;
        }
        self.cpu.read32(DSM_GSM_OFFSET + self.offset + byte_off)
    }
    fn write32(&self, byte_off: u64, val: u32) {
        if byte_off < GSC_BYTES {
            self.cpu
                .write32(DSM_GSM_OFFSET + self.offset + byte_off, val);
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_stolen_tests.rs"]
mod tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_stolen_gsc_tests.rs"]
mod gsc_tests;
