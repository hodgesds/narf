//! The media GT's GSC private object in DSM and its GGTT DM mapping.
//! Literal values follow MIT Linux b90c984d: xe_gsc.c
//! xe_gsc_init_post_hwconfig (SZ_4M, XE_BO_FLAG_STOLEN | XE_BO_FLAG_GGTT),
//! xe_ttm_stolen_mgr.c detect_bar2_integrated (stolen_base SZ_8M, io_base
//! BAR2 + 8 MiB), xe_ggtt.c xelpg_ggtt_pte_flags / xe_ggtt_map_bo and
//! regs/xe_gtt_defs.h (XE_PAGE_PRESENT, XE_GGTT_PTE_DM, XELPG_GGTT_PTE_PAT0/1).
//! Every fixture uses its own DSM base: the claim registry is
//! device-lifetime state keyed by it.

use super::*;
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::GtPlatform;
use crate::intel_gpu_rcs::{GgttArena, GpuAllocator, GpuBacking, SharedArena};
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

const MIB: u64 = 1 << 20;
const GMADR: u64 = 0x40_0000_0000;
const MTL: GtPlatform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);

/// GGMS=3, GMS=0x02 (64 MiB), WOPCM 4 MiB, the Wa_14019821291 GSC cut at
/// 52 MiB (so 52 MiB usable), a fixture-unique DSM base `dw1:0x5C00_0000`.
fn facts(dw1: u32) -> Facts {
    Facts {
        ggc: (0x02 << GMS_SHIFT) | GGMS_MASK,
        stolen_reserved_lo: 2 << WOPCM_SIZE_SHIFT,
        media_gmd_id: (13 << 22) | 4,
        gscpsmi_base: GMADR + DSM_GSM_OFFSET + 52 * MIB,
        gmadr_base: GMADR,
        gmadr_len: 256 * MIB,
        bsm_dw0: 0x5C00_0000,
        bsm_dw1: dw1,
    }
}

/// The boot framebuffer (DSM 0..4 MiB) and a stray DM page at 9 MiB in the
/// aperture, system-memory PTEs elsewhere.
fn surveyed(layout: Layout) -> Carve {
    let mut ptes: Vec<u64> = (0..3000u64)
        .map(|i| (0x8000_0000 + i * PAGE) | GGTT_PTE_PRESENT)
        .collect();
    for i in 0..1024u64 {
        ptes[1000 + i as usize] = (DSM_GSM_OFFSET + i * PAGE) | GGTT_PTE_DM | GGTT_PTE_PRESENT;
    }
    ptes[2999] = (DSM_GSM_OFFSET + 9 * MIB) | GGTT_PTE_DM | GGTT_PTE_PRESENT;
    let mut carve = Carve::new(layout, ptes.len() as u64);
    while !carve.survey(CARVE_CHUNK_PTES, |i| ptes[i as usize]) {}
    carve
}

fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.0 + b.1 && b.0 < a.0 + a.1
}

/// The GSC private object never overlaps the boot framebuffer's DM pages,
/// a CFB placed before or after it, the WOPCM or the Wa_14019821291 GSC
/// region; it is placed once and every later incarnation gets the same
/// range back without a survey.
fn smoke_media_gsc_stolen_object_avoids_fbc_boot_fb_wopcm_and_gsc_wa() -> TestResult {
    let not_ram = |_| false;
    // FBC first: a 3 MiB CFB lands above the boot framebuffer (4..7 MiB),
    // so the GSC object skips it and the stray page at 9 MiB.
    let l = layout(facts(0x51)).unwrap();
    kt_assert_eq!((l.usable, l.gsc, l.wopcm), (52 * MIB, 8 * MIB, 4 * MIB));
    let Some((cfb, cfb_bytes, _)) = surveyed(l).place(3 * MIB, 2, not_ram) else {
        return TestResult::Fail("the CFB must fit");
    };
    let cfb = (u64::from(cfb), cfb_bytes);
    kt_assert_eq!(gsc_claim(l), None);
    // An incomplete survey without a claim places nothing.
    kt_assert!(Carve::new(l, 3000).place_gsc(not_ram).is_none());
    let Some(Ok(gsc)) = surveyed(l).place_gsc(not_ram) else {
        return TestResult::Fail("the GSC object must fit");
    };
    kt_assert_eq!(gsc.1, GSC_BYTES);
    kt_assert!(!overlaps(gsc, cfb));
    kt_assert!(!overlaps(gsc, (0, 4 * MIB)), "boot framebuffer");
    kt_assert!(!overlaps(gsc, (9 * MIB, PAGE)), "stray DM page");
    kt_assert!(
        gsc.0 >= MIN_OFFSET && gsc.0 + gsc.1 <= l.usable,
        "WOPCM / GSC WA"
    );
    kt_assert_eq!(gsc, (9 * MIB + PAGE, GSC_BYTES));
    kt_assert_eq!(gsc_claim(l), Some(gsc));
    // A later GT0 incarnation: the same range, with no survey and even with
    // a placement that would now refuse (every page RAM-backed).
    kt_assert_eq!(Carve::new(l, 3000).place_gsc(|_| true), Some(Ok(gsc)));
    // FBC after the GSC claim: every CFB size avoids it.
    for size in [3 * MIB, 8 * MIB, 16 * MIB] {
        let Some((offset, bytes, _)) = surveyed(l).place(size, 1, not_ram) else {
            return TestResult::Fail("a CFB must still fit beside the GSC object");
        };
        kt_assert!(!overlaps((u64::from(offset), bytes), gsc));
    }
    kt_assert_eq!(gsc_claim(l), Some(gsc));

    // GSC first on another function: the lowest fit above the boot FB, and a
    // later CFB goes around it.
    let l = layout(facts(0x52)).unwrap();
    let Some(Ok(gsc)) = surveyed(l).place_gsc(not_ram) else {
        return TestResult::Fail("the GSC object must fit first");
    };
    kt_assert_eq!(gsc, (4 * MIB, GSC_BYTES));
    let Some((offset, bytes, _)) = surveyed(l).place(3 * MIB, 1, not_ram) else {
        return TestResult::Fail("the CFB must fit after the GSC object");
    };
    kt_assert!(!overlaps((u64::from(offset), bytes), gsc));
    kt_assert!(!overlaps((u64::from(offset), bytes), (9 * MIB, PAGE)));

    // Exclusivity against the page allocator: nothing is claimed.
    let l = layout(facts(0x53)).unwrap();
    let ram = l.base_phys + 4 * MIB;
    kt_assert_eq!(
        surveyed(l).place_gsc(|phys| phys == ram),
        Some(Err(StolenError::SystemRam(ram)))
    );
    kt_assert_eq!(gsc_claim(l), None);
    // Too little DSM below the WOPCM: refused, nothing claimed.
    let small = layout(Facts {
        ggc: (0xF1 << GMS_SHIFT) | GGMS_MASK, // 8 MiB
        stolen_reserved_lo: 0,                // 1 MiB WOPCM
        gscpsmi_base: 0,
        ..facts(0x54)
    })
    .unwrap();
    kt_assert_eq!(small.usable, 7 * MIB);
    kt_assert_eq!(
        surveyed(small).place_gsc(not_ram),
        Some(Err(StolenError::NoSpace))
    );
    kt_assert_eq!(gsc_claim(small), None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_stolen_object_avoids_fbc_boot_fb_wopcm_and_gsc_wa
);

/// A BAR2 model: writes and reads by offset.
#[derive(Default)]
struct Bar2(RefCell<alloc::collections::BTreeMap<u64, u32>>);
impl MmioWindow for &Bar2 {
    fn read32(&self, offset: u64) -> u32 {
        *self.0.borrow().get(&offset).unwrap_or(&0)
    }
    fn write32(&self, offset: u64, value: u32) {
        self.0.borrow_mut().insert(offset, value);
    }
}

/// A RAM-backed 16 MiB BAR0 (fixture-unique GGTT ledger key).
struct RamBar {
    _words: Vec<u32>,
    region: narf_bus::bar::MmioRegion,
}
impl RamBar {
    fn new(key: u64) -> Self {
        let mut words = alloc::vec![0u32; 4 * 1024 * 1024];
        let region = narf_bus::bar::MmioRegion {
            phys: narf_memory::PhysAddr::new(key),
            virt: words.as_mut_ptr() as u64,
            len: 16 << 20,
            kind: narf_bus::bar::BarKind::Mmio64 {
                prefetchable: false,
            },
        };
        Self {
            _words: words,
            region,
        }
    }
    fn pte(&self, ggtt: u64) -> u64 {
        let at = crate::intel_gpu_gtt::GGTT_ARRAY_BASE + ggtt / PAGE * 8;
        // SAFETY: `_words` backs the whole fixture BAR and outlives every
        // arena built over it; the aligned slot is in bounds.
        unsafe {
            let low = core::ptr::read_volatile((self.region.virt + at) as *const u32);
            let high = core::ptr::read_volatile((self.region.virt + at + 4) as *const u32);
            u64::from(low) | u64::from(high) << 32
        }
    }
}

fn arena(bar: &RamBar, platform: GtPlatform, configure: bool) -> SharedArena {
    let cap =
        narf_capabilities::Cap::<narf_bus::BusDeviceCap, narf_capabilities::Write>::bootstrap();
    let arena = SharedArena::new(GgttArena::for_gt(bar.region, cap, platform));
    if configure {
        let mut seed = arena.clone().alloc(1).expect("fixture seed page");
        arena
            .configure_cache(
                &mut seed,
                crate::intel_gpu_gt_hw::CachePolicy {
                    platform,
                    ggtt_pat: 3,
                    media: None,
                },
            )
            .expect("fixture cache policy");
        arena.clone().free(seed);
    }
    arena
}

/// XE_PAGE_PRESENT | XE_GGTT_PTE_DM | PAT0 | PAT1 (WB index 3) over
/// stolen_base (8 MiB) + DSM offset for each of the 1024 pages, at the fixed
/// GSC window above the GT arena and outside the CPU aperture; no GuC TLB
/// invalidation; a later incarnation rewrites identical entries; the CPU
/// writes the object through BAR2 at io_base + offset.
fn smoke_media_gsc_dm_ptes_encode_stolen_and_survive_incarnations() -> TestResult {
    use crate::intel_gpu_gtt::{GttError, PteFormat};
    kt_assert_eq!(
        PteFormat::XeLpg.encode_ggtt_stolen(DSM_GSM_OFFSET + 0x10_0000, 3),
        Ok(0x0030_0000_0090_0003)
    );
    kt_assert_eq!(
        PteFormat::XeLpg.encode_ggtt_stolen(DSM_GSM_OFFSET, 0),
        Ok(0x0080_0003)
    );
    kt_assert!(PteFormat::Gen12
        .encode_ggtt_stolen(DSM_GSM_OFFSET, 0)
        .is_err());
    kt_assert_eq!(
        PteFormat::XeLpg.encode_ggtt_stolen(DSM_GSM_OFFSET + 4, 3),
        Err(GttError::UnalignedPhys)
    );
    kt_assert_eq!(
        PteFormat::XeLpg.encode_ggtt_stolen(DSM_GSM_OFFSET, 4),
        Err(GttError::InvalidPatIndex)
    );
    kt_assert_eq!(GSC_GGTT, 0x1200_0000);
    kt_assert_eq!(
        u64::from(crate::intel_gpu_rcs::GGTT_ARENA_BASE)
            + u64::from(crate::intel_gpu_rcs::GGTT_ARENA_PAGES) * PAGE,
        GSC_GGTT
    );

    let bar = RamBar::new(0x6_f100_0000);
    let gt0 = arena(&bar, MTL, true);
    let offset = 9 * MIB + PAGE;
    // Refusals before any entry is written: no cache policy yet, a wrong
    // size, an unaligned offset, and non-MTL platforms.
    kt_assert!(arena(&bar, MTL, false)
        .map_gsc_stolen(offset, 1024)
        .is_err());
    kt_assert!(gt0.map_gsc_stolen(offset, 1023).is_err());
    kt_assert!(gt0.map_gsc_stolen(offset + 4, 1024).is_err());
    kt_assert_eq!(bar.pte(GSC_GGTT), 0);
    let tgl_bar = RamBar::new(0x6_f200_0000);
    let tgl = arena(
        &tgl_bar,
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
        true,
    );
    kt_assert!(tgl.map_gsc_stolen(offset, 1024).is_err());
    kt_assert_eq!(tgl_bar.pte(GSC_GGTT), 0);
    drop((tgl, tgl_bar));
    // GUC_TLB_INV_CR as left by the seed's publication.
    let inv = || {
        // SAFETY: fixture BAR memory, aligned in-bounds dword.
        unsafe { core::ptr::read_volatile((bar.region.virt + 0xcee8) as *const u32) }
    };
    let before = inv();
    kt_assert_eq!(gt0.map_gsc_stolen(offset, 1024), Ok(GSC_GGTT as u32));
    for page in 0..1024u64 {
        let want = (DSM_GSM_OFFSET + offset + page * PAGE) | 3 | 3 << 52;
        kt_assert_eq!(bar.pte(GSC_GGTT + page * PAGE), want);
    }
    kt_assert_eq!(bar.pte(GSC_GGTT + GSC_BYTES), 0, "nothing past the object");
    kt_assert_eq!(inv(), before, "no GuC TLB invalidation on this insert");
    // The aperture survey never sees the GSC mapping.
    let aperture: Vec<u64> = (0..256 * MIB / PAGE).map(|i| bar.pte(i * PAGE)).collect();
    kt_assert!(aperture_dsm_pages(aperture)
        .iter()
        .all(|page| !(offset..offset + GSC_BYTES).contains(page)));
    // The arena never hands out the window.
    let mut alloc = gt0.clone();
    let page = alloc.alloc(16).expect("arena page");
    kt_assert!(u64::from(page.ggtt_offset()) + 16 * PAGE <= GSC_GGTT);
    alloc.free(page);
    drop((alloc, gt0));
    // The next GT0 incarnation's arena rewrites the same entries.
    let next = arena(&bar, MTL, true);
    kt_assert_eq!(next.map_gsc_stolen(offset, 1024), Ok(GSC_GGTT as u32));
    kt_assert_eq!(
        bar.pte(GSC_GGTT + 1023 * PAGE),
        (DSM_GSM_OFFSET + offset + 1023 * PAGE) | 3 | 3 << 52
    );
    drop(next);

    // CPU access: BAR2 io_base + DSM offset, bounded to the claimed object.
    let l = layout(facts(0x55)).unwrap();
    let Some(Ok(claim)) = surveyed(l).place_gsc(|_| false) else {
        return TestResult::Fail("the GSC object must fit");
    };
    let bar2 = Bar2::default();
    kt_assert!(StolenObject::gsc(&bar2, l, claim, GSC_GGTT as u32 + 4096).is_none());
    kt_assert!(StolenObject::gsc(&bar2, l, (claim.0, PAGE), GSC_GGTT as u32).is_none());
    let unclaimed = layout(facts(0x56)).unwrap();
    kt_assert!(StolenObject::gsc(&bar2, unclaimed, claim, GSC_GGTT as u32).is_none());
    let Some(object) = StolenObject::gsc(&bar2, l, claim, GSC_GGTT as u32) else {
        return TestResult::Fail("the claimed object must open");
    };
    kt_assert_eq!(
        (object.ggtt_offset(), object.size_pages()),
        (GSC_GGTT as u32, 1024)
    );
    object.write32(0, 0x1234_5678);
    object.write32(GSC_BYTES - 4, 0x9abc_def0);
    object.write32(GSC_BYTES, 0xdead_beef);
    kt_assert_eq!(object.read32(GSC_BYTES), u32::MAX);
    let writes = bar2.0.borrow().clone();
    kt_assert_eq!(
        writes.into_iter().collect::<Vec<_>>(),
        [
            (DSM_GSM_OFFSET + claim.0, 0x1234_5678),
            (DSM_GSM_OFFSET + claim.0 + GSC_BYTES - 4, 0x9abc_def0)
        ]
    );
    kt_assert_eq!(object.read32(0), 0x1234_5678);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gsc_dm_ptes_encode_stolen_and_survive_incarnations
);
