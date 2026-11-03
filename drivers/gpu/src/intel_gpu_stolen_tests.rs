//! DSM discovery and CFB placement fixtures. Register values are
//! hand-encoded from the pinned field definitions cited in the module.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

const MIB: u64 = 1 << 20;
const GMADR: u64 = 0x40_0000_0000;

/// GGMS=3, GMS=0x02 (64 MiB); WOPCM field 2 (4 MiB); no GSC carve-out.
fn facts() -> Facts {
    Facts {
        ggc: (0x02 << GMS_SHIFT) | GGMS_MASK,
        stolen_reserved_lo: 2 << WOPCM_SIZE_SHIFT,
        gscpsmi_base: 0,
        gmadr_base: GMADR,
        gmadr_len: 256 * MIB,
        bsm_dw0: 0x7C00_0000 | 0x5, // low flag bits are masked off
        bsm_dw1: 0x1,
    }
}

fn smoke_stolen_discovery_decodes_pinned_fields() -> TestResult {
    if gms_bytes((0x04 << GMS_SHIFT) | GGMS_MASK) != Ok(128 * MIB)
        || gms_bytes((0xF0 << GMS_SHIFT) | GGMS_MASK) != Ok(4 * MIB)
        || gms_bytes((0xFE << GMS_SHIFT) | GGMS_MASK) != Ok(60 * MIB)
        || gms_bytes((0x05 << GMS_SHIFT) | GGMS_MASK) != Err(StolenError::BadGms(5))
        || gms_bytes(0x02 << GMS_SHIFT) != Err(StolenError::BadGgms(0x200))
    {
        return TestResult::Fail("GMS/GGMS decode diverges from detect_bar2_integrated");
    }
    if wopcm_bytes(0) != Ok(MIB)
        || wopcm_bytes(3 << WOPCM_SIZE_SHIFT) != Ok(8 * MIB)
        || wopcm_bytes(5 << WOPCM_SIZE_SHIFT) != Ok(16 * MIB)
        || wopcm_bytes(6 << WOPCM_SIZE_SHIFT) != Ok(32 * MIB)
        || wopcm_bytes(4 << WOPCM_SIZE_SHIFT) != Err(StolenError::BadWopcm(4))
    {
        return TestResult::Fail("WOPCM decode diverges from get_wopcm_size");
    }
    let Ok(l) = layout(facts()) else {
        return TestResult::Fail("reference facts must decode");
    };
    if l.total != 64 * MIB
        || l.wopcm != 4 * MIB
        || l.usable != 60 * MIB
        || l.gsc != 0
        || l.base_phys != 0x1_7C00_0000
    {
        return TestResult::Fail("layout must carve WOPCM and mask BSM to 1 MiB");
    }
    // Wa_14019821291: a GSC base inside DSM cuts everything above it.
    let gsc = GMADR + DSM_GSM_OFFSET + 52 * MIB;
    let Ok(l) = layout(Facts {
        gscpsmi_base: gsc | 0x3F,
        ..facts()
    }) else {
        return TestResult::Fail("GSC facts must decode");
    };
    if l.usable != 52 * MIB || l.gsc != 8 * MIB {
        return TestResult::Fail("the GSC PSMI region must be carved below the WOPCM");
    }
    // Outside DSM: no carve-out (the BIOS did not apply the workaround).
    if layout(Facts {
        gscpsmi_base: GMADR,
        ..facts()
    })
    .map(|l| l.usable)
        != Ok(60 * MIB)
    {
        return TestResult::Fail("a GSC base outside DSM must not carve");
    }
    if layout(Facts {
        gmadr_len: 64 * MIB,
        ..facts()
    }) != Err(StolenError::ApertureTooSmall)
        || layout(Facts {
            ggc: u32::MAX,
            ..facts()
        }) != Err(StolenError::Unavailable)
    {
        return TestResult::Fail("undersized aperture / unreadable GGC must refuse");
    }
    if GGC != 0x108040
        || STOLEN_RESERVED != 0x1082C0
        || MEDIA_GSCPSMI_BASE != 0x38880C
        || PCI_BSM_DW0 != 0xC0
        || GGTT_PTE_DM != 2
    {
        return TestResult::Fail("DSM register facts diverge from the pinned tree");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_stolen",
    smoke_stolen_discovery_decodes_pinned_fields
);

fn smoke_stolen_cfb_avoids_boot_fb_wopcm_and_gsc() -> TestResult {
    // The boot GOP framebuffer: DSM pages 0..=1023 (4 MiB) mapped by DM
    // PTEs in the aperture, plus one stray DM page at 6 MiB. A system
    // memory PTE (no DM) and a non-present DM PTE are not DSM mappings.
    let mut ptes: Vec<u64> = (0..1024u64)
        .map(|i| (DSM_GSM_OFFSET + i * PAGE) | GGTT_PTE_DM | GGTT_PTE_PRESENT)
        .collect();
    ptes.push((DSM_GSM_OFFSET + 6 * MIB) | GGTT_PTE_DM | GGTT_PTE_PRESENT);
    ptes.push(0x8000_0000 | GGTT_PTE_PRESENT);
    ptes.push((DSM_GSM_OFFSET + 9 * MIB) | GGTT_PTE_DM);
    let pages = aperture_dsm_pages(ptes);
    if pages.len() != 1025 || pages.first() != Some(&0) || pages.last() != Some(&(6 * MIB)) {
        return TestResult::Fail("only present DM PTEs map DSM pages");
    }
    let gsc = GMADR + DSM_GSM_OFFSET + 52 * MIB;
    let Ok(l) = layout(Facts {
        gscpsmi_base: gsc,
        ..facts()
    }) else {
        return TestResult::Fail("facts must decode");
    };
    let mut dsm = Dsm::new(l, pages);
    let not_ram = |_| false;
    // 4..6 MiB (between the boot FB and the stray page) holds only 2 MiB,
    // so a 3 MiB first fit lands just past the stray page at 6 MiB.
    let Ok(cfb) = dsm.place(3 * MIB, PAGE, CFB_BASE_MAX, not_ram) else {
        return TestResult::Fail("a 3 MiB CFB fits above the boot framebuffer");
    };
    if cfb != 6 * MIB + PAGE {
        return TestResult::Fail("first fit must skip the boot FB and the stray DM page");
    }
    // Never below 4 KiB, never in the boot FB, never at/above the GSC cut
    // (which also keeps it out of the WOPCM).
    if cfb < MIN_OFFSET || cfb < 4 * MIB || cfb + 3 * MIB > l.usable {
        return TestResult::Fail("placement escaped the reserved ranges");
    }
    // Too large for what remains below the GSC cut: refused.
    if dsm.place(50 * MIB, PAGE, CFB_BASE_MAX, not_ram) != Err(StolenError::NoSpace) {
        return TestResult::Fail("a CFB reaching the GSC/WOPCM carve-outs must refuse");
    }
    // Page-allocator exclusivity: a candidate containing a system-RAM page
    // is refused and nothing is recorded. First fit puts a 2 MiB request
    // in the 4..6 MiB gap below the stray page, so mark a page there.
    let ram_page = l.base_phys + 4 * MIB + PAGE;
    let before = dsm.placed().len();
    if dsm.place(2 * MIB, PAGE, CFB_BASE_MAX, |p| p == ram_page)
        != Err(StolenError::SystemRam(ram_page))
        || dsm.placed().len() != before
    {
        return TestResult::Fail("a range with a system-RAM page must never be handed out");
    }
    // Bounded: a second placement fits, a third is refused.
    if dsm.place(MIB, PAGE, CFB_BASE_MAX, not_ram).is_err()
        || dsm.place(PAGE, PAGE, CFB_BASE_MAX, not_ram) != Err(StolenError::Exhausted)
    {
        return TestResult::Fail("placements must be bounded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_stolen",
    smoke_stolen_cfb_avoids_boot_fb_wopcm_and_gsc
);

/// 5000 GGTT entries: the boot framebuffer (DSM pages 0..1024) at entries
/// 3000..4024, a stray DM page at 6 MiB in the last entry, system-memory
/// PTEs everywhere else.
fn aperture() -> Vec<u64> {
    let mut ptes: Vec<u64> = (0..5000u64)
        .map(|i| (0x8000_0000 + i * PAGE) | GGTT_PTE_PRESENT)
        .collect();
    for i in 0..1024u64 {
        ptes[3000 + i as usize] = (DSM_GSM_OFFSET + i * PAGE) | GGTT_PTE_DM | GGTT_PTE_PRESENT;
    }
    ptes[4999] = (DSM_GSM_OFFSET + 6 * MIB) | GGTT_PTE_DM | GGTT_PTE_PRESENT;
    ptes
}

fn smoke_stolen_carve_survey_is_chunked_and_places_like_one_shot() -> TestResult {
    let ptes = aperture();
    let l = layout(facts()).unwrap();
    let mut carve = Carve::new(l, ptes.len() as u64);
    // Before the survey completes nothing is placed.
    if carve.clone().place(3 * MIB, 1, |_| false).is_some() {
        return TestResult::Fail("an incomplete survey must not place");
    }
    let mut seen = alloc::vec![0u32; ptes.len()];
    let mut steps = 0;
    loop {
        let mut reads = 0u64;
        let done = carve.survey(CARVE_CHUNK_PTES, |i| {
            reads += 1;
            seen[i as usize] += 1;
            ptes[i as usize]
        });
        steps += 1;
        if reads > CARVE_CHUNK_PTES {
            return TestResult::Fail("a survey step must stay within its chunk");
        }
        if done {
            break;
        }
    }
    // ceil(5000 / 1024) bounded steps, each entry read exactly once.
    if steps != 5 || carve.read() != 5000 || seen.iter().any(|&n| n != 1) {
        return TestResult::Fail("the survey must read every entry once, in chunks");
    }
    if !carve.survey(CARVE_CHUNK_PTES, |_| panic!("no reads after completion")) {
        return TestResult::Fail("a complete survey stays complete");
    }
    // The chunked survey places exactly what the one-shot scan would:
    // find_compression_limit tries 2x first (6 MiB does not fit the 4..6
    // MiB gap, so it lands past the stray page).
    let mut one_shot = Dsm::new(l, aperture_dsm_pages(ptes.iter().copied()));
    let mut want = None;
    let (limit, bytes) = crate::intel_gpu_fbc::find_compression_limit(3 * MIB, 1, |bytes| {
        match one_shot.place(bytes, PAGE, CFB_BASE_MAX, |_| false) {
            Ok(offset) => {
                want = Some(offset);
                true
            }
            Err(_) => false,
        }
    })
    .unwrap();
    let placed = carve.clone().place(3 * MIB, 1, |_| false);
    if placed != Some((want.unwrap() as u32, bytes, limit))
        || placed != Some(((6 * MIB + PAGE) as u32, 6 * MIB, 1))
    {
        return TestResult::Fail("chunked survey must place like the one-shot scan");
    }
    // The placement keeps its RAM proof: every candidate RAM-backed.
    if carve.place(3 * MIB, 1, |_| true).is_some() {
        return TestResult::Fail("RAM-backed DSM must never be handed out");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_stolen",
    smoke_stolen_carve_survey_is_chunked_and_places_like_one_shot
);

fn smoke_stolen_carve_slot_polls_without_blocking() -> TestResult {
    use core::cell::Cell;
    use core::task::Poll;
    let slot = CarveSlot::new();
    let starts = Cell::new(0);
    let start = || starts.set(starts.get() + 1);
    // The first poll launches the off-path carve and returns at once.
    if slot.poll(100, 1, start) != Poll::Pending || starts.get() != 1 {
        return TestResult::Fail("the first poll launches exactly one carve");
    }
    // While it runs: Pending, no second launch, for any parameters.
    if slot.poll(100, 1, start) != Poll::Pending
        || slot.poll(200, 1, start) != Poll::Pending
        || starts.get() != 1
    {
        return TestResult::Fail("a running carve is never relaunched or waited for");
    }
    // A completion for other parameters is ignored.
    slot.finish(200, 1, Some((1, 2, 1)));
    if slot.poll(100, 1, start) != Poll::Pending || starts.get() != 1 {
        return TestResult::Fail("only the running carve may finish");
    }
    slot.finish(100, 1, Some((0x1000, 200, 1)));
    if slot.poll(100, 1, start) != Poll::Ready(Some((0x1000, 200, 1))) || starts.get() != 1 {
        return TestResult::Fail("a finished carve answers without relaunching");
    }
    // New parameters (a replaced console geometry) carve again.
    if slot.poll(300, 2, start) != Poll::Pending || starts.get() != 2 {
        return TestResult::Fail("new parameters launch a new carve");
    }
    slot.finish(300, 2, None);
    if slot.poll(300, 2, start) != Poll::Ready(None) {
        return TestResult::Fail("a carve that placed nothing is a refusal");
    }
    // Lost access abandons a running carve; the next poll relaunches.
    if slot.poll(400, 1, start) != Poll::Pending || starts.get() != 3 {
        return TestResult::Fail("relaunch for new parameters");
    }
    slot.abandon();
    if slot.poll(400, 1, start) != Poll::Pending || starts.get() != 4 {
        return TestResult::Fail("an abandoned carve is relaunched");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_stolen",
    smoke_stolen_carve_slot_polls_without_blocking
);
