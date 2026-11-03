// MTL/Arrow media-GT stop around loaded GSC firmware through the production
// MediaGuc/GuCGt owners on the GuC model. Literal identities follow MIT Linux
// b90c984d: xe_gt.c::do_gt_reset brackets GRDOM_FULL with
// xe_gsc.c::xe_gsc_wa_14015076503 (MEDIA_VERSION(1300) in xe_wa_oob.rules),
// regs/xe_gsc_regs.h HECI1_FWSTS1 INIT_COMPLETE, HECI_H_GS1 ER_PREP and
// HECI_H_CSR IG/RST at the absolute MTL_GSC_HECI1/2 bases.
use super::media_gt_sched::{media_tick, media_until, start_media, Hw};
use super::*;
use crate::intel_gpu_gt::media::{MediaGucError, MediaGucState};

const FWSTS1: u64 = 0x116c40;
const GS1: u64 = 0x117c4c;
const CSR: u64 = 0x117004;
const GDRST: u64 = 0x38941c;

fn position(writes: &[(u64, u32)], write: (u64, u32)) -> usize {
    writes
        .iter()
        .position(|w| *w == write)
        .unwrap_or_else(|| panic!("missing write {write:x?}"))
}

/// With `narf.intel.gsc=1` the media GuC schedules beside loaded GSC
/// firmware, and its verified stop alerts the GSC (GS1 ER_PREP, then the
/// HECI2 interrupt with the CSR reset bit cleared), waits the 200 ms
/// preparation, writes GRDOM_FULL and clears only ER_PREP afterwards.
fn smoke_media_gt_gsc_wa_14015076503_brackets_stop_and_admits_scheduling() -> TestResult {
    let (w, arena) = media_model();
    {
        let mut d = w.0.borrow_mut();
        d.regs.insert(FWSTS1, 1 << 9);
        // An unrelated GS1 bit, and HECI2 CSR with RDY and a stale RST.
        d.regs.insert(GS1, 0x100);
        d.regs.insert(CSR, 0x18);
    }
    let mut guc = start_media(&w, &arena);
    guc.honour_gsc_reset_workaround().unwrap();
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert!(guc.publication().is_some());
    // Start never touched the GSC, and the choice is frozen once scheduled.
    assert!(!w
        .0
        .borrow()
        .writes
        .iter()
        .any(|(reg, _)| *reg == GS1 || *reg == CSR));
    assert_eq!(
        guc.honour_gsc_reset_workaround(),
        Err(MediaGucError::Gt(GtError::State))
    );
    let from = w.0.borrow().writes.len();
    guc.begin_stop(now + 1);
    let (mut prepared, mut full, mut stopped) = (None, None, false);
    for tick in 0..2000u64 {
        let at = now + 2 + tick * 1_000_000;
        let polled = media_tick(&mut guc, &w, &mut hw, at);
        {
            let d = w.0.borrow();
            let writes = &d.writes[from..];
            if prepared.is_none() && writes.contains(&(GS1, 0x101)) {
                prepared = Some(at);
            }
            if full.is_none() && writes.contains(&(GDRST, 1)) {
                full = Some(at);
            }
        }
        if polled == Poll::Ready(Ok(MediaGucState::Stopped)) {
            stopped = true;
            break;
        }
    }
    assert!(stopped);
    assert!(guc.reclaimable());
    let (prepared, full) = (prepared.unwrap(), full.unwrap());
    assert!(
        full - prepared >= 200_000_000,
        "GRDOM_FULL before the GSC prepared"
    );
    {
        let d = w.0.borrow();
        let writes = &d.writes[from..];
        let guc_reset = position(writes, (GDRST, 8));
        let alert = position(writes, (GS1, 0x101));
        let interrupt = position(writes, (CSR, 0xc));
        let reset = position(writes, (GDRST, 1));
        let clear = position(writes, (GS1, 0x100));
        let sleep = position(writes, (0x38a540, 0x0001_0000));
        assert!(guc_reset < alert && alert < interrupt && interrupt < reset);
        assert!(reset < clear && clear < sleep);
        assert_eq!(writes.iter().filter(|(reg, _)| *reg == GS1).count(), 2);
        assert_eq!(writes.iter().filter(|(reg, _)| *reg == CSR).count(), 1);
        assert_eq!(d.regs[&GS1], 0x100);
        // GSC firmware survives the GT reset; nothing reloads or clears it.
        assert_eq!(d.regs[&FWSTS1], 1 << 9);
        assert!(!writes.iter().any(|(reg, _)| *reg == FWSTS1));
        assert_eq!(d.regs[&0xa188], 1, "GT0 wake untouched");
    }
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // Unloaded GSC firmware: the same option leaves the stop unchanged.
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    guc.honour_gsc_reset_workaround().unwrap();
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    guc.begin_stop(now + 1);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    {
        let d = w.0.borrow();
        assert!(d.writes.contains(&(GDRST, 1)));
        assert!(!d.writes.iter().any(|(reg, _)| *reg == GS1 || *reg == CSR));
    }
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_gsc_wa_14015076503_brackets_stop_and_admits_scheduling
);

/// Without the option the deviation stays: GSC firmware that reports loaded
/// only after scheduling began keeps the owner retained at stop, with no
/// GRDOM_FULL and no GSC register written. A GRDOM_FULL that never clears
/// under the workaround still clears the notification before the owner
/// reports the loss.
fn smoke_media_gt_gsc_without_option_retains_and_failed_reset_clears() -> TestResult {
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    w.0.borrow_mut().regs.insert(FWSTS1, 1 << 9);
    let from = w.0.borrow().writes.len();
    guc.begin_stop(now + 1);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Err(MediaGucError::Retained)));
    assert_eq!(guc.state(), MediaGucState::Retained);
    assert!(!guc.reclaimable());
    {
        let d = w.0.borrow();
        let writes = &d.writes[from..];
        assert!(writes.contains(&(GDRST, 8)), "the GuC reset still ran");
        assert!(!writes.contains(&(GDRST, 1)));
        assert!(!writes.iter().any(|(reg, _)| *reg == GS1 || *reg == CSR));
    }
    // A retained owner keeps its memory; it is never reclaimed.
    core::mem::forget(guc);

    // The workaround with a GRDOM_FULL that never self-clears: the 5 ms
    // reset bound expires after the 200 ms preparation, and the loss still
    // clears ER_PREP (do_gt_reset runs the clear after a failed wait).
    let (w, arena) = media_model();
    w.0.borrow_mut().regs.insert(FWSTS1, 1 << 9);
    let mut guc = start_media(&w, &arena);
    guc.honour_gsc_reset_workaround().unwrap();
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let from = w.0.borrow().writes.len();
    guc.begin_stop(now + 1);
    let mut lost = None;
    for tick in 0..2000u64 {
        let at = now + 2 + tick * 1_000_000;
        // Hold GRDOM_FULL set once it was written; the GuC reset still
        // self-clears through the model.
        let full = w.0.borrow().writes[from..].contains(&(GDRST, 1));
        let polled = if full {
            w.0.borrow_mut().regs.insert(GDRST, 1);
            guc.poll(at, || true)
        } else {
            media_tick(&mut guc, &w, &mut hw, at)
        };
        if polled.is_ready() {
            lost = Some(polled);
            break;
        }
    }
    assert_eq!(lost, Some(Poll::Ready(Err(MediaGucError::Retained))));
    {
        let d = w.0.borrow();
        let writes = &d.writes[from..];
        let alert = position(writes, (GS1, 1));
        let reset = position(writes, (GDRST, 1));
        let clear = position(writes, (GS1, 0));
        assert!(alert < reset && reset < clear);
        assert_eq!(d.regs[&GS1], 0);
    }
    core::mem::forget(guc);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_gsc_without_option_retains_and_failed_reset_clears
);
