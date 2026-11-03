// MTL/Arrow standalone media GT (GT1) scheduling conversations through the
// production MediaGuc/GuCGt/GuCBoot/scheduler owners on the GuC model.
// Literal identities follow MIT Linux b90c984d: xe_hw_engine.c (media fuse
// engine list, enable_ring), xe_guc_ads.c (mapping/enable masks, regsets),
// xe_lrc.c dg2_xcs_offsets, xe_ring_ops.c __emit_job_gen12_video with the
// media GSI-adjusted AUX_INV and xe_reg_whitelist.c oam_mmio_trg_vcs/vecs.
use super::*;
use crate::intel_gpu_engine::{Engine, EngineSet};
use crate::intel_gpu_exec::PpgttProbeResult;
use crate::intel_gpu_gt::media::{
    MediaGt, MediaGuc, MediaGucError, MediaGucState, GSI_OFFSET,
};
use crate::intel_gpu_user::{UserBatch, UserContext};

/// VCS0, VCS2 and VECS0 present (positive-polarity media fuse).
const FUSE: u32 = 0x0001_0005;
/// RPM_CONFIG0: 19.2 MHz crystal, CTC shift 3 -> 19.2 MHz timestamp.
const RPM_CONFIG0: u32 = (1 << 3) | (3 << 1);

fn media_engines() -> EngineSet {
    EngineSet::of(&[Engine::Vcs0, Engine::Vcs2, Engine::Vecs0])
}

/// GT1 offsets plus the absolute media engine register banks.
fn gt1_owned(offset: u64) -> bool {
    media_owned(offset) || (0x1c0000..0x200000).contains(&offset)
}

#[derive(Default)]
struct Hw {
    /// Contexts whose ring the modeled engines already executed.
    executed: BTreeSet<u32>,
    registered: BTreeMap<u32, u32>,
    /// Engine bases that executed a private-PPGTT ring.
    ppgtt: Vec<u32>,
    /// Hold every VDBOX/VEBOX acknowledgement low (lost engine well).
    stuck_wells: bool,
    /// The engine at this base runs its ring but drops the PPGTT store.
    drop_store: Option<u32>,
}

/// Hardware side of one tick: forcewake acknowledgements follow requests,
/// GuC/GT resets self-clear with MIA held in reset and DMA idle, firmware
/// DMA completes and authenticates, and the media MMIO mailbox answers the
/// CT registration (1) and enable (0) requests.
fn media_hw(w: &Window, hw: &Hw) {
    let mut d = w.0.borrow_mut();
    let gt = d.regs.get(&0x38a188).copied().unwrap_or(0) & 1;
    d.regs.insert(0x380dfc, gt);
    for domain in 1..13 {
        let (request, ack) = crate::intel_gpu_gt::media::domain_registers(domain);
        let awake = d.regs.get(&(request + GSI_OFFSET)).copied().unwrap_or(0) & 1;
        d.regs
            .insert(ack + GSI_OFFSET, if hw.stuck_wells { 0 } else { awake });
    }
    if d.regs.get(&0x38941c).copied().unwrap_or(0) != 0 {
        d.regs.insert(0x38941c, 0);
        d.regs.insert(0x38c000, 1);
        d.regs.insert(0x38c314, 0);
    }
    if d.regs.get(&0x38c314).copied().unwrap_or(0) & 1 != 0 {
        d.regs.insert(0x38c314, 0x10);
    }
    let last = |reg: u64, value: Option<u32>| {
        d.writes
            .iter()
            .rposition(|(r, v)| *r == reg && value.is_none_or(|value| *v == value))
    };
    if last(0x38c314, Some(0x0010_0000)) > last(0x38941c, None)
        && d.regs.get(&0x38c000) == Some(&1)
    {
        d.regs.insert(0x38c000, 0x8000_f000);
    }
    let header = d.regs.get(&0x190310).copied().unwrap_or(0);
    if header != 0 && header & (1 << 31) == 0 {
        d.regs.insert(
            0x190310,
            if header & 0xffff == 0x4509 {
                0xf000_0000
            } else {
                0xf000_0001
            },
        );
    }
}

/// Independent VCS/VECS model on the MTL media GT: dg2_xcs register state,
/// the plain or MI_FLUSH_DW breadcrumb, and for PPGTT jobs the GSI-adjusted
/// AUX invalidation ahead of the TLB-invalidating start stamp.
fn execute_media(w: &Window, base: u32, hw: &mut Hw) {
    let d = w.0.borrow();
    assert!(d.synced.contains(&base));
    let image = d.memory[&base].clone();
    let (engine, tail, ring_base, root) = {
        let data = image.borrow();
        assert_eq!(data.len(), 2048, "VCS/VECS LRC is PPHWSP + one page");
        let engine = data[1026] - 0x244;
        assert!((0x1c0000..0x200000).contains(&engine));
        assert_eq!(
            &data[1024..1031],
            &[
                0,
                0x1108101d,
                engine + 0x244,
                data[1027],
                engine + 0x34,
                0,
                engine + 0x30
            ]
        );
        // dg2_xcs_offsets carries CTX_TIMESTAMP(_UDW) in its first LRI.
        assert_eq!((data[1024 + 28], data[1024 + 30]), (engine + 0x120, engine + 0x124));
        assert_eq!(data[1024 + 0x21], 0x11081011);
        assert_eq!(data[1024 + 0x71], 0x01000000);
        let root = (u64::from(data[1024 + 0x31]) << 32) | u64::from(data[1024 + 0x33]);
        (engine, data[1024 + 7], data[1024 + 9], root)
    };
    assert!(d.synced.contains(&ring_base));
    let ring = d.memory[&ring_base].borrow().clone();
    drop(d);
    let mut words = &ring[..tail as usize / 4];
    if words[0] == 0x12480002 {
        assert_eq!(&words[..4], &[0x12480002, 0x3a8, base + 0x810, 0]);
        words = &words[4..];
    }
    let stamp = if words[..3] == [0x04000001, 0, 0x10400002] {
        assert_eq!(words[3], base + 0x800);
        words[5]
    } else {
        let at = words
            .windows(7)
            .rposition(|v| {
                v[..3] == [0x13004002, (base + 0x800) | 4, 0]
                    && v[4..] == [0x01000000, 0x04000001, 0x02800000]
            })
            .expect("video breadcrumb");
        words[at + 3]
    };
    assert_ne!(stamp, 0);
    if root != 0 {
        let aux = GSI_OFFSET as u32
            + if (engine & 0xc000) == 0x8000 {
                0x4238
            } else {
                0x4218
            };
        assert_eq!(
            &words[..6],
            &[0x04000001, 0x02800101, 0x11020001, aux, 1, 0]
        );
        let normalized: Vec<u32> = words[..2].iter().chain(&words[6..]).copied().collect();
        assert_eq!(
            &normalized[..7],
            &[
                0x04000001,
                0x02800101,
                0x13044002,
                (base + 0x808) | 4,
                0,
                stamp,
                0x02800100
            ]
        );
        if hw.drop_store != Some(engine) {
            execute_copy_ppgtt(root, &normalized[7..], false);
        }
        hw.ppgtt.push(engine);
    }
    image.borrow_mut()[0x800 / 4] = stamp;
    image.borrow_mut()[1024 + 5] = tail;
}

/// One model tick around a production poll: hardware first, then GuC CT
/// service and execution of every newly submitted context.
fn media_tick(
    guc: &mut MediaGuc<Window, Arena>,
    w: &Window,
    hw: &mut Hw,
    now: u64,
) -> Poll<Result<MediaGucState, MediaGucError>> {
    media_hw(w, hw);
    let polled = guc.poll(now, || true);
    let ct = w
        .0
        .borrow()
        .memory
        .values()
        .any(|backing| backing.borrow().len() == 6144);
    if ct && w.0.borrow().regs.get(&0x190310) == Some(&0xf000_0000) {
        let mut registered = core::mem::take(&mut hw.registered);
        service_contexts(w, &mut registered, false);
        let pending: Vec<u32> = registered
            .values()
            .copied()
            .filter(|base| !hw.executed.contains(base))
            .collect();
        for base in pending {
            let tail = w.0.borrow().memory[&base].borrow()[1024 + 7];
            if tail != 0 {
                execute_media(w, base, hw);
                hw.executed.insert(base);
            }
        }
        hw.registered = registered;
    }
    polled
}

fn media_until(
    guc: &mut MediaGuc<Window, Arena>,
    w: &Window,
    hw: &mut Hw,
    from: u64,
    done: impl Fn(&Poll<Result<MediaGucState, MediaGucError>>) -> bool,
) -> (u64, Poll<Result<MediaGucState, MediaGucError>>) {
    // One millisecond per tick: mailbox replies beat their 10 ms bound and
    // a stuck 50 ms forcewake acknowledgement really times out.
    for tick in 0..2000 {
        let now = from + tick * 1_000_000;
        let polled = media_tick(guc, w, hw, now);
        if done(&polled) {
            return (now, polled);
        }
    }
    panic!("media GuC made no progress");
}

fn start_media(w: &Window, arena: &Arena) -> MediaGuc<Window, Arena> {
    let firmware = GuCFirmware::from_fixture(MTL, &image()).unwrap();
    let media = MediaGt::initialized_for_test(MTL, MEDIA_GMD, FUSE);
    w.0.borrow_mut().regs.insert(0x380d00, RPM_CONFIG0);
    MediaGuc::start(w.clone(), arena.clone(), &firmware, media_config(), &media, 0).unwrap()
}

fn smoke_media_gt_sched_engines_prime_probe_publish_and_stop() -> TestResult {
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let publication = guc.publication().expect("published GT1");
    assert_eq!(publication.engines, media_engines());
    assert_eq!(publication.gmd, MEDIA_GMD);
    assert_eq!(publication.reference_clock, 19_200_000);
    assert_ne!(publication.epoch, 0);
    // Every published engine executed its own private PPGTT job.
    let mut ran = hw.ppgtt.clone();
    ran.sort_unstable();
    assert_eq!(ran, [0x1c0000, 0x1c8000, 0x1d0000]);
    {
        let d = w.0.borrow();
        // Only the fused VDBOX0/VDBOX2/VEBOX0 wells were requested.
        for (request, wanted) in [
            (0x38a540, true),
            (0x38a544, false),
            (0x38a548, true),
            (0x38a560, true),
            (0x38a564, false),
        ] {
            assert_eq!(
                d.writes.contains(&(request, 0x0001_0001)),
                wanted,
                "engine well request"
            );
        }
        for engine in media_engines().iter() {
            let base = u64::from(engine.base());
            // oam_mmio_trg grants, then RING_NOPID for every unused slot.
            for slot in 0..12u64 {
                let expected = crate::intel_gpu_nonpriv::MEDIA_OAM
                    .get(slot as usize)
                    .copied()
                    .unwrap_or(engine.base() + 0x94);
                assert_eq!(d.regs[&(base + 0x4d0 + slot * 4)], expected);
            }
            // xe_hw_engine_enable_ring with MTL's uncached MOCS 9.
            assert_eq!(d.regs[&(base + 0xc4)], 0x3f7e_0000 | 9 << 8 | 9 << 1);
            assert_eq!(d.regs[&(base + 0x29c)], 0x0008_0008);
            assert_ne!(d.regs[&(base + 0x80)], 0);
        }
        // Submission-enabled reload of the populated media ADS.
        assert_eq!(d.regs[&0x38c18c], 1 << 4);
        assert_eq!(d.media_ct, Some(true));
        let ads = d.memory[&0x20001000].borrow();
        // VIDEO logical 0,1 -> physical 0,2; VIDEOENHANCE logical 0 -> 0.
        assert_eq!(ads[(0x123c + 32) / 4], 0x2020_0200);
        assert_eq!(ads[(0x123c + 64) / 4], 0x2020_2000);
        assert_eq!(ads[(0x123c + 512) / 4], 0, "no render engine");
        assert_eq!(ads[(0x123c + 516) / 4], 0b101);
        assert_eq!(ads[(0x123c + 520) / 4], 0b1);
        assert_ne!(ads[0x1014 / 4 + 1], 0);
        assert_ne!(ads[0x1014 / 4 + 2], 0);
        assert_eq!(ads[0x1014 / 4], 0);
    }
    for engine in media_engines().iter() {
        let saves = ads_registers(&w, engine);
        let base = engine.base();
        let mut expected: Vec<u32> = [0x80, 0xa8, 0xc4, 0x29c]
            .into_iter()
            .chain((0..12).map(|slot| 0x4d0 + slot * 4))
            .map(|offset| base + offset)
            .collect();
        expected.sort_unstable();
        assert_eq!(saves.keys().copied().collect::<Vec<_>>(), expected);
        assert_eq!(saves[&(base + 0xc4)].1, 1);
        assert_eq!(saves[&(base + 0x29c)].1, 0);
    }
    // A real user job on VECS0 runs in GT1's epoch and retires.
    let context = UserContext::for_engine(Engine::Vecs0);
    let (batch, result) = PpgttProbeResult::prepare(MTL).unwrap();
    let (_, fence) = guc
        .submit_user(now + 1, context.clone(), UserBatch(batch), None)
        .unwrap();
    let (now, _) = media_until(&mut guc, &w, &mut hw, now + 2, |_| fence.result().is_some());
    assert_eq!(fence.result(), Some(Ok(())));
    assert_eq!(result.verify(), Ok(()));
    assert_eq!(context.check_epoch(publication.epoch), Ok(()));
    // An engine GT1 did not publish is refused before any allocation.
    let live = arena.live_allocations();
    let (batch, _) = PpgttProbeResult::prepare(MTL).unwrap();
    assert!(guc
        .submit_user(now, UserContext::for_engine(Engine::Vcs1), UserBatch(batch), None)
        .is_err());
    assert_eq!(arena.live_allocations(), live);
    // Verified stop: GuC reset, then media GRDOM_FULL, wells released last.
    let reset_from = w.0.borrow().writes.len();
    guc.begin_stop(now + 1);
    assert_eq!(guc.publication(), None);
    assert_eq!(w.0.borrow().media_ct, Some(false));
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    {
        let d = w.0.borrow();
        let writes = &d.writes[reset_from..];
        let guc_reset = writes.iter().position(|w| *w == (0x38941c, 8)).unwrap();
        let full = writes.iter().position(|w| *w == (0x38941c, 1)).unwrap();
        let sleep = writes.iter().position(|w| *w == (0x38a540, 0x0001_0000)).unwrap();
        assert!(guc_reset < full && full < sleep);
        for request in [0x38a548, 0x38a560] {
            assert!(writes.contains(&(request, 0x0001_0000)));
        }
        assert_eq!(d.media_tlb, Some(false));
        assert!(d.writes.iter().all(|(reg, _)| gt1_owned(*reg)));
        assert_eq!(d.regs[&0xa188], 1, "GT0 wake untouched");
        assert_eq!(d.gmd_reads, 0, "GT0 GMD_ID untouched");
    }
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_sched_engines_prime_probe_publish_and_stop
);

fn smoke_media_gt_sched_refusals_stop_and_publish_nothing() -> TestResult {
    // A lost engine well times out before any engine register is written.
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw {
        stuck_wells: true,
        ..Hw::default()
    };
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(
        polled,
        Poll::Ready(Err(MediaGucError::Wells(crate::intel_gpu_gt::media::MediaError::Timeout)))
    );
    hw.stuck_wells = false;
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 1, |p| {
        *p == Poll::Ready(Ok(MediaGucState::Stopped))
    });
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert_eq!(guc.publication(), None);
    assert!(!w.0.borrow().writes.iter().any(|(reg, _)| (0x1c0000..0x200000).contains(reg)));
    assert!(!w.0.borrow().writes.contains(&(0x38941c, 1)), "no scheduler, no GRDOM_FULL");
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // Loaded GSC firmware: scheduling is refused (no Wa_14015076503 owner).
    let (w, arena) = media_model();
    w.0.borrow_mut().regs.insert(0x116c40, 1 << 9);
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Err(MediaGucError::Gt(GtError::Busy))));
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 1, |p| {
        *p == Poll::Ready(Ok(MediaGucState::Stopped))
    });
    assert!(polled.is_ready());
    assert!(!w.0.borrow().writes.iter().any(|(reg, _)| (0x1c0000..0x200000).contains(reg)));
    assert!(!w.0.borrow().writes.contains(&(0x38941c, 1)));
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // An engine that runs its ring but loses its private store never
    // publishes GT1; the stop still resets the media GT and frees all.
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw {
        drop_store: Some(0x1c8000),
        ..Hw::default()
    };
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Err(MediaGucError::Probe)));
    assert_eq!(guc.publication(), None);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 1, |p| {
        *p == Poll::Ready(Ok(MediaGucState::Stopped))
    });
    assert!(polled.is_ready());
    {
        let d = w.0.borrow();
        assert!(d.writes.contains(&(0x38941c, 1)));
        assert!(d.writes.iter().all(|(reg, _)| gt1_owned(*reg)));
        assert_eq!(d.regs[&0xa188], 1, "GT0 wake untouched");
    }
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // Owner-level refusals: no render engine, no primary-only API.
    let (_, arena) = media_model();
    let all = EngineSet::of(&[Engine::Vcs0, Engine::Vecs0]);
    assert!(crate::intel_gpu_guc_sched::GuCScheduler::allocate_media(
        arena.clone(),
        MTL,
        EngineSet::of(&[Engine::Rcs0, Engine::Vcs0])
    )
    .is_err());
    assert!(crate::intel_gpu_guc_sched::GuCScheduler::allocate_media(
        arena.clone(),
        GtPlatform::Battlemage,
        all
    )
    .is_err());
    assert!(crate::intel_gpu_guc_sched::GuCScheduler::allocate_media(
        arena.clone(),
        MTL,
        EngineSet::default()
    )
    .is_err());
    let mut scheduler =
        crate::intel_gpu_guc_sched::GuCScheduler::allocate_media(arena.clone(), MTL, all).unwrap();
    assert!(scheduler.submit_probe(1).is_err());
    drop(scheduler);
    assert_eq!(arena.live_allocations(), 0);
    assert!(crate::intel_gpu_reset_policy::ResetPolicy::media(MTL, 0x7d55, all).is_some());
    assert!(crate::intel_gpu_reset_policy::ResetPolicy::media(
        MTL,
        0x7d55,
        EngineSet::of(&[Engine::Rcs0])
    )
    .is_none());
    assert!(crate::intel_gpu_nonpriv::EnginePolicy::media(MTL, all).is_ok());
    assert!(crate::intel_gpu_nonpriv::EnginePolicy::media(
        MTL,
        EngineSet::of(&[Engine::Bcs0])
    )
    .is_err());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_sched_refusals_stop_and_publish_nothing
);

fn smoke_media_gt_video_ring_ops_and_lrc_layout() -> TestResult {
    // __emit_job_gen12_video: AUX_INV + gt->mmio.adj_offset on GT1, the
    // unadjusted register on Gen12's single GT.
    for (engine, aux) in [(Engine::Vcs2, 0x384218), (Engine::Vecs0, 0x384238)] {
        let words = crate::intel_gpu_engine::media_ring_at(
            engine,
            GSI_OFFSET as u32,
            Some(0x1234_0000_0000),
            None,
            0x100_0000,
            9,
        );
        assert_eq!(&words[..6], &[0x04000001, 0x02800101, 0x11020001, aux, 1, 0]);
        let gen12 = crate::intel_gpu_engine::media_ring(engine, Some(0x1234_0000_0000), None, 0x100_0000, 9);
        assert_eq!(gen12[3], aux - GSI_OFFSET as u32);
        assert_eq!(&words[6..], &gen12[6..]);
    }
    // Empty media 13.00 WA job versus Gen12's graphics1200 lrc_was.
    assert!(crate::intel_gpu_engine::media_seed(MTL).is_empty());
    assert_eq!(
        crate::intel_gpu_engine::media_seed(GtPlatform::Gen12(
            crate::intel_gpu_gt::Gen12Platform::TigerLake
        )),
        crate::intel_gpu_engine::gen12_nonrender_seed()
    );
    // dg2_xcs_offsets for MTL VCS/VECS; Gen12 media keeps gen12_xcs.
    let image =
        crate::intel_gpu_engine::tests::Image(RefCell::new(alloc::vec![0; 2048]));
    crate::intel_gpu_engine::xcs_image(Engine::Vecs0, &image, MTL, 0x40_0000);
    assert_eq!(image.read32(4096 + 4), 0x1108101d);
    assert_eq!(
        (image.read32(4096 + 28 * 4), image.read32(4096 + 30 * 4)),
        (0x1c8120, 0x1c8124)
    );
    assert_eq!(Engine::Vecs0.first_lri(MTL), 0x1108101d);
    assert_eq!(Engine::Vecs0.lrc_pages(MTL), 2);
    let gen12 = crate::intel_gpu_engine::tests::Image(RefCell::new(alloc::vec![0; 2048]));
    crate::intel_gpu_engine::xcs_image(
        Engine::Vecs0,
        &gen12,
        GtPlatform::Gen12(crate::intel_gpu_gt::Gen12Platform::TigerLake),
        0x40_0000,
    );
    assert_eq!(gen12.read32(4096 + 4), 0x11081019);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_video_ring_ops_and_lrc_layout
);
