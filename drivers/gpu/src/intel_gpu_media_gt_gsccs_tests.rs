// GSCCS0 as a kernel-only engine of the MTL/Arrow standalone media GuC,
// through the production MediaGuc/GuCGt/GuCBoot/scheduler owners on the GuC
// model. Literal identities follow MIT Linux b90c984d: xe_hw_engine.c
// (engine_infos[XE_HW_ENGINE_GSCCS0], hw_engine_setup_default_state's "MTL
// GSCCS IDLE MSG enable", hw_engine_init_early's 600 ms preempt floor,
// xe_hw_engine_is_reserved), xe_force_wake.c (XE_FW_GSC), xe_guc_ads.c
// (GUC_GSC_OTHER_CLASS mapping/enable masks, golden LRC, regsets), xe_lrc.c
// dg2_xcs_offsets, xe_ring_ops.c emit_job_gen12_gsc and
// instructions/xe_gsc_commands.h.
use super::media_gt_sched::{media_tick, media_until, start_media, Hw};
use super::*;
use crate::intel_gpu_engine::{Engine, EngineSet};
use crate::intel_gpu_gt::media::gsc::load::{Gsccs, LoadError};
use crate::intel_gpu_gt::media::{GscQueue, MediaGucState, GSI_OFFSET};

const GSCCS: u64 = 0x11a000;

fn gsccs_reg(offset: u64) -> bool {
    (GSCCS..GSCCS + 0x2000).contains(&offset)
}

/// Engine identity, policy tables and the reserved-class exclusions, without
/// a GuC: every value is the xe_hw_engine.c / regs literal.
fn smoke_media_gt_gsccs_identity_policy_and_reserved_exclusion() -> TestResult {
    let gsc = Engine::Gsccs0;
    assert_eq!(Engine::COUNT, 20);
    assert_eq!(Engine::ALL[19], gsc);
    assert_eq!(gsc.index(), 19);
    // GSCCS_RING_BASE, GUC_GSC_OTHER_CLASS, XE_ENGINE_CLASS_OTHER,
    // OTHER_GSC_INSTANCE.
    assert_eq!(
        (
            gsc.base(),
            gsc.guc_class(),
            gsc.hw_class(),
            gsc.physical_instance()
        ),
        (0x11a000, 5, 4, 6)
    );
    // ENGINE_ID class for the other engines is unchanged by the GSC entry.
    for (engine, class) in [
        (Engine::Rcs0, 0),
        (Engine::Vcs3, 1),
        (Engine::Vecs1, 2),
        (Engine::Bcs8, 3),
        (Engine::Ccs2, 5),
    ] {
        assert_eq!(engine.hw_class(), class);
    }
    // xe_gt_lrc_size: PPHWSP plus one page; dg2_xcs_offsets on MTL.
    assert_eq!(gsc.lrc_pages(MTL), 2);
    assert_eq!(gsc.first_lri(MTL), 0x1108101d);
    assert!(gsc.simple_ring() && gsc.reserved() && gsc.is_gsc());
    assert!(!gsc.is_media() && !gsc.is_copy() && !gsc.is_compute());
    assert_eq!(gsc.xe_class(), crate::intel_gpu_engine::RESERVED_CLASS);
    // No UAPI lookup resolves a reserved engine, even in a set holding it.
    let set = EngineSet::of(&[Engine::Vcs0, Engine::Vecs0, gsc]);
    for class in [0, 1, 2, 3, 4, 5, crate::intel_gpu_engine::RESERVED_CLASS] {
        for logical in 0..2 {
            assert_ne!(set.from_class_instance(class, logical), Some(gsc));
        }
    }
    assert_eq!(set.from_class_instance(2, 0), Some(Engine::Vcs0));
    assert_eq!(set.logical_mask(EngineSet::of(&[gsc])), None);
    assert_eq!(set.logical_instance(gsc), Some(0));
    // ENGINE_ID class OTHER (4), instance 6; never confused with COMPUTE (5).
    assert_eq!(set.decode_hardware_id(4 | 6 << 4), Some(gsc));
    assert_eq!(set.decode_hardware_id(5 | 6 << 4), None);
    // XE_FW_GSC: FORCEWAKE_GSC / FORCEWAKE_ACK_GSC, GSI-translated on GT1.
    let gsc_domain = crate::intel_gpu_gt::media::GSC_DOMAIN;
    assert_eq!(gsc_domain, 13);
    assert_eq!(
        crate::intel_gpu_gt::media::domain_registers(gsc_domain),
        (0xa618, 0xdf8)
    );
    assert_eq!(
        crate::intel_gpu_gt::media::engine_domains(set),
        1 << 1 | 1 << 9 | 1 << 13
    );
    // The 600 ms preempt floor for class OTHER only.
    assert_eq!(crate::intel_gpu_guc_sched::preemption_timeout_us(gsc), 600_000);
    for engine in [Engine::Rcs0, Engine::Vcs0, Engine::Vecs0, Engine::Bcs0] {
        assert_eq!(
            crate::intel_gpu_guc_sched::preemption_timeout_us(engine),
            500_000
        );
    }
    // The kernel queue admits only the worker's two GSC instruction shapes.
    use crate::intel_gpu_gt::media::gsc::{fw_load, heci_packet};
    assert!(crate::intel_gpu_engine::gsc_job_valid(&fw_load(
        0x0100_0000,
        4 << 20
    )));
    assert!(crate::intel_gpu_engine::gsc_job_valid(
        &heci_packet(0x0050_0000, 40, 0x0050_1000, 4096).unwrap()
    ));
    for refused in [
        &[][..],
        &[0x0500_0000][..],
        &[0x4040_0002, 0x0100_0000, 0, 0x400][..],
        &[0x4040_0002, 0x0100_0000, 1, 0x8000_0400][..],
        &[0x4040_0002, 0x0100_0000, 0, 0x8000_0000][..],
        &[0x4000_0006, 0x0050_0000, 0, 35, 0x0050_1000, 0, 4096, 0][..],
        &[0x4000_0006, 0x0050_0000, 0, 40, 0x0050_1000, 0, 4096, 0x0500_0000][..],
        &[0x4000_0006, 0x0050_0000, 0, 40, 0x0050_1000, 0, 4096][..],
    ] {
        assert!(!crate::intel_gpu_engine::gsc_job_valid(refused));
    }
    // reg_sr adds the masked RING_PSMI_CTL and RING_PWRCTX_MAXCNT; no
    // whitelist grant, so every NONPRIV slot is the GSC engine's NOPID.
    let policy = crate::intel_gpu_reset_policy::ResetPolicy::media(MTL, 0x7d55, set).unwrap();
    let saves = policy.registers(gsc).unwrap();
    let flags = |offset: u32| {
        saves
            .iter()
            .find(|save| save.offset == 0x11a000 + offset)
            .map(|save| save.flags)
    };
    assert_eq!(
        [0x50, 0x54, 0x80, 0xa8, 0xc4, 0x29c].map(flags),
        [Some(1), Some(0), Some(0), Some(0), Some(1), Some(0)]
    );
    assert!((0..12).all(|slot| flags(0x4d0 + slot * 4) == Some(0)));
    assert!(policy
        .registers(Engine::Vcs0)
        .unwrap()
        .iter()
        .all(|save| save.offset != 0x1c0050 && save.offset != 0x1c0054));
    // A media set needs a VCS/VECS: GSCCS0 alone, or with a GT0 engine, is
    // refused by every media policy.
    for refused in [
        EngineSet::of(&[gsc]),
        EngineSet::of(&[Engine::Vcs0, gsc, Engine::Rcs0]),
    ] {
        assert!(crate::intel_gpu_reset_policy::ResetPolicy::media(MTL, 0x7d55, refused).is_none());
        assert!(crate::intel_gpu_nonpriv::EnginePolicy::media(MTL, refused).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_gsccs_identity_policy_and_reserved_exclusion
);

/// Drive ticks until the GSC queue's job finishes.
fn finish_gsc_job(
    guc: &mut crate::intel_gpu_gt::media::MediaGuc<Window, Arena>,
    w: &Window,
    hw: &mut Hw,
    from: u64,
) -> (u64, Result<(), LoadError>) {
    for tick in 0..2000 {
        let now = from + tick * 1_000_000;
        let polled = media_tick(guc, w, hw, now);
        assert!(!matches!(polled, Poll::Ready(Err(_))), "{polled:?}");
        assert_eq!(guc.state(), MediaGucState::Running);
        if let Some(result) = GscQueue::new(guc, now).finished() {
            return (now, result);
        }
    }
    panic!("GSC job never retired");
}

/// `narf.intel.gsc=1` with available firmware: GSCCS0 is scheduled beside
/// the fused VCS/VECS under its own XE_FW_GSC wake, gets its idle-message
/// pair, ring enable, NOPID-only NONPRIV, ADS class entry, regsets and
/// golden LRC (an empty WA job), and executes exactly the GSC instructions
/// the kernel queue admits. It is never published, placed or sampled, and
/// the verified stop releases its wake with the others. Without the option
/// no GSCCS register or GSC wake is ever written.
fn smoke_media_gt_gsccs_schedules_primes_and_executes_gsc_jobs() -> TestResult {
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    assert!(!guc.gsccs_scheduled());
    guc.schedule_gsccs().unwrap();
    assert!(guc.gsccs_scheduled());
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    // Too late once scheduling started.
    assert_eq!(
        guc.schedule_gsccs(),
        Err(crate::intel_gpu_gt::media::MediaGucError::State)
    );
    let publication = guc.publication().expect("published GT1");
    assert_eq!(
        publication.engines,
        EngineSet::of(&[Engine::Vcs0, Engine::Vcs2, Engine::Vecs0])
    );
    // Priming ran GSCCS0's empty WA job; no GSC instruction yet.
    assert!(hw.gsc_jobs.is_empty());
    assert_eq!(hw.gsc_empty, 1);
    {
        let d = w.0.borrow();
        let fw = GSI_OFFSET + 0xa618;
        assert!(d.writes.contains(&(fw, 0x0001_0001)), "XE_FW_GSC requested");
        let idle = d.writes.iter().position(|w| *w == (GSCCS + 0x50, 0x0001_0000));
        let maxcnt = d.writes.iter().position(|w| *w == (GSCCS + 0x54, 0xa));
        let mode = d.writes.iter().position(|w| *w == (GSCCS + 0x29c, 0x0008_0008));
        assert!(idle.unwrap() < maxcnt.unwrap() && maxcnt.unwrap() < mode.unwrap());
        assert_eq!(d.regs[&(GSCCS + 0xc4)], 0x3f7e_0000 | 9 << 8 | 9 << 1);
        assert_eq!(d.regs[&(GSCCS + 0xa8)], u32::MAX);
        assert_ne!(d.regs[&(GSCCS + 0x80)], 0);
        for slot in 0..12u64 {
            assert_eq!(d.regs[&(GSCCS + 0x4d0 + slot * 4)], 0x11a094);
        }
        let ads = d.memory[&0x20001000].borrow();
        // GUC_GSC_OTHER_CLASS logical 0 -> OTHER_GSC_INSTANCE, enable bit 6,
        // its own golden LRC and size (one page minus the 96-dword header).
        assert_eq!(ads[(0x123c + 5 * 32) / 4] & 0xff, 6);
        assert_eq!(ads[(0x123c + 512 + 5 * 4) / 4], 1 << 6);
        assert_ne!(ads[0x1014 / 4 + 5], 0);
        assert_eq!(ads[0x1054 / 4 + 5], 4096 - 96 * 4);
        // The VCS/VECS entries are those of the GSC-less media GT.
        assert_eq!(ads[(0x123c + 516) / 4], 0b101);
        assert_eq!(ads[(0x123c + 520) / 4], 0b1);
    }
    let saves = ads_registers(&w, Engine::Gsccs0);
    let expected: Vec<u32> = [0x50, 0x54, 0x80, 0xa8, 0xc4, 0x29c]
        .into_iter()
        .chain((0..12).map(|slot| 0x4d0 + slot * 4))
        .map(|offset| 0x11a000 + offset)
        .collect();
    assert_eq!(saves.keys().copied().collect::<Vec<_>>(), expected);
    assert_eq!(
        [0x11a050, 0x11a054, 0x11a0c4].map(|reg| saves[&reg].1),
        [1, 0, 1]
    );
    // GT1's user surfaces never reach GSCCS0.
    let live = arena.live_allocations();
    let (batch, _) = crate::intel_gpu_exec::PpgttProbeResult::prepare(MTL).unwrap();
    assert!(guc
        .submit_user(
            now,
            crate::intel_gpu_user::UserContext::for_engine(Engine::Gsccs0),
            crate::intel_gpu_user::UserBatch(batch),
            None
        )
        .is_err());
    assert!(guc.engine_cycles(now, Engine::Gsccs0, 1).is_err());
    // A command stream the queue does not admit allocates nothing.
    let mut queue = GscQueue::new(&mut guc, now);
    assert!(queue.holds_wake());
    assert_eq!(queue.submit(&[0x0500_0000]), Err(LoadError::Invalid));
    assert_eq!(queue.finished(), None);
    drop(queue);
    assert_eq!(arena.live_allocations(), live);
    // GSC_FW_LOAD, then a GSC_HECI_CMD_PKT, each inline on GSCCS0.
    let load = crate::intel_gpu_gt::media::gsc::fw_load(0x0100_0000, 4 << 20);
    let mut queue = GscQueue::new(&mut guc, now + 1);
    queue.submit(&load).unwrap();
    // One job at a time: the worker never queues behind an unretired job.
    assert_eq!(queue.submit(&load), Err(LoadError::Queue));
    drop(queue);
    let (now, result) = finish_gsc_job(&mut guc, &w, &mut hw, now + 2);
    assert_eq!(result, Ok(()));
    let packet =
        crate::intel_gpu_gt::media::gsc::heci_packet(0x0050_0000, 40, 0x0050_1000, 4096).unwrap();
    GscQueue::new(&mut guc, now + 1).submit(&packet).unwrap();
    let (now, result) = finish_gsc_job(&mut guc, &w, &mut hw, now + 2);
    assert_eq!(result, Ok(()));
    assert_eq!(hw.gsc_jobs, [load.to_vec(), packet.to_vec()]);
    // Verified stop: GuC reset, media GRDOM_FULL, then every well, GSC's
    // included, released; nothing is published meanwhile.
    let from = w.0.borrow().writes.len();
    guc.begin_stop(now + 1);
    assert!(GscQueue::new(&mut guc, now + 1).submit(&load).is_err());
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    {
        let d = w.0.borrow();
        let writes = &d.writes[from..];
        let full = writes.iter().position(|w| *w == (0x38941c, 1)).unwrap();
        let sleep = writes
            .iter()
            .position(|w| *w == (GSI_OFFSET + 0xa618, 0x0001_0000))
            .unwrap();
        assert!(full < sleep);
        assert!(d
            .writes
            .iter()
            .all(|(reg, _)| gsccs_reg(*reg) || (0x380000..0x3c0000).contains(reg)
                || (0x1c0000..0x200000).contains(reg)
                || (0x190304..=0x19031c).contains(reg)
                || matches!(*reg, 0x13816c | 0x1900e8)));
        assert_eq!(d.regs[&0xa188], 1, "GT0 wake untouched");
    }
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);

    // Option off: the same GT1 never touches GSCCS0 or XE_FW_GSC.
    let (w, arena) = media_model();
    let mut guc = start_media(&w, &arena);
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &w, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    assert!(GscQueue::new(&mut guc, now).submit(&load).is_err());
    guc.begin_stop(now + 1);
    let (_, polled) = media_until(&mut guc, &w, &mut hw, now + 2, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    {
        let d = w.0.borrow();
        assert!(!d
            .writes
            .iter()
            .any(|(reg, _)| gsccs_reg(*reg) || *reg == GSI_OFFSET + 0xa618));
        let ads = d.memory[&0x20001000].borrow();
        assert_eq!(ads[(0x123c + 512 + 5 * 4) / 4], 0);
    }
    assert_eq!((hw.gsc_jobs.len(), hw.gsc_empty), (0, 0));
    drop(guc);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_media_gt_gsccs_schedules_primes_and_executes_gsc_jobs
);
