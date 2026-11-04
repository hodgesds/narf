use super::*;
use crate::{intel_gpu_engine::Engine, intel_gpu_timestamp::EngineCycles};

#[derive(Debug)]
struct StampReply {
    result: IrqSafeSpinLock<Option<Result<EngineCycles, FsError>>>,
    waker: IrqSafeSpinLock<Option<Waker>>,
}
#[derive(Debug)]
struct Timestamps {
    backend: Arc<dyn UserBackend>,
    pending: IrqSafeSpinLock<Vec<(Engine, i32, Arc<StampReply>)>>,
}
impl UserBackend for Timestamps {
    fn native_xe(&self) -> bool {
        true
    }
    fn status(&self) -> Option<UserStatus> {
        self.backend.status()
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        self.backend.device_facts()
    }
    fn engine_cycles(&self, engine: Engine, clock: i32) -> FsFuture<'_, EngineCycles> {
        Box::pin(async move {
            let reply = Arc::new(StampReply {
                result: IrqSafeSpinLock::new(None),
                waker: IrqSafeSpinLock::new(None),
            });
            self.pending.lock().push((engine, clock, reply.clone()));
            core::future::poll_fn(|cx| {
                *reply.waker.lock() = Some(cx.waker().clone());
                match reply.result.lock().take() {
                    Some(result) => Poll::Ready(result),
                    None => Poll::Pending,
                }
            })
            .await
        })
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.backend.submit(context, batch)
    }
}

fn query(user: &Cpu, size: u32) {
    let mut wire = [0; 40];
    put32(&mut wire, 8, 6);
    put32(&mut wire, 12, size);
    put64(&mut wire, 16, 0x2000);
    user.wire.store(64, &wire);
}

fn smoke_xe_engine_cycles_live_owner_and_query_snapshot() -> TestResult {
    for (platform, ack, upper, width, expected) in [
        (GtPlatform::Alchemist, 0x130044, 4, 36, 0x4_12345678),
        (
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake),
            0xdfc,
            4,
            36,
            0x4_12345678,
        ),
        (
            GtPlatform::Battlemage,
            0xdfc,
            0x01234567,
            64,
            0x0123456712345678,
        ),
    ] {
        let (w, arena, mut gt) = hardware_model(platform, ack);
        assert_eq!(gt.engine_cycles(Engine::Rcs0, 1), Err(GtError::State));
        prime(&mut gt, &w, ack);
        let (mailbox, mut info) = setup(&mut gt, &w, platform);
        let sampler = Arc::new(Timestamps {
            backend: info.backend.take().unwrap(),
            pending: IrqSafeSpinLock::new(Vec::new()),
        });
        info.backend = Some(sampler.clone());
        // Distinct per-engine RING_TIMESTAMP banks; the query must select.
        w.0.borrow_mut().regs.insert(0x235c, upper);
        w.0.borrow_mut().regs.insert(0x2358, 0x12345678);
        w.0.borrow_mut().regs.insert(0x2235c, upper ^ 1);
        w.0.borrow_mut().regs.insert(0x22358, 0x0badf00d);
        w.0.borrow_mut().regs.insert(0x1a35c, upper ^ 2);
        w.0.borrow_mut().regs.insert(0x1a358, 0x0c0ffee0);
        w.0.borrow_mut().regs.insert(0x3ee35c, upper ^ 3);
        w.0.borrow_mut().regs.insert(0x3ee358, 0x0bc58000);
        let present: Vec<Engine> = gt.engines().unwrap().iter().collect();
        let file = RenderFile::new();
        let user = Cpu::new();
        query(&user, 0);
        user.wire.store(80, &u64::MAX.to_le_bytes());
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        assert_eq!(u32_at(&user.wire.load(64, 40), 12), 40);
        for (engine, clock) in [0, 1, 4, 7]
            .into_iter()
            .flat_map(|clock| present.iter().map(move |engine| (*engine, clock)))
        {
            let expected = match engine {
                Engine::Rcs0 => expected,
                Engine::Bcs0 => u64::from(upper ^ 1) << 32 | 0x0badf00d,
                Engine::Bcs8 => u64::from(upper ^ 3) << 32 | 0x0bc58000,
                Engine::Ccs0 | Engine::Ccs1 | Engine::Ccs2 | Engine::Ccs3 => {
                    u64::from(upper ^ 2) << 32 | 0x0c0ffee0
                }
                _ => unreachable!("this fixture's platforms expose graphics engines"),
            };
            let mut payload = [0xa5; 40];
            payload[..6].fill(0);
            payload[..2].copy_from_slice(&engine.xe_class().to_le_bytes());
            payload[2..4].copy_from_slice(
                &gt.engines()
                    .unwrap()
                    .logical_instance(engine)
                    .unwrap()
                    .to_le_bytes(),
            );
            put32(&mut payload, 8, clock);
            user.wire.store(0x2000, &payload);
            query(&user, 40);
            assert_eq!(
                invoke(&file, &info, &user, xe::DEVICE_QUERY),
                Err(FsError::WouldBlock)
            );
            let mut call = core::pin::pin!(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let (sampled, captured, reply) = sampler.pending.lock().pop().unwrap();
            assert_eq!((sampled, captured), (engine, clock as i32));
            let before = narf_time::monotonic_ns();
            let stamp = gt.engine_cycles(sampled, captured).unwrap();
            let after = narf_time::monotonic_ns();
            if clock != 0 {
                assert!((before..=after).contains(&stamp.cpu_timestamp));
            }
            assert_eq!(stamp.engine_cycles, expected);
            assert_eq!(stamp.width, width);
            *reply.result.lock() = Some(Ok(stamp));
            if let Some(waker) = reply.waker.lock().take() {
                waker.wake();
            }
            // Copyout uses the retained destination and touches only outputs.
            user.wire.store(64, &[0xff; 40]);
            user.wire.store(0x2008, &[0x5a; 4]);
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Ok(0)))
            );
            let result = user.wire.load(0x2000, 40);
            assert_eq!(
                &result[2..4],
                &gt.engines()
                    .unwrap()
                    .logical_instance(engine)
                    .unwrap()
                    .to_le_bytes()
            );
            assert_eq!(&result[4..6], &[0; 2]);
            assert_eq!(&result[6..8], &[0xa5; 2]); // ignored pad, untouched
            assert_eq!(&result[8..12], &[0x5a; 4]);
            assert_eq!(u32_at(&result, 12), width);
            assert_eq!(u64_at(&result, 16), expected);
            assert_eq!(u64_at(&result, 24), stamp.cpu_timestamp);
            assert_eq!(u64_at(&result, 32), stamp.cpu_delta);
        }
        // VIDEO_DECODE class, logical instance 1, GT1, then bad clocks.
        for (eci, clock) in [(2, 1), (1 << 16, 1), (0, 11), (0, u32::MAX)] {
            let mut payload = [0; 40];
            put32(&mut payload, 0, eci);
            put32(&mut payload, 8, clock);
            user.wire.store(0x2000, &payload);
            query(&user, 40);
            let mut call = core::pin::pin!(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &user));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Err(FsError::InvalidData)))
            );
            assert!(sampler.pending.lock().is_empty());
        }
        *mailbox.status.lock() = None;
        let mut payload = [0; 40];
        put32(&mut payload, 8, 1);
        user.wire.store(0x2000, &payload);
        query(&user, 40);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::NoDevice)))
        );
        assert!(sampler.pending.lock().is_empty());
        let mut payload = [0; 40];
        put32(&mut payload, 4, 1); // gt_id 1
        put32(&mut payload, 8, 1);
        user.wire.store(0x2000, &payload);
        query(&user, 40);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
        let request = w.0.borrow().regs[&0xa188];
        w.0.borrow_mut().regs.insert(0xa188, request & !1);
        assert_eq!(gt.engine_cycles(Engine::Bcs0, 1), Err(GtError::WakeLost));
        assert_eq!(gt.state(), GtState::Lost);
        assert!(gt.user_epoch().is_none());
        w.0.borrow_mut().regs.insert(0xa188, request);
        hardware_stop(&mut gt, &w, ack);
        drop(gt);
        assert_eq!(arena.live_allocations(), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_engine_cycles_live_owner_and_query_snapshot
);

/// A backend whose published GT1 samples are answered by the test from the
/// real media GuC. GT0's `engine_cycles` keeps the trait default (ENOTSUP),
/// so a gt_id 1 query routed to GT0 cannot pass.
#[derive(Debug)]
struct MediaStamps {
    backend: Arc<dyn UserBackend>,
    pending: IrqSafeSpinLock<Vec<(Engine, i32, Arc<StampReply>)>>,
}
impl UserBackend for MediaStamps {
    fn native_xe(&self) -> bool {
        true
    }
    fn status(&self) -> Option<UserStatus> {
        self.backend.status()
    }
    fn media_gt(&self) -> Option<crate::intel_gpu_user::MediaGtStatus> {
        self.backend.media_gt()
    }
    fn device_facts(&self) -> Option<crate::intel_gpu_user::DeviceFacts> {
        self.backend.device_facts()
    }
    fn media_engine_cycles(&self, engine: Engine, clock: i32) -> FsFuture<'_, EngineCycles> {
        Box::pin(async move {
            let reply = Arc::new(StampReply {
                result: IrqSafeSpinLock::new(None),
                waker: IrqSafeSpinLock::new(None),
            });
            self.pending.lock().push((engine, clock, reply.clone()));
            core::future::poll_fn(|cx| {
                *reply.waker.lock() = Some(cx.waker().clone());
                match reply.result.lock().take() {
                    Some(result) => Poll::Ready(result),
                    None => Poll::Pending,
                }
            })
            .await
        })
    }
    fn submit<'a>(
        &'a self,
        context: Arc<UserContext>,
        batch: UserBatch,
    ) -> FsFuture<'a, Arc<CompletionFence>> {
        self.backend.submit(context, batch)
    }
}

fn media_cycles_payload(user: &Cpu, class: u16, logical: u16, gt_id: u16, clock: u32) {
    let mut payload = [0xa5; 40];
    payload[..2].copy_from_slice(&class.to_le_bytes());
    payload[2..4].copy_from_slice(&logical.to_le_bytes());
    payload[4..6].copy_from_slice(&gt_id.to_le_bytes());
    put32(&mut payload, 8, clock);
    user.wire.store(0x2000, &payload);
    query(user, 40);
}

/// DRM_XE_DEVICE_QUERY_ENGINE_CYCLES and DRM_XE_DEVICE_QUERY_GT_TOPOLOGY for
/// the published MTL/Arrow media GT, following xe_query.c: gt_id 1 resolves
/// through xe_device_get_gt only while GT1 is published, then
/// xe_gt_hw_engine(.., logical) on GT1; RING_TIMESTAMP is read at the media
/// engine's absolute base (above MEDIA_GT_GSI_LENGTH) under GT1's wake and
/// wells; the topology appends GT1's own fuse mirrors after GT0's. Without
/// a published GT1 both queries are byte-for-byte GT0-only.
fn smoke_xe_mtl_media_gt1_engine_cycles_and_topology() -> TestResult {
    use super::super::super::media_gt_sched::{media_until, start_media_with, Hw};
    use crate::intel_gpu_gt::media::{MediaGucError, MediaGucState, MediaTopology};
    let platform = GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake);
    let (w, arena, mut gt) = hardware_model(platform, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let file = RenderFile::new();
    let user = Cpu::new();
    // Unpublished GT1 (option off): GT0-only topology, gt_id 1 is EINVAL.
    let (_, off) = setup(&mut gt, &w, platform);
    let gt0_topology = xe_query(&file, &off, &user, 5);
    let mut at = 0;
    let mut gt0_entries = 0;
    while at < gt0_topology.len() {
        assert_eq!(&gt0_topology[at..at + 2], &[0, 0], "GT0 entries only");
        at += 8 + u32_at(&gt0_topology, at + 4) as usize;
        gt0_entries += 1;
    }
    // Geometry, compute, L3 bank and EU: query_gt_topology now reports GT0's
    // L3 entry too (MEML3_EN node 0 with GT_L3_EXC_MASK pair 0 = banks 0-1).
    assert_eq!((at, gt0_entries), (gt0_topology.len(), 4));
    assert_eq!(
        &gt0_topology[24..40],
        &[0, 0, 3, 0, 8, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]
    );
    for (class, logical) in [(2, 0), (3, 0), (0, 0)] {
        media_cycles_payload(&user, class, logical, 1, 1);
        let mut call = core::pin::pin!(file.dispatch_user(&off, xe::DEVICE_QUERY, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
    }
    // GT1 on its own media GuC model with observed topology fuses.
    let (mw, marena) = media_model();
    let topology = MediaTopology {
        geometry: 0,
        compute: 0x5,
        eu_per_dss: 0x00f3,
        l3_bank: 0x0f0f,
    };
    let mut guc = start_media_with(&mw, &marena, topology);
    assert_eq!(
        guc.engine_cycles(0, Engine::Vcs0, 1),
        Err(GtError::State),
        "no sample before publication"
    );
    let mut hw = Hw::default();
    let (now, polled) = media_until(&mut guc, &mw, &mut hw, 1, |p| p.is_ready());
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Running)));
    let publication = guc.publication().unwrap();
    assert_eq!(publication.topology, topology);
    let status = crate::intel_gpu_user::MediaGtStatus {
        epoch: publication.epoch,
        engines: publication.engines,
        gmd: publication.gmd,
        reference_clock: publication.reference_clock,
        topology: publication.topology,
    };
    let (_, mut info) = setup_media(&mut gt, &w, platform, Some(status));
    let sampler = Arc::new(MediaStamps {
        backend: info.backend.take().unwrap(),
        pending: IrqSafeSpinLock::new(Vec::new()),
    });
    info.backend = Some(sampler.clone());
    // query_gt_topology: GT0's entries unchanged, then GT1's geometry,
    // compute, 8-byte L3 bank (xe_gt_topology_report_l3: media before 30)
    // and SIMD8 EU-per-DSS masks with gt_id 1.
    let topo = xe_query(&file, &info, &user, 5);
    assert_eq!(&topo[..gt0_topology.len()], &gt0_topology[..]);
    assert_eq!(
        &topo[gt0_topology.len()..],
        &[
            1, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0, 0, // DSS_GEOMETRY
            1, 0, 2, 0, 4, 0, 0, 0, 5, 0, 0, 0, // DSS_COMPUTE
            1, 0, 3, 0, 8, 0, 0, 0, 0x0f, 0x0f, 0, 0, 0, 0, 0, 0, // L3_BANK
            1, 0, 4, 0, 2, 0, 0, 0, 0xf3, 0, // EU_PER_DSS (SIMD8)
        ]
    );
    // Per-engine RING_TIMESTAMP banks at the absolute media engine bases;
    // the GSI-shifted alias of each bank holds a decoy.
    for (base, upper, lower) in [
        (0x1c0000u64, 0x3, 0x1111_1111),
        (0x1d0000, 0x5, 0x2222_2222),
        (0x1c8000, 0x7, 0x3333_3333),
    ] {
        let mut d = mw.0.borrow_mut();
        d.regs.insert(base + 0x35c, upper);
        d.regs.insert(base + 0x358, lower);
        d.regs.insert(base + 0x380000 + 0x35c, 0xf);
        d.regs.insert(base + 0x380000 + 0x358, 0xdead_beef);
    }
    let mut now = now;
    for (class, logical, engine, expected) in [
        (2u16, 0u16, Engine::Vcs0, 0x3_1111_1111u64),
        (2, 1, Engine::Vcs2, 0x5_2222_2222),
        (3, 0, Engine::Vecs0, 0x7_3333_3333),
    ] {
        for clock in [0, 1, 4, 7] {
            media_cycles_payload(&user, class, logical, 1, clock);
            let mut call = core::pin::pin!(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &user));
            assert!(call
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            let (sampled, captured, reply) = sampler.pending.lock().pop().unwrap();
            assert_eq!((sampled, captured), (engine, clock as i32));
            now += 1;
            let stamp = guc.engine_cycles(now, sampled, captured).unwrap();
            assert_eq!(stamp.engine_cycles, expected);
            assert_eq!(stamp.width, 36, "GRAPHICS_VER < 20");
            *reply.result.lock() = Some(Ok(stamp));
            if let Some(waker) = reply.waker.lock().take() {
                waker.wake();
            }
            user.wire.store(0x2008, &[0x5a; 4]);
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Ok(0)))
            );
            let result = user.wire.load(0x2000, 40);
            assert_eq!(u16::from_le_bytes([result[0], result[1]]), class);
            assert_eq!(u16::from_le_bytes([result[2], result[3]]), logical);
            assert_eq!(&result[4..6], &[1, 0], "gt_id untouched");
            assert_eq!(&result[6..8], &[0xa5; 2], "ignored pad untouched");
            assert_eq!(&result[8..12], &[0x5a; 4]);
            assert_eq!(u32_at(&result, 12), 36);
            assert_eq!(u64_at(&result, 16), expected);
            assert_eq!(u64_at(&result, 24), stamp.cpu_timestamp);
            assert_eq!(u64_at(&result, 32), stamp.cpu_delta);
        }
    }
    // Linux-ordered EINVALs with GT1 published, none reaching a sampler:
    // a bad clock, GT1 render/copy/compute, an absent GT1 logical instance,
    // an out-of-table class, an unknown gt_id, and VCS named on GT0.
    for (class, logical, gt_id, clock) in [
        (2u16, 0u16, 1u16, 11u32),
        (0, 0, 1, 1),
        (1, 0, 1, 1),
        (4, 0, 1, 1),
        (2, 2, 1, 1),
        (3, 1, 1, 1),
        (5, 0, 1, 1),
        (2, 0, 2, 1),
        (2, 0, u16::MAX, 1),
        (2, 0, 0, 1),
        (3, 0, 0, 1),
    ] {
        media_cycles_payload(&user, class, logical, gt_id, clock);
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::DEVICE_QUERY, 64, &user));
        assert_eq!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Some(Err(FsError::InvalidData)))
        );
        assert!(sampler.pending.lock().is_empty());
    }
    // A lost VDBOX well (Linux: XE_FORCEWAKE_ALL not held) fails the sample,
    // unpublishes GT1 and starts the media GuC's verified stop.
    mw.0.borrow_mut().regs.insert(0x380d50, 0);
    assert_eq!(
        guc.engine_cycles(now + 1, Engine::Vcs0, 1),
        Err(GtError::WakeLost)
    );
    assert_eq!(guc.publication(), None);
    assert_eq!(guc.state(), MediaGucState::Stopping);
    assert_eq!(guc.error(), Some(MediaGucError::Gt(GtError::WakeLost)));
    assert_eq!(guc.engine_cycles(now + 2, Engine::Vcs0, 1), Err(GtError::State));
    let (_, polled) = media_until(&mut guc, &mw, &mut hw, now + 3, |p| {
        *p == Poll::Ready(Ok(MediaGucState::Stopped))
    });
    assert_eq!(polled, Poll::Ready(Ok(MediaGucState::Stopped)));
    assert!(guc.reclaimable());
    drop(guc);
    assert_eq!(marena.live_allocations(), 0);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_media_gt",
    smoke_xe_mtl_media_gt1_engine_cycles_and_topology
);
