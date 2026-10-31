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
        let file = RenderFile::new();
        let user = Cpu::new();
        query(&user, 0);
        user.wire.store(80, &u64::MAX.to_le_bytes());
        assert_eq!(invoke(&file, &info, &user, xe::DEVICE_QUERY), Ok(0));
        assert_eq!(u32_at(&user.wire.load(64, 40), 12), 40);
        for (engine, clock) in [0, 1, 4, 7]
            .into_iter()
            .flat_map(|clock| Engine::ALL.map(|engine| (engine, clock)))
        {
            let expected = if engine == Engine::Rcs0 {
                expected
            } else {
                u64::from(upper ^ 1) << 32 | 0x0badf00d
            };
            let mut payload = [0xa5; 40];
            payload[..6].fill(0);
            payload[..2].copy_from_slice(&engine.xe_class().to_le_bytes());
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
            assert_eq!(&result[2..6], &[0; 4]);
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
