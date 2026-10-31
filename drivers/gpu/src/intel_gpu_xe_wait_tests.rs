// Infinite waits use the existing syscall park/reexecute contract. Finite
// relative deadlines remain in their original future across timer wakes.
use super::*;
use core::sync::atomic::{AtomicU64, Ordering};

struct RestartWait {
    cpu: Cpu,
    repoll_ns: AtomicU64,
}
impl IoctlContext for RestartWait {
    fn read(&self, address: u64, data: &mut [u8]) -> Result<(), FsError> {
        self.cpu.read(address, data)
    }
    fn write(&self, address: u64, data: &[u8]) -> Result<(), FsError> {
        self.cpu.write(address, data)
    }
    fn read_u64_acquire(&self, address: u64) -> Result<u64, FsError> {
        self.cpu.read_u64_acquire(address)
    }
    fn nonblocking(&self) -> bool {
        false
    }
    fn restart_after(&self, ns: u64) -> bool {
        self.repoll_ns.store(ns, Ordering::Release);
        true
    }
}

fn smoke_xe_infinite_user_wait_restarts_without_changing_deadlines() -> TestResult {
    let (w, arena, mut gt) = hardware_model(GtPlatform::Battlemage, 0xdfc);
    prime(&mut gt, &w, 0xdfc);
    let (_, info) = setup(&mut gt, &w, GtPlatform::Battlemage);
    let file = RenderFile::new();
    let user = RestartWait {
        cpu: Cpu::new(),
        repoll_ns: AtomicU64::new(0),
    };
    for timeout in [-1i64, i64::MIN] {
        for flags in [0u16, 1] {
            let mut wire = [0; 72];
            put64(&mut wire, 8, 0x6000);
            wire[18..20].copy_from_slice(&flags.to_le_bytes());
            put64(&mut wire, 24, 1);
            put64(&mut wire, 32, u64::MAX);
            put64(&mut wire, 40, timeout as u64);
            user.cpu.wire.store(64, &wire);
            user.cpu.wire.store(0x6000, &0u64.to_le_bytes());
            user.repoll_ns.store(0, Ordering::Release);
            {
                let mut call =
                    core::pin::pin!(file.dispatch_user(&info, xe::WAIT_USER_FENCE, 64, &user));
                assert_eq!(
                    call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Some(Err(FsError::WouldBlock)))
                );
            }
            assert_eq!(user.repoll_ns.load(Ordering::Acquire), 100_000);
            assert_eq!(user.cpu.wire.load(64, 72), wire);
            // The reexecuted call observes completion before requesting park.
            user.cpu.wire.store(0x6000, &1u64.to_le_bytes());
            user.repoll_ns.store(0, Ordering::Release);
            let mut call =
                core::pin::pin!(file.dispatch_user(&info, xe::WAIT_USER_FENCE, 64, &user));
            assert_eq!(
                call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Some(Ok(0)))
            );
            assert_eq!(user.repoll_ns.load(Ordering::Acquire), 0);
        }
    }
    let mut wire = [0; 72];
    put64(&mut wire, 8, 0x6000);
    put64(&mut wire, 24, 1);
    put64(&mut wire, 32, u64::MAX);
    user.cpu.wire.store(0x6000, &0u64.to_le_bytes());
    // Immediate timeout never parks or silently extends a relative deadline.
    user.cpu.wire.store(64, &wire);
    let mut call = core::pin::pin!(file.dispatch_user(&info, xe::WAIT_USER_FENCE, 64, &user));
    assert_eq!(
        call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Err(FsError::TimedOut)))
    );
    assert_eq!(user.repoll_ns.load(Ordering::Acquire), 0);
    put64(&mut wire, 40, 1_000_000_000);
    user.cpu.wire.store(64, &wire);
    {
        let mut call = core::pin::pin!(file.dispatch_user(&info, xe::WAIT_USER_FENCE, 64, &user));
        assert!(matches!(
            call.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending | Poll::Ready(Some(Err(FsError::TimedOut)))
        ));
    }
    assert_eq!(user.repoll_ns.load(Ordering::Acquire), 0);
    hardware_stop(&mut gt, &w, 0xdfc);
    drop(gt);
    assert_eq!(arena.live_allocations(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_user",
    smoke_xe_infinite_user_wait_restarts_without_changing_deadlines
);
