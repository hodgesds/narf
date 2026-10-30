use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

#[derive(Copy, Clone, Debug)]
struct Failure {
    config: PhysAddr,
    callback: Option<fn()>,
    consumed: bool,
    arm: bool,
}

static FAILURE: IrqSafeSpinLock<Option<Failure>> = IrqSafeSpinLock::new(None);

/// Scoped loss of one arm receipt after the real native config write.
/// Kernel-test only; confining it to one config window prevents an unrelated
/// device's source from being affected by the fixture.
#[derive(Debug)]
pub struct ReadbackFailure;

pub fn __test_arm_readback_failure(config: PhysAddr, callback: Option<fn()>) -> ReadbackFailure {
    install(config, callback, true)
}

pub fn __test_disarm_readback_failure(config: PhysAddr) -> ReadbackFailure {
    install(config, None, false)
}

fn install(config: PhysAddr, callback: Option<fn()>, arm: bool) -> ReadbackFailure {
    let mut failure = FAILURE.lock();
    assert!(failure.is_none(), "nested PME receipt fixture");
    *failure = Some(Failure {
        config,
        callback,
        consumed: false,
        arm,
    });
    ReadbackFailure
}

pub(super) fn fail_readback(config: PhysAddr, arm: bool) -> bool {
    let callback = {
        let mut failure = FAILURE.lock();
        let Some(failure) = failure.as_mut() else {
            return false;
        };
        if failure.config != config || failure.consumed || failure.arm != arm {
            return false;
        }
        failure.consumed = true;
        failure.callback
    };
    if let Some(callback) = callback {
        callback();
    }
    true
}

impl Drop for ReadbackFailure {
    fn drop(&mut self) {
        *FAILURE.lock() = None;
    }
}
