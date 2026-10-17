//! `amdgpu_gfx_off_ctrl` semantics against a PMFW model.
use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Pmfw {
    /// true = AllowGfxOff, false = DisallowGfxOff.
    messages: Vec<bool>,
    reject: bool,
}
impl Control for Pmfw {
    async fn control(&mut self, allow: bool) -> Result<(), ()> {
        self.messages.push(allow);
        if self.reject {
            Err(())
        } else {
            Ok(())
        }
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn navi22_gfxoff_disabled_is_a_no_op() -> TestResult {
    let mut c = Controller::new();
    let mut pmfw = Pmfw::default();
    if run(c.disallow(&mut pmfw)) != Ok(())
        || c.allow() != Ok(None)
        || c.allow() != Ok(None)
        || run(c.delayed_allow(0, &mut pmfw)) != Ok(false)
        || !pmfw.messages.is_empty()
        || c.status().enabled
        || c.status().requests != 1
    {
        return TestResult::Fail("disabled controller acted");
    }
    // The global path: a default boot never started the controller, so a
    // submission's reference is inert and sends nothing.
    match run(Reference::acquire()) {
        Ok(reference) if !reference.active() => {}
        _ => return TestResult::Fail("default-boot reference was active"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-gfxoff",
    navi22_gfxoff_disabled_is_a_no_op
);

fn navi22_gfxoff_follows_linux_request_counting() -> TestResult {
    let mut c = Controller::new();
    let mut pmfw = Pmfw::default();
    c.start().unwrap();
    // set_powergating_state(GATE): 1 -> 0, delayed allow scheduled.
    let Ok(Some(first)) = c.allow() else {
        return TestResult::Fail("gate did not schedule the delayed allow");
    };
    if !pmfw.messages.is_empty() || !c.status().pending {
        return TestResult::Fail("allow sent without the delay");
    }
    // A disable request before the delay expires cancels it: no message,
    // GFX was never off.
    run(c.disallow(&mut pmfw)).unwrap();
    if run(c.delayed_allow(first, &mut pmfw)) != Ok(false) || !pmfw.messages.is_empty() {
        return TestResult::Fail("cancelled allow fired");
    }
    // Release: the new delayed allow is the one that fires.
    let Ok(Some(second)) = c.allow() else {
        return TestResult::Fail("release did not reschedule");
    };
    if run(c.delayed_allow(second, &mut pmfw)) != Ok(true)
        || pmfw.messages != [true]
        || !c.status().off
    {
        return TestResult::Fail("delayed allow");
    }
    // Nested references: only the first sends DisallowGfxOff, only the last
    // release schedules the allow again.
    run(c.disallow(&mut pmfw)).unwrap();
    run(c.disallow(&mut pmfw)).unwrap();
    if pmfw.messages != [true, false] || c.status().off || c.status().requests != 2 {
        return TestResult::Fail("first disable request did not disallow");
    }
    if c.allow() != Ok(None) || c.status().requests != 1 {
        return TestResult::Fail("inner release scheduled");
    }
    let Ok(Some(third)) = c.allow() else {
        return TestResult::Fail("outer release did not schedule");
    };
    run(c.delayed_allow(third, &mut pmfw)).unwrap();
    // Imbalance: an extra enable is refused and changes nothing.
    if c.allow() != Err(Error::Imbalance) || c.status().requests != 0 {
        return TestResult::Fail("imbalanced enable");
    }
    // Ungate/stop: GFX powered, controller inert, cannot restart.
    run(c.stop(&mut pmfw)).unwrap();
    if pmfw.messages != [true, false, true, false]
        || c.status().enabled
        || c.status().off
        || c.start() != Err(Error::Busy)
        || run(c.disallow(&mut pmfw)) != Ok(())
        || pmfw.messages.len() != 4
    {
        return TestResult::Fail("stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-gfxoff",
    navi22_gfxoff_follows_linux_request_counting
);

fn navi22_gfxoff_fails_closed() -> TestResult {
    let mut c = Controller::new();
    let mut pmfw = Pmfw::default();
    c.start().unwrap();
    let generation = c.allow().unwrap().unwrap();
    // A rejected allow leaves GFX on and the controller usable.
    pmfw.reject = true;
    if run(c.delayed_allow(generation, &mut pmfw)) != Err(Error::Control)
        || c.status().off
        || c.status().failed
    {
        return TestResult::Fail("rejected allow");
    }
    pmfw.reject = false;
    run(c.disallow(&mut pmfw)).unwrap();
    let generation = c.allow().unwrap().unwrap();
    run(c.delayed_allow(generation, &mut pmfw)).unwrap();
    // A rejected disallow: GC power unknown; every later request refused.
    pmfw.reject = true;
    if run(c.disallow(&mut pmfw)) != Err(Error::Control)
        || !c.status().failed
        || run(c.disallow(&mut pmfw)) != Err(Error::Failed)
    {
        return TestResult::Fail("failed disallow was not terminal");
    }
    // A cancelled disallow (future dropped mid-message) is equally terminal.
    let mut c = Controller::new();
    let mut pmfw = Pmfw::default();
    c.start().unwrap();
    let generation = c.allow().unwrap().unwrap();
    run(c.delayed_allow(generation, &mut pmfw)).unwrap();
    {
        let mut stall = Stall;
        let mut future = core::pin::pin!(c.disallow(&mut stall));
        let waker = core::task::Waker::noop();
        let _ = future
            .as_mut()
            .poll(&mut core::task::Context::from_waker(waker));
    }
    if !c.status().failed || run(c.disallow(&mut pmfw)) != Err(Error::Failed) {
        return TestResult::Fail("cancelled disallow");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/navi22-gfxoff", navi22_gfxoff_fails_closed);

/// A PMFW message that never completes.
struct Stall;
impl Control for Stall {
    fn control(&mut self, _: bool) -> impl Future<Output = Result<(), ()>> + Send {
        core::future::pending()
    }
}
