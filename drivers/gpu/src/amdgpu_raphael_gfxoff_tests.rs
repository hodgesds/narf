use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Fake {
    events: Vec<&'static str>,
}
impl Control for Fake {
    async fn control(&mut self, allow: bool) -> Result<(), ()> {
        self.events.push(if allow { "allow" } else { "disallow" });
        Ok(())
    }
}
impl PowerGating for Fake {
    async fn set_power_gating(&mut self, enable: bool) -> Result<(), ()> {
        self.events.push(if enable { "pg on" } else { "pg off" });
        Ok(())
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

/// gfx_v10_0_set_powergating_state for GC 10.3.6 with amdgpu_gfx_off_ctrl's
/// count: accesses before GATE send nothing (GFX is held on), GATE turns
/// power gating on and allows GFXOFF after the delay, a GC access while off
/// disallows first, a disable before the delay cancels it, and UNGATE
/// disallows before power gating goes off.
fn raphael_gfxoff_follows_gfx_v10_powergating() -> TestResult {
    let (mut hw, mut g) = (Fake::default(), GfxOff::new(true));
    if run(g.hold(&mut hw)).is_err() || g.release() != Ok(None) || !hw.events.is_empty() {
        return TestResult::Fail("an access before GATE reached PMFW");
    }
    let Ok(Some(first)) = run(g.gate(&mut hw)) else {
        return TestResult::Fail("GATE scheduled no allow");
    };
    if hw.events != ["pg on"] || run(g.gate(&mut hw)) != Ok(None) || hw.events.len() != 1 {
        return TestResult::Fail("GATE order, or a second GATE acted");
    }
    if run(g.delayed(first, &mut hw)) != Ok(true) || !g.status().off {
        return TestResult::Fail("the delayed allow");
    }
    // A READ_MMR_REG while GFX may be off.
    if run(g.hold(&mut hw)).is_err() || hw.events.last() != Some(&"disallow") {
        return TestResult::Fail("an access did not disallow first");
    }
    let Ok(Some(second)) = g.release() else {
        return TestResult::Fail("the access's release scheduled no allow");
    };
    // Another access before the delay cancels it without a message.
    let sent = hw.events.len();
    let _ = run(g.hold(&mut hw));
    let Ok(Some(third)) = g.release() else {
        return TestResult::Fail("the second release scheduled no allow");
    };
    if hw.events.len() != sent
        || run(g.delayed(second, &mut hw)) != Ok(false)
        || run(g.delayed(third, &mut hw)) != Ok(true)
    {
        return TestResult::Fail("a cancelled allow was delivered");
    }
    hw.events.clear();
    if run(g.ungate(&mut hw)).is_err() || hw.events != ["disallow", "pg off"] || g.gated() {
        return TestResult::Fail("UNGATE order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/raphael-gfxoff",
    raphael_gfxoff_follows_gfx_v10_powergating
);

/// A re-armed coordinator's GfxOff ignores an allow scheduled by the one
/// before it; without PP_GFXOFF_MASK only power gating follows GATE and
/// UNGATE, and nothing reaches PMFW.
fn raphael_gfxoff_epochs_and_the_feature_mask() -> TestResult {
    let (mut hw, mut old) = (Fake::default(), GfxOff::new(true));
    let Ok(Some(stale)) = run(old.gate(&mut hw)) else {
        return TestResult::Fail("GATE scheduled no allow");
    };
    let mut new = GfxOff::new(true);
    let _ = run(new.gate(&mut hw));
    hw.events.clear();
    if run(new.delayed(stale, &mut hw)) != Ok(false) || !hw.events.is_empty() {
        return TestResult::Fail("an allow from an older lifetime landed");
    }
    let (mut hw, mut off) = (Fake::default(), GfxOff::new(false));
    if run(off.gate(&mut hw)) != Ok(None)
        || run(off.hold(&mut hw)).is_err()
        || off.release() != Ok(None)
        || run(off.ungate(&mut hw)).is_err()
        || hw.events != ["pg on", "pg off"]
    {
        return TestResult::Fail("GFXOFF requests without PP_GFXOFF_MASK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/raphael-gfxoff",
    raphael_gfxoff_epochs_and_the_feature_mask
);
