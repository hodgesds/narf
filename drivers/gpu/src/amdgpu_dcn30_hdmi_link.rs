//! SCDC reception state and bounded HDMI link-loss recovery. A lock proves
//! reception of TMDS, not that a compositor has presented an image.
use super::{scdc, ScdcStatus, Stream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkHealth {
    Unmonitored,
    Unknown,
    Acquiring,
    Locked,
    ConfigurationLost,
}

pub fn link_health(stream: &Stream, status: Option<ScdcStatus>) -> LinkHealth {
    if !stream.scdc {
        return LinkHealth::Unmonitored;
    }
    let Some(status) = status else {
        return LinkHealth::Unknown;
    };
    if status.tmds_config & 3 != stream.scramble.tmds_config() {
        return LinkHealth::ConfigurationLost;
    }
    let Some(flags) = status.status_flags else {
        return LinkHealth::Unknown;
    };
    if flags & scdc::RECEPTION_LOCK != scdc::RECEPTION_LOCK {
        return LinkHealth::Acquiring;
    }
    if stream.scramble.tmds_config() & scdc::SCRAMBLING_ENABLE != 0 {
        match status.scrambler_status {
            None => return LinkHealth::Unknown,
            Some(v) if v & 1 == 0 => return LinkHealth::Acquiring,
            Some(_) => {}
        }
    }
    LinkHealth::Locked
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkAction {
    None,
    Relight,
    Faulted,
}

/// Three consecutive observed failures trigger one relight per connection.
/// A second sustained loss reports a fault and stops automatic recovery;
/// healthy outputs in the same context keep running. Unreadable status
/// never causes a reset loop. Polling is limited to once per second.
#[derive(Clone, Copy, Debug)]
pub struct LinkMonitor {
    failures: u8,
    relit: bool,
    stopped: bool,
    next_sample_ms: u64,
}
impl LinkMonitor {
    pub const fn new() -> Self {
        Self {
            failures: 0,
            relit: false,
            stopped: false,
            next_sample_ms: 0,
        }
    }
    pub fn poll_due(&mut self, now_ms: u64) -> bool {
        if self.stopped || now_ms < self.next_sample_ms {
            return false;
        }
        self.next_sample_ms = now_ms.saturating_add(1000);
        true
    }
    pub fn observe(&mut self, health: LinkHealth) -> LinkAction {
        if self.stopped {
            return LinkAction::None;
        }
        if !matches!(
            health,
            LinkHealth::Acquiring | LinkHealth::ConfigurationLost
        ) {
            self.failures = 0;
            return LinkAction::None;
        }
        self.failures += 1;
        if self.failures < 3 {
            return LinkAction::None;
        }
        self.failures = 0;
        if self.relit {
            self.stopped = true;
            LinkAction::Faulted
        } else {
            self.relit = true;
            LinkAction::Relight
        }
    }
}
impl Default for LinkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn hdmi_loss_requires_observation_and_has_a_connection_budget() -> TestResult {
        let mut m = LinkMonitor::new();
        for health in [
            LinkHealth::Acquiring,
            LinkHealth::Unknown,
            LinkHealth::Acquiring,
            LinkHealth::Locked,
            LinkHealth::ConfigurationLost,
            LinkHealth::Unmonitored,
        ] {
            if m.observe(health) != LinkAction::None {
                return TestResult::Fail("transient loss reset link");
            }
        }
        for expected in [LinkAction::None, LinkAction::None, LinkAction::Relight] {
            if m.observe(LinkHealth::ConfigurationLost) != expected {
                return TestResult::Fail("relight threshold");
            }
        }
        // A good sample recovers health, but does not replenish reset budget.
        if m.observe(LinkHealth::Locked) != LinkAction::None {
            return TestResult::Fail("good sample");
        }
        for expected in [LinkAction::None, LinkAction::None, LinkAction::Faulted] {
            if m.observe(LinkHealth::Acquiring) != expected {
                return TestResult::Fail("stop threshold");
            }
        }
        for _ in 0..10 {
            if m.observe(LinkHealth::Acquiring) != LinkAction::None {
                return TestResult::Fail("unbounded recovery");
            }
        }
        m = LinkMonitor::new(); // HPD disconnect / new sink resets the budget.
        for expected in [LinkAction::None, LinkAction::None, LinkAction::Relight] {
            if m.observe(LinkHealth::Acquiring) != expected {
                return TestResult::Fail("new connection budget");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-hdmi/link",
        hdmi_loss_requires_observation_and_has_a_connection_budget
    );
    fn hdmi_poll_is_rate_limited_even_when_modesets_wake_the_monitor() -> TestResult {
        let mut m = LinkMonitor::new();
        for (now, due) in [
            (0, true),
            (0, false),
            (50, false),
            (999, false),
            (1000, true),
            (1001, false),
            (1999, false),
            (2000, true),
        ] {
            if m.poll_due(now) != due {
                return TestResult::Fail("SCDC poll cadence");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-hdmi/link",
        hdmi_poll_is_rate_limited_even_when_modesets_wake_the_monitor
    );
}
