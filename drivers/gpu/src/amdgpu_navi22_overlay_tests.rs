//! Slave-pipe lease fixtures.
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn overlay_lease_prefers_the_mirror_pipe() -> TestResult {
    // DCN30's 6 pipes, `resource_find_free_secondary_pipe_legacy`'s
    // preferred mapping: primary 0 -> slave 5, 1 -> 4, 2 -> 3, 3 -> 2.
    for (primary, slave) in [(0, 5), (1, 4), (2, 3), (3, 2)] {
        if lease_slave(6, primary, &[])
            != Some(SlaveLease {
                pipe: slave,
                primary,
            })
        {
            return TestResult::Fail("mirror lease wrong");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-overlay",
    overlay_lease_prefers_the_mirror_pipe
);

fn overlay_lease_falls_back_to_the_highest_free_pipe() -> TestResult {
    // Primary 0's mirror (5) taken by another stream's slave.
    if lease_slave(6, 0, &[5])
        != Some(SlaveLease {
            pipe: 4,
            primary: 0,
        })
    {
        return TestResult::Fail("fallback lease wrong");
    }
    // Primary 1's mirror (4) is its own ODM secondary: never leased.
    if lease_slave(6, 1, &[4])
        != Some(SlaveLease {
            pipe: 5,
            primary: 1,
        })
    {
        return TestResult::Fail("ODM secondary leased");
    }
    // The only free pipe is the primary itself: no lease.
    if lease_slave(6, 2, &[0, 1, 3, 4, 5]).is_some() {
        return TestResult::Fail("primary leased to itself");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-overlay",
    overlay_lease_falls_back_to_the_highest_free_pipe
);

fn overlay_lease_refuses_an_exhausted_pool() -> TestResult {
    // 4 primaries + 2 overlays is all 6 pipes: a third overlay has no pipe.
    if lease_slave(6, 3, &[0, 1, 2, 4, 5]).is_some() {
        return TestResult::Fail("exhausted pool leased");
    }
    // Out-of-range primaries refuse.
    if lease_slave(6, 6, &[]).is_some() || lease_slave(0, 0, &[]).is_some() {
        return TestResult::Fail("bad pool leased");
    }
    if MAX_SLAVE_PLANES != 2 {
        return TestResult::Fail("slave plane count wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-overlay",
    overlay_lease_refuses_an_exhausted_pool
);
