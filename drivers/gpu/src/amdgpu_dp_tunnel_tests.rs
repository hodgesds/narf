use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A host router's DPCD tunnelling space.
struct Router {
    regs: Vec<(u32, u8)>,
    writes: Vec<(u32, u8)>,
    /// Defer this many AUX transactions before answering.
    defers: usize,
    fail: bool,
    /// Answer a bandwidth request with failure instead of success.
    refuse: bool,
    /// Never answer a request at all.
    silent: bool,
    /// Report success but grant less than was asked for.
    under_grant: bool,
}
impl Router {
    fn new() -> Self {
        let mut router = Self {
            regs: Vec::new(),
            writes: Vec::new(),
            defers: 0,
            fail: false,
            refuse: false,
            silent: false,
            under_grant: false,
        };
        // Allocation-capable, 0.25 Gbps granularity, 20 steps estimated (5 Gbps),
        // HBR2 over four lanes.
        router.set(TUNNELING_CAPABILITIES, CAP_DP_TUNNELING | CAP_DPIA_BW_ALLOC);
        router.set(DRIVER_BW_CAPABILITY, CAP_DRIVER_BW_ALLOC);
        router.set(BW_GRANULARITY, 0);
        router.set(ESTIMATED_BW, 20);
        router.set(MAX_LINK_RATE, 20);
        router.set(MAX_LANE_COUNT, 4);
        router.set(TUNNELING_STATUS, 0);
        router.set(ALLOCATED_BW, 0);
        router
    }
    fn set(&mut self, address: u32, value: u8) {
        if let Some(entry) = self.regs.iter_mut().find(|(a, _)| *a == address) {
            entry.1 = value;
        } else {
            self.regs.push((address, value));
        }
    }
    fn get(&self, address: u32) -> u8 {
        self.regs
            .iter()
            .find(|(a, _)| *a == address)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }
}
impl Phy for Router {
    async fn command(&mut self, _: [u8; 64]) -> Result<(), crate::amdgpu_dp_training::Error> {
        Ok(())
    }
    async fn typec(
        &mut self,
        _: u8,
    ) -> Result<(bool, bool, bool), crate::amdgpu_dp_training::Error> {
        Ok((false, false, false))
    }
    async fn aux(
        &mut self,
        _: Channel,
        _: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), AuxError> {
        if self.fail {
            return Err(AuxError::Failed);
        }
        if self.defers > 0 {
            self.defers -= 1;
            return Err(AuxError::Defer);
        }
        if action == 0x90 {
            data[0] = self.get(address);
        } else {
            self.writes.push((address, data[0]));
            if address == TUNNELING_STATUS {
                // The status bits are write-one-to-clear, which is how Linux
                // acknowledges them after handling an event.
                let cleared = self.get(address) & !data[0];
                self.set(address, cleared);
            } else {
                self.set(address, data[0]);
            }
            // The router answers a bandwidth request by granting it.
            if address == REQUESTED_BW && !self.silent {
                if self.refuse {
                    self.set(TUNNELING_STATUS, STATUS_REQUEST_FAILED);
                } else {
                    self.set(TUNNELING_STATUS, STATUS_REQUEST_SUCCEEDED);
                    let granted = if self.under_grant { 1 } else { data[0] };
                    self.set(ALLOCATED_BW, granted);
                }
            }
        }
        Ok(())
    }
}
fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
/// 1080p60 at eight bits per component.
const REQUIRED_1080P: u32 = 148_500 * 24;

fn tunnel_allocation_rounds_the_request_up_to_a_step() -> TestResult {
    let mut router = Router::new();
    let allocation = match run(allocate(&mut router, 2, REQUIRED_1080P)) {
        Ok(allocation) => allocation,
        Err(_) => return TestResult::Fail("1080p allocation refused"),
    };
    // 3.564 Gbps at 0.25 Gbps steps is 14.256 steps, which must round up to 15
    // or the stream is short of what it needs.
    if router
        .writes
        .iter()
        .find(|(a, _)| *a == REQUESTED_BW)
        .map(|(_, v)| *v)
        != Some(15)
    {
        return TestResult::Fail("request not rounded up to a whole step");
    }
    if allocation.allocated_kbps != 15 * 250_000 {
        return TestResult::Fail("granted bandwidth");
    }
    if allocation.allocated_kbps < REQUIRED_1080P {
        return TestResult::Fail("granted less than the mode needs");
    }
    if allocation.estimated_kbps != 20 * 250_000 {
        return TestResult::Fail("estimated bandwidth");
    }
    if allocation.granularity_steps_per_gbps != 4 {
        return TestResult::Fail("granularity");
    }
    if (allocation.max_link_rate, allocation.max_lanes) != (20, 4) {
        return TestResult::Fail("endpoint maxima");
    }
    // Allocation mode is taken, with change reporting unmasked, before anything
    // is read out of the allocation registers.
    let control = router
        .writes
        .iter()
        .position(|(a, v)| *a == ALLOCATION_MODE_CONTROL && *v == MODE_ENABLE | MODE_UNMASK_IRQ);
    let request = router.writes.iter().position(|(a, _)| *a == REQUESTED_BW);
    if control.is_none() || request.is_none() || control >= request {
        return TestResult::Fail("allocation mode not taken before requesting");
    }
    // Coarser granularity rounds to its own step: 1 Gbps steps need four.
    let mut coarse = Router::new();
    coarse.set(BW_GRANULARITY, 2);
    coarse.set(ESTIMATED_BW, 10);
    let coarse_alloc = run(allocate(&mut coarse, 0, REQUIRED_1080P)).unwrap();
    if coarse_alloc.granularity_steps_per_gbps != 1
        || coarse_alloc.allocated_kbps != 4 * GBPS_IN_KBPS
    {
        return TestResult::Fail("coarse granularity rounding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-tunnel",
    tunnel_allocation_rounds_the_request_up_to_a_step
);

fn tunnel_without_allocation_support_is_not_a_failure() -> TestResult {
    // A tunnel that does no allocation carries the fixed allocation it was
    // created with, so the caller may proceed on that.
    for (address, value) in [
        (TUNNELING_CAPABILITIES, CAP_DPIA_BW_ALLOC),
        (TUNNELING_CAPABILITIES, CAP_DP_TUNNELING),
        (DRIVER_BW_CAPABILITY, 0),
    ] {
        let mut router = Router::new();
        router.set(address, value);
        if run(allocate(&mut router, 0, REQUIRED_1080P)) != Err(Error::Unsupported) {
            return TestResult::Fail("incapable endpoint not reported as unsupported");
        }
        // Nothing is programmed on an endpoint that does not do allocation.
        if router
            .writes
            .iter()
            .any(|(a, _)| *a == ALLOCATION_MODE_CONTROL)
        {
            return TestResult::Fail("took allocation mode on an incapable endpoint");
        }
    }
    // The reserved granularity encoding is refused rather than guessed, since
    // guessing it scales every request.
    let mut reserved = Router::new();
    reserved.set(BW_GRANULARITY, 3);
    if run(allocate(&mut reserved, 0, REQUIRED_1080P)) != Err(Error::Unsupported) {
        return TestResult::Fail("reserved granularity accepted");
    }
    if run(allocate(&mut Router::new(), 0, 0)) != Err(Error::Unsupported) {
        return TestResult::Fail("zero requirement accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-tunnel",
    tunnel_without_allocation_support_is_not_a_failure
);

fn tunnel_refuses_a_mode_it_cannot_carry() -> TestResult {
    // The router estimates 5 Gbps; 4K60 at 24bpp needs far more. Linux clamps
    // the request down to the estimate, which would starve the stream.
    let mut router = Router::new();
    let required = 594_000 * 24;
    match run(allocate(&mut router, 0, required)) {
        Err(Error::Insufficient {
            estimated_kbps,
            required_kbps,
        }) => {
            if estimated_kbps != 20 * 250_000 || required_kbps != required {
                return TestResult::Fail("insufficient report");
            }
        }
        _ => return TestResult::Fail("mode beyond the tunnel accepted"),
    }
    // Nothing was requested, so no other endpoint's estimate was disturbed.
    if router.writes.iter().any(|(a, _)| *a == REQUESTED_BW) {
        return TestResult::Fail("requested bandwidth it could not have");
    }
    // A router that reports success but grants less than it was asked for is
    // still a tunnel that cannot carry the mode, so its own figure is believed
    // over the request.
    let mut mean = Router::new();
    mean.under_grant = true;
    match run(allocate(&mut mean, 0, REQUIRED_1080P)) {
        Err(Error::Insufficient { estimated_kbps, .. }) => {
            if estimated_kbps != 250_000 {
                return TestResult::Fail("under-grant not reported as granted");
            }
        }
        _ => return TestResult::Fail("under-granted allocation accepted"),
    }
    // An outright refusal, and a router that never answers.
    let mut refusing = Router::new();
    refusing.refuse = true;
    if run(allocate(&mut refusing, 0, REQUIRED_1080P)) != Err(Error::Refused) {
        return TestResult::Fail("refusal not reported");
    }
    let mut silent = Router::new();
    silent.silent = true;
    if run(allocate(&mut silent, 0, REQUIRED_1080P)) != Err(Error::Timeout) {
        return TestResult::Fail("silent router not timed out");
    }
    let mut broken = Router::new();
    broken.fail = true;
    if run(allocate(&mut broken, 0, REQUIRED_1080P)) != Err(Error::Aux) {
        return TestResult::Fail("AUX failure not reported");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-tunnel",
    tunnel_refuses_a_mode_it_cannot_carry
);

fn tunnel_retries_deferred_aux_and_releases_on_stop() -> TestResult {
    // A deferred reply is the router asking for a moment, not a failure.
    let mut router = Router::new();
    router.defers = 3;
    if run(allocate(&mut router, 1, REQUIRED_1080P)).is_err() {
        return TestResult::Fail("deferred AUX not retried");
    }
    // Stopping a stream must hand the bandwidth back, or the other endpoints
    // never see it again.
    let mut router = Router::new();
    if run(release(&mut router, 1)).is_err() {
        return TestResult::Fail("release rejected");
    }
    if router.writes.last() != Some(&(REQUESTED_BW, 0)) {
        return TestResult::Fail("bandwidth not handed back");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-tunnel",
    tunnel_retries_deferred_aux_and_releases_on_stop
);

fn tunnel_clears_a_stale_result_before_requesting() -> TestResult {
    // A leftover success from an earlier request must not be read back as this
    // request's answer, so the status is cleared first.
    let mut router = Router::new();
    router.set(TUNNELING_STATUS, STATUS_REQUEST_SUCCEEDED);
    router.silent = true;
    if run(allocate(&mut router, 0, REQUIRED_1080P)) != Err(Error::Timeout) {
        return TestResult::Fail("stale success read back as this request's answer");
    }
    let cleared = router
        .writes
        .iter()
        .position(|(a, v)| *a == TUNNELING_STATUS && *v & STATUS_REQUEST_SUCCEEDED != 0);
    let requested = router.writes.iter().position(|(a, _)| *a == REQUESTED_BW);
    if cleared.is_none() || requested.is_none() || cleared >= requested {
        return TestResult::Fail("status not cleared before requesting");
    }
    // A stale failure likewise must not be mistaken for a refusal of this one.
    let mut stale_failure = Router::new();
    stale_failure.set(TUNNELING_STATUS, STATUS_REQUEST_FAILED);
    if run(allocate(&mut stale_failure, 0, REQUIRED_1080P)).is_err() {
        return TestResult::Fail("stale failure read back as a refusal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dp-tunnel",
    tunnel_clears_a_stale_result_before_requesting
);
