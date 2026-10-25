use super::*;
use core::cell::Cell;
use narf_kernel_test::{kernel_test_in, TestResult};

fn id() -> Endpoint {
    Endpoint {
        generation: 42,
        slot: 5,
        dci: 3,
    }
}
fn event(token: &Token, code: u8, residue: u32) -> [u32; 4] {
    [
        token.trb as u32,
        (token.trb >> 32) as u32,
        u32::from(code) << 24 | residue,
        32 << 10 | u32::from(token.endpoint) << 16 | u32::from(token.slot) << 24,
    ]
}

fn smoke_xhci_bulk_dropped_receipt_keeps_dma_owned() -> TestResult {
    let mut state = State::new();
    let publications = Cell::new(0);
    let bounce = Cell::new(0u8);
    {
        let _token = state
            .begin(id(), Direction::Out, 512, || {
                bounce.set(1);
                publications.set(publications.get() + 1);
                0x1234_5000
            })
            .unwrap();
    } // Neither a receipt nor a waiting future cancels hardware.
    if !state.active()
        || !matches!(
            state.begin(id(), Direction::Out, 512, || {
                bounce.set(2);
                publications.set(publications.get() + 1);
                0x1234_5010
            }),
            Err(Error::Busy)
        )
        || bounce.get() != 1
        || publications.get() != 1
    {
        return TestResult::Fail("bulk receipt Drop reused an unretired DMA scratch page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_bulk_dropped_receipt_keeps_dma_owned
);

fn smoke_xhci_bulk_matches_td_and_generation() -> TestResult {
    let mut state = State::new();
    let token = state
        .begin(id(), Direction::In, 512, || 0x1234_5000)
        .unwrap();
    let good = event(&token, 13, 12);
    let consumed = Cell::new(0);
    for index in 0..5 {
        let mut bad = good;
        match index {
            0 => bad[0] += 16,
            1 => bad[1] += 1,
            2 => bad[3] ^= 1 << 24,
            3 => bad[3] ^= 1 << 16,
            _ => bad[3] |= 1 << 2,
        }
        if state.complete(42, &token, &bad, |_| consumed.set(1)) != Ok(None) {
            return TestResult::Fail("another TD/event-data record completed bulk transfer");
        }
    }
    if state.complete(43, &token, &good, |_| consumed.set(1)) != Err(Error::Stale)
        || consumed.get() != 0
        || !state.active()
    {
        return TestResult::Fail("stale device generation touched bulk DMA");
    }
    if state.complete(42, &token, &good, |bytes| consumed.set(bytes)) != Ok(Some(500))
        || consumed.get() != 500
        || state.active()
    {
        return TestResult::Fail("short IN completion did not transfer ownership exactly once");
    }
    let next = state
        .begin(id(), Direction::In, 512, || 0x1234_5000)
        .unwrap();
    if state.complete(42, &token, &good, |_| consumed.set(0)) != Err(Error::Stale)
        || !state.active()
        || state.complete(42, &next, &event(&next, 1, 0), |_| ()) != Ok(Some(512))
    {
        return TestResult::Fail("retired receipt released a reused ring address");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_bulk_matches_td_and_generation
);

fn smoke_xhci_bulk_ambiguous_errors_keep_endpoint_poisoned() -> TestResult {
    for (direction, code, residue, error) in [
        (Direction::In, 6, 0, Error::Completion(6)),
        (Direction::Out, 13, 0, Error::Completion(13)),
        (Direction::In, 1, 513, Error::Malformed),
    ] {
        let mut state = State::new();
        let token = state.begin(id(), direction, 512, || 0x1000).unwrap();
        let consumed = Cell::new(false);
        if state.complete(42, &token, &event(&token, code, residue), |_| {
            consumed.set(true)
        }) != Err(error)
            || consumed.get()
            || !state.active()
            || !matches!(
                state.begin(id(), direction, 512, || panic!("reuse after error")),
                Err(Error::Busy)
            )
        {
            return TestResult::Fail("ambiguous bulk failure reopened scratch DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_bulk_ambiguous_errors_keep_endpoint_poisoned
);

fn smoke_xhci_bulk_preflight_never_publishes_invalid_transfer() -> TestResult {
    for length in [0, 4097] {
        let mut state = State::new();
        if !matches!(
            state.begin(id(), Direction::In, length, || panic!(
                "invalid publication"
            )),
            Err(Error::BadLength)
        ) || state.active()
        {
            return TestResult::Fail("invalid bulk size claimed DMA");
        }
    }
    let mut state = State::new();
    state.next = u64::MAX;
    if !matches!(
        state.begin(id(), Direction::In, 4096, || panic!("serial wrap")),
        Err(Error::Exhausted)
    ) || state.active()
    {
        return TestResult::Fail("bulk receipt serial wrapped into stale identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_bulk_preflight_never_publishes_invalid_transfer
);

fn smoke_xhci_configuration_cancel_retains_published_dma() -> TestResult {
    struct Resource<'a>(&'a Cell<usize>);
    impl Drop for Resource<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let released = Cell::new(0);
    drop(CommandDma::new(Resource(&released)));
    if released.get() != 1 {
        return TestResult::Fail("unpublished context was not ordinary ownership");
    }
    let mut cancelled = CommandDma::new(Resource(&released));
    cancelled.publish();
    drop(cancelled);
    if released.get() != 1 {
        return TestResult::Fail("cancel freed published configure-endpoint DMA");
    }
    let mut completed = CommandDma::new(Resource(&released));
    completed.publish();
    let adopted = completed.complete();
    if released.get() != 1 {
        return TestResult::Fail("completion freed context before adoption");
    }
    drop(adopted);
    if released.get() != 2 {
        return TestResult::Fail("adopted context leaked ordinary ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_configuration_cancel_retains_published_dma
);

fn smoke_xhci_ep0_claims_before_reuse_and_rejects_stale_generation() -> TestResult {
    let mut state = ControlState::new();
    if state.begin(42, 41) != Err(Error::Stale)
        || state.active()
        || state.begin(42, 42) != Ok(())
        || !state.active()
        || state.begin(42, 42) != Err(Error::Busy)
        || state.complete(0, 42) != Err(Error::Stale)
        || !state.active()
        || state.complete(42, 42) != Ok(())
        || state.active()
        || state.begin(42, 42) != Ok(())
    {
        return TestResult::Fail("EP0 scratch ownership accepted stale/reentrant reuse");
    }
    // Simulate dropping the transfer while hardware owns the published TD.
    if state.begin(42, 42) != Err(Error::Busy) || !state.active() {
        return TestResult::Fail("failed/cancelled EP0 transfer reopened its page");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_ep0_claims_before_reuse_and_rejects_stale_generation
);

fn smoke_xhci_address_reservations_never_reuse_published_slots() -> TestResult {
    let mut slots = Slots::new();
    if slots.any_reserved()
        || slots.is_unused(0)
        || !slots.is_unused(5)
        || slots.begin(5, 42) != Ok(())
        || slots.is_unused(5)
        || !slots.any_reserved()
        || slots.begin(5, 43) != Err(Error::Busy)
    {
        return TestResult::Fail("address attempt did not reserve slot before DMA");
    }
    slots.release_unpublished(5, 41);
    if !slots.matches(5, 42) {
        return TestResult::Fail("stale attempt released address reservation");
    }
    slots.release_unpublished(5, 42);
    if slots.any_reserved() || !slots.is_unused(5) || slots.begin(5, 43) != Ok(()) {
        return TestResult::Fail("unpublished address error leaked reservation");
    }
    // Publication omits release_unpublished; disable permanently retires it.
    slots.retire(5);
    slots.release_unpublished(5, 43);
    if slots.matches(5, 43)
        || slots.is_unused(5)
        || slots.begin(5, 44) != Err(Error::Busy)
        || !slots.any_reserved()
    {
        return TestResult::Fail("disabled slot silently reused retained device DMA");
    }
    // Holding a retired hardware slot reserved lets a fixture obtain another
    // slot without changing the old ownership generation or its DMA claim.
    if !slots.is_unused(6)
        || slots.begin(6, 45) != Ok(())
        || !slots.matches(6, 45)
        || slots.is_unused(5)
        || slots.begin(5, 46) != Err(Error::Busy)
    {
        return TestResult::Fail("fresh fixture reservation weakened retired-slot ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_address_reservations_never_reuse_published_slots
);

fn smoke_xhci_context_commands_match_originating_trb() -> TestResult {
    let command = 0x1234_5678_9000u64;
    let event = [
        command as u32,
        (command >> 32) as u32,
        1 << 24,
        33 << 10 | 5 << 24,
    ];
    if !command_matches(&event, 5, command) {
        return TestResult::Fail("own command did not match");
    }
    for change in 0..4 {
        let mut wrong = event;
        match change {
            0 => wrong[0] += 16,
            1 => wrong[1] += 1,
            2 => wrong[3] ^= 1 << 24,
            _ => wrong[3] ^= 1 << 10,
        }
        if command_matches(&wrong, 5, command) {
            return TestResult::Fail("another context command retired retained DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_context_commands_match_originating_trb
);

/// Slot lifecycle: a live slot refuses reclaim, a retired slot
/// reclaims to unused, and a reclaimed id re-reserves only under a
/// fresh generation — the old generation never matches again.
/// `invalidate_all` + `reset` cover the controller-recovery sweep.
fn smoke_xhci_slot_reclaim_cycle() -> TestResult {
    let mut slots = Slots::new();
    if slots.begin(5, 42).is_err() || slots.is_retired(5) {
        return TestResult::Fail("fresh slot did not reserve");
    }
    if !matches!(slots.reclaim(5), Err(Error::Stale)) {
        return TestResult::Fail("live slot reclaimed without Disable Slot");
    }
    slots.retire(5);
    if !slots.is_retired(5) || slots.matches(5, 42) {
        return TestResult::Fail("retired slot still matches its generation");
    }
    if slots.reclaim(5).is_err() || !slots.is_unused(5) {
        return TestResult::Fail("retired slot did not reclaim to unused");
    }
    if slots.begin(5, 43).is_err() || !slots.matches(5, 43) || slots.matches(5, 42) {
        return TestResult::Fail("reclaimed slot did not re-reserve under a fresh generation");
    }
    if slots.begin(7, 9).is_err() {
        return TestResult::Fail("second slot did not reserve");
    }
    slots.invalidate_all();
    if slots.matches(5, 43) || slots.matches(7, 9) || !slots.is_retired(7) {
        return TestResult::Fail("invalidate_all left a live generation");
    }
    slots.reset();
    if slots.any_reserved() || !slots.is_unused(5) || !slots.is_unused(7) {
        return TestResult::Fail("reset left a slot reserved");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_slot_reclaim_cycle);

/// Halt recovery: an idle endpoint degenerates to no-ops; a retained
/// TD enters quarantine under its stop identity (foreign generation
/// is stale, a second begin is busy, the token validates busy while
/// quarantined) and finishing recovery stales the token for good.
fn smoke_xhci_halt_recovery_quarantine_and_finish() -> TestResult {
    let mut idle = State::new();
    if !matches!(idle.begin_halt_recovery(42), Ok(None)) {
        return TestResult::Fail("idle endpoint reported a retained TD");
    }
    if idle.finish_halt_recovery(None).is_err() || idle.active() {
        return TestResult::Fail("idle halt recovery did not finish clean");
    }
    let mut state = State::new();
    let token = match state.begin(id(), Direction::Out, 512, || 0x1234_5000) {
        Ok(token) => token,
        Err(_) => return TestResult::Fail("bulk begin failed"),
    };
    if !matches!(state.begin_halt_recovery(43), Err(Error::Stale)) {
        return TestResult::Fail("halt recovery accepted a foreign generation");
    }
    let identity = match state.begin_halt_recovery(42) {
        Ok(Some(identity)) => identity,
        _ => return TestResult::Fail("retained TD did not enter halt recovery"),
    };
    if identity.generation != 42 || identity.slot != 5 || identity.dci != 3 {
        return TestResult::Fail("halt recovery identity mismatch");
    }
    if !matches!(state.begin_halt_recovery(42), Err(Error::Busy)) {
        return TestResult::Fail("second halt recovery did not report busy");
    }
    if !matches!(state.validate(42, &token), Err(Error::Busy)) {
        return TestResult::Fail("token validated during halt-recovery quarantine");
    }
    if state.finish_halt_recovery(Some(identity)).is_err() {
        return TestResult::Fail("halt recovery finish rejected its identity");
    }
    if state.active() || !matches!(state.validate(42, &token), Err(Error::Stale)) {
        return TestResult::Fail("token survived halt recovery");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_halt_recovery_quarantine_and_finish
);

/// `ControlState::force_reset` is the one sanctioned release of the
/// EP0 claim without a terminal completion — after it, the pipe is
/// unclaimed and a fresh claim completes normally.
fn smoke_xhci_control_force_reset_releases_claim() -> TestResult {
    let mut control = ControlState::new();
    if control.begin(7, 7).is_err() || !control.active() {
        return TestResult::Fail("control claim did not take");
    }
    control.force_reset();
    if control.active() {
        return TestResult::Fail("force_reset left the control pipe claimed");
    }
    if control.begin(9, 9).is_err() || control.complete(9, 9).is_err() {
        return TestResult::Fail("control pipe did not reopen after force_reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_control_force_reset_releases_claim
);
