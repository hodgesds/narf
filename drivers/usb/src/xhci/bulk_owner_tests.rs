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

/// Isochronous completion identity (#885): the Transfer Event
/// must pointer-match the originating Isoch TRB — a same
/// slot/DCI event for another TRB, or an Event Data record, never
/// retires the TD — and one owner state holds at most one TD at a
/// time (the endpoint pipeline is one such state per slot,
/// #2060). The event words are built from the xHCI 1.2 §6.4.2.1
/// Transfer Event layout (TRB Pointer in dwords 0..1, Completion
/// Code in dword 2 bits 31:24, residue in bits 23:0, type 32 in
/// dword 3 bits 15:10, endpoint in bits 20:16, slot in bits
/// 31:24), not from the driver's own constants.
fn smoke_xhci_isoch_completion_identity() -> TestResult {
    let mut state = State::new();
    let publications = Cell::new(0);
    let token = state
        .begin(id(), Direction::Out, 512, || {
            publications.set(publications.get() + 1);
            0x1234_5000
        })
        .unwrap();
    // One-in-flight: a second begin is Busy and never publishes.
    if !matches!(
        state.begin(id(), Direction::Out, 512, || panic!("second isoch publish")),
        Err(Error::Busy)
    ) || publications.get() != 1
        || !state.active()
    {
        return TestResult::Fail("second isoch TD published over a live one");
    }
    // A stale event — wrong TRB pointer, wrong slot, wrong
    // endpoint, or Event Data — never retires the TD.
    let good = event(&token, 1, 0);
    for index in 0..5 {
        let mut bad = good;
        match index {
            0 => bad[0] += 16,
            1 => bad[1] += 1,
            2 => bad[3] ^= 1 << 24,
            3 => bad[3] ^= 1 << 16,
            _ => bad[3] |= 1 << 2,
        }
        if state.complete_isoch(42, &token, &bad, |_| ()) != Ok(None) || !state.active() {
            return TestResult::Fail("another TD/event-data record completed isoch transfer");
        }
    }
    // Short Packet is a normal isoch completion for OUT (and IN):
    // the device's per-frame budget cut the packet short.
    let consumed = Cell::new(0);
    if state.complete_isoch(42, &token, &event(&token, 13, 12), |bytes| {
        consumed.set(bytes)
    }) != Ok(Some(500))
        || consumed.get() != 500
        || state.active()
    {
        return TestResult::Fail("isoch OUT short packet did not complete");
    }
    // A retired receipt never matches a reused ring address.
    let next = state
        .begin(id(), Direction::In, 512, || 0x1234_5000)
        .unwrap();
    if state.complete_isoch(42, &token, &good, |_| ()) != Err(Error::Stale)
        || !state.active()
        || state.complete_isoch(42, &next, &event(&next, 13, 0), |_| ()) != Ok(Some(512))
    {
        return TestResult::Fail("retired isoch receipt released a reused ring address");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usb/xhci", smoke_xhci_isoch_completion_identity);

/// Isochronous error discipline: error completions and malformed
/// residue poison the endpoint (the TD stays retained, the next
/// begin stays Busy) instead of reopening the scratch page.
/// Unlike bulk, CC 13 is not an error here in either direction.
fn smoke_xhci_isoch_ambiguous_errors_keep_endpoint_poisoned() -> TestResult {
    for (direction, code, residue, error) in [
        (Direction::In, 6, 0, Error::Completion(6)),
        (Direction::Out, 6, 0, Error::Completion(6)),
        (Direction::In, 1, 513, Error::Malformed),
        (Direction::Out, 1, 513, Error::Malformed),
    ] {
        let mut state = State::new();
        let token = state.begin(id(), direction, 512, || 0x1000).unwrap();
        let consumed = Cell::new(false);
        if state.complete_isoch(42, &token, &event(&token, code, residue), |_| {
            consumed.set(true)
        }) != Err(error)
            || consumed.get()
            || !state.active()
            || !matches!(
                state.begin(id(), direction, 512, || panic!("reuse after error")),
                Err(Error::Busy)
            )
        {
            return TestResult::Fail("ambiguous isoch failure reopened scratch DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_isoch_ambiguous_errors_keep_endpoint_poisoned
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

/// Isochronous pipeline (#2060): up to `ISOCH_PIPELINE_DEPTH` TDs
/// in flight on one endpoint, each completing against its own
/// pointer-matched Transfer Event in any order — and the next
/// begin past a full pool is `Busy` without publishing.
fn smoke_xhci_isoch_pool_pipelines_four_transfers() -> TestResult {
    let mut pool = IsochPool::new();
    if pool.active() {
        return TestResult::Fail("fresh isoch pool reported a TD in flight");
    }
    let mut tokens: [Option<Token>; ISOCH_PIPELINE_DEPTH] = core::array::from_fn(|_| None);
    for (index, slot) in tokens.iter_mut().enumerate() {
        let free = match pool.free_slot() {
            Some(free) => free,
            None => return TestResult::Fail("isoch pool ran out of free slots early"),
        };
        if free != index {
            return TestResult::Fail("isoch pool did not hand out slots in order");
        }
        let trb = 0x1234_5000u64 + (index as u64) * 16;
        match pool.begin_on(free, id(), Direction::In, 512, || trb) {
            Ok(token) => *slot = Some(token),
            Err(_) => return TestResult::Fail("isoch pool begin failed"),
        }
    }
    if !pool.active()
        || pool.free_slot().is_some()
        || !matches!(
            pool.begin_on(0, id(), Direction::In, 512, || panic!(
                "fifth isoch publish"
            )),
            Err(Error::Busy)
        )
    {
        return TestResult::Fail("fifth isoch TD published over a full pipeline");
    }
    // Complete out of order: the second TD first, then the rest.
    // Each completion reports only its own length.
    let consumed = Cell::new(0usize);
    for index in [1usize, 3, 0, 2] {
        let token = tokens[index].as_ref().unwrap();
        match pool.complete_isoch(42, token, &event(token, 1, 0), |bytes| consumed.set(bytes)) {
            Ok(Some(512)) if consumed.get() == 512 => {}
            _ => return TestResult::Fail("isoch pool completion did not retire its own TD"),
        }
    }
    if pool.active() || pool.free_slot() != Some(0) {
        return TestResult::Fail("isoch pool did not free its slots on completion");
    }
    // A retired receipt never matches a reused ring address.
    let token = tokens[0].as_ref().unwrap();
    if pool.complete_isoch(42, token, &event(token, 1, 0), |_| ()) != Err(Error::Stale) {
        return TestResult::Fail("retired isoch receipt completed after pipeline drain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_isoch_pool_pipelines_four_transfers
);

/// Isochronous pool event routing (#2060): the demux latches a
/// Transfer Event into the slot whose TRB it names, and only
/// that slot's waiter can take it. An event for another TRB
/// never latches anywhere.
fn smoke_xhci_isoch_pool_routes_events_by_trb() -> TestResult {
    let mut pool = IsochPool::new();
    let mut tokens: [Option<Token>; ISOCH_PIPELINE_DEPTH] = core::array::from_fn(|_| None);
    for (index, slot) in tokens.iter_mut().enumerate() {
        let free = match pool.free_slot() {
            Some(free) => free,
            None => return TestResult::Fail("isoch pool ran out of free slots early"),
        };
        let trb = 0x2000_0000u64 + (index as u64) * 16;
        match pool.begin_on(free, id(), Direction::In, 512, || trb) {
            Ok(token) => *slot = Some(token),
            Err(_) => return TestResult::Fail("isoch pool begin failed"),
        }
    }
    // An event for a TRB that is not in flight latches nowhere.
    let mut foreign = event(tokens[0].as_ref().unwrap(), 1, 0);
    foreign[0] += 16 * 16;
    if pool.record(foreign) {
        return TestResult::Fail("foreign Transfer Event latched into the isoch pool");
    }
    // The second TD's event latches into its slot only: the
    // first TD's waiter cannot take it, the second's can.
    let second = event(tokens[1].as_ref().unwrap(), 1, 12);
    if !pool.record(second) {
        return TestResult::Fail("matching Transfer Event did not latch");
    }
    let first = tokens[0].as_ref().unwrap();
    let taken_first = match pool.take_matching(&mut |ev| first.matches(ev)) {
        Ok(taken) => taken,
        Err(_) => return TestResult::Fail("take_matching failed on a foreign event"),
    };
    if taken_first.is_some() {
        return TestResult::Fail("first TD's waiter took the second TD's event");
    }
    let second_token = tokens[1].as_ref().unwrap();
    let taken_second = match pool.take_matching(&mut |ev| second_token.matches(ev)) {
        Ok(taken) => taken,
        Err(_) => return TestResult::Fail("take_matching failed on the matching event"),
    };
    match taken_second {
        Some(ev) if ev == second => {}
        _ => return TestResult::Fail("second TD's waiter did not take its own event"),
    }
    // The latched event completes the TD; the slot frees.
    let consumed = Cell::new(0usize);
    if pool.complete_isoch(42, second_token, &second, |bytes| consumed.set(bytes)) != Ok(Some(500))
        || consumed.get() != 500
    {
        return TestResult::Fail("latched isoch event did not complete its TD");
    }
    if pool.slot_of(second_token).is_some() {
        return TestResult::Fail("completed isoch TD still owns its pool slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_isoch_pool_routes_events_by_trb
);

/// Isochronous stop (#2060): claiming a stop on one TD retires
/// the whole pipeline — Set TR Dequeue moves the dequeue past
/// every posted TD, so the siblings go stale with the stopped
/// one and the pool reopens for a fresh begin.
fn smoke_xhci_isoch_pool_stop_retires_whole_pipeline() -> TestResult {
    let mut pool = IsochPool::new();
    let mut tokens: [Option<Token>; ISOCH_PIPELINE_DEPTH] = core::array::from_fn(|_| None);
    for (index, slot) in tokens.iter_mut().enumerate().take(2) {
        let free = match pool.free_slot() {
            Some(free) => free,
            None => return TestResult::Fail("isoch pool ran out of free slots early"),
        };
        let trb = 0x3000_0000u64 + (index as u64) * 16;
        match pool.begin_on(free, id(), Direction::Out, 512, || trb) {
            Ok(token) => *slot = Some(token),
            Err(_) => return TestResult::Fail("isoch pool begin failed"),
        }
    }
    let first = tokens[0].as_ref().unwrap();
    let second = tokens[1].as_ref().unwrap();
    let identity = match pool.begin_stop(42, first) {
        Ok(identity) => identity,
        Err(_) => return TestResult::Fail("isoch pool stop claim failed"),
    };
    // The stop identity names the stopped TD's TRB, not just its
    // per-slot serial: both slots began at serial 1.
    if identity.trb != 0x3000_0000 || identity.slot != 5 || identity.dci != 3 {
        return TestResult::Fail("isoch stop identity mismatch");
    }
    if !matches!(pool.validate(42, first), Err(Error::Busy))
        || !matches!(pool.validate(42, second), Ok(()))
    {
        return TestResult::Fail("stop claim did not quarantine only the stopped TD");
    }
    if pool.finish_stop(identity).is_err() {
        return TestResult::Fail("isoch pool stop finish rejected its identity");
    }
    if pool.active()
        || !matches!(pool.validate(42, first), Err(Error::Stale))
        || !matches!(pool.validate(42, second), Err(Error::Stale))
    {
        return TestResult::Fail("sibling isoch TD survived the pipeline stop");
    }
    // The pool reopens: a fresh TD begins in the freed slot.
    match pool.begin_on(0, id(), Direction::Out, 512, || 0x3000_1000) {
        Ok(_) => TestResult::Pass,
        Err(_) => TestResult::Fail("isoch pool did not reopen after the stop"),
    }
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_isoch_pool_stop_retires_whole_pipeline
);

/// Isochronous stopping quarantine (#2060): while one TD is
/// mid-stop, a sibling's genuine completion still latches (exact
/// pointer match wins), but a forced event at the successor TRB
/// is quarantined — it must never satisfy a later TD recycled
/// onto that ring position.
fn smoke_xhci_isoch_pool_stop_quarantines_successor_event() -> TestResult {
    let mut pool = IsochPool::new();
    let mut tokens: [Option<Token>; 2] = core::array::from_fn(|_| None);
    for (index, slot) in tokens.iter_mut().enumerate() {
        let free = match pool.free_slot() {
            Some(free) => free,
            None => return TestResult::Fail("isoch pool ran out of free slots early"),
        };
        let trb = 0x4000_0000u64 + (index as u64) * 16;
        match pool.begin_on(free, id(), Direction::In, 512, || trb) {
            Ok(token) => *slot = Some(token),
            Err(_) => return TestResult::Fail("isoch pool begin failed"),
        }
    }
    let first = tokens[0].as_ref().unwrap();
    let second = tokens[1].as_ref().unwrap();
    if pool.begin_stop(42, first).is_err() {
        return TestResult::Fail("isoch pool stop claim failed");
    }
    // The sibling's genuine completion latches during the stop.
    let sibling = event(second, 1, 0);
    if !pool.record(sibling) {
        return TestResult::Fail("sibling completion did not latch during the stop");
    }
    // A forced event at the successor TRB (the next ring position
    // after the pipeline) is quarantined, never latched or queued.
    let mut forced = event(second, 1, 0);
    forced[0] += 16;
    if !pool.record(forced) {
        return TestResult::Fail("forced successor event was not quarantined");
    }
    let taken = match pool.take_matching(&mut |ev| second.matches(ev)) {
        Ok(taken) => taken,
        Err(_) => return TestResult::Fail("take_matching failed during the stop"),
    };
    match taken {
        Some(ev) if ev == sibling => {}
        _ => return TestResult::Fail("sibling waiter did not take its own event"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usb/xhci",
    smoke_xhci_isoch_pool_stop_quarantines_successor_event
);
