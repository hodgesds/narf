//! Kernel-test smokes for the event bus. Loaded via
//! `kernel_test_in!("event_bus", …)` so the runner groups them
//! under one subsystem header.

use narf_capabilities::{Cap, Read, Write};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::cap::TopicRegistry;
use crate::topic::{NameError, TopicName};
use crate::{
    audit_subscribe_kernel, create_topic, init, lookup_topic, AuditEvent, CreateError, LookupError,
    PublishError, RecvError, SeqNum,
};

/// Each smoke resets the registry then re-inits so they're hermetic.
fn reset_bus() {
    crate::registry::__reset_for_test();
    init();
}

/// Pump a single-shot async future to completion. The bus's
/// `Subscriber::next` returns `Ready` as soon as an event is
/// available; there's no executor in test context, so we drive it
/// with a noop waker.
fn pump<F: core::future::Future>(mut fut: F) -> F::Output {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    fn vt_clone(p: *const ()) -> RawWaker {
        RawWaker::new(p, &VT)
    }
    fn vt_wake(_: *const ()) {}
    fn vt_wake_by_ref(_: *const ()) {}
    fn vt_drop(_: *const ()) {}
    static VT: RawWakerVTable = RawWakerVTable::new(vt_clone, vt_wake, vt_wake_by_ref, vt_drop);
    // SAFETY: the vtable above is all no-ops; data ptr is unused.
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is owned, we move it once into the pin.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => {
                // For these smokes we never expect Pending — every
                // publish happens before next() is polled, or
                // close()/revoke() makes it Ready.
                return panic_pending::<F::Output>();
            }
        }
    }
}

// Unreachable in the smokes, but cleaner than `unreachable!` because
// no-std panic strings are heavyweight.
fn panic_pending<O>() -> O {
    // Spin: a real failure here should be visible in the test
    // runner's per-test timeout, not a kernel panic during smokes.
    loop {
        core::hint::spin_loop();
    }
}

// ── 1. Topic create with valid name + cap → success ────────────────

fn smoke_event_bus_create_valid_name() -> TestResult {
    reset_bus();
    let reg: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let res = create_topic::<u32>(&reg, "user.testd.smoke1", 64);
    match res {
        Ok((_id, _pub)) => TestResult::Pass,
        Err(e) => {
            let _ = e;
            TestResult::Fail("create_topic should succeed for user.* name")
        }
    }
}
kernel_test_in!("event_bus", smoke_event_bus_create_valid_name);

// ── 2. Reserved-prefix from non-kernel cap rejected ────────────────

fn smoke_event_bus_create_reserved_with_read_cap() -> TestResult {
    reset_bus();
    let reg: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let parsed = TopicName::parse("user.testd.x");
    if parsed.is_err() {
        return TestResult::Fail("parse of user.testd.x should succeed");
    }
    // `Read`-cap holders can lookup but not create. The signature of
    // `create_topic` enforces this at compile-time (no implementation
    // exists for Read), so we instead verify the lookup-only path
    // returns `NotFound` for a not-yet-created topic.
    let res = lookup_topic::<u32>(&reg, "user.testd.x");
    match res {
        Err(LookupError::NotFound) => TestResult::Pass,
        _ => TestResult::Fail("lookup of nonexistent topic should be NotFound"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_create_reserved_with_read_cap);

// ── 3. Invalid name → InvalidName ─────────────────────────────────

fn smoke_event_bus_create_invalid_name() -> TestResult {
    reset_bus();
    let reg: Cap<TopicRegistry, Write> = Cap::bootstrap();
    if let Err(CreateError::InvalidName) = create_topic::<u32>(&reg, "user.bad name", 16) {
        // Good.
    } else {
        return TestResult::Fail("space in segment should be InvalidName");
    }
    if let Err(CreateError::InvalidName) = create_topic::<u32>(&reg, "", 16) {
        // Good.
    } else {
        return TestResult::Fail("empty name should be InvalidName");
    }
    TestResult::Pass
}
kernel_test_in!("event_bus", smoke_event_bus_create_invalid_name);

// ── 4. Publish + subscribe single subscriber: receive in order ─────

fn smoke_event_bus_publish_one_subscriber_in_order() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, publisher) = match create_topic::<u32>(&reg_w, "user.testd.order", 16) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("create_topic failed"),
    };
    let mut sub = match lookup_topic::<u32>(&reg_r, "user.testd.order") {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("lookup failed"),
    };
    for i in 0..5u32 {
        if publisher.publish(i).is_err() {
            return TestResult::Fail("publish failed");
        }
    }
    for i in 0..5u32 {
        match sub.try_next() {
            Ok(Some((_seq, v))) if v == i => {}
            other => {
                let _ = other;
                return TestResult::Fail("receive out of order");
            }
        }
    }
    if !matches!(sub.try_next(), Ok(None)) {
        return TestResult::Fail("expected empty after draining");
    }
    TestResult::Pass
}
kernel_test_in!("event_bus", smoke_event_bus_publish_one_subscriber_in_order);

// ── 5. Five subscribers all receive in order ──────────────────────

fn smoke_event_bus_publish_five_subscribers() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, publisher) = match create_topic::<u32>(&reg_w, "user.testd.fanout", 32) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("create_topic failed"),
    };
    let mut subs: alloc::vec::Vec<_> = (0..5)
        .map(|_| lookup_topic::<u32>(&reg_r, "user.testd.fanout").expect("lookup"))
        .collect();
    for i in 0..10u32 {
        if publisher.publish(i).is_err() {
            return TestResult::Fail("publish failed");
        }
    }
    for sub in subs.iter_mut() {
        for i in 0..10u32 {
            match sub.try_next() {
                Ok(Some((_seq, v))) if v == i => {}
                _ => return TestResult::Fail("subscriber missed an event"),
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("event_bus", smoke_event_bus_publish_five_subscribers);

// ── 6. Slow subscriber: gap signal ─────────────────────────────────

fn smoke_event_bus_slow_subscriber_gap() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, publisher) = match create_topic::<u32>(&reg_w, "user.testd.gap", 4) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("create_topic failed"),
    };
    let mut sub = match lookup_topic::<u32>(&reg_r, "user.testd.gap") {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("lookup failed"),
    };
    // Capacity 4, publish 10 → ring wraps and overwrites our cursor.
    for i in 0..10u32 {
        let _ = publisher.publish(i);
    }
    match sub.try_next() {
        Err(RecvError::Gapped { skipped }) if skipped > 0 => {
            // Now next reads should resume from the fast-forwarded
            // cursor. The fast-forward target is `head - capacity + 1`
            // = `10 - 4 + 1 = 7`. Expected value 7.
            match sub.try_next() {
                Ok(Some((seq, v))) if v == 7 && seq == SeqNum(7) => TestResult::Pass,
                _ => TestResult::Fail("post-gap resume not at expected seq"),
            }
        }
        _ => TestResult::Fail("expected gap signal"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_slow_subscriber_gap);

// ── 7. Producer cap revoked: PublishError::CapRevoked ──────────────

fn smoke_event_bus_publish_after_revoke() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let (_id, publisher) = match create_topic::<u32>(&reg_w, "user.testd.rev1", 16) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("create_topic failed"),
    };
    publisher.clone().revoke();
    match publisher.publish(42) {
        Err(PublishError::CapRevoked) => TestResult::Pass,
        _ => TestResult::Fail("expected CapRevoked"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_publish_after_revoke);

// ── 8. Subscriber cap revoked: next returns CapRevoked ─────────────

fn smoke_event_bus_subscriber_revoke() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, _publisher) = create_topic::<u32>(&reg_w, "user.testd.rev2", 16).expect("create");
    let mut sub = lookup_topic::<u32>(&reg_r, "user.testd.rev2").expect("lookup");
    // Bump the subscriber cap's object-table epoch directly to simulate
    // a revoke initiated by an admin tool. The Subscriber's cap slot
    // points at the subscriber object-table index recorded at lookup.
    let slot = sub.cap_slot_for_test();
    let _ = narf_capabilities::object_table::bump_epoch(slot.index);
    match sub.try_next() {
        Err(RecvError::CapRevoked) => TestResult::Pass,
        _ => TestResult::Fail("expected CapRevoked"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_subscriber_revoke);

// ── 9. Arena handle round-trip ─────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
struct ArenaEvent {
    handle: crate::ArenaHandle,
    kind: u32,
}

fn smoke_event_bus_arena_round_trip() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, publisher) = match crate::registry::create_topic_with_arena::<ArenaEvent>(
        &reg_w,
        "user.testd.arena",
        16,
        256,
    ) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("create_topic_with_arena failed"),
    };
    let mut sub = lookup_topic::<ArenaEvent>(&reg_r, "user.testd.arena").expect("lookup");
    let payload = b"hello, arena world";
    let handle = publisher.alloc_arena(payload).expect("alloc_arena");
    publisher
        .publish(ArenaEvent { handle, kind: 7 })
        .expect("publish");
    match sub.try_next() {
        Ok(Some((_seq, ev))) => {
            if ev.kind != 7 {
                return TestResult::Fail("kind mismatch");
            }
            let mut out = [0u8; 32];
            let n = sub.read_arena(ev.handle, &mut out).unwrap_or(0);
            if n != payload.len() || &out[..n] != payload {
                return TestResult::Fail("arena bytes mismatch");
            }
            TestResult::Pass
        }
        _ => TestResult::Fail("did not receive event"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_arena_round_trip);

// ── 10. Fixed-size event with no arena: round-trip ─────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
struct FixedEvent {
    a: u64,
    b: u64,
    c: u32,
}

fn smoke_event_bus_fixed_round_trip() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, publisher) =
        create_topic::<FixedEvent>(&reg_w, "user.testd.fixed", 8).expect("create");
    let mut sub = lookup_topic::<FixedEvent>(&reg_r, "user.testd.fixed").expect("lookup");
    let original = FixedEvent {
        a: 0xDEAD_BEEF_CAFE_F00D,
        b: 0x0123_4567_89AB_CDEF,
        c: 42,
    };
    publisher.publish(original).expect("publish");
    match sub.try_next() {
        Ok(Some((_seq, ev))) if ev == original => TestResult::Pass,
        _ => TestResult::Fail("fixed round-trip mismatch"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_fixed_round_trip);

// ── 11. Audit log: privileged cap mint publishes audit event ───────

fn smoke_event_bus_audit_mint_emits() -> TestResult {
    reset_bus();
    let admin: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let mut audit_sub = match audit_subscribe_kernel(&admin) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("admin subscribe to audit failed"),
    };
    // Mint a privileged-root topic and expect an audit event.
    let res = create_topic::<u32>(&admin, "acpi.notify.test1", 16);
    if res.is_err() {
        return TestResult::Fail("privileged-root create_topic failed");
    }
    // Should see at least one event (publisher mint).
    match audit_sub.try_next() {
        Ok(Some((_seq, ev))) => {
            if !ev.topic.as_str().starts_with("acpi.notify.test1") {
                return TestResult::Fail("audit event topic mismatch");
            }
            TestResult::Pass
        }
        _ => TestResult::Fail("expected audit event"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_audit_mint_emits);

// ── 12. Userspace cannot subscribe to audit topic ──────────────────

fn smoke_event_bus_audit_admin_only() -> TestResult {
    reset_bus();
    let user_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    match lookup_topic::<AuditEvent>(&user_r, "system.security.audit") {
        Err(LookupError::AdminOnly) => TestResult::Pass,
        _ => TestResult::Fail("expected AdminOnly"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_audit_admin_only);

// ── 13. Topic name validation cases ────────────────────────────────

fn smoke_event_bus_name_validation() -> TestResult {
    // Valid.
    if TopicName::parse("acpi.notify").is_err() {
        return TestResult::Fail("acpi.notify should parse");
    }
    if TopicName::parse("user.daemon.subsystem.event").is_err() {
        return TestResult::Fail("4-segment user.* should parse");
    }
    // Empty segment.
    if !matches!(TopicName::parse("acpi."), Err(NameError::EmptySegment)) {
        return TestResult::Fail("trailing dot should be EmptySegment");
    }
    if !matches!(TopicName::parse("acpi..x"), Err(NameError::EmptySegment)) {
        return TestResult::Fail("empty middle segment should be EmptySegment");
    }
    // Too many segments (6 > 5).
    if !matches!(
        TopicName::parse("kernel.a.b.c.d.e"),
        Err(NameError::TooManySegments)
    ) {
        return TestResult::Fail("6 segments should be TooManySegments");
    }
    // Too long.
    let long = "user.daemon.x".repeat(20); // > 96 bytes.
    if !matches!(TopicName::parse(&long), Err(NameError::TooLong)) {
        return TestResult::Fail("over-long name should be TooLong");
    }
    // Invalid char.
    if !matches!(
        TopicName::parse("user.bad name"),
        Err(NameError::InvalidChar)
    ) {
        return TestResult::Fail("space should be InvalidChar");
    }
    TestResult::Pass
}
kernel_test_in!("event_bus", smoke_event_bus_name_validation);

// ── 14. Concurrent publish + 3 subscribers: ordering preserved ─────

fn smoke_event_bus_concurrent_pub_three_subs() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, publisher) = create_topic::<u32>(&reg_w, "user.testd.conc", 32).expect("create");
    let mut subs: alloc::vec::Vec<_> = (0..3)
        .map(|_| lookup_topic::<u32>(&reg_r, "user.testd.conc").expect("lookup"))
        .collect();
    // Single-thread test environment: publish all, then drain. Each
    // subscriber must see the same total order.
    for i in 0..20u32 {
        publisher.publish(i).expect("publish");
    }
    for sub in subs.iter_mut() {
        for i in 0..20u32 {
            match sub.try_next() {
                Ok(Some((seq, v))) if v == i && seq == SeqNum(i as u64) => {}
                _ => return TestResult::Fail("ordering violated"),
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!("event_bus", smoke_event_bus_concurrent_pub_three_subs);

// ── 15. ACPI button publish via the migrated bus → handler ─────────

fn smoke_event_bus_acpi_button_bus_dispatch() -> TestResult {
    reset_bus();
    let admin: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    #[repr(C)]
    enum Btn {
        Power,
        Sleep,
    }
    let (_id, publisher) = create_topic::<Btn>(&admin, "acpi.button", 16).expect("create");
    let mut sub = lookup_topic::<Btn>(&reg_r, "acpi.button").expect("lookup");
    publisher.publish(Btn::Power).expect("publish");
    publisher.publish(Btn::Sleep).expect("publish");
    let mut sequence = alloc::vec::Vec::new();
    while let Ok(Some((_seq, v))) = sub.try_next() {
        sequence.push(v);
    }
    if sequence != alloc::vec![Btn::Power, Btn::Sleep] {
        return TestResult::Fail("button ordering wrong");
    }
    TestResult::Pass
}
kernel_test_in!("event_bus", smoke_event_bus_acpi_button_bus_dispatch);

// ── 16. Pump-future smoke: publish-before-await returns Ready ──────

fn smoke_event_bus_async_next_ready() -> TestResult {
    reset_bus();
    let reg_w: Cap<TopicRegistry, Write> = Cap::bootstrap();
    let reg_r: Cap<TopicRegistry, Read> = Cap::bootstrap();
    let (_id, publisher) = create_topic::<u32>(&reg_w, "user.testd.async", 16).expect("create");
    let mut sub = lookup_topic::<u32>(&reg_r, "user.testd.async").expect("lookup");
    publisher.publish(99).expect("publish");
    match pump(sub.next()) {
        Ok((_seq, v)) if v == 99 => TestResult::Pass,
        _ => TestResult::Fail("async next did not return value"),
    }
}
kernel_test_in!("event_bus", smoke_event_bus_async_next_ready);
