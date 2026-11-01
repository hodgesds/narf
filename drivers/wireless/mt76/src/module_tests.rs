//! Deferred native fixtures for the real module wire/retained-work boundary.
use super::*;
use core::sync::atomic::AtomicUsize;
use narf_kernel_test::{kernel_test_in, TestResult};

struct Held {
    ready: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    polls: Arc<AtomicUsize>,
}
impl Future for Held {
    type Output = Result<Reply, i32>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.polls.fetch_add(1, Ordering::AcqRel);
        if self.ready.load(Ordering::Acquire) {
            Poll::Ready(Ok(Reply::plain(alloc::vec![7, 9])))
        } else {
            Poll::Pending
        }
    }
}
impl Drop for Held {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::AcqRel);
    }
}
type HeldFixture = (
    Operation,
    Arc<AtomicBool>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
);
fn held() -> HeldFixture {
    let ready = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicUsize::new(0));
    let polls = Arc::new(AtomicUsize::new(0));
    let operation = Operation {
        id: 9,
        started: false,
        cancelled: false,
        future: Some(Box::pin(Held {
            ready: ready.clone(),
            dropped: dropped.clone(),
            polls: polls.clone(),
        })),
        result: None,
    };
    (operation, ready, dropped, polls)
}
fn smoke_mt76_module_cancel_retains_started_native_work_until_actual_terminal() -> TestResult {
    let (mut operation, ready, dropped, polls) = held();
    let mut cx = Context::from_waker(Waker::noop());
    operation.advance(&mut cx);
    operation.request_cancel();
    operation.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 0
        || operation.result.is_some()
        || polls.load(Ordering::Acquire) != 2
        || !operation.started
    {
        return TestResult::Fail("cancel dropped or completed held native module work");
    }
    ready.store(true, Ordering::Release);
    operation.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 1
        || operation.future.is_some()
        || !matches!(operation.result, Some(Err(-114)))
    {
        return TestResult::Fail(
            "started module cancellation invented cancelled success or missed terminal release",
        );
    }
    let (mut unstarted, _, dropped, polls) = held();
    unstarted.request_cancel();
    unstarted.advance(&mut cx);
    if dropped.load(Ordering::Acquire) != 1
        || polls.load(Ordering::Acquire) != 0
        || !matches!(unstarted.result, Some(Err(-125)))
    {
        return TestResult::Fail("unstarted module cancellation entered native work");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/module",
    smoke_mt76_module_cancel_retains_started_native_work_until_actual_terminal
);

fn smoke_mt76_module_protocol_bounds_and_real_init_identity() -> TestResult {
    let mut init = alloc::vec![0; wire::INIT_FIXED + 5];
    init[..4].copy_from_slice(&wire::VERSION.to_le_bytes());
    init[4..8].copy_from_slice(&wire::FAMILY.to_le_bytes());
    init[12..18].copy_from_slice(&[2, 1, 2, 3, 4, 5]);
    init[20..24].copy_from_slice(&27u32.to_le_bytes());
    init[57] = 5;
    init[58..].copy_from_slice(b"wlan7");
    if !wire::initialized(&init) {
        return TestResult::Fail("valid module initialization identity rejected");
    }
    for at in [0, 4, 12, 20, 57] {
        let mut bad = init.clone();
        if at == 12 {
            bad[at] |= 1;
        } else {
            bad[at] = 0;
        }
        if wire::initialized(&bad) {
            return TestResult::Fail(
                "module initialized from wrong version/family/MAC/index/length",
            );
        }
    }
    let scan = [1, 1, 1, 0, 0, 0, 0, 0, 0x6c, 9, 0, 0, 2, b'a', b'p'];
    if wire::validate(wire::SCAN, &scan).is_err() {
        return TestResult::Fail("valid bounded module scan rejected");
    }
    for at in [1, 2, 3, 4, 6, 12] {
        let mut bad = scan;
        bad[at] = 255;
        if wire::validate(wire::SCAN, &bad).is_ok() {
            return TestResult::Fail("malformed module scan accepted");
        }
    }
    let mut assoc = alloc::vec![0; 20 + 2 + 32];
    assoc[..6].copy_from_slice(&[2, 3, 4, 5, 6, 7]);
    assoc[6] = 1;
    assoc[7] = 1;
    assoc[8..12].copy_from_slice(&2412u32.to_le_bytes());
    assoc[12..14].copy_from_slice(&2u16.to_le_bytes());
    assoc[16..18].copy_from_slice(&32u16.to_le_bytes());
    assoc[20..22].copy_from_slice(b"ap");
    if wire::validate(wire::ASSOCIATE, &assoc).is_err() {
        return TestResult::Fail("valid PSK module association rejected");
    }
    for at in [0, 6, 7, 12, 14, 16, 18] {
        let mut bad = assoc.clone();
        bad[at] = 255;
        if wire::validate(wire::ASSOCIATE, &bad).is_ok() {
            return TestResult::Fail("malformed module association accepted");
        }
    }
    if wire::validate(wire::FIRMWARE_CHUNK, &[2, 0, 1, 0, 0, 0, 0, 0]).is_ok()
        || wire::validate(wire::FIRMWARE_CHUNK, &[0, 0, 0, 0, 0, 0, 0, 0]).is_ok()
        || wire::validate(99, &[]).is_ok()
        || wire::validate(wire::TRANSMIT, &[0; 13]).is_ok()
    {
        return TestResult::Fail("module ABI accepted arbitrary firmware selector/empty chunk/unknown operation/short Ethernet");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/mt7921/module",
    smoke_mt76_module_protocol_bounds_and_real_init_identity
);
