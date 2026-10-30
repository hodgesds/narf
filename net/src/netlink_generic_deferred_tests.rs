use super::*;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use core::task::{Context, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, Default)]
struct NativeReceipt {
    ready: AtomicBool,
    polls: AtomicU32,
    drops: AtomicU32,
}

struct Gate(Arc<NativeReceipt>, i32);
impl Future for Gate {
    type Output = Result<(), i32>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.0.polls.fetch_add(1, Ordering::AcqRel);
        if self.0.ready.load(Ordering::Acquire) {
            Poll::Ready(if self.1 == 0 { Ok(()) } else { Err(self.1) })
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        self.0.drops.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct Sink {
    alive: AtomicBool,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
}
impl Sink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            alive: AtomicBool::new(true),
            messages: IrqSafeSpinLock::new(Vec::new()),
        })
    }
}
impl DeferredReplySink for Sink {
    fn current(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(ECANCELED);
        }
        self.messages.lock().push(message);
        Ok(())
    }
}

fn request(command: u8, flags: u16) -> Vec<u8> {
    // A nonempty payload detects accidental success echoes of sensitive
    // command attributes; the original nlmsghdr length remains intact.
    frame(0x7e2e, flags, 0x1234_5678, &[command, 1, 0, 0, 4, 0, 1, 0])
}

fn terminal_ack_preserves_native_result_sequence_and_options() -> TestResult {
    for errno in [0, 5] {
        for cap_ack in [false, true] {
            for ext_ack in [false, true] {
                let receipt = Arc::new(NativeReceipt::default());
                let sink = Sink::new();
                let original = request(1, 5);
                let mut future = Box::pin(run_ack(
                    Box::pin(Gate(receipt.clone(), errno)),
                    None,
                    sink.clone(),
                    Zeroizing::new(original.clone()),
                    ReplyOptions { cap_ack, ext_ack },
                    Some(0x0102_0304_0506_0708),
                ));
                let mut cx = Context::from_waker(Waker::noop());
                if future.as_mut().poll(&mut cx).is_ready() || !sink.messages.lock().is_empty() {
                    return TestResult::Fail(
                        "queued control reported success before native receipt",
                    );
                }
                receipt.ready.store(true, Ordering::Release);
                if future.as_mut().poll(&mut cx).is_pending()
                    || receipt.drops.load(Ordering::Acquire) != 1
                {
                    return TestResult::Fail("terminal native result did not retire its waiter");
                }
                let messages = sink.messages.lock();
                if messages.len() != 1 {
                    return TestResult::Fail("native control did not produce exactly one ACK");
                }
                let ack = &messages[0];
                let flags = u16::from_ne_bytes(ack[6..8].try_into().unwrap());
                if ack[4..6] != NLMSG_ERROR.to_ne_bytes()
                    || ack[8..12] != 0x1234_5678u32.to_ne_bytes()
                    || ack[16..20] != (-errno).to_ne_bytes()
                    || ack[20..36] != original[..16]
                    || (flags & NLM_F_CAPPED != 0) != (errno == 0 || cap_ack)
                    || (flags & NLM_F_ACK_TLVS != 0) != ext_ack
                {
                    return TestResult::Fail("deferred ACK lost errno, sequence, echo or options");
                }
                if errno == 0 {
                    let length = if ext_ack { 48 } else { 36 };
                    if ack.len() != length
                        || ext_ack
                            && (ack[36..40] != [12, 0, 4, 0]
                                || ack[40..48] != 0x0102_0304_0506_0708u64.to_ne_bytes())
                    {
                        return TestResult::Fail("success echoed attributes or lost capped cookie");
                    }
                } else if !cap_ack && ack[36..44] != original[16..24] {
                    return TestResult::Fail("uncapped native error lost its original request");
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    terminal_ack_preserves_native_result_sequence_and_options
);

fn socket_loss_cancels_the_waiter_without_publishing_an_ack() -> TestResult {
    let receipt = Arc::new(NativeReceipt::default());
    let sink = Sink::new();
    let mut future = Box::pin(run_ack(
        Box::pin(Gate(receipt.clone(), 0)),
        None,
        sink.clone(),
        Zeroizing::new(request(1, 5)),
        ReplyOptions::default(),
        None,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx).is_ready() {
        return TestResult::Fail("native control gate did not suspend");
    }
    sink.alive.store(false, Ordering::Release);
    if future.as_mut().poll(&mut cx).is_pending()
        || receipt.polls.load(Ordering::Acquire) != 1
        || receipt.drops.load(Ordering::Acquire) != 1
        || !sink.messages.lock().is_empty()
    {
        return TestResult::Fail("closed source continued native work or published its result");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    socket_loss_cancels_the_waiter_without_publishing_an_ack
);

fn no_ack_requests_still_execute_and_report_actual_errors() -> TestResult {
    let mut cx = Context::from_waker(Waker::noop());
    for errno in [0, 5] {
        let receipt = Arc::new(NativeReceipt::default());
        receipt.ready.store(true, Ordering::Release);
        let sink = Sink::new();
        let mut future = Box::pin(run_ack(
            Box::pin(Gate(receipt.clone(), errno)),
            None,
            sink.clone(),
            Zeroizing::new(request(1, 1)),
            ReplyOptions::default(),
            None,
        ));
        if future.as_mut().poll(&mut cx).is_pending()
            || receipt.polls.load(Ordering::Acquire) != 1
            || sink.messages.lock().len() != usize::from(errno != 0)
        {
            return TestResult::Fail("NLM_F_ACK absence suppressed work/error or invented success");
        }
    }
    let sink = Sink::new();
    let dump = DeferredRequest::new(sink, true);
    let receipt = Arc::new(NativeReceipt::default());
    if dump.defer(Box::pin(Gate(receipt.clone(), 0))) != Err(EOPNOTSUPP)
        || receipt.polls.load(Ordering::Acquire) != 0
        || receipt.drops.load(Ordering::Acquire) != 1
        || dump.take().is_some()
    {
        return TestResult::Fail("multipart dump admitted an unsupported deferred control job");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    no_ack_requests_still_execute_and_report_actual_errors
);

#[derive(Debug)]
struct Authority(AtomicBool);
impl DeferredAuthority for Authority {
    fn current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
struct RevokeAtReceipt(Arc<Authority>);
impl Future for RevokeAtReceipt {
    type Output = Result<(), i32>;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        self.0 .0.store(false, Ordering::Release);
        Poll::Ready(Ok(()))
    }
}
fn authority_is_retained_and_rechecked_at_terminal_ack_publication() -> TestResult {
    let authority = Arc::new(Authority(AtomicBool::new(true)));
    let sink = Sink::new();
    let mut future = Box::pin(run_ack(
        Box::pin(RevokeAtReceipt(authority.clone())),
        Some(authority.clone()),
        sink.clone(),
        Zeroizing::new(request(1, 5)),
        ReplyOptions::default(),
        None,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx).is_pending()
        || sink.messages.lock().len() != 1
        || sink.messages.lock()[0][16..20] != (-EPERM).to_ne_bytes()
    {
        return TestResult::Fail("revocation at native receipt published a successful ACK");
    }
    let slot = DeferredRequest::new(sink, false);
    let receipt = Arc::new(NativeReceipt::default());
    if slot.defer_checked(Box::pin(Gate(receipt.clone(), 0)), authority) != Err(EPERM)
        || receipt.polls.load(Ordering::Acquire) != 0
        || receipt.drops.load(Ordering::Acquire) != 1
    {
        return TestResult::Fail("revoked authority admitted a new deferred native operation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    authority_is_retained_and_rechecked_at_terminal_ack_publication
);

static RECEIPT: IrqSafeSpinLock<Option<Arc<NativeReceipt>>> = IrqSafeSpinLock::new(None);
const ID: u16 = 0x7e2e;
const OPS: &[GenlOperation] = &[
    GenlOperation {
        command: 1,
        flags: GENL_CMD_CAP_DO | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 2,
        flags: GENL_CMD_CAP_DO | GENL_UNS_ADMIN_PERM,
    },
    GenlOperation {
        command: 3,
        flags: GENL_CMD_CAP_DO | GENL_UNS_ADMIN_PERM,
    },
];
fn handler(_: u8, _: &[u8], _: bool) -> Result<Vec<GenlReply>, i32> {
    Err(EOPNOTSUPP)
}
fn deferred_handler(
    command: u8,
    _: &[u8],
    _: bool,
    _: RequestContext<'_>,
    slot: &DeferredRequest,
) -> Result<Vec<GenlReply>, i32> {
    let receipt = RECEIPT.lock().as_ref().cloned().ok_or(ENOENT)?;
    slot.defer(Box::pin(Gate(receipt, 0)))?;
    match command {
        1 => Ok(Vec::new()),
        2 => Err(EINVAL),
        _ => Ok(vec![GenlReply {
            command,
            attrs: Vec::new(),
        }]),
    }
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        FAMILIES.lock().retain(|family| family.id != ID);
        DEFERRED_HANDLERS.lock().retain(|(id, _)| *id != ID);
        RECEIPT.lock().take();
    }
}

fn native_router_defers_only_successful_empty_admission() -> TestResult {
    if FAMILIES.lock().iter().any(|family| family.id == ID) {
        return TestResult::Fail("reserved deferred-test family already registered");
    }
    let _restore = Restore;
    if !register_family(GenlFamily {
        id: ID,
        name: "narf-deferred-test",
        version: 1,
        max_attr: 1,
        operations: OPS,
        groups: &[],
        handler,
    }) || !register_deferred_context_handler(ID, deferred_handler)
    {
        return TestResult::Fail("native deferred family registration");
    }
    let context = RequestContext {
        net_admin: true,
        ..RequestContext::default()
    };
    let sink = Sink::new();
    for command in [2, 3] {
        let receipt = Arc::new(NativeReceipt::default());
        *RECEIPT.lock() = Some(receipt.clone());
        let Ok(messages) = build_replies_with_endpoint(
            &request(command, 5),
            ReplyOptions::default(),
            context,
            sink.clone(),
        ) else {
            return TestResult::Fail("native rejected deferred dispatch framing");
        };
        if messages.len() != 1
            || messages[0][16..20] != (-EINVAL).to_ne_bytes()
            || receipt.polls.load(Ordering::Acquire) != 0
            || receipt.drops.load(Ordering::Acquire) != 1
            || !sink.messages.lock().is_empty()
        {
            return TestResult::Fail(
                "rejected/mixed callback started work or acknowledged success",
            );
        }
    }
    let receipt = Arc::new(NativeReceipt::default());
    *RECEIPT.lock() = Some(receipt.clone());
    if !matches!(build_replies_with_endpoint(
        &request(1, 5), ReplyOptions::default(), context, sink.clone(),
    ), Ok(messages) if messages.is_empty())
        || receipt.polls.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail("deferred native dispatch emitted an early ACK");
    }
    narf_scheduler::poll_one_round();
    if receipt.polls.load(Ordering::Acquire) == 0 || !sink.messages.lock().is_empty() {
        return TestResult::Fail("native deferred task did not remain pending at its receipt");
    }
    receipt.ready.store(true, Ordering::Release);
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if !sink.messages.lock().is_empty() {
            break;
        }
    }
    if sink.messages.lock().len() != 1 || receipt.drops.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("native deferred task lost its terminal ACK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    native_router_defers_only_successful_empty_admission
);
