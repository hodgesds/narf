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
    GenlOperation {
        command: 4,
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
    if command == 4 {
        slot.defer_replies_checked(
            Box::pin(async move {
                Gate(receipt, 0).await?;
                Ok(vec![GenlReply {
                    command: 4,
                    attrs: vec![8, 0, 1, 0, 0x76, 0, 0, 0],
                }])
            }),
            Arc::new(Authority(AtomicBool::new(true))),
        )?;
        return Ok(Vec::new());
    }
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
    sink.messages.lock().clear();
    let receipt = Arc::new(NativeReceipt::default());
    *RECEIPT.lock() = Some(receipt.clone());
    if !matches!(build_replies_with_endpoint(&request(4,5),ReplyOptions::default(),context,sink.clone()),Ok(messages) if messages.is_empty())
    {
        return TestResult::Fail("native result-bearing dispatch admission");
    }
    narf_scheduler::poll_one_round();
    if !sink.messages.lock().is_empty() {
        return TestResult::Fail("native result-bearing dispatch returned an early cookie");
    }
    receipt.ready.store(true, Ordering::Release);
    for _ in 0..16 {
        narf_scheduler::poll_one_round();
        if sink.messages.lock().len() == 2 {
            break;
        }
    }
    let messages = sink.messages.lock();
    if messages.len() != 2
        || messages[0][4..6] != ID.to_ne_bytes()
        || messages[0][8..12] != 0x12345678u32.to_ne_bytes()
        || messages[0][16..20] != [4, 1, 0, 0]
        || messages[0][20..28] != [8, 0, 1, 0, 0x76, 0, 0, 0]
        || messages[1][16..20] != [0; 4]
        || receipt.drops.load(Ordering::Acquire) != 1
    {
        return TestResult::Fail(
            "native terminal replies lost admitted family/version/sequence or final ACK",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    native_router_defers_only_successful_empty_admission
);

fn terminal_replies_recheck_exact_socket_and_authority_before_payload() -> TestResult {
    for boundary in 0..3 {
        let authority = Arc::new(Authority(AtomicBool::new(true)));
        let sink = Sink::new();
        let replacement = Sink::new();
        let receipt = Arc::new(NativeReceipt::default());
        let captured = receipt.clone();
        let revoke = authority.clone();
        let future = Box::pin(async move {
            Gate(captured, 0).await?;
            if boundary == 2 {
                revoke.0.store(false, Ordering::Release);
            }
            Ok(vec![GenlReply {
                command: 7,
                attrs: vec![4, 0, 1, 0],
            }])
        });
        let mut task = Box::pin(run_replies(
            future,
            Some(authority),
            sink.clone(),
            Zeroizing::new(request(4, 5)),
            ReplyOptions::default(),
            None,
            3,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if task.as_mut().poll(&mut cx).is_ready() || !sink.messages.lock().is_empty() {
            return TestResult::Fail("native result appeared before terminal receipt");
        }
        if boundary == 1 {
            sink.alive.store(false, Ordering::Release);
        }
        receipt.ready.store(true, Ordering::Release);
        if task.as_mut().poll(&mut cx).is_pending()
            || receipt.drops.load(Ordering::Acquire) != 1
            || !replacement.messages.lock().is_empty()
        {
            return TestResult::Fail(
                "deferred reply lost native cancellation or retargeted a replacement socket",
            );
        }
        let messages = sink.messages.lock();
        match boundary {
            0 if messages.len() == 2
                && messages[0][16..20] == [7, 3, 0, 0]
                && messages[1][16..20] == [0; 4] => {}
            1 if messages.is_empty() => (),
            2 if messages.len() == 1
                && messages[0][4..6] == NLMSG_ERROR.to_ne_bytes()
                && messages[0][16..20] == (-EPERM).to_ne_bytes() => {}
            _ => {
                return TestResult::Fail(
                    "deferred native payload ignored final socket/authority ownership",
                )
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    terminal_replies_recheck_exact_socket_and_authority_before_payload
);

#[derive(Debug)]
struct ReentrantSink {
    sink: Arc<Sink>,
    authority: Arc<Authority>,
}
impl DeferredReplySink for ReentrantSink {
    fn current(&self) -> bool {
        self.sink.current()
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        self.sink.deliver(message)?;
        self.authority.0.store(false, Ordering::Release);
        Ok(())
    }
}
fn each_deferred_reply_and_final_ack_rechecks_after_reentrant_delivery() -> TestResult {
    let authority = Arc::new(Authority(AtomicBool::new(true)));
    let storage = Sink::new();
    let sink = Arc::new(ReentrantSink {
        sink: storage.clone(),
        authority: authority.clone(),
    });
    let future = Box::pin(async {
        Ok(vec![
            GenlReply {
                command: 7,
                attrs: Vec::new(),
            },
            GenlReply {
                command: 8,
                attrs: Vec::new(),
            },
        ])
    });
    let mut task = Box::pin(run_replies(
        future,
        Some(authority),
        sink,
        Zeroizing::new(request(4, 5)),
        ReplyOptions::default(),
        None,
        3,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if task.as_mut().poll(&mut cx).is_pending() {
        return TestResult::Fail("ready native reply unexpectedly pending");
    }
    let messages = storage.messages.lock();
    if messages.len() != 2
        || messages[0][16] != 7
        || messages[1][4..6] != NLMSG_ERROR.to_ne_bytes()
        || messages[1][16..20] != (-EPERM).to_ne_bytes()
    {
        return TestResult::Fail(
            "a later payload/success ACK survived revocation by prior delivery",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    each_deferred_reply_and_final_ack_rechecks_after_reentrant_delivery
);

#[derive(Debug, Default)]
struct Publication {
    lost: AtomicBool,
    committed: AtomicU32,
}
impl DeferredAuthority for Publication {
    fn current(&self) -> bool {
        !self.lost.load(Ordering::Acquire)
    }
    fn delivered(&self) {
        self.committed.fetch_add(1, Ordering::AcqRel);
    }
}
#[derive(Debug)]
struct PublicationSink {
    sink: Arc<Sink>,
    calls: AtomicU32,
    fail_on: u32,
    lose_on: u32,
    publication: Arc<Publication>,
}
impl DeferredReplySink for PublicationSink {
    fn current(&self) -> bool {
        self.sink.current()
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        let number = self.calls.fetch_add(1, Ordering::AcqRel) + 1;
        if number == self.fail_on {
            return Err(125);
        }
        let delivered = self.sink.deliver(message);
        if number == self.lose_on {
            self.publication.lost.store(true, Ordering::Release);
        }
        delivered
    }
}
fn terminal_publication_commits_only_after_successful_replies_and_requested_ack() -> TestResult {
    for (flags, fail_on, native_errno, expected) in [
        (1, 0, 0, 1),
        (5, 0, 0, 1),
        (5, 1, 0, 0),
        (5, 2, 0, 0),
        (5, 0, 5, 0),
    ] {
        let publication = Arc::new(Publication::default());
        let sink = Arc::new(PublicationSink {
            sink: Sink::new(),
            calls: AtomicU32::new(0),
            fail_on,
            lose_on: 0,
            publication: publication.clone(),
        });
        let mut future = Box::pin(run_replies(
            Box::pin(async move {
                if native_errno != 0 {
                    Err(native_errno)
                } else {
                    Ok(alloc::vec![GenlReply {
                        command: 7,
                        attrs: alloc::vec![4, 0, 1, 0]
                    }])
                }
            }),
            Some(publication.clone()),
            sink,
            Zeroizing::new(request(7, flags)),
            ReplyOptions::default(),
            None,
            1,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_pending()
            || publication.committed.load(Ordering::Acquire) != expected
        {
            return TestResult::Fail("terminal publication committed before every successful response/ACK, or missed no-ACK success");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    terminal_publication_commits_only_after_successful_replies_and_requested_ack
);
fn terminal_publication_rechecks_family_authority_after_a_response_delivery() -> TestResult {
    let publication = Arc::new(Publication::default());
    let sink = Sink::new();
    let endpoint = Arc::new(PublicationSink {
        sink: sink.clone(),
        calls: AtomicU32::new(0),
        fail_on: 0,
        lose_on: 1,
        publication: publication.clone(),
    });
    let mut future = Box::pin(run_replies(
        Box::pin(async {
            Ok(alloc::vec![GenlReply {
                command: 7,
                attrs: Vec::new()
            }])
        }),
        Some(publication.clone()),
        endpoint,
        Zeroizing::new(request(7, 5)),
        ReplyOptions::default(),
        None,
        1,
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx).is_pending()
        || publication.committed.load(Ordering::Acquire) != 0
    {
        return TestResult::Fail(
            "lost authority committed lifecycle metadata after response delivery",
        );
    }
    let messages = sink.messages.lock();
    if messages.len() != 2 || messages[1].get(16..20) != Some(&(-EPERM).to_ne_bytes()) {
        return TestResult::Fail("authority loss at final publication became a successful ACK");
    }
    TestResult::Pass
}
kernel_test_in!(
    "net/generic_deferred",
    terminal_publication_rechecks_family_authority_after_a_response_delivery
);
