//! Exact-socket deferred ACKs for native asynchronous control operations.

use super::*;
use alloc::{boxed::Box, sync::Arc};
use core::{cell::RefCell, fmt, future::Future, pin::Pin, task::Poll};
use zeroize::Zeroizing;

#[cfg(feature = "kernel-test")]
#[path = "netlink_generic_deferred_tests.rs"]
mod tests;

const EBUSY: i32 = 16;
const ECANCELED: i32 = 125;

/// Supplied by the actual sending socket. Production implementations retain
/// a Weak to that exact socket, never a namespace/port-id lookup. The sink
/// grants no interface control authority.
pub trait DeferredReplySink: fmt::Debug + Send + Sync {
    fn current(&self) -> bool;
    /// Concrete weak source observation supplied only by the actual socket
    /// provider after its full current check. Unknown providers cannot arm
    /// autonomous native emission. This observation grants no administration.
    fn native_source(&self) -> Option<crate::native_emission::Lifetime> {
        None
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32>;
    /// Retain an actual fresh control-child grant on this exact source.
    /// No name lookup, WDEV or wire bytes create administration. Legacy
    /// sinks do not implement control-child delegation.
    fn retain_control_admin(&self, _admin: crate::AdminHandle) -> Result<(), i32> {
        Err(EOPNOTSUPP)
    }
    /// Resolve only a previously explicitly retained current child grant
    /// on this exact source/namespace. This supplies no ambient authority.
    fn control_admin(&self, _name: &str, _namespace: u64) -> Option<crate::AdminHandle> {
        None
    }
}

/// A family's retained current authority for the final ACK edge. This can
/// only deny completion; it does not replace that family's native checks.
pub trait DeferredAuthority: fmt::Debug + Send + Sync {
    fn current(&self) -> bool;
    /// Called only after the successful result's responses and requested
    /// ACK have reached this exact source. A lifecycle owner may commit
    /// metadata publication here; rejection, socket loss or drop never
    /// invokes it. This notification grants no interface authority.
    fn delivered(&self) {}
}

pub(super) struct PendingAck {
    future: CompletionFuture,
    authority: Option<Arc<dyn DeferredAuthority>>,
}

/// This path delays an ACK, not a multipart response or dump. The family
/// owns current interface authority and native cancellation/retirement.
pub type DeferredAckFuture = Pin<Box<dyn Future<Output = Result<(), i32>> + Send + 'static>>;
/// Terminal unicast responses from native asynchronous work. These are
/// framed with the admitted request's sequence/family, after current socket
/// and family-authority checks. Dumps remain unsupported on this path.
pub type DeferredReplyFuture =
    Pin<Box<dyn Future<Output = Result<Vec<GenlReply>, i32>> + Send + 'static>>;

enum CompletionFuture {
    Ack(DeferredAckFuture),
    Replies(DeferredReplyFuture),
}

/// Borrowed only during the synchronous family callback. A rejected
/// callback drops its unpolled future; only Ok(empty replies) can commit
/// deferred work. The future cannot borrow this request or its admin handle.
pub struct DeferredRequest {
    sink: Arc<dyn DeferredReplySink>,
    job: RefCell<Option<PendingAck>>,
    dump: bool,
}

impl fmt::Debug for DeferredRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeferredRequest")
            .field("has_job", &self.job.borrow().is_some())
            .field("dump", &self.dump)
            .finish_non_exhaustive()
    }
}

impl DeferredRequest {
    pub(super) fn new(sink: Arc<dyn DeferredReplySink>, dump: bool) -> Self {
        Self {
            sink,
            job: RefCell::new(None),
            dump,
        }
    }

    /// A liveness check for a family's retained native authority guard.
    /// It does not grant interface access or acknowledge successful work.
    pub fn reply_sink(&self) -> Arc<dyn DeferredReplySink> {
        self.sink.clone()
    }

    pub fn defer(&self, job: DeferredAckFuture) -> Result<(), i32> {
        self.defer_inner(CompletionFuture::Ack(job), None)
    }

    pub fn defer_checked(
        &self,
        job: DeferredAckFuture,
        authority: Arc<dyn DeferredAuthority>,
    ) -> Result<(), i32> {
        self.defer_inner(CompletionFuture::Ack(job), Some(authority))
    }

    pub fn defer_replies_checked(
        &self,
        job: DeferredReplyFuture,
        authority: Arc<dyn DeferredAuthority>,
    ) -> Result<(), i32> {
        self.defer_inner(CompletionFuture::Replies(job), Some(authority))
    }

    fn defer_inner(
        &self,
        job: CompletionFuture,
        authority: Option<Arc<dyn DeferredAuthority>>,
    ) -> Result<(), i32> {
        if self.dump {
            return Err(EOPNOTSUPP);
        }
        if !self.sink.current() {
            return Err(ECANCELED);
        }
        if authority.as_ref().is_some_and(|guard| !guard.current()) {
            return Err(EPERM);
        }
        let mut slot = self.job.borrow_mut();
        if slot.is_some() {
            return Err(EBUSY);
        }
        *slot = Some(PendingAck {
            future: job,
            authority,
        });
        Ok(())
    }

    pub(super) fn take(&self) -> Option<PendingAck> {
        self.job.borrow_mut().take()
    }
}

/// An additive handler, selected only when the socket supplied a bound sink.
/// Existing synchronous handlers and context-free callers keep their path.
pub type DeferredContextHandler =
    fn(u8, &[u8], bool, RequestContext<'_>, &DeferredRequest) -> Result<Vec<GenlReply>, i32>;

static DEFERRED_HANDLERS: IrqSafeSpinLock<Vec<(u16, DeferredContextHandler)>> =
    IrqSafeSpinLock::new(Vec::new());

pub fn register_deferred_context_handler(id: u16, handler: DeferredContextHandler) -> bool {
    if !FAMILIES.lock().iter().any(|family| family.id == id) {
        return false;
    }
    let mut handlers = DEFERRED_HANDLERS.lock();
    if handlers.iter().any(|(known, _)| *known == id) {
        return false;
    }
    handlers.push((id, handler));
    true
}

pub(super) fn handler(id: u16) -> Option<DeferredContextHandler> {
    DEFERRED_HANDLERS
        .lock()
        .iter()
        .find(|(known, _)| *known == id)
        .map(|(_, handler)| *handler)
}

/// Commit after the family's complete synchronous validation returned
/// Ok(empty). No hardware work has been polled before this point.
pub(super) fn spawn_ack(
    job: PendingAck,
    sink: Arc<dyn DeferredReplySink>,
    request: Zeroizing<Vec<u8>>,
    options: ReplyOptions,
    cookie: Option<u64>,
    version: u8,
) {
    match job.future {
        CompletionFuture::Ack(future) => narf_scheduler::spawn(run_ack(
            future,
            job.authority,
            sink,
            request,
            options,
            cookie,
        )),
        CompletionFuture::Replies(future) => narf_scheduler::spawn(run_replies(
            future,
            job.authority,
            sink,
            request,
            options,
            cookie,
            version,
        )),
    };
}

async fn run_ack(
    job: DeferredAckFuture,
    authority: Option<Arc<dyn DeferredAuthority>>,
    sink: Arc<dyn DeferredReplySink>,
    request: Zeroizing<Vec<u8>>,
    options: ReplyOptions,
    cookie: Option<u64>,
) {
    run_replies(
        Box::pin(async move { job.await.map(|()| Vec::new()) }),
        authority,
        sink,
        request,
        options,
        cookie,
        0,
    )
    .await;
}

async fn run_replies(
    mut job: DeferredReplyFuture,
    authority: Option<Arc<dyn DeferredAuthority>>,
    sink: Arc<dyn DeferredReplySink>,
    request: Zeroizing<Vec<u8>>,
    options: ReplyOptions,
    cookie: Option<u64>,
    version: u8,
) {
    let result = core::future::poll_fn(|cx| {
        if !sink.current() {
            return Poll::Ready(Err(ECANCELED));
        }
        if authority.as_ref().is_some_and(|guard| !guard.current()) {
            return Poll::Ready(Err(EPERM));
        }
        job.as_mut().poll(cx)
    })
    .await;
    // Dropping a native waiter requests cancellation. Its retained
    // driver owner still settles hardware before releasing resources.
    drop(job);
    if !sink.current() {
        return;
    }
    let flags = u16::from_ne_bytes([request[6], request[7]]);
    let seq = u32::from_ne_bytes(request[8..12].try_into().unwrap());
    // Keep the family's actual authority alive beyond dropping the native
    // future, and recheck it at the final publication edge too.
    let mut result = if authority.as_ref().is_some_and(|guard| !guard.current()) {
        Err(EPERM)
    } else {
        result
    };
    if let Ok(replies) = result.as_mut() {
        let family = u16::from_ne_bytes(request[4..6].try_into().unwrap());
        for reply in replies.drain(..) {
            if !sink.current() {
                return;
            }
            if authority.as_ref().is_some_and(|guard| !guard.current()) {
                break;
            }
            let mut body = vec![reply.command, version, 0, 0];
            body.extend_from_slice(&reply.attrs);
            if sink.deliver(frame(family, 0, seq, &body)).is_err() {
                return;
            }
        }
    }
    if !sink.current() {
        return;
    }
    if authority.as_ref().is_some_and(|guard| !guard.current()) {
        result = Err(EPERM);
    }
    let errno = match result {
        Ok(_) if flags & NLM_F_ACK == 0 => {
            if let Some(authority) = authority.as_ref() {
                authority.delivered();
            }
            return;
        }
        Ok(_) => 0,
        Err(errno) => errno,
    };
    let mut ack = error(errno, seq, &request);
    // Linux netlink_ack always caps a successful ACK; CAP_ACK also caps
    // errors. In particular, a successful NEW_KEY never echoes its key.
    if options.cap_ack || errno == 0 {
        cap_acknowledgement(&mut ack);
    }
    if options.ext_ack && errno == 0 {
        if let Some(cookie) = cookie {
            push_attr(&mut ack, NLMSGERR_ATTR_COOKIE, &cookie.to_ne_bytes());
            let len = ack.len() as u32;
            ack[..4].copy_from_slice(&len.to_ne_bytes());
            let flags = u16::from_ne_bytes([ack[6], ack[7]]) | NLM_F_ACK_TLVS;
            ack[6..8].copy_from_slice(&flags.to_ne_bytes());
        }
    }
    if options.ext_ack {
        append_extended_ack(&mut ack);
    }
    if sink.deliver(ack).is_ok() && errno == 0 {
        if let Some(authority) = authority.as_ref() {
            authority.delivered();
        }
    }
}
