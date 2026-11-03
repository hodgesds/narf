//! Bounded GuC event/crash relay with one source flush/cursor/ack owner.
//!
//! MIT Linux b90c984d: i915 intel_guc_log.c relay/control actions and
//! xe/abi/guc_log_abi.h. NARFGSTR v2 reports firmware modulo-counter lower
//! bounds and exact per-reader host overwrites. Only the GT worker accesses
//! live DMA/CT; descriptor reads and readiness are entirely cached.
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_guc::GuCMessage,
    intel_gpu_guc_log::Identity,
    intel_gpu_guc_transport::{TransportError, XeLpgTransport},
    intel_gpu_rcs::{GpuAllocator, GpuBacking},
};
use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{fence, AtomicBool, AtomicU64, AtomicU8, Ordering};
use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_ERR, POLL_HUP, POLL_IN,
};
use narf_lib::{readiness::Readiness, sync::IrqSafeSpinLock};

const MAX_CARDS: usize = 64;
const HEADER: usize = 256;
const FRAME: usize = HEADER + 0x14000;
const READERS: usize = 4;
const DATA: u32 = 1;
const FW_LOSS: u32 = 2;
const EVENT_RING_IMAGE: u32 = 4;
const CRASH_RING_IMAGE: u32 = 8;
const FW_MODULO_BOUND: u32 = 16;
const START_GAP: u32 = 32;
const HOST_LOSS: u32 = 64;
const HOST_SATURATED: u32 = 128;
const TIMEOUT: u64 = 500_000_000;
pub(crate) const FIRST_FENCE: u16 = 0x7f00;
pub(crate) const LAST_FENCE: u16 = 0x7ffc;
pub(crate) const ACK_FENCE: u16 = 0x7fff;
static ACTIVE: [AtomicBool; MAX_CARDS] = [const { AtomicBool::new(false) }; MAX_CARDS];
pub(crate) struct Publication {
    serial: AtomicU64,
    incarnation: AtomicU64,
}
impl Publication {
    pub(crate) fn new() -> Self {
        Self {
            serial: AtomicU64::new(0),
            incarnation: AtomicU64::new(0),
        }
    }
}
static NEXT_PUBLICATION: AtomicU64 = AtomicU64::new(1);
static PUBLICATIONS: IrqSafeSpinLock<[Weak<Publication>; MAX_CARDS]> =
    IrqSafeSpinLock::new([const { Weak::new() }; MAX_CARDS]);
static ROOTS: IrqSafeSpinLock<[Weak<StreamSession>; MAX_CARDS]> =
    IrqSafeSpinLock::new([const { Weak::new() }; MAX_CARDS]);

fn opted_in(args: narf_boot::args::KernelCmdline<'_>) -> bool {
    let mut values = args
        .tokens()
        .filter_map(|s| s.strip_prefix("narf.intel.guc_stream="));
    values.next() == Some("1") && values.next().is_none() && !args.has_flag("narf.intel.guc_stream")
}
pub(crate) fn enabled() -> bool {
    opted_in(narf_boot::args())
}
fn capable() -> bool {
    narf_filesystem::caller_capable(34) && narf_filesystem::caller_capable(21)
}
#[derive(Copy, Clone)]
struct Gate {
    enabled: fn() -> bool,
    capable: fn() -> bool,
}
impl Gate {
    const PHYSICAL: Self = Self { enabled, capable };
    fn check(self) -> Result<(), FsError> {
        if (self.enabled)() && (self.capable)() {
            Ok(())
        } else {
            Err(FsError::OperationNotPermitted)
        }
    }
}
struct Permit(u32, bool);
impl Drop for Permit {
    fn drop(&mut self) {
        if self.1 {
            ACTIVE[self.0 as usize].store(false, Ordering::Release);
        }
    }
}
struct Buffer {
    bytes: Vec<u8>,
    len: usize,
    read: usize,
}
impl Buffer {
    fn new() -> Result<Self, FsError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(FRAME)
            .map_err(|_| FsError::OutOfMemory)?;
        bytes.resize(FRAME, 0);
        Ok(Self {
            bytes,
            len: 0,
            read: 0,
        })
    }
}
struct Queue {
    free: [Option<Buffer>; 2],
    ready: [Option<Buffer>; 2],
    head: usize,
    len: usize,
    terminal: Option<FsError>,
    lost_frames: u64,
    lost_bytes: u64,
    saturated: bool,
    first_sequence: Option<u64>,
}
/// One privileged open-file description. Dup shares the same FIFO; copied
/// records remain readable after reset, followed by an explicit terminal error.
pub struct StreamSession {
    queue: IrqSafeSpinLock<Queue>,
    ready: Readiness,
    attached: AtomicBool,
    stop: AtomicBool,
    reader_closed: AtomicBool,
    relay_failed: AtomicBool,
    /// Followers retain the original source owner; the root holds only Weak
    /// followers. One source actor and fence lease remain authoritative.
    root: Option<Arc<StreamSession>>,
    /// Nonzero cached actual firmware incarnation sampled at open. Runtime
    /// user epochs can survive park, so they cannot identify this request.
    publication: Option<Arc<Publication>>,
    request_serial: u64,
    request_incarnation: u64,
    followers: IrqSafeSpinLock<[Weak<StreamSession>; READERS - 1]>,
    retained_followers: AtomicU8,
    /// Independent producer storage prevents a slow/partial reader from
    /// blocking source cursor/ACK progress. Allocated before actor attachment.
    staging: IrqSafeSpinLock<Option<Buffer>>,
    /// One spare rotates through all reader queues. Copy outside their locks,
    /// then commit data, eviction accounting and terminal ordering together.
    fanout_spare: IrqSafeSpinLock<Option<Buffer>>,
    // Drop storage before returning either quota. A retained revoked/closed
    // reader consumes its slot until its copied buffers are actually freed.
    _follower_quota: Option<FollowerQuota>,
    permit: Permit,
}
struct FollowerQuota(Arc<StreamSession>);
impl Drop for FollowerQuota {
    fn drop(&mut self) {
        self.0.retained_followers.fetch_sub(1, Ordering::AcqRel);
    }
}
impl core::fmt::Debug for StreamSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GuCStreamSession")
            .field(&self.index())
            .finish()
    }
}
impl StreamSession {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn reserve_for_test(index: u32) -> Result<Arc<Self>, FsError> {
        Self::reserve(index)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn subscribe_for_test(self: &Arc<Self>) -> Result<Arc<Self>, FsError> {
        self.subscribe()
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn read_for_test(&self, out: &mut [u8]) -> Result<usize, FsError> {
        self.read(out)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn stop_for_test(&self) {
        self.stop.store(true, Ordering::Release);
    }
    fn reserve(index: u32) -> Result<Arc<Self>, FsError> {
        ACTIVE
            .get(index as usize)
            .ok_or(FsError::NoDevice)?
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| FsError::Busy)?;
        Self::allocate(Permit(index, true), None)
    }
    fn allocate(permit: Permit, root: Option<Arc<Self>>) -> Result<Arc<Self>, FsError> {
        let free = [Some(Buffer::new()?), Some(Buffer::new()?)];
        let staging = if root.is_none() {
            Some(Buffer::new()?)
        } else {
            None
        };
        let fanout_spare = if root.is_none() {
            Some(Buffer::new()?)
        } else {
            None
        };
        let follower_quota = root.as_ref().map(|root| FollowerQuota(root.clone()));
        Ok(Arc::new(Self {
            queue: IrqSafeSpinLock::new(Queue {
                free,
                ready: [None, None],
                head: 0,
                len: 0,
                terminal: None,
                lost_frames: 0,
                lost_bytes: 0,
                saturated: false,
                first_sequence: None,
            }),
            ready: Readiness::new(0),
            attached: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            reader_closed: AtomicBool::new(false),
            relay_failed: AtomicBool::new(false),
            root,
            publication: None,
            request_serial: 0,
            request_incarnation: 0,
            retained_followers: AtomicU8::new(0),
            followers: IrqSafeSpinLock::new([const { Weak::new() }; READERS - 1]),
            staging: IrqSafeSpinLock::new(staging),
            fanout_spare: IrqSafeSpinLock::new(fanout_spare),
            _follower_quota: follower_quota,
            permit,
        }))
    }
    fn open(index: u32) -> Result<Arc<Self>, FsError> {
        let publication = PUBLICATIONS
            .lock()
            .get(index as usize)
            .ok_or(FsError::NoDevice)?
            .upgrade()
            .ok_or(FsError::Unsupported)?;
        let (serial, incarnation, existing) = {
            let roots = ROOTS.lock();
            (
                publication.serial.load(Ordering::Acquire),
                publication.incarnation.load(Ordering::Acquire),
                roots[index as usize].upgrade(),
            )
        };
        if serial == 0 || incarnation == 0 {
            return Err(FsError::NoDevice);
        }
        if let Some(root) = existing {
            if root.request_serial != serial || root.requested_incarnation() != Some(incarnation) {
                root.fail(FsError::NoDevice);
                return Err(FsError::NoDevice);
            }
            return root.subscribe();
        }
        // Allocation is outside both registries. Claim before allocation;
        // insertion and publication closure share ROOTS, closing the race
        // where reset could miss an allocated-but-not-yet-queued request.
        let mut root = Self::reserve(index)?;
        let unique = Arc::get_mut(&mut root).expect("unpublished source owner");
        unique.publication = Some(publication.clone());
        unique.request_serial = serial;
        unique.request_incarnation = incarnation;
        let mut roots = ROOTS.lock();
        if publication.serial.load(Ordering::Acquire) != serial
            || publication.incarnation.load(Ordering::Acquire) != incarnation
        {
            return Err(FsError::NoDevice);
        }
        roots[index as usize] = Arc::downgrade(&root);
        Ok(root)
    }
    pub(crate) fn requested_incarnation(&self) -> Option<u64> {
        self.publication.as_ref().and_then(|publication| {
            (self.request_serial != 0
                && self.request_incarnation != 0
                && publication.serial.load(Ordering::Acquire) == self.request_serial
                && publication.incarnation.load(Ordering::Acquire) == self.request_incarnation)
                .then_some(self.request_incarnation)
        })
    }
    fn subscribe(self: &Arc<Self>) -> Result<Arc<Self>, FsError> {
        self.retained_followers
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < (READERS - 1) as u8).then_some(n + 1)
            })
            .map_err(|_| FsError::Busy)?;
        let reader = match Self::allocate(Permit(self.index(), false), Some(self.clone())) {
            Ok(reader) => reader,
            Err(error) => {
                self.retained_followers.fetch_sub(1, Ordering::AcqRel);
                return Err(error);
            }
        };
        let mut followers = self.followers.lock();
        if self.stop.load(Ordering::Acquire)
            || self.relay_failed.load(Ordering::Acquire)
            || (self.publication.is_some() && self.requested_incarnation().is_none())
        {
            return Err(FsError::Busy);
        }
        let slot = followers
            .iter_mut()
            .find(|s| s.upgrade().is_none())
            .ok_or(FsError::Busy)?;
        *slot = Arc::downgrade(&reader);
        Ok(reader)
    }
    fn receivers(self: &Arc<Self>) -> [Option<Arc<Self>>; READERS] {
        let followers = self.followers.lock();
        core::array::from_fn(|i| {
            if i == 0 {
                Some(self.clone())
            } else {
                followers[i - 1].upgrade()
            }
        })
    }
    fn close_reader(&self) {
        self.reader_closed.store(true, Ordering::Release);
        let root = self.root.as_deref().unwrap_or(self);
        let followers = root.followers.lock();
        if root.reader_closed.load(Ordering::Acquire)
            && followers.iter().all(|r| {
                r.upgrade()
                    .is_none_or(|r| r.reader_closed.load(Ordering::Acquire))
            })
        {
            root.stop.store(true, Ordering::Release);
        }
    }
    fn fail_reader(&self, error: FsError) {
        self.queue.lock().terminal.get_or_insert(error);
        self.ready.set_wake_all(POLL_ERR | POLL_HUP, 0);
        self.close_reader();
    }
    fn take_staging(&self) -> Option<Buffer> {
        self.staging.lock().take()
    }
    fn deliver(&self, source: &Buffer, mut spare: Buffer) -> Buffer {
        if self.reader_closed.load(Ordering::Acquire) {
            return spare;
        }
        // These are owned host buffers; copy outside the IRQ-safe queue lock.
        spare.bytes[..source.len].copy_from_slice(&source.bytes[..source.len]);
        spare.len = source.len;
        spare.read = 0;
        self.publish(spare)
    }
    fn relay_publish(self: &Arc<Self>, source: Buffer) {
        let mut spare = self
            .fanout_spare
            .lock()
            .take()
            .expect("single fanout owner");
        for reader in self.receivers().into_iter().flatten() {
            spare = reader.deliver(&source, spare);
        }
        let old = self.fanout_spare.lock().replace(spare);
        assert!(old.is_none(), "single fanout owner");
        let old = self.staging.lock().replace(source);
        assert!(old.is_none(), "single flush/copy owner");
    }
    pub(crate) fn source_open(&self) -> bool {
        !self.stop.load(Ordering::Acquire)
            && !self.relay_failed.load(Ordering::Acquire)
            && (self.publication.is_none() || self.requested_incarnation().is_some())
    }
    pub(crate) fn matches_incarnation(&self, incarnation: u64) -> bool {
        self.source_open()
            && (self.publication.is_none() || self.requested_incarnation() == Some(incarnation))
    }
    pub(crate) fn source_owner(self: &Arc<Self>) -> Arc<Self> {
        self.root.as_ref().unwrap_or(self).clone()
    }
    pub(crate) fn index(&self) -> u32 {
        self.permit.0
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn take_free(&self) -> Option<Buffer> {
        self.queue.lock().free.iter_mut().find_map(Option::take)
    }
    fn publish(&self, mut buffer: Buffer) -> Buffer {
        let mut q = self.queue.lock();
        if q.terminal.is_some() {
            // A reset/revocation can win while fan-out copies outside this
            // lock. Retain every old record and return the external spare.
            return buffer;
        }
        let outgoing = if q.len < 2 {
            q.free
                .iter_mut()
                .find_map(Option::take)
                .expect("free reader slot")
        } else {
            // A partially returned record is immutable until its final byte.
            // Eviction, its exact loss accounting and replacement commit are
            // one transaction, ordered against terminal state by this lock.
            let at = if q.ready[q.head].as_ref().expect("reader head").read == 0 {
                let at = q.head;
                q.head = (q.head + 1) % 2;
                at
            } else {
                (q.head + 1) % 2
            };
            let old = q.ready[at].take().expect("unread overwrite slot");
            assert_eq!(old.read, 0);
            q.len -= 1;
            let saturated = q.lost_frames.checked_add(1).is_none()
                || q.lost_bytes.checked_add(old.len as u64).is_none();
            q.saturated |= saturated;
            q.lost_frames = q.lost_frames.saturating_add(1);
            q.lost_bytes = q.lost_bytes.saturating_add(old.len as u64);
            old
        };
        let first = q.first_sequence.is_none();
        let sequence = u64::from_le_bytes(buffer.bytes[32..40].try_into().expect("sequence"));
        let start = *q.first_sequence.get_or_insert(sequence);
        put64(&mut buffer.bytes, 208, q.lost_frames);
        put64(&mut buffer.bytes, 216, q.lost_bytes);
        put64(&mut buffer.bytes, 240, start);
        let mut flags = u32::from_le_bytes(buffer.bytes[20..24].try_into().expect("flags"));
        if first {
            flags |= START_GAP;
        }
        if q.lost_frames != 0 {
            flags |= HOST_LOSS;
        }
        if q.saturated {
            flags |= HOST_SATURATED;
        }
        put32(&mut buffer.bytes, 20, flags);
        let tail = (q.head + q.len) % 2;
        assert!(q.len < 2 && q.ready[tail].is_none());
        q.ready[tail] = Some(buffer);
        q.len += 1;
        self.ready.set(POLL_IN, 0);
        outgoing
    }
    pub(crate) fn fail(self: &Arc<Self>, error: FsError) {
        self.relay_failed.store(true, Ordering::Release);
        self.stop.store(true, Ordering::Release);
        for reader in self.receivers().into_iter().flatten() {
            let mut q = reader.queue.lock();
            q.terminal.get_or_insert(error);
            reader.ready.set_wake_all(POLL_ERR | POLL_HUP, 0);
        }
    }
    fn read(&self, output: &mut [u8]) -> Result<usize, FsError> {
        let mut q = self.queue.lock();
        if q.len == 0 {
            return q.terminal.map_or(Err(FsError::WouldBlock), Err);
        }
        let head = q.head;
        let b = q.ready[head].as_mut().expect("owned stream head");
        // Bound the IRQ-safe host-copy critical section to one page.
        let n = output.len().min(4096).min(b.len - b.read);
        output[..n].copy_from_slice(&b.bytes[b.read..b.read + n]);
        b.read += n;
        if b.read == b.len {
            let buffer = q.ready[head].take().expect("consumed stream frame");
            *q.free
                .iter_mut()
                .find(|slot| slot.is_none())
                .expect("free stream slot") = Some(buffer);
            q.head = (head + 1) % 2;
            q.len -= 1;
            if q.len == 0 {
                self.ready.set(0, POLL_IN);
            }
        }
        if q.len != 0 && n != 0 {
            // Dup may have several exclusive blocking readers. A short read
            // leaves readiness high; relay progress without inventing a poll
            // edge or stranding another sleeper behind the first waiter.
            let _ = self
                .ready
                .set_event_with_continuation(0, 0, 0, POLL_IN, |_, w| w.wake_by_ref());
        }
        Ok(n)
    }
}

/// Disjoint CT namespace: scheduler IDs1..64, SLPC0x8000..fffe. The GT
/// reserves three unique, never-recycled fences per source actor before attach.
pub(crate) struct Sideband {
    flush: bool,
    replies: [Option<GuCMessage>; 4],
}
impl Sideband {
    pub(crate) fn new() -> Self {
        Self {
            flush: false,
            replies: [const { None }; 4],
        }
    }
    pub(crate) fn route(&mut self, m: GuCMessage) -> Result<Option<GuCMessage>, TransportError> {
        if m.kind == 1 && m.auxiliary == 0x8003 {
            if !m.payload.is_empty() {
                return Err(TransportError::Protocol(0x8003));
            }
            self.flush = true;
            return Ok(None);
        }
        if (FIRST_FENCE..=ACK_FENCE).contains(&m.fence) {
            let slot = self
                .replies
                .iter_mut()
                .find(|r| r.is_none())
                .ok_or(TransportError::Protocol(0x8003))?;
            *slot = Some(m);
            return Ok(None);
        }
        Ok(Some(m))
    }
    fn reply(&mut self) -> Option<GuCMessage> {
        let result = self.replies[0].take();
        self.replies.rotate_left(1);
        result
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Phase {
    Enable,
    Enabling,
    Force,
    Forcing,
    Running,
    Disable,
    Disabling,
    Poisoned,
    Done,
}
pub(crate) struct Actor {
    session: Arc<StreamSession>,
    phase: Phase,
    fences: [u16; 3],
    deadline: u64,
    identity: Identity,
    sequence: u64,
    pending: Option<(Buffer, [[u32; 9]; 2])>,
    cursors: Option<[u32; 2]>,
    cursor_published: bool,
    overflows: [u8; 2],
    observed: [u64; 2],
    unstable_since: Option<u64>,
}
impl Actor {
    pub(crate) fn new(session: Arc<StreamSession>, identity: Identity, first: u16) -> Self {
        Self {
            session,
            phase: Phase::Enable,
            fences: [first, first + 1, first + 2],
            deadline: 0,
            identity,
            sequence: 0,
            pending: None,
            cursors: None,
            cursor_published: false,
            overflows: [0; 2],
            observed: [0; 2],
            unstable_since: None,
        }
    }
    pub(crate) fn is(&self, session: &Arc<StreamSession>) -> bool {
        Arc::ptr_eq(&self.session, session)
    }
    fn failure(&mut self, error: FsError) {
        self.session.fail(error);
        if !matches!(
            self.phase,
            Phase::Disable | Phase::Disabling | Phase::Poisoned | Phase::Done
        ) {
            self.phase = Phase::Disable;
            self.deadline = 0;
        }
        self.pending.take();
    }
    pub(crate) fn lost(&mut self) {
        self.session.fail(FsError::NoDevice);
        self.phase = Phase::Poisoned;
        self.pending.take();
    }
    pub(crate) fn poll<M: MmioWindow, A: GpuAllocator>(
        &mut self,
        ct: &mut XeLpgTransport<M, A>,
        backing: &impl GpuBacking,
        now: u64,
        mut access: impl FnMut() -> bool,
    ) -> Result<bool, TransportError> {
        if !access() {
            self.lost();
            return Ok(true);
        }
        let side = ct.log_sideband();
        while let Some(m) = side.reply() {
            let expected = match self.phase {
                Phase::Enabling => self.fences[0],
                Phase::Forcing => self.fences[1],
                Phase::Disabling => self.fences[2],
                _ => 0,
            };
            if m.fence != expected {
                if m.fence == ACK_FENCE {
                    if matches!(self.phase, Phase::Disabling | Phase::Done) {
                        self.lost();
                    } else {
                        self.failure(crate::intel_gpu_user::io_error());
                    }
                }
                continue; // expired unique command, never a replacement ACK
            }
            if m.kind != 7 || m.auxiliary != 0 || !m.payload.is_empty() {
                if self.phase == Phase::Disabling {
                    self.lost();
                } else {
                    self.failure(crate::intel_gpu_user::io_error());
                }
                continue;
            }
            self.deadline = 0;
            if self.phase == Phase::Forcing {
                side.flush = true;
            }
            self.phase = match self.phase {
                Phase::Enabling => Phase::Force,
                Phase::Forcing => Phase::Running,
                Phase::Disabling => Phase::Done,
                _ => unreachable!(),
            };
        }
        if self.session.stop.load(Ordering::Acquire)
            && !matches!(
                self.phase,
                Phase::Disable | Phase::Disabling | Phase::Poisoned | Phase::Done
            )
        {
            self.phase = Phase::Disable;
            self.deadline = 0;
            self.pending.take();
        }
        if matches!(
            self.phase,
            Phase::Enabling | Phase::Forcing | Phase::Disabling
        ) && now >= self.deadline
        {
            if self.phase == Phase::Disabling {
                self.lost();
            } else {
                self.failure(crate::intel_gpu_user::io_error());
            }
        }
        let command = match self.phase {
            Phase::Enable => Some((self.fences[0], 0x40, 0x101, Phase::Enabling)),
            Phase::Force => Some((self.fences[1], 0x302, 0, Phase::Forcing)),
            Phase::Disable => Some((self.fences[2], 0x40, 0x100, Phase::Disabling)),
            _ => None,
        };
        if let Some((id, action, value, next)) = command {
            if self.deadline == 0 {
                self.deadline = now.saturating_add(TIMEOUT);
            }
            // guc_ct_send_locked retries -EBUSY and gives up only after a
            // failed attempt: CT space found by a late poll sends.
            match ct.send(id, action, 0, &[value], false) {
                Ok(()) => {
                    self.phase = next;
                    self.deadline = now.saturating_add(TIMEOUT);
                }
                Err(TransportError::Ct(crate::intel_gpu_guc::GuCError::Full)) => {
                    if now >= self.deadline {
                        self.lost();
                    }
                }
                Err(e) => {
                    self.lost();
                    return Err(e);
                }
            }
            return Ok(true);
        }
        if self.phase == Phase::Done {
            return Ok(false);
        }
        if self.phase != Phase::Running {
            return Ok(true);
        }
        // The initial forced flush is consumed even if its event was coalesced
        // before the success reply. Later samples require a flush flag/event.
        let notified = core::mem::take(&mut ct.log_sideband().flush);
        if self.pending.is_none() {
            if !access() {
                self.lost();
                return Ok(true);
            }
            if !backing.coherent_for_device()
                || u64::from(backing.size_pages()) * 4096 != super::LOG_BYTES as u64
            {
                self.failure(FsError::Unsupported);
                return Ok(true);
            }
            let states = read_states(backing);
            if !notified && states.iter().all(|s| s[7] & 1 == 0) {
                return Ok(true);
            }
            // Only the single actor owns staging. Slow readers cannot
            // withhold source consumption or allocate unbounded records.
            let Some(mut buffer) = self.session.take_staging() else {
                self.failure(FsError::InvalidData);
                return Ok(true);
            };
            let mut identity = self.identity;
            identity.now_ns = now;
            match copy_frame_with_loss(
                backing,
                &mut buffer,
                states,
                identity,
                self.session.index(),
                self.sequence,
                self.cursors,
                self.overflows,
                self.observed,
                &mut access,
            ) {
                Ok(()) => {
                    self.unstable_since = None;
                    self.pending = Some((buffer, states));
                    self.cursor_published = false;
                    self.deadline = now.saturating_add(TIMEOUT);
                }
                Err(FsError::WouldBlock) => {
                    // A producer advanced sampled state during copying. No
                    // cursor/ACK was published: discard the private image and
                    // resample, retaining the modulo-overflow baseline.
                    *self.session.staging.lock() = Some(buffer);
                    let since = *self.unstable_since.get_or_insert(now);
                    if now.saturating_sub(since) >= TIMEOUT {
                        self.failure(FsError::InvalidData);
                    } else {
                        ct.log_sideband().flush = true;
                    }
                    return Ok(true);
                }
                Err(e) => {
                    self.failure(e);
                    return Ok(true);
                }
            }
        }
        let (buffer, states) = self.pending.as_ref().expect("copied flush frame");
        let _ = buffer;
        if !access() {
            self.lost();
            return Ok(true);
        }
        let current = read_states(backing);
        if !states.iter().zip(current.iter()).all(|(a, b)| {
            stable(a, b)
                && b[2] == (if self.cursor_published { a[5] } else { a[2] })
                && b[7]
                    == (if self.cursor_published {
                        a[7] & !1
                    } else {
                        a[7]
                    })
        }) {
            self.failure(FsError::InvalidData);
            return Ok(true);
        }
        // Cursor/flush state publication is source-defined. Preserve all
        // firmware-owned fields and overflow bits; never acknowledge capture.
        if !self.cursor_published {
            for (i, s) in states.iter().enumerate() {
                if !access() {
                    self.lost();
                    return Ok(true);
                }
                backing.write32((i * 36 + 8) as u64, s[5]);
                backing.write32((i * 36 + 28) as u64, s[7] & !1);
            }
            fence(Ordering::Release);
            self.cursor_published = true;
        }
        if !access() {
            self.lost();
            return Ok(true);
        }
        match ct.send(ACK_FENCE, 0x30, 0, &[0], true) {
            Ok(()) => {
                let (buffer, states) = self.pending.take().expect("acknowledged frame");
                self.cursors = Some([states[0][5], states[1][5]]);
                self.sequence = self
                    .sequence
                    .checked_add(1)
                    .ok_or(TransportError::Poisoned)?;
                for (i, state) in states.iter().enumerate() {
                    let full = ((state[7] >> 1) & 15) as u8;
                    let delta = full.wrapping_sub(self.overflows[i]) & 15;
                    self.observed[i] = self.observed[i]
                        .checked_add(u64::from(delta))
                        .ok_or(TransportError::Poisoned)?;
                    self.overflows[i] = full;
                }
                self.session.relay_publish(buffer);
            }
            // The frame's bound covers only this ACK's CT backpressure. As
            // guc_ct_send_locked, it fails only after an attempt finds no room.
            Err(TransportError::Ct(crate::intel_gpu_guc::GuCError::Full)) => {
                if now >= self.deadline {
                    self.failure(crate::intel_gpu_user::io_error());
                }
            }
            Err(e) => {
                self.lost();
                return Err(e);
            }
        }
        Ok(true)
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        self.session.fail(FsError::NoDevice);
    }
}
fn read_states(b: &impl GpuBacking) -> [[u32; 9]; 2] {
    fence(Ordering::Acquire);
    core::array::from_fn(|i| core::array::from_fn(|w| b.read32((i * 36 + w * 4) as u64)))
}
fn stable(a: &[u32; 9], b: &[u32; 9]) -> bool {
    [0, 1, 4, 5, 6, 8].into_iter().all(|i| a[i] == b[i]) && (a[7] & !1) == (b[7] & !1)
}
#[cfg(any(test, feature = "kernel-test"))]
#[allow(clippy::too_many_arguments)]
fn copy_frame(
    backing: &impl GpuBacking,
    out: &mut Buffer,
    states: [[u32; 9]; 2],
    identity: Identity,
    card: u32,
    sequence: u64,
    cursors: Option<[u32; 2]>,
    access: &mut impl FnMut() -> bool,
) -> Result<(), FsError> {
    copy_frame_with_loss(
        backing, out, states, identity, card, sequence, cursors, [0; 2], [0; 2], access,
    )
}
#[allow(clippy::too_many_arguments)] // wire identity and source ownership are distinct proofs
fn copy_frame_with_loss(
    backing: &impl GpuBacking,
    out: &mut Buffer,
    states: [[u32; 9]; 2],
    identity: Identity,
    card: u32,
    sequence: u64,
    cursors: Option<[u32; 2]>,
    previous: [u8; 2],
    observed: [u64; 2],
    access: &mut impl FnMut() -> bool,
) -> Result<(), FsError> {
    if !backing.coherent_for_device()
        || u64::from(backing.size_pages()) * 4096 != super::LOG_BYTES as u64
    {
        return Err(FsError::Unsupported);
    }
    out.bytes.fill(0);
    out.read = 0;
    let mut end = HEADER;
    // A zero delta can hide multiples of sixteen. This qualifier is present
    // even on apparently loss-free frames; pre-attach history is unknown.
    let mut flags = DATA | FW_MODULO_BOUND | if sequence == 0 { START_GAP } else { 0 };
    for (i, s) in states.iter().enumerate() {
        let size = if i == 0 { 0x10000 } else { 0x4000 };
        let marker = if i == 0 { 0xdeadfeed } else { 0x8086dead };
        if s[0] != 0xcabba9e6
            || s[1] != marker
            || s[4] != size
            || s[7] & !0x1f != 0
            || [s[2], s[3], s[5], s[6]].into_iter().any(|n| n > size)
            || cursors.is_some_and(|c| c[i] != s[2])
        {
            return Err(FsError::InvalidData);
        }
        let base = if i == 0 { 4096 } else { 0x11000 };
        let delta = ((((s[7] >> 1) & 15) as u8).wrapping_sub(previous[i]) & 15) as u64;
        put64(&mut out.bytes, 192 + i * 8, delta);
        put64(
            &mut out.bytes,
            224 + i * 8,
            observed[i].checked_add(delta).ok_or(FsError::NoSpace)?,
        );
        let ranges = if delta != 0 {
            // Source relay takes a whole-buffer image on overflow. It is an
            // opaque physical ring image, not an ordered/atomic event list.
            flags |= FW_LOSS
                | if i == 0 {
                    EVENT_RING_IMAGE
                } else {
                    CRASH_RING_IMAGE
                };
            [(0, size), (0, 0)]
        } else if s[2] > s[5] {
            if s[6] < s[2] {
                return Err(FsError::InvalidData);
            }
            [(s[2], s[6]), (0, s[5])]
        } else {
            [(s[2], s[5]), (0, 0)]
        };
        let start = end;
        for (begin, finish) in ranges {
            let length = (finish - begin) as usize;
            let dest = out
                .bytes
                .get_mut(end..end + length)
                .ok_or(FsError::InvalidData)?;
            let mut cached = (u64::MAX, 0u32);
            for (j, byte) in dest.iter_mut().enumerate() {
                if j % 4096 == 0 {
                    if !access() {
                        return Err(FsError::NoDevice);
                    }
                    fence(Ordering::Acquire);
                }
                let at = u64::from(base + begin) + j as u64;
                if cached.0 != at & !3 {
                    cached = (at & !3, backing.read32(at & !3));
                }
                *byte = (cached.1 >> ((at & 3) * 8)) as u8;
            }
            end += length;
        }
        put32(&mut out.bytes, 72 + i * 8, start as u32);
        put32(&mut out.bytes, 76 + i * 8, (end - start) as u32);
        for (w, value) in s.iter().enumerate() {
            put32(&mut out.bytes, 88 + i * 36 + w * 4, *value);
        }
    }
    if !access() {
        return Err(FsError::NoDevice);
    }
    let after = read_states(backing);
    if !states
        .iter()
        .zip(after.iter())
        .all(|(a, b)| stable(a, b) && a[2] == b[2] && a[7] == b[7])
    {
        return Err(FsError::WouldBlock);
    }
    out.bytes[..8].copy_from_slice(b"NARFGSTR");
    for (at, v) in [
        (8, 2),
        (12, HEADER as u32),
        (16, end as u32),
        (20, flags),
        (24, super::platform_tag(identity.platform)),
        (28, card),
    ] {
        put32(&mut out.bytes, at, v);
    }
    put64(&mut out.bytes, 32, sequence);
    put64(&mut out.bytes, 40, identity.epoch);
    put64(&mut out.bytes, 48, identity.incarnation);
    put64(&mut out.bytes, 56, identity.now_ns);
    put32(
        &mut out.bytes,
        64,
        u32::from(identity.firmware_version.0)
            | u32::from(identity.firmware_version.1) << 8
            | u32::from(identity.firmware_version.2) << 16,
    );
    out.bytes[160..192].copy_from_slice(&identity.firmware_digest);
    out.len = end;
    Ok(())
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at + 8].copy_from_slice(&n.to_le_bytes());
}

struct Node {
    index: u32,
    gate: Gate,
}
impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GuCStreamNode").field(&self.index).finish()
    }
}
struct File {
    session: Arc<StreamSession>,
    gate: Gate,
}
impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GuCStreamFile")
            .field(&self.session.index())
            .finish()
    }
}
fn stat() -> Stat {
    Stat {
        size: 0,
        blocks: 0,
        mode: Mode {
            file_type: FileType::Special,
            perms: 0o400,
        },
        mtime_cycles: 0,
    }
}
impl FileOps for Node {
    fn open_instance_checked(&self, write: bool) -> Result<Option<Arc<dyn FileOps>>, FsError> {
        self.gate.check()?;
        if write {
            return Err(FsError::ReadOnly);
        }
        Ok(Some(Arc::new(File {
            session: StreamSession::open(self.index)?,
            gate: self.gate,
        })))
    }
    fn read<'a>(&'a self, _: u64, _: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::OperationNotPermitted) })
    }
    fn write<'a>(&'a self, _: u64, _: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        stat()
    }
}
impl Drop for File {
    fn drop(&mut self) {
        self.session.close_reader();
    }
}
impl FileOps for File {
    fn read<'a>(&'a self, _: u64, out: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if let Err(e) = self.gate.check() {
                self.session.fail_reader(e);
                return Err(e);
            }
            if out.is_empty() {
                return Ok(0);
            }
            self.session.read(out)
        })
    }
    fn write<'a>(&'a self, _: u64, _: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
        stat()
    }
    fn is_stream(&self) -> bool {
        true
    }
    fn nonblock_read_eagain(&self) -> bool {
        true
    }
    fn readiness(&self) -> Option<&Readiness> {
        if let Err(error) = self.gate.check() {
            self.session.fail_reader(error);
            None
        } else {
            Some(&self.session.ready)
        }
    }
    fn poll_readiness(&self) -> u32 {
        if let Err(error) = self.gate.check() {
            self.session.fail_reader(error);
            POLL_ERR | POLL_HUP
        } else {
            self.session.ready.mask()
        }
    }
}
/// Called only by the card worker under its reset mutex. Never resumes D0.
pub(crate) fn take_requested(index: u32) -> Option<Arc<StreamSession>> {
    let root = ROOTS.lock().get(index as usize)?.upgrade()?;
    if root.stop.load(Ordering::Acquire) {
        return None;
    }
    if root.requested_incarnation().is_none() {
        root.fail(FsError::NoDevice);
        return None;
    }
    root.attached
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()?;
    Some(root)
}
pub(crate) fn supported(platform: crate::intel_gpu_gt::GtPlatform, version: (u8, u8, u8)) -> bool {
    // Only the existing pinned GuC70 profiles own this CT/log ABI. New
    // firmware majors/platforms must obtain independent protocol qualification.
    use crate::{intel_gpu::Generation, intel_gpu_gt::GtPlatform};
    matches!(
        platform,
        GtPlatform::Gen12(_)
            | GtPlatform::Alchemist
            | GtPlatform::Battlemage
            | GtPlatform::Integrated(Generation::MeteorLake)
    ) && version.0 == 70
        && platform.guc().is_some_and(|p| version >= p.minimum_version)
}
/// The actual card-lifetime worker registers cached queue service. A generic
/// UserBackend with no physical flush owner must never advertise this stream.
pub(crate) fn register_owner(
    index: u32,
    platform: crate::intel_gpu_gt::GtPlatform,
    publication: &Arc<Publication>,
) {
    if platform
        .guc()
        .is_some_and(|profile| supported(platform, profile.minimum_version))
    {
        if let Some(slot) = PUBLICATIONS.lock().get_mut(index as usize) {
            *slot = Arc::downgrade(publication);
        }
    }
}
/// Publish under the actual GT reset mutex only after Running admission.
/// A fresh serial prevents ABA even when execution or firmware IDs survive.
pub(crate) fn publish(publication: &Publication, incarnation: u64) {
    if incarnation == 0 {
        return;
    }
    let serial = NEXT_PUBLICATION
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .expect("GuC log publication exhausted");
    let _roots = ROOTS.lock();
    publication
        .incarnation
        .store(incarnation, Ordering::Relaxed);
    publication.serial.store(serial, Ordering::Release);
}
/// Under the actual reset mutex, before stop/park/S3 or epoch withdrawal.
/// No MMIO and no IRQ-safe guard crosses a wait. The shared registry excludes
/// an open inserting itself between the zero publication and invalidation.
pub(crate) fn close_publication(index: u32, publication: &Publication) {
    let root = {
        let roots = ROOTS.lock();
        publication.serial.store(0, Ordering::Release);
        roots.get(index as usize).and_then(Weak::upgrade)
    };
    if let Some(root) = root {
        root.fail(FsError::NoDevice);
    }
}
pub(crate) fn visible(index: u32) -> bool {
    enabled()
        && PUBLICATIONS
            .lock()
            .get(index as usize)
            .is_some_and(|publication| publication.strong_count() != 0)
        && crate::drm_registry::card(index)
            .is_some_and(|c| c.vendor_id() == 0x8086 && c.intel_user_backend().is_some())
}
pub(crate) fn lookup(name: &str) -> Option<Arc<dyn FileOps>> {
    let index = name.strip_prefix("guc-log-stream")?.parse::<u32>().ok()?;
    if name != alloc::format!("guc-log-stream{index}") || !visible(index) {
        return None;
    }
    Some(Arc::new(Node {
        index,
        gate: Gate::PHYSICAL,
    }))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_guc_stream_tests.rs"]
mod tests;
