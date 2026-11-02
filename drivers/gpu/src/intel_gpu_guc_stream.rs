//! Bounded GuC event/crash relay with source flush/cursor/ack ownership.
//!
//! MIT Linux b90c984d: i915 intel_guc_log.c relay/control actions and
//! xe/abi/guc_log_abi.h. Overflow is terminal and explicit, never silent.
use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_guc::GuCMessage,
    intel_gpu_guc_log::Identity,
    intel_gpu_guc_transport::{TransportError, XeLpgTransport},
    intel_gpu_rcs::{GpuAllocator, GpuBacking},
    intel_gpu_user::UserBackend,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{fence, AtomicBool, Ordering};
use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_ERR, POLL_HUP, POLL_IN,
};
use narf_lib::{readiness::Readiness, sync::IrqSafeSpinLock};

const MAX_CARDS: usize = 64;
const HEADER: usize = 192;
const FRAME: usize = HEADER + 0x14000;
const TIMEOUT: u64 = 500_000_000;
pub(crate) const FIRST_FENCE: u16 = 0x7f00;
pub(crate) const LAST_FENCE: u16 = 0x7ffc;
pub(crate) const ACK_FENCE: u16 = 0x7fff;
static ACTIVE: [AtomicBool; MAX_CARDS] = [const { AtomicBool::new(false) }; MAX_CARDS];

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
struct Permit(u32);
impl Drop for Permit {
    fn drop(&mut self) {
        ACTIVE[self.0 as usize].store(false, Ordering::Release);
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
}
/// One privileged open-file description. Dup shares the same FIFO; copied
/// records remain readable after reset, followed by an explicit terminal error.
pub struct StreamSession {
    permit: Permit,
    queue: IrqSafeSpinLock<Queue>,
    ready: Readiness,
    attached: AtomicBool,
    stop: AtomicBool,
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
        let permit = Permit(index);
        let free = [Some(Buffer::new()?), Some(Buffer::new()?)];
        Ok(Arc::new(Self {
            permit,
            queue: IrqSafeSpinLock::new(Queue {
                free,
                ready: [None, None],
                head: 0,
                len: 0,
                terminal: None,
            }),
            ready: Readiness::new(0),
            attached: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        }))
    }
    pub(crate) fn index(&self) -> u32 {
        self.permit.0
    }
    fn take_free(&self) -> Option<Buffer> {
        self.queue.lock().free.iter_mut().find_map(Option::take)
    }
    fn publish(&self, buffer: Buffer) {
        let mut q = self.queue.lock();
        let tail = (q.head + q.len) % 2;
        assert!(q.len < 2 && q.ready[tail].is_none());
        q.ready[tail] = Some(buffer);
        q.len += 1;
        self.ready.set(POLL_IN, 0);
    }
    pub(crate) fn fail(&self, error: FsError) {
        let mut q = self.queue.lock();
        q.terminal.get_or_insert(error);
        self.stop.store(true, Ordering::Release);
        self.ready.set(POLL_ERR | POLL_HUP, 0);
    }
    fn read(&self, output: &mut [u8]) -> Result<usize, FsError> {
        let mut q = self.queue.lock();
        if q.len == 0 {
            return q.terminal.map_or(Ok(0), Err);
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
        Ok(n)
    }
}

/// Disjoint CT namespace: scheduler IDs1..64, SLPC0x8000..fffe. The GT
/// reserves three unique, never-recycled fences per session before attach.
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
    blocked_since: Option<u64>,
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
            blocked_since: None,
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
            if now >= self.deadline {
                self.lost();
                return Ok(true);
            }
            match ct.send(id, action, 0, &[value], false) {
                Ok(()) => {
                    self.phase = next;
                    self.deadline = now.saturating_add(TIMEOUT);
                }
                Err(TransportError::Ct(crate::intel_gpu_guc::GuCError::Full)) => {}
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
            // Refuse known loss even while both host buffers are occupied.
            if states.iter().any(|s| s[7] & !1 != 0) {
                self.failure(FsError::InvalidData);
                return Ok(true);
            }
            let Some(mut buffer) = self.session.take_free() else {
                let since = *self.blocked_since.get_or_insert(now);
                if now.saturating_sub(since) >= TIMEOUT {
                    self.failure(FsError::NoSpace);
                } else {
                    ct.log_sideband().flush = true;
                }
                return Ok(true);
            };
            self.blocked_since = None;
            let mut identity = self.identity;
            identity.now_ns = now;
            match copy_frame(
                backing,
                &mut buffer,
                states,
                identity,
                self.session.index(),
                self.sequence,
                self.cursors,
                &mut access,
            ) {
                Ok(()) => {
                    self.pending = Some((buffer, states));
                    self.cursor_published = false;
                    self.deadline = now.saturating_add(TIMEOUT);
                }
                Err(e) => {
                    self.failure(e);
                    return Ok(true);
                }
            }
        }
        let (buffer, states) = self.pending.as_ref().expect("copied flush frame");
        let _ = buffer;
        if now >= self.deadline {
            self.failure(crate::intel_gpu_user::io_error());
            return Ok(true);
        }
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
                self.session.publish(buffer);
            }
            Err(TransportError::Ct(crate::intel_gpu_guc::GuCError::Full)) => {}
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
#[allow(clippy::too_many_arguments)] // fixed wire identity and prior host cursors are distinct proofs
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
    if !backing.coherent_for_device()
        || u64::from(backing.size_pages()) * 4096 != super::LOG_BYTES as u64
    {
        return Err(FsError::Unsupported);
    }
    out.bytes.fill(0);
    out.read = 0;
    let mut end = HEADER;
    for (i, s) in states.iter().enumerate() {
        let size = if i == 0 { 0x10000 } else { 0x4000 };
        let marker = if i == 0 { 0xdeadfeed } else { 0x8086dead };
        if s[0] != 0xcabba9e6
            || s[1] != marker
            || s[4] != size
            || s[7] & !1 != 0
            || [s[2], s[3], s[5], s[6]].into_iter().any(|n| n > size)
            || cursors.is_some_and(|c| c[i] != s[2])
        {
            return Err(FsError::InvalidData);
        }
        let base = if i == 0 { 4096 } else { 0x11000 };
        let ranges = if s[2] > s[5] {
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
        return Err(FsError::InvalidData);
    }
    out.bytes[..8].copy_from_slice(b"NARFGSTR");
    for (at, v) in [
        (8, 1),
        (12, HEADER as u32),
        (16, end as u32),
        (20, 1),
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
    backend: Arc<dyn UserBackend>,
    gate: Gate,
}
impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("GuCStreamNode").field(&self.index).finish()
    }
}
struct File {
    session: Arc<StreamSession>,
    backend: Arc<dyn UserBackend>,
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
            session: StreamSession::reserve(self.index)?,
            backend: self.backend.clone(),
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
        self.session.stop.store(true, Ordering::Release);
    }
}
impl FileOps for File {
    fn read<'a>(&'a self, _: u64, out: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if let Err(e) = self.gate.check() {
                self.session.fail(e);
                return Err(e);
            }
            if out.is_empty() {
                return Ok(0);
            }
            if !self.session.attached.load(Ordering::Acquire) {
                if self.session.stop.load(Ordering::Acquire) {
                    return self.session.read(out);
                }
                if let Err(e) = self.backend.guc_log_stream(self.session.clone()).await {
                    self.session.fail(e);
                    return Err(e);
                }
                self.session.attached.store(true, Ordering::Release);
            }
            if let Err(e) = self.gate.check() {
                self.session.fail(e);
                return Err(e);
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
        self.gate.check().ok().map(|_| &self.session.ready)
    }
    fn poll_readiness(&self) -> u32 {
        if self.gate.check().is_err() {
            POLL_ERR | POLL_HUP
        } else {
            self.session.ready.mask()
        }
    }
}
pub(crate) fn visible(index: u32) -> bool {
    enabled()
        && index < MAX_CARDS as u32
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
        backend: crate::drm_registry::card(index)?.intel_user_backend()?,
        gate: Gate::PHYSICAL,
    }))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_guc_stream_tests.rs"]
mod tests;
