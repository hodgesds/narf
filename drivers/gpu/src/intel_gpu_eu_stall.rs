//! BMG EU-stall observation, pinned MIT Linux b90c984d xe_eu_stall.c,
//! xe_observation.c and regs/xe_eu_stall_regs.h. Fixed host bounds, current
//! perf authority, MCR ownership and retained DMA are part of the interface.
use crate::{
    intel_gpu_aux::MmioWindow, intel_gpu_guc_boot::BootAllocator, intel_gpu_rcs::GpuBacking,
    intel_gpu_user::UserBackend,
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    sync::atomic::{fence, AtomicBool, Ordering},
};
use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat, POLL_ERR, POLL_HUP, POLL_IN,
};
use narf_lib::{readiness::Readiness, sync::IrqSafeSpinLock};

pub const PER_CORE: usize = 512 * 1024;
pub const RECORD: usize = 64;
const HOST_BYTES: usize = 64 * 1024;
const CHUNK: usize = 4096;
const ENABLE: u32 = 0x6900;
const DISABLE: u32 = 0x6901;
const POLL_NS: u64 = 5_000_000;
static ACTIVE: [AtomicBool; 64] = [const { AtomicBool::new(false) }; 64];

/// Cached physical main-GT topology, published only by an admitted BMG PF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub card: u32,
    pub dss: u32,
    pub per_group: u8,
}
impl Info {
    pub(crate) fn validate(self) -> Result<Self, FsError> {
        if self.card >= 64
            || self.dss == 0
            || self.per_group == 0
            || self.per_group > 16
            || (0..32).any(|i| self.dss & (1 << i) != 0 && i / u32::from(self.per_group) > 15)
        {
            return Err(FsError::Unsupported);
        }
        Ok(self)
    }
    pub(crate) fn from_tables(
        card: u32,
        platform: crate::intel_gpu_gt::GtPlatform,
        topology: &crate::intel_gpu_topology::GtTopology,
        config: &crate::intel_gpu_hwconfig::HardwareConfig,
    ) -> Option<Self> {
        if platform != crate::intel_gpu_gt::GtPlatform::Battlemage
            || topology.platform() != platform
        {
            return None;
        }
        let slices = config.lookup_u32(1).ok().flatten();
        let dss = config.lookup_u32(70).ok().flatten();
        let per_group = match (slices, dss) {
            (Some(s), Some(d)) if s != 0 && d != 0 => d.div_ceil(s),
            _ => 4,
        };
        let info = Self {
            card,
            dss: topology.geometry_dss() | topology.compute_dss(),
            per_group: u8::try_from(per_group).ok()?,
        };
        info.validate().ok()
    }
    fn last(self) -> usize {
        (32 - self.dss.leading_zeros()) as usize
    }
    fn reports(self) -> u64 {
        u64::from(self.dss.count_ones()) * (PER_CORE / RECORD) as u64
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub rate: u32,
    pub wait: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Attach,
    Enable,
    Disable,
}
pub(crate) fn capable() -> bool {
    narf_filesystem::caller_capable(38) || narf_filesystem::caller_capable(21)
}
#[derive(Clone, Copy)]
struct Gate {
    capable: fn() -> bool,
}
impl Gate {
    const PHYSICAL: Self = Self { capable };
    fn check(self) -> Result<(), FsError> {
        if (self.capable)() {
            Ok(())
        } else {
            Err(FsError::OperationNotPermitted)
        }
    }
}
pub(crate) fn enabled() -> bool {
    let args = narf_boot::args();
    let mut values = args
        .tokens()
        .take_while(|t| *t != "--")
        .filter_map(|t| t.strip_prefix("narf.intel.eu_stall="));
    values.next() == Some("1") && values.next().is_none() && !args.has_flag("narf.intel.eu_stall")
}
struct Permit(u32);
impl Drop for Permit {
    fn drop(&mut self) {
        ACTIVE[self.0 as usize].store(false, Ordering::Release);
    }
}
struct Queue {
    bytes: Vec<u8>,
    head: usize,
    len: usize,
    overflow: bool,
    terminal: Option<FsError>,
}
/// One open description; hardware never writes this bounded host FIFO.
pub struct Session {
    info: Info,
    config: Config,
    _permit: Permit,
    queue: IrqSafeSpinLock<Queue>,
    ready: Readiness,
    enabled: AtomicBool,
    stop: AtomicBool,
}
impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EuStallSession").field(&self.info).finish()
    }
}
impl Session {
    pub(crate) fn new(info: Info, config: Config) -> Result<Arc<Self>, FsError> {
        let info = info.validate()?;
        if !(1..=7).contains(&config.rate) || config.wait == 0 || config.wait > info.reports() {
            return Err(FsError::InvalidData);
        }
        if config.wait != 1 {
            return Err(FsError::Unsupported);
        }
        ACTIVE[info.card as usize]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| FsError::Busy)?;
        let permit = Permit(info.card);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(HOST_BYTES)
            .map_err(|_| FsError::OutOfMemory)?;
        bytes.resize(HOST_BYTES, 0);
        Ok(Arc::new(Self {
            info,
            config,
            _permit: permit,
            queue: IrqSafeSpinLock::new(Queue {
                bytes,
                head: 0,
                len: 0,
                overflow: false,
                terminal: None,
            }),
            ready: Readiness::new(0),
            enabled: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        }))
    }
    fn level(&self, q: &Queue) {
        let mask = if q.len != 0 && (self.enabled.load(Ordering::Acquire) || q.terminal.is_some()) {
            POLL_IN
        } else {
            0
        } | if q.overflow { POLL_ERR | POLL_IN } else { 0 }
            | if q.terminal.is_some() {
                POLL_ERR | POLL_HUP
            } else {
                0
            };
        self.ready
            .set(mask, (POLL_IN | POLL_ERR | POLL_HUP) & !mask);
    }
    pub(crate) fn info(&self) -> Info {
        self.info
    }
    pub(crate) fn fail(&self, error: FsError) {
        self.stop.store(true, Ordering::Release);
        let mut q = self.queue.lock();
        q.terminal.get_or_insert(error);
        self.level(&q);
    }
    fn push(&self, data: &[u8]) -> bool {
        let mut q = self.queue.lock();
        if data.len() > HOST_BYTES - q.len || q.terminal.is_some() {
            return false;
        }
        for &value in data {
            let at = (q.head + q.len) % HOST_BYTES;
            q.bytes[at] = value;
            q.len += 1;
        }
        self.level(&q);
        true
    }
    fn room(&self) -> usize {
        HOST_BYTES - self.queue.lock().len
    }
    fn dropped(&self) {
        let mut q = self.queue.lock();
        q.overflow = true;
        self.level(&q);
    }
    fn read(&self, out: &mut [u8]) -> Result<usize, FsError> {
        if out.len() < RECORD {
            return Err(FsError::InvalidData);
        }
        let mut q = self.queue.lock();
        if q.overflow {
            q.overflow = false;
            self.level(&q);
            return Err(crate::intel_gpu_user::io_error());
        }
        if !self.enabled.load(Ordering::Acquire) && q.terminal.is_none() {
            return Err(FsError::InvalidData);
        }
        let count = out.len().min(q.len).min(CHUNK) / RECORD * RECORD;
        if count == 0 {
            return Err(q.terminal.unwrap_or(FsError::WouldBlock));
        }
        for byte in &mut out[..count] {
            *byte = q.bytes[q.head];
            q.head = (q.head + 1) % HOST_BYTES;
            q.len -= 1;
        }
        self.level(&q);
        Ok(count)
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn read_for_test(&self, out: &mut [u8]) -> Result<usize, FsError> {
        self.read(out)
    }
}

pub(crate) fn query(info: Info) -> Result<Vec<u8>, FsError> {
    info.validate()?;
    let mut bytes = alloc::vec![0; 80 + 7 * 8];
    for (at, value) in [
        (8, 1u64),
        (16, RECORD as u64),
        (24, PER_CORE as u64),
        (72, 7),
    ] {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    for n in 1..=7u64 {
        let at = 80 + (n as usize - 1) * 8;
        bytes[at..at + 8].copy_from_slice(&(251 * n).to_le_bytes());
    }
    Ok(bytes)
}
fn properties(info: Info, mut address: u64, user: &dyn IoctlContext) -> Result<Config, FsError> {
    let mut config = Config { rate: 4, wait: 1 };
    let mut found = false;
    let mut seen = [0; 5];
    let mut count = 0;
    while address != 0 {
        if count == 5 || seen[..count].contains(&address) {
            return Err(FsError::InvalidData);
        }
        seen[count] = address;
        count += 1;
        let mut wire = [0; 32];
        user.read(address, &mut wire)?;
        let u32_at = |at| u32::from_le_bytes(wire[at..at + 4].try_into().unwrap());
        let value = u64::from_le_bytes(wire[24..32].try_into().unwrap());
        if u32_at(8) != 0 || u32_at(12) != 0 || u32_at(20) != 0 {
            return Err(FsError::InvalidData);
        }
        match u32_at(16) {
            1 if value == 0 => found = true,
            2 if (1..=7).contains(&(value / 251)) => config.rate = (value / 251) as u32,
            3 if value != 0 && value <= info.reports() => config.wait = value,
            _ => return Err(FsError::InvalidData),
        }
        address = u64::from_le_bytes(wire[..8].try_into().unwrap());
    }
    if !found {
        return Err(FsError::InvalidData);
    }
    if config.wait != 1 {
        return Err(FsError::Unsupported);
    }
    Ok(config)
}
pub(crate) async fn open(
    backend: Arc<dyn UserBackend>,
    address: u64,
    user: &dyn IoctlContext,
) -> Result<u64, FsError> {
    open_with_gate(backend, address, user, Gate::PHYSICAL).await
}
async fn open_with_gate(
    backend: Arc<dyn UserBackend>,
    address: u64,
    user: &dyn IoctlContext,
    gate: Gate,
) -> Result<u64, FsError> {
    gate.check()?;
    let info = backend
        .eu_stall_info()
        .ok_or(FsError::NoDevice)?
        .validate()?;
    let mut wire = [0; 32];
    user.read(address, &mut wire)?;
    let value = |at| u64::from_le_bytes(wire[at..at + 8].try_into().unwrap());
    if value(0) != 0 || value(8) != 1 || value(16) != 0 {
        return Err(FsError::InvalidData);
    }
    let session = Session::new(info, properties(info, value(24), user)?)?;
    let mut pending = PendingOpen {
        session: session.clone(),
        committed: false,
    };
    backend
        .eu_stall_control(session.clone(), Operation::Attach)
        .await?;
    if let Err(error) = gate.check() {
        session.fail(error);
        return Err(error);
    }
    let file = Arc::new(File {
        session,
        backend,
        gate,
    });
    let fd = user.install_file(file, false)?;
    pending.committed = true;
    Ok(fd as u64)
}
struct PendingOpen {
    session: Arc<Session>,
    committed: bool,
}
impl Drop for PendingOpen {
    fn drop(&mut self) {
        if !self.committed {
            self.session.fail(FsError::NoDevice);
        }
    }
}

struct File {
    session: Arc<Session>,
    backend: Arc<dyn UserBackend>,
    gate: Gate,
}
impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("EuStallFile").field(&self.session).finish()
    }
}
impl Drop for File {
    fn drop(&mut self) {
        self.session.stop.store(true, Ordering::Release);
    }
}
impl FileOps for File {
    fn read<'a>(&'a self, _: u64, output: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if !(self.gate.capable)() {
                self.session.fail(FsError::OperationNotPermitted);
                return Err(FsError::OperationNotPermitted);
            }
            self.session.read(output)
        })
    }
    fn write<'a>(&'a self, _: u64, _: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Err(FsError::ReadOnly) })
    }
    fn stat(&self) -> Stat {
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
    fn ioctl_user<'a>(&'a self, cmd: u32, _: u64, _: &'a dyn IoctlContext) -> FsFuture<'a, u64> {
        Box::pin(async move {
            if !(self.gate.capable)() {
                self.session.fail(FsError::OperationNotPermitted);
                return Err(FsError::OperationNotPermitted);
            }
            let operation = match cmd {
                ENABLE => Operation::Enable,
                DISABLE => Operation::Disable,
                _ => return Err(FsError::InvalidData),
            };
            self.backend
                .eu_stall_control(self.session.clone(), operation)
                .await?;
            if !(self.gate.capable)() {
                self.session.fail(FsError::OperationNotPermitted);
                return Err(FsError::OperationNotPermitted);
            }
            Ok(0)
        })
    }
    fn is_stream(&self) -> bool {
        true
    }
    fn nonblock_read_eagain(&self) -> bool {
        true
    }
    fn poll_readiness(&self) -> u32 {
        if (self.gate.capable)() {
            self.session.ready.mask()
        } else {
            POLL_ERR | POLL_HUP
        }
    }
    fn readiness(&self) -> Option<&Readiness> {
        Some(&self.session.ready)
    }
}

/// The physical DMA owner lives inside GuCGt's retained Parts, never a file.
/// Disabling does not free/rebind its BO; only full reset releases that lease.
pub(crate) struct Collector<A: BootAllocator> {
    allocator: A,
    backing: Option<A::Backing>,
    info: Info,
    session: Option<Arc<Session>>,
    read: [u32; 32],
    write: [u32; 32],
    active: bool,
    exposed: bool,
    retired: bool,
    poisoned: bool,
    next_poll: u64,
    cursor: usize,
}
impl<A: BootAllocator> Collector<A> {
    pub(crate) fn new(mut allocator: A, info: Info) -> Result<Self, FsError> {
        let info = info.validate()?;
        let pages = (info.last() * PER_CORE / 4096) as u32;
        let backing = allocator.alloc(pages).map_err(|_| FsError::OutOfMemory)?;
        if !backing.coherent_for_device()
            || backing.size_pages() != pages
            || backing.ggtt_offset() & 63 != 0
            || u64::from(backing.ggtt_offset()) + u64::from(pages) * 4096 > u64::from(u32::MAX) + 1
        {
            allocator.free(backing);
            return Err(FsError::Unsupported);
        }
        Ok(Self {
            allocator,
            backing: Some(backing),
            info,
            session: None,
            read: [0; 32],
            write: [0; 32],
            active: false,
            exposed: false,
            retired: false,
            poisoned: false,
            next_poll: 0,
            cursor: 0,
        })
    }
    pub(crate) fn info(&self) -> Info {
        self.info
    }
    pub(crate) fn attach(&mut self, session: Arc<Session>) -> Result<(), FsError> {
        if self.poisoned || session.info != self.info {
            return Err(FsError::NoDevice);
        }
        if self.session.is_some() {
            return Err(FsError::Busy);
        }
        self.session = Some(session);
        Ok(())
    }
    pub(crate) fn owns(&self, session: &Arc<Session>) -> bool {
        self.session
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(old, session))
    }
    pub(crate) fn idle(&self) -> bool {
        !self.active && !self.poisoned
    }
    pub(crate) fn invalidate(&mut self) {
        if let Some(session) = &self.session {
            session.fail(FsError::NoDevice);
        }
    }
    pub(crate) fn lost(&mut self) {
        self.poisoned = true;
        self.invalidate();
    }
    fn transaction<M: MmioWindow, T>(
        &self,
        io: &M,
        mut access: impl FnMut() -> bool,
        operation: impl FnOnce(&Mcr<'_, M>) -> Result<T, FsError>,
    ) -> Result<T, FsError> {
        let mcr = Mcr {
            io,
            info: self.info,
            access: RefCell::new(&mut access),
            lost: Cell::new(false),
        };
        let sem = mcr.raw_read(0xfd0)?;
        if sem & 1 == 0 {
            return Err(FsError::WouldBlock);
        }
        let old = mcr.raw_read(0xfd4)?;
        let result = operation(&mcr);
        if mcr.lost.get() {
            return Err(FsError::NoDevice);
        }
        mcr.raw_write(0xfd4, old)?;
        if mcr.raw_read(0xfd4)? != old {
            return Err(FsError::NoDevice);
        }
        mcr.raw_write(0xfd0, 1)?;
        result
    }
    pub(crate) fn control(
        &mut self,
        io: &impl MmioWindow,
        session: &Arc<Session>,
        enable: bool,
        access: impl FnMut() -> bool,
    ) -> Result<(), FsError> {
        if self.poisoned || !self.owns(session) || session.stop.load(Ordering::Acquire) {
            return Err(FsError::NoDevice);
        }
        if self.active == enable {
            return Ok(());
        }
        if !enable {
            return self.disable(io, access);
        }
        let base = self
            .backing
            .as_ref()
            .ok_or(FsError::NoDevice)?
            .ggtt_offset();
        // Mark uncertain before the first possible enable write. Any partial
        // failure retains the unchanged allocation until verified full reset.
        self.exposed = true;
        let mut pointers = [0; 32];
        let result = self.transaction(io, access, |mcr| {
            for (i, pointer) in pointers.iter_mut().enumerate() {
                if self.info.dss & (1 << i) != 0 {
                    if mcr.read(i, 0xe520)? & 2 != 0 {
                        return Err(FsError::Unsupported);
                    }
                    let status = mcr.read(i, 0xe528)?;
                    *pointer = ((status & 0xfffc) >> 2 << 6) & ((PER_CORE as u32 * 2) - 1);
                    mcr.write(i, 0xe528, 2 << 16, Some((2, 0)))?;
                    mcr.write(
                        i,
                        0xe52c,
                        0xfffc0000 | (status & 0xfffc),
                        Some((0xfffc, status & 0xfffc)),
                    )?;
                    // BMG UC MOCS3, source encodes index<<1 in CTRL[9:3].
                    mcr.write(
                        i,
                        0xe53c,
                        0x03ff0000 | (6 << 3) | session.config.rate,
                        Some((0x3ff, (6 << 3) | session.config.rate)),
                    )?;
                    mcr.write(i, 0xe524, 0, Some((u32::MAX, 0)))?;
                }
            }
            fence(Ordering::Release);
            // All samplers share one base; physical DSS index selects its
            // fixed-size sub-buffer, including holes in the fuse mask.
            for i in 0..32 {
                if self.info.dss & (1 << i) != 0 {
                    mcr.write(
                        i,
                        0xe520,
                        base | (2 << 3) | 2,
                        Some((u32::MAX, base | (2 << 3) | 2)),
                    )?;
                }
            }
            Ok(())
        });
        match result {
            Ok(()) => {
                self.read = pointers;
                self.write = pointers;
                self.active = true;
                self.next_poll = 0;
                let mut queue = session.queue.lock();
                queue.head = 0;
                queue.len = 0;
                queue.overflow = false;
                session.enabled.store(true, Ordering::Release);
                session.level(&queue);
                Ok(())
            }
            Err(FsError::WouldBlock) => Err(FsError::WouldBlock),
            Err(error) => {
                self.lost();
                Err(error)
            }
        }
    }
    pub(crate) fn disable(
        &mut self,
        io: &impl MmioWindow,
        access: impl FnMut() -> bool,
    ) -> Result<(), FsError> {
        if !self.exposed {
            return Ok(());
        }
        let result = self.transaction(io, access, |mcr| {
            for i in 0..32 {
                if self.info.dss & (1 << i) != 0 {
                    mcr.write(i, 0xe520, 0, Some((u32::MAX, 0)))?;
                }
            }
            Ok(())
        });
        if result.is_ok() {
            self.active = false;
            if let Some(session) = &self.session {
                session.enabled.store(false, Ordering::Release);
                session.level(&session.queue.lock());
            }
        } else if result != Err(FsError::WouldBlock) {
            self.lost();
        }
        result
    }
    pub(crate) fn poll(
        &mut self,
        io: &impl MmioWindow,
        now: u64,
        access: impl FnMut() -> bool,
    ) -> Result<(), FsError> {
        let result = self.poll_inner(io, now, access);
        match result {
            Err(FsError::WouldBlock) => result,
            Err(FsError::Io(_)) => {
                if let Some(session) = &self.session {
                    session.dropped();
                }
                Ok(())
            }
            Err(_) => {
                self.lost();
                result
            }
            Ok(()) => Ok(()),
        }
    }
    fn poll_inner(
        &mut self,
        io: &impl MmioWindow,
        now: u64,
        mut access: impl FnMut() -> bool,
    ) -> Result<(), FsError> {
        let Some(session) = self.session.clone() else {
            return Ok(());
        };
        if session.stop.load(Ordering::Acquire) {
            self.disable(io, access)?;
            self.session = None;
            return Ok(());
        }
        if self.poisoned {
            return Ok(());
        }
        if !self.active || now < self.next_poll {
            return Ok(());
        }
        self.next_poll = now.saturating_add(POLL_NS);
        let mut pointers = [0; 32];
        let mut dropped = false;
        self.transaction(io, &mut access, |mcr| {
            for (i, pointer) in pointers.iter_mut().enumerate() {
                if self.info.dss & (1 << i) != 0 {
                    let value = mcr.read(i, 0xe528)?;
                    *pointer = ((value & 0xfffc) >> 2 << 6) & ((PER_CORE as u32 * 2) - 1);
                    if value & 2 != 0 {
                        dropped = true;
                        mcr.write(i, 0xe528, 2 << 16, Some((2, 0)))?;
                    }
                }
            }
            Ok(())
        })?;
        self.write = pointers;
        if (0..32).any(|i| {
            self.info.dss & (1 << i) != 0 && distance(self.read[i], self.write[i]) > PER_CORE
        }) {
            return Err(FsError::InvalidData);
        }
        if dropped {
            session.dropped();
        }
        let available: u64 = (0..32)
            .filter(|i| self.info.dss & (1 << i) != 0)
            .map(|i| distance(self.read[i], self.write[i]) as u64 / RECORD as u64)
            .sum();
        if available < session.config.wait || session.room() < RECORD {
            return Ok(());
        }
        let Some(i) = (0..32)
            .map(|n| (self.cursor + n) % 32)
            .find(|&i| self.info.dss & (1 << i) != 0 && self.read[i] != self.write[i])
        else {
            return Ok(());
        };
        let count = distance(self.read[i], self.write[i])
            .min(CHUNK)
            .min(session.room())
            / RECORD
            * RECORD;
        let mut bytes = [0; CHUNK];
        if !access() {
            self.lost();
            return Err(FsError::NoDevice);
        }
        fence(Ordering::Acquire);
        let backing = self.backing.as_ref().ok_or(FsError::NoDevice)?;
        for (n, word) in bytes[..count].chunks_exact_mut(4).enumerate() {
            let at = i * PER_CORE + (self.read[i] as usize + n * 4) % PER_CORE;
            word.copy_from_slice(&backing.read32(at as u64).to_le_bytes());
        }
        let next = (self.read[i] + count as u32) & ((PER_CORE as u32 * 2) - 1);
        self.transaction(io, &mut access, |mcr| {
            let after = mcr.read(i, 0xe528)?;
            if after & 2 != 0 {
                return Err(crate::intel_gpu_user::io_error());
            }
            fence(Ordering::Release);
            mcr.write(
                i,
                0xe52c,
                0xfffc0000 | ((next >> 6) << 2),
                Some((0xfffc, (next >> 6) << 2)),
            )
        })?;
        self.read[i] = next;
        self.cursor = (i + 1) % 32;
        if !session.push(&bytes[..count]) {
            self.lost();
            return Err(FsError::NoDevice);
        }
        Ok(())
    }
    /// # Safety
    /// The caller has proven full graphics-GT reset, GuC reset and DMA idle.
    pub(crate) unsafe fn release_after_reset(mut self) {
        self.invalidate();
        self.retired = true;
    }
}
impl<A: BootAllocator> Drop for Collector<A> {
    fn drop(&mut self) {
        self.invalidate();
        if let Some(backing) = self.backing.take() {
            if !self.exposed || self.retired {
                self.allocator.free(backing);
            } else {
                core::mem::forget(backing);
            }
        }
    }
}
fn distance(read: u32, write: u32) -> usize {
    ((write.wrapping_sub(read)) & ((PER_CORE as u32 * 2) - 1)) as usize
}
struct Mcr<'a, M: MmioWindow> {
    io: &'a M,
    info: Info,
    access: RefCell<&'a mut dyn FnMut() -> bool>,
    lost: Cell<bool>,
}
impl<M: MmioWindow> Mcr<'_, M> {
    fn check(&self) -> Result<(), FsError> {
        if self.lost.get() || !(self.access.borrow_mut())() {
            self.lost.set(true);
            Err(FsError::NoDevice)
        } else {
            Ok(())
        }
    }
    fn raw_read(&self, reg: u64) -> Result<u32, FsError> {
        self.check()?;
        let value = self.io.read32(reg);
        if value == u32::MAX {
            self.lost.set(true);
            return Err(FsError::NoDevice);
        }
        self.check()?;
        Ok(value)
    }
    fn raw_write(&self, reg: u64, value: u32) -> Result<(), FsError> {
        self.check()?;
        self.io.write32(reg, value);
        self.check()
    }
    fn select(&self, dss: usize, multicast: bool) -> Result<(), FsError> {
        let value = (if multicast { 1 << 31 } else { 0 })
            | ((dss as u32 / u32::from(self.info.per_group)) << 8)
            | (dss as u32 % u32::from(self.info.per_group));
        self.raw_write(0xfd4, value)?;
        if self.raw_read(0xfd4)? == value {
            Ok(())
        } else {
            self.lost.set(true);
            Err(FsError::NoDevice)
        }
    }
    fn read(&self, dss: usize, reg: u64) -> Result<u32, FsError> {
        self.select(dss, true)?;
        self.raw_read(reg)
    }
    fn write(
        &self,
        dss: usize,
        reg: u64,
        value: u32,
        expected: Option<(u32, u32)>,
    ) -> Result<(), FsError> {
        self.select(dss, false)?;
        self.raw_write(reg, value)?;
        if let Some((mask, expected)) = expected {
            if self.read(dss, reg)? & mask != expected {
                self.lost.set(true);
                return Err(FsError::NoDevice);
            }
        }
        Ok(())
    }
}
#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_eu_stall_tests.rs"]
mod tests;
