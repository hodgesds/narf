use crate::fd::{self, FdEntry};
use crate::handlers::{copy_from_user, copy_to_user, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

static ACTIVE_PERF_EVENTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_PERF_EVENT_ID: AtomicU64 = AtomicU64::new(1);
static PERF_EVENT_REGISTRY: IrqSafeSpinLock<Vec<Weak<PerfEventFile>>> =
    IrqSafeSpinLock::new(Vec::new());

pub const PERF_ATTR_SIZE_VER0: u32 = 64;
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
const PERF_FORMAT_ID: u64 = 1 << 2;
const PERF_FORMAT_GROUP: u64 = 1 << 3;
const PERF_FORMAT_LOST: u64 = 1 << 4;
const PERF_FORMAT_SUPPORTED: u64 = (1 << 5) - 1;

const PERF_ATTR_DISABLED: u64 = 1 << 0;
const PERF_ATTR_ENABLE_ON_EXEC: u64 = 1 << 12;

const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;
const PERF_EVENT_IOC_RESET: u32 = 0x2403;
const PERF_EVENT_IOC_ID: u32 = 0x8008_2407;
const PERF_IOC_FLAG_GROUP: usize = 1;
const PERF_MMAP_PAGE_BYTES: usize = 4096;
const PERF_MMAP_MAX_DATA_PAGES: usize = 256;
const PERF_MMAP_LOCK_OFFSET: usize = 8;
const PERF_MMAP_OFFSET_OFFSET: usize = 16;
const PERF_MMAP_TIME_ENABLED_OFFSET: usize = 24;
const PERF_MMAP_TIME_RUNNING_OFFSET: usize = 32;
const PERF_MMAP_DATA_OFFSET_OFFSET: usize = 1040;
const PERF_MMAP_DATA_SIZE_OFFSET: usize = 1048;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct perf_event_attr {
    pub type_: u32,
    pub size: u32,
    pub config: u64,
    pub sample_period_or_freq: u64,
    pub sample_type: u64,
    pub read_format: u64,
    pub flags: u64,
    pub wakeup_events_or_watermark: u32,
    pub bp_type: u32,
    pub bp_addr_or_config1: u64,
    pub bp_len_or_config2: u64,
    pub branch_sample_type: u64,
    pub sample_regs_user: u64,
    pub sample_stack_user: u32,
    pub clockid: i32,
    pub sample_regs_intr: u64,
    pub aux_watermark: u32,
    pub sample_max_stack: u16,
    pub __reserved_2: u16,
    pub aux_sample_size: u32,
    pub __reserved_3: u32,
    pub sig_data: u64,
}

struct PerfEventFile {
    attr: perf_event_attr,
    id: u64,
    target_task: u64,
    target_pid: u64,
    target_cpu: i32,
    enabled: AtomicBool,
    count_base: AtomicU64,
    count_accumulated: AtomicU64,
    enabled_at_ns: AtomicU64,
    time_enabled_ns: AtomicU64,
    registered: AtomicBool,
    mmap_seq: AtomicU32,
    mmap: IrqSafeSpinLock<Option<PerfMmap>>,
    group_members: IrqSafeSpinLock<Vec<Weak<dyn FileOps>>>,
    // A member keeps its leader's open-file description alive. The leader
    // holds only weak member links, so this cannot form a reference cycle.
    _group_leader: Option<Arc<dyn FileOps>>,
    #[cfg(target_arch = "x86_64")]
    pmu_counter: Option<narf_arch::x86_64::pmu::PmuCounter>,
}

struct PerfMmap {
    frames: Vec<narf_memory::PhysFrame>,
    len: usize,
}

impl PerfMmap {
    fn allocate(len: usize) -> Result<Self, FsError> {
        let pages = len / PERF_MMAP_PAGE_BYTES;
        let data_pages = pages.saturating_sub(1);
        if len < PERF_MMAP_PAGE_BYTES * 2
            || len % PERF_MMAP_PAGE_BYTES != 0
            || !data_pages.is_power_of_two()
            || data_pages > PERF_MMAP_MAX_DATA_PAGES
        {
            return Err(FsError::InvalidData);
        }
        let mut frames = Vec::with_capacity(pages);
        while frames.len() < pages {
            let frame = match narf_memory::alloc_frame() {
                Ok(frame) => frame,
                Err(_) => {
                    for frame in frames.drain(..) {
                        narf_memory::free_frame(frame);
                    }
                    return Err(FsError::NoSpace);
                }
            };
            // SAFETY: `frame` is freshly allocated, owned here, and identity
            // mapped for the full 4 KiB page.
            unsafe {
                core::ptr::write_bytes(
                    frame.start_address().raw() as *mut u8,
                    0,
                    PERF_MMAP_PAGE_BYTES,
                );
            }
            frames.push(frame);
        }
        let mapping = Self { frames, len };
        mapping.write_u64(PERF_MMAP_DATA_OFFSET_OFFSET, PERF_MMAP_PAGE_BYTES as u64);
        mapping.write_u64(
            PERF_MMAP_DATA_SIZE_OFFSET,
            (len - PERF_MMAP_PAGE_BYTES) as u64,
        );
        Ok(mapping)
    }

    fn write_u32(&self, offset: usize, value: u32) {
        // SAFETY: the metadata frame is a live identity-mapped 4 KiB frame and
        // every call site uses a naturally aligned in-page u32 field.
        unsafe {
            core::ptr::write_volatile(
                (self.frames[0].start_address().raw() as usize + offset) as *mut u32,
                value,
            );
        }
    }

    fn write_u64(&self, offset: usize, value: u64) {
        // SAFETY: same as write_u32, for naturally aligned u64 fields.
        unsafe {
            core::ptr::write_volatile(
                (self.frames[0].start_address().raw() as usize + offset) as *mut u64,
                value,
            );
        }
    }

    fn raw_frames(&self) -> Vec<u64> {
        self.frames
            .iter()
            .map(|frame| frame.start_address().raw())
            .collect()
    }
}

impl Drop for PerfMmap {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            narf_memory::free_frame(frame);
        }
    }
}

impl core::fmt::Debug for PerfEventFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PerfEventFile")
            .field("id", &self.id)
            .field("target_task", &self.target_task)
            .field("target_pid", &self.target_pid)
            .field("target_cpu", &self.target_cpu)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl PerfEventFile {
    fn raw_count(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = self.pmu_counter {
            // SAFETY: the counter belongs to this open file and remains allocated
            // until Drop, which cannot run while this method borrows `self`.
            return unsafe { narf_arch::x86_64::pmu::read(&counter) };
        }

        match self.attr.type_ {
            // PERF_TYPE_HARDWARE. Only values backed by a real counter reach this
            // fallback on non-x86 targets; cycles/ref-cycles remain useful there.
            0 => match self.attr.config {
                0 | 9 => narf_time::now_cycles(),
                _ => 0,
            },
            // PERF_TYPE_SOFTWARE
            1 => match self.attr.config {
                0 | 1 => narf_time::monotonic_ns(),
                2 | 5 => narf_lib::perf::snapshot().page_faults,
                3 => narf_lib::perf::snapshot().ctx,
                9 => 0,
                12 => narf_lib::perf::snapshot().syscalls,
                _ => 0,
            },
            _ => 0,
        }
    }

    fn enable(&self) {
        if !self.enabled.swap(true, Ordering::AcqRel) {
            self.count_base.store(self.raw_count(), Ordering::Release);
            self.enabled_at_ns
                .store(narf_time::monotonic_ns(), Ordering::Release);
        }
        self.publish_mmap_state();
    }

    fn disable(&self) {
        if self.enabled.swap(false, Ordering::AcqRel) {
            let raw = self.raw_count();
            let base = self.count_base.load(Ordering::Acquire);
            self.count_accumulated
                .fetch_add(raw.wrapping_sub(base), Ordering::AcqRel);
            let now = narf_time::monotonic_ns();
            let since = self.enabled_at_ns.load(Ordering::Acquire);
            self.time_enabled_ns
                .fetch_add(now.saturating_sub(since), Ordering::AcqRel);
        }
        self.publish_mmap_state();
    }

    fn reset(&self) {
        self.count_accumulated.store(0, Ordering::Release);
        self.time_enabled_ns.store(0, Ordering::Release);
        if self.enabled.load(Ordering::Acquire) {
            self.count_base.store(self.raw_count(), Ordering::Release);
            self.enabled_at_ns
                .store(narf_time::monotonic_ns(), Ordering::Release);
        }
        self.publish_mmap_state();
    }

    fn snapshot(&self) -> (u64, u64) {
        let mut value = self.count_accumulated.load(Ordering::Acquire);
        let mut time = self.time_enabled_ns.load(Ordering::Acquire);
        if self.enabled.load(Ordering::Acquire) {
            value = value.wrapping_add(
                self.raw_count()
                    .wrapping_sub(self.count_base.load(Ordering::Acquire)),
            );
            time = time.saturating_add(
                narf_time::monotonic_ns()
                    .saturating_sub(self.enabled_at_ns.load(Ordering::Acquire)),
            );
        }
        (value, time)
    }

    fn publish_mmap_state(&self) {
        let (value, time) = self.snapshot();
        let mapping = self.mmap.lock();
        let Some(mapping) = mapping.as_ref() else {
            return;
        };
        let sequence = self.mmap_seq.fetch_add(2, Ordering::Relaxed);
        mapping.write_u32(PERF_MMAP_LOCK_OFFSET, sequence.wrapping_add(1));
        core::sync::atomic::compiler_fence(Ordering::Release);
        // `index == 0` (the zeroed default) tells userspace that direct RDPMC
        // is unavailable; Linux then treats `offset` as the count snapshot.
        mapping.write_u64(PERF_MMAP_OFFSET_OFFSET, value);
        mapping.write_u64(PERF_MMAP_TIME_ENABLED_OFFSET, time);
        mapping.write_u64(PERF_MMAP_TIME_RUNNING_OFFSET, time);
        core::sync::atomic::compiler_fence(Ordering::Release);
        mapping.write_u32(PERF_MMAP_LOCK_OFFSET, sequence.wrapping_add(2));
    }

    fn member_files(&self) -> Vec<Arc<dyn FileOps>> {
        self.group_members
            .lock()
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }

    fn add_group_member(&self, member: &Arc<dyn FileOps>) {
        self.group_members.lock().push(Arc::downgrade(member));
    }

    fn for_group(&self, flags: usize, mut op: impl FnMut(&PerfEventFile)) -> Result<(), FsError> {
        if flags & !PERF_IOC_FLAG_GROUP != 0 {
            return Err(FsError::InvalidData);
        }
        op(self);
        if flags & PERF_IOC_FLAG_GROUP != 0 {
            for file in self.member_files() {
                if let Some(event) = file
                    .as_any()
                    .and_then(|any| any.downcast_ref::<PerfEventFile>())
                {
                    op(event);
                }
            }
        }
        Ok(())
    }

    fn push_word(buf: &mut [u8], cursor: &mut usize, value: u64) -> Result<(), FsError> {
        let end = cursor.saturating_add(8);
        let dst = buf.get_mut(*cursor..end).ok_or(FsError::InvalidData)?;
        dst.copy_from_slice(&value.to_ne_bytes());
        *cursor = end;
        Ok(())
    }
}

/// Apply Linux `enable_on_exec` at the point a task commits a new image.
///
/// Events are owned by the monitoring process but keyed by the target task,
/// matching the way the upstream perf CLI opens events for its stopped child.
pub(crate) fn on_exec(task: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.target_task == task
            && event.attr.flags & PERF_ATTR_ENABLE_ON_EXEC != 0
            && event._group_leader.is_none()
        {
            let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::enable);
        }
        true
    });
}

/// Stop task-targeted events when the target process becomes group-dead.
pub(crate) fn on_process_exit(pid: u64, _tid: u64) {
    let mut registry = PERF_EVENT_REGISTRY.lock();
    registry.retain(|weak| {
        let Some(event) = weak.upgrade() else {
            return false;
        };
        if event.target_pid == pid && event._group_leader.is_none() {
            let _ = event.for_group(PERF_IOC_FLAG_GROUP, PerfEventFile::disable);
        }
        true
    });
}

impl Drop for PerfEventFile {
    fn drop(&mut self) {
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = self.pmu_counter {
            // SAFETY: releasing the counter we allocated.
            unsafe {
                narf_arch::x86_64::pmu::release(counter);
            }
        }
        if self.registered.load(Ordering::Acquire)
            && ACTIVE_PERF_EVENTS.fetch_sub(1, Ordering::Relaxed) == 1
        {
            narf_lib::perf::set_enabled(false);
        }
    }
}

impl FileOps for PerfEventFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            let (value, time_enabled) = self.snapshot();
            let format = self.attr.read_format;
            let mut cursor = 0;

            if format & PERF_FORMAT_GROUP != 0 {
                let members = self.member_files();
                Self::push_word(buf, &mut cursor, 1 + members.len() as u64)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                Self::push_word(buf, &mut cursor, value)?;
                if format & PERF_FORMAT_ID != 0 {
                    Self::push_word(buf, &mut cursor, self.id)?;
                }
                if format & PERF_FORMAT_LOST != 0 {
                    Self::push_word(buf, &mut cursor, 0)?;
                }
                for file in members {
                    let event = file
                        .as_any()
                        .and_then(|any| any.downcast_ref::<PerfEventFile>())
                        .ok_or(FsError::InvalidData)?;
                    let (member_value, _) = event.snapshot();
                    Self::push_word(buf, &mut cursor, member_value)?;
                    if format & PERF_FORMAT_ID != 0 {
                        Self::push_word(buf, &mut cursor, event.id)?;
                    }
                    if format & PERF_FORMAT_LOST != 0 {
                        Self::push_word(buf, &mut cursor, 0)?;
                    }
                }
            } else {
                Self::push_word(buf, &mut cursor, value)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_ID != 0 {
                    Self::push_word(buf, &mut cursor, self.id)?;
                }
                if format & PERF_FORMAT_LOST != 0 {
                    Self::push_word(buf, &mut cursor, 0)?;
                }
            }
            Ok(cursor)
        })
    }

    fn write<'a>(&'a self, _offset: u64, _buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move { Err(FsError::ReadOnly) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        match cmd {
            PERF_EVENT_IOC_ENABLE => {
                self.for_group(arg, PerfEventFile::enable)?;
                Ok(0)
            }
            PERF_EVENT_IOC_DISABLE => {
                self.for_group(arg, PerfEventFile::disable)?;
                Ok(0)
            }
            PERF_EVENT_IOC_RESET => {
                self.for_group(arg, PerfEventFile::reset)?;
                Ok(0)
            }
            PERF_EVENT_IOC_ID => {
                // SAFETY: ioctl's user pointer is validated and SMAP-bracketed by
                // copy_to_user; a bad pointer is reported as InvalidData/EINVAL.
                unsafe { copy_to_user(arg as u64, &self.id.to_ne_bytes()) }
                    .map_err(|_| FsError::InvalidData)?;
                Ok(0)
            }
            _ => Err(FsError::Unsupported),
        }
    }

    fn mmap_frames(&self, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
        if offset != 0 {
            return Err(FsError::InvalidData);
        }

        let frames = {
            let mut slot = self.mmap.lock();
            if let Some(mapping) = slot.as_ref() {
                if mapping.len != len {
                    return Err(FsError::InvalidData);
                }
                mapping.raw_frames()
            } else {
                let mapping = PerfMmap::allocate(len)?;
                let frames = mapping.raw_frames();
                *slot = Some(mapping);
                frames
            }
        };
        self.publish_mmap_state();
        Ok(frames)
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

pub fn sys_perf_event_open(ctx: &mut dyn TrapContext) {
    let attr_ptr = ctx.args().arg0;
    let pid = ctx.args().arg1 as i32;
    let cpu = ctx.args().arg2 as i32;
    let group_fd = ctx.args().arg3 as i32;
    let flags = ctx.args().arg4;

    // Reject unknown flags per Linux
    // PERF_FLAG_FD_NO_GROUP = 1, PERF_FLAG_FD_OUTPUT = 2, PERF_FLAG_PID_CGROUP = 4, PERF_FLAG_FD_CLOEXEC = 8
    if (flags & !15) != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // Redirected output and cgroup attachment require the mmap/sampling and
    // cgroup implementations. Do not silently create a differently scoped event.
    if flags & (2 | 4) != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if attr_ptr == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    let mut attr = perf_event_attr::default();

    // We need to read the size first (u32 at offset 4).
    let mut size: u32 = 0;
    // SAFETY: getting mutable slice of local size variable
    let size_slice =
        unsafe { core::slice::from_raw_parts_mut(&mut size as *mut u32 as *mut u8, 4) };

    // SAFETY: `size_slice` is a 4-byte view of the local `size` u32 (live for this
    // call); `attr_ptr` is the user-supplied pointer and was checked non-null above.
    // `copy_from_user` validates the user range and SMAP-brackets the read, so a bad
    // user address yields Err rather than faulting the kernel.
    if unsafe { copy_from_user(size_slice, attr_ptr + 4) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    if size == 0 {
        size = PERF_ATTR_SIZE_VER0;
    }

    if !(PERF_ATTR_SIZE_VER0..=4096).contains(&size) {
        ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
        return;
    }

    // Read the attr structure
    let to_read = core::cmp::min(size as usize, core::mem::size_of::<perf_event_attr>());

    // Since perf_event_attr has padding/not perfectly transparent, we read bytes
    // SAFETY: `attr` is a live local `perf_event_attr`; we form a byte view spanning
    // exactly its `size_of` so the slice stays within the object. It is only used as
    // the destination of `copy_from_user` below, which writes at most `to_read` bytes.
    let attr_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut attr as *mut _ as *mut u8,
            core::mem::size_of::<perf_event_attr>(),
        )
    };

    // SAFETY: `attr_bytes[..to_read]` is a sub-slice of the live `attr` byte view
    // (`to_read <= size_of::<perf_event_attr>()`); `attr_ptr` is the non-null user
    // pointer. `copy_from_user` validates the user range and SMAP-brackets the read.
    if unsafe { copy_from_user(&mut attr_bytes[..to_read], attr_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    // If user passed a larger struct, the extra bytes must be zero
    if size as usize > core::mem::size_of::<perf_event_attr>() {
        let mut extra_byte: u8 = 0;
        for i in core::mem::size_of::<perf_event_attr>()..(size as usize) {
            let extra_slice = core::slice::from_mut(&mut extra_byte);
            // SAFETY: `extra_slice` is a 1-byte view of the live local `extra_byte`;
            // `attr_ptr + i` stays within the user-declared `size` window (i < size).
            // `copy_from_user` validates the user range and SMAP-brackets the read.
            if unsafe { copy_from_user(extra_slice, attr_ptr + i as u64) }.is_err() {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
            if extra_byte != 0 {
                ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
                return;
            }
        }
    }

    if attr.__reserved_2 != 0 || attr.__reserved_3 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    if attr.read_format & !PERF_FORMAT_SUPPORTED != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    // Period/frequency sampling needs a perf mmap ring. Counting events may
    // still set sample_type (current perf does so for identifiers), provided
    // no sampling period/frequency was requested.
    if attr.sample_period_or_freq != 0 {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    if !is_supported_event(&attr) {
        ctx.set_return(SyscallReturn::ok((-2i64) as u64)); // ENOENT
        return;
    }

    let task = current_task_id();

    let target_task = if pid == 0 {
        task
    } else if pid > 0 {
        match crate::handlers::pid_to_task_raw(pid as u64) {
            Some(target) => target,
            None if pid as u64 == task => task,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    } else {
        // pid == -1 denotes a per-CPU event with no task target.
        u64::MAX
    };
    let target_pid = if pid == 0 {
        crate::handlers::task_to_pid_raw(task).unwrap_or(task)
    } else if pid > 0 {
        pid as u64
    } else {
        u64::MAX
    };

    if cpu != -1 && (cpu < 0 || !narf_lib::smp::is_online(cpu as u32)) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    let group_leader = if group_fd != -1 {
        let leader =
            fd::with_table(task, |t| t.get(group_fd as u32).map(|e| Arc::clone(&e.ops))).flatten();
        let Some(leader) = leader else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        };
        let Some(leader_event) = leader
            .as_any()
            .and_then(|any| any.downcast_ref::<PerfEventFile>())
        else {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        };
        if leader_event.target_task != target_task || leader_event.target_cpu != cpu {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        Some(leader)
    } else {
        None
    };

    // Try to allocate PMU counter if target_arch is x86_64
    #[cfg(target_arch = "x86_64")]
    let pmu_counter = {
        let event_opt = match attr.type_ {
            // PERF_TYPE_HARDWARE
            0 => match attr.config {
                0 => Some(narf_arch::x86_64::pmu::PmuEvent::Cycles),
                1 => Some(narf_arch::x86_64::pmu::PmuEvent::Instructions),
                2 => Some(narf_arch::x86_64::pmu::PmuEvent::CacheMisses), // PERF_COUNT_HW_CACHE_REFERENCES (Intel uses LLC ref)
                3 => Some(narf_arch::x86_64::pmu::PmuEvent::CacheMisses), // PERF_COUNT_HW_CACHE_MISSES
                4 => Some(narf_arch::x86_64::pmu::PmuEvent::BranchInstructions),
                5 => Some(narf_arch::x86_64::pmu::PmuEvent::BranchMisses),
                9 => Some(narf_arch::x86_64::pmu::PmuEvent::Cycles), // PERF_COUNT_HW_REF_CPU_CYCLES
                _ => None,
            },
            // PERF_TYPE_HW_CACHE
            3 => {
                let cache_id = attr.config & 0xFF;
                let result_id = (attr.config >> 16) & 0xFF;
                match (cache_id, result_id) {
                    (0, 1) => Some(narf_arch::x86_64::pmu::PmuEvent::CacheMisses), // L1D Miss
                    (2, 1) => Some(narf_arch::x86_64::pmu::PmuEvent::LlcMisses),   // LLC Miss
                    _ => None,
                }
            }
            // PERF_TYPE_RAW
            4 => Some(narf_arch::x86_64::pmu::PmuEvent::Raw(attr.config)),
            _ => None,
        };

        if let Some(event) = event_opt {
            // SAFETY: alloc_counter programs PMU hardware registers, which requires CPL=0.
            match unsafe { narf_arch::x86_64::pmu::alloc_counter(event) } {
                Ok(counter) => Some(counter),
                // QEMU and early hardware without a programmable PMU can still
                // expose the architectural cycle clock. Other hardware events
                // must not silently degrade to fabricated values.
                Err(narf_arch::x86_64::pmu::PmuError::NoPmu)
                    if attr.type_ == 0 && matches!(attr.config, 0 | 9) =>
                {
                    None
                }
                Err(narf_arch::x86_64::pmu::PmuError::NoFreeCounter) => {
                    ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
                    return;
                }
                Err(_) => {
                    ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
                    return;
                }
            }
        } else {
            None
        }
    };

    #[cfg(not(target_arch = "x86_64"))]
    if attr.type_ != 1 && !(attr.type_ == 0 && matches!(attr.config, 0 | 9)) {
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

    // Allocate an fd
    let cloexec = (flags & 8) != 0; // PERF_FLAG_FD_CLOEXEC
    let install_flags = if cloexec { fd::FD_CLOEXEC } else { 0 };

    let mut opened_file = None;
    let fd_num_opt = fd::with_table(task, |t| {
        // A group member is scheduled only through its leader even when its
        // own disabled bit is clear (the upstream CLI relies on this).
        let initially_enabled = group_leader.is_none() && attr.flags & PERF_ATTR_DISABLED == 0;
        let file = Arc::new(PerfEventFile {
            attr,
            id: NEXT_PERF_EVENT_ID.fetch_add(1, Ordering::Relaxed),
            target_task,
            target_pid,
            target_cpu: cpu,
            enabled: AtomicBool::new(false),
            count_base: AtomicU64::new(0),
            count_accumulated: AtomicU64::new(0),
            enabled_at_ns: AtomicU64::new(0),
            time_enabled_ns: AtomicU64::new(0),
            registered: AtomicBool::new(false),
            mmap_seq: AtomicU32::new(0),
            mmap: IrqSafeSpinLock::new(None),
            group_members: IrqSafeSpinLock::new(Vec::new()),
            _group_leader: group_leader.clone(),
            #[cfg(target_arch = "x86_64")]
            pmu_counter,
        });
        if initially_enabled {
            file.enable();
        }
        let ops: Arc<dyn FileOps> = file.clone();
        if let Some(leader) = &group_leader {
            if let Some(event) = leader
                .as_any()
                .and_then(|any| any.downcast_ref::<PerfEventFile>())
            {
                event.add_group_member(&ops);
            }
        }
        let result = t.open(FdEntry {
            ops,
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        });
        opened_file = Some(file);
        result
    });

    if let Some(fd_num) = fd_num_opt {
        // Mark registration before publishing the global enabled bit. The fd table
        // owns another Arc, so this file remains alive after `opened_file` drops.
        if let Some(file) = opened_file {
            file.registered.store(true, Ordering::Release);
            PERF_EVENT_REGISTRY.lock().push(Arc::downgrade(&file));
        }
        if ACTIVE_PERF_EVENTS.fetch_add(1, Ordering::Relaxed) == 0 {
            narf_lib::perf::set_enabled(true);
        }
        ctx.set_return(SyscallReturn::ok(fd_num as u64));
    } else {
        // No fd table exists for the current task, so the closure never took
        // ownership of the allocated counter.
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = pmu_counter {
            // SAFETY: this is the counter allocated above and no file owns it.
            unsafe {
                narf_arch::x86_64::pmu::release(counter);
            }
        }
        ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // EMFILE
    }
}

fn is_supported_event(attr: &perf_event_attr) -> bool {
    match attr.type_ {
        // PERF_TYPE_HARDWARE
        0 => matches!(attr.config, 0..=5 | 9),
        // PERF_TYPE_SOFTWARE
        1 => matches!(attr.config, 0 | 1 | 2 | 3 | 5 | 9 | 12),
        // PERF_TYPE_HW_CACHE (3)
        3 => {
            let cache_id = attr.config & 0xFF;
            let op_id = (attr.config >> 8) & 0xFF;
            let result_id = (attr.config >> 16) & 0xFF;
            matches!((cache_id, op_id, result_id), (0 | 2, 0, 1))
        }
        // PERF_TYPE_RAW (4)
        4 => true,
        _ => false,
    }
}
