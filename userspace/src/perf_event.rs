use crate::fd::{self, FdEntry};
use crate::handlers::{copy_from_user, copy_to_user, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

static ACTIVE_PERF_EVENTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_PERF_EVENT_ID: AtomicU64 = AtomicU64::new(1);

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

#[derive(Debug)]
struct PerfEventFile {
    attr: perf_event_attr,
    id: u64,
    enabled: AtomicBool,
    count_base: AtomicU64,
    count_accumulated: AtomicU64,
    enabled_at_ns: AtomicU64,
    time_enabled_ns: AtomicU64,
    registered: AtomicBool,
    #[cfg(target_arch = "x86_64")]
    pmu_counter: Option<narf_arch::x86_64::pmu::PmuCounter>,
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
    }

    fn reset(&self) {
        self.count_accumulated.store(0, Ordering::Release);
        self.time_enabled_ns.store(0, Ordering::Release);
        if self.enabled.load(Ordering::Acquire) {
            self.count_base.store(self.raw_count(), Ordering::Release);
            self.enabled_at_ns
                .store(narf_time::monotonic_ns(), Ordering::Release);
        }
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

    fn push_word(buf: &mut [u8], cursor: &mut usize, value: u64) -> Result<(), FsError> {
        let end = cursor.saturating_add(8);
        let dst = buf.get_mut(*cursor..end).ok_or(FsError::InvalidData)?;
        dst.copy_from_slice(&value.to_ne_bytes());
        *cursor = end;
        Ok(())
    }
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
                Self::push_word(buf, &mut cursor, 1)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                Self::push_word(buf, &mut cursor, value)?;
            } else {
                Self::push_word(buf, &mut cursor, value)?;
                if format & PERF_FORMAT_TOTAL_TIME_ENABLED != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
                if format & PERF_FORMAT_TOTAL_TIME_RUNNING != 0 {
                    Self::push_word(buf, &mut cursor, time_enabled)?;
                }
            }
            if format & PERF_FORMAT_ID != 0 {
                Self::push_word(buf, &mut cursor, self.id)?;
            }
            if format & PERF_FORMAT_LOST != 0 {
                Self::push_word(buf, &mut cursor, 0)?;
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
                self.enable();
                Ok(0)
            }
            PERF_EVENT_IOC_DISABLE => {
                self.disable();
                Ok(0)
            }
            PERF_EVENT_IOC_RESET => {
                self.reset();
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

    if pid > 0 && pid as u64 != task && crate::handlers::pid_to_task_raw(pid as u64).is_none() {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
        return;
    }

    if cpu != -1 && (cpu < 0 || !narf_lib::smp::is_online(cpu as u32)) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }

    if group_fd != -1 {
        let valid_group =
            fd::with_table(task, |t| t.get(group_fd as u32).is_some()).unwrap_or(false);
        if !valid_group {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        }
        // Group leaders can expose the single-event GROUP read shape, but
        // linking member events is not implemented yet.
        ctx.set_return(SyscallReturn::ok((-95i64) as u64)); // EOPNOTSUPP
        return;
    }

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
            unsafe { narf_arch::x86_64::pmu::alloc_counter(event).ok() }
        } else {
            None
        }
    };

    // Allocate an fd
    let cloexec = (flags & 8) != 0; // PERF_FLAG_FD_CLOEXEC
    let install_flags = if cloexec { fd::FD_CLOEXEC } else { 0 };

    let mut opened_file = None;
    let fd_num_opt = fd::with_table(task, |t| {
        let initially_enabled =
            attr.flags & PERF_ATTR_DISABLED == 0 || attr.flags & PERF_ATTR_ENABLE_ON_EXEC != 0;
        let file = Arc::new(PerfEventFile {
            attr,
            id: NEXT_PERF_EVENT_ID.fetch_add(1, Ordering::Relaxed),
            enabled: AtomicBool::new(false),
            count_base: AtomicU64::new(0),
            count_accumulated: AtomicU64::new(0),
            enabled_at_ns: AtomicU64::new(0),
            time_enabled_ns: AtomicU64::new(0),
            registered: AtomicBool::new(false),
            #[cfg(target_arch = "x86_64")]
            pmu_counter,
        });
        if initially_enabled {
            file.enable();
        }
        let result = t.open(FdEntry {
            ops: file.clone(),
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
        0 => matches!(attr.config, 0..=9),
        // PERF_TYPE_SOFTWARE
        1 => matches!(attr.config, 0..=12),
        // PERF_TYPE_HW_CACHE (3)
        3 => {
            let cache_id = attr.config & 0xFF;
            let op_id = (attr.config >> 8) & 0xFF;
            let result_id = (attr.config >> 16) & 0xFF;
            cache_id <= 6 && op_id <= 2 && result_id <= 1
        }
        // PERF_TYPE_RAW (4)
        4 => true,
        _ => false,
    }
}
