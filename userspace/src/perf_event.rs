use crate::fd::{self, FdEntry};
use crate::handlers::{copy_from_user, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

static ACTIVE_PERF_EVENTS: AtomicUsize = AtomicUsize::new(0);

pub const PERF_ATTR_SIZE_VER0: u32 = 64;

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
    _attr: perf_event_attr,
    #[cfg(target_arch = "x86_64")]
    pmu_counter: Option<narf_arch::x86_64::pmu::PmuCounter>,
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
        if ACTIVE_PERF_EVENTS.fetch_sub(1, Ordering::Relaxed) == 1 {
            narf_lib::perf::set_enabled(false);
        }
    }
}

impl FileOps for PerfEventFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let attr = self._attr;
        #[cfg(target_arch = "x86_64")]
        let pmu = self.pmu_counter;

        Box::pin(async move {
            if buf.len() < 8 {
                return Err(FsError::InvalidData);
            }

            #[allow(clippy::needless_late_init)]
            let val: u64;

            #[cfg(target_arch = "x86_64")]
            if let Some(counter) = pmu {
                // SAFETY: counter was returned by alloc_counter and not yet released.
                val = unsafe { narf_arch::x86_64::pmu::read(&counter) };
                buf[0..8].copy_from_slice(&val.to_ne_bytes());
                return Ok(8);
            }

            val = match attr.type_ {
                // PERF_TYPE_HARDWARE
                0 => match attr.config {
                    // PERF_COUNT_HW_CPU_CYCLES
                    0 => narf_time::now_cycles(),
                    // PERF_COUNT_HW_INSTRUCTIONS
                    1 => narf_time::now_cycles(),
                    // PERF_COUNT_HW_CACHE_REFERENCES (stubbed)
                    2 => narf_time::now_cycles() / 20,
                    // PERF_COUNT_HW_CACHE_MISSES (stubbed)
                    3 => narf_time::now_cycles() / 100,
                    // PERF_COUNT_HW_BRANCH_INSTRUCTIONS (stubbed)
                    4 => narf_time::now_cycles() / 4,
                    // PERF_COUNT_HW_BRANCH_MISSES (stubbed)
                    5 => narf_time::now_cycles() / 100,
                    // PERF_COUNT_HW_BUS_CYCLES (stubbed)
                    6 => narf_time::now_cycles() / 10,
                    // PERF_COUNT_HW_STALLED_CYCLES_FRONTEND (stubbed)
                    7 => 0,
                    // PERF_COUNT_HW_STALLED_CYCLES_BACKEND (stubbed)
                    8 => 0,
                    // PERF_COUNT_HW_REF_CPU_CYCLES
                    9 => narf_time::now_cycles(),
                    _ => return Err(FsError::Unsupported),
                },
                // PERF_TYPE_SOFTWARE
                1 => match attr.config {
                    // PERF_COUNT_SW_CPU_CLOCK
                    0 => narf_time::monotonic_ns(),
                    // PERF_COUNT_SW_TASK_CLOCK
                    1 => narf_time::monotonic_ns(),
                    // PERF_COUNT_SW_PAGE_FAULTS
                    2 => narf_lib::perf::snapshot().page_faults,
                    // PERF_COUNT_SW_CONTEXT_SWITCHES
                    3 => narf_lib::perf::snapshot().ctx,
                    // PERF_COUNT_SW_CPU_MIGRATIONS (stubbed)
                    4 => 0,
                    // PERF_COUNT_SW_PAGE_FAULTS_MIN
                    5 => narf_lib::perf::snapshot().page_faults,
                    // PERF_COUNT_SW_PAGE_FAULTS_MAJ (stubbed)
                    6 => 0,
                    // PERF_COUNT_SW_ALIGNMENT_FAULTS (stubbed)
                    7 => 0,
                    // PERF_COUNT_SW_EMULATION_FAULTS (stubbed)
                    8 => 0,
                    // PERF_COUNT_SW_DUMMY
                    9 => 0,
                    // PERF_COUNT_SW_BPF_OUTPUT (stubbed)
                    10 => 0,
                    // PERF_COUNT_SW_CGROUP_SWITCHES (stubbed)
                    11 => 0,
                    // PERF_COUNT_SW_SYSCALLS (custom)
                    12 => narf_lib::perf::snapshot().syscalls,
                    _ => return Err(FsError::Unsupported),
                },
                // PERF_TYPE_HW_CACHE (3) - stub fallback when PMU is missing
                3 => {
                    let cache_id = attr.config & 0xFF;
                    let op_id = (attr.config >> 8) & 0xFF;
                    let result_id = (attr.config >> 16) & 0xFF;
                    if cache_id > 6 || op_id > 2 || result_id > 1 {
                        return Err(FsError::Unsupported);
                    }
                    if result_id == 1 {
                        narf_time::now_cycles() / 100 // Cache Miss fallback
                    } else {
                        narf_time::now_cycles() / 20 // Cache Reference/Access fallback
                    }
                }
                // PERF_TYPE_RAW (4)
                4 => narf_time::now_cycles(),
                _ => return Err(FsError::Unsupported),
            };

            buf[0..8].copy_from_slice(&val.to_ne_bytes());
            Ok(8)
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

    let fd_num_opt = fd::with_table(task, |t| {
        t.open(FdEntry {
            ops: Arc::new(PerfEventFile {
                _attr: attr,
                #[cfg(target_arch = "x86_64")]
                pmu_counter,
            }),
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        })
    });

    if let Some(fd_num) = fd_num_opt {
        if ACTIVE_PERF_EVENTS.fetch_add(1, Ordering::Relaxed) == 0 {
            narf_lib::perf::set_enabled(true);
        }
        ctx.set_return(SyscallReturn::ok(fd_num as u64));
    } else {
        // If fd table full, we must drop the allocated PMU counter explicitly
        #[cfg(target_arch = "x86_64")]
        if let Some(counter) = pmu_counter {
            // SAFETY: releasing the counter we allocated.
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
