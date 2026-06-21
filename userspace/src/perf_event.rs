use crate::fd::{self, FdEntry};
use crate::handlers::{copy_from_user, current_task_id};
use crate::syscall::{SyscallReturn, TrapContext};
use alloc::boxed::Box;
use alloc::sync::Arc;
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat};

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

struct PerfEventFile {
    _attr: perf_event_attr,
}

impl FileOps for PerfEventFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let attr = self._attr;
        Box::pin(async move {
            if buf.len() < 8 {
                return Err(FsError::InvalidData);
            }

            let val: u64 = match attr.type_ {
                // PERF_TYPE_HARDWARE
                0 => match attr.config {
                    // PERF_COUNT_HW_CPU_CYCLES
                    0 => narf_time::now_cycles(),
                    // PERF_COUNT_HW_INSTRUCTIONS (stubbed to cycles for now)
                    1 => narf_time::now_cycles(),
                    _ => return Err(FsError::Unsupported),
                },
                // PERF_TYPE_SOFTWARE
                1 => match attr.config {
                    // PERF_COUNT_SW_PAGE_FAULTS
                    2 => narf_lib::perf::snapshot().page_faults,
                    // PERF_COUNT_SW_CONTEXT_SWITCHES
                    3 => narf_lib::perf::snapshot().ctx,
                    _ => return Err(FsError::Unsupported),
                },
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
    let _pid = ctx.args().arg1 as i32;
    let _cpu = ctx.args().arg2 as i32;
    let _group_fd = ctx.args().arg3 as i32;
    let flags = ctx.args().arg4 as u64;

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

    if unsafe { copy_from_user(size_slice, attr_ptr + 4) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    if size == 0 {
        size = PERF_ATTR_SIZE_VER0;
    }

    if size < PERF_ATTR_SIZE_VER0 || size > 4096 {
        ctx.set_return(SyscallReturn::ok((-7i64) as u64)); // E2BIG
        return;
    }

    // Read the attr structure
    let to_read = core::cmp::min(size as usize, core::mem::size_of::<perf_event_attr>());

    // Since perf_event_attr has padding/not perfectly transparent, we read bytes
    let attr_bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut attr as *mut _ as *mut u8,
            core::mem::size_of::<perf_event_attr>(),
        )
    };

    if unsafe { copy_from_user(&mut attr_bytes[..to_read], attr_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    // If user passed a larger struct, the extra bytes must be zero
    if size as usize > core::mem::size_of::<perf_event_attr>() {
        let mut extra_byte: u8 = 0;
        for i in core::mem::size_of::<perf_event_attr>()..(size as usize) {
            let extra_slice = core::slice::from_mut(&mut extra_byte);
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

    // Allocate an fd
    let task = current_task_id();
    let cloexec = (flags & 8) != 0; // PERF_FLAG_FD_CLOEXEC
    let install_flags = if cloexec { fd::FD_CLOEXEC } else { 0 };

    let fd_num_opt = fd::with_table(task, |t| {
        t.open(FdEntry {
            ops: Arc::new(PerfEventFile { _attr: attr }),
            offset: 0,
            flags: install_flags,
            status_flags: 0,
        })
    });

    if let Some(fd_num) = fd_num_opt {
        ctx.set_return(SyscallReturn::ok(fd_num as u64));
    } else {
        ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // EMFILE
    }
}
