//! Linux syscall ABI conformance — perf_event_open group.
//!
//! Covers perf_event_open parameter validation, CPU checking,
//! task checks, and configuration validation.

#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;
use crate::perf_event::perf_event_attr;

const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
const PERF_FORMAT_ID: u64 = 1 << 2;
const PERF_FORMAT_GROUP: u64 = 1 << 3;

const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u64 = 0x2401;
const PERF_EVENT_IOC_RESET: u64 = 0x2403;
const PERF_EVENT_IOC_ID: u64 = 0x8008_2407;
const EOPNOTSUPP: i64 = -95;

fn smoke_abi_perf_event_open_validation() -> TestResult {
    with_setup(|| {
        if core::mem::size_of::<perf_event_attr>() != 128
            || core::mem::offset_of!(perf_event_attr, config) != 8
            || core::mem::offset_of!(perf_event_attr, flags) != 40
            || core::mem::offset_of!(perf_event_attr, sig_data) != 120
        {
            return Err("perf_event_attr does not match Linux PERF_ATTR_SIZE_VER7 layout");
        }

        // Test 1: attr_ptr == 0 -> expect EFAULT (-14)
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(0, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(EFAULT) => {}
            _ => return Err("perf_event_open(NULL) did not return EFAULT"),
        }

        // Test 2: invalid CPU -> expect EINVAL (-22)
        let attr = perf_event_attr {
            type_: 0, // PERF_TYPE_HARDWARE
            size: core::mem::size_of::<perf_event_attr>() as u32,
            config: 0, // PERF_COUNT_HW_CPU_CYCLES
            ..perf_event_attr::default()
        };

        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 0, 9999, -1i32 as u64),
        ) {
            Some(EINVAL) => {}
            _ => return Err("perf_event_open(invalid CPU) did not return EINVAL"),
        }

        // Test 3: invalid PID -> expect ESRCH (-3)
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 9999, -1i32 as u64, -1i32 as u64),
        ) {
            Some(ESRCH) => {}
            _ => return Err("perf_event_open(invalid PID) did not return ESRCH"),
        }

        // Test 4: invalid group_fd -> expect EBADF (-9)
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 0, -1i32 as u64, 9999),
        ) {
            Some(EBADF) => {}
            _ => return Err("perf_event_open(invalid group_fd) did not return EBADF"),
        }

        // Test 5: invalid type/config -> expect ENOENT (-2)
        let bad_attr = perf_event_attr {
            type_: 9999, // invalid type
            size: core::mem::size_of::<perf_event_attr>() as u32,
            ..perf_event_attr::default()
        };

        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&bad_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(ENOENT) => {}
            _ => return Err("perf_event_open(invalid type) did not return ENOENT"),
        }

        // Test 6: Unknown flags -> expect EINVAL (-22)
        match call(
            Syscall::PerfEventOpen.raw(),
            SyscallArgs {
                arg0: &attr as *const _ as u64,
                arg1: 0,
                arg2: -1i32 as u64,
                arg3: -1i32 as u64,
                arg4: 1 << 30, // unknown flag
                ..SyscallArgs::default()
            },
        ) {
            Some(EINVAL) => {}
            _ => return Err("perf_event_open(unknown flags) did not return EINVAL"),
        }

        // Sampling requires the mmap ring, which is deliberately outside the
        // counting-only compatibility slice.
        let sampling_attr = perf_event_attr {
            sample_period_or_freq: 1000,
            ..attr
        };
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &sampling_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(EOPNOTSUPP) => {}
            _ => return Err("perf_event_open(sampling) did not return EOPNOTSUPP"),
        }

        // PERF_FLAG_PID_CGROUP cannot be approximated as a normal pid event.
        match call(
            Syscall::PerfEventOpen.raw(),
            SyscallArgs {
                arg0: &attr as *const _ as u64,
                arg1: 0,
                arg2: -1i32 as u64,
                arg3: -1i32 as u64,
                arg4: 4,
                ..SyscallArgs::default()
            },
        ) {
            Some(EOPNOTSUPP) => {}
            _ => return Err("perf_event_open(PID_CGROUP) did not return EOPNOTSUPP"),
        }

        // Test 7: Size less than PERF_ATTR_SIZE_VER0 -> expect E2BIG (-7)
        let mut short_attr = attr;
        short_attr.size = 32; // invalid size
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &short_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(-7) => {} // E2BIG
            _ => return Err("perf_event_open(size too small) did not return E2BIG"),
        }

        // Test 8: Size greater than 4096 -> expect E2BIG (-7)
        let mut huge_attr = attr;
        huge_attr.size = 8192; // invalid size
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&huge_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(-7) => {} // E2BIG
            _ => return Err("perf_event_open(size too large) did not return E2BIG"),
        }

        // Test 9: Reserved fields non-zero -> expect EINVAL (-22)
        let mut res_attr = attr;
        res_attr.__reserved_2 = 1;
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&res_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(EINVAL) => {}
            _ => return Err("perf_event_open(reserved_2 non-zero) did not return EINVAL"),
        }

        // Test 10: Successful creation & read
        let sw_attr = perf_event_attr {
            type_: 1, // PERF_TYPE_SOFTWARE
            size: core::mem::size_of::<perf_event_attr>() as u32,
            config: 0, // PERF_COUNT_SW_CPU_CLOCK
            ..perf_event_attr::default()
        };

        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&sw_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(valid software event) failed to create fd"),
        };

        // Read into too small buffer (< 8 bytes) -> expect -EINVAL (-22)
        let mut small_buf = [0u8; 4];
        let read_res = call_raw(
            Syscall::Read.raw(),
            a2(fd as u64, small_buf.as_mut_ptr() as u64, 4),
        );
        if read_res.status != SyscallReturn::INVALID_OP {
            return Err(
                "read from perf fd with buffer < 8 bytes did not return SyscallReturn::INVALID_OP",
            );
        }

        // Read into valid 8-byte buffer -> expect success (returns 8)
        let mut valid_buf = [0u8; 8];
        match call(
            Syscall::Read.raw(),
            a2(fd as u64, valid_buf.as_mut_ptr() as u64, 8),
        ) {
            Some(8) => {
                let val = u64::from_ne_bytes(valid_buf);
                if val == 0 {
                    return Err("read value from software CPU clock was 0");
                }
            }
            _ => return Err("read from perf fd into valid 8-byte buffer did not return 8"),
        }

        // Test 11: Close the FD
        match call(Syscall::Close.raw(), a0(fd as u64)) {
            Some(0) => {}
            _ => return Err("close of perf event fd failed"),
        }

        // Test 12: Cloexec flag
        let fd_cloexec = match call(
            Syscall::PerfEventOpen.raw(),
            SyscallArgs {
                arg0: &sw_attr as *const _ as u64,
                arg1: 0,
                arg2: -1i32 as u64,
                arg3: -1i32 as u64,
                arg4: 8, // PERF_FLAG_FD_CLOEXEC
                ..SyscallArgs::default()
            },
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open with CLOEXEC flag failed to create fd"),
        };

        let is_cloexec = crate::fd::with_table(FAKE_TASK, |t| {
            t.get(fd_cloexec)
                .map(|entry| (entry.flags & crate::fd::FD_CLOEXEC) != 0)
        })
        .flatten()
        .unwrap_or(false);

        if !is_cloexec {
            return Err("fd created with PERF_FLAG_FD_CLOEXEC did not have FD_CLOEXEC flag set");
        }

        let _ = call(Syscall::Close.raw(), a0(fd_cloexec as u64));

        // Test 13: perf-stat read format and the counting-control ioctls.
        let stat_attr = perf_event_attr {
            type_: 1,
            size: core::mem::size_of::<perf_event_attr>() as u32,
            config: 0, // PERF_COUNT_SW_CPU_CLOCK
            read_format: PERF_FORMAT_TOTAL_TIME_ENABLED
                | PERF_FORMAT_TOTAL_TIME_RUNNING
                | PERF_FORMAT_ID,
            flags: 1, // disabled
            ..perf_event_attr::default()
        };
        let stat_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&stat_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(stat-format event) failed"),
        };

        let mut id = 0u64;
        match call(
            Syscall::Ioctl.raw(),
            a2(stat_fd as u64, PERF_EVENT_IOC_ID, &mut id as *mut _ as u64),
        ) {
            Some(0) if id != 0 => {}
            _ => return Err("PERF_EVENT_IOC_ID did not return a stable non-zero id"),
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(stat_fd as u64, PERF_EVENT_IOC_RESET, 0),
        ) != Some(0)
            || call(
                Syscall::Ioctl.raw(),
                a2(stat_fd as u64, PERF_EVENT_IOC_ENABLE, 0),
            ) != Some(0)
        {
            return Err("perf reset/enable ioctl failed");
        }

        let mut stat_read = [0u64; 4];
        match call(
            Syscall::Read.raw(),
            a2(
                stat_fd as u64,
                stat_read.as_mut_ptr() as u64,
                core::mem::size_of_val(&stat_read) as u64,
            ),
        ) {
            Some(32) => {}
            _ => return Err("perf stat-format read did not return four u64 words"),
        }
        if stat_read[2] == 0 || stat_read[3] != id {
            return Err("perf stat-format time/id fields are invalid");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(stat_fd as u64, PERF_EVENT_IOC_DISABLE, 0),
        ) != Some(0)
        {
            return Err("PERF_EVENT_IOC_DISABLE failed");
        }
        let mut stopped_a = [0u64; 4];
        let mut stopped_b = [0u64; 4];
        let _ = call(
            Syscall::Read.raw(),
            a2(
                stat_fd as u64,
                stopped_a.as_mut_ptr() as u64,
                core::mem::size_of_val(&stopped_a) as u64,
            ),
        );
        let _ = call(
            Syscall::Read.raw(),
            a2(
                stat_fd as u64,
                stopped_b.as_mut_ptr() as u64,
                core::mem::size_of_val(&stopped_b) as u64,
            ),
        );
        if stopped_a != stopped_b {
            return Err("disabled perf event continued accumulating");
        }
        let _ = call(Syscall::Close.raw(), a0(stat_fd as u64));

        // Test 14: enable_on_exec remains stopped until the target commits exec.
        let exec_attr = perf_event_attr {
            flags: 1 | (1 << 12), // disabled | enable_on_exec
            ..stat_attr
        };
        let exec_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&exec_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(enable_on_exec) failed"),
        };
        let mut exec_before = [u64::MAX; 4];
        let _ = call(
            Syscall::Read.raw(),
            a2(
                exec_fd as u64,
                exec_before.as_mut_ptr() as u64,
                core::mem::size_of_val(&exec_before) as u64,
            ),
        );
        if exec_before[0] != 0 || exec_before[1] != 0 {
            return Err("enable_on_exec event started before exec");
        }
        crate::perf_event::on_exec(crate::handlers::current_task_id());
        let mut exec_after = [0u64; 4];
        let _ = call(
            Syscall::Read.raw(),
            a2(
                exec_fd as u64,
                exec_after.as_mut_ptr() as u64,
                core::mem::size_of_val(&exec_after) as u64,
            ),
        );
        if exec_after[1] == 0 {
            return Err("enable_on_exec event did not start at exec commit");
        }
        let task = crate::handlers::current_task_id();
        crate::perf_event::on_process_exit(
            crate::handlers::task_to_pid_raw(task).unwrap_or(task),
            task,
        );
        let mut exit_stopped_a = [0u64; 4];
        let mut exit_stopped_b = [0u64; 4];
        let _ = call(
            Syscall::Read.raw(),
            a2(
                exec_fd as u64,
                exit_stopped_a.as_mut_ptr() as u64,
                core::mem::size_of_val(&exit_stopped_a) as u64,
            ),
        );
        let _ = call(
            Syscall::Read.raw(),
            a2(
                exec_fd as u64,
                exit_stopped_b.as_mut_ptr() as u64,
                core::mem::size_of_val(&exit_stopped_b) as u64,
            ),
        );
        if exit_stopped_a != exit_stopped_b {
            return Err("perf event continued after target process exit");
        }
        let _ = call(Syscall::Close.raw(), a0(exec_fd as u64));

        // Test 15: linked group wire shape and group-wide lifecycle ioctls.
        let group_attr = perf_event_attr {
            read_format: PERF_FORMAT_GROUP
                | PERF_FORMAT_TOTAL_TIME_ENABLED
                | PERF_FORMAT_TOTAL_TIME_RUNNING
                | PERF_FORMAT_ID,
            ..stat_attr
        };
        let group_read_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &group_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(group-format event) failed"),
        };
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&group_attr as *const _ as u64, 0, 0, group_read_fd as u64),
        ) {
            Some(EINVAL) => {}
            _ => return Err("perf group accepted mismatched CPU target"),
        }
        let group_member_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &group_attr as *const _ as u64,
                0,
                -1i32 as u64,
                group_read_fd as u64,
            ),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(group member) failed"),
        };
        if call(
            Syscall::Ioctl.raw(),
            a2(group_read_fd as u64, PERF_EVENT_IOC_RESET, 1),
        ) != Some(0)
            || call(
                Syscall::Ioctl.raw(),
                a2(group_read_fd as u64, PERF_EVENT_IOC_ENABLE, 1),
            ) != Some(0)
        {
            return Err("group-wide RESET/ENABLE failed");
        }
        let mut group_read = [0u64; 7];
        match call(
            Syscall::Read.raw(),
            a2(
                group_read_fd as u64,
                group_read.as_mut_ptr() as u64,
                core::mem::size_of_val(&group_read) as u64,
            ),
        ) {
            Some(56)
                if group_read[0] == 2
                    && group_read[4] != 0
                    && group_read[6] != 0
                    && group_read[4] != group_read[6] => {}
            _ => return Err("PERF_FORMAT_GROUP read layout is invalid"),
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(group_read_fd as u64, PERF_EVENT_IOC_DISABLE, 1),
        ) != Some(0)
        {
            return Err("group-wide DISABLE failed");
        }
        let _ = call(Syscall::Close.raw(), a0(group_member_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(group_read_fd as u64));

        // Test 16: unknown read-format bits are rejected at open.
        let bad_format_attr = perf_event_attr {
            read_format: 1 << 63,
            ..sw_attr
        };
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &bad_format_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(EINVAL) => {}
            _ => return Err("perf_event_open accepted unknown read_format bits"),
        }

        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_perf_event_open_validation);
