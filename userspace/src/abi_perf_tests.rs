//! Linux syscall ABI conformance — perf_event_open group.
//!
//! Covers perf_event_open parameter validation, CPU checking,
//! task checks, and configuration validation.

#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;
use narf_linux_perf_uapi::{
    PerfEventAttr, PERF_ATTR_FLAG_BPF_EVENT, PERF_ATTR_FLAG_FREQ, PERF_ATTR_FLAG_INHERIT,
    PERF_ATTR_FLAG_WATERMARK,
};

const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;
const PERF_FORMAT_ID: u64 = 1 << 2;
const PERF_FORMAT_GROUP: u64 = 1 << 3;
const PERF_FORMAT_LOST: u64 = 1 << 4;

const PERF_EVENT_IOC_ENABLE: u64 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u64 = 0x2401;
const PERF_EVENT_IOC_REFRESH: u64 = 0x2402;
const PERF_EVENT_IOC_RESET: u64 = 0x2403;
const PERF_EVENT_IOC_PERIOD: u64 = 0x4008_2404;
const PERF_EVENT_IOC_SET_OUTPUT: u64 = 0x2405;
const PERF_EVENT_IOC_ID: u64 = 0x8008_2407;
const PERF_EVENT_IOC_PAUSE_OUTPUT: u64 = 0x4004_2409;
const EOPNOTSUPP: i64 = -95;

fn smoke_abi_perf_event_open_validation() -> TestResult {
    with_setup(|| {
        let rotated: [usize; 4] =
            core::array::from_fn(|offset| crate::perf_event::rotation_index_for_test(2, offset, 4));
        if rotated != [2, 3, 0, 1] {
            return Err("perf multiplex cursor did not wrap fairly");
        }
        if crate::perf_event::advance_rotation_cursor_for_test(u64::MAX, 7, 3) != 3
            || crate::perf_event::advance_rotation_cursor_for_test(7, 7, 3) != 3
            || crate::perf_event::advance_rotation_cursor_for_test(7, 8, 3) != 4
        {
            return Err("perf multiplex cursor advanced without a task switch");
        }
        if !crate::perf_event::multiplex_quantum_due_for_test(0, 1)
            || crate::perf_event::multiplex_quantum_due_for_test(1, 1_000_000)
            || !crate::perf_event::multiplex_quantum_due_for_test(1, 1_000_001)
        {
            return Err("perf multiplex timer quantum boundary is incorrect");
        }
        if crate::perf_event::remaining_sample_period_for_test(100_000, 25_000) != 75_000
            || crate::perf_event::remaining_sample_period_for_test(100_000, 100_000) != 1
            || crate::perf_event::remaining_sample_period_for_test(100_000, 125_000) != 1
        {
            return Err("perf sampled period-left accounting is incorrect");
        }

        #[cfg(target_arch = "x86_64")]
        {
            if crate::perf_event::frequency_period(20_000, 100_000, 10_000) != 20_000
                || crate::perf_event::frequency_period(20_000, 100_000, 40_000) != 5_000
                || crate::perf_event::frequency_period(20_000, 100_000, 2_500) != 80_000
            {
                return Err("perf frequency controller ratio or slew bounds are wrong");
            }
        }
        if core::mem::size_of::<PerfEventAttr>() != 144
            || core::mem::offset_of!(PerfEventAttr, config) != 8
            || core::mem::offset_of!(PerfEventAttr, flags) != 40
            || core::mem::offset_of!(PerfEventAttr, sig_data) != 120
        {
            return Err("PerfEventAttr does not match Linux PERF_ATTR_SIZE_VER9 layout");
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
        let attr = PerfEventAttr {
            type_: 1, // PERF_TYPE_SOFTWARE
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 9, // PERF_COUNT_SW_DUMMY
            ..PerfEventAttr::default()
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

        // Test 5: unsupported type/config -> expect EOPNOTSUPP (-95)
        let bad_attr = PerfEventAttr {
            type_: 9999, // invalid type
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            ..PerfEventAttr::default()
        };

        match call(
            Syscall::PerfEventOpen.raw(),
            a3(&bad_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(EOPNOTSUPP) => {}
            _ => return Err("perf_event_open(unsupported type) did not return EOPNOTSUPP"),
        }

        // aarch64 currently has only the cycle-counting backend. It must not
        // accept programmable events and return plausible-looking zeroes.
        #[cfg(target_arch = "aarch64")]
        {
            let instructions_attr = PerfEventAttr {
                type_: 0,  // PERF_TYPE_HARDWARE
                config: 1, // PERF_COUNT_HW_INSTRUCTIONS
                ..attr
            };
            match call(
                Syscall::PerfEventOpen.raw(),
                a3(
                    &instructions_attr as *const _ as u64,
                    0,
                    -1i32 as u64,
                    -1i32 as u64,
                ),
            ) {
                Some(EOPNOTSUPP) => {}
                _ => return Err("aarch64 accepted an unimplemented programmable PMU event"),
            }
            let raw_attr = PerfEventAttr {
                type_: 4, // PERF_TYPE_RAW
                config: 0x08,
                ..attr
            };
            match call(
                Syscall::PerfEventOpen.raw(),
                a3(&raw_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
            ) {
                Some(EOPNOTSUPP) => {}
                _ => return Err("aarch64 accepted an unimplemented raw PMU event"),
            }
        }

        let approximate_sw_attr = PerfEventAttr {
            type_: 1,
            config: 0, // PERF_COUNT_SW_CPU_CLOCK needs per-target accounting
            ..attr
        };
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &approximate_sw_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(EOPNOTSUPP) => {}
            _ => return Err("perf_event_open admitted an approximate software event"),
        }

        let exact_cpu_clock_attr = PerfEventAttr {
            type_: 1,
            config: 0,     // PERF_COUNT_SW_CPU_CLOCK
            flags: 1 << 5, // exclude_kernel
            ..attr
        };
        let cpu_clock_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &exact_cpu_clock_attr as *const _ as u64,
                -1i32 as u64,
                narf_lib::percpu::current_cpu() as u64,
                -1i32 as u64,
            ),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("exact per-CPU user clock was not admitted"),
        };
        crate::perf_event::on_task_switch(0xfeed, true);
        for _ in 0..10_000 {
            core::hint::black_box(());
        }
        crate::perf_event::on_task_switch(0xfeed, false);
        let mut cpu_clock_count = [0u8; 8];
        if call(
            Syscall::Read.raw(),
            a2(cpu_clock_fd as u64, cpu_clock_count.as_mut_ptr() as u64, 8),
        ) != Some(8)
            || u64::from_ne_bytes(cpu_clock_count) == 0
        {
            return Err("per-CPU user clock did not report scheduler execution");
        }
        let _ = call(Syscall::Close.raw(), a0(cpu_clock_fd as u64));

        let ignored_attr_flag = PerfEventAttr {
            flags: 1 << 2, // pinned scheduling is not implemented
            ..attr
        };
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &ignored_attr_flag as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(EOPNOTSUPP) => {}
            _ => return Err("perf_event_open ignored an unimplemented attr flag"),
        }

        let zero_frequency = PerfEventAttr {
            flags: PERF_ATTR_FLAG_FREQ,
            ..attr
        };
        match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &zero_frequency as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(EINVAL) => {}
            _ => return Err("perf_event_open accepted zero frequency mode"),
        }

        // perf record opens this per-CPU dummy event to consume BPF lifecycle
        // sideband records. NARF has no BPF runtime, so its watermark-selected
        // record domain is truthfully empty and the fd remains readable as a
        // real zero-count software event.
        let empty_bpf_sideband = PerfEventAttr {
            flags: PERF_ATTR_FLAG_BPF_EVENT | PERF_ATTR_FLAG_WATERMARK,
            wakeup_events_or_watermark: 1,
            ..attr
        };
        let sideband_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &empty_bpf_sideband as *const _ as u64,
                -1i32 as u64,
                narf_lib::percpu::current_cpu() as u64,
                -1i32 as u64,
            ),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("perf_event_open rejected the empty BPF sideband event"),
        };
        let _ = call(Syscall::Close.raw(), a0(sideband_fd));

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

        // Unsupported sample payloads remain fail-closed even though the
        // common perf-record layout is implemented.
        let sampling_attr = PerfEventAttr {
            sample_period_or_freq: 1000,
            sample_type: 1 << 3, // PERF_SAMPLE_ADDR is not implemented
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
            _ => {
                return Err("perf_event_open(unsupported sample layout) did not return EOPNOTSUPP")
            }
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
        let sw_attr = PerfEventAttr {
            type_: 1, // PERF_TYPE_SOFTWARE
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 9, // PERF_COUNT_SW_DUMMY
            ..PerfEventAttr::default()
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
                if val != 0 {
                    return Err("PERF_COUNT_SW_DUMMY did not return its specified zero count");
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
        let stat_attr = PerfEventAttr {
            type_: 1,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 9, // PERF_COUNT_SW_DUMMY
            read_format: PERF_FORMAT_TOTAL_TIME_ENABLED
                | PERF_FORMAT_TOTAL_TIME_RUNNING
                | PERF_FORMAT_ID,
            flags: 1, // disabled
            ..PerfEventAttr::default()
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
        if stat_read[1] == 0
            || stat_read[2] == 0
            || stat_read[2] > stat_read[1]
            || stat_read[3] != id
        {
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
        let exec_attr = PerfEventAttr {
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
        crate::perf_event::on_exec(crate::handlers::current_task_id(), &[], "/test");
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
        let group_attr = PerfEventAttr {
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
        let bad_format_attr = PerfEventAttr {
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

        // Test 17: counting fds expose Linux's metadata page and a
        // power-of-two data area. The same open-file description owns one
        // stable set of frames for the mapping's lifetime.
        let mmap_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&stat_attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(mmap event) failed"),
        };
        let mmap_ops =
            crate::fd::with_table(FAKE_TASK, |t| t.get(mmap_fd).map(|entry| entry.ops.clone()))
                .flatten()
                .ok_or("perf mmap fd was absent from the fd table")?;
        let frames = mmap_ops
            .mmap_frames(0, 3 * 4096)
            .map_err(|_| "valid perf mmap layout was rejected")?;
        if frames.len() != 3 {
            return Err("perf mmap returned the wrong number of frames");
        }
        // SAFETY: the perf file owns these live, identity-mapped physical
        // frames until mmap_ops is dropped. Linux's u64 metadata fields are
        // naturally aligned within the first page.
        let read_meta = |offset: usize| unsafe {
            core::ptr::read_volatile((frames[0] as usize + offset) as *const u64)
        };
        if read_meta(1040) != 4096 || read_meta(1048) != 8192 {
            return Err("perf mmap data_offset/data_size metadata is invalid");
        }
        if read_meta(1024) != 0 || read_meta(1032) != 0 {
            return Err("new perf mmap ring did not start empty");
        }
        let repeated = mmap_ops
            .mmap_frames(0, 3 * 4096)
            .map_err(|_| "repeated perf mmap was rejected")?;
        if repeated != frames {
            return Err("repeated perf mmap returned different backing frames");
        }
        if mmap_ops.mmap_frames(0, 4 * 4096).is_ok() || mmap_ops.mmap_frames(4096, 3 * 4096).is_ok()
        {
            return Err("perf mmap accepted an invalid layout or offset");
        }
        let _ = call(Syscall::Close.raw(), a0(mmap_fd as u64));

        // Test 18: a due sample becomes a Linux PERF_RECORD_SAMPLE in the
        // mmap data ring and makes the fd POLLIN-readable.
        let sample_attr = PerfEventAttr {
            type_: 1, // PERF_TYPE_SOFTWARE
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 9, // PERF_COUNT_SW_DUMMY
            sample_period_or_freq: 0,
            sample_type: (1 << 0) // IP
                | (1 << 1) // TID
                | (1 << 2) // TIME
                | (1 << 6) // ID
                | (1 << 7) // CPU
                | (1 << 8), // PERIOD
            read_format: PERF_FORMAT_LOST,
            flags: 1 | PERF_ATTR_FLAG_INHERIT | (1 << 18), // disabled + inherit + sample_id_all
            ..PerfEventAttr::default()
        };
        let sample_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &sample_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(sample event) failed"),
        };
        let sample_ops = crate::fd::with_table(FAKE_TASK, |t| {
            t.get(sample_fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("perf sample fd was absent from the fd table")?;
        let sample_frames = sample_ops
            .mmap_frames(0, 3 * 4096)
            .map_err(|_| "perf sample mmap failed")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(sample_fd as u64, PERF_EVENT_IOC_ENABLE, 0),
        ) != Some(0)
        {
            return Err("enabling sampled perf event failed");
        }
        let sample_parent = FAKE_TASK;
        if !crate::perf_event::event_tracks_task_for_test(sample_fd, sample_parent) {
            return Err("perf event did not retain its opening task");
        }
        let sample_pid = crate::handlers::task_to_pid_raw(sample_parent).unwrap_or(sample_parent);
        crate::perf_event::on_fork(sample_pid, 77, sample_parent, 88);
        if !crate::perf_event::event_tracks_task_for_test(sample_fd, 88) {
            return Err("perf inherit did not attach the child task");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(sample_fd as u64, PERF_EVENT_IOC_PAUSE_OUTPUT, 1),
        ) != Some(0)
        {
            return Err("pausing perf output failed");
        }
        crate::perf_event::sample_from_irq_for_test(88, 0xDEAD_BEEF);
        // SAFETY: sample_ops owns the metadata frame.
        if unsafe { core::ptr::read_volatile((sample_frames[0] as usize + 1024) as *const u64) }
            != 0
        {
            return Err("paused perf output still committed a record");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(sample_fd as u64, PERF_EVENT_IOC_PAUSE_OUTPUT, 0),
        ) != Some(0)
        {
            return Err("resuming perf output failed");
        }
        crate::perf_event::sample_from_irq_for_test(88, 0x1234_5678);
        // SAFETY: sample_ops owns all three identity-mapped frames here.
        let data_head =
            unsafe { core::ptr::read_volatile((sample_frames[0] as usize + 1024) as *const u64) };
        if data_head == 0 {
            return Err("inherited perf event did not sample its child task");
        }
        if data_head != 56 {
            return Err("perf sample record has the wrong wire size");
        }
        // SAFETY: the first 56-byte record starts at the beginning of data page 0.
        let record = unsafe {
            core::slice::from_raw_parts(sample_frames[1] as *const u8, data_head as usize)
        };
        if u32::from_ne_bytes(record[0..4].try_into().unwrap()) != 9
            || u16::from_ne_bytes(record[6..8].try_into().unwrap()) != 56
            || u64::from_ne_bytes(record[8..16].try_into().unwrap()) != 0x1234_5678
            || u64::from_ne_bytes(record[48..56].try_into().unwrap()) != 0
        {
            return Err("PERF_RECORD_SAMPLE wire layout is invalid");
        }
        if sample_ops.poll_readiness() & narf_filesystem::POLL_IN == 0
            || !sample_ops.readiness_notifies()
        {
            return Err("sampled perf fd did not become POLLIN-readable");
        }
        let redirect_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &sample_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(redirect event) failed"),
        };
        if call(
            Syscall::Ioctl.raw(),
            a2(
                redirect_fd as u64,
                PERF_EVENT_IOC_SET_OUTPUT,
                sample_fd as u64,
            ),
        ) != Some(0)
            || call(
                Syscall::Ioctl.raw(),
                a2(redirect_fd as u64, PERF_EVENT_IOC_ENABLE, 0),
            ) != Some(0)
        {
            return Err("redirecting perf output failed");
        }
        crate::perf_event::sample_from_irq_for_test(sample_parent, 0x8765_4321);
        // Both the target event and redirected event commit a 56-byte sample
        // to the target ring; the redirected event has no mmap of its own.
        // SAFETY: sample_ops owns the mapped metadata frame.
        let redirected_head =
            unsafe { core::ptr::read_volatile((sample_frames[0] as usize + 1024) as *const u64) };
        if redirected_head != data_head + 112 {
            return Err("PERF_EVENT_IOC_SET_OUTPUT did not share the target ring");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(redirect_fd as u64, PERF_EVENT_IOC_SET_OUTPUT, u64::MAX),
        ) != Some(0)
        {
            return Err("detaching redirected perf output failed");
        }
        let _ = call(Syscall::Close.raw(), a0(redirect_fd as u64));
        for _ in 0..200 {
            crate::perf_event::sample_from_irq_for_test(88, 0x1234_5678);
        }
        let mut lost_read = [0u8; 16];
        if call(
            Syscall::Read.raw(),
            a2(
                sample_fd as u64,
                lost_read.as_mut_ptr() as u64,
                lost_read.len() as u64,
            ),
        ) != Some(16)
            || u64::from_ne_bytes(lost_read[8..16].try_into().unwrap()) == 0
        {
            return Err("PERF_FORMAT_LOST did not report ring drops");
        }
        // Free the ring and trigger one more sample. The pending loss must be
        // emitted first with the sample_id_all trailer perf uses to resolve
        // the owning event.
        // SAFETY: sample_ops owns the metadata and two data frames.
        let full_head =
            unsafe { core::ptr::read_volatile((sample_frames[0] as usize + 1024) as *const u64) };
        // SAFETY: userspace owns data_tail in perf_event_mmap_page.
        unsafe {
            core::ptr::write_volatile((sample_frames[0] as usize + 1032) as *mut u64, full_head);
        }
        crate::perf_event::sample_from_irq_for_test(88, 0xCAFE_BABE);
        // SAFETY: sample_ops owns the metadata frame.
        let recovered_head =
            unsafe { core::ptr::read_volatile((sample_frames[0] as usize + 1024) as *const u64) };
        if recovered_head != full_head + 112 {
            return Err("PERF_RECORD_LOST and following sample have wrong combined size");
        }
        let ring_byte = |absolute: u64| {
            let ring_offset = absolute as usize & (2 * 4096 - 1);
            // SAFETY: the selected byte is inside one of the two data frames.
            unsafe {
                *((sample_frames[1 + ring_offset / 4096] as usize + ring_offset % 4096)
                    as *const u8)
            }
        };
        let ring_u32 = |absolute: u64| {
            u32::from_ne_bytes(core::array::from_fn(|i| ring_byte(absolute + i as u64)))
        };
        let ring_u16 = |absolute: u64| {
            u16::from_ne_bytes(core::array::from_fn(|i| ring_byte(absolute + i as u64)))
        };
        let ring_u64 = |absolute: u64| {
            u64::from_ne_bytes(core::array::from_fn(|i| ring_byte(absolute + i as u64)))
        };
        let child_pid = crate::handlers::task_to_pid_raw(88).unwrap_or(88) as u32;
        if ring_u32(full_head) != 2
            || ring_u16(full_head + 6) != 56
            || ring_u64(full_head + 8) == 0
            || ring_u64(full_head + 8) != ring_u64(full_head + 40)
            || ring_u32(full_head + 24) != child_pid
            || ring_u32(full_head + 28) != 88
        {
            return Err("PERF_RECORD_LOST sample_id_all wire encoding is invalid");
        }
        crate::perf_event::on_thread_exit(77, 88);
        let _ = call(Syscall::Close.raw(), a0(sample_fd as u64));

        // Test 19: real lifecycle callbacks encode COMM/FORK/EXIT records,
        // including the requested sample_id_all identity trailer.
        let metadata_attr = PerfEventAttr {
            type_: 1,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 9, // PERF_COUNT_SW_DUMMY
            sample_type: (1 << 1) // TID
                | (1 << 2) // TIME
                | (1 << 6) // ID
                | (1 << 7) // CPU
                | (1 << 16), // IDENTIFIER
            flags: (1 << 9) // comm
                | (1 << 13) // task
                | (1 << 18) // sample_id_all
                | (1 << 17) // mmap_data
                | (1 << 23), // mmap2 (also covers executable mappings)
            ..PerfEventAttr::default()
        };
        let metadata_fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &metadata_attr as *const _ as u64,
                0,
                -1i32 as u64,
                -1i32 as u64,
            ),
        ) {
            Some(f) if f >= 0 => f as u32,
            _ => return Err("perf_event_open(metadata event) failed"),
        };
        let metadata_ops = crate::fd::with_table(FAKE_TASK, |t| {
            t.get(metadata_fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("perf metadata fd was absent from the fd table")?;
        let metadata_frames = metadata_ops
            .mmap_frames(0, 3 * 4096)
            .map_err(|_| "perf metadata mmap failed")?;
        let task = crate::handlers::current_task_id();
        let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
        crate::perf_event::on_mmap(task, -1, 0x4000_0000, 0x2000, 0, 5, 0x22);
        crate::perf_event::on_mmap(task, -1, 0x5000_0000, 0x3000, 0, 3, 0x21);
        crate::perf_event::on_comm(task, "worker");
        crate::perf_event::on_fork(pid, 77, task, 88);
        crate::perf_event::on_process_exit(pid, task);
        // SAFETY: metadata_ops owns these identity-mapped frames.
        let metadata_head =
            unsafe { core::ptr::read_volatile((metadata_frames[0] as usize + 1024) as *const u64) };
        if metadata_head != 448 {
            return Err("perf metadata records have the wrong combined wire size");
        }
        // SAFETY: all three records fit contiguously in the first data page.
        let records = unsafe {
            core::slice::from_raw_parts(metadata_frames[1] as *const u8, metadata_head as usize)
        };
        let header = |offset: usize| {
            (
                u32::from_ne_bytes(records[offset..offset + 4].try_into().unwrap()),
                u16::from_ne_bytes(records[offset + 6..offset + 8].try_into().unwrap()),
            )
        };
        if header(0) != (10, 120)
            || header(120) != (10, 120)
            || header(240) != (3, 64)
            || header(304) != (7, 72)
            || header(376) != (4, 72)
        {
            return Err("perf MMAP2/COMM/FORK/EXIT wire headers are invalid");
        }
        if u64::from_ne_bytes(records[16..24].try_into().unwrap()) != 0x4000_0000
            || u32::from_ne_bytes(records[64..68].try_into().unwrap()) != 5
            || u32::from_ne_bytes(records[68..72].try_into().unwrap()) != 2
            || &records[72..79] != b"//anon\0"
            || u16::from_ne_bytes(records[124..126].try_into().unwrap()) != (1 << 13)
            || u32::from_ne_bytes(records[184..188].try_into().unwrap()) != 3
            || u32::from_ne_bytes(records[188..192].try_into().unwrap()) != 1
            || &records[256..263] != b"worker\0"
            || u32::from_ne_bytes(records[312..316].try_into().unwrap()) != 77
            || u32::from_ne_bytes(records[320..324].try_into().unwrap()) != 88
        {
            return Err("perf metadata record payloads are invalid");
        }
        let _ = call(Syscall::Close.raw(), a0(metadata_fd as u64));

        // Test 20: task-scoped hardware events own a real current-CPU PMU
        // context and report retired work instead of counting peer tasks.
        {
            #[cfg(target_arch = "x86_64")]
            let pmu_available = narf_arch::x86_64::pmu::detect().is_some();
            #[cfg(target_arch = "aarch64")]
            let pmu_available = narf_arch::aarch64::pmu::available();
            if !pmu_available {
                return Ok(());
            }
            let hardware_attr = PerfEventAttr {
                type_: 0, // PERF_TYPE_HARDWARE
                size: core::mem::size_of::<PerfEventAttr>() as u32,
                config: 0, // PERF_COUNT_HW_CPU_CYCLES
                ..PerfEventAttr::default()
            };
            let hardware_fd = match call(
                Syscall::PerfEventOpen.raw(),
                a3(
                    &hardware_attr as *const _ as u64,
                    0,
                    -1i32 as u64,
                    -1i32 as u64,
                ),
            ) {
                Some(fd) if fd >= 0 => fd as u32,
                _ => return Err("task-scoped hardware event was not admitted"),
            };
            for _ in 0..10_000 {
                core::hint::black_box(());
            }
            let mut count = [0u8; 8];
            if call(
                Syscall::Read.raw(),
                a2(hardware_fd as u64, count.as_mut_ptr() as u64, 8),
            ) != Some(8)
                || u64::from_ne_bytes(count) == 0
            {
                return Err("task-scoped hardware counter did not report real execution");
            }
            let _ = call(Syscall::Close.raw(), a0(hardware_fd as u64));

            #[cfg(target_arch = "x86_64")]
            let initial_period = 1000;
            #[cfg(target_arch = "aarch64")]
            let initial_period = 100_000;
            let sampling_hardware_attr = PerfEventAttr {
                sample_period_or_freq: initial_period,
                sample_type: 1, // PERF_SAMPLE_IP
                flags: 1,       // disabled
                ..hardware_attr
            };
            let period_fd = match call(
                Syscall::PerfEventOpen.raw(),
                a3(
                    &sampling_hardware_attr as *const _ as u64,
                    0,
                    -1i32 as u64,
                    -1i32 as u64,
                ),
            ) {
                Some(fd) if fd >= 0 => fd as u32,
                _ => return Err("disabled hardware sampling event was not admitted"),
            };
            #[cfg(target_arch = "x86_64")]
            let new_period = 4096u64;
            #[cfg(target_arch = "aarch64")]
            let new_period = 100_000u64;
            if call(
                Syscall::Ioctl.raw(),
                a2(
                    period_fd as u64,
                    PERF_EVENT_IOC_PERIOD,
                    &new_period as *const u64 as u64,
                ),
            ) != Some(0)
            {
                return Err("PERF_EVENT_IOC_PERIOD rejected an exact disabled update");
            }
            let zero_period = 0u64;
            if call(
                Syscall::Ioctl.raw(),
                a2(
                    period_fd as u64,
                    PERF_EVENT_IOC_PERIOD,
                    &zero_period as *const u64 as u64,
                ),
            ) != Some(EINVAL)
            {
                return Err("PERF_EVENT_IOC_PERIOD accepted a zero period");
            }

            if call(
                Syscall::Ioctl.raw(),
                a2(period_fd as u64, PERF_EVENT_IOC_REFRESH, 2),
            ) != Some(0)
                || crate::perf_event::event_refresh_state_for_test(period_fd)
                    != Some((true, 2, false))
            {
                return Err("PERF_EVENT_IOC_REFRESH did not arm two overflows");
            }
            let task = crate::handlers::current_task_id();
            crate::perf_event::sample_from_irq_for_test(task, 0x1111);
            if crate::perf_event::event_refresh_state_for_test(period_fd) != Some((true, 1, false))
            {
                return Err("first refreshed overflow did not consume one credit");
            }
            crate::perf_event::sample_from_irq_for_test(task, 0x2222);
            if crate::perf_event::event_refresh_state_for_test(period_fd) != Some((false, 0, true))
            {
                return Err("last refreshed overflow did not stop with HUP");
            }
            let _ = call(Syscall::Close.raw(), a0(period_fd as u64));

            let inherited_sampling_attr = PerfEventAttr {
                flags: 1 | PERF_ATTR_FLAG_INHERIT,
                ..sampling_hardware_attr
            };
            let inherited_fd = match call(
                Syscall::PerfEventOpen.raw(),
                a3(
                    &inherited_sampling_attr as *const _ as u64,
                    0,
                    -1i32 as u64,
                    -1i32 as u64,
                ),
            ) {
                Some(fd) if fd >= 0 => fd as u32,
                _ => return Err("inherited sampling event was not admitted"),
            };
            if call(
                Syscall::Ioctl.raw(),
                a2(inherited_fd as u64, PERF_EVENT_IOC_REFRESH, 1),
            ) != Some(EINVAL)
            {
                return Err("PERF_EVENT_IOC_REFRESH accepted an inherited event");
            }
            let _ = call(Syscall::Close.raw(), a0(inherited_fd as u64));
        }

        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_perf_event_open_validation);

#[cfg(target_arch = "aarch64")]
fn smoke_abi_perf_pmuv3_overflow_record() -> TestResult {
    with_setup(|| {
        let attr = PerfEventAttr {
            type_: 0,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 0,
            sample_period_or_freq: 200_000,
            sample_type: 1,
            flags: 1,
            ..PerfEventAttr::default()
        };
        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(
                &attr as *const _ as u64,
                -1i32 as u64,
                narf_lib::percpu::current_cpu() as u64,
                -1i32 as u64,
            ),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("system-wide PMUv3 cycles event was not admitted"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| {
            table.get(fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("PMUv3 fd missing")?;
        let frames = ops
            .mmap_frames(0, 3 * 4096)
            .map_err(|_| "PMUv3 mmap failed")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_REFRESH, 1),
        ) != Some(0)
        {
            return Err("PMUv3 one-overflow refresh failed");
        }
        let live_period = 100_000u64;
        if call(
            Syscall::Ioctl.raw(),
            a2(
                fd as u64,
                PERF_EVENT_IOC_PERIOD,
                &live_period as *const u64 as u64,
            ),
        ) != Some(0)
        {
            return Err("PMUv3 live period update failed");
        }
        // SAFETY: kernel test executes at EL1 and owns the PMUv3 cycle counter.
        if unsafe { narf_arch::aarch64::sysreg::read_pmcntenset_el0() } & (1 << 31) == 0 {
            return Err("PMUv3 cycle enable bit was not set by ioctl enable");
        }
        struct IrqMaskRestore(bool);
        impl Drop for IrqMaskRestore {
            fn drop(&mut self) {
                if self.0 {
                    // SAFETY: restore the kernel-test harness's masked entry
                    // state after the real PPI delivery window.
                    unsafe { narf_arch::disable_interrupts() };
                }
            }
        }
        let restore_mask = !narf_arch::interrupts_enabled();
        if restore_mask {
            // SAFETY: the PMUv3 overflow PPI is configured and armed above;
            // this opens a real IRQ-delivery window for the synchronous
            // kernel-test harness, which normally runs with DAIF.I set.
            unsafe { narf_arch::enable_interrupts() };
        }
        let _irq_mask_restore = IrqMaskRestore(restore_mask);
        for _ in 0..200 {
            for _ in 0..10_000 {
                core::hint::black_box(());
            }
            crate::perf_event::drain_irq_samples();
            // SAFETY: ops owns this mapped metadata frame.
            if unsafe { core::ptr::read_volatile((frames[0] as usize + 1024) as *const u64) } != 0 {
                if crate::perf_event::event_refresh_state_for_test(fd) != Some((false, 0, true)) {
                    return Err("real PMUv3 overflow did not exhaust refresh budget");
                }
                // SAFETY: kernel test executes at EL1 and still owns the counter.
                if unsafe { narf_arch::aarch64::sysreg::read_pmcntenset_el0() } & (1 << 31) != 0 {
                    return Err("refresh exhaustion left PMUv3 cycle counter enabled");
                }
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
                return Ok(());
            }
        }
        if narf_interrupts::fire_count(23) != 0 {
            return Err("PMUv3 PPI dispatched without a drained sample");
        }
        // SAFETY: kernel test executes at EL1 and owns the PMUv3 cycle counter.
        if unsafe { narf_arch::aarch64::sysreg::read_pmcntenset_el0() } & (1 << 31) == 0 {
            return Err("PMUv3 cycle enable bit did not remain set");
        }
        // SAFETY: kernel test executes at EL1 and owns the PMUv3 cycle counter.
        if unsafe { narf_arch::aarch64::sysreg::read_pmintenset_el1() } & (1 << 31) == 0 {
            return Err("PMUv3 interrupt enable bit did not remain set");
        }
        // SAFETY: kernel test executes at EL1 and owns the PMUv3 cycle counter.
        if unsafe { narf_arch::aarch64::sysreg::read_pmovsclr_el0() } & (1 << 31) != 0 {
            return Err("PMUv3 overflow pending without PPI dispatch");
        }
        // SAFETY: kernel test executes at EL1 and owns the PMUv3 cycle counter.
        let raw = unsafe { narf_arch::aarch64::sysreg::read_pmccntr_el0() };
        let preload = 0u64.wrapping_sub(live_period);
        if raw == preload {
            return Err("PMUv3 cycle counter did not advance after enable");
        }
        if raw > preload {
            return Err("PMUv3 cycle counter advanced but did not reach overflow");
        }
        Err("PMUv3 overflow produced no mmap sample")
    })
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("syscall_abi", smoke_abi_perf_pmuv3_overflow_record);

#[cfg(target_arch = "aarch64")]
fn smoke_abi_perf_pmuv3_programmable_overflow_record() -> TestResult {
    with_setup(|| {
        let attr = PerfEventAttr {
            type_: 4,     // PERF_TYPE_RAW
            config: 0x11, // ARM PMUv3 CPU cycles
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            sample_period_or_freq: 100_000,
            sample_type: 1,
            flags: 1,
            ..PerfEventAttr::default()
        };
        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("PMUv3 programmable event was not admitted"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| {
            table.get(fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("PMUv3 programmable fd missing")?;
        let frames = ops
            .mmap_frames(0, 3 * 4096)
            .map_err(|_| "PMUv3 programmable mmap failed")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
        ) != Some(0)
        {
            return Err("PMUv3 programmable enable failed");
        }
        struct IrqMaskRestore(bool);
        impl Drop for IrqMaskRestore {
            fn drop(&mut self) {
                if self.0 {
                    // SAFETY: restore the kernel-test harness's masked entry state.
                    unsafe { narf_arch::disable_interrupts() };
                }
            }
        }
        let restore_mask = !narf_arch::interrupts_enabled();
        if restore_mask {
            // SAFETY: the test has routed and armed the PMU PPI above.
            unsafe { narf_arch::enable_interrupts() };
        }
        let _irq_mask_restore = IrqMaskRestore(restore_mask);
        for _ in 0..200 {
            for _ in 0..10_000 {
                core::hint::black_box(());
            }
            crate::perf_event::drain_irq_samples();
            // SAFETY: ops owns this mapped metadata frame for the test duration.
            if unsafe { core::ptr::read_volatile((frames[0] as usize + 1024) as *const u64) } != 0 {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
                return Ok(());
            }
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Err("PMUv3 programmable overflow produced no mmap sample")
    })
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!(
    "syscall_abi",
    smoke_abi_perf_pmuv3_programmable_overflow_record
);

#[cfg(target_arch = "aarch64")]
fn smoke_abi_perf_pmuv3_frequency_record() -> TestResult {
    with_setup(|| {
        let attr = PerfEventAttr {
            type_: 0,
            size: core::mem::size_of::<PerfEventAttr>() as u32,
            config: 0,
            sample_period_or_freq: 1_000,
            sample_type: 1,
            flags: 1 | (1 << 10),
            ..PerfEventAttr::default()
        };
        let fd = match call(
            Syscall::PerfEventOpen.raw(),
            a3(&attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
        ) {
            Some(fd) if fd >= 0 => fd as u32,
            _ => return Err("PMUv3 frequency event was not admitted"),
        };
        let ops = crate::fd::with_table(FAKE_TASK, |table| {
            table.get(fd).map(|entry| entry.ops.clone())
        })
        .flatten()
        .ok_or("PMUv3 frequency fd missing")?;
        let frames = ops
            .mmap_frames(0, 3 * 4096)
            .map_err(|_| "PMUv3 frequency mmap failed")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(fd as u64, PERF_EVENT_IOC_ENABLE, 0),
        ) != Some(0)
        {
            return Err("PMUv3 frequency enable failed");
        }
        let restore_mask = !narf_arch::interrupts_enabled();
        if restore_mask {
            // SAFETY: the test has routed and armed the PMU PPI above.
            unsafe { narf_arch::enable_interrupts() };
        }
        for _ in 0..400 {
            for _ in 0..10_000 {
                core::hint::black_box(());
            }
            crate::perf_event::drain_irq_samples();
            // SAFETY: ops owns this mapped metadata frame for the test duration.
            if unsafe { core::ptr::read_volatile((frames[0] as usize + 1024) as *const u64) } >= 32
            {
                if restore_mask {
                    // SAFETY: restore the kernel-test harness's masked entry state.
                    unsafe { narf_arch::disable_interrupts() };
                }
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
                return Ok(());
            }
        }
        if restore_mask {
            // SAFETY: restore the kernel-test harness's masked entry state.
            unsafe { narf_arch::disable_interrupts() };
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Err("PMUv3 frequency overflow produced no mmap sample")
    })
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("syscall_abi", smoke_abi_perf_pmuv3_frequency_record);
