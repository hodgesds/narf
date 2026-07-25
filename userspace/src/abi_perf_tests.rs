//! Linux syscall ABI conformance — perf_event_open group.
//!
//! Covers perf_event_open parameter validation, CPU checking,
//! task checks, and configuration validation.

#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;
use narf_linux_perf_uapi::PerfEventAttr;

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

        let ignored_attr_flag = PerfEventAttr {
            flags: 1 << 5, // exclude_user
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
            flags: 1, // disabled
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
        crate::perf_event::sample_from_irq_for_test(
            crate::handlers::current_task_id(),
            0x1234_5678,
        );
        // SAFETY: sample_ops owns all three identity-mapped frames here.
        let data_head =
            unsafe { core::ptr::read_volatile((sample_frames[0] as usize + 1024) as *const u64) };
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
        let _ = call(Syscall::Close.raw(), a0(sample_fd as u64));

        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_perf_event_open_validation);
