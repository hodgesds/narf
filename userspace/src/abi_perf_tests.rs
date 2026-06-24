//! Linux syscall ABI conformance — perf_event_open group.
//!
//! Covers perf_event_open parameter validation, CPU checking,
//! task checks, and configuration validation.

#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;
use crate::perf_event::perf_event_attr;

fn smoke_abi_perf_event_open_validation() -> TestResult {
    with_setup(|| {
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

        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_perf_event_open_validation);
