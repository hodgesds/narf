//! `time` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

fn smoke_userspace_clock_gettime_writes_timespec() -> TestResult {
    // ClockGetTime: writes monotonic { tv_sec, tv_nsec } to the
    // user buffer. We don't have a true user AS active here — the
    // handler writes through whatever vaddr it gets — so we point
    // arg1 at a kernel-stack-resident `[i64; 2]` and read back.
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xC10C);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }
    let mut ts: [i64; 2] = [-1, -1];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: ts.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);

    let ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK);
    __test_clear_global();
    if !ok {
        return TestResult::Fail("ClockGetTime did not return Ok");
    }
    if ts[0] < 0 || ts[1] < 0 {
        return TestResult::Fail("ClockGetTime did not write timespec");
    }
    if ts[1] >= 1_000_000_000 {
        return TestResult::Fail("tv_nsec out of range");
    }
    TestResult::Pass
}
#[cfg(not(feature = "user-mode-e2e"))]
kernel_test_in!("userspace", smoke_userspace_clock_gettime_writes_timespec);

fn smoke_userspace_sleep_advances_time() -> TestResult {
    // Drive sys_sleep with 50 ms; assert monotonic_ns advanced by
    // at least that amount. The handler spin-waits in trap context
    // (see `sys_sleep`'s docstring) so we measure a real wall-time
    // advance, not a scheduler-driven sleep.
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    const TARGET_NS: u64 = 50_000_000; // 50 ms

    let before = narf_scheduler::narf_time::monotonic_ns();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: TARGET_NS,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Sleep.raw(), &mut ctx);
    let after = narf_scheduler::narf_time::monotonic_ns();

    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("Sleep did not Ok");
    }
    let elapsed = after.saturating_sub(before);
    if elapsed < TARGET_NS {
        return TestResult::Fail("Sleep returned before deadline");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_sleep_advances_time);

fn smoke_userspace_clock_gettime_distinguishes_clocks() -> TestResult {
    // ClockGetTime now honours arg0:
    //   0 = CLOCK_REALTIME  (wall via time::now_wall)
    //   1 = CLOCK_MONOTONIC (monotonic_ns)
    //   anything else → InvalidOp.
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut buf = [0i64; 2];
    let buf_addr = buf.as_mut_ptr() as u64;

    // CLOCK_MONOTONIC: read twice, expect non-decreasing.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let m1 = (buf[0], buf[1]);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("monotonic clock_gettime did not return OK");
    }

    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let m2 = (buf[0], buf[1]);
    if (m2.0, m2.1) < (m1.0, m1.1) {
        return TestResult::Fail("monotonic clock went backwards");
    }

    // CLOCK_REALTIME: must succeed and produce a non-negative time.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK) {
        return TestResult::Fail("realtime clock_gettime did not return OK");
    }
    if buf[0] < 0 || buf[1] < 0 {
        return TestResult::Fail("realtime clock surfaced a negative timespec");
    }

    // Bogus clock id rejected with InvalidOp status.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 99,
            arg1: buf_addr,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let bogus_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::INVALID_OP,
    );
    if !bogus_rejected {
        return TestResult::Fail("unknown clock id was not rejected");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_gettime_distinguishes_clocks
);

fn smoke_userspace_times_writes_tms_struct() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // The kernel-test harness runs every test as one shared task, so prior
    // tests' kernel_syscall_entry brackets accumulated in-syscall CPU time
    // against it. Clear it so this test measures a FRESH task's stime (== 0)
    // rather than the suite's cumulative kernel time — which under slow TCG
    // execution exceeds one tick and flaps the stime==0 assertion below.
    crate::handlers::__test_reset_kernel_time();

    let mut buf = [0i64; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Times.raw(), &mut ctx);
    let wall = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as i64,
        _ => return TestResult::Fail("times did not return OK"),
    };
    // The RETURN value is wall-clock uptime in ticks. The tms FIELDS carry
    // per-task CPU time: utime / cutime are the task's own + reaped-children
    // CPU ticks (>= 0; not the wall return — that decoupling is the whole
    // point of the accounting fix), and we never split out system time so
    // stime / cstime are always zero.
    if buf[1] != 0 || buf[3] != 0 {
        return TestResult::Fail("times: stime/cstime must be zero (no user/sys split)");
    }
    if buf[0] < 0 || buf[2] < 0 {
        return TestResult::Fail("times: utime/cutime must be non-negative CPU ticks");
    }
    if wall < 0 {
        return TestResult::Fail("times surfaced a negative wall-clock");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_times_writes_tms_struct);

fn smoke_userspace_clock_settime_pushes_wall_offset() -> TestResult {
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Reset wall offset to a known baseline: target = 1.7 billion
    // seconds (≈ Nov 2023).
    let target_sec: i64 = 1_700_000_000;
    let target_nsec: i64 = 0;
    let ts: [i64; 2] = [target_sec, target_nsec];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0, // CLOCK_REALTIME
            arg1: ts.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockSetTime.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("clock_settime did not return OK");
    }

    // Read back via clock_gettime(REALTIME). Allow a 2-second
    // window for monotonic-clock drift between the set and the get.
    let mut out = [0i64; 2];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: out.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx);
    let got_sec = out[0];
    if got_sec < target_sec || got_sec > target_sec + 2 {
        return TestResult::Fail("clock_gettime did not reflect the new wall offset");
    }

    // CLOCK_MONOTONIC (1) is not settable — expect -1.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: ts.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockSetTime.raw(), &mut ctx);
    let mono_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !mono_rejected {
        return TestResult::Fail("clock_settime(MONOTONIC) was not rejected");
    }

    // Reset wall offset back to 0 so subsequent tests see normal
    // behaviour. (Re-setting REALTIME to (current monotonic) leaves
    // offset = 0.)
    let cur_mono: u64 = narf_scheduler::narf_time::monotonic_ns();
    let cur_sec = (cur_mono / 1_000_000_000) as i64;
    let cur_nsec = (cur_mono % 1_000_000_000) as i64;
    let reset_ts: [i64; 2] = [cur_sec, cur_nsec];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: reset_ts.as_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockSetTime.raw(), &mut ctx);

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_settime_pushes_wall_offset
);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_clock_gettime_monotonic_raw_and_boottime() -> TestResult {
    // CLOCK_MONOTONIC_RAW(4) and CLOCK_BOOTTIME(7) both return sane
    // timespec values and two consecutive readings are non-decreasing.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xE014);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    for clkid in [4u64, 7u64] {
        let mut ts1 = [0u8; 16];
        let mut ctx1 = FakeCtx {
            args: SyscallArgs {
                arg0: clkid,
                arg1: ts1.as_mut_ptr() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx1);
        if !matches!(ctx1.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
            __test_clear_global();
            return TestResult::Fail("clock_gettime failed for RAW/BOOTTIME");
        }
        let sec1 = i64::from_ne_bytes(ts1[..8].try_into().unwrap());
        let nsec1 = i64::from_ne_bytes(ts1[8..].try_into().unwrap());
        if sec1 < 0 {
            __test_clear_global();
            return TestResult::Fail("tv_sec < 0 on first read");
        }
        if !(0..1_000_000_000).contains(&nsec1) {
            __test_clear_global();
            return TestResult::Fail("tv_nsec out of range on first read");
        }

        let mut ts2 = [0u8; 16];
        let mut ctx2 = FakeCtx {
            args: SyscallArgs {
                arg0: clkid,
                arg1: ts2.as_mut_ptr() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx2);
        if !matches!(ctx2.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
            __test_clear_global();
            return TestResult::Fail("clock_gettime second read failed");
        }
        let sec2 = i64::from_ne_bytes(ts2[..8].try_into().unwrap());
        let nsec2 = i64::from_ne_bytes(ts2[8..].try_into().unwrap());
        let ns1 = (sec1 as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec1 as u64);
        let ns2 = (sec2 as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(nsec2 as u64);
        if ns2 < ns1 {
            __test_clear_global();
            return TestResult::Fail("clock_gettime not monotonically non-decreasing");
        }
    }

    __test_clear_global();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_gettime_monotonic_raw_and_boottime
);
