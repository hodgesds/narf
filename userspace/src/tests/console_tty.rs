//! `console_tty` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

// ── ConsoleFile stdin smoke tests (Wave 37) ───────────────────────────────────
//
// These tests drive ConsoleFile::read (fd 0 / stdin) through the BYTE_RING
// to verify the wired serial RX path end-to-end at the FileOps level.
//
// All four tests use the syscall path (sys_read via kernel_syscall_entry) so
// they exercise the same code path as the real shell.

fn smoke_console_read_empty_buf_returns_zero() -> TestResult {
    // ConsoleFile::read with an empty (zero-length) user buffer must
    // return Ok(0) immediately — the fast-path guard before the await.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0001);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Open stdin (fd 0) is pre-populated by fd::with_table with ConsoleFile.
    // We need fd 0 to exist; force-create the table entry.
    let _dummy = fd::with_table(task, |_t| ());

    // Dummy output buffer — we ask for 0 bytes.
    let mut buf = [0u8; 4];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0, // fd 0 = stdin
            arg1: buf.as_mut_ptr() as u64,
            arg2: 0, // zero-length read
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("zero-len read did not return Ok(0)")
        }
    }
}
kernel_test_in!("userspace", smoke_console_read_empty_buf_returns_zero);

fn smoke_console_read_one_byte_in_ring() -> TestResult {
    // ConsoleFile::read with one byte pre-loaded into the BYTE_RING must
    // return Ok(1) and the exact byte value.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0002);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // The console defaults to cooked (line-buffered) mode now; this test
    // asserts raw byte-at-a-time surfacing, so put the shared discipline
    // in raw mode (ICANON/ECHO/ISIG off) and clear any leftover buffers.
    narf_filesystem::console_tty::__test_reset_raw();

    // Pre-load one byte ('A' = 0x41) into the ASCII ring.
    narf_input::push_global(narf_input::InputEvent::AsciiByte(b'A'));

    let _ = fd::with_table(task, |_t| ());

    let mut buf = [0u8; 4];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 1 => {
            if buf[0] == b'A' {
                TestResult::Pass
            } else {
                TestResult::Fail("byte value mismatch — expected 'A'")
            }
        }
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            TestResult::Fail("read returned 0 bytes — byte in ring was not consumed")
        }
        _ => TestResult::Fail("sys_read returned unexpected status"),
    }
}
kernel_test_in!("userspace", smoke_console_read_one_byte_in_ring);

fn smoke_console_read_drains_burst() -> TestResult {
    // ConsoleFile::read with 3 bytes pre-loaded must return Ok(3) and
    // deliver all three bytes in order (paste-burst drain path).
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0003);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Raw mode so the 3-byte burst surfaces immediately (the shared
    // console discipline defaults to cooked/line-buffered now).
    narf_filesystem::console_tty::__test_reset_raw();

    // Pre-load "hi\n" (3 bytes) into the ASCII ring.
    for &b in b"hi\n" {
        narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
    }

    let _ = fd::with_table(task, |_t| ());

    let mut buf = [0u8; 8];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 3 => {
            if &buf[..3] == b"hi\n" {
                TestResult::Pass
            } else {
                TestResult::Fail("3-byte burst: payload mismatch")
            }
        }
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            TestResult::Fail("3-byte burst: read returned 0 — bytes not consumed")
        }
        Some(r) if r.status == SyscallReturn::OK => {
            TestResult::Fail("3-byte burst: wrong count returned")
        }
        _ => TestResult::Fail("3-byte burst: sys_read bad status"),
    }
}
kernel_test_in!("userspace", smoke_console_read_drains_burst);

fn smoke_console_read_empty_ring_returns_zero() -> TestResult {
    // ConsoleFile::read with an empty ring and a non-zero buffer must return
    // Ok(0) — no bytes available yet. The shell's usleep-retry loop handles
    // the backoff; returning 0 is the non-blocking "try again later" signal.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_0004);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Ring is empty — no push.
    let _ = fd::with_table(task, |_t| ());

    let mut buf = [0u8; 4];
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    fd::__test_reset();
    __test_clear_global();

    // Either Ok(0) — poll_blocking timed out → handler unwrap_or(0) —
    // or a deliberate Ok(0) from the future. Both signal "no data now".
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => TestResult::Pass,
        _ => TestResult::Fail("empty ring: expected Ok(0) from sys_read"),
    }
}
kernel_test_in!("userspace", smoke_console_read_empty_ring_returns_zero);

fn smoke_console_ctrlc_signals_foreground_pgrp() -> TestResult {
    // ^C on the console (ISIG cooked mode) must deliver SIGINT to the
    // ENTIRE foreground process group — proper job control — not just the
    // single reading task. Drive the unified line discipline end-to-end:
    // install the console signal hook, mark a leader task as the
    // foreground console reader, put a second task in its group, push a
    // ^C byte, then read the console (which pumps the discipline → hook →
    // deliver_signal_to_pgrp). Assert BOTH tasks have SIGINT pending and
    // the ^C was consumed (did not surface through read).
    use crate::handlers::{
        __test_pgid_reset, __test_reset_task_id_lookup, __test_set_pgid, __test_signal_reset,
        maybe_deliver_signal_for_input, note_console_reader, pgid_init, signal_init,
        signal_pending_of,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_00C1);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let leader = TASK_ID.load(Ordering::Relaxed);
    let member: u64 = 0xC0_00C2;

    __test_signal_reset();
    signal_init();
    __test_pgid_reset();
    pgid_init();
    crate::install_task_id_lookup(task_lookup);
    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    narf_filesystem::console_tty::__test_reset_cooked();
    // The kernel-test boot doesn't run cross_crate_init, so install the
    // console signal hook explicitly.
    narf_filesystem::console_tty::install_signal_hook(maybe_deliver_signal_for_input);

    // `leader` is its own group (pgid defaults to pid); put `member` in it.
    __test_set_pgid(member, leader);
    // `leader` is the foreground console reader.
    note_console_reader(leader);

    // Push ^C (0x03) and pump the discipline by reading.
    narf_input::push_global(narf_input::InputEvent::AsciiByte(0x03));
    let mut buf = [0u8; 8];
    let n = narf_filesystem::console_tty::read_into(&mut buf);

    let lead_pending = signal_pending_of(leader);
    let mem_pending = signal_pending_of(member);

    // Clean up shared globals.
    __test_signal_reset();
    __test_pgid_reset();
    narf_filesystem::console_tty::__test_reset_cooked();
    __test_reset_task_id_lookup();

    let sigint = crate::handlers::sig_bit(2); // SIGINT = 2
    if n != 0 {
        return TestResult::Fail("^C should be consumed as a signal, not returned by read");
    }
    if lead_pending & sigint == 0 {
        return TestResult::Fail("foreground leader did not get SIGINT");
    }
    if mem_pending & sigint == 0 {
        return TestResult::Fail("foreground group member did not get SIGINT");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_console_ctrlc_signals_foreground_pgrp);

#[cfg(feature = "linux-compat")]
fn smoke_tty_background_read_raises_sigttin() -> TestResult {
    // A process in a BACKGROUND process group that reads its controlling
    // terminal must be sent SIGTTIN (default action: stop) and the read
    // interrupted with -EINTR. Install a synthetic controlling-tty fd whose
    // foreground pgrp differs from the caller's, drive sys_read through it,
    // and assert SIGTTIN is pending + the syscall returned -EINTR.
    use crate::fd::{self, FdEntry};
    use crate::handlers::{
        __test_pgid_reset, __test_reset_task_id_lookup, __test_signal_reset, ctty_init, pgid_init,
        signal_init, signal_pending_of,
    };
    use crate::{
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Mode, Stat, TTY_ID_CONSOLE};

    struct FakeTty {
        fg: u64,
    }
    impl FileOps for FakeTty {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
        fn tty_id(&self) -> Option<u32> {
            Some(TTY_ID_CONSOLE)
        }
        fn tty_fg_pgrp(&self) -> Option<u64> {
            Some(self.fg)
        }
    }

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_00D1);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    __test_signal_reset();
    signal_init();
    __test_pgid_reset();
    pgid_init();
    ctty_init();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Foreground pgrp 0x7777 ≠ caller's pgid (defaults to its own tid), so
    // the caller is a background process on this tty. tty_id == the console
    // sentinel and task_ctty defaults to the console, so it IS the ctty.
    fd::with_table(task, |tbl| {
        tbl.set(
            5,
            FdEntry {
                ops: Arc::new(FakeTty { fg: 0x7777 }),
                offset: 0,
                flags: 0,
                status_flags: 0,
            },
        );
    });

    let mut buf = [0u8; 8];
    struct Ctx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for Ctx {
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
        fn set_rip(&mut self, _r: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }
    let mut ctx = Ctx {
        args: SyscallArgs {
            arg0: 5,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);

    let pending = signal_pending_of(task);
    let ret = ctx.ret.map(|r| r.value as i64);

    fd::__test_reset();
    __test_signal_reset();
    __test_pgid_reset();
    __test_reset_task_id_lookup();

    let sigttin = crate::handlers::sig_bit(21); // SIGTTIN
    if pending & sigttin == 0 {
        return TestResult::Fail("background console read did not raise SIGTTIN");
    }
    if ret != Some(-4) {
        return TestResult::Fail("background read should return -EINTR");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_tty_background_read_raises_sigttin);

// ── Wave 39: end-to-end `echo hello world` golden path ────────────────────
//
// The Wave-37/38/39 chain (serial RX → BYTE_RING → ConsoleFile::read →
// shell built-in echo → ConsoleFile::write → console::write_str → klog)
// is the project's end-to-end target. Each link has its own unit-level
// smoke; this one drives the whole chain in one shot so a regression
// anywhere along the way is caught by a single failing test.
//
// Steps:
//   1. Pre-load "echo hello world\n" into the BYTE_RING (simulates QEMU
//      `-serial stdio` typing).
//   2. sys_read on fd 0 — must drain the full line into a buffer.
//   3. Parse the line shell-style: split on first space, take "hello world"
//      as `rest`. Mirror userspace/shell/src/main.rs:1560-1564's built-in
//      echo (write rest, write NEWLINE).
//   4. sys_write each segment on fd 1 — routes through ConsoleFile::write
//      → narf_console::Writer → write_str → klog::record.
//   5. klog::snapshot must contain "hello world\n" as a contiguous run.
//
// We can't observe the real UART backend in a kernel-test (no QEMU stdio
// hooked to the SUT's COM1 in test mode), but klog is fed unconditionally
// upstream of the backend, so it's a faithful proxy for "the bytes left
// the userspace task and reached the platform console layer."

#[cfg(target_arch = "x86_64")]
fn smoke_echo_hello_world_end_to_end() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC0_E2E0);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    // Earlier console tests deliberately select raw mode. The shared line
    // discipline outlives their fd tables, so make this cooked-line test
    // independent of registration/execution order.
    narf_filesystem::console_tty::__test_reset_cooked();
    fd::__test_reset();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Step 1: stuff "echo hello world\n" into the global ASCII byte ring,
    // exactly as the IRQ-4 serial RX handler would on real bytes typed
    // into `qemu -serial stdio`.
    const LINE: &[u8] = b"echo hello world\n";
    for &b in LINE {
        narf_input::push_global(narf_input::InputEvent::AsciiByte(b));
    }

    // Force the per-task fd table to materialise with fd 0/1/2 wired
    // to ConsoleFile.
    let _ = fd::with_table(task, |_t| ());

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

    // Step 2: sys_read on fd 0. Buffer is sized for the full line plus a
    // generous tail.
    let mut buf = [0u8; 64];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    let n_read = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("sys_read on fd 0: bad status");
        }
    };
    if n_read != LINE.len() || &buf[..n_read] != LINE {
        fd::__test_reset();
        __test_clear_global();
        return TestResult::Fail("sys_read drained wrong payload");
    }

    // Step 3: shell-style parse. Find the first space; "echo" is the
    // command, the rest is the argv tail. Strip the trailing newline so
    // the echo built-in's write_all(rest) matches what we expect on the
    // wire.
    let line_no_nl = &buf[..n_read - 1]; // drop '\n'
    let space_at = match line_no_nl.iter().position(|&b| b == b' ') {
        Some(i) => i,
        None => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("parse: no space in line");
        }
    };
    let cmd = &line_no_nl[..space_at];
    let rest = &line_no_nl[space_at + 1..];
    if cmd != b"echo" {
        fd::__test_reset();
        __test_clear_global();
        return TestResult::Fail("parse: cmd != echo");
    }

    // Snapshot klog *before* we write so we can find the new region after.
    let pre_len = narf_console::klog::snapshot().len();

    // Step 4: sys_write on fd 1 — the body, then a newline. Two calls
    // mirror the shell's `write_all(fd, rest); write_all(fd, NEWLINE);`.
    let mut ctx_w1 = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: rest.as_ptr() as u64,
            arg2: rest.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx_w1);
    match ctx_w1.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == rest.len() as u64 => {}
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("sys_write(rest) failed");
        }
    }

    let nl: &[u8] = b"\n";
    let mut ctx_w2 = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: nl.as_ptr() as u64,
            arg2: 1,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx_w2);
    match ctx_w2.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 1 => {}
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("sys_write(NL) failed");
        }
    }

    // Step 5: pull a fresh klog snapshot and look for "hello world\n"
    // anywhere in the post-write tail. The pre/post split is just a
    // performance hint — if the ring has wrapped, search the whole
    // window.
    let post = narf_console::klog::snapshot();
    let needle: &[u8] = b"hello world\n";
    let tail_start = pre_len.min(post.len().saturating_sub(needle.len()));
    let haystack = &post[tail_start..];
    let found = haystack.windows(needle.len()).any(|w| w == needle);

    fd::__test_reset();
    __test_clear_global();

    if found {
        TestResult::Pass
    } else {
        TestResult::Fail("klog did not contain \"hello world\\n\" after sys_write on fd 1")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_echo_hello_world_end_to_end);

// ── Wave-51: terminal ioctls on the console fd ─────────────────────
//
// Real userspace (ls, bash, vi, less) probes TIOCGWINSZ / FIONREAD /
// TIOCGPGRP to decide whether stdout is a tty and what dimensions
// to draw to. Wave-51 wires these against ConsoleFile so the probes
// stop returning ENOTTY. Each smoke runs the syscall path end-to-end
// via sys_ioctl.

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_tiocgwinsz_default_80x24() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1001);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    // Kernel-stack buffer for the winsize copy-out. The ioctl arg
    // pointer goes straight into the FileOps impl; copy_to_user's
    // pointer check passes for canonical addresses regardless of
    // half.
    let mut ws = fd::Winsize::default();
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1, // stdout
            arg1: fd::TIOCGWINSZ as u64,
            arg2: &mut ws as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            if ws.ws_row == 24 && ws.ws_col == 80 {
                TestResult::Pass
            } else {
                TestResult::Fail("TIOCGWINSZ default not 80x24")
            }
        }
        _ => TestResult::Fail("TIOCGWINSZ did not return Ok(0)"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_tiocgwinsz_default_80x24);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_tiocswinsz_round_trip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1002);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    let set = fd::Winsize {
        ws_row: 50,
        ws_col: 132,
        ws_xpixel: 0,
        ws_ypixel: 0,
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
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: fd::TIOCSWINSZ as u64,
            arg2: &set as *const _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    let set_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    let mut got = fd::Winsize::default();
    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: fd::TIOCGWINSZ as u64,
            arg2: &mut got as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx2);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    if !set_ok {
        return TestResult::Fail("TIOCSWINSZ did not return Ok(0)");
    }
    if got.ws_row == 50 && got.ws_col == 132 {
        TestResult::Pass
    } else {
        TestResult::Fail("TIOCSWINSZ value did not round-trip through TIOCGWINSZ")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_tiocswinsz_round_trip);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_fionread_empty_ring_returns_zero() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1003);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    narf_input::init_global_ring(256);
    narf_input::__reset_global_ring_for_test();
    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    let mut n: i32 = 0xAAAA;
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: fd::FIONREAD as u64,
            arg2: &mut n as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
            if n == 0 {
                TestResult::Pass
            } else {
                TestResult::Fail("FIONREAD on empty ring did not report 0")
            }
        }
        _ => TestResult::Fail("FIONREAD did not return Ok(0)"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_console_ioctl_fionread_empty_ring_returns_zero
);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_tiocspgrp_round_trip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1004);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

    // Set fg pgrp = 4242
    let pgid_in: i32 = 4242;
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
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: fd::TIOCSPGRP as u64,
            arg2: &pgid_in as *const _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    let set_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    let mut pgid_out: i32 = -1;
    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: fd::TIOCGPGRP as u64,
            arg2: &mut pgid_out as *mut _ as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx2);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    if !set_ok {
        return TestResult::Fail("TIOCSPGRP did not return Ok(0)");
    }
    if pgid_out == 4242 {
        TestResult::Pass
    } else {
        TestResult::Fail("TIOCSPGRP value did not round-trip through TIOCGPGRP")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_tiocspgrp_round_trip);

// The boot console is a SINGLETON: every `ConsoleFile` (fd 0/1/2) and
// `/dev/console` share one foreground process group, which lives in
// `console_tty`. So a tcsetpgrp on one is visible on the others — that is
// what lets getty's tcsetpgrp(fd 0) take effect for a shell reading
// /dev/console. (Per-PTY isolation is provided separately, by each Pty's
// own `fg_pgrp` — see the devfs_pty tests.)
#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_fg_pgrp_is_shared_singleton() -> TestResult {
    use crate::fd::{ConsoleFile, TIOCGPGRP, TIOCSPGRP};
    use narf_filesystem::FileOps;

    // Clear the singleton fg_pgrp + any leaked task-id lookup so the
    // TIOCGPGRP auto-install path sees a clean unset console.
    narf_filesystem::console_tty::__test_reset_cooked();
    crate::handlers::__test_reset_task_id_lookup();

    let tty_a = ConsoleFile::new();
    let tty_b = ConsoleFile::new();

    // tcsetpgrp on A is immediately visible through B — one console.
    let pgid: i32 = 111;
    if tty_a.ioctl(TIOCSPGRP, &pgid as *const _ as usize).is_err() {
        return TestResult::Fail("TIOCSPGRP on tty_a failed");
    }
    let mut got_b: i32 = -1;
    if tty_b
        .ioctl(TIOCGPGRP, &mut got_b as *mut _ as usize)
        .is_err()
    {
        return TestResult::Fail("TIOCGPGRP on tty_b failed");
    }
    if got_b != 111 {
        narf_filesystem::console_tty::__test_reset_cooked();
        return TestResult::Fail("console fg_pgrp not shared across ConsoleFile instances");
    }

    // And a write through B is visible through A — fully symmetric.
    let pgid2: i32 = 222;
    if tty_b.ioctl(TIOCSPGRP, &pgid2 as *const _ as usize).is_err() {
        return TestResult::Fail("TIOCSPGRP on tty_b failed");
    }
    let mut got_a: i32 = -1;
    if tty_a
        .ioctl(TIOCGPGRP, &mut got_a as *mut _ as usize)
        .is_err()
    {
        return TestResult::Fail("TIOCGPGRP on tty_a failed");
    }
    narf_filesystem::console_tty::__test_reset_cooked();
    if got_a != 222 {
        return TestResult::Fail("console fg_pgrp not shared (B→A)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_fg_pgrp_is_shared_singleton);

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_unknown_cmd_returns_enotty() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1005);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

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
    let mut dummy = [0u8; 8];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 0xDEAD_BEEF,
            arg2: dummy.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    // ENOTTY = 25, returned as the negated value through SyscallReturn::ok.
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && (r.value as i64) == -25 => TestResult::Pass,
        _ => TestResult::Fail("unknown ioctl cmd did not return -ENOTTY"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_unknown_cmd_returns_enotty);

// KDSIGACCEPT (0x4B4E) — systemd-PID-1 arms the console kbrequest signal
// during early init. NARF accepts it as a no-op success so the boot log
// doesn't carry "Failed to enable kbrequest handling".
#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn smoke_console_ioctl_kdsigaccept_ok() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xC5_1006);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
    }
    let task = TASK_ID.load(Ordering::Relaxed);

    fd::__test_reset();
    fd::__test_reset_tty();
    fd::init();
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    let _ = fd::with_table(task, |_t| ());

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
    // arg1 = KDSIGACCEPT; arg2 carries the requested signal number (ignored).
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0, // /dev/console (fd 0)
            arg1: fd::KDSIGACCEPT as u64,
            arg2: 10, // SIGUSR1 — accepted and ignored
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
    fd::__test_reset();
    fd::__test_reset_tty();
    __test_clear_global();

    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => TestResult::Pass,
        _ => TestResult::Fail("KDSIGACCEPT ioctl did not return success"),
    }
}
#[cfg(target_arch = "x86_64")]
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_console_ioctl_kdsigaccept_ok);

// ── Wave-76: controlling-tty hook ──────────────────────────────────
//
// PtySlave::ioctl(TIOCSCTTY) calls back into the userspace crate via
// the function-pointer hook installed in `boot_init`. This smoke
// pokes the hook directly (`set_controlling_tty(idx)`) and reads
// the per-task table via `ctty_for(task)`. setsid() detaches the ctty
// (DETACHED marker), which `task_ctty` resolves to "no controlling tty".

#[cfg(feature = "linux-compat")]
fn smoke_userspace_ctty_hook_roundtrip_and_setsid_clears() -> TestResult {
    use crate::handlers::{
        __test_ctty_reset, __test_pgid_reset, __test_sid_reset, ctty_for, current_task_id,
        set_controlling_tty, task_ctty,
    };
    use crate::{
        init_per_task_state, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    __test_pgid_reset();
    __test_sid_reset();
    __test_ctty_reset();
    init_per_task_state();

    let task = current_task_id();

    // The Wave-76 hook records the PTY index against the current task.
    set_controlling_tty(7);
    if ctty_for(task) != Some(7) {
        __test_clear_global();
        return TestResult::Fail("ctty_for did not see TIOCSCTTY hook write");
    }

    // setsid() must drop the controlling tty per POSIX.
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
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Setsid.raw(), &mut ctx);

    // setsid marks the slot DETACHED (a distinct state from the boot-console
    // default), which `task_ctty` resolves to "no controlling terminal".
    if task_ctty(task).is_some() {
        __test_clear_global();
        return TestResult::Fail("setsid did not clear controlling_tty");
    }
    __test_clear_global();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_ctty_hook_roundtrip_and_setsid_clears
);

// getty/login controlling-terminal acquisition over the *console*: after
// setsid() detaches, `set_controlling_tty_console` (the /dev/console
// TIOCSCTTY hook) re-acquires the boot console so `task_ctty` resolves to
// CONSOLE and TIOCGSID (`current_task_sid_user`) reports the new session.
// `detach_controlling_tty` (TIOCNOTTY) then drops it again. This is the
// exact sequence agetty runs: setsid → open(/dev/tty1) → TIOCSCTTY.
#[cfg(feature = "linux-compat")]
fn smoke_userspace_console_ctty_acquire_release_and_sid() -> TestResult {
    use crate::handlers::{
        __test_ctty_reset, __test_pgid_reset, __test_sid_reset, current_task_id,
        current_task_sid_user, detach_controlling_tty, set_controlling_tty_console, task_ctty,
    };
    use crate::{
        init_per_task_state, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    __test_pgid_reset();
    __test_sid_reset();
    __test_ctty_reset();
    init_per_task_state();

    let task = current_task_id();

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

    // setsid() starts a new session and detaches any ctty.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Setsid.raw(), &mut ctx);
    if task_ctty(task).is_some() {
        __test_clear_global();
        return TestResult::Fail("setsid did not detach the ctty");
    }

    // open(/dev/tty1) + ioctl(TIOCSCTTY) → the console-hook body.
    set_controlling_tty_console(task);
    if task_ctty(task) != Some(crate::handlers::CTTY_CONSOLE) {
        __test_clear_global();
        return TestResult::Fail("TIOCSCTTY did not make the console the ctty");
    }

    // tcgetsid(3) via TIOCGSID reports this session's id (== leader pid).
    if current_task_sid_user() != crate::handlers::pgid_to_user(task) {
        __test_clear_global();
        return TestResult::Fail("TIOCGSID did not report the setsid session");
    }

    // TIOCNOTTY drops it again.
    detach_controlling_tty(task);
    if task_ctty(task).is_some() {
        __test_clear_global();
        return TestResult::Fail("TIOCNOTTY did not detach the ctty");
    }

    // vhangup(2) is registered and returns 0 (safe no-op on the console).
    let mut vctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Vhangup.raw(), &mut vctx);
    match vctx.ret {
        Some(r) if r.value == 0 => {}
        _ => {
            __test_clear_global();
            return TestResult::Fail("vhangup did not return 0");
        }
    }

    __test_clear_global();
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_console_ctty_acquire_release_and_sid
);
