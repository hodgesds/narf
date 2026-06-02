//! Wave-32 shell end-to-end smokes.
//!
//! Covers the two distinct layers of "shell works":
//!
//! **Layer A — Parser unit tests (smokes 1-8).**
//! The shell binary (`userspace/shell/src/main.rs`) has no library
//! surface (`#![no_std] #![no_main]`), so its private helpers cannot
//! be linked here. Instead we carry inline re-implementations of the
//! same pure functions (`split_first`, `skip_ws`, `trim_arg`,
//! `classify`, `line_contains`) and verify the *semantics* they
//! produce. Both the shell and this file implement the identical
//! short logic — trivially audited side-by-side.
//!
//! **Layer B — Syscall-layer smokes (smokes 9-15).**
//! Drives the kernel syscall handlers (`sys_pipe`, `sys_dup2`,
//! `sys_write`, `sys_read`, `sys_fork`, `sys_wait4`) directly via
//! `kernel_syscall_entry` — the same technique used by Wave 30's
//! `process_e2e_tests.rs`. This validates the plumbing the shell
//! *would* call for "echo hello" (fork+wait4), "ls | grep foo"
//! (pipe+dup2), and "echo hi > file" (open+dup2).
//!
//! **Not-yet-implemented by the shell binary (deferred smokes):**
//! - Background `&`: shell has no job-control / SIGCHLD handler.
//! - Sequence `;`: shell has no sequence separator in its parser.
//! - `&&` / `||` short-circuit: not parsed by dispatch_line.
//! - Fork+exec of external binaries: shell dispatch loop only has
//!   built-ins; wiring fork+exec is a follow-up.
//! - Full pipe + redirect parse: `|` and `>` land in `rest`
//!   unparsed (documented in smokes 4 and 5 below).
//!
//! Linux references (for the syscall smokes):
//!   - `fs/pipe.c::do_pipe_flags`       (pipe semantics)
//!   - `fs/fcntl.c::sys_dup2`           (dup2 semantics)
//!   - `kernel/fork.c::copy_process`    (fork + fd-table inheritance)
//!   - `kernel/exit.c::do_wait`         (wait4 / zombie reap)

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::AddressSpace;

use crate::syscall::{
    kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
use crate::{
    fd, install_address_space_lookup, install_core_syscalls, install_global,
    install_task_id_lookup,
};
use narf_lib::sync::IrqSafeSpinLock;

// ── Shared infrastructure ─────────────────────────────────────────────

/// Synthetic `TrapContext` used where the test doesn't need signal
/// delivery or `returning_to_user`. Exactly the same shape as the
/// one in `tests.rs` and `process_e2e_tests.rs`.
struct StubCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}

impl TrapContext for StubCtx {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.ret = Some(r);
    }
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
}

/// Shared AS used by smokes that call `sys_fork`.
#[cfg(target_arch = "x86_64")]
static SHELL_PARENT_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
    IrqSafeSpinLock::new(None);

#[cfg(target_arch = "x86_64")]
fn lookup_shell_parent_as() -> Option<Arc<AddressSpace>> {
    SHELL_PARENT_AS.lock().clone()
}

/// Task-id shared between all smokes.  Written before each smoke that
/// needs per-task kernel state; read by the `install_task_id_lookup`
/// shim.
static SHELL_TASK: AtomicU64 = AtomicU64::new(0x5001);

fn shell_task_id() -> u64 {
    SHELL_TASK.load(Ordering::Relaxed)
}

/// Reset all per-task kernel state installed for the fork smoke.
#[cfg(target_arch = "x86_64")]
fn teardown_shell_fork_state() {
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    crate::handlers::__test_wait_reset();
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    crate::user_task::__test_clear_exit_observers();
    crate::syscall::__test_clear_global();
}

// ── Layer A: parser helpers (inline re-implementations) ───────────────
//
// These are semantically equivalent to the private functions in
// `userspace/shell/src/main.rs`. Keep them in sync when the shell
// parser changes.

fn skip_ws(s: &[u8]) -> &[u8] {
    let i = s.iter().position(|&b| b != b' ').unwrap_or(s.len());
    &s[i..]
}

fn trim_arg(s: &[u8]) -> &[u8] {
    let s = skip_ws(s);
    let mut end = s.len();
    while end > 0 && (s[end - 1] == b' ' || s[end - 1] < 0x20) {
        end -= 1;
    }
    &s[..end]
}

/// Returns `(command_token, rest_after_leading_whitespace)`.
fn split_first(line: &[u8]) -> (&[u8], &[u8]) {
    let start = line
        .iter()
        .position(|&b| b != b' ')
        .unwrap_or(line.len());
    let line = &line[start..];
    match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], skip_ws(&line[i..])),
        None => (line, &[]),
    }
}

/// Mirror of `classify` in the shell's line editor.
enum LineAction {
    Append(u8),
    Backspace,
    Submit,
    Ignore,
}

fn classify(b: u8) -> LineAction {
    match b {
        b'\n' | b'\r' => LineAction::Submit,
        0x7F | 0x08 => LineAction::Backspace,
        0x20..=0x7E => LineAction::Append(b),
        _ => LineAction::Ignore,
    }
}

/// Naive literal substring search — mirror of `line_contains` in
/// `run_grep`.
fn line_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    let last = haystack.len() - needle.len();
    let mut i = 0usize;
    while i <= last {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

// ── Smoke 1: empty line → no command ─────────────────────────────────
//
// Shell contract: `dispatch_line` returns immediately (keeps looping)
// when `split_first` yields an empty command token.  The line editor
// strips the newline before calling dispatch_line, so the effective
// input is b"".

fn smoke_shell_parser_empty_line() -> TestResult {
    // Empty buffer → empty command.
    let (cmd, _) = split_first(b"");
    if !cmd.is_empty() {
        return TestResult::Fail("empty line: split_first should give empty cmd");
    }
    // Whitespace-only → still empty command (all WS stripped).
    let (cmd2, _) = split_first(b"   ");
    if !cmd2.is_empty() {
        return TestResult::Fail("whitespace-only: split_first should give empty cmd");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_empty_line);

// ── Smoke 2: `echo hello` → argv split ───────────────────────────────
//
// Shell contract: the first space-delimited token is the command
// name; the remainder (after consuming the separating whitespace) is
// `rest` passed to the command handler.

fn smoke_shell_parser_echo_hello() -> TestResult {
    let (cmd, rest) = split_first(b"echo hello");
    if cmd != b"echo" {
        return TestResult::Fail("echo hello: cmd should be b\"echo\"");
    }
    if rest != b"hello" {
        return TestResult::Fail("echo hello: rest should be b\"hello\"");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_echo_hello);

// ── Smoke 3: quoted args ──────────────────────────────────────────────
//
// The shell's `dispatch_line` does NOT strip quotes — they arrive
// verbatim in `rest`.  grep internally strips its pattern quotes;
// that sub-path is tested in smoke 7.  Here we pin the dispatcher's
// view.

fn smoke_shell_parser_quoted_args() -> TestResult {
    let (cmd, rest) = split_first(b"echo \"hello world\"");
    if cmd != b"echo" {
        return TestResult::Fail("quoted: cmd should be b\"echo\"");
    }
    // The shell's echo builtin receives the bytes including the quotes.
    if rest != b"\"hello world\"" {
        return TestResult::Fail("quoted: rest should include the quote chars verbatim");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_quoted_args);

// ── Smoke 4: pipe syntax — not yet parsed ────────────────────────────
//
// The NARF shell does NOT yet implement a pipe parser.  `|` in the
// command line lands uninterpreted in `rest`.  This smoke documents
// the current behaviour so a future pipe-parser landing immediately
// shows up as a test change.
//
// The syscall-layer pipe mechanics are verified separately in
// smokes 9-11.

fn smoke_shell_parser_pipe_not_yet_parsed() -> TestResult {
    let (cmd, rest) = split_first(b"ls | grep foo");
    if cmd != b"ls" {
        return TestResult::Fail("pipe: first token should be \"ls\"");
    }
    // The pipe character is in `rest`, uninterpreted.
    if !rest.starts_with(b"|") {
        return TestResult::Fail("pipe: rest should begin with '|' (pipe not yet parsed)");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_pipe_not_yet_parsed);

// ── Smoke 5: redirect syntax — not yet parsed ─────────────────────────
//
// Same situation as pipe: `>` is not scanned by dispatch_line.
// This smoke pins the current parser behaviour.

fn smoke_shell_parser_redirect_not_yet_parsed() -> TestResult {
    let (cmd, rest) = split_first(b"echo hi > /tmp/test.txt");
    if cmd != b"echo" {
        return TestResult::Fail("redir: cmd should be \"echo\"");
    }
    if !rest.contains(&b'>') {
        return TestResult::Fail("redir: rest should contain '>'");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_redirect_not_yet_parsed);

// ── Smoke 6: builtin `cd` arg parsing ────────────────────────────────
//
// Shell contract: `cd /tmp` → cmd="cd", trim_arg(rest)="/tmp".
// trim_arg also strips trailing CR so a CRLF terminal doesn't sneak
// a stray byte into the path.

fn smoke_shell_parser_cd_arg() -> TestResult {
    let (cmd, rest) = split_first(b"cd /tmp");
    if cmd != b"cd" {
        return TestResult::Fail("cd: cmd should be \"cd\"");
    }
    if trim_arg(rest) != b"/tmp" {
        return TestResult::Fail("cd: trim_arg(rest) should be b\"/tmp\"");
    }

    // Trailing CR must be stripped (CRLF terminal compatibility).
    let (cmd2, rest2) = split_first(b"cd /tmp\r");
    if cmd2 != b"cd" {
        return TestResult::Fail("cd+CR: cmd should be \"cd\"");
    }
    if trim_arg(rest2) != b"/tmp" {
        return TestResult::Fail("cd+CR: trim_arg should strip trailing \\r");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_cd_arg);

// ── Smoke 7: grep's literal-match helper ─────────────────────────────
//
// `line_contains` is the inner loop of `run_grep` in the shell. It
// must find needles, reject misses, accept empty needles, and handle
// the quote-stripping step that grep does before passing the pattern.

fn smoke_shell_parser_grep_line_contains() -> TestResult {
    // Basic match.
    if !line_contains(b"hello world", b"world") {
        return TestResult::Fail("line_contains: should find \"world\" in \"hello world\"");
    }
    // Miss.
    if line_contains(b"hello world", b"xyz") {
        return TestResult::Fail("line_contains: should NOT find \"xyz\"");
    }
    // Empty needle always matches.
    if !line_contains(b"anything", b"") {
        return TestResult::Fail("line_contains: empty needle should always match");
    }
    // Needle == haystack (boundary).
    if !line_contains(b"abc", b"abc") {
        return TestResult::Fail("line_contains: needle == haystack should match");
    }
    // Simulate grep's quote-strip: `"hello world"` → pattern = b"hello world".
    let raw: &[u8] = b"\"hello world\" /file";
    let quote = raw[0];
    let inner = &raw[1..];
    match inner.iter().position(|&b| b == quote) {
        Some(c) => {
            let pattern = &inner[..c];
            if pattern != b"hello world" {
                return TestResult::Fail("grep-quote: extracted pattern mismatch");
            }
        }
        None => return TestResult::Fail("grep-quote: closing quote not found"),
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_grep_line_contains);

// ── Smoke 8: classify — line-editor byte classifier ──────────────────
//
// The shell's `classify` function determines the line-editor action for
// each incoming byte. Verified here because it gates whether characters
// reach dispatch_line at all.

fn smoke_shell_parser_classify() -> TestResult {
    // Newline → Submit.
    if !matches!(classify(b'\n'), LineAction::Submit) {
        return TestResult::Fail("classify: '\\n' should be Submit");
    }
    if !matches!(classify(b'\r'), LineAction::Submit) {
        return TestResult::Fail("classify: '\\r' should be Submit");
    }
    // DEL and ^H → Backspace.
    if !matches!(classify(0x7F), LineAction::Backspace) {
        return TestResult::Fail("classify: 0x7F (DEL) should be Backspace");
    }
    if !matches!(classify(0x08), LineAction::Backspace) {
        return TestResult::Fail("classify: 0x08 (^H) should be Backspace");
    }
    // Printable ASCII → Append with the same byte.
    if !matches!(classify(b'a'), LineAction::Append(b'a')) {
        return TestResult::Fail("classify: 'a' should be Append('a')");
    }
    if !matches!(classify(b' '), LineAction::Append(b' ')) {
        return TestResult::Fail("classify: ' ' should be Append(' ')");
    }
    if !matches!(classify(b'~'), LineAction::Append(b'~')) {
        return TestResult::Fail("classify: '~' (0x7E) should be Append");
    }
    // Control bytes other than \n / \r / ^H / DEL → Ignore.
    if !matches!(classify(0x01), LineAction::Ignore) {
        return TestResult::Fail("classify: SOH (0x01) should be Ignore");
    }
    if !matches!(classify(0x1B), LineAction::Ignore) {
        return TestResult::Fail("classify: ESC (0x1B) should be Ignore");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_classify);

// ── Smoke 9: pipe syscall round-trip ─────────────────────────────────
//
// Verifies sys_pipe allocates a read/write fd pair, sys_write
// enqueues data into the shared ring, and sys_read dequeues it.
//
// This is the kernel half of the `echo hello | cat` pipeline.
//
// Linux ref: fs/pipe.c::do_pipe_flags, fs/read_write.c::sys_write.

fn smoke_shell_pipe_round_trip() -> TestResult {
    crate::syscall::__test_clear_global();
    fd::__test_reset();
    fd::init();

    SHELL_TASK.store(0x5009, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // sys_pipe — fills [read_fd, write_fd] into the caller's array.
    let mut pipe_fds: [i32; 2] = [-1, -1];
    let mut pctx = StubCtx {
        args: SyscallArgs {
            arg0: pipe_fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("pipe-rt: sys_pipe did not return Ok(0)");
    }
    if pipe_fds[0] < 3 || pipe_fds[1] < 3 || pipe_fds[0] == pipe_fds[1] {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("pipe-rt: fd pair must be >= 3 and distinct");
    }
    let rfd = pipe_fds[0] as u64;
    let wfd = pipe_fds[1] as u64;

    // Write "hello\n".
    let payload = b"hello\n";
    let mut wctx = StubCtx {
        args: SyscallArgs {
            arg0: wfd,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
    if wctx.ret != Some(SyscallReturn::ok(payload.len() as u64)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("pipe-rt: write returned wrong byte count");
    }

    // Read back — must get exactly "hello\n".
    let mut buf = [0u8; 16];
    let mut rctx = StubCtx {
        args: SyscallArgs {
            arg0: rfd,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    let n = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("pipe-rt: read returned non-OK");
        }
    };
    if n != payload.len() || &buf[..n] != payload {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("pipe-rt: round-trip bytes mismatch");
    }

    fd::__test_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_pipe_round_trip);

// ── Smoke 10: dup2 wires child stdout to pipe write-end ──────────────
//
// Child-side setup of `ls | grep foo`: after fork the child calls
// dup2(write_fd, 1) to redirect its stdout into the pipe write-end.
// Verify sys_dup2 installs the clone at fd 1 and that writing to fd 1
// enqueues into the ring (readable from the pipe read-end).
//
// Linux ref: fs/fcntl.c::sys_dup2.

fn smoke_shell_dup2_stdout_to_pipe() -> TestResult {
    crate::syscall::__test_clear_global();
    fd::__test_reset();
    fd::init();

    SHELL_TASK.store(0x500A, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Allocate a pipe.
    let mut pipe_fds: [i32; 2] = [-1, -1];
    let mut pctx = StubCtx {
        args: SyscallArgs {
            arg0: pipe_fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("dup2-stdout: sys_pipe failed");
    }
    let rfd = pipe_fds[0] as u64;
    let wfd = pipe_fds[1] as u64;

    // dup2(write_fd, 1) — stdout now points at the pipe write-end.
    let mut dctx = StubCtx {
        args: SyscallArgs {
            arg0: wfd,
            arg1: 1,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Dup2.raw(), &mut dctx);
    match dctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 1 => {}
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("dup2-stdout: dup2(wfd,1) should return Ok(1)");
        }
    }

    // Write "world\n" to fd 1 (the redirected stdout).
    let payload = b"world\n";
    let mut wctx = StubCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
    if wctx.ret != Some(SyscallReturn::ok(payload.len() as u64)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("dup2-stdout: write to fd 1 returned wrong count");
    }

    // Read back from the original read-end — confirms dup2 wired the
    // right backing FileOps under fd 1.
    let mut buf = [0u8; 16];
    let mut rctx = StubCtx {
        args: SyscallArgs {
            arg0: rfd,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    let n = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("dup2-stdout: read from pipe-read-end returned non-OK");
        }
    };
    if n != payload.len() || &buf[..n] != payload {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("dup2-stdout: bytes mismatch after dup2-based write");
    }

    fd::__test_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_dup2_stdout_to_pipe);

// ── Smoke 11: dup2 wires child stdin from pipe read-end ───────────────
//
// Stdin wiring for the second child in a pipeline: dup2(read_fd, 0)
// makes fd 0 (stdin) drain from the pipe instead of /dev/console.
// Verifies that a Read on fd 0 retrieves whatever was written to the
// write-end beforehand.
//
// This is the right-hand child of `echo hello | cat`.

fn smoke_shell_dup2_stdin_from_pipe() -> TestResult {
    crate::syscall::__test_clear_global();
    fd::__test_reset();
    fd::init();

    SHELL_TASK.store(0x500B, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Allocate a pipe.
    let mut pipe_fds: [i32; 2] = [-1, -1];
    let mut pctx = StubCtx {
        args: SyscallArgs {
            arg0: pipe_fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("dup2-stdin: sys_pipe failed");
    }
    let rfd = pipe_fds[0] as u64;
    let wfd = pipe_fds[1] as u64;

    // Pre-load data into the write-end.
    let payload = b"stdin_data\n";
    let mut wctx = StubCtx {
        args: SyscallArgs {
            arg0: wfd,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
    if wctx.ret != Some(SyscallReturn::ok(payload.len() as u64)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("dup2-stdin: pre-write to write-end failed");
    }

    // dup2(read_fd, 0) — stdin now drains from the pipe.
    let mut dctx = StubCtx {
        args: SyscallArgs {
            arg0: rfd,
            arg1: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Dup2.raw(), &mut dctx);
    match dctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("dup2-stdin: dup2(rfd,0) should return Ok(0)");
        }
    }

    // Read from fd 0 — must drain what was written to the write-end.
    let mut buf = [0u8; 32];
    let mut rctx = StubCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    let n = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("dup2-stdin: read from fd 0 returned non-OK");
        }
    };
    if n != payload.len() || &buf[..n] != payload {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("dup2-stdin: bytes drained from fd-0 mismatch");
    }

    fd::__test_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_dup2_stdin_from_pipe);

// ── Smoke 12: fork + wait4 + exit-status propagation ─────────────────
//
// The kernel half of "shell forks a child, waits for it, reads the
// exit status". Uses the same `notify_task_exited` + `wait4(WNOHANG)`
// pattern that Wave-30 smoke 1 established.
//
// Linux ref: kernel/fork.c::copy_process, kernel/exit.c::do_wait.

#[cfg(target_arch = "x86_64")]
fn smoke_shell_fork_wait4_exit_status() -> TestResult {
    const PARENT: u64 = 0x5012;

    crate::syscall::__test_clear_global();
    narf_scheduler::__reset_queues_for_test();

    SHELL_TASK.store(PARENT, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);
    crate::handlers::__test_sigaction_reset();
    crate::handlers::__test_signal_reset();
    crate::handlers::__test_wait_reset();
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    crate::user_task::__test_clear_exit_observers();
    crate::sigaction_init();
    crate::signal_init();
    crate::handlers::pgid_init();
    crate::handlers::sid_init();
    crate::handlers::wait_init();

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => {
            teardown_shell_fork_state();
            return TestResult::Fail("AddressSpace::new_for_user failed");
        }
    };
    *SHELL_PARENT_AS.lock() = Some(parent_as);
    install_address_space_lookup(lookup_shell_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // (1) Fork — parent receives a non-zero child tid.
    let mut fctx = StubCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fork.raw(), &mut fctx);
    let child_tid = match fctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != 0 => r.value,
        _ => {
            teardown_shell_fork_state();
            *SHELL_PARENT_AS.lock() = None;
            return TestResult::Fail("fork: parent did not receive a non-zero child tid");
        }
    };

    // (2) Simulate the child calling sys_exit_task (the exit observer
    //     fires `notify_task_exited` which enqueues the child in the
    //     wait table).
    crate::user_task::notify_task_exited(child_tid);

    // (3) wait4(-1, &wstatus, WNOHANG) — child already exited so
    //     WNOHANG must reap immediately and return the child tid.
    let mut wstatus: i32 = -1;
    SHELL_TASK.store(PARENT, Ordering::Relaxed);
    let mut wctx = StubCtx {
        args: SyscallArgs {
            arg0: u64::MAX,                    // -1 as u64 = any child
            arg1: &mut wstatus as *mut i32 as u64,
            arg2: 1,                           // WNOHANG
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Wait4.raw(), &mut wctx);
    let reaped = match wctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            teardown_shell_fork_state();
            *SHELL_PARENT_AS.lock() = None;
            return TestResult::Fail("wait4: did not return OK");
        }
    };
    if reaped != child_tid {
        teardown_shell_fork_state();
        *SHELL_PARENT_AS.lock() = None;
        return TestResult::Fail("wait4: reaped tid does not match child tid");
    }
    // wstatus == 0 because on_child_exit records status=0 unconditionally
    // (exit-code threading not yet wired — see handlers.rs TODO at line ~3632).
    if wstatus != 0 {
        teardown_shell_fork_state();
        *SHELL_PARENT_AS.lock() = None;
        return TestResult::Fail("wait4: wstatus should be 0 (exit-code threading deferred)");
    }

    teardown_shell_fork_state();
    *SHELL_PARENT_AS.lock() = None;
    narf_memory::frame::cow::__test_clear();
    TestResult::Pass
}

#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace/shell", smoke_shell_fork_wait4_exit_status);

// ── Smoke 13: pipe full-ring round-trip (4 KiB) ───────────────────────
//
// NARF's PipeShared ring is capped at PIPE_BUF_BYTES (4096 bytes).
// Write exactly 4 KiB then read it back. Exercises the VecDeque
// capacity path inside PipeWrite::write and confirms no truncation.

fn smoke_shell_pipe_full_ring() -> TestResult {
    crate::syscall::__test_clear_global();
    fd::__test_reset();
    fd::init();

    SHELL_TASK.store(0x500D, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut pipe_fds: [i32; 2] = [-1, -1];
    let mut pctx = StubCtx {
        args: SyscallArgs {
            arg0: pipe_fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("full-ring: sys_pipe failed");
    }
    let rfd = pipe_fds[0] as u64;
    let wfd = pipe_fds[1] as u64;

    // Write 4096 bytes (fills the ring exactly).
    let write_buf = [0xABu8; 4096];
    let mut wctx = StubCtx {
        args: SyscallArgs {
            arg0: wfd,
            arg1: write_buf.as_ptr() as u64,
            arg2: 4096,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
    match wctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 4096 => {}
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("full-ring: write of 4096 bytes returned wrong count");
        }
    }

    // Read all 4096 bytes back.
    let mut read_buf = [0u8; 4096];
    let mut rctx = StubCtx {
        args: SyscallArgs {
            arg0: rfd,
            arg1: read_buf.as_mut_ptr() as u64,
            arg2: 4096,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 4096 => {}
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("full-ring: read returned wrong count");
        }
    }
    if read_buf != write_buf {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("full-ring: bytes mismatch after round-trip");
    }

    fd::__test_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_pipe_full_ring);

// ── Smoke 14: dup2 no-op on same fd ──────────────────────────────────
//
// POSIX: dup2(fd, fd) is a no-op and returns `fd` when `fd` is
// open. The shell's pre-exec fd-setup must not accidentally close a
// live fd by calling dup2 with oldfd == newfd.
//
// Linux ref: fs/fcntl.c::sys_dup2 — "If oldfd == newfd ... return fd."

fn smoke_shell_dup2_same_fd_noop() -> TestResult {
    crate::syscall::__test_clear_global();
    fd::__test_reset();
    fd::init();

    SHELL_TASK.store(0x500E, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Get a valid fd > 2 (use the pipe read-end).
    let mut pipe_fds: [i32; 2] = [-1, -1];
    let mut pctx = StubCtx {
        args: SyscallArgs {
            arg0: pipe_fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("dup2-noop: sys_pipe failed");
    }
    let some_fd = pipe_fds[0] as u64;

    // dup2(some_fd, some_fd) — must return Ok(some_fd).
    let mut dctx = StubCtx {
        args: SyscallArgs {
            arg0: some_fd,
            arg1: some_fd,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Dup2.raw(), &mut dctx);
    match dctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == some_fd => {}
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("dup2-noop: dup2(fd, fd) should return Ok(fd)");
        }
    }

    // Confirm fd is still live: a Read should return Ok(...) not an error.
    let mut rbuf = [0u8; 4];
    let mut rctx = StubCtx {
        args: SyscallArgs {
            arg0: some_fd,
            arg1: rbuf.as_mut_ptr() as u64,
            arg2: 4,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    // Empty pipe read-end returns Ok(0) — not an error code.
    match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => {}
        _ => {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("dup2-noop: fd was closed after dup2(fd,fd) — should be live");
        }
    }

    fd::__test_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_dup2_same_fd_noop);

// ── Smoke 15: two sequential writes + reads preserve FIFO order ───────
//
// Simulates the data-ordering guarantee of `echo a; echo b` piped
// through a single pipe: two successive writes followed by two
// successive reads must come back in the same order.
//
// This is the ordering property `ls | grep foo` depends on.

fn smoke_shell_pipe_sequential_writes() -> TestResult {
    crate::syscall::__test_clear_global();
    fd::__test_reset();
    fd::init();

    SHELL_TASK.store(0x500F, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut pipe_fds: [i32; 2] = [-1, -1];
    let mut pctx = StubCtx {
        args: SyscallArgs {
            arg0: pipe_fds.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("seq-writes: sys_pipe failed");
    }
    let rfd = pipe_fds[0] as u64;
    let wfd = pipe_fds[1] as u64;

    let msgs: [&[u8]; 2] = [b"aaa\n", b"bbb\n"];

    // Two sequential writes.
    for msg in msgs {
        let mut wctx = StubCtx {
            args: SyscallArgs {
                arg0: wfd,
                arg1: msg.as_ptr() as u64,
                arg2: msg.len() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
        if wctx.ret != Some(SyscallReturn::ok(msg.len() as u64)) {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("seq-writes: write returned wrong count");
        }
    }

    // Two sequential reads — must arrive in the same order.
    for expected in msgs {
        let mut buf = [0u8; 8];
        let mut rctx = StubCtx {
            args: SyscallArgs {
                arg0: rfd,
                arg1: buf.as_mut_ptr() as u64,
                arg2: expected.len() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
        let n = match rctx.ret {
            Some(r) if r.status == SyscallReturn::OK => r.value as usize,
            _ => {
                fd::__test_reset();
                crate::syscall::__test_clear_global();
                return TestResult::Fail("seq-writes: read returned non-OK");
            }
        };
        if n != expected.len() || &buf[..n] != expected {
            fd::__test_reset();
            crate::syscall::__test_clear_global();
            return TestResult::Fail("seq-writes: FIFO order violated or bytes mismatch");
        }
    }

    fd::__test_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_pipe_sequential_writes);
