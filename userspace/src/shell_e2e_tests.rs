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
    fd, install_address_space_lookup, install_core_syscalls, install_global, install_task_id_lookup,
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
static SHELL_PARENT_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

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
    let start = line.iter().position(|&b| b != b' ').unwrap_or(line.len());
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

// ── Smoke 4: pipe syntax — parser recognises `|` (Wave 33) ──────────
//
// Wave 33 added a proper tokeniser.  `|` is now a `Pipe` token;
// `ls | grep foo` should lex to [Word("ls"), Pipe, Word("grep"),
// Word("foo"), Eof] — i.e. a pipeline with two stages.
//
// We mirror the production `lex` function inline and assert the
// token stream so the smoke stays in lock-step with parser.rs.

/// Mirror of the production `Tok` enum (pure-value subset).
#[derive(Debug, PartialEq, Eq)]
enum Tok4 {
    Word,
    Pipe,
    Semicolon,
    And,
    Or,
    Ampersand,
    RedirIn,
    RedirOut,
    RedirAppend,
    Eof,
}

fn lex4(input: &[u8]) -> alloc::vec::Vec<Tok4> {
    let mut out = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        if b == b' ' || b == b'\t' {
            i += 1;
            continue;
        }
        match b {
            b'|' if i + 1 < input.len() && input[i + 1] == b'|' => {
                out.push(Tok4::Or);
                i += 2;
            }
            b'|' => {
                out.push(Tok4::Pipe);
                i += 1;
            }
            b'&' if i + 1 < input.len() && input[i + 1] == b'&' => {
                out.push(Tok4::And);
                i += 2;
            }
            b'&' => {
                out.push(Tok4::Ampersand);
                i += 1;
            }
            b';' => {
                out.push(Tok4::Semicolon);
                i += 1;
            }
            b'>' if i + 1 < input.len() && input[i + 1] == b'>' => {
                out.push(Tok4::RedirAppend);
                i += 2;
            }
            b'>' => {
                out.push(Tok4::RedirOut);
                i += 1;
            }
            b'<' => {
                out.push(Tok4::RedirIn);
                i += 1;
            }
            _ => {
                // Consume a word token.
                while i < input.len() {
                    let c = input[i];
                    match c {
                        b' ' | b'\t' | b'|' | b'&' | b';' | b'>' | b'<' => break,
                        b'\'' => {
                            i += 1;
                            while i < input.len() && input[i] != b'\'' {
                                i += 1;
                            }
                            if i < input.len() {
                                i += 1;
                            }
                        }
                        b'"' => {
                            i += 1;
                            while i < input.len() && input[i] != b'"' {
                                i += 1;
                            }
                            if i < input.len() {
                                i += 1;
                            }
                        }
                        b'\\' => {
                            i += 2;
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
                out.push(Tok4::Word);
            }
        }
    }
    out.push(Tok4::Eof);
    out
}

fn smoke_shell_parser_pipe_recognized() -> TestResult {
    // "ls | grep foo" → [Word("ls"), Pipe, Word("grep"), Word("foo"), Eof]
    // That is exactly a 2-stage pipeline.
    let toks = lex4(b"ls | grep foo");
    if toks.len() != 5 {
        return TestResult::Fail("pipe: expected 5 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("pipe: tok[0] should be Word(\"ls\")");
    }
    if toks[1] != Tok4::Pipe {
        return TestResult::Fail("pipe: tok[1] should be Pipe");
    }
    if toks[2] != Tok4::Word {
        return TestResult::Fail("pipe: tok[2] should be Word(\"grep\")");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("pipe: tok[3] should be Word(\"foo\")");
    }
    if toks[4] != Tok4::Eof {
        return TestResult::Fail("pipe: tok[4] should be Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_pipe_recognized);

// ── Smoke 5: redirect syntax — parser recognises `>` (Wave 33) ───────
//
// "echo hi > /tmp/test.txt" should lex to:
//   [Word("echo"), Word("hi"), RedirOut, Word("/tmp/test.txt"), Eof]
//
// The `Simple` command therefore has:
//   argv  = ["echo", "hi"]
//   redirs = [StdoutTo("/tmp/test.txt")]

fn smoke_shell_parser_redirect_recognized() -> TestResult {
    let toks = lex4(b"echo hi > /tmp/test.txt");
    if toks.len() != 5 {
        return TestResult::Fail("redir: expected 5 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("redir: tok[0] should be Word(\"echo\")");
    }
    if toks[1] != Tok4::Word {
        return TestResult::Fail("redir: tok[1] should be Word(\"hi\")");
    }
    if toks[2] != Tok4::RedirOut {
        return TestResult::Fail("redir: tok[2] should be RedirOut");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("redir: tok[3] should be Word(\"/tmp/test.txt\")");
    }
    if toks[4] != Tok4::Eof {
        return TestResult::Fail("redir: tok[4] should be Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_redirect_recognized);

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
    crate::user_task::notify_task_exited(child_tid, child_tid);

    // (3) wait4(-1, &wstatus, WNOHANG) — child already exited so
    //     WNOHANG must reap immediately and return the child tid.
    let mut wstatus: i32 = -1;
    SHELL_TASK.store(PARENT, Ordering::Relaxed);
    let mut wctx = StubCtx {
        args: SyscallArgs {
            arg0: u64::MAX, // -1 as u64 = any child
            arg1: &mut wstatus as *mut i32 as u64,
            arg2: 1, // WNOHANG
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

// ═══════════════════════════════════════════════════════════════════════
// Wave 33 — new parser + exec-engine smokes (smokes 16 – 29)
// ═══════════════════════════════════════════════════════════════════════
//
// Layer A — pure tokeniser / parser unit tests (no kernel required).
// These carry inline helpers that mirror `userspace/shell/src/parser.rs`.
// The production file is audited side-by-side; any divergence here
// means the tests need to be updated.

// ── Token word extraction helper ──────────────────────────────────────
//
// `word_at(toks, pos)` extracts the word bytes for token at position
// `pos` from the original input.  Used by smokes that need to assert
// the actual characters in a word, not just that a Word token was seen.
//
// For brevity we use the `lex4` helper defined in smoke 4 above and
// `lex4_words` which pairs the token stream with the original word
// bytes scanned in the same pass.

fn lex4_with_words<'a>(input: &'a [u8]) -> alloc::vec::Vec<(Tok4, &'a [u8])> {
    let mut out = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        if b == b' ' || b == b'\t' {
            i += 1;
            continue;
        }
        match b {
            b'|' if i + 1 < input.len() && input[i + 1] == b'|' => {
                out.push((Tok4::Or, &input[i..i + 2]));
                i += 2;
            }
            b'|' => {
                out.push((Tok4::Pipe, &input[i..i + 1]));
                i += 1;
            }
            b'&' if i + 1 < input.len() && input[i + 1] == b'&' => {
                out.push((Tok4::And, &input[i..i + 2]));
                i += 2;
            }
            b'&' => {
                out.push((Tok4::Ampersand, &input[i..i + 1]));
                i += 1;
            }
            b';' => {
                out.push((Tok4::Semicolon, &input[i..i + 1]));
                i += 1;
            }
            b'>' if i + 1 < input.len() && input[i + 1] == b'>' => {
                out.push((Tok4::RedirAppend, &input[i..i + 2]));
                i += 2;
            }
            b'>' => {
                out.push((Tok4::RedirOut, &input[i..i + 1]));
                i += 1;
            }
            b'<' => {
                out.push((Tok4::RedirIn, &input[i..i + 1]));
                i += 1;
            }
            _ => {
                let start = i;
                while i < input.len() {
                    let c = input[i];
                    match c {
                        b' ' | b'\t' | b'|' | b'&' | b';' | b'>' | b'<' => break,
                        b'\'' => {
                            i += 1;
                            while i < input.len() && input[i] != b'\'' {
                                i += 1;
                            }
                            if i < input.len() {
                                i += 1;
                            }
                        }
                        b'"' => {
                            i += 1;
                            while i < input.len() && input[i] != b'"' {
                                i += 1;
                            }
                            if i < input.len() {
                                i += 1;
                            }
                        }
                        b'\\' => {
                            i += 2;
                        }
                        _ => {
                            i += 1;
                        }
                    }
                }
                out.push((Tok4::Word, &input[start..i]));
            }
        }
    }
    out.push((Tok4::Eof, &input[input.len()..]));
    out
}

/// Extract the unquoted value of a word token (mirrors production `lex_word`).
/// Only handles the simple cases needed by the smokes below.
fn word_value(raw: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        match raw[i] {
            b'\'' => {
                i += 1;
                while i < raw.len() && raw[i] != b'\'' {
                    out.push(raw[i]);
                    i += 1;
                }
                if i < raw.len() {
                    i += 1;
                }
            }
            b'"' => {
                i += 1;
                while i < raw.len() && raw[i] != b'"' {
                    if raw[i] == b'\\' && i + 1 < raw.len() && raw[i + 1] == b'"' {
                        out.push(b'"');
                        i += 2;
                    } else {
                        out.push(raw[i]);
                        i += 1;
                    }
                }
                if i < raw.len() {
                    i += 1;
                }
            }
            b'\\' => {
                if i + 1 < raw.len() {
                    out.push(raw[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

// ── Smoke 16: sequence `;` recognised ────────────────────────────────
//
// "echo a; echo b" should lex to:
//   [Word, Word, Semicolon, Word, Word, Eof]

fn smoke_shell_parser_sequence_recognized() -> TestResult {
    let toks = lex4(b"echo a; echo b");
    // Tokens: Word("echo") Word("a") Semicolon Word("echo") Word("b") Eof
    if toks.len() != 6 {
        return TestResult::Fail("seq: expected 6 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("seq: tok[0] not Word");
    }
    if toks[1] != Tok4::Word {
        return TestResult::Fail("seq: tok[1] not Word");
    }
    if toks[2] != Tok4::Semicolon {
        return TestResult::Fail("seq: tok[2] not Semicolon");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("seq: tok[3] not Word");
    }
    if toks[4] != Tok4::Word {
        return TestResult::Fail("seq: tok[4] not Word");
    }
    if toks[5] != Tok4::Eof {
        return TestResult::Fail("seq: tok[5] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_sequence_recognized);

// ── Smoke 17: `&&` recognised ─────────────────────────────────────────
//
// "true && echo ok" → [Word, And, Word, Word, Eof]

fn smoke_shell_parser_and_recognized() -> TestResult {
    let toks = lex4(b"true && echo ok");
    if toks.len() != 5 {
        return TestResult::Fail("and: expected 5 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("and: tok[0] not Word");
    }
    if toks[1] != Tok4::And {
        return TestResult::Fail("and: tok[1] not And");
    }
    if toks[2] != Tok4::Word {
        return TestResult::Fail("and: tok[2] not Word");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("and: tok[3] not Word");
    }
    if toks[4] != Tok4::Eof {
        return TestResult::Fail("and: tok[4] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_and_recognized);

// ── Smoke 18: `||` recognised ────────────────────────────────────────
//
// "false || echo recovered" → [Word, Or, Word, Word, Eof]

fn smoke_shell_parser_or_recognized() -> TestResult {
    let toks = lex4(b"false || echo recovered");
    if toks.len() != 5 {
        return TestResult::Fail("or: expected 5 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("or: tok[0] not Word");
    }
    if toks[1] != Tok4::Or {
        return TestResult::Fail("or: tok[1] not Or");
    }
    if toks[2] != Tok4::Word {
        return TestResult::Fail("or: tok[2] not Word");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("or: tok[3] not Word");
    }
    if toks[4] != Tok4::Eof {
        return TestResult::Fail("or: tok[4] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_or_recognized);

// ── Smoke 19: `&` background recognised ──────────────────────────────
//
// "sleep 0 &" → [Word, Word, Ampersand, Eof]

fn smoke_shell_parser_background_recognized() -> TestResult {
    let toks = lex4(b"sleep 0 &");
    if toks.len() != 4 {
        return TestResult::Fail("bg: expected 4 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("bg: tok[0] not Word");
    }
    if toks[1] != Tok4::Word {
        return TestResult::Fail("bg: tok[1] not Word");
    }
    if toks[2] != Tok4::Ampersand {
        return TestResult::Fail("bg: tok[2] not Ampersand");
    }
    if toks[3] != Tok4::Eof {
        return TestResult::Fail("bg: tok[3] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_background_recognized);

// ── Smoke 20: `>>` append redirect recognised ─────────────────────────
//
// "echo line >> /tmp/r.txt" → [Word, Word, RedirAppend, Word, Eof]

fn smoke_shell_parser_append_recognized() -> TestResult {
    let toks = lex4(b"echo line >> /tmp/r.txt");
    if toks.len() != 5 {
        return TestResult::Fail("append: expected 5 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("append: tok[0] not Word");
    }
    if toks[1] != Tok4::Word {
        return TestResult::Fail("append: tok[1] not Word");
    }
    if toks[2] != Tok4::RedirAppend {
        return TestResult::Fail("append: tok[2] not RedirAppend");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("append: tok[3] not Word");
    }
    if toks[4] != Tok4::Eof {
        return TestResult::Fail("append: tok[4] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_append_recognized);

// ── Smoke 21: `<` stdin redirect recognised ───────────────────────────
//
// "cat < /tmp/r.txt" → [Word, RedirIn, Word, Eof]

fn smoke_shell_parser_stdin_redir_recognized() -> TestResult {
    let toks = lex4(b"cat < /tmp/r.txt");
    if toks.len() != 4 {
        return TestResult::Fail("stdin-redir: expected 4 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("stdin-redir: tok[0] not Word");
    }
    if toks[1] != Tok4::RedirIn {
        return TestResult::Fail("stdin-redir: tok[1] not RedirIn");
    }
    if toks[2] != Tok4::Word {
        return TestResult::Fail("stdin-redir: tok[2] not Word");
    }
    if toks[3] != Tok4::Eof {
        return TestResult::Fail("stdin-redir: tok[3] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_stdin_redir_recognized);

// ── Smoke 22: double-quoted word preserves spaces ─────────────────────
//
// `echo "a b" c` → three word tokens; word[1] value = "a b"

fn smoke_shell_parser_double_quoted() -> TestResult {
    let pairs = lex4_with_words(b"echo \"a b\" c");
    // Tokens: Word("echo") Word("\"a b\"") Word("c") Eof
    if pairs.len() != 4 {
        return TestResult::Fail("dquote: expected 4 tokens");
    }
    if pairs[0].0 != Tok4::Word {
        return TestResult::Fail("dquote: tok[0] not Word");
    }
    if pairs[1].0 != Tok4::Word {
        return TestResult::Fail("dquote: tok[1] not Word");
    }
    if pairs[2].0 != Tok4::Word {
        return TestResult::Fail("dquote: tok[2] not Word");
    }
    // The raw token for "\"a b\"" — strip quotes and verify interior bytes.
    let v = word_value(pairs[1].1);
    if v != b"a b" {
        return TestResult::Fail("dquote: double-quoted word value should be \"a b\"");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_double_quoted);

// ── Smoke 23: single-quoted word is literal ───────────────────────────
//
// `echo 'literal "quoted"'` → two word tokens; word[1] value is
// `literal "quoted"` (the double-quotes are literal, not metacharacters).

fn smoke_shell_parser_single_quoted() -> TestResult {
    let pairs = lex4_with_words(b"echo 'literal \"quoted\"'");
    if pairs.len() != 3 {
        return TestResult::Fail("squote: expected 3 tokens");
    }
    if pairs[0].0 != Tok4::Word {
        return TestResult::Fail("squote: tok[0] not Word");
    }
    if pairs[1].0 != Tok4::Word {
        return TestResult::Fail("squote: tok[1] not Word");
    }
    let v = word_value(pairs[1].1);
    if v != b"literal \"quoted\"" {
        return TestResult::Fail(
            "squote: single-quoted value should preserve double-quotes literally",
        );
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_single_quoted);

// ── Smoke 24: backslash escape outside quotes ─────────────────────────
//
// `echo \"hello\"` → two word tokens; word[1] value is `"hello"`.

fn smoke_shell_parser_backslash_escape() -> TestResult {
    let pairs = lex4_with_words(b"echo \\\"hello\\\"");
    if pairs.len() != 3 {
        return TestResult::Fail("bslash: expected 3 tokens");
    }
    if pairs[0].0 != Tok4::Word {
        return TestResult::Fail("bslash: tok[0] not Word");
    }
    if pairs[1].0 != Tok4::Word {
        return TestResult::Fail("bslash: tok[1] not Word");
    }
    let v = word_value(pairs[1].1);
    if v != b"\"hello\"" {
        return TestResult::Fail(
            "bslash: escaped quotes should produce literal double-quote chars",
        );
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_backslash_escape);

// ── Smoke 25: multi-pipe three-stage ──────────────────────────────────
//
// "echo a | cat | cat" → [Word, Word, Pipe, Word, Pipe, Word, Eof]
// That is 3 stages: echo a, cat, cat.

fn smoke_shell_parser_multi_pipe() -> TestResult {
    let toks = lex4(b"echo a | cat | cat");
    // Word Word Pipe Word Pipe Word Eof
    if toks.len() != 7 {
        return TestResult::Fail("multi-pipe: expected 7 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("multi-pipe: tok[0] not Word");
    }
    if toks[1] != Tok4::Word {
        return TestResult::Fail("multi-pipe: tok[1] not Word");
    }
    if toks[2] != Tok4::Pipe {
        return TestResult::Fail("multi-pipe: tok[2] not Pipe");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("multi-pipe: tok[3] not Word");
    }
    if toks[4] != Tok4::Pipe {
        return TestResult::Fail("multi-pipe: tok[4] not Pipe");
    }
    if toks[5] != Tok4::Word {
        return TestResult::Fail("multi-pipe: tok[5] not Word");
    }
    if toks[6] != Tok4::Eof {
        return TestResult::Fail("multi-pipe: tok[6] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_multi_pipe);

// ── Smoke 26: `|` and `||` disambiguated ──────────────────────────────
//
// "a || b | c" → [Word, Or, Word, Pipe, Word, Eof]
// `||` must be consumed as a single token, not as `|` + `|`.

fn smoke_shell_parser_pipe_vs_or() -> TestResult {
    let toks = lex4(b"a || b | c");
    if toks.len() != 6 {
        return TestResult::Fail("pipe-vs-or: expected 6 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("pipe-vs-or: tok[0] not Word");
    }
    if toks[1] != Tok4::Or {
        return TestResult::Fail("pipe-vs-or: tok[1] not Or (got Pipe?)");
    }
    if toks[2] != Tok4::Word {
        return TestResult::Fail("pipe-vs-or: tok[2] not Word");
    }
    if toks[3] != Tok4::Pipe {
        return TestResult::Fail("pipe-vs-or: tok[3] not Pipe");
    }
    if toks[4] != Tok4::Word {
        return TestResult::Fail("pipe-vs-or: tok[4] not Word");
    }
    if toks[5] != Tok4::Eof {
        return TestResult::Fail("pipe-vs-or: tok[5] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_pipe_vs_or);

// ── Smoke 27: `&` vs `&&` disambiguated ───────────────────────────────
//
// "cmd1 && cmd2 &" → [Word, And, Word, Ampersand, Eof]

fn smoke_shell_parser_ampersand_vs_and() -> TestResult {
    let toks = lex4(b"cmd1 && cmd2 &");
    if toks.len() != 5 {
        return TestResult::Fail("amp-vs-and: expected 5 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("amp-vs-and: tok[0] not Word");
    }
    if toks[1] != Tok4::And {
        return TestResult::Fail("amp-vs-and: tok[1] not And (got Ampersand?)");
    }
    if toks[2] != Tok4::Word {
        return TestResult::Fail("amp-vs-and: tok[2] not Word");
    }
    if toks[3] != Tok4::Ampersand {
        return TestResult::Fail("amp-vs-and: tok[3] not Ampersand");
    }
    if toks[4] != Tok4::Eof {
        return TestResult::Fail("amp-vs-and: tok[4] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_ampersand_vs_and);

// ── Smoke 28: empty-line still gives Empty ────────────────────────────
//
// An empty input after Wave 33's lex/parse should still yield no
// tokens except Eof (mirrors smoke 1 but via the new lexer).

fn smoke_shell_parser_empty_line_v2() -> TestResult {
    let toks = lex4(b"");
    if toks.len() != 1 {
        return TestResult::Fail("empty-v2: expected exactly Eof");
    }
    if toks[0] != Tok4::Eof {
        return TestResult::Fail("empty-v2: only token should be Eof");
    }
    let toks2 = lex4(b"   ");
    if toks2.len() != 1 {
        return TestResult::Fail("empty-v2: whitespace-only should give just Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_empty_line_v2);

// ── Smoke 29: complex command-line round-trip ─────────────────────────
//
// "echo hi > /tmp/out.txt; cat < /tmp/out.txt | grep hi && echo found"
//
// This exercises all major operator classes together.  We only assert
// the token stream shape, not the execution result.
//
// Expected token stream:
//  Word("echo") Word("hi") RedirOut Word("/tmp/out.txt")
//  Semicolon
//  Word("cat") RedirIn Word("/tmp/out.txt")
//  Pipe
//  Word("grep") Word("hi")
//  And
//  Word("echo") Word("found")
//  Eof
//  total = 14 tokens

fn smoke_shell_parser_complex_pipeline() -> TestResult {
    let toks = lex4(b"echo hi > /tmp/out.txt; cat < /tmp/out.txt | grep hi && echo found");
    // Count: echo hi > /tmp/out.txt = 4 tokens
    //        ; = 1
    //        cat < /tmp/out.txt = 3
    //        | = 1
    //        grep hi = 2
    //        && = 1
    //        echo found = 2
    //        Eof = 1
    //        total = 15
    if toks.len() != 15 {
        return TestResult::Fail("complex: expected 15 tokens");
    }
    if toks[0] != Tok4::Word {
        return TestResult::Fail("complex: tok[0]  not Word");
    }
    if toks[1] != Tok4::Word {
        return TestResult::Fail("complex: tok[1]  not Word");
    }
    if toks[2] != Tok4::RedirOut {
        return TestResult::Fail("complex: tok[2]  not RedirOut");
    }
    if toks[3] != Tok4::Word {
        return TestResult::Fail("complex: tok[3]  not Word");
    }
    if toks[4] != Tok4::Semicolon {
        return TestResult::Fail("complex: tok[4]  not Semicolon");
    }
    if toks[5] != Tok4::Word {
        return TestResult::Fail("complex: tok[5]  not Word");
    }
    if toks[6] != Tok4::RedirIn {
        return TestResult::Fail("complex: tok[6]  not RedirIn");
    }
    if toks[7] != Tok4::Word {
        return TestResult::Fail("complex: tok[7]  not Word");
    }
    if toks[8] != Tok4::Pipe {
        return TestResult::Fail("complex: tok[8]  not Pipe");
    }
    if toks[9] != Tok4::Word {
        return TestResult::Fail("complex: tok[9]  not Word");
    }
    if toks[10] != Tok4::Word {
        return TestResult::Fail("complex: tok[10] not Word");
    }
    if toks[11] != Tok4::And {
        return TestResult::Fail("complex: tok[11] not And");
    }
    if toks[12] != Tok4::Word {
        return TestResult::Fail("complex: tok[12] not Word");
    }
    if toks[13] != Tok4::Word {
        return TestResult::Fail("complex: tok[13] not Word");
    }
    if toks[14] != Tok4::Eof {
        return TestResult::Fail("complex: tok[14] not Eof");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_parser_complex_pipeline);

// ── Smoke 30: pipe write+read via syscall layer with dup2 wiring ──────
//
// Full "echo hello | cat" plumbing at the syscall level:
//   1. pipe() → (rfd, wfd)
//   2. write("hello\n") to wfd (simulating echo's stdout)
//   3. dup2(rfd, 0) (simulating cat's stdin)
//   4. read(fd 0) → "hello\n"
//
// This is the kernel-layer proof that the pieces the exec engine
// calls actually compose correctly for a single-pipe command.

fn smoke_shell_pipe_exec_wiring() -> TestResult {
    crate::syscall::__test_clear_global();
    fd::__test_reset();
    fd::init();

    SHELL_TASK.store(0x5020, Ordering::Relaxed);
    install_task_id_lookup(shell_task_id);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // (1) Create pipe.
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
        return TestResult::Fail("pipe-exec-wiring: sys_pipe failed");
    }
    let rfd = pipe_fds[0] as u64;
    let wfd = pipe_fds[1] as u64;

    // (2) "echo side": write "hello\n" to the write-end.
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
        return TestResult::Fail("pipe-exec-wiring: write to wfd failed");
    }

    // (3) dup2(rfd, 0) — wire stdin to the read-end.
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
            return TestResult::Fail("pipe-exec-wiring: dup2(rfd,0) failed");
        }
    }

    // (4) "cat side": read from fd 0.
    let mut buf = [0u8; 16];
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
            return TestResult::Fail("pipe-exec-wiring: read from fd 0 failed");
        }
    };
    if n != payload.len() || &buf[..n] != payload {
        fd::__test_reset();
        crate::syscall::__test_clear_global();
        return TestResult::Fail("pipe-exec-wiring: payload mismatch on cat-side read");
    }

    fd::__test_reset();
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace/shell", smoke_shell_pipe_exec_wiring);
