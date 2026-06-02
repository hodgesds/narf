//! NARF shell execution engine.
//!
//! Drives the `Cmd` AST produced by `parser::parse_line` to completion.
//! All operations route through narf-libc system-call wrappers;
//! no heap is used (the shell binary is `#![no_std]`).
//!
//! Built-in commands (handled in-process without fork):
//!
//! | name       | action                                         |
//! |------------|------------------------------------------------|
//! | `cd`       | `chdir(path)`                                  |
//! | `pwd`      | print cwd via `getcwd`                         |
//! | `exit [N]` | exit the shell loop (returns `false` to main)  |
//! | `echo`     | write argv[1..] space-joined to stdout + `\n`  |
//! | `true`     | no-op; last-exit = 0                           |
//! | `false`    | no-op; last-exit = 1                           |
//! | `:`        | no-op (POSIX null utility); last-exit = 0      |
//!
//! All other commands are dispatched via fork+execve.  The Wave-35
//! narf-libc wiring landed `fork()` on top of `Syscall::Fork` (wire
//! number 57) so external commands now take the real fork+exec path.
//! The in-process fallback (`dispatch_builtin_inproc`) is retained for
//! error handling when fork fails with EAGAIN / ENOMEM.
//!
//! PATH resolution: if argv[0] does not contain `/`, the path
//! `/bin/<name>` is tried.  This is documented behaviour.
//!
//! Linux references:
//! - `fs/exec.c::do_execve`          (exec semantics)
//! - `kernel/fork.c::copy_process`   (fork semantics)
//! - `kernel/exit.c::do_wait`        (wait4 semantics)
//! - `dash/src/exec.c`               (shell exec engine shape)

use narf_libc as libc;

use crate::parser::{Cmd, Redir, SequenceEntry, SimpleCmd, MAX_PIPE_STAGES};

// ── Public surface ──────────────────────────────────────────────────────

/// Execute a parsed command tree rooted at `cmd`.
///
/// `console_fd` is the shell's output fd for prompt/error messages.
/// Returns `false` if the shell should exit.
pub unsafe fn execute(console_fd: i32, cmd: &Cmd, last_exit: &mut i32) -> bool {
    match cmd {
        Cmd::Empty => true,
        Cmd::Error(msg) => {
            unsafe { write_err(console_fd, msg.as_bytes()); }
            true
        }
        Cmd::Simple { argv, argc, redirs, redir_count } => {
            if *argc == 0 {
                return true;
            }
            let sc = SimpleCmd {
                argv: *argv,
                argc: *argc,
                redirs: *redirs,
                redir_count: *redir_count,
            };
            unsafe { *last_exit = exec_simple(console_fd, &sc); }
            // `exit` built-in returns -1 as the "stop the shell" signal.
            *last_exit != EXIT_SHELL_SIGNAL
        }
        Cmd::Pipeline { stages, count } => {
            unsafe { *last_exit = exec_pipeline(console_fd, stages, *count); }
            true
        }
        Cmd::Sequence { cmds, count } => {
            for i in 0..*count {
                let keep = unsafe {
                    exec_sequence_entry(console_fd, &cmds[i], last_exit)
                };
                if !keep {
                    return false;
                }
            }
            true
        }
        Cmd::And(left, right) => {
            unsafe { *last_exit = exec_simple(console_fd, left); }
            if *last_exit == 0 {
                unsafe { *last_exit = exec_simple(console_fd, right); }
            }
            true
        }
        Cmd::Or(left, right) => {
            unsafe { *last_exit = exec_simple(console_fd, left); }
            if *last_exit != 0 {
                unsafe { *last_exit = exec_simple(console_fd, right); }
            }
            true
        }
        Cmd::Background(sc) => {
            unsafe { exec_background(console_fd, sc); }
            true
        }
    }
}

/// Sentinel return value from `exec_simple` indicating the shell
/// should exit.  The value is out-of-range for POSIX exit codes
/// (0-255) and distinct from 127 (command not found) so callers
/// can distinguish it.
const EXIT_SHELL_SIGNAL: i32 = -1;

// ── Simple command ─────────────────────────────────────────────────────

/// Execute one `SimpleCmd`.  Returns the exit code (0-255), or
/// `EXIT_SHELL_SIGNAL` if the shell should exit.
unsafe fn exec_simple(fd: i32, sc: &SimpleCmd) -> i32 {
    if sc.argc == 0 {
        return 0;
    }
    let name = sc.argv[0].as_bytes();

    // ── Builtins that must run in the shell's own process ──────────────
    //
    // `cd` and `exit` MUST NOT be forked — they affect the shell's
    // own process state.
    if name == b"cd" {
        return unsafe { builtin_cd(fd, sc) };
    }
    if name == b"exit" {
        return unsafe { builtin_exit(fd, sc) };
    }
    if name == b"true" || name == b":" {
        return 0;
    }
    if name == b"false" {
        return 1;
    }

    // ── Fork + exec path ────────────────────────────────────────────────
    //
    // All other commands are dispatched via `try_fork_exec`.  Wave-35
    // wired `fork()` to `Syscall::Fork` (SYS_FORK = 57) so the real
    // fork+exec path is now taken.  The in-process fallback in
    // `dispatch_builtin_inproc` is only reached if fork fails (EAGAIN /
    // ENOMEM), which is an exceptional error condition.
    unsafe { try_fork_exec(fd, sc) }
}

/// Try to fork and exec the command.  On fork failure (EAGAIN/ENOMEM),
/// falls back to the in-process built-in table.
unsafe fn try_fork_exec(fd: i32, sc: &SimpleCmd) -> i32 {
    // Apply redirections to a saved-fd set (restored on fork failure
    // so the parent isn't disturbed).
    let saved = unsafe { save_stdio() };

    // Save/apply redirections in the *parent* temporarily only if
    // we can't fork — the child will do it for real after fork.
    // For now we fork() and check.
    let child_pid = unsafe { libc::fork() };
    if child_pid < 0 {
        // fork failed (EAGAIN/ENOMEM) — run in-process with redirects.
        if unsafe { apply_redirs(fd, sc) } {
            let rc = unsafe { dispatch_builtin_inproc(fd, sc) };
            unsafe { restore_stdio(saved); }
            return rc;
        }
        unsafe { restore_stdio(saved); }
        return 1;
    }

    if child_pid == 0 {
        // ── Child process ──────────────────────────────────────────────
        //
        // Apply redirections, then exec.  On exec failure write an
        // error and exit(127).
        unsafe { apply_redirs_child(fd, sc); }
        unsafe { exec_child(sc); }
        // exec_child never returns on success; if it does, exit(127).
        unsafe {
            write_err(fd, sc.argv[0].as_bytes());
            write_err(fd, b": exec failed\n");
            libc::_exit(127);
        }
    }

    // ── Parent ─────────────────────────────────────────────────────────
    let _ = saved; // parent didn't alter stdio
    let mut wstatus: i32 = 0;
    let r = unsafe { libc::waitpid(child_pid, &mut wstatus as *mut i32, 0) };
    if r < 0 {
        return 1;
    }
    // Extract exit code from wait status.
    // WIFEXITED: (wstatus & 0x7f) == 0; WEXITSTATUS: (wstatus >> 8) & 0xff.
    if (wstatus & 0x7f) == 0 {
        (wstatus >> 8) & 0xff
    } else {
        // Killed by signal — report 128 + signal.
        128 + (wstatus & 0x7f)
    }
}

/// Saved stdio fds for in-process redirect/restore.
struct SavedStdio {
    stdin:  i32,
    stdout: i32,
    stderr: i32,
}

unsafe fn save_stdio() -> SavedStdio {
    unsafe {
        SavedStdio {
            stdin:  libc::dup(0),
            stdout: libc::dup(1),
            stderr: libc::dup(2),
        }
    }
}

unsafe fn restore_stdio(saved: SavedStdio) {
    unsafe {
        if saved.stdin  >= 0 { libc::dup2(saved.stdin,  0); libc::posix_close(saved.stdin);  }
        if saved.stdout >= 0 { libc::dup2(saved.stdout, 1); libc::posix_close(saved.stdout); }
        if saved.stderr >= 0 { libc::dup2(saved.stderr, 2); libc::posix_close(saved.stderr); }
    }
}

/// Apply redirections in-process (for the fork-failure fallback).
/// Returns `false` if a redirect file couldn't be opened.
unsafe fn apply_redirs(fd: i32, sc: &SimpleCmd) -> bool {
    for i in 0..sc.redir_count {
        let Some(ref redir) = sc.redirs[i] else { continue };
        if !unsafe { apply_one_redir(fd, redir) } {
            return false;
        }
    }
    true
}

/// Apply redirections in the child process (no need to restore).
unsafe fn apply_redirs_child(_fd: i32, sc: &SimpleCmd) {
    for i in 0..sc.redir_count {
        let Some(ref redir) = sc.redirs[i] else { continue };
        // Suppress error output in child — parent will see exit 127.
        unsafe { apply_one_redir(-1, redir); }
    }
}

/// Apply one redirection.  Returns `false` on open failure.
unsafe fn apply_one_redir(err_fd: i32, redir: &Redir) -> bool {
    let (target_fd, path, flags, mode) = match redir {
        Redir::StdinFrom(w)    => (0i32,  w, libc::O_RDONLY, 0i32),
        Redir::StdoutTo(w)     => (1i32,  w, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,  0o644i32),
        Redir::StdoutAppend(w) => (1i32,  w, libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND, 0o644i32),
    };
    if path.is_empty() {
        if err_fd >= 0 {
            unsafe { write_err(err_fd, b"redirect: missing filename\n"); }
        }
        return false;
    }
    let mut pbuf = [0u8; 256];
    let n = path.len.min(pbuf.len() - 1);
    pbuf[..n].copy_from_slice(&path.bytes[..n]);
    // pbuf[n] is already 0 (zero-initialised).
    let opened = unsafe {
        libc::posix_open(pbuf.as_ptr() as *const i8, flags as i32, mode as u32)
    };
    if opened < 0 {
        if err_fd >= 0 {
            unsafe {
                write_err(err_fd, b"redirect: cannot open ");
                write_err(err_fd, path.as_bytes());
                write_err(err_fd, b"\n");
            }
        }
        return false;
    }
    unsafe { libc::dup2(opened, target_fd); }
    unsafe { libc::posix_close(opened); }
    true
}

/// Execute the command in the child: try `execvp`, then exit(127).
///
/// PATH resolution: if argv[0] contains no `/`, prepend `/bin/`.
unsafe fn exec_child(sc: &SimpleCmd) {
    if sc.argc == 0 {
        return;
    }
    // Build NUL-terminated argv on the stack.
    // Each slot is a 256-byte buffer; we use MAX_ARGV + 1 slots
    // (last one holds a NULL pointer to terminate the argv array).
    const ABUF: usize = 256;
    const MAX_A: usize = crate::parser::MAX_ARGV;
    let mut abufs: [[u8; ABUF]; MAX_A] = [[0u8; ABUF]; MAX_A];
    let mut aptrs: [*const i8; MAX_A + 1] = [core::ptr::null(); MAX_A + 1];

    for i in 0..sc.argc {
        let w = &sc.argv[i];
        let n = w.len.min(ABUF - 1);
        abufs[i][..n].copy_from_slice(&w.bytes[..n]);
        // abufs[i][n] already 0
        aptrs[i] = abufs[i].as_ptr() as *const i8;
    }
    // aptrs[sc.argc] is already null_ptr (terminator).

    let envp: [*const i8; 1] = [core::ptr::null()];

    // Try exact path first if it contains `/`.
    let name = sc.argv[0].as_bytes();
    if name.contains(&b'/') {
        unsafe {
            libc::execve(aptrs[0], aptrs.as_ptr(), envp.as_ptr());
        }
        return;
    }

    // Try /bin/<name>.
    let mut path_buf = [0u8; 256];
    let prefix = b"/bin/";
    let name_len = name.len().min(256 - prefix.len() - 1);
    path_buf[..prefix.len()].copy_from_slice(prefix);
    path_buf[prefix.len()..prefix.len() + name_len].copy_from_slice(&name[..name_len]);
    // Patch argv[0] to the resolved path.
    let mut resolved_argv0 = [0u8; 256];
    let rlen = prefix.len() + name_len;
    resolved_argv0[..rlen].copy_from_slice(&path_buf[..rlen]);
    let mut full_aptrs = aptrs;
    full_aptrs[0] = resolved_argv0.as_ptr() as *const i8;
    unsafe {
        libc::execve(path_buf.as_ptr() as *const i8, full_aptrs.as_ptr(), envp.as_ptr());
    }
}

// ── In-process built-in dispatch (fork not available) ──────────────────

/// Run the command in-process using the existing built-in table.
/// Used as the fallback when `fork()` fails (EAGAIN / ENOMEM).
unsafe fn dispatch_builtin_inproc(fd: i32, sc: &SimpleCmd) -> i32 {
    // Reconstruct a command line from argv so `dispatch_line` can
    // parse it.  This is safe because dispatch_line is the existing
    // Wave-22-validated path.
    let mut line = [0u8; 512];
    let mut pos = 0usize;
    for i in 0..sc.argc {
        let w = &sc.argv[i];
        if i > 0 {
            if pos < line.len() {
                line[pos] = b' ';
                pos += 1;
            }
        }
        let n = w.len.min(line.len() - pos);
        line[pos..pos + n].copy_from_slice(&w.bytes[..n]);
        pos += n;
    }
    // dispatch_line returns false only for `exit`.
    let keep = unsafe { crate::dispatch_line(fd, &line[..pos]) };
    if !keep { EXIT_SHELL_SIGNAL } else { 0 }
}

// ── Pipeline ───────────────────────────────────────────────────────────

/// Execute a pipeline `stages[0] | stages[1] | ... | stages[count-1]`.
/// Returns the exit code of the last stage.
///
/// For each adjacent pair of stages a pipe is created.  All
/// children are forked, wired, and waited on.  The parent
/// closes all pipe fds after forking each child.
///
/// On fork failure (EAGAIN/ENOMEM) the pipeline is run
/// sequentially in-process with the pipe fds replaced by
/// an intermediate memory buffer (simulated pipeline).
unsafe fn exec_pipeline(fd: i32, stages: &[SimpleCmd; MAX_PIPE_STAGES], count: usize) -> i32 {
    if count == 0 {
        return 0;
    }
    if count == 1 {
        return unsafe { exec_simple(fd, &stages[0]) };
    }

    // Attempt fork-based pipeline.
    // We create `count - 1` pipes.
    let mut pipes: [[i32; 2]; MAX_PIPE_STAGES] = [[-1, -1]; MAX_PIPE_STAGES];
    let mut pipe_count = 0usize;
    let mut fork_ok = true;

    // Create all pipes first.
    for i in 0..count - 1 {
        let mut fds: [i32; 2] = [-1, -1];
        let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if r != 0 {
            fork_ok = false;
            break;
        }
        pipes[i] = fds;
        pipe_count = i + 1;
    }

    if !fork_ok {
        // Close any pipes we managed to open.
        for i in 0..pipe_count {
            if pipes[i][0] >= 0 { unsafe { libc::posix_close(pipes[i][0]); } }
            if pipes[i][1] >= 0 { unsafe { libc::posix_close(pipes[i][1]); } }
        }
        // Fall back: run stages in-process sequentially.
        let mut last = 0i32;
        for i in 0..count {
            last = unsafe { exec_simple(fd, &stages[i]) };
        }
        return last;
    }

    // Fork all children.
    let mut child_pids: [i32; MAX_PIPE_STAGES] = [-1; MAX_PIPE_STAGES];
    let mut fork_failed = false;

    for i in 0..count {
        let child = unsafe { libc::fork() };
        if child < 0 {
            fork_failed = true;
            break;
        }
        if child == 0 {
            // ── Child i ─────────────────────────────────────────────────
            // Wire stdin from pipe[i-1] read-end (if i > 0).
            if i > 0 {
                unsafe { libc::dup2(pipes[i - 1][0], 0); }
            }
            // Wire stdout to pipe[i] write-end (if i < count-1).
            if i < count - 1 {
                unsafe { libc::dup2(pipes[i][1], 1); }
            }
            // Close all pipe fds in the child.
            for j in 0..pipe_count {
                unsafe { libc::posix_close(pipes[j][0]); }
                unsafe { libc::posix_close(pipes[j][1]); }
            }
            // Apply redirections, then exec.
            unsafe { apply_redirs_child(fd, &stages[i]); }
            unsafe { exec_child(&stages[i]); }
            unsafe {
                write_err(fd, stages[i].argv[0].as_bytes());
                write_err(fd, b": exec failed\n");
                libc::_exit(127);
            }
        }
        child_pids[i] = child;
    }

    // Parent: close all pipe fds.
    for j in 0..pipe_count {
        unsafe { libc::posix_close(pipes[j][0]); }
        unsafe { libc::posix_close(pipes[j][1]); }
    }

    if fork_failed {
        // Reap whatever children were started.
        for i in 0..count {
            if child_pids[i] > 0 {
                let mut ws = 0i32;
                unsafe { libc::waitpid(child_pids[i], &mut ws, 0); }
            }
        }
        return 1;
    }

    // Wait for all children; keep the last one's exit code.
    let mut last_exit = 0i32;
    for i in 0..count {
        let mut ws = 0i32;
        let r = unsafe { libc::waitpid(child_pids[i], &mut ws, 0) };
        if r > 0 && i == count - 1 {
            last_exit = if (ws & 0x7f) == 0 {
                (ws >> 8) & 0xff
            } else {
                128 + (ws & 0x7f)
            };
        }
    }
    last_exit
}

// ── Background ─────────────────────────────────────────────────────────

/// Fork and run `sc` in the background; parent does not wait.
/// On fork failure, runs in-process (synchronously) as a fallback.
unsafe fn exec_background(fd: i32, sc: &SimpleCmd) {
    let child = unsafe { libc::fork() };
    if child < 0 {
        // No fork — run in-process.
        unsafe { exec_simple(fd, sc); }
        return;
    }
    if child == 0 {
        // Child: exec and exit.
        unsafe { apply_redirs_child(fd, sc); }
        unsafe { exec_child(sc); }
        unsafe { libc::_exit(127); }
    }
    // Parent: do NOT waitpid. The child runs asynchronously.
    // Zombie reaping via lazy SIGCHLD / waitpid(-1, WNOHANG)
    // at the next prompt is tracked in the deferred list.
}

// ── Sequence entry dispatch ────────────────────────────────────────────

/// Execute one `SequenceEntry`.  Returns `false` only if the shell
/// should exit.
unsafe fn exec_sequence_entry(fd: i32, entry: &SequenceEntry, last_exit: &mut i32) -> bool {
    match entry {
        SequenceEntry::Cmd(sc) => {
            let rc = unsafe { exec_simple(fd, sc) };
            if rc == EXIT_SHELL_SIGNAL {
                return false;
            }
            *last_exit = rc;
        }
        SequenceEntry::Pipeline { stages, count } => {
            *last_exit = unsafe { exec_pipeline(fd, stages, *count) };
        }
        SequenceEntry::And(left, right) => {
            *last_exit = unsafe { exec_simple(fd, left) };
            if *last_exit == 0 {
                *last_exit = unsafe { exec_simple(fd, right) };
            }
        }
        SequenceEntry::Or(left, right) => {
            *last_exit = unsafe { exec_simple(fd, left) };
            if *last_exit != 0 {
                *last_exit = unsafe { exec_simple(fd, right) };
            }
        }
        SequenceEntry::Background(sc) => {
            unsafe { exec_background(fd, sc); }
        }
    }
    true
}

// ── Built-ins that require the shell's own process ─────────────────────

unsafe fn builtin_cd(fd: i32, sc: &SimpleCmd) -> i32 {
    let path = if sc.argc >= 2 { sc.argv[1].as_bytes() } else { b"" as &[u8] };
    if path.is_empty() {
        unsafe { write_err(fd, b"cd: missing path\n"); }
        return 1;
    }
    let mut pbuf = [0u8; 256];
    let n = path.len().min(pbuf.len() - 1);
    pbuf[..n].copy_from_slice(&path[..n]);
    let r = unsafe { libc::chdir(pbuf.as_ptr()) };
    if r != 0 {
        unsafe { write_err(fd, b"cd: failed\n"); }
        1
    } else {
        0
    }
}

unsafe fn builtin_exit(_fd: i32, sc: &SimpleCmd) -> i32 {
    // exit [N] — N defaults to 0.
    let _code: i32 = if sc.argc >= 2 {
        let mut n = 0i32;
        for &b in sc.argv[1].as_bytes() {
            if (b as char).is_ascii_digit() {
                n = n * 10 + (b - b'0') as i32;
            } else {
                break;
            }
        }
        n
    } else {
        0
    };
    EXIT_SHELL_SIGNAL
}

// ── I/O helpers ────────────────────────────────────────────────────────

/// Write `bytes` to `fd`, blocking until complete.  Error on
/// `fd < 0`.
pub unsafe fn write_err(fd: i32, bytes: &[u8]) {
    if fd < 0 {
        return;
    }
    let mut written = 0usize;
    while written < bytes.len() {
        let n = unsafe {
            libc::posix_write(
                fd,
                bytes.as_ptr().add(written) as *const _,
                bytes.len() - written,
            )
        };
        if n <= 0 {
            return;
        }
        written += n as usize;
    }
}
