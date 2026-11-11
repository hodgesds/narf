//! Linux syscall ABI conformance — what `/proc/<pid>/fd/<n>` names.
//!
//! On Linux the link is `d_path(&file->f_path)`: the open file itself knows
//! what it names, so every descriptor that refers to it — a `dup`, a thread
//! of the process, a forked child, another process holding it — reads the
//! same string, the string follows a rename, and an unlinked file reads
//! `<path> (deleted)`. A file with no name in any mounted filesystem reads
//! its class instead (`pipe:[ino]`, `socket:[ino]`, `anon_inode:[eventfd]`,
//! `/memfd:<name> (deleted)`), never a placeholder.
//!
//! Programs resolve real paths this way. Bun's `fs.realpath` opens the file
//! `O_PATH` on a worker thread and reads the link; with a placeholder for an
//! answer it created its lock directory `anon_inode:[FileOps].lock` in the
//! current directory instead of next to its config file. glibc `ttyname`,
//! `fexecve`, `fchmodat(AT_SYMLINK_NOFOLLOW)` and systemd's `fd_get_path` /
//! `fd_reopen` read or reopen the same link.

use crate::abi_test_support::*;
use alloc::string::String;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;
const O_DIRECTORY: u64 = 0o200_000;
const O_NOFOLLOW: u64 = 0o400_000;
const O_CLOEXEC: u64 = 0o2_000_000;
const O_PATH: u64 = 0o10_000_000;
const O_TMPFILE: u64 = 0o20_000_000 | O_DIRECTORY;
const F_DUPFD: u64 = 0;
const F_DUPFD_CLOEXEC: u64 = 1030;

/// A second task of the fixture process (a `CLONE_FILES` thread) and a
/// second process.
const THREAD: u64 = FAKE_TASK + 21;
const OTHER: u64 = FAKE_TASK + 22;

fn open(path: &str, flags: u64, what: &'static str) -> Result<u64, &'static str> {
    let path = alloc::format!("{path}\0");
    match call(
        Syscall::Openat.raw(),
        a3(AT_FDCWD, path.as_ptr() as u64, flags, 0o644),
    ) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err(what),
    }
}

fn close(fd: u64) {
    let _ = call(Syscall::Close.raw(), a0(fd));
}

fn new_fd(r: Option<i64>, what: &'static str) -> Result<u64, &'static str> {
    match r {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err(what),
    }
}

/// `readlink("/proc/<who>/fd/<fd>")`.
fn link_at(who: &str, fd: u64) -> Result<String, &'static str> {
    let link = alloc::format!("/proc/{who}/fd/{fd}\0");
    let mut buf = [0u8; 256];
    match call_readlink(link.as_ptr() as u64, buf.as_mut_ptr() as u64, 255) {
        Some(n) if n > 0 => core::str::from_utf8(&buf[..n as usize])
            .map(String::from)
            .map_err(|_| "the fd link is not UTF-8"),
        _ => Err("readlink(/proc/<pid>/fd/N) failed"),
    }
}

fn link_of(fd: u64) -> Result<String, &'static str> {
    link_at("self", fd)
}

fn expect(fd: u64, want: &str, msg: &'static str) -> Result<(), &'static str> {
    if link_of(fd)? == want {
        Ok(())
    } else {
        Err(msg)
    }
}

fn st_ino(fd: u64) -> Result<u64, &'static str> {
    let mut sb = [0u8; 256];
    if call(Syscall::Fstat.raw(), a1(fd, sb.as_mut_ptr() as u64)) != Some(0) {
        return Err("fstat failed");
    }
    Ok(u64::from_ne_bytes(sb[8..16].try_into().unwrap()))
}

fn mkdir(path: &str) -> bool {
    let path = alloc::format!("{path}\0");
    call_mkdir(path.as_ptr() as u64, 0o755) == Some(0)
}

fn rename(old: &str, new: &str) -> bool {
    let (old, new) = (alloc::format!("{old}\0"), alloc::format!("{new}\0"));
    call_rename(old.as_ptr() as u64, new.as_ptr() as u64) == Some(0)
}

fn unlink(path: &str) -> bool {
    let path = alloc::format!("{path}\0");
    call_unlink(path.as_ptr() as u64) == Some(0)
}

fn symlink(target: &str, link: &str) -> bool {
    let (target, link) = (alloc::format!("{target}\0"), alloc::format!("{link}\0"));
    call_symlink(target.as_ptr() as u64, link.as_ptr() as u64) == Some(0)
}

fn create(path: &str) -> bool {
    match open(path, O_CREAT | O_WRONLY, "create") {
        Ok(fd) => {
            close(fd);
            true
        }
        Err(_) => false,
    }
}

/// A tmpfs at `/pf` holding `f`, `d/f`, the symlinks `l -> /pf/d/f` and
/// `dl -> d`, with the procfs fd-link hook installed for the body.
fn with_fs(body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    with_tmpfs("/pf", "size=1M", || {
        let prev = narf_filesystem::procfs::__test_fd_path_hook_snapshot();
        narf_filesystem::procfs::__test_fd_path_hook_restore(crate::handlers::fd_path_of as usize);
        let seeded = create("/pf/f")
            && mkdir("/pf/d")
            && create("/pf/d/f")
            && symlink("/pf/d/f", "/pf/l")
            && symlink("d", "/pf/dl");
        let outcome = if seeded {
            body()
        } else {
            Err("fixture: could not seed the tmpfs")
        };
        narf_filesystem::procfs::__test_fd_path_hook_restore(prev);
        outcome
    })
}

/// [`with_setup`] with the procfs fd-link hook installed, for the cases that
/// need no filesystem of their own.
fn with_links(body: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    with_setup(|| {
        let prev = narf_filesystem::procfs::__test_fd_path_hook_snapshot();
        narf_filesystem::procfs::__test_fd_path_hook_restore(crate::handlers::fd_path_of as usize);
        let outcome = body();
        narf_filesystem::procfs::__test_fd_path_hook_restore(prev);
        outcome
    })
}

/// Make `pid` a live process of its own (as `fork` would) whose descriptor
/// table is a copy of the fixture task's.
fn fork_process(pid: u64) {
    crate::fd::fork(FAKE_TASK, pid);
    crate::handlers::register_task_to_pid(pid, pid);
    crate::handlers::register_pid_task_mapping(pid, pid);
    if crate::task::task_get(pid).is_none() {
        let _ = crate::task::Task::new_registered(pid, pid);
    }
    crate::handlers::set_proc_comm(pid, "procfd-child");
    crate::handlers::set_proc_argv(pid, &["procfd-child"]);
    crate::handlers::__test_inject_parent_of(pid, FAKE_TASK);
}

fn reap_process(pid: u64) {
    set_task(FAKE_TASK);
    crate::fd::detach(pid);
    crate::handlers::release_reaped_task(pid);
    crate::handlers::__test_forget_task_pid(pid);
}

// ───────────────────────── opened by path ─────────────────────────

/// Bun `fs.realpath`: `open(path, O_PATH|O_CLOEXEC)` then
/// `readlink("/proc/self/fd/N")`.
fn smoke_abi_procfd_o_path_names_the_file() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d/f", O_PATH | O_CLOEXEC, "open(O_PATH) failed")?;
        let r = expect(
            fd,
            "/pf/d/f",
            "an O_PATH descriptor is not named by its path",
        );
        close(fd);
        r
    })
}
kernel_test_in!("syscall_abi/procfd", smoke_abi_procfd_o_path_names_the_file);

/// `open(path, O_RDONLY)` and `open(dir, O_DIRECTORY)`.
fn smoke_abi_procfd_rdonly_names_file_and_directory() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/f", O_RDONLY, "open(O_RDONLY) failed")?;
        let dir = open("/pf/d", O_RDONLY | O_DIRECTORY, "open(O_DIRECTORY) failed")?;
        let r = expect(
            fd,
            "/pf/f",
            "a read-only descriptor is not named by its path",
        )
        .and_then(|()| {
            expect(
                dir,
                "/pf/d",
                "a directory descriptor is not named by its path",
            )
        });
        close(dir);
        close(fd);
        r
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_rdonly_names_file_and_directory
);

/// `openat(dirfd, "name")` and `openat(dirfd, "../name")`: the name is the
/// file's own path, whatever it was opened relative to.
fn smoke_abi_procfd_openat_relative_to_dirfd() -> TestResult {
    with_fs(|| {
        let dir = open("/pf/d", O_RDONLY | O_DIRECTORY, "open(O_DIRECTORY) failed")?;
        let at = |name: &[u8], what| {
            new_fd(
                call(
                    Syscall::Openat.raw(),
                    a3(dir, name.as_ptr() as u64, O_RDONLY, 0),
                ),
                what,
            )
        };
        let inner = at(b"f\0", "openat(dirfd, \"f\") failed");
        let outer = at(b"../f\0", "openat(dirfd, \"../f\") failed");
        let r = inner
            .and_then(|fd| expect(fd, "/pf/d/f", "openat(dirfd, name) is not named dir/name"))
            .and(outer)
            .and_then(|fd| expect(fd, "/pf/f", "openat(dirfd, ../name) is not normalised"));
        for fd in [inner, outer].into_iter().flatten() {
            close(fd);
        }
        close(dir);
        r
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_openat_relative_to_dirfd
);

/// `O_CREAT` and `creat(2)` name the file they made.
fn smoke_abi_procfd_created_file_is_named() -> TestResult {
    with_fs(|| {
        let made = open("/pf/new", O_CREAT | O_RDWR, "open(O_CREAT) failed")?;
        let path = b"/pf/new2\0";
        let creat = new_fd(
            call(Syscall::Creat.raw(), a1(path.as_ptr() as u64, 0o644)),
            "creat failed",
        );
        let r = expect(
            made,
            "/pf/new",
            "an O_CREAT descriptor is not named by its path",
        )
        .and(creat)
        .and_then(|fd| {
            expect(
                fd,
                "/pf/new2",
                "a creat() descriptor is not named by its path",
            )
        });
        if let Ok(fd) = creat {
            close(fd);
        }
        close(made);
        r
    })
}
kernel_test_in!("syscall_abi/procfd", smoke_abi_procfd_created_file_is_named);

/// The name is the resolved path: a final symlink is followed (and kept with
/// `O_PATH|O_NOFOLLOW`), a symlinked directory and `..` are resolved away.
fn smoke_abi_procfd_symlinks_and_dotdot_resolve() -> TestResult {
    with_fs(|| {
        let cases: [(&str, u64, &str, &'static str); 4] = [
            (
                "/pf/l",
                O_RDONLY,
                "/pf/d/f",
                "a final symlink was not resolved in the name",
            ),
            (
                "/pf/dl/f",
                O_RDONLY,
                "/pf/d/f",
                "a symlinked directory was not resolved",
            ),
            (
                "/pf/d/../f",
                O_RDONLY,
                "/pf/f",
                "`..` was not resolved in the name",
            ),
            (
                "/pf/l",
                O_PATH | O_NOFOLLOW,
                "/pf/l",
                "O_PATH|O_NOFOLLOW does not name the symlink itself",
            ),
        ];
        for (path, flags, want, msg) in cases {
            let fd = open(path, flags, "open through a symlink failed")?;
            let r = expect(fd, want, msg);
            close(fd);
            r?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_symlinks_and_dotdot_resolve
);

/// Reopening through the magic link (`fd_reopen`, `fexecve`) names the real
/// file, not the procfs path.
fn smoke_abi_procfd_reopen_through_magic_links() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d/f", O_PATH | O_CLOEXEC, "open(O_PATH) failed")?;
        let re = open(
            &alloc::format!("/proc/self/fd/{fd}"),
            O_RDONLY,
            "reopen through /proc/self/fd/N failed",
        );
        let r = re.and_then(|fd| {
            expect(
                fd,
                "/pf/d/f",
                "a reopened descriptor is not named by the file",
            )
        });
        if let Ok(re) = re {
            close(re);
        }
        close(fd);
        r
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_reopen_through_magic_links
);

/// `O_TMPFILE`: `d_tmpfile` names the unlinked inode `#<ino>` in the
/// directory it was made in, so the link reads `<dir>/#<ino> (deleted)`.
fn smoke_abi_procfd_tmpfile_is_hash_ino_deleted() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d", O_TMPFILE | O_RDWR, "open(O_TMPFILE) failed")?;
        let want = st_ino(fd).map(|ino| alloc::format!("/pf/d/#{ino} (deleted)"));
        let got = link_of(fd);
        close(fd);
        if got? != want? {
            return Err("an O_TMPFILE descriptor is not named <dir>/#<ino> (deleted)");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_tmpfile_is_hash_ino_deleted
);

// ─────────────────── every descriptor of the open file ───────────────────

/// `dup`, `dup2`, `dup3`, `F_DUPFD` and `F_DUPFD_CLOEXEC` are the same open
/// file and read the same name, also after the first descriptor is closed.
/// A descriptor number that is reused takes the name of its new file.
fn smoke_abi_procfd_dup_family_shares_the_name() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d/f", O_RDONLY, "open failed")?;
        let dups = [
            new_fd(call(Syscall::Dup.raw(), a0(fd)), "dup failed"),
            new_fd(call_dup2(fd, 40), "dup2 failed"),
            new_fd(
                call(Syscall::Dup3.raw(), a2(fd, 41, O_CLOEXEC)),
                "dup3 failed",
            ),
            new_fd(
                call(Syscall::Fcntl.raw(), a2(fd, F_DUPFD, 50)),
                "F_DUPFD failed",
            ),
            new_fd(
                call(Syscall::Fcntl.raw(), a2(fd, F_DUPFD_CLOEXEC, 60)),
                "F_DUPFD_CLOEXEC failed",
            ),
        ];
        close(fd);
        let mut r = Ok(());
        for dup in dups {
            r = r.and(dup).and_then(|dup| {
                expect(dup, "/pf/d/f", "a duplicate does not read the file's name")
            });
        }
        // dup2 of an unnamed file over a named descriptor: the number now
        // names the unnamed file.
        let event = new_fd(call(Syscall::Eventfd.raw(), a1(0, 0)), "eventfd failed");
        let r = r.and(event).and_then(|event| {
            new_fd(call_dup2(event, 40), "dup2 over a named descriptor failed")?;
            expect(
                40,
                "anon_inode:[eventfd]",
                "a reused descriptor kept its old file's name",
            )
        });
        if let Ok(event) = event {
            close(event);
        }
        for dup in dups.into_iter().flatten() {
            close(dup);
        }
        r
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_dup_family_shares_the_name
);

/// The failure that made Bun create `anon_inode:[FileOps].lock`: a thread
/// other than the leader opens the file and reads `/proc/self/fd/N`. The
/// descriptor table is the process's, so the link names the file whichever
/// thread opened it and whichever thread asks — and a directory descriptor
/// opened by one thread anchors another thread's `openat`.
fn smoke_abi_procfd_thread_open_is_named_for_the_process() -> TestResult {
    with_fs(|| {
        let dir = open("/pf/d", O_PATH | O_DIRECTORY, "open(dir) failed")?;
        crate::fd::share(FAKE_TASK, THREAD);
        crate::handlers::register_task_to_pid(THREAD, FAKE_TASK);
        set_task(THREAD);
        let opened = open("/pf/f", O_PATH | O_CLOEXEC, "open in a thread failed");
        let in_thread = opened.and_then(link_of);
        let at = new_fd(
            call(
                Syscall::Openat.raw(),
                a3(dir, c"f".as_ptr() as u64, O_RDONLY, 0),
            ),
            "openat on the leader's directory descriptor failed in a thread",
        );
        let at_link = at.and_then(link_of);
        set_task(FAKE_TASK);
        let in_leader = opened.and_then(link_of);
        crate::fd::detach(THREAD);
        crate::handlers::__test_forget_task_pid(THREAD);
        for fd in [opened, at].into_iter().flatten() {
            close(fd);
        }
        close(dir);
        if in_thread? != "/pf/f" {
            return Err("/proc/self/fd/N is not the path for a file a thread opened");
        }
        if in_leader? != "/pf/f" {
            return Err("the leader does not read the path of a file a thread opened");
        }
        if at_link? != "/pf/d/f" {
            return Err("openat on another thread's directory descriptor lost the path");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_thread_open_is_named_for_the_process
);

/// `tid_base_stuff` has `fd` too: `/proc/thread-self/fd/N` is the link
/// `/proc/self/fd/N` is, to read and to reopen through.
fn smoke_abi_procfd_thread_self_fd_is_the_same_link() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d/f", O_PATH | O_CLOEXEC, "open(O_PATH) failed")?;
        let link = link_at("thread-self", fd);
        let re = open(
            &alloc::format!("/proc/thread-self/fd/{fd}"),
            O_RDONLY,
            "reopen through /proc/thread-self/fd/N failed",
        );
        let reopened = re.and_then(link_of);
        if let Ok(re) = re {
            close(re);
        }
        close(fd);
        if link? != "/pf/d/f" {
            return Err("/proc/thread-self/fd/N does not name the file");
        }
        if reopened? != "/pf/d/f" {
            return Err("a reopen through /proc/thread-self/fd/N is not named by the file");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_thread_self_fd_is_the_same_link
);

/// A forked child holds the same open files: it reads their names through
/// `/proc/self/fd`, and its parent reads them through `/proc/<child>/fd`.
fn smoke_abi_procfd_fork_child_and_other_readers() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d/f", O_RDONLY, "open failed")?;
        fork_process(OTHER);
        let from_parent = link_at(&alloc::format!("{OTHER}"), fd);
        set_task(OTHER);
        let in_child = link_of(fd);
        reap_process(OTHER);
        close(fd);
        if in_child? != "/pf/d/f" {
            return Err("a forked child does not read the name of an inherited file");
        }
        if from_parent? != "/pf/d/f" {
            return Err("/proc/<child>/fd/N does not name the child's file");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_fork_child_and_other_readers
);

// ─────────────────────── the name follows the file ───────────────────────

/// `d_move`: after `rename(2)` of the file, of its directory, or into another
/// directory, the link reads the new path.
fn smoke_abi_procfd_rename_is_followed() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/f", O_RDONLY, "open failed")?;
        let dir = open("/pf/d", O_RDONLY | O_DIRECTORY, "open(dir) failed")?;
        let inner = open("/pf/d/f", O_RDONLY, "open(d/f) failed")?;
        let r = (|| {
            if !rename("/pf/f", "/pf/g") {
                return Err("fixture: rename failed");
            }
            expect(fd, "/pf/g", "the link does not follow a rename of the file")?;
            if !rename("/pf/g", "/pf/d/h") {
                return Err("fixture: rename into another directory failed");
            }
            expect(
                fd,
                "/pf/d/h",
                "the link does not follow a rename across directories",
            )?;
            if !rename("/pf/d", "/pf/e") {
                return Err("fixture: rename of the directory failed");
            }
            expect(
                dir,
                "/pf/e",
                "a directory's link does not follow its rename",
            )?;
            expect(
                inner,
                "/pf/e/f",
                "the link does not follow a rename of the parent",
            )?;
            expect(
                fd,
                "/pf/e/h",
                "a moved file does not follow a rename of its new parent",
            )
        })();
        close(inner);
        close(dir);
        close(fd);
        r
    })
}
kernel_test_in!("syscall_abi/procfd", smoke_abi_procfd_rename_is_followed);

/// `d_unlinked`: an unlinked file, a file replaced by a rename and a removed
/// directory read `<path> (deleted)`; a new file made at the same path does
/// not.
fn smoke_abi_procfd_unlink_reads_deleted() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/f", O_RDONLY, "open failed")?;
        let target = open("/pf/d/f", O_RDONLY, "open(d/f) failed")?;
        let r = (|| {
            if !unlink("/pf/f") {
                return Err("fixture: unlink failed");
            }
            expect(
                fd,
                "/pf/f (deleted)",
                "an unlinked file does not read (deleted)",
            )?;
            let again = open("/pf/f", O_CREAT | O_RDWR, "recreate failed")?;
            let fresh = expect(
                again,
                "/pf/f",
                "a file made at an unlinked path reads (deleted)",
            );
            let old = expect(
                fd,
                "/pf/f (deleted)",
                "recreating the path revived the old link",
            );
            if !rename("/pf/f", "/pf/d/f") {
                close(again);
                return Err("fixture: rename over an open file failed");
            }
            let replaced = expect(
                target,
                "/pf/d/f (deleted)",
                "a file replaced by rename does not read (deleted)",
            );
            let moved = expect(
                again,
                "/pf/d/f",
                "the replacing file does not read the new path",
            );
            close(again);
            fresh.and(old).and(replaced).and(moved)?;
            if !mkdir("/pf/gone") {
                return Err("fixture: mkdir failed");
            }
            let gone = open("/pf/gone", O_RDONLY | O_DIRECTORY, "open(dir) failed")?;
            let path = b"/pf/gone\0";
            let removed = call_rmdir(path.as_ptr() as u64) == Some(0);
            let r = expect(
                gone,
                "/pf/gone (deleted)",
                "a removed directory does not read (deleted)",
            );
            close(gone);
            if !removed {
                return Err("fixture: rmdir failed");
            }
            r
        })();
        close(target);
        close(fd);
        r
    })
}
kernel_test_in!("syscall_abi/procfd", smoke_abi_procfd_unlink_reads_deleted);

// ─────────────────────── files with no path ───────────────────────

/// `pipefs_dname` / `sockfs_dname`: `pipe:[ino]` and `socket:[ino]`, with the
/// inode `fstat` reports.
fn smoke_abi_procfd_pipe_and_socket_read_class_and_inode() -> TestResult {
    with_links(|| {
        let mut fds = [0i32; 2];
        if call(Syscall::Pipe2.raw(), a1(fds.as_mut_ptr() as u64, 0)) != Some(0) {
            return Err("pipe2 failed");
        }
        let sock = new_fd(
            call(Syscall::SocketOpen.raw(), a2(1, 1, 0)),
            "socket failed",
        );
        let mut pair = [0i32; 2];
        let paired = call(
            Syscall::SocketPair.raw(),
            a3(1, 1, 0, pair.as_mut_ptr() as u64),
        ) == Some(0);
        let mut r = Ok(());
        for (fd, class) in [
            (Ok(fds[0] as u64), "pipe"),
            (Ok(fds[1] as u64), "pipe"),
            (sock, "socket"),
            (Ok(pair[0] as u64), "socket"),
        ] {
            r = r.and(fd).and_then(|fd| {
                let want = alloc::format!("{class}:[{}]", st_ino(fd)?);
                expect(
                    fd,
                    &want,
                    "a pipe or socket does not read <class>:[<st_ino>]",
                )
            });
        }
        for fd in [fds[0], fds[1], pair[0], pair[1]] {
            close(fd as u64);
        }
        if let Ok(sock) = sock {
            close(sock);
        }
        if !paired {
            return Err("socketpair failed");
        }
        r
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_pipe_and_socket_read_class_and_inode
);

/// `anon_inode_getfile(name, …)`: each anonymous-inode file reads the class
/// name its creator gives it on Linux.
fn smoke_abi_procfd_anon_inode_classes() -> TestResult {
    with_links(|| {
        let mask = [0u8; 8];
        let cases: [(Option<i64>, &str, &'static str); 7] = [
            (
                call(Syscall::Eventfd.raw(), a1(0, 0)),
                "anon_inode:[eventfd]",
                "eventfd is not anon_inode:[eventfd]",
            ),
            (
                call(Syscall::EpollCreate.raw(), a0(0)),
                "anon_inode:[eventpoll]",
                "epoll is not anon_inode:[eventpoll]",
            ),
            (
                call(Syscall::TimerfdCreate.raw(), a1(1, 0)),
                "anon_inode:[timerfd]",
                "timerfd is not anon_inode:[timerfd]",
            ),
            (
                call(
                    Syscall::Signalfd.raw(),
                    a3(u64::MAX, mask.as_ptr() as u64, 8, 0),
                ),
                "anon_inode:[signalfd]",
                "signalfd is not anon_inode:[signalfd]",
            ),
            (
                call(Syscall::InotifyInit1.raw(), a0(0)),
                "anon_inode:inotify",
                "inotify is not anon_inode:inotify",
            ),
            (
                call(Syscall::FanotifyInit.raw(), a1(0, 0)),
                "anon_inode:[fanotify]",
                "fanotify is not anon_inode:[fanotify]",
            ),
            (
                call(Syscall::PidfdOpen.raw(), a1(FAKE_TASK, 0)),
                "anon_inode:[pidfd]",
                "pidfd is not anon_inode:[pidfd]",
            ),
        ];
        let mut r = Ok(());
        for (made, want, msg) in cases {
            let fd = new_fd(made, "fixture: could not create an anonymous-inode file");
            r = r.and(fd).and_then(|fd| expect(fd, want, msg));
            if let Ok(fd) = fd {
                close(fd);
            }
        }
        r
    })
}
kernel_test_in!("syscall_abi/procfd", smoke_abi_procfd_anon_inode_classes);

/// Files on kernel-internal mounts: `memfd_create` is shmem's
/// `/memfd:<name> (deleted)`, `memfd_secret` is `/secretmem (deleted)`.
fn smoke_abi_procfd_memfd_and_secretmem() -> TestResult {
    with_links(|| {
        let name = b"cfg\0";
        let memfd = new_fd(
            call(Syscall::MemfdCreate.raw(), a1(name.as_ptr() as u64, 0)),
            "memfd_create failed",
        );
        let secret = new_fd(
            call(Syscall::MemfdSecret.raw(), a0(0)),
            "memfd_secret failed",
        );
        let r = memfd
            .and_then(|fd| {
                expect(
                    fd,
                    "/memfd:cfg (deleted)",
                    "a memfd is not /memfd:<name> (deleted)",
                )
            })
            .and(secret)
            .and_then(|fd| {
                expect(
                    fd,
                    "/secretmem (deleted)",
                    "memfd_secret is not /secretmem (deleted)",
                )
            });
        for fd in [memfd, secret].into_iter().flatten() {
            close(fd);
        }
        r
    })
}
kernel_test_in!("syscall_abi/procfd", smoke_abi_procfd_memfd_and_secretmem);

/// Device nodes are ordinary paths: `/dev/null`, and the pty master reads
/// the ptmx node it was opened through.
fn smoke_abi_procfd_device_nodes_read_their_path() -> TestResult {
    with_links(|| {
        let null = open("/dev/null", O_RDWR, "open(/dev/null) failed")?;
        let ptmx = open("/dev/ptmx", O_RDWR, "open(/dev/ptmx) failed");
        let r = expect(null, "/dev/null", "/dev/null is not named by its path")
            .and(ptmx)
            .and_then(|fd| expect(fd, "/dev/ptmx", "a pty master is not named /dev/ptmx"));
        if let Ok(fd) = ptmx {
            close(fd);
        }
        close(null);
        r
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_device_nodes_read_their_path
);

/// `stat` through the link is the file (`proc_fd_link` is a jump, not a
/// path), `lstat` is the link, and `fdinfo` exists for every descriptor.
fn smoke_abi_procfd_stat_lstat_and_fdinfo() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d/f", O_PATH | O_CLOEXEC, "open(O_PATH) failed")?;
        let link = alloc::format!("/proc/self/fd/{fd}\0");
        let info = alloc::format!("/proc/self/fdinfo/{fd}");
        let mut via = [0u8; 256];
        let mut own = [0u8; 256];
        let stat = call_stat(link.as_ptr() as u64, via.as_mut_ptr() as u64);
        let lstat = call_lstat(link.as_ptr() as u64, own.as_mut_ptr() as u64);
        let ino = st_ino(fd);
        let fdinfo = open(&info, O_RDONLY, "open(/proc/self/fdinfo/N) failed");
        if let Ok(fdinfo) = fdinfo {
            close(fdinfo);
        }
        close(fd);
        if stat != Some(0) || u64::from_ne_bytes(via[8..16].try_into().unwrap()) != ino? {
            return Err("stat through /proc/self/fd/N is not the file");
        }
        if lstat != Some(0) || stat_mode(&own) & 0o170_000 != 0o120_000 {
            return Err("lstat of /proc/self/fd/N is not a symlink");
        }
        fdinfo.map(|_| ())
    })
}
kernel_test_in!("syscall_abi/procfd", smoke_abi_procfd_stat_lstat_and_fdinfo);

/// `d_path` renders relative to the reader's root: after `chroot("/pf")` the
/// file `/pf/d/f` reads `/d/f`.
fn smoke_abi_procfd_link_is_relative_to_the_readers_root() -> TestResult {
    with_fs(|| {
        let fd = open("/pf/d/f", O_RDONLY, "open failed")?;
        let root = b"/pf\0";
        let chrooted = call(Syscall::Chroot.raw(), a0(root.as_ptr() as u64)) == Some(0);
        // `/proc` is not mounted below the new root, so ask the procfs hook
        // the link is rendered by directly.
        let seen = crate::handlers::fd_path_of(FAKE_TASK, fd as u32).map(|snapshot| snapshot.path);
        crate::handlers::__test_root_dir_reset();
        close(fd);
        if !chrooted {
            return Err("fixture: chroot failed");
        }
        if seen.as_deref() != Some("/d/f") {
            return Err("the link is not rendered relative to the reader's root");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/procfd",
    smoke_abi_procfd_link_is_relative_to_the_readers_root
);
