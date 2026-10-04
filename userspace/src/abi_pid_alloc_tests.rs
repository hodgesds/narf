//! Linux PID allocation semantics: cyclic allocation, the RESERVED_PIDS wrap,
//! `/proc/sys/kernel/ns_last_pid`, `/proc/sys/kernel/pid_max`, and clone3
//! `set_tid` bounds.
//!
//! Linux allocates pids with `idr_alloc_cyclic(&ns->idr, NULL, pid_min,
//! pid_max)` (`kernel/pid.c::alloc_pid`): the search starts one past the last
//! pid handed out in that namespace and wraps at `pid_max`. Once the cursor
//! has passed `RESERVED_PIDS` (300) the wrap goes back to 300, not to 1. A
//! freshly released pid is therefore NOT the next one handed out.
//!
//! That matters to every daemon that keeps a PID file. avahi-daemon (via
//! libdaemon's `daemon_pid_file_is_running`) refuses to start when the pid in
//! its stale PID file names a live process. NARF used to hand out the LOWEST
//! free pid, so a crashed-and-restarted daemon got its old pid straight back,
//! read its own pid out of the stale file and exited with "Daemon already
//! running on PID N". On Linux the restart lands on a new pid.
//!
//! The cursor is driven through `ns_last_pid` — the interface CRIU uses — so
//! the wrap is testable without forking 32k processes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::abi_test_support::*;

const PID_MAX_PATH: &[u8] = b"/proc/sys/kernel/pid_max\0";
const NS_LAST_PID_PATH: &[u8] = b"/proc/sys/kernel/ns_last_pid\0";
/// `include/linux/pid.h`.
const RESERVED_PIDS: u64 = 300;
const CAP_CHECKPOINT_RESTORE: u64 = 40;

fn proc_read(path: &[u8]) -> Result<String, &'static str> {
    let fd = call_open(path.as_ptr() as u64, 0).ok_or("open returned a non-Linux status")?;
    if fd < 0 {
        return Err("sysctl file could not be opened for reading");
    }
    let mut buf = [0u8; 64];
    let n = call(
        Syscall::Read.raw(),
        a2(fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
    );
    let _ = call(Syscall::Close.raw(), a0(fd as u64));
    match n {
        Some(n) if n >= 0 => Ok(String::from_utf8_lossy(&buf[..n as usize]).into_owned()),
        _ => Err("sysctl read failed"),
    }
}

fn proc_read_u64(path: &[u8]) -> Result<u64, &'static str> {
    proc_read(path)?
        .trim()
        .parse::<u64>()
        .map_err(|_| "sysctl did not read back as an integer")
}

/// Write `v` to a sysctl file; the Linux return of `write(2)` (bytes or
/// -errno), or the open's -errno.
fn proc_write(path: &[u8], v: &[u8]) -> i64 {
    let fd = match call_open(path.as_ptr() as u64, 1) {
        Some(fd) => fd,
        None => return i64::MIN,
    };
    if fd < 0 {
        return fd;
    }
    let n = call(
        Syscall::Write.raw(),
        a2(fd as u64, v.as_ptr() as u64, v.len() as u64),
    )
    .unwrap_or(i64::MIN);
    let _ = call(Syscall::Close.raw(), a0(fd as u64));
    n
}

/// `ns_last_pid` is `idr_get_cursor() - 1`, so a namespace that has not
/// allocated yet reads -1: parse it signed.
fn read_ns_last_pid() -> Result<i64, &'static str> {
    proc_read(NS_LAST_PID_PATH)?
        .trim()
        .parse::<i64>()
        .map_err(|_| "ns_last_pid did not read back as an integer")
}

/// Put the cursor back where a test found it. A cursor that had never moved
/// (-1) cannot be written back through the sysctl, on Linux either; leave it.
fn restore_ns_last_pid(original: i64) {
    if original >= 0 {
        let _ = set_ns_last_pid(original as u64);
    }
}

fn set_ns_last_pid(v: u64) -> Result<(), &'static str> {
    let s = format!("{v}\n");
    if proc_write(NS_LAST_PID_PATH, s.as_bytes()) != s.len() as i64 {
        return Err("writing ns_last_pid as a privileged task failed");
    }
    Ok(())
}

// ── (a) a released pid is not handed straight back ─────────────────────
//
// `idr_alloc_cyclic` resumes one past the last allocation, so
// alloc → free → alloc yields last+1 (when free), never the freed pid.
fn smoke_abi_pid_alloc_released_pid_not_reused() -> TestResult {
    with_setup(|| {
        let a = crate::alloc_pid();
        if a == crate::ProcessId::KERNEL {
            return Err("alloc_pid failed");
        }
        crate::release_pid(a);
        let b = crate::alloc_pid();
        crate::release_pid(b);
        if b == a {
            return Err("a released pid was handed straight back (lowest-free, not cyclic)");
        }
        if b.raw() != a.raw() + 1 {
            return Err("the next pid after a release was not last+1");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/pid_alloc",
    smoke_abi_pid_alloc_released_pid_not_reused
);

// ── (b) wrap at pid_max goes back to RESERVED_PIDS, skipping in-use pids ─
//
// `if (idr_get_cursor(&tmp->idr) > RESERVED_PIDS) pid_min = RESERVED_PIDS;`
fn smoke_abi_pid_alloc_wraps_to_reserved_pids() -> TestResult {
    with_setup(|| {
        let pid_max = proc_read_u64(PID_MAX_PATH)?;
        let original = read_ns_last_pid()?;
        let mut owned: Vec<crate::ProcessId> = Vec::new();
        // Occupy 300 and 301 so the wrap has to skip in-use pids. EEXIST means
        // something live already holds the number — equally occupied.
        for id in [RESERVED_PIDS, RESERVED_PIDS + 1] {
            if let Ok(pid) = crate::alloc_pid_specific(id) {
                owned.push(pid);
            }
        }
        let verdict = (|| {
            set_ns_last_pid(pid_max - 3)?;
            let x1 = crate::alloc_pid();
            owned.push(x1);
            if x1.raw() != pid_max - 2 {
                return Err("allocation did not resume one past ns_last_pid");
            }
            if read_ns_last_pid()? != x1.raw() as i64 {
                return Err("ns_last_pid did not report the pid just allocated");
            }
            let x2 = crate::alloc_pid();
            owned.push(x2);
            if x2.raw() != pid_max - 1 {
                return Err("pid_max - 1 was not allocatable (pid_max is exclusive)");
            }
            let x3 = crate::alloc_pid();
            owned.push(x3);
            if x3 == crate::ProcessId::KERNEL {
                return Err("allocation failed instead of wrapping at pid_max");
            }
            if x3.raw() < RESERVED_PIDS {
                return Err("wrap went below RESERVED_PIDS after the cursor passed 300");
            }
            if x3.raw() <= RESERVED_PIDS + 1 || x3.raw() >= x1.raw() {
                return Err("wrap handed out an in-use pid or did not wrap");
            }
            // Every number the wrap skipped must really be in use.
            for id in RESERVED_PIDS + 2..x3.raw() {
                if let Ok(pid) = crate::alloc_pid_specific(id) {
                    crate::release_pid(pid);
                    return Err("wrap skipped a free pid");
                }
            }
            if read_ns_last_pid()? != x3.raw() as i64 {
                return Err("ns_last_pid did not follow the wrap");
            }
            Ok(())
        })();
        restore_ns_last_pid(original);
        for pid in owned {
            crate::release_pid(pid);
        }
        verdict
    })
}
kernel_test_in!(
    "syscall_abi/pid_alloc",
    smoke_abi_pid_alloc_wraps_to_reserved_pids
);

// ── ns_last_pid write rules ────────────────────────────────────────────
//
// `kernel/pid_namespace.c::pid_ns_ctl_handler`: mode 0666, and the handler
// itself refuses a write without `checkpoint_restore_ns_capable` (CAP_SYS_ADMIN
// or CAP_CHECKPOINT_RESTORE in the pid namespace's user namespace) with EPERM —
// before parsing. The value goes through `proc_dointvec_minmax` over
// [0, pid_ns->pid_max], so out-of-range is EINVAL.
fn smoke_abi_pid_alloc_ns_last_pid_write_rules() -> TestResult {
    with_setup(|| {
        let pid_max = proc_read_u64(PID_MAX_PATH)?;
        let original = read_ns_last_pid()?;

        crate::handlers::__test_set_fsids(FAKE_TASK, 1000, 1000);
        crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);
        let unprivileged = proc_write(NS_LAST_PID_PATH, b"100\n");
        let unprivileged_garbage = proc_write(NS_LAST_PID_PATH, b"garbage\n");
        crate::handlers::__test_set_caps(
            FAKE_TASK,
            1 << CAP_CHECKPOINT_RESTORE,
            1 << CAP_CHECKPOINT_RESTORE,
        );
        let checkpoint_restore = proc_write(NS_LAST_PID_PATH, b"100\n");
        let after_cr = read_ns_last_pid();
        crate::handlers::__test_set_fsids(FAKE_TASK, 0, 0);
        crate::handlers::__test_set_caps(FAKE_TASK, !0, !0);

        let negative = proc_write(NS_LAST_PID_PATH, b"-1\n");
        let over = proc_write(NS_LAST_PID_PATH, format!("{}\n", pid_max + 1).as_bytes());
        let at_max = proc_write(NS_LAST_PID_PATH, format!("{pid_max}\n").as_bytes());
        let read_max = read_ns_last_pid();
        restore_ns_last_pid(original);

        if unprivileged != EPERM {
            return Err(
                "ns_last_pid write without CAP_SYS_ADMIN/CAP_CHECKPOINT_RESTORE must be -EPERM",
            );
        }
        if unprivileged_garbage != EPERM {
            return Err("ns_last_pid capability check must precede parsing (-EPERM)");
        }
        if checkpoint_restore != 4 || after_cr != Ok(100) {
            return Err("CAP_CHECKPOINT_RESTORE alone must be enough to write ns_last_pid");
        }
        if negative != EINVAL || over != EINVAL {
            return Err("ns_last_pid outside [0, pid_max] must be -EINVAL");
        }
        if at_max <= 0 || read_max != Ok(pid_max as i64) {
            return Err("ns_last_pid = pid_max must be accepted");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/pid_alloc",
    smoke_abi_pid_alloc_ns_last_pid_write_rules
);

// ── pid_max sysctl bounds the allocator ────────────────────────────────
//
// `pid_max` is `proc_dointvec_minmax` over [pid_max_min = RESERVED_PIDS + 1,
// PID_MAX_LIMIT]; `alloc_pid` reads the live value. With pid_max = 301 and the
// cursor past 300 the only allocatable pid is 300: once that is taken, fork
// is -EAGAIN (`idr_alloc_cyclic` -ENOSPC → -EAGAIN).
fn smoke_abi_pid_alloc_pid_max_bounds_allocator() -> TestResult {
    with_setup(|| {
        let pid_max = proc_read_u64(PID_MAX_PATH)?;
        let original = read_ns_last_pid()?;
        let below_min = proc_write(PID_MAX_PATH, b"300\n");
        let mut owned = Vec::new();
        let verdict = (|| {
            if below_min != EINVAL {
                return Err("pid_max below RESERVED_PIDS + 1 must be -EINVAL");
            }
            if let Ok(pid) = crate::alloc_pid_specific(RESERVED_PIDS) {
                owned.push(pid);
            }
            if proc_write(PID_MAX_PATH, b"301\n") != 4 {
                return Err("pid_max = 301 must be accepted");
            }
            set_ns_last_pid(RESERVED_PIDS)?;
            let exhausted = crate::alloc_pid();
            if exhausted != crate::ProcessId::KERNEL {
                owned.push(exhausted);
                return Err("allocation ignored a lowered pid_max");
            }
            Ok(())
        })();
        let _ = proc_write(PID_MAX_PATH, format!("{pid_max}\n").as_bytes());
        restore_ns_last_pid(original);
        for pid in owned {
            crate::release_pid(pid);
        }
        if proc_read_u64(PID_MAX_PATH)? != pid_max {
            return Err("failed to restore pid_max");
        }
        verdict
    })
}
kernel_test_in!(
    "syscall_abi/pid_alloc",
    smoke_abi_pid_alloc_pid_max_bounds_allocator
);

// ── (d) set_tid: EINVAL out of range, EEXIST when taken ─────────────────
//
// `alloc_pid`: `if (tid < 1 || tid >= pid_max) -EINVAL`; an exact
// `idr_alloc(tid, tid + 1)` that hits a used id is -ENOSPC → -EEXIST. The
// exact allocation is `idr_alloc`, not `idr_alloc_cyclic`, so it does not move
// the cyclic cursor.
fn smoke_abi_pid_alloc_set_tid_bounds_and_collision() -> TestResult {
    with_setup(|| {
        const EINVAL_POS: u64 = 22;
        const EEXIST_POS: u64 = 17;
        let pid_max = proc_read_u64(PID_MAX_PATH)?;
        let mut owned = Vec::new();
        let verdict = (|| {
            if crate::alloc_pid_specific(0).err() != Some(EINVAL_POS) {
                return Err("set_tid 0 must be EINVAL");
            }
            match crate::alloc_pid_specific(pid_max) {
                Err(EINVAL_POS) => {}
                Ok(pid) => {
                    owned.push(pid);
                    return Err("set_tid == pid_max must be EINVAL (pid_max is exclusive)");
                }
                Err(_) => return Err("set_tid == pid_max returned the wrong errno"),
            }
            let top = crate::alloc_pid_specific(pid_max - 1)
                .map_err(|_| "set_tid pid_max - 1 must be allocatable")?;
            owned.push(top);
            if crate::alloc_pid_specific(pid_max - 1).err() != Some(EEXIST_POS) {
                return Err("set_tid of an in-use pid must be EEXIST");
            }

            let a = crate::alloc_pid();
            owned.push(a);
            if let Ok(pid) = crate::alloc_pid_specific(a.raw() + 5) {
                owned.push(pid);
            }
            let b = crate::alloc_pid();
            owned.push(b);
            if b.raw() != a.raw() + 1 {
                return Err("an exact set_tid allocation moved the cyclic cursor");
            }

            // The same collision through clone3(2) itself.
            install_test_address_space()?;
            let requested = a.raw() as i32;
            let mut args = [0u8; 80];
            args[64..72].copy_from_slice(&(core::ptr::addr_of!(requested) as u64).to_ne_bytes());
            args[72..80].copy_from_slice(&1u64.to_ne_bytes());
            if call(
                Syscall::Clone3.raw(),
                a1(args.as_ptr() as u64, args.len() as u64),
            ) != Some(EEXIST)
            {
                return Err("clone3 set_tid of an in-use pid must return -EEXIST");
            }
            Ok(())
        })();
        for pid in owned {
            crate::release_pid(pid);
        }
        verdict
    })
}
kernel_test_in!(
    "syscall_abi/pid_alloc",
    smoke_abi_pid_alloc_set_tid_bounds_and_collision
);

// ── (c) the same, inside a child PID namespace ─────────────────────────
//
// Each `struct pid_namespace` has its own idr and cursor; `ns_last_pid`
// reads and writes the caller's ACTIVE namespace. This is the path the
// CachyOS avahi restart took: systemd runs inside `unshare --pid`.
#[cfg(feature = "container")]
fn smoke_abi_pid_alloc_cyclic_in_child_pid_ns() -> TestResult {
    with_setup(|| {
        const NS_PARENT: u64 = 0xE5_00;
        const EINVAL_POS: u64 = 22;
        const EEXIST_POS: u64 = 17;
        let pid_max = proc_read_u64(PID_MAX_PATH)?;
        let root_last = read_ns_last_pid()?;

        crate::pid_ns::unshare_pid_ns_for_children(NS_PARENT)
            .map_err(|_| "unshare(CLONE_NEWPID) failed")?;
        let init = crate::pid_ns::prepare_clone(NS_PARENT, &[], false, None)
            .map_err(|_| "namespace init allocation failed")?;
        if init.child_inner() != 1 {
            init.rollback();
            return Err("the first task in a new pid namespace must be pid 1");
        }
        // FAKE_TASK becomes the namespace's init, so the ns_last_pid file it
        // opens resolves this namespace.
        init.install(FAKE_TASK);
        let mut plans = Vec::new();
        let verdict = (|| {
            let alloc = || crate::pid_ns::prepare_clone(FAKE_TASK, &[], false, None);
            let a = alloc().map_err(|_| "namespace allocation failed")?;
            let ai = a.child_inner();
            a.rollback();
            let b = alloc().map_err(|_| "namespace allocation failed")?;
            let bi = b.child_inner();
            plans.push(b);
            if bi == ai {
                return Err("child pid namespace handed a released pid straight back");
            }
            if bi != ai + 1 {
                return Err("child pid namespace did not advance to last+1");
            }
            if read_ns_last_pid()? != bi as i64 {
                return Err("ns_last_pid did not report the namespace's own cursor");
            }

            set_ns_last_pid(pid_max - 2)?;
            let c = alloc().map_err(|_| "namespace allocation after ns_last_pid failed")?;
            let ci = c.child_inner();
            plans.push(c);
            if ci != pid_max - 1 {
                return Err("namespace allocation did not resume one past ns_last_pid");
            }
            let d = alloc().map_err(|_| "namespace allocation did not wrap")?;
            let di = d.child_inner();
            plans.push(d);
            if di != RESERVED_PIDS {
                return Err("namespace wrap did not land on RESERVED_PIDS");
            }
            // Wrap again with 300 taken: skips to 301.
            set_ns_last_pid(pid_max - 1)?;
            let e = alloc().map_err(|_| "second namespace wrap failed")?;
            let ei = e.child_inner();
            plans.push(e);
            if ei != RESERVED_PIDS + 1 {
                return Err("namespace wrap did not skip the in-use RESERVED_PIDS");
            }

            // set_tid inside the namespace: collision and range.
            match crate::pid_ns::prepare_clone(FAKE_TASK, &[RESERVED_PIDS as i32], false, None) {
                Err(EEXIST_POS) => {}
                Ok(p) => {
                    plans.push(p);
                    return Err("namespace set_tid of an in-use pid succeeded");
                }
                Err(_) => return Err("namespace set_tid collision must be EEXIST"),
            }
            match crate::pid_ns::prepare_clone(FAKE_TASK, &[pid_max as i32], false, None) {
                Err(EINVAL_POS) => {}
                Ok(p) => {
                    plans.push(p);
                    return Err("namespace set_tid == pid_max succeeded");
                }
                Err(_) => return Err("namespace set_tid == pid_max must be EINVAL"),
            }
            Ok(())
        })();
        for plan in plans {
            plan.rollback();
        }
        crate::pid_ns::clear_ns(FAKE_TASK);
        init.rollback();
        crate::pid_ns::clear_ns(NS_PARENT);
        // The namespace's cursor is its own: the root namespace's only moved
        // by the handful of outer pids the plans above allocated, not to the
        // values written through the child namespace's ns_last_pid.
        let root_after = read_ns_last_pid();
        verdict?;
        match root_after {
            Ok(v) if v > root_last && v <= root_last + 16 => Ok(()),
            _ => Err("a child namespace's ns_last_pid write moved the root cursor"),
        }
    })
}
#[cfg(feature = "container")]
kernel_test_in!(
    "syscall_abi/pid_alloc",
    smoke_abi_pid_alloc_cyclic_in_child_pid_ns
);
