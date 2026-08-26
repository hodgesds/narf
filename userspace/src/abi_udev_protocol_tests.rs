//! systemd-udevd manager↔worker protocol conformance.
//!
//! udev's manager and its workers speak a four-layer protocol, and every
//! layer crosses a NARF ABI surface:
//!
//!     1. fork       — worker is a pid-namespace child of the manager
//!     2. sd_notify  — worker → manager AF_UNIX datagram (INOTIFY_WATCH_*,
//!                     PROCESSED=1/ERRNO=…), sender named by SCM_CREDENTIALS
//!     3. ack        — manager → worker `pidref_sigqueue(SIGUSR1)`, which is
//!                     sigqueue(2) → rt_sigqueueinfo(2) since the PidRef has
//!                     no pidfd (NARF attaches no SCM_PIDFD)
//!     4. wake       — worker's nested sd_event loop reads its signalfd and
//!                     accepts the ack only if `ssi_pid == manager_pid`
//!
//! Each existing test covered a fragment of one layer; nothing covered the
//! chain, and the CachyOS bring-up wedge lives between layers 2 and 3:
//! `assert(worker->event)` at udev-manager.c:1199 fires when a datagram is
//! attributed to the WRONG worker, and a worker starves forever when its ack
//! is delivered to the WRONG process. Both "wrong"s are pid-translation
//! bugs, invisible at every layer individually — the calls all succeed.
//!
//! Linux refs: kernel/signal.c `do_rt_sigqueueinfo` → `kill_proc_info` →
//! `find_task_by_vpid` (the pid is the CALLER's namespace view, exactly like
//! kill(2)); net/core/scm.c credential translation into the receiver's pid
//! namespace (an unmapped sender reads as pid 0, never as someone else).
#![cfg(feature = "container")]
use crate::abi_test_support::*;

const SOCK_DGRAM: u64 = 2;
const SOL_SOCKET: u64 = 1;
const SO_PASSCRED: u64 = 16;
const SCM_CREDENTIALS: i32 = 2;
const SIGUSR1: u32 = 10;
const SI_QUEUE: i32 = -1;

fn unix_sockaddr(path: &[u8]) -> ([u8; 128], u64) {
    let mut buf = [0u8; 128];
    buf[0..2].copy_from_slice(&1u16.to_le_bytes()); // AF_UNIX
    let n = core::cmp::min(path.len(), 110);
    buf[2..2 + n].copy_from_slice(&path[..n]);
    (buf, (2 + n) as u64)
}

fn open_dgram() -> Result<u64, &'static str> {
    match call(Syscall::SocketOpen.raw(), a2(1, SOCK_DGRAM, 0)) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("socket(AF_UNIX, SOCK_DGRAM) failed"),
    }
}

/// Register a task the way a real spawned process is registered: refcounted
/// task entry plus both directions of the pid↔task maps.
fn register_process(task: u64, outer_pid: u64) {
    crate::task::release_task(task);
    let _ = crate::task::Task::new_registered(task, outer_pid);
    crate::handlers::register_task_to_pid(task, outer_pid);
    crate::handlers::register_pid_task_mapping(outer_pid, task);
}

/// The fixed siginfo prefix imported by the signal handlers, filled the way
/// systemd's `pidref_sigqueue` fills it: SI_QUEUE, si_pid = manager's own
/// getpid(), payload value.
fn sigqueue_info(si_pid: u32) -> [u8; 48] {
    let mut si = [0u8; 48];
    si[0..4].copy_from_slice(&SIGUSR1.to_le_bytes());
    si[8..12].copy_from_slice(&SI_QUEUE.to_le_bytes());
    si[16..20].copy_from_slice(&si_pid.to_le_bytes());
    si[24..32].copy_from_slice(&0u64.to_le_bytes());
    si
}

// ── Layer 3: the ack must target the CALLER-NAMESPACE pid ─────────────

/// `rt_sigqueueinfo(pid, …)` from a task in a pid namespace must deliver to
/// the process the CALLER knows by that pid — not to whatever process owns
/// the same number in the outer pid space.
///
/// This is the udev ack: the manager (inner pid 1) reads the worker's inner
/// pid from SCM_CREDENTIALS and sigqueues SIGUSR1 at it. Outer pids with
/// small numbers always exist (early boot processes), so an untranslated
/// lookup does not fail — it succeeds against the WRONG process, the call
/// returns 0, the manager logs nothing, and the worker waits forever for an
/// ack that went elsewhere. That starvation is why udev workers never go
/// idle, never get reused, and pile up to the children_max=18 ceiling.
fn smoke_udev_ack_sigqueue_targets_inner_pid() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC3_00;
        const MANAGER_PID: u64 = 0xA3_00;
        const WORKER_TASK: u64 = 0xC3_01;
        const WORKER_PID: u64 = 0xA3_01;
        // The collision victim: a root-namespace process whose OUTER pid
        // equals the worker's INNER pid (2). In a real boot this is
        // journald, a getty, the gate script's bash — someone always owns
        // the small numbers.
        const VICTIM_TASK: u64 = 0xC3_02;
        const VICTIM_PID: u64 = 2;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register_process(MANAGER_TASK, MANAGER_PID);
            register_process(WORKER_TASK, WORKER_PID);
            register_process(VICTIM_TASK, VICTIM_PID);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);
            if crate::pid_ns::inherit_into_child(MANAGER_TASK, WORKER_TASK, WORKER_PID) != Some(2) {
                return Err("worker was not assigned inner pid 2");
            }

            set_task(MANAGER_TASK);
            let si = sigqueue_info(1);
            if call(
                Syscall::RtSigqueueinfo.raw(),
                a2(2, SIGUSR1 as u64, si.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("manager's rt_sigqueueinfo(inner 2, SIGUSR1) did not return 0");
            }

            let worker_pending = crate::handlers::signal_pending_of(WORKER_TASK);
            let victim_pending = crate::handlers::signal_pending_of(VICTIM_TASK);
            if victim_pending != 0 {
                return Err(
                    "SIGUSR1 was delivered to the OUTER pid 2 process — rt_sigqueueinfo did not translate through the caller's pid namespace",
                );
            }
            if worker_pending & (1u64 << (SIGUSR1 - 1)) == 0 {
                return Err("SIGUSR1 never reached the worker the manager addressed");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        for t in [0xC3_00u64, 0xC3_01, 0xC3_02] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!(
    "syscall_abi/udev",
    smoke_udev_ack_sigqueue_targets_inner_pid
);

/// An inner pid that is NOT bound in the caller's namespace must be ESRCH —
/// even when a root-namespace process owns that number. Without this arm the
/// misdelivery above is silent in both directions: the wrong process gets
/// the signal AND the caller is told everything worked.
fn smoke_udev_ack_sigqueue_unbound_inner_is_esrch() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC3_10;
        const MANAGER_PID: u64 = 0xA3_10;
        const OUTSIDER_TASK: u64 = 0xC3_11;
        const OUTSIDER_PID: u64 = 9;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register_process(MANAGER_TASK, MANAGER_PID);
            register_process(OUTSIDER_TASK, OUTSIDER_PID);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);

            set_task(MANAGER_TASK);
            let si = sigqueue_info(1);
            let r = call(
                Syscall::RtSigqueueinfo.raw(),
                a2(9, SIGUSR1 as u64, si.as_ptr() as u64),
            );
            if crate::handlers::signal_pending_of(OUTSIDER_TASK) != 0 {
                return Err(
                    "rt_sigqueueinfo(unbound inner 9) signalled the outer-pid-9 process instead of failing",
                );
            }
            if r != Some(ESRCH) {
                return Err("rt_sigqueueinfo of an unbound in-namespace pid must be ESRCH");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        for t in [0xC3_10u64, 0xC3_11] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!(
    "syscall_abi/udev",
    smoke_udev_ack_sigqueue_unbound_inner_is_esrch
);

// ── Layer 2: a foreign sender must never borrow a worker's identity ───

/// SCM_CREDENTIALS translation must never FABRICATE an identity. A sender
/// whose outer pid is not mapped into the receiver's pid namespace reads as
/// pid 0 (Linux: an unmapped pid renders as 0) — never as some other
/// process's valid inner pid.
///
/// The hazard is `self_inner_pid`'s miss-fallback, which retries the lookup
/// with the OBSERVER'S TASK ID as the key. Task ids and outer pids share the
/// same small integers in a real boot, so when a process is registered under
/// an outer pid that happens to equal the manager's task id, every
/// unmapped sender's datagram is attributed to THAT process. For udev this
/// is `hashmap_get(manager->workers, &sender)` finding a VALID worker that
/// never sent the message — `on_worker_notify` then detaches or asserts on
/// the wrong worker's event. No warning fires anywhere, because the borrowed
/// identity is a real registered worker.
fn smoke_udev_notify_cred_never_borrows_another_identity() -> TestResult {
    with_setup(|| {
        // The manager's TASK id doubles as a valid OUTER pid — the numeric
        // collision that makes the fallback dangerous.
        const MANAGER_TASK: u64 = 0x60;
        const MANAGER_PID: u64 = 0xA3_20;
        const INNOCENT_TASK: u64 = 0xC3_21;
        const INNOCENT_PID: u64 = 0x60; // == MANAGER_TASK
        const STRANGER_TASK: u64 = 0xC3_22;
        const STRANGER_PID: u64 = 0xB3_22;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register_process(MANAGER_TASK, MANAGER_PID);
            register_process(INNOCENT_TASK, INNOCENT_PID);
            register_process(STRANGER_TASK, STRANGER_PID);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);
            let innocent_inner =
                crate::pid_ns::inherit_into_child(MANAGER_TASK, INNOCENT_TASK, INNOCENT_PID);
            if innocent_inner != Some(2) {
                return Err("innocent worker was not assigned inner pid 2");
            }
            // The stranger is deliberately NOT inherited into the namespace.

            set_task(MANAGER_TASK);
            let rx = open_dgram()?;
            let (addr, alen) = unix_sockaddr(b"\0narf-udev-cred-borrow");
            if call(
                Syscall::SocketBind.raw(),
                a2(rx, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("manager could not bind its notify socket");
            }
            let on = 1u32.to_ne_bytes();
            if call(
                Syscall::SocketSetSockOpt.raw(),
                SyscallArgs {
                    arg0: rx,
                    arg1: SOL_SOCKET,
                    arg2: SO_PASSCRED,
                    arg3: on.as_ptr() as u64,
                    arg4: on.len() as u64,
                    arg5: 0,
                },
            ) != Some(0)
            {
                return Err("manager could not enable SO_PASSCRED");
            }

            set_task(STRANGER_TASK);
            let tx = open_dgram()?;
            let payload = b"INOTIFY_WATCH_REMOVE=1\n";
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
            let mut msg = [0u8; 56];
            msg[..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
            msg[8..16].copy_from_slice(&alen.to_ne_bytes());
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            if call(Syscall::SocketSendMsg.raw(), a2(tx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
            {
                return Err("stranger sendmsg failed");
            }

            set_task(MANAGER_TASK);
            let mut dst = [0u8; 64];
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
            let mut ctrl = [0u8; 64];
            let mut msg = [0u8; 56];
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
            msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
            if call(Syscall::SocketRecvMsg.raw(), a2(rx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
            {
                return Err("manager did not receive the stranger's datagram");
            }
            let cred_type = i32::from_le_bytes(ctrl[12..16].try_into().unwrap());
            let cred_pid = u32::from_le_bytes(ctrl[16..20].try_into().unwrap());
            if cred_type != SCM_CREDENTIALS {
                return Err("no SCM_CREDENTIALS attached");
            }
            if cred_pid as u64 == 2 {
                return Err(
                    "an unmapped sender's datagram was attributed to the innocent worker's inner pid — the translation fallback fabricated an identity",
                );
            }
            if cred_pid != 0 {
                return Err("an unmapped sender must render as pid 0 in the receiver's namespace");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        for t in [0x60u64, 0xC3_21, 0xC3_22] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!(
    "syscall_abi/udev",
    smoke_udev_notify_cred_never_borrows_another_identity
);

// ── Layers 2+3+4 chained: the full ack round trip ─────────────────────

/// The whole handshake, end to end: worker sends its notification with real
/// sendmsg; the manager reads the sender's inner pid from SCM_CREDENTIALS
/// and acks it with rt_sigqueueinfo(SI_QUEUE, si_pid = manager's own pid);
/// the worker's signalfd must then report `ssi_signo == SIGUSR1` with
/// `ssi_pid` naming the MANAGER — which is precisely what udev's
/// `on_sigusr1` checks (`ssi_pid != worker->manager_pid` → ack ignored →
/// the worker keeps waiting forever).
fn smoke_udev_ack_round_trip_signalfd_names_manager() -> TestResult {
    with_setup(|| {
        const MANAGER_TASK: u64 = 0xC3_30;
        const MANAGER_PID: u64 = 0xA3_30;
        const WORKER_TASK: u64 = 0xC3_31;
        const WORKER_PID: u64 = 0xA3_31;
        const VICTIM_TASK: u64 = 0xC332;
        const VICTIM_PID: u64 = 2;

        crate::pid_ns::__test_reset();
        let result = (|| {
            register_process(MANAGER_TASK, MANAGER_PID);
            register_process(WORKER_TASK, WORKER_PID);
            register_process(VICTIM_TASK, VICTIM_PID);
            crate::pid_ns::unshare_pid_ns(MANAGER_TASK, MANAGER_PID);
            if crate::pid_ns::inherit_into_child(MANAGER_TASK, WORKER_TASK, WORKER_PID) != Some(2) {
                return Err("worker was not assigned inner pid 2");
            }

            // Manager binds its worker-notify socket, SO_PASSCRED on.
            set_task(MANAGER_TASK);
            let rx = open_dgram()?;
            let (addr, alen) = unix_sockaddr(b"\0narf-udev-roundtrip");
            if call(
                Syscall::SocketBind.raw(),
                a2(rx, addr.as_ptr() as u64, alen),
            ) != Some(0)
            {
                return Err("manager could not bind its notify socket");
            }
            let on = 1u32.to_ne_bytes();
            if call(
                Syscall::SocketSetSockOpt.raw(),
                SyscallArgs {
                    arg0: rx,
                    arg1: SOL_SOCKET,
                    arg2: SO_PASSCRED,
                    arg3: on.as_ptr() as u64,
                    arg4: on.len() as u64,
                    arg5: 0,
                },
            ) != Some(0)
            {
                return Err("manager could not enable SO_PASSCRED");
            }

            // Worker installs its SIGUSR1 signalfd (the nested sd_event
            // loop's wake source), then notifies.
            set_task(WORKER_TASK);
            let mask = (1u64 << (SIGUSR1 - 1)).to_le_bytes();
            let sfd = match call(
                Syscall::Signalfd.raw(),
                a3((-1i64) as u64, mask.as_ptr() as u64, 8, 0),
            ) {
                Some(fd) if fd >= 0 => fd as u64,
                _ => return Err("worker signalfd creation failed"),
            };
            let tx = open_dgram()?;
            let payload = b"INOTIFY_WATCH_REMOVE=1\n";
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(payload.as_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(payload.len() as u64).to_ne_bytes());
            let mut msg = [0u8; 56];
            msg[..8].copy_from_slice(&(addr.as_ptr() as u64).to_ne_bytes());
            msg[8..16].copy_from_slice(&alen.to_ne_bytes());
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            if call(Syscall::SocketSendMsg.raw(), a2(tx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
            {
                return Err("worker's INOTIFY_WATCH_REMOVE send failed");
            }

            // Manager receives, reads the sender's inner pid, acks it.
            set_task(MANAGER_TASK);
            let mut dst = [0u8; 64];
            let mut iov = [0u8; 16];
            iov[..8].copy_from_slice(&(dst.as_mut_ptr() as u64).to_ne_bytes());
            iov[8..].copy_from_slice(&(dst.len() as u64).to_ne_bytes());
            let mut ctrl = [0u8; 64];
            let mut msg = [0u8; 56];
            msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
            msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
            msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
            msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
            if call(Syscall::SocketRecvMsg.raw(), a2(rx, msg.as_ptr() as u64, 0))
                != Some(payload.len() as i64)
            {
                return Err("manager did not receive the worker's notification");
            }
            let sender_pid = u32::from_le_bytes(ctrl[16..20].try_into().unwrap());
            if sender_pid != 2 {
                return Err("SCM_CREDENTIALS did not name the worker's inner pid");
            }
            let si = sigqueue_info(1); // si_pid = manager's own (inner) pid
            if call(
                Syscall::RtSigqueueinfo.raw(),
                a2(sender_pid as u64, SIGUSR1 as u64, si.as_ptr() as u64),
            ) != Some(0)
            {
                return Err("manager's ack sigqueue did not return 0");
            }
            if crate::handlers::signal_pending_of(VICTIM_TASK) != 0 {
                return Err("the ack was delivered to the outer-pid collision victim");
            }

            // Worker's signalfd must surface the ack, naming the manager.
            set_task(WORKER_TASK);
            let mut rec = [0u8; 128];
            if call(
                Syscall::Read.raw(),
                a2(sfd, rec.as_mut_ptr() as u64, rec.len() as u64),
            ) != Some(128)
            {
                return Err("worker signalfd read returned no record — the ack never arrived");
            }
            if u32::from_le_bytes(rec[0..4].try_into().unwrap()) != SIGUSR1 {
                return Err("worker signalfd record is not SIGUSR1");
            }
            if i32::from_le_bytes(rec[8..12].try_into().unwrap()) != SI_QUEUE {
                return Err(
                    "ack ssi_code is not SI_QUEUE (worker's si_code_from_process rejects it)",
                );
            }
            if u32::from_le_bytes(rec[12..16].try_into().unwrap()) != 1 {
                return Err("ack ssi_pid does not name the manager (worker ignores the ack)");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::pid_ns::__test_reset();
        for t in [0xC3_30u64, 0xC3_31, 0xC332] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!(
    "syscall_abi/udev",
    smoke_udev_ack_round_trip_signalfd_names_manager
);
