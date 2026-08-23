//! Linux syscall ABI conformance — ipc group.
//!
//! Covers POSIX message queues (`mq_*`), System V semaphores / message
//! queues / shared memory (`sem* / msg* / shm*`), and the NARF-native
//! `shmem_*` registry surface. Shares the harness in
//! [`crate::abi_test_support`].
//!
//! Harness caveats that shape these tests:
//!   * There is no user address space wired in (`current_address_space()`
//!     returns `None`), so any handler that maps frames into an AS
//!     (`shmem_map`, `shmat`, `shmdt`) cannot reach its success path —
//!     those get a negative/stub test only.
//!   * `copy_to_user` / `copy_from_user` validate canonicality + length
//!     only (not user-vs-kernel range), so kernel-stack buffers round-trip
//!     fine — the side-table IPC objects (`sem*`, `msg*`, `mq_*`) exercise
//!     full positive paths.
//!   * The `narf_shmem` syscall vtable is installed by a `Stage::Subsys`
//!     initcall before the test phase runs, so `shmem_create` / `shmget`
//!     reach real frame backing.
#![cfg(feature = "linux-compat")]
#![allow(dead_code)] // errno/flag reference table + harness helpers

use crate::abi_test_support::*;

// IPC flag bits (octal, matching the handlers).
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_RMID: u64 = 0;
const IPC_STAT: u64 = 2;
const SETVAL: u64 = 16;
const GETVAL: u64 = 12;

const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_RDWR: u64 = 0o2;
const O_RDONLY: u64 = 0;
const O_NONBLOCK: u64 = 0o4000;

// ════════════════════════════════════════════════════════════════════
// POSIX message queues
// ════════════════════════════════════════════════════════════════════

// ── MqOpen ──────────────────────────────────────────────────────────
//
// mq_open(name, oflag, mode, attr). The Linux syscall ABI receives the leaf
// name after libc validates and strips the POSIX leading slash. arg0 is that
// NUL-terminated leaf and arg1 is oflag. O_CREAT with no attr → default
// 10 x 8192 queue; returns an fd.

fn smoke_abi_ipc_mq_open_pos() -> TestResult {
    with_setup(|| {
        let name = b"abi_mq_open_pos\0";
        // O_CREAT, no attr (arg3 = 0) → fresh queue, real fd >= 0.
        let r = call(
            Syscall::MqOpen.raw(),
            a1(name.as_ptr() as u64, O_CREAT | O_RDWR),
        );
        match r {
            Some(fd) if fd >= 0 => Ok(()),
            Some(_) => Err("mq_open O_CREAT returned a negative value"),
            None => Err("mq_open returned non-Ok status"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_open_pos);

fn smoke_abi_ipc_mq_open_neg() -> TestResult {
    with_setup(|| {
        // No O_CREAT and the name does not exist → ENOENT.
        let name = b"abi_mq_open_missing\0";
        match call(Syscall::MqOpen.raw(), a1(name.as_ptr() as u64, 0)) {
            Some(v) if v == ENOENT => Ok(()),
            other => {
                let _ = other;
                Err("mq_open of a missing name without O_CREAT must be ENOENT")
            }
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_open_neg);

// ── MqUnlink ────────────────────────────────────────────────────────

fn smoke_abi_ipc_mq_unlink_pos() -> TestResult {
    with_setup(|| {
        let name = b"abi_mq_unlink_pos\0";
        // Create then unlink the name → 0.
        let _ = call(
            Syscall::MqOpen.raw(),
            a1(name.as_ptr() as u64, O_CREAT | O_RDWR),
        );
        match call(Syscall::MqUnlink.raw(), a0(name.as_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("mq_unlink of an existing name should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_unlink_pos);

fn smoke_abi_ipc_mq_unlink_neg() -> TestResult {
    with_setup(|| {
        let name = b"abi_mq_unlink_missing\0";
        match call(Syscall::MqUnlink.raw(), a0(name.as_ptr() as u64)) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("mq_unlink of a missing name must be ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_unlink_neg);

// ── #25 mq_notify si_pid ────────────────────────────────────────────
//
// When a message arrives at an empty queue with a registered SIGEV_SIGNAL
// notification, Linux (mqueue.c __do_notify) delivers the signal with
// si_code = SI_MESGQ, si_value = the registered sigev_value, and si_pid = the
// SENDER's pid in the RECEIVER's namespace — NOT 0. The old code raised a bare
// signal with no siginfo. A receiver R registers the notify; a distinct sender
// S sends; the queued siginfo for R must carry (SI_MESGQ, value, S's pid).
fn smoke_abi_ipc_mq_notify_si_pid() -> TestResult {
    with_setup(|| {
        const R_TASK: u64 = 0x7300_0000;
        const R_PID: u64 = 0x7300_1000;
        const S_TASK: u64 = 0x7300_0001;
        const S_PID: u64 = 0x7300_1001;
        const SIG: u64 = 40; // an RT signal, queued by store_sigqueue_info
        const SI_MESGQ: i32 = -3;
        const VALUE: u64 = 0xDEAD_BEEF_0000_0042;
        let name = b"abi_mq_notify_sipid\0";

        // Register both tasks so task_to_pid_raw(S) == S_PID (the si_pid).
        for (t, p) in [(R_TASK, R_PID), (S_TASK, S_PID)] {
            crate::task::release_task(t);
            let _ = crate::task::Task::new_registered(t, p);
            crate::handlers::register_task_to_pid(t, p);
            crate::handlers::register_pid_task_mapping(p, t);
        }

        let result = (|| {
            // Receiver R: open the queue and register a SIGEV_SIGNAL notify.
            set_task(R_TASK);
            let fd_r = open_mq(name)?;
            let mut sigevent = [0u8; 64];
            sigevent[0..8].copy_from_slice(&VALUE.to_ne_bytes());
            sigevent[8..12].copy_from_slice(&(SIG as i32).to_ne_bytes());
            sigevent[12..16].copy_from_slice(&0i32.to_ne_bytes()); // SIGEV_SIGNAL
            if call(Syscall::MqNotify.raw(), a1(fd_r, sigevent.as_ptr() as u64)) != Some(0) {
                return Err("mq_notify(SIGEV_SIGNAL) did not succeed");
            }

            // Sender S: open the same queue and send one message.
            set_task(S_TASK);
            let fd_s = open_mq(name)?;
            let payload = b"ping";
            if call(
                Syscall::MqTimedsend.raw(),
                a3(fd_s, payload.as_ptr() as u64, payload.len() as u64, 0),
            ) != Some(0)
            {
                return Err("mq_timedsend into the empty queue did not succeed");
            }

            // The receiver's queued siginfo must name the sender.
            match crate::handlers::take_sigqueue_info(R_TASK, SIG as u32) {
                Some((code, value, si_pid)) => {
                    if code != SI_MESGQ {
                        Err("mq notify siginfo si_code was not SI_MESGQ")
                    } else if value != VALUE {
                        Err("mq notify siginfo si_value was not the registered sigev_value")
                    } else if si_pid as u64 != S_PID {
                        Err("mq notify si_pid was not the sender's pid (0/unset means no siginfo was stored)")
                    } else {
                        Ok(())
                    }
                }
                None => Err("mq notify stored NO siginfo — si_pid would read 0 (the #25 bug)"),
            }
        })();
        set_task(FAKE_TASK);
        let _ = call(Syscall::MqUnlink.raw(), a0(name.as_ptr() as u64));
        for t in [R_TASK, S_TASK] {
            crate::task::release_task(t);
        }
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_notify_si_pid);

/// Open a fresh queue and return its fd (or Err string for the body).
fn open_mq(name: &[u8]) -> Result<u64, &'static str> {
    match call(
        Syscall::MqOpen.raw(),
        a1(name.as_ptr() as u64, O_CREAT | O_RDWR),
    ) {
        Some(fd) if fd >= 0 => Ok(fd as u64),
        _ => Err("setup: mq_open O_CREAT failed"),
    }
}

// ── MqTimedsend ─────────────────────────────────────────────────────
//
// mq_timedsend(mqd, msg_ptr, msg_len, msg_prio, timeout). A send into a
// fresh (non-full) queue returns 0.

fn smoke_abi_ipc_mq_timedsend_pos() -> TestResult {
    with_setup(|| {
        let fd = open_mq(b"abi_mq_send_pos\0")?;
        let payload = b"hello-mq";
        let r = call(
            Syscall::MqTimedsend.raw(),
            a3(fd, payload.as_ptr() as u64, payload.len() as u64, 0),
        );
        match r {
            Some(0) => Ok(()),
            _ => Err("mq_timedsend into an empty queue should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_timedsend_pos);

fn smoke_abi_ipc_mq_timedsend_neg() -> TestResult {
    with_setup(|| {
        // arg0 is not a valid mqd fd → EBADF.
        let payload = b"x";
        match call(
            Syscall::MqTimedsend.raw(),
            a3(4242, payload.as_ptr() as u64, payload.len() as u64, 0),
        ) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("mq_timedsend on a bad fd must be EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_timedsend_neg);

// ── MqTimedreceive ──────────────────────────────────────────────────
//
// mq_timedreceive(mqd, msg_ptr, msg_len, prio_ptr, timeout). The receive
// buffer must be >= mq_msgsize (8192 default). After a send, a receive
// returns the byte count.

fn smoke_abi_ipc_mq_timedreceive_pos() -> TestResult {
    with_setup(|| {
        let fd = open_mq(b"abi_mq_recv_pos\0")?;
        let payload = b"abcd";
        let s = call(
            Syscall::MqTimedsend.raw(),
            a3(fd, payload.as_ptr() as u64, payload.len() as u64, 7),
        );
        if s != Some(0) {
            return Err("setup: mq_timedsend failed");
        }
        // Receive buffer must be at least mq_msgsize (8192).
        let mut rbuf = [0u8; 8192];
        let r = call(
            Syscall::MqTimedreceive.raw(),
            a3(fd, rbuf.as_mut_ptr() as u64, rbuf.len() as u64, 0),
        );
        match r {
            Some(n) if n == payload.len() as i64 => {
                if &rbuf[..4] == payload {
                    Ok(())
                } else {
                    Err("mq_timedreceive returned wrong payload bytes")
                }
            }
            _ => Err("mq_timedreceive should return the message length"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_timedreceive_pos);

fn smoke_abi_ipc_mq_timedreceive_neg() -> TestResult {
    with_setup(|| {
        // Bad fd → EBADF (checked before any buffer math).
        let mut rbuf = [0u8; 8192];
        match call(
            Syscall::MqTimedreceive.raw(),
            a3(4242, rbuf.as_mut_ptr() as u64, rbuf.len() as u64, 0),
        ) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("mq_timedreceive on a bad fd must be EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_timedreceive_neg);

// ── MqGetsetattr ────────────────────────────────────────────────────
//
// mq_getsetattr(mqd, newattr_ptr, oldattr_ptr). With new=0 and a 64-byte
// old buffer, snapshots the queue attrs and returns 0.

fn smoke_abi_ipc_mq_getsetattr_pos() -> TestResult {
    with_setup(|| {
        let fd = open_mq(b"abi_mq_attr_pos\0")?;
        let mut oldattr = [0u8; 64];
        let r = call(
            Syscall::MqGetsetattr.raw(),
            a2(fd, 0, oldattr.as_mut_ptr() as u64),
        );
        if r != Some(0) {
            return Err("mq_getsetattr (get) should return 0");
        }
        // mq_maxmsg lives at bytes 8..16; default is 10.
        let maxmsg = i64::from_le_bytes(oldattr[8..16].try_into().unwrap());
        if maxmsg != 10 {
            return Err("mq_getsetattr old buffer mq_maxmsg should be the default 10");
        }
        if oldattr[32..].iter().any(|byte| *byte != 0) {
            return Err("mq_getsetattr did not zero the reserved fields");
        }
        let mut invalid = [0u8; 64];
        invalid[..8].copy_from_slice(&1i64.to_ne_bytes());
        if call(
            Syscall::MqGetsetattr.raw(),
            a2(fd, invalid.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("mq_getsetattr accepted flags other than O_NONBLOCK");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_getsetattr_pos);

fn smoke_abi_ipc_mq_getsetattr_neg() -> TestResult {
    with_setup(|| {
        let mut oldattr = [0u8; 64];
        match call(
            Syscall::MqGetsetattr.raw(),
            a2(4242, 0, oldattr.as_mut_ptr() as u64),
        ) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("mq_getsetattr on a bad fd must be EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_getsetattr_neg);

fn smoke_abi_ipc_mq_linux_descriptor_semantics() -> TestResult {
    with_setup(|| {
        const F_GETFD: u64 = 1;
        const FD_CLOEXEC: i64 = 1;
        let name = b"abi_mq_linux_fd\0";
        let fd = match call(
            Syscall::MqOpen.raw(),
            a1(name.as_ptr() as u64, O_CREAT | O_RDONLY | O_NONBLOCK),
        ) {
            Some(fd) if fd >= 0 => fd as u64,
            _ => return Err("mq_open setup failed"),
        };
        if call(Syscall::Fcntl.raw(), a2(fd, F_GETFD, 0)) != Some(FD_CLOEXEC) {
            return Err("Linux requires mq_open descriptors to be FD_CLOEXEC");
        }
        let payload = b"read-only";
        if call(
            Syscall::MqTimedsend.raw(),
            a3(fd, payload.as_ptr() as u64, payload.len() as u64, 0),
        ) != Some(EBADF)
        {
            return Err("mq_timedsend accepted an O_RDONLY mqd");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_linux_descriptor_semantics);

fn smoke_abi_ipc_mq_priority_and_expired_timeout() -> TestResult {
    with_setup(|| {
        let fd = open_mq(b"abi_mq_timeout\0")?;
        let payload = b"priority";
        if call(
            Syscall::MqTimedsend.raw(),
            a3(fd, payload.as_ptr() as u64, payload.len() as u64, 32_768),
        ) != Some(EINVAL)
        {
            return Err("mq_timedsend accepted priority == MQ_PRIO_MAX");
        }
        let timeout = [0i64, 0];
        let mut receive = [0u8; 8192];
        let args = SyscallArgs {
            arg0: fd,
            arg1: receive.as_mut_ptr() as u64,
            arg2: receive.len() as u64,
            arg4: timeout.as_ptr() as u64,
            ..SyscallArgs::default()
        };
        if call(Syscall::MqTimedreceive.raw(), args) != Some(-110) {
            return Err("empty blocking mq_timedreceive ignored expired deadline");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_priority_and_expired_timeout);

fn smoke_abi_ipc_mq_notify_signal_once() -> TestResult {
    with_setup(|| {
        let fd = open_mq(b"abi_mq_notify\0")?;
        let mut event = [0u8; 64];
        event[8..12].copy_from_slice(&10i32.to_ne_bytes()); // SIGUSR1
        event[12..16].copy_from_slice(&0i32.to_ne_bytes()); // SIGEV_SIGNAL
        if call(Syscall::MqNotify.raw(), a1(fd, event.as_ptr() as u64)) != Some(0) {
            return Err("mq_notify SIGEV_SIGNAL registration failed");
        }
        let payload = b"wake";
        if call(
            Syscall::MqTimedsend.raw(),
            a3(fd, payload.as_ptr() as u64, payload.len() as u64, 0),
        ) != Some(0)
        {
            return Err("send after mq_notify failed");
        }
        if crate::handlers::signal_pending_bits(FAKE_TASK) & crate::handlers::sig_bit(10) == 0 {
            return Err("mq_notify did not queue its signal");
        }
        let zero_fd = open_mq(b"abi_mq_notify_zero\0")?;
        let mut zero_event = [0u8; 64];
        zero_event[12..16].copy_from_slice(&0i32.to_ne_bytes()); // SIGEV_SIGNAL
        if call(
            Syscall::MqNotify.raw(),
            a1(zero_fd, zero_event.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("mq_notify rejected Linux's signal-zero registration");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_mq_notify_signal_once);

// ════════════════════════════════════════════════════════════════════
// System V semaphores
// ════════════════════════════════════════════════════════════════════

/// semget a private set of `nsems` semaphores; return the id.
fn make_semset(nsems: u64) -> Result<u64, &'static str> {
    // key = IPC_PRIVATE (0) always allocates a fresh set.
    match call(Syscall::Semget.raw(), a2(0, nsems, IPC_CREAT)) {
        Some(id) if id > 0 => Ok(id as u64),
        _ => Err("setup: semget IPC_PRIVATE failed"),
    }
}

// ── Semget ──────────────────────────────────────────────────────────

fn smoke_abi_ipc_semget_pos() -> TestResult {
    with_setup(|| {
        // IPC_PRIVATE, 2 sems, create → new id > 0.
        match call(Syscall::Semget.raw(), a2(0, 2, IPC_CREAT)) {
            Some(id) if id > 0 => Ok(()),
            _ => Err("semget IPC_PRIVATE should return a positive id"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semget_pos);

fn smoke_abi_ipc_semget_neg() -> TestResult {
    with_setup(|| {
        // nsems = 0 on a create → EINVAL.
        match call(Syscall::Semget.raw(), a2(0, 0, IPC_CREAT)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("semget with nsems=0 must be EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semget_neg);

// ── Semop ───────────────────────────────────────────────────────────
//
// semop(semid, sops, nsops). struct sembuf { u16 sem_num; i16 sem_op;
// i16 sem_flg; } = 6 bytes. A +1 op on sem 0 succeeds → 0.

fn smoke_abi_ipc_semop_pos() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        // sembuf { sem_num=0, sem_op=+1, sem_flg=0 }
        let mut sop = [0u8; 6];
        sop[0..2].copy_from_slice(&0u16.to_le_bytes());
        sop[2..4].copy_from_slice(&1i16.to_le_bytes());
        match call(Syscall::Semop.raw(), a2(id, sop.as_ptr() as u64, 1)) {
            Some(0) => Ok(()),
            _ => Err("semop +1 on a fresh sem should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semop_pos);

fn smoke_abi_ipc_semop_neg() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        // A -1 op on a zero-valued semaphore would block; non-blocking
        // handler returns EAGAIN.
        let mut sop = [0u8; 6];
        sop[0..2].copy_from_slice(&0u16.to_le_bytes());
        sop[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        match call(Syscall::Semop.raw(), a2(id, sop.as_ptr() as u64, 1)) {
            Some(v) if v == EAGAIN => Ok(()),
            _ => Err("semop -1 on a 0 sem must be EAGAIN (non-blocking)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semop_neg);

// A multi-sop semop is all-or-nothing across the sops array, accumulating
// repeated sem_num within the call (Linux atomic-block semantics). Set sem 0
// to 1, then submit {sem0 -1, sem0 -1}: the first -1 succeeds (1→0), the
// second would block, so the WHOLE op is rolled back — sem 0 stays 1.
fn smoke_abi_ipc_semop_atomic_rollback() -> TestResult {
    with_setup(|| {
        let id = make_semset(2)?;
        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 1)) != Some(0) {
            return Err("setup: SETVAL sem0=1 failed");
        }
        // Two ops on the SAME sem_num: -1 then -1. Running value hits -1 on
        // the second, so the whole op must be EAGAIN with no net change.
        let mut sops = [0u8; 12];
        // sop0: sem_num=0, sem_op=-1
        sops[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        // sop1: sem_num=0, sem_op=-1
        sops[6..8].copy_from_slice(&0u16.to_le_bytes());
        sops[8..10].copy_from_slice(&(-1i16).to_le_bytes());
        match call(Syscall::Semop.raw(), a2(id, sops.as_ptr() as u64, 2)) {
            Some(v) if v == EAGAIN => {}
            _ => return Err("blocking multi-sop semop must return EAGAIN"),
        }
        // Rollback must have restored sem 0 to 1 (not left it at 0).
        match call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) {
            Some(1) => Ok(()),
            _ => Err("failed multi-sop semop left a partial delta (rollback bug)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semop_atomic_rollback);

// A multi-sop semop that fully succeeds applies every delta. Set sem0=0,
// sem1=5; submit {sem0 +2, sem1 -5, sem0 +1}: all satisfiable → sem0=3,
// sem1=0.
fn smoke_abi_ipc_semop_multi_commit() -> TestResult {
    with_setup(|| {
        let id = make_semset(2)?;
        if call(Syscall::Semctl.raw(), a3(id, 1, SETVAL, 5)) != Some(0) {
            return Err("setup: SETVAL sem1=5 failed");
        }
        let mut sops = [0u8; 18];
        // sop0: sem0 += 2
        sops[2..4].copy_from_slice(&2i16.to_le_bytes());
        // sop1: sem1 -= 5
        sops[6..8].copy_from_slice(&1u16.to_le_bytes());
        sops[8..10].copy_from_slice(&(-5i16).to_le_bytes());
        // sop2: sem0 += 1
        sops[12..14].copy_from_slice(&0u16.to_le_bytes());
        sops[14..16].copy_from_slice(&1i16.to_le_bytes());
        if call(Syscall::Semop.raw(), a2(id, sops.as_ptr() as u64, 3)) != Some(0) {
            return Err("satisfiable multi-sop semop should return 0");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(3) {
            return Err("sem0 should be 3 after +2 then +1");
        }
        match call(Syscall::Semctl.raw(), a3(id, 1, GETVAL, 0)) {
            Some(0) => Ok(()),
            _ => Err("sem1 should be 0 after -5"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semop_multi_commit);

// Many private sem sets are created and each is independently addressable —
// exercises the keyed id lookup that replaced the old scratch-clone path.
fn smoke_abi_ipc_semget_many_lookup() -> TestResult {
    with_setup(|| {
        const N: usize = 64;
        let mut ids = [0u64; N];
        for (i, slot) in ids.iter_mut().enumerate() {
            let id = make_semset(1)?;
            // Stamp a distinct value so a mixed-up id shows up on read-back.
            if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, i as u64)) != Some(0) {
                return Err("setup: SETVAL failed");
            }
            *slot = id;
        }
        // Every set must still read back exactly its stamped value.
        for (i, &id) in ids.iter().enumerate() {
            match call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) {
                Some(v) if v == i as i64 => {}
                _ => return Err("a sem set read back a foreign value (id lookup bug)"),
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semget_many_lookup);

// ── Semtimedop ──────────────────────────────────────────────────────
//
// Same shape as semop with a trailing timeout (ignored — never blocks).

fn smoke_abi_ipc_semtimedop_pos() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut sop = [0u8; 6];
        sop[0..2].copy_from_slice(&0u16.to_le_bytes());
        sop[2..4].copy_from_slice(&2i16.to_le_bytes());
        // arg3 = timeout pointer (ignored); pass 0.
        match call(Syscall::Semtimedop.raw(), a3(id, sop.as_ptr() as u64, 1, 0)) {
            Some(0) => Ok(()),
            _ => Err("semtimedop +2 should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semtimedop_pos);

fn smoke_abi_ipc_semtimedop_neg() -> TestResult {
    with_setup(|| {
        // nsops = 0 → EINVAL (checked before any semid lookup).
        match call(Syscall::Semtimedop.raw(), a3(1, 0x1000, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("semtimedop nsops=0 must be EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semtimedop_neg);

// ── Semctl ──────────────────────────────────────────────────────────
//
// semctl(semid, semnum, cmd, arg). SETVAL then GETVAL round-trips.

fn smoke_abi_ipc_semctl_pos() -> TestResult {
    with_setup(|| {
        let id = make_semset(2)?;
        // SETVAL sem 1 = 5.
        let s = call(Syscall::Semctl.raw(), a3(id, 1, SETVAL, 5));
        if s != Some(0) {
            return Err("semctl SETVAL should return 0");
        }
        // GETVAL sem 1 → 5.
        match call(Syscall::Semctl.raw(), a3(id, 1, GETVAL, 0)) {
            Some(5) => Ok(()),
            _ => Err("semctl GETVAL should read back the SETVAL value"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semctl_pos);

fn smoke_abi_ipc_semctl_neg() -> TestResult {
    with_setup(|| {
        // IPC_RMID on a non-existent id → EINVAL.
        match call(Syscall::Semctl.raw(), a3(987654, 0, IPC_RMID, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("semctl IPC_RMID on a bad id must be EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semctl_neg);

// ════════════════════════════════════════════════════════════════════
// System V message queues
// ════════════════════════════════════════════════════════════════════

/// msgget a private queue; return the id.
fn make_msgq() -> Result<u64, &'static str> {
    match call(Syscall::Msgget.raw(), a1(0, IPC_CREAT)) {
        Some(id) if id > 0 => Ok(id as u64),
        _ => Err("setup: msgget IPC_PRIVATE failed"),
    }
}

// ── Msgget ──────────────────────────────────────────────────────────

fn smoke_abi_ipc_msgget_pos() -> TestResult {
    with_setup(|| {
        // msgget(key=IPC_PRIVATE, msgflg=IPC_CREAT) → new id > 0.
        match call(Syscall::Msgget.raw(), a1(0, IPC_CREAT)) {
            Some(id) if id > 0 => Ok(()),
            _ => Err("msgget IPC_PRIVATE should return a positive id"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgget_pos);

fn smoke_abi_ipc_msgget_neg() -> TestResult {
    with_setup(|| {
        // A non-private key with no IPC_CREAT that doesn't exist → ENOENT.
        match call(Syscall::Msgget.raw(), a1(0x5151, 0)) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("msgget of a missing key without IPC_CREAT must be ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgget_neg);

// ── Msgsnd ──────────────────────────────────────────────────────────
//
// msgsnd(msqid, msgp, msgsz, msgflg). msgp = { i64 mtype; u8 mtext[]; }.

fn smoke_abi_ipc_msgsnd_pos() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        // mtype = 1, payload = "ping".
        let mut buf = [0u8; 8 + 4];
        buf[0..8].copy_from_slice(&1i64.to_le_bytes());
        buf[8..12].copy_from_slice(b"ping");
        match call(Syscall::Msgsnd.raw(), a3(id, buf.as_ptr() as u64, 4, 0)) {
            Some(0) => Ok(()),
            _ => Err("msgsnd of a valid message should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgsnd_pos);

fn smoke_abi_ipc_msgsnd_neg() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        // mtype <= 0 is invalid → EINVAL.
        let mut buf = [0u8; 8 + 2];
        buf[0..8].copy_from_slice(&0i64.to_le_bytes());
        match call(Syscall::Msgsnd.raw(), a3(id, buf.as_ptr() as u64, 2, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("msgsnd with mtype<=0 must be EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgsnd_neg);

// ── Msgrcv ──────────────────────────────────────────────────────────
//
// msgrcv(msqid, msgp, msgsz, msgtyp, msgflg). Returns the payload length.

fn smoke_abi_ipc_msgrcv_pos() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        let mut sbuf = [0u8; 8 + 4];
        sbuf[0..8].copy_from_slice(&1i64.to_le_bytes());
        sbuf[8..12].copy_from_slice(b"pong");
        if call(Syscall::Msgsnd.raw(), a3(id, sbuf.as_ptr() as u64, 4, 0)) != Some(0) {
            return Err("setup: msgsnd failed");
        }
        // msgtyp = 0 (any), msgsz = 4.
        let mut rbuf = [0u8; 8 + 4];
        let r = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: rbuf.as_mut_ptr() as u64,
                arg2: 4,
                arg3: 0,
                arg4: 0,
                ..Default::default()
            },
        );
        if r.status != SyscallReturn::OK {
            return Err("msgrcv returned non-Ok status");
        }
        if r.value as i64 != 4 {
            return Err("msgrcv should return the 4-byte payload length");
        }
        if &rbuf[8..12] == b"pong" {
            Ok(())
        } else {
            Err("msgrcv payload mismatch")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgrcv_pos);

fn smoke_abi_ipc_msgrcv_neg() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        // Empty queue (no msgsnd) → ENOMSG (non-blocking).
        let mut rbuf = [0u8; 8 + 4];
        let r = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: rbuf.as_mut_ptr() as u64,
                arg2: 4,
                arg3: 0,
                arg4: 0,
                ..Default::default()
            },
        );
        // ENOMSG = -42 (not in the harness errno table).
        if r.status == SyscallReturn::OK && r.value as i64 == -42 {
            Ok(())
        } else {
            Err("msgrcv on an empty queue must be ENOMSG (-42)")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgrcv_neg);

// msgrcv type selection with the two-write output path: send mtype 3 then
// mtype 1; msgtyp=1 must skip the type-3 message and deliver the type-1 one,
// writing the mtype header and payload correctly.
fn smoke_abi_ipc_msgrcv_type_select() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        // Send type 3 = "three", then type 1 = "one!".
        let mut s3 = [0u8; 8 + 5];
        s3[0..8].copy_from_slice(&3i64.to_le_bytes());
        s3[8..13].copy_from_slice(b"three");
        if call(Syscall::Msgsnd.raw(), a3(id, s3.as_ptr() as u64, 5, 0)) != Some(0) {
            return Err("setup: msgsnd type 3 failed");
        }
        let mut s1 = [0u8; 8 + 4];
        s1[0..8].copy_from_slice(&1i64.to_le_bytes());
        s1[8..12].copy_from_slice(b"one!");
        if call(Syscall::Msgsnd.raw(), a3(id, s1.as_ptr() as u64, 4, 0)) != Some(0) {
            return Err("setup: msgsnd type 1 failed");
        }
        // msgtyp = 1 → first message of exactly type 1 (skips the type-3 head).
        let mut rbuf = [0xEEu8; 8 + 8];
        let r = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: rbuf.as_mut_ptr() as u64,
                arg2: 8,
                arg3: 1, // msgtyp
                arg4: 0,
                ..Default::default()
            },
        );
        if r.status != SyscallReturn::OK || r.value as i64 != 4 {
            return Err("msgrcv(msgtyp=1) should return the 4-byte type-1 payload");
        }
        if i64::from_le_bytes(rbuf[0..8].try_into().unwrap()) != 1 {
            return Err("msgrcv wrote the wrong mtype header");
        }
        if &rbuf[8..12] != b"one!" {
            return Err("msgrcv delivered the wrong (type-3) message body");
        }
        // The type-3 message must still be queued: a msgtyp=0 recv gets it.
        let mut r2 = [0u8; 8 + 8];
        let g = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: r2.as_mut_ptr() as u64,
                arg2: 8,
                arg3: 0,
                arg4: 0,
                ..Default::default()
            },
        );
        if g.value as i64 != 5 || &r2[8..13] != b"three" {
            return Err("the skipped type-3 message was not left on the queue");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgrcv_type_select);

// ── Msgctl ──────────────────────────────────────────────────────────

fn smoke_abi_ipc_msgctl_pos() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        // IPC_RMID on a live queue → 0.
        match call(Syscall::Msgctl.raw(), a2(id, IPC_RMID, 0)) {
            Some(0) => Ok(()),
            _ => Err("msgctl IPC_RMID on a live queue should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgctl_pos);

fn smoke_abi_ipc_msgctl_neg() -> TestResult {
    with_setup(|| {
        // IPC_RMID on a non-existent id → EINVAL.
        match call(Syscall::Msgctl.raw(), a2(987654, IPC_RMID, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("msgctl IPC_RMID on a bad id must be EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgctl_neg);

// ════════════════════════════════════════════════════════════════════
// System V shared memory (linux-compat: sys_shmget_compat / shmat / …)
// ════════════════════════════════════════════════════════════════════

// ── Shmget ──────────────────────────────────────────────────────────
//
// shmget(key, size, shmflg). Backed by the narf-shmem registry (vtable
// installed by a Subsys initcall before the test phase). key != 0 with
// IPC_CREAT allocates a real segment; the returned shmid is positive.

fn smoke_abi_ipc_shmget_pos() -> TestResult {
    with_setup(|| {
        // A private create (key=0, IPC_CREAT) → positive shmid.
        match call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT)) {
            Some(id) if id > 0 => Ok(()),
            Some(v) => {
                let _ = v;
                Err("shmget create returned a non-positive id (vtable wired at boot?)")
            }
            None => Err("shmget returned non-Ok status (shmem vtable absent)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmget_pos);

fn smoke_abi_ipc_shmget_neg() -> TestResult {
    with_setup(|| {
        // A non-zero key that does not exist and no IPC_CREAT → ENOENT.
        // This path returns before the vtable is consulted, so it is
        // deterministic regardless of shmem wiring.
        match call(Syscall::Shmget.raw(), a2(0x6161, 4096, 0)) {
            Some(v) if v == ENOENT => Ok(()),
            _ => Err("shmget of a missing key without IPC_CREAT must be ENOENT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmget_neg);

// ── Shmat ───────────────────────────────────────────────────────────
//
// shmat(shmid, shmaddr, shmflg). The success path maps frames into the
// caller's address space, which the harness has none of — so only the
// invalid-shmid error path (returned before the AS lookup) is reachable.

fn smoke_abi_ipc_shmat_neg() -> TestResult {
    with_setup(|| {
        // Unknown shmid → EINVAL (segment lookup fails first).
        match call(Syscall::Shmat.raw(), a2(987654, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("shmat on a bad shmid must be EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmat_neg);

// ── Shmdt ───────────────────────────────────────────────────────────
//
// shmdt(shmaddr). The handler dereferences current_address_space() FIRST,
// which is None in this harness, so it returns invalid_op() for every
// input — neither the ok(0) nor the -EINVAL Linux paths are reachable.

fn smoke_abi_ipc_shmdt_neg() -> TestResult {
    with_setup(|| {
        // No address space → invalid_op (call() returns None).
        // LINUX-GAP: Linux returns -EINVAL for an unmapped/unknown addr;
        // here the missing-AS guard short-circuits to a non-Ok status.
        match call(Syscall::Shmdt.raw(), a0(0x4000_0000)) {
            None => Ok(()),
            Some(_) => Err("shmdt with no address space should be invalid_op (None)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmdt_neg);

// ── Shmctl ──────────────────────────────────────────────────────────
//
// shmctl(shmid, cmd, buf). IPC_RMID on an unknown id → -EINVAL; IPC_STAT
// with buf=0 on an unknown id → -EINVAL. A real positive path needs a
// segment, which requires the vtable-backed shmget — covered separately.

fn smoke_abi_ipc_shmctl_pos() -> TestResult {
    with_setup(|| {
        // Create a real segment, then IPC_STAT (buf=0) → 0.
        let id = match call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT)) {
            Some(id) if id > 0 => id as u64,
            _ => return Err("setup: shmget create failed (shmem vtable absent?)"),
        };
        let stat = call(Syscall::Shmctl.raw(), a3(id, IPC_STAT, 0, 0));
        if stat != Some(0) {
            return Err("shmctl IPC_STAT (buf=0) on a live segment should return 0");
        }
        // Clean up: IPC_RMID → 0.
        match call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0)) {
            Some(0) => Ok(()),
            _ => Err("shmctl IPC_RMID on a live segment should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmctl_pos);

fn smoke_abi_ipc_shmctl_neg() -> TestResult {
    with_setup(|| {
        // IPC_RMID on a non-existent id → EINVAL (no vtable dependency).
        match call(Syscall::Shmctl.raw(), a2(987654, IPC_RMID, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("shmctl IPC_RMID on a bad shmid must be EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmctl_neg);

// #33: shmctl(IPC_STAT) fills shm_cpid (creator) at offset 80, translated into
// the reader's namespace, instead of leaving it caller-zeroed. shm_lpid stays
// 0 until the first shmat (unreachable here — no live AS).
fn smoke_abi_ipc_shmctl_cpid() -> TestResult {
    with_setup(|| {
        const C_TASK: u64 = 0x7500_0000;
        const C_PID: u64 = 0x00AB_CDEF; // fits shm_cpid's 4 bytes

        crate::task::release_task(C_TASK);
        let _ = crate::task::Task::new_registered(C_TASK, C_PID);
        crate::handlers::register_task_to_pid(C_TASK, C_PID);
        crate::handlers::register_pid_task_mapping(C_PID, C_TASK);

        let result = (|| {
            set_task(C_TASK);
            let id = match call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT)) {
                Some(id) if id > 0 => id as u64,
                _ => return Err("setup: shmget create failed (shmem vtable absent?)"),
            };
            let mut buf = [0u8; 112];
            if call(
                Syscall::Shmctl.raw(),
                a3(id, IPC_STAT, buf.as_mut_ptr() as u64, 0),
            ) != Some(0)
            {
                return Err("shmctl IPC_STAT into a buffer should return 0");
            }
            let segsz = u64::from_le_bytes(buf[48..56].try_into().unwrap());
            let cpid = u32::from_le_bytes(buf[80..84].try_into().unwrap());
            let lpid = u32::from_le_bytes(buf[84..88].try_into().unwrap());
            let _ = call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0));
            if segsz != 4096 {
                Err("shmctl IPC_STAT shm_segsz (offset 48) wrong")
            } else if cpid as u64 != C_PID {
                Err("shmctl IPC_STAT shm_cpid (offset 80) was not the creator's pid — left caller-zeroed (#33 bug)")
            } else if lpid != 0 {
                Err("shm_lpid should be 0 before any shmat")
            } else {
                Ok(())
            }
        })();
        set_task(FAKE_TASK);
        crate::task::release_task(C_TASK);
        result
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmctl_cpid);

// ════════════════════════════════════════════════════════════════════
// NARF-native shmem registry (ShmemCreate / ShmemMap / ShmemDestroy)
// ════════════════════════════════════════════════════════════════════

// ── ShmemCreate ─────────────────────────────────────────────────────
//
// ShmemCreate(len): arg0 = length. Returns an opaque handle (ok) or
// invalid_op() when the registry rejects it (len=0 → BadLen → handle 0).

fn smoke_abi_ipc_shmem_create_pos() -> TestResult {
    with_setup(|| {
        // A 4 KiB segment → positive handle. Destroy it to clean up.
        match call(Syscall::ShmemCreate.raw(), a0(4096)) {
            Some(h) if h > 0 => {
                let _ = call(Syscall::ShmemDestroy.raw(), a0(h as u64));
                Ok(())
            }
            Some(_) => Err("shmem_create returned a non-positive handle"),
            None => Err("shmem_create returned invalid_op (shmem vtable absent)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmem_create_pos);

fn smoke_abi_ipc_shmem_create_neg() -> TestResult {
    with_setup(|| {
        // len = 0 → registry BadLen → handle 0 → invalid_op (None).
        // (Also the path taken when the vtable is absent — either way None.)
        match call(Syscall::ShmemCreate.raw(), a0(0)) {
            None => Ok(()),
            Some(_) => Err("shmem_create(0) should be invalid_op (None)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmem_create_neg);

// ── ShmemMap ────────────────────────────────────────────────────────
//
// ShmemMap(handle): maps the owning segment's frames into the AS. The
// harness has no address space, AND a foreign/unknown handle fails the
// pid-ownership check first — both lead to invalid_op(). Only the
// negative path is reachable.

fn smoke_abi_ipc_shmem_map_neg() -> TestResult {
    with_setup(|| {
        // Unknown handle → pid_of(handle)=0 != FAKE_TASK → invalid_op.
        // LINUX-GAP: not a Linux syscall (NARF-native); no errno wire
        // value — failure is a non-Ok NARF status, not -EINVAL.
        match call(Syscall::ShmemMap.raw(), a0(987654)) {
            None => Ok(()),
            Some(_) => Err("shmem_map of a foreign/unknown handle should be invalid_op (None)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmem_map_neg);

// ── ShmemDestroy ────────────────────────────────────────────────────
//
// ShmemDestroy(handle): the owner destroys its segment (ok(0)); a foreign
// or unknown handle fails the pid check → invalid_op().

fn smoke_abi_ipc_shmem_destroy_pos() -> TestResult {
    with_setup(|| {
        // Create as FAKE_TASK, then destroy as the same task → ok(0).
        let h = match call(Syscall::ShmemCreate.raw(), a0(4096)) {
            Some(h) if h > 0 => h as u64,
            _ => return Err("setup: shmem_create failed (shmem vtable absent?)"),
        };
        match call(Syscall::ShmemDestroy.raw(), a0(h)) {
            Some(0) => Ok(()),
            _ => Err("shmem_destroy of an owned handle should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmem_destroy_pos);

fn smoke_abi_ipc_shmem_destroy_neg() -> TestResult {
    with_setup(|| {
        // Unknown handle → pid mismatch → invalid_op (None).
        match call(Syscall::ShmemDestroy.raw(), a0(987654)) {
            None => Ok(()),
            Some(_) => Err("shmem_destroy of an unknown handle should be invalid_op (None)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmem_destroy_neg);
