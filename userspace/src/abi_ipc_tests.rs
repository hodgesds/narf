//! Linux syscall ABI conformance — ipc group.
//!
//! Covers POSIX message queues (`mq_*`), System V semaphores / message
//! queues / shared memory (`sem* / msg* / shm*`), and the NARF-native
//! `shmem_*` registry surface. Shares the harness in
//! [`crate::abi_test_support`].
//!
//! Harness caveats that shape these tests:
//!   * The default fixture has no user address space. Focused System V shared
//!     memory tests install a fresh real `AddressSpace` for their duration so
//!     `shmat`/`shmdt` success and rollback paths are exercised.
//!   * `copy_to_user` / `copy_from_user` validate canonicality + length
//!     only (not user-vs-kernel range), so kernel-stack buffers round-trip
//!     fine — the side-table IPC objects (`sem*`, `msg*`, `mq_*`) exercise
//!     full positive paths.
//!   * The `narf_shmem` syscall vtable is installed by a `Stage::Subsys`
//!     initcall before the test phase runs, so `shmem_create` / `shmget`
//!     reach real frame backing.
#![allow(dead_code)] // errno/flag reference table + harness helpers

use crate::abi_test_support::*;
use alloc::sync::Arc;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};

// IPC flag bits (octal, matching the handlers).
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const IPC_64: u64 = 0x100;
const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_EXEC: u64 = 0o100000;
const SHM_LOCK: u64 = 11;
const SHM_UNLOCK: u64 = 12;
const SHM_STAT: u64 = 13;
const SHM_INFO: u64 = 14;
const SHM_STAT_ANY: u64 = 15;
const SHM_LOCKED: u32 = 0o2000;
// shmget-only shmflg bits (include/uapi/linux/shm.h). SHM_HUGETLB shares its
// value with IPC_NOWAIT, which shmget never consults.
const SHM_HUGETLB: u64 = 0o4000;
const SHM_NORESERVE: u64 = 0o10000;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;
const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SEM_STAT: u64 = 18;
const SEM_INFO: u64 = 19;
const SEM_STAT_ANY: u64 = 20;
const MSG_STAT: u64 = 11;
const MSG_INFO: u64 = 12;
const MSG_STAT_ANY: u64 = 13;
const IPCMNI_IDX_MASK: u64 = (1 << 15) - 1;
const E2BIG: i64 = -7;
const EFBIG: i64 = -27;
const ENOMSG: i64 = -42;
const MSG_NOERROR: u64 = 0o10000;
const MSG_COPY: u64 = 0o40000;
const SEM_UNDO: i16 = 0o10000;
const EIDRM: i64 = -43;
const ENOSPC: i64 = -28;
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_RDWR: u64 = 0o2;
const O_RDONLY: u64 = 0;
const O_NONBLOCK: u64 = 0o4000;

static IPC_SHM_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

fn lookup_ipc_shm_as() -> Option<Arc<AddressSpace>> {
    IPC_SHM_AS.lock().clone()
}

fn with_ipc_shm_as(
    body: impl FnOnce(&Arc<AddressSpace>) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    // SAFETY: kernel tests run after paging is enabled; the new root remains
    // owned by IPC_SHM_AS for the complete syscall sequence.
    let as_ref = match unsafe { AddressSpace::new_for_user() } {
        Ok(as_ref) => Arc::new(as_ref),
        Err(_) => return Err("failed to create shared-memory test address space"),
    };
    *IPC_SHM_AS.lock() = Some(Arc::clone(&as_ref));
    crate::handlers::install_address_space_lookup(lookup_ipc_shm_as);
    let result = body(&as_ref);
    crate::handlers::restore_address_space_lookup(None);
    *IPC_SHM_AS.lock() = None;
    result
}

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
        Some(id) if id >= 0 => Ok(id as u64),
        _ => Err("setup: semget IPC_PRIVATE failed"),
    }
}

// ── Semget ──────────────────────────────────────────────────────────

fn smoke_abi_ipc_semget_pos() -> TestResult {
    with_setup(|| {
        // IPC_PRIVATE, 2 sems, create → a non-negative Linux SysV id.
        match call(Syscall::Semget.raw(), a2(0, 2, IPC_CREAT)) {
            Some(id) if id >= 0 => Ok(()),
            _ => Err("semget IPC_PRIVATE should return a non-negative id"),
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

#[cfg(feature = "kernel-test")]
fn smoke_abi_ipc_distinct_sem_sets_do_not_share_mutation_lock() -> TestResult {
    with_setup(|| {
        let locked = make_semset(1)?;
        let active = make_semset(1)?;
        if crate::sysvipc::__test_sem_sets_lock_independently(locked, active) != Some(true) {
            return Err("distinct semaphore sets did not own independent mutation locks");
        }
        if call(Syscall::Semctl.raw(), a3(active, 0, SETVAL, 3)) != Some(0)
            || call(Syscall::Semctl.raw(), a3(active, 0, GETVAL, 0)) != Some(3)
        {
            return Err("operation on independently locked semaphore set failed");
        }
        if call(Syscall::Semctl.raw(), a3(locked, 0, GETVAL, 0)) != Some(0) {
            return Err("unrelated semaphore set was modified");
        }
        Ok(())
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_distinct_sem_sets_do_not_share_mutation_lock
);

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
        sop[4..6].copy_from_slice(&(IPC_NOWAIT as i16).to_le_bytes());
        match call(Syscall::Semop.raw(), a2(id, sop.as_ptr() as u64, 1)) {
            Some(v) if v == EAGAIN => Ok(()),
            _ => Err("semop IPC_NOWAIT -1 on a 0 sem must be EAGAIN"),
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
        sops[4..6].copy_from_slice(&(IPC_NOWAIT as i16).to_le_bytes());
        // sop1: sem_num=0, sem_op=-1
        sops[6..8].copy_from_slice(&0u16.to_le_bytes());
        sops[8..10].copy_from_slice(&(-1i16).to_le_bytes());
        sops[10..12].copy_from_slice(&(IPC_NOWAIT as i16).to_le_bytes());
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

// Linux checks SEMOPM before importing sops, but a non-null semtimedop timeout
// is imported by the wrapper before either check.
fn smoke_abi_ipc_semop_errno_order() -> TestResult {
    with_setup(|| {
        if call(Syscall::Semop.raw(), a2(u64::MAX, BAD_PTR, 501)) != Some(E2BIG) {
            return Err("semop nsops>SEMOPM must be E2BIG before sops/semid access");
        }
        if call(Syscall::Semop.raw(), a2(u64::MAX, BAD_PTR, 1)) != Some(EFAULT) {
            return Err("semop bad sops must be EFAULT before semid lookup");
        }
        if call(Syscall::Semop.raw(), a2(u64::MAX, BAD_PTR, 0)) != Some(EINVAL) {
            return Err("semop nsops=0 must be EINVAL before sops access");
        }
        if call(
            Syscall::Semtimedop.raw(),
            a3(u64::MAX, BAD_PTR, 501, BAD_PTR),
        ) != Some(EFAULT)
        {
            return Err("semtimedop must import timeout before the nsops E2BIG check");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semop_errno_order);

fn smoke_abi_ipc_sem_undo_allocation_errno_order() -> TestResult {
    with_setup(|| {
        let mut zero_undo = [0u8; 6];
        zero_undo[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        let valid = make_semset(1)?;
        crate::sysvipc::__test_fail_next_sem_undo_reserve();
        if call(
            Syscall::Semop.raw(),
            a2(987_654, zero_undo.as_ptr() as u64, 1),
        ) != Some(EINVAL)
        {
            return Err("invalid semid must precede SEM_UNDO allocation");
        }
        if call(
            Syscall::Semop.raw(),
            a2(valid, zero_undo.as_ptr() as u64, 1),
        ) != Some(ENOMEM)
        {
            return Err("zero SEM_UNDO operation must allocate before evaluation");
        }

        let invalid_member = make_semset(1)?;
        let mut out_of_range = [0u8; 6];
        out_of_range[..2].copy_from_slice(&1u16.to_le_bytes());
        out_of_range[2..4].copy_from_slice(&1i16.to_le_bytes());
        out_of_range[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        crate::sysvipc::__test_fail_next_sem_undo_reserve();
        if call(
            Syscall::Semop.raw(),
            a2(invalid_member, out_of_range.as_ptr() as u64, 1),
        ) != Some(ENOMEM)
        {
            return Err("SEM_UNDO ENOMEM must precede EFBIG");
        }
        if call(
            Syscall::Semop.raw(),
            a2(invalid_member, out_of_range.as_ptr() as u64, 1),
        ) != Some(EFBIG)
        {
            return Err("out-of-range member must return EFBIG after undo allocation");
        }

        let denied = make_semset(1)?;
        let mut increment = [0u8; 6];
        increment[2..4].copy_from_slice(&1i16.to_le_bytes());
        increment[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        crate::handlers::__test_set_fsids(FAKE_TASK, 1000, 1000);
        crate::sysvipc::__test_fail_next_sem_undo_reserve();
        if call(
            Syscall::Semop.raw(),
            a2(denied, increment.as_ptr() as u64, 1),
        ) != Some(ENOMEM)
        {
            return Err("SEM_UNDO ENOMEM must precede EACCES");
        }
        if call(
            Syscall::Semop.raw(),
            a2(denied, increment.as_ptr() as u64, 1),
        ) != Some(EACCES)
        {
            return Err("denied operation must return EACCES after undo allocation");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_undo_allocation_errno_order
);

fn smoke_abi_ipc_semop_semopm_boundary() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut sops = alloc::vec![0u8; 500 * 6];
        for i in 0..500 {
            let offset = i * 6;
            let op = if i & 1 == 0 { 1i16 } else { -1i16 };
            sops[offset + 2..offset + 4].copy_from_slice(&op.to_le_bytes());
            sops[offset + 4..offset + 6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        }
        if call(Syscall::Semop.raw(), a2(id, sops.as_ptr() as u64, 500)) != Some(0) {
            return Err("semop must accept the exact Linux SEMOPM boundary");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0) {
            return Err("500-operation transaction did not preserve its net value");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_semop_semopm_boundary
);

fn smoke_abi_ipc_semop_flag_tolerance_bounds_and_blocking_retry() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut sop = [0u8; 6];
        sop[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        // Linux ignores sem_flg extension bits rather than rejecting them or
        // interpreting them as IPC_NOWAIT.
        sop[4..6].copy_from_slice(&0x2000i16.to_le_bytes());
        let blocked = call_raw(Syscall::Semop.raw(), a2(id, sop.as_ptr() as u64, 1));
        if blocked.value != 0xDEAD {
            return Err("blocking semop fabricated a completed errno/result");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 1)) != Some(0) {
            return Err("setup: SETVAL did not satisfy the blocked semop");
        }
        // The re-execution must use the kernel-owned sembuf snapshot retained
        // when the operation blocked, not this now-invalid user pointer.
        if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(0) {
            return Err("blocked semop did not retry its retained operation");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0) {
            return Err("retried semop did not apply its original decrement");
        }

        let mut out_of_range = [0u8; 6];
        out_of_range[..2].copy_from_slice(&1u16.to_le_bytes());
        out_of_range[2..4].copy_from_slice(&1i16.to_le_bytes());
        if call(
            Syscall::Semop.raw(),
            a2(id, out_of_range.as_ptr() as u64, 1),
        ) != Some(EFBIG)
        {
            return Err("semop sem_num outside the set must return EFBIG");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_semop_flag_tolerance_bounds_and_blocking_retry
);

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
// Same atomic operation as semop with a trailing relative timeout.

fn smoke_abi_ipc_semtimedop_pos() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut sop = [0u8; 6];
        sop[0..2].copy_from_slice(&0u16.to_le_bytes());
        sop[2..4].copy_from_slice(&2i16.to_le_bytes());
        // A null timeout is an indefinite wait, irrelevant on this ready op.
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

fn smoke_abi_ipc_semctl_pid_and_waiter_state() -> TestResult {
    with_setup(|| {
        let id = make_semset(2)?;
        if call(Syscall::Semctl.raw(), a3(id, 0, GETPID, 0)) != Some(0) {
            return Err("a newly-created semaphore must have sempid 0");
        }

        // SETALL attributes every member to the setter.
        const SETTER: u64 = FAKE_TASK + 10;
        set_task(SETTER);
        let values = [0u16, 1u16];
        if call(
            Syscall::Semctl.raw(),
            a3(id, 0, SETALL, values.as_ptr() as u64),
        ) != Some(0)
        {
            set_task(FAKE_TASK);
            return Err("setup: SETALL failed");
        }
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETPID, 0)) != Some(SETTER as i64)
            || call(Syscall::Semctl.raw(), a3(id, 1, GETPID, 0)) != Some(SETTER as i64)
        {
            return Err("SETALL did not publish the setter as sempid for every member");
        }

        // A complex operation is counted only on its first blocking sembuf:
        // sem0 -1 blocks first, even though the later sem1 zero-wait also
        // cannot proceed. A second task waits directly for sem1 to reach zero.
        const ALTER_WAITER: u64 = FAKE_TASK + 11;
        const ZERO_WAITER: u64 = FAKE_TASK + 12;
        let mut complex = [0u8; 12];
        complex[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        complex[6..8].copy_from_slice(&1u16.to_le_bytes());
        set_task(ALTER_WAITER);
        if call_raw(Syscall::Semop.raw(), a2(id, complex.as_ptr() as u64, 2)).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("setup: decrement waiter did not block");
        }
        let mut wait_zero = [0u8; 6];
        wait_zero[..2].copy_from_slice(&1u16.to_le_bytes());
        set_task(ZERO_WAITER);
        if call_raw(Syscall::Semop.raw(), a2(id, wait_zero.as_ptr() as u64, 1)).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("setup: zero waiter did not block");
        }
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETNCNT, 0)) != Some(1)
            || call(Syscall::Semctl.raw(), a3(id, 0, GETZCNT, 0)) != Some(0)
            || call(Syscall::Semctl.raw(), a3(id, 1, GETNCNT, 0)) != Some(0)
            || call(Syscall::Semctl.raw(), a3(id, 1, GETZCNT, 0)) != Some(1)
        {
            return Err("GETNCNT/GETZCNT did not classify each wait by its first blocker");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETPID, 0)) != Some(SETTER as i64)
            || call(Syscall::Semctl.raw(), a3(id, 1, GETPID, 0)) != Some(SETTER as i64)
        {
            return Err("blocked operations changed sempid before successful completion");
        }

        // Interrupting a waiter unlinks it from the observable count.
        crate::handlers::raise_signal_pending(ALTER_WAITER, 10);
        set_task(ALTER_WAITER);
        if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 2)) != Some(EINTR) {
            set_task(FAKE_TASK);
            return Err("interrupted semaphore waiter did not return EINTR");
        }
        crate::handlers::clear_signal_pending(ALTER_WAITER, 10);
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETNCNT, 0)) != Some(0) {
            return Err("interrupted waiter remained in GETNCNT");
        }

        // Satisfy and retry the zero waiter. The successful zero operation
        // updates sempid even though it does not alter semval.
        if call(Syscall::Semctl.raw(), a3(id, 1, SETVAL, 0)) != Some(0) {
            return Err("setup: SETVAL did not satisfy zero waiter");
        }
        set_task(ZERO_WAITER);
        if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("satisfied zero waiter did not complete");
        }
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 1, GETZCNT, 0)) != Some(0) {
            return Err("completed zero waiter remained in GETZCNT");
        }
        if call(Syscall::Semctl.raw(), a3(id, 1, GETPID, 0)) != Some(ZERO_WAITER as i64) {
            return Err("successful zero-wait operation did not update sempid");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_semctl_pid_and_waiter_state
);

/// Linux evaluates queued operations while holding the semaphore-set lock:
/// insertion order determines scan order, but an older unsatisfied request is
/// skipped rather than imposing head-of-line blocking. Completion is cached
/// before either task runs again, and repeated park registration owns only one
/// wake slot.
fn smoke_abi_ipc_sem_queue_handoff_order_and_waker_dedupe() -> TestResult {
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU32, Ordering};

    struct CountWake(AtomicU32);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    with_setup(|| {
        let id = make_semset(1)?;
        const OLDER: u64 = FAKE_TASK + 21;
        const YOUNGER: u64 = FAKE_TASK + 22;
        let mut minus_two = [0u8; 6];
        minus_two[2..4].copy_from_slice(&(-2i16).to_le_bytes());
        let mut minus_one = [0u8; 6];
        minus_one[2..4].copy_from_slice(&(-1i16).to_le_bytes());

        set_task(OLDER);
        if call_raw(Syscall::Semop.raw(), a2(id, minus_two.as_ptr() as u64, 1)).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("older -2 operation did not queue");
        }
        set_task(YOUNGER);
        if call_raw(Syscall::Semop.raw(), a2(id, minus_one.as_ptr() as u64, 1)).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("younger -1 operation did not queue");
        }

        let younger_wakes = Arc::new(CountWake(AtomicU32::new(0)));
        let younger_waker = core::task::Waker::from(Arc::clone(&younger_wakes));
        if crate::sysvipc::register_sem_wait_waker(YOUNGER, younger_waker.clone())
            != crate::sysvipc::SemParkState::Pending
            || crate::sysvipc::register_sem_wait_waker(YOUNGER, younger_waker)
                != crate::sysvipc::SemParkState::Pending
        {
            set_task(FAKE_TASK);
            return Err("queued waiter rejected durable waker registration");
        }

        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 1)) != Some(0) {
            return Err("SETVAL failed to drive queued handoff");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0)
            || call(Syscall::Semctl.raw(), a3(id, 0, GETNCNT, 0)) != Some(1)
        {
            return Err("scan did not skip -2 and commit younger eligible -1");
        }
        if younger_wakes.0.load(Ordering::Relaxed) != 1 {
            return Err("repeated registration produced duplicate wakes");
        }

        // The user's sembuf pointer is deliberately invalid: success must be
        // consumed from the cached terminal result, not re-imported/retried.
        set_task(YOUNGER);
        if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("completed waiter did not consume cached success");
        }
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 2)) != Some(0) {
            return Err("SETVAL failed to satisfy the remaining waiter");
        }
        set_task(OLDER);
        if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("older waiter did not receive its later handoff");
        }
        set_task(FAKE_TASK);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_queue_handoff_order_and_waker_dedupe
);

/// A single value transition can complete several semaphore operations.  The
/// allocation-free wake queue must preserve the set's handoff order rather
/// than the task-id order used by the global registration index.
fn smoke_abi_ipc_sem_wake_queue_batches_in_handoff_order() -> TestResult {
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU64, Ordering};

    struct OrderedWake {
        marker: u64,
        order: Arc<AtomicU64>,
    }

    impl OrderedWake {
        fn record(&self) {
            self.order
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                    Some(old * 10 + self.marker)
                })
                .expect("infallible wake-order update");
        }
    }

    impl Wake for OrderedWake {
        fn wake(self: Arc<Self>) {
            self.record();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.record();
        }
    }

    with_setup(|| {
        let id = make_semset(1)?;
        // Deliberately reverse task-id order so a scan of the global sorted
        // waiter index would produce 21 instead of the required FIFO 12.
        const FIRST: u64 = FAKE_TASK + 32;
        const SECOND: u64 = FAKE_TASK + 31;
        let mut decrement = [0u8; 6];
        decrement[2..4].copy_from_slice(&(-1i16).to_le_bytes());

        set_task(FIRST);
        if call_raw(Syscall::Semop.raw(), a2(id, decrement.as_ptr() as u64, 1)).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("first batch waiter did not queue");
        }
        set_task(SECOND);
        if call_raw(Syscall::Semop.raw(), a2(id, decrement.as_ptr() as u64, 1)).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("second batch waiter did not queue");
        }

        let order = Arc::new(AtomicU64::new(0));
        let first_waker = core::task::Waker::from(Arc::new(OrderedWake {
            marker: 1,
            order: Arc::clone(&order),
        }));
        let second_waker = core::task::Waker::from(Arc::new(OrderedWake {
            marker: 2,
            order: Arc::clone(&order),
        }));
        if crate::sysvipc::register_sem_wait_waker(FIRST, first_waker)
            != crate::sysvipc::SemParkState::Pending
            || crate::sysvipc::register_sem_wait_waker(SECOND, second_waker)
                != crate::sysvipc::SemParkState::Pending
        {
            set_task(FAKE_TASK);
            return Err("batch waiters rejected durable waker registration");
        }

        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 2)) != Some(0) {
            return Err("SETVAL failed to complete the waiter batch");
        }
        if order.load(Ordering::Relaxed) != 12 {
            return Err("batched semaphore wakes did not preserve handoff order");
        }

        for task in [FIRST, SECOND] {
            set_task(task);
            if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(0) {
                set_task(FAKE_TASK);
                return Err("batched waiter did not consume cached success");
            }
        }
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0) {
            return Err("batched semaphore operations were not committed atomically");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_wake_queue_batches_in_handoff_order
);

/// Linux unlinks an interrupted `sem_queue` directly from its intrusive list.
/// Removing a middle waiter must leave both FIFO neighbours linked and must
/// not change their handoff order.
fn smoke_abi_ipc_sem_middle_cancel_preserves_pending_fifo() -> TestResult {
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU64, Ordering};

    struct OrderedWake {
        marker: u64,
        order: Arc<AtomicU64>,
    }

    impl OrderedWake {
        fn record(&self) {
            self.order
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                    Some(old * 10 + self.marker)
                })
                .expect("infallible wake-order update");
        }
    }

    impl Wake for OrderedWake {
        fn wake(self: Arc<Self>) {
            self.record();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.record();
        }
    }

    with_setup(|| {
        let id = make_semset(1)?;
        let mut decrement = [0u8; 6];
        decrement[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        // Deliberately avoid task-id order so the global waiter index cannot
        // accidentally satisfy this FIFO assertion.
        const FIRST: u64 = FAKE_TASK + 35;
        const MIDDLE: u64 = FAKE_TASK + 33;
        const LAST: u64 = FAKE_TASK + 34;
        for task in [FIRST, MIDDLE, LAST] {
            set_task(task);
            if call_raw(Syscall::Semop.raw(), a2(id, decrement.as_ptr() as u64, 1)).value != 0xDEAD
            {
                set_task(FAKE_TASK);
                return Err("semaphore waiter did not enter the pending FIFO");
            }
        }

        let order = Arc::new(AtomicU64::new(0));
        for (task, marker) in [(FIRST, 1), (LAST, 3)] {
            let waker = core::task::Waker::from(Arc::new(OrderedWake {
                marker,
                order: Arc::clone(&order),
            }));
            if crate::sysvipc::register_sem_wait_waker(task, waker)
                != crate::sysvipc::SemParkState::Pending
            {
                set_task(FAKE_TASK);
                return Err("pending FIFO waiter rejected durable waker registration");
            }
        }

        set_task(MIDDLE);
        crate::handlers::raise_signal_pending(MIDDLE, 10);
        if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(EINTR) {
            crate::handlers::clear_signal_pending(MIDDLE, 10);
            set_task(FAKE_TASK);
            return Err("middle semaphore waiter did not cancel with EINTR");
        }
        crate::handlers::clear_signal_pending(MIDDLE, 10);

        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETNCNT, 0)) != Some(2) {
            return Err("middle cancellation corrupted the pending wait count");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 2)) != Some(0) {
            return Err("SETVAL failed to complete pending FIFO neighbours");
        }
        if order.load(Ordering::Relaxed) != 13 {
            return Err("middle cancellation changed neighbour handoff order");
        }
        for task in [FIRST, LAST] {
            set_task(task);
            if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(0) {
                set_task(FAKE_TASK);
                return Err("pending FIFO neighbour did not consume cached success");
            }
        }
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0)
            || call(Syscall::Semctl.raw(), a3(id, 0, GETNCNT, 0)) != Some(0)
        {
            return Err("pending FIFO retained stale state after completion");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_middle_cancel_preserves_pending_fifo
);

fn smoke_abi_ipc_sem_queue_timeout_and_undo_handoff() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut decrement = [0u8; 6];
        decrement[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        let zero_timeout = [0i64, 0i64];
        const TIMED: u64 = FAKE_TASK + 23;
        set_task(TIMED);
        crate::handlers::raise_signal_pending(TIMED, 10);
        if call(
            Syscall::Semtimedop.raw(),
            a3(
                id,
                decrement.as_ptr() as u64,
                1,
                zero_timeout.as_ptr() as u64,
            ),
        ) != Some(EAGAIN)
        {
            crate::handlers::clear_signal_pending(TIMED, 10);
            set_task(FAKE_TASK);
            return Err("expired semtimedop did not beat a simultaneous signal with EAGAIN");
        }
        crate::handlers::clear_signal_pending(TIMED, 10);
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETNCNT, 0)) != Some(0) {
            return Err("timed-out semaphore waiter remained linked");
        }

        const UNDO_WAITER: u64 = FAKE_TASK + 24;
        decrement[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        set_task(UNDO_WAITER);
        let undo_pid = u64::from(crate::handlers::current_ucred().pid);
        if call_raw(Syscall::Semop.raw(), a2(id, decrement.as_ptr() as u64, 1)).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("SEM_UNDO decrement did not queue");
        }
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 1)) != Some(0)
            || call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0)
        {
            return Err("SEM_UNDO queued handoff was not committed atomically");
        }
        set_task(UNDO_WAITER);
        if call(Syscall::Semop.raw(), a2(id, BAD_PTR, 1)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("SEM_UNDO waiter did not consume cached success");
        }
        crate::sysvipc::sem_undo_process_exit(undo_pid, UNDO_WAITER);
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(1) {
            return Err("exit did not reverse the queued SEM_UNDO handoff");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_queue_timeout_and_undo_handoff
);

fn smoke_abi_ipc_sem_exit_undo_is_set_atomic() -> TestResult {
    with_setup(|| {
        let id = make_semset(2)?;
        let initial = [1u16, 0u16];
        if call(
            Syscall::Semctl.raw(),
            a3(id, 0, SETALL, initial.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setup: SETALL [1,0] failed");
        }

        const OWNER: u64 = FAKE_TASK + 25;
        let mut establish = [0u8; 12];
        establish[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        establish[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        establish[6..8].copy_from_slice(&1u16.to_le_bytes());
        establish[8..10].copy_from_slice(&1i16.to_le_bytes());
        establish[10..12].copy_from_slice(&SEM_UNDO.to_le_bytes());
        set_task(OWNER);
        let owner_pid = u64::from(crate::handlers::current_ucred().pid);
        if call(Syscall::Semop.raw(), a2(id, establish.as_ptr() as u64, 2)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("setup: two-member SEM_UNDO transaction failed");
        }

        const WAITER: u64 = FAKE_TASK + 26;
        let mut decrement_both = [0u8; 12];
        decrement_both[2..4].copy_from_slice(&(-1i16).to_le_bytes());
        decrement_both[6..8].copy_from_slice(&1u16.to_le_bytes());
        decrement_both[8..10].copy_from_slice(&(-1i16).to_le_bytes());
        set_task(WAITER);
        if call_raw(
            Syscall::Semop.raw(),
            a2(id, decrement_both.as_ptr() as u64, 2),
        )
        .value
            != 0xDEAD
        {
            set_task(FAKE_TASK);
            return Err("setup: atomic decrement waiter did not block");
        }

        crate::sysvipc::sem_undo_process_exit(owner_pid, OWNER);
        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(1)
            || call(Syscall::Semctl.raw(), a3(id, 1, GETVAL, 0)) != Some(0)
        {
            return Err("exit exposed an intermediate SEM_UNDO set state");
        }
        if call(Syscall::Semctl.raw(), a3(id, 1, GETNCNT, 0)) != Some(1) {
            return Err("waiter committed between member-wise undo adjustments");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_exit_undo_is_set_atomic
);

fn smoke_abi_ipc_sem_exit_undo_retains_other_owners() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut increment = [0u8; 6];
        increment[2..4].copy_from_slice(&1i16.to_le_bytes());
        increment[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());

        const OWNER_A: u64 = FAKE_TASK + 27;
        set_task(OWNER_A);
        let owner_a_pid = u64::from(crate::handlers::current_ucred().pid);
        if call(Syscall::Semop.raw(), a2(id, increment.as_ptr() as u64, 1)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("setup: first owner's SEM_UNDO increment failed");
        }

        const OWNER_B: u64 = FAKE_TASK + 28;
        set_task(OWNER_B);
        let owner_b_pid = u64::from(crate::handlers::current_ucred().pid);
        if call(Syscall::Semop.raw(), a2(id, increment.as_ptr() as u64, 1)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("setup: second owner's SEM_UNDO increment failed");
        }

        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(2) {
            return Err("setup: both SEM_UNDO increments were not applied");
        }

        crate::sysvipc::sem_undo_process_exit(owner_a_pid, OWNER_A);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(1) {
            return Err("first owner exit did not apply exactly its SEM_UNDO entry");
        }

        crate::sysvipc::sem_undo_process_exit(owner_b_pid, OWNER_B);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0) {
            return Err("first owner exit discarded the second owner's SEM_UNDO entry");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_exit_undo_retains_other_owners
);

fn smoke_abi_ipc_semctl_observable_errno_order() -> TestResult {
    with_setup(|| {
        // Linux's SETVAL wrapper rejects the value before looking up semid.
        if call(
            Syscall::Semctl.raw(),
            a3(987_654, 999, SETVAL, u32::MAX as u64),
        ) != Some(ERANGE)
        {
            return Err("SETVAL must report ERANGE before semid/semnum lookup");
        }
        let id = make_semset(1)?;
        // semctl_main checks read permission before sem_num for GET*.
        crate::handlers::__test_set_fsids(FAKE_TASK, 1000, 1000);
        if call(Syscall::Semctl.raw(), a3(id, u32::MAX as u64, GETNCNT, 0)) != Some(EACCES) {
            return Err("GETNCNT must report EACCES before invalid sem_num");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_semctl_observable_errno_order
);

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

fn smoke_abi_ipc_semctl_stat_set_layout() -> TestResult {
    with_setup(|| {
        #[cfg(target_arch = "x86_64")]
        const SIZE: usize = 104;
        #[cfg(target_arch = "x86_64")]
        const NSEMS: usize = 80;
        #[cfg(target_arch = "aarch64")]
        const SIZE: usize = 88;
        #[cfg(target_arch = "aarch64")]
        const NSEMS: usize = 64;

        let id = make_semset(2)?;
        if call(Syscall::Semctl.raw(), a3(987_654, 0, IPC_STAT, BAD_PTR)) != Some(EINVAL) {
            return Err("semctl IPC_STAT must resolve id before copyout");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, IPC_STAT, BAD_PTR)) != Some(EFAULT) {
            return Err("live semctl IPC_STAT bad output must be EFAULT");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, IPC_STAT | IPC_64, BAD_PTR)) != Some(EINVAL) {
            return Err("native semctl must reject IPC_64 tagged commands");
        }
        let mut stat = [0u8; SIZE];
        if call(
            Syscall::Semctl.raw(),
            a3(id, 0, IPC_STAT, stat.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("semctl IPC_STAT failed");
        }
        if u64::from_ne_bytes(stat[NSEMS..NSEMS + 8].try_into().unwrap()) != 2 {
            return Err("semctl IPC_STAT wrote sem_nsems at the wrong ABI offset");
        }

        let mut update = [0u8; SIZE];
        update[20..24].copy_from_slice(&0o640u32.to_ne_bytes());
        if call(Syscall::Semctl.raw(), a3(987_654, 0, IPC_SET, BAD_PTR)) != Some(EFAULT) {
            return Err("semctl IPC_SET must import the full struct before id lookup");
        }
        if call(
            Syscall::Semctl.raw(),
            a3(id, 0, IPC_SET, update.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("semctl IPC_SET failed");
        }
        stat.fill(0);
        let _ = call(
            Syscall::Semctl.raw(),
            a3(id, 0, IPC_STAT, stat.as_mut_ptr() as u64),
        );
        if u32::from_ne_bytes(stat[20..24].try_into().unwrap()) & 0o777 != 0o640 {
            return Err("semctl IPC_SET mode did not round-trip through IPC_STAT");
        }
        let task = crate::handlers::current_task_id();
        crate::handlers::__test_set_fsids(task, 1000, 1000);
        if call(
            Syscall::Semctl.raw(),
            a3(id, 0, IPC_STAT, stat.as_mut_ptr() as u64),
        ) != Some(EACCES)
        {
            return Err("non-readable semctl IPC_STAT must return EACCES");
        }
        if call(
            Syscall::Semctl.raw(),
            a3(id, 0, IPC_SET, update.as_ptr() as u64),
        ) != Some(EPERM)
        {
            return Err("non-owner semctl IPC_SET must return EPERM");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_semctl_stat_set_layout);

fn smoke_abi_ipc_semctl_info_and_indexed_stat() -> TestResult {
    with_setup(|| {
        #[cfg(target_arch = "x86_64")]
        const STAT_SIZE: usize = 104;
        #[cfg(target_arch = "aarch64")]
        const STAT_SIZE: usize = 88;

        let read_i32 = |bytes: &[u8], offset: usize| {
            i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
        };
        let mut info = [0u8; 40];
        let _ = call_raw(
            Syscall::Semctl.raw(),
            a3(0, 0, SEM_INFO, info.as_mut_ptr() as u64),
        );
        let usage_before = (read_i32(&info, 28), read_i32(&info, 36));
        let id = make_semset(2)?;
        info.fill(0);
        let _ = call_raw(
            Syscall::Semctl.raw(),
            a3(id, 0, SEM_INFO, info.as_mut_ptr() as u64),
        );
        if (read_i32(&info, 28), read_i32(&info, 36)) != (usage_before.0 + 1, usage_before.1 + 2) {
            return Err("semget did not update exact namespace usage");
        }
        info.fill(0);
        let ipc_info = call_raw(
            Syscall::Semctl.raw(),
            a3(id, 0, IPC_INFO, info.as_mut_ptr() as u64),
        );
        let index = id & IPCMNI_IDX_MASK;
        if ipc_info.value < index
            || read_i32(&info, 0) != 1_024_000_000
            || read_i32(&info, 4) != 32_000
            || read_i32(&info, 8) != 1_024_000_000
            || read_i32(&info, 12) != 1_024_000_000
            || read_i32(&info, 16) != 32_000
            || read_i32(&info, 20) != 500
            || read_i32(&info, 24) != 500
            || read_i32(&info, 28) != 20
            || read_i32(&info, 32) != 32_767
            || read_i32(&info, 36) != 32_767
        {
            return Err("semctl IPC_INFO did not expose Linux semaphore limits");
        }

        info.fill(0);
        let sem_info = call_raw(
            Syscall::Semctl.raw(),
            a3(id, 0, SEM_INFO, info.as_mut_ptr() as u64),
        );
        if sem_info.value < index || read_i32(&info, 28) < 1 || read_i32(&info, 36) < 2 {
            return Err("semctl SEM_INFO did not aggregate live sets and semaphores");
        }

        let mut stat = [0u8; STAT_SIZE];
        if call(
            Syscall::Semctl.raw(),
            a3(index, 0, SEM_STAT, stat.as_mut_ptr() as u64),
        ) != Some(id as i64)
        {
            return Err("semctl SEM_STAT did not return the indexed set's full id");
        }
        if call(Syscall::Semctl.raw(), a3(987_654, 0, SEM_STAT, BAD_PTR)) != Some(EINVAL) {
            return Err("semctl SEM_STAT must resolve its index before copyout");
        }
        if call(Syscall::Semctl.raw(), a3(index, 0, SEM_STAT, BAD_PTR)) != Some(EFAULT) {
            return Err("semctl SEM_STAT bad output must return EFAULT after lookup");
        }
        if call(
            Syscall::Semctl.raw(),
            a3(u64::from(u32::MAX), 0, IPC_INFO, BAD_PTR),
        ) != Some(EINVAL)
        {
            return Err("negative semctl id must precede IPC_INFO copyout");
        }

        let task = crate::handlers::current_task_id();
        crate::handlers::__test_set_fsids(task, 1000, 1000);
        if call(
            Syscall::Semctl.raw(),
            a3(index, 0, SEM_STAT, stat.as_mut_ptr() as u64),
        ) != Some(EACCES)
        {
            return Err("SEM_STAT must enforce read permission");
        }
        if call(
            Syscall::Semctl.raw(),
            a3(index, 0, SEM_STAT_ANY, stat.as_mut_ptr() as u64),
        ) != Some(id as i64)
        {
            return Err("SEM_STAT_ANY must bypass ordinary read permission");
        }
        crate::handlers::__test_set_fsids(task, 0, 0);
        if call(Syscall::Semctl.raw(), a3(id, 0, IPC_RMID, 0)) != Some(0) {
            return Err("semctl info test cleanup failed");
        }
        info.fill(0);
        let _ = call_raw(
            Syscall::Semctl.raw(),
            a3(id, 0, SEM_INFO, info.as_mut_ptr() as u64),
        );
        if (read_i32(&info, 28), read_i32(&info, 36)) != usage_before {
            return Err("semctl IPC_RMID did not restore exact namespace usage");
        }
        let replacement = make_semset(1)?;
        if replacement & IPCMNI_IDX_MASK != index || replacement == id {
            return Err("semget did not reuse the freed slot with a new sequence id");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, IPC_STAT, BAD_PTR)) != Some(EINVAL) {
            return Err("stale semaphore sequence id must return EINVAL before copyout");
        }
        if call(
            Syscall::Semctl.raw(),
            a3(index, 0, SEM_STAT, stat.as_mut_ptr() as u64),
        ) != Some(replacement as i64)
        {
            return Err("SEM_STAT slot lookup did not return the replacement full id");
        }
        if call(Syscall::Semctl.raw(), a3(replacement, 0, IPC_RMID, 0)) != Some(0) {
            return Err("replacement semaphore cleanup failed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_semctl_info_and_indexed_stat
);

#[cfg(feature = "kernel-test")]
fn smoke_abi_ipc_semget_limits_and_undo_rollback() -> TestResult {
    struct ResetLimit;
    impl Drop for ResetLimit {
        fn drop(&mut self) {
            crate::sysvipc::__test_set_semmni(0);
        }
    }

    with_setup(|| {
        if call(Syscall::Semget.raw(), a2(0x55aa, 32_001, 0)) != Some(EINVAL) {
            return Err("semget above Linux SEMMSL must return EINVAL before lookup");
        }
        let baseline = crate::sysvipc::__test_sem_set_count();
        crate::sysvipc::__test_set_semmni(baseline.saturating_add(1));
        let _reset = ResetLimit;
        let id = make_semset(1)?;
        if call(Syscall::Semget.raw(), a2(0, 1, IPC_CREAT)) != Some(ENOSPC) {
            return Err("semget at SEMMNI must return ENOSPC");
        }
        crate::sysvipc::__test_set_semmni(0);

        if call(Syscall::Semctl.raw(), a3(id, 0, SETVAL, 1)) != Some(0) {
            return Err("setup: SETVAL before SEM_UNDO rollback failed");
        }
        let mut sops = [0u8; 12];
        sops[2..4].copy_from_slice(&1i16.to_le_bytes());
        sops[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        sops[8..10].copy_from_slice(&(-3i16).to_le_bytes());
        sops[10..12].copy_from_slice(&(SEM_UNDO | IPC_NOWAIT as i16).to_le_bytes());
        if call(Syscall::Semop.raw(), a2(id, sops.as_ptr() as u64, 2)) != Some(EAGAIN) {
            return Err("unsatisfied SEM_UNDO transaction must fail atomically");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(1) {
            return Err("failed SEM_UNDO transaction changed the semaphore value");
        }
        let pid = u64::from(crate::handlers::current_ucred().pid);
        crate::sysvipc::sem_undo_process_exit(pid, crate::handlers::current_task_id());
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(1) {
            return Err("failed SEM_UNDO transaction leaked an exit adjustment");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, IPC_RMID, 0)) != Some(0) {
            return Err("semget limit test cleanup failed");
        }
        Ok(())
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_semget_limits_and_undo_rollback
);

fn smoke_abi_ipc_sem_undo_and_rmid_wake() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut sop = [0u8; 6];
        sop[2..4].copy_from_slice(&1i16.to_le_bytes());
        sop[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        if call(Syscall::Semop.raw(), a2(id, sop.as_ptr() as u64, 1)) != Some(0) {
            return Err("SEM_UNDO setup operation failed");
        }
        let pid = u64::from(crate::handlers::current_ucred().pid);
        crate::sysvipc::sem_undo_process_exit(pid, crate::handlers::current_task_id());
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(0) {
            return Err("process exit did not reverse SEM_UNDO adjustment");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETPID, 0)) != Some(pid as i64) {
            return Err("exit-time SEM_UNDO did not publish the exiting process as sempid");
        }

        crate::sysvipc::__test_begin_removed_wait(0, id);
        if call(Syscall::Semctl.raw(), a3(id, 0, IPC_RMID, 0)) != Some(0) {
            return Err("semctl IPC_RMID setup failed");
        }
        if call(Syscall::Semop.raw(), a2(id, sop.as_ptr() as u64, 1)) != Some(EIDRM) {
            return Err("a semaphore waiter awakened by RMID must receive EIDRM");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_undo_and_rmid_wake
);

fn smoke_abi_ipc_sem_rmid_only_retires_target_set_waiters() -> TestResult {
    with_setup(|| {
        let removed_id = make_semset(1)?;
        let live_id = make_semset(1)?;
        let mut decrement = [0u8; 6];
        decrement[2..4].copy_from_slice(&(-1i16).to_le_bytes());

        const REMOVED_WAITER: u64 = FAKE_TASK + 36;
        set_task(REMOVED_WAITER);
        if call_raw(
            Syscall::Semop.raw(),
            a2(removed_id, decrement.as_ptr() as u64, 1),
        )
        .value
            != 0xDEAD
        {
            set_task(FAKE_TASK);
            return Err("removed-set waiter did not block");
        }

        const LIVE_WAITER: u64 = FAKE_TASK + 37;
        set_task(LIVE_WAITER);
        if call_raw(
            Syscall::Semop.raw(),
            a2(live_id, decrement.as_ptr() as u64, 1),
        )
        .value
            != 0xDEAD
        {
            set_task(FAKE_TASK);
            return Err("live-set waiter did not block");
        }

        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(removed_id, 0, IPC_RMID, 0)) != Some(0) {
            return Err("IPC_RMID failed for target semaphore set");
        }
        set_task(REMOVED_WAITER);
        if call(Syscall::Semop.raw(), a2(removed_id, BAD_PTR, 1)) != Some(EIDRM) {
            set_task(FAKE_TASK);
            return Err("target-set waiter did not consume EIDRM");
        }

        set_task(FAKE_TASK);
        if call(Syscall::Semctl.raw(), a3(live_id, 0, GETNCNT, 0)) != Some(1) {
            return Err("IPC_RMID disturbed another set's pending waiter");
        }
        if call(Syscall::Semctl.raw(), a3(live_id, 0, SETVAL, 1)) != Some(0) {
            return Err("SETVAL failed on unaffected semaphore set");
        }
        set_task(LIVE_WAITER);
        if call(Syscall::Semop.raw(), a2(live_id, BAD_PTR, 1)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("unaffected set waiter did not consume cached success");
        }
        set_task(FAKE_TASK);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_sem_rmid_only_retires_target_set_waiters
);

fn smoke_abi_ipc_retained_semop_and_shared_undo() -> TestResult {
    with_setup(|| {
        let id = make_semset(1)?;
        let mut original = [0u8; 6];
        original[2..4].copy_from_slice(&1i16.to_le_bytes());
        crate::sysvipc::__test_stage_sem_wait(id, &original);
        original[2..4].copy_from_slice(&2i16.to_le_bytes());
        if call(Syscall::Semop.raw(), a2(id, original.as_ptr() as u64, 1)) != Some(0) {
            return Err("staged semop re-execution failed");
        }
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(1) {
            return Err("semop re-imported a user-mutated sembuf after park");
        }

        let mut undo = [0u8; 6];
        undo[2..4].copy_from_slice(&1i16.to_le_bytes());
        undo[4..6].copy_from_slice(&SEM_UNDO.to_le_bytes());
        if call(Syscall::Semop.raw(), a2(id, undo.as_ptr() as u64, 1)) != Some(0) {
            return Err("shared SEM_UNDO setup failed");
        }
        let parent = u64::from(crate::handlers::current_ucred().pid);
        let child = parent.wrapping_add(0x4000_0000);
        crate::sysvipc::clone_sem_undo(parent, child, true);
        crate::sysvipc::sem_undo_process_exit(parent, 0);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(2) {
            return Err("CLONE_SYSVSEM applied undo before the final sharer exited");
        }
        crate::sysvipc::sem_undo_process_exit(child, 0);
        if call(Syscall::Semctl.raw(), a3(id, 0, GETVAL, 0)) != Some(1) {
            return Err("final CLONE_SYSVSEM sharer did not apply the shared undo list");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_retained_semop_and_shared_undo);

fn smoke_abi_ipc_wait_restart_classification() -> TestResult {
    with_setup(|| {
        for syscall in [
            Syscall::Semop,
            Syscall::Semtimedop,
            Syscall::Msgsnd,
            Syscall::Msgrcv,
        ] {
            if crate::handlers::__test_is_restartable_syscall(syscall.raw()) {
                return Err("blocking SysV IPC syscall must not be SA_RESTART-restarted");
            }
        }
        if !crate::handlers::__test_is_restartable_syscall(Syscall::Read.raw()) {
            return Err("restart classification test control unexpectedly failed");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_wait_restart_classification);

// ════════════════════════════════════════════════════════════════════
// System V message queues
// ════════════════════════════════════════════════════════════════════

/// msgget a private queue; return the id.
fn make_msgq() -> Result<u64, &'static str> {
    match call(Syscall::Msgget.raw(), a1(0, IPC_CREAT)) {
        Some(id) if id >= 0 => Ok(id as u64),
        _ => Err("setup: msgget IPC_PRIVATE failed"),
    }
}

// ── Msgget ──────────────────────────────────────────────────────────

fn smoke_abi_ipc_msgget_pos() -> TestResult {
    with_setup(|| {
        // msgget(key=IPC_PRIVATE, msgflg=IPC_CREAT) → a non-negative SysV id.
        match call(Syscall::Msgget.raw(), a1(0, IPC_CREAT)) {
            Some(id) if id >= 0 => Ok(()),
            _ => Err("msgget IPC_PRIVATE should return a non-negative id"),
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

fn smoke_abi_ipc_msgsnd_fault_order() -> TestResult {
    with_setup(|| {
        // Linux's ksys_msgsnd imports mtype before do_msgsnd validates msgsz
        // or resolves msqid.
        match call(
            Syscall::Msgsnd.raw(),
            a3(u64::MAX, BAD_PTR, 8193, IPC_NOWAIT),
        ) {
            Some(EFAULT) => Ok(()),
            _ => Err("msgsnd bad msgp must be EFAULT before size/id validation"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgsnd_fault_order);

fn smoke_abi_ipc_msgsnd_retains_kernel_snapshot() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        let mut user_msg = [0u8; 11];
        user_msg[..8].copy_from_slice(&9i64.to_ne_bytes());
        user_msg[8..].copy_from_slice(b"new");
        crate::sysvipc::__test_stage_msg_send(id, 7, b"old", 0);
        if !crate::sysvipc::__test_reblock_staged_msg_send(id)
            || !crate::sysvipc::__test_reblock_staged_msg_send(id)
        {
            return Err("staged msgsnd lost its owned payload across repeated rechecks");
        }
        if call(
            Syscall::Msgsnd.raw(),
            a3(id, user_msg.as_ptr() as u64, 3, 0),
        ) != Some(0)
        {
            return Err("staged msgsnd re-execution failed");
        }
        let mut received = [0u8; 11];
        let result = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: received.as_mut_ptr() as u64,
                arg2: 3,
                arg3: 0,
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        );
        if result.status != SyscallReturn::OK || result.value != 3 {
            return Err("receiving retained msgsnd snapshot failed");
        }
        if i64::from_ne_bytes(received[..8].try_into().unwrap()) != 7 || &received[8..] != b"old" {
            return Err("msgsnd re-imported user-mutated type or payload after park");
        }

        let removed = make_msgq()?;
        crate::sysvipc::__test_stage_msg_send(removed, 7, b"removed", 0);
        crate::handlers::raise_signal_pending(crate::handlers::current_task_id(), 10);
        if call(Syscall::Msgctl.raw(), a2(removed, IPC_RMID, 0)) != Some(0) {
            return Err("setup: staged sender queue removal failed");
        }
        if call(
            Syscall::Msgsnd.raw(),
            a3(removed, BAD_PTR, u64::MAX, IPC_NOWAIT),
        ) != Some(EIDRM)
        {
            return Err("RMID must beat a simultaneous signal for a staged sender");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgsnd_retains_kernel_snapshot);

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
                arg4: IPC_NOWAIT,
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
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        );
        if r.status == SyscallReturn::OK && r.value as i64 == ENOMSG {
            Ok(())
        } else {
            Err("msgrcv on an empty queue must be ENOMSG (-42)")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgrcv_neg);

fn smoke_abi_ipc_msgrcv_size_and_fault_order() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        let mut sent = [0u8; 12];
        sent[..8].copy_from_slice(&7i64.to_le_bytes());
        sent[8..].copy_from_slice(b"data");
        if call(Syscall::Msgsnd.raw(), a3(id, sent.as_ptr() as u64, 4, 0)) != Some(0) {
            return Err("setup: msgsnd failed");
        }

        let mut short = [0u8; 10];
        let recv = |ptr, size, flags| {
            call_raw(
                Syscall::Msgrcv.raw(),
                SyscallArgs {
                    arg0: id,
                    arg1: ptr,
                    arg2: size,
                    arg3: 0,
                    arg4: flags,
                    ..Default::default()
                },
            )
        };
        if recv(short.as_mut_ptr() as u64, 2, 0).value as i64 != E2BIG {
            return Err("oversize msgrcv without MSG_NOERROR must return E2BIG");
        }
        if recv(BAD_PTR, 4, 0).value as i64 != EFAULT {
            return Err("selected-message copyout fault must return EFAULT");
        }
        let mut full = [0u8; 12];
        if recv(full.as_mut_ptr() as u64, 4, IPC_NOWAIT).value as i64 != ENOMSG {
            return Err("ordinary msgrcv EFAULT must consume the selected message");
        }

        // E2BIG remains non-destructive: the original message is still first.
        if call(Syscall::Msgsnd.raw(), a3(id, sent.as_ptr() as u64, 4, 0)) != Some(0) {
            return Err("setup: replacement msgsnd failed");
        }
        let r = recv(full.as_mut_ptr() as u64, 4, IPC_NOWAIT);
        if r.value as i64 != 4 || &full[8..] != b"data" {
            return Err("E2BIG must leave the queued message available");
        }

        // MSG_NOERROR permits truncation and removal.
        if call(Syscall::Msgsnd.raw(), a3(id, sent.as_ptr() as u64, 4, 0)) != Some(0) {
            return Err("setup: second msgsnd failed");
        }
        let mut truncated = [0u8; 10];
        let r = recv(truncated.as_mut_ptr() as u64, 2, IPC_NOWAIT | MSG_NOERROR);
        if r.value as i64 != 2 || &truncated[8..] != b"da" {
            return Err("MSG_NOERROR must truncate to msgsz and return copied length");
        }
        if recv(full.as_mut_ptr() as u64, 4, IPC_NOWAIT).value as i64 != ENOMSG {
            return Err("successful MSG_NOERROR receive must dequeue the message");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgrcv_size_and_fault_order);

fn smoke_abi_ipc_msgrcv_copy_fault_is_non_destructive() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        let mut sent = [0u8; 12];
        sent[..8].copy_from_slice(&11i64.to_le_bytes());
        sent[8..].copy_from_slice(b"copy");
        if call(Syscall::Msgsnd.raw(), a3(id, sent.as_ptr() as u64, 4, 0)) != Some(0) {
            return Err("setup: msgsnd failed");
        }
        let recv = |ptr, flags| {
            call_raw(
                Syscall::Msgrcv.raw(),
                SyscallArgs {
                    arg0: id,
                    arg1: ptr,
                    arg2: 4,
                    arg3: 0,
                    arg4: flags,
                    ..Default::default()
                },
            )
        };
        let invalid = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: 987_654,
                arg1: BAD_PTR,
                arg2: 4,
                arg3: 0,
                arg4: IPC_NOWAIT | MSG_COPY,
                ..Default::default()
            },
        );
        if invalid.value as i64 != EFAULT {
            return Err("MSG_COPY must fault its scratch import before queue lookup");
        }
        if recv(BAD_PTR, IPC_NOWAIT | MSG_COPY).value as i64 != EFAULT {
            return Err("MSG_COPY bad output must return EFAULT");
        }
        let mut copied = [0u8; 12];
        let copy_result = recv(copied.as_mut_ptr() as u64, IPC_NOWAIT | MSG_COPY);
        if copy_result.value as i64 != 4
            || copied[..8] != 11i64.to_le_bytes()
            || &copied[8..] != b"copy"
        {
            return Err("MSG_COPY must return the selected message without dequeueing it");
        }
        let mut short = [0u8; 10];
        let oversized_copy = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: short.as_mut_ptr() as u64,
                arg2: 2,
                arg3: 0,
                arg4: IPC_NOWAIT | MSG_COPY | MSG_NOERROR,
                ..Default::default()
            },
        );
        if oversized_copy.value as i64 != EINVAL {
            return Err("oversize MSG_COPY|MSG_NOERROR must return EINVAL");
        }
        let mut full = [0u8; 12];
        let r = recv(full.as_mut_ptr() as u64, IPC_NOWAIT);
        if r.value as i64 != 4 || full[..8] != 11i64.to_le_bytes() || &full[8..] != b"copy" {
            return Err("MSG_COPY EFAULT must leave the selected message queued");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ipc_msgrcv_copy_fault_is_non_destructive
);

fn smoke_abi_ipc_msgrcv_blocking_retry() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        let mut received = [0u8; 12];
        let args = SyscallArgs {
            arg0: id,
            arg1: received.as_mut_ptr() as u64,
            arg2: 4,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        if call_raw(Syscall::Msgrcv.raw(), args).value != 0xDEAD {
            return Err("blocking msgrcv fabricated ENOMSG/EAGAIN in an empty queue");
        }

        // Publish from a distinct task so the receiver's staged wait remains
        // keyed to its original task, as it is for a real blocked process.
        set_task(FAKE_TASK + 1);
        let mut sent = [0u8; 12];
        sent[..8].copy_from_slice(&9i64.to_le_bytes());
        sent[8..].copy_from_slice(b"wake");
        if call(Syscall::Msgsnd.raw(), a3(id, sent.as_ptr() as u64, 4, 0)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("setup: peer msgsnd failed");
        }
        set_task(FAKE_TASK);
        let retried = call_raw(Syscall::Msgrcv.raw(), args);
        if retried.value as i64 != 4 || received[..8] != 9i64.to_le_bytes() {
            return Err("blocked msgrcv did not retry after message publication");
        }
        if &received[8..] != b"wake" {
            return Err("retried msgrcv copied the wrong payload");
        }

        // Linux's IPC_SET path wakes sleeping receivers through an internal
        // EAGAIN sentinel, rechecks the queue, and does not expose EAGAIN when
        // the receive still needs to block.
        if call_raw(Syscall::Msgrcv.raw(), args).value != 0xDEAD {
            return Err("second blocking msgrcv did not remain staged");
        }
        let mut update = [0u8; 120];
        update[20..24].copy_from_slice(&0o600u32.to_ne_bytes());
        update[88..96].copy_from_slice(&16384u64.to_ne_bytes());
        if call(
            Syscall::Msgctl.raw(),
            a2(id, IPC_SET, update.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("msgctl IPC_SET failed while a receiver was staged");
        }
        if call_raw(Syscall::Msgrcv.raw(), args).value != 0xDEAD {
            return Err("IPC_SET leaked its internal EAGAIN retry sentinel");
        }
        set_task(FAKE_TASK + 1);
        sent[8..].copy_from_slice(b"next");
        if call(Syscall::Msgsnd.raw(), a3(id, sent.as_ptr() as u64, 4, 0)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("setup: second peer msgsnd failed");
        }
        set_task(FAKE_TASK);
        if call_raw(Syscall::Msgrcv.raw(), args).value as i64 != 4 || &received[8..] != b"next" {
            return Err("IPC_SET retry did not remain wakeable by a later sender");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_msgrcv_blocking_retry
);

/// Message waits retain queue transitions across the publication-to-waker
/// window and own only one scheduler wake slot. Queue removal publishes EIDRM
/// through that same record before the queue becomes unresolvable.
fn smoke_abi_ipc_msg_wait_waker_handoff_and_rmid() -> TestResult {
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU32, Ordering};

    struct CountWake(AtomicU32);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    with_setup(|| {
        const RECEIVER: u64 = FAKE_TASK + 31;
        const SENDER: u64 = FAKE_TASK + 32;
        let id = make_msgq()?;
        let unrelated = make_msgq()?;
        let mut out = [0u8; 9];
        let recv_args = SyscallArgs {
            arg0: id,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };

        set_task(RECEIVER);
        if call_raw(Syscall::Msgrcv.raw(), recv_args).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("message receiver did not publish its blocked wait");
        }
        let wakes = Arc::new(CountWake(AtomicU32::new(0)));
        let waker = core::task::Waker::from(Arc::clone(&wakes));
        if crate::sysvipc::register_msg_wait_waker(RECEIVER, waker.clone())
            != crate::sysvipc::MsgParkState::Pending
            || crate::sysvipc::register_msg_wait_waker(RECEIVER, waker)
                != crate::sysvipc::MsgParkState::Pending
        {
            set_task(FAKE_TASK);
            return Err("message wait rejected durable waker registration");
        }

        set_task(SENDER);
        let mut msg = [0u8; 9];
        msg[..8].copy_from_slice(&5i64.to_ne_bytes());
        msg[8] = b'x';

        // Activity and removal on another queue must not scan, mark, or wake
        // this queue's receiver. This is the behavioral half of the per-queue
        // lock contract; the lock-holding test below checks independent
        // progress directly.
        if call(
            Syscall::Msgsnd.raw(),
            a3(unrelated, msg.as_ptr() as u64, 1, IPC_NOWAIT),
        ) != Some(0)
        {
            set_task(FAKE_TASK);
            return Err("unrelated sender setup failed");
        }
        let mut unrelated_out = [0u8; 9];
        if call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: unrelated,
                arg1: unrelated_out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        )
        .value as i64
            != 1
            || unrelated_out != msg
            || call(Syscall::Msgctl.raw(), a2(unrelated, IPC_RMID, 0)) != Some(0)
        {
            set_task(FAKE_TASK);
            return Err("unrelated queue traffic or cleanup failed");
        }
        if wakes.0.load(Ordering::Relaxed) != 0 {
            set_task(FAKE_TASK);
            return Err("unrelated queue activity woke this queue's receiver");
        }

        if call(Syscall::Msgsnd.raw(), a3(id, msg.as_ptr() as u64, 1, 0)) != Some(0) {
            set_task(FAKE_TASK);
            return Err("sender failed to publish receiver readiness");
        }
        if wakes.0.load(Ordering::Relaxed) != 1 {
            set_task(FAKE_TASK);
            return Err("message transition produced a lost or duplicate wake");
        }
        // `ready` is retained after the waker is consumed. A poll that races
        // after publication must re-execute immediately rather than sleep.
        let late = core::task::Waker::from(Arc::new(CountWake(AtomicU32::new(0))));
        if crate::sysvipc::register_msg_wait_waker(RECEIVER, late)
            != crate::sysvipc::MsgParkState::Ready
        {
            set_task(FAKE_TASK);
            return Err("message readiness was lost before late waker registration");
        }
        set_task(RECEIVER);
        if call_raw(Syscall::Msgrcv.raw(), recv_args).value as i64 != 1 || out[8] != b'x' {
            set_task(FAKE_TASK);
            return Err("awakened message receiver did not consume the publication");
        }

        // A second empty receive is linked before RMID. The removal and EIDRM
        // publication are one state transaction, including the late-register
        // case where no waker existed at removal time.
        if call_raw(Syscall::Msgrcv.raw(), recv_args).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("second message receive did not block");
        }
        set_task(FAKE_TASK);
        if call(Syscall::Msgctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("message queue removal failed");
        }
        let removed = core::task::Waker::from(Arc::new(CountWake(AtomicU32::new(0))));
        if crate::sysvipc::register_msg_wait_waker(RECEIVER, removed)
            != crate::sysvipc::MsgParkState::Ready
        {
            return Err("RMID terminal state was not retained for late registration");
        }
        set_task(RECEIVER);
        if call_raw(Syscall::Msgrcv.raw(), recv_args).value as i64 != EIDRM {
            set_task(FAKE_TASK);
            return Err("RMID waiter observed EINVAL instead of EIDRM");
        }
        set_task(FAKE_TASK);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_msg_wait_waker_handoff_and_rmid
);

/// Full-queue senders use the same queue-local publication protocol as
/// receivers: one retained waker, EIDRM on removal, and a reusable task slot
/// after the terminal result is consumed.
fn smoke_abi_ipc_msg_sender_waker_rmid_and_slot_reuse() -> TestResult {
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU32, Ordering};

    struct CountWake(AtomicU32);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    with_setup(|| {
        const BLOCKED: u64 = FAKE_TASK + 41;
        let id = make_msgq()?;
        let mut update = [0u8; 120];
        update[20..24].copy_from_slice(&0o600u32.to_ne_bytes());
        update[88..96].copy_from_slice(&1u64.to_ne_bytes());
        if call(
            Syscall::Msgctl.raw(),
            a2(id, IPC_SET, update.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setup: failed to set one-byte message capacity");
        }

        let mut msg = [0u8; 9];
        msg[..8].copy_from_slice(&7i64.to_ne_bytes());
        msg[8] = b's';
        if call(
            Syscall::Msgsnd.raw(),
            a3(id, msg.as_ptr() as u64, 1, IPC_NOWAIT),
        ) != Some(0)
        {
            return Err("setup: failed to fill one-byte message queue");
        }

        set_task(BLOCKED);
        let send_args = a3(id, msg.as_ptr() as u64, 1, 0);
        // The direct ABI harness has no schedulable UserTaskCtx, so a real
        // blocking msgsnd deliberately falls back to EAGAIN there. Publish
        // and recheck the exact retained record through the kernel-test hook;
        // the ordinary syscall below still consumes its terminal result.
        crate::sysvipc::__test_stage_msg_send(id, 7, b"s", 0);
        if !crate::sysvipc::__test_reblock_staged_msg_send(id) {
            set_task(FAKE_TASK);
            return Err("full-queue sender wait did not survive a recheck");
        }
        let wakes = Arc::new(CountWake(AtomicU32::new(0)));
        let waker = core::task::Waker::from(Arc::clone(&wakes));
        if crate::sysvipc::register_msg_wait_waker(BLOCKED, waker.clone())
            != crate::sysvipc::MsgParkState::Pending
            || crate::sysvipc::register_msg_wait_waker(BLOCKED, waker)
                != crate::sysvipc::MsgParkState::Pending
        {
            set_task(FAKE_TASK);
            return Err("blocked sender rejected deduplicated waker registration");
        }

        set_task(FAKE_TASK);
        if call(Syscall::Msgctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("sender-wait queue removal failed");
        }
        if wakes.0.load(Ordering::Relaxed) != 1 {
            return Err("RMID produced a lost or duplicate sender wake");
        }
        let late = core::task::Waker::from(Arc::new(CountWake(AtomicU32::new(0))));
        if crate::sysvipc::register_msg_wait_waker(BLOCKED, late)
            != crate::sysvipc::MsgParkState::Ready
        {
            return Err("sender RMID state was lost before late registration");
        }
        set_task(BLOCKED);
        if call_raw(Syscall::Msgsnd.raw(), send_args).value as i64 != EIDRM {
            set_task(FAKE_TASK);
            return Err("removed blocked sender observed an errno other than EIDRM");
        }
        if crate::sysvipc::register_msg_wait_waker(
            BLOCKED,
            core::task::Waker::from(Arc::new(CountWake(AtomicU32::new(0)))),
        ) != crate::sysvipc::MsgParkState::NotWaiting
        {
            set_task(FAKE_TASK);
            return Err("terminal sender wait remained linked after EIDRM consumption");
        }

        // Reuse the same task for a receiver on another queue. Recycled wait
        // slots must not hide the new wait or retain the removed queue.
        set_task(FAKE_TASK);
        let replacement = make_msgq()?;
        let mut out = [0u8; 9];
        let recv_args = SyscallArgs {
            arg0: replacement,
            arg1: out.as_mut_ptr() as u64,
            arg2: 1,
            arg3: 0,
            arg4: 0,
            ..Default::default()
        };
        set_task(BLOCKED);
        if call_raw(Syscall::Msgrcv.raw(), recv_args).value != 0xDEAD {
            set_task(FAKE_TASK);
            return Err("reused task slot did not publish a receiver wait");
        }
        let reused_wakes = Arc::new(CountWake(AtomicU32::new(0)));
        if crate::sysvipc::register_msg_wait_waker(
            BLOCKED,
            core::task::Waker::from(Arc::clone(&reused_wakes)),
        ) != crate::sysvipc::MsgParkState::Pending
        {
            set_task(FAKE_TASK);
            return Err("reused task slot rejected its receiver waker");
        }
        set_task(FAKE_TASK);
        if call(
            Syscall::Msgsnd.raw(),
            a3(replacement, msg.as_ptr() as u64, 1, 0),
        ) != Some(0)
            || reused_wakes.0.load(Ordering::Relaxed) != 1
        {
            return Err("reused task slot was not woken by its new queue");
        }
        set_task(BLOCKED);
        if call_raw(Syscall::Msgrcv.raw(), recv_args).value as i64 != 1 || out != msg {
            set_task(FAKE_TASK);
            return Err("reused task slot received the wrong queue publication");
        }
        set_task(FAKE_TASK);
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_msg_sender_waker_rmid_and_slot_reuse
);

fn smoke_abi_ipc_msg_sender_wakes_only_for_sufficient_capacity() -> TestResult {
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicU32, Ordering};

    struct CountWake(AtomicU32);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    with_setup(|| {
        const BLOCKED: u64 = FAKE_TASK + 42;
        let id = make_msgq()?;
        let mut update = [0u8; 120];
        update[20..24].copy_from_slice(&0o600u32.to_ne_bytes());
        update[88..96].copy_from_slice(&3u64.to_ne_bytes());
        if call(
            Syscall::Msgctl.raw(),
            a2(id, IPC_SET, update.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setup: failed to set three-byte message capacity");
        }

        for byte in b"abc" {
            let mut msg = [0u8; 9];
            msg[..8].copy_from_slice(&1i64.to_ne_bytes());
            msg[8] = *byte;
            if call(
                Syscall::Msgsnd.raw(),
                a3(id, msg.as_ptr() as u64, 1, IPC_NOWAIT),
            ) != Some(0)
            {
                return Err("setup: failed to fill three-byte message queue");
            }
        }

        set_task(BLOCKED);
        crate::sysvipc::__test_stage_msg_send(id, 9, b"zz", 0);
        let wakes = Arc::new(CountWake(AtomicU32::new(0)));
        if crate::sysvipc::register_msg_wait_waker(
            BLOCKED,
            core::task::Waker::from(Arc::clone(&wakes)),
        ) != crate::sysvipc::MsgParkState::Pending
        {
            set_task(FAKE_TASK);
            return Err("capacity waiter rejected its sender waker");
        }

        let mut out = [0u8; 10];
        let recv = SyscallArgs {
            arg0: id,
            arg1: out.as_mut_ptr() as u64,
            arg2: 2,
            arg3: 0,
            arg4: IPC_NOWAIT,
            ..Default::default()
        };
        set_task(FAKE_TASK);
        if call_raw(Syscall::Msgrcv.raw(), recv).value as i64 != 1 {
            return Err("setup: first capacity receive failed");
        }
        if wakes.0.load(Ordering::Relaxed) != 0 {
            return Err("sender woke before enough byte capacity was available");
        }
        if call_raw(Syscall::Msgrcv.raw(), recv).value as i64 != 1 {
            return Err("setup: second capacity receive failed");
        }
        if wakes.0.load(Ordering::Relaxed) != 1 {
            return Err("sender was not woken exactly once when its message fit");
        }

        let mut ignored_user_msg = [0u8; 10];
        ignored_user_msg[..8].copy_from_slice(&77i64.to_ne_bytes());
        ignored_user_msg[8..].copy_from_slice(b"xx");
        set_task(BLOCKED);
        if call(
            Syscall::Msgsnd.raw(),
            a3(id, ignored_user_msg.as_ptr() as u64, 2, 0),
        ) != Some(0)
        {
            set_task(FAKE_TASK);
            return Err("capacity wake did not let the staged sender commit");
        }
        set_task(FAKE_TASK);
        if call_raw(Syscall::Msgrcv.raw(), recv).value as i64 != 1
            || call_raw(Syscall::Msgrcv.raw(), recv).value as i64 != 2
            || i64::from_ne_bytes(out[..8].try_into().unwrap()) != 9
            || &out[8..] != b"zz"
        {
            return Err("capacity wake lost or replaced the staged sender payload");
        }
        if call(Syscall::Msgctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("capacity wake queue cleanup failed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_msg_sender_wakes_only_for_sufficient_capacity
);

fn smoke_abi_ipc_msgrcv_negative_selects_lowest_type() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        for (mtype, byte) in [(3i64, b'3'), (1, b'1'), (2, b'2')] {
            let mut msg = [0u8; 9];
            msg[..8].copy_from_slice(&mtype.to_le_bytes());
            msg[8] = byte;
            if call(Syscall::Msgsnd.raw(), a3(id, msg.as_ptr() as u64, 1, 0)) != Some(0) {
                return Err("setup: typed msgsnd failed");
            }
        }
        let mut out = [0u8; 9];
        let r = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: (-3i64) as u64,
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        );
        if r.value as i64 != 1
            || i64::from_le_bytes(out[..8].try_into().unwrap()) != 1
            || out[8] != b'1'
        {
            return Err("negative msgtyp must select the lowest eligible type");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_ipc_msgrcv_negative_selects_lowest_type
);

// msgrcv type selection with the transactional output path: send mtype 3 then
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

fn smoke_abi_ipc_msgctl_capacity_stat_and_rmid() -> TestResult {
    with_setup(|| {
        let id = make_msgq()?;
        let mut update = [0u8; 120];
        update[20..24].copy_from_slice(&0o600u32.to_ne_bytes());
        update[88..96].copy_from_slice(&1u64.to_ne_bytes());
        if call(Syscall::Msgctl.raw(), a2(987_654, IPC_SET, BAD_PTR)) != Some(EFAULT) {
            return Err("msgctl IPC_SET must import the full struct before id lookup");
        }
        if call(
            Syscall::Msgctl.raw(),
            a2(id, IPC_SET, update.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("msgctl IPC_SET qbytes=1 failed");
        }

        let mut msg = [0u8; 9];
        msg[..8].copy_from_slice(&1i64.to_ne_bytes());
        msg[8] = b'x';
        if call(
            Syscall::Msgsnd.raw(),
            a3(id, msg.as_ptr() as u64, 1, IPC_NOWAIT),
        ) != Some(0)
        {
            return Err("first message should fit qbytes=1");
        }
        if call(
            Syscall::Msgsnd.raw(),
            a3(id, msg.as_ptr() as u64, 1, IPC_NOWAIT),
        ) != Some(EAGAIN)
        {
            return Err("full queue IPC_NOWAIT send must return EAGAIN");
        }

        let mut stat = [0u8; 120];
        if call(
            Syscall::Msgctl.raw(),
            a2(id, IPC_STAT, stat.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("msgctl IPC_STAT failed");
        }
        if u64::from_ne_bytes(stat[72..80].try_into().unwrap()) != 1
            || u64::from_ne_bytes(stat[80..88].try_into().unwrap()) != 1
            || u64::from_ne_bytes(stat[88..96].try_into().unwrap()) != 1
        {
            return Err("msgctl IPC_STAT byte/count/qbytes metadata mismatch");
        }

        let mut drained = [0u8; 9];
        let receive = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: drained.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        );
        if receive.value as i64 != 1 {
            return Err("capacity-test receive failed");
        }
        if call(
            Syscall::Msgsnd.raw(),
            a3(id, msg.as_ptr() as u64, 1, IPC_NOWAIT),
        ) != Some(0)
        {
            return Err("dequeue did not release message-queue capacity");
        }

        crate::sysvipc::__test_begin_removed_wait(2, id);
        if call(Syscall::Msgctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("msgctl IPC_RMID failed");
        }
        crate::handlers::raise_signal_pending(crate::handlers::current_task_id(), 10);
        let mut out = [0u8; 9];
        let result = call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: id,
                arg1: out.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        );
        if result.value as i64 != EIDRM {
            return Err("message receiver must observe RMID before a simultaneous signal");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_msgctl_capacity_stat_and_rmid);

fn smoke_abi_ipc_msgctl_info_and_indexed_stat() -> TestResult {
    with_setup(|| {
        let read_i32 = |bytes: &[u8], offset: usize| {
            i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
        };
        let mut info = [0u8; 32];
        let _ = call_raw(
            Syscall::Msgctl.raw(),
            a2(0, MSG_INFO, info.as_mut_ptr() as u64),
        );
        let usage_before = (read_i32(&info, 0), read_i32(&info, 4), read_i32(&info, 24));
        let id = make_msgq()?;
        let mut msg = [0u8; 9];
        msg[..8].copy_from_slice(&1i64.to_ne_bytes());
        msg[8] = b'i';
        if call(Syscall::Msgsnd.raw(), a3(id, msg.as_ptr() as u64, 1, 0)) != Some(0) {
            return Err("setup: msgctl info message send failed");
        }
        info.fill(0);
        let _ = call_raw(
            Syscall::Msgctl.raw(),
            a2(id, MSG_INFO, info.as_mut_ptr() as u64),
        );
        if (read_i32(&info, 0), read_i32(&info, 4), read_i32(&info, 24))
            != (usage_before.0 + 1, usage_before.1 + 1, usage_before.2 + 1)
        {
            return Err("msgsnd did not update exact namespace usage");
        }
        info.fill(0);
        let ipc_info = call_raw(
            Syscall::Msgctl.raw(),
            a2(id, IPC_INFO, info.as_mut_ptr() as u64),
        );
        let index = id & IPCMNI_IDX_MASK;
        if ipc_info.value < index
            || read_i32(&info, 0) != 512_000
            || read_i32(&info, 4) != 16_384
            || read_i32(&info, 8) != 8_192
            || read_i32(&info, 12) != 16_384
            || read_i32(&info, 16) != 32_000
            || read_i32(&info, 20) != 16
            || read_i32(&info, 24) != 16_384
            || u16::from_ne_bytes(info[28..30].try_into().unwrap()) != u16::MAX
        {
            return Err("msgctl IPC_INFO did not expose Linux message limits");
        }

        info.fill(0);
        let msg_info = call_raw(
            Syscall::Msgctl.raw(),
            a2(id, MSG_INFO, info.as_mut_ptr() as u64),
        );
        if msg_info.value < index
            || read_i32(&info, 0) < 1
            || read_i32(&info, 4) < 1
            || read_i32(&info, 24) < 1
        {
            return Err("msgctl MSG_INFO did not aggregate live queues/messages/bytes");
        }

        let mut stat = [0u8; 120];
        if call(
            Syscall::Msgctl.raw(),
            a2(index, MSG_STAT, stat.as_mut_ptr() as u64),
        ) != Some(id as i64)
            || u64::from_ne_bytes(stat[72..80].try_into().unwrap()) != 1
            || u64::from_ne_bytes(stat[80..88].try_into().unwrap()) != 1
        {
            return Err("msgctl MSG_STAT did not return the indexed queue and full id");
        }
        stat.fill(0);
        if call(
            Syscall::Msgctl.raw(),
            a2(index, MSG_STAT_ANY, stat.as_mut_ptr() as u64),
        ) != Some(id as i64)
        {
            return Err("msgctl MSG_STAT_ANY did not return the full queue id");
        }
        if call(Syscall::Msgctl.raw(), a2(987_654, MSG_STAT, BAD_PTR)) != Some(EINVAL) {
            return Err("msgctl MSG_STAT must resolve its index before copyout");
        }
        if call(Syscall::Msgctl.raw(), a2(index, MSG_STAT, BAD_PTR)) != Some(EFAULT) {
            return Err("msgctl MSG_STAT bad output must return EFAULT after lookup");
        }
        if call(
            Syscall::Msgctl.raw(),
            a2(u64::from(u32::MAX), IPC_INFO, BAD_PTR),
        ) != Some(EINVAL)
        {
            return Err("negative msgctl id must precede IPC_INFO copyout");
        }
        if call(Syscall::Msgctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("msgctl info test cleanup failed");
        }
        info.fill(0);
        let _ = call_raw(
            Syscall::Msgctl.raw(),
            a2(id, MSG_INFO, info.as_mut_ptr() as u64),
        );
        if (read_i32(&info, 0), read_i32(&info, 4), read_i32(&info, 24)) != usage_before {
            return Err("msgctl IPC_RMID did not restore exact namespace usage");
        }
        let replacement = make_msgq()?;
        if replacement & IPCMNI_IDX_MASK != index || replacement == id {
            return Err("msgget did not reuse the freed slot with a new sequence id");
        }
        if call(Syscall::Msgctl.raw(), a2(id, IPC_STAT, BAD_PTR)) != Some(EINVAL) {
            return Err("stale message sequence id must return EINVAL before copyout");
        }
        if call(
            Syscall::Msgctl.raw(),
            a2(index, MSG_STAT, stat.as_mut_ptr() as u64),
        ) != Some(replacement as i64)
        {
            return Err("MSG_STAT slot lookup did not return the replacement full id");
        }
        if call(Syscall::Msgctl.raw(), a2(replacement, IPC_RMID, 0)) != Some(0) {
            return Err("replacement message queue cleanup failed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_msgctl_info_and_indexed_stat
);

/// MSG_INFO aggregates cheap per-CPU deltas across independently locked
/// queues. MSG_COPY is non-destructive, ordinary receive subtracts exactly
/// once, and RMID subtracts every message still owned by that queue.
fn smoke_abi_ipc_msg_info_aggregates_queue_local_counters() -> TestResult {
    with_setup(|| {
        let read_i32 = |bytes: &[u8], offset: usize| {
            i32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
        };
        let snapshot = || {
            let mut info = [0u8; 32];
            let _ = call_raw(
                Syscall::Msgctl.raw(),
                a2(0, MSG_INFO, info.as_mut_ptr() as u64),
            );
            (read_i32(&info, 0), read_i32(&info, 4), read_i32(&info, 24))
        };

        let baseline = snapshot();
        let first = make_msgq()?;
        let second = make_msgq()?;
        let mut one = [0u8; 9];
        one[..8].copy_from_slice(&1i64.to_ne_bytes());
        one[8] = b'a';
        let mut three = [0u8; 11];
        three[..8].copy_from_slice(&2i64.to_ne_bytes());
        three[8..].copy_from_slice(b"bcd");
        if call(Syscall::Msgsnd.raw(), a3(first, one.as_ptr() as u64, 1, 0)) != Some(0)
            || call(
                Syscall::Msgsnd.raw(),
                a3(second, three.as_ptr() as u64, 3, 0),
            ) != Some(0)
        {
            return Err("setup: queue-local counter sends failed");
        }
        if snapshot() != (baseline.0 + 2, baseline.1 + 2, baseline.2 + 4) {
            return Err("MSG_INFO did not aggregate messages from distinct queues");
        }

        let mut copied = [0u8; 11];
        if call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: second,
                arg1: copied.as_mut_ptr() as u64,
                arg2: 3,
                arg3: 0,
                arg4: MSG_COPY | IPC_NOWAIT,
                ..Default::default()
            },
        )
        .value as i64
            != 3
            || copied != three
            || snapshot() != (baseline.0 + 2, baseline.1 + 2, baseline.2 + 4)
        {
            return Err("MSG_COPY changed queue-local namespace counters");
        }

        let mut received = [0u8; 9];
        if call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: first,
                arg1: received.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        )
        .value as i64
            != 1
            || received != one
            || snapshot() != (baseline.0 + 2, baseline.1 + 1, baseline.2 + 3)
        {
            return Err("ordinary receive did not subtract its queue-local counters");
        }

        if call(Syscall::Msgctl.raw(), a2(second, IPC_RMID, 0)) != Some(0)
            || snapshot() != (baseline.0 + 1, baseline.1, baseline.2)
        {
            return Err("IPC_RMID did not subtract the removed queue's retained messages");
        }
        if call(Syscall::Msgctl.raw(), a2(first, IPC_RMID, 0)) != Some(0) || snapshot() != baseline
        {
            return Err("queue-local counter cleanup did not restore the baseline");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_msg_info_aggregates_queue_local_counters
);

#[cfg(feature = "kernel-test")]
fn smoke_abi_ipc_distinct_queues_do_not_share_content_lock() -> TestResult {
    with_setup(|| {
        let locked = make_msgq()?;
        let active = make_msgq()?;
        let mut msg = [0u8; 9];
        msg[..8].copy_from_slice(&7i64.to_ne_bytes());
        msg[8] = b'q';
        if crate::sysvipc::__test_msg_queues_lock_independently(locked, active) != Some(true) {
            return Err("distinct message queues did not own independent content locks");
        }
        if call(
            Syscall::Msgsnd.raw(),
            a3(active, msg.as_ptr() as u64, 1, IPC_NOWAIT),
        ) != Some(0)
        {
            return Err("per-queue lock test send failed");
        }
        let mut received = [0u8; 9];
        if call_raw(
            Syscall::Msgrcv.raw(),
            SyscallArgs {
                arg0: active,
                arg1: received.as_mut_ptr() as u64,
                arg2: 1,
                arg3: 0,
                arg4: IPC_NOWAIT,
                ..Default::default()
            },
        )
        .value
            != 1
            || received != msg
        {
            return Err("per-queue lock test traffic failed");
        }
        if call(Syscall::Msgctl.raw(), a2(locked, IPC_RMID, 0)) != Some(0)
            || call(Syscall::Msgctl.raw(), a2(active, IPC_RMID, 0)) != Some(0)
        {
            return Err("per-queue lock test cleanup failed");
        }
        Ok(())
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_distinct_queues_do_not_share_content_lock
);

#[cfg(feature = "kernel-test")]
fn smoke_abi_ipc_msgget_limit_is_enospc() -> TestResult {
    struct ResetLimit;
    impl Drop for ResetLimit {
        fn drop(&mut self) {
            crate::sysvipc::__test_set_msg_max_queues(0);
        }
    }

    with_setup(|| {
        let baseline = crate::sysvipc::__test_msg_queue_count();
        crate::sysvipc::__test_set_msg_max_queues(baseline.saturating_add(1));
        let _reset = ResetLimit;
        let id = make_msgq()?;
        if call(Syscall::Msgget.raw(), a1(0, IPC_CREAT)) != Some(ENOSPC) {
            return Err("msgget at MSGMNI must return ENOSPC");
        }
        if call(Syscall::Msgctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("msgget limit test cleanup failed");
        }
        Ok(())
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_msgget_limit_is_enospc
);

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

// `ipc/shm.c::newseg` inspects SHM_HUGETLB only on the create path, after the
// size EINVAL and both namespace ENOSPC gates:
//     if (shmflg & SHM_HUGETLB) {
//             hs = hstate_sizelog((shmflg >> SHM_HUGE_SHIFT) & SHM_HUGE_MASK);
//             if (!hs) { error = -EINVAL; goto no_file; }
// NARF has no huge-page backing, so it takes the !hs arm the way a kernel
// built without CONFIG_HUGETLB_PAGE does. Silently returning a 4 KiB-backed
// segment instead would leave a caller that asked for huge pages with no
// error and no huge pages.
fn smoke_abi_ipc_shmget_hugetlb_and_flag_width() -> TestResult {
    with_setup(|| {
        const HUGE_KEY: u64 = 0x51_2001;

        if call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | SHM_HUGETLB)) != Some(EINVAL) {
            return Err("shmget SHM_HUGETLB must be EINVAL, not a silent 4 KiB segment");
        }
        // The flag lives in newseg, so ipcget_public's ENOENT for a missing
        // key still outranks it — order, not just value.
        if call(Syscall::Shmget.raw(), a2(HUGE_KEY, 4096, SHM_HUGETLB)) != Some(ENOENT) {
            return Err("SHM_HUGETLB must not preempt ipcget_public's ENOENT");
        }

        // Positive paths that must stay open. SHM_NORESERVE only steers
        // Linux's accounting, so it is accepted-and-ignored on both sides.
        let id = call(
            Syscall::Shmget.raw(),
            a2(HUGE_KEY, 4096, IPC_CREAT | SHM_NORESERVE | 0o600),
        )
        .filter(|id| *id > 0)
        .ok_or("SHM_NORESERVE create was rejected")? as u64;
        // An existing key resolves through ipc_findkey and never reaches
        // newseg, so SHM_HUGETLB on a lookup still returns the id.
        if call(
            Syscall::Shmget.raw(),
            a2(HUGE_KEY, 4096, SHM_HUGETLB | 0o600),
        ) != Some(id as i64)
        {
            return Err("SHM_HUGETLB on an existing-key lookup must return the id");
        }
        // shmflg is a C int. Junk above bit 31 in the argument register is
        // not part of it and must not reach any flag test.
        if call(
            Syscall::Shmget.raw(),
            a2(HUGE_KEY, 4096, (1u64 << 40) | 0o600),
        ) != Some(id as i64)
        {
            return Err("shmget honoured shmflg bits above the 32-bit int");
        }

        if call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("hugetlb/flag-width test cleanup failed");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmget_hugetlb_and_flag_width);

/// Real SysV objects are scoped by the current IPC namespace. Namespace
/// inheritance shares all three tables by reference, while CLONE_NEWIPC's
/// fresh namespace may reuse the same numeric ids without aliasing them.
#[cfg(feature = "container")]
fn smoke_abi_sysvipc_namespace_share_and_isolation() -> TestResult {
    with_setup(|| {
        crate::namespaces::__test_reset_all();
        let result = (|| {
            const SHARED_TASK: u64 = FAKE_TASK + 1;
            const FRESH_TASK: u64 = FAKE_TASK + 2;
            const SEM_KEY: u64 = 0x51_1001;
            const MSG_KEY: u64 = 0x51_1002;
            const SHM_KEY: u64 = 0x51_1003;

            crate::namespaces::unshare_ipc(FAKE_TASK);
            let shared_ns = crate::namespaces::current_ipc_ns(FAKE_TASK)
                .ok_or("setup: initial private IPC namespace missing")?;

            set_task(FAKE_TASK);
            // A successful *get returns the id (>= 0); an error is a negative
            // errno. The FIRST object created in a fresh IPC namespace lands in
            // slot 0 with sequence 0, whose Linux-style public id is exactly 0
            // (see IpcIdTable::allocate) — the same value Linux's ipc_buildid
            // yields — so accept 0 as a valid id, not just > 0.
            let sem_a = call(Syscall::Semget.raw(), a2(SEM_KEY, 1, IPC_CREAT | 0o600))
                .filter(|id| *id >= 0)
                .ok_or("setup: namespace-A semget failed")? as u64;
            if call(Syscall::Semctl.raw(), a3(sem_a, 0, SETVAL, 7)) != Some(0) {
                return Err("setup: namespace-A SETVAL failed");
            }
            let msg_a = call(Syscall::Msgget.raw(), a1(MSG_KEY, IPC_CREAT | 0o600))
                .filter(|id| *id >= 0)
                .ok_or("setup: namespace-A msgget failed")? as u64;
            let shm_a = call(Syscall::Shmget.raw(), a2(SHM_KEY, 4096, IPC_CREAT | 0o600))
                .filter(|id| *id >= 0)
                .ok_or("setup: namespace-A shmget failed")? as u64;

            crate::namespaces::setns_ipc(SHARED_TASK, shared_ns);
            set_task(SHARED_TASK);
            if call(Syscall::Semget.raw(), a2(SEM_KEY, 1, 0)) != Some(sem_a as i64)
                || call(Syscall::Semctl.raw(), a3(sem_a, 0, GETVAL, 0)) != Some(7)
                || call(Syscall::Msgget.raw(), a1(MSG_KEY, 0)) != Some(msg_a as i64)
                || call(Syscall::Shmget.raw(), a2(SHM_KEY, 0, 0)) != Some(shm_a as i64)
            {
                return Err("inherited IPC namespace did not share all SysV tables");
            }

            crate::namespaces::unshare_ipc(FRESH_TASK);
            set_task(FRESH_TASK);
            if call(Syscall::Semget.raw(), a2(SEM_KEY, 1, 0)) != Some(ENOENT)
                || call(Syscall::Msgget.raw(), a1(MSG_KEY, 0)) != Some(ENOENT)
                || call(Syscall::Shmget.raw(), a2(SHM_KEY, 0, 0)) != Some(ENOENT)
            {
                return Err("fresh IPC namespace leaked a SysV key from its parent");
            }
            let sem_c = call(Syscall::Semget.raw(), a2(SEM_KEY, 1, IPC_CREAT | 0o600))
                .ok_or("fresh namespace semget failed")? as u64;
            let msg_c = call(Syscall::Msgget.raw(), a1(MSG_KEY, IPC_CREAT | 0o600))
                .ok_or("fresh namespace msgget failed")? as u64;
            let shm_c = call(Syscall::Shmget.raw(), a2(SHM_KEY, 8192, IPC_CREAT | 0o600))
                .ok_or("fresh namespace shmget failed")? as u64;
            if sem_c != sem_a || msg_c != msg_a || shm_c != shm_a {
                return Err("fresh IPC namespace did not use an independent per-family id space");
            }
            if call(Syscall::Semctl.raw(), a3(sem_c, 0, GETVAL, 0)) != Some(0) {
                return Err("same numeric semid aliased the parent namespace's semaphore");
            }
            let mut fresh_stat = [0u8; 112];
            if call(
                Syscall::Shmctl.raw(),
                a2(shm_c, IPC_STAT, fresh_stat.as_mut_ptr() as u64),
            ) != Some(0)
                || u64::from_ne_bytes(fresh_stat[48..56].try_into().unwrap()) != 8192
            {
                return Err("same numeric shmid aliased the parent namespace's segment");
            }
            let _ = call(Syscall::Semctl.raw(), a3(sem_c, 0, IPC_RMID, 0));
            let _ = call(Syscall::Msgctl.raw(), a2(msg_c, IPC_RMID, 0));
            let _ = call(Syscall::Shmctl.raw(), a2(shm_c, IPC_RMID, 0));

            set_task(SHARED_TASK);
            let mut shared_stat = [0u8; 112];
            if call(Syscall::Semctl.raw(), a3(sem_a, 0, GETVAL, 0)) != Some(7)
                || call(Syscall::Msgget.raw(), a1(MSG_KEY, 0)) != Some(msg_a as i64)
                || call(
                    Syscall::Shmctl.raw(),
                    a2(shm_a, IPC_STAT, shared_stat.as_mut_ptr() as u64),
                ) != Some(0)
                || u64::from_ne_bytes(shared_stat[48..56].try_into().unwrap()) != 4096
            {
                return Err("removing colliding fresh-namespace ids damaged shared namespace");
            }
            let _ = call(Syscall::Semctl.raw(), a3(sem_a, 0, IPC_RMID, 0));
            let _ = call(Syscall::Msgctl.raw(), a2(msg_a, IPC_RMID, 0));
            let _ = call(Syscall::Shmctl.raw(), a2(shm_a, IPC_RMID, 0));
            Ok(())
        })();
        crate::namespaces::__test_reset_all();
        set_task(FAKE_TASK);
        result
    })
}
#[cfg(feature = "container")]
kernel_test_in!(
    "syscall_abi/sysvipc_namespace",
    smoke_abi_sysvipc_namespace_share_and_isolation
);

// ── Shmat ───────────────────────────────────────────────────────────
//
// shmat(shmid, shmaddr, shmflg). Entry validation precedes object lookup and
// the focused positive test installs a live address space.

fn smoke_abi_ipc_shmat_neg() -> TestResult {
    with_setup(|| {
        if call(Syscall::Shmat.raw(), a2(987654, 0, 0)) != Some(EINVAL) {
            return Err("shmat on a bad shmid must be EINVAL");
        }
        let id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o700))
            .filter(|id| *id > 0)
            .ok_or("setup: shmget failed")? as u64;
        if call(Syscall::Shmat.raw(), a2(id, 0, SHM_REMAP)) != Some(EINVAL) {
            return Err("SHM_REMAP with a NULL address was not EINVAL");
        }
        if call(Syscall::Shmat.raw(), a2(id, 0x4000_0001, 0)) != Some(EINVAL) {
            return Err("unaligned shmat without SHM_RND was not EINVAL");
        }
        if call(Syscall::Shmat.raw(), a2(id, 0x123, SHM_RND | SHM_REMAP)) != Some(EINVAL) {
            return Err("SHM_RND|SHM_REMAP accepted an address rounded to NULL");
        }
        // Linux ignores unknown shmat bits. With no fixture AS, reaching the
        // normal mapping guard yields InvalidOp/None rather than EINVAL.
        if call(Syscall::Shmat.raw(), a2(id, 0, 0x2)).is_some() {
            return Err("shmat rejected an otherwise ignored unknown flag bit");
        }
        let _ = call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmat_neg);

fn smoke_abi_ipc_shmat_address_modes_and_remap() -> TestResult {
    with_setup(|| {
        with_ipc_shm_as(|as_ref| {
            let id = call(Syscall::Shmget.raw(), a2(0, 8192, IPC_CREAT | 0o700))
                .filter(|id| *id > 0)
                .ok_or("setup: first shmget failed")? as u64;
            let rounded = AddressSpace::USER_FIXED_FLOOR + 0x20_0000;
            if call(Syscall::Shmat.raw(), a2(id, rounded + 0x123, SHM_RND)) != Some(rounded as i64)
            {
                return Err("SHM_RND did not round the fixed address down");
            }
            if call(Syscall::Shmat.raw(), a2(id, rounded, 0)) != Some(EINVAL) {
                return Err("fixed shmat silently replaced an overlap without SHM_REMAP");
            }

            let exec_base = rounded + 0x4000;
            if call(
                Syscall::Shmat.raw(),
                a2(id, exec_base, SHM_RDONLY | SHM_EXEC),
            ) != Some(exec_base as i64)
            {
                return Err("SHM_RDONLY|SHM_EXEC attach failed");
            }
            let exec_region = as_ref
                .regions_snapshot()
                .into_iter()
                .find(|region| region.base.as_u64() == exec_base)
                .ok_or("readonly executable attach has no VMA")?;
            if !exec_region.perms.contains(RegionPerms::READ)
                || !exec_region.perms.contains(RegionPerms::EXEC)
                || !exec_region.perms.contains(RegionPerms::SHARED)
                || exec_region.perms.contains(RegionPerms::WRITE)
            {
                return Err("SHM_RDONLY|SHM_EXEC produced wrong region permissions");
            }
            if call(Syscall::MProtect.raw(), a2(exec_base + 4096, 4096, 1)) != Some(0) {
                return Err("mprotect could not split the tracked SysV attachment");
            }

            let id2 = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
                .filter(|id| *id > 0)
                .ok_or("setup: second shmget failed")? as u64;
            if call(Syscall::Shmat.raw(), a2(id2, rounded, SHM_REMAP)) != Some(rounded as i64) {
                return Err("SHM_REMAP did not replace the fixed mapping");
            }
            let munmap_base = rounded + 0x8000;
            if call(Syscall::Shmat.raw(), a2(id2, munmap_base, 0)) != Some(munmap_base as i64)
                || call(Syscall::Munmap.raw(), a1(munmap_base, 4096)) != Some(0)
            {
                return Err("munmap did not remove a complete SysV attachment");
            }

            let mut stat1 = [0u8; 112];
            let mut stat2 = [0u8; 112];
            if call(
                Syscall::Shmctl.raw(),
                a2(id, IPC_STAT, stat1.as_mut_ptr() as u64),
            ) != Some(0)
                || call(
                    Syscall::Shmctl.raw(),
                    a2(id2, IPC_STAT, stat2.as_mut_ptr() as u64),
                ) != Some(0)
            {
                return Err("IPC_STAT after SHM_REMAP failed");
            }
            if u64::from_ne_bytes(stat1[88..96].try_into().unwrap()) != 2
                || u64::from_ne_bytes(stat2[88..96].try_into().unwrap()) != 1
            {
                return Err("SHM_REMAP did not update shm_nattch exactly");
            }
            if call(Syscall::Shmdt.raw(), a0(rounded)) != Some(0)
                || call(Syscall::Shmdt.raw(), a0(rounded)) != Some(0)
                || call(Syscall::Shmdt.raw(), a0(exec_base)) != Some(0)
            {
                return Err("shmdt failed for a tracked attachment");
            }
            let _ = call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0));
            let _ = call(Syscall::Shmctl.raw(), a2(id2, IPC_RMID, 0));
            Ok(())
        })
    })
}
kernel_test_in!(
    "syscall_abi/shmat",
    smoke_abi_ipc_shmat_address_modes_and_remap
);

fn smoke_abi_ipc_mremap_fixed_detaches_destination_shm() -> TestResult {
    with_setup(|| {
        with_ipc_shm_as(|as_ref| {
            const TARGET: u64 = AddressSpace::USER_FIXED_FLOOR + 0x60_0000;
            const SOURCE: u64 = TARGET + 0x20_0000;
            const MREMAP_MAYMOVE_FIXED: u64 = 3;
            let id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
                .filter(|id| *id > 0)
                .ok_or("setup: shmget failed")? as u64;
            if call(Syscall::Shmat.raw(), a2(id, TARGET, 0)) != Some(TARGET as i64) {
                return Err("setup: fixed shmat destination failed");
            }
            if as_ref
                .map_region(Region {
                    base: VirtAddr::new(SOURCE),
                    len: 4096,
                    perms: RegionPerms::READ | RegionPerms::WRITE,
                    phys: alloc::vec![PhysAddr::new(0)],
                })
                .is_err()
            {
                return Err("setup: private mremap source failed");
            }
            let moved = call(
                Syscall::Mremap.raw(),
                SyscallArgs {
                    arg0: SOURCE,
                    arg1: 4096,
                    arg2: 4096,
                    arg3: MREMAP_MAYMOVE_FIXED,
                    arg4: TARGET,
                    ..Default::default()
                },
            );
            if moved != Some(TARGET as i64) {
                return Err("MREMAP_FIXED did not replace the SysV destination");
            }
            let mut stat = [0u8; 112];
            if call(
                Syscall::Shmctl.raw(),
                a2(id, IPC_STAT, stat.as_mut_ptr() as u64),
            ) != Some(0)
                || u64::from_ne_bytes(stat[88..96].try_into().unwrap()) != 0
            {
                return Err("MREMAP_FIXED destination punch did not decrement shm_nattch");
            }
            if call(Syscall::Shmdt.raw(), a0(TARGET)) != Some(EINVAL) {
                return Err("displaced SysV destination left a stale shmdt attachment");
            }
            let _ = call(Syscall::Munmap.raw(), a1(TARGET, 4096));
            let _ = call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0));
            Ok(())
        })
    })
}
kernel_test_in!(
    "syscall_abi/shmat",
    smoke_abi_ipc_mremap_fixed_detaches_destination_shm
);

// ── Shmdt ───────────────────────────────────────────────────────────
//
// shmdt(shmaddr) requires a page-aligned original attachment address.

fn smoke_abi_ipc_shmdt_neg() -> TestResult {
    with_setup(|| {
        if call(Syscall::Shmdt.raw(), a0(0x4000_0001)) != Some(EINVAL)
            || call(Syscall::Shmdt.raw(), a0(0x4000_0000)) != Some(EINVAL)
        {
            Err("shmdt invalid/misaligned address was not EINVAL")
        } else {
            Ok(())
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_ipc_shmdt_neg);

fn smoke_abi_ipc_shm_rmid_defers_until_shmdt() -> TestResult {
    with_setup(|| {
        with_ipc_shm_as(|as_ref| {
            let id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
                .filter(|id| *id > 0)
                .ok_or("setup: shmget failed")? as u64;
            let base = call(Syscall::Shmat.raw(), a2(id, 0, 0))
                .filter(|base| *base > 0)
                .ok_or("automatic shmat failed")? as u64;
            if call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
                return Err("IPC_RMID of attached segment failed");
            }
            let mut stat = [0u8; 112];
            if call(
                Syscall::Shmctl.raw(),
                a2(id, IPC_STAT, stat.as_mut_ptr() as u64),
            ) != Some(EINVAL)
            {
                return Err("IPC_RMID did not remove the public shmid immediately");
            }
            if as_ref.region_len_at_base(narf_memory::VirtAddr::new(base)) != Some(4096) {
                return Err("IPC_RMID destroyed a still-attached mapping");
            }
            if call(Syscall::Shmdt.raw(), a0(base)) != Some(0)
                || call(Syscall::Shmdt.raw(), a0(base)) != Some(EINVAL)
            {
                return Err("final shmdt lifecycle/duplicate result was wrong");
            }
            Ok(())
        })
    })
}
kernel_test_in!(
    "syscall_abi/shmat",
    smoke_abi_ipc_shm_rmid_defers_until_shmdt
);

fn smoke_abi_ipc_shm_process_exit_updates_nattch() -> TestResult {
    with_setup(|| {
        with_ipc_shm_as(|_| {
            let id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
                .filter(|id| *id > 0)
                .ok_or("setup: shmget failed")? as u64;
            if call(Syscall::Shmat.raw(), a2(id, 0, 0)).is_none() {
                return Err("setup: shmat failed");
            }
            let pid = u64::from(crate::handlers::current_ucred().pid);
            crate::handlers::shm_process_exit(pid, crate::handlers::current_task_id());

            let mut stat = [0u8; 112];
            if call(
                Syscall::Shmctl.raw(),
                a2(id, IPC_STAT, stat.as_mut_ptr() as u64),
            ) != Some(0)
                || u64::from_ne_bytes(stat[88..96].try_into().unwrap()) != 0
            {
                return Err("process exit did not close the inherited SysV attachment");
            }
            if call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
                return Err("IPC_RMID after implicit exit detach failed");
            }
            Ok(())
        })
    })
}
kernel_test_in!(
    "syscall_abi/shmat",
    smoke_abi_ipc_shm_process_exit_updates_nattch
);

// ── Shmctl ──────────────────────────────────────────────────────────
//
// shmctl(shmid, cmd, buf). IPC_RMID on an unknown id → -EINVAL; IPC_STAT
// with buf=0 on an unknown id → -EINVAL. A real positive path needs a
// segment, which requires the vtable-backed shmget — covered separately.

fn smoke_abi_ipc_shmctl_pos() -> TestResult {
    with_setup(|| {
        // Create a real segment, then IPC_STAT fills one complete shmid64_ds.
        let id = match call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT)) {
            Some(id) if id > 0 => id as u64,
            _ => return Err("setup: shmget create failed (shmem vtable absent?)"),
        };
        let mut stat = [0u8; 112];
        if call(
            Syscall::Shmctl.raw(),
            a2(id, IPC_STAT, stat.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("shmctl IPC_STAT on a live segment should return 0");
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

fn smoke_abi_ipc_shmctl_exact_order_permissions_and_set() -> TestResult {
    with_setup(|| {
        if call(Syscall::Shmctl.raw(), a2(987654, IPC_SET, BAD_PTR)) != Some(EFAULT) {
            return Err("IPC_SET did not import shmid_ds before id lookup");
        }
        if call(Syscall::Shmctl.raw(), a2(987654, 0x7f, BAD_PTR)) != Some(EINVAL)
            || call(
                Syscall::Shmctl.raw(),
                a2(987654, IPC_STAT | IPC_64, BAD_PTR),
            ) != Some(EINVAL)
        {
            return Err("native shmctl did not reject unknown/IPC_64-tagged commands first");
        }

        let id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
            .filter(|id| *id > 0)
            .ok_or("setup: shmget failed")? as u64;
        if call(Syscall::Shmctl.raw(), a2(id, IPC_STAT, BAD_PTR)) != Some(EFAULT) {
            return Err("IPC_STAT bad output pointer was not EFAULT");
        }
        let mut set = [0u8; 112];
        set[4..8].copy_from_slice(&2000u32.to_ne_bytes());
        set[8..12].copy_from_slice(&3000u32.to_ne_bytes());
        set[20..24].copy_from_slice(&0o640u32.to_ne_bytes());
        if call(Syscall::Shmctl.raw(), a2(id, IPC_SET, set.as_ptr() as u64)) != Some(0) {
            return Err("owner IPC_SET failed");
        }
        let mut stat = [0u8; 112];
        if call(
            Syscall::Shmctl.raw(),
            a2(id, IPC_STAT, stat.as_mut_ptr() as u64),
        ) != Some(0)
            || u32::from_ne_bytes(stat[4..8].try_into().unwrap()) != 2000
            || u32::from_ne_bytes(stat[8..12].try_into().unwrap()) != 3000
            || u32::from_ne_bytes(stat[20..24].try_into().unwrap()) != 0o640
        {
            return Err("IPC_SET fields did not round-trip through IPC_STAT");
        }

        // Move only the EFFECTIVE uid, keeping the saved uid at 0 as the
        // way back. `setresuid(1000, 1000, 1000)` moves all three and is
        // IRREVERSIBLE — Linux clears the capability sets on a root ->
        // non-root transition (cap_emulate_setxuid), so the restore
        // afterwards would need a CAP_SETUID the task no longer holds.
        // Dropping euid alone clears only the EFFECTIVE set, and returning
        // euid to 0 restores it from permitted, which is exactly how a
        // set-uid helper brackets a privileged section.
        if call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 1000, u32::MAX as u64),
        ) != Some(0)
        {
            return Err("failed to install non-owner test credentials");
        }
        let non_owner_set = call(Syscall::Shmctl.raw(), a2(id, IPC_SET, set.as_ptr() as u64));
        let non_owner_rmid = call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0));
        let _ = call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 0, u32::MAX as u64),
        );
        if non_owner_set != Some(EPERM) || non_owner_rmid != Some(EPERM) {
            return Err("non-owner shmctl mutation was not EPERM");
        }
        let _ = call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/shmat",
    smoke_abi_ipc_shmctl_exact_order_permissions_and_set
);

fn smoke_abi_ipc_shmctl_info_stat_and_lock() -> TestResult {
    with_setup(|| {
        if call(Syscall::Shmget.raw(), a2(0, 1024 * 1024 + 1, IPC_CREAT)) != Some(EINVAL) {
            return Err("shmget above configured SHMMAX must return EINVAL");
        }
        let id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
            .filter(|id| *id > 0)
            .ok_or("setup: shmget failed")? as u64;

        let mut limits = [0u8; 72];
        let ipc_info = call_raw(
            Syscall::Shmctl.raw(),
            a2(id, IPC_INFO, limits.as_mut_ptr() as u64),
        );
        let read_u64 = |bytes: &[u8], offset: usize| {
            u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
        };
        if ipc_info.value < id
            || read_u64(&limits, 0) != 1024 * 1024
            || read_u64(&limits, 8) != 1
            || read_u64(&limits, 16) != 4096
            || read_u64(&limits, 24) != 4096
            || read_u64(&limits, 32) != 4096 * 256
        {
            return Err("shmctl IPC_INFO did not expose configured shared-memory limits");
        }
        let mut usage = [0u8; 48];
        let shm_info = call_raw(
            Syscall::Shmctl.raw(),
            a2(id, SHM_INFO, usage.as_mut_ptr() as u64),
        );
        if shm_info.value < id
            || u32::from_ne_bytes(usage[..4].try_into().unwrap()) < 1
            || read_u64(&usage, 8) < 1
            || read_u64(&usage, 16) < 1
            || read_u64(&usage, 24) != 0
        {
            return Err("shmctl SHM_INFO did not report resident namespace usage");
        }

        let mut stat = [0u8; 112];
        if call(
            Syscall::Shmctl.raw(),
            a2(id, SHM_STAT, stat.as_mut_ptr() as u64),
        ) != Some(id as i64)
        {
            return Err("shmctl SHM_STAT did not return the indexed segment's full id");
        }
        if call(Syscall::Shmctl.raw(), a2(987_654, SHM_STAT, BAD_PTR)) != Some(EINVAL)
            || call(Syscall::Shmctl.raw(), a2(id, SHM_STAT, BAD_PTR)) != Some(EFAULT)
            || call(
                Syscall::Shmctl.raw(),
                a2(u64::from(u32::MAX), IPC_INFO, BAD_PTR),
            ) != Some(EINVAL)
        {
            return Err("extended shmctl lookup/copyout errno ordering diverged from Linux");
        }

        if call(Syscall::Shmctl.raw(), a2(id, SHM_LOCK, 0)) != Some(0) {
            return Err("owner shmctl SHM_LOCK failed");
        }
        stat.fill(0);
        if call(
            Syscall::Shmctl.raw(),
            a2(id, IPC_STAT, stat.as_mut_ptr() as u64),
        ) != Some(0)
            || u32::from_ne_bytes(stat[20..24].try_into().unwrap()) & SHM_LOCKED == 0
        {
            return Err("SHM_LOCK did not publish Linux's SHM_LOCKED mode bit");
        }
        if call(Syscall::Shmctl.raw(), a2(id, SHM_UNLOCK, 0)) != Some(0) {
            return Err("owner shmctl SHM_UNLOCK failed");
        }

        if call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 1000, u32::MAX as u64),
        ) != Some(0)
        {
            return Err("failed to install non-owner test credentials");
        }
        let denied_stat = call(
            Syscall::Shmctl.raw(),
            a2(id, SHM_STAT, stat.as_mut_ptr() as u64),
        );
        let any_stat = call(
            Syscall::Shmctl.raw(),
            a2(id, SHM_STAT_ANY, stat.as_mut_ptr() as u64),
        );
        let denied_lock = call(Syscall::Shmctl.raw(), a2(id, SHM_LOCK, 0));
        let _ = call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 0, u32::MAX as u64),
        );
        if denied_stat != Some(EACCES) || any_stat != Some(id as i64) || denied_lock != Some(EPERM)
        {
            return Err("extended shmctl permission behavior diverged from Linux");
        }

        let mut owner = [0u8; 112];
        owner[4..8].copy_from_slice(&1000u32.to_ne_bytes());
        owner[8..12].copy_from_slice(&1000u32.to_ne_bytes());
        owner[20..24].copy_from_slice(&0o600u32.to_ne_bytes());
        if call(
            Syscall::Shmctl.raw(),
            a2(id, IPC_SET, owner.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setup: could not assign SHM_LOCK test owner");
        }
        let task = crate::handlers::current_task_id();
        crate::handlers::__test_set_fsids(task, 1000, 1000);
        let mut limit = [0u8; 16];
        limit[8..].copy_from_slice(&(8u64 * 1024 * 1024).to_ne_bytes());
        if call(Syscall::Setrlimit.raw(), a1(8, limit.as_ptr() as u64)) != Some(0)
            || call(Syscall::Shmctl.raw(), a2(id, SHM_LOCK, 0)) != Some(EPERM)
        {
            return Err("zero RLIMIT_MEMLOCK must make owner SHM_LOCK return EPERM");
        }
        limit[..8].copy_from_slice(&4096u64.to_ne_bytes());
        if call(Syscall::Setrlimit.raw(), a1(8, limit.as_ptr() as u64)) != Some(0)
            || call(Syscall::Shmctl.raw(), a2(id, SHM_LOCK, 0)) != Some(0)
        {
            return Err("owner SHM_LOCK within RLIMIT_MEMLOCK failed");
        }
        let second = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
            .filter(|second| *second > 0)
            .ok_or("setup: second SHM_LOCK segment failed")? as u64;
        if call(Syscall::Shmctl.raw(), a2(second, SHM_LOCK, 0)) != Some(ENOMEM) {
            return Err("aggregate SHM_LOCK charge above RLIMIT_MEMLOCK must be ENOMEM");
        }
        if call(Syscall::Shmctl.raw(), a2(id, SHM_UNLOCK, 0)) != Some(0)
            || call(Syscall::Shmctl.raw(), a2(second, SHM_LOCK, 0)) != Some(0)
            || call(Syscall::Shmctl.raw(), a2(second, IPC_RMID, 0)) != Some(0)
        {
            return Err("SHM_UNLOCK did not release the per-user lock charge");
        }
        crate::handlers::__test_set_fsids(task, 0, 0);
        if call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0)) != Some(0) {
            return Err("extended shmctl test cleanup failed");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_shmctl_info_stat_and_lock
);

fn smoke_abi_ipc_shmat_permission_denied_before_as() -> TestResult {
    with_setup(|| {
        let id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o400))
            .filter(|id| *id > 0)
            .ok_or("setup: shmget failed")? as u64;
        let _ = call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 1000, u32::MAX as u64),
        );
        let readonly = call(Syscall::Shmat.raw(), a2(id, 0, SHM_RDONLY));
        let writable = call(Syscall::Shmat.raw(), a2(id, 0, 0));
        let _ = call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 0, u32::MAX as u64),
        );
        let _ = call(Syscall::Shmctl.raw(), a2(id, IPC_RMID, 0));
        if readonly != Some(EACCES) || writable != Some(EACCES) {
            Err("shmat did not enforce read/write IPC permissions before mapping")
        } else {
            Ok(())
        }
    })
}
kernel_test_in!(
    "syscall_abi/shmat",
    smoke_abi_ipc_shmat_permission_denied_before_as
);

// shmctl's three refusals are not interchangeable, and which one wins is
// decided by different kernel helpers:
//   * ipc/util.c::ipcctl_obtain_check  -> -EINVAL (no such id) then -EPERM
//     (not uid/cuid, no CAP_SYS_ADMIN) for IPC_SET / IPC_RMID;
//   * ipc/shm.c::shmctl_do_lock        -> the same ladder for SHM_LOCK /
//     SHM_UNLOCK, gated on CAP_IPC_LOCK;
//   * ipc/util.c::ipcperms             -> -EACCES, reached only by the
//     read-only IPC_STAT / SHM_STAT family.
// So a world-readable, world-writable segment still refuses a foreign
// IPC_RMID with -EPERM: the mutating commands never look at the mode bits.
// An ipcrm-style reaper depends on exactly this — -EINVAL means "already
// gone, keep going", -EPERM means "someone else's, report it".
fn smoke_abi_ipc_shmctl_eperm_vs_eacces_vs_einval() -> TestResult {
    with_setup(|| {
        // Mode 0o666: every permission bit granted to every class.
        let open_id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o666))
            .filter(|id| *id > 0)
            .ok_or("setup: world-accessible shmget failed")? as u64;
        // Mode 0o600: readable by the owner only.
        let closed_id = call(Syscall::Shmget.raw(), a2(0, 4096, IPC_CREAT | 0o600))
            .filter(|id| *id > 0)
            .ok_or("setup: owner-only shmget failed")? as u64;

        let mut stat = [0u8; 112];
        let mut set = [0u8; 112];
        set[20..24].copy_from_slice(&0o666u32.to_ne_bytes());

        if call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 1000, u32::MAX as u64),
        ) != Some(0)
        {
            return Err("failed to install non-owner test credentials");
        }
        // ipcperms grants the read, so IPC_STAT succeeds ...
        let open_stat = call(
            Syscall::Shmctl.raw(),
            a2(open_id, IPC_STAT, stat.as_mut_ptr() as u64),
        );
        // ... while every mutating command still answers EPERM, because
        // ipcctl_obtain_check / shmctl_do_lock consult ownership only.
        let open_set = call(
            Syscall::Shmctl.raw(),
            a2(open_id, IPC_SET, set.as_ptr() as u64),
        );
        let open_rmid = call(Syscall::Shmctl.raw(), a2(open_id, IPC_RMID, 0));
        let open_lock = call(Syscall::Shmctl.raw(), a2(open_id, SHM_LOCK, 0));
        let open_unlock = call(Syscall::Shmctl.raw(), a2(open_id, SHM_UNLOCK, 0));
        // The owner-only segment is where EACCES lives.
        let closed_stat = call(
            Syscall::Shmctl.raw(),
            a2(closed_id, IPC_STAT, stat.as_mut_ptr() as u64),
        );
        let closed_rmid = call(Syscall::Shmctl.raw(), a2(closed_id, IPC_RMID, 0));
        // ksys_shmctl screens the ints before it dispatches, so a negative
        // shmid outranks an unknown command, and an unknown command outranks
        // the lookup. IPC_64 is not stripped by the native entry point.
        let neg_id = call(Syscall::Shmctl.raw(), a2(u64::from(u32::MAX), 0x7f, 0));
        let unknown_cmd = call(Syscall::Shmctl.raw(), a2(open_id, 0x7f, 0));
        let _ = call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 0, u32::MAX as u64),
        );

        if open_stat != Some(0) {
            return Err("mode 0o666 IPC_STAT was refused although ipcperms grants read");
        }
        if open_set != Some(EPERM)
            || open_rmid != Some(EPERM)
            || open_lock != Some(EPERM)
            || open_unlock != Some(EPERM)
        {
            return Err("mode 0o666 mutation by a non-owner was not EPERM");
        }
        if closed_stat != Some(EACCES) {
            return Err("mode 0o600 IPC_STAT by a non-owner was not EACCES");
        }
        if closed_rmid != Some(EPERM) {
            return Err("IPC_RMID by a non-owner reported the mode bits, not ownership");
        }
        if neg_id != Some(EINVAL) || unknown_cmd != Some(EINVAL) {
            return Err("shmctl argument/command screening did not precede the lookup");
        }

        // Back as the owner: the first IPC_RMID succeeds, and the second one
        // is EINVAL — ipc_rmid unpublishes the id, so a repeat reap looks
        // like "never existed", not EIDRM and not EPERM.
        if call(Syscall::Shmctl.raw(), a2(open_id, IPC_RMID, 0)) != Some(0)
            || call(Syscall::Shmctl.raw(), a2(closed_id, IPC_RMID, 0)) != Some(0)
        {
            return Err("owner IPC_RMID failed");
        }
        if call(Syscall::Shmctl.raw(), a2(open_id, IPC_RMID, 0)) != Some(EINVAL)
            || call(
                Syscall::Shmctl.raw(),
                a2(open_id, IPC_STAT, stat.as_mut_ptr() as u64),
            ) != Some(EINVAL)
            || call(Syscall::Shmctl.raw(), a2(open_id, SHM_LOCK, 0)) != Some(EINVAL)
        {
            return Err("a reaped shmid must be EINVAL for every shmctl command");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/sysvipc_correctness",
    smoke_abi_ipc_shmctl_eperm_vs_eacces_vs_einval
);

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
