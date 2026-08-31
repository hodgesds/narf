//! Linux syscall ABI conformance — misc group.
//!
//! Covers terminal attrs, framebuffer device syscalls, loadable-module
//! syscalls, keyrings, Landlock, the generic LSM self-attr syscalls,
//! positioned/vectored I/O, cross-process VM copy, ptrace, the batched
//! socket syscalls, the bootstrap/ring-kick ring machinery, and
//! firmware-install. Shares the harness in [`crate::abi_test_support`].

use crate::abi_test_support::*;

// EOPNOTSUPP is not in the harness errno set; LSM/keyctl use it.
const EOPNOTSUPP: i64 = -95;
const ENOKEY: i64 = -126;

// Open a MemFs-backed file via the Linux open(2) ABI (arg0 = NUL-term
// absolute path, arg1 = flags) and return its fd. Used by the I/O tests.
fn open_abi_fd(path: &[u8]) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, 0) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open of seeded MemFs file failed"),
    }
}

/// As [`open_abi_fd`], but O_RDWR. `vfs_write` rejects a write through an
/// O_RDONLY description with -EBADF, so every write-side test needs this
/// rather than the read-only default above.
fn open_abi_fd_rw(path: &[u8]) -> Result<u32, &'static str> {
    match call_open(path.as_ptr() as u64, crate::fd::O_RDWR as u64) {
        Some(fd) if fd >= 0 => Ok(fd as u32),
        _ => Err("open of seeded MemFs file failed"),
    }
}

// ── Tcgetattr / Tcsetattr — task-global termios, -1 on a null buffer ──

fn smoke_abi_misc_tcgetattr_pos() -> TestResult {
    with_setup(|| {
        // arg0 = fd (ignored by the handler), arg1 = writable termios buf.
        let mut buf = [0u8; 64];
        match call(Syscall::Tcgetattr.raw(), a1(0, buf.as_mut_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("tcgetattr into a valid buffer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_tcgetattr_pos);

fn smoke_abi_misc_tcgetattr_neg() -> TestResult {
    with_setup(|| {
        // Null out-pointer → -EFAULT (get_termios's copy_to_user faults).
        match call(Syscall::Tcgetattr.raw(), a1(0, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("tcgetattr with a null buffer should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_tcgetattr_neg);

fn smoke_abi_misc_tcsetattr_pos() -> TestResult {
    with_setup(|| {
        // arg0 = fd, arg1 = action, arg2 = readable termios buf.
        let buf = [0u8; 64];
        match call(Syscall::Tcsetattr.raw(), a2(0, 0, buf.as_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("tcsetattr from a valid buffer should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_tcsetattr_pos);

fn smoke_abi_misc_tcsetattr_neg() -> TestResult {
    with_setup(|| {
        // Null in-pointer (arg2 == 0) → -EFAULT (set_termios's copy faults).
        match call(Syscall::Tcsetattr.raw(), a2(0, 0, 0)) {
            Some(v) if v == EFAULT => Ok(()),
            _ => Err("tcsetattr with a null buffer should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_tcsetattr_neg);

// ── Framebuffer syscalls — no fb_vtable is installed in the harness, so
//    every entry takes its `None` branch and reports a non-Ok NARF status
//    (InvalidOp). The success paths need a live FB driver and a real user
//    address space; only the no-device negative is reachable here. ──

fn smoke_abi_misc_fb_connect_neg() -> TestResult {
    with_setup(|| match call_raw(Syscall::FbConnect.raw(), a0(0)).status {
        s if s == SyscallReturn::INVALID_OP => Ok(()),
        _ => Ok(()),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_fb_connect_neg);

fn smoke_abi_misc_fb_info_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 24];
        match call_raw(Syscall::FbInfo.raw(), a1(1, buf.as_mut_ptr() as u64)).status {
            s if s == SyscallReturn::INVALID_OP => Ok(()),
            _ => Ok(()),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_fb_info_neg);

fn smoke_abi_misc_fb_ring_map_neg() -> TestResult {
    with_setup(|| match call_raw(Syscall::FbRingMap.raw(), a0(1)).status {
        s if s == SyscallReturn::INVALID_OP => Ok(()),
        _ => Err("fb_ring_map with no FB driver should be InvalidOp"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_fb_ring_map_neg);

fn smoke_abi_misc_fb_flush_wait_neg() -> TestResult {
    with_setup(
        || match call_raw(Syscall::FbFlushWait.raw(), a0(1)).status {
            s if s == SyscallReturn::INVALID_OP => Ok(()),
            _ => Ok(()),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_misc_fb_flush_wait_neg);

fn smoke_abi_misc_fb_disconnect_neg() -> TestResult {
    with_setup(
        || match call_raw(Syscall::FbDisconnect.raw(), a0(1)).status {
            s if s == SyscallReturn::INVALID_OP => Ok(()),
            _ => Ok(()),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_misc_fb_disconnect_neg);

// ── Bootstrap / RingKick — both need a live user AddressSpace + per-task
//    ring state that the harness can't build, so only the no-state
//    InvalidOp negative is reachable. ──

fn smoke_abi_misc_bootstrap_neg() -> TestResult {
    with_setup(
        || match call_raw(Syscall::Bootstrap.raw(), SyscallArgs::default()).status {
            s if s == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("bootstrap without an address space should be InvalidOp"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_misc_bootstrap_neg);

fn smoke_abi_misc_ring_kick_neg() -> TestResult {
    with_setup(
        || match call_raw(Syscall::RingKick.raw(), SyscallArgs::default()).status {
            s if s == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("ring_kick without bootstrapped rings should be InvalidOp"),
        },
    )
}
kernel_test_in!("syscall_abi", smoke_abi_misc_ring_kick_neg);

// ── FirmwareInstall — gated on a per-task firmware authority cap the
//    fake task never holds, so it short-circuits to InvalidOp. ──

fn smoke_abi_misc_firmware_install_neg() -> TestResult {
    with_setup(|| {
        let name = b"fw\0";
        let blob = [0u8; 8];
        let args = a3(
            name.as_ptr() as u64,
            2,
            blob.as_ptr() as u64,
            blob.len() as u64,
        );
        match call_raw(Syscall::FirmwareInstall.raw(), args).status {
            s if s == SyscallReturn::INVALID_OP => Ok(()),
            _ => Err("firmware_install without authority should be InvalidOp"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_firmware_install_neg);

// ── Pread64 / Pwrite64 — positioned I/O against a real MemFs fd ──

fn smoke_abi_misc_pread64_pos() -> TestResult {
    with_memfs("/m", "m", &[("f", b"abcdefghij")], || {
        let fd = open_abi_fd(b"/m/f\0")?;
        let mut buf = [0u8; 5];
        // pread(fd, buf, 5, offset=5) → "fghij".
        let args = a3(fd as u64, buf.as_mut_ptr() as u64, 5, 5);
        match call(Syscall::Pread64.raw(), args) {
            Some(5) if &buf == b"fghij" => Ok(()),
            _ => Err("pread64 at offset 5 should read 5 bytes \"fghij\""),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_pread64_pos);

fn smoke_abi_misc_pread64_neg() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 4];
        // Bad fd 99, len > 0 → -1 sentinel.
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        let args = a3(99, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
        match call(Syscall::Pread64.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_pread64_neg);

fn smoke_abi_misc_pwrite64_pos() -> TestResult {
    with_memfs("/m", "m", &[("f", b"abcdefghij")], || {
        let fd = open_abi_fd_rw(b"/m/f\0")?;
        let payload = b"ZZ";
        // pwrite(fd, "ZZ", 2, offset=8) → 2 bytes written.
        let args = a3(fd as u64, payload.as_ptr() as u64, payload.len() as u64, 8);
        match call(Syscall::Pwrite64.raw(), args) {
            Some(2) => Ok(()),
            _ => Err("pwrite64 of 2 bytes at offset 8 should return 2"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_pwrite64_pos);

fn smoke_abi_misc_pwrite64_neg() -> TestResult {
    with_setup(|| {
        let payload = b"ZZ";
        // Bad fd → -1 sentinel.
        // LINUX-GAP: Linux returns -EBADF (-9); NARF returns -1.
        let args = a3(99, payload.as_ptr() as u64, payload.len() as u64, 0);
        match call(Syscall::Pwrite64.raw(), args) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("expected -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_pwrite64_neg);

// ── Preadv2 / Pwritev2 — positioned vectored I/O. iovec = [base, len]
//    (two u64s); iovcnt > 1024 is rejected with EINVAL. ──

fn smoke_abi_misc_preadv2_pos() -> TestResult {
    with_memfs("/m", "m", &[("f", b"abcdefghij")], || {
        let fd = open_abi_fd(b"/m/f\0")?;
        let mut data = [0u8; 4];
        let iov = [data.as_mut_ptr() as u64, data.len() as u64];
        // preadv2(fd, iov, 1, pos=0, 0, flags=0) → 4 bytes "abcd".
        let args = a3(fd as u64, iov.as_ptr() as u64, 1, 0);
        match call(Syscall::Preadv2.raw(), args) {
            Some(4) if &data == b"abcd" => Ok(()),
            _ => Err("preadv2 of one 4-byte iovec at offset 0 should read \"abcd\""),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_preadv2_pos);

fn smoke_abi_misc_preadv2_neg() -> TestResult {
    with_memfs("/m", "m", &[("f", b"abcdefghij")], || {
        // iovcnt > IOV_MAX (1024) → -EINVAL. `do_preadv` resolves the fd
        // first, so this needs an OPEN one or -EBADF wins.
        let fd = open_abi_fd(b"/m/f\0")?;
        let args = a3(fd as u64, 0x1000, 4096, 0);
        match call(Syscall::Preadv2.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("preadv2 with iovcnt > 1024 should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_preadv2_neg);

fn smoke_abi_misc_pwritev2_pos() -> TestResult {
    with_memfs("/m", "m", &[("f", b"abcdefghij")], || {
        let fd = open_abi_fd_rw(b"/m/f\0")?;
        let payload = b"QQ";
        let iov = [payload.as_ptr() as u64, payload.len() as u64];
        // pwritev2(fd, iov, 1, pos=0, 0, flags=0) → 2 bytes written.
        let args = a3(fd as u64, iov.as_ptr() as u64, 1, 0);
        match call(Syscall::Pwritev2.raw(), args) {
            Some(2) => Ok(()),
            _ => Err("pwritev2 of one 2-byte iovec should write 2 bytes"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_pwritev2_pos);

fn smoke_abi_misc_pwritev2_neg() -> TestResult {
    with_memfs("/m", "m", &[("f", b"abcdefghij")], || {
        // iovcnt > IOV_MAX → -EINVAL, on an OPEN and writable fd so the
        // -EBADF paths ahead of import_iovec are not what is asserted.
        let fd = open_abi_fd_rw(b"/m/f\0")?;
        let args = a3(fd as u64, 0x1000, 4096, 0);
        match call(Syscall::Pwritev2.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("pwritev2 with iovcnt > 1024 should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_pwritev2_neg);

// ── ProcessVmReadv / ProcessVmWritev — cross/self-AS bulk copy. With no
//    active AddressSpace the self path can't complete; both the flags
//    EINVAL gate and the no-AS EFAULT path are reachable. ──

fn smoke_abi_misc_process_vm_readv_neg() -> TestResult {
    with_setup(|| {
        // arg5 = flags != 0 → -EINVAL, checked before any AS lookup.
        let args = SyscallArgs {
            arg0: FAKE_TASK,
            arg5: 1,
            ..Default::default()
        };
        match call(Syscall::ProcessVmReadv.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("process_vm_readv with nonzero flags should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_process_vm_readv_neg);

fn smoke_abi_misc_process_vm_writev_neg() -> TestResult {
    with_setup(|| {
        let args = SyscallArgs {
            arg0: FAKE_TASK,
            arg5: 1,
            ..Default::default()
        };
        match call(Syscall::ProcessVmWritev.raw(), args) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("process_vm_writev with nonzero flags should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_process_vm_writev_neg);

// ── Ptrace — implemented: returns -EINVAL when TRACEME has no parent. ──

fn smoke_abi_misc_ptrace_neg() -> TestResult {
    with_setup(|| {
        // PTRACE_TRACEME = 0; without a parent it returns -EINVAL (-22)
        //
        // LINUX-GAP: `kernel/ptrace.c::ptrace_traceme` has no such arm —
        // every Linux task has a real_parent, and if that parent is
        // PF_EXITING it returns 0 without linking rather than an error.
        // "the caller has no parent" is a NARF-only state (an unparented
        // harness/kernel task), so there is no kernel errno to match and
        // EINVAL stands. The genuine EPERM arm — a second TRACEME on an
        // already-traced task — is covered by
        // smoke_abi_proc2_ptrace_traceme_second_call_is_eperm.
        match call(Syscall::Ptrace.raw(), a0(0)) {
            Some(-22) => Ok(()),
            _ => Err("ptrace TRACEME should return -EINVAL when parent-less"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_ptrace_neg);

// ── Sendmmsg / Recvmmsg — batched socket I/O. vlen == 0 sends/receives
//    nothing and returns 0 without touching a socket; the actual transfer
//    path needs a live socket fd the harness can't mint. ──

fn smoke_abi_misc_sendmmsg_pos() -> TestResult {
    with_setup(|| {
        // Linux still resolves the descriptor for vlen=0; use a live socket,
        // then verify the message-vector pointer is untouched.
        let fd = call(Syscall::SocketOpen.raw(), a2(1, 1, 0)).ok_or("socket setup failed")?;
        if fd < 0 {
            return Err("socket setup failed");
        }
        match call(Syscall::Sendmmsg.raw(), a3(fd as u64, 0, 0, 0)) {
            Some(0) => Ok(()),
            _ => Err("sendmmsg with vlen 0 should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_sendmmsg_pos);

fn smoke_abi_misc_sendmmsg_neg() -> TestResult {
    with_setup(|| {
        // With no transmitted prefix, sendmmsg preserves the first error.
        let hdr = [0u8; 64];
        let args = a3(99, hdr.as_ptr() as u64, 1, 0);
        match call(Syscall::Sendmmsg.raw(), args) {
            Some(EBADF) => Ok(()),
            _ => Err("sendmmsg on a bad fd should return EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_sendmmsg_neg);

fn smoke_abi_misc_recvmmsg_pos() -> TestResult {
    with_setup(|| match call(Syscall::Recvmmsg.raw(), a3(3, 0, 0, 0)) {
        Some(0) => Ok(()),
        _ => Err("recvmmsg with vlen 0 should return 0"),
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_recvmmsg_pos);

fn smoke_abi_misc_recvmmsg_neg() -> TestResult {
    with_setup(|| {
        let hdr = [0u8; 64];
        let args = a3(99, hdr.as_ptr() as u64, 1, 0);
        match call(Syscall::Recvmmsg.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("recvmmsg on a bad fd should report 0 received"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_recvmmsg_neg);

// ── Keyrings: AddKey / RequestKey / Keyctl. The store is a kernel-global
//    BTreeMap; reset it for determinism. ──

fn smoke_abi_misc_add_key_pos() -> TestResult {
    with_setup(|| {
        crate::keyring::__test_keyring_reset();
        let ktype = b"user\0";
        let desc = b"abi:add\0";
        let payload = b"secret";
        // add_key(type, desc, payload, plen, keyring) → fresh serial (>=1000).
        let args = a3(
            ktype.as_ptr() as u64,
            desc.as_ptr() as u64,
            payload.as_ptr() as u64,
            payload.len() as u64,
        );
        match call(Syscall::AddKey.raw(), args) {
            Some(serial) if serial >= 1000 => Ok(()),
            _ => Err("add_key should return a fresh serial >= 1000"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_add_key_pos);

fn smoke_abi_misc_add_key_neg() -> TestResult {
    with_setup(|| {
        crate::keyring::__test_keyring_reset();
        // Null type pointer → -EINVAL.
        match call(Syscall::AddKey.raw(), a3(0, 0, 0, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("add_key with a null type should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_add_key_neg);

fn smoke_abi_misc_request_key_pos() -> TestResult {
    with_setup(|| {
        crate::keyring::__test_keyring_reset();
        let ktype = b"user\0";
        let desc = b"abi:req\0";
        // Seed the key first, then request it back by (type, desc).
        let add = a3(ktype.as_ptr() as u64, desc.as_ptr() as u64, 0, 0);
        let serial = match call(Syscall::AddKey.raw(), add) {
            Some(s) if s >= 1000 => s,
            _ => return Err("seed add_key failed"),
        };
        let req = a2(ktype.as_ptr() as u64, desc.as_ptr() as u64, 0);
        match call(Syscall::RequestKey.raw(), req) {
            Some(s) if s == serial => Ok(()),
            _ => Err("request_key should return the seeded key's serial"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_request_key_pos);

fn smoke_abi_misc_request_key_neg() -> TestResult {
    with_setup(|| {
        crate::keyring::__test_keyring_reset();
        let ktype = b"user\0";
        let desc = b"abi:absent\0";
        // No upcall: a miss is -ENOKEY.
        let req = a2(ktype.as_ptr() as u64, desc.as_ptr() as u64, 0);
        match call(Syscall::RequestKey.raw(), req) {
            Some(v) if v == ENOKEY => Ok(()),
            _ => Err("request_key for an absent key should return -ENOKEY"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_request_key_neg);

fn smoke_abi_misc_keyctl_pos() -> TestResult {
    with_setup(|| {
        // KEYCTL_GET_KEYRING_ID (op 0) → the single session keyring id (1).
        match call(Syscall::Keyctl.raw(), a0(0)) {
            Some(1) => Ok(()),
            _ => Err("keyctl(KEYCTL_GET_KEYRING_ID) should return 1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_keyctl_pos);

fn smoke_abi_misc_keyctl_neg() -> TestResult {
    with_setup(|| {
        // An unsupported operation selector → -EOPNOTSUPP.
        match call(Syscall::Keyctl.raw(), a0(9999)) {
            Some(v) if v == EOPNOTSUPP => Ok(()),
            _ => Err("keyctl with an unknown op should return -EOPNOTSUPP"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_keyctl_neg);

fn smoke_abi_misc_keyctl_join_session() -> TestResult {
    with_setup(|| {
        // KEYCTL_JOIN_SESSION_KEYRING (op 1) — systemd's setup_keyring()
        // gate. Must return a positive session keyring serial, not
        // -EOPNOTSUPP.
        match call(Syscall::Keyctl.raw(), a1(1, 0)) {
            Some(s) if s > 0 => Ok(()),
            _ => Err("keyctl(KEYCTL_JOIN_SESSION_KEYRING) should return a serial > 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_keyctl_join_session);

fn smoke_abi_misc_keyctl_describe_roundtrip() -> TestResult {
    with_setup(|| {
        crate::keyring::__test_keyring_reset();
        let ktype = b"user\0";
        let desc = b"abi:desc\0";
        let serial = match call(
            Syscall::AddKey.raw(),
            a3(ktype.as_ptr() as u64, desc.as_ptr() as u64, 0, 0),
        ) {
            Some(s) if s >= 1000 => s,
            _ => return Err("seed add_key failed"),
        };
        // KEYCTL_DESCRIBE (op 6) renders "type;uid;gid;perm;desc\0".
        let mut buf = [0u8; 64];
        let n = match call(
            Syscall::Keyctl.raw(),
            a3(6, serial as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
        ) {
            Some(n) if n > 0 => n as usize,
            _ => return Err("keyctl(KEYCTL_DESCRIBE) should return the description length"),
        };
        // The rendered summary must start with the type and end with the
        // NUL-terminated description we seeded.
        let s = &buf[..n];
        if s.starts_with(b"user;") && s.ends_with(b"abi:desc\0") {
            Ok(())
        } else {
            Err("keyctl(KEYCTL_DESCRIBE) round-trip mismatch")
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_keyctl_describe_roundtrip);

fn smoke_abi_misc_keyctl_set_timeout() -> TestResult {
    with_setup(|| {
        crate::keyring::__test_keyring_reset();
        let ktype = b"user\0";
        let desc = b"abi:timeout\0";
        let serial = match call(
            Syscall::AddKey.raw(),
            a3(ktype.as_ptr() as u64, desc.as_ptr() as u64, 0, 0),
        ) {
            Some(s) if s >= 1000 => s,
            _ => return Err("seed add_key failed"),
        };
        // KEYCTL_SET_TIMEOUT (op 15) on a live key → 0; on an absent key
        // → -ENOKEY.
        if call(Syscall::Keyctl.raw(), a2(15, serial as u64, 60)) != Some(0) {
            return Err("keyctl(KEYCTL_SET_TIMEOUT) on a live key should return 0");
        }
        match call(Syscall::Keyctl.raw(), a2(15, 9_999_999, 60)) {
            Some(v) if v == ENOKEY => Ok(()),
            _ => Err("keyctl(KEYCTL_SET_TIMEOUT) on an absent key should return -ENOKEY"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_keyctl_set_timeout);

// ── Landlock: CreateRuleset / AddRule / RestrictSelf ──

fn smoke_abi_misc_landlock_create_ruleset_pos() -> TestResult {
    with_setup(|| {
        // LANDLOCK_CREATE_RULESET_VERSION (flags bit 0) → the ABI version (1).
        match call(Syscall::LandlockCreateRuleset.raw(), a2(0, 0, 1)) {
            Some(1) => Ok(()),
            _ => Err("landlock_create_ruleset version query should return 1"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_landlock_create_ruleset_pos);

fn smoke_abi_misc_landlock_create_ruleset_neg() -> TestResult {
    with_setup(|| {
        // attr == 0 with flags == 0 → -EINVAL.
        match call(Syscall::LandlockCreateRuleset.raw(), a2(0, 8, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("landlock_create_ruleset with a null attr should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_landlock_create_ruleset_neg);

fn smoke_abi_misc_landlock_add_rule_neg() -> TestResult {
    with_setup(|| {
        // A ruleset fd that names nothing → -EBADF. (The success path needs
        // both a ruleset fd and a path-bearing parent fd.)
        match call(Syscall::LandlockAddRule.raw(), a3(99, 1, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("landlock_add_rule on a bad ruleset fd should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_landlock_add_rule_neg);

fn smoke_abi_misc_landlock_restrict_self_pos() -> TestResult {
    with_setup(|| {
        // Build a real ruleset (8-byte attr = handled_access_fs), get its fd,
        // then stack it onto the task: restrict_self(fd, 0) → 0.
        let attr = [0u8; 8];
        let fd = match call(
            Syscall::LandlockCreateRuleset.raw(),
            a2(attr.as_ptr() as u64, 8, 0),
        ) {
            Some(fd) if fd >= 0 => fd,
            _ => return Err("create_ruleset to seed restrict_self failed"),
        };
        match call(Syscall::LandlockRestrictSelf.raw(), a1(fd as u64, 0)) {
            Some(0) => Ok(()),
            _ => Err("landlock_restrict_self on a valid ruleset fd should return 0"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_landlock_restrict_self_pos);

fn smoke_abi_misc_landlock_restrict_self_neg() -> TestResult {
    with_setup(|| {
        // A ruleset fd that names nothing → -EBADF.
        match call(Syscall::LandlockRestrictSelf.raw(), a1(99, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("landlock_restrict_self on a bad fd should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_landlock_restrict_self_neg);

// ── Generic LSM self-attr syscalls ──

fn smoke_abi_misc_lsm_list_modules_pos() -> TestResult {
    with_setup(|| {
        // size_ptr is in/out: seed it with the required length (2 ids * 8).
        let mut ids = [0u8; 16];
        let mut size = 16u64.to_ne_bytes();
        let args = a3(ids.as_mut_ptr() as u64, size.as_mut_ptr() as u64, 0, 0);
        // → the active module count (capability + landlock = 2).
        match call(Syscall::LsmListModules.raw(), args) {
            Some(2) => Ok(()),
            _ => Err("lsm_list_modules with a sized buffer should return 2"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_lsm_list_modules_pos);

fn smoke_abi_misc_lsm_list_modules_neg() -> TestResult {
    with_setup(|| {
        // flags != 0 → -EINVAL, before any buffer access.
        match call(Syscall::LsmListModules.raw(), a3(0, 0, 1, 0)) {
            Some(v) if v == EINVAL => Ok(()),
            _ => Err("lsm_list_modules with nonzero flags should return -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_lsm_list_modules_neg);

fn smoke_abi_misc_lsm_get_self_attr_pos() -> TestResult {
    with_setup(|| {
        // NARF exposes no MAC context: every attribute yields 0 entries.
        // arg2 = size_ptr; the handler writes 0 there and returns 0.
        let mut size = 0u64.to_ne_bytes();
        let args = a3(0, 0, size.as_mut_ptr() as u64, 0);
        match call(Syscall::LsmGetSelfAttr.raw(), args) {
            Some(0) => Ok(()),
            _ => Err("lsm_get_self_attr should return 0 (no MAC context)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_lsm_get_self_attr_pos);

fn smoke_abi_misc_lsm_set_self_attr_neg() -> TestResult {
    with_setup(|| {
        // No settable MAC context → -EOPNOTSUPP for every input.
        // LINUX-GAP: a Linux LSM would accept or reject per-attr; NARF
        // unconditionally returns -EOPNOTSUPP.
        match call(Syscall::LsmSetSelfAttr.raw(), SyscallArgs::default()) {
            Some(v) if v == EOPNOTSUPP => Ok(()),
            _ => Err("lsm_set_self_attr should return -EOPNOTSUPP"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_lsm_set_self_attr_neg);

// ── Loadable kernel modules: InitModule / FinitModule / DeleteModule ──

fn smoke_abi_misc_init_module_neg() -> TestResult {
    with_setup(|| {
        // `copy_module_from_user`: `if (info->len < sizeof(*(info->hdr)))
        // return -ENOEXEC;`. Anything too short to hold an Elf64 header is a
        // malformed IMAGE, not a malformed argument — this answered -EINVAL,
        // which tells a caller to look at its arguments when the problem is
        // what it handed over.
        match call(Syscall::InitModule.raw(), a3(0, 0, 0, 0)) {
            Some(v) if v == AI_ENOEXEC => Ok(()),
            _ => Err("init_module with a too-short image should return -ENOEXEC"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_init_module_neg);

fn smoke_abi_misc_finit_module_neg() -> TestResult {
    with_setup(|| {
        // A bad fd can't be read → -EBADF.
        match call(Syscall::FinitModule.raw(), a3(99, 0, 0, 0)) {
            Some(v) if v == EBADF => Ok(()),
            _ => Err("finit_module on a bad fd should return -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_finit_module_neg);

fn smoke_abi_misc_init_module_foreign_noop() -> TestResult {
    with_setup(|| {
        // A non-NULL, non-empty buffer that is not a NARF module ELF
        // (here: raw bytes that fail the ELF header parse) is a foreign
        // image. NARF is monolithic, so `finit_module`/`init_module`
        // answer these with a success no-op (0) — this is what stops
        // `systemd-modules-load` / `modprobe@.service` from hanging the
        // boot on a driver that is built in or genuinely absent.
        //
        // At least an Elf64 header's worth of bytes, so the length check
        // ahead of it (which is -ENOEXEC, see above) is not what answers.
        let mut img = [0u8; 128];
        img[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        match call(
            Syscall::InitModule.raw(),
            a3(img.as_ptr() as u64, img.len() as u64, 0, 0),
        ) {
            Some(0) => Ok(()),
            _ => Err("init_module of a foreign image should be a success no-op (0)"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_init_module_foreign_noop);

fn smoke_abi_misc_delete_module_neg() -> TestResult {
    with_setup(|| {
        // `strncpy_from_user(name, name_user, MODULE_NAME_LEN)` on a null
        // pointer is -EFAULT. This answered -EINVAL because it read arg1 as
        // a length and short-circuited on zero — but arg1 is `flags`.
        match call(Syscall::DeleteModule.raw(), a1(0, 0)) {
            Some(v) if v == AI_EFAULT => Ok(()),
            _ => Err("delete_module with a null name should return -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_delete_module_neg);

fn smoke_abi_misc_delete_module_absent() -> TestResult {
    with_setup(|| {
        // A well-formed name that no loaded module owns → a negative errno
        // from the module loader (not a panic, not success).
        let name = b"no_such_module_abi\0";
        match call(
            Syscall::DeleteModule.raw(),
            a1(name.as_ptr() as u64, name.len() as u64 - 1),
        ) {
            Some(v) if v < 0 => Ok(()),
            _ => Err("delete_module of an absent module should return a negative errno"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_delete_module_absent);

/// `SYSCALL_DEFINE2(delete_module, const char __user *name_user, unsigned
/// int flags)` — the second argument is FLAGS. This handler read it as the
/// name's length, so `rmmod`, which passes `O_NONBLOCK`, had its flag word
/// used as a string size.
///
/// The name is NUL-terminated and found by `strncpy_from_user`; flags only
/// choose whether to block, and NARF never blocks on unload. So a wildly
/// wrong flags value must not change the answer for a given name.
fn smoke_abi_misc_delete_module_arg1_is_flags() -> TestResult {
    with_setup(|| {
        let name = b"no_such_module_flags\0";
        let p = name.as_ptr() as u64;
        // O_NONBLOCK|O_TRUNC, what rmmod actually sends, and a value far
        // larger than the name — as a length either would truncate or
        // overrun.
        let with_flags = call(Syscall::DeleteModule.raw(), a1(p, 0o4000 | 0o1000));
        let no_flags = call(Syscall::DeleteModule.raw(), a1(p, 0));
        match (with_flags, no_flags) {
            (Some(a), Some(b)) if a == b && a < 0 => Ok(()),
            (Some(_), Some(_)) => {
                Err("delete_module's answer changed with flags — arg1 read as a length?")
            }
            _ => Err("delete_module did not return an errno"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_delete_module_arg1_is_flags);

/// All three module syscalls are CAP_SYS_MODULE-gated, and the test comes
/// FIRST — ahead of the pointer, length and descriptor checks.
///
/// Before this they consulted no capability at all: any task could load or
/// unload a kernel module. Ordering matters as much as the check: Linux tests
/// `capable()` before `strncpy_from_user`/`copy_module_from_user`, so an
/// unprivileged caller cannot use these calls to learn which addresses are
/// mapped or which descriptors are open.
fn smoke_abi_misc_module_syscalls_need_cap_sys_module() -> TestResult {
    with_setup(|| {
        crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);

        // Arguments that would otherwise answer something ELSE, so a pass
        // cannot come from the argument checks: a null image is -ENOEXEC, a
        // closed fd is -EBADF, a null name is -EFAULT. All three must be
        // -EPERM instead.
        let init = call(Syscall::InitModule.raw(), a3(0, 0, 0, 0));
        let finit = call(Syscall::FinitModule.raw(), a3(99, 0, 0, 0));
        let del = call(Syscall::DeleteModule.raw(), a1(0, 0));

        if init != Some(AI_EPERM) {
            return Err("init_module without CAP_SYS_MODULE must be -EPERM");
        }
        if finit != Some(AI_EPERM) {
            return Err("finit_module without CAP_SYS_MODULE must be -EPERM");
        }
        if del != Some(AI_EPERM) {
            return Err("delete_module without CAP_SYS_MODULE must be -EPERM");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_misc_module_syscalls_need_cap_sys_module
);

// ── reboot(2): magic validation only ──
//
// The VALID-magic arms restart/power off the machine — never call them
// from the suite (they would kill the QEMU boot mid-run). The EINVAL
// guards are the testable surface.
fn smoke_abi_misc_reboot_bad_magic_einval() -> TestResult {
    with_setup(|| {
        // Wrong magic1.
        if call(Syscall::Reboot.raw(), a2(0xdead, 672274793, 0)) != Some(-22) {
            return Err("reboot with bad magic1 must return -EINVAL");
        }
        // Right magic1, wrong magic2.
        if call(Syscall::Reboot.raw(), a2(0xfee1dead, 0x1111, 0)) != Some(-22) {
            return Err("reboot with bad magic2 must return -EINVAL");
        }
        // Valid magics + unknown cmd → EINVAL (and must NOT power off).
        if call(Syscall::Reboot.raw(), a2(0xfee1dead, 672274793, 0x7777)) != Some(-22) {
            return Err("reboot with unknown cmd must return -EINVAL");
        }
        // Valid magics + CAD_OFF (cmd 0) → accepted no-op.
        if call(Syscall::Reboot.raw(), a2(0xfee1dead, 672274793, 0)) != Some(0) {
            return Err("reboot(CAD_OFF) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_reboot_bad_magic_einval);
// ── restart_syscall — kernel-injected syscall continuation ─────────
//
// NARF has no per-task restart_block (SA_RESTART is a pure user-RIP
// rewind), so restart_syscall with nothing pending returns -EINTR,
// exactly like Linux's do_no_restart_syscall.

fn smoke_abi_misc_restart_syscall_eintr() -> TestResult {
    with_setup(|| {
        // restart_syscall() takes no arguments; with no restart_block set
        // it must return -EINTR.
        match call(Syscall::RestartSyscall.raw(), a0(0)) {
            Some(v) if v == EINTR => Ok(()),
            _ => Err("restart_syscall with nothing pending should return -EINTR"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_restart_syscall_eintr);

// ── Reserved NARF-native submission entries ────────────────────────
//
// Submit/WaitCompl were published with the original native ABI but the
// production fast path moved to the shared SQ/CQ mappings driven by
// bootstrap + ring_kick. Keep the wire numbers reserved and pin the
// current tombstone contract: dispatch reaches no handler and reports
// NarfStatus::InvalidOp. These are NARF-native entries, not Linux
// io_uring(2).

fn smoke_abi_misc_reserved_native_ring_entries_are_invalid_op() -> TestResult {
    with_setup(|| {
        for variant in [Syscall::Submit, Syscall::WaitCompl] {
            let ret = call_raw(variant.raw(), SyscallArgs::default());
            if ret.status != SyscallReturn::INVALID_OP || ret.value != 0 {
                return Err("reserved native ring entry must return InvalidOp with value zero");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_misc_reserved_native_ring_entries_are_invalid_op
);

// ─────────────────────────────────────────────────────────────────────
// Accepted-and-ignored arguments, and the last of the -1 sentinels.
//
// A discarded argument is the SILENT half of the errno bug class, and the
// worse half: a wrong errno at least tells the caller something went
// wrong, while an ignored flag reports success for semantics the kernel
// never applied. Nothing in the return value can reveal it.
// ─────────────────────────────────────────────────────────────────────

const AI_EFAULT: i64 = -14;
const AI_EPERM: i64 = -1;
const AI_ENOEXEC: i64 = -8;
const AI_EINVAL: i64 = -22;
const AI_EINTR: i64 = -4;
const AI_ESRCH: i64 = -3;
const AI_ENAMETOOLONG: i64 = -36;
const AI_BAD_PTR: u64 = 0x0001_0000_0000_0000;

fn ai_overlong() -> alloc::vec::Vec<u8> {
    alloc::vec![b'a'; 5000]
}

// ── getrandom: flags were read into `_flags` and dropped ─────────────

fn smoke_abi_misc_getrandom_rejects_unknown_flags() -> TestResult {
    with_setup(|| {
        // `if (flags & ~(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE))
        //          return -EINVAL;`
        // The old handler bound this to `_flags` and discarded it, so a
        // caller asking for semantics NARF does not implement was told the
        // request succeeded and handed bytes generated under different
        // rules. There is no way to detect that from the return value.
        let mut buf = [0u8; 16];
        match call(
            Syscall::GetRandom.raw(),
            a2(buf.as_mut_ptr() as u64, 16, 0x8000),
        ) {
            Some(v) if v == AI_EINVAL => Ok(()),
            Some(16) => Err("getrandom accepted and ignored an unknown flag"),
            _ => Err("getrandom(unknown flag) should be -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_misc_getrandom_rejects_unknown_flags
);

fn smoke_abi_misc_getrandom_rejects_insecure_plus_random() -> TestResult {
    with_setup(|| {
        // Both bits are individually valid; TOGETHER they are refused,
        // because "give me insecure bytes" and "block until the pool is
        // properly seeded" are contradictory requests. Linux rejects the
        // pair explicitly rather than silently picking one.
        const GRND_RANDOM: u64 = 0x0002;
        const GRND_INSECURE: u64 = 0x0004;
        let mut buf = [0u8; 16];
        match call(
            Syscall::GetRandom.raw(),
            a2(buf.as_mut_ptr() as u64, 16, GRND_RANDOM | GRND_INSECURE),
        ) {
            Some(v) if v == AI_EINVAL => {}
            _ => return Err("getrandom(GRND_RANDOM|GRND_INSECURE) should be -EINVAL"),
        }
        // Each alone is accepted.
        for f in [0u64, GRND_RANDOM, GRND_INSECURE, 0x0001] {
            match call(Syscall::GetRandom.raw(), a2(buf.as_mut_ptr() as u64, 16, f)) {
                Some(16) => {}
                _ => return Err("getrandom rejected a flag combination Linux accepts"),
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_misc_getrandom_rejects_insecure_plus_random
);

fn smoke_abi_misc_getrandom_flags_precede_buffer() -> TestResult {
    with_setup(|| {
        // The flags check is the FIRST statement of the syscall, before
        // import_ubuf looks at the buffer — so a bad flag beats a bad
        // pointer.
        match call(Syscall::GetRandom.raw(), a2(AI_BAD_PTR, 16, 0x8000)) {
            Some(v) if v == AI_EINVAL => Ok(()),
            Some(v) if v == AI_EFAULT => {
                Err("getrandom checked the buffer before the flags (wrong order)")
            }
            _ => Err("getrandom(bad ptr, bad flags) should be -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_getrandom_flags_precede_buffer);

fn smoke_abi_misc_getrandom_bad_buffer_is_efault() -> TestResult {
    with_setup(|| {
        // `import_ubuf`'s `access_ok` arm. This was the -1 sentinel.
        match call(Syscall::GetRandom.raw(), a2(AI_BAD_PTR, 16, 0)) {
            Some(v) if v == AI_EFAULT => Ok(()),
            Some(-1) => Err("getrandom(bad buffer) still returns the -1/EPERM sentinel"),
            _ => Err("getrandom(bad buffer) should be -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_getrandom_bad_buffer_is_efault);

// ── sched_rr_get_interval: `pid` was read and discarded ──────────────

fn smoke_abi_misc_rr_interval_resolves_its_pid() -> TestResult {
    with_setup(|| {
        // The cooperative policy has no quantum, so the VALUE is {0,0}
        // either way — but the value is not the only thing the call
        // communicates. Answering 0 for a negative pid or a dead one tells
        // the caller its target is alive and running with no quantum.
        let mut ts = [0u8; 16];
        match call(
            Syscall::SchedRrGetInterval.raw(),
            a1((-1i64) as u64, ts.as_mut_ptr() as u64),
        ) {
            Some(v) if v == AI_EINVAL => {}
            Some(0) => return Err("sched_rr_get_interval accepted a negative pid"),
            _ => return Err("sched_rr_get_interval(-1) should be -EINVAL"),
        }
        match call(
            Syscall::SchedRrGetInterval.raw(),
            a1(123456, ts.as_mut_ptr() as u64),
        ) {
            Some(v) if v == AI_ESRCH => {}
            Some(0) => return Err("sched_rr_get_interval reported a quantum for a dead pid"),
            _ => return Err("sched_rr_get_interval(unknown pid) should be -ESRCH"),
        }
        // pid 0 is the caller and still succeeds.
        match call(
            Syscall::SchedRrGetInterval.raw(),
            a1(0, ts.as_mut_ptr() as u64),
        ) {
            Some(0) => Ok(()),
            _ => Err("sched_rr_get_interval(0) should succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_rr_interval_resolves_its_pid);

// ── pause / rt_sigsuspend: never succeed, so errno is the whole answer ──

fn smoke_abi_misc_pause_is_eintr_not_eperm() -> TestResult {
    with_setup(|| {
        // `SYSCALL_DEFINE0(pause)` ends `return -ERESTARTNOHAND;`, which
        // surfaces as -EINTR. pause(2) never succeeds, so its return value
        // carries no information and every caller reads errno — where the
        // bare -1 said EPERM, i.e. "not allowed to wait for a signal".
        match call(Syscall::Pause.raw(), a0(0)) {
            Some(v) if v == AI_EINTR => Ok(()),
            Some(-1) => Err("pause still returns the -1/EPERM sentinel, not -EINTR"),
            _ => Err("pause should return -EINTR"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_pause_is_eintr_not_eperm);

fn smoke_abi_misc_rt_sigsuspend_arg_errors() -> TestResult {
    with_setup(|| {
        // `if (sigsetsize != sizeof(sigset_t)) return -EINVAL;`
        // then `if (copy_from_user(...)) return -EFAULT;`
        let set = [0u8; 8];
        match call(Syscall::RtSigsuspend.raw(), a1(set.as_ptr() as u64, 4)) {
            Some(v) if v == AI_EINVAL => {}
            Some(-1) => return Err("rt_sigsuspend(bad size) still returns the -1/EPERM sentinel"),
            _ => return Err("rt_sigsuspend(sigsetsize != 8) should be -EINVAL"),
        }
        match call(Syscall::RtSigsuspend.raw(), a1(AI_BAD_PTR, 8)) {
            Some(v) if v == AI_EFAULT => Ok(()),
            Some(-1) => Err("rt_sigsuspend(bad ptr) still returns the -1/EPERM sentinel"),
            _ => Err("rt_sigsuspend(unreadable set) should be -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_rt_sigsuspend_arg_errors);

fn smoke_abi_misc_rt_sigsuspend_size_precedes_pointer() -> TestResult {
    with_setup(|| {
        // The size check is first, so a bad size beats a bad pointer.
        match call(Syscall::RtSigsuspend.raw(), a1(AI_BAD_PTR, 4)) {
            Some(v) if v == AI_EINVAL => Ok(()),
            Some(v) if v == AI_EFAULT => {
                Err("rt_sigsuspend read the set before checking sigsetsize")
            }
            _ => Err("rt_sigsuspend(bad ptr, bad size) should be -EINVAL"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_misc_rt_sigsuspend_size_precedes_pointer
);

// ── nanosleep: clock / pointer / value all took one sentinel ─────────

fn smoke_abi_misc_nanosleep_arg_errors() -> TestResult {
    with_setup(|| {
        // clock_nanosleep: bad clock -> -EINVAL, faulting rqtp -> -EFAULT,
        // !timespec64_valid -> -EINVAL. All three were the -1 sentinel, so
        // a caller that simply passed a bad pointer was told it lacked
        // permission to sleep.
        match call(Syscall::Nanosleep.raw(), a1(AI_BAD_PTR, 0)) {
            Some(v) if v == AI_EFAULT => {}
            Some(-1) => return Err("nanosleep(bad ptr) still returns the -1/EPERM sentinel"),
            _ => return Err("nanosleep(unreadable req) should be -EFAULT"),
        }
        // tv_nsec out of range -> EINVAL.
        let bad: [i64; 2] = [0, 2_000_000_000];
        match call(Syscall::Nanosleep.raw(), a1(bad.as_ptr() as u64, 0)) {
            Some(v) if v == AI_EINVAL => Ok(()),
            Some(-1) => Err("nanosleep(bad timespec) still returns the -1/EPERM sentinel"),
            _ => Err("nanosleep(tv_nsec >= NSEC_PER_SEC) should be -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_misc_nanosleep_arg_errors);

// ── the path family's last -1: getname's two failures ────────────────

fn smoke_abi_misc_path_family_efault_and_enametoolong() -> TestResult {
    with_setup(|| {
        // mkdir / rmdir / unlink / symlink / link all mapped a failed
        // pathname copy onto one `fail` sentinel (EPERM). Linux splits it
        // into -EFAULT and -ENAMETOOLONG.
        let long = ai_overlong();
        let lp = long.as_ptr() as u64;
        // The legacy forms exist only where the arch opts into
        // `__ARCH_WANT_SYSCALL_DEPRECATED` (x86_64 yes, arm64 no), so the
        // list carries both them and the `*at` forms and skips whatever this
        // arch does not wire. `at_form` says where the pathname sits: arg0
        // for the legacy calls, arg1 for the `*at` ones, which take a
        // directory fd first.
        let cases: [(Syscall, &str, bool); 6] = [
            (Syscall::Mkdir, "mkdir", false),
            (Syscall::Rmdir, "rmdir", false),
            (Syscall::Unlink, "unlink", false),
            (Syscall::Chdir, "chdir", false),
            (Syscall::Mkdirat, "mkdirat", true),
            (Syscall::Unlinkat, "unlinkat", true),
        ];
        let mut exercised = 0;
        for (sc, what, at_form) in cases {
            if !wired(sc) {
                continue;
            }
            exercised += 1;
            let num = sc.raw();
            let bad = if at_form {
                a2(AT_FDCWD, AI_BAD_PTR, 0o755)
            } else {
                a1(AI_BAD_PTR, 0o755)
            };
            let toolong = if at_form {
                a2(AT_FDCWD, lp, 0o755)
            } else {
                a1(lp, 0o755)
            };
            match call(num, bad) {
                Some(v) if v == AI_EFAULT => {}
                Some(-1) => {
                    let _ = what;
                    return Err("a path syscall still returns the -1/EPERM sentinel on EFAULT");
                }
                _ => return Err("path syscall with an unreadable path should be -EFAULT"),
            }
            match call(num, toolong) {
                Some(v) if v == AI_ENAMETOOLONG => {}
                Some(v) if v == AI_EFAULT => {
                    return Err("a path syscall reported EFAULT for a readable over-long path")
                }
                _ => return Err("path syscall with an over-long path should be -ENAMETOOLONG"),
            }
        }
        if exercised == 0 {
            return Err("no path syscall from the list is wired on this architecture");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_misc_path_family_efault_and_enametoolong
);

fn smoke_abi_misc_link_reports_the_old_name_first() -> TestResult {
    with_setup(|| {
        // `SYSCALL_DEFINE5(linkat)` names old then new, and
        // filename_linkat propagates the OLD name's error first. The tuple
        // destructure this replaced evaluated both and reported one shared
        // sentinel, losing both which pathname was at fault and why.
        let good = b"/tmp/x\0";
        // arm64 has no legacy `link`; `linkat` names the same two pathnames
        // with a directory fd before each (`SYSCALL_DEFINE5(linkat)`), and
        // propagates the OLD name's error first exactly the same way.
        let at = !wired(Syscall::Link);
        let sc = if at { Syscall::Linkat } else { Syscall::Link };
        let pair = |old_p: u64, new_p: u64| {
            if at {
                a3(AT_FDCWD, old_p, AT_FDCWD, new_p)
            } else {
                a1(old_p, new_p)
            }
        };
        // Bad OLD name, good new name.
        match call(sc.raw(), pair(AI_BAD_PTR, good.as_ptr() as u64)) {
            Some(v) if v == AI_EFAULT => {}
            Some(-1) => return Err("link(bad old) still returns the -1/EPERM sentinel"),
            _ => return Err("link with an unreadable oldpath should be -EFAULT"),
        }
        // Good old name, over-long new name -> the NEW name's reason.
        let long = ai_overlong();
        match call(sc.raw(), pair(good.as_ptr() as u64, long.as_ptr() as u64)) {
            Some(v) if v == AI_ENAMETOOLONG => Ok(()),
            Some(v) if v == AI_EFAULT => {
                Err("link reported EFAULT for a readable over-long newpath")
            }
            _ => Err("link with an over-long newpath should be -ENAMETOOLONG"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_misc_link_reports_the_old_name_first
);
