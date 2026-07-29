//! Linux syscall ABI conformance — `bpf(2)`.
//!
//! Positive *and* negative per command, per `feedback_tests_are_the_value`.
//! The two commands NARF implements get success paths; the ones it does not
//! get `ENOTSUP`, and that is itself a contract worth pinning — a probing
//! loader has to be able to tell "this kernel does not do that" from "you
//! passed nonsense", which is why the unimplemented arms are not `EINVAL`.

#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// `enum bpf_cmd`, from include/uapi/linux/bpf.h.
const BPF_MAP_CREATE: u64 = 0;
const BPF_PROG_LOAD: u64 = 5;
const BPF_OBJ_PIN: u64 = 6;
const BPF_PROG_TEST_RUN: u64 = 10;
const BPF_BTF_LOAD: u64 = 18;

const EOPNOTSUPP: i64 = -95;

/// `BPF_PROG_TYPE_TRACING`. NARF maps it to `Context::Atomic` — the probe
/// sites are the fentry-shaped hook, and they run with IRQs masked.
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;

/// A `union bpf_attr` big enough for `prog_load` and `test`.
const ATTR_LEN: usize = 128;

fn put_u32(buf: &mut [u8; ATTR_LEN], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8; ATTR_LEN], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn get_u32(buf: &[u8; ATTR_LEN], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// `r0 = <v>; exit` — two slots, encoded by hand so this file stays a pure
/// ABI test and does not depend on the assembler.
fn ret_imm(v: i32) -> [u8; 16] {
    let mut p = [0u8; 16];
    // BPF_ALU64 | BPF_MOV | BPF_K = 0xB7, dst = r0.
    p[0] = 0xB7;
    p[4..8].copy_from_slice(&v.to_le_bytes());
    // BPF_JMP | BPF_EXIT = 0x95.
    p[8] = 0x95;
    p
}

fn load_prog(prog_type: u32, insns: &[u8]) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, 0, prog_type);
    put_u32(&mut attr, 4, (insns.len() / 8) as u32);
    put_u64(&mut attr, 8, insns.as_ptr() as u64);
    // prog_name, a fixed 16-byte NUL-padded field at offset 48.
    attr[48..52].copy_from_slice(b"abit");
    call(
        Syscall::Bpf.raw(),
        a2(BPF_PROG_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

// ── BPF_PROG_LOAD ───────────────────────────────────────────────────

fn smoke_abi_bpf_prog_load_pos() -> TestResult {
    with_setup(|| {
        let insns = ret_imm(7);
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        // Linux always sets close-on-exec on a bpf fd
        // (`bpf_prog_new_fd` passes `O_CLOEXEC`) because a leaked program fd
        // is a leaked capability.
        let flags =
            call(Syscall::Fcntl.raw(), a2(fd as u64, 1 /* F_GETFD */, 0)).ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("bpf prog fd is not close-on-exec");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_pos);

fn smoke_abi_bpf_prog_load_neg() -> TestResult {
    with_setup(|| {
        // Null attr.
        if call(Syscall::Bpf.raw(), a2(BPF_PROG_LOAD, 0, ATTR_LEN as u64)) != Some(EINVAL) {
            return Err("BPF_PROG_LOAD with a null attr did not return EINVAL");
        }
        // Zero size.
        let attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_LOAD, attr.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_LOAD with size 0 did not return EINVAL");
        }
        // Zero instructions.
        if load_prog(BPF_PROG_TYPE_TRACING, &[]) != Some(EINVAL) {
            return Err("BPF_PROG_LOAD with insn_cnt 0 did not return EINVAL");
        }
        // A program with no `exit` runs off the end; the verifier must reject
        // it, and does so before Phase 2 lands because falling off the end is
        // structural.
        let mut no_exit = [0u8; 8];
        no_exit[0] = 0xB7;
        if load_prog(BPF_PROG_TYPE_TRACING, &no_exit) != Some(EINVAL) {
            return Err("BPF_PROG_LOAD accepted a program with no exit");
        }
        // A program type whose attach surface does not exist yet.
        if load_prog(BPF_PROG_TYPE_SOCKET_FILTER, &ret_imm(0)) != Some(EOPNOTSUPP) {
            return Err("an unimplemented prog_type did not return EOPNOTSUPP");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_neg);

// ── BPF_PROG_TEST_RUN ───────────────────────────────────────────────

fn smoke_abi_bpf_prog_test_run_pos() -> TestResult {
    with_setup(|| {
        let insns = ret_imm(0x2A);
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd as u32);
        let r = call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        )
        .ok_or("bpf() not Ok")?;
        if r != 0 {
            return Err("BPF_PROG_TEST_RUN failed on a trivial program");
        }
        // Linux reports the program's return value in `attr.test.retval` and
        // lets the syscall itself succeed.
        if get_u32(&attr, 4) != 0x2A {
            return Err("BPF_PROG_TEST_RUN did not write retval back");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_test_run_pos);

fn smoke_abi_bpf_prog_test_run_ctx() -> TestResult {
    with_setup(|| {
        // `r0 = *(u64 *)(r1 + 8); exit` — read the second context word.
        let mut insns = [0u8; 16];
        // BPF_LDX | BPF_MEM | BPF_DW = 0x79, dst = r0, src = r1, off = 8.
        insns[0] = 0x79;
        insns[1] = 0x10; // dst in the low nibble, src in the high
        insns[2..4].copy_from_slice(&8i16.to_le_bytes());
        insns[8] = 0x95;

        let fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected the context-read program");
        }
        let ctx: [u64; 4] = [11, 0x1234, 0, 0];
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd as u32);
        put_u32(&mut attr, 40, 32); // ctx_size_in
        put_u64(&mut attr, 48, ctx.as_ptr() as u64); // ctx_in
        let r = call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        )
        .ok_or("bpf() not Ok")?;
        if r != 0 {
            return Err("BPF_PROG_TEST_RUN with a context failed");
        }
        if get_u32(&attr, 4) != 0x1234 {
            return Err("program did not read the supplied context word");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_test_run_ctx);

fn smoke_abi_bpf_prog_test_run_neg() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, 4242); // not an open fd
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EBADF)
        {
            return Err("BPF_PROG_TEST_RUN on a closed fd did not return EBADF");
        }

        // An fd that exists but is not a program.
        let mut pipefds = [0u8; 8];
        let _ = call(Syscall::Pipe.raw(), a0(pipefds.as_mut_ptr() as u64));
        let readfd = u32::from_le_bytes([pipefds[0], pipefds[1], pipefds[2], pipefds[3]]);
        put_u32(&mut attr, 0, readfd);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_TEST_RUN on a non-program fd did not return EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_test_run_neg);

// ── the deliberately-absent commands ────────────────────────────────

fn smoke_abi_bpf_unimplemented_cmds() -> TestResult {
    with_setup(|| {
        let attr = [0u8; ATTR_LEN];
        for cmd in [BPF_MAP_CREATE, BPF_OBJ_PIN, BPF_BTF_LOAD, 9999] {
            let r = call(
                Syscall::Bpf.raw(),
                a2(cmd, attr.as_ptr() as u64, ATTR_LEN as u64),
            );
            if r != Some(EOPNOTSUPP) {
                return Err("an unimplemented bpf(2) command did not return EOPNOTSUPP");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_unimplemented_cmds);

// ── privilege ───────────────────────────────────────────────────────

/// `bpf(2)` must refuse an unprivileged caller.
///
/// The original handler "gated" on a `Cap<BpfProgLoad, Grant>` that it minted
/// itself, so the check proved only that nothing had revoked a capability the
/// syscall created a moment earlier. Any process could load and run BPF, which
/// makes the verifier the sole barrier and turns every verifier bug into an
/// unprivileged primitive.
fn smoke_abi_bpf_requires_privilege() -> TestResult {
    with_setup(|| {
        let insns = ret_imm(7);

        // Unprivileged: refused, and refused *before* the attribute block is
        // read — so a bad pointer must still give EPERM, not EFAULT.
        crate::handlers::__test_set_fsids(FAKE_TASK, 1000, 1000);
        if load_prog(BPF_PROG_TYPE_TRACING, &insns) != Some(-1 /* EPERM */) {
            return Err("unprivileged BPF_PROG_LOAD was not refused with EPERM");
        }
        if call(Syscall::Bpf.raw(), a2(BPF_PROG_LOAD, 0, ATTR_LEN as u64)) != Some(-1) {
            return Err("unprivileged bpf() with a null attr did not return EPERM");
        }
        // Every command, not just the implemented ones — otherwise the gate
        // could be added to one arm and quietly missed on the rest.
        for cmd in [BPF_MAP_CREATE, BPF_OBJ_PIN, BPF_BTF_LOAD, BPF_PROG_TEST_RUN] {
            if call(Syscall::Bpf.raw(), a2(cmd, 0, ATTR_LEN as u64)) != Some(-1) {
                return Err("an unprivileged bpf() command was not refused");
            }
        }

        // Privileged: the same call succeeds, so the gate is a privilege check
        // and not a blanket refusal.
        crate::handlers::__test_set_fsids(FAKE_TASK, 0, 0);
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("privileged BPF_PROG_LOAD was refused");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_requires_privilege);
