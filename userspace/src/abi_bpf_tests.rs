//! Linux syscall ABI conformance — `bpf(2)`.
//!
//! Positive *and* negative per command, per `feedback_tests_are_the_value`.
//! The commands NARF implements — `BPF_PROG_LOAD`, `BPF_PROG_TEST_RUN`, and the
//! map family — get success paths; the ones it does not get `ENOTSUP`, and that
//! is itself a contract worth pinning — a probing loader has to be able to tell
//! "this kernel does not do that" from "you passed nonsense", which is why the
//! unimplemented arms are not `EINVAL`.

#![cfg(feature = "linux-compat")]

use crate::abi_test_support::*;

// `enum bpf_cmd`, from include/uapi/linux/bpf.h.
const BPF_MAP_CREATE: u64 = 0;
const BPF_PROG_LOAD: u64 = 5;
const BPF_OBJ_PIN: u64 = 6;
const BPF_OBJ_GET: u64 = 7;
const BPF_PROG_TEST_RUN: u64 = 10;
const BPF_MAP_LOOKUP_AND_DELETE_ELEM: u64 = 21;
const BPF_MAP_FREEZE: u64 = 22;
const BPF_ENABLE_STATS: u64 = 32;
const BPF_PROG_BIND_MAP: u64 = 35;
/// `BPF_PROG_QUERY` — still unimplemented, and the stand-in for `BPF_OBJ_PIN`
/// in the "deliberately absent" list now that pinning has landed.
const BPF_PROG_QUERY: u64 = 16;
const BPF_RAW_TRACEPOINT_OPEN: u64 = 17;
const BPF_BTF_LOAD: u64 = 18;

const EOPNOTSUPP: i64 = -95;

/// Atomic probe program types NARF keeps distinct at attach time.
const BPF_PROG_TYPE_RAW_TRACEPOINT: u32 = 17;
const BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE: u32 = 24;
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
const BPF_PROG_TYPE_XDP: u32 = 6;

/// A `union bpf_attr` big enough for `prog_load` and `test`.
const ATTR_LEN: usize = 160;

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

/// XDP: prove bytes 0..14 against `data_end`, then drop only when byte 12 is
/// `0x11`. Hand-encoded to keep this an ABI test independent of the assembler.
fn xdp_bounded_byte_program() -> [u8; 96] {
    let mut p = [0u8; 96];
    let mut put = |i: usize, code: u8, dst: u8, src: u8, off: i16, imm: i32| {
        let at = i * 8;
        p[at] = code;
        p[at + 1] = (src << 4) | dst;
        p[at + 2..at + 4].copy_from_slice(&off.to_le_bytes());
        p[at + 4..at + 8].copy_from_slice(&imm.to_le_bytes());
    };
    put(0, 0x79, 2, 1, 0, 0); // r2 = ctx[0] (data)
    put(1, 0x79, 3, 1, 8, 0); // r3 = ctx[1] (data_end)
    put(2, 0xbf, 4, 2, 0, 0); // r4 = r2
    put(3, 0x07, 4, 0, 0, 14); // r4 += 14
    put(4, 0x2d, 4, 3, 5, 0); // if r4 > r3 -> pass
    put(5, 0x71, 1, 2, 12, 0); // r1 = *(u8 *)(r2 + 12)
    put(6, 0xb7, 0, 0, 0, 2); // XDP_PASS
    put(7, 0x55, 1, 0, 1, 0x11); // if r1 != 0x11 -> exit
    put(8, 0xb7, 0, 0, 0, 1); // XDP_DROP
    put(9, 0x95, 0, 0, 0, 0);
    put(10, 0xb7, 0, 0, 0, 2); // short frame: XDP_PASS
    put(11, 0x95, 0, 0, 0, 0);
    p
}

fn load_prog(prog_type: u32, insns: &[u8]) -> Option<i64> {
    load_prog_license(prog_type, insns, b"GPL\0")
}

fn load_prog_license(prog_type: u32, insns: &[u8], license: &[u8]) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, 0, prog_type);
    put_u32(&mut attr, 4, (insns.len() / 8) as u32);
    put_u64(&mut attr, 8, insns.as_ptr() as u64);
    put_u64(&mut attr, 16, license.as_ptr() as u64);
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

fn smoke_abi_bpf_prog_load_license_pos() -> TestResult {
    with_setup(|| {
        const GPL_LICENSES: [&[u8]; 6] = [
            b"GPL\0",
            b"GPL v2\0",
            b"GPL and additional rights\0",
            b"Dual BSD/GPL\0",
            b"Dual MIT/GPL\0",
            b"Dual MPL/GPL\0",
        ];
        let insns = ret_imm(1);
        for license in GPL_LICENSES {
            let fd =
                load_prog_license(BPF_PROG_TYPE_TRACING, &insns, license).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_PROG_LOAD rejected a GPL-compatible license");
            }
            let mut info = [0u8; INFO_BUF];
            if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
                return Err("BPF_OBJ_GET_INFO_BY_FD failed for a licensed program");
            }
            if info_u32(&info, PI_GPL_COMPATIBLE) & 1 != 1 {
                return Err("bpf_prog_info did not classify a GPL-compatible license");
            }
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
        }

        for license in [b"MIT\0".as_slice(), b"GPL v3\0", b"gpl\0", b"GPL \0"] {
            let fd =
                load_prog_license(BPF_PROG_TYPE_TRACING, &insns, license).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_PROG_LOAD rejected a non-GPL license");
            }
            let mut info = [0u8; INFO_BUF];
            if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
                return Err("BPF_OBJ_GET_INFO_BY_FD failed for a licensed program");
            }
            if info_u32(&info, PI_GPL_COMPATIBLE) & 1 != 0 {
                return Err("bpf_prog_info accepted a near-miss GPL license");
            }
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
        }

        // Linux forcibly terminates its 128-byte stack buffer after copying
        // at most 127 bytes, so lack of an earlier NUL is not itself an error.
        let unterminated = [b'X'; 127];
        let fd = load_prog_license(BPF_PROG_TYPE_TRACING, &insns, &unterminated)
            .ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a 127-byte unterminated license");
        }
        let mut info = [0u8; INFO_BUF];
        if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0)
            || info_u32(&info, PI_GPL_COMPATIBLE) & 1 != 0
        {
            return Err("unterminated license was not accepted as non-GPL");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_license_pos);

fn smoke_abi_bpf_prog_load_license_neg() -> TestResult {
    with_setup(|| {
        let insns = ret_imm(1);
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, BPF_PROG_TYPE_TRACING);
        put_u32(&mut attr, 4, (insns.len() / 8) as u32);
        put_u64(&mut attr, 8, insns.as_ptr() as u64);

        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EFAULT)
        {
            return Err("BPF_PROG_LOAD with a NULL license did not return EFAULT");
        }
        put_u64(&mut attr, 16, u64::MAX);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EFAULT)
        {
            return Err("BPF_PROG_LOAD with an invalid license did not return EFAULT");
        }

        let license = b"GPL\0";
        put_u64(&mut attr, 16, license.as_ptr() as u64);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_LOAD, attr.as_ptr() as u64, 16),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_LOAD accepted an attr truncated before license");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_license_neg);

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
        if load_prog(BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, &ret_imm(0)) != Some(EOPNOTSUPP) {
            return Err("writable raw tracepoints were accepted without writable ctx support");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_neg);

fn smoke_abi_bpf_prog_load_log_pos() -> TestResult {
    with_setup(|| {
        let license = b"GPL\0";
        // `exit` reads R0 before it has been initialized. This pins that a
        // verifier rejection includes both the variant and instruction index.
        let invalid = [0x95u8, 0, 0, 0, 0, 0, 0, 0];
        let mut log = [0xAAu8; 192];
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, BPF_PROG_TYPE_TRACING);
        put_u32(&mut attr, 4, 1);
        put_u64(&mut attr, 8, invalid.as_ptr() as u64);
        put_u64(&mut attr, 16, license.as_ptr() as u64);
        put_u32(&mut attr, 24, 1); // BPF_LOG_LEVEL1
        put_u32(&mut attr, 28, log.len() as u32);
        put_u64(&mut attr, 32, log.as_mut_ptr() as u64);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_LOAD, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_LOAD did not preserve a verifier rejection");
        }
        let true_size = get_u32(&attr, 140) as usize;
        if true_size == 0 || true_size > log.len() {
            return Err("BPF_PROG_LOAD did not report the verifier log's true size");
        }
        if log[true_size - 1] != 0 {
            return Err("BPF_PROG_LOAD verifier log is not NUL terminated");
        }
        let text = core::str::from_utf8(&log[..true_size - 1])
            .map_err(|_| "BPF_PROG_LOAD verifier log was not UTF-8")?;
        if !text.contains("UninitRegister") || !text.contains("at: 0") {
            return Err("BPF_PROG_LOAD verifier log omitted the rejection location");
        }

        // Successful verification also produces a bounded diagnostic when
        // requested, and still returns the program fd.
        let valid = ret_imm(1);
        let mut success_log = [0u8; 96];
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, BPF_PROG_TYPE_TRACING);
        put_u32(&mut attr, 4, 2);
        put_u64(&mut attr, 8, valid.as_ptr() as u64);
        put_u64(&mut attr, 16, license.as_ptr() as u64);
        put_u32(&mut attr, 24, 1);
        put_u32(&mut attr, 28, success_log.len() as u32);
        put_u64(&mut attr, 32, success_log.as_mut_ptr() as u64);
        let fd = call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_LOAD, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
        )
        .ok_or("bpf() not Ok")?;
        if fd < 0 || !success_log.starts_with(b"verification accepted: 2 instructions\n\0") {
            return Err("successful BPF_PROG_LOAD did not return its verifier log");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_log_pos);

fn smoke_abi_bpf_prog_load_log_neg() -> TestResult {
    with_setup(|| {
        let insns = ret_imm(1);
        let license = b"GPL\0";
        let base = || {
            let mut attr = [0u8; ATTR_LEN];
            put_u32(&mut attr, 0, BPF_PROG_TYPE_TRACING);
            put_u32(&mut attr, 4, 2);
            put_u64(&mut attr, 8, insns.as_ptr() as u64);
            put_u64(&mut attr, 16, license.as_ptr() as u64);
            attr
        };

        let mut log = [0xAAu8; 64];
        let mut attr = base();
        put_u32(&mut attr, 28, log.len() as u32);
        put_u64(&mut attr, 32, log.as_mut_ptr() as u64);
        if bpf(BPF_PROG_LOAD, &attr) != Some(EINVAL) {
            return Err("BPF_PROG_LOAD accepted a log buffer without log_level");
        }
        let mut attr = base();
        put_u32(&mut attr, 24, 16); // outside BPF_LOG_MASK
        if bpf(BPF_PROG_LOAD, &attr) != Some(EINVAL) {
            return Err("BPF_PROG_LOAD accepted an unknown log_level bit");
        }
        let mut attr = base();
        put_u32(&mut attr, 24, 1);
        put_u32(&mut attr, 28, 1);
        put_u64(&mut attr, 32, log.as_mut_ptr() as u64);
        if bpf(BPF_PROG_LOAD, &attr) != Some(-28 /* ENOSPC */) {
            return Err("BPF_PROG_LOAD did not report a truncated verifier log");
        }
        if log[0] != 0 || get_u32(&attr, 140) <= 1 {
            return Err("truncated verifier log did not publish NUL and true size");
        }
        let mut attr = base();
        put_u32(&mut attr, 24, 1);
        put_u32(&mut attr, 28, 64);
        put_u64(&mut attr, 32, u64::MAX);
        if bpf(BPF_PROG_LOAD, &attr) != Some(EFAULT) {
            return Err("BPF_PROG_LOAD with a bad verifier log pointer was not EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_log_neg);

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

fn smoke_abi_bpf_prog_test_run_xdp() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_XDP, &xdp_bounded_byte_program()).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected the bounded XDP program");
        }

        let mut frame = [0u8; 64];
        frame[12] = 0x11;
        let mut output = [0xAAu8; 64];
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd as u32);
        put_u32(&mut attr, 8, frame.len() as u32); // data_size_in
        put_u32(&mut attr, 12, output.len() as u32); // data_size_out
        put_u64(&mut attr, 16, frame.as_ptr() as u64); // data_in
        put_u64(&mut attr, 24, output.as_mut_ptr() as u64); // data_out
        put_u32(&mut attr, 32, 3); // repeat
        let r = call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        )
        .ok_or("bpf() not Ok")?;
        if r != 0 || get_u32(&attr, 4) != 1 {
            return Err("XDP test-run did not report XDP_DROP");
        }
        if get_u32(&attr, 12) != frame.len() as u32 || output != frame {
            return Err("XDP test-run did not copy the packet output");
        }

        // The current XDP contract is read-only, but Linux still reports a
        // truncated data_out prefix and the actual required length.
        let mut short = [0u8; 8];
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd as u32);
        put_u32(&mut attr, 8, frame.len() as u32);
        put_u32(&mut attr, 12, short.len() as u32);
        put_u64(&mut attr, 16, frame.as_ptr() as u64);
        put_u64(&mut attr, 24, short.as_mut_ptr() as u64);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(ENOSPC)
        {
            return Err("short XDP data_out did not return ENOSPC");
        }
        if get_u32(&attr, 12) != frame.len() as u32
            || get_u32(&attr, 4) != 1
            || short != frame[..short.len()]
        {
            return Err("short XDP data_out did not publish result and required size");
        }

        // `ctx_in` must never become a raw native-pointer escape hatch.
        let forged_ctx = [frame.as_ptr() as u64, frame.as_ptr_range().end as u64];
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd as u32);
        put_u32(&mut attr, 8, frame.len() as u32);
        put_u64(&mut attr, 16, frame.as_ptr() as u64);
        put_u32(&mut attr, 40, 16);
        put_u64(&mut attr, 48, forged_ctx.as_ptr() as u64);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("XDP test-run accepted a caller-forged context");
        }

        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd as u32);
        put_u32(&mut attr, 8, 13);
        put_u64(&mut attr, 16, frame.as_ptr() as u64);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("XDP test-run accepted a frame shorter than Ethernet");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_prog_test_run_xdp);

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
        // `BPF_BTF_LOAD` used to be in this list; it is implemented now, and
        // its own conformance group lives in `abi_bpf_btf_tests.rs`. So were
        // `BPF_OBJ_PIN` / `BPF_OBJ_GET`, whose group is at the end of this file,
        // and `BPF_PROG_QUERY`, whose group is below. `BPF_TASK_FD_QUERY` (20)
        // is the remaining introspection gap; an out-of-range command is the
        // catch-all.
        for cmd in [20u64, 9999] {
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

// ── BPF_TASK_FD_QUERY ───────────────────────────────────────────────

const BPF_TASK_FD_QUERY: u64 = 20;

fn task_fd_query_attr(pid: u32, fd: u32) -> [u8; ATTR_LEN] {
    let mut a = [0u8; ATTR_LEN];
    put_u32(&mut a, 0, pid);
    put_u32(&mut a, 4, fd);
    // flags @8, buf_len @12, buf @16 all zero — no name buffer.
    a
}

fn bpf_mut(cmd: u64, attr: &mut [u8; ATTR_LEN]) -> Option<i64> {
    call(
        Syscall::Bpf.raw(),
        a2(cmd, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
    )
}

fn smoke_abi_bpf_task_fd_query_pos() -> TestResult {
    with_setup(|| {
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a program");
        }
        let mut info = [0u8; INFO_BUF];
        if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD failed on the program");
        }
        let want_id = info_u32(&info, PI_ID);

        let ev = open_tracepoint_event().ok_or("could not open a tracepoint event")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, prog_fd as u64),
        ) != Some(0)
        {
            return Err("SET_BPF on the tracepoint event was refused");
        }

        // The query on the perf event fd names the attached program, and reports
        // fd_type TRACEPOINT (1). `pid = 0` means "this task".
        let mut q = task_fd_query_attr(0, ev);
        if bpf_mut(BPF_TASK_FD_QUERY, &mut q) != Some(0) {
            return Err("BPF_TASK_FD_QUERY on an event with a program failed");
        }
        if get_u32(&q, 24) != want_id {
            return Err("BPF_TASK_FD_QUERY returned the wrong program id");
        }
        if get_u32(&q, 28) != 1 {
            return Err("BPF_TASK_FD_QUERY did not report fd_type TRACEPOINT");
        }

        // Detach, and the event no longer carries a program.
        let _ = call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, u64::from(u32::MAX)),
        );
        let mut q = task_fd_query_attr(0, ev);
        if bpf_mut(BPF_TASK_FD_QUERY, &mut q) != Some(EOPNOTSUPP) {
            return Err("query on an event with no program was not ENOTSUP");
        }

        let _ = call(Syscall::Close.raw(), a0(ev as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_task_fd_query_pos);

fn smoke_abi_bpf_task_fd_query_neg() -> TestResult {
    with_setup(|| {
        // An fd that carries no BPF program (a fresh program fd is not a perf
        // event) is ENOTSUP.
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        let mut q = task_fd_query_attr(0, prog_fd as u32);
        if bpf_mut(BPF_TASK_FD_QUERY, &mut q) != Some(EOPNOTSUPP) {
            return Err("BPF_TASK_FD_QUERY on a non-perf fd was not ENOTSUP");
        }
        // A pid that is not this task is a cross-task query NARF does not do.
        let mut q = task_fd_query_attr(0x7fff_0000, prog_fd as u32);
        if bpf_mut(BPF_TASK_FD_QUERY, &mut q) != Some(EOPNOTSUPP) {
            return Err("BPF_TASK_FD_QUERY for another pid was not ENOTSUP");
        }
        // A nonzero flags is nonsense.
        let mut q = task_fd_query_attr(0, prog_fd as u32);
        put_u32(&mut q, 8, 1);
        if bpf_mut(BPF_TASK_FD_QUERY, &mut q) != Some(EINVAL) {
            return Err("BPF_TASK_FD_QUERY with flags did not return EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_task_fd_query_neg);

// ── PERF_EVENT_IOC_SET_BPF ──────────────────────────────────────────

/// `_IOW('$', 8, __u32)`.
const PERF_EVENT_IOC_SET_BPF: u64 = 0x4004_2408;
/// `PERF_TYPE_TRACEPOINT`, the only type NARF wires to its trace events.
const PERF_TYPE_TRACEPOINT_: u32 = 2;
const PERF_TYPE_SOFTWARE_: u32 = 1;

/// A `perf_event_open` of `type_`.
///
/// Uses the real `PerfEventAttr` from `narf-linux-perf-uapi`, not a local
/// re-declaration. A first attempt hand-rolled the struct and every open
/// failed on the `size` field — which is the good outcome, because the bad one
/// is a duplicate ABI struct that happens to be accepted and then diverges
/// silently.
fn open_event_of_type(type_: u32, config: u64) -> Option<u32> {
    let attr = narf_linux_perf_uapi::PerfEventAttr {
        type_,
        size: core::mem::size_of::<narf_linux_perf_uapi::PerfEventAttr>() as u32,
        config,
        sample_period_or_freq: 1,
        sample_type: 1 << 10, // PERF_SAMPLE_RAW
        flags: 1,             // disabled
        ..Default::default()
    };
    match call(
        Syscall::PerfEventOpen.raw(),
        a3(&attr as *const _ as u64, 0, -1i32 as u64, -1i32 as u64),
    ) {
        Some(fd) if fd >= 0 => Some(fd as u32),
        _ => None,
    }
}

fn open_tracepoint_event() -> Option<u32> {
    // A NARF trace-event id; the tracepoint type takes it in `config`.
    open_event_of_type(PERF_TYPE_TRACEPOINT_, 0x5a17)
}

fn smoke_abi_perf_set_bpf_pos() -> TestResult {
    with_setup(|| {
        // `observability/PERF_LINUX_COMPAT_AUDIT.md` recorded this ioctl as
        // returning ENOTTY, with the note that BPF should land only once its
        // capability and safety story existed. This is that arm working.
        let insns = ret_imm(1);
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a filter program");
        }
        let ev = open_tracepoint_event().ok_or("could not open a tracepoint event")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, prog_fd as u64),
        ) != Some(0)
        {
            return Err("SET_BPF on a tracepoint event was refused");
        }
        // Detaching with an all-ones fd is the SET_OUTPUT convention and must
        // work here too, or a program can never be removed.
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, u64::from(u32::MAX)),
        ) != Some(0)
        {
            return Err("detaching the program was refused");
        }
        let _ = call(Syscall::Close.raw(), a0(ev as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_perf_set_bpf_pos);

fn smoke_abi_perf_set_bpf_neg() -> TestResult {
    // The arch-neutral half: fd validation. Split from the event-type gate
    // below because that one needs a *non-tracepoint* perf event to exist, and
    // which software events are admitted differs by architecture — bundling
    // them made this whole test fail on aarch64 for a reason unrelated to what
    // it checks.
    with_setup(|| {
        let insns = ret_imm(1);
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        let ev = open_tracepoint_event().ok_or("could not open a tracepoint event")?;
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, 4095),
        ) != Some(EINVAL)
        {
            return Err("SET_BPF with a bad fd did not return EINVAL");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, ev as u64),
        ) != Some(EINVAL)
        {
            return Err("SET_BPF with a non-program fd did not return EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(ev as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_perf_set_bpf_neg);

/// `SET_BPF` is an entry point into running a BPF program, so it takes the same
/// privilege gate `bpf(2)` does.
///
/// It did not. `bpf(2)` checks euid on every command, but `perf_event_open`
/// takes no credential at all and this ioctl took none either — so a program fd
/// that left its privileged loader, inherited across `fork` (`FD_CLOEXEC` is
/// consumed only on the exec path) or passed deliberately over `SCM_RIGHTS`,
/// let an unprivileged task attach it to a tracepoint it opened and then fire
/// it at will. Each fire runs up to `DEFAULT_FUEL` instructions from the perf
/// drain with IRQs masked and two locks held.
///
/// Both arms are gated, and both are checked here: the *clear* arm matters
/// independently, because without it any holder of the event fd could silently
/// remove a filter a privileged task installed.
fn smoke_abi_perf_set_bpf_requires_privilege() -> TestResult {
    with_setup(|| {
        // Set up privileged, exactly as the legitimate loader would.
        let insns = ret_imm(1);
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a filter program");
        }
        let ev = open_tracepoint_event().ok_or("could not open a tracepoint event")?;

        // Drop privilege. The fds survive — that is the whole point.
        //
        // LINUX-GAP: Linux returns EPERM here — `perf_allow_tracepoint()`
        // (include/linux/perf_event.h) is `-EPERM`, distinct from
        // `perf_allow_cpu()`'s `-EACCES`. NARF reports EACCES, because
        // `sys_ioctl` maps every `FsError::PermissionDenied` to `-13` and
        // `FsError` has no variant that reaches EPERM through that path.
        // Asserted as EACCES rather than left unpinned, so the divergence is a
        // recorded fact and a future `FsError` split flips this one line
        // instead of discovering the gap. The refusal itself — which is the
        // security property — is identical either way.
        crate::handlers::__test_set_fsids(FAKE_TASK, 1000, 1000);
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, prog_fd as u64),
        ) != Some(EACCES)
        {
            return Err("unprivileged SET_BPF was not refused");
        }
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, u64::from(u32::MAX)),
        ) != Some(EACCES)
        {
            return Err("unprivileged SET_BPF clear was not refused");
        }

        // Privileged again: the same calls work, so this is a privilege gate
        // and not a blanket refusal.
        crate::handlers::__test_set_fsids(FAKE_TASK, 0, 0);
        if call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, prog_fd as u64),
        ) != Some(0)
        {
            return Err("privileged SET_BPF was refused");
        }
        let _ = call(
            Syscall::Ioctl.raw(),
            a2(ev as u64, PERF_EVENT_IOC_SET_BPF, u64::from(u32::MAX)),
        );
        let _ = call(Syscall::Close.raw(), a0(ev as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_perf_set_bpf_requires_privilege);

fn smoke_abi_perf_set_bpf_wrong_event_type() -> TestResult {
    // NARF wires only the tracepoint type to its trace events, so attaching to
    // anything else would install a program that could never run — a silently
    // dead filter, worse than a refusal.
    //
    // Needs a non-tracepoint event to exist. `PERF_COUNT_SW_DUMMY` is the one
    // `perf_event.rs:1105` names for sideband use, but admission is
    // arch-dependent, so a failure to open is reported as a Skip with its
    // reason rather than as a failure of the gate under test. Not silently
    // passing: an unopenable event leaves the gate unverified on that arch and
    // the skip says so.
    /// Returned by the closure when no non-tracepoint event can be opened, so
    /// the result becomes a Skip rather than a Pass. A Pass would claim the gate
    /// was verified on an architecture where it was not tested at all.
    const NO_SW_EVENT: &str = "no non-tracepoint perf event is admitted here";

    let outcome = with_setup(|| {
        let insns = ret_imm(1);
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        let Some(sw) = open_event_of_type(PERF_TYPE_SOFTWARE_, 9) else {
            let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
            return Err(NO_SW_EVENT);
        };
        let refused = call(
            Syscall::Ioctl.raw(),
            a2(sw as u64, PERF_EVENT_IOC_SET_BPF, prog_fd as u64),
        ) == Some(EINVAL);
        let _ = call(Syscall::Close.raw(), a0(sw as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        if refused {
            Ok(())
        } else {
            Err("SET_BPF on a non-tracepoint event was not refused")
        }
    });
    match outcome {
        TestResult::Fail(m) if m == NO_SW_EVENT => TestResult::Skip(NO_SW_EVENT),
        other => other,
    }
}
kernel_test_in!("syscall_abi", smoke_abi_perf_set_bpf_wrong_event_type);

// ════════════════════════════════════════════════════════════════════
// The map commands.
//
// Positive *and* negative per command. The errno is the contract here, not
// merely "it failed": a loader distinguishes a full map (`E2BIG`) from a
// missing key (`ENOENT`) from a flag violation (`EEXIST`) and behaves
// differently for each, so a test that only checked `< 0` would let any two of
// them swap places.
// ════════════════════════════════════════════════════════════════════

const BPF_MAP_LOOKUP_ELEM: u64 = 1;
const BPF_MAP_UPDATE_ELEM: u64 = 2;
const BPF_MAP_DELETE_ELEM: u64 = 3;
const BPF_MAP_GET_NEXT_KEY: u64 = 4;

/// `abi_test_support` does not name it; the map family is the only caller.
const E2BIG: i64 = -7;

// `enum bpf_map_type`.
const BPF_MAP_TYPE_UNSPEC: u32 = 0;
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

// `map_create` field offsets.
const MC_MAP_TYPE: usize = 0;
const MC_KEY_SIZE: usize = 4;
const MC_VALUE_SIZE: usize = 8;
const MC_MAX_ENTRIES: usize = 12;
const MC_MAP_FLAGS: usize = 16;

// `map_elem` field offsets.
const ME_MAP_FD: usize = 0;
const ME_KEY: usize = 8;
const ME_VALUE: usize = 16;
const ME_FLAGS: usize = 24;

const BPF_ANY: u64 = 0;
const BPF_NOEXIST: u64 = 1;
const BPF_EXIST: u64 = 2;
const BPF_F_LOCK: u64 = 4;

const BPF_F_NO_PREALLOC: u32 = 1;
const BPF_F_RDONLY: u32 = 1 << 3;
const BPF_F_WRONLY: u32 = 1 << 4;
/// `BPF_F_MMAPABLE` — a flag NARF has no implementation of, so it must be
/// refused rather than silently ignored.
const BPF_F_MMAPABLE: u32 = 1024;

fn create_map_flags(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, MC_MAP_TYPE, map_type);
    put_u32(&mut attr, MC_KEY_SIZE, key_size);
    put_u32(&mut attr, MC_VALUE_SIZE, value_size);
    put_u32(&mut attr, MC_MAX_ENTRIES, max_entries);
    put_u32(&mut attr, MC_MAP_FLAGS, map_flags);
    call(
        Syscall::Bpf.raw(),
        a2(BPF_MAP_CREATE, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

fn create_map(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> Option<i64> {
    create_map_flags(map_type, key_size, value_size, max_entries, 0)
}

/// One element command, with explicit key / value / flags.
fn elem(cmd: u64, fd: i64, key: u64, value: u64, flags: u64) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, ME_MAP_FD, fd as u32);
    put_u64(&mut attr, ME_KEY, key);
    put_u64(&mut attr, ME_VALUE, value);
    put_u64(&mut attr, ME_FLAGS, flags);
    call(
        Syscall::Bpf.raw(),
        a2(cmd, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

/// Freeze one map using the Linux `map_fd`-only attribute shape.
fn freeze_map(fd: i64) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, 0, fd as u32);
    call(
        Syscall::Bpf.raw(),
        a2(BPF_MAP_FREEZE, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

/// Bind a map to a loaded program's lifetime.
fn bind_map(prog_fd: i64, map_fd: i64, flags: u32) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, 0, prog_fd as u32);
    put_u32(&mut attr, 4, map_fd as u32);
    put_u32(&mut attr, 8, flags);
    call(
        Syscall::Bpf.raw(),
        a2(BPF_PROG_BIND_MAP, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

/// Enable one Linux runtime-statistics type and return its lifetime fd.
fn enable_stats(stats_type: u32) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, 0, stats_type);
    call(
        Syscall::Bpf.raw(),
        a2(BPF_ENABLE_STATS, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

// ── BPF_MAP_CREATE ──────────────────────────────────────────────────

fn smoke_abi_bpf_map_create_pos() -> TestResult {
    with_setup(|| {
        for kind in [
            BPF_MAP_TYPE_ARRAY,
            BPF_MAP_TYPE_HASH,
            BPF_MAP_TYPE_PERCPU_ARRAY,
            BPF_MAP_TYPE_PERCPU_HASH,
        ] {
            let fd = create_map(kind, 4, 8, 4).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_MAP_CREATE refused a supported map kind");
            }
            // Linux's `bpf_map_new_fd` passes `O_CLOEXEC`: a leaked map fd is a
            // leaked capability.
            let flags = call(Syscall::Fcntl.raw(), a2(fd as u64, 1 /* F_GETFD */, 0))
                .ok_or("fcntl not Ok")?;
            if flags & 1 == 0 {
                return Err("a bpf map fd is not close-on-exec");
            }
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
        }
        // `BPF_F_NO_PREALLOC` is what libbpf sets for most hash maps. NARF
        // always pre-sizes, so the flag is already satisfied and refusing it
        // would refuse most real programs.
        let fd = create_map_flags(BPF_MAP_TYPE_HASH, 4, 8, 4, BPF_F_NO_PREALLOC)
            .ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE refused BPF_F_NO_PREALLOC");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_create_pos);

fn smoke_abi_bpf_map_create_unsupported_kinds() -> TestResult {
    with_setup(|| {
        // Not "not yet": spec §3.4 makes the map-type zoo an arena + kfunc
        // library rather than kernel map types, so these are permanently
        // absent. `EOPNOTSUPP` rather than `EINVAL` so a probing loader can
        // tell "this kernel does not do that" from "you passed nonsense" —
        // libbpf's feature probes depend on exactly that difference.
        // `BPF_MAP_TYPE_RINGBUF` is NOT here any more — it is implemented (see
        // `smoke_abi_bpf_ringbuf_*`). The rest stay permanently absent.
        for kind in [
            BPF_MAP_TYPE_UNSPEC,
            BPF_MAP_TYPE_PROG_ARRAY,
            BPF_MAP_TYPE_LRU_HASH,
            BPF_MAP_TYPE_LPM_TRIE,
            9999,
        ] {
            if create_map(kind, 4, 8, 4) != Some(EOPNOTSUPP) {
                return Err("an unsupported map type did not return EOPNOTSUPP");
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_create_unsupported_kinds);

fn smoke_abi_bpf_map_create_neg() -> TestResult {
    with_setup(|| {
        if create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 0) != Some(EINVAL) {
            return Err("BPF_MAP_CREATE with max_entries 0 did not return EINVAL");
        }
        if create_map(BPF_MAP_TYPE_ARRAY, 4, 0, 4) != Some(EINVAL) {
            return Err("BPF_MAP_CREATE with value_size 0 did not return EINVAL");
        }
        // An array key *is* its index, so it is exactly 4 bytes
        // (`array_map_alloc_check`).
        if create_map(BPF_MAP_TYPE_ARRAY, 8, 8, 4) != Some(EINVAL) {
            return Err("BPF_MAP_CREATE accepted an 8-byte array key");
        }
        if create_map(BPF_MAP_TYPE_HASH, 0, 8, 4) != Some(EINVAL) {
            return Err("BPF_MAP_CREATE accepted a zero-width hash key");
        }
        // The product of `value_size` and `max_entries` is what gets allocated;
        // both factors here are individually legal.
        if create_map(BPF_MAP_TYPE_ARRAY, 4, 4096, 1 << 20) != Some(E2BIG) {
            return Err("BPF_MAP_CREATE did not return E2BIG for an oversized footprint");
        }
        // A flag with no implementation must be refused, not ignored: a caller
        // that asked for a read-only or mmapable map and got neither would
        // discover it much later.
        if create_map_flags(BPF_MAP_TYPE_ARRAY, 4, 8, 4, BPF_F_MMAPABLE) != Some(EINVAL) {
            return Err("BPF_MAP_CREATE accepted BPF_F_MMAPABLE");
        }
        if call(Syscall::Bpf.raw(), a2(BPF_MAP_CREATE, 0, ATTR_LEN as u64)) != Some(EINVAL) {
            return Err("BPF_MAP_CREATE with a null attr did not return EINVAL");
        }
        // Too short to hold `max_entries`, so there is nothing to validate.
        let attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_MAP_CREATE, attr.as_ptr() as u64, 8),
        ) != Some(EINVAL)
        {
            return Err("BPF_MAP_CREATE with a truncated attr did not return EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_create_neg);

fn smoke_abi_bpf_map_fd_access_modes() -> TestResult {
    with_setup(|| {
        let ro = create_map_flags(BPF_MAP_TYPE_ARRAY, 4, 8, 2, BPF_F_RDONLY)
            .ok_or("read-only BPF_MAP_CREATE was not Ok")?;
        let wo = create_map_flags(BPF_MAP_TYPE_ARRAY, 4, 8, 2, BPF_F_WRONLY)
            .ok_or("write-only BPF_MAP_CREATE was not Ok")?;
        if ro < 0 || wo < 0 {
            return Err("BPF_MAP_CREATE refused an fd access mode");
        }
        if create_map_flags(BPF_MAP_TYPE_ARRAY, 4, 8, 2, BPF_F_RDONLY | BPF_F_WRONLY)
            != Some(EINVAL)
        {
            return Err("BPF_MAP_CREATE accepted both access modes");
        }

        // The mode is part of the file description as well as the bpf(2)
        // permission check, so ordinary F_GETFL must report it.
        const F_GETFL: u64 = 3;
        const O_ACCMODE: i64 = 3;
        if call(Syscall::Fcntl.raw(), a2(ro as u64, F_GETFL, 0)) != Some(0) {
            return Err("F_GETFL did not report O_RDONLY on a read-only map fd");
        }
        if call(Syscall::Fcntl.raw(), a2(wo as u64, F_GETFL, 0)).map(|flags| flags & O_ACCMODE)
            != Some(1)
        {
            return Err("F_GETFL did not report O_WRONLY on a write-only map fd");
        }

        let key = 0u32;
        let value = 0xAABB_CCDD_EEFF_0011u64;
        let kptr = (&key) as *const u32 as u64;
        let vptr = (&value) as *const u64 as u64;
        let mut out = 0u64;
        let out_ptr = (&mut out) as *mut u64 as u64;
        let mut next = u32::MAX;

        if elem(BPF_MAP_LOOKUP_ELEM, ro, kptr, out_ptr, 0) != Some(0)
            || elem(
                BPF_MAP_GET_NEXT_KEY,
                ro,
                0,
                (&mut next) as *mut u32 as u64,
                0,
            ) != Some(0)
        {
            return Err("a read-only map fd refused a read operation");
        }
        if elem(BPF_MAP_UPDATE_ELEM, ro, kptr, vptr, BPF_ANY) != Some(-1)
            || elem(BPF_MAP_DELETE_ELEM, ro, kptr, 0, 0) != Some(-1)
            || freeze_map(ro) != Some(-1)
        {
            return Err("a read-only map fd admitted a write operation");
        }
        // Permission is checked after fd resolution but before user pointers.
        if elem(BPF_MAP_UPDATE_ELEM, ro, 0, 0, BPF_ANY) != Some(-1) {
            return Err("read-only permission did not precede pointer validation");
        }

        if elem(BPF_MAP_UPDATE_ELEM, wo, kptr, vptr, BPF_ANY) != Some(0) {
            return Err("a write-only map fd refused an update");
        }
        if elem(BPF_MAP_LOOKUP_ELEM, wo, kptr, out_ptr, 0) != Some(-1)
            || elem(
                BPF_MAP_GET_NEXT_KEY,
                wo,
                0,
                (&mut next) as *mut u32 as u64,
                0,
            ) != Some(-1)
        {
            return Err("a write-only map fd admitted a read operation");
        }
        if elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, ro, kptr, out_ptr, 0) != Some(-1)
            || elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, wo, kptr, out_ptr, 0) != Some(-1)
        {
            return Err("lookup-and-delete did not require both permissions");
        }

        let keys = [key];
        let mut values = [value];
        if batch(
            BPF_MAP_LOOKUP_BATCH,
            ro,
            0,
            0,
            keys.as_ptr() as u64,
            values.as_mut_ptr() as u64,
            1,
            0,
        )
        .0 != Some(0)
            || batch(
                BPF_MAP_UPDATE_BATCH,
                ro,
                0,
                0,
                keys.as_ptr() as u64,
                values.as_ptr() as u64,
                1,
                BPF_ANY,
            )
            .0 != Some(-1)
            || batch(
                BPF_MAP_LOOKUP_BATCH,
                wo,
                0,
                0,
                keys.as_ptr() as u64,
                values.as_mut_ptr() as u64,
                1,
                0,
            )
            .0 != Some(-1)
            || batch(
                BPF_MAP_UPDATE_BATCH,
                wo,
                0,
                0,
                keys.as_ptr() as u64,
                values.as_ptr() as u64,
                1,
                BPF_ANY,
            )
            .0 != Some(0)
        {
            return Err("batch operations did not enforce their read/write direction");
        }
        if batch(
            BPF_MAP_LOOKUP_AND_DELETE_BATCH,
            ro,
            0,
            0,
            keys.as_ptr() as u64,
            values.as_mut_ptr() as u64,
            1,
            0,
        )
        .0 != Some(-1)
            || batch(
                BPF_MAP_LOOKUP_AND_DELETE_BATCH,
                wo,
                0,
                0,
                keys.as_ptr() as u64,
                values.as_mut_ptr() as u64,
                1,
                0,
            )
            .0 != Some(-1)
        {
            return Err("lookup-and-delete batch did not require both permissions");
        }

        let _ = call(Syscall::Close.raw(), a0(ro as u64));
        let _ = call(Syscall::Close.raw(), a0(wo as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_map_fd_access_modes);

// ── array element commands ──────────────────────────────────────────

fn smoke_abi_bpf_map_array_elem_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let key: u32 = 2;
        let mut value: u64 = 0xDEAD_BEEF_CAFE_F00D;
        // Every array slot exists from creation, so lookup succeeds before any
        // update and reads zero.
        let mut read: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            (&key) as *const u32 as u64,
            (&mut read) as *mut u64 as u64,
            0,
        ) != Some(0)
        {
            return Err("BPF_MAP_LOOKUP_ELEM on a fresh array slot failed");
        }
        if read != 0 {
            return Err("a fresh array slot did not read as zero");
        }
        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&key) as *const u32 as u64,
            (&mut value) as *mut u64 as u64,
            BPF_ANY,
        ) != Some(0)
        {
            return Err("BPF_MAP_UPDATE_ELEM failed");
        }
        read = 0;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            (&key) as *const u32 as u64,
            (&mut read) as *mut u64 as u64,
            0,
        ) != Some(0)
        {
            return Err("BPF_MAP_LOOKUP_ELEM after an update failed");
        }
        if read != 0xDEAD_BEEF_CAFE_F00D {
            return Err("BPF_MAP_LOOKUP_ELEM returned the wrong value");
        }
        // The neighbouring slot must be untouched: the value is copied by width
        // from a userspace pointer, so an off-by-one lands on the next entry.
        let neighbour: u32 = 3;
        read = 1;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            (&neighbour) as *const u32 as u64,
            (&mut read) as *mut u64 as u64,
            0,
        ) != Some(0)
        {
            return Err("BPF_MAP_LOOKUP_ELEM on the neighbour failed");
        }
        if read != 0 {
            return Err("an update reached the neighbouring array slot");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_array_elem_pos);

fn smoke_abi_bpf_map_array_elem_neg() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let mut value: u64 = 1;
        let vptr = (&mut value) as *mut u64 as u64;
        let past: u32 = 4;
        let pptr = (&past) as *const u32 as u64;
        let zero: u32 = 0;
        let zptr = (&zero) as *const u32 as u64;

        // A key past `max_entries` is a *missing* key on lookup and an
        // oversized one on update. `array_map_lookup_elem` returns NULL ⇒
        // ENOENT; `array_map_update_elem` returns -E2BIG.
        if elem(BPF_MAP_LOOKUP_ELEM, fd, pptr, vptr, 0) != Some(ENOENT) {
            return Err("lookup past max_entries did not return ENOENT");
        }
        if elem(BPF_MAP_UPDATE_ELEM, fd, pptr, vptr, BPF_ANY) != Some(E2BIG) {
            return Err("update past max_entries did not return E2BIG");
        }
        // Every array slot already exists, so "create only" can never succeed.
        if elem(BPF_MAP_UPDATE_ELEM, fd, zptr, vptr, BPF_NOEXIST) != Some(EEXIST) {
            return Err("array update with BPF_NOEXIST did not return EEXIST");
        }
        // ...and "overwrite only" always can.
        if elem(BPF_MAP_UPDATE_ELEM, fd, zptr, vptr, BPF_EXIST) != Some(0) {
            return Err("array update with BPF_EXIST was refused");
        }
        // An array slot cannot stop existing: `array_map_delete_elem` is
        // -EINVAL, not -ENOENT.
        if elem(BPF_MAP_DELETE_ELEM, fd, zptr, 0, 0) != Some(EINVAL) {
            return Err("array delete did not return EINVAL");
        }
        // No NARF map value can carry a `bpf_spin_lock` — there is no BTF to
        // say where one would live — so `BPF_F_LOCK` is EINVAL, the same errno
        // Linux gives for a map with no lock field.
        if elem(BPF_MAP_UPDATE_ELEM, fd, zptr, vptr, BPF_F_LOCK) != Some(EINVAL) {
            return Err("BPF_F_LOCK was not rejected");
        }
        if elem(BPF_MAP_UPDATE_ELEM, fd, zptr, vptr, BPF_NOEXIST | BPF_EXIST) != Some(EINVAL) {
            return Err("a nonsense flag word was not rejected");
        }
        // A NULL key is a fault, exactly as `copy_from_user` makes it on Linux.
        if elem(BPF_MAP_LOOKUP_ELEM, fd, 0, vptr, 0) != Some(EFAULT) {
            return Err("lookup with a null key did not return EFAULT");
        }
        if elem(BPF_MAP_LOOKUP_ELEM, fd, zptr, 0, 0) != Some(EFAULT) {
            return Err("lookup with a null value pointer did not return EFAULT");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        // The fd is gone, so the map is not reachable through it any more.
        if elem(BPF_MAP_LOOKUP_ELEM, fd, zptr, vptr, 0) != Some(EBADF) {
            return Err("an element command on a closed fd did not return EBADF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_array_elem_neg);

fn smoke_abi_bpf_map_elem_on_a_non_map_fd() -> TestResult {
    with_setup(|| {
        // A *program* fd is the interesting wrong fd: it is a bpf object, it
        // downcasts through the same `as_any` hook, and confusing the two would
        // be a type confusion rather than a missing check.
        let insns = ret_imm(1);
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        let key: u32 = 0;
        let mut value: u64 = 0;
        for cmd in [
            BPF_MAP_LOOKUP_ELEM,
            BPF_MAP_UPDATE_ELEM,
            BPF_MAP_DELETE_ELEM,
            BPF_MAP_GET_NEXT_KEY,
            BPF_MAP_LOOKUP_AND_DELETE_ELEM,
        ] {
            if elem(
                cmd,
                prog_fd,
                (&key) as *const u32 as u64,
                (&mut value) as *mut u64 as u64,
                0,
            ) != Some(EINVAL)
            {
                return Err("an element command on a program fd did not return EINVAL");
            }
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_elem_on_a_non_map_fd);

// ── hash element commands ───────────────────────────────────────────

fn smoke_abi_bpf_map_hash_elem_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 2).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let key: u32 = 77;
        let kptr = (&key) as *const u32 as u64;
        let mut value: u64 = 0x1234_5678;
        let vptr = (&mut value) as *mut u64 as u64;

        // Absent until created — unlike an array.
        if elem(BPF_MAP_LOOKUP_ELEM, fd, kptr, vptr, 0) != Some(ENOENT) {
            return Err("lookup of an absent hash key did not return ENOENT");
        }
        if elem(BPF_MAP_UPDATE_ELEM, fd, kptr, vptr, BPF_NOEXIST) != Some(0) {
            return Err("hash update with BPF_NOEXIST on an absent key failed");
        }
        let mut read: u64 = 0;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            kptr,
            (&mut read) as *mut u64 as u64,
            0,
        ) != Some(0)
        {
            return Err("hash lookup after create failed");
        }
        if read != 0x1234_5678 {
            return Err("hash lookup returned the wrong value");
        }
        if elem(BPF_MAP_DELETE_ELEM, fd, kptr, 0, 0) != Some(0) {
            return Err("hash delete failed");
        }
        if elem(BPF_MAP_LOOKUP_ELEM, fd, kptr, vptr, 0) != Some(ENOENT) {
            return Err("a deleted hash key is still present");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_hash_elem_pos);

fn smoke_abi_bpf_map_hash_elem_neg() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 2).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let mut value: u64 = 5;
        let vptr = (&mut value) as *mut u64 as u64;
        let k0: u32 = 10;
        let k1: u32 = 11;
        let k2: u32 = 12;

        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&k0) as *const u32 as u64,
            vptr,
            BPF_EXIST,
        ) != Some(ENOENT)
        {
            return Err("hash update with BPF_EXIST on an absent key did not return ENOENT");
        }
        if elem(BPF_MAP_DELETE_ELEM, fd, (&k0) as *const u32 as u64, 0, 0) != Some(ENOENT) {
            return Err("hash delete of an absent key did not return ENOENT");
        }
        // Fill the two slots, then ask for a third.
        for k in [&k0, &k1] {
            if elem(
                BPF_MAP_UPDATE_ELEM,
                fd,
                k as *const u32 as u64,
                vptr,
                BPF_ANY,
            ) != Some(0)
            {
                return Err("hash update failed while filling the map");
            }
        }
        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&k2) as *const u32 as u64,
            vptr,
            BPF_ANY,
        ) != Some(E2BIG)
        {
            return Err("insertion into a full hash did not return E2BIG");
        }
        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&k0) as *const u32 as u64,
            vptr,
            BPF_NOEXIST,
        ) != Some(EEXIST)
        {
            return Err("hash update with BPF_NOEXIST on a present key did not return EEXIST");
        }
        // Deleting frees the node, so the third key now fits — capacity is
        // reclaimed rather than leaked.
        if elem(BPF_MAP_DELETE_ELEM, fd, (&k0) as *const u32 as u64, 0, 0) != Some(0) {
            return Err("hash delete failed");
        }
        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&k2) as *const u32 as u64,
            vptr,
            BPF_ANY,
        ) != Some(0)
        {
            return Err("a deleted node's capacity was not reclaimed");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_hash_elem_neg);

// ── BPF_MAP_LOOKUP_AND_DELETE_ELEM ─────────────────────────────────

fn smoke_abi_bpf_map_lookup_and_delete_elem_pos() -> TestResult {
    with_setup(|| {
        for kind in [BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_HASH] {
            let fd = create_map(kind, 4, 8, 4).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_MAP_CREATE failed");
            }
            let key: u32 = kind;
            let cpus = if kind == BPF_MAP_TYPE_PERCPU_HASH {
                narf_lib::smp::cpu_count().max(1) as usize
            } else {
                1
            };
            let values: alloc::vec::Vec<u64> = (0..cpus)
                .map(|cpu| 0x1122_0000_0000_0000 | cpu as u64)
                .collect();
            if elem(
                BPF_MAP_UPDATE_ELEM,
                fd,
                (&key) as *const u32 as u64,
                values.as_ptr() as u64,
                BPF_ANY,
            ) != Some(0)
            {
                return Err("seed update failed");
            }
            let mut out = alloc::vec![0u64; cpus];
            if elem(
                BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                fd,
                (&key) as *const u32 as u64,
                out.as_mut_ptr() as u64,
                0,
            ) != Some(0)
            {
                return Err("BPF_MAP_LOOKUP_AND_DELETE_ELEM failed");
            }
            if out != values {
                return Err("lookup-and-delete returned the wrong syscall-width value");
            }
            if elem(
                BPF_MAP_LOOKUP_ELEM,
                fd,
                (&key) as *const u32 as u64,
                out.as_mut_ptr() as u64,
                0,
            ) != Some(ENOENT)
            {
                return Err("lookup-and-delete left the key live");
            }
            if elem(
                BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                fd,
                (&key) as *const u32 as u64,
                out.as_mut_ptr() as u64,
                0,
            ) != Some(ENOENT)
            {
                return Err("lookup-and-delete of an absent key was not ENOENT");
            }
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_map_lookup_and_delete_elem_pos);

fn smoke_abi_bpf_map_lookup_and_delete_elem_neg() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 4).ok_or("bpf() not Ok")?;
        let array_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok_or("bpf() not Ok")?;
        if fd < 0 || array_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let key = 9u32;
        let value = 0x8877_6655_4433_2211u64;
        let kptr = (&key) as *const u32 as u64;
        let vptr = (&value) as *const u64 as u64;

        if elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, array_fd, kptr, vptr, 0) != Some(EOPNOTSUPP) {
            return Err("lookup-and-delete on an Array was not EOPNOTSUPP");
        }
        if elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, fd, kptr, vptr, BPF_F_LOCK) != Some(EINVAL)
            || elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, fd, kptr, vptr, 8) != Some(EINVAL)
        {
            return Err("lookup-and-delete accepted unsupported flags");
        }
        if elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, -1, kptr, vptr, 8) != Some(EINVAL) {
            return Err("lookup-and-delete resolved the fd before validating flags");
        }
        if elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, fd, 0, vptr, 0) != Some(EFAULT) {
            return Err("lookup-and-delete accepted a null key");
        }
        // The output pointer is not touched until a key has been found and
        // consumed, so an absent key wins over the pointer fault.
        if elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, fd, kptr, 0, 0) != Some(ENOENT) {
            return Err("absent lookup-and-delete touched its output pointer");
        }

        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, ME_MAP_FD, fd as u32);
        put_u64(&mut attr, ME_KEY, kptr);
        put_u64(&mut attr, ME_VALUE, vptr);
        // Linux zero-extends short attrs. Omitting the flags field is valid;
        // this key is absent, so the operation reaches the map and says so.
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                attr.as_ptr() as u64,
                (ME_VALUE + 8) as u64,
            ),
        ) != Some(ENOENT)
        {
            return Err("lookup-and-delete did not zero-extend an omitted flags field");
        }
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                attr.as_ptr() as u64,
                (ME_VALUE + 7) as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("lookup-and-delete accepted a truncated attr");
        }
        attr[ME_FLAGS + 8] = 1;
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_MAP_LOOKUP_AND_DELETE_ELEM,
                attr.as_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("lookup-and-delete accepted a non-zero attr tail");
        }

        // Linux removes the element before copying it to userspace. Preserve
        // that ordering: an output EFAULT consumes the key without returning
        // its value.
        if elem(BPF_MAP_UPDATE_ELEM, fd, kptr, vptr, BPF_ANY) != Some(0) {
            return Err("seed update before output fault failed");
        }
        if elem(BPF_MAP_LOOKUP_AND_DELETE_ELEM, fd, kptr, 0, 0) != Some(EFAULT) {
            return Err("bad lookup-and-delete output pointer was not EFAULT");
        }
        let mut out = 0u64;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            kptr,
            (&mut out) as *mut u64 as u64,
            0,
        ) != Some(ENOENT)
        {
            return Err("output EFAULT did not consume the hash entry");
        }

        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        let _ = call(Syscall::Close.raw(), a0(array_fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_map_lookup_and_delete_elem_neg);

// ── BPF_MAP_FREEZE ─────────────────────────────────────────────────

fn smoke_abi_bpf_map_freeze_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 4).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let key: u32 = 7;
        let value: u64 = 0x1122_3344_5566_7788;
        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&key) as *const u32 as u64,
            (&value) as *const u64 as u64,
            BPF_ANY,
        ) != Some(0)
        {
            return Err("seed update failed before freeze");
        }
        if freeze_map(fd) != Some(0) {
            return Err("BPF_MAP_FREEZE failed on a keyed map");
        }
        if freeze_map(fd) != Some(EBUSY) {
            return Err("a repeated BPF_MAP_FREEZE was not EBUSY");
        }

        // Reads survive, and the value present at freeze time is unchanged.
        let mut read = 0u64;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            (&key) as *const u32 as u64,
            (&mut read) as *mut u64 as u64,
            0,
        ) != Some(0)
            || read != value
        {
            return Err("lookup on a frozen map failed or returned the wrong value");
        }

        // Every syscall mutation path observes the same object-level bit.
        let replacement = 9u64;
        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&key) as *const u32 as u64,
            (&replacement) as *const u64 as u64,
            BPF_ANY,
        ) != Some(-1 /* EPERM */)
        {
            return Err("single update mutated a frozen map");
        }
        if elem(BPF_MAP_DELETE_ELEM, fd, (&key) as *const u32 as u64, 0, 0)
            != Some(-1 /* EPERM */)
        {
            return Err("single delete mutated a frozen map");
        }
        let mut deleted = 0u64;
        if elem(
            BPF_MAP_LOOKUP_AND_DELETE_ELEM,
            fd,
            (&key) as *const u32 as u64,
            (&mut deleted) as *mut u64 as u64,
            0,
        ) != Some(-1 /* EPERM */)
        {
            return Err("lookup-and-delete mutated a frozen map");
        }
        let keys = [key];
        let values = [replacement];
        if batch(
            BPF_MAP_UPDATE_BATCH,
            fd,
            0,
            0,
            keys.as_ptr() as u64,
            values.as_ptr() as u64,
            1,
            BPF_ANY,
        )
        .0 != Some(-1 /* EPERM */)
        {
            return Err("batch update mutated a frozen map");
        }
        if batch(
            BPF_MAP_DELETE_BATCH,
            fd,
            0,
            0,
            keys.as_ptr() as u64,
            0,
            1,
            0,
        )
        .0 != Some(-1 /* EPERM */)
        {
            return Err("batch delete mutated a frozen map");
        }
        let mut out_key = 0u32;
        let mut out_value = 0u64;
        let mut cursor = 0u32;
        if batch(
            BPF_MAP_LOOKUP_AND_DELETE_BATCH,
            fd,
            0,
            (&mut cursor) as *mut u32 as u64,
            (&mut out_key) as *mut u32 as u64,
            (&mut out_value) as *mut u64 as u64,
            1,
            0,
        )
        .0 != Some(-1 /* EPERM */)
        {
            return Err("lookup-and-delete batch mutated a frozen map");
        }

        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_map_freeze_pos);

fn smoke_abi_bpf_map_freeze_neg() -> TestResult {
    with_setup(|| {
        if freeze_map(4095) != Some(EBADF) {
            return Err("BPF_MAP_FREEZE on an unopened fd was not EBADF");
        }
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(0)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 || freeze_map(prog_fd) != Some(EINVAL) {
            return Err("BPF_MAP_FREEZE on a program fd was not EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));

        // A ring has a writable consumer-page mmap surface that NARF cannot
        // account as an active writer yet, so claiming to freeze it would be
        // false. Refuse that map kind explicitly.
        let ring = create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, 4096).ok_or("bpf() not Ok")?;
        if ring < 0 || freeze_map(ring) != Some(EOPNOTSUPP) {
            return Err("BPF_MAP_FREEZE on a ring buffer was not EOPNOTSUPP");
        }
        let _ = call(Syscall::Close.raw(), a0(ring as u64));

        let mut attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_MAP_FREEZE, attr.as_ptr() as u64, 3),
        ) != Some(EINVAL)
        {
            return Err("BPF_MAP_FREEZE accepted a truncated attr");
        }
        attr[4] = 1;
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_MAP_FREEZE, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("BPF_MAP_FREEZE accepted a non-zero attr tail");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_map_freeze_neg);

// ── BPF_PROG_BIND_MAP ──────────────────────────────────────────────

fn smoke_abi_bpf_prog_bind_map_pos() -> TestResult {
    with_setup(|| {
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(0)).ok_or("bpf() not Ok")?;
        let map_fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 4).ok_or("bpf() not Ok")?;
        if prog_fd < 0 || map_fd < 0 {
            return Err("BPF program or map creation failed");
        }
        let map_id = map_id_of(map_fd)?;

        if bind_map(prog_fd, map_fd, 0) != Some(0) || bind_map(prog_fd, map_fd, 0) != Some(0) {
            return Err("BPF_PROG_BIND_MAP failed or was not idempotent");
        }

        // Explicit bindings participate in bpf_prog_info.map_ids exactly once.
        let mut ids = [0u32; 2];
        let mut info = [0u8; INFO_BUF];
        info[PI_NR_MAP_IDS..PI_NR_MAP_IDS + 4].copy_from_slice(&2u32.to_le_bytes());
        info[PI_MAP_IDS..PI_MAP_IDS + 8].copy_from_slice(&(ids.as_mut_ptr() as u64).to_le_bytes());
        if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0)
            || info_u32(&info, PI_NR_MAP_IDS) != 1
            || ids[0] != map_id
        {
            return Err("program info did not report the bound map exactly once");
        }

        // The program now owns the only strong map reference. Its id remains
        // resolvable after the creating fd closes and disappears when the
        // program's final fd closes.
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        let reopened = fd_by_id(BPF_MAP_GET_FD_BY_ID, map_id).ok_or("bpf() not Ok")?;
        if reopened < 0 {
            return Err("bound map died when its creating fd closed");
        }
        let _ = call(Syscall::Close.raw(), a0(reopened as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        if fd_by_id(BPF_MAP_GET_FD_BY_ID, map_id) != Some(ENOENT) {
            return Err("bound map survived the program's last reference");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_prog_bind_map_pos);

fn smoke_abi_bpf_prog_bind_map_neg() -> TestResult {
    with_setup(|| {
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(0)).ok_or("bpf() not Ok")?;
        let map_fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 4).ok_or("bpf() not Ok")?;
        if prog_fd < 0 || map_fd < 0 {
            return Err("BPF program or map creation failed");
        }

        if bind_map(4095, map_fd, 0) != Some(EBADF) {
            return Err("binding through an unopened program fd was not EBADF");
        }
        if bind_map(map_fd, map_fd, 0) != Some(EINVAL) {
            return Err("binding through a map-as-program fd was not EINVAL");
        }
        if bind_map(prog_fd, 4095, 0) != Some(EBADF) {
            return Err("binding an unopened map fd was not EBADF");
        }
        if bind_map(prog_fd, prog_fd, 0) != Some(EINVAL) {
            return Err("binding a program-as-map fd was not EINVAL");
        }
        if bind_map(prog_fd, map_fd, 1) != Some(EINVAL) {
            return Err("BPF_PROG_BIND_MAP accepted non-zero flags");
        }

        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, prog_fd as u32);
        put_u32(&mut attr, 4, map_fd as u32);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_BIND_MAP, attr.as_ptr() as u64, 11),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_BIND_MAP accepted a truncated attr");
        }
        attr[12] = 1;
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_BIND_MAP, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_BIND_MAP accepted a non-zero attr tail");
        }

        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_prog_bind_map_neg);

// ── BPF_ENABLE_STATS ───────────────────────────────────────────────

fn smoke_abi_bpf_enable_stats_pos() -> TestResult {
    with_setup(|| {
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(0)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        let run = || {
            let mut attr = [0u8; ATTR_LEN];
            put_u32(&mut attr, 0, prog_fd as u32);
            call(
                Syscall::Bpf.raw(),
                a2(BPF_PROG_TEST_RUN, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
            )
        };
        let read_stats = || -> Result<(u64, u64), &'static str> {
            let mut info = [0u8; INFO_BUF];
            if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
                return Err("BPF_OBJ_GET_INFO_BY_FD failed");
            }
            Ok((info_u64(&info, PI_RUN_CNT), info_u64(&info, PI_RUN_TIME_NS)))
        };

        if run() != Some(0) || read_stats()? != (0, 0) {
            return Err("an invocation before enable was accounted");
        }

        let stats_fd = enable_stats(0).ok_or("BPF_ENABLE_STATS was not Ok")?;
        let second = enable_stats(0).ok_or("second BPF_ENABLE_STATS was not Ok")?;
        if stats_fd < 0 || second < 0 {
            return Err("BPF_ENABLE_STATS rejected BPF_STATS_RUN_TIME");
        }
        let flags = call(
            Syscall::Fcntl.raw(),
            a2(stats_fd as u64, 1 /* F_GETFD */, 0),
        )
        .ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("BPF_ENABLE_STATS fd is not close-on-exec");
        }
        let duplicate = call(
            Syscall::Fcntl.raw(),
            a2(stats_fd as u64, 0 /* F_DUPFD */, 0),
        )
        .ok_or("F_DUPFD not Ok")?;
        if duplicate < 0 {
            return Err("could not duplicate the stats fd");
        }

        if run() != Some(0) {
            return Err("BPF_PROG_TEST_RUN failed while stats were enabled");
        }
        let (count1, time1) = read_stats()?;
        if count1 != 1 {
            return Err("enabled runtime stats did not count one invocation");
        }

        // Close both independently-created handles. The duplicate still owns
        // the first file description, so accounting must remain enabled.
        let _ = call(Syscall::Close.raw(), a0(stats_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(second as u64));
        if run() != Some(0) {
            return Err("BPF_PROG_TEST_RUN failed through a duplicated stats fd");
        }
        let (count2, time2) = read_stats()?;
        if count2 != 2 || time2 < time1 || time2 == 0 {
            return Err("duplicated stats fd did not preserve accounting");
        }

        let _ = call(Syscall::Close.raw(), a0(duplicate as u64));
        if run() != Some(0) {
            return Err("BPF_PROG_TEST_RUN failed after stats were disabled");
        }
        if read_stats()? != (count2, time2) {
            return Err("runtime stats changed after the final enable fd closed");
        }

        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_enable_stats_pos);

fn smoke_abi_bpf_prog_info_recursion_misses_pos() -> TestResult {
    with_setup(|| {
        use narf_bpf::mem::BpfStack;

        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }

        let provider = narf_bpf::mem::PerCpuRegion;
        let mut occupied = alloc::vec::Vec::new();
        for _ in 0..narf_memory::bpf_stack::MAX_NEST {
            occupied.push(
                provider
                    .acquire(64)
                    .ok_or("could not occupy every per-CPU nesting level")?,
            );
        }

        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, prog_fd as u32);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EAGAIN)
        {
            return Err("BPF_PROG_TEST_RUN did not report a nesting refusal");
        }

        let mut info = [0u8; INFO_BUF];
        if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD failed after a nesting refusal");
        }
        if info_u64(&info, PI_RECURSION_MISSES) != 1 {
            return Err("bpf_prog_info.recursion_misses did not report the refusal");
        }

        drop(occupied);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
        ) != Some(0)
        {
            return Err("BPF_PROG_TEST_RUN did not recover after releasing stack levels");
        }
        let mut info = [0u8; INFO_BUF];
        if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0)
            || info_u64(&info, PI_RECURSION_MISSES) != 1
        {
            return Err("a successful run changed bpf_prog_info.recursion_misses");
        }

        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_prog_info_recursion_misses_pos);

fn smoke_abi_bpf_enable_stats_neg() -> TestResult {
    with_setup(|| {
        if enable_stats(1) != Some(EINVAL) {
            return Err("BPF_ENABLE_STATS accepted an unknown stats type");
        }
        let mut attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_ENABLE_STATS, attr.as_ptr() as u64, 3),
        ) != Some(EINVAL)
        {
            return Err("BPF_ENABLE_STATS accepted a truncated attr");
        }
        attr[4] = 1;
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_ENABLE_STATS, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("BPF_ENABLE_STATS accepted a non-zero attr tail");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_enable_stats_neg);

// ── BPF_MAP_GET_NEXT_KEY ────────────────────────────────────────────

fn smoke_abi_bpf_map_get_next_key_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 3).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let mut next: u32 = 0xFFFF_FFFF;
        let nptr = (&mut next) as *mut u32 as u64;
        // A NULL key means "start at the first key" — the one element command
        // where NULL is a value rather than a fault.
        if elem(BPF_MAP_GET_NEXT_KEY, fd, 0, nptr, 0) != Some(0) {
            return Err("GET_NEXT_KEY with a null key failed");
        }
        if next != 0 {
            return Err("GET_NEXT_KEY with a null key did not start at 0");
        }
        for (from, want) in [(0u32, 1u32), (1, 2)] {
            next = 0xFFFF_FFFF;
            if elem(
                BPF_MAP_GET_NEXT_KEY,
                fd,
                (&from) as *const u32 as u64,
                nptr,
                0,
            ) != Some(0)
            {
                return Err("GET_NEXT_KEY failed mid-walk");
            }
            if next != want {
                return Err("GET_NEXT_KEY returned the wrong successor");
            }
        }
        // The last index terminates the walk. `ENOENT` is how every
        // `bpf_map_get_next_key` loop knows it is done.
        let last: u32 = 2;
        if elem(
            BPF_MAP_GET_NEXT_KEY,
            fd,
            (&last) as *const u32 as u64,
            nptr,
            0,
        ) != Some(ENOENT)
        {
            return Err("GET_NEXT_KEY past the last index did not return ENOENT");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_get_next_key_pos);

fn smoke_abi_bpf_map_get_next_key_neg() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 2).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let mut next: u32 = 0;
        let nptr = (&mut next) as *mut u32 as u64;
        // An empty map terminates immediately; anything else would hand the
        // caller an uninitialised key.
        if elem(BPF_MAP_GET_NEXT_KEY, fd, 0, nptr, 0) != Some(ENOENT) {
            return Err("GET_NEXT_KEY on an empty hash did not return ENOENT");
        }
        // The output pointer is not optional.
        if elem(BPF_MAP_GET_NEXT_KEY, fd, 0, 0, 0) != Some(EFAULT) {
            return Err("GET_NEXT_KEY with a null next_key did not return EFAULT");
        }
        if elem(BPF_MAP_GET_NEXT_KEY, 4095, 0, nptr, 0) != Some(EBADF) {
            return Err("GET_NEXT_KEY on a bad fd did not return EBADF");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_get_next_key_neg);

// ── BPF_MAP_*_BATCH ──────────────────────────────────────────────────

const BPF_MAP_LOOKUP_BATCH: u64 = 24;
const BPF_MAP_LOOKUP_AND_DELETE_BATCH: u64 = 25;
const BPF_MAP_UPDATE_BATCH: u64 = 26;
const BPF_MAP_DELETE_BATCH: u64 = 27;

// `batch` field offsets. `map_fd` is at 36 here, not 0 as in `map_elem`.
const BA_IN_BATCH: usize = 0;
const BA_OUT_BATCH: usize = 8;
const BA_KEYS: usize = 16;
const BA_VALUES: usize = 24;
const BA_COUNT: usize = 32;
const BA_MAP_FD: usize = 36;
const BA_ELEM_FLAGS: usize = 40;

/// One batch command. `count` is in/out: the buffer's slot count going in, the
/// number the kernel filled coming back — read from the attr the kernel wrote
/// in place. Returns `(syscall_result, count_out)`.
#[allow(clippy::too_many_arguments)]
fn batch(
    cmd: u64,
    fd: i64,
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    elem_flags: u64,
) -> (Option<i64>, u32) {
    let mut attr = [0u8; ATTR_LEN];
    put_u64(&mut attr, BA_IN_BATCH, in_batch);
    put_u64(&mut attr, BA_OUT_BATCH, out_batch);
    put_u64(&mut attr, BA_KEYS, keys);
    put_u64(&mut attr, BA_VALUES, values);
    put_u32(&mut attr, BA_COUNT, count);
    put_u32(&mut attr, BA_MAP_FD, fd as u32);
    put_u64(&mut attr, BA_ELEM_FLAGS, elem_flags);
    let r = call(
        Syscall::Bpf.raw(),
        a2(cmd, attr.as_ptr() as u64, ATTR_LEN as u64),
    );
    let count_out = u32::from_le_bytes([
        attr[BA_COUNT],
        attr[BA_COUNT + 1],
        attr[BA_COUNT + 2],
        attr[BA_COUNT + 3],
    ]);
    (r, count_out)
}

/// Whether the `(key, value)` pairs in `got` are exactly the set in `exp`,
/// order-independent — a batch dump promises every element once, not an order.
fn batch_set_matches(got_k: &[u32], got_v: &[u64], exp_k: &[u32], exp_v: &[u64]) -> bool {
    if got_k.len() != exp_k.len() {
        return false;
    }
    for j in 0..exp_k.len() {
        let mut hits = 0;
        for i in 0..got_k.len() {
            if got_k[i] == exp_k[j] && got_v[i] == exp_v[j] {
                hits += 1;
            }
        }
        if hits != 1 {
            return false;
        }
    }
    true
}

/// Seed a hash map with three `(key, value)` pairs through single updates.
fn seed_three(fd: i64, ks: &[u32; 3], vs: &[u64; 3]) -> Result<(), &'static str> {
    for i in 0..3 {
        if elem(
            BPF_MAP_UPDATE_ELEM,
            fd,
            (&ks[i]) as *const u32 as u64,
            (&vs[i]) as *const u64 as u64,
            BPF_ANY,
        ) != Some(0)
        {
            return Err("seed update failed");
        }
    }
    Ok(())
}

fn smoke_abi_bpf_map_lookup_batch_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 8).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let ks: [u32; 3] = [10, 20, 30];
        let vs: [u64; 3] = [100, 200, 300];
        seed_three(fd, &ks, &vs)?;

        // One-shot dump: ask for more slots than exist. Every pair comes back,
        // and the exhausted walk terminates with ENOENT — the signal libbpf's
        // dump loop stops on — with `count` set to what was filled.
        let mut ok = [0u32; 8];
        let mut ov = [0u64; 8];
        let mut cur = [0u8; 4];
        let (r, n) = batch(
            BPF_MAP_LOOKUP_BATCH,
            fd,
            0,
            cur.as_mut_ptr() as u64,
            ok.as_mut_ptr() as u64,
            ov.as_mut_ptr() as u64,
            8,
            0,
        );
        if r != Some(ENOENT) {
            return Err("an exhausted lookup batch did not return ENOENT");
        }
        if n != 3 {
            return Err("lookup batch filled the wrong count");
        }
        if !batch_set_matches(&ok[..3], &ov[..3], &ks, &vs) {
            return Err("lookup batch returned the wrong (key, value) set");
        }

        // Cursor resume: two elements at a time, feeding out_batch back in as
        // in_batch, must visit every key exactly once across the split.
        let mut seen_k = [0u32; 8];
        let mut seen_v = [0u64; 8];
        let mut total = 0usize;
        let mut cursor = [0u8; 4];
        let mut in_ptr = 0u64;
        for _guard in 0..8 {
            let mut bk = [0u32; 2];
            let mut bv = [0u64; 2];
            let (r, n) = batch(
                BPF_MAP_LOOKUP_BATCH,
                fd,
                in_ptr,
                cursor.as_mut_ptr() as u64,
                bk.as_mut_ptr() as u64,
                bv.as_mut_ptr() as u64,
                2,
                0,
            );
            for i in 0..n as usize {
                seen_k[total] = bk[i];
                seen_v[total] = bv[i];
                total += 1;
            }
            in_ptr = cursor.as_ptr() as u64;
            match r {
                Some(0) => continue,
                Some(x) if x == ENOENT => break,
                _ => return Err("cursor lookup batch returned an unexpected code"),
            }
        }
        if total != 3 {
            return Err("cursor walk visited the wrong number of keys");
        }
        if !batch_set_matches(&seen_k[..3], &seen_v[..3], &ks, &vs) {
            return Err("cursor walk returned the wrong (key, value) set");
        }

        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_lookup_batch_pos);

fn smoke_abi_bpf_map_lookup_and_delete_batch_drains() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 8).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let ks: [u32; 3] = [10, 20, 30];
        let vs: [u64; 3] = [100, 200, 300];
        seed_three(fd, &ks, &vs)?;

        let mut ok = [0u32; 8];
        let mut ov = [0u64; 8];
        let mut cur = [0u8; 4];
        let (r, n) = batch(
            BPF_MAP_LOOKUP_AND_DELETE_BATCH,
            fd,
            0,
            cur.as_mut_ptr() as u64,
            ok.as_mut_ptr() as u64,
            ov.as_mut_ptr() as u64,
            8,
            0,
        );
        if r != Some(ENOENT) {
            return Err("lookup-and-delete batch did not terminate with ENOENT");
        }
        if n != 3 || !batch_set_matches(&ok[..3], &ov[..3], &ks, &vs) {
            return Err("lookup-and-delete batch returned the wrong set");
        }

        // The map is drained: a follow-up dump yields nothing, and single
        // lookups miss.
        let (r2, n2) = batch(
            BPF_MAP_LOOKUP_BATCH,
            fd,
            0,
            cur.as_mut_ptr() as u64,
            ok.as_mut_ptr() as u64,
            ov.as_mut_ptr() as u64,
            8,
            0,
        );
        if r2 != Some(ENOENT) || n2 != 0 {
            return Err("lookup-and-delete batch did not drain the map");
        }
        let mut scratch: u64 = 0;
        for k in &ks {
            if elem(
                BPF_MAP_LOOKUP_ELEM,
                fd,
                k as *const u32 as u64,
                (&mut scratch) as *mut u64 as u64,
                0,
            ) != Some(ENOENT)
            {
                return Err("a drained key is still present");
            }
        }

        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_map_lookup_and_delete_batch_drains
);

fn smoke_abi_bpf_map_update_and_delete_batch_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 8).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let ks: [u32; 3] = [1, 2, 3];
        let vs: [u64; 3] = [11, 22, 33];
        let (r, n) = batch(
            BPF_MAP_UPDATE_BATCH,
            fd,
            0,
            0,
            ks.as_ptr() as u64,
            vs.as_ptr() as u64,
            3,
            BPF_ANY,
        );
        if r != Some(0) || n != 3 {
            return Err("update batch did not insert every element");
        }
        // Each pair is now individually visible.
        for i in 0..3 {
            let mut got: u64 = 0;
            if elem(
                BPF_MAP_LOOKUP_ELEM,
                fd,
                (&ks[i]) as *const u32 as u64,
                (&mut got) as *mut u64 as u64,
                0,
            ) != Some(0)
                || got != vs[i]
            {
                return Err("update batch did not store the right value");
            }
        }

        // Delete two of the three by batch; the third survives.
        let dk: [u32; 2] = [1, 2];
        let (r, n) = batch(BPF_MAP_DELETE_BATCH, fd, 0, 0, dk.as_ptr() as u64, 0, 2, 0);
        if r != Some(0) || n != 2 {
            return Err("delete batch did not remove every named key");
        }
        let mut got: u64 = 0;
        for k in &dk {
            if elem(
                BPF_MAP_LOOKUP_ELEM,
                fd,
                k as *const u32 as u64,
                (&mut got) as *mut u64 as u64,
                0,
            ) != Some(ENOENT)
            {
                return Err("a batch-deleted key is still present");
            }
        }
        let survivor: u32 = 3;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            (&survivor) as *const u32 as u64,
            (&mut got) as *mut u64 as u64,
            0,
        ) != Some(0)
            || got != 33
        {
            return Err("delete batch removed a key it was not given");
        }

        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_update_and_delete_batch_pos);

fn smoke_abi_bpf_map_batch_neg() -> TestResult {
    with_setup(|| {
        // A per-element `BPF_F_LOCK` names spin-locked storage NARF has no
        // implementation of; it must be refused, not silently ignored.
        let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 2).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let mut ok = [0u32; 4];
        let mut ov = [0u64; 4];
        let mut cur = [0u8; 4];
        let (r, _) = batch(
            BPF_MAP_LOOKUP_BATCH,
            fd,
            0,
            cur.as_mut_ptr() as u64,
            ok.as_mut_ptr() as u64,
            ov.as_mut_ptr() as u64,
            4,
            BPF_F_LOCK,
        );
        if r != Some(EINVAL) {
            return Err("lookup batch accepted an unsupported BPF_F_LOCK");
        }

        // Partial progress: the map holds two, so a three-element update stops
        // at the third with E2BIG and reports exactly the two that landed.
        let ks: [u32; 3] = [7, 8, 9];
        let vs: [u64; 3] = [70, 80, 90];
        let (r, n) = batch(
            BPF_MAP_UPDATE_BATCH,
            fd,
            0,
            0,
            ks.as_ptr() as u64,
            vs.as_ptr() as u64,
            3,
            BPF_NOEXIST,
        );
        if r != Some(E2BIG) {
            return Err("an over-capacity update batch did not return E2BIG");
        }
        if n != 2 {
            return Err("update batch did not report its partial progress in count");
        }

        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_batch_neg);

// ── BPF_MAP_TYPE_RINGBUF ─────────────────────────────────────────────

fn smoke_abi_bpf_ringbuf_create_and_reject_elem() -> TestResult {
    with_setup(|| {
        // A page-multiple power of two creates. Key and value widths are zero —
        // a ring buffer has neither.
        let fd = create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, 4096).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE refused a valid ring buffer");
        }
        // The keyed element commands are all EINVAL on a ring buffer, exactly
        // as Linux's ringbuf element ops are — it is reached through mmap and
        // kfuncs, not through the element syscalls.
        let key: u32 = 0;
        let kptr = (&key) as *const u32 as u64;
        let mut val: u64 = 0;
        let vptr = (&mut val) as *mut u64 as u64;
        for cmd in [
            BPF_MAP_LOOKUP_ELEM,
            BPF_MAP_DELETE_ELEM,
            BPF_MAP_GET_NEXT_KEY,
        ] {
            if elem(cmd, fd, kptr, vptr, 0) != Some(EINVAL) {
                return Err("an element command on a ring buffer was not EINVAL");
            }
        }
        if elem(BPF_MAP_UPDATE_ELEM, fd, kptr, vptr, BPF_ANY) != Some(EINVAL) {
            return Err("update on a ring buffer was not EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_ringbuf_create_and_reject_elem);

fn smoke_abi_bpf_ringbuf_create_neg() -> TestResult {
    with_setup(|| {
        // Not a power of two, sub-page, and a non-zero key or value width are
        // each EINVAL; a ring past the footprint cap is E2BIG.
        if create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, 4096 + 8) != Some(EINVAL) {
            return Err("a non-power-of-two ring buffer was accepted");
        }
        if create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, 2048) != Some(EINVAL) {
            return Err("a sub-page ring buffer was accepted");
        }
        if create_map(BPF_MAP_TYPE_RINGBUF, 4, 0, 4096) != Some(EINVAL) {
            return Err("a ring buffer with a key width was accepted");
        }
        if create_map(BPF_MAP_TYPE_RINGBUF, 0, 8, 4096) != Some(EINVAL) {
            return Err("a ring buffer with a value width was accepted");
        }
        if create_map(BPF_MAP_TYPE_RINGBUF, 0, 0, 32 * 1024 * 1024) != Some(E2BIG) {
            return Err("an oversize ring buffer was not E2BIG");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_ringbuf_create_neg);

// ── per-CPU maps through the syscall ────────────────────────────────

fn smoke_abi_bpf_map_percpu_value_width() -> TestResult {
    with_setup(|| {
        // The syscall view of a per-CPU map spans every CPU, so the value
        // buffer is `cpus * round_up(value_size, 8)` bytes.
        //
        // // LINUX-GAP: Linux exposes the CPU count through
        // `sysconf(_SC_NPROCESSORS_CONF)` (i.e.
        // `/sys/devices/system/cpu/possible`), which NARF's sysfs does not
        // carry in a form this harness can read. The successful per-CPU
        // round-trip is therefore covered in-kernel by
        // `smoke_bpf_map_percpu_array_views`, which can ask
        // `narf_lib::smp::cpu_count()` directly. The count is not
        // discoverable from this harness at all, so what is pinned here is
        // that the *element commands still work at
        // all* on a per-CPU map created with `value_size = 8`: the copy is by
        // the map's own width, not the caller's, and a caller that guessed
        // wrong must not corrupt the kernel.
        //
        // A 4 KiB buffer is larger than any plausible `cpus * 8`, so the copy
        // fits whatever the real width is.
        let fd = create_map(BPF_MAP_TYPE_PERCPU_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE refused a per-CPU array");
        }
        let key: u32 = 0;
        let mut buf = [0u8; 4096];
        let r = elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            (&key) as *const u32 as u64,
            buf.as_mut_ptr() as u64,
            0,
        );
        if r != Some(0) {
            return Err("per-CPU array lookup failed");
        }
        // Every CPU's slot is zero on a fresh map.
        if buf.iter().any(|b| *b != 0) {
            return Err("a fresh per-CPU array slot was not zeroed");
        }
        // ...and a key past `max_entries` is still ENOENT.
        let past: u32 = 2;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            fd,
            (&past) as *const u32 as u64,
            buf.as_mut_ptr() as u64,
            0,
        ) != Some(ENOENT)
        {
            return Err("per-CPU array lookup past max_entries did not return ENOENT");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_map_percpu_value_width);

// ── BPF_PROG_LOAD with a map reference ──────────────────────────────

/// `ld_imm64 r1 = map_fd(<fd>); r0 = 0; exit` — four slots.
///
/// Hand-encoded so this file stays a pure ABI test. `LD_IMM64` is
/// `BPF_LD | BPF_IMM | BPF_DW` = 0x18, the register byte is
/// `dst | (src << 4)`, and `src = BPF_PSEUDO_MAP_FD = 1` is what makes `imm` a
/// file descriptor rather than the low half of a constant.
fn ld_map_fd_prog(fd: i64) -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = 0x18;
    p[1] = 0x11;
    p[4..8].copy_from_slice(&(fd as i32).to_le_bytes());
    // Slot 1 of the pair is all zeroes for the map-fd form; a non-zero reserved
    // field there is `MalformedImm64`.
    p[16] = 0xB7; // r0 = 0
    p[24] = 0x95; // exit
    p
}

/// `ld_imm64 r1 = map_by_idx(<index>); r0 = 0; exit`.
fn ld_map_idx_prog(index: i32) -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = 0x18;
    // dst = r1, src = BPF_PSEUDO_MAP_IDX (5).
    p[1] = 0x51;
    p[4..8].copy_from_slice(&index.to_le_bytes());
    p[16] = 0xB7;
    p[24] = 0x95;
    p
}

/// Load an indexed map into r1, put `key` in r2, and call
/// `narf_map_delete(map, key)`. The returned errno becomes the program result.
fn ld_map_idx_delete_prog(index: i32, key: i32) -> [u8; 40] {
    let mut p = [0u8; 40];
    p[0] = 0x18;
    p[1] = 0x51;
    p[4..8].copy_from_slice(&index.to_le_bytes());
    p[16] = 0xB7; // r2 = key
    p[17] = 0x02;
    p[20..24].copy_from_slice(&key.to_le_bytes());
    p[24] = 0x85; // call narf_map_delete
    p[25] = 0x20; // src = BPF_PSEUDO_KFUNC_CALL (2)
    p[28..32].copy_from_slice(&narf_bpf::kfunc::id_for("narf_map_delete").to_le_bytes());
    p[32] = 0x95;
    p
}

const PROG_LOAD_EXT_LEN: usize = 152;
const PL_FD_ARRAY: usize = 120;
const PL_FD_ARRAY_CNT: usize = 148;
const EPROTO: i64 = -71;

/// Load using the extended `prog_load` shape that reaches `fd_array_cnt`.
fn load_prog_fd_array_raw(insns: &[u8], fd_array: u64, fd_array_cnt: u32) -> Option<i64> {
    let mut attr = [0u8; PROG_LOAD_EXT_LEN];
    attr[0..4].copy_from_slice(&BPF_PROG_TYPE_TRACING.to_le_bytes());
    attr[4..8].copy_from_slice(&((insns.len() / 8) as u32).to_le_bytes());
    attr[8..16].copy_from_slice(&(insns.as_ptr() as u64).to_le_bytes());
    attr[16..24].copy_from_slice(&(c"GPL".as_ptr() as u64).to_le_bytes());
    attr[48..52].copy_from_slice(b"fdar");
    attr[PL_FD_ARRAY..PL_FD_ARRAY + 8].copy_from_slice(&fd_array.to_le_bytes());
    attr[PL_FD_ARRAY_CNT..PL_FD_ARRAY_CNT + 4].copy_from_slice(&fd_array_cnt.to_le_bytes());
    call(
        Syscall::Bpf.raw(),
        a2(
            BPF_PROG_LOAD,
            attr.as_ptr() as u64,
            PROG_LOAD_EXT_LEN as u64,
        ),
    )
}

fn load_prog_fd_array(insns: &[u8], fds: &[i32]) -> Option<i64> {
    load_prog_fd_array_raw(insns, fds.as_ptr() as u64, fds.len() as u32)
}

fn smoke_bpf_prog_load_fd_array_maps() -> TestResult {
    with_setup(|| {
        let first = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        let second = create_map(BPF_MAP_TYPE_HASH, 4, 8, 2).ok_or("bpf() not Ok")?;
        if first < 0 || second < 0 {
            return Err("map creation for fd_array failed");
        }
        let first_id = map_id_of(first)?;
        let second_id = map_id_of(second)?;
        let fds = [first as i32, second as i32, first as i32];

        let key = 1u32;
        let value = 0x55AAu64;
        if elem(
            BPF_MAP_UPDATE_ELEM,
            second,
            (&key) as *const u32 as u64,
            (&value) as *const u64 as u64,
            BPF_ANY,
        ) != Some(0)
        {
            return Err("seeding the indexed hash map failed");
        }

        let prog_fd = load_prog_fd_array(&ld_map_idx_delete_prog(1, key as i32), &fds)
            .ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a valid map fd_array");
        }
        {
            let prog = prog_behind_fd(prog_fd).ok_or("program fd did not hold BpfProg")?;
            if prog.map_by_idx(1).map(|map| map.id) != Some(second_id) {
                return Err("BPF_PSEUDO_MAP_IDX resolved the wrong fd_array position");
            }
            if prog.jited_len() == 0 {
                return Err("the map-index program did not exercise the JIT fixup path");
            }
        }
        let mut test_attr = [0u8; ATTR_LEN];
        let mut missing = 0u64;
        put_u32(&mut test_attr, 0, prog_fd as u32);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_PROG_TEST_RUN,
                test_attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(0)
            || get_u32(&test_attr, 4) != 0
            || elem(
                BPF_MAP_LOOKUP_ELEM,
                second,
                (&key) as *const u32 as u64,
                (&mut missing) as *mut u64 as u64,
                0,
            ) != Some(ENOENT)
        {
            return Err("the JIT did not execute against fd_array index 1");
        }

        // Eager binding reports duplicate objects once, in first-seen order.
        let mut ids = [0u32; 4];
        let mut info = [0u8; INFO_BUF];
        put_info_u32(&mut info, PI_NR_MAP_IDS, ids.len() as u32);
        put_info_u64(&mut info, PI_MAP_IDS, ids.as_mut_ptr() as u64);
        if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0)
            || info_u32(&info, PI_NR_MAP_IDS) != 2
            || ids[..2] != [first_id, second_id]
        {
            return Err("fd_array maps were not deduplicated in program info");
        }

        // The legacy count-zero form still supplies indices lazily.
        let legacy = load_prog_fd_array_raw(&ld_map_idx_prog(2), fds.as_ptr() as u64, 0)
            .ok_or("legacy fd_array load not Ok")?;
        if legacy < 0 {
            return Err("legacy count-zero fd_array was rejected");
        }
        {
            let prog = prog_behind_fd(legacy).ok_or("legacy program fd did not hold BpfProg")?;
            if prog.map_by_idx(2).map(|map| map.id) != Some(first_id) {
                return Err("legacy fd_array index resolved the wrong map");
            }
        }
        let _ = call(Syscall::Close.raw(), a0(legacy as u64));

        // Closing the creating map fds leaves both eager bindings alive.
        let _ = call(Syscall::Close.raw(), a0(first as u64));
        let _ = call(Syscall::Close.raw(), a0(second as u64));
        for id in [first_id, second_id] {
            let held = fd_by_id(BPF_MAP_GET_FD_BY_ID, id).ok_or("map id lookup not Ok")?;
            if held < 0 {
                return Err("fd_array map died when its creating fd closed");
            }
            let _ = call(Syscall::Close.raw(), a0(held as u64));
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        if fd_by_id(BPF_MAP_GET_FD_BY_ID, first_id) != Some(ENOENT)
            || fd_by_id(BPF_MAP_GET_FD_BY_ID, second_id) != Some(ENOENT)
        {
            return Err("fd_array maps survived the program's last reference");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_prog_load_fd_array_maps);

fn smoke_bpf_prog_load_fd_array_btf_lifetime() -> TestResult {
    with_setup(|| {
        let blob = minimal_btf();
        let btf_fd = btf_load(&blob).ok_or("BPF_BTF_LOAD not Ok")?;
        if btf_fd < 0 {
            return Err("BPF_BTF_LOAD failed");
        }
        let btf_id = info_u32(&btf_info_of(btf_fd)?, BI_ID);
        let fds = [btf_fd as i32];
        let prog_fd = load_prog_fd_array(&ret_imm(0), &fds).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a BTF fd_array entry");
        }
        let _ = call(Syscall::Close.raw(), a0(btf_fd as u64));
        let held = fd_by_id(BPF_BTF_GET_FD_BY_ID, btf_id).ok_or("BTF id lookup not Ok")?;
        if held < 0 {
            return Err("fd_array BTF died when its creating fd closed");
        }
        let _ = call(Syscall::Close.raw(), a0(held as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        if fd_by_id(BPF_BTF_GET_FD_BY_ID, btf_id) != Some(ENOENT) {
            return Err("fd_array BTF survived the program's last reference");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_prog_load_fd_array_btf_lifetime);

fn smoke_bpf_prog_load_fd_array_neg() -> TestResult {
    with_setup(|| {
        if load_prog_fd_array_raw(&ret_imm(0), 0, 1) != Some(EFAULT) {
            return Err("a non-zero fd_array_cnt with null fd_array was not EFAULT");
        }
        if load_prog_fd_array_raw(&ld_map_idx_prog(0), 0, 0) != Some(EPROTO) {
            return Err("BPF_PSEUDO_MAP_IDX without fd_array was not EPROTO");
        }
        let invalid = [4095i32];
        if load_prog_fd_array(&ret_imm(0), &invalid) != Some(EBADF) {
            return Err("an unopened fd_array entry was not EBADF");
        }
        let mut pipefds = [0u8; 8];
        if call(Syscall::Pipe.raw(), a0(pipefds.as_mut_ptr() as u64)) != Some(0) {
            return Err("pipe setup failed");
        }
        let pipe_fd = i32::from_le_bytes([pipefds[0], pipefds[1], pipefds[2], pipefds[3]]);
        if load_prog_fd_array(&ret_imm(0), &[pipe_fd]) != Some(EINVAL) {
            return Err("a non-map/non-BTF fd_array entry was not EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(pipe_fd as u64));
        let write_fd = i32::from_le_bytes([pipefds[4], pipefds[5], pipefds[6], pipefds[7]]);
        let _ = call(Syscall::Close.raw(), a0(write_fd as u64));

        if load_prog_fd_array_raw(&ret_imm(0), 0, u32::MAX) != Some(EINVAL) {
            return Err("an overflowing fd_array_cnt was not EINVAL");
        }

        // Linux's verifier admits at most 64 distinct used maps. Duplicate
        // descriptors do not consume another slot, but a 65th object does.
        let mut map_fds = alloc::vec::Vec::new();
        for _ in 0..65 {
            let map = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok_or("bpf() not Ok")?;
            if map < 0 {
                for fd in map_fds {
                    let _ = call(Syscall::Close.raw(), a0(fd as u64));
                }
                return Err("map creation for the fd_array limit failed");
            }
            map_fds.push(map);
        }
        let raw_fds: alloc::vec::Vec<i32> = map_fds.iter().map(|fd| *fd as i32).collect();
        let too_many = load_prog_fd_array(&ret_imm(0), &raw_fds);
        for fd in map_fds {
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
        }
        if too_many != Some(E2BIG) {
            if let Some(fd) = too_many.filter(|fd| *fd >= 0) {
                let _ = call(Syscall::Close.raw(), a0(fd as u64));
            }
            return Err("a 65th distinct fd_array map was not E2BIG");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_prog_load_fd_array_neg);

fn smoke_abi_bpf_prog_load_with_a_map_pos() -> TestResult {
    with_setup(|| {
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let prog = ld_map_fd_prog(map_fd);
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &prog).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a program holding a map handle");
        }
        // Closing the map fd must not invalidate the program: it holds an `Arc`,
        // the same shape as Linux's `prog->aux->used_maps`.
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, prog_fd as u32);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(0)
        {
            return Err("a program holding a map handle could not be run after the map fd closed");
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_with_a_map_pos);

fn smoke_abi_bpf_prog_load_with_a_map_neg() -> TestResult {
    with_setup(|| {
        // A map fd that names nothing.
        if load_prog(BPF_PROG_TYPE_TRACING, &ld_map_fd_prog(4095)) != Some(EBADF) {
            return Err("BPF_PROG_LOAD with an unopened map fd did not return EBADF");
        }
        // A fd that names something that is not a map. Using a *program* fd
        // again, because that is the confusion a downcast has to catch.
        let other = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if other < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        if load_prog(BPF_PROG_TYPE_TRACING, &ld_map_fd_prog(other)) != Some(EINVAL) {
            return Err("BPF_PROG_LOAD with a non-map fd did not return EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(other as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_load_with_a_map_neg);

// ════════════════════════════════════════════════════════════════════
// Introspection — `BPF_OBJ_GET_INFO_BY_FD` and the id family.
//
// Three properties carry the weight here and each has its own smoke:
//
//  1. the `info_len` in/out truncation contract, in *both* directions —
//     an older caller must see only the prefix it understands, a newer
//     one must be told how much was filled;
//  2. id lifetime — an id is never reused, a freed object's id is
//     `ENOENT` rather than a dangling handle, and an fd obtained by id
//     holds its own reference;
//  3. the errno vocabulary — `EBADF` for a bad fd, `ENOENT` for an
//     unknown id, `EINVAL` for nonsense, `ENOTSUP` for absent features.
// ════════════════════════════════════════════════════════════════════

const BPF_PROG_GET_NEXT_ID: u64 = 11;
const BPF_MAP_GET_NEXT_ID: u64 = 12;
const BPF_PROG_GET_FD_BY_ID: u64 = 13;
const BPF_MAP_GET_FD_BY_ID: u64 = 14;
const BPF_OBJ_GET_INFO_BY_FD: u64 = 15;
const BPF_LINK_GET_FD_BY_ID: u64 = 30;
const BPF_LINK_GET_NEXT_ID: u64 = 31;

/// `sizeof(struct bpf_prog_info)` and `sizeof(struct bpf_map_info)`, as the
/// handler reports them. Spelled out again rather than imported from
/// `sys_bpf_info.rs`: a test that shared the constant would agree with the
/// implementation by construction and could never catch it drifting from the
/// uapi header.
const PROG_INFO_LEN: usize = 232;
const MAP_INFO_LEN: usize = 88;

/// Big enough for either info struct plus room to sentinel past the end.
const INFO_BUF: usize = 320;

// `struct bpf_prog_info` field offsets.
const PI_TYPE: usize = 0;
const PI_ID: usize = 4;
const PI_TAG: usize = 8;
const PI_JITED_PROG_LEN: usize = 16;
const PI_XLATED_PROG_LEN: usize = 20;
const PI_JITED_PROG_INSNS: usize = 24;
const PI_XLATED_PROG_INSNS: usize = 32;
const PI_LOAD_TIME: usize = 40;
const PI_CREATED_BY_UID: usize = 48;
const PI_NR_MAP_IDS: usize = 52;
const PI_MAP_IDS: usize = 56;
const PI_NAME: usize = 64;
const PI_GPL_COMPATIBLE: usize = 84;
const PI_RUN_TIME_NS: usize = 192;
const PI_RUN_CNT: usize = 200;
const PI_RECURSION_MISSES: usize = 208;

// `struct bpf_map_info` field offsets.
const MI_TYPE: usize = 0;
const MI_ID: usize = 4;
const MI_KEY_SIZE: usize = 8;
const MI_VALUE_SIZE: usize = 12;
const MI_MAX_ENTRIES: usize = 16;
const MI_NAME: usize = 24;

// `struct { … } info` offsets within `union bpf_attr`.
const AI_BPF_FD: usize = 0;
const AI_INFO_LEN: usize = 4;
const AI_INFO: usize = 8;

fn info_u32(buf: &[u8; INFO_BUF], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn info_u64(buf: &[u8; INFO_BUF], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

fn put_info_u64(buf: &mut [u8; INFO_BUF], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `BPF_OBJ_GET_INFO_BY_FD` with a caller-chosen `info_len`.
///
/// Returns the syscall result *and* the `info_len` the kernel wrote back — the
/// second half of the truncation contract, and the half a test that only
/// checked field values would never look at.
fn obj_info(fd: i64, info: &mut [u8; INFO_BUF], info_len: u32) -> (Option<i64>, u32) {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, AI_BPF_FD, fd as u32);
    put_u32(&mut attr, AI_INFO_LEN, info_len);
    put_u64(&mut attr, AI_INFO, info.as_mut_ptr() as u64);
    let r = call(
        Syscall::Bpf.raw(),
        a2(
            BPF_OBJ_GET_INFO_BY_FD,
            attr.as_mut_ptr() as u64,
            ATTR_LEN as u64,
        ),
    );
    (r, get_u32(&attr, AI_INFO_LEN))
}

/// `BPF_*_GET_NEXT_ID`: the syscall result and the id written back.
fn next_id(cmd: u64, start: u32) -> (Option<i64>, u32) {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, 0, start);
    let r = call(
        Syscall::Bpf.raw(),
        a2(cmd, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
    );
    (r, get_u32(&attr, 4))
}

/// `BPF_*_GET_FD_BY_ID`.
fn fd_by_id(cmd: u64, id: u32) -> Option<i64> {
    fd_by_id_flags(cmd, id, 0)
}

fn fd_by_id_flags(cmd: u64, id: u32, flags: u32) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u32(&mut attr, 0, id);
    put_u32(&mut attr, 8, flags);
    call(
        Syscall::Bpf.raw(),
        a2(cmd, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
    )
}

/// The id of the program behind `fd`, read out of its info struct.
fn id_of(fd: i64) -> Result<u32, &'static str> {
    let mut info = [0u8; INFO_BUF];
    let (r, _) = obj_info(fd, &mut info, PROG_INFO_LEN as u32);
    if r != Some(0) {
        return Err("BPF_OBJ_GET_INFO_BY_FD failed on a program fd");
    }
    Ok(info_u32(&info, PI_ID))
}

/// The id of the *map* behind `fd`. Same offset as a program's, but reached
/// through the map struct's length, so this is the call a map caller makes.
fn map_id_of(fd: i64) -> Result<u32, &'static str> {
    let mut info = [0u8; INFO_BUF];
    let (r, _) = obj_info(fd, &mut info, MAP_INFO_LEN as u32);
    if r != Some(0) {
        return Err("BPF_OBJ_GET_INFO_BY_FD failed on a map fd");
    }
    Ok(info_u32(&info, MI_ID))
}

// ── BPF_OBJ_GET_INFO_BY_FD: programs ────────────────────────────────

fn smoke_abi_bpf_obj_get_info_prog_pos() -> TestResult {
    with_setup(|| {
        let insns = ret_imm(7);
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &insns).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let mut info = [0u8; INFO_BUF];
        let (r, back) = obj_info(fd, &mut info, PROG_INFO_LEN as u32);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD on a program fd failed");
        }
        if back != PROG_INFO_LEN as u32 {
            return Err("bpf_prog_info: kernel did not report sizeof(bpf_prog_info) back");
        }
        // `BPF_PROG_TYPE_TRACING` is what this was loaded as, so the round trip
        // has to land back on it — a reported type that will not reload is
        // worse than no type at all.
        if info_u32(&info, PI_TYPE) != BPF_PROG_TYPE_TRACING {
            return Err("bpf_prog_info.type did not round-trip BPF_PROG_TYPE_TRACING");
        }
        if info_u32(&info, PI_ID) == 0 {
            return Err("bpf_prog_info.id is 0 — ids start at 1");
        }
        // First eight bytes of SHA-256 over `ret_imm(7)`, independently
        // generated with Linux's program-tag algorithm. This pins byte order,
        // digest choice, and truncation rather than merely checking non-zero.
        if info[PI_TAG..PI_TAG + 8] != [0x9e, 0xfe, 0x88, 0x73, 0x12, 0x07, 0x41, 0xb3] {
            return Err("bpf_prog_info.tag is not Linux's SHA-256 program tag");
        }
        // NARF does not rewrite instructions, so the xlated length is exactly
        // the loaded image.
        if info_u32(&info, PI_XLATED_PROG_LEN) != insns.len() as u32 {
            return Err("bpf_prog_info.xlated_prog_len is not the loaded image size");
        }
        if &info[PI_NAME..PI_NAME + 4] != b"abit" || info[PI_NAME + 4] != 0 {
            return Err("bpf_prog_info.name is not the NUL-padded load-time name");
        }
        let load_time = info_u64(&info, PI_LOAD_TIME);
        if load_time == 0 {
            return Err("bpf_prog_info.load_time is zero");
        }
        if info_u32(&info, PI_CREATED_BY_UID) != 0 {
            return Err("bpf_prog_info.created_by_uid did not capture the root loader");
        }
        if info_u64(&info, PI_RUN_CNT) != 0 {
            return Err("bpf_prog_info.run_cnt is non-zero for a program never run");
        }
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd as u32);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_TEST_RUN, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
        ) != Some(0)
        {
            return Err("BPF_PROG_TEST_RUN failed");
        }
        // Length fields are input capacities as well as outputs. Start a fresh
        // sizing query rather than accidentally requesting copies to the null
        // pointers from the first query.
        let mut info = [0u8; INFO_BUF];
        let (r, _) = obj_info(fd, &mut info, PROG_INFO_LEN as u32);
        if r != Some(0) {
            return Err("second BPF_OBJ_GET_INFO_BY_FD failed");
        }
        if info_u64(&info, PI_LOAD_TIME) != load_time {
            return Err("bpf_prog_info.load_time changed between queries");
        }
        // A program the JIT declined reports 0; one it compiled reports the
        // emitted byte count. Either is correct — what is not is a non-zero
        // length claimed for something that never got text, so pin the only
        // relation that holds either way.
        let jited = info_u32(&info, PI_JITED_PROG_LEN);
        if jited != 0 && jited < insns.len() as u32 {
            return Err("bpf_prog_info.jited_prog_len is non-zero but implausibly small");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_get_info_prog_pos);

/// Linux removes map fds from the tag input because descriptor numbers are
/// allocation-local. Two otherwise-identical programs must therefore retain
/// one identity even when their maps arrived through different fds.
fn smoke_abi_bpf_obj_get_info_prog_tag_map_fd_pos() -> TestResult {
    with_setup(|| {
        let map_a = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok_or("bpf() not Ok")?;
        let map_b = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok_or("bpf() not Ok")?;
        if map_a < 0 || map_b < 0 || map_a == map_b {
            return Err("BPF_MAP_CREATE did not return two distinct descriptors");
        }
        let prog_a =
            load_prog(BPF_PROG_TYPE_TRACING, &ld_map_fd_prog(map_a)).ok_or("bpf() not Ok")?;
        let prog_b =
            load_prog(BPF_PROG_TYPE_TRACING, &ld_map_fd_prog(map_b)).ok_or("bpf() not Ok")?;
        if prog_a < 0 || prog_b < 0 {
            return Err("BPF_PROG_LOAD rejected a map-fd program");
        }

        let mut info_a = [0u8; INFO_BUF];
        let mut info_b = [0u8; INFO_BUF];
        if obj_info(prog_a, &mut info_a, PROG_INFO_LEN as u32).0 != Some(0)
            || obj_info(prog_b, &mut info_b, PROG_INFO_LEN as u32).0 != Some(0)
        {
            return Err("BPF_OBJ_GET_INFO_BY_FD failed for a map-fd program");
        }
        let expected = [0x0b, 0xd0, 0x16, 0x86, 0x76, 0xc7, 0xc7, 0x79];
        if info_a[PI_TAG..PI_TAG + 8] != expected || info_b[PI_TAG..PI_TAG + 8] != expected {
            return Err("program tag retained an unstable map descriptor");
        }

        let _ = call(Syscall::Close.raw(), a0(prog_a as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_b as u64));
        let _ = call(Syscall::Close.raw(), a0(map_a as u64));
        let _ = call(Syscall::Close.raw(), a0(map_b as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_obj_get_info_prog_tag_map_fd_pos
);

fn smoke_abi_bpf_obj_get_info_neg() -> TestResult {
    with_setup(|| {
        let mut info = [0u8; INFO_BUF];
        // An fd that names nothing.
        if obj_info(4095, &mut info, PROG_INFO_LEN as u32).0 != Some(EBADF) {
            return Err("BPF_OBJ_GET_INFO_BY_FD on an unopened fd did not return EBADF");
        }
        // An fd that names something that is not a BPF object. `EINVAL` and not
        // `ENOTSUP`: the kernel did not fail to *support* the object, it failed
        // to recognise one.
        let efd = call(Syscall::Eventfd.raw(), a0(0)).ok_or("eventfd() not Ok")?;
        if efd < 0 {
            return Err("eventfd failed");
        }
        if obj_info(efd, &mut info, PROG_INFO_LEN as u32).0 != Some(EINVAL) {
            return Err("BPF_OBJ_GET_INFO_BY_FD on a non-BPF fd did not return EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(efd as u64));

        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        // A NULL info pointer with a non-zero length is a fault, not a silent
        // no-op — the caller believes it has a filled buffer.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, AI_BPF_FD, fd as u32);
        put_u32(&mut attr, AI_INFO_LEN, PROG_INFO_LEN as u32);
        put_u64(&mut attr, AI_INFO, 0);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_OBJ_GET_INFO_BY_FD,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EFAULT)
        {
            return Err("BPF_OBJ_GET_INFO_BY_FD with a NULL info pointer did not return EFAULT");
        }
        // A `bpf_attr` shorter than the command's own fields.
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_OBJ_GET_INFO_BY_FD, attr.as_mut_ptr() as u64, 12),
        ) != Some(EINVAL)
        {
            return Err("BPF_OBJ_GET_INFO_BY_FD with a truncated bpf_attr did not return EINVAL");
        }
        // `CHECK_ATTR`: a non-zero byte past this command's last field means
        // the caller relies on something this kernel does not implement.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, AI_BPF_FD, fd as u32);
        put_u32(&mut attr, AI_INFO_LEN, PROG_INFO_LEN as u32);
        put_u64(&mut attr, AI_INFO, info.as_mut_ptr() as u64);
        attr[16] = 1;
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_OBJ_GET_INFO_BY_FD,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_OBJ_GET_INFO_BY_FD ignored a non-zero byte past its last field");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_get_info_neg);

/// The instruction-dump fields use their length words as input capacities and
/// output true lengths. Exercise prefixes deliberately: accepting only a full
/// buffer would break the two-call sizing pattern used by bpftool.
fn smoke_abi_bpf_obj_get_info_dump_pos() -> TestResult {
    with_setup(|| {
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        // A map pseudo-load makes the exact-byte assertion load-bearing: Linux
        // normally rewrites this immediate to a kernel pointer, while NARF's
        // contract keeps the submitted fd in the immutable translated image.
        let xlated = ld_map_fd_prog(map_fd);
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &xlated).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        let jited = prog_behind_fd(fd)
            .ok_or("program fd did not hold BpfProg")?
            .jited_bytes()
            .to_vec();
        if jited.len() < 2 {
            return Err("trivial program did not produce a dumpable JIT image");
        }

        let xlated_cap = xlated.len() - 3;
        let jited_cap = jited.len() - 1;
        let mut xlated_out = alloc::vec![0xA5; xlated_cap + 1];
        let mut jited_out = alloc::vec![0xA5; jited_cap + 1];
        let mut info = [0u8; INFO_BUF];
        info[PI_XLATED_PROG_LEN..PI_XLATED_PROG_LEN + 4]
            .copy_from_slice(&(xlated_cap as u32).to_le_bytes());
        info[PI_JITED_PROG_LEN..PI_JITED_PROG_LEN + 4]
            .copy_from_slice(&(jited_cap as u32).to_le_bytes());
        put_info_u64(
            &mut info,
            PI_XLATED_PROG_INSNS,
            xlated_out.as_mut_ptr() as u64,
        );
        put_info_u64(
            &mut info,
            PI_JITED_PROG_INSNS,
            jited_out.as_mut_ptr() as u64,
        );
        if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD instruction dump failed");
        }
        if xlated_out[..xlated_cap] != xlated[..xlated_cap] || xlated_out[xlated_cap] != 0xA5 {
            return Err("translated dump did not copy exactly its declared prefix");
        }
        if jited_out[..jited_cap] != jited[..jited_cap] || jited_out[jited_cap] != 0xA5 {
            return Err("JIT dump did not copy exactly its declared prefix");
        }
        if info_u32(&info, PI_XLATED_PROG_LEN) != xlated.len() as u32
            || info_u32(&info, PI_JITED_PROG_LEN) != jited.len() as u32
        {
            return Err("instruction dump did not report full output lengths");
        }
        if info_u64(&info, PI_XLATED_PROG_INSNS) != xlated_out.as_ptr() as u64
            || info_u64(&info, PI_JITED_PROG_INSNS) != jited_out.as_ptr() as u64
        {
            return Err("instruction dump did not preserve its in/out pointers");
        }

        // Capacity zero is a sizing query even when the pointer is nonsense.
        let mut info = [0u8; INFO_BUF];
        put_info_u64(&mut info, PI_XLATED_PROG_INSNS, u64::MAX);
        put_info_u64(&mut info, PI_JITED_PROG_INSNS, u64::MAX);
        if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
            return Err("zero-capacity instruction sizing query touched its pointer");
        }
        if info_u32(&info, PI_XLATED_PROG_LEN) != xlated.len() as u32
            || info_u32(&info, PI_JITED_PROG_LEN) != jited.len() as u32
        {
            return Err("instruction sizing query returned the wrong lengths");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_obj_get_info_dump_pos);

fn smoke_abi_bpf_obj_get_info_dump_neg() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }

        let mut info = [0u8; INFO_BUF];
        info[PI_XLATED_PROG_LEN..PI_XLATED_PROG_LEN + 4].copy_from_slice(&1u32.to_le_bytes());
        if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(EFAULT) {
            return Err("translated dump with a null output pointer was not EFAULT");
        }

        let mut info = [0u8; INFO_BUF];
        info[PI_JITED_PROG_LEN..PI_JITED_PROG_LEN + 4].copy_from_slice(&1u32.to_le_bytes());
        if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(EFAULT) {
            return Err("JIT dump with a null output pointer was not EFAULT");
        }

        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_abi_bpf_obj_get_info_dump_neg);

/// `nr_map_ids` / `map_ids` — the in/out pair a loader uses to rediscover the
/// maps a program holds.
fn smoke_abi_bpf_obj_get_info_map_ids_pos() -> TestResult {
    with_setup(|| {
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let map_id = map_id_of(map_fd)?;
        let prog_fd =
            load_prog(BPF_PROG_TYPE_TRACING, &ld_map_fd_prog(map_fd)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a program holding a map handle");
        }

        // Pass 1: capacity 0. The count comes back, nothing is written — this
        // is how a caller sizes its buffer.
        let mut info = [0u8; INFO_BUF];
        if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD failed");
        }
        if info_u32(&info, PI_NR_MAP_IDS) != 1 {
            return Err("bpf_prog_info.nr_map_ids is not the program's map count");
        }

        // Pass 2: a real buffer, with a sentinel in the slot *immediately*
        // after the one the kernel may fill. One id is due, so `ids[1]` must
        // survive.
        let mut ids = [0xAAAA_AAAAu32; 2];
        let mut info = [0u8; INFO_BUF];
        info[PI_NR_MAP_IDS..PI_NR_MAP_IDS + 4].copy_from_slice(&1u32.to_le_bytes());
        put_info_u64(&mut info, PI_MAP_IDS, ids.as_mut_ptr() as u64);
        if obj_info(prog_fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD with a map_ids buffer failed");
        }
        if ids[0] != map_id {
            return Err("bpf_prog_info.map_ids[0] is not the id of the map the program holds");
        }
        if ids[1] != 0xAAAA_AAAA {
            return Err("bpf_prog_info.map_ids wrote past the caller's declared capacity");
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_get_info_map_ids_pos);

// ── BPF_OBJ_GET_INFO_BY_FD: maps ────────────────────────────────────

fn smoke_abi_bpf_obj_get_info_map_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_PERCPU_HASH, 4, 8, 6).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let mut info = [0u8; INFO_BUF];
        let (r, back) = obj_info(fd, &mut info, MAP_INFO_LEN as u32);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD on a map fd failed");
        }
        if back != MAP_INFO_LEN as u32 {
            return Err("bpf_map_info: kernel did not report sizeof(bpf_map_info) back");
        }
        // The type must round-trip through `BPF_MAP_CREATE`'s own value, or a
        // loader reopening a map from its info would create the wrong kind.
        if info_u32(&info, MI_TYPE) != BPF_MAP_TYPE_PERCPU_HASH {
            return Err("bpf_map_info.type did not round-trip BPF_MAP_TYPE_PERCPU_HASH");
        }
        if info_u32(&info, MI_ID) == 0 {
            return Err("bpf_map_info.id is 0 — ids start at 1");
        }
        if info_u32(&info, MI_KEY_SIZE) != 4 {
            return Err("bpf_map_info.key_size is wrong");
        }
        if info_u32(&info, MI_VALUE_SIZE) != 8 {
            return Err("bpf_map_info.value_size is wrong");
        }
        if info_u32(&info, MI_MAX_ENTRIES) != 6 {
            return Err("bpf_map_info.max_entries is wrong");
        }
        if info[MI_NAME] != 0 {
            return Err("bpf_map_info.name should be empty for an unnamed map");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_get_info_map_pos);

// ── the info_len truncation contract ────────────────────────────────

/// Backward compatibility: a caller compiled against a *smaller* struct gets
/// exactly the prefix it declared and not one byte more.
fn smoke_abi_bpf_info_len_short_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 3).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let id = map_id_of(fd)?;

        // Sentinel the *whole* buffer. Anything written past the declared 8
        // bytes is an overrun into a caller that never asked for the space —
        // the failure this contract exists to prevent.
        let mut info = [0xAAu8; INFO_BUF];
        let (r, back) = obj_info(fd, &mut info, 8);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD with a short info_len failed");
        }
        if back != 8 {
            return Err("a short info_len must be echoed back unchanged");
        }
        if info_u32(&info, MI_TYPE) != BPF_MAP_TYPE_ARRAY {
            return Err("the 8-byte prefix does not carry bpf_map_info.type");
        }
        if info_u32(&info, MI_ID) != id {
            return Err("the 8-byte prefix does not carry bpf_map_info.id");
        }
        // Byte 8 is the first the kernel must not touch — one slot past the
        // boundary, not somewhere safely distant.
        if info[8] != 0xAA {
            return Err("BPF_OBJ_GET_INFO_BY_FD wrote past the caller's declared info_len");
        }
        if info[MAP_INFO_LEN - 1] != 0xAA || info[MAP_INFO_LEN] != 0xAA {
            return Err("BPF_OBJ_GET_INFO_BY_FD filled the whole struct despite a short info_len");
        }
        // An info_len of 0 is legal and writes nothing.
        let mut info = [0xAAu8; INFO_BUF];
        let (r, back) = obj_info(fd, &mut info, 0);
        if r != Some(0) || back != 0 {
            return Err("an info_len of 0 should succeed and report 0");
        }
        if info[0] != 0xAA {
            return Err("an info_len of 0 still wrote to the caller's buffer");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_info_len_short_pos);

/// Forward compatibility: a caller compiled against a *larger* struct is told
/// how much was filled, so it can tell "this kernel left the field alone" from
/// "the field is genuinely zero".
fn smoke_abi_bpf_info_len_long_pos() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 3).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        // Tail zeroed, as a well-behaved newer caller does.
        let mut info = [0u8; INFO_BUF];
        let (r, back) = obj_info(fd, &mut info, MAP_INFO_LEN as u32 + 32);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD with an oversized info_len failed");
        }
        if back != MAP_INFO_LEN as u32 {
            return Err(
                "an oversized info_len must be answered with sizeof, not echoed — the caller \
                 cannot otherwise tell which suffix went unfilled",
            );
        }
        if info_u32(&info, MI_MAX_ENTRIES) != 3 {
            return Err("the leading struct was not filled");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_info_len_long_pos);

fn smoke_abi_bpf_info_len_long_neg() -> TestResult {
    with_setup(|| {
        let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 3).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        // A non-zero byte in the part this kernel cannot fill means the caller
        // relies on a field that does not exist here. `E2BIG` says so;
        // succeeding would leave it reading its own stale value as an answer.
        let mut info = [0u8; INFO_BUF];
        info[MAP_INFO_LEN] = 1;
        if obj_info(fd, &mut info, MAP_INFO_LEN as u32 + 32).0 != Some(E2BIG) {
            return Err("an oversized info_len with a non-zero tail did not return E2BIG");
        }
        // …and the byte immediately *before* the boundary is inside the struct,
        // so it must not trigger the check.
        let mut info = [0u8; INFO_BUF];
        info[MAP_INFO_LEN - 1] = 1;
        if obj_info(fd, &mut info, MAP_INFO_LEN as u32 + 32).0 != Some(0) {
            return Err("the tail-zero check started one byte early");
        }
        // Silly large, matching Linux's PAGE_SIZE guard.
        let mut info = [0u8; INFO_BUF];
        if obj_info(fd, &mut info, 8192).0 != Some(E2BIG) {
            return Err("an absurd info_len did not return E2BIG");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_info_len_long_neg);

// ── BPF_*_GET_NEXT_ID ───────────────────────────────────────────────

fn smoke_abi_bpf_get_next_id_pos() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(3)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        let want = id_of(fd)?;
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let want_map = map_id_of(map_fd)?;

        // A walk from 0 must reach the object just made, and must terminate.
        // The step bound is generous but finite: an id table that never says
        // ENOENT is an infinite loop in every enumerating tool.
        let mut cur = 0u32;
        let mut found = false;
        let mut steps = 0;
        loop {
            let (r, id) = next_id(BPF_PROG_GET_NEXT_ID, cur);
            if r == Some(ENOENT) {
                break;
            }
            if r != Some(0) {
                return Err("BPF_PROG_GET_NEXT_ID returned neither 0 nor ENOENT");
            }
            if id <= cur {
                return Err("BPF_PROG_GET_NEXT_ID did not advance strictly — a walk would loop");
            }
            if id == want {
                found = true;
            }
            cur = id;
            steps += 1;
            if steps > 100_000 {
                return Err("BPF_PROG_GET_NEXT_ID never terminated");
            }
        }
        if !found {
            return Err("a freshly loaded program was not reachable by BPF_PROG_GET_NEXT_ID");
        }

        let mut cur = 0u32;
        let mut found = false;
        let mut steps = 0;
        loop {
            let (r, id) = next_id(BPF_MAP_GET_NEXT_ID, cur);
            if r == Some(ENOENT) {
                break;
            }
            if r != Some(0) {
                return Err("BPF_MAP_GET_NEXT_ID returned neither 0 nor ENOENT");
            }
            if id <= cur {
                return Err("BPF_MAP_GET_NEXT_ID did not advance strictly");
            }
            if id == want_map {
                found = true;
            }
            cur = id;
            steps += 1;
            if steps > 100_000 {
                return Err("BPF_MAP_GET_NEXT_ID never terminated");
            }
        }
        if !found {
            return Err("a freshly created map was not reachable by BPF_MAP_GET_NEXT_ID");
        }
        // Starting *at* an object's own id must skip it: the walk contract is
        // "strictly greater", which is what makes feeding each answer back in
        // terminate rather than repeat.
        let (r, id) = next_id(BPF_MAP_GET_NEXT_ID, want_map);
        if r == Some(0) && id == want_map {
            return Err("BPF_MAP_GET_NEXT_ID returned the id it was given");
        }
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_get_next_id_pos);

fn smoke_abi_bpf_get_next_id_neg() -> TestResult {
    with_setup(|| {
        // Past the last possible id there is nothing, and the answer is ENOENT
        // rather than a zero id reported as success.
        if next_id(BPF_PROG_GET_NEXT_ID, u32::MAX).0 != Some(ENOENT) {
            return Err("BPF_PROG_GET_NEXT_ID past the end did not return ENOENT");
        }
        if next_id(BPF_MAP_GET_NEXT_ID, u32::MAX).0 != Some(ENOENT) {
            return Err("BPF_MAP_GET_NEXT_ID past the end did not return ENOENT");
        }
        // A `bpf_attr` shorter than the command's own fields.
        let mut attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_GET_NEXT_ID, attr.as_mut_ptr() as u64, 4),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_GET_NEXT_ID with a truncated bpf_attr did not return EINVAL");
        }
        // `CHECK_ATTR`: `open_flags` is past this command's last field.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 8, 1);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_PROG_GET_NEXT_ID,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_GET_NEXT_ID ignored a non-zero byte past its last field");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_get_next_id_neg);

// ── BPF_*_GET_FD_BY_ID ──────────────────────────────────────────────

fn smoke_abi_bpf_get_fd_by_id_pos() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(9)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        let id = id_of(fd)?;
        let fd2 = fd_by_id(BPF_PROG_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
        if fd2 < 0 {
            return Err("BPF_PROG_GET_FD_BY_ID failed for a live program");
        }
        if fd2 == fd {
            return Err("BPF_PROG_GET_FD_BY_ID handed back the same fd, not a new one");
        }
        if id_of(fd2)? != id {
            return Err("the fd obtained by id names a different program");
        }
        // Linux sets close-on-exec on every bpf fd, including this one.
        let flags = call(Syscall::Fcntl.raw(), a2(fd2 as u64, 1, 0)).ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("BPF_PROG_GET_FD_BY_ID did not set close-on-exec");
        }

        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let map_id = map_id_of(map_fd)?;
        let map_fd2 = fd_by_id(BPF_MAP_GET_FD_BY_ID, map_id).ok_or("bpf() not Ok")?;
        if map_fd2 < 0 {
            return Err("BPF_MAP_GET_FD_BY_ID failed for a live map");
        }
        if map_id_of(map_fd2)? != map_id {
            return Err("the fd obtained by id names a different map");
        }
        let ro = fd_by_id_flags(BPF_MAP_GET_FD_BY_ID, map_id, BPF_F_RDONLY)
            .ok_or("read-only BPF_MAP_GET_FD_BY_ID was not Ok")?;
        let wo = fd_by_id_flags(BPF_MAP_GET_FD_BY_ID, map_id, BPF_F_WRONLY)
            .ok_or("write-only BPF_MAP_GET_FD_BY_ID was not Ok")?;
        if ro < 0 || wo < 0 {
            return Err("BPF_MAP_GET_FD_BY_ID refused an access mode");
        }
        let key = 0u32;
        let value = 0x1234_5678_9ABC_DEF0u64;
        if elem(
            BPF_MAP_UPDATE_ELEM,
            wo,
            (&key) as *const u32 as u64,
            (&value) as *const u64 as u64,
            BPF_ANY,
        ) != Some(0)
        {
            return Err("write-only by-id fd could not update its map");
        }
        let mut out = 0u64;
        if elem(
            BPF_MAP_LOOKUP_ELEM,
            ro,
            (&key) as *const u32 as u64,
            (&mut out) as *mut u64 as u64,
            0,
        ) != Some(0)
            || out != value
        {
            return Err("read-only by-id fd did not address the same map");
        }
        if elem(
            BPF_MAP_UPDATE_ELEM,
            ro,
            (&key) as *const u32 as u64,
            (&value) as *const u64 as u64,
            BPF_ANY,
        ) != Some(-1)
            || elem(
                BPF_MAP_LOOKUP_ELEM,
                wo,
                (&key) as *const u32 as u64,
                (&mut out) as *mut u64 as u64,
                0,
            ) != Some(-1)
        {
            return Err("by-id access mode was not enforced");
        }
        let _ = call(Syscall::Close.raw(), a0(ro as u64));
        let _ = call(Syscall::Close.raw(), a0(wo as u64));
        let _ = call(Syscall::Close.raw(), a0(map_fd2 as u64));
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(fd2 as u64));
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_get_fd_by_id_pos);

fn smoke_abi_bpf_get_fd_by_id_neg() -> TestResult {
    with_setup(|| {
        // Id 0 is never assigned — both counters start at 1.
        if fd_by_id(BPF_PROG_GET_FD_BY_ID, 0) != Some(ENOENT) {
            return Err("BPF_PROG_GET_FD_BY_ID(0) did not return ENOENT");
        }
        if fd_by_id(BPF_MAP_GET_FD_BY_ID, 0) != Some(ENOENT) {
            return Err("BPF_MAP_GET_FD_BY_ID(0) did not return ENOENT");
        }
        // An id far past anything this boot assigned.
        if fd_by_id(BPF_PROG_GET_FD_BY_ID, u32::MAX) != Some(ENOENT) {
            return Err("BPF_PROG_GET_FD_BY_ID on an unassigned id did not return ENOENT");
        }
        if fd_by_id(BPF_MAP_GET_FD_BY_ID, u32::MAX) != Some(ENOENT) {
            return Err("BPF_MAP_GET_FD_BY_ID on an unassigned id did not return ENOENT");
        }

        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        let prog_id = id_of(fd)?;
        // The two id spaces are independent, so a program id may or may not
        // also name a map. What must never happen is the *program* coming back
        // through the map table.
        if let Some(r) = fd_by_id(BPF_MAP_GET_FD_BY_ID, prog_id) {
            if r >= 0 {
                let mut info = [0u8; INFO_BUF];
                let (ok, back) = obj_info(r, &mut info, PROG_INFO_LEN as u32);
                if ok == Some(0) && back == PROG_INFO_LEN as u32 {
                    return Err("BPF_MAP_GET_FD_BY_ID resolved a program id to a program fd");
                }
                let _ = call(Syscall::Close.raw(), a0(r as u64));
            }
        }
        // `CHECK_ATTR`: a program fd takes no `open_flags`.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, prog_id);
        put_u32(&mut attr, 8, 1);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_PROG_GET_FD_BY_ID,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_GET_FD_BY_ID ignored a non-zero open_flags");
        }
        // Map open flags are a two-value access mode. Unknown bits and asking
        // for both directions at once are malformed.
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let map_id = map_id_of(map_fd)?;
        if fd_by_id_flags(BPF_MAP_GET_FD_BY_ID, map_id, 1) != Some(EINVAL)
            || fd_by_id_flags(BPF_MAP_GET_FD_BY_ID, map_id, BPF_F_RDONLY | BPF_F_WRONLY)
                != Some(EINVAL)
        {
            return Err("BPF_MAP_GET_FD_BY_ID accepted invalid open_flags");
        }
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_get_fd_by_id_neg);

// ── id lifetime ─────────────────────────────────────────────────────

/// An fd obtained by id holds its **own** reference: closing the fd the object
/// was created through must not invalidate it. That is the whole reason
/// `GET_FD_BY_ID` exists, and it is the property that rots silently if the
/// second fd ever ends up sharing the first one's ownership.
fn smoke_abi_bpf_fd_by_id_keeps_object_alive_pos() -> TestResult {
    with_setup(|| {
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let id = map_id_of(map_fd)?;
        let by_id = fd_by_id(BPF_MAP_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
        if by_id < 0 {
            return Err("BPF_MAP_GET_FD_BY_ID failed");
        }
        // Drop the creating fd. Everything below runs against `by_id` alone.
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));

        if map_id_of(by_id)? != id {
            return Err("the id-obtained fd stopped naming its map once the creating fd closed");
        }
        // Not just readable metadata — the map itself must still work.
        let key = 1u32;
        let value = 0x1122_3344_5566_7788u64;
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, ME_MAP_FD, by_id as u32);
        put_u64(&mut attr, ME_KEY, (&key as *const u32) as u64);
        put_u64(&mut attr, ME_VALUE, (&value as *const u64) as u64);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_MAP_UPDATE_ELEM,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(0)
        {
            return Err("update through an id-obtained fd failed after the creating fd closed");
        }
        let mut got = 0u64;
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, ME_MAP_FD, by_id as u32);
        put_u64(&mut attr, ME_KEY, (&key as *const u32) as u64);
        put_u64(&mut attr, ME_VALUE, (&mut got as *mut u64) as u64);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_MAP_LOOKUP_ELEM,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(0)
        {
            return Err("lookup through an id-obtained fd failed");
        }
        if got != value {
            return Err("the id-obtained fd read back the wrong value — it is not the same map");
        }
        // And the id is still live for a *third* opener while `by_id` is held.
        let third = fd_by_id(BPF_MAP_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
        if third < 0 {
            return Err("the id stopped resolving while an id-obtained fd was still open");
        }
        let _ = call(Syscall::Close.raw(), a0(third as u64));
        let _ = call(Syscall::Close.raw(), a0(by_id as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_fd_by_id_keeps_object_alive_pos);

/// The teardown half: once the last reference goes, the id stops resolving —
/// and is never handed to a later object. A reused id is how a loader that
/// cached one silently starts addressing something else.
fn smoke_abi_bpf_id_not_reused_after_teardown_neg() -> TestResult {
    with_setup(|| {
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let dead_id = map_id_of(map_fd)?;
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));

        // The object is gone: the registry holds a weak reference, so this is a
        // failed lookup and not a dangling handle.
        if fd_by_id(BPF_MAP_GET_FD_BY_ID, dead_id) != Some(ENOENT) {
            return Err("BPF_MAP_GET_FD_BY_ID resolved a map whose last fd was closed");
        }
        // …and the walk no longer visits it.
        let (r, id) = next_id(BPF_MAP_GET_NEXT_ID, dead_id - 1);
        if r == Some(0) && id == dead_id {
            return Err("BPF_MAP_GET_NEXT_ID still walks over a freed map's id");
        }

        // The next map must not inherit the freed id.
        let next = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 2).ok_or("bpf() not Ok")?;
        if next < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let new_id = map_id_of(next)?;
        if new_id == dead_id {
            return Err("a freed map's id was reused — a cached id now names a different map");
        }
        if new_id < dead_id {
            return Err("map ids went backwards");
        }

        // Same for programs.
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        let dead_prog = id_of(prog_fd)?;
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        if fd_by_id(BPF_PROG_GET_FD_BY_ID, dead_prog) != Some(ENOENT) {
            return Err("BPF_PROG_GET_FD_BY_ID resolved a program whose last fd was closed");
        }
        let again = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if again < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        if id_of(again)? == dead_prog {
            return Err("a freed program's id was reused");
        }
        let _ = call(Syscall::Close.raw(), a0(again as u64));
        let _ = call(Syscall::Close.raw(), a0(next as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_id_not_reused_after_teardown_neg
);

/// A map a program still references outlives its own fd — so its id keeps
/// resolving. The complement of the teardown smoke: "the fd closed" is not the
/// same event as "the object died", and an id table that confused the two would
/// hide exactly the maps a loader most wants to rediscover.
fn smoke_abi_bpf_id_survives_fd_close_while_referenced_pos() -> TestResult {
    with_setup(|| {
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let map_id = map_id_of(map_fd)?;
        let prog_fd =
            load_prog(BPF_PROG_TYPE_TRACING, &ld_map_fd_prog(map_fd)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected a program holding a map handle");
        }
        // The program holds an `Arc`, so closing the creating fd does not free
        // the map.
        let _ = call(Syscall::Close.raw(), a0(map_fd as u64));

        let reopened = fd_by_id(BPF_MAP_GET_FD_BY_ID, map_id).ok_or("bpf() not Ok")?;
        if reopened < 0 {
            return Err("a map still referenced by a program stopped resolving by id");
        }
        if map_id_of(reopened)? != map_id {
            return Err("the reopened fd names a different map");
        }
        let _ = call(Syscall::Close.raw(), a0(reopened as u64));
        // Now drop the program too. With no reference left the id must stop
        // resolving — otherwise the entry, not the object, was keeping it alive.
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        if fd_by_id(BPF_MAP_GET_FD_BY_ID, map_id) != Some(ENOENT) {
            return Err("the map's id still resolved after its last reference went away");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_id_survives_fd_close_while_referenced_pos
);

// ── links ───────────────────────────────────────────────────────────

/// The errno vocabulary of the link id commands.
///
/// This test used to pin both commands at `ENOTSUP`, because there was no link
/// object to assign ids to. There is now, so the contract has inverted: an
/// unknown id is `ENOENT` (not `ENOTSUP`, which would tell a probing loader the
/// kernel has no links at all) and a malformed `bpf_attr` is `EINVAL`.
fn smoke_abi_bpf_link_id_cmds_neg() -> TestResult {
    with_setup(|| {
        // Id 0 is never assigned — the counter starts at 1.
        if fd_by_id(BPF_LINK_GET_FD_BY_ID, 0) != Some(ENOENT) {
            return Err("BPF_LINK_GET_FD_BY_ID(0) did not return ENOENT");
        }
        // An id far past anything this boot assigned.
        if fd_by_id(BPF_LINK_GET_FD_BY_ID, u32::MAX) != Some(ENOENT) {
            return Err("BPF_LINK_GET_FD_BY_ID on an unassigned id did not return ENOENT");
        }
        // Past the last possible id there is nothing, and the answer is ENOENT
        // rather than a zero id reported as success.
        if next_id(BPF_LINK_GET_NEXT_ID, u32::MAX).0 != Some(ENOENT) {
            return Err("BPF_LINK_GET_NEXT_ID past the end did not return ENOENT");
        }
        // A `bpf_attr` shorter than the command's own fields.
        let mut attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_LINK_GET_NEXT_ID, attr.as_mut_ptr() as u64, 4),
        ) != Some(EINVAL)
        {
            return Err("BPF_LINK_GET_NEXT_ID with a truncated bpf_attr did not return EINVAL");
        }
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_LINK_GET_FD_BY_ID, attr.as_mut_ptr() as u64, 2),
        ) != Some(EINVAL)
        {
            return Err("BPF_LINK_GET_FD_BY_ID with a truncated bpf_attr did not return EINVAL");
        }
        // `CHECK_ATTR`: `BPF_LINK_GET_FD_BY_ID_LAST_FIELD` is `link_id`, so a
        // link fd takes no `open_flags` — a caller that set one is relying on
        // behaviour this kernel does not implement.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 8, 1);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_LINK_GET_FD_BY_ID,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_LINK_GET_FD_BY_ID ignored a non-zero byte past its last field");
        }
        // `BPF_LINK_GET_NEXT_ID_LAST_FIELD` is `next_id`, so `open_flags` is
        // past it here too.
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_LINK_GET_NEXT_ID,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_LINK_GET_NEXT_ID ignored a non-zero byte past its last field");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_id_cmds_neg);

// ════════════════════════════════════════════════════════════════════
// The attach commands — BPF_PROG_ATTACH / DETACH and the link family.
//
// `sys_bpf_attach.rs` owns the translation from Linux's `bpf_attach_type` onto
// NARF's two hooks. The errno each refusal produces is a contract a probing
// loader reads, so every one of them is pinned here.
// ════════════════════════════════════════════════════════════════════

const BPF_PROG_ATTACH: u64 = 8;
const BPF_PROG_DETACH: u64 = 9;
const BPF_LINK_CREATE: u64 = 28;
const BPF_LINK_UPDATE: u64 = 29;
const BPF_LINK_DETACH: u64 = 34;

/// `enum bpf_attach_type`. `BPF_TRACE_FENTRY` is NARF's probe sites and
/// `BPF_XDP` is the classifier's XDP slot; the other two here exist to pin the
/// `ENOTSUP`-vs-`EINVAL` split.
const BPF_TRACE_FENTRY: u32 = 24;
const BPF_XDP: u32 = 37;
/// A type Linux defines and NARF has no surface for → `EOPNOTSUPP`.
const BPF_CGROUP_INET_INGRESS: u32 = 0;
/// Past `__MAX_BPF_ATTACH_TYPE` → `EINVAL`, because it is not a value at all.
const BPF_ATTACH_TYPE_NONSENSE: u32 = 4242;

/// `BPF_PROG_TYPE_SYSCALL` — NARF's `Context::Sleepable`.
const BPF_PROG_TYPE_SYSCALL: u32 = 31;

const EBUSY: i64 = -16;
const ENOSPC: i64 = -28;

fn bpf(cmd: u64, attr: &[u8; ATTR_LEN]) -> Option<i64> {
    call(
        Syscall::Bpf.raw(),
        a2(cmd, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

/// `bpf_attr` for `BPF_PROG_ATTACH` / `BPF_PROG_DETACH`.
fn attach_attr(target: u32, prog_fd: u32, attach_type: u32) -> [u8; ATTR_LEN] {
    let mut a = [0u8; ATTR_LEN];
    put_u32(&mut a, 0, target); // target_fd / target_ifindex
    put_u32(&mut a, 4, prog_fd); // attach_bpf_fd
    put_u32(&mut a, 8, attach_type);
    a
}

/// `bpf_attr.link_create`.
fn link_attr(prog_fd: u32, target: u32, attach_type: u32) -> [u8; ATTR_LEN] {
    let mut a = [0u8; ATTR_LEN];
    put_u32(&mut a, 0, prog_fd);
    put_u32(&mut a, 4, target); // target_fd / target_ifindex
    put_u32(&mut a, 8, attach_type);
    a
}

/// A fresh probe id, so tests never contend for the same target.
fn fresh_probe() -> u32 {
    narf_tracing::dispatch::reserve_probe_id()
}

fn raw_tracepoint_attr(name: u64, prog_fd: u32, cookie: u64) -> [u8; ATTR_LEN] {
    let mut attr = [0u8; ATTR_LEN];
    put_u64(&mut attr, 0, name);
    put_u32(&mut attr, 8, prog_fd);
    put_u64(&mut attr, 16, cookie);
    attr
}

fn smoke_abi_bpf_raw_tracepoint_open_pos() -> TestResult {
    with_setup(|| {
        const NAME: &[u8] = b"abi_raw_tp\0";
        const COOKIE: u64 = 0x1122_3344_5566_7788;
        let probe_id = narf_tracing::register_named_probe("abi_raw_tp")
            .map_err(|_| "could not register the named tracepoint")?;
        let prog_fd = load_prog(BPF_PROG_TYPE_RAW_TRACEPOINT, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected the raw-tracepoint program");
        }
        let stats_fd = enable_stats(0).ok_or("BPF_ENABLE_STATS not Ok")?;
        if stats_fd < 0 {
            return Err("BPF_ENABLE_STATS failed");
        }
        let attr = raw_tracepoint_attr(NAME.as_ptr() as u64, prog_fd as u32, COOKIE);
        let link_fd = bpf(BPF_RAW_TRACEPOINT_OPEN, &attr).ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_RAW_TRACEPOINT_OPEN rejected a registered name");
        }
        let flags = call(Syscall::Fcntl.raw(), a2(link_fd as u64, 1, 0)).ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("raw-tracepoint link fd is not close-on-exec");
        }
        if bpf(BPF_RAW_TRACEPOINT_OPEN, &attr) != Some(-16 /* EBUSY */) {
            return Err("a second raw-tracepoint link did not report EBUSY");
        }

        let mut name_out = [0xAAu8; 32];
        let mut link_info = [0u8; INFO_BUF];
        put_info_u64(&mut link_info, LI_RAW_NAME, name_out.as_mut_ptr() as u64);
        put_info_u32(&mut link_info, LI_RAW_NAME_LEN, name_out.len() as u32);
        let (r, back) = obj_info(link_fd, &mut link_info, RAW_LINK_INFO_LEN as u32);
        if r != Some(0) || back != RAW_LINK_INFO_LEN as u32 {
            return Err("raw-tracepoint BPF_OBJ_GET_INFO_BY_FD failed");
        }
        if info_u32(&link_info, LI_TYPE) != BPF_LINK_TYPE_RAW_TRACEPOINT
            || info_u32(&link_info, LI_PROG_ID) != id_of(prog_fd)?
        {
            return Err("raw-tracepoint link info reported the wrong type or program");
        }
        if info_u64(&link_info, LI_RAW_NAME) != name_out.as_mut_ptr() as u64
            || info_u32(&link_info, LI_RAW_NAME_LEN) != NAME.len() as u32
            || info_u64(&link_info, LI_RAW_COOKIE) != COOKIE
            || name_out[..NAME.len()] != NAME[..]
        {
            return Err("raw-tracepoint link info lost its name or cookie");
        }

        let mut size_info = [0u8; INFO_BUF];
        let (r, back) = obj_info(link_fd, &mut size_info, RAW_LINK_INFO_LEN as u32);
        if r != Some(0)
            || back != RAW_LINK_INFO_LEN as u32
            || info_u32(&size_info, LI_RAW_NAME_LEN) != NAME.len() as u32
            || info_u64(&size_info, LI_RAW_COOKIE) != COOKIE
        {
            return Err("raw-tracepoint link info sizing lost the true length");
        }

        let mut short_name = [0xAAu8; 4];
        let mut short_info = [0u8; INFO_BUF];
        put_info_u64(&mut short_info, LI_RAW_NAME, short_name.as_mut_ptr() as u64);
        put_info_u32(&mut short_info, LI_RAW_NAME_LEN, short_name.len() as u32);
        let (r, back) = obj_info(link_fd, &mut short_info, RAW_LINK_INFO_LEN as u32);
        if r != Some(ENOSPC)
            || back != RAW_LINK_INFO_LEN as u32
            || short_name != *b"abi\0"
            || info_u32(&short_info, LI_RAW_NAME_LEN) != short_name.len() as u32
        {
            return Err("raw-tracepoint link info truncation diverged from Linux");
        }

        let mut bad_info = [0u8; INFO_BUF];
        put_info_u64(&mut bad_info, LI_RAW_NAME, u64::MAX);
        put_info_u32(&mut bad_info, LI_RAW_NAME_LEN, 4);
        if obj_info(link_fd, &mut bad_info, RAW_LINK_INFO_LEN as u32).0 != Some(EFAULT) {
            return Err("raw-tracepoint link info did not reject an invalid name pointer");
        }

        let mut mismatched_info = [0u8; INFO_BUF];
        put_info_u32(&mut mismatched_info, LI_RAW_NAME_LEN, 1);
        if obj_info(link_fd, &mut mismatched_info, RAW_LINK_INFO_LEN as u32).0 != Some(EINVAL) {
            return Err("raw-tracepoint link info accepted a mismatched name pointer/capacity");
        }

        narf_tracing::dispatch::fire(probe_id, narf_tracing::dispatch::ProbeArgs::none());
        let mut prog_info = [0u8; INFO_BUF];
        if obj_info(prog_fd, &mut prog_info, PROG_INFO_LEN as u32).0 != Some(0)
            || info_u32(&prog_info, PI_TYPE) != BPF_PROG_TYPE_RAW_TRACEPOINT
            || info_u64(&prog_info, PI_RUN_CNT) != 1
        {
            return Err("the named raw tracepoint lost its type or did not run");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        narf_tracing::dispatch::fire(probe_id, narf_tracing::dispatch::ProbeArgs::none());
        let mut after = [0u8; INFO_BUF];
        if obj_info(prog_fd, &mut after, PROG_INFO_LEN as u32).0 != Some(0)
            || info_u64(&after, PI_RUN_CNT) != 1
        {
            return Err("closing the raw-tracepoint link did not detach it");
        }
        let _ = call(Syscall::Close.raw(), a0(stats_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_raw_tracepoint_open_pos);

fn smoke_abi_bpf_raw_tracepoint_open_neg() -> TestResult {
    with_setup(|| {
        const KNOWN: &[u8] = b"abi_raw_tp_neg\0";
        const UNKNOWN: &[u8] = b"abi_raw_tp_missing\0";
        let _probe_id = narf_tracing::register_named_probe("abi_raw_tp_neg")
            .map_err(|_| "could not register the negative-test tracepoint")?;
        let prog_fd = load_prog(BPF_PROG_TYPE_RAW_TRACEPOINT, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD failed");
        }
        if bpf(
            BPF_RAW_TRACEPOINT_OPEN,
            &raw_tracepoint_attr(UNKNOWN.as_ptr() as u64, prog_fd as u32, 0),
        ) != Some(ENOENT)
        {
            return Err("an unknown raw tracepoint name was not ENOENT");
        }
        if bpf(
            BPF_RAW_TRACEPOINT_OPEN,
            &raw_tracepoint_attr(u64::MAX, prog_fd as u32, 0),
        ) != Some(EFAULT)
        {
            return Err("an invalid raw tracepoint name pointer was not EFAULT");
        }
        if bpf(
            BPF_RAW_TRACEPOINT_OPEN,
            &raw_tracepoint_attr(KNOWN.as_ptr() as u64, 4095, 0),
        ) != Some(EBADF)
        {
            return Err("an unopened raw tracepoint program fd was not EBADF");
        }
        let tracing = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if tracing < 0 {
            return Err("BPF_PROG_LOAD rejected the tracing negative fixture");
        }
        if bpf(
            BPF_RAW_TRACEPOINT_OPEN,
            &raw_tracepoint_attr(KNOWN.as_ptr() as u64, tracing as u32, 0),
        ) != Some(EINVAL)
        {
            return Err("an atomic fentry program attached through the raw-tracepoint API");
        }
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(prog_fd as u32, fresh_probe(), BPF_TRACE_FENTRY),
        ) != Some(EINVAL)
        {
            return Err("a raw-tracepoint program attached through the fentry API");
        }
        let mut attr = raw_tracepoint_attr(KNOWN.as_ptr() as u64, prog_fd as u32, 0);
        put_u32(&mut attr, 12, 1);
        if bpf(BPF_RAW_TRACEPOINT_OPEN, &attr) != Some(EINVAL) {
            return Err("BPF_RAW_TRACEPOINT_OPEN accepted its reserved word");
        }
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_RAW_TRACEPOINT_OPEN,
                attr.as_ptr() as u64,
                8, // truncated before prog_fd
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_RAW_TRACEPOINT_OPEN accepted a truncated attr");
        }
        let _ = call(Syscall::Close.raw(), a0(tracing as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_raw_tracepoint_open_neg);

// ── BPF iterators: BPF_LINK_CREATE(BPF_TRACE_ITER) + BPF_ITER_CREATE ──

const BPF_TRACE_ITER: u32 = 28;
const BPF_ITER_CREATE: u64 = 33;
const ITER_KIND_MAP: u32 = 0;

/// `r0 = *(u64 *)(r1 + 0); exit` — an iterator program that emits the id its
/// context carries (NARF emits a program's return value, one u64 per object).
fn iter_emit_id_prog() -> [u8; 16] {
    let mut insns = [0u8; 16];
    insns[0] = 0x79; // BPF_LDX | BPF_MEM | BPF_DW
    insns[1] = 0x10; // dst = r0 (low nibble), src = r1 (high)
                     // off = 0, so it reads context word 0
    insns[8] = 0x95; // exit
    insns
}

fn smoke_abi_bpf_iter_map_pos() -> TestResult {
    with_setup(|| {
        // Two maps to iterate, and their ids.
        let m1 = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok_or("bpf() not Ok")?;
        let m2 = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 1).ok_or("bpf() not Ok")?;
        if m1 < 0 || m2 < 0 {
            return Err("BPF_MAP_CREATE rejected an array map");
        }
        let id1 = map_id_of(m1)?;
        let id2 = map_id_of(m2)?;

        let prog_fd =
            load_prog(BPF_PROG_TYPE_TRACING, &iter_emit_id_prog()).ok_or("bpf() not Ok")?;
        if prog_fd < 0 {
            return Err("BPF_PROG_LOAD rejected the iterator program");
        }

        // Bind the program to the map target, then create the iterator fd.
        let link = bpf(
            BPF_LINK_CREATE,
            &link_attr(prog_fd as u32, ITER_KIND_MAP, BPF_TRACE_ITER),
        )
        .ok_or("bpf() not Ok")?;
        if link < 0 {
            return Err("BPF_LINK_CREATE(BPF_TRACE_ITER) failed");
        }
        let mut ic = [0u8; ATTR_LEN];
        put_u32(&mut ic, 0, link as u32); // iter_create.link_fd
        let iter = call(
            Syscall::Bpf.raw(),
            a2(BPF_ITER_CREATE, ic.as_ptr() as u64, ATTR_LEN as u64),
        )
        .ok_or("bpf() not Ok")?;
        if iter < 0 {
            return Err("BPF_ITER_CREATE failed");
        }

        // The iterator emits one u64 (a map id) per map.
        let mut buf = [0u8; 4096];
        let n = call(
            Syscall::Read.raw(),
            a2(iter as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
        )
        .ok_or("read() not Ok")?;
        if n <= 0 || n % 8 != 0 {
            return Err("iterator read did not return whole u64 records");
        }

        // Both created maps must appear among the records.
        let (mut saw1, mut saw2) = (false, false);
        let mut off = 0usize;
        while off + 8 <= n as usize {
            let v = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap());
            saw1 |= v == u64::from(id1);
            saw2 |= v == u64::from(id2);
            off += 8;
        }
        if !saw1 || !saw2 {
            return Err("the map iterator did not emit both created map ids");
        }

        // A second read from the end returns EOF (0), the whole-buffer contract.
        let eof = call(
            Syscall::Read.raw(),
            a2(iter as u64, buf.as_mut_ptr() as u64, buf.len() as u64),
        );
        if eof != Some(0) {
            return Err("a fully-drained iterator did not return EOF");
        }

        let _ = call(Syscall::Close.raw(), a0(iter as u64));
        let _ = call(Syscall::Close.raw(), a0(link as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(m1 as u64));
        let _ = call(Syscall::Close.raw(), a0(m2 as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_iter_map_pos);

fn smoke_abi_bpf_iter_neg() -> TestResult {
    with_setup(|| {
        let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(0)).ok_or("bpf() not Ok")?;

        // ITER_CREATE on a fd that is not an iterator link is EINVAL.
        let mut ic = [0u8; ATTR_LEN];
        put_u32(&mut ic, 0, prog_fd as u32);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_ITER_CREATE, ic.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("BPF_ITER_CREATE on a non-link fd was not EINVAL");
        }
        // ITER_CREATE on an unopened fd is EBADF.
        let mut ic = [0u8; ATTR_LEN];
        put_u32(&mut ic, 0, 4095);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_ITER_CREATE, ic.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EBADF)
        {
            return Err("BPF_ITER_CREATE on an unopened fd was not EBADF");
        }
        // An out-of-range iterator kind is rejected at link create.
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(prog_fd as u32, 99, BPF_TRACE_ITER),
        ) != Some(EINVAL)
        {
            return Err("BPF_LINK_CREATE(BPF_TRACE_ITER) with a bad kind was not EINVAL");
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_iter_neg);

/// `bpf_attr.query` for `BPF_PROG_QUERY`.
fn query_attr(target: u32, attach_type: u32, count: u32, prog_ids: u64) -> [u8; ATTR_LEN] {
    let mut a = [0u8; ATTR_LEN];
    put_u32(&mut a, 0, target); // target_fd / target_ifindex
    put_u32(&mut a, 4, attach_type);
    // query_flags @8 = 0, attach_flags (out) @12
    put_u64(&mut a, 16, prog_ids);
    put_u32(&mut a, 24, count);
    a
}

/// Run `BPF_PROG_QUERY` on a mutable attr and hand back the syscall result. The
/// caller reads the out-fields (`count` @24, `attach_flags` @12) from `attr`.
fn prog_query(attr: &mut [u8; ATTR_LEN]) -> Option<i64> {
    call(
        Syscall::Bpf.raw(),
        a2(BPF_PROG_QUERY, attr.as_mut_ptr() as u64, ATTR_LEN as u64),
    )
}

// ── BPF_PROG_QUERY ──────────────────────────────────────────────────

fn smoke_abi_bpf_prog_query_pos() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        // The program's real id, to compare against what the query reports.
        let mut info = [0u8; INFO_BUF];
        if obj_info(fd, &mut info, PROG_INFO_LEN as u32).0 != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD failed on the program");
        }
        let want_id = info_u32(&info, PI_ID);
        let probe = fresh_probe();
        let mut ids = [0u32; 4];

        // Nothing attached yet: the count comes back zero.
        let mut q = query_attr(probe, BPF_TRACE_FENTRY, 4, ids.as_mut_ptr() as u64);
        if prog_query(&mut q) != Some(0) {
            return Err("BPF_PROG_QUERY on an unattached target did not succeed");
        }
        if get_u32(&q, 24) != 0 {
            return Err("query on an unattached target reported a program");
        }

        // Attach, then the query names exactly that program.
        if bpf(
            BPF_PROG_ATTACH,
            &attach_attr(probe, fd as u32, BPF_TRACE_FENTRY),
        ) != Some(0)
        {
            return Err("BPF_PROG_ATTACH failed");
        }
        let mut q = query_attr(probe, BPF_TRACE_FENTRY, 4, ids.as_mut_ptr() as u64);
        if prog_query(&mut q) != Some(0) {
            return Err("BPF_PROG_QUERY on an attached target failed");
        }
        if get_u32(&q, 24) != 1 {
            return Err("query did not report exactly one attached program");
        }
        if get_u32(&q, 12) != 0 {
            return Err("query reported nonzero attach_flags — NARF has none");
        }
        if ids[0] != want_id {
            return Err("query returned the wrong program id");
        }

        // A count-0, null-array probe learns the count without writing anything.
        let mut q = query_attr(probe, BPF_TRACE_FENTRY, 0, 0);
        if prog_query(&mut q) != Some(0) {
            return Err("BPF_PROG_QUERY count-only probe failed");
        }
        if get_u32(&q, 24) != 1 {
            return Err("count-only probe did not report one program");
        }
        // But a zero-capacity array that the count won't fit is ENOSPC.
        let mut q = query_attr(probe, BPF_TRACE_FENTRY, 0, ids.as_mut_ptr() as u64);
        if prog_query(&mut q) != Some(ENOSPC) {
            return Err("BPF_PROG_QUERY into a too-small array did not return ENOSPC");
        }

        let _ = bpf(
            BPF_PROG_DETACH,
            &attach_attr(probe, fd as u32, BPF_TRACE_FENTRY),
        );
        let mut q = query_attr(probe, BPF_TRACE_FENTRY, 4, ids.as_mut_ptr() as u64);
        let _ = prog_query(&mut q);
        if get_u32(&q, 24) != 0 {
            return Err("query still reported a program after detach");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_query_pos);

fn smoke_abi_bpf_prog_query_neg() -> TestResult {
    with_setup(|| {
        // A truncated attr (before `count`) is EINVAL.
        let mut q = [0u8; ATTR_LEN];
        put_u32(&mut q, 4, BPF_TRACE_FENTRY);
        put_u32(&mut q, 0, fresh_probe());
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_PROG_QUERY, q.as_mut_ptr() as u64, 8),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_QUERY with a truncated attr did not return EINVAL");
        }
        // A nonzero query_flags is nonsense here — NARF has no cgroup effective
        // vs. attached distinction.
        let mut q = query_attr(fresh_probe(), BPF_TRACE_FENTRY, 0, 0);
        put_u32(&mut q, 8, 1);
        if prog_query(&mut q) != Some(EINVAL) {
            return Err("BPF_PROG_QUERY with query_flags did not return EINVAL");
        }
        // A target 0 is not a probe id (they start at 1).
        let mut q = query_attr(0, BPF_TRACE_FENTRY, 0, 0);
        if prog_query(&mut q) != Some(EINVAL) {
            return Err("BPF_PROG_QUERY on probe id 0 did not return EINVAL");
        }
        // An attach type NARF has no surface for is ENOTSUP, not EINVAL.
        let mut q = query_attr(1, 0, 0, 0);
        if prog_query(&mut q) != Some(EOPNOTSUPP) {
            return Err("BPF_PROG_QUERY with an unsupported attach type was not ENOTSUP");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_query_neg);

// ── BPF_PROG_ATTACH / BPF_PROG_DETACH ───────────────────────────────

fn smoke_abi_bpf_prog_attach_pos() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let probe = fresh_probe();
        let attr = attach_attr(probe, fd as u32, BPF_TRACE_FENTRY);
        if bpf(BPF_PROG_ATTACH, &attr) != Some(0) {
            return Err("BPF_PROG_ATTACH on a fresh probe id failed");
        }
        // Attaching twice is `EBUSY`: NARF's probe sites hold one program, and
        // the flags that mean "several" on Linux are cgroup-hierarchy concepts.
        if bpf(BPF_PROG_ATTACH, &attr) != Some(EBUSY) {
            return Err("a second BPF_PROG_ATTACH on the same target did not return EBUSY");
        }
        if bpf(BPF_PROG_DETACH, &attr) != Some(0) {
            return Err("BPF_PROG_DETACH failed");
        }
        // And once detached the target is free again.
        if bpf(BPF_PROG_ATTACH, &attr) != Some(0) {
            return Err("the target was not released by BPF_PROG_DETACH");
        }
        let _ = bpf(BPF_PROG_DETACH, &attr);
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_attach_pos);

fn smoke_abi_bpf_prog_attach_neg() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        // An fd that names nothing.
        if bpf(
            BPF_PROG_ATTACH,
            &attach_attr(fresh_probe(), 4095, BPF_TRACE_FENTRY),
        ) != Some(EBADF)
        {
            return Err("BPF_PROG_ATTACH with an unopened prog fd did not return EBADF");
        }
        // An fd that names something that is not a program. A *map* fd, because
        // that is the confusion the downcast exists to catch.
        let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
        if map_fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        if bpf(
            BPF_PROG_ATTACH,
            &attach_attr(fresh_probe(), map_fd as u32, BPF_TRACE_FENTRY),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_ATTACH with a map fd did not return EINVAL");
        }
        // A probe id of 0. `reserve_probe_id` starts at 1 and keeps 0 as
        // "unassigned", so 0 names no site.
        if bpf(
            BPF_PROG_ATTACH,
            &attach_attr(0, fd as u32, BPF_TRACE_FENTRY),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_ATTACH with probe id 0 did not return EINVAL");
        }
        // An attach type Linux defines and NARF has no surface for. `ENOTSUP`,
        // not `EINVAL` — the whole point of the split.
        if bpf(
            BPF_PROG_ATTACH,
            &attach_attr(1, fd as u32, BPF_CGROUP_INET_INGRESS),
        ) != Some(EOPNOTSUPP)
        {
            return Err("an unimplemented attach type did not return EOPNOTSUPP");
        }
        // An attach type that is not a value at all.
        if bpf(
            BPF_PROG_ATTACH,
            &attach_attr(1, fd as u32, BPF_ATTACH_TYPE_NONSENSE),
        ) != Some(EINVAL)
        {
            return Err("an out-of-enum attach type did not return EINVAL");
        }
        // `attach_flags` selects multi-program semantics NARF's hooks cannot
        // provide, so it is refused rather than ignored.
        let mut flagged = attach_attr(fresh_probe(), fd as u32, BPF_TRACE_FENTRY);
        put_u32(&mut flagged, 12, 1 /* BPF_F_ALLOW_OVERRIDE */);
        if bpf(BPF_PROG_ATTACH, &flagged) != Some(EINVAL) {
            return Err("BPF_PROG_ATTACH with attach_flags did not return EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_attach_neg);

fn smoke_abi_bpf_prog_detach_neg() -> TestResult {
    with_setup(|| {
        // Detaching a target nothing is attached to.
        if bpf(
            BPF_PROG_DETACH,
            &attach_attr(fresh_probe(), 0, BPF_TRACE_FENTRY),
        ) != Some(ENOENT)
        {
            return Err("BPF_PROG_DETACH of nothing did not return ENOENT");
        }
        // A link's target is not detachable this way. Without that rule the
        // link's own close would later unhook whatever had replaced it.
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let probe = fresh_probe();
        let link_fd = bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, probe, BPF_TRACE_FENTRY),
        )
        .ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_LINK_CREATE failed");
        }
        if bpf(BPF_PROG_DETACH, &attach_attr(probe, 0, BPF_TRACE_FENTRY)) != Some(EBUSY) {
            return Err("BPF_PROG_DETACH on a link-held target did not return EBUSY");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_prog_detach_neg);

// ── BPF_LINK_CREATE ─────────────────────────────────────────────────

fn smoke_abi_bpf_link_create_pos() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let probe = fresh_probe();
        let link_fd = bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, probe, BPF_TRACE_FENTRY),
        )
        .ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_LINK_CREATE failed on a fresh probe id");
        }
        // Linux's `bpf_link_new_fd` passes `O_CLOEXEC`; here a leaked link fd
        // is a leaked *attach*, since only its last close detaches.
        let flags = call(Syscall::Fcntl.raw(), a2(link_fd as u64, 1 /* F_GETFD */, 0))
            .ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("bpf link fd is not close-on-exec");
        }
        // A second link on the same target is `EBUSY`, and must not disturb the
        // first.
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, probe, BPF_TRACE_FENTRY),
        ) != Some(EBUSY)
        {
            return Err("a second link on one probe id did not return EBUSY");
        }
        if call(Syscall::Close.raw(), a0(link_fd as u64)) != Some(0) {
            return Err("closing the link fd failed");
        }
        // Closed → detached → the target is free.
        let again = bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, probe, BPF_TRACE_FENTRY),
        )
        .ok_or("bpf() not Ok")?;
        if again < 0 {
            return Err("closing the link fd did not release its target");
        }
        let _ = call(Syscall::Close.raw(), a0(again as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_create_pos);

fn smoke_abi_bpf_link_create_neg() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(4095, fresh_probe(), BPF_TRACE_FENTRY),
        ) != Some(EBADF)
        {
            return Err("BPF_LINK_CREATE with an unopened prog fd did not return EBADF");
        }
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, 1, BPF_CGROUP_INET_INGRESS),
        ) != Some(EOPNOTSUPP)
        {
            return Err("an unimplemented attach type did not return EOPNOTSUPP");
        }
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, 1, BPF_ATTACH_TYPE_NONSENSE),
        ) != Some(EINVAL)
        {
            return Err("an out-of-enum attach type did not return EINVAL");
        }
        // No `BPF_LINK_CREATE` flag NARF understands; every one Linux defines
        // belongs to an attach type NARF does not have.
        let mut flagged = link_attr(fd as u32, fresh_probe(), BPF_TRACE_FENTRY);
        put_u32(&mut flagged, 12, 1);
        if bpf(BPF_LINK_CREATE, &flagged) != Some(EINVAL) {
            return Err("BPF_LINK_CREATE with a flag set did not return EINVAL");
        }
        // XDP: ifindex 1 is the rtnetlink dump's synthetic loopback, which no
        // driver RX path classifies — a program attached there would install
        // cleanly and never run, so it is refused.
        if bpf(BPF_LINK_CREATE, &link_attr(fd as u32, 1, BPF_XDP)) != Some(ENODEV) {
            return Err("XDP on the synthetic loopback did not return ENODEV");
        }
        // …and an ifindex past every registered NIC.
        if bpf(BPF_LINK_CREATE, &link_attr(fd as u32, 0xFFFF, BPF_XDP)) != Some(ENODEV) {
            return Err("XDP on an unknown ifindex did not return ENODEV");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_create_neg);

fn smoke_abi_bpf_link_create_context_mismatch_neg() -> TestResult {
    with_setup(|| {
        // Spec §4.5: a probe site is `Atomic`. A program verified for
        // `Sleepable` declines at run time, and for XDP "declines" means "pass
        // the frame" — so an accepted attach would leave an interface that
        // looks filtered and is not. `EINVAL`, at attach.
        let fd = load_prog(BPF_PROG_TYPE_SYSCALL, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial sleepable program");
        }
        let probe = fresh_probe();
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, probe, BPF_TRACE_FENTRY),
        ) != Some(EINVAL)
        {
            return Err("a sleepable program linked to an atomic hook");
        }
        if bpf(
            BPF_PROG_ATTACH,
            &attach_attr(probe, fd as u32, BPF_TRACE_FENTRY),
        ) != Some(EINVAL)
        {
            return Err("BPF_PROG_ATTACH accepted a sleepable program on an atomic hook");
        }
        // The refusal must not have claimed the target.
        let ok = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if ok < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial atomic program");
        }
        let link_fd = bpf(
            BPF_LINK_CREATE,
            &link_attr(ok as u32, probe, BPF_TRACE_FENTRY),
        )
        .ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("a refused attach left the target claimed");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_link_create_context_mismatch_neg
);

// ── BPF_LINK_UPDATE / BPF_LINK_DETACH ───────────────────────────────

fn smoke_abi_bpf_link_detach_pos() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let probe = fresh_probe();
        let link_fd = bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, probe, BPF_TRACE_FENTRY),
        )
        .ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_LINK_CREATE failed");
        }
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, link_fd as u32);
        if bpf(BPF_LINK_DETACH, &attr) != Some(0) {
            return Err("BPF_LINK_DETACH failed");
        }
        // The fd stays valid and the link stays dead — Linux's shape too.
        if bpf(BPF_LINK_DETACH, &attr) != Some(ENOENT) {
            return Err("a second BPF_LINK_DETACH did not return ENOENT");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_detach_pos);

fn smoke_abi_bpf_link_detach_neg() -> TestResult {
    with_setup(|| {
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, 4095);
        if bpf(BPF_LINK_DETACH, &attr) != Some(EBADF) {
            return Err("BPF_LINK_DETACH on an unopened fd did not return EBADF");
        }
        // A program fd is not a link fd.
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        put_u32(&mut attr, 0, fd as u32);
        if bpf(BPF_LINK_DETACH, &attr) != Some(EINVAL) {
            return Err("BPF_LINK_DETACH on a program fd did not return EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_detach_neg);

fn smoke_abi_bpf_link_update_neg() -> TestResult {
    with_setup(|| {
        let a = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        let b = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(2)).ok_or("bpf() not Ok")?;
        if a < 0 || b < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let probe = fresh_probe();
        let link_fd = bpf(
            BPF_LINK_CREATE,
            &link_attr(a as u32, probe, BPF_TRACE_FENTRY),
        )
        .ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_LINK_CREATE failed");
        }
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, link_fd as u32); // link_fd
        put_u32(&mut attr, 4, b as u32); // new_prog_fd
                                         // LINUX-GAP: `BPF_LINK_UPDATE` on a tracing link. `narf_tracing`'s
                                         // `HandlerTable` has register and unregister and no atomic replace, so
                                         // a swap would silently drop every probe that fired between them.
                                         // Linux's is atomic; imitating it non-atomically is the divergence this
                                         // subsystem exists to avoid, so the honest answer is EOPNOTSUPP.
        if bpf(BPF_LINK_UPDATE, &attr) != Some(EOPNOTSUPP) {
            return Err("BPF_LINK_UPDATE on a tracing link did not return EOPNOTSUPP");
        }
        // Unknown flags are refused before anything else is touched.
        let mut flagged = attr;
        put_u32(&mut flagged, 8, 1);
        if bpf(BPF_LINK_UPDATE, &flagged) != Some(EINVAL) {
            return Err("BPF_LINK_UPDATE with an unknown flag did not return EINVAL");
        }
        // A program fd where a link fd belongs.
        let mut wrong = attr;
        put_u32(&mut wrong, 0, a as u32);
        if bpf(BPF_LINK_UPDATE, &wrong) != Some(EINVAL) {
            return Err("BPF_LINK_UPDATE on a program fd did not return EINVAL");
        }
        // An unopened link fd.
        put_u32(&mut wrong, 0, 4095);
        if bpf(BPF_LINK_UPDATE, &wrong) != Some(EBADF) {
            return Err("BPF_LINK_UPDATE on an unopened fd did not return EBADF");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_update_neg);

// ════════════════════════════════════════════════════════════════════
// End-to-end, in the `bpf` subsystem: load through `bpf(2)`, attach through
// `bpf(2)`, fire the real hook, observe the effect, undo it, fire again.
//
// The errno pins above are conformance; these are the ones that would catch an
// attach that reports success and does nothing.
// ════════════════════════════════════════════════════════════════════

/// The `Arc<BpfProg>` behind a program fd, so a test can read `runs()`.
///
/// The same resolution the handler uses. Reaching into the fd table is fair
/// here: these tests run inside the kernel, and the alternative — inferring
/// "did it run" from a side effect — is what lets a test pass for the wrong
/// reason.
fn prog_behind_fd(fd: i64) -> Option<alloc::sync::Arc<narf_bpf::prog::BpfProg>> {
    let ops = fd::with_table(FAKE_TASK, |t| t.get(fd as u32).map(|e| e.ops.clone()))??;
    let file = ops
        .as_any()
        .and_then(|a| a.downcast_ref::<narf_bpf::prog::ProgFile>())?;
    Some(file.prog())
}

fn smoke_bpf_syscall_link_close_detaches_the_probe() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let prog = prog_behind_fd(fd).ok_or("could not recover the program behind its fd")?;
        let probe = fresh_probe();
        let link_fd = bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, probe, BPF_TRACE_FENTRY),
        )
        .ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_LINK_CREATE failed");
        }

        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 1 {
            return Err("the program attached through bpf(2) did not run when the probe fired");
        }

        // Closing the *program* fd must not disturb the attach: the link holds
        // its own `Arc`.
        if call(Syscall::Close.raw(), a0(fd as u64)) != Some(0) {
            return Err("closing the program fd failed");
        }
        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 2 {
            return Err("closing the program fd detached the link");
        }

        // The keystone: closing the link fd is the detach.
        if call(Syscall::Close.raw(), a0(link_fd as u64)) != Some(0) {
            return Err("closing the link fd failed");
        }
        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 2 {
            return Err("the probe still ran the program after the link fd was closed");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_syscall_link_close_detaches_the_probe);

fn smoke_bpf_syscall_prog_attach_fires_then_detach_stops() -> TestResult {
    with_setup(|| {
        let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let prog = prog_behind_fd(fd).ok_or("could not recover the program behind its fd")?;
        let probe = fresh_probe();
        let attr = attach_attr(probe, fd as u32, BPF_TRACE_FENTRY);
        if bpf(BPF_PROG_ATTACH, &attr) != Some(0) {
            return Err("BPF_PROG_ATTACH failed");
        }
        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 1 {
            return Err("the attached program did not run when the probe fired");
        }
        if bpf(BPF_PROG_DETACH, &attr) != Some(0) {
            return Err("BPF_PROG_DETACH failed");
        }
        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 1 {
            return Err("the probe still ran the program after BPF_PROG_DETACH");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_syscall_prog_attach_fires_then_detach_stops);

fn smoke_bpf_syscall_link_close_detaches_xdp() -> TestResult {
    with_setup(|| {
        use narf_net::bypass::classifier::{classify, Verdict};

        // A NIC of this test's own. `iface::register` de-dups by name, so a
        // re-run replaces rather than accumulating.
        const IFACE: &str = "bpf-abi-xdp0";
        fn discard(_frame: &[u8]) -> Result<(), ()> {
            Ok(())
        }
        narf_net::iface::register(IFACE, [0x02, 0, 0, 0, 0xB9, 1], discard);

        // The ifindex NARF's rtnetlink dump would report for it: 1 is the
        // synthetic loopback, registered NICs follow at 2, 3, … in registration
        // order. Deriving it here from the same public source the handler uses
        // is what pins the two together — if the handler resolved a different
        // interface, the classify() below would not see the program at all.
        let ifindex = narf_net::iface::snapshot_all()
            .iter()
            .position(|nic| nic.name == IFACE)
            .map(|i| i as u32 + 2)
            .ok_or("the registered interface is not in the snapshot")?;

        let fd = load_prog(BPF_PROG_TYPE_XDP, &xdp_bounded_byte_program()).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let tracing_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1))
            .ok_or("tracing BPF_PROG_LOAD was not Ok")?;
        if tracing_fd < 0
            || bpf(
                BPF_LINK_CREATE,
                &link_attr(tracing_fd as u32, ifindex, BPF_XDP),
            ) != Some(EINVAL)
        {
            return Err("a tracing program attached to the XDP hook");
        }
        if bpf(
            BPF_LINK_CREATE,
            &link_attr(fd as u32, fresh_probe(), BPF_TRACE_FENTRY),
        ) != Some(EINVAL)
        {
            return Err("an XDP program attached to a tracing hook");
        }
        let _ = call(Syscall::Close.raw(), a0(tracing_fd as u64));
        let link_fd =
            bpf(BPF_LINK_CREATE, &link_attr(fd as u32, ifindex, BPF_XDP)).ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_LINK_CREATE on a registered interface's ifindex failed");
        }

        let mut frame = [0u8; 64];
        frame[12] = 0x11;
        if !matches!(classify(IFACE, &mut frame), Verdict::Dropped) {
            return Err("the linked XDP program did not read and drop the matching frame");
        }
        frame[12] = 0x22;
        if !matches!(classify(IFACE, &mut frame), Verdict::PassThrough) {
            return Err("the bounded XDP read did not distinguish packet bytes");
        }
        if !matches!(classify(IFACE, &mut [0u8; 3]), Verdict::PassThrough) {
            return Err("the XDP data_end guard did not pass a short frame");
        }
        if call(Syscall::Close.raw(), a0(link_fd as u64)) != Some(0) {
            return Err("closing the link fd failed");
        }
        frame[12] = 0x11;
        if !matches!(classify(IFACE, &mut frame), Verdict::PassThrough) {
            return Err("frames were still dropped after the link fd was closed");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_syscall_link_close_detaches_xdp);

// ════════════════════════════════════════════════════════════════════
// The link and BTF id commands — BPF_LINK_GET_NEXT_ID (33) /
// BPF_LINK_GET_FD_BY_ID (32) / BPF_BTF_GET_NEXT_ID (23) /
// BPF_BTF_GET_FD_BY_ID (19), and the `bpf_link_info` / `bpf_btf_info`
// arms of BPF_OBJ_GET_INFO_BY_FD.
//
// The interesting half is id *lifetime*, not the happy path:
//
//  * an fd obtained by id holds its own reference, so the object outlives
//    the fd it was created through;
//  * for a link that reference is also an *attach*, so the id-obtained fd
//    must still detach when it is the last one closed — `BpfLink::drop`
//    exists for exactly that, and
//    `smoke_bpf_syscall_link_by_id_still_detaches` is the pin;
//  * a freed object's id is `ENOENT`, never a dangling handle, and is
//    never handed to a later object.
// ════════════════════════════════════════════════════════════════════

const BPF_BTF_GET_FD_BY_ID: u64 = 19;
const BPF_BTF_GET_NEXT_ID: u64 = 23;

/// `enum bpf_link_type` values NARF can produce.
const BPF_LINK_TYPE_RAW_TRACEPOINT: u32 = 1;
const BPF_LINK_TYPE_TRACING: u32 = 2;
const BPF_LINK_TYPE_XDP: u32 = 6;

// `struct bpf_link_info` field offsets.
const LI_TYPE: usize = 0;
const LI_ID: usize = 4;
const LI_PROG_ID: usize = 8;
/// The union: `tracing.attach_type`, or `xdp.ifindex`.
const LI_UNION: usize = 16;
/// What NARF fills of `struct bpf_link_info` — short of Linux's 64, because
/// every union member NARF can produce ends before it. The truncation contract
/// reports this number back, so a caller compiled against the full struct knows
/// the tail is untouched.
const LINK_INFO_LEN: usize = 32;
const RAW_LINK_INFO_LEN: usize = 40;
const LI_RAW_NAME: usize = 16;
const LI_RAW_NAME_LEN: usize = 24;
const LI_RAW_COOKIE: usize = 32;

// `struct bpf_btf_info` field offsets.
const BI_BTF: usize = 0;
const BI_BTF_SIZE: usize = 8;
const BI_ID: usize = 12;
const BI_NAME: usize = 16;
const BI_NAME_LEN: usize = 24;
const BI_KERNEL_BTF: usize = 28;
/// `sizeof(struct bpf_btf_info)`. Spelled out here rather than imported from
/// `sys_bpf_info.rs`, so a test cannot agree with the implementation by
/// construction while both drift from the uapi header.
const BTF_INFO_LEN: usize = 32;

// `struct { … } btf` offsets within `union bpf_attr`, for BPF_BTF_LOAD.
const BTF_DATA: usize = 0;
const BTF_SIZE: usize = 16;

fn put_info_u32(buf: &mut [u8; INFO_BUF], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

// bpffs — `BPF_OBJ_PIN` (6) and `BPF_OBJ_GET` (7).
//
// Three things are pinned here, in rising order of importance:
//
//  1. the errno vocabulary, positive and negative per command;
//  2. that `OBJ_GET` returns a *working* fd on the *same* object rather than a
//     lookalike — proved by mutating a map through one fd and reading the
//     mutation back through the other, and by running a program through a
//     reopened fd;
//  3. **lifetime** — the object survives the creating fd's close while a pin
//     exists, and is freed when the last pin and fd go. The oracle for "is it
//     still alive" is `BPF_MAP_GET_FD_BY_ID`, because `narf_bpf::idreg` holds
//     `Weak`s and `Drop for BpfMap` prunes its entry: an id whose object has
//     been dropped is `ENOENT`, one whose object lives resolves. That makes
//     "a pin is a strong reference" an observable claim rather than a comment.
// ════════════════════════════════════════════════════════════════════

// `struct { … }` (BPF_OBJ_* commands) offsets within `union bpf_attr`.
const OB_PATHNAME: usize = 0;
const OB_BPF_FD: usize = 8;
const OB_FILE_FLAGS: usize = 12;
const OB_PATH_FD: usize = 16;
/// `offsetofend(union bpf_attr, path_fd)` — where `CHECK_ATTR(BPF_OBJ)` starts
/// demanding zeroes.
const OB_END: usize = 20;

const BPF_F_RDONLY_FLAG: u32 = 1 << 3;
const BPF_F_WRONLY_FLAG: u32 = 1 << 4;
const BPF_F_PATH_FD: u32 = 1 << 14;

/// `F_GETFD`.
const F_GETFD: u64 = 1;

/// A NUL-terminated path in a fixed buffer, so the handler's `copy_user_cstr`
/// sees the shape a real C caller hands it.
struct CPath([u8; 96]);

impl CPath {
    fn new(s: &str) -> Self {
        let mut b = [0u8; 96];
        b[..s.len()].copy_from_slice(s.as_bytes());
        Self(b)
    }
    fn ptr(&self) -> u64 {
        self.0.as_ptr() as u64
    }
}

fn obj_attr(path_ptr: u64, bpf_fd: u32, file_flags: u32, path_fd: u32) -> [u8; ATTR_LEN] {
    let mut a = [0u8; ATTR_LEN];
    put_u64(&mut a, OB_PATHNAME, path_ptr);
    put_u32(&mut a, OB_BPF_FD, bpf_fd);
    put_u32(&mut a, OB_FILE_FLAGS, file_flags);
    put_u32(&mut a, OB_PATH_FD, path_fd);
    a
}

fn obj_pin(fd: i64, path: &CPath) -> Option<i64> {
    bpf(BPF_OBJ_PIN, &obj_attr(path.ptr(), fd as u32, 0, 0))
}

fn obj_get(path: &CPath) -> Option<i64> {
    obj_get_flags(path, 0)
}

fn obj_get_flags(path: &CPath, flags: u32) -> Option<i64> {
    bpf(BPF_OBJ_GET, &obj_attr(path.ptr(), 0, flags, 0))
}

fn obj_pin_at(fd: i64, path: &CPath, path_fd: i64) -> Option<i64> {
    bpf(
        BPF_OBJ_PIN,
        &obj_attr(path.ptr(), fd as u32, BPF_F_PATH_FD, path_fd as u32),
    )
}

fn obj_get_at_flags(path: &CPath, path_fd: i64, flags: u32) -> Option<i64> {
    bpf(
        BPF_OBJ_GET,
        &obj_attr(path.ptr(), 0, flags | BPF_F_PATH_FD, path_fd as u32),
    )
}

/// The smallest well-formed BTF blob: a header, one `BTF_KIND_INT` named
/// "int", and a five-byte string section. The only use here is to obtain a
/// BTF fd.
///
/// Hand-encoded, and a second copy of the one in `abi_bpf_btf_tests.rs`: a
/// fixture shared between two conformance files would let one change move both
/// at once, which is the coupling these ABI files exist to avoid.
fn minimal_btf() -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(&0xeb9fu16.to_le_bytes()); // magic
    v.push(1); // version
    v.push(0); // flags
    v.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
    v.extend_from_slice(&0u32.to_le_bytes()); // type_off
    v.extend_from_slice(&16u32.to_le_bytes()); // type_len
    v.extend_from_slice(&16u32.to_le_bytes()); // str_off
    v.extend_from_slice(&5u32.to_le_bytes()); // str_len
    v.extend_from_slice(&1u32.to_le_bytes()); // btf_type.name_off
    v.extend_from_slice(&(1u32 << 24).to_le_bytes()); // btf_type.info: KIND_INT
    v.extend_from_slice(&4u32.to_le_bytes()); // btf_type.size
    v.extend_from_slice(&32u32.to_le_bytes()); // int_data: 32 bits
    v.extend_from_slice(b"\0int\0");
    v
}

fn btf_load(blob: &[u8]) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u64(&mut attr, BTF_DATA, blob.as_ptr() as u64);
    put_u32(&mut attr, BTF_SIZE, blob.len() as u32);
    call(
        Syscall::Bpf.raw(),
        a2(BPF_BTF_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

/// A link fd on a fresh probe, the program fd behind it, and the probe id.
fn make_link() -> Result<(i64, i64, u32), &'static str> {
    let prog_fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(1)).ok_or("bpf() not Ok")?;
    if prog_fd < 0 {
        return Err("BPF_PROG_LOAD failed");
    }
    let probe = fresh_probe();
    let link_fd = bpf(
        BPF_LINK_CREATE,
        &link_attr(prog_fd as u32, probe, BPF_TRACE_FENTRY),
    )
    .ok_or("bpf() not Ok")?;
    if link_fd < 0 {
        return Err("BPF_LINK_CREATE failed");
    }
    Ok((link_fd, prog_fd, probe))
}

/// A link's `bpf_link_info`, read through the syscall. Also pins the reported
/// length, which is the half of the truncation contract a field-value check
/// would never look at.
fn link_info_of(fd: i64) -> Result<[u8; INFO_BUF], &'static str> {
    let mut info = [0u8; INFO_BUF];
    let (r, back) = obj_info(fd, &mut info, LINK_INFO_LEN as u32);
    if r != Some(0) {
        return Err("BPF_OBJ_GET_INFO_BY_FD failed on a link fd");
    }
    if back != LINK_INFO_LEN as u32 {
        return Err("BPF_OBJ_GET_INFO_BY_FD reported the wrong bpf_link_info length");
    }
    Ok(info)
}

/// A blob's `bpf_btf_info`, with no request to copy the blob out.
fn btf_info_of(fd: i64) -> Result<[u8; INFO_BUF], &'static str> {
    let mut info = [0u8; INFO_BUF];
    let (r, back) = obj_info(fd, &mut info, BTF_INFO_LEN as u32);
    if r != Some(0) {
        return Err("BPF_OBJ_GET_INFO_BY_FD failed on a btf fd");
    }
    if back != BTF_INFO_LEN as u32 {
        return Err("BPF_OBJ_GET_INFO_BY_FD reported the wrong bpf_btf_info length");
    }
    Ok(info)
}

/// `BPF_*_GET_FD_BY_ID`, asserting success and closing the fd it produced.
///
/// For the "does this id still resolve?" checks, where leaving the fd open
/// would change what the *next* assertion is looking at.
fn id_resolves(cmd: u64, id: u32) -> bool {
    match fd_by_id(cmd, id) {
        Some(fd) if fd >= 0 => {
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
            true
        }
        _ => false,
    }
}

// ── BPF_OBJ_GET_INFO_BY_FD: links ───────────────────────────────────

fn smoke_abi_bpf_obj_get_info_link_pos() -> TestResult {
    with_setup(|| {
        let (link_fd, prog_fd, _probe) = make_link()?;
        let prog_id = id_of(prog_fd)?;
        let info = link_info_of(link_fd)?;

        if info_u32(&info, LI_TYPE) != BPF_LINK_TYPE_TRACING {
            return Err("a probe link did not report BPF_LINK_TYPE_TRACING");
        }
        if info_u32(&info, LI_ID) == 0 {
            return Err("a live link reported id 0, which means 'no link'");
        }
        if info_u32(&info, LI_PROG_ID) != prog_id {
            return Err("bpf_link_info.prog_id is not the id of the attached program");
        }
        if info_u32(&info, LI_UNION) != BPF_TRACE_FENTRY {
            return Err("bpf_link_info.tracing.attach_type is not BPF_TRACE_FENTRY");
        }

        // A detached link keeps its fd and its id but reports no program:
        // saying otherwise would claim an attach that is gone.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, link_fd as u32);
        if bpf(BPF_LINK_DETACH, &attr) != Some(0) {
            return Err("BPF_LINK_DETACH failed");
        }
        let info = link_info_of(link_fd)?;
        if info_u32(&info, LI_PROG_ID) != 0 {
            return Err("a detached link still reports a prog_id");
        }
        if info_u32(&info, LI_ID) == 0 {
            return Err("a detached link lost its id");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_get_info_link_pos);

/// `BPF_OBJ_GET_INFO_BY_FD` picks its info struct from the *object*, not from
/// the length the caller asked for.
///
/// A caller compiled for `bpf_prog_info` that hands over a link fd must get
/// link info truncated to what NARF fills, and be told so — not 232 bytes of
/// program-shaped nonsense. This is the assertion that catches the four
/// downcast arms being tried in an order that lets one shadow another.
fn smoke_abi_bpf_obj_get_info_dispatches_on_object_neg() -> TestResult {
    with_setup(|| {
        let (link_fd, prog_fd, _probe) = make_link()?;
        let blob = minimal_btf();
        let btf_fd = btf_load(&blob).ok_or("bpf() not Ok")?;
        if btf_fd < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }

        let mut info = [0u8; INFO_BUF];
        let (r, back) = obj_info(link_fd, &mut info, PROG_INFO_LEN as u32);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD on a link fd with a prog-sized buffer failed");
        }
        if back != LINK_INFO_LEN as u32 {
            return Err("a link fd answered with a program-sized info struct");
        }

        let mut info = [0u8; INFO_BUF];
        let (r, back) = obj_info(btf_fd, &mut info, MAP_INFO_LEN as u32);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD on a btf fd with a map-sized buffer failed");
        }
        if back != BTF_INFO_LEN as u32 {
            return Err("a btf fd answered with a map-sized info struct");
        }

        let _ = call(Syscall::Close.raw(), a0(btf_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_obj_get_info_dispatches_on_object_neg
);

// ── BPF_OBJ_GET_INFO_BY_FD: BTF ─────────────────────────────────────

fn smoke_abi_bpf_obj_get_info_btf_pos() -> TestResult {
    with_setup(|| {
        let blob = minimal_btf();
        let fd = btf_load(&blob).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }

        // Capacity 0 — the size probe every loader does first. Nothing is
        // written to the (absent) buffer and the true size comes back.
        let info = btf_info_of(fd)?;
        if info_u32(&info, BI_BTF_SIZE) as usize != blob.len() {
            return Err("bpf_btf_info.btf_size is not the blob's true size");
        }
        if info_u32(&info, BI_ID) == 0 {
            return Err("a loaded blob reported id 0, which means 'no BTF'");
        }
        if info_u32(&info, BI_KERNEL_BTF) != 0 {
            return Err("a userspace-loaded blob claimed to be kernel BTF");
        }
        // LINUX-GAP: NARF records no BTF name, so `name_len` is 0 and the
        // caller's name buffer is left untouched rather than invented.
        if info_u32(&info, BI_NAME_LEN) != 0 {
            return Err("bpf_btf_info.name_len is not 0");
        }

        // The copy-out, which is how `bpftool btf dump` reads a blob.
        let mut sink = [0xAAu8; 64];
        let mut info = [0u8; INFO_BUF];
        put_info_u64(&mut info, BI_BTF, sink.as_mut_ptr() as u64);
        put_info_u32(&mut info, BI_BTF_SIZE, sink.len() as u32);
        let (r, _) = obj_info(fd, &mut info, BTF_INFO_LEN as u32);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD with a btf buffer failed");
        }
        if info_u32(&info, BI_BTF_SIZE) as usize != blob.len() {
            return Err("the copy-out call did not report the blob's true size");
        }
        if info_u64(&info, BI_BTF) != sink.as_mut_ptr() as u64 {
            return Err("bpf_btf_info.btf was not echoed back");
        }
        if sink[..blob.len()] != blob[..] {
            return Err("the blob copied out is not the blob that was loaded");
        }
        if sink[blob.len()..].iter().any(|b| *b != 0xAA) {
            return Err("the copy-out wrote past the blob's own length");
        }

        // A capacity smaller than the blob truncates rather than overruns, and
        // still reports the true size so the caller can size a buffer and retry.
        let mut sink = [0xAAu8; 64];
        let mut info = [0u8; INFO_BUF];
        put_info_u64(&mut info, BI_BTF, sink.as_mut_ptr() as u64);
        put_info_u32(&mut info, BI_BTF_SIZE, 8);
        let (r, _) = obj_info(fd, &mut info, BTF_INFO_LEN as u32);
        if r != Some(0) {
            return Err("BPF_OBJ_GET_INFO_BY_FD with a short btf buffer failed");
        }
        if info_u32(&info, BI_BTF_SIZE) as usize != blob.len() {
            return Err("a short copy-out did not report the blob's true size");
        }
        if sink[..8] != blob[..8] {
            return Err("a short copy-out did not write the leading bytes");
        }
        if sink[8..].iter().any(|b| *b != 0xAA) {
            return Err("a short copy-out wrote past the capacity the caller declared");
        }
        // The name pointer is echoed but never followed, since `name_len` is 0.
        if info_u64(&info, BI_NAME) != 0 {
            return Err("bpf_btf_info.name was not echoed back unchanged");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_get_info_btf_pos);

// ── BPF_LINK_GET_FD_BY_ID / BPF_LINK_GET_NEXT_ID ────────────────────

fn smoke_abi_bpf_link_get_fd_by_id_pos() -> TestResult {
    with_setup(|| {
        let (link_fd, prog_fd, _probe) = make_link()?;
        let id = info_u32(&link_info_of(link_fd)?, LI_ID);

        let fd2 = fd_by_id(BPF_LINK_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
        if fd2 < 0 {
            return Err("BPF_LINK_GET_FD_BY_ID failed for a live link");
        }
        if fd2 == link_fd {
            return Err("BPF_LINK_GET_FD_BY_ID handed back the same fd, not a new one");
        }
        let info = link_info_of(fd2)?;
        if info_u32(&info, LI_ID) != id {
            return Err("the fd obtained by id names a different link");
        }
        if info_u32(&info, LI_TYPE) != BPF_LINK_TYPE_TRACING {
            return Err("the fd obtained by id reports the wrong link type");
        }
        // Linux sets close-on-exec on every bpf fd, this one included — and a
        // leaked link fd is a leaked *attach*.
        let flags = call(Syscall::Fcntl.raw(), a2(fd2 as u64, 1, 0)).ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("BPF_LINK_GET_FD_BY_ID did not set close-on-exec");
        }
        // The id-obtained fd is a full link fd, not a read-only view: it must
        // answer the link commands too.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 0, fd2 as u32);
        if bpf(BPF_LINK_DETACH, &attr) != Some(0) {
            return Err("BPF_LINK_DETACH through an id-obtained link fd failed");
        }
        let _ = call(Syscall::Close.raw(), a0(fd2 as u64));
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_get_fd_by_id_pos);

fn smoke_abi_bpf_link_get_next_id_pos() -> TestResult {
    with_setup(|| {
        let (link_fd, prog_fd, _probe) = make_link()?;
        let want = info_u32(&link_info_of(link_fd)?, LI_ID);

        // A walk from 0 must reach the link just made, and must terminate. The
        // step bound is generous but finite: an id table that never says ENOENT
        // is an infinite loop in every enumerating tool.
        let mut cur = 0u32;
        let mut found = false;
        let mut steps = 0;
        loop {
            let (r, id) = next_id(BPF_LINK_GET_NEXT_ID, cur);
            if r == Some(ENOENT) {
                break;
            }
            if r != Some(0) {
                return Err("BPF_LINK_GET_NEXT_ID returned neither 0 nor ENOENT");
            }
            if id <= cur {
                return Err("BPF_LINK_GET_NEXT_ID did not advance strictly — a walk would loop");
            }
            if id == want {
                found = true;
            }
            cur = id;
            steps += 1;
            if steps > 100_000 {
                return Err("BPF_LINK_GET_NEXT_ID never terminated");
            }
        }
        if !found {
            return Err("a freshly created link was not reachable by BPF_LINK_GET_NEXT_ID");
        }
        // "Strictly greater" is what makes feeding each answer back in
        // terminate rather than repeat.
        let (r, id) = next_id(BPF_LINK_GET_NEXT_ID, want);
        if r == Some(0) && id == want {
            return Err("BPF_LINK_GET_NEXT_ID returned the id it was given");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_link_get_next_id_pos);

/// A link's id stops resolving once its last fd closes, and is never reused.
///
/// Stronger here than for a map: an entry that kept a link alive would keep its
/// *attach* alive too, because `BpfLink::drop` is the only thing that undoes
/// one — so a leaked id entry is a hook armed for the rest of the boot.
fn smoke_abi_bpf_link_id_not_reused_after_teardown_neg() -> TestResult {
    with_setup(|| {
        let (link_fd, prog_fd, _probe) = make_link()?;
        let dead = info_u32(&link_info_of(link_fd)?, LI_ID);
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));

        if fd_by_id(BPF_LINK_GET_FD_BY_ID, dead) != Some(ENOENT) {
            return Err("BPF_LINK_GET_FD_BY_ID resolved a link whose last fd was closed");
        }
        // …and the walk no longer visits it.
        let (r, id) = next_id(BPF_LINK_GET_NEXT_ID, dead - 1);
        if r == Some(0) && id == dead {
            return Err("BPF_LINK_GET_NEXT_ID still walks over a freed link's id");
        }

        let (link2, prog2, _p2) = make_link()?;
        let fresh = info_u32(&link_info_of(link2)?, LI_ID);
        if fresh == dead {
            return Err("a freed link's id was reused — a cached id now names a different attach");
        }
        if fresh < dead {
            return Err("link ids went backwards");
        }
        let _ = call(Syscall::Close.raw(), a0(link2 as u64));
        let _ = call(Syscall::Close.raw(), a0(prog2 as u64));
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_link_id_not_reused_after_teardown_neg
);

// ── BPF_BTF_GET_FD_BY_ID / BPF_BTF_GET_NEXT_ID ──────────────────────

fn smoke_abi_bpf_btf_get_fd_by_id_pos() -> TestResult {
    with_setup(|| {
        let blob = minimal_btf();
        let fd = btf_load(&blob).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }
        let id = info_u32(&btf_info_of(fd)?, BI_ID);

        let fd2 = fd_by_id(BPF_BTF_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
        if fd2 < 0 {
            return Err("BPF_BTF_GET_FD_BY_ID failed for a live blob");
        }
        if fd2 == fd {
            return Err("BPF_BTF_GET_FD_BY_ID handed back the same fd, not a new one");
        }
        if info_u32(&btf_info_of(fd2)?, BI_ID) != id {
            return Err("the fd obtained by id names a different blob");
        }
        let flags = call(Syscall::Fcntl.raw(), a2(fd2 as u64, 1, 0)).ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("BPF_BTF_GET_FD_BY_ID did not set close-on-exec");
        }

        // A walk must reach it, and must terminate.
        let mut cur = 0u32;
        let mut found = false;
        let mut steps = 0;
        loop {
            let (r, got) = next_id(BPF_BTF_GET_NEXT_ID, cur);
            if r == Some(ENOENT) {
                break;
            }
            if r != Some(0) {
                return Err("BPF_BTF_GET_NEXT_ID returned neither 0 nor ENOENT");
            }
            if got <= cur {
                return Err("BPF_BTF_GET_NEXT_ID did not advance strictly");
            }
            if got == id {
                found = true;
            }
            cur = got;
            steps += 1;
            if steps > 100_000 {
                return Err("BPF_BTF_GET_NEXT_ID never terminated");
            }
        }
        if !found {
            return Err("a freshly loaded blob was not reachable by BPF_BTF_GET_NEXT_ID");
        }
        let _ = call(Syscall::Close.raw(), a0(fd2 as u64));
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_get_fd_by_id_pos);

/// An fd obtained by id holds its own reference to the blob, and the id stops
/// resolving only when the last one goes.
///
/// `live_btf_count` counts blobs rather than fds, so it distinguishes "the
/// second handle kept the one allocation" from "the second handle leaked a
/// second copy" — a distinction an id-only check cannot make.
fn smoke_abi_bpf_btf_fd_by_id_keeps_blob_alive_pos() -> TestResult {
    with_setup(|| {
        let before = crate::handlers::live_btf_count();
        let blob = minimal_btf();
        let fd = btf_load(&blob).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }
        let id = info_u32(&btf_info_of(fd)?, BI_ID);
        let fd2 = fd_by_id(BPF_BTF_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
        if fd2 < 0 {
            return Err("BPF_BTF_GET_FD_BY_ID failed");
        }
        if crate::handlers::live_btf_count() != before + 1 {
            return Err("a second fd on one blob was counted as a second blob");
        }

        // Drop the loading fd. Everything below runs against `fd2` alone.
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        if crate::handlers::live_btf_count() != before + 1 {
            return Err("closing the loading fd freed a blob another fd still holds");
        }
        let info = btf_info_of(fd2)?;
        if info_u32(&info, BI_ID) != id {
            return Err("the id-obtained fd stopped naming its blob once the loading fd closed");
        }
        if info_u32(&info, BI_BTF_SIZE) as usize != blob.len() {
            return Err("the id-obtained fd reports the wrong blob size");
        }
        if !id_resolves(BPF_BTF_GET_FD_BY_ID, id) {
            return Err("the id stopped resolving while an id-obtained fd was still open");
        }

        // Now the last one.
        let _ = call(Syscall::Close.raw(), a0(fd2 as u64));
        if crate::handlers::live_btf_count() != before {
            return Err("closing every fd on a blob did not free it");
        }
        if fd_by_id(BPF_BTF_GET_FD_BY_ID, id) != Some(ENOENT) {
            return Err("a blob's id still resolved after its last reference went away");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_btf_fd_by_id_keeps_blob_alive_pos
);

/// The teardown half for BTF, and the "never reused" half.
///
/// The `btf_ids().len()` check is the part that rots silently. A registry entry
/// left behind after the blob dies still answers `get` with `None`, so every
/// errno above stays right while the table grows one dead slot per blob the
/// boot ever loaded — and pins the `Arc` control block with it. Nothing
/// observable through the syscall can see that, so the test reaches into the
/// table directly.
fn smoke_abi_bpf_btf_id_not_reused_after_teardown_neg() -> TestResult {
    with_setup(|| {
        let blob = minimal_btf();
        let entries_before = crate::handlers::btf_ids().len();
        let fd = btf_load(&blob).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }
        if crate::handlers::btf_ids().len() != entries_before + 1 {
            return Err("loading a blob did not add an id entry");
        }
        let dead = info_u32(&btf_info_of(fd)?, BI_ID);
        let _ = call(Syscall::Close.raw(), a0(fd as u64));

        if crate::handlers::btf_ids().len() != entries_before {
            return Err("freeing a blob did not prune its id entry — the table leaks a slot");
        }
        if fd_by_id(BPF_BTF_GET_FD_BY_ID, dead) != Some(ENOENT) {
            return Err("BPF_BTF_GET_FD_BY_ID resolved a blob whose last fd was closed");
        }
        let (r, id) = next_id(BPF_BTF_GET_NEXT_ID, dead - 1);
        if r == Some(0) && id == dead {
            return Err("BPF_BTF_GET_NEXT_ID still walks over a freed blob's id");
        }

        let again = btf_load(&blob).ok_or("bpf() not Ok")?;
        if again < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }
        let fresh = info_u32(&btf_info_of(again)?, BI_ID);
        if fresh == dead {
            return Err("a freed blob's id was reused — a cached id now names a different blob");
        }
        if fresh < dead {
            return Err("btf ids went backwards");
        }
        let _ = call(Syscall::Close.raw(), a0(again as u64));
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_bpf_btf_id_not_reused_after_teardown_neg
);

fn smoke_abi_bpf_btf_id_cmds_neg() -> TestResult {
    with_setup(|| {
        // Id 0 is never assigned — the counter starts at 1, and 0 means "no
        // BTF" everywhere in the ABI.
        if fd_by_id(BPF_BTF_GET_FD_BY_ID, 0) != Some(ENOENT) {
            return Err("BPF_BTF_GET_FD_BY_ID(0) did not return ENOENT");
        }
        if fd_by_id(BPF_BTF_GET_FD_BY_ID, u32::MAX) != Some(ENOENT) {
            return Err("BPF_BTF_GET_FD_BY_ID on an unassigned id did not return ENOENT");
        }
        if next_id(BPF_BTF_GET_NEXT_ID, u32::MAX).0 != Some(ENOENT) {
            return Err("BPF_BTF_GET_NEXT_ID past the end did not return ENOENT");
        }
        // A `bpf_attr` shorter than the command's own fields.
        let mut attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_GET_FD_BY_ID, attr.as_mut_ptr() as u64, 2),
        ) != Some(EINVAL)
        {
            return Err("BPF_BTF_GET_FD_BY_ID with a truncated bpf_attr did not return EINVAL");
        }
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_GET_NEXT_ID, attr.as_mut_ptr() as u64, 4),
        ) != Some(EINVAL)
        {
            return Err("BPF_BTF_GET_NEXT_ID with a truncated bpf_attr did not return EINVAL");
        }
        // `CHECK_ATTR`: `BPF_BTF_GET_FD_BY_ID_LAST_FIELD` is `btf_id`, so a
        // blob fd takes no `open_flags` either.
        let mut attr = [0u8; ATTR_LEN];
        put_u32(&mut attr, 8, 1);
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_BTF_GET_FD_BY_ID,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_BTF_GET_FD_BY_ID ignored a non-zero byte past its last field");
        }
        if call(
            Syscall::Bpf.raw(),
            a2(
                BPF_BTF_GET_NEXT_ID,
                attr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        ) != Some(EINVAL)
        {
            return Err("BPF_BTF_GET_NEXT_ID ignored a non-zero byte past its last field");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_id_cmds_neg);

/// The keystone: a link fetched by id still **detaches on close**.
///
/// In the `bpf` group rather than `syscall_abi` because it fires the real probe
/// dispatcher — the only way to tell "the attach is still installed" from "the
/// fd still exists". An id-obtained link fd that did not run `BpfLink::drop`
/// would leave the hook armed for the rest of the boot with no handle left to
/// undo it, and every errno above would still be right.
fn smoke_bpf_syscall_link_by_id_still_detaches() -> TestResult {
    with_setup(|| {
        let (link_fd, prog_fd, probe) = make_link()?;
        let prog = prog_behind_fd(prog_fd).ok_or("could not recover the program behind its fd")?;
        let id = info_u32(&link_info_of(link_fd)?, LI_ID);

        let by_id = fd_by_id(BPF_LINK_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
        if by_id < 0 {
            return Err("BPF_LINK_GET_FD_BY_ID failed for a live link");
        }
        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 1 {
            return Err("the linked program did not run when the probe fired");
        }

        // Close the fd the link was created through. The attach must survive,
        // because the id-obtained fd is an owner in its own right — that is the
        // whole promise of GET_FD_BY_ID.
        if call(Syscall::Close.raw(), a0(link_fd as u64)) != Some(0) {
            return Err("closing the creating link fd failed");
        }
        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 2 {
            return Err("closing the creating fd detached a link another fd still held");
        }
        if !id_resolves(BPF_LINK_GET_FD_BY_ID, id) {
            return Err("the link's id stopped resolving while an fd still held it");
        }

        // The keystone: the last close is the detach, whichever fd it came
        // through.
        if call(Syscall::Close.raw(), a0(by_id as u64)) != Some(0) {
            return Err("closing the id-obtained link fd failed");
        }
        narf_tracing::dispatch::fire(probe, narf_tracing::dispatch::ProbeArgs::none());
        if prog.runs() != 2 {
            return Err("closing the id-obtained link fd did not detach the probe");
        }
        if fd_by_id(BPF_LINK_GET_FD_BY_ID, id) != Some(ENOENT) {
            return Err("the link's id still resolved after its last fd closed");
        }
        let _ = call(Syscall::Close.raw(), a0(prog_fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_syscall_link_by_id_still_detaches);

/// `bpf_link_info` for an XDP link, including the ifindex round-trip.
///
/// In the `bpf` group because it needs a registered interface. The ifindex is
/// derived here from `iface::snapshot_all` the way `netlink_route`'s dump
/// derives it, so this pins `sys_bpf_attach.rs`'s `ifindex_for_iface` against
/// the same public source its inverse consumes — the cross-crate convention
/// that would otherwise stay correct-looking after the other side changed.
fn smoke_bpf_syscall_link_info_xdp() -> TestResult {
    with_setup(|| {
        const IFACE: &str = "bpf-abi-xdp1";
        fn discard(_frame: &[u8]) -> Result<(), ()> {
            Ok(())
        }
        narf_net::iface::register(IFACE, [0x02, 0, 0, 0, 0xB9, 2], discard);
        let ifindex = narf_net::iface::snapshot_all()
            .iter()
            .position(|nic| nic.name == IFACE)
            .map(|i| i as u32 + 2)
            .ok_or("the registered interface is not in the snapshot")?;

        let fd = load_prog(BPF_PROG_TYPE_XDP, &ret_imm(1)).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_PROG_LOAD rejected a trivial program");
        }
        let link_fd =
            bpf(BPF_LINK_CREATE, &link_attr(fd as u32, ifindex, BPF_XDP)).ok_or("bpf() not Ok")?;
        if link_fd < 0 {
            return Err("BPF_LINK_CREATE on a registered interface's ifindex failed");
        }
        let info = link_info_of(link_fd)?;
        if info_u32(&info, LI_TYPE) != BPF_LINK_TYPE_XDP {
            return Err("an XDP link did not report BPF_LINK_TYPE_XDP");
        }
        if info_u32(&info, LI_UNION) != ifindex {
            return Err("bpf_link_info.xdp.ifindex is not the ifindex the link was created with");
        }
        if info_u32(&info, LI_PROG_ID) != id_of(fd)? {
            return Err("an XDP link reports the wrong prog_id");
        }
        // Reachable by id, like any other link.
        let id = info_u32(&info, LI_ID);
        if !id_resolves(BPF_LINK_GET_FD_BY_ID, id) {
            return Err("an XDP link was not reachable by BPF_LINK_GET_FD_BY_ID");
        }
        let _ = call(Syscall::Close.raw(), a0(link_fd as u64));
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_syscall_link_info_xdp);
/// The mount authority every bpffs test mount is created under.
///
/// Minted once and cached: `Cap::bootstrap()` allocates an object-table slot
/// per call, so a per-test `bootstrap_mount_authority()` would leak one slot
/// per smoke. `registry().mount_arc` runs `check_live()` on it at every use,
/// which is the part that proves the grant is still valid — possession alone
/// proves only that it was granted once.
fn mount_authority() -> &'static Cap<MountPoint, Grant> {
    use narf_lib::sync::IrqSafeSpinLock;
    static SLOT: IrqSafeSpinLock<Option<&'static Cap<MountPoint, Grant>>> =
        IrqSafeSpinLock::new(None);
    let mut g = SLOT.lock();
    if g.is_none() {
        let c: &'static _ =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(bootstrap_mount_authority()));
        *g = Some(c);
    }
    g.expect("just installed")
}

type MountHandle = Cap<MountPoint, narf_capabilities::Write>;

/// Mount a private bpffs at `at`. Every test uses its own path and unmounts
/// before returning, so no smoke can see another's pins.
fn mount_bpffs(at: &str) -> Option<MountHandle> {
    registry()
        .mount_arc(
            mount_authority(),
            at,
            alloc::sync::Arc::new(narf_filesystem::bpffs::BpfFs::new()),
        )
        .ok()
}

fn mount_tmpfs(at: &str) -> Option<MountHandle> {
    registry()
        .mount_arc(
            mount_authority(),
            at,
            alloc::sync::Arc::new(MemFs::new("tmpfs")),
        )
        .ok()
}

/// Run `body` with a bpffs mounted at `at`, unmounting whatever the outcome.
fn with_bpffs(
    at: &str,
    body: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    let handle = mount_bpffs(at).ok_or("mounting bpffs failed")?;
    let outcome = body();
    let _ = registry().unmount(&handle, at);
    outcome
}

// ── BPF_OBJ_PIN / BPF_OBJ_GET: positive ─────────────────────────────

fn smoke_abi_bpf_obj_pin_pos() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-pin-pos";
        with_bpffs(AT, || {
            let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_MAP_CREATE failed");
            }
            let path = CPath::new("/bpf-pin-pos/m");
            if obj_pin(fd, &path) != Some(0) {
                return Err("BPF_OBJ_PIN of a map into bpffs failed");
            }
            let reopened = obj_get(&path).ok_or("bpf() not Ok")?;
            if reopened < 0 {
                return Err("BPF_OBJ_GET of a live pin failed");
            }
            if reopened == fd {
                return Err("BPF_OBJ_GET returned the caller's own fd, not a new one");
            }
            // Linux's `bpf_map_new_fd` passes `O_CLOEXEC`: a leaked bpf fd is a
            // leaked capability, and `OBJ_GET` is a way to obtain one.
            let flags = call(Syscall::Fcntl.raw(), a2(reopened as u64, F_GETFD, 0))
                .ok_or("fcntl not Ok")?;
            if flags & 1 == 0 {
                return Err("the fd from BPF_OBJ_GET is not close-on-exec");
            }

            // The same object, not a lookalike: write through one fd and read
            // the write back through the other. An implementation that pinned a
            // *copy* passes every errno check above and fails here.
            let key: u32 = 2;
            let kptr = (&key) as *const u32 as u64;
            let value: u64 = 0xFEED_FACE_C0DE_1234;
            let vptr = (&value) as *const u64 as u64;
            if elem(BPF_MAP_UPDATE_ELEM, fd, kptr, vptr, BPF_ANY) != Some(0) {
                return Err("update through the original fd failed");
            }
            let mut back: u64 = 0;
            let bptr = (&mut back) as *mut u64 as u64;
            if elem(BPF_MAP_LOOKUP_ELEM, reopened, kptr, bptr, 0) != Some(0) {
                return Err("lookup through the reopened fd failed");
            }
            if back != value {
                return Err("the reopened fd addressed a different map");
            }
            let ro = obj_get_flags(&path, BPF_F_RDONLY_FLAG)
                .ok_or("read-only BPF_OBJ_GET was not Ok")?;
            let wo = obj_get_flags(&path, BPF_F_WRONLY_FLAG)
                .ok_or("write-only BPF_OBJ_GET was not Ok")?;
            if ro < 0 || wo < 0 {
                return Err("BPF_OBJ_GET refused a map access mode");
            }
            if elem(BPF_MAP_LOOKUP_ELEM, ro, kptr, bptr, 0) != Some(0)
                || elem(BPF_MAP_UPDATE_ELEM, ro, kptr, vptr, BPF_ANY) != Some(-1)
                || elem(BPF_MAP_LOOKUP_ELEM, wo, kptr, bptr, 0) != Some(-1)
            {
                return Err("BPF_OBJ_GET did not enforce its requested access mode");
            }
            let replacement = 0x1020_3040_5060_7080u64;
            if elem(
                BPF_MAP_UPDATE_ELEM,
                wo,
                kptr,
                (&replacement) as *const u64 as u64,
                BPF_ANY,
            ) != Some(0)
                || elem(BPF_MAP_LOOKUP_ELEM, reopened, kptr, bptr, 0) != Some(0)
                || back != replacement
            {
                return Err("restricted BPF_OBJ_GET fds did not share the pinned map");
            }
            // The ids agree too — the strongest single statement that one
            // object wears both fds.
            if map_id_of(fd)? != map_id_of(reopened)? {
                return Err("the reopened fd reports a different map id");
            }

            let _ = call(Syscall::Close.raw(), a0(ro as u64));
            let _ = call(Syscall::Close.raw(), a0(wo as u64));
            let _ = call(Syscall::Close.raw(), a0(reopened as u64));
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_pin_pos);

/// `BPF_F_PATH_FD` gives both object commands openat(2)-style anchoring.
///
/// The absolute-path case is load-bearing too: Linux ignores the selected fd
/// for an absolute pathname, so eagerly validating `path_fd` would reject a
/// request that `user_path_at` accepts.
fn smoke_abi_bpf_obj_path_fd_pos() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-path-fd";
        const O_DIRECTORY: u64 = 0o200000;
        with_bpffs(AT, || {
            let root = CPath::new(AT);
            let dir_fd = call_open(root.ptr(), O_DIRECTORY).ok_or("open directory not Ok")?;
            if dir_fd < 0 {
                return Err("opening bpffs as a directory fd failed");
            }
            let map_fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
            if map_fd < 0 {
                return Err("BPF_MAP_CREATE failed");
            }

            let relative = CPath::new("m");
            if obj_get_at_flags(&relative, map_fd, 0) != Some(ENOTDIR) {
                return Err("BPF_OBJ_GET with a non-directory path_fd was not ENOTDIR");
            }
            if obj_pin_at(map_fd, &relative, dir_fd) != Some(0) {
                return Err("BPF_OBJ_PIN did not resolve a relative path under path_fd");
            }

            let absolute = CPath::new("/bpf-path-fd/m");
            let by_absolute = obj_get(&absolute).ok_or("absolute BPF_OBJ_GET not Ok")?;
            let by_relative = obj_get_at_flags(&relative, dir_fd, BPF_F_RDONLY_FLAG)
                .ok_or("relative BPF_OBJ_GET not Ok")?;
            if by_absolute < 0 || by_relative < 0 {
                return Err("a path-fd pin could not be reopened");
            }
            if map_id_of(map_fd)? != map_id_of(by_absolute)?
                || map_id_of(map_fd)? != map_id_of(by_relative)?
            {
                return Err("path-fd operations did not address the pinned map");
            }

            // Access-mode flags compose with PATH_FD rather than changing its
            // resolution. The relative descriptor above is read-only.
            let key = 0u32;
            let value = 7u64;
            let mut out = 0u64;
            if elem(
                BPF_MAP_UPDATE_ELEM,
                map_fd,
                (&key) as *const u32 as u64,
                (&value) as *const u64 as u64,
                BPF_ANY,
            ) != Some(0)
                || elem(
                    BPF_MAP_LOOKUP_ELEM,
                    by_relative,
                    (&key) as *const u32 as u64,
                    (&mut out) as *mut u64 as u64,
                    0,
                ) != Some(0)
                || out != value
                || elem(
                    BPF_MAP_UPDATE_ELEM,
                    by_relative,
                    (&key) as *const u32 as u64,
                    (&value) as *const u64 as u64,
                    BPF_ANY,
                ) != Some(EPERM)
            {
                return Err("PATH_FD did not compose with a read-only map reopen");
            }

            // openat(2) semantics: an absolute pathname does not consult its
            // dirfd, even when the caller supplied BPF_F_PATH_FD.
            let ignored_bad_fd = obj_get_at_flags(&absolute, 4095, 0)
                .ok_or("absolute path-fd BPF_OBJ_GET not Ok")?;
            if ignored_bad_fd < 0 || map_id_of(ignored_bad_fd)? != map_id_of(map_fd)? {
                return Err("an absolute BPF_OBJ_GET incorrectly consulted path_fd");
            }

            let _ = call(Syscall::Close.raw(), a0(ignored_bad_fd as u64));
            let _ = call(Syscall::Close.raw(), a0(by_relative as u64));
            let _ = call(Syscall::Close.raw(), a0(by_absolute as u64));
            let _ = call(Syscall::Close.raw(), a0(map_fd as u64));
            let _ = call(Syscall::Close.raw(), a0(dir_fd as u64));
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_path_fd_pos);

/// A program is pinnable too, and one reopened by path still *runs* — an fd
/// that resolved to the right object but a broken image would pass every check
/// in the map test above.
fn smoke_abi_bpf_obj_pin_prog_pos() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-pin-prog-pos";
        with_bpffs(AT, || {
            let fd = load_prog(BPF_PROG_TYPE_TRACING, &ret_imm(0x5A)).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_PROG_LOAD failed");
            }
            let path = CPath::new("/bpf-pin-prog-pos/p");
            if obj_pin(fd, &path) != Some(0) {
                return Err("BPF_OBJ_PIN of a program failed");
            }
            // Close the creating fd: from here the pin is the only reference.
            if call(Syscall::Close.raw(), a0(fd as u64)) != Some(0) {
                return Err("closing the program fd failed");
            }
            // Linux accepts an access flag here but program fds do not carry
            // map element permissions; the reopened program remains runnable.
            let reopened = obj_get_flags(&path, BPF_F_RDONLY_FLAG).ok_or("bpf() not Ok")?;
            if reopened < 0 {
                return Err("BPF_OBJ_GET failed after the creating fd was closed");
            }
            let mut attr = [0u8; ATTR_LEN];
            put_u32(&mut attr, 0, reopened as u32);
            if call(
                Syscall::Bpf.raw(),
                a2(BPF_PROG_TEST_RUN, attr.as_ptr() as u64, ATTR_LEN as u64),
            ) != Some(0)
            {
                return Err("BPF_PROG_TEST_RUN on a reopened program fd failed");
            }
            if get_u32(&attr, 4) != 0x5A {
                return Err("the reopened program returned the wrong value");
            }
            let _ = call(Syscall::Close.raw(), a0(reopened as u64));
            Ok(())
        })
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_pin_prog_pos);

// ── BPF_OBJ_PIN: negative ───────────────────────────────────────────

fn smoke_abi_bpf_obj_pin_neg() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-pin-neg";
        const TMP: &str = "/bpf-pin-neg-tmp";
        let tmp = mount_tmpfs(TMP).ok_or("mounting the control tmpfs failed")?;
        let outcome = with_bpffs(AT, || {
            let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_MAP_CREATE failed");
            }
            let good = CPath::new("/bpf-pin-neg/m");

            // Attribute-block shape.
            if call(Syscall::Bpf.raw(), a2(BPF_OBJ_PIN, 0, ATTR_LEN as u64)) != Some(EINVAL) {
                return Err("BPF_OBJ_PIN with a null attr did not return EINVAL");
            }
            let attr = obj_attr(good.ptr(), fd as u32, 0, 0);
            if call(Syscall::Bpf.raw(), a2(BPF_OBJ_PIN, attr.as_ptr() as u64, 0)) != Some(EINVAL) {
                return Err("BPF_OBJ_PIN with size 0 did not return EINVAL");
            }
            if call(
                Syscall::Bpf.raw(),
                a2(BPF_OBJ_PIN, attr.as_ptr() as u64, OB_BPF_FD as u64),
            ) != Some(EINVAL)
            {
                return Err("BPF_OBJ_PIN with a truncated bpf_attr did not return EINVAL");
            }

            // The fd, checked before the path — `bpf_obj_pin_user` resolves the
            // object first, so a caller probing with a bad fd hears about it.
            if bpf(BPF_OBJ_PIN, &obj_attr(good.ptr(), 4095, 0, 0)) != Some(EBADF) {
                return Err("BPF_OBJ_PIN with an unopened fd did not return EBADF");
            }
            let mut pipefds = [0u8; 8];
            let _ = call(Syscall::Pipe.raw(), a0(pipefds.as_mut_ptr() as u64));
            let readfd = u32::from_le_bytes([pipefds[0], pipefds[1], pipefds[2], pipefds[3]]);
            if bpf(BPF_OBJ_PIN, &obj_attr(good.ptr(), readfd, 0, 0)) != Some(EINVAL) {
                return Err("BPF_OBJ_PIN of a non-BPF fd did not return EINVAL");
            }
            // A BTF fd is NOT pinnable: Linux's `bpf_fd_probe_obj` tries
            // program, map and link only, so it answers EINVAL here as well.
            // The bar this clears is a `is_pinnable` written as "anything with
            // an `as_any`", which every BPF fd wrapper has.
            let blob = minimal_btf();
            let mut btf_attr = [0u8; ATTR_LEN];
            put_u64(&mut btf_attr, 0, blob.as_ptr() as u64);
            put_u32(&mut btf_attr, 16, blob.len() as u32);
            let btf = bpf(BPF_BTF_LOAD, &btf_attr).ok_or("bpf() not Ok")?;
            if btf < 0 {
                return Err("BPF_BTF_LOAD rejected a minimal blob");
            }
            if bpf(BPF_OBJ_PIN, &obj_attr(good.ptr(), btf as u32, 0, 0)) != Some(EINVAL) {
                return Err("BPF_OBJ_PIN of a BTF fd did not return EINVAL");
            }

            // A valid fd with a null pathname faults where `getname` does.
            if bpf(BPF_OBJ_PIN, &obj_attr(0, fd as u32, 0, 0)) != Some(EFAULT) {
                return Err("BPF_OBJ_PIN with a null pathname did not return EFAULT");
            }

            // Flags.
            if bpf(
                BPF_OBJ_PIN,
                &obj_attr(good.ptr(), fd as u32, BPF_F_RDONLY_FLAG, 0),
            ) != Some(EINVAL)
            {
                return Err("BPF_OBJ_PIN accepted a flag outside its mask");
            }
            let relative = CPath::new("m");
            if obj_pin_at(fd, &relative, 4095) != Some(EBADF) {
                return Err("BPF_OBJ_PIN with an unopened path_fd was not EBADF");
            }
            if obj_pin_at(fd, &relative, fd) != Some(ENOTDIR) {
                return Err("BPF_OBJ_PIN with a non-directory path_fd was not ENOTDIR");
            }
            if bpf(BPF_OBJ_PIN, &obj_attr(0, fd as u32, BPF_F_PATH_FD, 4095)) != Some(EFAULT) {
                return Err("BPF_OBJ_PIN checked path_fd before a bad pathname");
            }
            if bpf(BPF_OBJ_PIN, &obj_attr(good.ptr(), fd as u32, 0, 3)) != Some(EINVAL) {
                return Err("a path_fd without BPF_F_PATH_FD was not rejected");
            }
            let mut tail = obj_attr(good.ptr(), fd as u32, 0, 0);
            tail[OB_END] = 1;
            if bpf(BPF_OBJ_PIN, &tail) != Some(EINVAL) {
                return Err("BPF_OBJ_PIN ignored a non-zero byte past its last field");
            }

            // Paths.
            let missing = CPath::new("/bpf-pin-neg/no/such/dir/m");
            if bpf(BPF_OBJ_PIN, &obj_attr(missing.ptr(), fd as u32, 0, 0)) != Some(ENOENT) {
                return Err("BPF_OBJ_PIN under a missing directory did not return ENOENT");
            }
            let not_bpffs = CPath::new("/bpf-pin-neg-tmp/m");
            if bpf(BPF_OBJ_PIN, &obj_attr(not_bpffs.ptr(), fd as u32, 0, 0)) != Some(EPERM) {
                return Err("BPF_OBJ_PIN into a non-bpffs directory did not return EPERM");
            }

            // …and only now the happy path, so the duplicate below is the one
            // thing in this test that can produce EEXIST.
            if obj_pin(fd, &good) != Some(0) {
                return Err("BPF_OBJ_PIN failed on a clean name");
            }
            if obj_pin(fd, &good) != Some(EEXIST) {
                return Err("a second BPF_OBJ_PIN at a live name did not return EEXIST");
            }
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
            let _ = call(Syscall::Close.raw(), a0(btf as u64));
            Ok(())
        });
        let _ = registry().unmount(&tmp, TMP);
        outcome
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_pin_neg);

// ── BPF_OBJ_GET: negative ───────────────────────────────────────────

fn smoke_abi_bpf_obj_get_neg() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-get-neg";
        const TMP: &str = "/bpf-get-neg-tmp";
        let tmp = mount_tmpfs(TMP).ok_or("mounting the control tmpfs failed")?;
        let outcome = with_bpffs(AT, || {
            if bpf(BPF_OBJ_GET, &[0u8; ATTR_LEN]) != Some(EFAULT) {
                return Err("BPF_OBJ_GET with a null pathname did not return EFAULT");
            }
            let absent = CPath::new("/bpf-get-neg/nothing");
            if obj_get(&absent) != Some(ENOENT) {
                return Err("BPF_OBJ_GET of an absent name did not return ENOENT");
            }
            let no_parent = CPath::new("/bpf-get-neg/no/such/dir/x");
            if obj_get(&no_parent) != Some(ENOENT) {
                return Err("BPF_OBJ_GET under a missing directory did not return ENOENT");
            }

            // `bpf_fd` is not a field of this command; a non-zero one means the
            // caller filled in the wrong union member.
            let path = CPath::new("/bpf-get-neg/m");
            if bpf(BPF_OBJ_GET, &obj_attr(path.ptr(), 3, 0, 0)) != Some(EINVAL) {
                return Err("BPF_OBJ_GET with a non-zero bpf_fd did not return EINVAL");
            }
            // Flags outside the mask and contradictory access modes are
            // malformed. One valid access mode proceeds to path resolution.
            if bpf(BPF_OBJ_GET, &obj_attr(path.ptr(), 0, 1, 0)) != Some(EINVAL) {
                return Err("BPF_OBJ_GET accepted a flag outside its mask");
            }
            if obj_get_flags(&path, BPF_F_RDONLY_FLAG | BPF_F_WRONLY_FLAG) != Some(EINVAL) {
                return Err("BPF_OBJ_GET accepted both access modes");
            }
            if obj_get_flags(&path, BPF_F_RDONLY_FLAG) != Some(ENOENT) {
                return Err("BPF_OBJ_GET did not resolve a path after accepting BPF_F_RDONLY");
            }
            let relative = CPath::new("nothing");
            if obj_get_at_flags(&relative, 4095, 0) != Some(EBADF) {
                return Err("BPF_OBJ_GET with an unopened path_fd was not EBADF");
            }
            if bpf(BPF_OBJ_GET, &obj_attr(0, 0, BPF_F_PATH_FD, 4095)) != Some(EFAULT) {
                return Err("BPF_OBJ_GET checked path_fd before a bad pathname");
            }
            if bpf(BPF_OBJ_GET, &obj_attr(path.ptr(), 0, 0, 3)) != Some(EINVAL) {
                return Err("a path_fd without BPF_F_PATH_FD was not rejected");
            }
            let mut tail = obj_attr(path.ptr(), 0, 0, 0);
            tail[OB_END] = 1;
            if bpf(BPF_OBJ_GET, &tail) != Some(EINVAL) {
                return Err("BPF_OBJ_GET ignored a non-zero byte past its last field");
            }

            // A path that exists but is not a BPF object is EACCES, not ENOENT
            // — Linux's `bpf_inode_type`. Both halves matter: a loader probing
            // for a pin has to tell "no such path" from "that is not a pin".
            let tmp_missing = CPath::new("/bpf-get-neg-tmp/absent");
            if obj_get(&tmp_missing) != Some(ENOENT) {
                return Err("BPF_OBJ_GET of an absent non-bpffs path was not ENOENT");
            }
            let tmp_file = CPath::new("/bpf-get-neg-tmp/plain");
            let created = call_creat(tmp_file.ptr(), 0o644).ok_or("creat not Ok")?;
            if created < 0 {
                return Err("could not create a control file on tmpfs");
            }
            let _ = call(Syscall::Close.raw(), a0(created as u64));
            if obj_get(&tmp_file) != Some(EACCES) {
                return Err("BPF_OBJ_GET of a plain file did not return EACCES");
            }

            // A bpffs *directory* is present but is not an object either.
            let sub = CPath::new("/bpf-get-neg/dir");
            if call_mkdir(sub.ptr(), 0o755) != Some(0) {
                return Err("mkdir inside bpffs failed");
            }
            if obj_get(&sub) != Some(EACCES) {
                return Err("BPF_OBJ_GET of a bpffs directory did not return EACCES");
            }
            Ok(())
        });
        let _ = registry().unmount(&tmp, TMP);
        outcome
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_obj_get_neg);

// ════════════════════════════════════════════════════════════════════
// The lifetime contract, in the `bpf` subsystem.
//
//   pin, then close every fd     → still alive   (the pin is a STRONG ref)
//   unlink the pin, no fd open   → gone          (and the pin was the last)
//
// A pin holding a `Weak` fails the first; a pin that never dropped fails the
// second. `BPF_MAP_GET_FD_BY_ID` is the only oracle either assertion consults,
// and it answers from `idreg`'s `Weak` table, so neither can pass for another
// reason.
// ════════════════════════════════════════════════════════════════════

fn smoke_bpf_obj_pin_outlives_its_fd() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-pin-life";
        with_bpffs(AT, || {
            let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_MAP_CREATE failed");
            }
            let id = map_id_of(fd)?;
            let path = CPath::new("/bpf-pin-life/m");
            if obj_pin(fd, &path) != Some(0) {
                return Err("BPF_OBJ_PIN failed");
            }

            // Close the creating fd. The pin is now the *only* reference.
            if call(Syscall::Close.raw(), a0(fd as u64)) != Some(0) {
                return Err("closing the map fd failed");
            }
            let by_id = fd_by_id(BPF_MAP_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
            if by_id < 0 {
                return Err("the pinned map died when its creating fd closed");
            }
            if call(Syscall::Close.raw(), a0(by_id as u64)) != Some(0) {
                return Err("closing the by-id fd failed");
            }
            // Zero fds, one pin: still alive.
            let again = fd_by_id(BPF_MAP_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
            if again < 0 {
                return Err("the pinned map died with no fd open");
            }
            let _ = call(Syscall::Close.raw(), a0(again as u64));
            // …and reachable BY PATH, not merely alive.
            let reopened = obj_get(&path).ok_or("bpf() not Ok")?;
            if reopened < 0 {
                return Err("BPF_OBJ_GET failed with only the pin holding the map");
            }
            let _ = call(Syscall::Close.raw(), a0(reopened as u64));

            // Removing the pin removes the last reference.
            if call_unlink(path.ptr()) != Some(0) {
                return Err("unlinking the pin failed");
            }
            if fd_by_id(BPF_MAP_GET_FD_BY_ID, id) != Some(ENOENT) {
                return Err("the map outlived its last pin — the reference leaked");
            }
            if obj_get(&path) != Some(ENOENT) {
                return Err("the unlinked path still resolves");
            }
            Ok(())
        })
    })
}
kernel_test_in!("bpf", smoke_bpf_obj_pin_outlives_its_fd);

/// The other end of the same contract: an fd from `BPF_OBJ_GET` is a full
/// reference in its own right, so unlinking the pin while it is open does not
/// free the object — and closing it afterwards does.
fn smoke_bpf_obj_get_fd_is_a_real_reference() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-get-life";
        with_bpffs(AT, || {
            let fd = create_map(BPF_MAP_TYPE_HASH, 4, 8, 4).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_MAP_CREATE failed");
            }
            let id = map_id_of(fd)?;
            let path = CPath::new("/bpf-get-life/m");
            if obj_pin(fd, &path) != Some(0) {
                return Err("BPF_OBJ_PIN failed");
            }
            let reopened = obj_get(&path).ok_or("bpf() not Ok")?;
            if reopened < 0 {
                return Err("BPF_OBJ_GET failed");
            }
            if call(Syscall::Close.raw(), a0(fd as u64)) != Some(0) {
                return Err("closing the creating fd failed");
            }
            // Pin gone, one OBJ_GET fd left: the object must survive.
            if call_unlink(path.ptr()) != Some(0) {
                return Err("unlinking the pin failed");
            }
            let still = fd_by_id(BPF_MAP_GET_FD_BY_ID, id).ok_or("bpf() not Ok")?;
            if still < 0 {
                return Err("unlinking the pin freed a map an open fd still held");
            }
            if call(Syscall::Close.raw(), a0(still as u64)) != Some(0) {
                return Err("closing the by-id fd failed");
            }
            // Now the last holder goes.
            if call(Syscall::Close.raw(), a0(reopened as u64)) != Some(0) {
                return Err("closing the reopened fd failed");
            }
            if fd_by_id(BPF_MAP_GET_FD_BY_ID, id) != Some(ENOENT) {
                return Err("the map outlived every pin and fd");
            }
            Ok(())
        })
    })
}
kernel_test_in!("bpf", smoke_bpf_obj_get_fd_is_a_real_reference);

/// Unmounting a bpffs drops every pin it held — otherwise a mount/umount cycle
/// would strand objects for the boot with no path left to reach them by.
fn smoke_bpf_unmounting_bpffs_drops_its_pins() -> TestResult {
    with_setup(|| {
        const AT: &str = "/bpf-unmount-life";
        let fd = create_map(BPF_MAP_TYPE_ARRAY, 4, 8, 4).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_MAP_CREATE failed");
        }
        let id = map_id_of(fd)?;
        let handle = mount_bpffs(AT).ok_or("mounting bpffs failed")?;
        let path = CPath::new("/bpf-unmount-life/m");
        let pinned = obj_pin(fd, &path);
        let closed = call(Syscall::Close.raw(), a0(fd as u64));
        let unmounted = registry().unmount(&handle, AT);
        if pinned != Some(0) {
            return Err("BPF_OBJ_PIN failed");
        }
        if closed != Some(0) {
            return Err("closing the map fd failed");
        }
        if unmounted.is_err() {
            return Err("unmounting bpffs failed");
        }
        if fd_by_id(BPF_MAP_GET_FD_BY_ID, id) != Some(ENOENT) {
            return Err("unmounting bpffs stranded its pinned objects");
        }
        Ok(())
    })
}
kernel_test_in!("bpf", smoke_bpf_unmounting_bpffs_drops_its_pins);
