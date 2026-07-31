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
        // `BPF_BTF_LOAD` used to be in this list; it is implemented now, and
        // its own conformance group lives in `abi_bpf_btf_tests.rs`.
        for cmd in [BPF_OBJ_PIN, 9999] {
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
        for kind in [
            BPF_MAP_TYPE_UNSPEC,
            BPF_MAP_TYPE_PROG_ARRAY,
            BPF_MAP_TYPE_LRU_HASH,
            BPF_MAP_TYPE_LPM_TRIE,
            BPF_MAP_TYPE_RINGBUF,
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
