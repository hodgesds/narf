//! Linux syscall ABI conformance — the user/kernel address boundary that
//! every `copy_to_user` / `copy_from_user` call site inherits.
//!
//! `validate_user_range` is the single choke point for ~180 `copy_to_user`
//! sites and every `copy_from_user` site in this crate. Until this file
//! existed it accepted canonical *kernel-half* addresses on the theory that
//! SMAP would stop the access. It does not: SMAP faults a CPL-0 touch of a
//! page with `PTE.U=1`, says nothing about a kernel page (`U=0`), and
//! `copy_user_guarded` runs the whole transfer inside a `STAC`/`CLAC`
//! bracket that disables it outright. A mapped kernel destination was
//! written silently and the caller got `Ok(())` — an arbitrary-kernel-write
//! primitive out of any syscall with a caller-supplied (address, length,
//! content) triple.
//!
//! What lives here:
//!
//!  * the boundary predicate itself, positive and negative, with the
//!    last-byte cases that a first-byte-only check would pass;
//!  * the demonstrated `bpf(BPF_OBJ_GET_INFO_BY_FD)` BTF gadget, end to
//!    end, asserting both the errno *and* that the kernel bytes the copy
//!    would have landed on are untouched;
//!  * the `btf_log_buf` variant of the same primitive;
//!  * the read direction (`copy_from_user` from a kernel source is an
//!    info leak, not just a write hazard);
//!  * proof that the `kernel-test` opt-in is dynamically scoped — it
//!    closes when its scope does, which is what keeps every other test in
//!    the suite exercising the production predicate.

use crate::abi_test_support::*;

/// Last addressable byte of the user half on both supported
/// architectures (48-bit canonical VAs, split at bit 47).
///
/// Spelled out rather than derived from `handlers::USER_VA_LIMIT`: a test
/// that imported the constant would agree with the implementation by
/// construction and could never catch it moving.
const USER_TOP: u64 = 0x0000_7FFF_FFFF_FFFF;
/// First address above the user half.
const KERNEL_FIRST_NONCANON: u64 = 0x0000_8000_0000_0000;
/// First *canonical* kernel-half address.
const KERNEL_FIRST_CANON: u64 = 0xFFFF_8000_0000_0000;
/// 16 MiB — the per-call transfer cap, restated for the same reason.
const MAX_COPY: usize = 16 * 1024 * 1024;

const EFAULT_E: u64 = 14;
const EINVAL_E: u64 = 22;

fn vur(ptr: u64, len: usize) -> Result<(), u64> {
    crate::handlers::validate_user_range(ptr, len)
}

/// Distinctive fill for the canary, and its size. 64 bytes so a copy the
/// tests size at 64 would overwrite all of it.
const CANARY_BYTE: u8 = 0x5A;
const CANARY_LEN: usize = 64;

/// The kernel buffer the negative tests point a syscall at.
///
/// A **static**, deliberately: it lives in the kernel image's `.data`,
/// which is in the kernel half on both architectures and writable at
/// runtime — x86_64 links higher-half (`.data` at 0xFFFF_FFFF_821D_4000),
/// aarch64 runs entirely out of TTBR1 (`KERNEL_VIRT_BASE =
/// 0xFFFF_FF80_0000_0000`, `build/linker/aarch64.ld`). A heap or stack
/// buffer would not do: on x86_64 those come back through the low
/// identity map and are numerically in the *user* half, so a test aimed
/// at one would pass the predicate and prove nothing.
///
/// This is what makes these tests more than errno checks. An errno alone
/// cannot distinguish "the pointer was rejected" from "the copy faulted
/// harmlessly"; bytes that are still `CANARY_BYTE` afterwards can.
static CANARY: [core::sync::atomic::AtomicU8; CANARY_LEN] =
    [const { core::sync::atomic::AtomicU8::new(CANARY_BYTE) }; CANARY_LEN];

/// Address of [`CANARY`], as a syscall would see it. Asserted kernel-half
/// by [`canary_arm`] before every use.
fn canary_addr() -> u64 {
    CANARY.as_ptr() as u64
}

/// Refill the canary and confirm it really is a kernel-half target. The
/// smokes share one kernel image, so a previous run must not decide this
/// one.
fn canary_arm() -> Result<u64, &'static str> {
    for b in CANARY.iter() {
        b.store(CANARY_BYTE, core::sync::atomic::Ordering::Relaxed);
    }
    let a = canary_addr();
    if a < KERNEL_FIRST_CANON {
        return Err("the canary static is not in the kernel half — test is vacuous");
    }
    Ok(a)
}

/// Can a test build a *fixture* — an `attr` block, a BTF blob — that the
/// strict predicate will accept as a user pointer?
///
/// Only where this build's kernel stack and heap are numerically in the
/// user half. On x86_64 they are: the frame allocator hands back physical
/// addresses reached through the low identity map, so a fixture's address
/// was < 2^47. That is no longer true of the heap: it is reached through
/// the high-half direct map (`KERNEL_DIRECT_MAP_BASE`), like aarch64, where
/// everything runs out of TTBR1 at
/// `KERNEL_VIRT_BASE = 0xFFFF_FF80_0000_0000`.
///
/// Tests that need to *drive a syscall through its fixture* and have the
/// same syscall reject a kernel destination cannot exist on aarch64: the
/// opt-in is one flag, so admitting the fixture would admit the
/// destination too. Those tests skip there with this as the reason, rather
/// than passing vacuously because the fixture EFAULTed first. The
/// predicate itself is still covered on aarch64 by the tests that pass a
/// kernel address as a bare syscall *argument*, which needs no fixture.
fn fixture_ptrs_are_user_half() -> bool {
    // Probe BOTH kernel stack and kernel heap. These used to travel
    // together on x86_64 -- both were reached through the low identity map,
    // so one probe answered for both. Freeing the low half moved the heap
    // into the high-half direct map while the stack stayed low, so a
    // stack-only probe now reports "user half" for a fixture whose heap
    // buffers are kernel-half, and the test fails where it means to skip.
    let stack_probe = [0u8; 8];
    let heap_probe: alloc::vec::Vec<u8> = alloc::vec![0u8; 8];
    (stack_probe.as_ptr() as u64) < (1u64 << 47) && (heap_probe.as_ptr() as u64) < (1u64 << 47)
}

/// Did anything write to the canary?
fn canary_intact() -> bool {
    CANARY
        .iter()
        .all(|b| b.load(core::sync::atomic::Ordering::Relaxed) == CANARY_BYTE)
}

// ── the predicate: positive ─────────────────────────────────────────

fn smoke_abi_uaccess_user_half_pos() -> TestResult {
    with_setup_strict(|| {
        // Lowest addressable user byte (0 is null, rejected separately).
        if vur(1, 1).is_err() {
            return Err("validate_user_range rejected the first user byte");
        }
        if vur(0x1000, 4096).is_err() {
            return Err("validate_user_range rejected an ordinary user page");
        }
        // Zero-length is legal — several syscalls copy nothing.
        if vur(0x1000, 0).is_err() {
            return Err("validate_user_range rejected a zero-length range");
        }
        // Highest addressable user byte, as a one-byte range.
        if vur(USER_TOP, 1).is_err() {
            return Err("validate_user_range rejected the last user byte");
        }
        // A range ENDING exactly on the last user byte. Off-by-one here is
        // the obvious way to break the boundary in the safe direction.
        if vur(USER_TOP - 15, 16).is_err() {
            return Err("validate_user_range rejected a range ending on the last user byte");
        }
        // The full per-call cap, still entirely inside the user half.
        if vur(0x1000, MAX_COPY).is_err() {
            return Err("validate_user_range rejected a max-size user range");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_uaccess_user_half_pos);

// ── the predicate: negative ─────────────────────────────────────────

fn smoke_abi_uaccess_kernel_half_neg() -> TestResult {
    with_setup_strict(|| {
        // First address above the user half. Non-canonical as well, so this
        // one was already rejected before the hardening — it is here so the
        // boundary is pinned from both sides.
        if vur(KERNEL_FIRST_NONCANON, 1) != Err(EFAULT_E) {
            return Err("the first address above the user half was not EFAULT");
        }
        // First *canonical* kernel address. This is the one the old code
        // deliberately let through.
        if vur(KERNEL_FIRST_CANON, 1) != Err(EFAULT_E) {
            return Err("a canonical kernel-half address was not EFAULT");
        }
        // The kernel image higher-half window (x86_64 PML4[511]) — mapped,
        // writable, and therefore the most dangerous shape of all.
        if vur(0xFFFF_FFFF_8000_0000, 8) != Err(EFAULT_E) {
            return Err("the kernel image window was not EFAULT");
        }
        // The x86_64 high-half direct map base.
        if vur(0xFFFF_C000_0000_0000, 8) != Err(EFAULT_E) {
            return Err("the kernel direct-map base was not EFAULT");
        }
        // aarch64's TTBR1 kernel window.
        if vur(0xFFFF_FF80_0000_0000, 8) != Err(EFAULT_E) {
            return Err("the aarch64 kernel window was not EFAULT");
        }
        // LAST-BYTE cases. A check that looked only at `ptr` would accept
        // every one of these and then copy almost the whole transfer out of
        // the user half.
        if vur(USER_TOP, 2) != Err(EFAULT_E) {
            return Err("a range whose last byte leaves the user half was not EFAULT");
        }
        if vur(USER_TOP - 15, 17) != Err(EFAULT_E) {
            return Err("a range overrunning the last user byte by one was not EFAULT");
        }
        if vur(USER_TOP, MAX_COPY) != Err(EFAULT_E) {
            return Err("a user-half base with a kernel-half tail was not EFAULT");
        }
        // The pre-existing rules must survive the rewrite.
        if vur(0, 1) != Err(EFAULT_E) {
            return Err("a null pointer was not EFAULT");
        }
        if vur(u64::MAX, 1) != Err(EFAULT_E) {
            return Err("an end-overflowing range was not EFAULT");
        }
        if vur(0x1000, MAX_COPY + 1) != Err(EINVAL_E) {
            return Err("an oversized length was not EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_uaccess_kernel_half_neg);

// ── the opt-in is dynamically scoped ────────────────────────────────

/// The `kernel-test` opt-in exists so a handler can be unit-tested with a
/// kernel scratch buffer standing in for a user buffer. It must open only
/// for the block that asks for it — a build-wide bypass would mean the
/// thousands of other cases in this suite, and the two negative tests
/// above, stopped testing anything.
fn smoke_abi_uaccess_kernel_scope_is_scoped() -> TestResult {
    with_setup_strict(|| {
        if vur(KERNEL_FIRST_CANON, 8) != Err(EFAULT_E) {
            return Err("a kernel address was accepted before the scope opened");
        }
        let inside = crate::handlers::with_kernel_buffers(|| vur(KERNEL_FIRST_CANON, 8));
        #[cfg(feature = "kernel-test")]
        if inside.is_err() {
            return Err("the kernel-buffer scope did not admit a kernel address");
        }
        #[cfg(not(feature = "kernel-test"))]
        if inside != Err(EFAULT_E) {
            return Err("a non-kernel-test build has no bypass, yet one fired");
        }
        // Even inside the scope a range that straddles the canonical hole
        // stays rejected: the opt-in relaxes the half, not canonicality.
        let straddle = crate::handlers::with_kernel_buffers(|| vur(USER_TOP, 2));
        if straddle != Err(EFAULT_E) {
            return Err("the kernel-buffer scope admitted a hole-spanning range");
        }
        // And it is closed again on the way out.
        if vur(KERNEL_FIRST_CANON, 8) != Err(EFAULT_E) {
            return Err("the kernel-buffer scope stayed open after its block ended");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_uaccess_kernel_scope_is_scoped);

// ── the demonstrated gadget, end to end ─────────────────────────────

const BPF_BTF_LOAD: u64 = 18;
const BPF_OBJ_GET_INFO_BY_FD: u64 = 15;
const ATTR_LEN: usize = 64;

// `union bpf_attr` → `struct { … } btf`.
const BTF_DATA: usize = 0;
const BTF_LOG_BUF: usize = 8;
const BTF_SIZE: usize = 16;
const BTF_LOG_SIZE: usize = 20;
const BTF_LOG_LEVEL: usize = 24;
// `union bpf_attr` → `struct { … } info`.
const AI_BPF_FD: usize = 0;
const AI_INFO_LEN: usize = 4;
const AI_INFO: usize = 8;
// `struct bpf_btf_info`.
const BTF_INFO_LEN: usize = 40;
const BI_BTF: usize = 0;
const BI_BTF_SIZE: usize = 8;

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// The smallest well-formed BTF blob. Hand-encoded, like the one in
/// `abi_bpf_btf_tests.rs`, so this file depends on the wire format and not
/// on the builder.
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
    v.extend_from_slice(&(1u32 << 24).to_le_bytes()); // info: KIND_INT
    v.extend_from_slice(&4u32.to_le_bytes()); // size
    v.extend_from_slice(&32u32.to_le_bytes()); // int_data
    v.extend_from_slice(b"\0int\0");
    v
}

/// `bpf(BPF_OBJ_GET_INFO_BY_FD)` on a BTF fd with `bpf_btf_info.btf`
/// pointing into the kernel.
///
/// This is the gadget an adversarial audit demonstrated: `BPF_BTF_LOAD`
/// parks up to 16 MiB of attacker-chosen bytes in kernel storage (only the
/// first and last byte of the string section must be NUL, and only
/// referenced offsets are charset-checked), and this command then copies
/// `btf_size` of them to `btf` — attacker content, attacker length,
/// attacker address. It must be EFAULT, and the kernel bytes at that
/// address must be exactly as they were.
fn smoke_abi_uaccess_bpf_btf_info_kernel_dst_neg() -> TestResult {
    if !fixture_ptrs_are_user_half() {
        return TestResult::Skip(
            "kernel stack/heap is not in the user half here: the fixture and the kernel destination cannot be distinguished by a single opt-in (see fixture_ptrs_are_user_half)",
        );
    }

    let kdst = match canary_arm() {
        Ok(a) => a,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = with_setup_strict(|| {
        let blob = minimal_btf();
        let mut attr = [0u8; ATTR_LEN];
        put_u64(&mut attr, BTF_DATA, blob.as_ptr() as u64);
        put_u32(&mut attr, BTF_SIZE, blob.len() as u32);
        let fd = call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
        )
        .ok_or("BPF_BTF_LOAD not Ok")?;
        if fd < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }

        let mut info = [0u8; BTF_INFO_LEN];
        put_u64(&mut info, BI_BTF, kdst);
        put_u32(&mut info, BI_BTF_SIZE, CANARY_LEN as u32);

        let mut iattr = [0u8; ATTR_LEN];
        put_u32(&mut iattr, AI_BPF_FD, fd as u32);
        put_u32(&mut iattr, AI_INFO_LEN, BTF_INFO_LEN as u32);
        put_u64(&mut iattr, AI_INFO, info.as_mut_ptr() as u64);
        let r = call(
            Syscall::Bpf.raw(),
            a2(
                BPF_OBJ_GET_INFO_BY_FD,
                iattr.as_mut_ptr() as u64,
                ATTR_LEN as u64,
            ),
        );
        let _ = call(Syscall::Close.raw(), a0(fd as u64));

        if r != Some(EFAULT) {
            return Err("BPF_OBJ_GET_INFO_BY_FD with a kernel-half btf pointer did not EFAULT");
        }
        Ok(())
    });
    // The memory verdict comes first: an errno can be right for the wrong
    // reason, bytes cannot.
    if !canary_intact() {
        return TestResult::Fail(
            "BPF_OBJ_GET_INFO_BY_FD wrote BTF bytes into a kernel buffer (arbitrary kernel write)",
        );
    }
    outcome
}
kernel_test_in!("syscall_abi", smoke_abi_uaccess_bpf_btf_info_kernel_dst_neg);

/// The same primitive through `BPF_BTF_LOAD`'s verifier log: `btf_log_buf`
/// is a caller-supplied address, `btf_log_size` a caller-supplied length,
/// and the message is influenced by the blob the caller submitted.
///
/// `LogTarget::emit` swallows the copy error on purpose (Linux does too —
/// a bad log buffer must not change the verdict), so the errno carries no
/// information here. The canary is the whole assertion.
fn smoke_abi_uaccess_bpf_btf_log_buf_kernel_dst_neg() -> TestResult {
    if !fixture_ptrs_are_user_half() {
        return TestResult::Skip(
            "kernel stack/heap is not in the user half here: the fixture and the kernel destination cannot be distinguished by a single opt-in (see fixture_ptrs_are_user_half)",
        );
    }

    let kdst = match canary_arm() {
        Ok(a) => a,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = with_setup_strict(|| {
        // A blob that fails to parse, so the verifier has something to say.
        let bad = alloc::vec![0u8; 8];
        let mut attr = [0u8; ATTR_LEN];
        put_u64(&mut attr, BTF_DATA, bad.as_ptr() as u64);
        put_u32(&mut attr, BTF_SIZE, bad.len() as u32);
        put_u64(&mut attr, BTF_LOG_BUF, kdst);
        put_u32(&mut attr, BTF_LOG_SIZE, CANARY_LEN as u32);
        put_u32(&mut attr, BTF_LOG_LEVEL, 1);
        let r = call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
        );
        // Precondition, not incidental: an intact canary proves nothing if
        // the syscall rejected the *attr block* and never reached the
        // verifier. EFAULT here means the fixture, not the log buffer, was
        // refused — exactly the vacuous pass this check exists to catch.
        if r == Some(EFAULT) {
            return Err("BPF_BTF_LOAD refused the fixture attr block, so the log path never ran");
        }
        Ok(())
    });
    if !canary_intact() {
        return TestResult::Fail("btf_log_buf wrote the verifier log into a kernel buffer");
    }
    outcome
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_uaccess_bpf_btf_log_buf_kernel_dst_neg
);

// ── the read direction ──────────────────────────────────────────────

/// A kernel-half *source* is an information leak rather than a write, and
/// `copy_from_user` shares the same predicate. Pin it here so a future
/// change that relaxes only the write direction still goes red.
fn smoke_abi_uaccess_kernel_src_neg() -> TestResult {
    with_setup_strict(|| {
        // `write(2)`'s buffer is a `copy_from_user` source.
        let n = call(
            Syscall::Write.raw(),
            a2(1 /* stdout */, KERNEL_FIRST_CANON, 16),
        );
        if n != Some(EFAULT) {
            return Err("write(2) from a canonical kernel-half buffer did not EFAULT");
        }
        // The kernel image window: mapped and readable, so without the
        // predicate this leaks kernel .text/.rodata to whatever fd the
        // caller picked.
        let n = call(Syscall::Write.raw(), a2(1, 0xFFFF_FFFF_8000_0000, 16));
        if n != Some(EFAULT) {
            return Err("write(2) from the kernel image window did not EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_uaccess_kernel_src_neg);

// ── a non-BPF write path ────────────────────────────────────────────

/// The hole was never a BPF bug — `bpf(2)` was only the loudest gadget.
/// One ordinary syscall stands in for the ~180 `copy_to_user` sites that
/// share the helper.
///
/// LINUX-GAP: Linux `clock_gettime(2)` returns `-EFAULT` for an unwritable
/// `struct timespec *`. NARF's handler turns the `copy_to_user` failure
/// into `SyscallReturn::invalid_op()` — a non-`Ok` NARF status with no
/// Linux errno at all — so a caller cannot tell EFAULT from EINVAL. That
/// is a separate defect from the one this file is about; the assertion
/// below is therefore "the call did not succeed", and
/// `smoke_abi_uaccess_kernel_src_neg` carries the strict errno contract on
/// a path that does map it (`write(2)` → `-EFAULT`). Tighten this to
/// `EFAULT` when the handler is fixed.
fn smoke_abi_uaccess_clock_gettime_kernel_dst_neg() -> TestResult {
    let kdst = match canary_arm() {
        Ok(a) => a,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = with_setup_strict(|| {
        let r = call_raw(
            Syscall::ClockGetTime.raw(),
            a1(0 /* CLOCK_REALTIME */, kdst),
        );
        if r.status == SyscallReturn::OK && (r.value as i64) >= 0 {
            return Err("clock_gettime(2) into a kernel-half timespec reported success");
        }
        Ok(())
    });
    // The load-bearing half: whatever errno shape came back, no timespec
    // may have landed in kernel memory.
    if !canary_intact() {
        return TestResult::Fail("clock_gettime(2) wrote a timespec into a kernel buffer");
    }
    outcome
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_uaccess_clock_gettime_kernel_dst_neg
);
