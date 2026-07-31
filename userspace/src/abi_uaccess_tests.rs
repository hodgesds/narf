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

#![cfg(feature = "linux-compat")]

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

/// A canonical **kernel-half** VA that aliases the bytes at `p`, writable,
/// or `None` if this build has no such window for that pointer.
///
/// This is what makes the negative tests below more than an errno check: a
/// destination that is merely kernel-shaped would be rejected by the
/// pointer predicate *or* fault harmlessly, and the test could not tell the
/// two apart. An alias of a canary the test owns can.
///
///  * aarch64 — every kernel VA is already in TTBR1's high half
///    (`KERNEL_VIRT_BASE = 0xFFFF_FF80_0000_0000`, `build/linker/aarch64.ld`),
///    so the pointer is its own alias.
///  * x86_64 — the kernel image is identity-mapped low, but `init_mmu`
///    (`memory/src/x86_64/mmu.rs`) also installs PML4[511]/PDPT[510] as one
///    writable 1-GiB huge page mapping VA `0xFFFF_FFFF_8000_0000 + x` to
///    phys `x`, and a low identity pointer *is* its physical address. RAM
///    above 512 GiB instead comes back through the direct map and is
///    already high-half.
fn kernel_alias(p: *const u8) -> Option<u64> {
    let v = p as u64;
    if v >= KERNEL_FIRST_CANON {
        return Some(v);
    }
    #[cfg(target_arch = "x86_64")]
    if v < (1u64 << 30) {
        return Some(0xFFFF_FFFF_8000_0000u64 + v);
    }
    None
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

/// Canary the copy would land on: a distinctive fill the test can prove
/// survived. 64 bytes so a `btf_size` of 64 would overwrite all of it.
const CANARY_BYTE: u8 = 0x5A;
const CANARY_LEN: usize = 64;

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
    let mut canary = alloc::vec![CANARY_BYTE; CANARY_LEN];
    let Some(kdst) = kernel_alias(canary.as_ptr()) else {
        return TestResult::Skip("no kernel-half alias window for the canary on this build");
    };
    with_setup_strict(|| {
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
    // Checked after `with_setup` so the verdict is about the memory, not
    // about which error string won the race to be returned.
    if canary.iter().any(|&b| b != CANARY_BYTE) {
        return TestResult::Fail(
            "BPF_OBJ_GET_INFO_BY_FD wrote BTF bytes into a kernel buffer (arbitrary kernel write)",
        );
    }
    // Keep the canary alive across the syscall.
    canary[0] = CANARY_BYTE;
    TestResult::Pass
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
    let mut canary = alloc::vec![CANARY_BYTE; CANARY_LEN];
    let Some(kdst) = kernel_alias(canary.as_ptr()) else {
        return TestResult::Skip("no kernel-half alias window for the canary on this build");
    };
    with_setup_strict(|| {
        // A blob that fails to parse, so the verifier has something to say.
        let bad = alloc::vec![0u8; 8];
        let mut attr = [0u8; ATTR_LEN];
        put_u64(&mut attr, BTF_DATA, bad.as_ptr() as u64);
        put_u32(&mut attr, BTF_SIZE, bad.len() as u32);
        put_u64(&mut attr, BTF_LOG_BUF, kdst);
        put_u32(&mut attr, BTF_LOG_SIZE, CANARY_LEN as u32);
        put_u32(&mut attr, BTF_LOG_LEVEL, 1);
        let _ = call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
        );
        Ok(())
    });
    if canary.iter().any(|&b| b != CANARY_BYTE) {
        return TestResult::Fail("btf_log_buf wrote the verifier log into a kernel buffer");
    }
    canary[0] = CANARY_BYTE;
    TestResult::Pass
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
fn smoke_abi_uaccess_clock_gettime_kernel_dst_neg() -> TestResult {
    let mut canary = alloc::vec![CANARY_BYTE; CANARY_LEN];
    let Some(kdst) = kernel_alias(canary.as_ptr()) else {
        return TestResult::Skip("no kernel-half alias window for the canary on this build");
    };
    with_setup_strict(|| {
        let r = call(
            Syscall::ClockGetTime.raw(),
            a1(0 /* CLOCK_REALTIME */, kdst),
        );
        if r != Some(EFAULT) {
            return Err("clock_gettime(2) into a kernel-half timespec did not EFAULT");
        }
        Ok(())
    });
    if canary.iter().any(|&b| b != CANARY_BYTE) {
        return TestResult::Fail("clock_gettime(2) wrote a timespec into a kernel buffer");
    }
    canary[0] = CANARY_BYTE;
    TestResult::Pass
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_uaccess_clock_gettime_kernel_dst_neg
);
