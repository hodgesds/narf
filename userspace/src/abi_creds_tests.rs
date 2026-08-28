//! Linux syscall ABI conformance — creds group.
use crate::abi_test_support::*;

// ─────────────────────────────────────────────────────────────────────
// Notes on the harness reality these tests pin:
//
// * The credential / umask / hostname tables are *global* kernel statics
//   that the ABI harness does NOT reset between tests, and whose
//   initialised-ness depends on whether boot ran `uidgid_init()` /
//   `umask_init()`. `read_uidgid()` always works (`unwrap_or_default()`
//   ⇒ 0), so the get* family is deterministic. The set* family returns
//   `0` when the table is initialised and `-1` (write-failed shape) when
//   it is not — so set-tests accept either of those two Ok-status shapes
//   rather than a single value.
//
// * `copy_to_user` / `copy_user_path` validate only canonicality + len,
//   not page residency (see `validate_user_range` — kernel-test pointers
//   are explicitly tolerated), so a kernel stack/heap buffer address is a
//   valid "user" out-pointer here and the copy lands in real memory.
//
// * All of these handlers return their Linux value as `SyscallReturn::ok`
//   (NARF status Ok), so `call()` yields `Some(value)`; a `None` would
//   mean a non-Ok NARF status, which none of these produce.
// ─────────────────────────────────────────────────────────────────────

// A canonical-but-bad (NULL) user pointer the copy helpers reject → -1.
const NULL_PTR: u64 = 0;
// A non-canonical pointer: bits 48..=62 partially set ⇒ EFAULT in
// validate_user_range, so copy_to_user/copy_user_path fail.
const BAD_PTR: u64 = 0x0001_0000_0000_0000;

// ── getuid ───────────────────────────────────────────────────────────
fn smoke_abi_creds_getuid_pos() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::GetUid.raw(), a0(0)).ok_or("getuid not Ok")?;
        if r < 0 {
            return Err("getuid returned negative");
        }
        // Stable across calls.
        let r2 = call(Syscall::GetUid.raw(), a0(0)).ok_or("getuid#2 not Ok")?;
        if r != r2 {
            return Err("getuid not stable");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getuid_pos);

fn smoke_abi_creds_getuid_neg() -> TestResult {
    with_setup(|| {
        // getuid ignores its argument entirely; passing garbage must not
        // change the Ok-status / non-negative result. (No error path
        // exists for getuid — this pins that robustness.)
        let r = call(Syscall::GetUid.raw(), a0(0xDEAD_BEEF)).ok_or("getuid not Ok")?;
        if r < 0 {
            return Err("getuid with junk arg returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getuid_neg);

// ── getgid ───────────────────────────────────────────────────────────
fn smoke_abi_creds_getgid_pos() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::GetGid.raw(), a0(0)).ok_or("getgid not Ok")?;
        if r < 0 {
            return Err("getgid returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getgid_pos);

fn smoke_abi_creds_getgid_neg() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::GetGid.raw(), a0(0xDEAD_BEEF)).ok_or("getgid not Ok")?;
        if r < 0 {
            return Err("getgid with junk arg returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getgid_neg);

// ── geteuid ──────────────────────────────────────────────────────────
fn smoke_abi_creds_geteuid_pos() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::Geteuid.raw(), a0(0)).ok_or("geteuid not Ok")?;
        if r < 0 {
            return Err("geteuid returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_geteuid_pos);

fn smoke_abi_creds_geteuid_neg() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::Geteuid.raw(), a0(0xDEAD_BEEF)).ok_or("geteuid not Ok")?;
        if r < 0 {
            return Err("geteuid with junk arg returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_geteuid_neg);

// ── getegid ──────────────────────────────────────────────────────────
fn smoke_abi_creds_getegid_pos() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::Getegid.raw(), a0(0)).ok_or("getegid not Ok")?;
        if r < 0 {
            return Err("getegid returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getegid_pos);

fn smoke_abi_creds_getegid_neg() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::Getegid.raw(), a0(0xDEAD_BEEF)).ok_or("getegid not Ok")?;
        if r < 0 {
            return Err("getegid with junk arg returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getegid_neg);

// ── setuid ───────────────────────────────────────────────────────────
// Without the `container` feature there is no user-ns gate, so the only
// failure mode is "uid/gid table not initialised" ⇒ Ok(-1). With it
// initialised ⇒ Ok(0). Accept both Ok shapes.
fn smoke_abi_creds_setuid_pos() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::SetUid.raw(), a0(0)).ok_or("setuid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setuid(0) returned an unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setuid_pos);

fn smoke_abi_creds_setuid_neg() -> TestResult {
    with_setup(|| {
        // A huge uid is still accepted by the no-container path (it's just
        // stored); the value is truncated to u32. Pin the actual shape:
        // Ok status, value 0 (stored) or -1 (table uninit). LINUX-GAP:
        // Linux would EPERM an unprivileged setuid to an arbitrary id; the
        // NARF no-container path is notionally-privileged and never EPERMs.
        let r = call(Syscall::SetUid.raw(), a0(0xFFFF_FFFE)).ok_or("setuid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setuid(big) returned an unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setuid_neg);

// ── setgid ───────────────────────────────────────────────────────────
fn smoke_abi_creds_setgid_pos() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::SetGid.raw(), a0(0)).ok_or("setgid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setgid(0) returned an unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setgid_pos);

fn smoke_abi_creds_setgid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux EPERMs an unprivileged setgid to an arbitrary
        // gid; the NARF no-container path stores it and returns Ok.
        let r = call(Syscall::SetGid.raw(), a0(0xFFFF_FFFE)).ok_or("setgid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setgid(big) returned an unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setgid_neg);

// ── setreuid ─────────────────────────────────────────────────────────
fn smoke_abi_creds_setreuid_pos() -> TestResult {
    with_setup(|| {
        // (-1, -1) ⇒ leave both unchanged; Ok(0) when table init, Ok(-1)
        // when not.
        let r = call(
            Syscall::Setreuid.raw(),
            a1(u32::MAX as u64, u32::MAX as u64),
        )
        .ok_or("setreuid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setreuid(-1,-1) unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setreuid_pos);

fn smoke_abi_creds_setreuid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux EPERMs an unprivileged caller raising ruid to
        // an unrelated id; the no-container path stores it ⇒ Ok(0)/Ok(-1).
        let r = call(Syscall::Setreuid.raw(), a1(1234, 5678)).ok_or("setreuid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setreuid(1234,5678) unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setreuid_neg);

// ── setregid ─────────────────────────────────────────────────────────
fn smoke_abi_creds_setregid_pos() -> TestResult {
    with_setup(|| {
        let r = call(
            Syscall::Setregid.raw(),
            a1(u32::MAX as u64, u32::MAX as u64),
        )
        .ok_or("setregid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setregid(-1,-1) unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setregid_pos);

fn smoke_abi_creds_setregid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux EPERMs an unprivileged gid raise; NARF stores it.
        let r = call(Syscall::Setregid.raw(), a1(1234, 5678)).ok_or("setregid not Ok")?;
        if r != 0 && r != -1 {
            return Err("setregid(1234,5678) unexpected value");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setregid_neg);

// ── setresuid ────────────────────────────────────────────────────────
// Always returns Ok(0), regardless of table init (the write result is
// discarded by the handler).
fn smoke_abi_creds_setresuid_pos() -> TestResult {
    with_setup(|| {
        let r = call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, u32::MAX as u64, u32::MAX as u64),
        )
        .ok_or("setresuid not Ok")?;
        if r != 0 {
            return Err("setresuid(-1,-1,-1) expected 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setresuid_pos);

fn smoke_abi_creds_setresuid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: Linux EPERMs an unprivileged caller setting arbitrary
        // r/e/s uids; NARF collapses onto its single uid and ALWAYS
        // returns Ok(0) (no EPERM path, write-failure swallowed).
        let r = call(Syscall::Setresuid.raw(), a2(1000, 2000, 3000)).ok_or("setresuid not Ok")?;
        if r != 0 {
            return Err("setresuid(arbitrary) expected 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setresuid_neg);

// ── setresgid ────────────────────────────────────────────────────────
fn smoke_abi_creds_setresgid_pos() -> TestResult {
    with_setup(|| {
        let r = call(
            Syscall::Setresgid.raw(),
            a2(u32::MAX as u64, u32::MAX as u64, u32::MAX as u64),
        )
        .ok_or("setresgid not Ok")?;
        if r != 0 {
            return Err("setresgid(-1,-1,-1) expected 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setresgid_pos);

fn smoke_abi_creds_setresgid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: same as setresuid — NARF always returns Ok(0).
        let r = call(Syscall::Setresgid.raw(), a2(1000, 2000, 3000)).ok_or("setresgid not Ok")?;
        if r != 0 {
            return Err("setresgid(arbitrary) expected 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setresgid_neg);

// ── setfsuid ─────────────────────────────────────────────────────────
// Returns the PREVIOUS fsuid; never an errno. `-1` queries only.
fn smoke_abi_creds_setfsuid_pos() -> TestResult {
    with_setup(|| {
        // Query (arg0 == -1) ⇒ returns current fsuid, must be >= 0.
        let r = call(Syscall::Setfsuid.raw(), a0(u32::MAX as u64)).ok_or("setfsuid not Ok")?;
        if r < 0 {
            return Err("setfsuid query returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setfsuid_pos);

fn smoke_abi_creds_setfsuid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: setfsuid never reports failure in Linux either — an
        // unprivileged change just silently no-ops and still returns the
        // old fsuid. So even an "arbitrary" target yields Ok(old) >= 0,
        // never an errno. This pins that no-error contract.
        let r = call(Syscall::Setfsuid.raw(), a0(4242)).ok_or("setfsuid not Ok")?;
        if r < 0 {
            return Err("setfsuid(arbitrary) returned an errno");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setfsuid_neg);

// ── setfsgid ─────────────────────────────────────────────────────────
fn smoke_abi_creds_setfsgid_pos() -> TestResult {
    with_setup(|| {
        let r = call(Syscall::Setfsgid.raw(), a0(u32::MAX as u64)).ok_or("setfsgid not Ok")?;
        if r < 0 {
            return Err("setfsgid query returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setfsgid_pos);

fn smoke_abi_creds_setfsgid_neg() -> TestResult {
    with_setup(|| {
        // LINUX-GAP: no error path; returns Ok(old fsgid) >= 0 always.
        let r = call(Syscall::Setfsgid.raw(), a0(4242)).ok_or("setfsgid not Ok")?;
        if r < 0 {
            return Err("setfsgid(arbitrary) returned an errno");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setfsgid_neg);

// ── getresuid ────────────────────────────────────────────────────────
// Writes the (single) uid into up to three u32 out-pointers; Ok(0) on
// success, Ok(-1) on copy fault. read_uidgid always works, so the
// positive path is deterministic.
fn smoke_abi_creds_getresuid_pos() -> TestResult {
    with_setup(|| {
        let mut ruid: u32 = 0xAAAA_AAAA;
        let mut euid: u32 = 0xBBBB_BBBB;
        let mut suid: u32 = 0xCCCC_CCCC;
        let p0 = &mut ruid as *mut u32 as u64;
        let p1 = &mut euid as *mut u32 as u64;
        let p2 = &mut suid as *mut u32 as u64;
        let r = call(Syscall::Getresuid.raw(), a2(p0, p1, p2)).ok_or("getresuid not Ok")?;
        if r != 0 {
            return Err("getresuid expected 0");
        }
        // All three slots must hold the same uid the get* family reports.
        let uid = call(Syscall::GetUid.raw(), a0(0)).ok_or("getuid not Ok")? as u32;
        if ruid != uid || euid != uid || suid != uid {
            return Err("getresuid did not fill all three slots with uid");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getresuid_pos);

fn smoke_abi_creds_getresuid_neg() -> TestResult {
    with_setup(|| {
        // `kernel/sys.c::SYSCALL_DEFINE3(getresuid)` is three chained `put_user`s
        // and returns their result, so an unwritable out-pointer is -EFAULT.
        // The `-1` sentinel said EPERM, which for a credential QUERY reads as
        // "you may not ask" rather than "your pointer is bad".
        let r = call(Syscall::Getresuid.raw(), a2(BAD_PTR, 0, 0)).ok_or("getresuid not Ok")?;
        if r != EFAULT {
            return Err("getresuid(bad ptr) must return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getresuid_neg);

// ── getresgid ────────────────────────────────────────────────────────
fn smoke_abi_creds_getresgid_pos() -> TestResult {
    with_setup(|| {
        let mut rgid: u32 = 0x1111_1111;
        let mut egid: u32 = 0x2222_2222;
        let mut sgid: u32 = 0x3333_3333;
        let p0 = &mut rgid as *mut u32 as u64;
        let p1 = &mut egid as *mut u32 as u64;
        let p2 = &mut sgid as *mut u32 as u64;
        let r = call(Syscall::Getresgid.raw(), a2(p0, p1, p2)).ok_or("getresgid not Ok")?;
        if r != 0 {
            return Err("getresgid expected 0");
        }
        let gid = call(Syscall::GetGid.raw(), a0(0)).ok_or("getgid not Ok")? as u32;
        if rgid != gid || egid != gid || sgid != gid {
            return Err("getresgid did not fill all three slots with gid");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getresgid_pos);

fn smoke_abi_creds_getresgid_neg() -> TestResult {
    with_setup(|| {
        // As `getresuid` above: `SYSCALL_DEFINE3(getresgid)` returns its
        // `put_user` result, so an unwritable out-pointer is -EFAULT.
        let r = call(Syscall::Getresgid.raw(), a2(BAD_PTR, 0, 0)).ok_or("getresgid not Ok")?;
        if r != EFAULT {
            return Err("getresgid(bad ptr) must return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getresgid_neg);

// ── getgroups / setgroups ────────────────────────────────────────────
fn smoke_abi_creds_getgroups_pos() -> TestResult {
    with_setup(|| {
        let input = [10u32, 20, 30];
        if call(
            Syscall::Setgroups.raw(),
            a1(input.len() as u64, input.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setgroups did not install group list");
        }
        let count = call(Syscall::Getgroups.raw(), a1(0, 0)).ok_or("getgroups count")?;
        if count != input.len() as i64 {
            return Err("getgroups(0,NULL) returned wrong count");
        }
        let mut output = [0u32; 3];
        let n = call(
            Syscall::Getgroups.raw(),
            a1(output.len() as u64, output.as_mut_ptr() as u64),
        )
        .ok_or("getgroups data")?;
        if n != input.len() as i64 || output != input {
            return Err("getgroups did not round-trip group list");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getgroups_pos);

fn smoke_abi_creds_getgroups_neg() -> TestResult {
    with_setup(|| {
        let input = [10u32, 20];
        if call(
            Syscall::Setgroups.raw(),
            a1(input.len() as u64, input.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setgroups setup failed");
        }
        if call(Syscall::Getgroups.raw(), a1(1, BAD_PTR)) != Some(-22) {
            return Err("getgroups undersized list did not return EINVAL");
        }
        if call(Syscall::Getgroups.raw(), a1(2, BAD_PTR)) != Some(-14) {
            return Err("getgroups bad pointer did not return EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getgroups_neg);

// ── setgroups ────────────────────────────────────────────────────────
fn smoke_abi_creds_setgroups_pos() -> TestResult {
    with_setup(|| {
        let input = [7u32, 8];
        if call(
            Syscall::Setgroups.raw(),
            a1(input.len() as u64, input.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setgroups(nonempty) expected 0");
        }
        if call(Syscall::Setgroups.raw(), a1(0, 0)) != Some(0)
            || call(Syscall::Getgroups.raw(), a1(0, 0)) != Some(0)
        {
            return Err("setgroups(0,NULL) did not clear groups");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setgroups_pos);

fn smoke_abi_creds_setgroups_neg() -> TestResult {
    with_setup(|| {
        if call(Syscall::Setgroups.raw(), a1(4, BAD_PTR)) != Some(-14) {
            return Err("setgroups bad pointer did not return EFAULT");
        }
        if call(Syscall::Setgroups.raw(), a1(65_537, BAD_PTR)) != Some(-22) {
            return Err("setgroups above NGROUPS_MAX did not return EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setgroups_neg);

// ── getgroups / setgroups: argument width ────────────────────────────
// `kernel/groups.c` declares `gidsetsize` as a signed `int` in both
// calls. getgroups rejects a negative one outright; setgroups compares
// it as `unsigned` against NGROUPS_MAX, which is what makes a negative
// size EINVAL there. Either way only 32 bits are significant.

fn smoke_abi_creds_getgroups_negative_size_neg() -> TestResult {
    with_setup(|| {
        let input = [10u32, 20];
        if call(
            Syscall::Setgroups.raw(),
            a1(input.len() as u64, input.as_ptr() as u64),
        ) != Some(0)
        {
            return Err("setgroups setup failed");
        }
        // `if (gidsetsize < 0) return -EINVAL;` is the FIRST check. Reading
        // the argument as a 64-bit register turned this into an enormous
        // "size" that sailed past the `i > gidsetsize` bound and wrote the
        // whole list into a buffer the caller never sized.
        let mut out = [0u32; 4];
        let p = out.as_mut_ptr() as u64;
        if call(Syscall::Getgroups.raw(), a1((-1i32) as u32 as u64, p)) != Some(EINVAL) {
            return Err("getgroups(-1, buf) must return -EINVAL");
        }
        if call(Syscall::Getgroups.raw(), a1(i32::MIN as u32 as u64, p)) != Some(EINVAL) {
            return Err("getgroups(INT_MIN, buf) must return -EINVAL");
        }
        // Positive control: a roomy buffer still round-trips.
        if call(Syscall::Getgroups.raw(), a1(4, p)) != Some(2) || out[..2] != input {
            return Err("getgroups with a roomy buffer should still succeed");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getgroups_negative_size_neg);

fn smoke_abi_creds_getgroups_empty_list_pos() -> TestResult {
    with_setup(|| {
        if call(Syscall::Setgroups.raw(), a1(0, NULL_PTR)) != Some(0) {
            return Err("setgroups(0,NULL) setup failed");
        }
        // `groups_to_user()` copies exactly `ngroups` entries, so with no
        // supplementary groups it never dereferences `grouplist` — this is
        // a successful 0, not EFAULT.
        if call(Syscall::Getgroups.raw(), a1(4, NULL_PTR)) != Some(0) {
            return Err("getgroups(4,NULL) with an empty list should return 0");
        }
        if call(Syscall::Getgroups.raw(), a1(4, BAD_PTR)) != Some(0) {
            return Err("getgroups(4,badptr) with an empty list should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getgroups_empty_list_pos);

fn smoke_abi_creds_setgroups_size_width_pos() -> TestResult {
    with_setup(|| {
        // `(unsigned)gidsetsize > NGROUPS_MAX` reads 32 bits. A caller with
        // junk in the upper half of the register asked for setgroups(0),
        // and Linux honours it; the 64-bit read rejected it as EINVAL.
        if call(Syscall::Setgroups.raw(), a1(1u64 << 32, NULL_PTR)) != Some(0) {
            return Err("setgroups(0 with junk upper bits) should succeed");
        }
        if call(Syscall::Getgroups.raw(), a1(0, NULL_PTR)) != Some(0) {
            return Err("setgroups should have cleared the group list");
        }
        // A negative size is still EINVAL (it compares as a huge unsigned).
        if call(Syscall::Setgroups.raw(), a1((-1i32) as u32 as u64, BAD_PTR)) != Some(EINVAL) {
            return Err("setgroups(-1) must return -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setgroups_size_width_pos);

// ── capset / capget: version handshake vs. EPERM vs. EFAULT ──────────
// `kernel/capability.c`. EPERM is a LEGITIMATE answer from capset ("you
// asked about another process"), so it must not double as the generic
// failure value — and the version check runs BEFORE the data pointer is
// touched, so a caller with a stale header learns that first and gets the
// supported version written back.

const CAP_VERSION_3: u32 = 0x2008_0522;

fn smoke_abi_creds_capset_version_before_data_neg() -> TestResult {
    with_setup(|| {
        // `cap_validate_magic()` runs first: a bad version is -EINVAL with
        // the header rewritten, even though `datap` is NULL and would
        // otherwise be -EFAULT.
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        if call(Syscall::Capset.raw(), a1(hdr.as_mut_ptr() as u64, NULL_PTR)) != Some(EINVAL) {
            return Err("capset(bad version, NULL data) must return -EINVAL, not -EFAULT");
        }
        if u32::from_le_bytes(hdr[..4].try_into().unwrap()) != CAP_VERSION_3 {
            return Err("capset must write the supported version back into the header");
        }
        // With a good version, a null/faulting data pointer is -EFAULT.
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        if call(Syscall::Capset.raw(), a1(hdr.as_mut_ptr() as u64, NULL_PTR)) != Some(EFAULT) {
            return Err("capset(v3, NULL data) must return -EFAULT");
        }
        if call(Syscall::Capset.raw(), a1(hdr.as_mut_ptr() as u64, BAD_PTR)) != Some(EFAULT) {
            return Err("capset(v3, bad data) must return -EFAULT");
        }
        // …and a null header is -EFAULT before anything else.
        if call(Syscall::Capset.raw(), a1(NULL_PTR, NULL_PTR)) != Some(EFAULT) {
            return Err("capset(NULL header) must return -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_creds_capset_version_before_data_neg
);

fn smoke_abi_creds_capget_negative_pid_neg() -> TestResult {
    with_setup(|| {
        // `if (pid < 0) return -EINVAL;` — the header pid is a signed
        // `int`, and a negative one is malformed, not "some other task".
        let mut hdr = [0u8; 8];
        hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
        hdr[4..].copy_from_slice(&(-1i32).to_le_bytes());
        let mut data = [0u8; 24];
        if call(
            Syscall::Capget.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        ) != Some(EINVAL)
        {
            return Err("capget with a negative header pid must return -EINVAL");
        }
        // Positive control: pid 0 (self) still round-trips.
        hdr[4..].copy_from_slice(&0i32.to_le_bytes());
        if call(
            Syscall::Capget.raw(),
            a1(hdr.as_mut_ptr() as u64, data.as_mut_ptr() as u64),
        ) != Some(0)
        {
            return Err("capget(pid=0) should return 0");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_capget_negative_pid_neg);

// ── gethostname ──────────────────────────────────────────────────────
// arg0 = buf, arg1 = len. Success ⇒ Ok(hostname byte length). buf==0 or
// len==0 ⇒ Ok(-1); buf too small for name+NUL ⇒ Ok(-1).
fn smoke_abi_creds_gethostname_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 128];
        let p = buf.as_mut_ptr() as u64;
        let r = call(Syscall::GetHostname.raw(), a1(p, buf.len() as u64))
            .ok_or("gethostname not Ok")?;
        if r < 0 {
            return Err("gethostname into a roomy buffer should not fail");
        }
        // Returned length is the byte count (excludes the trailing NUL it
        // also writes); the NUL must sit right after it.
        let n = r as usize;
        if n >= buf.len() || buf[n] != 0 {
            return Err("gethostname did not NUL-terminate at returned length");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_gethostname_pos);

fn smoke_abi_creds_gethostname_neg() -> TestResult {
    with_setup(|| {
        // `kernel/sys.c::SYSCALL_DEFINE2(gethostname)` — a buffer with no
        // room for name+NUL is -ENAMETOOLONG (the errno POSIX specifies,
        // and the one glibc's uname()-based gethostname raises). As the
        // bare -1 it reached libc as EPERM, so a caller running the
        // standard grow-the-buffer-and-retry loop gave up instead of
        // retrying with a bigger buffer.
        let mut buf = [0u8; 16];
        let p = buf.as_mut_ptr() as u64;
        let r = call(Syscall::GetHostname.raw(), a1(p, 0)).ok_or("gethostname not Ok")?;
        if r != ENAMETOOLONG {
            return Err("gethostname(buf,0) expected -ENAMETOOLONG");
        }
        // `if (len < 0) return -EINVAL;` — and `len` is a signed `int`.
        // Read as a 64-bit register, -1 became a colossal length that
        // passed the fits-in-the-buffer test and wrote past the array.
        let neg = call(Syscall::GetHostname.raw(), a1(p, (-1i32) as u32 as u64))
            .ok_or("gethostname not Ok")?;
        if neg != EINVAL {
            return Err("gethostname(buf,-1) expected -EINVAL");
        }
        // A destination the copy cannot reach is -EFAULT.
        let r2 = call(Syscall::GetHostname.raw(), a1(NULL_PTR, 64)).ok_or("gethostname not Ok")?;
        if r2 != EFAULT {
            return Err("gethostname(NULL,64) expected -EFAULT");
        }
        let r3 = call(Syscall::GetHostname.raw(), a1(BAD_PTR, 64)).ok_or("gethostname not Ok")?;
        if r3 != EFAULT {
            return Err("gethostname(BAD_PTR,64) expected -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_gethostname_neg);

// ── sethostname ──────────────────────────────────────────────────────
// arg0 = buf (raw bytes, length-delimited — NOT NUL-terminated), arg1 =
// len. Success ⇒ Ok(0). len==0 or len>HOSTNAME_MAX(64) ⇒ Ok(-1).
fn smoke_abi_creds_sethostname_pos() -> TestResult {
    with_setup(|| {
        let name = b"narfbox";
        let r = call(
            Syscall::SetHostname.raw(),
            a1(name.as_ptr() as u64, name.len() as u64),
        )
        .ok_or("sethostname not Ok")?;
        if r != 0 {
            return Err("sethostname(valid) expected 0");
        }
        // Round-trip: gethostname should now read it back.
        let mut buf = [0u8; 64];
        let got = call(
            Syscall::GetHostname.raw(),
            a1(buf.as_mut_ptr() as u64, buf.len() as u64),
        )
        .ok_or("gethostname not Ok")?;
        if got != name.len() as i64 || &buf[..name.len()] != name {
            return Err("sethostname/gethostname round-trip mismatch");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_sethostname_pos);

fn smoke_abi_creds_sethostname_neg() -> TestResult {
    with_setup(|| {
        // len > __NEW_UTS_LEN (64) ⇒ -EINVAL.
        let big = [b'x'; 65];
        if call(
            Syscall::SetHostname.raw(),
            a1(big.as_ptr() as u64, big.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("sethostname(len>64) expected -EINVAL");
        }
        // A faulting name of a valid length ⇒ -EFAULT.
        if call(Syscall::SetHostname.raw(), a1(BAD_PTR, 8)) != Some(EFAULT) {
            return Err("sethostname(faulting name) expected -EFAULT");
        }
        // len == 0 is legal in Linux (sets an empty hostname) ⇒ 0.
        if call(Syscall::SetHostname.raw(), a1(big.as_ptr() as u64, 0)) != Some(0) {
            return Err("sethostname(len=0) expected 0 (empty hostname)");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_sethostname_neg);

// ── uname ────────────────────────────────────────────────────────────
// arg0 = buf (struct utsname, 6 × 65 = 390 bytes). buf==0 ⇒ Ok(-1);
// success ⇒ Ok(0) with "NARF" in sysname.
fn smoke_abi_creds_uname_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 6 * 65];
        let r = call(Syscall::Uname.raw(), a0(buf.as_mut_ptr() as u64)).ok_or("uname not Ok")?;
        if r != 0 {
            return Err("uname(valid) expected 0");
        }
        // sysname field (first 65 bytes) must be "NARF\0...".
        if &buf[..4] != b"NARF" || buf[4] != 0 {
            return Err("uname sysname is not NARF");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_uname_pos);

fn smoke_abi_creds_uname_neg() -> TestResult {
    with_setup(|| {
        // NULL buf ⇒ -EFAULT (copy_to_user of the utsname struct).
        if call(Syscall::Uname.raw(), a0(NULL_PTR)) != Some(EFAULT) {
            return Err("uname(NULL) expected -EFAULT");
        }
        // A faulting non-NULL buf is likewise -EFAULT.
        if call(Syscall::Uname.raw(), a0(BAD_PTR)) != Some(EFAULT) {
            return Err("uname(faulting buf) expected -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_uname_neg);

// ── setdomainname ────────────────────────────────────────────────────
// arg0 = buf (length-delimited), arg1 = len. Success ⇒ Ok(0). len==0 or
// len>HOSTNAME_MAX(64) ⇒ Ok(-1).
fn smoke_abi_creds_setdomainname_pos() -> TestResult {
    with_setup(|| {
        let dom = b"narf.local";
        let r = call(
            Syscall::Setdomainname.raw(),
            a1(dom.as_ptr() as u64, dom.len() as u64),
        )
        .ok_or("setdomainname not Ok")?;
        if r != 0 {
            return Err("setdomainname(valid) expected 0");
        }
        // The domainname now flows into uname's 6th field (offset 5*65).
        let mut buf = [0u8; 6 * 65];
        let _ = call(Syscall::Uname.raw(), a0(buf.as_mut_ptr() as u64)).ok_or("uname not Ok")?;
        if &buf[5 * 65..5 * 65 + dom.len()] != dom {
            return Err("setdomainname not reflected in uname domainname field");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setdomainname_pos);

fn smoke_abi_creds_setdomainname_neg() -> TestResult {
    with_setup(|| {
        // len > 64 ⇒ -EINVAL.
        let big = [b'd'; 65];
        if call(
            Syscall::Setdomainname.raw(),
            a1(big.as_ptr() as u64, big.len() as u64),
        ) != Some(EINVAL)
        {
            return Err("setdomainname(len>64) expected -EINVAL");
        }
        // A faulting name of a valid length ⇒ -EFAULT.
        if call(Syscall::Setdomainname.raw(), a1(BAD_PTR, 8)) != Some(EFAULT) {
            return Err("setdomainname(faulting name) expected -EFAULT");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_setdomainname_neg);

// ── umask ────────────────────────────────────────────────────────────
// arg0 = new mask (& 0o777). Returns the PRIOR mask; never an errno. If
// the per-task table is uninitialised it returns UMASK_DEFAULT (0o022)
// and does not persist; if initialised, the value round-trips.
fn smoke_abi_creds_umask_pos() -> TestResult {
    with_setup(|| {
        // Set a known mask, then set again to read the prior value back.
        let _ = call(Syscall::Umask.raw(), a0(0o027)).ok_or("umask not Ok")?;
        let prior = call(Syscall::Umask.raw(), a0(0o022)).ok_or("umask#2 not Ok")?;
        // Either the table persisted our 0o027, or it's uninitialised and
        // we keep getting the 0o022 default. Both are valid Ok shapes.
        if prior != 0o027 && prior != 0o022 {
            return Err("umask prior was neither our set value nor the default");
        }
        if prior < 0 {
            return Err("umask returned negative");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_umask_pos);

fn smoke_abi_creds_umask_neg() -> TestResult {
    with_setup(|| {
        // umask has no error path: high bits beyond 0o777 are masked off
        // and it still returns a valid (non-negative, <= 0o777) prior
        // mask. Pin that the junk high bits do not leak into the return.
        let r = call(Syscall::Umask.raw(), a0(0xFFFF_F123)).ok_or("umask not Ok")?;
        if !(0..=0o777).contains(&r) {
            return Err("umask return outside 0..=0o777");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_umask_neg);

// ── getrandom ────────────────────────────────────────────────────────
// arg0 = buf, arg1 = len, arg2 = flags (ignored). ptr==0 ⇒ Ok(-1);
// len==0 ⇒ Ok(0); len>MAX_USER_COPY ⇒ Ok(-EINVAL); else fills buf and
// returns Ok(len).
fn smoke_abi_creds_getrandom_pos() -> TestResult {
    with_setup(|| {
        let mut buf = [0u8; 32];
        let r = call(
            Syscall::GetRandom.raw(),
            a2(buf.as_mut_ptr() as u64, buf.len() as u64, 0),
        )
        .ok_or("getrandom not Ok")?;
        if r != buf.len() as i64 {
            return Err("getrandom expected to return the requested length");
        }
        // The buffer should no longer be all-zero (probabilistic, but a
        // 256-bit all-zero draw is not a real concern).
        if buf.iter().all(|&b| b == 0) {
            return Err("getrandom left the buffer all-zero");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getrandom_pos);

fn smoke_abi_creds_getrandom_neg() -> TestResult {
    with_setup(|| {
        // `import_ubuf`'s `access_ok` arm: a NULL buffer is -EFAULT.
        let r = call(Syscall::GetRandom.raw(), a2(NULL_PTR, 16, 0)).ok_or("getrandom not Ok")?;
        if r != -14 {
            return Err("getrandom(NULL,16) expected -EFAULT");
        }
        // len==0 with a valid pointer ⇒ Ok(0) (nothing to do).
        let mut one = [0u8; 1];
        let r0 = call(Syscall::GetRandom.raw(), a2(one.as_mut_ptr() as u64, 0, 0))
            .ok_or("getrandom not Ok")?;
        if r0 != 0 {
            return Err("getrandom(buf,0) expected 0");
        }
        // len > MAX_USER_COPY (16 MiB) ⇒ Ok(-EINVAL).
        let r_big = call(
            Syscall::GetRandom.raw(),
            a2(one.as_mut_ptr() as u64, (16 * 1024 * 1024 + 1) as u64, 0),
        )
        .ok_or("getrandom not Ok")?;
        if r_big != EINVAL {
            return Err("getrandom(huge len) expected -EINVAL");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_creds_getrandom_neg);

// ─────────────────────────────────────────────────────────────────────
// Capability enforcement — security/commoncap.c + kernel/sys.c
//
// Before this existed, CAP_TABLE was an ABI round-trip store: capset
// wrote whatever it was handed, and no syscall consulted the result. The
// tests below pin the two halves that make it a credential instead of a
// buffer — capset refusing to grant, and the call sites consulting it.
//
// The harness task holds `Caps::boot` (the full set) unless a case drops
// it with `__test_set_caps`, which mirrors boot: init is privileged and
// everything else descends from it.
// ─────────────────────────────────────────────────────────────────────

/// Build a v3 capget/capset header + data pair. Data is
/// `{ effective, permitted, inheritable }` x2 (low then high 32 bits).
fn cap_hdr(pid: i32) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
    h[4..].copy_from_slice(&pid.to_le_bytes());
    h
}

fn cap_data(effective: u64, permitted: u64, inheritable: u64) -> [u8; 24] {
    let mut d = [0u8; 24];
    for (i, v) in [effective, permitted, inheritable].into_iter().enumerate() {
        d[i * 4..i * 4 + 4].copy_from_slice(&(v as u32).to_le_bytes());
        d[12 + i * 4..12 + i * 4 + 4].copy_from_slice(&((v >> 32) as u32).to_le_bytes());
    }
    d
}

fn do_capset(effective: u64, permitted: u64, inheritable: u64) -> Option<i64> {
    let hdr = cap_hdr(0);
    let data = cap_data(effective, permitted, inheritable);
    call(
        Syscall::Capset.raw(),
        a1(hdr.as_ptr() as u64, data.as_ptr() as u64),
    )
}

/// Read back (effective, permitted, inheritable) via capget.
fn do_capget() -> Result<(u64, u64, u64), &'static str> {
    let hdr = cap_hdr(0);
    let mut data = [0u8; 24];
    match call(
        Syscall::Capget.raw(),
        a1(hdr.as_ptr() as u64, data.as_mut_ptr() as u64),
    ) {
        Some(0) => {}
        _ => return Err("capget failed"),
    }
    let field = |i: usize| {
        let lo = u32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().unwrap()) as u64;
        let hi = u32::from_le_bytes(data[12 + i * 4..12 + i * 4 + 4].try_into().unwrap()) as u64;
        lo | (hi << 32)
    };
    Ok((field(0), field(1), field(2)))
}

const CAP_SETUID_BIT: u64 = 1 << 7;
const CAP_SETGID_BIT: u64 = 1 << 6;
const CAP_SYS_ADMIN_BIT: u64 = 1 << 21;
const CAP_SYS_CHROOT_BIT: u64 = 1 << 18;
const CAP_SYS_TIME_BIT: u64 = 1 << 25;

fn drop_all_caps() {
    crate::handlers::__test_set_caps(FAKE_TASK, 0, 0);
}

fn set_caps(effective: u64, permitted: u64) {
    crate::handlers::__test_set_caps(FAKE_TASK, effective, permitted);
}

// ── capset: the gate that makes every other check meaningful ─────────

fn smoke_abi_caps_capset_cannot_grant_beyond_permitted() -> TestResult {
    with_setup(|| {
        // `if (!cap_issubset(*permitted, old->cap_permitted)) return -EPERM;`
        //
        // This is THE load-bearing rule. Without it a task hands itself
        // CAP_SETUID and every capable() gate in the tree is decorative:
        // `capset(CAP_SETUID); setuid(0);` would succeed from an
        // unprivileged process.
        drop_all_caps();
        match do_capset(CAP_SETUID_BIT, CAP_SETUID_BIT, 0) {
            Some(-1) => {}
            Some(0) => return Err("capset granted a capability the task did not hold"),
            _ => return Err("capset with an out-of-permitted raise: want -EPERM"),
        }
        // And the store must be unchanged, not partially written.
        match do_capget()? {
            (0, 0, 0) => Ok(()),
            _ => Err("a refused capset still mutated the credential"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_capset_cannot_grant_beyond_permitted
);

fn smoke_abi_caps_capset_may_drop() -> TestResult {
    with_setup(|| {
        // Shrinking pP is always allowed — that is how a privileged
        // service sheds capabilities it no longer needs.
        set_caps(
            CAP_SETUID_BIT | CAP_SETGID_BIT,
            CAP_SETUID_BIT | CAP_SETGID_BIT,
        );
        match do_capset(CAP_SETGID_BIT, CAP_SETGID_BIT, 0) {
            Some(0) => {}
            _ => return Err("capset could not drop a capability"),
        }
        match do_capget()? {
            (e, p, _) if e == CAP_SETGID_BIT && p == CAP_SETGID_BIT => Ok(()),
            _ => Err("capget did not read back the dropped credential"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_capset_may_drop);

fn smoke_abi_caps_capset_drop_is_irreversible() -> TestResult {
    with_setup(|| {
        // The consequence of pP being monotonically shrinking: once
        // dropped, a capability cannot be re-raised. A drop that could be
        // undone is not a drop.
        set_caps(CAP_SETUID_BIT, CAP_SETUID_BIT);
        if do_capset(0, 0, 0) != Some(0) {
            return Err("capset could not drop to the empty set");
        }
        match do_capset(CAP_SETUID_BIT, CAP_SETUID_BIT, 0) {
            Some(-1) => Ok(()),
            Some(0) => Err("a dropped capability was re-raised"),
            _ => Err("re-raising a dropped capability: want -EPERM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_capset_drop_is_irreversible);

fn smoke_abi_caps_capset_effective_must_be_within_permitted() -> TestResult {
    with_setup(|| {
        // `if (!cap_issubset(*effective, *permitted)) return -EPERM;`
        // An effective bit with no permitted bit behind it would be a
        // capability the task can exercise but was never granted.
        set_caps(CAP_SETUID_BIT, CAP_SETUID_BIT);
        match do_capset(CAP_SETUID_BIT, 0, 0) {
            Some(-1) => Ok(()),
            Some(0) => Err("capset allowed pE to exceed pP"),
            _ => Err("capset with pE outside pP: want -EPERM"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_capset_effective_must_be_within_permitted
);

fn smoke_abi_caps_capset_inheritable_bounded() -> TestResult {
    with_setup(|| {
        // `if (!cap_issubset(*inheritable, cap_combine(old->cap_inheritable,
        //                    old->cap_permitted))) return -EPERM;`
        // pI cannot name something the task neither holds nor already
        // inherits.
        drop_all_caps();
        match do_capset(0, 0, CAP_SETUID_BIT) {
            Some(-1) => Ok(()),
            Some(0) => Err("capset allowed pI outside pP|pI"),
            _ => Err("capset with an unbacked inheritable bit: want -EPERM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_capset_inheritable_bounded);

// ── setuid / setgid: the CAP_SETUID rule from kernel/sys.c ───────────

fn smoke_abi_caps_setuid_unprivileged_is_eperm() -> TestResult {
    with_setup(|| {
        // `else if (!uid_eq(kuid, old->uid) && !uid_eq(kuid, new->suid))
        //          goto error;`  /* -EPERM */
        // The harness task is uid 0 / suid 0, so 4242 is neither.
        drop_all_caps();
        match call(Syscall::SetUid.raw(), a0(4242)) {
            Some(-1) => Ok(()),
            Some(0) => Err("an unprivileged task changed its uid to an arbitrary id"),
            _ => Err("unprivileged setuid: want -EPERM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_setuid_unprivileged_is_eperm);

fn smoke_abi_caps_setuid_needs_capset_first_and_capset_refuses() -> TestResult {
    with_setup(|| {
        // The composed attack the whole design exists to stop: ask for the
        // capability, then use it. Both halves must refuse.
        drop_all_caps();
        if do_capset(CAP_SETUID_BIT, CAP_SETUID_BIT, 0) == Some(0) {
            return Err("capset self-granted CAP_SETUID");
        }
        match call(Syscall::SetUid.raw(), a0(0xFFFF_FFFE)) {
            Some(-1) => Ok(()),
            Some(0) => Err("capset+setuid escalated an unprivileged task"),
            _ => Err("setuid after a refused capset: want -EPERM"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setuid_needs_capset_first_and_capset_refuses
);

fn smoke_abi_caps_setuid_privileged_moves_every_id() -> TestResult {
    with_setup(|| {
        // `new->suid = new->uid = kuid; ... new->fsuid = new->euid = kuid;`
        // With CAP_SETUID the change is total, which is what makes it
        // irreversible: no id is left holding the old value to return to.
        set_caps(CAP_SETUID_BIT, CAP_SETUID_BIT);
        if call(Syscall::SetUid.raw(), a0(1000)) != Some(0) {
            return Err("privileged setuid failed");
        }
        let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
        if call(
            Syscall::Getresuid.raw(),
            a2(
                &mut r as *mut u32 as u64,
                &mut e as *mut u32 as u64,
                &mut s as *mut u32 as u64,
            ),
        ) != Some(0)
        {
            return Err("getresuid failed");
        }
        if (r, e, s) == (1000, 1000, 1000) {
            Ok(())
        } else {
            Err("privileged setuid did not move real, effective AND saved uid")
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setuid_privileged_moves_every_id
);

fn smoke_abi_caps_setuid_unprivileged_restore_from_saved() -> TestResult {
    with_setup(|| {
        // The reason the saved uid has to be a real field: an unprivileged
        // caller may switch to `old->suid`, and only euid/fsuid move. That
        // is a set-uid program dropping privilege reversibly.
        //
        // Reach the state the way a real program does — a privileged
        // setresuid(-1, 1000, 0) leaves suid 0 behind — then drop caps.
        set_caps(CAP_SETUID_BIT, CAP_SETUID_BIT);
        if call(Syscall::Setresuid.raw(), a2(u32::MAX as u64, 1000, 0)) != Some(0) {
            return Err("setresuid setup failed");
        }
        drop_all_caps();
        // suid is 0, so switching back to 0 is permitted without CAP_SETUID.
        if call(Syscall::SetUid.raw(), a0(0)) != Some(0) {
            return Err("unprivileged setuid to the SAVED uid was refused");
        }
        let (mut r, mut e, mut s) = (9u32, 9u32, 9u32);
        if call(
            Syscall::Getresuid.raw(),
            a2(
                &mut r as *mut u32 as u64,
                &mut e as *mut u32 as u64,
                &mut s as *mut u32 as u64,
            ),
        ) != Some(0)
        {
            return Err("getresuid failed");
        }
        // Only the effective id moved; real and saved are untouched.
        if e != 0 {
            return Err("unprivileged setuid did not move the effective uid");
        }
        if s != 0 {
            return Err("unprivileged setuid clobbered the saved uid");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setuid_unprivileged_restore_from_saved
);

fn smoke_abi_caps_getresuid_reports_a_distinct_saved_id() -> TestResult {
    with_setup(|| {
        // getresuid used to write the same value into all three slots
        // because no saved id existed. A set-uid program reads the third
        // slot to learn what it can still restore, so duplicating the
        // effective id there reports a reversible drop as permanent.
        set_caps(CAP_SETUID_BIT, CAP_SETUID_BIT);
        if call(Syscall::Setresuid.raw(), a2(0, 1000, 0)) != Some(0) {
            return Err("setresuid setup failed");
        }
        let (mut r, mut e, mut s) = (9u32, 9u32, 9u32);
        if call(
            Syscall::Getresuid.raw(),
            a2(
                &mut r as *mut u32 as u64,
                &mut e as *mut u32 as u64,
                &mut s as *mut u32 as u64,
            ),
        ) != Some(0)
        {
            return Err("getresuid failed");
        }
        match (r, e, s) {
            (0, 1000, 0) => Ok(()),
            (0, 1000, 1000) => Err("getresuid reported the effective uid as the saved uid"),
            _ => Err("getresuid did not report (real, effective, saved)"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_getresuid_reports_a_distinct_saved_id
);

fn smoke_abi_caps_setresuid_permutation_needs_no_capability() -> TestResult {
    with_setup(|| {
        // `ruid_new = ruid != -1 && !uid_eq(kruid, old->uid) &&
        //             !uid_eq(kruid, old->euid) && !uid_eq(kruid, old->suid);`
        // Only a GENUINELY NEW id needs CAP_SETUID; rearranging ids the
        // task already holds does not.
        set_caps(CAP_SETUID_BIT, CAP_SETUID_BIT);
        if call(Syscall::Setresuid.raw(), a2(0, 1000, 0)) != Some(0) {
            return Err("setresuid setup failed");
        }
        drop_all_caps();
        // Swap effective and saved — both ids are already held.
        match call(Syscall::Setresuid.raw(), a2(u32::MAX as u64, 0, 1000)) {
            Some(0) => {}
            Some(-1) => return Err("setresuid refused a permutation of ids already held"),
            _ => return Err("setresuid permutation: unexpected return"),
        }
        // But introducing a new id is -EPERM.
        match call(
            Syscall::Setresuid.raw(),
            a2(u32::MAX as u64, 4242, u32::MAX as u64),
        ) {
            Some(-1) => Ok(()),
            Some(0) => Err("setresuid introduced a new uid without CAP_SETUID"),
            _ => Err("setresuid with a new id: want -EPERM"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setresuid_permutation_needs_no_capability
);

fn smoke_abi_caps_setgid_unprivileged_is_eperm() -> TestResult {
    with_setup(|| {
        // `else if (gid_eq(kgid, old->gid) || gid_eq(kgid, old->sgid)) ...
        //  else goto error;`
        drop_all_caps();
        match call(Syscall::SetGid.raw(), a0(4242)) {
            Some(-1) => Ok(()),
            Some(0) => Err("an unprivileged task changed its gid to an arbitrary id"),
            _ => Err("unprivileged setgid: want -EPERM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_setgid_unprivileged_is_eperm);

fn smoke_abi_caps_setreuid_saved_is_a_source_for_euid_only() -> TestResult {
    with_setup(|| {
        // The permitted source sets DIFFER between setreuid's two
        // arguments: a new REAL uid may come from {uid, euid}; a new
        // EFFECTIVE uid may come from {uid, euid, suid}. So with
        // (uid=0, euid=1000, suid=0), setreuid(-1, 0) is allowed by the
        // saved id but setreuid(2000, -1) is not.
        set_caps(CAP_SETUID_BIT, CAP_SETUID_BIT);
        if call(Syscall::Setresuid.raw(), a2(1000, 1000, 0)) != Some(0) {
            return Err("setresuid setup failed");
        }
        drop_all_caps();
        // euid <- 0 is permitted: 0 is the saved uid.
        if call(Syscall::Setreuid.raw(), a1(u32::MAX as u64, 0)) != Some(0) {
            return Err("setreuid(-1, saved) was refused");
        }
        // ruid <- 2000 is not: it is none of uid/euid.
        match call(Syscall::Setreuid.raw(), a1(2000, u32::MAX as u64)) {
            Some(-1) => Ok(()),
            Some(0) => Err("setreuid took a real uid from outside {uid, euid}"),
            _ => Err("setreuid with an unrelated real uid: want -EPERM"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setreuid_saved_is_a_source_for_euid_only
);

// ── CAP_SYS_ADMIN / CHROOT / TIME, and where each check SITS ─────────

fn smoke_abi_caps_sethostname_requires_sys_admin() -> TestResult {
    with_setup(|| {
        drop_all_caps();
        let name = b"host\0";
        match call(Syscall::SetHostname.raw(), a1(name.as_ptr() as u64, 4)) {
            Some(-1) => {}
            Some(0) => return Err("an unprivileged task set the hostname"),
            _ => return Err("unprivileged sethostname: want -EPERM"),
        }
        set_caps(CAP_SYS_ADMIN_BIT, CAP_SYS_ADMIN_BIT);
        match call(Syscall::SetHostname.raw(), a1(name.as_ptr() as u64, 4)) {
            Some(0) => Ok(()),
            _ => Err("sethostname with CAP_SYS_ADMIN should succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_sethostname_requires_sys_admin);

fn smoke_abi_caps_sethostname_eperm_precedes_einval_and_efault() -> TestResult {
    with_setup(|| {
        // `if (!ns_capable(...)) return -EPERM;` is the FIRST line of
        // SYSCALL_DEFINE2(sethostname) — before the length check and
        // before the copy. An unprivileged caller learns nothing about
        // whether its other arguments were also wrong.
        drop_all_caps();
        // Over-long length AND an unmapped buffer, together.
        match call(Syscall::SetHostname.raw(), a1(BAD_PTR, 1 << 20)) {
            Some(-1) => Ok(()),
            Some(-22) => Err("sethostname checked the length before the capability"),
            Some(-14) => Err("sethostname copied from the buffer before the capability check"),
            _ => Err("sethostname(bad len, bad ptr, no cap): want -EPERM"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_sethostname_eperm_precedes_einval_and_efault
);

fn smoke_abi_caps_settimeofday_eperm_comes_last() -> TestResult {
    with_setup(|| {
        // The mirror image of sethostname, and the reason each site had to
        // be placed individually rather than by rule: `security_settime64`
        // sits INSIDE do_sys_settimeofday64, after the wrapper's EFAULT and
        // after the value EINVAL. An unprivileged caller with a bad pointer
        // gets -EFAULT, not -EPERM.
        drop_all_caps();
        match call(Syscall::Settimeofday.raw(), a1(BAD_PTR, 0)) {
            Some(-14) => {}
            Some(-1) => return Err("settimeofday checked the capability before the pointer"),
            _ => return Err("settimeofday(bad ptr): want -EFAULT"),
        }
        // Valid pointer, invalid tv_usec → EINVAL still beats EPERM.
        let tv: [i64; 2] = [1, 2_000_000];
        match call(Syscall::Settimeofday.raw(), a1(tv.as_ptr() as u64, 0)) {
            Some(-22) => {}
            Some(-1) => return Err("settimeofday checked the capability before the value"),
            _ => return Err("settimeofday(bad tv_usec): want -EINVAL"),
        }
        // Everything valid, still unprivileged → EPERM.
        let good: [i64; 2] = [1, 0];
        match call(Syscall::Settimeofday.raw(), a1(good.as_ptr() as u64, 0)) {
            Some(-1) => Ok(()),
            Some(0) => Err("an unprivileged task set the wall clock"),
            _ => Err("unprivileged settimeofday: want -EPERM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_settimeofday_eperm_comes_last);

fn smoke_abi_caps_clock_settime_requires_sys_time() -> TestResult {
    with_setup(|| {
        let ts: [i64; 2] = [1, 0];
        drop_all_caps();
        match call(Syscall::ClockSetTime.raw(), a1(0, ts.as_ptr() as u64)) {
            Some(-1) => {}
            Some(0) => return Err("an unprivileged task set CLOCK_REALTIME"),
            _ => return Err("unprivileged clock_settime: want -EPERM"),
        }
        set_caps(CAP_SYS_TIME_BIT, CAP_SYS_TIME_BIT);
        match call(Syscall::ClockSetTime.raw(), a1(0, ts.as_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("clock_settime with CAP_SYS_TIME should succeed"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_clock_settime_requires_sys_time
);

fn smoke_abi_caps_chroot_enoent_still_precedes_eperm() -> TestResult {
    with_setup(|| {
        // `error = -EPERM; if (!ns_capable(current_user_ns(),
        //  CAP_SYS_CHROOT)) goto dput_and_out;` runs AFTER filename_lookup,
        // so a path that does not exist is -ENOENT even for an
        // unprivileged caller. Hoisting the capability check to the top of
        // the handler would leak less than Linux does — and diverge from
        // it, breaking a program that tells the two apart.
        // The probe is the EMPTY path, whose -ENOENT arm (`getname()`
        // rejects "" with -ENOENT) is the one NARF actually reaches before
        // the capability check.
        //
        // A non-existent path like "/definitely-not-here" does NOT work as
        // the probe here, and the reason is a pre-existing gap rather than
        // anything to do with capabilities: NARF's existence test is
        // `resolve_absolute(...).unwrap_or(false)`, which asks whether a
        // filesystem COVERS the path, not whether the entry exists. With
        // "/" mounted, every absolute path is covered — the LINUX-GAP
        // already recorded in sys_chroot.rs.
        drop_all_caps();
        let path = b"\0";
        match call(Syscall::Chroot.raw(), a0(path.as_ptr() as u64)) {
            Some(-2) => Ok(()),
            Some(-1) => Err("chroot checked the capability before resolving the path"),
            _ => Err("chroot on an empty path: want -ENOENT"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_chroot_enoent_still_precedes_eperm
);

fn smoke_abi_caps_chroot_requires_sys_chroot() -> TestResult {
    with_setup(|| {
        // Past the lookup, on a path that DOES resolve, the capability is
        // what decides.
        let root = b"/\0";
        drop_all_caps();
        match call(Syscall::Chroot.raw(), a0(root.as_ptr() as u64)) {
            Some(-1) => {}
            Some(0) => return Err("an unprivileged task called chroot"),
            _ => return Err("unprivileged chroot on an existing dir: want -EPERM"),
        }
        set_caps(CAP_SYS_CHROOT_BIT, CAP_SYS_CHROOT_BIT);
        match call(Syscall::Chroot.raw(), a0(root.as_ptr() as u64)) {
            Some(0) => Ok(()),
            _ => Err("chroot(\"/\") with CAP_SYS_CHROOT should succeed"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_chroot_requires_sys_chroot);

fn smoke_abi_caps_fork_inherits_the_credential() -> TestResult {
    with_setup(|| {
        // `kernel/fork.c` copies the parent's struct cred wholesale;
        // capabilities are transformed at EXECVE, not at fork. A child
        // that did not inherit a dropped set would undo the drop.
        set_caps(CAP_SETGID_BIT, CAP_SETGID_BIT);
        const CHILD: u64 = 0xCA9F;
        crate::handlers::__test_cap_fork(FAKE_TASK, CHILD);
        if !crate::handlers::__test_task_capable(CHILD, 6) {
            return Err("fork child did not inherit CAP_SETGID");
        }
        if crate::handlers::__test_task_capable(CHILD, 7) {
            return Err("fork child gained CAP_SETUID its parent did not hold");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_fork_inherits_the_credential);

// ─────────────────────────────────────────────────────────────────────
// The remaining permission gates, now that capable() exists.
//
// These were the LINUX-GAP notes that said the check "is not modelled" —
// true only because there was no credential to consult. Each is placed
// where Linux places it, which differs per call.
// ─────────────────────────────────────────────────────────────────────

const CAP_SYS_NICE_BIT: u64 = 1 << 23;

fn smoke_abi_caps_mount_requires_sys_admin() -> TestResult {
    with_setup(|| {
        // `path_mount`: `if (!may_mount()) return -EPERM;` where may_mount
        // is ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN).
        let src = b"none\0";
        let tgt = b"/mnt\0";
        let fst = b"tmpfs\0";
        drop_all_caps();
        match call(
            Syscall::Mount.raw(),
            a4(
                src.as_ptr() as u64,
                tgt.as_ptr() as u64,
                fst.as_ptr() as u64,
                0,
                0,
            ),
        ) {
            Some(-1) => Ok(()),
            Some(0) => Err("an unprivileged task mounted a filesystem"),
            _ => Err("unprivileged mount: want -EPERM"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_mount_requires_sys_admin);

fn smoke_abi_caps_mount_efault_precedes_eperm() -> TestResult {
    with_setup(|| {
        // `may_mount()` sits inside path_mount, AFTER the four
        // copy_mount_string calls in the syscall wrapper. So an
        // unprivileged caller with a faulting pointer still gets -EFAULT.
        drop_all_caps();
        let tgt = b"/mnt\0";
        let fst = b"tmpfs\0";
        match call(
            Syscall::Mount.raw(),
            a4(0, tgt.as_ptr() as u64, fst.as_ptr() as u64, 0, BAD_PTR),
        ) {
            Some(-14) => Ok(()),
            Some(-1) => Err("mount checked the capability before copying its strings"),
            _ => Err("mount(bad data ptr, no cap): want -EFAULT"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_mount_efault_precedes_eperm);

/// `unshare(CLONE_NEWUSER)` rebinds the caller's credentials to the new
/// namespace with a FULL capability set
/// (`kernel/user_namespace.c::set_cred_user_ns`):
///
///     cred->cap_permitted = CAP_FULL_SET;
///     cred->cap_effective = CAP_FULL_SET;
///     cred->cap_bset      = CAP_FULL_SET;
///
/// above the comment "Start with the same capabilities as init but useless
/// for doing anything as the capabilities are bound to the new user
/// namespace". `ksys_unshare` builds that credential BEFORE
/// `unshare_nsproxy_namespaces` tests CAP_SYS_ADMIN, and that test reads
/// `user_ns = new_cred ? new_cred->user_ns : current_user_ns()` — so the
/// combined call authorises itself.
///
/// This is the whole of rootless containers, and NARF refused it: the
/// capability test ran first, against the old unprivileged credentials.
///
/// The last arm is the one that makes the grant safe rather than a hole. A
/// full capability set that also worked on the HOST would be an escalation
/// available to any process, since creating a user namespace needs no
/// privilege at all.
fn smoke_abi_caps_newuser_grants_authority_only_inside_the_namespace() -> TestResult {
    with_setup(|| {
        const CLONE_NEWUTS: u64 = 0x0400_0000;
        const CLONE_NEWUSER: u64 = 0x1000_0000;
        drop_all_caps();

        // Control: on its own, CLONE_NEWUTS needs CAP_SYS_ADMIN and the
        // caller has none.
        if call(Syscall::Unshare.raw(), a0(CLONE_NEWUTS)) != Some(-1) {
            return Err("unprivileged unshare(CLONE_NEWUTS) should be -EPERM");
        }
        // Combined, the user namespace is created first and authorises the
        // rest. Same caller, same (absent) host privilege.
        if call(Syscall::Unshare.raw(), a0(CLONE_NEWUSER | CLONE_NEWUTS)) != Some(0) {
            return Err("unshare(CLONE_NEWUSER|CLONE_NEWUTS) was refused");
        }
        // Authority INSIDE: naming its own UTS namespace is now permitted.
        let name = b"narf-container";
        if call(
            Syscall::SetHostname.raw(),
            a1(name.as_ptr() as u64, name.len() as u64),
        ) != Some(0)
        {
            return Err("owner could not name its own UTS namespace");
        }
        // Authority OUTSIDE: the host clock is governed by the initial user
        // namespace, which this task can never reach. `capable()` walking to
        // the initial namespace returns -EPERM before ever reading the
        // effective set, so the full set granted above buys nothing here.
        let mut tv = [0u8; 16];
        tv[..8].copy_from_slice(&1_700_000_000i64.to_ne_bytes());
        if call(Syscall::Settimeofday.raw(), a1(tv.as_ptr() as u64, 0)) != Some(-1) {
            return Err("namespace-bound capabilities reached the host clock");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_newuser_grants_authority_only_inside_the_namespace
);

/// `fs/namespace.c::may_mount` gates mount(2) on the MOUNT namespace's owner:
///
///     return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
///
/// So the two arms below differ only in whether the caller unshared a mount
/// namespace, and they must differ in outcome. A container that unshared one
/// owns it and may mount inside it; a task that unshared only a USER
/// namespace is still using the host's mount namespace, whose owner is the
/// initial user namespace, and may not.
///
/// Asking the host question for both — what `capable()` does — gets one of
/// them wrong whichever way the caller's credentials happen to fall.
fn smoke_abi_caps_mount_follows_the_mount_namespace_owner() -> TestResult {
    with_setup(|| {
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const CLONE_NEWUSER: u64 = 0x1000_0000;
        let tgt = b"/mnt\0";
        let fst = b"tmpfs\0";
        let src = b"none\0";

        // Arm 1: a user namespace only. The host mount namespace is out of
        // reach, so mount is -EPERM.
        drop_all_caps();
        if call(Syscall::Unshare.raw(), a0(CLONE_NEWUSER)) != Some(0) {
            return Err("unshare(CLONE_NEWUSER) failed");
        }
        if call(
            Syscall::Mount.raw(),
            a4(
                src.as_ptr() as u64,
                tgt.as_ptr() as u64,
                fst.as_ptr() as u64,
                0,
                0,
            ),
        ) != Some(-1)
        {
            return Err("a user namespace alone allowed a host mount");
        }

        // Arm 2: unshare the mount namespace too. The caller now owns it, so
        // the capability gate passes — whatever the mount itself then does,
        // it must not be -EPERM.
        if call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) != Some(0) {
            return Err("unshare(CLONE_NEWNS) was refused inside a user namespace");
        }
        match call(
            Syscall::Mount.raw(),
            a4(
                src.as_ptr() as u64,
                tgt.as_ptr() as u64,
                fst.as_ptr() as u64,
                0,
                0,
            ),
        ) {
            Some(-1) => Err("owner of a mount namespace was refused a mount inside it"),
            Some(_) => Ok(()),
            None => Err("mount inside a private namespace returned InvalidOp"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_mount_follows_the_mount_namespace_owner
);

fn smoke_abi_caps_unshare_needs_sys_admin_except_newuser() -> TestResult {
    with_setup(|| {
        // `unshare_nsproxy_namespaces` gates CLONE_NEWNS|NEWUTS|NEWIPC|
        // NEWNET|NEWPID|NEWCGROUP|NEWTIME on CAP_SYS_ADMIN — and pointedly
        // does NOT gate CLONE_NEWUSER. Creating a user namespace
        // unprivileged is the entire point of user namespaces; gating it
        // would invert the feature.
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const CLONE_NEWUSER: u64 = 0x1000_0000;
        drop_all_caps();
        match call(Syscall::Unshare.raw(), a0(CLONE_NEWNS)) {
            Some(-1) => {}
            Some(0) => return Err("an unprivileged task unshared its mount namespace"),
            _ => return Err("unprivileged unshare(CLONE_NEWNS): want -EPERM"),
        }
        match call(Syscall::Unshare.raw(), a0(CLONE_NEWUSER)) {
            Some(0) => Ok(()),
            Some(-1) => Err("unshare(CLONE_NEWUSER) was gated on CAP_SYS_ADMIN; Linux allows it"),
            _ => Err("unprivileged unshare(CLONE_NEWUSER) should succeed"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_unshare_needs_sys_admin_except_newuser
);

fn smoke_abi_caps_unshare_einval_precedes_eperm() -> TestResult {
    with_setup(|| {
        // `check_unshare_flags` runs before the capability check, so an
        // unsupported bit is -EINVAL even unprivileged — and, importantly,
        // leaves the caller's namespaces untouched either way.
        drop_all_caps();
        match call(Syscall::Unshare.raw(), a0(1 << 62)) {
            Some(-22) => Ok(()),
            Some(-1) => Err("unshare checked the capability before validating its flags"),
            _ => Err("unshare(unsupported flag): want -EINVAL"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_unshare_einval_precedes_eperm);

fn smoke_abi_caps_setns_ebadf_precedes_eperm() -> TestResult {
    with_setup(|| {
        // `validate_nsset`'s CAP_SYS_ADMIN check runs after the descriptor
        // is resolved, so a bad fd is -EBADF regardless of privilege.
        drop_all_caps();
        match call(Syscall::Setns.raw(), a1(4242, 0)) {
            Some(-9) => Ok(()),
            Some(-1) => Err("setns checked the capability before the descriptor"),
            _ => Err("setns(bad fd): want -EBADF"),
        }
    })
}
kernel_test_in!("syscall_abi", smoke_abi_caps_setns_ebadf_precedes_eperm);

fn smoke_abi_caps_setpriority_foreign_uid_is_eperm() -> TestResult {
    with_setup(|| {
        // `set_one_prio_perm`: the caller's EFFECTIVE uid must match the
        // target's real OR effective uid, else CAP_SYS_NICE, else -EPERM.
        // Move the caller's euid away from the target's (both are the same
        // task here, so change euid and leave the target row at 0).
        const OTHER: u64 = 0xC201;
        crate::task::release_task(OTHER);
        let _t = crate::task::Task::new_registered(OTHER, OTHER);
        crate::handlers::register_task_to_pid(OTHER, OTHER);
        crate::handlers::register_pid_task_mapping(OTHER, OTHER);
        crate::handlers::__test_set_uidgid_euid(OTHER, 4242);
        drop_all_caps();
        let r = call(Syscall::Setpriority.raw(), a2(0, OTHER, 5));
        crate::task::release_task(OTHER);
        match r {
            Some(-1) => Ok(()),
            Some(0) => Err("an unprivileged task reniced a process it does not own"),
            _ => Err("setpriority on a foreign uid: want -EPERM"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setpriority_foreign_uid_is_eperm
);

fn smoke_abi_caps_setpriority_reduction_is_eacces_not_eperm() -> TestResult {
    with_setup(|| {
        // The second, DIFFERENT arm: the process is yours, but making it
        // more favourable needs CAP_SYS_NICE (or RLIMIT_NICE headroom,
        // whose Linux default is 0).
        //
        // -EPERM means "not your process"; -EACCES means "yours, but you
        // may not raise its priority". renice reports them differently, so
        // collapsing them sends a user after the wrong problem.
        drop_all_caps();
        match call(Syscall::Setpriority.raw(), a2(0, 0, (-5i64) as u64)) {
            Some(-13) => {}
            Some(-1) => return Err("a nice REDUCTION reported EPERM; Linux uses EACCES"),
            Some(0) => return Err("an unprivileged task lowered its own nice value"),
            _ => return Err("unprivileged nice reduction: want -EACCES"),
        }
        // Raising nice (less favourable) is always allowed.
        match call(Syscall::Setpriority.raw(), a2(0, 0, 5)) {
            Some(0) => Ok(()),
            _ => Err("raising nice should not need a capability"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setpriority_reduction_is_eacces_not_eperm
);

fn smoke_abi_caps_setpriority_sys_nice_permits_reduction() -> TestResult {
    with_setup(|| {
        set_caps(CAP_SYS_NICE_BIT, CAP_SYS_NICE_BIT);
        match call(Syscall::Setpriority.raw(), a2(0, 0, (-5i64) as u64)) {
            Some(0) => Ok(()),
            _ => Err("CAP_SYS_NICE should permit a nice reduction"),
        }
    })
}
kernel_test_in!(
    "syscall_abi",
    smoke_abi_caps_setpriority_sys_nice_permits_reduction
);
