//! Linux syscall ABI conformance — creds group.
#![cfg(feature = "linux-compat")]
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
        // First slot is a bad (non-canonical) pointer ⇒ copy_to_user fails
        // ⇒ Ok(-1).
        let r = call(Syscall::Getresuid.raw(), a2(BAD_PTR, 0, 0)).ok_or("getresuid not Ok")?;
        if r != -1 {
            return Err("getresuid(bad ptr) expected -1");
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
        let r = call(Syscall::Getresgid.raw(), a2(BAD_PTR, 0, 0)).ok_or("getresgid not Ok")?;
        if r != -1 {
            return Err("getresgid(bad ptr) expected -1");
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
        // len == 0 ⇒ Ok(-1) (the explicit early-out). LINUX-GAP: Linux
        // returns -EINVAL/-ENAMETOOLONG, NARF returns the bare -1 shape.
        let mut buf = [0u8; 16];
        let p = buf.as_mut_ptr() as u64;
        let r = call(Syscall::GetHostname.raw(), a1(p, 0)).ok_or("gethostname not Ok")?;
        if r != -1 {
            return Err("gethostname(buf,0) expected -1");
        }
        // NULL buffer ⇒ also -1.
        let r2 = call(Syscall::GetHostname.raw(), a1(NULL_PTR, 16)).ok_or("gethostname not Ok")?;
        if r2 != -1 {
            return Err("gethostname(NULL,16) expected -1");
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
        // NULL pointer ⇒ Ok(-1). LINUX-GAP: Linux returns -EFAULT.
        let r = call(Syscall::GetRandom.raw(), a2(NULL_PTR, 16, 0)).ok_or("getrandom not Ok")?;
        if r != -1 {
            return Err("getrandom(NULL,16) expected -1");
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
