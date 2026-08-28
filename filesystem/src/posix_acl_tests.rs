//! POSIX.1e ACL suite for `crate::posix_acl` and its wiring into
//! `posix_access_ok_with_acl` / `MemFs`.
//!
//! Every expectation below is taken from Linux 7.0.0-rc7:
//! `fs/posix_acl.c` for the algebra and the xattr codec,
//! `fs/namei.c::acl_permission_check` for where the ACL sits in the
//! permission walk, and `include/uapi/linux/posix_acl_xattr.h` for the
//! on-the-wire layout.
//!
//! ## Smoke inventory
//!
//!   1. `smoke_acl_xattr_codec`            — header/entry layout, round-trip, decode rejections
//!   2. `smoke_acl_valid_ordering`         — `posix_acl_valid` state machine + needs_mask
//!   3. `smoke_acl_mode_bridge`            — `posix_acl_from_mode` / `posix_acl_equiv_mode`
//!   4. `smoke_acl_mask_limits_entries`    — ACL_MASK caps everything but USER_OBJ/OTHER
//!   5. `smoke_acl_permission_ordering`    — owner short-circuit, group `found`, malformed → EIO
//!   6. `smoke_acl_chmod_and_create_masq`  — `__posix_acl_chmod_masq`, `posix_acl_create`
//!   7. `smoke_acl_memfs_mode_coherence`   — memfs setxattr↔mode, chmod→mask, default-on-file
//!
//! GPL-2.0-or-later.

extern crate alloc;

use alloc::vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::posix_acl::{
    posix_acl_create, posix_acl_permission, AclDecision, AclEntry, AclType, PosixAcl, ACL_EXECUTE,
    ACL_GROUP, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER, ACL_READ, ACL_USER, ACL_USER_OBJ, ACL_WRITE,
    POSIX_ACL_XATTR_VERSION, XATTR_NAME_POSIX_ACL_ACCESS, XATTR_NAME_POSIX_ACL_DEFAULT,
};
use crate::{AccessRequest, Accessor, FileOwner, FsError};

fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTAB)
    }
    // SAFETY: the vtable's clone/wake/drop are no-ops over a null data
    // pointer, so the waker is never dereferenced and never freed.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: `fut` is a local that is never moved again after this.
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// A file owned by 1000:2000, mode 0o640, not a directory.
fn owner_1000() -> FileOwner {
    FileOwner {
        uid: 1000,
        gid: 2000,
        perms: 0o640,
        is_dir: false,
    }
}

fn req(r: bool, w: bool, x: bool) -> AccessRequest {
    AccessRequest {
        read: r,
        write: w,
        exec: x,
    }
}

/// An unprivileged accessor: no DAC overrides at all. `Accessor::new`
/// would derive them from `uid == 0`, which is exactly what these tests
/// must not have.
fn plain(uid: u32, gid: u32, groups: alloc::vec::Vec<u32>) -> Accessor {
    Accessor {
        uid,
        gid,
        groups,
        dac_override: false,
        dac_read_search: false,
    }
}

// ── 1. xattr codec ────────────────────────────────────────────────────

fn smoke_acl_xattr_codec() -> TestResult {
    // `struct posix_acl_xattr_header { __le32 a_version; }` followed by
    // `{ __le16 e_tag; __le16 e_perm; __le32 e_id; }` per entry.
    let acl = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE),
        AclEntry::with_id(ACL_USER, 1001, ACL_READ),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_MASK, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    let raw = acl.to_xattr();
    if raw.len() != 4 + 5 * 8 || raw.len() != acl.xattr_size() {
        return TestResult::Fail("posix_acl_xattr_size mismatch");
    }
    if raw[0..4] != POSIX_ACL_XATTR_VERSION.to_le_bytes() {
        return TestResult::Fail("a_version not le32(2)");
    }
    // Entry 0: tag=1 perm=6 id=-1 (non-id tags always serialise as
    // ACL_UNDEFINED_ID — the `default:` arm of posix_acl_to_xattr).
    if raw[4..6] != [0x01, 0x00] || raw[6..8] != [0x06, 0x00] || raw[8..12] != [0xff; 4] {
        return TestResult::Fail("ACL_USER_OBJ entry mis-encoded");
    }
    // Entry 1: tag=2 perm=4 id=1001.
    if raw[12..14] != [0x02, 0x00] || raw[16..20] != 1001u32.to_le_bytes() {
        return TestResult::Fail("ACL_USER entry mis-encoded");
    }
    match PosixAcl::from_xattr(&raw) {
        Ok(Some(back)) if back == acl => {}
        _ => return TestResult::Fail("to_xattr/from_xattr did not round-trip"),
    }

    // A valid header with zero entries is Linux's `return NULL` — no ACL,
    // not an empty one. do_set_acl then removes the ACL.
    match PosixAcl::from_xattr(&POSIX_ACL_XATTR_VERSION.to_le_bytes()) {
        Ok(None) => {}
        _ => return TestResult::Fail("zero-entry header did not decode to None"),
    }
    // Truncated header → -EINVAL.
    if PosixAcl::from_xattr(&[2u8, 0, 0]) != Err(FsError::InvalidData) {
        return TestResult::Fail("short header not rejected as EINVAL");
    }
    // Wrong a_version → -EOPNOTSUPP, NOT -EINVAL.
    if PosixAcl::from_xattr(&1u32.to_le_bytes()) != Err(FsError::Unsupported) {
        return TestResult::Fail("a_version != 2 not rejected as EOPNOTSUPP");
    }
    // Ragged entry array → -EINVAL.
    let mut ragged = raw.clone();
    ragged.truncate(raw.len() - 1);
    if PosixAcl::from_xattr(&ragged) != Err(FsError::InvalidData) {
        return TestResult::Fail("ragged entry array not rejected");
    }
    // Unknown tag → -EINVAL.
    let mut bad_tag = raw.clone();
    bad_tag[4] = 0x40;
    if PosixAcl::from_xattr(&bad_tag) != Err(FsError::InvalidData) {
        return TestResult::Fail("unknown e_tag not rejected");
    }
    // ACL_USER with e_id == ACL_UNDEFINED_ID is `!uid_valid()` → -EINVAL.
    let mut bad_id = raw.clone();
    bad_id[16..20].copy_from_slice(&[0xff; 4]);
    if PosixAcl::from_xattr(&bad_id) != Err(FsError::InvalidData) {
        return TestResult::Fail("ACL_USER with ACL_UNDEFINED_ID not rejected");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_acl_xattr_codec);

// ── 2. posix_acl_valid ────────────────────────────────────────────────

fn smoke_acl_valid_ordering() -> TestResult {
    // The minimal valid ACL: no named entries, so no mask is required.
    let minimal = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    if minimal.valid().is_err() {
        return TestResult::Fail("three-entry ACL rejected");
    }
    // `needs_mask`: a named ACL_USER makes ACL_MASK mandatory.
    let no_mask = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ),
        AclEntry::with_id(ACL_USER, 1001, ACL_READ),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    if no_mask.valid().is_ok() {
        return TestResult::Fail("named ACL_USER without ACL_MASK accepted");
    }
    let mut with_mask = no_mask.clone();
    with_mask
        .entries
        .insert(3, AclEntry::tagged(ACL_MASK, ACL_READ));
    if with_mask.valid().is_err() {
        return TestResult::Fail("named ACL_USER with ACL_MASK rejected");
    }
    // Out-of-order: GROUP_OBJ before USER_OBJ.
    let swapped = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    if swapped.valid().is_ok() {
        return TestResult::Fail("GROUP_OBJ before USER_OBJ accepted");
    }
    // Two ACL_USER_OBJ entries: the state machine leaves ACL_USER_OBJ
    // after the first, so the second is -EINVAL.
    let dup = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ),
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    if dup.valid().is_ok() {
        return TestResult::Fail("duplicate ACL_USER_OBJ accepted");
    }
    // Missing ACL_OTHER leaves the state machine short of 0.
    let no_other = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
    ]);
    if no_other.valid().is_ok() {
        return TestResult::Fail("ACL without ACL_OTHER accepted");
    }
    // An empty ACL is not valid either — state never reaches 0.
    if PosixAcl::new().valid().is_ok() {
        return TestResult::Fail("empty ACL accepted");
    }
    // e_perm outside rwx.
    let wide = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, 0o10),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    if wide.valid().is_ok() {
        return TestResult::Fail("e_perm outside rwx accepted");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_acl_valid_ordering);

// ── 3. mode bridge ────────────────────────────────────────────────────

fn smoke_acl_mode_bridge() -> TestResult {
    let acl = PosixAcl::from_mode(0o751);
    if acl.entries
        != [
            AclEntry::tagged(ACL_USER_OBJ, 7),
            AclEntry::tagged(ACL_GROUP_OBJ, 5),
            AclEntry::tagged(ACL_OTHER, 1),
        ]
    {
        return TestResult::Fail("posix_acl_from_mode(0751) wrong");
    }
    // Exactly equivalent → not_equiv == false, and the mode is unchanged.
    let mut mode = 0o4751u16;
    match acl.equiv_mode(&mut mode) {
        Ok(false) if mode == 0o4751 => {}
        Ok(false) => return TestResult::Fail("equiv_mode clobbered the setuid bit"),
        _ => return TestResult::Fail("mode-equivalent ACL reported not_equiv"),
    }
    // A mask makes it inequivalent AND supplies the group triplet — the
    // ACL_GROUP_OBJ value is overwritten, not ORed. This is why `ls -l`
    // shows the mask in the group column of an ACL'd file.
    let masked = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::with_id(ACL_USER, 1001, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 7),
        AclEntry::tagged(ACL_MASK, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 1),
    ]);
    let mut mode = 0o777u16;
    match masked.equiv_mode(&mut mode) {
        Ok(true) if mode == 0o741 => {}
        Ok(true) => return TestResult::Fail("mask did not replace the group triplet"),
        _ => return TestResult::Fail("ACL with mask + named user reported equivalent"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_acl_mode_bridge);

// ── 4. ACL_MASK ───────────────────────────────────────────────────────

/// The mask limits every entry EXCEPT `ACL_USER_OBJ` and `ACL_OTHER`.
///
/// Getting this wrong silently GRANTS: `setfacl -m u:1001:rwx,m::r--`
/// must leave 1001 with read only, and `posix_acl_permission` enforces it
/// by ANDing the matched entry with the first `ACL_MASK` found after it
/// (the `mask:` label in `fs/posix_acl.c`).
fn smoke_acl_mask_limits_entries() -> TestResult {
    let file = owner_1000();
    // u::rw-, u:1001:rwx, g::rwx, g:3000:rwx, m::r--, o::rwx
    let acl = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE),
        AclEntry::with_id(ACL_USER, 1001, ACL_READ | ACL_WRITE | ACL_EXECUTE),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ | ACL_WRITE | ACL_EXECUTE),
        AclEntry::with_id(ACL_GROUP, 3000, ACL_READ | ACL_WRITE | ACL_EXECUTE),
        AclEntry::tagged(ACL_MASK, ACL_READ),
        AclEntry::tagged(ACL_OTHER, ACL_READ | ACL_WRITE | ACL_EXECUTE),
    ]);
    if acl.valid().is_err() {
        return TestResult::Fail("fixture ACL is not valid");
    }

    let named_user = plain(1001, 9999, vec![]);
    if posix_acl_permission(&acl, file, &named_user, 4) != AclDecision::Granted {
        return TestResult::Fail("ACL_USER denied read that the mask allows");
    }
    if posix_acl_permission(&acl, file, &named_user, 2) != AclDecision::Denied {
        return TestResult::Fail("ACL_USER granted write past a r-- mask");
    }

    // ACL_GROUP_OBJ is maskable too: the accessor is in gid 2000 (the
    // file's group) so it matches, and the mask must cut it to r--.
    let group_obj = plain(1002, 2000, vec![]);
    if posix_acl_permission(&acl, file, &group_obj, 4) != AclDecision::Granted {
        return TestResult::Fail("ACL_GROUP_OBJ denied read that the mask allows");
    }
    if posix_acl_permission(&acl, file, &group_obj, 2) != AclDecision::Denied {
        return TestResult::Fail("ACL_GROUP_OBJ granted write past a r-- mask");
    }

    // A named group, matched supplementarily.
    let named_group = plain(1003, 9999, vec![3000]);
    if posix_acl_permission(&acl, file, &named_group, 2) != AclDecision::Denied {
        return TestResult::Fail("ACL_GROUP granted write past a r-- mask");
    }

    // ACL_OTHER is NOT maskable: an unrelated uid gets the full rwx the
    // other entry names, even though the mask is r--.
    let other = plain(4242, 4242, vec![]);
    if posix_acl_permission(&acl, file, &other, 7) != AclDecision::Granted {
        return TestResult::Fail("ACL_MASK wrongly limited ACL_OTHER");
    }
    // ACL_USER_OBJ is not maskable either.
    let owner = plain(1000, 9999, vec![]);
    if posix_acl_permission(&acl, file, &owner, 2) != AclDecision::Granted {
        return TestResult::Fail("ACL_MASK wrongly limited ACL_USER_OBJ");
    }

    // A mask placed BEFORE the entry it should limit does not limit it —
    // Linux scans forward from the match only. Pinned so a future
    // "search the whole ACL" simplification has to argue with this test.
    let mask_first = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ),
        AclEntry::tagged(ACL_MASK, ACL_READ),
        AclEntry::with_id(ACL_USER, 1001, ACL_READ | ACL_WRITE),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    if posix_acl_permission(&mask_first, file, &named_user, 2) != AclDecision::Granted {
        return TestResult::Fail("a preceding ACL_MASK was applied backwards");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_acl_mask_limits_entries);

// ── 5. ordering through posix_access_ok_with_acl ──────────────────────

fn smoke_acl_permission_ordering() -> TestResult {
    // File 1000:2000 mode 0640. Its ACL grants uid 1001 rwx.
    let file = owner_1000();
    let acl = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE),
        AclEntry::with_id(ACL_USER, 1001, ACL_READ | ACL_WRITE | ACL_EXECUTE),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_MASK, ACL_READ | ACL_WRITE | ACL_EXECUTE),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);

    // Without the ACL, 1001 is "other" on a 0640 file → denied.
    let u1001 = plain(1001, 9999, vec![]);
    if crate::posix_access_ok(file, &u1001, req(true, false, false)) {
        return TestResult::Fail("mode-only check granted read on 0640 to a stranger");
    }
    // With it, the named entry grants rwx.
    if !crate::posix_access_ok_with_acl(file, &u1001, req(true, true, true), Some(&acl)) {
        return TestResult::Fail("ACL_USER entry did not grant rwx");
    }

    // The OWNER test comes BEFORE the ACL (fs/namei.c). The owner's mode
    // triplet is rw-, so exec is refused even though the ACL's mask and
    // ACL_USER_OBJ... would not matter: no ACL entry can rescue it.
    let owner = plain(1000, 9999, vec![]);
    if crate::posix_access_ok_with_acl(file, &owner, req(false, false, true), Some(&acl)) {
        return TestResult::Fail("owner got exec from the ACL — owner must short-circuit first");
    }

    // `found`: once a GROUP entry matched, ACL_OTHER is not a fallback.
    // gid 2000 matches ACL_GROUP_OBJ (r--) so a write request is EACCES,
    // NOT "fall through to o::rwx".
    let permissive_other = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_OTHER, ACL_READ | ACL_WRITE | ACL_EXECUTE),
    ]);
    let in_group = plain(1002, 2000, vec![]);
    if crate::posix_access_ok_with_acl(
        file,
        &in_group,
        req(false, true, false),
        Some(&permissive_other),
    ) {
        return TestResult::Fail("group match fell through to the more permissive ACL_OTHER");
    }

    // The "everybody may" cheap path must NOT fire when an ACL exists.
    // Mode 0777 says yes to everything, but the ACL denies group writes;
    // Linux guards the shortcut with no_acl_inode()/IS_POSIXACL().
    let wide_mode = FileOwner {
        uid: 1000,
        gid: 2000,
        perms: 0o777,
        is_dir: false,
    };
    if crate::posix_access_ok_with_acl(
        wide_mode,
        &in_group,
        req(false, true, false),
        Some(&permissive_other),
    ) {
        return TestResult::Fail("cheap 'everybody may' path bypassed the ACL");
    }

    // `mode & S_IRWXG == 0` short-circuits the ACL entirely: with no group
    // bits the mask is empty, so Linux never calls check_acl.
    let no_group_bits = FileOwner {
        uid: 1000,
        gid: 2000,
        perms: 0o600,
        is_dir: false,
    };
    if crate::posix_access_ok_with_acl(no_group_bits, &u1001, req(true, false, false), Some(&acl)) {
        return TestResult::Fail("ACL consulted despite mode & S_IRWXG == 0");
    }

    // A malformed ACL is -EIO, and generic_permission returns it BEFORE
    // the capability overrides — CAP_DAC_OVERRIDE must not rescue it.
    let malformed = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        // no ACL_OTHER → the loop falls off the end → -EIO
    ]);
    if posix_acl_permission(&malformed, file, &u1001, 4) != AclDecision::Malformed {
        return TestResult::Fail("ACL without ACL_OTHER did not report Malformed");
    }
    let root = Accessor {
        uid: 0,
        gid: 0,
        groups: alloc::vec::Vec::new(),
        dac_override: true,
        dac_read_search: true,
    };
    if crate::posix_access_ok_with_acl(file, &root, req(true, false, false), Some(&malformed)) {
        return TestResult::Fail("CAP_DAC_OVERRIDE overrode a malformed (-EIO) ACL");
    }
    // The same accessor on the same file with no ACL is allowed, so the
    // check above failed for the right reason.
    if !crate::posix_access_ok(file, &root, req(true, false, false)) {
        return TestResult::Fail("CAP_DAC_OVERRIDE denied read with no ACL");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_acl_permission_ordering);

// ── 6. chmod_masq / posix_acl_create ─────────────────────────────────

fn smoke_acl_chmod_and_create_masq() -> TestResult {
    // __posix_acl_chmod_masq: outer triplets land on USER_OBJ/OTHER, the
    // middle one on ACL_MASK when there is one, and named entries are
    // left alone (chmod cannot delete a grant).
    let mut acl = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::with_id(ACL_USER, 1001, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 7),
        AclEntry::tagged(ACL_MASK, 7),
        AclEntry::tagged(ACL_OTHER, 7),
    ]);
    if acl.chmod_masq(0o640).is_err() {
        return TestResult::Fail("chmod_masq failed on a well-formed ACL");
    }
    if acl.entries[0].perm != 6 || acl.entries[4].perm != 0 {
        return TestResult::Fail("chmod_masq did not set USER_OBJ/OTHER from the mode");
    }
    if acl.entries[3].perm != 4 {
        return TestResult::Fail("chmod_masq did not put the group triplet on ACL_MASK");
    }
    if acl.entries[2].perm != 7 || acl.entries[1].perm != 7 {
        return TestResult::Fail("chmod_masq clobbered GROUP_OBJ or a named entry");
    }
    // With no mask, ACL_GROUP_OBJ takes the group triplet instead.
    let mut plain_acl = PosixAcl::from_mode(0o777);
    if plain_acl.chmod_masq(0o750).is_err() {
        return TestResult::Fail("chmod_masq failed on a three-entry ACL");
    }
    if plain_acl != PosixAcl::from_mode(0o750) {
        return TestResult::Fail("chmod_masq on a mask-less ACL did not match from_mode");
    }

    // posix_acl_create: no default ACL → the umask applies and nothing is
    // inherited.
    let mut mode = 0o666u16;
    match posix_acl_create(None, false, false, &mut mode, 0o022) {
        Ok(c) if c.default_acl.is_none() && c.access_acl.is_none() && mode == 0o644 => {}
        Ok(_) => return TestResult::Fail("no-default create did not apply the umask"),
        Err(_) => return TestResult::Fail("posix_acl_create errored with no default ACL"),
    }
    // A symlink inherits nothing and is NOT umasked — Linux returns on
    // S_ISLNK before touching *mode.
    let mut mode = 0o777u16;
    match posix_acl_create(None, false, true, &mut mode, 0o022) {
        Ok(c) if c.default_acl.is_none() && c.access_acl.is_none() && mode == 0o777 => {}
        _ => return TestResult::Fail("symlink create applied the umask"),
    }

    // With a default ACL the umask is IGNORED and the ACL is intersected
    // with the requested mode instead. d:u::rwx,d:u:1001:rwx,d:g::r-x,
    // d:m::rwx,d:o::r-x, creating a 0666 file with umask 0777.
    let dflt = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::with_id(ACL_USER, 1001, 7),
        AclEntry::tagged(ACL_GROUP_OBJ, 5),
        AclEntry::tagged(ACL_MASK, 7),
        AclEntry::tagged(ACL_OTHER, 5),
    ]);
    let mut mode = 0o666u16;
    let created = match posix_acl_create(Some(&dflt), false, false, &mut mode, 0o777) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("posix_acl_create errored with a default ACL"),
    };
    if mode != 0o664 {
        return TestResult::Fail("create_masq did not intersect mode with the default ACL");
    }
    // Named entry + mask → the access ACL must be stored.
    let access = match created.access_acl {
        Some(a) => a,
        None => return TestResult::Fail("inherited ACL with a named entry was not stored"),
    };
    if access.entries[0].perm != 6 {
        return TestResult::Fail("USER_OBJ not clamped to the requested owner bits");
    }
    if access.entries[3].perm != 6 {
        return TestResult::Fail("ACL_MASK not clamped to the requested group bits");
    }
    if access.entries[1].perm != 7 {
        return TestResult::Fail("named ACL_USER was clamped — only the mask should be");
    }
    if access.entries[4].perm != 4 {
        return TestResult::Fail("ACL_OTHER not clamped to the requested other bits");
    }
    // A non-directory does NOT inherit the default ACL itself.
    if created.default_acl.is_some() {
        return TestResult::Fail("a regular file inherited a default ACL");
    }
    // A directory does — verbatim, so the default keeps propagating.
    let mut mode = 0o777u16;
    match posix_acl_create(Some(&dflt), true, false, &mut mode, 0o022) {
        Ok(c) if c.default_acl.as_ref() == Some(&dflt) => {}
        _ => return TestResult::Fail("a new directory did not inherit the default ACL verbatim"),
    }
    // A default ACL with no named entries and no mask collapses to mode
    // bits: create_masq reports not_equiv == false, so nothing is stored.
    let simple = PosixAcl::from_mode(0o750);
    let mut mode = 0o777u16;
    match posix_acl_create(Some(&simple), false, false, &mut mode, 0o000) {
        Ok(c) if c.access_acl.is_none() && mode == 0o750 => {}
        _ => return TestResult::Fail("mode-equivalent default ACL was stored anyway"),
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_acl_chmod_and_create_masq);

// ── 7. MemFs storage + mode coherence ────────────────────────────────

fn smoke_acl_memfs_mode_coherence() -> TestResult {
    use crate::{FsInstance, MemFs};
    let fs = MemFs::new("acl-coherence");
    let root = fs.root();
    let file = match poll_once(root.create("f")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create failed"),
    };
    if poll_once(file.set_perms(0o600)).is_none() {
        return TestResult::Fail("set_perms did not complete");
    }

    // Setting an access ACL rewrites the mode (posix_acl_update_mode):
    // u::rw-, u:1001:rwx, g::r--, m::r-x, o::--- → mode 0650 (the MASK,
    // not GROUP_OBJ, supplies the group triplet).
    let acl = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_USER_OBJ, ACL_READ | ACL_WRITE),
        AclEntry::with_id(ACL_USER, 1001, ACL_READ | ACL_WRITE | ACL_EXECUTE),
        AclEntry::tagged(ACL_GROUP_OBJ, ACL_READ),
        AclEntry::tagged(ACL_MASK, ACL_READ | ACL_EXECUTE),
        AclEntry::tagged(ACL_OTHER, 0),
    ]);
    match poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_ACCESS, &acl.to_xattr(), 0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("setxattr(system.posix_acl_access) failed"),
    }
    if file.stat().mode.perms != 0o650 {
        return TestResult::Fail("setting an ACL did not update the file mode");
    }
    // It reads back through the normal xattr path, byte-identical.
    match poll_once(file.get_xattr(XATTR_NAME_POSIX_ACL_ACCESS)) {
        Some(Ok(raw)) if raw == acl.to_xattr() => {}
        _ => return TestResult::Fail("stored ACL did not round-trip through get_xattr"),
    }
    // And the decoded ACL is what posix_access_ok_with_acl sees.
    let (uid, gid) = file.owners();
    let owner = FileOwner {
        uid,
        gid,
        perms: file.stat().mode.perms,
        is_dir: false,
    };
    let live = match poll_once(crate::acl_of_file(file.as_ref(), AclType::Access)) {
        Some(Ok(Some(a))) => a,
        _ => return TestResult::Fail("acl_of_file did not return the stored ACL"),
    };
    let u1001 = plain(1001, 9999, vec![]);
    if !crate::posix_access_ok_with_acl(owner, &u1001, req(true, false, true), Some(&live)) {
        return TestResult::Fail("stored ACL did not grant uid 1001 r-x");
    }
    if crate::posix_access_ok_with_acl(owner, &u1001, req(false, true, false), Some(&live)) {
        return TestResult::Fail("stored ACL granted write past the r-x mask");
    }

    // chmod pushes the new mode back INTO the ACL: g-x must move the mask
    // from r-x to r--, which is the only thing that can revoke 1001's x.
    if poll_once(file.set_perms(0o640)).is_none() {
        return TestResult::Fail("chmod did not complete");
    }
    let after = match poll_once(crate::acl_of_file(file.as_ref(), AclType::Access)) {
        Some(Ok(Some(a))) => a,
        _ => return TestResult::Fail("ACL vanished across chmod"),
    };
    if after.entries[3].perm != ACL_READ {
        return TestResult::Fail("chmod did not update ACL_MASK");
    }
    if after.entries[1].perm != (ACL_READ | ACL_WRITE | ACL_EXECUTE) {
        return TestResult::Fail("chmod clobbered the named ACL_USER entry");
    }
    let owner = FileOwner {
        uid,
        gid,
        perms: file.stat().mode.perms,
        is_dir: false,
    };
    if crate::posix_access_ok_with_acl(owner, &u1001, req(false, false, true), Some(&after)) {
        return TestResult::Fail("chmod g-x did not revoke exec through the mask");
    }

    // A mode-equivalent ACL is not stored at all (posix_acl_update_mode
    // sets *acl = NULL), so the xattr disappears.
    let plain_acl = PosixAcl::from_mode(0o644);
    match poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_ACCESS, &plain_acl.to_xattr(), 0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("setting a mode-equivalent ACL failed"),
    }
    if file.stat().mode.perms != 0o644 {
        return TestResult::Fail("mode-equivalent ACL did not set the mode");
    }
    if poll_once(file.get_xattr(XATTR_NAME_POSIX_ACL_ACCESS)) != Some(Err(FsError::NotFound)) {
        return TestResult::Fail("mode-equivalent ACL was stored instead of dropped");
    }

    // An invalid ACL is refused, and refusal leaves the mode untouched.
    let unordered = PosixAcl::from_entries(vec![
        AclEntry::tagged(ACL_GROUP_OBJ, 7),
        AclEntry::tagged(ACL_USER_OBJ, 7),
        AclEntry::tagged(ACL_OTHER, 7),
    ]);
    if poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_ACCESS, &unordered.to_xattr(), 0))
        != Some(Err(FsError::InvalidData))
    {
        return TestResult::Fail("out-of-order ACL was accepted");
    }
    if file.stat().mode.perms != 0o644 {
        return TestResult::Fail("a rejected ACL still moved the mode");
    }

    // A DEFAULT ACL on a non-directory is -EACCES (set_posix_acl), while
    // a zero-length value — which do_set_acl turns into "remove" — is a
    // silent success.
    if poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_DEFAULT, &plain_acl.to_xattr(), 0))
        != Some(Err(FsError::PermissionDenied))
    {
        return TestResult::Fail("default ACL on a regular file was accepted");
    }
    if poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_DEFAULT, &[], 0)) != Some(Ok(())) {
        return TestResult::Fail("removing an absent default ACL was not a no-op");
    }

    // Removal via an empty value drops the ACL and leaves the mode alone
    // (vfs_remove_acl -> simple_set_acl with a NULL acl short-circuits
    // posix_acl_equiv_mode).
    match poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_ACCESS, &acl.to_xattr(), 0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("re-setting the ACL failed"),
    }
    let before = file.stat().mode.perms;
    if poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_ACCESS, &[], 0)) != Some(Ok(())) {
        return TestResult::Fail("empty-value ACL removal failed");
    }
    if poll_once(file.get_xattr(XATTR_NAME_POSIX_ACL_ACCESS)) != Some(Err(FsError::NotFound)) {
        return TestResult::Fail("empty-value set did not remove the ACL");
    }
    if file.stat().mode.perms != before {
        return TestResult::Fail("removing an ACL changed the mode");
    }

    // removexattr routes the same way: an absent DEFAULT ACL on a
    // non-directory is `set_posix_acl(type, NULL)` -> 0, not ENODATA.
    if poll_once(file.remove_xattr(XATTR_NAME_POSIX_ACL_DEFAULT)) != Some(Ok(())) {
        return TestResult::Fail("removexattr of an absent default ACL was not a no-op");
    }
    match poll_once(file.set_xattr(XATTR_NAME_POSIX_ACL_ACCESS, &acl.to_xattr(), 0)) {
        Some(Ok(())) => {}
        _ => return TestResult::Fail("re-setting the ACL before removexattr failed"),
    }
    let before = file.stat().mode.perms;
    if poll_once(file.remove_xattr(XATTR_NAME_POSIX_ACL_ACCESS)) != Some(Ok(())) {
        return TestResult::Fail("removexattr of a present access ACL failed");
    }
    if file.stat().mode.perms != before {
        return TestResult::Fail("removexattr of an ACL changed the mode");
    }
    if poll_once(file.remove_xattr(XATTR_NAME_POSIX_ACL_ACCESS)) != Some(Err(FsError::NotFound)) {
        return TestResult::Fail("removexattr of an absent access ACL did not report ENODATA");
    }
    TestResult::Pass
}
kernel_test_in!("filesystem", smoke_acl_memfs_mode_coherence);
