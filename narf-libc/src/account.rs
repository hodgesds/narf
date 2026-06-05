//! `<pwd.h>` + `<grp.h>` — single-user account database.
//!
//! NARF runs a single-user model: there is exactly one user
//! ("narf", uid 0) and one group ("narf", gid 0). Real C programs
//! reach for `getpwuid(getuid())` very early during init (curses
//! libraries chasing `$HOME`, login shells, sudo-style helpers,
//! python's `pwd` module). Returning NULL from these functions
//! makes most of those programs treat the system as misconfigured
//! and bail; returning a fixed entry lets them proceed.
//!
//! The returned pointer is to a `'static` table; callers must not
//! free it. The shape of `passwd` and `group` matches the SUSv4
//! `<pwd.h>` / `<grp.h>` definitions on x86_64 / aarch64 so a binary
//! compiled against system headers observes the expected field offsets.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

pub type uid_t = u32;
pub type gid_t = u32;

// ── struct passwd ───────────────────────────────────────────────────

/// `<pwd.h>` `struct passwd` per SUSv4. `pw_passwd` is the
/// classic shadow-redirect "x"; real password material conventionally
/// lives in `/etc/shadow` and we don't ship a shadow DB.
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut c_char,
    pub pw_passwd: *mut c_char,
    pub pw_uid: uid_t,
    pub pw_gid: gid_t,
    pub pw_gecos: *mut c_char,
    pub pw_dir: *mut c_char,
    pub pw_shell: *mut c_char,
}

static PW_NAME: [u8; 5] = *b"narf\0";
static PW_PASSWD: [u8; 2] = *b"x\0";
static PW_GECOS: [u8; 5] = *b"NARF\0";
static PW_DIR: [u8; 6] = *b"/root\0";
static PW_SHELL: [u8; 10] = *b"/bin/sh\0\0\0";

// SAFETY: the static fields below alias `'static` byte arrays. The
// `passwd` struct is read-only from the caller's perspective; we
// never hand out a writable view.
static mut PW_ENTRY: passwd = passwd {
    pw_name: PW_NAME.as_ptr() as *mut c_char,
    pw_passwd: PW_PASSWD.as_ptr() as *mut c_char,
    pw_uid: 0,
    pw_gid: 0,
    pw_gecos: PW_GECOS.as_ptr() as *mut c_char,
    pw_dir: PW_DIR.as_ptr() as *mut c_char,
    pw_shell: PW_SHELL.as_ptr() as *mut c_char,
};

#[inline]
unsafe fn cstr_eq(p: *const c_char, want: &[u8]) -> bool {
    if p.is_null() {
        return false;
    }
    // SAFETY: caller-asserted NUL-termination.
    unsafe {
        for (i, &b) in want.iter().enumerate() {
            let ch = *p.add(i) as u8;
            if ch != b {
                return false;
            }
        }
        // Past `want`'s last byte should be the NUL we don't include.
        *p.add(want.len()) == 0
    }
}

/// `getpwuid(uid)` — return the fixed "narf" entry for uid 0,
/// otherwise NULL (no such user). Pointer is `'static`; do not free.
///
/// # Safety
/// Returned pointer aliases a `'static` table; the caller must not
/// mutate any of the string fields.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwuid(uid: uid_t) -> *mut passwd {
    if uid != 0 {
        return core::ptr::null_mut();
    }
    let p = &raw mut PW_ENTRY;
    p
}

/// `getpwnam(name)` — same fixed entry for `name == "narf"`,
/// otherwise NULL.
///
/// # Safety
/// `name`, when non-null, must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwnam(name: *const c_char) -> *mut passwd {
    // SAFETY: caller-asserted NUL-termination.
    if !unsafe { cstr_eq(name, b"narf") } {
        return core::ptr::null_mut();
    }
    let p = &raw mut PW_ENTRY;
    p
}

/// `getpwent()` / `setpwent()` / `endpwent()` — iterate the whole
/// password database. We have one entry; the iterator returns it
/// once after `setpwent`, then NULL.
static mut PW_ITER_DONE: bool = false;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpwent() {
    // SAFETY: single-threaded user mode; no concurrent observer.
    unsafe {
        PW_ITER_DONE = false;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn endpwent() {
    // SAFETY: same.
    unsafe {
        PW_ITER_DONE = true;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpwent() -> *mut passwd {
    // SAFETY: same.
    unsafe {
        if PW_ITER_DONE {
            return core::ptr::null_mut();
        }
        PW_ITER_DONE = true;
        &raw mut PW_ENTRY
    }
}

// ── struct group ────────────────────────────────────────────────────

/// `<grp.h>` `struct group` per SUSv4. `gr_mem` is a NULL-
/// terminated array of member-name pointers; we ship a single-element
/// `["narf", NULL]` array so iterators terminate cleanly.
#[repr(C)]
pub struct group {
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: gid_t,
    pub gr_mem: *mut *mut c_char,
}

static GR_NAME: [u8; 5] = *b"narf\0";
static GR_PASSWD: [u8; 2] = *b"x\0";

// `gr_mem` points at a static `[member, NULL]` array. We need it
// mutable-ish for the C ABI; use a raw `static mut`.
static mut GR_MEMBERS: [*mut c_char; 2] = [GR_NAME.as_ptr() as *mut c_char, core::ptr::null_mut()];

static mut GR_ENTRY: group = group {
    gr_name: GR_NAME.as_ptr() as *mut c_char,
    gr_passwd: GR_PASSWD.as_ptr() as *mut c_char,
    gr_gid: 0,
    // Late-initialised in `getgrgid` etc. — we can't take a `&raw mut`
    // of another `static mut` in const context here, so the initial
    // value is NULL and we patch it on first call.
    gr_mem: core::ptr::null_mut(),
};

#[inline]
unsafe fn ensure_grmem() {
    // SAFETY: single-threaded user mode; the patch is idempotent.
    unsafe {
        if GR_ENTRY.gr_mem.is_null() {
            GR_ENTRY.gr_mem = (&raw mut GR_MEMBERS) as *mut *mut c_char;
        }
    }
}

/// `getgrgid(gid)` — return the fixed "narf" group for gid 0, else NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrgid(gid: gid_t) -> *mut group {
    if gid != 0 {
        return core::ptr::null_mut();
    }
    // SAFETY: see ensure_grmem.
    unsafe {
        ensure_grmem();
    }
    &raw mut GR_ENTRY
}

/// `getgrnam(name)` — same entry for `name == "narf"`, else NULL.
///
/// # Safety
/// `name`, when non-null, must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrnam(name: *const c_char) -> *mut group {
    // SAFETY: caller-asserted NUL-termination.
    if !unsafe { cstr_eq(name, b"narf") } {
        return core::ptr::null_mut();
    }
    // SAFETY: see ensure_grmem.
    unsafe {
        ensure_grmem();
    }
    &raw mut GR_ENTRY
}

static mut GR_ITER_DONE: bool = false;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgrent() {
    // SAFETY: single-threaded.
    unsafe {
        GR_ITER_DONE = false;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn endgrent() {
    // SAFETY: same.
    unsafe {
        GR_ITER_DONE = true;
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrent() -> *mut group {
    // SAFETY: same.
    unsafe {
        if GR_ITER_DONE {
            return core::ptr::null_mut();
        }
        GR_ITER_DONE = true;
        ensure_grmem();
        &raw mut GR_ENTRY
    }
}

/// `getgrouplist(user, group, groups, ngroups)` — fill `groups[]`
/// with the group memberships of `user`. NARF's single-user model:
/// the user "narf" is in exactly one group (gid 0). `ngroups` is an
/// in/out parameter; we set it to the actual count and return -1 if
/// the caller's buffer was too small (per SUSv4).
///
/// # Safety
/// `groups` must point to at least `*ngroups` `gid_t` slots when
/// `ngroups` is non-null; `user` must be a valid NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgrouplist(
    _user: *const c_char,
    group: gid_t,
    groups: *mut gid_t,
    ngroups: *mut c_int,
) -> c_int {
    if ngroups.is_null() {
        return -1;
    }
    // SAFETY: caller-asserted writable slots.
    unsafe {
        let cap = *ngroups;
        // Always exactly two: the primary group and "narf" (0).
        // Deduplicate so callers see a clean list.
        let want: [gid_t; 1] = [group];
        let count: c_int = want.len() as c_int;
        *ngroups = count;
        if cap < count || groups.is_null() {
            return -1;
        }
        for (i, &g) in want.iter().enumerate() {
            *groups.add(i) = g;
        }
        count
    }
}
