//! `<search.h>` + `<utmp.h>` + `<crypt.h>` — three small headers
//! grouped into one module because none of them carry enough surface
//! to merit their own file.
//!
//! `<search.h>`: `tsearch` / `tfind` / `tdelete` / `twalk` —
//! POSIX binary search trees. The tree lives entirely in caller-
//! provided heap (we go through `malloc`); the comparison function
//! is supplied by the caller and we stay no_std-friendly.
//!
//! `<utmp.h>`: `getutent` / `setutent` / `endutent` /
//! `pututline` — login-session tracking. NARF has no login DB; the
//! iterator is empty (`getutent` returns NULL) and pututline is a
//! no-op success.
//!
//! `<crypt.h>`: `crypt` / `crypt_r` — password hashing. We don't
//! ship a hash; both return NULL with `errno = ENOSYS`.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int, c_void};

pub const ENOSYS: c_int = 38;

// ── tsearch family ──────────────────────────────────────────────────
//
// Binary search tree with externally-keyed nodes. Each node carries
// a caller-provided `key` pointer (the actual data — we store the
// pointer the caller passed to `tsearch`, not a copy) plus left/right
// child pointers. The tree is balanced only by the order of inserts;
// classic POSIX `tsearch` is a plain BST with no rebalancing.
//
// Comparison function signature: `int compar(const void *, const void *)`.
// Returns negative, zero, positive — same as `qsort`.

type CmpFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

#[repr(C)]
struct TNode {
    key: *const c_void,
    left: *mut TNode,
    right: *mut TNode,
}

unsafe fn tnode_alloc(key: *const c_void) -> *mut TNode {
    // SAFETY: malloc returns a zeroed/uninit block of the requested
    // size; we initialise every field before returning.
    unsafe {
        let p = crate::heap::malloc(core::mem::size_of::<TNode>()) as *mut TNode;
        if !p.is_null() {
            (*p).key = key;
            (*p).left = core::ptr::null_mut();
            (*p).right = core::ptr::null_mut();
        }
        p
    }
}

/// `tsearch(key, rootp, compar)` — insert `key` into the tree at
/// `*rootp`, allocating a node if needed. Returns a pointer to the
/// matching node's `key` slot (so the caller can reach the same
/// pointer back via `*(void**)return`).
///
/// # Safety
/// `rootp` must point to a writable `*mut TNode`-shaped slot;
/// `compar` must be a valid `CmpFn`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tsearch(
    key: *const c_void,
    rootp: *mut *mut c_void,
    compar: CmpFn,
) -> *mut c_void {
    if rootp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller-supplied writable slot.
    unsafe {
        let mut cur: *mut *mut TNode = rootp as *mut *mut TNode;
        while !(*cur).is_null() {
            let n = *cur;
            let c = compar(key, (*n).key);
            if c == 0 {
                // Found — return pointer to its key slot.
                return &mut (*n).key as *mut *const c_void as *mut c_void;
            } else if c < 0 {
                cur = &mut (*n).left as *mut *mut TNode;
            } else {
                cur = &mut (*n).right as *mut *mut TNode;
            }
        }
        // Insert new node here.
        let n = tnode_alloc(key);
        if n.is_null() {
            return core::ptr::null_mut();
        }
        *cur = n;
        &mut (*n).key as *mut *const c_void as *mut c_void
    }
}

/// `tfind(key, rootp, compar)` — locate `key` without inserting.
/// Returns the matching node's key-slot pointer or NULL.
///
/// # Safety
/// `rootp` must point to a readable `*mut TNode`-shaped slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tfind(
    key: *const c_void,
    rootp: *const *mut c_void,
    compar: CmpFn,
) -> *mut c_void {
    if rootp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller-supplied readable slot.
    unsafe {
        let mut cur = *rootp as *mut TNode;
        while !cur.is_null() {
            let c = compar(key, (*cur).key);
            if c == 0 {
                return &mut (*cur).key as *mut *const c_void as *mut c_void;
            } else if c < 0 {
                cur = (*cur).left;
            } else {
                cur = (*cur).right;
            }
        }
        core::ptr::null_mut()
    }
}

/// `tdelete(key, rootp, compar)` — remove the node matching `key`.
/// Returns the parent of the deleted node, or NULL if `key` was
/// absent.
///
/// # Safety
/// Same as `tsearch`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tdelete(
    key: *const c_void,
    rootp: *mut *mut c_void,
    compar: CmpFn,
) -> *mut c_void {
    if rootp.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller-supplied writable slot.
    unsafe {
        let mut parent: *mut *mut TNode = core::ptr::null_mut();
        let mut cur: *mut *mut TNode = rootp as *mut *mut TNode;
        while !(*cur).is_null() {
            let n = *cur;
            let c = compar(key, (*n).key);
            if c == 0 {
                // Splice out: classic BST delete.
                let replacement: *mut TNode = if (*n).left.is_null() {
                    (*n).right
                } else if (*n).right.is_null() {
                    (*n).left
                } else {
                    // Find inorder successor (leftmost of right
                    // subtree), unlink it, and patch in.
                    let mut succ_parent: *mut *mut TNode = &mut (*n).right as *mut *mut TNode;
                    while !(**succ_parent).left.is_null() {
                        succ_parent = &mut (**succ_parent).left as *mut *mut TNode;
                    }
                    let succ = *succ_parent;
                    *succ_parent = (*succ).right;
                    (*succ).left = (*n).left;
                    (*succ).right = (*n).right;
                    succ
                };
                *cur = replacement;
                crate::heap::free(n as *mut u8);
                if parent.is_null() {
                    return core::ptr::null_mut();
                }
                return *parent as *mut c_void;
            } else if c < 0 {
                parent = cur;
                cur = &mut (*n).left as *mut *mut TNode;
            } else {
                parent = cur;
                cur = &mut (*n).right as *mut *mut TNode;
            }
        }
        core::ptr::null_mut()
    }
}

/// VISIT enumeration for `twalk`. Numeric values per SUSv4 `<search.h>`.
pub const PREORDER: c_int = 0;
pub const POSTORDER: c_int = 1;
pub const ENDORDER: c_int = 2;
pub const LEAF: c_int = 3;

type WalkAction = unsafe extern "C" fn(*const c_void, c_int, c_int);

unsafe fn twalk_recurse(node: *const TNode, depth: c_int, action: WalkAction) {
    if node.is_null() {
        return;
    }
    // SAFETY: node was non-null on entry; recursive descent stays
    // inside the tree allocated via `malloc`.
    unsafe {
        let leaf = (*node).left.is_null() && (*node).right.is_null();
        if leaf {
            action(node as *const c_void, LEAF, depth);
        } else {
            action(node as *const c_void, PREORDER, depth);
            twalk_recurse((*node).left, depth + 1, action);
            action(node as *const c_void, POSTORDER, depth);
            twalk_recurse((*node).right, depth + 1, action);
            action(node as *const c_void, ENDORDER, depth);
        }
    }
}

/// `twalk(root, action)` — traverse the tree rooted at `root`
/// calling `action(node, which, depth)` at each visit. `which` is
/// one of PREORDER/POSTORDER/ENDORDER/LEAF.
///
/// # Safety
/// `root` must be a tree built exclusively by `tsearch`; `action`
/// must be a valid `WalkAction`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn twalk(root: *const c_void, action: WalkAction) {
    // SAFETY: forwarded.
    unsafe {
        twalk_recurse(root as *const TNode, 0, action);
    }
}

// ── utmp ────────────────────────────────────────────────────────────

/// `<utmp.h>` `struct utmp` per SUSv4, simplified. The full struct
/// has many architecture-specific quirks; we ship the load-bearing
/// fields most callers touch.
#[repr(C)]
pub struct utmp {
    pub ut_type: i16,
    pub ut_pid: i32,
    pub ut_line: [c_char; 32],
    pub ut_id: [c_char; 4],
    pub ut_user: [c_char; 32],
    pub ut_host: [c_char; 256],
    pub ut_exit: [i32; 2],
    pub ut_session: i32,
    pub ut_tv: [i32; 2],
    pub ut_addr_v6: [i32; 4],
    pub __unused: [c_char; 20],
}

/// `setutent()` — rewind the utmp iterator. No-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setutent() {}

/// `endutent()` — close the utmp iterator. No-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn endutent() {}

/// `getutent()` — return the next utmp entry, or NULL when the
/// iterator is exhausted. NARF has no login DB, so the first call
/// already returns NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getutent() -> *mut utmp {
    core::ptr::null_mut()
}

/// `pututline(ut)` — append `ut` to the utmp DB. No-op success
/// (returns the input pointer per SUSv4).
///
/// # Safety
/// `ut`, when non-null, must point at a valid `utmp`. We don't
/// inspect it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pututline(ut: *const utmp) -> *mut utmp {
    ut as *mut utmp
}

/// `utmpname(file)` — switch the iterator to `file`. No-op success.
///
/// # Safety
/// `file`, when non-null, must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn utmpname(_file: *const c_char) -> c_int {
    0
}

// ── crypt ───────────────────────────────────────────────────────────

/// `<crypt.h>` `struct crypt_data` — opaque scratchpad for `crypt_r`.
/// Fields don't matter (we never inspect them); shape matches the
/// conventional `<crypt.h>` layout so a binary's
/// `sizeof(struct crypt_data)` lines up.
#[repr(C)]
pub struct crypt_data {
    pub keysched: [c_char; 16 * 8],
    pub sb0: [c_char; 32768],
    pub sb1: [c_char; 32768],
    pub sb2: [c_char; 32768],
    pub sb3: [c_char; 32768],
    pub crypt_3_buf: [c_char; 14],
    pub current_salt: [c_char; 2],
    pub current_saltbits: i64,
    pub direction: c_int,
    pub initialized: c_int,
}

/// `crypt(key, salt)` — hash `key` under `salt`. NARF doesn't ship a
/// hash today; returns NULL with `errno = ENOSYS`.
///
/// # Safety
/// `key` and `salt`, when non-null, must each be valid NUL-terminated
/// C strings. We don't read them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypt(_key: *const c_char, _salt: *const c_char) -> *mut c_char {
    crate::errno::set_errno(ENOSYS);
    core::ptr::null_mut()
}

/// `crypt_r(key, salt, data)` — re-entrant variant. Same NULL/ENOSYS.
///
/// # Safety
/// `data`, when non-null, must point to a writable `crypt_data` slot;
/// we don't touch it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypt_r(
    _key: *const c_char,
    _salt: *const c_char,
    _data: *mut crypt_data,
) -> *mut c_char {
    crate::errno::set_errno(ENOSYS);
    core::ptr::null_mut()
}
