//! Batch 21 — Linux keyrings (`add_key` / `request_key` / `keyctl`).
//!
//! A real in-kernel key store, not a stub. Keys are
//! `(type, description, payload, perm)` tuples held in a global side table
//! keyed by an opaque positive serial:
//!
//!  - `add_key` inserts a new key (or updates the payload of an existing
//!    `(type, description)`) and returns its serial.
//!  - `request_key` and `KEYCTL_SEARCH` look a key up by
//!    `(type, description)`, returning its serial or `-ENOKEY`.
//!  - `keyctl` operates on a key by serial: `READ` copies the payload back,
//!    `UPDATE` replaces it, `REVOKE` tombstones it (subsequent reads return
//!    `-EKEYREVOKED`), `DESCRIBE` renders the `type;uid;gid;perm;desc`
//!    summary, `SETPERM` sets the permission mask, `SET_TIMEOUT` accepts an
//!    expiry (keys never expire here), `UNLINK` removes a key, `CLEAR`
//!    empties the keyring.
//!
//! NARF runs a single session, so the special keyring ids (the negative
//! `KEY_SPEC_*` constants and 0) all resolve to one implicit session
//! keyring that owns every key — there is no per-thread/-process/-user
//! keyring split to track. `JOIN_SESSION_KEYRING` therefore just hands back
//! that one keyring's serial, and `LINK` is a no-op.
//!
//! This is a compatibility shim (it lets systemd's `setup_keyring()`
//! succeed), not a security boundary: there is no per-key access control and
//! the store is process-global.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::handlers::{copy_from_user_vec, copy_to_user, copy_user_cstr};
use crate::syscall::{SyscallReturn, TrapContext};

// ── errno values (negated-long convention) ──────────────────────────
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const ENOKEY: i64 = 126;
const EKEYREVOKED: i64 = 128;
const EOPNOTSUPP: i64 = 95;

fn err(e: i64) -> SyscallReturn {
    SyscallReturn::ok((-e) as u64)
}
fn ok(v: u64) -> SyscallReturn {
    SyscallReturn::ok(v)
}

// ── keyctl(2) operation selectors ───────────────────────────────────
const KEYCTL_GET_KEYRING_ID: u64 = 0;
const KEYCTL_JOIN_SESSION_KEYRING: u64 = 1;
const KEYCTL_UPDATE: u64 = 2;
const KEYCTL_REVOKE: u64 = 3;
const KEYCTL_SETPERM: u64 = 5;
const KEYCTL_DESCRIBE: u64 = 6;
const KEYCTL_CLEAR: u64 = 7;
const KEYCTL_LINK: u64 = 8;
const KEYCTL_UNLINK: u64 = 9;
const KEYCTL_SEARCH: u64 = 10;
const KEYCTL_READ: u64 = 11;
const KEYCTL_SET_TIMEOUT: u64 = 15;

/// The single implicit session keyring's serial. Every special keyring id
/// (`KEY_SPEC_*` = -1..=-8, and 0) resolves to this one container.
const SESSION_KEYRING_ID: i32 = 1;

/// Default permission mask reported by `DESCRIBE` — possessor + user get
/// view/read/write/search (mirrors the kernel's default for a `user` key).
const KEY_DEFAULT_PERM: u32 = 0x3f1f_0000;

struct Key {
    serial: i32,
    ktype: String,
    description: String,
    payload: Vec<u8>,
    perm: u32,
    revoked: bool,
}

static KEYS: IrqSafeSpinLock<Option<BTreeMap<i32, Key>>> = IrqSafeSpinLock::new(None);
/// Serials start well above the reserved keyring id so user keys and the
/// session keyring never collide.
static NEXT_SERIAL: AtomicI32 = AtomicI32::new(1000);

fn with_keys<R>(f: impl FnOnce(&mut BTreeMap<i32, Key>) -> R) -> R {
    let mut g = KEYS.lock();
    f(g.get_or_insert_with(BTreeMap::new))
}

/// Test-only reset so in-kernel smokes start from an empty store.
#[doc(hidden)]
pub fn __test_keyring_reset() {
    *KEYS.lock() = Some(BTreeMap::new());
    NEXT_SERIAL.store(1000, Ordering::Relaxed);
}

/// `add_key(type, description, payload, plen, keyring)` → key serial.
///
/// Adding a `(type, description)` that already names a live key updates its
/// payload in place and returns the existing serial (Linux semantics).
pub fn sys_add_key(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let ktype = match copy_user_cstr(a.arg0, 256) {
        Some(t) if !t.is_empty() => t,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let desc = match copy_user_cstr(a.arg1, 4096) {
        Some(d) if !d.is_empty() => d,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let plen = a.arg3 as usize;
    // A null/zero payload is legal (e.g. an empty "keyring"-type key).
    let payload = if plen == 0 {
        Vec::new()
    } else {
        // SAFETY: copy_from_user_vec range-validates [arg2, arg2+plen).
        match unsafe { copy_from_user_vec(a.arg2, plen) } {
            Ok(v) => v,
            Err(_) => {
                ctx.set_return(err(EFAULT));
                return;
            }
        }
    };
    let serial = with_keys(|m| {
        if let Some(k) = m
            .values_mut()
            .find(|k| !k.revoked && k.ktype == ktype && k.description == desc)
        {
            k.payload = payload;
            k.serial
        } else {
            let serial = NEXT_SERIAL.fetch_add(1, Ordering::Relaxed);
            m.insert(
                serial,
                Key {
                    serial,
                    ktype,
                    description: desc,
                    payload,
                    perm: KEY_DEFAULT_PERM,
                    revoked: false,
                },
            );
            serial
        }
    });
    ctx.set_return(ok(serial as u64));
}

/// `request_key(type, description, callout_info, dest_keyring)` → serial.
///
/// No upcall: a miss is `-ENOKEY` (we never spawn `/sbin/request-key`).
pub fn sys_request_key(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let ktype = match copy_user_cstr(a.arg0, 256) {
        Some(t) if !t.is_empty() => t,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    let desc = match copy_user_cstr(a.arg1, 4096) {
        Some(d) if !d.is_empty() => d,
        _ => {
            ctx.set_return(err(EINVAL));
            return;
        }
    };
    match find_serial(&ktype, &desc) {
        Some(s) => ctx.set_return(ok(s as u64)),
        None => ctx.set_return(err(ENOKEY)),
    }
}

fn find_serial(ktype: &str, desc: &str) -> Option<i32> {
    with_keys(|m| {
        m.values()
            .find(|k| !k.revoked && k.ktype == ktype && k.description == desc)
            .map(|k| k.serial)
    })
}

/// `keyctl(operation, arg2, arg3, arg4, arg5)`.
pub fn sys_keyctl(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    match a.arg0 {
        // Every special keyring resolves to the one session keyring.
        KEYCTL_GET_KEYRING_ID => ctx.set_return(ok(SESSION_KEYRING_ID as u64)),

        // Join (or create) a named session keyring. Under the single-keyring
        // model there is nothing to allocate: the caller is handed the one
        // implicit session keyring. The optional name (arg1) is accepted and
        // ignored — we do not track named session keyrings separately.
        KEYCTL_JOIN_SESSION_KEYRING => ctx.set_return(ok(SESSION_KEYRING_ID as u64)),

        KEYCTL_READ => {
            let serial = a.arg1 as i32;
            let buf = a.arg2;
            let buflen = a.arg3 as usize;
            let payload = with_keys(|m| match m.get(&serial) {
                Some(k) if k.revoked => Err(EKEYREVOKED),
                Some(k) => Ok(k.payload.clone()),
                None => Err(ENOKEY),
            });
            match payload {
                Ok(p) => {
                    let n = core::cmp::min(buflen, p.len());
                    if n > 0 && buf != 0 {
                        // SAFETY: copy_to_user range-validates [buf, buf+n).
                        if unsafe { copy_to_user(buf, &p[..n]) }.is_err() {
                            ctx.set_return(err(EFAULT));
                            return;
                        }
                    }
                    // Linux returns the FULL payload length even when the
                    // caller's buffer was shorter (lets it size a retry).
                    ctx.set_return(ok(p.len() as u64));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }

        KEYCTL_UPDATE => {
            let serial = a.arg1 as i32;
            let plen = a.arg3 as usize;
            let payload = if plen == 0 {
                Vec::new()
            } else {
                // SAFETY: range-validated by copy_from_user_vec.
                match unsafe { copy_from_user_vec(a.arg2, plen) } {
                    Ok(v) => v,
                    Err(_) => {
                        ctx.set_return(err(EFAULT));
                        return;
                    }
                }
            };
            let r = with_keys(|m| match m.get_mut(&serial) {
                Some(k) if k.revoked => Err(EKEYREVOKED),
                Some(k) => {
                    k.payload = payload;
                    Ok(())
                }
                None => Err(ENOKEY),
            });
            match r {
                Ok(()) => ctx.set_return(ok(0)),
                Err(e) => ctx.set_return(err(e)),
            }
        }

        KEYCTL_REVOKE => {
            let serial = a.arg1 as i32;
            let r = with_keys(|m| match m.get_mut(&serial) {
                Some(k) if k.revoked => Err(EKEYREVOKED),
                Some(k) => {
                    k.revoked = true;
                    Ok(())
                }
                None => Err(ENOKEY),
            });
            match r {
                Ok(()) => ctx.set_return(ok(0)),
                Err(e) => ctx.set_return(err(e)),
            }
        }

        KEYCTL_SETPERM => {
            let serial = a.arg1 as i32;
            let perm = a.arg2 as u32;
            let r = with_keys(|m| match m.get_mut(&serial) {
                Some(k) if k.revoked => Err(EKEYREVOKED),
                Some(k) => {
                    k.perm = perm;
                    Ok(())
                }
                None => Err(ENOKEY),
            });
            match r {
                Ok(()) => ctx.set_return(ok(0)),
                Err(e) => ctx.set_return(err(e)),
            }
        }

        KEYCTL_DESCRIBE => {
            let serial = a.arg1 as i32;
            let buf = a.arg2;
            let buflen = a.arg3 as usize;
            let desc = with_keys(|m| match m.get(&serial) {
                Some(k) => Ok(format!("{};0;0;{:08x};{}", k.ktype, k.perm, k.description)),
                None => Err(ENOKEY),
            });
            match desc {
                Ok(s) => {
                    // NUL-terminated; the return value is the full length
                    // including the terminator (Linux semantics).
                    let mut bytes = s.into_bytes();
                    bytes.push(0);
                    let n = core::cmp::min(buflen, bytes.len());
                    if n > 0 && buf != 0 {
                        // SAFETY: range-validated by copy_to_user.
                        if unsafe { copy_to_user(buf, &bytes[..n]) }.is_err() {
                            ctx.set_return(err(EFAULT));
                            return;
                        }
                    }
                    ctx.set_return(ok(bytes.len() as u64));
                }
                Err(e) => ctx.set_return(err(e)),
            }
        }

        KEYCTL_SEARCH => {
            // (keyring=arg1, type=arg2, description=arg3, dest_keyring=arg4)
            let ktype = match copy_user_cstr(a.arg2, 256) {
                Some(t) if !t.is_empty() => t,
                _ => {
                    ctx.set_return(err(EINVAL));
                    return;
                }
            };
            let desc = match copy_user_cstr(a.arg3, 4096) {
                Some(d) if !d.is_empty() => d,
                _ => {
                    ctx.set_return(err(EINVAL));
                    return;
                }
            };
            match find_serial(&ktype, &desc) {
                Some(s) => ctx.set_return(ok(s as u64)),
                None => ctx.set_return(err(ENOKEY)),
            }
        }

        KEYCTL_UNLINK => {
            // (key=arg1, keyring=arg2) — single keyring, so unlink == remove.
            let serial = a.arg1 as i32;
            let removed = with_keys(|m| m.remove(&serial).is_some());
            if removed {
                ctx.set_return(ok(0));
            } else {
                ctx.set_return(err(ENOKEY));
            }
        }

        // Linking is a no-op under the single-keyring model: every key is
        // already a member of the only keyring there is.
        KEYCTL_LINK => ctx.set_return(ok(0)),

        // Set a key's expiry (arg2 = seconds; 0 clears it). Keys never expire
        // in this shim, so we validate the target exists and accept the
        // request. Callers only check for success/`-ENOKEY`.
        KEYCTL_SET_TIMEOUT => {
            let serial = a.arg1 as i32;
            let exists = with_keys(|m| m.contains_key(&serial));
            if exists {
                ctx.set_return(ok(0));
            } else {
                ctx.set_return(err(ENOKEY));
            }
        }

        KEYCTL_CLEAR => {
            with_keys(|m| m.clear());
            ctx.set_return(ok(0));
        }

        _ => ctx.set_return(err(EOPNOTSUPP)),
    }
}
