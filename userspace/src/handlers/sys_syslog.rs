//! `syslog(2)` — `kernel/printk/printk.c::do_syslog`.

#[allow(unused_imports)]
use super::*;

/// `include/linux/syslog.h`.
const ACTION_CLOSE: i64 = 0;
const ACTION_OPEN: i64 = 1;
const ACTION_READ: i64 = 2;
const ACTION_READ_ALL: i64 = 3;
const ACTION_READ_CLEAR: i64 = 4;
const ACTION_CLEAR: i64 = 5;
const ACTION_CONSOLE_OFF: i64 = 6;
const ACTION_CONSOLE_ON: i64 = 7;
const ACTION_CONSOLE_LEVEL: i64 = 8;
const ACTION_SIZE_UNREAD: i64 = 9;
const ACTION_SIZE_BUFFER: i64 = 10;

/// `LOGLEVEL_DEFAULT` — the "nothing saved" sentinel `CONSOLE_OFF` parks the
/// previous level under and `CONSOLE_ON` looks for.
const LOGLEVEL_DEFAULT: u32 = u32::MAX;

// The READ cursor (`syslog_seq` / `syslog_partial`) and `clear_seq` live in
// the kernel log store (`narf_console::klog`): `/dev/kmsg`'s SEEK_DATA reads
// `clear_seq` too, and both must move under the store's lock.

/// `saved_console_loglevel` — `CONSOLE_OFF` parks the current level here so
/// `CONSOLE_ON` can put it back.
static SAVED_CONSOLE_LOGLEVEL: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(LOGLEVEL_DEFAULT);

/// `syslog_action_restricted` + `check_syslog_permissions`.
///
/// ```text
/// if (dmesg_restrict) return 1;
/// return type != SYSLOG_ACTION_READ_ALL && type != SYSLOG_ACTION_SIZE_BUFFER;
/// ```
///
/// NARF's `/proc/sys/kernel/printk`-adjacent `kernel/dmesg_restrict` reports
/// `1` and is read-only — the kernel's stated posture is that the log is
/// exposed only to capability holders — so the first branch is the live one
/// and EVERY action is restricted. Reading the value from that file rather
/// than assuming `0` is the point: the two must not disagree, or a caller
/// that reads the sysctl to decide whether to try would be misled.
fn syslog_action_restricted(_action: i64) -> bool {
    // `dmesg_restrict` is 1 in NARF; when it becomes writable this becomes
    // `restrict || (action != READ_ALL && action != SIZE_BUFFER)`.
    true
}

/// Copy `text` to the user buffer, returning its length or `-EFAULT`.
fn copy_out(buf: u64, text: &[u8]) -> i64 {
    if text.is_empty() {
        return 0;
    }
    // SAFETY: copy_to_user range-validates the destination; `text.len()` is
    // at most the caller-declared capacity.
    match unsafe { copy_to_user(buf, text) } {
        Ok(_) => text.len() as i64,
        Err(_) => -EFAULT,
    }
}

/// `SYSCALL_DEFINE3(syslog, int type, char __user *buf, int len)` —
/// x86_64 103, generic 116.
///
/// `do_syslog(type, buf, len, SYSLOG_FROM_READER)`. `dmesg` and
/// `systemd-journald` are the callers that matter: journald's
/// `server_read_dev_kmsg` falls back to this when `/dev/kmsg` is
/// unavailable, and `dmesg` uses it unless told to use `/dev/kmsg`.
pub(crate) fn sys_syslog(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    // `int type` and `int len` — sign-extend from 32 bits, because a caller
    // passing a negative length must reach the `len < 0` check below rather
    // than being read as an enormous unsigned one.
    let action = a.arg0 as u32 as i32 as i64;
    let buf = a.arg1;
    let len = a.arg2 as u32 as i32 as i64;
    let task = current_task_id();

    // `error = check_syslog_permissions(type, source); if (error) return
    // error;` — BEFORE the action is even looked at, so an unprivileged
    // caller cannot learn which actions exist by probing errnos.
    if syslog_action_restricted(action) && !task_capable(task, CAP_SYSLOG) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }

    let r: i64 = match action {
        // Both are no-ops in Linux too: the log has no per-opener state,
        // and `/proc/kmsg`'s open is where its permission check lives.
        ACTION_CLOSE | ACTION_OPEN => 0,

        ACTION_READ | ACTION_READ_ALL | ACTION_READ_CLEAR => {
            // `if (!buf || len < 0) return -EINVAL; if (!len) return 0;`
            // The order matters: a null buffer with len 0 is EINVAL, not a
            // successful no-op.
            if buf == 0 || len < 0 {
                -EINVAL
            } else if len == 0 {
                0
            } else if validate_user_range(buf, len as usize).is_err() {
                // `if (!access_ok(buf, len)) return -EFAULT;`
                -EFAULT
            } else if action == ACTION_READ {
                // `syslog_print`: whole records while they fit, the first
                // one partially when not even it fits (the remainder comes
                // on the next call), "<prio>[secs.usecs] text\n" per line.
                //
                // LINUX-GAP: Linux blocks (`wait_event_interruptible`) when
                // nothing is unread; this returns 0 instead.
                let cap = (len as usize).min(narf_console::klog::syslog_size_unread().max(1));
                let mut tmp = alloc::vec![0u8; cap];
                let n = narf_console::klog::syslog_read(&mut tmp);
                copy_out(buf, &tmp[..n])
            } else {
                // `syslog_print_all`: the NEWEST records that fit in `len`
                // (not the first `len` bytes — `dmesg` with a small buffer
                // wants what just happened), from `clear_seq` on; READ_CLEAR
                // then moves `clear_seq` past what it returned. The kernel
                // buffer is sized to the text available (plus slack for
                // records racing in), not to an arbitrarily large `len`;
                // when it is smaller than `len`, everything fits either way.
                let want = narf_console::klog::syslog_all_size();
                let cap = (len as usize).min(want + 4096);
                let mut tmp = alloc::vec![0u8; cap];
                let n = narf_console::klog::syslog_read_all(&mut tmp, action == ACTION_READ_CLEAR);
                copy_out(buf, &tmp[..n])
            }
        }

        // `syslog_clear()` — the records stay; what changes is where
        // READ_ALL (and `/dev/kmsg` SEEK_DATA) starts.
        ACTION_CLEAR => {
            narf_console::klog::syslog_clear();
            0
        }

        // `if (saved_console_loglevel == LOGLEVEL_DEFAULT) saved = current;
        //  console_loglevel = minimum_console_loglevel;`
        //
        // Guarded, so two CONSOLE_OFFs in a row do not save the minimum
        // over the real level and make CONSOLE_ON a no-op.
        ACTION_CONSOLE_OFF => {
            let _ = SAVED_CONSOLE_LOGLEVEL.compare_exchange(
                LOGLEVEL_DEFAULT,
                narf_console::klog::console_loglevel(),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            narf_console::klog::set_console_loglevel(narf_console::klog::MINIMUM_CONSOLE_LOGLEVEL);
            0
        }

        ACTION_CONSOLE_ON => {
            let saved = SAVED_CONSOLE_LOGLEVEL.swap(LOGLEVEL_DEFAULT, Ordering::AcqRel);
            if saved != LOGLEVEL_DEFAULT {
                narf_console::klog::set_console_loglevel(saved);
            }
            0
        }

        // `if (len < 1 || len > 8) return -EINVAL;` then clamp UP to the
        // minimum. The clamp is not a rejection: asking for 0 is EINVAL,
        // but asking for a level below the floor silently gets the floor.
        ACTION_CONSOLE_LEVEL => {
            if !(1..=8).contains(&len) {
                -EINVAL
            } else {
                let want = core::cmp::max(len as u32, narf_console::klog::MINIMUM_CONSOLE_LOGLEVEL);
                narf_console::klog::set_console_loglevel(want);
                // "Implicitly re-enable logging to console" — an explicit
                // level supersedes a parked one, or a later CONSOLE_ON
                // would undo the caller's choice.
                SAVED_CONSOLE_LOGLEVEL.store(LOGLEVEL_DEFAULT, Ordering::Release);
                0
            }
        }

        // Formatted bytes the READ cursor has not consumed
        // (`get_record_print_text_size` summed, minus `syslog_partial`).
        ACTION_SIZE_UNREAD => narf_console::klog::syslog_size_unread() as i64,

        // `error = log_buf_len;`
        ACTION_SIZE_BUFFER => narf_console::klog::log_buf_len() as i64,

        _ => -EINVAL,
    };
    ctx.set_return(SyscallReturn::ok(r as u64));
}

/// Test hook — put the syslog cursors back where a fresh boot has them.
#[doc(hidden)]
pub fn __test_syslog_reset() {
    narf_console::klog::__reset_syslog_cursors();
    SAVED_CONSOLE_LOGLEVEL.store(LOGLEVEL_DEFAULT, Ordering::Release);
    narf_console::klog::set_console_loglevel(narf_console::klog::DEFAULT_CONSOLE_LOGLEVEL);
}
