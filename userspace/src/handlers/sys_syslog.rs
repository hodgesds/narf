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

/// Where `SYSLOG_ACTION_READ` has consumed to, as an ABSOLUTE byte position
/// in the log's history — Linux's `syslog_seq`.
///
/// Absolute rather than an offset into the live region: the ring wraps, so
/// an offset silently comes to mean a different byte every time a record is
/// written. An absolute position that falls off the back of the ring is
/// detectable, which is what lets this do what Linux does when the messages
/// a reader was waiting on are gone — "move to first one" rather than
/// return something arbitrary.
static SYSLOG_SEQ: AtomicU64 = AtomicU64::new(0);

/// Where `SYSLOG_ACTION_CLEAR` last cleared to. `READ_ALL` reports only
/// what was written after it.
static SYSLOG_CLEAR_SEQ: AtomicU64 = AtomicU64::new(0);

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

/// Clamp an absolute position into the live region, returning the offset to
/// read from and whether the position had fallen off the back.
///
/// `if (info.seq != syslog_seq) { syslog_seq = info.seq; syslog_partial = 0; }`
/// — Linux's spelling of the same thing. A reader that was too slow does not
/// get a short read of whatever happens to be there now; it gets moved to
/// the oldest surviving byte.
fn live_offset(abs: u64, written: u64, live: usize) -> (usize, u64) {
    let oldest = written - live as u64;
    if abs < oldest {
        (0, oldest)
    } else {
        ((abs - oldest) as usize, abs)
    }
}

/// Copy `[from, written)` — capped at `len` — to `buf`, returning bytes
/// written or a negative errno.
fn emit(buf: u64, len: usize, from: u64, written: u64, live: usize) -> i64 {
    let (off, _) = live_offset(from, written, live);
    let avail = live.saturating_sub(off);
    let n = avail.min(len);
    if n == 0 {
        return 0;
    }
    let mut tmp = alloc::vec![0u8; n];
    let got = narf_console::klog::read_at(off, &mut tmp);
    if got == 0 {
        return 0;
    }
    // SAFETY: copy_to_user range-validates the destination; `got <= len` is
    // the caller-declared capacity.
    match unsafe { copy_to_user(buf, &tmp[..got]) } {
        Ok(_) => got as i64,
        Err(_) => -14, // -EFAULT
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
    const EINVAL: i64 = -22;
    const EPERM: i64 = -1;
    const EFAULT: i64 = -14;

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
        ctx.set_return(SyscallReturn::ok(EPERM as u64));
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
                EINVAL
            } else if len == 0 {
                0
            } else if validate_user_range(buf, len as usize).is_err() {
                // `if (!access_ok(buf, len)) return -EFAULT;`
                EFAULT
            } else {
                let (written, live) = narf_console::klog::span();
                if action == ACTION_READ {
                    // Destructive read: advance the cursor past what was
                    // returned, so a second call continues rather than
                    // repeating. This is the `/proc/kmsg` drain shape.
                    let from = SYSLOG_SEQ.load(Ordering::Acquire);
                    let (_, from) = live_offset(from, written, live);
                    let n = emit(buf, len as usize, from, written, live);
                    if n > 0 {
                        SYSLOG_SEQ.store(from + n as u64, Ordering::Release);
                    }
                    n
                } else {
                    // `syslog_print_all`: the LAST `len` bytes, not the
                    // first — `dmesg` with a small buffer wants the most
                    // recent output, and a head-first read would hand it
                    // the boot banner forever.
                    let clear = SYSLOG_CLEAR_SEQ.load(Ordering::Acquire);
                    let (_, floor) = live_offset(clear, written, live);
                    let start = core::cmp::max(floor, written.saturating_sub(len as u64));
                    let n = emit(buf, len as usize, start, written, live);
                    if action == ACTION_READ_CLEAR && n >= 0 {
                        SYSLOG_CLEAR_SEQ.store(written, Ordering::Release);
                    }
                    n
                }
            }
        }

        // `syslog_clear()` — the bytes stay in the ring (Linux's is a
        // sequence bump too); what changes is where READ_ALL starts.
        ACTION_CLEAR => {
            let (written, _) = narf_console::klog::span();
            SYSLOG_CLEAR_SEQ.store(written, Ordering::Release);
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
                EINVAL
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

        // Bytes the READ cursor has not consumed. Linux reports the size of
        // the formatted text; NARF's ring holds the text itself, so the
        // count is exact rather than estimated.
        ACTION_SIZE_UNREAD => {
            let (written, live) = narf_console::klog::span();
            let from = SYSLOG_SEQ.load(Ordering::Acquire);
            let (off, _) = live_offset(from, written, live);
            live.saturating_sub(off) as i64
        }

        // `error = log_buf_len;`
        ACTION_SIZE_BUFFER => narf_console::klog::RING_CAPACITY as i64,

        _ => EINVAL,
    };
    ctx.set_return(SyscallReturn::ok(r as u64));
}

/// Test hook — put the syslog cursors back where a fresh boot has them.
#[doc(hidden)]
pub fn __test_syslog_reset() {
    SYSLOG_SEQ.store(0, Ordering::Release);
    SYSLOG_CLEAR_SEQ.store(0, Ordering::Release);
    SAVED_CONSOLE_LOGLEVEL.store(LOGLEVEL_DEFAULT, Ordering::Release);
    narf_console::klog::set_console_loglevel(narf_console::klog::DEFAULT_CONSOLE_LOGLEVEL);
}
