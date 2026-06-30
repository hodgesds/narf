//! Uevent broadcast channel — hotplug notifications.
//!
//! Linux reference: `lib/kobject_uevent.c`.
//!
//! Format: one event = a sequence of NUL-terminated `KEY=value` strings
//! packed into a contiguous buffer terminated by a bare NUL (`\0\0`).
//! Mandatory keys per Linux ABI:
//!
//!   ACTION=add|remove|change
//!   DEVPATH=/devices/...
//!   SUBSYSTEM=<class>
//!
//! Linux `kobject_uevent_env` (kobject_uevent.c:544) additionally
//! prepends the action string as the very first "header" line followed
//! by `@<devpath>` — we omit that line because our consumers are
//! kernel-internal only at Stage-4; the formatted text is newline-
//! delimited here for human readability during bring-up.
//!
//! The ring holds `UEVENT_RING_N` events.  The oldest event is
//! overwritten silently when the ring is full (matching Linux's
//! netlink-queue-full behaviour where slow consumers lose events).
//!
//! `UeventReader` is a ticket-style cursor that reads from where
//! it left off; multiple readers advance independently.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Poller wake hook ──────────────────────────────────────────────────
//
// A uevent emit must wake any `NETLINK_KOBJECT_UEVENT` monitor parked in
// poll/epoll, else udevd / `udevadm monitor` only see events on the coarse
// fallback tick. The wake lives in the net/socket layer (readiness gen +
// io-waiter wake); this crate can't depend on it, so the userspace layer
// installs it via `set_wake_hook` at boot. Stored as `fn() as usize`.
static WAKE_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Install the post-emit wake callback (typically `narf_net::readiness::
/// notify`). Called once during userspace bring-up.
pub fn set_wake_hook(f: fn()) {
    WAKE_HOOK.store(f as usize, Ordering::Release);
}

fn fire_wake() {
    let h = WAKE_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: only ever stored as `fn() as usize` by `set_wake_hook`.
        let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(h) };
        f();
    }
}

// ── Constants ─────────────────────────────────────────────────────────

/// Minimum ring capacity.  Linux's netlink queue default is 10 MiB;
/// here we're budget-conscious — 256 entries covers typical boot
/// (< 100 hotplug events) plus a headroom factor of ~2.
pub const UEVENT_RING_N: usize = 256;

// ── Action ───────────────────────────────────────────────────────────

/// Hotplug action.  Mirrors Linux `kobject_action` (kobject.h:57).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UeventAction {
    /// Device (or kobject) added.   Linux: `KOBJ_ADD`.
    Add,
    /// Device removed.              Linux: `KOBJ_REMOVE`.
    Remove,
    /// Device state changed.        Linux: `KOBJ_CHANGE`.
    Change,
}

impl UeventAction {
    /// Serialise to the value that appears in `ACTION=<x>`.
    pub fn as_str(self) -> &'static str {
        match self {
            UeventAction::Add => "add",
            UeventAction::Remove => "remove",
            UeventAction::Change => "change",
        }
    }
}

// ── UeventEnv ────────────────────────────────────────────────────────

/// One uevent: mandatory fields plus optional extras.
///
/// Linux ref: `struct kobj_uevent_env` (kobject.h:80).
#[derive(Clone, Debug)]
pub struct UeventEnv {
    /// `ACTION=<x>`
    pub action: UeventAction,
    /// `DEVPATH=<path>` — absolute path under /sys.
    pub devpath: String,
    /// `SUBSYSTEM=<x>` — class name.
    pub subsystem: String,
    /// Sequence number (monotonic, assigned on emit).
    pub seqnum: u64,
    /// Extra `KEY=value` pairs appended after the mandatory trio.
    pub extras: Vec<(String, String)>,
}

impl UeventEnv {
    /// Render to newline-separated `KEY=value` text, `\n\n` terminated.
    /// Format mirrors Linux `lib/kobject_uevent.c:uevent_net_broadcast_untagged`
    /// (lines ~560-580 in 6.9) which formats `ACTION=\nDEVPATH=\nSUBSYSTEM=\n…`.
    pub fn to_text(&self) -> String {
        let mut s = alloc::format!(
            "ACTION={}\nDEVPATH={}\nSUBSYSTEM={}\nSEQNUM={}\n",
            self.action.as_str(),
            self.devpath,
            self.subsystem,
            self.seqnum,
        );
        for (k, v) in &self.extras {
            s.push_str(&alloc::format!("{}={}\n", k, v));
        }
        s.push('\n'); // double-newline terminator
        s
    }

    /// Render to the on-the-wire **kernel netlink uevent** format that
    /// libudev / udevd parse off `NETLINK_KOBJECT_UEVENT` (group 1):
    /// a `"<action>@<devpath>\0"` header line, then NUL-separated
    /// `KEY=value\0` records. Linux ref: `kobject_uevent_env`
    /// (lib/kobject_uevent.c) building `env->buf`.
    pub fn to_netlink_bytes(&self) -> Vec<u8> {
        let action = self.action.as_str();
        let mut buf: Vec<u8> = Vec::new();
        // Header: "action@devpath\0"
        buf.extend_from_slice(action.as_bytes());
        buf.push(b'@');
        buf.extend_from_slice(self.devpath.as_bytes());
        buf.push(0);
        let mut kv = |k: &str, v: &str, buf: &mut Vec<u8>| {
            buf.extend_from_slice(k.as_bytes());
            buf.push(b'=');
            buf.extend_from_slice(v.as_bytes());
            buf.push(0);
        };
        kv("ACTION", action, &mut buf);
        kv("DEVPATH", &self.devpath, &mut buf);
        kv("SUBSYSTEM", &self.subsystem, &mut buf);
        let seq = alloc::format!("{}", self.seqnum);
        kv("SEQNUM", &seq, &mut buf);
        for (k, v) in &self.extras {
            kv(k, v, &mut buf);
        }
        buf
    }
}

// ── Global ring ───────────────────────────────────────────────────────

struct Ring {
    entries: VecDeque<UeventEnv>,
    next_seqnum: u64,
}

impl Ring {
    const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            next_seqnum: 1,
        }
    }

    fn push(&mut self, mut env: UeventEnv) {
        env.seqnum = self.next_seqnum;
        self.next_seqnum += 1;
        if self.entries.len() >= UEVENT_RING_N {
            self.entries.pop_front();
        }
        self.entries.push_back(env);
    }

    /// Read up to `max` entries whose seqnum >= `from_seqnum`.
    /// Returns the slice as a Vec and the next seqnum to read from.
    fn read_from(&self, from_seqnum: u64, max: usize) -> (Vec<UeventEnv>, u64) {
        let mut out = Vec::new();
        let mut last_seqnum = from_seqnum;
        for ev in &self.entries {
            if ev.seqnum >= from_seqnum {
                if out.len() >= max {
                    break;
                }
                last_seqnum = ev.seqnum + 1;
                out.push(ev.clone());
            }
        }
        (out, last_seqnum)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn next_seqnum(&self) -> u64 {
        self.next_seqnum
    }
}

static UEVENT_RING: IrqSafeSpinLock<Ring> = IrqSafeSpinLock::new(Ring::new());

// ── Public API ────────────────────────────────────────────────────────

/// Emit a uevent into the ring.  Called by `kobject_emit_uevent`.
/// This is the `kobject_uevent` entry point (kobject_uevent.c:639).
pub fn emit(action: UeventAction, devpath: String, subsystem: String) {
    emit_with_extras(action, devpath, subsystem, Vec::new());
}

/// Emit a uevent with extra `KEY=value` pairs (e.g. `DRIVER`, `MODALIAS`).
/// Matches `add_uevent_var` (kobject_uevent.c:107).
pub fn emit_with_extras(
    action: UeventAction,
    devpath: String,
    subsystem: String,
    extras: Vec<(String, String)>,
) {
    let env = UeventEnv {
        action,
        devpath,
        subsystem,
        seqnum: 0, // filled in by Ring::push
        extras,
    };
    UEVENT_RING.lock().push(env);
    // Wake any netlink monitor parked in poll/epoll (drop the ring lock
    // first — the hook may take other locks).
    fire_wake();
}

/// How many events are currently in the ring.
pub fn ring_len() -> usize {
    UEVENT_RING.lock().len()
}

/// The seqnum that the *next* emit will assign.
pub fn next_seqnum() -> u64 {
    UEVENT_RING.lock().next_seqnum()
}

// ── UeventReader ──────────────────────────────────────────────────────

/// Read-cursor into the uevent ring.  Create with `UeventReader::new()`
/// to start from the current tail (newest events only); create with
/// `UeventReader::from_start()` to replay from the oldest event in the
/// current ring window.
///
/// Linux analogue: `struct uevent_sock` (kobject_uevent.c:75) — each
/// connected netlink socket gets independent delivery.
#[derive(Debug, Clone)]
pub struct UeventReader {
    next_seqnum: u64,
}

impl Default for UeventReader {
    fn default() -> Self {
        Self::new()
    }
}

impl UeventReader {
    /// Position the reader at the *current* tail — future events only.
    pub fn new() -> Self {
        Self {
            next_seqnum: next_seqnum(),
        }
    }

    /// Position the reader at the oldest event still in the ring.
    pub fn from_start() -> Self {
        let ring = UEVENT_RING.lock();
        let oldest = ring
            .entries
            .front()
            .map(|e| e.seqnum)
            .unwrap_or(ring.next_seqnum);
        Self {
            next_seqnum: oldest,
        }
    }

    /// Drain up to `max` pending events.  Returns a vec of
    /// `(UeventEnv, rendered_text)` pairs in FIFO order.  Advances
    /// the cursor so a subsequent call yields only newer events.
    pub fn drain(&mut self, max: usize) -> Vec<UeventEnv> {
        let ring = UEVENT_RING.lock();
        let (evs, next) = ring.read_from(self.next_seqnum, max);
        drop(ring);
        self.next_seqnum = next;
        evs
    }

    /// Peek without advancing.
    pub fn peek(&self, max: usize) -> Vec<UeventEnv> {
        let ring = UEVENT_RING.lock();
        let (evs, _) = ring.read_from(self.next_seqnum, max);
        evs
    }

    /// True if there are events waiting.
    pub fn has_pending(&self) -> bool {
        !self.peek(1).is_empty()
    }
}

// ── /sys/kernel/uevent_seqnum virtual file ────────────────────────────

/// Generate the content of `/sys/kernel/uevent_seqnum`.
/// Linux: `lib/kobject_uevent.c:uevent_seqnum_show` (line ~91).
pub fn gen_uevent_seqnum() -> String {
    alloc::format!("{}\n", next_seqnum().saturating_sub(1))
}

/// Reset the ring for testing.  NOT for production use.
#[doc(hidden)]
pub fn __reset_for_test() {
    let mut ring = UEVENT_RING.lock();
    ring.entries.clear();
    ring.next_seqnum = 1;
}
