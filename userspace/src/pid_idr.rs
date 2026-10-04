//! A PID number space, allocated the way Linux allocates one.
//!
//! Linux keeps one `struct idr` per pid namespace and allocates from it in
//! `kernel/pid.c::alloc_pid`:
//!
//! ```c
//! int pid_min = 1;
//! /* init really needs pid 1, but after reaching the maximum
//!  * wrap back to RESERVED_PIDS */
//! if (idr_get_cursor(&tmp->idr) > RESERVED_PIDS)
//!         pid_min = RESERVED_PIDS;
//! nr = idr_alloc_cyclic(&tmp->idr, NULL, pid_min, pid_max, GFP_ATOMIC);
//! if (nr == -ENOSPC)
//!         nr = -EAGAIN;
//! ```
//!
//! `idr_alloc_cyclic` (`lib/idr.c`) starts its search at `idr_next` — one past
//! the last id it handed out — and wraps to `pid_min` only when nothing is
//! free between there and `pid_max` (exclusive). A pid that was just released
//! is therefore NOT the next one handed out; it comes back only after the
//! whole space has been cycled through.
//!
//! That is load-bearing for compatibility, not cosmetic. Daemons that keep a
//! PID file (avahi-daemon via libdaemon's `daemon_pid_file_is_running`, and
//! many others) decide "already running" by checking whether the pid in a
//! stale file is alive. A lowest-free allocator hands a crashed-and-restarted
//! daemon its predecessor's pid straight back, so the restart finds its OWN
//! pid in the stale file and exits. With cyclic allocation the restart lands
//! on a new pid, as on Linux.
//!
//! clone3 `set_tid` uses `idr_alloc(tid, tid + 1)` — an exact allocation
//! that does not move the cursor. `/proc/sys/kernel/ns_last_pid` reads
//! `idr_get_cursor() - 1` and writes `idr_set_cursor(v + 1)`.

use alloc::collections::BTreeSet;

/// `include/linux/pid.h`: once a namespace's cursor has passed this, the
/// cyclic wrap goes back to `RESERVED_PIDS` instead of 1, so the low pids
/// stay for early system daemons.
pub const RESERVED_PIDS: u64 = 300;

/// One namespace's pid numbers: the set in use plus Linux's `idr_next`.
#[derive(Debug, Default)]
pub struct PidIdr {
    used: BTreeSet<u64>,
    /// `idr->idr_next`: where the next cyclic search starts.
    next: u64,
}

impl PidIdr {
    pub const fn new() -> Self {
        Self {
            used: BTreeSet::new(),
            next: 0,
        }
    }

    /// `alloc_pid`'s automatic allocation in one namespace: the cyclic
    /// search over `[pid_min, pid_max)`. `None` is `idr_alloc_cyclic`'s
    /// -ENOSPC, which `alloc_pid` reports as -EAGAIN.
    pub fn alloc_cyclic(&mut self, pid_max: u64) -> Option<u64> {
        let pid_min = if self.next > RESERVED_PIDS {
            RESERVED_PIDS
        } else {
            1
        };
        // `idr_alloc_cyclic`: start at idr_next (clamped up to `start`);
        // on -ENOSPC retry once from `start` if the first search began
        // above it.
        let id = self.next.max(pid_min);
        let nr = match self.first_free(id, pid_max) {
            Some(nr) => nr,
            None if id > pid_min => self.first_free(pid_min, pid_max)?,
            None => return None,
        };
        self.used.insert(nr);
        self.next = nr + 1;
        Some(nr)
    }

    /// Lowest unused id in `[from, end)`.
    fn first_free(&self, from: u64, end: u64) -> Option<u64> {
        let mut candidate = from;
        for &used in self.used.range(from..) {
            if used != candidate || candidate >= end {
                break;
            }
            candidate += 1;
        }
        (candidate < end).then_some(candidate)
    }

    /// clone3 `set_tid`: `idr_alloc(nr, nr + 1)`. `false` when `nr` is
    /// already in use (-ENOSPC, reported as -EEXIST). The cursor does not move.
    pub fn alloc_exact(&mut self, nr: u64) -> bool {
        self.used.insert(nr)
    }

    /// `idr_remove`. The cursor does not move.
    pub fn remove(&mut self, nr: u64) -> bool {
        self.used.remove(&nr)
    }

    /// `idr_get_cursor`.
    pub fn cursor(&self) -> u64 {
        self.next
    }

    /// `idr_set_cursor`.
    pub fn set_cursor(&mut self, next: u64) {
        self.next = next;
    }

    /// `ns_last_pid`'s read value: `idr_get_cursor() - 1`.
    pub fn last_pid(&self) -> i64 {
        self.next as i64 - 1
    }

    /// Number of ids currently allocated.
    pub fn in_use(&self) -> usize {
        self.used.len()
    }
}
