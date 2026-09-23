//! Cross-subsystem sysctl tunables.
//!
//! Most `/proc/sys` knobs live next to the subsystem that enforces them.
//! These do not, because the two crates involved cannot see each other:
//! `narf-filesystem` owns the procfs registry that presents the knob, and
//! `narf-net` owns the code that must obey it, and neither depends on the
//! other (`frame/src/cross_crate_init.rs` wires them at boot). The existing
//! bridge in `filesystem/src/procfs/net.rs` is a set of read-only
//! fn-pointer hooks — procfs pulling a snapshot *out* of the net stack.
//! A sysctl runs the other way: procfs writes policy that the net stack
//! reads on the datapath.
//!
//! Rather than grow write hooks, the few knobs with that shape live here,
//! in the crate both sides already depend on. Storing them anywhere else
//! risks the split-brain this module exists to prevent: procfs updating one
//! copy while the datapath reads another, so a write to `/proc/sys` reads
//! back correctly and changes nothing.
//!
//! Add to this module only when a knob genuinely spans that boundary.

/// `net.ipv4.*` tunables.
pub mod ipv4 {
    use core::sync::atomic::{AtomicU32, Ordering};

    /// `net.ipv4.icmp_echo_ignore_all`. Non-zero means: do not answer ICMP
    /// echo requests at all. Linux default 0 (`icmp_sk_init`,
    /// `net/ipv4/icmp.c`).
    pub static ICMP_ECHO_IGNORE_ALL: AtomicU32 = AtomicU32::new(0);

    /// `net.ipv4.icmp_echo_ignore_broadcasts`. Non-zero means: do not answer
    /// echo requests addressed to a broadcast or multicast destination.
    /// Linux default 1 — this is the Smurf-amplification guard, so the
    /// secure value is the default and a fresh boot must already enforce it.
    pub static ICMP_ECHO_IGNORE_BROADCASTS: AtomicU32 = AtomicU32::new(1);

    /// True iff echo requests must be ignored outright.
    #[inline]
    pub fn icmp_echo_ignore_all() -> bool {
        ICMP_ECHO_IGNORE_ALL.load(Ordering::Relaxed) != 0
    }

    /// True iff echo requests to broadcast/multicast must be ignored.
    #[inline]
    pub fn icmp_echo_ignore_broadcasts() -> bool {
        ICMP_ECHO_IGNORE_BROADCASTS.load(Ordering::Relaxed) != 0
    }

    /// Restore both knobs to their Linux defaults. Test-only.
    pub fn __reset_for_test() {
        ICMP_ECHO_IGNORE_ALL.store(0, Ordering::Relaxed);
        ICMP_ECHO_IGNORE_BROADCASTS.store(1, Ordering::Relaxed);
    }
}
