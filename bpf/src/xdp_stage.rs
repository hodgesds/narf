//! Per-CPU staging buffers for XDP frame resizing.
//!
//! A bare RX frame has no slack: the driver hands the classifier a slice sized
//! to exactly the packet (virtio-net gives `&mut buf[12..end]`, e1000 the
//! same). `bpf_xdp_adjust_head`/`_tail` need room on either side of the packet
//! to grow into, so a resizing program is run against one of these buffers
//! instead — laid out `[headroom | packet | tailroom]` — with `data`/`data_end`
//! pointing at the packet sub-range. The adjust intrinsics move those pointers
//! within `[buf, buf + STAGE_LEN]`; the run path copies the effective
//! `[data, data_end)` back into the caller's frame afterwards (see
//! `crate::prog::run_xdp`).
//!
//! One buffer per CPU, claimed for the duration of a single program run. That
//! is sound for the same reason the per-CPU redirect slot in `crate::kfuncs` is:
//! an XDP program runs with IRQs masked and `XDP_PROGS` held
//! (`narf_net::bypass::classifier::run_xdp`), so between the claim and the
//! copy-back the running CPU cannot change and no other frame on this CPU can
//! reach the same buffer. The claim is nonetheless made atomic with respect to
//! interrupts and refuses re-entry, mirroring the per-CPU stack provider in
//! `crate::mem`, so a nested run (were the masking premise ever weakened)
//! declines rather than aliasing.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::percpu::{current_cpu, MAX_CPUS};
use narf_lib::sync::without_interrupts;

/// Headroom reserved before the packet, in bytes.
///
/// 256, matching Linux's `XDP_PACKET_HEADROOM`. It bounds how far
/// `bpf_xdp_adjust_head` may grow the head — enough for the header pushes XDP
/// programs actually do (an extra VLAN tag, an encap header) without making the
/// per-CPU buffers large.
pub const XDP_HEADROOM: usize = 256;

/// The largest packet the staged buffer can hold, in bytes.
///
/// A jumbo-ish ceiling above the 1514-byte Ethernet MTU, so the common frame
/// stages with tailroom to spare. A frame larger than this is run unresized
/// (`crate::prog::run_xdp_staged`) rather than truncated.
pub const XDP_STAGE_PACKET_MAX: usize = 2048;

/// Total staged buffer length: headroom, the largest packet, and an equal
/// tailroom for `bpf_xdp_adjust_tail` to grow into.
pub const XDP_STAGE_LEN: usize = XDP_HEADROOM + XDP_STAGE_PACKET_MAX + XDP_HEADROOM;

/// Per-CPU staging storage.
///
/// A bare array of `UnsafeCell`s with a hand-written `Sync`, the same trade
/// `crate::mem::PerCpuFrames` and the slab magazine make: a const-initialisable
/// mutable byte array cannot go through `narf_lib::percpu::PerCpu<T>` (which
/// needs `T: Copy`).
struct PerCpuStage {
    cells: [UnsafeCell<[u8; XDP_STAGE_LEN]>; MAX_CPUS],
}

// SAFETY: a cell is only ever reached through `current_cpu()` inside
// `without_interrupts`, and only after `IN_USE[cpu]` transitions 0 → 1. Two
// CPUs therefore touch disjoint cells, and one CPU cannot re-enter its own cell
// because the claim declines the second acquire. The `Guard` is `!Send` and
// records the CPU it was claimed on, so the release cannot land on the wrong
// flag. This is the argument `crate::mem::PerCpuFrames` makes.
unsafe impl Sync for PerCpuStage {}

static STAGE: PerCpuStage = PerCpuStage {
    cells: [const { UnsafeCell::new([0u8; XDP_STAGE_LEN]) }; MAX_CPUS],
};

/// Whether each CPU's staging buffer is currently claimed.
static IN_USE: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// An exclusive lease on the current CPU's staging buffer.
///
/// Held for one program run. Dropping it releases the buffer on the CPU it was
/// claimed on. `!Send` (the raw pointer sees to that) so the lease cannot
/// migrate between the claim and the release.
#[derive(Debug)]
pub struct Guard {
    cpu: usize,
    buf: *mut [u8; XDP_STAGE_LEN],
}

impl Guard {
    /// Claim this CPU's staging buffer.
    ///
    /// The caller runs with IRQs masked and `XDP_PROGS` held, so the claim
    /// always succeeds in practice; the atomic RMW is belt to that brace. On the
    /// impossible contended path it spins briefly — the holder is the same CPU a
    /// few instructions ahead and cannot be preempted under the masking premise,
    /// so this is a formality that keeps the type honest rather than a real wait.
    #[must_use]
    pub fn claim() -> Self {
        loop {
            let claimed = without_interrupts(|| {
                let cpu = current_cpu();
                IN_USE[cpu]
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                    .then_some(cpu)
            });
            if let Some(cpu) = claimed {
                return Self {
                    cpu,
                    buf: STAGE.cells[cpu].get(),
                };
            }
            core::hint::spin_loop();
        }
    }

    /// The staged buffer, exclusively borrowed.
    #[inline]
    #[must_use]
    pub fn bytes_mut(&mut self) -> &mut [u8; XDP_STAGE_LEN] {
        // SAFETY: `IN_USE[self.cpu]` went 0 → 1 in `claim` and stays 1 until this
        // guard drops, so this CPU has exclusive use of its cell. No other CPU
        // indexes it, and the guard is `!Send` so it cannot have migrated.
        unsafe { &mut *self.buf }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        without_interrupts(|| {
            debug_assert_eq!(
                self.cpu,
                current_cpu(),
                "an XDP staging buffer was released on a different CPU than it \
                 was claimed on — Guard is !Send precisely to make this \
                 impossible"
            );
            IN_USE[self.cpu].store(0, Ordering::Release);
        });
    }
}
