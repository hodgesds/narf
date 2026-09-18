//! SMP discovery + online-CPU accounting (cross-arch).
//!
//! The bookkeeping half of SMP — what CPUs exist, which ones the
//! kernel has actually brought up, and the bitmap drivers /
//! scheduler / RCU consult to size their per-CPU state. Lives in
//! `narf-lib` (the broadest lower-bound dep) so every subsystem
//! can see it without crate-cycle gymnastics.
//!
//! Bring-up — the trampoline assembly + INIT-SIPI-SIPI on x86_64
//! / PSCI CPU_ON on aarch64 — is layered on top of this surface
//! and lives in `frame/`.
//!
//! APs are brought up for real, so `cpu_count()` / `online_bitmap()`
//! report the discovered topology rather than a BSP-only stub, and user
//! tasks run on application processors (`narf_scheduler::enable_user_task_smp`).
//! The cross-CPU barrier rendezvous at the end of this file exists because
//! of that: primitives that were vacuous on a uniprocessor kernel now have
//! to be real.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

pub use crate::percpu::MAX_CPUS;

/// Total CPUs the firmware / DTB advertises.
static CPU_COUNT: AtomicU32 = AtomicU32::new(1);

/// Bit i = 1 → logical CPU i is online (responding, executing
/// kernel code). The BSP (id 0) sets its bit at static-init time.
static ONLINE_BITMAP: AtomicU64 = AtomicU64::new(0x0000_0000_0000_0001);

/// Bit i = 1 → logical CPU i has EVER been genuinely online this boot
/// (Linux `cpu_present_mask` analogue). Monotonic: set by [`mark_online`]
/// and never cleared — not by [`mark_offline`], not by
/// [`__reset_for_test`]. A really-started AP stays parked in the
/// scheduler's `run_forever` idle loop (owning its `CPU_HALTED` slot,
/// polling its queue) even when a hotplug/sysfs test rewrites the online
/// bitmap, so tests that need exclusive control of a CPU's scheduler
/// state must consult THIS record, which the test-only topology fakes
/// ([`__test_fake_online`], [`__reset_for_test`]) cannot falsify.
static EVER_ONLINE_BITMAP: AtomicU64 = AtomicU64::new(0x0000_0000_0000_0001);

/// Mark this CPU as online. Called once per CPU during its
/// per-CPU bring-up path.
///
/// # Safety
/// `logical_id` must match the calling CPU. AP bring-up writes
/// `IA32_TSC_AUX` (x86_64) or registers in the MPIDR table
/// (aarch64) before calling this so `arch::current_cpu_id()`
/// agrees. Tests faking a topology must use [`__test_fake_online`]
/// instead, so the monotonic ever-online record stays truthful.
pub unsafe fn mark_online(logical_id: u32) {
    if (logical_id as usize) < MAX_CPUS {
        ONLINE_BITMAP.fetch_or(1u64 << logical_id, Ordering::Release);
        EVER_ONLINE_BITMAP.fetch_or(1u64 << logical_id, Ordering::Release);
    }
}

/// Mark this CPU as offline. Called by the cpu-lifecycle hot-unplug
/// path before the AP halts.
pub fn mark_offline(logical_id: u32) {
    if (logical_id as usize) < MAX_CPUS {
        ONLINE_BITMAP.fetch_and(!(1u64 << logical_id), Ordering::Release);
    }
}

/// Total CPUs the firmware / DTB reports.
pub fn cpu_count() -> u32 {
    CPU_COUNT.load(Ordering::Acquire)
}

/// Set the total CPU count post-discovery. Only the discovery path
/// should call this; AP bring-up reads `cpu_count()` to size its
/// stack pool.
pub fn set_cpu_count(n: u32) {
    let n = n.max(1).min(MAX_CPUS as u32);
    CPU_COUNT.store(n, Ordering::Release);
}

/// Number of CPUs currently online.
pub fn online_count() -> u32 {
    ONLINE_BITMAP.load(Ordering::Acquire).count_ones()
}

/// Snapshot of the online-CPU bitmap.
pub fn online_bitmap() -> u64 {
    ONLINE_BITMAP.load(Ordering::Acquire)
}

/// `true` iff `logical_id` is online.
pub fn is_online(logical_id: u32) -> bool {
    if (logical_id as usize) >= MAX_CPUS {
        return false;
    }
    online_bitmap() & (1u64 << logical_id) != 0
}

/// Snapshot of the monotonic ever-online bitmap (see
/// [`EVER_ONLINE_BITMAP`]). `!= 1` ⇒ at least one AP genuinely came up
/// this boot, whatever the (fakeable) online bitmap currently claims.
pub fn ever_online_bitmap() -> u64 {
    EVER_ONLINE_BITMAP.load(Ordering::Acquire)
}

/// Test-only: force `logical_id`'s bit in the ONLINE bitmap without
/// recording it as ever-genuinely-online. For smokes that fake a
/// topology (scheduler remote-kick, bitmap surface tests); pair with
/// [`mark_offline`] to undo. Real bring-up must use [`mark_online`].
#[doc(hidden)]
pub fn __test_fake_online(logical_id: u32) {
    if (logical_id as usize) < MAX_CPUS {
        ONLINE_BITMAP.fetch_or(1u64 << logical_id, Ordering::Release);
    }
}

/// Test-only: force the published topology to single-CPU (BSP only).
///
/// PREFER [`__reset_for_test_scoped`]: this variant does NOT restore the
/// real topology, so on an SMP boot every later test in the run sees a
/// falsified `online_count()`/`cpu_count()` while the really-started APs
/// keep running — that defeated the scheduler remote-kick smoke's
/// "SMP=1 only" guard and made it flake against a live AP.
#[doc(hidden)]
pub fn __reset_for_test() {
    CPU_COUNT.store(1, Ordering::Release);
    ONLINE_BITMAP.store(1, Ordering::Release);
}

/// RAII restore for [`__reset_for_test_scoped`]: puts back the CPU count
/// and online bitmap captured before the fake, on every exit path.
#[doc(hidden)]
#[derive(Debug)]
pub struct TestTopologyReset {
    count: u32,
    bitmap: u64,
}

impl Drop for TestTopologyReset {
    fn drop(&mut self) {
        CPU_COUNT.store(self.count, Ordering::Release);
        ONLINE_BITMAP.store(self.bitmap, Ordering::Release);
    }
}

/// Test-only: force the published topology to single-CPU (BSP only) for
/// the lifetime of the returned guard, then RESTORE the real topology.
/// Use this (not [`__reset_for_test`]) from smokes that fake a CPU
/// count/bitmap — the kernel-test suite shares one boot, and a
/// left-falsified topology corrupts every later test's view of the
/// really-online CPUs.
#[doc(hidden)]
#[must_use = "the guard's Drop restores the real topology"]
pub fn __reset_for_test_scoped() -> TestTopologyReset {
    let snap = TestTopologyReset {
        count: CPU_COUNT.load(Ordering::Acquire),
        bitmap: ONLINE_BITMAP.load(Ordering::Acquire),
    };
    __reset_for_test();
    snap
}

/// Read CPUID leaf 1 EBX[23:16] for the logical-processor count
/// reported by the BSP. On QEMU `-smp N -cpu max` this matches `N`;
/// real hardware with multi-package topologies needs ACPI MADT
/// (later wave). Returns 1 if CPUID indicates a single-CPU system
/// (HTT bit clear in EDX:28).
///
/// # Safety
/// CPUID is always legal at CPL=0; the unsafe boundary is purely
/// for the inline-asm wrapper.
#[cfg(target_arch = "x86_64")]
pub unsafe fn count_x86_64_cpus_via_cpuid() -> u32 {
    use core::arch::asm;
    // CPUID leaf 0xB sub 1 (Core level). EBX[15:0] = logical
    // processors at this level = total LPs in the package on
    // single-package systems. QEMU `-smp N -cpu max` populates
    // this correctly; CPUID leaf 1 EBX[23:16] is *not* reliable
    // under QEMU.
    let mut a: u32 = 0xB;
    let b: u64;
    let mut c: u32 = 1; // sub-leaf
                        // SAFETY: CPUID is always legal at CPL=0; we preserve rbx.
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {b:r}, rbx",
            "pop rbx",
            inout("eax") a,
            inout("ecx") c,
            out("edx") _,
            b = out(reg) b,
            options(nostack, preserves_flags),
        );
    }
    let _ = a;
    let _ = c;
    let n = (b as u32) & 0xFFFF;
    if n == 0 {
        1
    } else {
        n
    }
}

/// Walk an FDT blob counting `cpu@N` nodes under the `cpus` parent.
/// Returns 0 on bad magic / truncation. Used by aarch64's discovery
/// path; x86_64 grows ACPI MADT parsing instead.
///
/// # Safety
/// `dtb_phys` (when non-zero) must point at an identity-mapped DTB
/// blob the caller has confirmed valid. The walker self-validates
/// the magic + bails on malformed structure tokens, so a bogus
/// pointer that points at random memory degrades to `0` rather
/// than UB — *provided* the pointer is at least readable.
pub unsafe fn count_aarch64_cpus_in_dtb(dtb_phys: u64) -> u32 {
    const FDT_BEGIN_NODE: u32 = 0x1;
    const FDT_END_NODE: u32 = 0x2;
    const FDT_PROP: u32 = 0x3;
    const FDT_NOP: u32 = 0x4;
    const FDT_END: u32 = 0x9;
    const FDT_MAGIC: u32 = 0xd00d_feed;

    if dtb_phys == 0 {
        return 0;
    }
    let base = crate::directmap::pv_ptr::<u8>(dtb_phys).cast_const();
    // SAFETY: caller-asserted pointer; reads bounded to the FDT
    // header (40 bytes) before trusting offsets.
    // SAFETY: Valid memory or trusted environment
    let header: [u8; 40] = unsafe { core::ptr::read(base as *const [u8; 40]) };
    let be32 = |b: &[u8]| -> u32 { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) };
    if be32(&header[0..4]) != FDT_MAGIC {
        return 0;
    }
    let off_dt_struct = be32(&header[8..12]) as usize;
    let size_dt_struct = be32(&header[36..40]) as usize;

    // SAFETY: caller's DTB blob covers off_struct + size_struct.
    let s = unsafe { core::slice::from_raw_parts(base.add(off_dt_struct), size_dt_struct) };

    let mut cursor = 0usize;
    let mut depth: i32 = 0;
    let mut in_cpus = false;
    let mut cpus_depth = 0i32;
    let mut count = 0u32;
    while cursor + 4 <= s.len() {
        let tok = be32(&s[cursor..cursor + 4]);
        cursor += 4;
        match tok {
            FDT_BEGIN_NODE => {
                let name_start = cursor;
                let mut end = name_start;
                while end < s.len() && s[end] != 0 {
                    end += 1;
                }
                let name = &s[name_start..end];
                let nlen_with_nul = (end - name_start) + 1;
                cursor = name_start + ((nlen_with_nul + 3) & !3);
                depth += 1;
                if !in_cpus && name == b"cpus" {
                    in_cpus = true;
                    cpus_depth = depth;
                }
                if in_cpus && depth == cpus_depth + 1 && name.starts_with(b"cpu@") {
                    count += 1;
                }
            }
            FDT_PROP => {
                if cursor + 8 > s.len() {
                    break;
                }
                let plen = be32(&s[cursor..cursor + 4]) as usize;
                cursor += 8;
                let padded = (plen + 3) & !3;
                if cursor + padded > s.len() {
                    break;
                }
                cursor += padded;
            }
            FDT_END_NODE => {
                if in_cpus && depth == cpus_depth {
                    in_cpus = false;
                }
                depth -= 1;
                if depth < 0 {
                    break;
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => break,
        }
    }
    count
}

// ── Cross-CPU barrier rendezvous ─────────────────────────────────
//
// The "interrupt a set of CPUs and wait until each has executed a full
// memory barrier" primitive behind `membarrier(2)`'s expedited commands.
// Linux spells this `smp_call_function_many(mask, ipi_mb, NULL, 1)`, where
// `ipi_mb()` is literally `smp_mb()` (kernel/sched/membarrier.c) — the
// load-bearing property is the synchronous rendezvous, not the work the
// handler does.
//
// The protocol is arch-neutral and lives here; only "poke this CPU set"
// is per-arch, and `narf-interrupts` installs it at boot (the same
// inversion `narf_memory::tlb_shootdown::set_ipi_fanout` uses, for the
// same reason: `narf-lib` sits below the interrupt controllers).
//
// The poke is allowed to be over-broad — aarch64's GICv3 `broadcast_others`
// has no target list, and a CPU that runs the handler without a pending
// request simply finds an empty bitmap. Under-poking is what would break
// the contract, so the ack set is tracked exactly and the wait covers only
// the CPUs the caller selected.

/// Bit `source` set ⇒ that source CPU is waiting for THIS target to
/// execute its barrier. A target claims the whole batch with `swap(0)`,
/// so one poke can discharge several concurrent senders.
static BARRIER_PENDING: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Per-source ack bitmap. Target `n` sets bit `n` only after its barrier
/// has executed. The source waits for exactly the bits it selected.
static BARRIER_ACKED: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// Serializes nested/concurrent publishers on one CPU, and (being
/// IRQ-safe) keeps `current_cpu()` stable for the lifetime of the lane.
static BARRIER_OUTGOING: [crate::sync::IrqSafeSpinLock<()>; MAX_CPUS] =
    [const { crate::sync::IrqSafeSpinLock::new(()) }; MAX_CPUS];

/// Completed rendezvous count, for smokes and diagnostics.
static BARRIER_SENT: AtomicU64 = AtomicU64::new(0);

/// Handler invocations that found at least one pending source.
static BARRIER_SERVICED: AtomicU64 = AtomicU64::new(0);

/// Per-arch "raise the barrier IPI on this CPU set". Installed once at
/// boot by `narf-interrupts`; `0` means no interrupt controller has
/// claimed the vector yet (UP boot, or pre-bring-up).
static BARRIER_POKE: AtomicUsize = AtomicUsize::new(0);

type BarrierPokeFn = fn(targets: u64);

/// Wire the per-arch barrier poke. Called once, after the vector (x86_64)
/// or SGI handler (aarch64) is installed.
pub fn set_barrier_poke(f: BarrierPokeFn) {
    BARRIER_POKE.store(f as usize, Ordering::Release);
}

/// Whether [`remote_barrier`] can actually deliver its guarantee.
///
/// True on a single-CPU system (there is no peer to synchronize with, so
/// the guarantee is vacuous and Linux returns success early for the same
/// reason) and on an SMP system whose barrier IPI is wired. Callers that
/// advertise a capability to userspace — `membarrier(2)`'s QUERY mask and
/// its registration commands — must gate on this rather than claim support
/// they cannot honour.
pub fn remote_barrier_available() -> bool {
    cpu_count() <= 1 || BARRIER_POKE.load(Ordering::Acquire) != 0
}

/// Execute a full memory barrier on every online CPU in `targets`, and
/// return only once all of them have done so.
///
/// The calling CPU is excluded (it executes its own barrier inline, and a
/// migration mid-call implies a context switch, which is itself a barrier).
/// Offline CPUs are dropped: they cannot hold user state, and their next
/// dispatch goes through a context switch.
///
/// Returns `false` without waiting when the rendezvous is unavailable —
/// see [`remote_barrier_available`]. Callers must not report success to
/// userspace in that case.
pub fn remote_barrier(targets: u64) -> bool {
    let source = crate::percpu::current_cpu().min(MAX_CPUS - 1);
    let source_bit = 1u64 << source;

    // (a) in Linux's ordering table: the caller's own writes must precede
    // the IPI, since system-call entry is not a barrier.
    core::sync::atomic::fence(Ordering::SeqCst);

    let targets = targets & online_bitmap() & !source_bit;
    if targets == 0 {
        // Nothing to rendezvous with. The fence above and the one below
        // still give the caller the local half of the guarantee.
        core::sync::atomic::fence(Ordering::SeqCst);
        return true;
    }

    let poke = BARRIER_POKE.load(Ordering::Acquire);
    if poke == 0 {
        return false;
    }
    // SAFETY: only `BarrierPokeFn as usize` is ever stored, and it is
    // non-null here.
    let poke: BarrierPokeFn = unsafe { core::mem::transmute(poke) };

    // IRQs stay masked for the lane's lifetime, so `source` cannot change
    // under us and a local nested publisher cannot reuse the ack cell.
    let _outgoing = BARRIER_OUTGOING[source].lock();
    BARRIER_ACKED[source].store(0, Ordering::Relaxed);

    let mut pending = targets;
    let mut kick = 0u64;
    while pending != 0 {
        let target = pending.trailing_zeros() as usize;
        pending &= pending - 1;
        // Only an empty→non-empty transition needs a new poke; an
        // in-flight IPI or a spinning peer will drain the added bit.
        if BARRIER_PENDING[target].fetch_or(source_bit, Ordering::Release) == 0 {
            kick |= 1u64 << target;
        }
    }
    if kick != 0 {
        poke(kick);
    }

    // Two senders that pick each other as targets would otherwise wait
    // forever: both spin with IRQs masked, so neither can take the other's
    // IPI. Servicing our own inbox inside the spin breaks that cycle —
    // the same reason the TLB shootdown sender polls.
    while BARRIER_ACKED[source].load(Ordering::Acquire) & targets != targets {
        service_pending_barriers();
        core::hint::spin_loop();
    }

    // (c) in Linux's ordering table: exit from the system call is not a
    // barrier either, so the caller's subsequent loads must not be
    // reordered before the last ack.
    core::sync::atomic::fence(Ordering::SeqCst);
    BARRIER_SENT.fetch_add(1, Ordering::Relaxed);
    true
}

/// Target side of the rendezvous. Executes this CPU's barrier and
/// acknowledges every source waiting on it.
///
/// Idempotent and safe to call with nothing pending, so it doubles as the
/// sender's anti-deadlock poll. Called from the barrier IPI handler
/// (x86_64 vector / aarch64 SGI), from [`remote_barrier`]'s wait, and from
/// the lock spin path in `crate::sync` — a CPU spinning with IRQs masked
/// cannot take the IPI, and unlike a shootdown the sender here never gives
/// up, so a stranded request would hang it.
///
/// Migrating between claiming the batch and acknowledging it is harmless.
/// `target` is read once and names the same CPU on both sides, and a
/// migration is a context switch, which is itself a full barrier on the CPU
/// being left — so the barrier the source asked for did happen, after its
/// request was published. This is the same property Linux leans on when it
/// skips the current CPU in `membarrier_global_expedited`.
pub fn service_pending_barriers() {
    let target = crate::percpu::current_cpu().min(MAX_CPUS - 1);
    let sources = BARRIER_PENDING[target].swap(0, Ordering::AcqRel);
    if sources == 0 {
        return;
    }

    // THE barrier. Claiming the batch above and acknowledging below must
    // sandwich a full fence, or an ack could be observed by the source
    // before this CPU's prior accesses are globally visible.
    core::sync::atomic::fence(Ordering::SeqCst);

    // Counted BEFORE the acknowledgements, not after. The ack is what
    // releases the sender, so a counter bumped afterwards can still be
    // invisible to it when `remote_barrier` returns — the release/acquire
    // pair on BARRIER_ACKED is what publishes this store. Ordering it the
    // other way made the rendezvous smoke fail on aarch64 and pass on
    // x86_64, which is the signature of exactly this mistake.
    BARRIER_SERVICED.fetch_add(1, Ordering::Relaxed);

    let mut remaining = sources;
    while remaining != 0 {
        let source = remaining.trailing_zeros() as usize;
        remaining &= remaining - 1;
        BARRIER_ACKED[source].fetch_or(1u64 << target, Ordering::Release);
    }
}

/// Completed [`remote_barrier`] rendezvous since boot.
pub fn barrier_sent_count() -> u64 {
    BARRIER_SENT.load(Ordering::Relaxed)
}

/// Barrier handler invocations that found work, since boot.
pub fn barrier_serviced_count() -> u64 {
    BARRIER_SERVICED.load(Ordering::Relaxed)
}
