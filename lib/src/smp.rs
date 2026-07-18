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
//! Today the kernel runs single-CPU. `cpu_count()` and
//! `online_cpus()` both return 1 (BSP). Once AP bring-up lands,
//! the same accessors expose the discovered topology without
//! caller changes.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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
    let base = dtb_phys as *const u8;
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
