//! Per-CPU kernel storage + swapgs setup.
//!
//! The `syscall` instruction and user→kernel interrupts all arrive
//! with GS unchanged from user state — the kernel needs its own
//! per-CPU data pointer on each trap to find things like
//! "what's the current task's kernel stack?". x86_64 handles this
//! with `IA32_KERNEL_GS_BASE`: on trap entry the kernel issues
//! `swapgs`, which exchanges the current `GS.base` with the
//! contents of `IA32_KERNEL_GS_BASE`. After `swapgs`:
//! - `GS.base` points at this `PerCpu` struct
//! - `IA32_KERNEL_GS_BASE` holds whatever the user had in GS
//!
//! Before `iretq` / `sysret`-to-user the kernel issues another
//! `swapgs` to restore the user's GS.
//!
//! Stage-4 structural: one `PerCpu` struct, BSP-only. SMP bring-up
//! will allocate a separate `PerCpu` per AP and set each AP's
//! `IA32_KERNEL_GS_BASE` to its own instance.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_arch::x86_64::msr;

/// Per-CPU kernel-side storage. Field 0 *must* be `kernel_rsp_save`
/// because the SYSCALL entry stub (landing later) reads it at `gs:0`
/// to find the kernel stack. Layout is load-bearing.
#[repr(C)]
#[derive(Debug)]
pub struct PerCpu {
    /// Scratch slot the trap entry uses to save the user RSP while
    /// it switches to the kernel stack from `gs:kernel_stack_top`.
    pub user_rsp_save:    AtomicU64,
    /// Top of the kernel stack for the currently-running task.
    /// Mirror of `TSS.rsp0` for the SYSCALL entry (which bypasses
    /// the TSS-triggered stack swap and has to look it up itself).
    pub kernel_stack_top: AtomicU64,
    /// Identity: which CPU this instance describes. BSP = 0.
    pub cpu_id:           u32,
    /// Padding to 64-byte cache-line alignment.
    _pad:                 [u32; 5],
}

impl PerCpu {
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            user_rsp_save:    AtomicU64::new(0),
            kernel_stack_top: AtomicU64::new(0),
            cpu_id,
            _pad:             [0; 5],
        }
    }
}

/// BSP instance, used for tests + Stage-4 single-CPU work. SMP
/// bring-up replaces this with a per-AP table.
static BSP_PERCPU: PerCpu = PerCpu::new(0);

/// MSR numbers we program at init.
const IA32_GS_BASE:         u32 = 0xC0000101;
const IA32_KERNEL_GS_BASE:  u32 = 0xC0000102;

/// Initialise per-CPU state for the BSP.
///
/// After this:
/// - `GS.base` = &BSP_PERCPU (kernel uses this directly — no
///   `swapgs` required from kernel-mode code paths).
/// - `IA32_KERNEL_GS_BASE` = 0 (set to the user's desired GS.base
///   when a user task is scheduled; until real user mode runs, 0
///   is the structural sentinel).
/// - `BSP_PERCPU.kernel_stack_top` mirrors `TSS.rsp0` so the
///   Stage-4 SYSCALL stub (landing later) can read the kernel
///   stack pointer from `gs:8`.
///
/// # Safety
/// Must run once on the BSP after `gdt::init` has installed
/// `TSS.rsp0`.
pub unsafe fn init_bsp() {
    let addr = core::ptr::addr_of!(BSP_PERCPU) as u64;

    // Mirror TSS.rsp0 into `PerCpu.kernel_stack_top`.
    BSP_PERCPU.kernel_stack_top.store(
        super::gdt::kernel_rsp0(),
        Ordering::Release,
    );

    // SAFETY: writing GS_BASE and KERNEL_GS_BASE at CPL=0 is a
    // documented operation. `msr::wrmsr` carries the
    // `compiler_fence(SeqCst)` pair from arch/ §4.
    unsafe {
        msr::wrmsr(IA32_GS_BASE,        addr);
        msr::wrmsr(IA32_KERNEL_GS_BASE, 0);
    }
}

/// Current per-CPU address (reads `IA32_GS_BASE`).
///
/// Diagnostic: kernel code paths that genuinely need per-CPU state
/// will eventually go through a `current_cpu()` helper that uses
/// `gs:offset` loads directly; this reader is for tests.
pub fn current_gs_base() -> u64 {
    // SAFETY: reads IA32_GS_BASE — always legal at CPL=0.
    unsafe { msr::rdmsr(IA32_GS_BASE) }
}

/// Reader for `IA32_KERNEL_GS_BASE`. Test/diagnostic only.
pub fn current_kernel_gs_base() -> u64 {
    // SAFETY: reads IA32_KERNEL_GS_BASE — always legal at CPL=0.
    unsafe { msr::rdmsr(IA32_KERNEL_GS_BASE) }
}

/// Update `IA32_KERNEL_GS_BASE` to the value a future user task
/// will see in GS.base on its first iretq. The scheduler calls
/// this as part of spawning a user task (Stage-4+).
///
/// # Safety
/// Only valid from CPL=0 in a non-preemptible section.
pub unsafe fn set_kernel_gs_base(user_gs: u64) {
    // SAFETY: documented MSR write.
    unsafe { msr::wrmsr(IA32_KERNEL_GS_BASE, user_gs); }
}

/// Address of the BSP's PerCpu struct — exposed for tests that
/// want to confirm `GS.base` matches after `init_bsp`.
pub fn bsp_percpu_addr() -> u64 {
    core::ptr::addr_of!(BSP_PERCPU) as u64
}
