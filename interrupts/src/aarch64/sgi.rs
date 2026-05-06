//! aarch64 Software-Generated Interrupts (SGIs).
//!
//! GICv3 reserves INTID 0..15 for software-generated IRQs the
//! kernel uses for inter-processor signalling. The sender writes
//! `ICC_SGI1R_EL1` with the target affinity + INTID; the receiving
//! CPU sees the SGI through its normal IRQ entry, ack'd via
//! `ICC_IAR1_EL1` and EOI'd via `ICC_EOIR1_EL1`.
//!
//! NARF's IPI vector assignments:
//!
//! | INTID | name           | semantics                      |
//! |-------|----------------|--------------------------------|
//! | 0     | RESCHED        | "wake target CPU's scheduler"  |
//! | 1     | TLB_SHOOTDOWN  | "invalidate VA range"          |
//! | 2     | PANIC_HALT     | "halt — printer is using serial"|
//! | 3..15 | reserved       |                                |

use core::sync::atomic::{AtomicU64, Ordering};

use narf_arch::aarch64::sysreg;

/// IPI vector for "yield to scheduler / pick up new work."
pub const SGI_RESCHED: u8 = 0;
/// IPI vector for "invalidate VA range" (TLB shootdown).
pub const SGI_TLB_SHOOTDOWN: u8 = 1;
/// IPI vector for "panic — stop touching the serial port + halt."
pub const SGI_PANIC_HALT: u8 = 2;

/// Per-CPU "scheduler should look for work next time it polls"
/// flag. Set by `default_resched_handler` on SGI_RESCHED receipt;
/// cleared by the scheduler when it next runs.
static NEEDS_RESCHED: [core::sync::atomic::AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { core::sync::atomic::AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

pub fn needs_resched(cpu: u32) -> bool {
    let i = (cpu as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    NEEDS_RESCHED[i].load(Ordering::Acquire)
}

pub fn clear_resched(cpu: u32) {
    let i = (cpu as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    NEEDS_RESCHED[i].store(false, Ordering::Release);
}

/// Default RESCHED handler — flips `NEEDS_RESCHED[current_cpu()]`
/// so the scheduler's next poll knows to look for new work.
fn default_resched_handler() {
    let cpu = narf_lib::percpu::current_cpu();
    NEEDS_RESCHED[cpu].store(true, Ordering::Release);
}

/// Default PANIC_HALT handler — masks IRQs + spins in WFI. Used
/// when one CPU panics and broadcasts to the others before
/// printing the trap frame so the serial port isn't raced.
fn default_panic_halt_handler() -> ! {
    // SAFETY: called from IRQ context on the receiving CPU; we
    // never want to leave halt, so masking IRQs is permanent here.
    unsafe {
        narf_arch::disable_interrupts();
    }
    loop {
        // SAFETY: WFI in EL1 is always defined; with IRQs masked
        // we never wake.
        unsafe {
            core::arch::asm!("wfi", options(nostack, preserves_flags));
        }
    }
}

/// Install the framework-default handlers for RESCHED + PANIC_HALT.
/// Called once at boot on the BSP and once per AP entry. Drivers
/// can override via `set_handler` after this runs.
pub fn install_defaults() {
    set_handler(SGI_RESCHED, default_resched_handler);
    // PANIC_HALT is `fn() -> !` while SgiHandler is `fn()`; the
    // never-returning fn fits with one extra trampoline.
    fn panic_halt_trampoline() {
        default_panic_halt_handler();
    }
    set_handler(SGI_PANIC_HALT, panic_halt_trampoline);
}

/// Convenience: broadcast PANIC_HALT to every other CPU. Called
/// from the panic path before the printer runs.
///
/// # Safety
/// Caller is in panic state — already accepts that we're tearing
/// down. The IPI handler on receiving CPUs masks IRQs + halts.
pub unsafe fn broadcast_panic_halt() {
    // SAFETY: GICv3 sysreg interface up.
    unsafe {
        broadcast_others(SGI_PANIC_HALT);
    }
}

/// Per-(CPU, INTID) receive count. Drivers can sample to confirm
/// IPI delivery.
static RX_COUNT: [[AtomicU64; 16]; narf_lib::percpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 16] }; narf_lib::percpu::MAX_CPUS];

/// Per-INTID SGI handler. The handler runs in IRQ context on the
/// receiving CPU after the trap path has read ICC_IAR1_EL1; it
/// runs *before* the EOI write so handler-side fences land while
/// the IRQ is still active.
pub type SgiHandler = fn();

/// Per-INTID handler table. A `None` slot just bumps the receive
/// counter; a `Some(fn)` runs the handler additionally.
static HANDLERS: [core::sync::atomic::AtomicUsize; 16] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; 16];

/// Install a handler for the given SGI INTID. Replaces any prior
/// handler. `intid` is bounded 0..16.
pub fn set_handler(intid: u8, handler: SgiHandler) {
    let i = (intid as usize).min(15);
    HANDLERS[i].store(handler as usize, Ordering::Release);
}

/// Clear the handler for `intid`. Subsequent SGI deliveries only
/// bump the receive counter.
pub fn clear_handler(intid: u8) {
    let i = (intid as usize).min(15);
    HANDLERS[i].store(0, Ordering::Release);
}

/// Snapshot of an SGI's per-CPU receive count.
pub fn rx_count(cpu: u32, intid: u8) -> u64 {
    let cpu_i = (cpu as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    let intid_i = (intid as usize).min(15);
    RX_COUNT[cpu_i][intid_i].load(Ordering::Relaxed)
}

/// Called by the trap path when an SGI lands. Bumps the per-CPU
/// counter + dispatches to the per-INTID handler when one is
/// installed.
#[inline]
pub fn on_sgi(intid: u8) {
    let cpu = narf_lib::percpu::current_cpu();
    let i = (intid as usize).min(15);
    RX_COUNT[cpu][i].fetch_add(1, Ordering::Relaxed);
    let h = HANDLERS[i].load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: stored as `SgiHandler as usize`; round-trip back
        // to the function pointer is sound when `h != 0`.
        let f: SgiHandler = unsafe { core::mem::transmute(h) };
        f();
    }
}

/// Send an SGI to a single CPU identified by its MPIDR affinity.
///
/// # Safety
/// GICv3 system-register interface must be enabled (it is, post
/// `gic::init_per_cpu`).
pub unsafe fn send_to_cpu_aff(intid: u8, target_aff: u32) {
    let intid = (intid as u64) & 0xF;
    // Decompose target affinity bytes.
    let aff0 = ((target_aff >> 0) & 0xFF) as u64;
    let aff1 = ((target_aff >> 8) & 0xFF) as u64;
    let aff2 = ((target_aff >> 16) & 0xFF) as u64;
    let aff3 = ((target_aff >> 24) & 0xFF) as u64;
    // ICC_SGI1R_EL1: bit pattern per Arm IHI 0069H §11.7.
    //   target list (bits[15:0]) = 1 << aff0
    //   Aff1 (bits[23:16])
    //   INTID (bits[27:24])
    //   Aff2 (bits[39:32])
    //   Aff3 (bits[55:48])
    let val = (1u64 << aff0) | (aff1 << 16) | (intid << 24) | (aff2 << 32) | (aff3 << 48);
    // SAFETY: caller-asserted GICv3 sysreg interface online.
    unsafe {
        sysreg::write_icc_sgi1r_el1(val);
    }
}

/// Broadcast an SGI to all CPUs except the sender.
///
/// # Safety
/// As `send_to_cpu_aff`.
pub unsafe fn broadcast_others(intid: u8) {
    let intid = (intid as u64) & 0xF;
    // IRM (bit 40) = 1 → all-but-self routing; affinity ignored.
    let val = (intid << 24) | (1u64 << 40);
    // SAFETY: see send_to_cpu_aff.
    unsafe {
        sysreg::write_icc_sgi1r_el1(val);
    }
}
