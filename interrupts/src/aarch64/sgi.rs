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
pub const SGI_RESCHED:        u8 = 0;
/// IPI vector for "invalidate VA range" (TLB shootdown).
pub const SGI_TLB_SHOOTDOWN:  u8 = 1;
/// IPI vector for "panic — stop touching the serial port + halt."
pub const SGI_PANIC_HALT:     u8 = 2;

/// Per-(CPU, INTID) receive count. Drivers can sample to confirm
/// IPI delivery.
static RX_COUNT: [[AtomicU64; 16]; narf_lib::percpu::MAX_CPUS] =
    [const { [const { AtomicU64::new(0) }; 16] }; narf_lib::percpu::MAX_CPUS];

/// Snapshot of an SGI's per-CPU receive count.
pub fn rx_count(cpu: u32, intid: u8) -> u64 {
    let cpu_i = (cpu as usize).min(narf_lib::percpu::MAX_CPUS - 1);
    let intid_i = (intid as usize).min(15);
    RX_COUNT[cpu_i][intid_i].load(Ordering::Relaxed)
}

/// Called by the trap path when an SGI lands. Bumps the per-CPU
/// counter for `intid`, then optional handler dispatch (TODO once
/// reschedule + TLB shootdown handlers land).
#[inline]
pub fn on_sgi(intid: u8) {
    let cpu = narf_lib::percpu::current_cpu();
    let i = (intid as usize).min(15);
    RX_COUNT[cpu][i].fetch_add(1, Ordering::Relaxed);
}

/// Send an SGI to a single CPU identified by its MPIDR affinity.
///
/// # Safety
/// GICv3 system-register interface must be enabled (it is, post
/// `gic::init_per_cpu`).
pub unsafe fn send_to_cpu_aff(intid: u8, target_aff: u32) {
    let intid = (intid as u64) & 0xF;
    // Decompose target affinity bytes.
    let aff0 = ((target_aff >> 0)  & 0xFF) as u64;
    let aff1 = ((target_aff >> 8)  & 0xFF) as u64;
    let aff2 = ((target_aff >> 16) & 0xFF) as u64;
    let aff3 = ((target_aff >> 24) & 0xFF) as u64;
    // ICC_SGI1R_EL1: bit pattern per Arm IHI 0069H §11.7.
    //   target list (bits[15:0]) = 1 << aff0
    //   Aff1 (bits[23:16])
    //   INTID (bits[27:24])
    //   Aff2 (bits[39:32])
    //   Aff3 (bits[55:48])
    let val = (1u64 << aff0)
        | (aff1   << 16)
        | (intid  << 24)
        | (aff2   << 32)
        | (aff3   << 48);
    // SAFETY: caller-asserted GICv3 sysreg interface online.
    unsafe { sysreg::write_icc_sgi1r_el1(val); }
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
    unsafe { sysreg::write_icc_sgi1r_el1(val); }
}
