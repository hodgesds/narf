//! Stop every other CPU when one panics — Linux `panic()` →
//! `panic_other_cpus_shutdown()` → `smp_send_stop()`
//! (`arch/x86/kernel/smp.c::native_stop_other_cpus`).
//!
//! A panic used to halt only the panicking CPU. Every other CPU kept running
//! its tasks — including filesystem writeback and NVMe I/O — against kernel
//! state the panic just declared inconsistent. Linux stops them first:
//! `native_stop_other_cpus` sends `REBOOT_VECTOR`, waits up to 1 s, then
//! NMIs the stragglers and waits 10 ms; each target runs
//! `stop_this_cpu()` (IRQs off, `hlt` forever).
//!
//! NARF goes straight to the NMI: it lands on a CPU spinning with IF=0 too,
//! and the handler never returns, so a CPU stopped inside its NMI handler
//! also never takes another NMI or IRQ. Lock-free throughout — the panicking
//! CPU may hold any lock.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::dispatch::IrqStatus;

const MAX: usize = narf_lib::percpu::MAX_CPUS;

/// Set once by the panicking CPU; every NMI after that stops its CPU.
static STOPPING: AtomicBool = AtomicBool::new(false);
/// Logical id of the CPU that panicked (never stopped by its own NMI).
static PANIC_CPU: AtomicU32 = AtomicU32::new(u32::MAX);
/// Bit `n` = CPU `n` has stopped.
static STOPPED: AtomicU64 = AtomicU64::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// How long the panicking CPU waits for the others to acknowledge.
pub const STOP_WAIT_MS: u64 = 1_000;

/// NMI-chain entry: stop this CPU if a panic stop is in progress.
fn stop_nmi(_cookie: u64) -> IrqStatus {
    if !STOPPING.load(Ordering::Acquire) {
        return IrqStatus::None;
    }
    let cpu = narf_lib::percpu::current_cpu();
    if cpu as u32 == PANIC_CPU.load(Ordering::Acquire) {
        return IrqStatus::None;
    }
    if cpu < MAX {
        STOPPED.fetch_or(1u64 << cpu, Ordering::AcqRel);
    }
    // `stop_this_cpu`: interrupts off, halt forever. Still inside the NMI
    // handler, so NMIs stay blocked as well.
    narf_arch::halt_forever();
}

/// Register the NMI handler and the console's panic-stop hook (idempotent).
/// Called from the BSP's LAPIC bring-up.
pub fn install() {
    if INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    let _ = crate::dispatch::add_nmi_handler(stop_nmi, 0);
    narf_console::set_panic_stop_hook(stop_other_cpus);
}

/// Bitmask of the online CPUs other than `me` that have an APIC id.
fn others(me: usize) -> u64 {
    let mut mask = 0u64;
    for cpu in 0..MAX {
        if cpu == me || !narf_lib::smp::is_online(cpu as u32) {
            continue;
        }
        if narf_acpi::apic_id_at(cpu).is_some() {
            mask |= 1u64 << cpu;
        }
    }
    mask
}

/// `smp_send_stop()`: NMI every other online CPU and wait (bounded) for each
/// to report stopped. Returns `(targeted, stopped)` bitmasks. Runs once;
/// a second call (a panic on a CPU that is itself being stopped) returns at
/// once.
pub fn stop_other_cpus() -> (u64, u64) {
    if STOPPING.swap(true, Ordering::AcqRel) {
        return (0, STOPPED.load(Ordering::Acquire));
    }
    let me = narf_lib::percpu::current_cpu();
    PANIC_CPU.store(me as u32, Ordering::Release);
    let targets = others(me);
    for cpu in 0..MAX {
        if targets & (1u64 << cpu) == 0 {
            continue;
        }
        if let Some(apic) = narf_acpi::apic_id_at(cpu) {
            // SAFETY: the LAPIC was initialised at boot (this is installed
            // from its bring-up); an NMI IPI only interrupts the target.
            unsafe { super::apic::send_nmi_ipi(apic) };
        }
    }
    let deadline = narf_time::Deadline::after_ms(STOP_WAIT_MS);
    while STOPPED.load(Ordering::Acquire) & targets != targets && !deadline.expired() {
        core::hint::spin_loop();
    }
    (targets, STOPPED.load(Ordering::Acquire))
}

/// Whether a panic stop has begun (diagnostic).
pub fn stopping() -> bool {
    STOPPING.load(Ordering::Acquire)
}
