//! x2APIC initialisation + LAPIC-timer periodic IRQ driver.
//!
//! x2APIC uses MSRs (0x800+) for LAPIC register access, avoiding the
//! MMIO aliasing headache of xAPIC. Modern hardware (and QEMU `-cpu
//! max`) supports it; the xAPIC-MMIO fallback arrives when the kernel
//! targets older parts.
//!
//! MSR map (subset; SDM Vol 3 §10.12):
//!
//! ```text
//! 0x1B    IA32_APIC_BASE          — global APIC enable + x2APIC enable
//! 0x802   APIC_ID                 — read-only identifier
//! 0x80B   APIC_EOI                — write-only end-of-interrupt
//! 0x80F   APIC_SIVR               — spurious-interrupt vector
//! 0x832   LVT_TIMER               — local-vector table, timer entry
//! 0x838   APIC_TIMER_INIT_COUNT   — initial count (write starts timer)
//! 0x839   APIC_TIMER_CUR_COUNT    — current count (read)
//! 0x83E   APIC_TIMER_DIVIDE       — divide configuration
//! ```

use core::sync::atomic::{AtomicU64, Ordering};

use narf_arch::x86_64::msr::{rdmsr, wrmsr};

const IA32_APIC_BASE: u32 = 0x0000_001B;

/// Bit 11: APIC global enable. Set to enable the LAPIC.
const APIC_BASE_EN:   u64 = 1 << 11;
/// Bit 10: x2APIC enable.
const APIC_BASE_EXTD: u64 = 1 << 10;

const APIC_EOI_MSR:        u32 = 0x0000_080B;
const APIC_SIVR_MSR:       u32 = 0x0000_080F;
const APIC_LVT_TIMER_MSR:  u32 = 0x0000_0832;
const APIC_TIMER_INIT_MSR: u32 = 0x0000_0838;
const APIC_TIMER_DIV_MSR:  u32 = 0x0000_083E;

/// SIVR bit 8: APIC software enable.
const SIVR_ENABLE: u64 = 1 << 8;

/// LVT Timer mode bits 17:18. `00` = one-shot, `01` = periodic,
/// `10` = TSC-deadline.
const LVT_TIMER_PERIODIC: u64 = 1 << 17;
/// LVT bit 16: masked. Clear to unmask.
const LVT_MASKED:         u64 = 1 << 16;

/// APIC timer divide values (documented SDM Vol 3 §10.5.4):
///   000 = /2, 001 = /4, 010 = /8, 011 = /16,
///   100 = /32, 101 = /64, 110 = /128, 111 = /1.
const DIV_16: u64 = 0b011;

static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Initialise the BSP's LAPIC in x2APIC mode (no timer yet).
///
/// Also masks both legacy 8259 PICs so their IRQs can't land on our
/// IDT vectors. The default BIOS-programmed PIC vectors on x86 PCs
/// typically *overlap* the LAPIC-timer vector we chose (32 = PIC
/// master IRQ 0 after the BIOS's standard remap), so leaving the PIC
/// unmasked plus enabling IRQs = spurious deliveries racing ours.
///
/// # Safety
/// - Must run on the BSP, exactly once.
/// - CPUID must confirm x2APIC; caller gates on `Features::probe`.
/// - Interrupts are assumed disabled at the call site.
pub unsafe fn init_bsp() {
    // SAFETY: caller confirmed x2APIC support via CPUID.
    let base = unsafe { rdmsr(IA32_APIC_BASE) };
    unsafe { wrmsr(IA32_APIC_BASE, base | APIC_BASE_EN | APIC_BASE_EXTD); }

    // Mask every IRQ on both 8259 PICs. This is the legacy-PIC
    // compatible way of saying "I don't want any interrupts from
    // you" — writes 0xFF to the master data port (0x21) and the
    // slave data port (0xA1). Stage-3 can revisit if we need PIC
    // support for some legacy device.
    // SAFETY: I/O-port writes to 0x21 / 0xA1 are standard PIC data.
    unsafe {
        use narf_arch::x86_64::io_port::outb;
        outb(0x21, 0xFF);
        outb(0xA1, 0xFF);
    }

    // Spurious-interrupt vector register: enable + vector 0xFF for
    // stray interrupts. Bit 8 = software enable.
    // SAFETY: x2APIC is now live; writes to 0x800+ are valid.
    unsafe {
        wrmsr(APIC_SIVR_MSR, SIVR_ENABLE | (super::super::VECTOR_SPURIOUS as u64));
        // Mask the timer explicitly until `start_timer` is called.
        wrmsr(APIC_LVT_TIMER_MSR, LVT_MASKED);
    }
}

/// Start the LAPIC timer in periodic mode firing IRQ `timer_vector`.
///
/// `initial_count` is in LAPIC-timer ticks (post-divide). Exact
/// real-time spacing depends on the bus/core frequency (Stage-3
/// calibration).
///
/// # Safety
/// `init_bsp` must have run; caller still owns IRQ masking.
pub unsafe fn start_timer(timer_vector: u8, initial_count: u32) {
    // SAFETY: APIC is enabled by init_bsp.
    unsafe {
        wrmsr(APIC_TIMER_DIV_MSR, DIV_16);
        wrmsr(APIC_LVT_TIMER_MSR,
              LVT_TIMER_PERIODIC
              | (timer_vector as u64));
        wrmsr(APIC_TIMER_INIT_MSR, initial_count as u64);
    }
}

/// Stop the LAPIC timer (mask the LVT entry, zero the initial count).
///
/// # Safety
/// `init_bsp` must have run.
pub unsafe fn stop_timer() {
    // SAFETY: APIC is enabled.
    unsafe {
        wrmsr(APIC_TIMER_INIT_MSR, 0);
        wrmsr(APIC_LVT_TIMER_MSR, LVT_MASKED);
    }
}

/// Signal end-of-interrupt to the LAPIC.
///
/// # Safety
/// Call exactly once per IRQ dispatch, from inside the handler.
#[inline]
pub unsafe fn eoi() {
    // SAFETY: APIC is initialised; EOI write has no side effect beyond
    // unblocking the same-or-lower-priority interrupts.
    unsafe { wrmsr(APIC_EOI_MSR, 0); }
}

/// Self-IPI: send an interrupt to this CPU's own LAPIC at the given
/// vector. Uses the x2APIC Self-IPI MSR (0x83F) which takes just the
/// vector in the low 8 bits.
///
/// # Safety
/// APIC must be in x2APIC mode.
#[inline]
pub unsafe fn self_ipi(vector: u8) {
    // SAFETY: MSR 0x83F is the x2APIC Self-IPI register.
    unsafe { wrmsr(0x83F, vector as u64); }
}

/// Called from the Rust trap handler on the timer IRQ.
#[inline]
pub fn on_timer_tick() {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot of how many timer IRQs have fired since boot.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}
