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
const APIC_BASE_EN: u64 = 1 << 11;
/// Bit 10: x2APIC enable.
const APIC_BASE_EXTD: u64 = 1 << 10;

const APIC_EOI_MSR: u32 = 0x0000_080B;
const APIC_SIVR_MSR: u32 = 0x0000_080F;
const APIC_LVT_TIMER_MSR: u32 = 0x0000_0832;
const APIC_TIMER_INIT_MSR: u32 = 0x0000_0838;
const APIC_TIMER_DIV_MSR: u32 = 0x0000_083E;
/// LVT Error register (Intel SDM Vol 3 §10.5.1).
const APIC_LVT_ERROR_MSR: u32 = 0x0000_0837;
/// IA32_X2APIC_ESR — Error Status Register. Read after writing
/// 0 to itself per Intel SDM §11.5.3.
const APIC_ESR_MSR: u32 = 0x0000_0828;

/// SIVR bit 8: APIC software enable.
const SIVR_ENABLE: u64 = 1 << 8;

/// LVT Timer mode bits 17:18. `00` = one-shot, `01` = periodic,
/// `10` = TSC-deadline.
const LVT_TIMER_PERIODIC: u64 = 1 << 17;
/// LVT bit 16: masked. Clear to unmask.
const LVT_MASKED: u64 = 1 << 16;

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
/// Set true by `init_bsp` only after the IA32_APIC_BASE.EXTD bit
/// is verified to have stuck. QEMU TCG's qemu64 model advertises
/// x2APIC in CPUID but the EXTD WRMSR is a silent no-op there; we
/// can't trust CPUID alone. Other LAPIC entry points check this
/// flag before doing x2APIC MSR writes that would otherwise #GP.
pub static X2APIC_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub unsafe fn init_bsp() {
    // SAFETY: caller confirmed x2APIC support via CPUID.
    // Two-step enable (some AMD silicon won't accept EN+EXTD in
    // a single WRMSR — needs APIC enabled first, then EXTD).
    let base = unsafe { rdmsr(IA32_APIC_BASE) };
    if base & APIC_BASE_EN == 0 {
        // SAFETY: enabling APIC is always safe at CPL=0.
        unsafe {
            wrmsr(IA32_APIC_BASE, base | APIC_BASE_EN);
        }
    }

    // Mask every IRQ on both 8259 PICs regardless of which APIC
    // mode we end up in — the LAPIC is the interrupt path.
    // SAFETY: I/O-port writes to 0x21 / 0xA1 are standard PIC data.
    unsafe {
        use narf_arch::x86_64::io_port::outb;
        outb(0x21, 0xFF);
        outb(0xA1, 0xFF);
    }

    let after_en = unsafe { rdmsr(IA32_APIC_BASE) };
    // SAFETY: separately set EXTD (x2APIC mode).
    unsafe {
        wrmsr(IA32_APIC_BASE, after_en | APIC_BASE_EXTD);
    }
    // Verify x2APIC actually came up. If not, fall back to xAPIC
    // MMIO mode — sufficient for SMP startup (INIT/SIPI), IPIs
    // (TLB shootdown), and IRQ delivery. Used under QEMU TCG and
    // any host whose firmware refuses the EXTD bit.
    let confirm = unsafe { rdmsr(IA32_APIC_BASE) };
    if confirm & APIC_BASE_EXTD == 0 {
        // SAFETY: LAPIC MMIO is identity-mapped (low 4 GiB).
        unsafe {
            init_lapic_xapic();
        }
        install_apic_diag_handlers();
        return;
    }
    X2APIC_ACTIVE.store(true, core::sync::atomic::Ordering::Release);

    // Spurious-interrupt vector register: enable + vector 0xFF for
    // stray interrupts. Bit 8 = software enable.
    // SAFETY: x2APIC is now live; writes to 0x800+ are valid.
    unsafe {
        wrmsr(
            APIC_SIVR_MSR,
            SIVR_ENABLE | (super::super::VECTOR_SPURIOUS as u64),
        );
        // Mask the timer explicitly until `start_timer` is called.
        wrmsr(APIC_LVT_TIMER_MSR, LVT_MASKED);
        // LVT Error: program vector + unmask. The handler reads
        // ESR for diagnostics. Spec: Intel SDM Vol 3 §10.5.1.
        wrmsr(APIC_LVT_ERROR_MSR, super::super::VECTOR_APIC_ERROR as u64);
    }
    install_apic_diag_handlers();
}

/// xAPIC MMIO initialisation: program SIVR (software-enable +
/// spurious vector), mask LVT_TIMER, and program LVT_ERROR. Used
/// by both init_bsp and init_ap when x2APIC isn't live.
///
/// # Safety
/// - LAPIC MMIO base must be identity-mapped + accessible.
/// - APIC_BASE.EN must already be set.
unsafe fn init_lapic_xapic() {
    let sivr = (XAPIC_MMIO_BASE + 0x0F0) as *mut u32;
    let lvt_timer = (XAPIC_MMIO_BASE + 0x320) as *mut u32;
    let lvt_error = (XAPIC_MMIO_BASE + 0x370) as *mut u32;
    // SAFETY: caller upholds MMIO + EN preconditions.
    unsafe {
        core::ptr::write_volatile(
            sivr,
            (SIVR_ENABLE as u32) | (super::super::VECTOR_SPURIOUS as u32),
        );
        core::ptr::write_volatile(lvt_timer, LVT_MASKED as u32);
        core::ptr::write_volatile(lvt_error, super::super::VECTOR_APIC_ERROR as u32);
    }
}

/// Install the diagnostic handlers for the APIC error +
/// spurious vectors. Both run in IRQ context: ESR is sampled
/// via the documented "write 0, read" sequence (Intel SDM
/// §11.5.3); spurious is just counted via the dispatch
/// fire-count infrastructure (no body needed).
///
/// Idempotent — installs the same handler pointers on every
/// call. AP path doesn't need to install separately because
/// the dispatch table is global, but each AP DOES need its
/// own LVT_ERROR programmed (handled in init_ap).
fn install_apic_diag_handlers() {
    crate::dispatch::install(super::super::VECTOR_APIC_ERROR, apic_error_handler);
    crate::dispatch::install(super::super::VECTOR_SPURIOUS, apic_spurious_handler);
}

fn apic_error_handler() {
    // SDM §11.5.3: ESR latches errors but only updates on a
    // write. Write 0, then read to drain.
    // SAFETY: APIC is live; ESR MSR is well-defined.
    let esr = unsafe {
        wrmsr(APIC_ESR_MSR, 0);
        rdmsr(APIC_ESR_MSR)
    };
    APIC_ERROR_LATCH.fetch_or(esr, core::sync::atomic::Ordering::Relaxed);
    APIC_ERROR_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

fn apic_spurious_handler() {
    APIC_SPURIOUS_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Diagnostic counters — public so tests / debug commands can
/// observe latched APIC errors + spurious-vector deliveries.
pub static APIC_ERROR_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static APIC_ERROR_LATCH: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub static APIC_SPURIOUS_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Start the LAPIC timer in periodic mode firing IRQ `timer_vector`.
///
/// `initial_count` is in LAPIC-timer ticks (post-divide). Exact
/// real-time spacing depends on the bus/core frequency (Stage-3
/// calibration).
///
/// # Safety
/// `init_bsp` must have run; caller still owns IRQ masking.
pub unsafe fn start_timer(timer_vector: u8, initial_count: u32) {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // x2APIC MSR path.
        // SAFETY: APIC is enabled by init_bsp.
        unsafe {
            wrmsr(APIC_TIMER_DIV_MSR, DIV_16);
            wrmsr(
                APIC_LVT_TIMER_MSR,
                LVT_TIMER_PERIODIC | (timer_vector as u64),
            );
            wrmsr(APIC_TIMER_INIT_MSR, initial_count as u64);
        }
        return;
    }
    // xAPIC MMIO path. Phoenix HawkPoint1 / Renoir BIOSes commonly
    // refuse the IA32_APIC_BASE.EXTD bit, so init_bsp falls back to
    // xAPIC mode and X2APIC_ACTIVE stays false. Without this path
    // the LAPIC timer never starts on real silicon — `tt=0` on the
    // status panel and every wheel-based wait wedges (panel paint
    // task, USB supervisor, etc.) because fire_due is never called.
    //
    // xAPIC LAPIC timer registers (Intel SDM Vol 3 §10.5.4 / AMD
    // APM Vol 2 §16.3.6, layout identical):
    //   0x320  LVT_TIMER       (mask bit 16, periodic bit 17, vector low 8)
    //   0x380  TIMER_INIT_CT
    //   0x3E0  TIMER_DIVIDE_CONF
    let lvt_timer = (XAPIC_MMIO_BASE + 0x320) as *mut u32;
    let init_ct = (XAPIC_MMIO_BASE + 0x380) as *mut u32;
    let div_conf = (XAPIC_MMIO_BASE + 0x3E0) as *mut u32;
    // SAFETY: LAPIC MMIO is identity-mapped (low 4 GiB) per init_bsp
    // contract. Writes are aligned 32-bit to architected registers.
    unsafe {
        core::ptr::write_volatile(div_conf, DIV_16 as u32);
        core::ptr::write_volatile(
            lvt_timer,
            (LVT_TIMER_PERIODIC as u32) | (timer_vector as u32),
        );
        core::ptr::write_volatile(init_ct, initial_count);
        // Read back LVT_TIMER and stash the value. If MMIO write
        // didn't stick (cache, mis-mapped, PAT confusion), the
        // readback won't show the periodic bit + vector we wrote.
        // Panel surfaces this so we can tell from outside whether
        // the timer is genuinely armed.
        let readback = core::ptr::read_volatile(lvt_timer as *const u32);
        LVT_TIMER_READBACK.store(readback, core::sync::atomic::Ordering::Release);
    }
}

/// LVT_TIMER value as read back AFTER `start_timer` programmed it.
/// 0 = start_timer never ran (or fix not in binary). Non-zero with
/// the expected `LVT_TIMER_PERIODIC | vector` bits set means the
/// LAPIC MMIO write took effect. Surfaced on the FB status panel
/// to debug `tt=0` on real HW where the x2APIC fallback to xAPIC
/// MMIO might not be reaching the LAPIC.
pub static LVT_TIMER_READBACK: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Stop the LAPIC timer (mask the LVT entry, zero the initial count).
///
/// # Safety
/// `init_bsp` must have run.
pub unsafe fn stop_timer() {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: APIC is enabled.
        unsafe {
            wrmsr(APIC_TIMER_INIT_MSR, 0);
            wrmsr(APIC_LVT_TIMER_MSR, LVT_MASKED);
        }
        return;
    }
    // xAPIC MMIO path — mirror of start_timer's fallback.
    let lvt_timer = (XAPIC_MMIO_BASE + 0x320) as *mut u32;
    let init_ct = (XAPIC_MMIO_BASE + 0x380) as *mut u32;
    // SAFETY: same as start_timer.
    unsafe {
        core::ptr::write_volatile(init_ct, 0);
        core::ptr::write_volatile(lvt_timer, LVT_MASKED as u32);
    }
}

/// Signal end-of-interrupt to the LAPIC.
///
/// # Safety
/// Call exactly once per IRQ dispatch, from inside the handler.
#[inline]
pub unsafe fn eoi() {
    if !X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    // SAFETY: APIC is initialised; EOI write has no side effect beyond
    // unblocking the same-or-lower-priority interrupts.
    unsafe {
        wrmsr(APIC_EOI_MSR, 0);
    }
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
    unsafe {
        wrmsr(0x83F, vector as u64);
    }
}

/// x2APIC ICR MSR (0x830). Writing this sends an IPI; the high 32
/// bits of the value carry the destination APIC ID and the low 32
/// bits carry the IPI fields (vector + delivery mode + level + etc).
const APIC_ICR_MSR: u32 = 0x0000_0830;

/// Write the x2APIC ICR with a fully-formed value. Used by the
/// cross-CPU IPI senders that compose their own ICR fields (delivery
/// shorthand, vector, etc).
///
/// # Safety
/// x2APIC must be enabled on this CPU.
#[inline]
pub unsafe fn wrmsr_icr(icr: u64) {
    // SAFETY: caller upholds the x2APIC precondition.
    unsafe {
        wrmsr(APIC_ICR_MSR, icr);
    }
}

/// Read this CPU's APIC ID via x2APIC MSR 0x802.
///
/// # Safety
/// x2APIC must be enabled.
#[inline]
pub unsafe fn apic_id() -> u32 {
    // SAFETY: MSR 0x802 is x2APIC APIC_ID — read-only.
    unsafe { rdmsr(0x0000_0802) as u32 }
}

/// Default xAPIC MMIO base. Used as the fallback when x2APIC isn't
/// active. APIC_BASE_MSR can carry a different base in theory, but
/// every consumer board we'd run on leaves this default in place.
const XAPIC_MMIO_BASE: u64 = 0xFEE0_0000;

/// Send an INIT IPI (assert) to the target APIC.
///
/// Routes through x2APIC ICR (MSR 0x830) when `X2APIC_ACTIVE`, or
/// through xAPIC MMIO ICR (LAPIC base + 0x300/0x310) otherwise.
/// xAPIC fallback covers QEMU TCG (incomplete x2APIC ICR
/// emulation) and any host whose firmware refuses the EXTD bit.
///
/// # Safety
/// LAPIC must have been initialized by `init_bsp` (whether or not
/// x2APIC actually came up). Caller is responsible for the 10 ms
/// delay PSCI/Intel SDM recommends between INIT and SIPI.
#[inline]
pub unsafe fn send_init_ipi(target_apic_id: u32) {
    // INIT (delivery mode 0b101 = 0x500), level=assert (bit 14),
    // trigger=edge (bit 15 = 0), destination=physical (bit 11 = 0).
    let icr_lo: u32 = 0x0000_4500;
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        let dest = (target_apic_id as u64) << 32;
        // SAFETY: MSR 0x830 is x2APIC ICR.
        unsafe {
            wrmsr(APIC_ICR_MSR, dest | icr_lo as u64);
        }
    } else {
        // xAPIC MMIO fallback. ICR_HI carries the destination
        // APIC ID in bits 24..31; ICR_LO carries the IPI fields.
        // Writing ICR_LO triggers the IPI, so write ICR_HI first.
        let lapic_hi = (XAPIC_MMIO_BASE + 0x310) as *mut u32;
        let lapic_lo = (XAPIC_MMIO_BASE + 0x300) as *mut u32;
        // SAFETY: LAPIC MMIO is identity-mapped (low 4 GiB).
        unsafe {
            core::ptr::write_volatile(lapic_hi, (target_apic_id & 0xFF) << 24);
            core::ptr::write_volatile(lapic_lo, icr_lo);
        }
    }
}

/// Send a STARTUP IPI (SIPI) to the target APIC.
///
/// `vector_page` is the page-aligned physical address of the AP
/// trampoline, divided by 4 KiB (so 0x8000 → 0x08). The AP starts
/// executing at `CS:IP = (vector_page << 8) : 0x0000` in real mode.
///
/// Routes through x2APIC ICR or xAPIC MMIO ICR — see
/// `send_init_ipi` for the rationale.
///
/// # Safety
/// LAPIC must be initialized. Caller must have already issued
/// INIT + waited 10 ms.
#[inline]
pub unsafe fn send_startup_ipi(target_apic_id: u32, vector_page: u8) {
    // SIPI (delivery mode 0b110 = 0x600), level=assert (bit 14)
    // + vector (low 8 bits).
    let icr_lo: u32 = 0x0000_4600 | (vector_page as u32);
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        let dest = (target_apic_id as u64) << 32;
        // SAFETY: MSR 0x830 is x2APIC ICR.
        unsafe {
            wrmsr(APIC_ICR_MSR, dest | icr_lo as u64);
        }
    } else {
        let lapic_hi = (XAPIC_MMIO_BASE + 0x310) as *mut u32;
        let lapic_lo = (XAPIC_MMIO_BASE + 0x300) as *mut u32;
        // SAFETY: LAPIC MMIO is identity-mapped (low 4 GiB).
        unsafe {
            core::ptr::write_volatile(lapic_hi, (target_apic_id & 0xFF) << 24);
            core::ptr::write_volatile(lapic_lo, icr_lo);
        }
    }
}

/// Initialise *this* CPU's LAPIC in x2APIC mode (no PIC-mask, no
/// SIVR — those are BSP-only). Used by AP bring-up after the AP
/// enters Rust.
///
/// # Safety
/// - Must run on the CPU being initialised.
/// - CPUID must confirm x2APIC support (gated by BSP).
/// - Interrupts disabled at call time.
pub unsafe fn init_ap() {
    // SAFETY: APIC base MSR read is unconditional.
    let base = unsafe { rdmsr(IA32_APIC_BASE) };
    if base & APIC_BASE_EN == 0 {
        // SAFETY: enabling APIC is always safe at CPL=0.
        unsafe {
            wrmsr(IA32_APIC_BASE, base | APIC_BASE_EN);
        }
    }
    // If the BSP couldn't get x2APIC up (TCG / firmware-locked),
    // mirror that on the AP — initialise the LAPIC via xAPIC
    // MMIO instead. Cross-CPU IPI senders already route through
    // xAPIC MMIO when X2APIC_ACTIVE is false.
    if !X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: LAPIC MMIO is identity-mapped + APIC_BASE.EN set.
        unsafe {
            init_lapic_xapic();
        }
        return;
    }
    // SAFETY: BSP confirmed x2APIC supports EXTD.
    unsafe {
        let after_en = rdmsr(IA32_APIC_BASE);
        wrmsr(IA32_APIC_BASE, after_en | APIC_BASE_EXTD);
    }
    // Spurious vector + software enable. x2APIC MSRs (0x800+) are
    // only valid once EXTD took.
    // SAFETY: x2APIC is now live on this CPU.
    unsafe {
        wrmsr(
            APIC_SIVR_MSR,
            SIVR_ENABLE | (super::super::VECTOR_SPURIOUS as u64),
        );
        wrmsr(APIC_LVT_TIMER_MSR, LVT_MASKED);
        // LVT Error: per-CPU; APs need this independently of
        // BSP since LVT MSRs are not shared.
        wrmsr(APIC_LVT_ERROR_MSR, super::super::VECTOR_APIC_ERROR as u64);
    }
}

/// Called from the Rust trap handler on the timer IRQ.
#[inline]
pub fn on_timer_tick() {
    TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
    // Drive the deadline wheel off the LAPIC tick unconditionally.
    // The LAPIC timer is the only timer source we KNOW fires
    // reliably across QEMU + every real-silicon platform we care
    // about; HPET-IRQ delivery is unreliable on some AMD chipsets
    // (Phoenix HawkPoint1, certain Renoir SKUs), so making
    // sleep_cycles wakes depend on HPET means real-HW pumps go
    // dormant.
    //
    // Tests that exercise the bare wheel without an HPET arm
    // (e.g. smoke_wheel_refresh_waker_rejects_recycled_handle)
    // must register deadlines large enough that LAPIC drain
    // won't fire them; `__reset_for_test` clears the wheel
    // between operations.
    let now = narf_time::now_cycles();
    let _ = narf_time::timer_wheel::fire_due(now);
}

/// Snapshot of how many timer IRQs have fired since boot.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}
