//! x2APIC initialisation + the per-CPU LAPIC-timer clockevent.
//!
//! Every CPU's LAPIC timer is its own one-shot clockevent (Linux
//! `lapic_events`, `setup_APIC_timer`): TSC-deadline where the CPU has it
//! (`lapic_next_deadline`), otherwise the LVT one-shot mode counting `TMICT`
//! down (`lapic_next_event`) at a rate calibrated once against the TSC
//! (`calibrate_APIC_clock`). Both carry the CPU's periodic tick, its
//! scheduler deadline and its own next hrtimer event. The hardware periodic
//! InitialCount mode remains only for a LAPIC timer that failed calibration.
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
//!
//! xAPIC MMIO has the same registers at `(msr - 0x800) * 16` (LVT timer
//! 0x320, initial count 0x380, current count 0x390, divide 0x3E0).

use core::sync::atomic::{compiler_fence, AtomicU64, AtomicU8, Ordering};

use narf_arch::x86_64::msr::{rdmsr, wrmsr};
use narf_lib::clockevent_scale::ClockEventScale;

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
const LVT_TIMER_ONESHOT: u64 = 0;
const LVT_TIMER_PERIODIC: u64 = 1 << 17;
const LVT_TIMER_TSC_DEADLINE: u64 = 2 << 17;
/// LVT bit 16: masked. Clear to unmask.
const LVT_MASKED: u64 = 1 << 16;

/// IA32_TSC_DEADLINE MSR (SDM Vol 3 §10.5.4.1). When LVT_TIMER's
/// mode bits select TSC-deadline, writing a TSC value here arms
/// the timer to fire when RDTSC reaches that value. Writing 0
/// disarms. Re-arming is done from the ISR — no periodic mode in
/// hardware, just keep writing the next deadline.
const IA32_TSC_DEADLINE: u32 = 0x0000_06E0;

/// APIC timer divide values (documented SDM Vol 3 §10.5.4):
///   000 = /2, 001 = /4, 010 = /8, 011 = /16,
///   100 = /32, 101 = /64, 110 = /128, 111 = /1.
const DIV_16: u64 = 0b011;

/// xAPIC MMIO offsets of the timer registers (Intel SDM Vol 3 §10.5.4, AMD
/// APM Vol 2 §16.4.1, identical layout). The x2APIC MSR is `0x800 + off/16`.
const LAPIC_LVTT: u64 = 0x320;
const LAPIC_TMICT: u64 = 0x380;
const LAPIC_TMCCT: u64 = 0x390;
const LAPIC_TDCR: u64 = 0x3E0;

/// Programmable one-shot range in divide-by-16 ticks: Linux
/// `lapic_init_clockevent` (`min_delta_ticks = 0xF`,
/// `max_delta_ticks = 0x7FFFFFFF`).
const LAPIC_MIN_DELTA_TICKS: u64 = 0xF;
const LAPIC_MAX_DELTA_TICKS: u64 = 0x7FFF_FFFF;

static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

/// Write LAPIC timer register `offset` through whichever interface is live
/// (x2APIC MSR or xAPIC MMIO), fenced against compiler reordering on both
/// sides (AGENTS.md invariant #4; `wrmsr` carries its own fence pair).
///
/// # Safety
/// This CPU's LAPIC is enabled; in xAPIC mode its registers are reachable
/// through [`lapic_reg`].
#[inline]
unsafe fn timer_write(offset: u64, value: u32) {
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        // SAFETY: x2APIC is live, so the timer MSR `0x800 + offset/16` exists.
        unsafe { wrmsr(0x800 + (offset >> 4) as u32, u64::from(value)) };
    } else {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: caller guarantees the mapped register page; aligned 32-bit.
        unsafe { core::ptr::write_volatile(lapic_reg(offset), value) };
        compiler_fence(Ordering::SeqCst);
    }
}

/// Read LAPIC timer register `offset`; see [`timer_write`].
///
/// # Safety
/// As for [`timer_write`].
#[inline]
unsafe fn timer_read(offset: u64) -> u32 {
    if X2APIC_ACTIVE.load(Ordering::Acquire) {
        // SAFETY: x2APIC is live, so the timer MSR `0x800 + offset/16` exists.
        unsafe { rdmsr(0x800 + (offset >> 4) as u32) as u32 }
    } else {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: caller guarantees the mapped register page; aligned 32-bit.
        let v = unsafe { core::ptr::read_volatile(lapic_reg(offset)) };
        compiler_fence(Ordering::SeqCst);
        v
    }
}

/// The LAPIC timer's count rate against the TSC (Linux `lapic_timer_period`
/// and the `lapic_clockevent` mult/min/max it configures). Measured once, on
/// the boot CPU, and shared by every CPU: `setup_APIC_timer` copies the boot
/// CPU's calibrated device the same way. `None` means the timer did not count
/// during calibration; CPUs then keep the hardware periodic mode.
static LAPIC_SCALE: narf_lib::sync::OnceLock<Option<ClockEventScale>> =
    narf_lib::sync::OnceLock::new();

/// Calibration window: at least this many divide-by-16 ticks AND TSC cycles,
/// so the one-tick count quantisation and the TMCCT read brackets stay near
/// 1e-4 of the window. About 10 ms on Zen (100 MHz APIC clock), 7 ms under
/// KVM (1 GHz emulated bus), 55 ms for a 19.2 MHz crystal.
const CAL_MIN_TICKS: u64 = 1 << 16;
const CAL_MIN_CYCLES: u64 = 1 << 25;
/// Abandon a calibration that has not completed after this many TSC cycles:
/// the timer does not count, or counts implausibly slowly.
const CAL_MAX_CYCLES: u64 = 1 << 31;

/// One calibration sample: `count` (TMCCT) read between two ordered TSC
/// reads, stamped at their midpoint. `half_bracket` bounds the stamp error.
#[derive(Copy, Clone, Debug)]
struct CalSample {
    tsc: u64,
    count: u32,
    half_bracket: u64,
}

/// The narrowest of four bracketed `(TSC, TMCCT)` reads. Under a hypervisor
/// a TMCCT read is a VM exit (~1-2 µs); the bracket records that cost as
/// measurement uncertainty instead of letting it bias the ratio.
///
/// # Safety
/// As for [`timer_read`].
unsafe fn cal_sample() -> CalSample {
    let mut best = CalSample {
        tsc: 0,
        count: 0,
        half_bracket: u64::MAX,
    };
    for _ in 0..4 {
        let t0 = narf_time::raw_cycles();
        // SAFETY: forwarded caller contract.
        let count = unsafe { timer_read(LAPIC_TMCCT) };
        let t1 = narf_time::raw_cycles();
        let width = t1.saturating_sub(t0);
        let half = width.div_ceil(2);
        if half < best.half_bracket {
            best = CalSample {
                tsc: t0 + width / 2,
                count,
                half_bracket: half,
            };
        }
    }
    best
}

/// Linux `calibrate_APIC_clock`: run this CPU's LAPIC timer masked at divide
/// 16 from `0xFFFF_FFFF` and count it against the invariant TSC. The ratio
/// does not depend on the TSC frequency calibration, so it is valid before
/// `narf_time` has calibrated (the boot CPU measures it in [`init_bsp`]).
/// Leaves the timer masked and stopped.
fn calibrate_lapic_timer() -> Option<ClockEventScale> {
    narf_lib::sync::without_interrupts(|| {
        // SAFETY: the LAPIC is enabled on this CPU (its init ran); the timer
        // stays masked for the whole measurement, so no interrupt is raised.
        unsafe {
            timer_write(LAPIC_LVTT, (LVT_MASKED | LVT_TIMER_ONESHOT) as u32);
            timer_write(LAPIC_TDCR, DIV_16 as u32);
            timer_write(LAPIC_TMICT, u32::MAX);
            let start = cal_sample();
            let scale = loop {
                let now = cal_sample();
                let cycles = now.tsc.saturating_sub(start.tsc);
                // The current count runs down; one that went up is not a
                // timer this can calibrate.
                let Some(ticks) = start.count.checked_sub(now.count).map(u64::from) else {
                    break None;
                };
                if ticks >= CAL_MIN_TICKS && cycles >= CAL_MIN_CYCLES {
                    break ClockEventScale::from_measurement(
                        cycles,
                        ticks,
                        start.half_bracket + now.half_bracket,
                        LAPIC_MIN_DELTA_TICKS,
                        LAPIC_MAX_DELTA_TICKS,
                    );
                }
                if cycles >= CAL_MAX_CYCLES || (ticks == 0 && cycles >= CAL_MIN_CYCLES) {
                    break None;
                }
                core::hint::spin_loop();
            };
            timer_write(LAPIC_TMICT, 0);
            timer_write(LAPIC_LVTT, LVT_MASKED as u32);
            scale
        }
    })
}

/// The calibrated LAPIC one-shot conversion (TSC cycles to divide-by-16
/// ticks), measuring it on first use. A first-use measurement reprograms the
/// calling CPU's LAPIC timer (masked), so it must come from a CPU that is
/// about to start its timer or is not using it.
pub fn lapic_timer_scale() -> Option<&'static ClockEventScale> {
    LAPIC_SCALE.get_or_init(calibrate_lapic_timer).as_ref()
}

/// The calibration if it has already been measured (never measures).
#[inline]
fn lapic_timer_scale_ready() -> Option<&'static ClockEventScale> {
    LAPIC_SCALE.get().and_then(Option::as_ref)
}

/// Boot-log the calibrated one-shot device once the TSC frequency is known
/// (Linux prints `lapic_timer_period` from `calibrate_APIC_clock`).
fn log_oneshot_calibration(scale: &ClockEventScale) {
    use core::fmt::Write as _;
    let ns_per_mtick = narf_time::cycles_to_ns(scale.ticks_to_units(1_000_000)).max(1);
    let _ = writeln!(
        narf_console::Writer,
        "  apic: LAPIC one-shot timer {} kHz (divide 16), delta {} ns..{} s",
        1_000_000_000_000u64 / ns_per_mtick,
        narf_time::cycles_to_ns(scale.min_delta()),
        narf_time::cycles_to_ns(scale.max_delta()) / 1_000_000_000,
    );
}

/// How a CPU's LAPIC timer is running.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LocalTimerMode {
    /// Masked; never started, or stopped.
    Stopped = 0,
    /// Hardware periodic InitialCount mode: ticks at a fixed rate and cannot
    /// be programmed per event (Linux's low-resolution periodic tick). Only
    /// for a LAPIC timer that failed calibration.
    Periodic = 1,
    /// `IA32_TSC_DEADLINE` one-shot (Linux `lapic-deadline`).
    TscDeadline = 2,
    /// LVT one-shot counting `TMICT` down (Linux `lapic` in oneshot state,
    /// `lapic_next_event`).
    Oneshot = 3,
}

impl LocalTimerMode {
    const fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Periodic,
            2 => Self::TscDeadline,
            3 => Self::Oneshot,
            _ => Self::Stopped,
        }
    }

    /// Whether the mode programs individual events (tickless idle, precise
    /// hrtimers): Linux `CLOCK_EVT_FEAT_ONESHOT`.
    pub const fn is_oneshot(self) -> bool {
        matches!(self, Self::TscDeadline | Self::Oneshot)
    }

    /// Short name for boot logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Periodic => "periodic",
            Self::TscDeadline => "tsc-deadline",
            Self::Oneshot => "one-shot",
        }
    }
}

/// Set true by `init_bsp` only after the IA32_APIC_BASE.EXTD bit
/// is verified to have stuck. QEMU TCG's qemu64 model advertises
/// x2APIC in CPUID but the EXTD WRMSR is a silent no-op there; we
/// can't trust CPUID alone. Other LAPIC entry points check this
/// flag before doing x2APIC MSR writes that would otherwise #GP.
pub static X2APIC_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// True once the BSP confirmed x2APIC came up (see [`X2APIC_ACTIVE`]).
/// The IPI shootdown path (`ipi::shoot_va` / `shoot_range`) writes the
/// x2APIC ICR MSR and has no xAPIC fallback, so callers that need
/// shootdown delivery — and the smokes that assert it — gate on this.
/// Real targets always bring up x2APIC; it returns `false` only on
/// CPUs/emulators that fall back to xAPIC (e.g. QEMU's qemu64 model,
/// which is what GitHub Actions' TCG runner exposes).
#[inline]
pub fn x2apic_active() -> bool {
    X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire)
}

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
    // SAFETY: CPL=0; rdmsr/wrmsr against IA32_APIC_BASE are
    // unconditional on long-mode x86_64. The EXTD write below is
    // CPUID-gated because CPUs without x2APIC support raise #GP
    // on that bit.
    // SAFETY: Valid memory or trusted environment
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

    // x2APIC enable — gated on CPUID.x2APIC support. Writing the
    // EXTD bit on a CPU that doesn't advertise x2APIC raises #GP
    // (observed on QEMU TCG with the default `-cpu` model). The
    // two-step (EN first, then EXTD) sequence is needed because
    // some AMD silicon refuses EN+EXTD in a single WRMSR.
    // SAFETY: CPUID is unconditional at CPL=0.
    let feats = unsafe { narf_arch::x86_64::Features::probe() };
    if feats.x2apic {
        // SAFETY: CPL=0; reading IA32_APIC_BASE is unconditional on
        // long mode. We re-read here to OR the EXTD bit onto the
        // current value rather than clobbering the APIC base address.
        // SAFETY: Valid memory or trusted environment
        let after_en = unsafe { rdmsr(IA32_APIC_BASE) };
        // SAFETY: CPUID-gated above; CPU supports the EXTD bit.
        unsafe {
            wrmsr(IA32_APIC_BASE, after_en | APIC_BASE_EXTD);
        }
    }
    // Verify x2APIC actually came up. If CPUID didn't advertise
    // it OR firmware refused the EXTD bit (BIOS lock), fall back
    // to xAPIC MMIO mode — sufficient for SMP startup (INIT/SIPI),
    // IPIs (TLB shootdown), and IRQ delivery. Used under QEMU TCG
    // without `+x2apic` and any host whose firmware refuses the
    // EXTD bit.
    // SAFETY: CPL=0; reading IA32_APIC_BASE is unconditional on long
    // mode. Reading back the just-written value tells us whether the
    // EXTD bit actually stuck (it silently drops on QEMU TCG / locked
    // firmware).
    // SAFETY: Valid memory or trusted environment
    let confirm = unsafe { rdmsr(IA32_APIC_BASE) };
    if confirm & APIC_BASE_EXTD == 0 {
        // Record the firmware-provided LAPIC base rather than assuming the
        // architectural default: IA32_APIC_BASE[35:12] is where Linux's
        // `apic.c` reads it from, and firmware is free to relocate it.
        // `remap_mmio` ioremaps whatever we latch here.
        LAPIC_PHYS.store(
            confirm & 0x0000_000F_FFFF_F000,
            core::sync::atomic::Ordering::Release,
        );
        // SAFETY: pre-`init_mmu`, so boot.S's low identity window still
        // covers the LAPIC page and `lapic_reg` resolves to a physical
        // address that is mapped. `remap_mmio` takes over after the CR3
        // handoff.
        unsafe {
            init_lapic_xapic();
        }
        install_apic_diag_handlers();
        calibrate_boot_lapic_timer(&feats);
        return;
    }
    X2APIC_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
    // Wire the clockevent broadcast IPI sender so a `Shared`
    // primary (e.g. HPET) can deliver ticks to CPUs registered
    // in BROADCAST_MASK.
    narf_time::clockevent::set_broadcast_sender(x2apic_broadcast);

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
    calibrate_boot_lapic_timer(&feats);
}

/// Boot CPU: measure the LAPIC timer rate before any AP starts, so every CPU
/// without TSC-deadline starts its timer directly in one-shot mode (Linux
/// `setup_boot_APIC_clock` → `calibrate_APIC_clock` runs before SMP boot,
/// and `setup_secondary_APIC_clock` reuses the result). A TSC-deadline CPU
/// never uses the count rate and skips the ~10 ms measurement.
fn calibrate_boot_lapic_timer(feats: &narf_arch::x86_64::Features) {
    if feats.tsc_deadline || lapic_timer_scale().is_some() {
        return;
    }
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  apic: LAPIC timer did not count during calibration; periodic InitialCount tick"
    );
}

/// xAPIC MMIO initialisation: program SIVR (software-enable +
/// spurious vector), mask every LVT entry the LAPIC ships with,
/// then program LVT_ERROR. Used by both init_bsp and init_ap when
/// x2APIC isn't live.
///
/// Masking every LVT is critical: BIOS firmware commonly leaves
/// LVT_LINT0 / LVT_LINT1 / LVT_THERMAL / LVT_PMC programmed with
/// stale vectors pointing at IDT entries the kernel hasn't
/// installed handlers for. The first `sti` after this routine
/// would then deliver those stale-vector IRQs and trigger a
/// cascading #DF when the trap path tries to dispatch them. The
/// x2APIC path doesn't trip because QEMU's x2APIC emulation
/// implicitly zeroes the LVTs on x2APIC-enable; xAPIC + TCG does
/// not, so the masks have to be programmed explicitly.
///
/// LVT register offsets (Intel SDM Vol 3 §10.5.1, AMD APM Vol 2
/// §16.4.6 — layout identical):
///   0x320  LVT Timer
///   0x330  LVT Thermal Monitor
///   0x340  LVT Performance Counter
///   0x350  LVT LINT0
///   0x360  LVT LINT1
///   0x370  LVT Error
///
/// # Safety
/// - LAPIC MMIO must be reachable through `lapic_reg` (boot identity
///   window before `init_mmu`, the `remap_mmio` window after).
/// - APIC_BASE.EN must already be set.
unsafe fn init_lapic_xapic() {
    let sivr = lapic_reg(0x0F0);
    let lvt_timer = lapic_reg(0x320);
    let lvt_thermal = lapic_reg(0x330);
    let lvt_perf = lapic_reg(0x340);
    let lvt_lint0 = lapic_reg(0x350);
    let lvt_lint1 = lapic_reg(0x360);
    let lvt_error = lapic_reg(0x370);
    // SAFETY: caller upholds MMIO + EN preconditions. Each write
    // is an aligned 32-bit write to an architected LVT register.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_volatile(
            sivr,
            (SIVR_ENABLE as u32) | (super::super::VECTOR_SPURIOUS as u32),
        );
        // Mask every LVT entry that could deliver a stale-vector
        // IRQ on the first `sti`. LVT_TIMER stays masked until
        // `start_timer` arms it; the others stay masked for the
        // lifetime of the boot (NARF doesn't route LINT / PMC /
        // thermal yet).
        core::ptr::write_volatile(lvt_timer, LVT_MASKED as u32);
        core::ptr::write_volatile(lvt_thermal, LVT_MASKED as u32);
        core::ptr::write_volatile(lvt_perf, LVT_MASKED as u32);
        core::ptr::write_volatile(lvt_lint0, LVT_MASKED as u32);
        core::ptr::write_volatile(lvt_lint1, LVT_MASKED as u32);
        // LVT_ERROR: program vector + leave unmasked. The handler
        // reads ESR for diagnostics.
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
    // A panic NMIs every other CPU to a halt before printing (see
    // `panic_stop`); its NMI handler and the console hook go in with the
    // BSP's LAPIC, which is what sends those NMIs.
    super::panic_stop::install();
    crate::dispatch::install(super::super::VECTOR_APIC_ERROR, apic_error_handler);
    crate::dispatch::install(super::super::VECTOR_SPURIOUS, apic_spurious_handler);
}

fn apic_error_handler() {
    // SDM §11.5.3: ESR latches errors but only updates on a
    // write. Write 0, then read to drain.
    let esr = if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: this handler only runs in x2APIC mode here, so the
        // APIC_ESR MSR is accessible at CPL=0; the write-then-read
        // drain sequence is the architected way to sample ESR.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            wrmsr(APIC_ESR_MSR, 0);
            rdmsr(APIC_ESR_MSR)
        }
    } else {
        // xAPIC ESR at MMIO offset 0x280.
        let esr_reg = lapic_reg(0x280);
        // SAFETY: in xAPIC mode the LAPIC MMIO window is reachable via `lapic_reg`
        // (low 4 GiB) and EN is set, so this 32-bit aligned write/read
        // to the architected ESR register at base+0x280 is valid.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::ptr::write_volatile(esr_reg, 0);
            core::ptr::read_volatile(esr_reg) as u64
        }
    };
    APIC_ERROR_LATCH.fetch_or(esr, core::sync::atomic::Ordering::Relaxed);
    APIC_ERROR_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

fn apic_spurious_handler() {
    APIC_SPURIOUS_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Diagnostic counters — public so tests / debug commands can
/// observe latched APIC errors + spurious-vector deliveries.
pub static APIC_ERROR_COUNT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static APIC_ERROR_LATCH: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
pub static APIC_SPURIOUS_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Start this CPU's LAPIC timer as its clockevent, firing IRQ
/// `timer_vector`, with a periodic tick every `initial_count` divide-by-16
/// LAPIC ticks.
///
/// With a calibrated LAPIC timer ([`lapic_timer_scale`]) the timer runs in
/// LVT one-shot mode and the tick is emulated in software at the same rate,
/// exactly as the TSC-deadline mode does: each interrupt re-arms `TMICT` for
/// the earliest of the next tick, the scheduler deadline and this CPU's next
/// hrtimer event, and an idle CPU can stop the tick (Linux
/// `lapic_timer_set_oneshot` + `tick_setup_periodic` in oneshot mode). Only
/// a timer that failed calibration falls back to the hardware periodic
/// InitialCount mode.
///
/// # Safety
/// `init_bsp` (or `init_ap`) must have run on this CPU; caller still owns
/// IRQ masking.
pub unsafe fn start_timer(timer_vector: u8, initial_count: u32) {
    if let Some(scale) = lapic_timer_scale() {
        let period_cycles = scale.ticks_to_units(u64::from(initial_count)).max(1);
        // SAFETY: forwarded caller contract.
        unsafe { start_timer_oneshot(timer_vector, period_cycles) };
        return;
    }
    // SAFETY: forwarded caller contract.
    unsafe { start_timer_periodic(timer_vector, initial_count) };
}

/// Start the LAPIC timer in hardware periodic mode firing IRQ
/// `timer_vector` every `initial_count` divide-by-16 ticks. For a LAPIC
/// timer that could not be calibrated (`start_timer` prefers one-shot).
///
/// # Safety
/// `init_bsp` must have run; caller still owns IRQ masking.
unsafe fn start_timer_periodic(timer_vector: u8, initial_count: u32) {
    // Periodic mode expires this CPU's hrtimers from its own tick
    // (`on_timer_tick` → `hrtimer_run_queues`, Linux's low-resolution
    // mode), so timers need no per-event programming here; publish that a
    // clockevent backs them, as the one-shot paths do, so a sleeper does not
    // self-wake and poll. `arm_hrtimer_event` is a no-op on a periodic CPU;
    // the HPET pump, when it comes up, installs the programmer that also
    // arms the precise broadcast.
    let cpu = tsc_cpu();
    TICK_PERIOD_CYCLES[cpu].store(0, Ordering::Relaxed);
    LOCAL_MODE[cpu].store(LocalTimerMode::Periodic as u8, Ordering::Relaxed);
    narf_time::hrtimer::hrtimers_prepare_cpu(cpu);
    if !narf_time::hrtimer::arm_callback_installed() {
        narf_time::hrtimer::set_arm_callback(arm_hrtimer_event);
    }
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
    let lvt_timer = lapic_reg(0x320);
    let init_ct = lapic_reg(0x380);
    let div_conf = lapic_reg(0x3E0);
    // SAFETY: LAPIC MMIO is reachable via `lapic_reg` per init_bsp
    // contract. Writes are aligned 32-bit to architected registers.
    // SAFETY: Valid memory or trusted environment
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

/// `ClockEvent` adapter wrapping the LAPIC-timer primitives above: one
/// per-CPU one-shot device (Linux `lapic_clockevent` copied per CPU by
/// `setup_APIC_timer`).
///
/// The timer runs in TSC-deadline mode where the CPU has it, otherwise in
/// LVT one-shot mode at the divide-by-16 rate calibrated against the TSC at
/// boot ([`lapic_timer_scale`]). Either way each CPU programs its own next
/// event; nothing about one CPU's timers involves another CPU's interrupt.
///
/// On CPUs without ARAT (CPUID 0x06 EAX[2], or implied by the vendor as in
/// Linux `init_amd`) the LAPIC timer stops in C3 and deeper C-states (Linux
/// `CLOCK_EVT_FEAT_C3STOP`); `timer_pump` then keeps the HPET broadcast
/// armed for every CPU's events. With ARAT no broadcast is needed.
#[derive(Debug)]
pub struct LapicClockEvent;

impl narf_time::clockevent::ClockEvent for LapicClockEvent {
    fn can_stop_idle_tick(&self) -> bool {
        local_oneshot_active()
    }

    fn set_idle_tick(&self, stop_tick: bool, budget_deadline: Option<u64>) -> bool {
        // Both one-shot modes are programmed in raw counter time (the
        // TSC-deadline MSR compares against it; the TMICT mode converts a
        // raw-counter delta); scheduler and hrtimer deadlines are monotonic
        // counter time (which excludes time spent suspended). Convert at this
        // boundary.
        let budget_deadline = budget_deadline.map(narf_time::mono_to_raw_cycles);
        let enabled = narf_arch::interrupts_enabled();
        // SAFETY: serialize the local deadline registers with the timer ISR.
        unsafe { narf_arch::disable_interrupts() };
        let cpu = tsc_cpu();
        let period = TICK_PERIOD_CYCLES[cpu].load(Ordering::Relaxed);
        if period != 0 {
            let now = narf_time::raw_cycles();
            let was_stopped = !narf_time::periodic_tick_wanted(cpu);
            narf_time::set_periodic_tick_wanted(cpu, !stop_tick);
            if !stop_tick && was_stopped {
                TICK_NEXT[cpu].store(now.saturating_add(period), Ordering::Relaxed);
            }
            TSC_SCHED_DEADLINE[cpu].store(budget_deadline.unwrap_or(u64::MAX), Ordering::Relaxed);
            let periodic = if stop_tick {
                u64::MAX
            } else {
                TICK_NEXT[cpu].load(Ordering::Relaxed)
            };
            // This CPU's own next hrtimer event (`tick_nohz_stop_tick` →
            // `hrtimer_get_next_event`); every CPU carries its own.
            let wheel =
                narf_time::hrtimer::next_event_cycles_local().map(narf_time::mono_to_raw_cycles);
            let target = next_arm_target(
                now,
                periodic.min(budget_deadline.unwrap_or(u64::MAX)),
                wheel,
                MIN_DELTA_CYCLES,
            );
            program_next_event(cpu, target);
        }
        if enabled {
            // SAFETY: restore the caller's IRQ state.
            unsafe { narf_arch::enable_interrupts() };
        }
        period != 0
    }
    fn name(&self) -> &'static str {
        "lapic"
    }

    fn supported(&self) -> bool {
        // LAPIC is present on every x86_64 CPU. Either x2APIC or
        // xAPIC paths apply; both can drive the timer.
        true
    }

    unsafe fn arm_periodic(
        &self,
        hz: u32,
        vector: u8,
    ) -> Result<(), narf_time::clockevent::ClockEventError> {
        if hz == 0 || hz > 100_000 {
            return Err(narf_time::clockevent::ClockEventError::InvalidFrequency);
        }
        // Linux `setup_APIC_timer`: TSC-deadline (CPUID 01H ECX[24]) when the
        // CPU has it — each IRQ re-arms by writing the next TSC value, no
        // LAPIC calibration needed. Otherwise the LVT one-shot mode at the
        // rate `calibrate_APIC_clock` measured (AMD Zen 2/3/4 have no
        // TSC-deadline). Only a timer that failed calibration falls back to
        // the hardware periodic InitialCount mode.
        // SAFETY: CPUID is always legal at CPL=0.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        // Period in TSC cycles for the requested IRQ rate.
        //
        // `ns_to_cycles`, NOT `* cycles_per_ns()`. The latter was a
        // TRUNCATED integer GHz clamped to 1..=6, so a 3.293 GHz TSC
        // read back as 3 and the period came out ~9.8% long — every
        // CPU ticking at ~1097 Hz against the 1000 Hz this asks for.
        let period_ns = 1_000_000_000u64 / hz as u64;
        let period_cycles = narf_time::wall::ns_to_cycles(period_ns).max(1);
        if feats.tsc_deadline {
            // SAFETY: caller upholds exclusive LAPIC access; we
            // gated on CPUID for TSC-deadline support.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                start_timer_tsc_deadline(vector, period_cycles);
            }
            // Self-rearming one-shot: each IRQ writes the next deadline, so
            // the tick is dependable and a halted CPU may trust it to wake.
            narf_time::set_tick_reliable(true);
        } else if let Some(scale) = lapic_timer_scale() {
            // SAFETY: caller upholds exclusive LAPIC access; the timer is
            // calibrated, so one-shot TMICT programming is defined.
            unsafe {
                start_timer_oneshot(vector, period_cycles);
            }
            log_oneshot_calibration(scale);
            // Self-rearming one-shot, as the TSC-deadline mode above.
            narf_time::set_tick_reliable(true);
        } else {
            // Periodic-InitialCount fallback. See start_timer
            // commentary; 10_000 is safely fast on any plausible
            // post-divide bus speed.
            let initial_count = 10_000u32;
            // SAFETY: same.
            unsafe {
                start_timer_periodic(vector, initial_count);
            }
            // Periodic LAPIC tick on every CPU (each AP arms its own in
            // `smp.rs`): it keeps firing through `hlt` (C1), so a halted CPU
            // is always woken within one period — Linux's periodic-tick idle
            // (`default_idle` → `sti; hlt`, woken by the tick, a device IRQ
            // or a reschedule IPI). The tick cannot be stopped or programmed
            // per event (`can_stop_idle_tick` is false), so there is no
            // NOHZ idle here; precise deadlines go through the HPET
            // broadcast (`timer_pump`), and between those a timer fires at
            // the next tick at the latest, as in Linux's low-resolution
            // mode. This used to publish "unreliable", which made every
            // idle CPU busy-poll in 1 ms slices at 100% CPU instead of
            // halting.
            narf_time::set_tick_reliable(true);
        }
        Ok(())
    }

    unsafe fn disarm(&self) {
        // SAFETY: caller upholds CPL=0 + exclusive backend access.
        unsafe {
            stop_timer();
        }
    }

    fn tick_count(&self) -> u64 {
        TIMER_TICKS.load(Ordering::Relaxed)
    }

    fn resolution_ns(&self) -> u64 {
        // Under TSC-deadline mode the resolution IS the TSC tick
        // (sub-nanosecond on modern Intel/AMD); resolution_ns has
        // u64 ns granularity, so report 1 ns — Linux's
        // lapic_clockevent_rating uses the same effective floor.
        // The TMICT one-shot resolves one divide-by-16 tick (160 ns at
        // a 100 MHz APIC clock). The uncalibrated periodic fallback
        // assumes that typical clock. ARAT doesn't change resolution,
        // only the C3 behaviour.
        //
        // SAFETY: CPUID is always legal at CPL=0.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        if feats.tsc_deadline {
            1
        } else if let Some(scale) = lapic_timer_scale_ready() {
            narf_time::cycles_to_ns(scale.ticks_to_units(1)).max(1)
        } else {
            160
        }
    }

    fn kind(&self) -> narf_time::clockevent::ClockEventKind {
        // LAPIC timer fires PER CPU — each core has its own.
        narf_time::clockevent::ClockEventKind::PerCpu
    }
}

/// Broadcast IPI sender for x2APIC. Installed once at boot via
/// `clockevent::set_broadcast_sender`. Iterates set bits in
/// `cpu_mask`, composes an ICR for each, and delivers a fixed-vector
/// IPI at `vector` — via APIC_ICR_MSR under x2APIC, or the xAPIC
/// ICR_HI/ICR_LO MMIO pair when it is not active.
///
/// ICR field layout (Intel SDM Vol 3 §10.12.10):
///   [7:0]    Vector
///   [10:8]   Delivery Mode (000 = Fixed)
///   [11]     Destination Mode (0 = Physical)
///   [14]     Level (1 = assert; 0 for INIT-deassert only)
///   [15]     Trigger Mode (0 = edge)
///   [19:18]  Dest Shorthand (00 = no shorthand, use [63:32])
///   [63:32]  Destination APIC ID (x2APIC: full 32-bit)
fn x2apic_broadcast(cpu_mask: u64, vector: u8) {
    // KVM PV_SEND_IPI: the whole target set in ONE hypercall instead of a
    // vmexit-per-target ICR loop (either mode below). Falls through to the
    // architectural paths off-KVM, if a target's APIC ID is outside the
    // hypercall's 64-bit window, or if the host rejects the call.
    if let Some(apic_mask) = apic_mask_of(cpu_mask) {
        if narf_memory::kvm_pv::pv_send_ipi(apic_mask, vector) {
            return;
        }
    }
    if !X2APIC_ACTIVE.load(Ordering::Acquire) {
        // xAPIC MMIO fallback. Same ICR fields as below, but split
        // across two 32-bit registers: ICR_HI carries the destination
        // in bits [31:24] (xAPIC IDs are 8-bit), ICR_LO the vector and
        // delivery fields. ICR_LO is written LAST because that write is
        // what actually sends.
        //
        // This used to `return` unsent. That is not a degraded tick —
        // `send_fixed_ipi` is also how `ipi::shoot_range` delivers TLB
        // shootdowns, and its ACK wait is documented as "must not time
        // out and return" because the caller may reuse a frame whose
        // stale translation is still cached on a peer. Dropping the IPI
        // therefore either wedges the sender forever (what the
        // `interrupts/ipi` smokes hit under `-x2apic`) or, if a peer
        // happens to drain the bit by polling, lets execution continue
        // with a stale TLB entry live on another core.
        let mut m = cpu_mask;
        while m != 0 {
            let apic = dest_apic_of_cpu(m.trailing_zeros());
            m &= m - 1;
            // SAFETY: LAPIC MMIO reached via `lapic_reg`; ICR writes are
            // architectural. `xapic_icr_send` serialises on Delivery
            // Status, which keeps a second target's ICR_LO from overwriting
            // an IPI still in flight (SDM Vol 3 §10.6.1), and masks
            // interrupts across the register pair.
            unsafe { xapic_icr_send((apic & 0xFF) << 24, u32::from(vector) | (1 << 14)) };
        }
        return;
    }
    let mut m = cpu_mask;
    while m != 0 {
        let apic = dest_apic_of_cpu(m.trailing_zeros());
        m &= m - 1;
        // Fixed delivery, edge-triggered, level-assert,
        // physical destination, no shorthand. Dest in high
        // 32 bits (x2APIC full APIC ID).
        let icr: u64 = (vector as u64)
            | (1u64 << 14)             // level = assert
            | ((apic as u64) << 32); // destination APIC id
                                     // SAFETY: x2APIC confirmed active above.
        unsafe {
            wrmsr_icr(icr);
        }
    }
}

/// The APIC ID to put in an ICR to reach logical CPU `cpu` (Linux
/// `per_cpu(x86_cpu_to_apicid, cpu)`): the MADT-derived map, or `cpu`
/// itself before the MADT is parsed — the only CPU then is the boot CPU,
/// and on a gap-free topology the two agree anyway.
#[inline]
fn dest_apic_of_cpu(cpu: u32) -> u32 {
    narf_acpi::apic_id_of_cpu(cpu as usize).unwrap_or(cpu)
}

/// `cpu_mask` (bit = logical CPU) as a bitmap of destination APIC IDs, the
/// form `KVM_HC_SEND_IPI` takes. `None` when an APIC ID is >= 64 and does
/// not fit the single-window call.
fn apic_mask_of(cpu_mask: u64) -> Option<u64> {
    let mut out = 0u64;
    let mut m = cpu_mask;
    while m != 0 {
        let apic = dest_apic_of_cpu(m.trailing_zeros());
        m &= m - 1;
        if apic >= 64 {
            return None;
        }
        out |= 1u64 << apic;
    }
    Some(out)
}

/// Send a fixed-vector IPI to every CPU in `cpu_mask`. Thin public
/// wrapper over the x2APIC ICR write — used by the scheduler's
/// reschedule IPI to kick an idle remote CPU off its HLT so a
/// cross-core wake takes effect immediately instead of at that CPU's
/// next timer tick. Fire-and-forget (no ack), edge-triggered fixed
/// delivery. Routes through the xAPIC ICR when x2APIC is not active.
#[inline]
pub fn send_fixed_ipi(cpu_mask: u64, vector: u8) {
    x2apic_broadcast(cpu_mask, vector);
}

/// Global singleton for registration with the clockevent registry.
pub static LAPIC_CLOCKEVENT: LapicClockEvent = LapicClockEvent;

/// Stop this CPU's LAPIC timer (Linux `lapic_timer_shutdown`): mask the LVT
/// entry, then zero the counter of the active mode — the initial count, or
/// `IA32_TSC_DEADLINE` in TSC-deadline mode ("belt and suspenders" for AMD
/// erratum 411, which can fire a masked timer).
///
/// # Safety
/// `init_bsp` must have run.
pub unsafe fn stop_timer() {
    narf_lib::sync::without_interrupts(|| {
        let cpu = tsc_cpu();
        let was = LocalTimerMode::from_raw(
            LOCAL_MODE[cpu].swap(LocalTimerMode::Stopped as u8, Ordering::Relaxed),
        );
        TICK_PERIOD_CYCLES[cpu].store(0, Ordering::Relaxed);
        TSC_ARMED[cpu].store(u64::MAX, Ordering::Relaxed);
        // SAFETY: the LAPIC is enabled (caller contract); masking the LVT
        // keeps its mode bits, so the matching counter is cleared below.
        unsafe {
            let lvt = timer_read(LAPIC_LVTT) | LVT_MASKED as u32;
            timer_write(LAPIC_LVTT, lvt);
            if was == LocalTimerMode::TscDeadline {
                wrmsr(IA32_TSC_DEADLINE, 0);
            } else {
                timer_write(LAPIC_TMICT, 0);
            }
        }
    });
}

/// Signal end-of-interrupt to the LAPIC.
///
/// # Safety
/// Call exactly once per IRQ dispatch, from inside the handler.
#[inline]
pub unsafe fn eoi() {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: x2APIC live; EOI MSR write clears the highest in-
        // service register bit, unblocking same/lower-priority IRQs.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            wrmsr(APIC_EOI_MSR, 0);
        }
    } else {
        // xAPIC EOI: write zero to LAPIC MMIO offset 0xB0. Without
        // this the in-service register stays set after the first
        // IRQ of a given priority, blocking all further deliveries
        // — the symptom is "first tick fires then nothing". This
        // is the canonical mainframe Linux pattern (`native_apic_mem_eoi`).
        let eoi_reg = lapic_reg(0x0B0);
        // SAFETY: in xAPIC mode the LAPIC MMIO window is reachable via `lapic_reg`
        // (low 4 GiB) with EN set, so this 32-bit aligned write to the
        // architected EOI register at base+0xB0 is valid and has no
        // side effect beyond acknowledging the in-service IRQ.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::ptr::write_volatile(eoi_reg, 0);
        }
    }
}

/// Self-IPI: send an interrupt to this CPU's own LAPIC at the
/// given vector. Routes through the x2APIC Self-IPI MSR (0x83F)
/// when x2APIC is live; otherwise uses ICR self-shorthand
/// (delivery shorthand 01 in bits[19:18]).
///
/// # Safety
/// `init_bsp` must have run.
#[inline]
pub unsafe fn self_ipi(vector: u8) {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: MSR 0x83F is the x2APIC Self-IPI register.
        unsafe {
            wrmsr(0x83F, vector as u64);
        }
    } else {
        // xAPIC self-IPI via ICR with shorthand `self`. Bits:
        //   [19:18] = 01 (self), [14] = 1 (level assert),
        //   [7:0]   = vector
        let icr_low: u32 = (vector as u32) | (1 << 14) | (1 << 18);
        // SAFETY: LAPIC MMIO reached via `lapic_reg`; high half irrelevant
        // for self-shorthand but Intel mandates writing it first.
        unsafe { xapic_icr_send(0, icr_low) };
    }
}

/// x2APIC ICR MSR (0x830). Writing this sends an IPI; the high 32
/// bits of the value carry the destination APIC ID and the low 32
/// bits carry the IPI fields (vector + delivery mode + level + etc).
const APIC_ICR_MSR: u32 = 0x0000_0830;

/// Write the ICR with a fully-formed value. Routes through x2APIC
/// MSR 0x830 (single 64-bit write) when x2APIC is active, or
/// through xAPIC MMIO (write high half at offset 0x310, then low
/// half at 0x300 to trigger send) otherwise.
///
/// xAPIC ICR layout differs from x2APIC: dest is in high half
/// bits[31:24] (8-bit APIC ID), with the low half carrying the
/// IPI fields. Linux's `default_send_IPI_dest_field` does the
/// equivalent translation.
///
/// # Safety
/// `init_bsp` must have run. LAPIC MMIO reached via `lapic_reg`.
#[inline]
pub unsafe fn wrmsr_icr(icr: u64) {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: x2APIC live; single 64-bit MSR write atomically
        // composes the ICR + sends.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            wrmsr(APIC_ICR_MSR, icr);
        }
    } else {
        // xAPIC: destination is in bits[31:24] of high half (the
        // top byte takes the 8-bit APIC ID). Convert the x2APIC
        // format (full 32-bit dest in bits[63:32]) to xAPIC by
        // shifting left another 24 bits.
        let dest_apic_id = (icr >> 32) & 0xFF;
        let icr_high = (dest_apic_id << 24) as u32;
        let icr_low = (icr & 0xFFFF_FFFF) as u32;
        // SAFETY: LAPIC MMIO reached via `lapic_reg`; spec mandates writing
        // ICR_HIGH before ICR_LOW (LOW write triggers send).
        unsafe { xapic_icr_send(icr_high, icr_low) };
    }
}

/// One step of an xAPIC ICR send, in the order the steps must happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IcrStep {
    /// Wait for the previous IPI to leave the ICR (Delivery Status clear).
    WaitIdle,
    /// Write ICR_HI: the destination.
    WriteHigh(u32),
    /// Write ICR_LO: the command. This is the write that sends.
    WriteLow(u32),
}

/// Perform the three steps of an xAPIC ICR send with interrupts masked from
/// before the first to after the last, restoring the caller's interrupt state.
///
/// In xAPIC mode the ICR is two memory-mapped registers and the send is not
/// atomic: the destination is latched by the ICR_HI write and the IPI goes out
/// on the ICR_LO write. A sender interrupted between the two by a handler that
/// sends an IPI of its own comes back to an ICR_HI holding the handler's
/// destination, and its ICR_LO write then delivers its vector there. Handlers
/// do send: the scheduler's tick sends reschedule and idle-balance kicks, the
/// stall watchdog sends an NMI probe from the tick, and a wake from any interrupt
/// can kick an idle CPU. A reschedule or TLB-shootdown IPI landing on the wrong
/// CPU is a lost wakeup or an unacknowledged shootdown.
///
/// Linux masks interrupts across the same pair (`default_send_IPI_single` and
/// the mask variants call `__default_send_IPI_dest_field` under
/// `local_irq_save`) and waits for Delivery Status first.
///
/// An NMI is not masked by this. Code that can run in NMI context must not
/// send through the xAPIC ICR.
#[inline]
pub(crate) fn icr_send_masked(icr_hi: u32, icr_lo: u32, mut step: impl FnMut(IcrStep)) {
    narf_lib::sync::without_interrupts(|| {
        step(IcrStep::WaitIdle);
        step(IcrStep::WriteHigh(icr_hi));
        step(IcrStep::WriteLow(icr_lo));
    });
}

/// Send one IPI through the memory-mapped xAPIC ICR. Every xAPIC sender in
/// this file goes through here; see [`icr_send_masked`] for why.
///
/// # Safety
/// The LAPIC must be initialised and reachable through [`lapic_reg`], and
/// x2APIC must not be the active mode.
#[inline]
unsafe fn xapic_icr_send(icr_hi: u32, icr_lo: u32) {
    let hi_reg = lapic_reg(0x310);
    let lo_reg = lapic_reg(0x300);
    icr_send_masked(icr_hi, icr_lo, |step| {
        // SAFETY: the caller guarantees both registers are mapped LAPIC MMIO;
        // the writes are the architectural ICR programming sequence.
        unsafe {
            match step {
                IcrStep::WaitIdle => wait_icr_idle(lo_reg),
                IcrStep::WriteHigh(value) => core::ptr::write_volatile(hi_reg, value),
                IcrStep::WriteLow(value) => core::ptr::write_volatile(lo_reg, value),
            }
        }
    });
}

/// Read this CPU's APIC ID via x2APIC MSR 0x802.
///
/// Read the current CPU's APIC ID. Routes through the x2APIC
/// APIC_ID MSR (0x802) when x2APIC is active, or the xAPIC MMIO
/// register (offset 0x20, upper 8 bits) when it isn't.
///
/// Reading MSR 0x802 with x2APIC disabled produces a #GP — a
/// large class of Renoir / Phoenix BIOSes refuse the
/// IA32_APIC_BASE.EXTD bit so we end up in xAPIC mode, and the
/// silent #GP from a bare rdmsr was masking the real LAPIC
/// failure mode for a long time. Match Linux's read_apic_id
/// which dispatches on the same flag.
///
/// # Safety
/// `init_bsp` must have run. LAPIC MMIO is reached via `lapic_reg`.
#[inline]
pub unsafe fn apic_id() -> u32 {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: MSR 0x802 is x2APIC APIC_ID — read-only.
        unsafe { rdmsr(0x0000_0802) as u32 }
    } else {
        let id_reg = lapic_reg(0x20);
        // SAFETY: caller guarantees init_bsp ran, so `lapic_reg` resolves
        // to a mapped window; this 32-bit aligned read of the
        // architected APIC_ID register at base+0x20 has no side effects.
        // SAFETY: Valid memory or trusted environment
        let raw = unsafe { core::ptr::read_volatile(id_reg) };
        // xAPIC APIC_ID occupies bits[31:24].
        raw >> 24
    }
}

/// Architectural default xAPIC MMIO base, used until `init_bsp` reads the
/// real one out of IA32_APIC_BASE. This is a PHYSICAL address; never
/// dereference it directly — go through [`lapic_reg`].
const XAPIC_MMIO_BASE: u64 = 0xFEE0_0000;

/// Physical base of the LAPIC register page, from IA32_APIC_BASE[35:12].
/// Linux (`arch/x86/kernel/apic/apic.c`) honours the MSR rather than
/// assuming the default, because firmware may relocate the window.
static LAPIC_PHYS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(XAPIC_MMIO_BASE);

/// Virtual address of the ioremap'd LAPIC page, or 0 before
/// [`remap_mmio`] has run.
///
/// The LAPIC is brought up in `init_bsp`, which runs BEFORE `init_mmu`
/// installs the final page tables, so the earliest accesses necessarily go
/// through boot.S's low identity window at the physical address. That
/// window does not exist in the kernel's own tables: `init_mmu` maps RAM
/// through a direct map at a RANDOMIZED base and nothing maps the low
/// 4 GiB, so every xAPIC access after the CR3 handoff faults on a raw
/// physical pointer. `remap_mmio` closes that gap.
static LAPIC_VA: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Pointer to LAPIC register `offset`.
///
/// Returns the ioremap'd virtual address once [`remap_mmio`] has run, and
/// the physical address before that — which is only dereferenceable while
/// boot.S's identity window is still live, i.e. exactly the early-boot
/// window in which it is the only option.
#[inline]
fn lapic_reg(offset: u64) -> *mut u32 {
    let va = LAPIC_VA.load(core::sync::atomic::Ordering::Acquire);
    let base = if va != 0 {
        va as u64
    } else {
        LAPIC_PHYS.load(core::sync::atomic::Ordering::Acquire)
    };
    (base + offset) as *mut u32
}

/// Spin until the xAPIC ICR reports the previous IPI delivered
/// (ICR_LO bit 12, Delivery Status, reads 0), bounded so a wedged LAPIC
/// degrades to a dropped IPI instead of hanging the sender forever.
///
/// # Safety
/// `icr_lo` must be a mapped LAPIC ICR_LO pointer from [`lapic_reg`].
#[inline]
unsafe fn wait_icr_idle(icr_lo: *mut u32) {
    const DELIVERY_STATUS: u32 = 1 << 12;
    for _ in 0..100_000 {
        // SAFETY: caller guarantees `icr_lo` is the mapped ICR_LO register;
        // reading it is side-effect free.
        if unsafe { core::ptr::read_volatile(icr_lo) } & DELIVERY_STATUS == 0 {
            return;
        }
        core::hint::spin_loop();
    }
}

/// Move LAPIC register access off the boot identity window and onto an
/// `ioremap` mapping. Called by the frame right after `init_mmu` installs
/// the final page tables, mirroring `gic::remap_mmio` on aarch64.
///
/// Idempotent, and a no-op when x2APIC is active (that path uses MSRs and
/// never touches MMIO). The mapping must be `Device`, not a direct-map
/// pointer: LAPIC registers are MMIO and must not be cached.
pub fn remap_mmio() {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        return;
    }
    if LAPIC_VA.load(core::sync::atomic::Ordering::Acquire) != 0 {
        return;
    }
    let phys = LAPIC_PHYS.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: the architectural LAPIC register page, owned by this CPU
    // package and mapped uncached.
    if let Ok(m) = unsafe {
        narf_memory::ioremap::ioremap(phys, 0x1000, narf_memory::ioremap::MmioAttrs::Device)
    } {
        LAPIC_VA.store(m.va() as usize, core::sync::atomic::Ordering::Release);
    }
}

/// True once the LAPIC MMIO window has been remapped (diagnostics/tests).
pub fn mmio_remapped() -> bool {
    LAPIC_VA.load(core::sync::atomic::Ordering::Acquire) != 0
}

/// Program this CPU's fixed-delivery performance-counter interrupt.
/// Returns false if xAPIC has no permanent device mapping yet. In particular,
/// never dereference IA32_APIC_BASE's physical address from a process CR3.
///
/// # Safety
/// CPL=0, APIC bring-up is complete, and the caller owns this CPU's LVT-PC.
pub unsafe fn program_current_lvt_pc(vector: u8, masked: bool) -> bool {
    if x2apic_active() {
        const APIC_LVT_PC_MSR: u32 = 0x834;
        let value = u64::from(vector) | if masked { LVT_MASKED } else { 0 };
        // SAFETY: bring-up confirmed x2APIC, so this CPU has the LVT-PC MSR.
        unsafe { wrmsr(APIC_LVT_PC_MSR, value) };
        true
    } else {
        let mapped_base = LAPIC_VA.load(Ordering::Acquire);
        // SAFETY: remap_mmio publishes a permanent, device-typed mapping;
        // zero is rejected before dereferencing any register.
        unsafe { program_xapic_lvt_pc(mapped_base, vector, masked) }
    }
}

unsafe fn program_xapic_lvt_pc(mapped_base: usize, vector: u8, masked: bool) -> bool {
    if mapped_base == 0 {
        return false;
    }
    // SAFETY: the caller supplies the mapped register page, not its physical
    // address. The architecture helper performs an aligned volatile write.
    unsafe { narf_arch::x86_64::pmi::program_lvt_pc(mapped_base, vector, false, masked) };
    true
}

fn smoke_pmi_mapped_register_access() -> narf_kernel_test::TestResult {
    let mut registers = [0xa5a5_a5a5u32; 256];
    let base = registers.as_mut_ptr() as usize;
    // SAFETY: zero is explicitly rejected; the array emulates a writable
    // register page and covers the aligned LVT-PC register at offset 0x340.
    unsafe {
        if program_xapic_lvt_pc(0, 0xee, false)
            || !program_xapic_lvt_pc(base, 0xee, true)
            || registers[0x340 / 4] != (0xee | LVT_MASKED as u32)
            || !program_xapic_lvt_pc(base, 0xef, false)
            || registers[0x340 / 4] != 0xef
        {
            return narf_kernel_test::TestResult::Fail("PMI did not use its supplied mapping");
        }
    }
    if registers
        .iter()
        .enumerate()
        .any(|(i, &v)| i != 0x340 / 4 && v != 0xa5a5_a5a5)
    {
        return narf_kernel_test::TestResult::Fail("PMI changed a different APIC register");
    }
    narf_kernel_test::TestResult::Pass
}
narf_kernel_test::kernel_test_in!("interrupts/pmi", smoke_pmi_mapped_register_access);

fn smoke_pmi_current_lvt_route() -> narf_kernel_test::TestResult {
    narf_lib::sync::without_interrupts(|| {
        let x2 = x2apic_active();
        if !x2 && !mmio_remapped() {
            return narf_kernel_test::TestResult::Fail("xAPIC has no permanent mapping");
        }
        // SAFETY: boot initialized this CPU's APIC. Keep IRQs masked and save
        // and restore the exact prior LVT value; the test route stays masked.
        let (ok, observed) = unsafe {
            let old = if x2 {
                rdmsr(0x834) as u32
            } else {
                core::ptr::read_volatile(lapic_reg(0x340))
            };
            let ok = program_current_lvt_pc(0xee, true);
            let value = if x2 {
                rdmsr(0x834) as u32
            } else {
                core::ptr::read_volatile(lapic_reg(0x340))
            };
            if x2 {
                wrmsr(0x834, u64::from(old));
            } else {
                core::ptr::write_volatile(lapic_reg(0x340), old);
            }
            (ok, value)
        };
        if !ok || observed & (LVT_MASKED as u32 | 0x7ff) != LVT_MASKED as u32 | 0xee {
            return narf_kernel_test::TestResult::Fail("PMI current-CPU route did not round-trip");
        }
        narf_kernel_test::TestResult::Pass
    })
}
narf_kernel_test::kernel_test_in!("interrupts/pmi", smoke_pmi_current_lvt_route);

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
        // SAFETY: LAPIC MMIO is reached via `lapic_reg`.
        unsafe { xapic_icr_send((target_apic_id & 0xFF) << 24, icr_lo) };
    }
}

/// Send an NMI IPI to the target APIC. Delivery mode 0b100 (NMI) is
/// non-maskable, so it lands even on a CPU spinning with IF=0 — the only way
/// to sample the RIP of a CPU wedged in an interrupts-disabled loop (the
/// stall-watchdog's stuck-CPU probe). Same ICR routing as [`send_init_ipi`].
///
/// # Safety
/// LAPIC must have been initialized by `init_bsp`.
#[inline]
pub unsafe fn send_nmi_ipi(target_apic_id: u32) {
    // NMI (delivery mode 0b100 = 0x400), level=assert (bit 14), edge,
    // destination=physical.
    let icr_lo: u32 = 0x0000_4400;
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        let dest = (target_apic_id as u64) << 32;
        // SAFETY: MSR 0x830 is x2APIC ICR.
        unsafe {
            wrmsr(APIC_ICR_MSR, dest | icr_lo as u64);
        }
    } else {
        // SAFETY: LAPIC MMIO is reached via `lapic_reg`. HI (dest) is
        // written before LO (triggers the IPI), with interrupts masked: this
        // one is sent from the timer tick, on top of whatever the tick
        // interrupted.
        unsafe { xapic_icr_send((target_apic_id & 0xFF) << 24, icr_lo) };
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
        // SAFETY: LAPIC MMIO is reached via `lapic_reg`.
        unsafe { xapic_icr_send((target_apic_id & 0xFF) << 24, icr_lo) };
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
        // SAFETY: LAPIC MMIO is reached via `lapic_reg`; APIC_BASE.EN set.
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
///
/// Both one-shot modes (TSC-deadline and TMICT) fire once per programming;
/// periodicity is a software construct. This ISR multiplexes the periodic
/// tick with the timer-wheel's earliest (possibly sub-tick) deadline so a
/// wheel sleep fires precisely instead of rounding up to the next periodic
/// tick (mirrors a Linux hrtimer one-shot tracking `min(tick, earliest
/// hrtimer)`, `tick_sched_timer` in oneshot mode).
///
/// Only a genuine periodic expiry (`now >= periodic_next`) bumps
/// TIMER_TICKS + advances the periodic accounting; an early wheel-deadline
/// fire must NOT advance the periodic deadline. We then re-arm the one-shot
/// to the sooner of the (possibly unchanged) periodic deadline and the
/// wheel's earliest, floored to `now + MIN_DELTA_CYCLES`. The TMICT
/// conversion never fires early ([`ClockEventScale::program`]), so each
/// tick interrupt is a genuine expiry rather than a premature one that
/// would need a second, minimum-delta interrupt.
#[inline]
pub fn on_timer_tick() {
    let cpu = tsc_cpu();
    let period = TICK_PERIOD_CYCLES[cpu].load(Ordering::Relaxed);
    if period == 0 {
        // InitialCount periodic mode: hardware auto-reloads; count, and run
        // the low-resolution hrtimer expiry (`hrtimer_run_queues`).
        TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
        narf_time::hrtimer::hrtimer_run_queues();
        return;
    }
    // SAFETY: _rdtsc compiles to RDTSC, unconditionally legal at CPL=0.
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let mut periodic_next = TICK_NEXT[cpu].load(Ordering::Relaxed);
    if now >= periodic_next {
        // Genuine periodic expiry (not an early wheel-deadline fire).
        TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
        // If we've fallen behind (e.g. long handler), snap forward to
        // now + period rather than slipping forever.
        periodic_next = if periodic_next.wrapping_add(period) > now {
            periodic_next.wrapping_add(period)
        } else {
            now.wrapping_add(period)
        };
        TICK_NEXT[cpu].store(periodic_next, Ordering::Relaxed);
    }
    // NO_HZ_IDLE: while this CPU is idle the scheduler clears
    // PERIODIC_TICK_WANTED, so we DON'T anchor the next deadline to the periodic
    // tick — we arm only for the next wheel deadline (or, with none, `u64::MAX`
    // → the floor, effectively "sleep until a device IRQ / reschedule IPI").
    let periodic_anchor = if narf_time::periodic_tick_wanted(cpu) {
        periodic_next
    } else {
        u64::MAX
    };
    // `hrtimer_interrupt`: expire THIS CPU's due hrtimers (each CPU's LAPIC
    // carries only its own base, so a stuck CPU delays only its own timers)
    // and learn its next event. Expiry retires the due timers here, so the
    // re-arm below never lands on an already-past event (no re-fire storm).
    // Monotonic → raw counter time, which both one-shot modes program in.
    let next_hrtimer = narf_time::mono_to_raw_cycles(narf_time::hrtimer::hrtimer_interrupt());
    let wheel_earliest = (next_hrtimer != u64::MAX).then_some(next_hrtimer);
    let scheduler =
        pending_scheduler_deadline(now, TSC_SCHED_DEADLINE[cpu].load(Ordering::Relaxed));
    TSC_SCHED_DEADLINE[cpu].store(scheduler, Ordering::Relaxed);
    let target = next_arm_target(
        now,
        periodic_anchor.min(scheduler),
        wheel_earliest,
        MIN_DELTA_CYCLES,
    );
    program_next_event(cpu, target);
}

pub(crate) const fn pending_scheduler_deadline(now: u64, deadline: u64) -> u64 {
    if deadline <= now {
        u64::MAX
    } else {
        deadline
    }
}

/// Program this CPU's one-shot to fire at raw-counter `target` (`u64::MAX`
/// disarms) and record in `TSC_ARMED` when it will have fired (Linux
/// `clockevents_program_event` → `set_next_event`). Callers hold IRQs
/// masked. No-op unless this CPU runs a one-shot mode.
fn program_next_event(cpu: usize, target: u64) {
    match LocalTimerMode::from_raw(LOCAL_MODE[cpu].load(Ordering::Relaxed)) {
        LocalTimerMode::TscDeadline => {
            TSC_ARMED[cpu].store(target, Ordering::Relaxed);
            // SAFETY: TSC-deadline MSR is unconditionally writable when the
            // LVT_TIMER is configured for deadline mode, which is what the
            // TscDeadline mode records.
            //
            // MFENCE before the WRMSR mirrors Linux's `weak_wrmsr_fence()`
            // (an alt-patched MFENCE enabled specifically on
            // TSC-deadline-capable CPUs). Intel erratum: certain Skylake-era
            // chips reorder memory ops around the IA32_TSC_DEADLINE WRMSR; AMD
            // APM is silent, but the fence is cheap and Linux applies it
            // unconditionally on TSC-deadline chips.
            unsafe {
                core::arch::asm!("mfence", options(nostack, preserves_flags));
                wrmsr(
                    IA32_TSC_DEADLINE,
                    if target == u64::MAX { 0 } else { target },
                );
            }
        }
        LocalTimerMode::Oneshot => {
            let Some(scale) = lapic_timer_scale_ready() else {
                return;
            };
            if target == u64::MAX {
                TSC_ARMED[cpu].store(u64::MAX, Ordering::Relaxed);
                // SAFETY: the LVT is in one-shot mode on this CPU; a zero
                // initial count stops the countdown without an interrupt.
                unsafe { timer_write(LAPIC_TMICT, 0) };
                return;
            }
            // Linux `lapic_next_event`: TMICT is relative, so convert the
            // remaining delta. The countdown starts at the write; `TSC_ARMED`
            // is stamped after it with the latest the timer can fire, so a
            // re-arm never mistakes a still-counting timer for an expired one
            // and cancels the interrupt it was about to raise.
            let now = narf_time::raw_cycles();
            let p = scale.program(target.saturating_sub(now));
            // SAFETY: the LVT is in one-shot mode on this CPU; `p.ticks` is
            // within the programmable range (<= 0x7FFF_FFFF).
            unsafe { timer_write(LAPIC_TMICT, p.ticks as u32) };
            TSC_ARMED[cpu].store(
                narf_time::raw_cycles().saturating_add(p.latest),
                Ordering::Relaxed,
            );
        }
        LocalTimerMode::Stopped | LocalTimerMode::Periodic => {}
    }
    // Hrtimer expiry in `on_timer_tick` wakes by reference only: the sleeper
    // keeps its Waker, so no Arc is released (freed) in this IRQ context.
}

/// Per-CPU one-shot timer state. The LAPIC timer registers (LVT_TIMER,
/// TMICT, IA32_TSC_DEADLINE) are inherently per-CPU, so the *software*
/// state that mirrors them — the mode, the period, the next periodic
/// deadline, and the currently-armed value — MUST be per-CPU too. Indexed
/// by `narf_lib::percpu::current_cpu()` (via `tsc_cpu()`).
///
/// ── BUG FIX (intermittent permanent SMP wedge) ──
/// These were single globals (the original code only ran the TSC-deadline
/// tick on the BSP). Under user-task SMP every AP also runs its own
/// TSC-deadline tick (`start_timer_tsc_deadline` in `smp.rs`) and arms its
/// own LAPIC for wheel sleeps via `arm_tsc_deadline_if_earlier`. With ONE
/// shared `TSC_ARMED`, a CPU's "is my new deadline earlier than what *I*
/// have armed?" guard actually read whatever *another* CPU last armed.
/// Concretely: cpu0's periodic tick stores its near deadline into the
/// global `TSC_ARMED`; cpu6 then registers a wheel sleeper, but its
/// `target < TSC_ARMED` test reads cpu0's value, sees "not earlier", and
/// SKIPS programming cpu6's own LAPIC. cpu6 halts with its LAPIC armed only
/// to a far/stale deadline, so the sleeper's wake fires only via the 2 ms
/// idle backstop (or never) — the task strands on the halted AP and any
/// connection it serves stalls. That is the ~50%-of-200-conn livelock,
/// masked into a ~950-rps degraded state by the backstop. Making the state
/// per-CPU means each core's guard reflects only its own armed MSR.
const MAXC: usize = narf_lib::percpu::MAX_CPUS;

/// This CPU's index, clamped into the per-CPU arrays below.
#[inline]
fn tsc_cpu() -> usize {
    let c = narf_lib::percpu::current_cpu();
    if c < MAXC {
        c
    } else {
        0
    }
}

/// [`LocalTimerMode`] of each CPU's LAPIC timer.
static LOCAL_MODE: [AtomicU8; MAXC] = [const { AtomicU8::new(0) }; MAXC];

/// Period (TSC cycles) of the software periodic tick a one-shot mode
/// emulates, per CPU. Non-zero gates the ISR's auto-rearm path; 0 means the
/// timer is stopped or in classic periodic-InitialCount mode and the ISR
/// does nothing extra (hardware re-loads from InitialCount).
static TICK_PERIOD_CYCLES: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];

/// This CPU's next periodic-tick deadline (raw TSC). The ISR computes the
/// next one as `max(prev + period, now + period)` to preserve drift-free
/// periodicity while never slipping behind the current TSC if a long
/// handler delayed us.
static TICK_NEXT: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];

/// Absolute TSC value by which this CPU's armed one-shot will have fired
/// (the earliest of its periodic tick and any wheel deadline): the
/// IA32_TSC_DEADLINE value, or the TMICT expiry's upper bound. Lets
/// `arm_tsc_deadline_if_earlier` reprogram only when a strictly-earlier
/// deadline appears (mirrors Linux hrtimer_reprogram's `expires >=
/// expires_next` guard) — now against THIS CPU's armed value, not a global.
static TSC_ARMED: [AtomicU64; MAXC] = [const { AtomicU64::new(u64::MAX) }; MAXC];
// Budget expiry/replenishment survives an earlier wheel or periodic interrupt.
static TSC_SCHED_DEADLINE: [AtomicU64; MAXC] = [const { AtomicU64::new(u64::MAX) }; MAXC];

/// Minimum delta (TSC cycles) to program — a deadline already in the past
/// is armed `now + MIN_DELTA_CYCLES` so it fires ASAP without a re-fire
/// storm. ~a few µs at multi-GHz; mirrors Linux clockevents min_delta_ns.
const MIN_DELTA_CYCLES: u64 = 10_000;

/// Earliest deadline to arm the one-shot for: the sooner of the next
/// periodic tick and the earliest wheel deadline, floored to `now +
/// min_delta` so we never program the past. Pure; unit-tested.
pub(crate) fn next_arm_target(
    now: u64,
    periodic_next: u64,
    wheel_earliest: Option<u64>,
    min_delta: u64,
) -> u64 {
    let mut target = periodic_next;
    if let Some(w) = wheel_earliest {
        if w < target {
            target = w;
        }
    }
    let floor = now.wrapping_add(min_delta);
    if target < floor {
        floor
    } else {
        target
    }
}

/// Whether the one-shot must be reprogrammed for `target`: it is no longer
/// armed (its mirror is in the past) or `target` is earlier than what is
/// armed — Linux `hrtimer_reprogram`'s `expires >= expires_next` test, with
/// no extra hysteresis. Timer coalescing is the hrtimers' own business
/// (`[_softexpires, expires]` ranges, the wheel's buckets): delaying an
/// earlier event here would make even a zero-slack timer late.
#[inline]
pub(crate) const fn should_rearm_tsc_deadline(now: u64, armed: u64, target: u64) -> bool {
    armed <= now || target < armed
}

/// Reprogram this CPU's LAPIC one-shot (TSC-deadline or TMICT) to
/// `deadline_cycles` IFF it is earlier than what's currently armed (mirrors
/// hrtimer_reprogram). Called from the hrtimer arm callback when a new
/// (possibly sub-tick) earliest event is queued on this CPU's base, so it
/// fires precisely instead of waiting for the periodic tick. No-op in
/// InitialCount mode. Brief IRQ-off RCW so on_timer_tick (which also writes
/// TSC_ARMED + the timer) can't interleave. `hrtimer_event` false = a
/// scheduler budget deadline, which is also recorded so it survives an
/// earlier interrupt.
fn arm_local_event(deadline_cycles: u64, hrtimer_event: bool) {
    // Callers pass monotonic counter time; the one-shot modes program the
    // raw counter.
    let deadline_cycles = narf_time::mono_to_raw_cycles(deadline_cycles);
    // IRQs are masked across the whole RCW below (see the disable/enable
    // pair), so `tsc_cpu()` is stable — we can't migrate mid-function — and
    // the per-CPU `TSC_ARMED`/timer we read, compare, and write all belong
    // to the same core.
    // Read RFLAGS.IF so we only re-enable IRQs if they were on coming in
    // (don't blindly STI inside an already-IRQ-disabled caller, e.g. an
    // hrtimer enqueue under its base lock).
    let irqs_were_on = narf_arch::current::asm::interrupts_enabled();
    if irqs_were_on {
        // SAFETY: CPL=0; pairs with the enable_interrupts() below.
        unsafe {
            narf_arch::current::disable_interrupts();
        }
    }
    let cpu = tsc_cpu();
    if TICK_PERIOD_CYCLES[cpu].load(Ordering::Relaxed) == 0 {
        if irqs_were_on {
            // SAFETY: restore caller IRQ state before the early return.
            unsafe {
                narf_arch::current::enable_interrupts();
            }
        }
        return;
    }
    // SAFETY: RDTSC is unconditionally legal at CPL=0.
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let floor = now.wrapping_add(MIN_DELTA_CYCLES);
    let target = if deadline_cycles < floor {
        floor
    } else {
        deadline_cycles
    };
    // Reprogram when the software mirror is already expired (the hardware
    // one-shot is then unarmed), or when the new target is earlier than the
    // live deadline. The expired case is
    // load-bearing for the idle backstop: treating a stale past `TSC_ARMED`
    // value as "earlier" suppresses the future backstop and lets a CPU HLT
    // forever with an awake task queued.
    let armed = TSC_ARMED[cpu].load(Ordering::Relaxed);
    if !hrtimer_event {
        let pending =
            pending_scheduler_deadline(now, TSC_SCHED_DEADLINE[cpu].load(Ordering::Relaxed));
        TSC_SCHED_DEADLINE[cpu].store(pending.min(deadline_cycles), Ordering::Relaxed);
    }
    if should_rearm_tsc_deadline(now, armed, target) {
        // Period != 0 gate above: this CPU runs a one-shot mode.
        program_next_event(cpu, target);
    }
    if irqs_were_on {
        // SAFETY: pairs with the disable above; restores caller IRQ state.
        unsafe {
            narf_arch::current::enable_interrupts();
        }
    }
}

/// Whether THIS CPU's LAPIC timer runs in TSC-deadline mode.
pub fn tsc_deadline_active() -> bool {
    local_timer_mode(tsc_cpu()) == LocalTimerMode::TscDeadline
}

/// Whether THIS CPU's LAPIC timer is a one-shot, per-event programmable
/// clockevent (TSC-deadline or TMICT; Linux `CLOCK_EVT_FEAT_ONESHOT`).
/// False only for a stopped timer or the uncalibrated periodic fallback.
pub fn local_oneshot_active() -> bool {
    local_timer_mode(tsc_cpu()).is_oneshot()
}

/// How `cpu`'s LAPIC timer is running (diagnostics, tests).
pub fn local_timer_mode(cpu: usize) -> LocalTimerMode {
    LOCAL_MODE.get(cpu).map_or(LocalTimerMode::Stopped, |m| {
        LocalTimerMode::from_raw(m.load(Ordering::Relaxed))
    })
}

/// Period of `cpu`'s software periodic tick in TSC cycles; 0 when it does
/// not run a one-shot mode (diagnostics, tests).
pub fn local_tick_period_cycles(cpu: usize) -> u64 {
    TICK_PERIOD_CYCLES
        .get(cpu)
        .map_or(0, |p| p.load(Ordering::Relaxed))
}

/// Reprogram this CPU's LAPIC deadline if `deadline_cycles` is materially
/// earlier than its current one-shot. Scheduler/budget deadlines use this.
/// Applies to both one-shot modes; the historical name is kept for the boot
/// hook that installs it.
pub fn arm_tsc_deadline_if_earlier(deadline_cycles: u64) {
    arm_local_event(deadline_cycles, false);
}

/// `tick_program_event` for this CPU's hrtimer base: pull the local one-shot
/// in to `deadline_cycles`.
pub(crate) fn arm_hrtimer_event(deadline_cycles: u64) {
    arm_local_event(deadline_cycles, true);
}

/// One masked TMICT one-shot measured against the TSC
/// ([`__test_masked_oneshot`]). All stamps are raw TSC.
#[doc(hidden)]
#[derive(Copy, Clone, Debug)]
pub struct MaskedOneshot {
    /// What the production conversion loaded.
    pub programmed: narf_lib::clockevent_scale::Programmed,
    /// Just before / after the TMICT write that started the countdown.
    pub before_write: u64,
    pub after_write: u64,
    /// Start of the last current-count read that was still non-zero.
    pub last_nonzero_start: u64,
    /// End of the first current-count read that returned zero.
    pub zero_read_end: u64,
}

/// Test-only: load a MASKED TMICT one-shot for `delta_cycles` through the
/// production conversion ([`ClockEventScale::program`]) on this CPU, and poll
/// the current count until it expires. Needs this CPU's timer stopped, and
/// leaves it stopped. `None` without a calibration or if the count never
/// reaches zero within 2^34 cycles.
#[doc(hidden)]
pub fn __test_masked_oneshot(delta_cycles: u64) -> Option<MaskedOneshot> {
    let scale = lapic_timer_scale()?;
    narf_lib::sync::without_interrupts(|| {
        if local_timer_mode(tsc_cpu()) != LocalTimerMode::Stopped {
            return None;
        }
        // SAFETY: this CPU's LAPIC is enabled and its timer stopped; the LVT
        // stays masked, so the expiry raises no interrupt.
        unsafe {
            timer_write(LAPIC_LVTT, (LVT_MASKED | LVT_TIMER_ONESHOT) as u32);
            timer_write(LAPIC_TDCR, DIV_16 as u32);
            let programmed = scale.program(delta_cycles);
            let before_write = narf_time::raw_cycles();
            timer_write(LAPIC_TMICT, programmed.ticks as u32);
            let after_write = narf_time::raw_cycles();
            let mut last_nonzero_start = after_write;
            let out = loop {
                let a = narf_time::raw_cycles();
                let count = timer_read(LAPIC_TMCCT);
                let b = narf_time::raw_cycles();
                if count == 0 {
                    break Some(MaskedOneshot {
                        programmed,
                        before_write,
                        after_write,
                        last_nonzero_start,
                        zero_read_end: b,
                    });
                }
                last_nonzero_start = a;
                if b.saturating_sub(before_write) > 1 << 34 {
                    break None;
                }
                core::hint::spin_loop();
            };
            timer_write(LAPIC_TMICT, 0);
            timer_write(LAPIC_LVTT, LVT_MASKED as u32);
            out
        }
    })
}

/// Test-only: install this CPU-local LAPIC programmer as the hrtimer
/// clockevent programmer when none is installed (the kernel-test boot runs
/// without the timer pump, so its sleeps poll). Returns whether it did; the
/// caller undoes it with `narf_time::hrtimer::clear_arm_callback`.
#[doc(hidden)]
pub fn __test_install_hrtimer_programmer() -> bool {
    if narf_time::hrtimer::arm_callback_installed() {
        return false;
    }
    narf_time::hrtimer::set_arm_callback(arm_hrtimer_event);
    true
}

/// Arm LAPIC TSC-deadline mode firing IRQ `timer_vector` every
/// `period_cycles` TSC ticks. Computes the first deadline from
/// `rdtsc() + period_cycles`, programs LVT_TIMER for deadline
/// mode, then writes IA32_TSC_DEADLINE to arm.
///
/// On subsequent timer IRQs, `on_timer_tick` re-arms by writing
/// the next deadline — TSC-deadline is one-shot in hardware,
/// periodicity is a software construct here.
///
/// # Safety
/// - `init_bsp` must have run.
/// - CPUID 01H ECX[24] must be set (caller gates on Features).
/// - Caller still owns IRQ masking (LVT_TIMER write is racy with
///   in-flight IRQs of the same vector).
pub unsafe fn start_timer_tsc_deadline(timer_vector: u8, period_cycles: u64) {
    // Caller owns IRQ masking (doc contract), so `tsc_cpu()` is stable and
    // this initialises THIS CPU's slot — each AP calls this on itself.
    let cpu = tsc_cpu();
    let first = start_local_oneshot(cpu, LocalTimerMode::TscDeadline, period_cycles);
    TSC_ARMED[cpu].store(first, Ordering::Release);
    let lvt = LVT_TIMER_TSC_DEADLINE | (timer_vector as u64);
    // SAFETY: APIC live; TSC-deadline support implied by caller.
    unsafe {
        timer_write(LAPIC_LVTT, lvt as u32);
        // SDM 10.5.4.1: a serializing MFENCE between the LVT
        // mode write and the deadline write avoids a race where
        // the deadline write is observed before the LVT mode
        // change. AMD APM is silent but Intel mandates this.
        core::arch::asm!("mfence", options(nostack, preserves_flags));
        wrmsr(IA32_TSC_DEADLINE, first);
    }
}

/// Start this CPU's LAPIC timer as a TMICT one-shot clockevent firing IRQ
/// `timer_vector` (Linux `lapic_timer_set_oneshot`: LVT one-shot, divide
/// 16; then `lapic_next_event` per event) that also carries a periodic tick
/// every `period_cycles` TSC cycles, exactly as the TSC-deadline mode does.
/// For CPUs without TSC-deadline; requires the boot calibration.
///
/// # Safety
/// - `init_bsp` (or `init_ap`) ran on this CPU and [`lapic_timer_scale`]
///   returned a calibration.
/// - The caller owns this CPU's LAPIC timer.
unsafe fn start_timer_oneshot(timer_vector: u8, period_cycles: u64) {
    // IRQs masked so the ISR never sees half-initialised state (the BSP's
    // `arm_periodic` runs from `select_primary` with interrupts enabled).
    narf_lib::sync::without_interrupts(|| {
        let cpu = tsc_cpu();
        let first = start_local_oneshot(cpu, LocalTimerMode::Oneshot, period_cycles);
        // SAFETY: caller contract — this CPU's LAPIC is enabled and owned.
        // Writing the LVT mode disarms any previous countdown (SDM
        // §10.5.4); `program_next_event` then loads the first TMICT.
        unsafe {
            timer_write(LAPIC_LVTT, (LVT_TIMER_ONESHOT | timer_vector as u64) as u32);
            timer_write(LAPIC_TDCR, DIV_16 as u32);
        }
        program_next_event(cpu, first);
    });
}

/// Software state shared by both one-shot modes, published before the
/// hardware is programmed: this CPU's hrtimer base, its mode and periodic
/// tick, the programmer hook and its `register_local` clockevent. Returns
/// the first periodic deadline (raw TSC).
fn start_local_oneshot(cpu: usize, mode: LocalTimerMode, period_cycles: u64) -> u64 {
    // `hrtimers_prepare_cpu`: this CPU's base exists before its first tick.
    narf_time::hrtimer::hrtimers_prepare_cpu(cpu);
    TICK_PERIOD_CYCLES[cpu].store(period_cycles, Ordering::Release);
    LOCAL_MODE[cpu].store(mode as u8, Ordering::Release);
    // The local one-shot clockevent is the hrtimer programmer
    // (`tick_program_event`) whether or not the HPET pump comes up; the pump,
    // when it does, installs a programmer that also drives this one.
    if !narf_time::hrtimer::arm_callback_installed() {
        narf_time::hrtimer::set_arm_callback(arm_hrtimer_event);
    }
    // SAFETY: RDTSC is unconditionally legal at CPL=0.
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let first = now.wrapping_add(period_cycles);
    TICK_NEXT[cpu].store(first, Ordering::Release);
    TSC_SCHED_DEADLINE[cpu].store(u64::MAX, Ordering::Relaxed);
    narf_time::set_periodic_tick_wanted(cpu, true);
    narf_time::clockevent::register_local(&LAPIC_CLOCKEVENT);
    first
}

/// The tick period, in TSC cycles, of a `hz` tick on the calibrated TSC.
pub fn tick_period_cycles_for(hz: u32) -> u64 {
    narf_time::wall::ns_to_cycles(1_000_000_000 / u64::from(hz.max(1))).max(1)
}

/// Give every other CPU's one-shot tick the `hz` period, once the TSC is
/// calibrated. The application processors start their tick during
/// bring-up, before calibration, so their periods were derived from an
/// uncalibrated scale (TSC-deadline: 10 ms at 1 cycle/ns; TMICT: 10 000
/// LAPIC counts, 1.6 ms at 100 MHz) instead of the boot CPU's `HZ`; Linux
/// sets every CPU's tick up from the calibrated clock
/// (`setup_APIC_timer` / `clockevents_config_and_register`). A CPU adopts
/// the period at its next tick (its next deadline is the previous one plus
/// the period); an idle CPU with its tick stopped, when it restarts it.
/// CPUs in the hardware periodic or stopped modes are left alone. Returns
/// how many CPUs were retuned.
pub fn retune_local_ticks(hz: u32) -> usize {
    let period = tick_period_cycles_for(hz);
    let me = tsc_cpu();
    let mut retuned = 0;
    for (cpu, p) in TICK_PERIOD_CYCLES.iter().enumerate() {
        if cpu == me {
            continue;
        }
        let old = p.load(Ordering::Acquire);
        if old != 0
            && old != period
            && p.compare_exchange(old, period, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            retuned += 1;
        }
    }
    retuned
}

/// Snapshot of how many timer IRQs have fired since boot.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}
