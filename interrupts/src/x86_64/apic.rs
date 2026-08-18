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

static TIMER_TICKS: AtomicU64 = AtomicU64::new(0);

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
        // SAFETY: LAPIC MMIO is identity-mapped (low 4 GiB).
        unsafe {
            init_lapic_xapic();
        }
        install_apic_diag_handlers();
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
/// - LAPIC MMIO base must be identity-mapped + accessible.
/// - APIC_BASE.EN must already be set.
unsafe fn init_lapic_xapic() {
    let sivr = (XAPIC_MMIO_BASE + 0x0F0) as *mut u32;
    let lvt_timer = (XAPIC_MMIO_BASE + 0x320) as *mut u32;
    let lvt_thermal = (XAPIC_MMIO_BASE + 0x330) as *mut u32;
    let lvt_perf = (XAPIC_MMIO_BASE + 0x340) as *mut u32;
    let lvt_lint0 = (XAPIC_MMIO_BASE + 0x350) as *mut u32;
    let lvt_lint1 = (XAPIC_MMIO_BASE + 0x360) as *mut u32;
    let lvt_error = (XAPIC_MMIO_BASE + 0x370) as *mut u32;
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
        let esr_reg = (XAPIC_MMIO_BASE + 0x280) as *mut u32;
        // SAFETY: in xAPIC mode the LAPIC MMIO window is identity-mapped
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

/// `ClockEvent` adapter wrapping the LAPIC-timer primitives above.
///
/// LAPIC timer ticks at `(bus_freq / divider)` Hz; with DIV_16 a
/// typical 100 MHz FSB gives ~6.25 MHz post-divide, so a desired
/// `100 Hz` (10 ms period) maps to ~62_500 ticks.
///
/// Phase 1 uses a hardcoded estimate of post-divide freq (100 MHz
/// raw / 16 = 6.25 MHz) — close enough on most platforms to deliver
/// at least *some* ticks per second so `probe_fires` can verify.
/// Phase 2 lands proper calibration against HPET / TSC.
///
/// On Intel, the LAPIC timer stops in C3 and deeper C-states
/// **unless** CPUID 0x06 EAX[2] (ARAT — Always Running APIC
/// Timer) is set, in which case the timer continues running. We
/// detect ARAT via [`narf_arch::x86_64::Features::arat`] but don't
/// currently use the result here — Linux's optimisation is to
/// clear the `CLOCK_EVT_FEAT_C3STOP` clockevent flag, but NARF
/// doesn't yet enter deep C-states in the idle path, so the
/// information is informational for diagnostics.
#[derive(Debug)]
pub struct LapicClockEvent;

impl narf_time::clockevent::ClockEvent for LapicClockEvent {
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
        // Prefer TSC-deadline mode (CPUID 01H ECX[24]) — modern
        // Linux's default for x86. Avoids LAPIC bus calibration
        // entirely: each IRQ re-arms by writing the next TSC
        // value. Renoir / Phoenix / QEMU TCG all support it.
        //
        // Fallback to periodic-InitialCount with a fixed small
        // count when TSC-deadline is unavailable (very old CPUs).
        // SAFETY: BSP, IRQs masked at the caller (clockevent
        // select_primary runs with IRQs disabled outside the
        // probe window).
        // SAFETY: Valid memory or trusted environment
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        if feats.tsc_deadline {
            // Period in TSC cycles for the requested IRQ rate.
            //
            // `ns_to_cycles`, NOT `* cycles_per_ns()`. The latter was a
            // TRUNCATED integer GHz clamped to 1..=6, so a 3.293 GHz TSC
            // read back as 3 and the period came out ~9.8% long — every
            // CPU ticking at ~1097 Hz against the 1000 Hz this asks for.
            let period_ns = 1_000_000_000u64 / hz as u64;
            let period_cycles = narf_time::wall::ns_to_cycles(period_ns).max(1);
            // SAFETY: caller upholds exclusive LAPIC access; we
            // gated on CPUID for TSC-deadline support.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                start_timer_tsc_deadline(vector, period_cycles);
            }
            // Self-rearming one-shot: each IRQ writes the next deadline, so
            // the tick is dependable and a halted CPU may trust it to wake.
            narf_time::set_tick_reliable(true);
        } else {
            // Periodic-InitialCount fallback. See start_timer
            // commentary; 10_000 is safely fast on any plausible
            // post-divide bus speed.
            let _ = hz;
            let initial_count = 10_000u32;
            // SAFETY: same.
            unsafe {
                start_timer(vector, initial_count);
            }
            // Uncalibrated fixed-count periodic: under TCG (qemu64, no
            // TSC-deadline) a tick can be dropped or late, so the executor
            // must not halt indefinitely on a near-term wheel deadline.
            narf_time::set_tick_reliable(false);
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
        // Classic periodic-InitialCount mode gives post-divide
        // 6.25 MHz on a typical 100 MHz BCLK ≈ 160 ns per tick.
        // ARAT (Intel) doesn't change resolution, only the C3
        // behaviour.
        //
        // SAFETY: CPUID is always legal at CPL=0.
        let feats = unsafe { narf_arch::x86_64::Features::probe() };
        if feats.tsc_deadline {
            1
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
/// `cpu_mask`, composes an x2APIC ICR for each, writes
/// APIC_ICR_MSR to deliver a fixed-vector IPI at `vector`.
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
    if !X2APIC_ACTIVE.load(Ordering::Acquire) {
        // xAPIC fallback not implemented yet — broadcast becomes
        // a no-op. CPUs in the mask don't get external ticks; if
        // their local clockevent is also dead they wedge. Future
        // work: program ICR via MMIO at XAPIC_MMIO_BASE+0x310.
        return;
    }
    let mut m = cpu_mask;
    while m != 0 {
        let cpu = m.trailing_zeros();
        m &= m - 1;
        // Fixed delivery, edge-triggered, level-assert,
        // physical destination, no shorthand. Dest in high
        // 32 bits (x2APIC full APIC ID).
        let icr: u64 = (vector as u64)
            | (1u64 << 14)             // level = assert
            | ((cpu as u64) << 32); // destination APIC id
                                    // SAFETY: x2APIC confirmed active above.
        unsafe {
            wrmsr_icr(icr);
        }
    }
}

/// Send a fixed-vector IPI to every CPU in `cpu_mask`. Thin public
/// wrapper over the x2APIC ICR write — used by the scheduler's
/// reschedule IPI to kick an idle remote CPU off its HLT so a
/// cross-core wake takes effect immediately instead of at that CPU's
/// next timer tick. Fire-and-forget (no ack), edge-triggered fixed
/// delivery. No-op under xAPIC fallback (same caveat as the broadcast).
#[inline]
pub fn send_fixed_ipi(cpu_mask: u64, vector: u8) {
    x2apic_broadcast(cpu_mask, vector);
}

/// Global singleton for registration with the clockevent registry.
pub static LAPIC_CLOCKEVENT: LapicClockEvent = LapicClockEvent;

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
        let eoi_reg = (XAPIC_MMIO_BASE + 0x0B0) as *mut u32;
        // SAFETY: in xAPIC mode the LAPIC MMIO window is identity-mapped
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
        // SAFETY: LAPIC MMIO identity-mapped; high half irrelevant
        // for self-shorthand but Intel mandates writing it first.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let icr_hi_reg = (XAPIC_MMIO_BASE + 0x310) as *mut u32;
            let icr_lo_reg = (XAPIC_MMIO_BASE + 0x300) as *mut u32;
            core::ptr::write_volatile(icr_hi_reg, 0);
            core::ptr::write_volatile(icr_lo_reg, icr_low);
        }
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
/// `init_bsp` must have run. LAPIC MMIO identity-mapped.
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
        // SAFETY: LAPIC MMIO identity-mapped; spec mandates writing
        // ICR_HIGH before ICR_LOW (LOW write triggers send).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let icr_hi_reg = (XAPIC_MMIO_BASE + 0x310) as *mut u32;
            let icr_lo_reg = (XAPIC_MMIO_BASE + 0x300) as *mut u32;
            core::ptr::write_volatile(icr_hi_reg, icr_high);
            core::ptr::write_volatile(icr_lo_reg, icr_low);
        }
    }
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
/// `init_bsp` must have run. LAPIC MMIO is identity-mapped per
/// init_bsp contract.
#[inline]
pub unsafe fn apic_id() -> u32 {
    if X2APIC_ACTIVE.load(core::sync::atomic::Ordering::Acquire) {
        // SAFETY: MSR 0x802 is x2APIC APIC_ID — read-only.
        unsafe { rdmsr(0x0000_0802) as u32 }
    } else {
        let id_reg = (XAPIC_MMIO_BASE + 0x20) as *const u32;
        // SAFETY: caller guarantees init_bsp ran, so the LAPIC MMIO
        // window is identity-mapped; this 32-bit aligned read of the
        // architected APIC_ID register at base+0x20 has no side effects.
        // SAFETY: Valid memory or trusted environment
        let raw = unsafe { core::ptr::read_volatile(id_reg) };
        // xAPIC APIC_ID occupies bits[31:24].
        raw >> 24
    }
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
        let lapic_hi = (XAPIC_MMIO_BASE + 0x310) as *mut u32;
        let lapic_lo = (XAPIC_MMIO_BASE + 0x300) as *mut u32;
        // SAFETY: LAPIC MMIO is identity-mapped (low 4 GiB). Write HI (dest)
        // before LO (triggers the IPI).
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
///
/// TSC-deadline mode is one-shot in hardware; periodicity is a software
/// construct. This ISR multiplexes the periodic 1 kHz tick with the
/// timer-wheel's earliest (possibly sub-tick) deadline so a wheel sleep
/// fires precisely instead of rounding up to the next periodic tick
/// (mirrors a Linux hrtimer one-shot tracking `min(tick, earliest hrtimer)`).
///
/// Only a genuine periodic expiry (`now >= periodic_next`) bumps
/// TIMER_TICKS + advances the periodic accounting; an early wheel-deadline
/// fire must NOT advance the periodic deadline. We then re-arm the one-shot
/// to the sooner of the (possibly unchanged) periodic deadline and the
/// wheel's earliest, floored to `now + MIN_DELTA_CYCLES`.
#[inline]
pub fn on_timer_tick() {
    let cpu = tsc_cpu();
    let period = TSC_DEADLINE_PERIOD_CYCLES[cpu].load(Ordering::Relaxed);
    if period == 0 {
        // InitialCount periodic mode: hardware auto-reloads; just count.
        TIMER_TICKS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    // SAFETY: _rdtsc compiles to RDTSC, unconditionally legal at CPL=0.
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let mut periodic_next = TSC_DEADLINE_NEXT[cpu].load(Ordering::Relaxed);
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
        TSC_DEADLINE_NEXT[cpu].store(periodic_next, Ordering::Relaxed);
    }
    let target = next_arm_target(
        now,
        periodic_next,
        narf_time::timer_wheel::next_deadline_cycles_try(),
        MIN_DELTA_CYCLES,
    );
    TSC_ARMED[cpu].store(target, Ordering::Relaxed);
    // SAFETY: TSC-deadline MSR is unconditionally writable when the
    // LVT_TIMER is configured for deadline mode, which is the gate that
    // set TSC_DEADLINE_PERIOD_CYCLES non-zero.
    //
    // MFENCE before the WRMSR mirrors Linux's `weak_wrmsr_fence()` (an
    // alt-patched MFENCE enabled specifically on TSC-deadline-capable
    // CPUs). Intel erratum: certain Skylake-era chips reorder memory ops
    // around the IA32_TSC_DEADLINE WRMSR; AMD APM is silent, but the
    // fence is cheap and Linux applies it unconditionally on TSC-deadline
    // chips.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
        wrmsr(IA32_TSC_DEADLINE, target);
    }
    // We deliberately do NOT call timer_wheel::fire_due here.
    //
    // fire_due iterates the wheel and consumes Wakers via wake(),
    // which drops the inner Arc — and the global allocator's
    // Sleepable free path panics when invoked with IRQs disabled
    // (`memory::context::AllocContext::Sleepable`). The trap
    // handler runs with IF=0, so freeing an Arc here trips that
    // check the moment a Waker's last reference goes away in the
    // same tick that a task completes.
    //
    // The wheel is advanced from non-IRQ context instead, by
    // `narf_scheduler::run_until_empty`'s idle path which busy-
    // polls `fire_due` between halts with IRQs enabled. That
    // path is safe to free from. The only thing the timer ISR
    // does now is bump TIMER_TICKS for diagnostics + return
    // promptly so the executor's halt_until_irq wakes up and
    // serves the wheel on the next round.
}

/// Per-CPU TSC-deadline timer state. The LAPIC TSC-deadline MSR is
/// inherently per-CPU (each core has its own LVT_TIMER + IA32_TSC_DEADLINE),
/// so the *software* state that mirrors it — the period, the next periodic
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

/// Period (TSC cycles) between consecutive TSC-deadline IRQs, per CPU.
/// Non-zero gates the ISR's auto-rearm path; 0 means the timer
/// is in classic periodic-InitialCount mode and the ISR does
/// nothing extra (hardware re-loads from InitialCount).
static TSC_DEADLINE_PERIOD_CYCLES: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];

/// Last deadline written to this CPU's IA32_TSC_DEADLINE. ISR computes the
/// next deadline as `max(prev + period, now + period)` to
/// preserve drift-free periodicity while never slipping behind
/// the current TSC if a long handler delayed us.
static TSC_DEADLINE_NEXT: [AtomicU64; MAXC] = [const { AtomicU64::new(0) }; MAXC];

/// Absolute TSC value currently programmed into this CPU's IA32_TSC_DEADLINE
/// (the earliest of its periodic tick and any wheel deadline). Lets
/// `arm_tsc_deadline_if_earlier` reprogram only when a strictly-earlier
/// deadline appears (mirrors Linux hrtimer_reprogram's `expires >=
/// expires_next` guard) — now against THIS CPU's armed value, not a global.
static TSC_ARMED: [AtomicU64; MAXC] = [const { AtomicU64::new(u64::MAX) }; MAXC];
/// Minimum delta (TSC cycles) to program — a deadline already in the past
/// is armed `now + MIN_DELTA_CYCLES` so it fires ASAP without a re-fire
/// storm. ~a few µs at multi-GHz; mirrors Linux clockevents min_delta_ns.
const MIN_DELTA_CYCLES: u64 = 10_000;

/// Coalescing slack (TSC cycles, ≈ 80 µs at 2.5 GHz) for the wheel-driven
/// re-arm path. `arm_tsc_deadline_if_earlier` reprograms the one-shot only
/// when the new deadline is earlier than what's already armed by MORE than
/// this — so a cluster of sleepers landing just before the already-armed
/// (typically the 1 kHz periodic) deadline does NOT trigger an MSR write
/// each. This is the hysteresis/slack Linux gets from hrtimer `_softexpires`
/// ranges and timer-wheel buckets; without it, ~1 ms sleepers re-arming the
/// LAPIC a hair early drove the effective IRQ rate to ~5x the configured
/// 1 kHz. A coalesced timer fires at most `COALESCE_SLACK_CYCLES` late
/// (bounded because we only skip when armed − target ≤ slack), and the next
/// periodic tick re-arms to the exact wheel minimum regardless, so precision
/// for genuinely sub-slack sleeps (which reprogram exactly) is preserved.
const COALESCE_SLACK_CYCLES: u64 = 200_000;

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

#[inline]
pub(crate) const fn should_rearm_tsc_deadline(
    now: u64,
    armed: u64,
    target: u64,
    coalesce_slack: u64,
) -> bool {
    armed <= now || armed.saturating_sub(target) > coalesce_slack
}

/// Reprogram the LAPIC TSC-deadline one-shot to `deadline_cycles` IFF it is
/// earlier than what's currently armed (mirrors hrtimer_reprogram). Called
/// from the timer-wheel arm-callback when a new (possibly sub-tick) deadline
/// is registered, so it fires precisely instead of waiting for the periodic
/// tick. No-op in InitialCount mode. Brief IRQ-off RCW so on_timer_tick
/// (which also writes TSC_ARMED + the MSR) can't interleave.
pub fn arm_tsc_deadline_if_earlier(deadline_cycles: u64) {
    // IRQs are masked across the whole RCW below (see the disable/enable
    // pair), so `tsc_cpu()` is stable — we can't migrate mid-function — and
    // the per-CPU `TSC_ARMED`/MSR we read, compare, and write all belong to
    // the same core.
    // Read RFLAGS.IF so we only re-enable IRQs if they were on coming in
    // (don't blindly STI inside an already-IRQ-disabled caller, e.g. the
    // wheel's `register()` under lock).
    let irqs_were_on = narf_arch::current::asm::interrupts_enabled();
    if irqs_were_on {
        // SAFETY: CPL=0; pairs with the enable_interrupts() below.
        unsafe {
            narf_arch::current::disable_interrupts();
        }
    }
    let cpu = tsc_cpu();
    if TSC_DEADLINE_PERIOD_CYCLES[cpu].load(Ordering::Relaxed) == 0 {
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
    // live deadline by more than the coalescing slack. The expired case is
    // load-bearing for the idle backstop: treating a stale past `TSC_ARMED`
    // value as "earlier" suppresses the future backstop and lets a CPU HLT
    // forever with an awake task queued.
    let armed = TSC_ARMED[cpu].load(Ordering::Relaxed);
    if should_rearm_tsc_deadline(now, armed, target, COALESCE_SLACK_CYCLES) {
        TSC_ARMED[cpu].store(target, Ordering::Relaxed);
        // SAFETY: TSC-deadline MSR writable (period != 0 gate above);
        // MFENCE mirrors Linux weak_wrmsr_fence (see on_timer_tick).
        unsafe {
            core::arch::asm!("mfence", options(nostack, preserves_flags));
            wrmsr(IA32_TSC_DEADLINE, target);
        }
    }
    if irqs_were_on {
        // SAFETY: pairs with the disable above; restores caller IRQ state.
        unsafe {
            narf_arch::current::enable_interrupts();
        }
    }
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
    TSC_DEADLINE_PERIOD_CYCLES[cpu].store(period_cycles, Ordering::Release);
    // SAFETY: caller upholds CPL=0 + LAPIC live.
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    let first = now.wrapping_add(period_cycles);
    TSC_DEADLINE_NEXT[cpu].store(first, Ordering::Release);
    TSC_ARMED[cpu].store(first, Ordering::Release);
    let lvt = LVT_TIMER_TSC_DEADLINE | (timer_vector as u64);
    // SAFETY: APIC live; TSC-deadline support implied by caller.
    unsafe {
        if X2APIC_ACTIVE.load(Ordering::Acquire) {
            wrmsr(APIC_LVT_TIMER_MSR, lvt);
        } else {
            let lvt_ptr = (XAPIC_MMIO_BASE + 0x320) as *mut u32;
            core::ptr::write_volatile(lvt_ptr, lvt as u32);
        }
        // SDM 10.5.4.1: a serializing MFENCE between the LVT
        // mode write and the deadline write avoids a race where
        // the deadline write is observed before the LVT mode
        // change. AMD APM is silent but Intel mandates this.
        core::arch::asm!("mfence", options(nostack, preserves_flags));
        wrmsr(IA32_TSC_DEADLINE, first);
    }
}

/// Snapshot of how many timer IRQs have fired since boot.
pub fn timer_ticks() -> u64 {
    TIMER_TICKS.load(Ordering::Relaxed)
}
