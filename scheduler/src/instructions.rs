//! Dedicated, per-CPU retired-instruction clocks. No programmable PMC is used.
//!
//! AMD uses IRPERF; Intel reserves fixed counter 0 for this boot. Both count
//! task kernel code as well as userspace. Measured hard-IRQ/NMI spans are
//! subtracted by the same entry/exit guards as time accounting. Enforcement is
//! sampled at existing preemption points; this module never switches contexts.

use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use narf_lib::percpu::MAX_CPUS;
use narf_lib::sync::IrqSafeSpinLock;

const UNKNOWN: u8 = 0;
const ABSENT: u8 = 1;
const AMD: u8 = 2;
#[cfg(any(target_arch = "x86_64", feature = "kernel-test"))]
const INTEL: u8 = 3;

#[derive(Debug)]
#[repr(align(64))]
struct Clock {
    source: AtomicU8,
    mask: AtomicU64,
    irq_total: AtomicU64,
    irq_sequence: AtomicU64,
    init: IrqSafeSpinLock<()>,
}

static CLOCKS: [Clock; MAX_CPUS] = [const {
    Clock {
        source: AtomicU8::new(UNKNOWN),
        mask: AtomicU64::new(0),
        irq_total: AtomicU64::new(0),
        irq_sequence: AtomicU64::new(0),
        init: IrqSafeSpinLock::new(()),
    }
}; MAX_CPUS];

/// The CPU identity and width travel with the sample: neither a migrated task
/// nor a narrow Intel counter may subtract unrelated counter values.
#[derive(Copy, Clone, Debug)]
pub(crate) struct Sample {
    cpu: usize,
    raw: u64,
    irq: u64,
    mask: u64,
}

impl Sample {
    #[cfg(feature = "kernel-test")]
    pub(crate) const fn for_test(raw: u64) -> Self {
        Self {
            cpu: 0,
            raw,
            irq: 0,
            mask: u64::MAX,
        }
    }

    pub(crate) fn elapsed_since(self, start: Self) -> Option<u64> {
        if self.cpu != start.cpu || self.mask != start.mask {
            return None;
        }
        Some(task_delta(
            self.raw,
            start.raw,
            self.irq.wrapping_sub(start.irq),
            self.mask,
        ))
    }
}

fn task_delta(end: u64, start: u64, interrupts: u64, mask: u64) -> u64 {
    (end.wrapping_sub(start) & mask).saturating_sub(interrupts)
}

#[cfg(any(target_arch = "x86_64", feature = "kernel-test"))]
fn width_mask(width: u8) -> Option<u64> {
    match width {
        1..=63 => Some((1u64 << width) - 1),
        64 => Some(u64::MAX),
        _ => None,
    }
}

/// Run on each CPU before its executor starts. Probes are pinned, IRQ-masked,
/// fallible, and never issued from a timer/NMI or a dispatch hot path.
pub(crate) fn init_current_cpu() {
    let _pin = crate::preempt_disable();
    let cpu = narf_lib::percpu::current_cpu();
    let Some(clock) = CLOCKS.get(cpu) else { return };
    if clock.source.load(Ordering::Acquire) != UNKNOWN {
        return;
    }
    let _guard = clock.init.lock();
    if clock.source.load(Ordering::Acquire) == UNKNOWN {
        let (source, mask) = probe().unwrap_or((ABSENT, 0));
        clock.mask.store(mask, Ordering::Relaxed);
        clock.source.store(source, Ordering::Release);
    }
}

pub(crate) fn cpu_available(cpu: usize) -> bool {
    CLOCKS
        .get(cpu)
        .is_some_and(|c| c.source.load(Ordering::Acquire) >= AMD)
}

/// Refuse policy installation before publication unless every online CPU has
/// prepared its own clock. A remote register is never accessed from this CPU.
pub(crate) fn available() -> bool {
    init_current_cpu();
    // A test or a logical offline transition may hide a physically started
    // executor in the volatile bitmap. Its parked continuation still exists.
    let physical = narf_lib::smp::online_bitmap() | narf_lib::smp::ever_online_bitmap();
    (0..MAX_CPUS).all(|cpu| {
        !(physical & (1u64 << cpu) != 0 || crate::cpu_online(crate::CpuId(cpu as u32)))
            || cpu_available(cpu)
    })
}

/// Only reads an already-probed local counter. The preemption guard keeps a
/// task on the same CPU while a timer interrupt is free to update IRQ totals.
pub(crate) fn sample() -> Option<Sample> {
    let _pin = crate::preempt_disable();
    sample_local(narf_lib::percpu::current_cpu())
}

fn sample_local(cpu: usize) -> Option<Sample> {
    let clock = CLOCKS.get(cpu)?;
    let source = clock.source.load(Ordering::Acquire);
    if source < AMD {
        return None;
    }
    let mask = clock.mask.load(Ordering::Relaxed);
    loop {
        let sequence = clock.irq_sequence.load(Ordering::Acquire);
        let irq = clock.irq_total.load(Ordering::Relaxed);
        let raw = read(source) & mask;
        // A nested interrupt may have completed between the total and raw
        // reads. Retry so both values describe the same accounting boundary.
        if sequence == clock.irq_sequence.load(Ordering::Acquire) {
            return Some(Sample {
                cpu,
                raw,
                irq,
                mask,
            });
        }
    }
}

/// Called only from an interrupt entry, which is already CPU-local. No probe,
/// lock, preemption guard, or allocation is permitted on this path.
pub(crate) fn irq_enter(cpu: usize) -> Option<Sample> {
    sample_local(cpu)
}

pub(crate) fn irq_exit(start: Sample) {
    let Some(end) = sample_local(start.cpu) else {
        return;
    };
    // Subtract completed nested IRQ/NMI spans from this guard before adding
    // its exclusive contribution. The combined total counts nesting once.
    let own = end.elapsed_since(start).unwrap_or(0);
    let clock = &CLOCKS[start.cpu];
    clock.irq_total.fetch_add(own, Ordering::Relaxed);
    clock.irq_sequence.fetch_add(1, Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
const MSR_IRPERF: u32 = 0xc000_00e9;
#[cfg(target_arch = "x86_64")]
const MSR_FIXED0: u32 = 0x309;

#[cfg(target_arch = "x86_64")]
fn read(source: u8) -> u64 {
    let msr = if source == AMD {
        MSR_IRPERF
    } else {
        MSR_FIXED0
    };
    // SAFETY: this CPU published the source only after guarded setup, readback,
    // and an advancing-counter check. The MSR wrappers bracket access with
    // compiler fences. The dedicated counter remains reserved for this boot.
    unsafe { narf_arch::x86_64::msr::rdmsr(msr) }
}

#[cfg(not(target_arch = "x86_64"))]
fn read(_source: u8) -> u64 {
    0
}

#[cfg(any(target_arch = "x86_64", feature = "kernel-test"))]
trait RegisterIo {
    fn read(&mut self, msr: u32) -> Option<u64>;
    fn write(&mut self, msr: u32, value: u64) -> Option<()>;
    fn advances(&mut self, msr: u32, mask: u64) -> bool;
}

#[cfg(target_arch = "x86_64")]
struct Hardware;

#[cfg(target_arch = "x86_64")]
impl RegisterIo for Hardware {
    fn read(&mut self, msr: u32) -> Option<u64> {
        narf_arch::x86_64::msr::rdmsr_or_gp(msr).ok()
    }
    fn write(&mut self, msr: u32, value: u64) -> Option<()> {
        narf_arch::x86_64::msr::wrmsr_or_gp(msr, value).ok()
    }
    fn advances(&mut self, msr: u32, mask: u64) -> bool {
        let Some(before) = self.read(msr) else {
            return false;
        };
        for i in 0..128u64 {
            core::hint::black_box(i);
        }
        self.read(msr)
            .is_some_and(|after| (after.wrapping_sub(before) & mask) != 0)
    }
}

#[cfg(any(target_arch = "x86_64", feature = "kernel-test"))]
fn prepare_amd(io: &mut impl RegisterIo) -> Option<(u8, u64)> {
    const HWCR: u32 = 0xc001_0015;
    const ENABLE: u64 = 1 << 30;
    let old = io.read(HWCR)?;
    io.write(HWCR, old | ENABLE)?;
    if io.read(HWCR).is_some_and(|v| v & ENABLE != 0) && io.advances(0xc000_00e9, u64::MAX) {
        Some((AMD, u64::MAX))
    } else {
        let _ = io.write(HWCR, old);
        None
    }
}

#[cfg(any(target_arch = "x86_64", feature = "kernel-test"))]
fn prepare_intel(io: &mut impl RegisterIo, width: u8) -> Option<(u8, u64)> {
    if width < 32 {
        return None;
    }
    let mask = width_mask(width)?;
    const CTRL: u32 = 0x38d;
    const GLOBAL: u32 = 0x38f;
    let ctrl = io.read(CTRL)?;
    let global = io.read(GLOBAL)?;
    // Never take over an enabled or interrupt-armed fixed counter.
    if ctrl & 0xf != 0 || global & (1 << 32) != 0 {
        return None;
    }
    // OS+USR; AnyThread=0 and PMI=0. Preserve every unrelated counter.
    io.write(CTRL, ctrl | 3)?;
    let enabled = io.write(GLOBAL, global | (1 << 32)).is_some()
        && io.read(CTRL).is_some_and(|v| v & 0xf == 3)
        && io.read(GLOBAL).is_some_and(|v| v & (1 << 32) != 0)
        && io.advances(0x309, mask);
    if enabled {
        Some((INTEL, mask))
    } else {
        let _ = io.write(GLOBAL, global);
        let _ = io.write(CTRL, ctrl);
        None
    }
}

#[cfg(target_arch = "x86_64")]
fn probe() -> Option<(u8, u64)> {
    use narf_arch::x86_64::cpuid::cpuid;
    // SAFETY: CPUID is available in long mode; optional leaves are gated.
    let (max, ebx, ecx, edx) = unsafe { cpuid(0, 0) };
    match (ebx, edx, ecx) {
        (0x6874_7541, 0x6974_6e65, 0x444d_4163) => {
            // AuthenticAMD. Linux disables IRPERF on early Zen1, erratum 1054.
            // SAFETY: basic leaf 1 exists on every long-mode AMD CPU.
            let (signature, _, _, _) = unsafe { cpuid(1, 0) };
            let base_family = (signature >> 8) & 0xf;
            let family = base_family
                + if base_family == 0xf {
                    (signature >> 20) & 0xff
                } else {
                    0
                };
            let model = ((signature >> 4) & 0xf) | ((signature >> 12) & 0xf0);
            if family == 0x17 && model < 0x30 {
                return None;
            }
            // SAFETY: the extended maximum leaf is always available on AMD.
            let max_ext = unsafe { cpuid(0x8000_0000, 0).0 };
            if max_ext < 0x8000_0008 {
                return None;
            }
            // SAFETY: the maximum extended leaf validated 0x80000008 above.
            if unsafe { cpuid(0x8000_0008, 0).1 } & 2 == 0 {
                return None;
            }
            prepare_amd(&mut Hardware)
        }
        (0x756e_6547, 0x4965_6e69, 0x6c65_746e) if max >= 0xa => {
            // GenuineIntel, architectural perfmon v2+ with fixed counter 0.
            // SAFETY: the basic maximum leaf validated 0x0a in the match guard.
            let (eax, _, _, edx) = unsafe { cpuid(0xa, 0) };
            if eax & 0xff < 2 || edx & 0x1f == 0 {
                return None;
            }
            prepare_intel(&mut Hardware, ((edx >> 5) & 0xff) as u8)
        }
        _ => None,
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn probe() -> Option<(u8, u64)> {
    None
}

/// Both boundaries are independent; the instruction limit never becomes a TSC
/// duration. Zero instructions requests a yield at the next legal check.
pub(crate) fn expired(
    time: u64,
    time_limit: u64,
    instructions: u64,
    instruction_limit: u64,
) -> bool {
    time >= time_limit || instructions >= instruction_limit
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Registers {
        ctrl: u64,
        global: u64,
        hwcr: u64,
        progress: bool,
        deny_global: bool,
        writes: usize,
    }

    impl Registers {
        fn new() -> Self {
            Self {
                ctrl: 0xa0,
                global: (1 << 2) | (1 << 34),
                hwcr: 0x1234,
                progress: true,
                deny_global: false,
                writes: 0,
            }
        }
    }

    impl RegisterIo for Registers {
        fn read(&mut self, msr: u32) -> Option<u64> {
            match msr {
                0x38d => Some(self.ctrl),
                0x38f => Some(self.global),
                0xc001_0015 => Some(self.hwcr),
                _ => None,
            }
        }
        fn write(&mut self, msr: u32, value: u64) -> Option<()> {
            self.writes += 1;
            match msr {
                0x38d => self.ctrl = value,
                0x38f if !self.deny_global => self.global = value,
                0xc001_0015 => self.hwcr = value,
                _ => return None,
            }
            Some(())
        }
        fn advances(&mut self, _msr: u32, _mask: u64) -> bool {
            self.progress
        }
    }

    fn smoke_instruction_intel_setup_preserves_other_counters() -> TestResult {
        let mut registers = Registers::new();
        let global = registers.global;
        if prepare_intel(&mut registers, 48) != Some((INTEL, (1u64 << 48) - 1))
            || registers.ctrl != 0xa3
            || registers.global != global | (1 << 32)
        {
            return TestResult::Fail(
                "Intel setup changed another counter or enabled AnyThread/PMI",
            );
        }
        for busy_ctrl in [1, 2, 4, 8] {
            let mut registers = Registers::new();
            registers.ctrl |= busy_ctrl;
            if prepare_intel(&mut registers, 48).is_some() || registers.writes != 0 {
                return TestResult::Fail("Intel setup took over an occupied fixed counter");
            }
        }
        let mut registers = Registers::new();
        registers.global |= 1 << 32;
        if prepare_intel(&mut registers, 48).is_some() || registers.writes != 0 {
            return TestResult::Fail("Intel setup took over a globally enabled fixed counter");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/instructions",
        smoke_instruction_intel_setup_preserves_other_counters
    );

    fn smoke_instruction_counter_setup_failure_rolls_back() -> TestResult {
        for locked in [false, true] {
            let mut registers = Registers::new();
            registers.progress = false;
            registers.deny_global = locked;
            let global = registers.global;
            if prepare_intel(&mut registers, 48).is_some()
                || registers.ctrl != 0xa0
                || registers.global != global
            {
                return TestResult::Fail("Intel locked/frozen-counter setup did not roll back");
            }
        }
        let mut registers = Registers::new();
        let hwcr = registers.hwcr;
        if prepare_amd(&mut registers) != Some((AMD, u64::MAX))
            || registers.hwcr != hwcr | (1 << 30)
        {
            return TestResult::Fail("IRPERF setup changed unrelated HWCR bits");
        }
        let mut registers = Registers::new();
        registers.progress = false;
        if prepare_amd(&mut registers).is_some() || registers.hwcr != hwcr {
            return TestResult::Fail("IRPERF frozen-counter setup did not roll back");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/instructions",
        smoke_instruction_counter_setup_failure_rolls_back
    );

    fn smoke_instruction_budget_independent_time_ceiling() -> TestResult {
        if expired(9, 10, 99, 100)
            || !expired(9, 10, 100, 100)
            || !expired(10, 10, 0, 100)
            || !expired(0, 10, 0, 0)
        {
            return TestResult::Fail("instruction and time boundaries are not independent");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/instructions",
        smoke_instruction_budget_independent_time_ceiling
    );

    fn smoke_instruction_counter_wrap_and_irq_exclusion() -> TestResult {
        for width in [32, 48, 64] {
            let mask = width_mask(width).unwrap();
            let start = Sample {
                cpu: 0,
                raw: mask - 9,
                irq: u64::MAX - 4,
                mask,
            };
            let end = Sample {
                cpu: 0,
                raw: 10,
                irq: 0,
                mask,
            };
            // Raw delta=20; IRQ total wraps with delta=5, leaving 15 for task.
            if end.elapsed_since(start) != Some(15) {
                return TestResult::Fail("hardware/IRQ wraparound lost task instructions");
            }
            if (Sample { cpu: 1, ..end }).elapsed_since(start).is_some()
                || (Sample {
                    mask: mask >> 1,
                    ..end
                })
                .elapsed_since(start)
                .is_some()
            {
                return TestResult::Fail("cross-CPU or cross-width sample was accepted");
            }
        }
        if width_mask(0).is_some()
            || width_mask(65).is_some()
            || task_delta(12, 10, 99, u64::MAX) != 0
        {
            return TestResult::Fail("invalid geometry or IRQ subtraction underflow");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/instructions",
        smoke_instruction_counter_wrap_and_irq_exclusion
    );

    fn smoke_instruction_nested_irq_exclusive_accounting() -> TestResult {
        let start = Sample {
            cpu: 0,
            raw: 100,
            irq: 10,
            mask: u64::MAX,
        };
        // Nested NMI retires 20 within the outer IRQ's 70 instructions.
        let end = Sample {
            raw: 170,
            irq: 30,
            ..start
        };
        let outer = end.elapsed_since(start).unwrap();
        let after = Sample {
            raw: 200,
            irq: end.irq + outer,
            ..start
        };
        if outer != 50 || after.elapsed_since(start) != Some(30) {
            return TestResult::Fail("nested IRQ instructions charged twice");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/instructions",
        smoke_instruction_nested_irq_exclusive_accounting
    );

    fn smoke_instruction_hardware_counter_and_irq_accounting() -> TestResult {
        init_current_cpu();
        let Some(before) = sample() else {
            return TestResult::Skip("no dedicated retired-instruction counter exposed");
        };
        let guard = crate::interrupt_account_enter(crate::InterruptKind::HardIrq);
        for i in 0..512u64 {
            core::hint::black_box(i);
        }
        let nmi = crate::interrupt_account_enter(crate::InterruptKind::Nmi);
        for i in 0..512u64 {
            core::hint::black_box(i);
        }
        drop(nmi);
        drop(guard);
        let Some(after) = sample() else {
            return TestResult::Fail("prepared instruction clock disappeared");
        };
        let raw = after.raw.wrapping_sub(before.raw) & before.mask;
        let Some(task) = after.elapsed_since(before) else {
            return TestResult::Fail("hardware sample changed CPU or width");
        };
        if raw == 0 || task >= raw || after.irq == before.irq {
            return TestResult::Fail("counter did not advance or IRQ work was not excluded");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "scheduler/instructions",
        smoke_instruction_hardware_counter_and_irq_accounting
    );
}
