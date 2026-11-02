//! Interrupt time accounting kept separate from schedulable task runtime.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InterruptKind {
    HardIrq,
    Nmi,
}

static HARDIRQ_DEPTH: [AtomicU32; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; narf_lib::percpu::MAX_CPUS];
static HARDIRQ_START: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
static HARDIRQ_CYCLES: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
static NMI_DEPTH: [AtomicU32; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU32::new(0) }; narf_lib::percpu::MAX_CPUS];
static NMI_START: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];
static NMI_CYCLES: [AtomicU64; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; narf_lib::percpu::MAX_CPUS];

/// IRQ-entry token. It cannot cross CPUs and records only the outermost span
/// of a nested kind, preventing same-kind nesting from double charging.
#[must_use = "the guard must cover the interrupt dispatch body"]
#[derive(Debug)]
pub struct InterruptAccountGuard {
    cpu: usize,
    kind: InterruptKind,
    outermost: bool,
    #[cfg(feature = "instruction-quantum")]
    instruction_start: Option<crate::instructions::Sample>,
    /// The instruction feature also brackets real NMIs. Remove those spans
    /// from an outer hard IRQ's time before adding the separate NMI account.
    #[cfg(feature = "instruction-quantum")]
    nmi_cycles_at_entry: u64,
    _not_send: PhantomData<*mut ()>,
}

pub fn interrupt_account_enter(kind: InterruptKind) -> InterruptAccountGuard {
    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    #[cfg(feature = "instruction-quantum")]
    let instruction_start = crate::instructions::irq_enter(cpu);
    #[cfg(feature = "instruction-quantum")]
    let nmi_cycles_at_entry = NMI_CYCLES[cpu].load(Ordering::Acquire);
    let (depth, start) = match kind {
        InterruptKind::HardIrq => (&HARDIRQ_DEPTH[cpu], &HARDIRQ_START[cpu]),
        InterruptKind::Nmi => (&NMI_DEPTH[cpu], &NMI_START[cpu]),
    };
    let outermost = depth.fetch_add(1, Ordering::AcqRel) == 0;
    if outermost {
        start.store(narf_time::now_cycles(), Ordering::Release);
    }
    InterruptAccountGuard {
        cpu,
        kind,
        outermost,
        #[cfg(feature = "instruction-quantum")]
        instruction_start,
        #[cfg(feature = "instruction-quantum")]
        nmi_cycles_at_entry,
        _not_send: PhantomData,
    }
}

impl Drop for InterruptAccountGuard {
    fn drop(&mut self) {
        #[cfg(feature = "instruction-quantum")]
        if let Some(start) = self.instruction_start {
            crate::instructions::irq_exit(start);
        }
        let (depth, start, cycles) = match self.kind {
            InterruptKind::HardIrq => (
                &HARDIRQ_DEPTH[self.cpu],
                &HARDIRQ_START[self.cpu],
                &HARDIRQ_CYCLES[self.cpu],
            ),
            InterruptKind::Nmi => (
                &NMI_DEPTH[self.cpu],
                &NMI_START[self.cpu],
                &NMI_CYCLES[self.cpu],
            ),
        };
        let previous = depth.fetch_sub(1, Ordering::AcqRel);
        assert!(previous != 0, "interrupt accounting depth underflow");
        if self.outermost {
            debug_assert_eq!(previous, 1);
            let elapsed = narf_time::now_cycles().saturating_sub(start.swap(0, Ordering::AcqRel));
            #[cfg(feature = "instruction-quantum")]
            let elapsed = if self.kind == InterruptKind::HardIrq {
                elapsed.saturating_sub(
                    NMI_CYCLES[self.cpu]
                        .load(Ordering::Acquire)
                        .saturating_sub(self.nmi_cycles_at_entry),
                )
            } else {
                elapsed
            };
            cycles.fetch_add(elapsed, Ordering::Relaxed);
        }
    }
}

pub fn hardirq_cycles(cpu: crate::CpuId) -> u64 {
    HARDIRQ_CYCLES
        .get(cpu.0 as usize)
        .map(|value| value.load(Ordering::Acquire))
        .unwrap_or(0)
}

pub fn nmi_cycles(cpu: crate::CpuId) -> u64 {
    NMI_CYCLES
        .get(cpu.0 as usize)
        .map(|value| value.load(Ordering::Acquire))
        .unwrap_or(0)
}

/// Aggregate interrupt time used to subtract hard-interrupt residency from a
/// task's wall-clock dispatch interval.
pub(crate) fn interrupt_cycles(cpu: usize) -> u64 {
    HARDIRQ_CYCLES[cpu]
        .load(Ordering::Acquire)
        .saturating_add(NMI_CYCLES[cpu].load(Ordering::Acquire))
}
