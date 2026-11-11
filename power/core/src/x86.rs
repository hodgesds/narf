//! Validated MONITOR/MWAIT and ACPI I/O-port idle entry.

use crate::IdleEntry;
use core::sync::atomic::{compiler_fence, AtomicU8, Ordering};
use narf_arch::x86_64::cpuid::cpuid;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuIdleCaps {
    pub apic_id: u32,
    pub mwait: bool,
    pub interrupt_break: bool,
    pub sub_states: u32,
    pub invariant_tsc: bool,
    pub arat: bool,
    pub amd_zen: bool,
}

impl CpuIdleCaps {
    pub fn probe() -> Self {
        // SAFETY: CPUID reads architectural feature and topology information.
        let ((max, ebx, ecx, edx), (max_ext, _, _, _), (signature, ids, features, _)) =
            unsafe { (cpuid(0, 0), cpuid(0x8000_0000, 0), cpuid(1, 0)) };
        let amd = ebx == 0x6874_7541 && edx == 0x6974_6e65 && ecx == 0x444d_4163;
        let base_family = (signature >> 8) & 0xf;
        let family = base_family
            + if base_family == 0xf {
                (signature >> 20) & 0xff
            } else {
                0
            };
        let mut caps = Self {
            apic_id: ids >> 24,
            mwait: max >= 5 && features & (1 << 3) != 0,
            amd_zen: amd && family >= 0x17,
            ..Self::default()
        };
        for leaf in [0x1f, 0xb] {
            if max >= leaf {
                // SAFETY: supported topology leaf.
                let (_, count, _, id) = unsafe { cpuid(leaf, 0) };
                if count != 0 {
                    caps.apic_id = id;
                    break;
                }
            }
        }
        if amd && max_ext >= 0x8000_001e {
            // SAFETY: extended topology is supported only when TopologyExtensions is set.
            let (_, _, extended, _) = unsafe { cpuid(0x8000_0001, 0) };
            if extended & (1 << 22) != 0 {
                // SAFETY: checked extended leaf and feature bit.
                caps.apic_id = unsafe { cpuid(0x8000_001e, 0) }.0;
            }
        }
        if caps.mwait {
            // SAFETY: MONITOR/MWAIT and leaf 5 were checked above.
            let (_, _, extensions, sub_states) = unsafe { cpuid(5, 0) };
            caps.interrupt_break = extensions & 3 == 3;
            caps.sub_states = sub_states;
        }
        if max_ext >= 0x8000_0007 {
            // SAFETY: supported extended power-management leaf.
            caps.invariant_tsc = unsafe { cpuid(0x8000_0007, 0) }.3 & (1 << 8) != 0;
        }
        // AMD family 12h and later retain the APIC timer in deep idle.
        caps.arat = (amd && family > 0x11)
            || (max >= 6 && {
                // SAFETY: supported thermal/power leaf.
                unsafe { cpuid(6, 0) }.0 & (1 << 2) != 0
            });
        caps
    }

    pub fn supports(self, entry: IdleEntry) -> bool {
        match entry {
            IdleEntry::Poll | IdleEntry::Halt => true,
            IdleEntry::Mwait { hint } => {
                // The first EDX nibble describes C0; hint 0 selects C1.
                let state = (hint >> 4) + 1;
                self.mwait
                    && self.interrupt_break
                    && hint <= 0x6f
                    && (state == 1 || (self.arat && self.invariant_tsc))
                    && (hint & 0xf) < ((self.sub_states >> (state * 4).min(31)) & 0xf)
            }
            IdleEntry::SystemIo { port, acpi_type } => {
                // Zen C3 is cache coherent and needs no bus-master arbitration
                // or post-entry PM-timer read. Other I/O drivers need those hooks.
                port != 0
                    && self.amd_zen
                    && self.arat
                    && self.invariant_tsc
                    && matches!(acpi_type, 2 | 3)
            }
            IdleEntry::Callback(_) => false,
        }
    }
}

#[repr(align(64))]
struct MonitorLine(AtomicU8);
static MONITORS: [MonitorLine; narf_lib::percpu::MAX_CPUS] =
    [const { MonitorLine(AtomicU8::new(0)) }; narf_lib::percpu::MAX_CPUS];

/// # Safety
/// The entry must have passed this CPU's `CpuIdleCaps::supports`. The caller
/// holds no locks, has completed its wake check, and has IRQs masked. Pending
/// interrupts break MWAIT even with IF=0. Returns with IRQs still masked.
pub unsafe fn enter(entry: IdleEntry) {
    match entry {
        IdleEntry::Mwait { hint } => {
            let cpu = narf_lib::percpu::current_cpu();
            let address = MONITORS[cpu].0.as_ptr();
            compiler_fence(Ordering::SeqCst);
            // SAFETY: capability validation includes extensions and interrupt
            // break support; the monitored line remains allocated permanently.
            unsafe {
                core::arch::asm!("monitor", in("rax") address, in("rcx") 0u32,
                    in("rdx") 0u32, options(nostack));
                core::arch::asm!("mwait", in("rax") hint, in("rcx") 1u32,
                    options(nostack));
            }
            compiler_fence(Ordering::SeqCst);
        }
        IdleEntry::SystemIo { port, .. } => {
            // SAFETY: firmware supplied this port and the platform supports
            // ACPI I/O entry without cache flushing or broadcast-timer setup.
            unsafe { narf_arch::x86_64::io_port::inb(port) };
        }
        _ => {
            // SAFETY: same masked-IRQ wake contract as the validated driver.
            unsafe { narf_arch::idle_halt_then_disable() };
        }
    }
}
