//! Validated MONITOR/MWAIT and ACPI I/O-port idle entry.

use crate::IdleEntry;
use core::sync::atomic::{compiler_fence, AtomicU32, AtomicU8, Ordering};
use narf_arch::x86_64::cpuid::cpuid;

/// CPUID.05H:ECX[0] — MONITOR/MWAIT extensions (ECX hints) are enumerated.
const CPUID5_ECX_EXTENSIONS_SUPPORTED: u32 = 1 << 0;
/// CPUID.05H:EDX[7:4] — number of MWAIT C1 sub-states.
const MWAIT_C1_SUBSTATE_MASK: u32 = 0xf0;

#[derive(Clone, Copy, Debug, Default)]
pub struct CpuIdleCaps {
    pub apic_id: u32,
    pub mwait: bool,
    pub interrupt_break: bool,
    pub sub_states: u32,
    pub invariant_tsc: bool,
    pub arat: bool,
    pub amd_zen: bool,
    /// Linux `X86_BUG_MONITOR`: a store to the monitored line may not wake
    /// MWAIT. MWAIT states stay usable, but never as a polling idle.
    pub monitor_bug: bool,
    /// Linux `X86_BUG_CLFLUSH_MONITOR`: flush the monitored line first.
    pub clflush_monitor: bool,
    /// Linux `prefer_mwait_c1_over_halt`: the default C1 is `mwait_idle`.
    pub mwait_c1: bool,
}

impl CpuIdleCaps {
    pub fn probe() -> Self {
        // SAFETY: CPUID reads architectural feature and topology information.
        let ((max, ebx, ecx, edx), (max_ext, _, _, _), (signature, ids, features, _)) =
            unsafe { (cpuid(0, 0), cpuid(0x8000_0000, 0), cpuid(1, 0)) };
        let amd = ebx == 0x6874_7541 && edx == 0x6974_6e65 && ecx == 0x444d_4163;
        let intel = ebx == 0x756e_6547 && edx == 0x4965_6e69 && ecx == 0x6c65_746e;
        let base_family = (signature >> 8) & 0xf;
        let family = base_family
            + if base_family == 0xf {
                (signature >> 20) & 0xff
            } else {
                0
            };
        let model = ((signature >> 4) & 0xf)
            | if matches!(base_family, 0x6 | 0xf) {
                ((signature >> 16) & 0xf) << 4
            } else {
                0
            };
        let stepping = signature & 0xf;
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
        let mut extensions = 0;
        if caps.mwait {
            // SAFETY: MONITOR/MWAIT and leaf 5 were checked above.
            let (_, _, ext, sub_states) = unsafe { cpuid(5, 0) };
            extensions = ext;
            caps.interrupt_break = ext & 3 == 3;
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
        // Linux `early_init_intel`: Goldmont and Lunar Lake M may miss the
        // monitor write; Dunnington and Nehalem-/Westmere-EX need CLFLUSH.
        caps.monitor_bug = intel && family == 6 && caps.mwait && matches!(model, 0x5c | 0xbd);
        caps.clflush_monitor = intel && family == 6 && matches!(model, 0x1d | 0x2e | 0x2f);
        // Linux `init_amd_k8`/`init_amd_gh`: erratum 400 parts may stop the
        // APIC timer in C1E. Linux confirms with an MSR before falling back to
        // HALT; without that probe, these legacy parts stay on HALT.
        let amd_e400 = amd
            && match family {
                0xf => model > 0x41 || (model == 0x41 && stepping >= 2),
                0x10 => model > 0x2 || (model == 0x2 && stepping >= 1),
                _ => false,
            };
        caps.mwait_c1 = prefer_mwait_c1_over_halt(
            caps.mwait,
            caps.monitor_bug || amd_e400,
            extensions,
            caps.sub_states,
        );
        caps
    }

    pub fn supports(self, entry: IdleEntry) -> bool {
        match entry {
            IdleEntry::Poll | IdleEntry::Halt => true,
            IdleEntry::MwaitIdle => self.mwait_c1,
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

    /// Whether `entry` is a polling idle on this CPU: a store to the monitored
    /// word ends it, so a waker may skip the interrupt (Linux sets
    /// `TIF_POLLING_NRFLAG` across `mwait_idle` and `mwait_idle_with_hints`
    /// unless `X86_BUG_MONITOR`, and across `poll_idle`).
    pub fn polls(self, entry: IdleEntry) -> bool {
        match entry {
            IdleEntry::Poll => true,
            IdleEntry::MwaitIdle | IdleEntry::Mwait { .. } => !self.monitor_bug,
            _ => false,
        }
    }
}

/// Linux `prefer_mwait_c1_over_halt` (arch/x86/kernel/process.c): MWAIT is
/// enumerated, neither the MONITOR bug nor the AMD C1E APIC bug applies, and
/// either MWAIT extensions are absent (EAX=0/ECX=0 is then always valid) or
/// CPUID.05H:EDX enumerates at least one C1 sub-state. Under a hypervisor
/// that hides CPUID.01H:ECX[3] this is false and HALT stays the C1 entry.
pub fn prefer_mwait_c1_over_halt(mwait: bool, bug: bool, ecx5: u32, edx5: u32) -> bool {
    if !mwait || bug {
        return false;
    }
    if ecx5 & CPUID5_ECX_EXTENSIONS_SUPPORTED == 0 {
        return true;
    }
    edx5 & MWAIT_C1_SUBSTATE_MASK != 0
}

#[repr(align(64))]
struct MonitorLine(AtomicU8);
static MONITORS: [MonitorLine; narf_lib::percpu::MAX_CPUS] =
    [const { MonitorLine(AtomicU8::new(0)) }; narf_lib::percpu::MAX_CPUS];

/// Arm the monitor on `address`, with the CLFLUSH workaround when needed.
///
/// # Safety
/// MONITOR is enumerated on this CPU and `address` stays mapped write-back.
#[inline(always)]
unsafe fn arm_monitor(address: *const u8, clflush: bool) {
    if clflush {
        compiler_fence(Ordering::SeqCst);
        // SAFETY: CLFLUSH of a mapped kernel line; fenced on both sides as
        // Linux does (`mb(); clflush(); mb()`).
        unsafe {
            core::arch::asm!("mfence", "clflush [{0}]", "mfence", in(reg) address,
                options(nostack, preserves_flags));
        }
        compiler_fence(Ordering::SeqCst);
    }
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller contract.
    unsafe {
        core::arch::asm!("monitor", in("rax") address, in("rcx") 0u32,
            in("rdx") 0u32, options(nostack, preserves_flags));
    }
    compiler_fence(Ordering::SeqCst);
}

/// # Safety
/// The entry must have passed this CPU's `CpuIdleCaps::supports`. The caller
/// holds no locks, has completed its wake check, and has IRQs masked. Pending
/// interrupts break MWAIT even with IF=0. Returns with IRQs still masked.
pub unsafe fn enter(entry: IdleEntry) {
    let cpu = narf_lib::percpu::current_cpu();
    let line = &MONITORS[cpu.min(narf_lib::percpu::MAX_CPUS - 1)].0;
    // SAFETY: caller contract. Nothing writes the private line, so only an
    // interrupt ends the wait, as for HALT.
    unsafe { enter_on(entry, line.as_ptr().cast_const(), &|| true) };
}

/// Polling entry: monitor `word` and wait only while it still holds `armed`.
/// A store by another CPU ends the wait without an interrupt — Linux
/// `mwait_idle`: `__monitor(&ti->flags)`, recheck `need_resched()`, then
/// `__sti_mwait`/`__mwait`.
///
/// # Safety
/// As [`enter`]; additionally `entry` must be one for which
/// [`CpuIdleCaps::polls`] holds, and `word` must be a permanently mapped
/// per-CPU line owned by the caller's wake protocol.
pub unsafe fn enter_monitored(entry: IdleEntry, word: &AtomicU32, armed: u32) {
    // SAFETY: caller contract; the recheck runs after MONITOR is armed.
    unsafe {
        enter_on(entry, word.as_ptr().cast_const().cast(), &|| {
            word.load(Ordering::Acquire) == armed
        })
    };
}

/// # Safety
/// As [`enter`]. `still_idle` is evaluated after MONITOR is armed.
unsafe fn enter_on(entry: IdleEntry, address: *const u8, still_idle: &dyn Fn() -> bool) {
    let clflush = CLFLUSH_MONITOR.load(Ordering::Relaxed);
    match entry {
        IdleEntry::Mwait { hint } => {
            // SAFETY: capability validation includes extensions and interrupt
            // break support; the monitored line remains allocated permanently.
            unsafe { arm_monitor(address, clflush) };
            if still_idle() {
                compiler_fence(Ordering::SeqCst);
                // SAFETY: ECX[0]=1 lets a pending interrupt break MWAIT with
                // IF=0, so the caller's masked wake check is not raced.
                unsafe {
                    core::arch::asm!("mwait", in("rax") hint, in("rcx") 1u32,
                        options(nostack));
                }
                compiler_fence(Ordering::SeqCst);
            }
        }
        IdleEntry::MwaitIdle => {
            // SAFETY: `prefer_mwait_c1_over_halt` held on this CPU.
            unsafe { arm_monitor(address, clflush) };
            if still_idle() {
                compiler_fence(Ordering::SeqCst);
                // SAFETY: Linux `__sti_mwait(0, 0)`: the STI shadow covers
                // MWAIT, so an interrupt pending since the caller's masked
                // wake check still ends the wait. EAX=0/ECX=0 is valid with
                // or without MWAIT extensions. Returns with IF=0.
                unsafe {
                    core::arch::asm!("sti", "mwait", "cli", in("rax") 0u32, in("rcx") 0u32,
                        options(nostack));
                }
                compiler_fence(Ordering::SeqCst);
            }
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

/// Mirror of this boot's `X86_BUG_CLFLUSH_MONITOR`, published by
/// `refresh_states` on every CPU that probes it (a per-model property, so all
/// CPUs agree).
static CLFLUSH_MONITOR: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub(crate) fn note_caps(caps: CpuIdleCaps) {
    if caps.clflush_monitor {
        CLFLUSH_MONITOR.store(true, Ordering::Relaxed);
    }
}
