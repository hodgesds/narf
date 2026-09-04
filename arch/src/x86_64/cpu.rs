//! CPU-identity primitive.
//!
//! `current_cpu()` returns the executing logical-CPU index in the
//! range `[0, MAX_CPUS)`. Used as the index into `PerCpu<T>` arrays.
//!
//! Implementation strategy:
//!
//! - **x86_64 with RDPID** (Intel Ice Lake / AMD Zen 2+): direct,
//!   non-serializing read of the IA32_TSC_AUX MSR's low 32 bits.
//! - **x86_64 with RDTSCP** (universal since Nehalem / Bulldozer):
//!   reads TSC + IA32_TSC_AUX in one instruction; we discard the
//!   TSC and keep the aux. The aux MSR is loaded by the boot path
//!   with the CPU's logical id when the AP comes up — until then
//!   it reads zero, which is the BSP-only correct answer.
//! - **Pre-RDTSCP fallback**: read CPUID.01h:EBX[31:24] for the
//!   initial APIC id. Slow (CPUID is serializing); only used as a
//!   compile-time-disabled fallback.
//!
//! AP bring-up writes each CPU's logical id into IA32_TSC_AUX before it
//! can enter the scheduler. RDPID and RDTSCP therefore return the same
//! identity cookie; RDPID is preferred because CPU identity does not need
//! RDTSCP's ordering or timestamp result.

use core::arch::asm;

/// Maximum number of logical CPUs the kernel ever supports. Sized
/// for high-end commodity hardware (sapphire-rapids tops out at
/// 60 hyperthreads / socket; we leave room for dual-socket plus
/// aarch64 server parts).
pub const MAX_CPUS: usize = 64;

/// Cached instruction used to read IA32_TSC_AUX. Set on first call.
///
/// 0 = unknown (probe needed), 1 = no reader, 2 = RDTSCP, 3 = RDPID.
static CPU_ID_READER: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

const READER_NONE: u8 = 1;
const READER_RDTSCP: u8 = 2;
const READER_RDPID: u8 = 3;

#[inline]
const fn select_cpu_id_reader(has_rdpid: bool, has_rdtscp: bool) -> u8 {
    if has_rdpid {
        READER_RDPID
    } else if has_rdtscp {
        READER_RDTSCP
    } else {
        READER_NONE
    }
}

#[inline(never)]
fn probe_cpu_id_reader() -> u8 {
    // CPUID.(EAX=07H,ECX=0):ECX[22] = RDPID.
    // CPUID.80000001h:EDX[27] = RDTSCP.
    // SAFETY: __cpuid is always legal at CPL=0.
    let max_basic = unsafe { core::arch::x86_64::__cpuid(0) }.eax;
    let has_rdpid = if max_basic >= 7 {
        // SAFETY: max_basic proves structured-feature leaf 7 exists.
        unsafe { core::arch::x86_64::__cpuid_count(7, 0) }.ecx & (1u32 << 22) != 0
    } else {
        false
    };
    // SAFETY: extended-leaf maximum query is always legal at CPL=0.
    let max_extended = unsafe { core::arch::x86_64::__cpuid(0x8000_0000) }.eax;
    let has_rdtscp = if max_extended >= 0x8000_0001 {
        // SAFETY: max_extended proves extended feature leaf 80000001H exists.
        unsafe { core::arch::x86_64::__cpuid(0x8000_0001) }.edx & (1u32 << 27) != 0
    } else {
        false
    };
    select_cpu_id_reader(has_rdpid, has_rdtscp)
}

/// Return the executing CPU's logical index from the IA32_TSC_AUX value
/// populated by BSP/AP bring-up.
///
/// Prefers RDPID, falls back to RDTSCP, and returns 0 (the BSP) on CPU
/// models that implement neither instruction.
///
/// # Safety
/// Reading TSC_AUX is always defined at CPL=0; the function is safe
/// to call from any context.
#[inline]
pub fn current_cpu() -> u32 {
    use core::sync::atomic::Ordering;
    let state = match CPU_ID_READER.load(Ordering::Acquire) {
        0 => {
            let reader = probe_cpu_id_reader();
            CPU_ID_READER.store(reader, Ordering::Release);
            reader
        }
        reader => reader,
    };
    if state == READER_RDPID {
        let aux: u64;
        // SAFETY: CPUID advertised RDPID. IA32_TSC_AUX is initialized by
        // BSP/AP bring-up before scheduler-visible per-CPU access.
        unsafe {
            asm!(
                "rdpid {aux}",
                aux = out(reg) aux,
                options(nomem, nostack, preserves_flags),
            );
        }
        return aux as u32;
    }
    if state == READER_RDTSCP {
        let aux: u32;
        let _hi: u32;
        let _lo: u32;
        // SAFETY: CPUID advertised RDTSCP.
        unsafe {
            asm!(
                "rdtscp",
                out("eax") _lo,
                out("edx") _hi,
                out("ecx") aux,
                options(nomem, nostack, preserves_flags),
            );
        }
        return aux;
    }
    // BSP fallback for CPUs without either TSC_AUX reader. SMP bring-up on
    // such hardware still needs a CPUID-leaf-0Bh logical-id fallback.
    0
}

/// Set the calling CPU's id (low 32 bits of IA32_TSC_AUX).
///
/// # Safety
/// Must run on the CPU whose id is being set, exactly once during
/// AP bring-up. The kernel reads TSC_AUX as the per-CPU index and
/// must never see stale or duplicate values.
#[inline]
pub unsafe fn set_current_cpu(id: u32) {
    use crate::x86_64::msr::wrmsr;
    // IA32_TSC_AUX = 0xC0000103.
    // SAFETY: caller asserts this is the post-AP-startup write
    // for the executing CPU.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        wrmsr(0xC000_0103, id as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_id_reader_prefers_rdpid_then_rdtscp() {
        assert_eq!(select_cpu_id_reader(true, true), READER_RDPID);
        assert_eq!(select_cpu_id_reader(true, false), READER_RDPID);
        assert_eq!(select_cpu_id_reader(false, true), READER_RDTSCP);
        assert_eq!(select_cpu_id_reader(false, false), READER_NONE);
    }
}
