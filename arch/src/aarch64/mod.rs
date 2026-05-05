//! aarch64 arch backend.

pub mod asm;
pub mod brbe;
pub mod bti;
pub mod cache;
pub mod cpu;
pub mod cpuid;
pub mod ete;
pub mod gcs;
pub mod ident;
pub mod mmio;
pub mod mpam;
pub mod mte;
pub mod pac;
pub mod psci;
pub mod rndr;
pub mod spe;
pub mod ssbs;
pub mod sve;
pub mod sysreg;
pub mod timer;
pub mod trbe;

pub use asm::{halt_forever, disable_interrupts, enable_interrupts, cas128, patch_word};
pub use cpuid::Features;
pub use mte::Mte;

/// Exit QEMU via ARM semihosting `SYS_EXIT`. Falls back to `halt_forever`
/// if semihosting isn't enabled.
///
/// # Safety
/// HLT #0xF000 traps to the semihosting handler; safe in a QEMU guest
/// with `-semihosting` enabled. No effect on real hardware beyond the
/// trap.
pub unsafe fn exit_qemu(code: u32) -> ! {
    use core::arch::asm;
    // ARM semihosting: W0 = SYS_EXIT (0x18), X1 = &(reason, subcode);
    // but the simpler SYS_EXIT_EXTENDED (0x20) takes reason + exit code.
    // Parameter block on the stack:
    //   [0] = ADP_Stopped_ApplicationExit = 0x20026
    //   [8] = exit code
    let params: [u64; 2] = [0x20026, code as u64];
    // SAFETY: HLT #0xF000 in EL1 traps into QEMU's semihosting if
    // `-semihosting` is supplied; otherwise it's an UNDEFINED that
    // traps to our (absent) exception vector — hence halt_forever
    // as fallback.
    unsafe {
        asm!(
            "mov x0, #0x20",            // SYS_EXIT_EXTENDED
            "mov x1, {params}",
            "hlt #0xF000",
            params = in(reg) params.as_ptr(),
            out("x0") _,
            out("x1") _,
            options(nostack),
        );
    }
    halt_forever()
}
