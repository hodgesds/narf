//! x86_64 S3 resume context save/restore.
//!
//! On S3 entry the CPU loses CR0/CR3/CR4/RFLAGS, the GDT and IDT
//! registers, and every general-purpose register. On wake the
//! platform firmware jumps to FACS.XFirmwareWakingVector (or
//! the legacy 32-bit FirmwareWakingVector) in long mode with
//! firmware-determined paging.
//!
//! The resume path is:
//!
//!   1. Pre-suspend: save_resume_context() captures the kernel's
//!      CR3 + GDTR + IDTR + RSP into a static struct in identity-
//!      mapped memory.
//!   2. Suspend: `acpi::arm_s3_waking_vector(s3_wake_entry)` tells
//!      the firmware where to jump on wake.
//!   3. Wake: firmware enters `s3_wake_entry`. The entry needs to
//!      be `extern "C" naked` with hand-written asm that:
//!        a. Loads the saved GDTR (lgdt)
//!        b. Loads the saved IDTR (lidt)
//!        c. Loads CR3 with the saved kernel page table phys
//!        d. Loads RSP from the saved kernel stack pointer
//!        e. Re-enters the high-half kernel via jmp to a Rust
//!           continuation function.
//!   4. Rust continuation: calls power::resume_all_devices() and
//!      returns to the suspending thread (longjmp-style).
//!
//! This module owns step (1) and the static struct that holds the
//! captured state. Step (3) is a naked asm trampoline that
//! lives in step (4)'s extern function — currently a stub that
//! will be filled in once the rest of the suspend integration
//! settles (the asm depends on layout constants that the linker
//! script may need to expose).

use core::sync::atomic::{AtomicBool, Ordering};

/// Captured pre-suspend CPU state. All fields are zero pre-capture;
/// `save_resume_context` fills them in.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ResumeContext {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub rflags: u64,
    /// GDT base + limit packed as the 80-bit `lgdt` operand
    /// expects: bits[15:0] = limit; bits[79:16] = base. We
    /// surface the 64-bit base + 16-bit limit separately for
    /// the Rust API and re-pack at restore time.
    pub gdt_base: u64,
    pub gdt_limit: u16,
    /// IDT base + limit, same shape as the GDT pair.
    pub idt_base: u64,
    pub idt_limit: u16,
    /// Kernel-stack pointer the resume trampoline jumps back to.
    pub rsp: u64,
}

#[cfg(target_arch = "x86_64")]
static RESUME_CONTEXT: narf_lib::sync::IrqSafeSpinLock<ResumeContext> =
    narf_lib::sync::IrqSafeSpinLock::new(ResumeContext {
        cr0: 0,
        cr3: 0,
        cr4: 0,
        rflags: 0,
        gdt_base: 0,
        gdt_limit: 0,
        idt_base: 0,
        idt_limit: 0,
        rsp: 0,
    });

/// True once `save_resume_context` has run on this boot.
static CAPTURED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
/// Snapshot the current CPU state so the resume trampoline can
/// reload it on wake. Called from the suspend phase machinery
/// right before the PM1 SLP_TYP|SLP_EN write.
///
/// # Safety
/// Caller is on the boot CPU with interrupts gated. The function
/// reads CR0/CR3/CR4/GDTR/IDTR/RSP/RFLAGS — these are
/// privileged-mode reads on x86_64.
pub unsafe fn save_resume_context() {
    let mut cr0: u64;
    let mut cr3: u64;
    let mut cr4: u64;
    let mut rflags: u64;
    let mut rsp: u64;
    let mut gdt: [u8; 10] = [0u8; 10];
    let mut idt: [u8; 10] = [0u8; 10];
    // SAFETY: reading control / system registers in CPL 0.
    unsafe {
        core::arch::asm!(
            "mov {0}, cr0",
            "mov {1}, cr3",
            "mov {2}, cr4",
            "pushfq",
            "pop {3}",
            "mov {4}, rsp",
            "sgdt [{5}]",
            "sidt [{6}]",
            out(reg) cr0,
            out(reg) cr3,
            out(reg) cr4,
            out(reg) rflags,
            out(reg) rsp,
            in(reg) gdt.as_mut_ptr(),
            in(reg) idt.as_mut_ptr(),
        );
    }
    let gdt_limit = u16::from_le_bytes([gdt[0], gdt[1]]);
    let gdt_base = u64::from_le_bytes([
        gdt[2], gdt[3], gdt[4], gdt[5], gdt[6], gdt[7], gdt[8], gdt[9],
    ]);
    let idt_limit = u16::from_le_bytes([idt[0], idt[1]]);
    let idt_base = u64::from_le_bytes([
        idt[2], idt[3], idt[4], idt[5], idt[6], idt[7], idt[8], idt[9],
    ]);
    *RESUME_CONTEXT.lock() = ResumeContext {
        cr0,
        cr3,
        cr4,
        rflags,
        gdt_base,
        gdt_limit,
        idt_base,
        idt_limit,
        rsp,
    };
    CAPTURED.store(true, Ordering::Release);
}

/// Read-only snapshot of the saved context. Diagnostic / smoke use.
pub fn captured_context() -> Option<ResumeContext> {
    if CAPTURED.load(Ordering::Acquire) {
        Some(*RESUME_CONTEXT.lock())
    } else {
        None
    }
}

/// Physical address of the s3_wake_entry stub, suitable for
/// passing to `acpi::arm_s3_waking_vector`. Currently a stub
/// returning 0 — the trampoline asm hasn't landed yet, and
/// suspend() will refuse to enter the real PM1 write without an
/// armed trampoline.
pub fn wake_entry_phys() -> u64 {
    0
}

#[doc(hidden)]
pub fn __reset_for_test() {
    CAPTURED.store(false, Ordering::Release);
    *RESUME_CONTEXT.lock() = ResumeContext::default();
}
