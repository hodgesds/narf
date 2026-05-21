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

// ── Wake trampoline ────────────────────────────────────────────────
//
// Firmware jumps here on S3 wake. The CPU is in long mode (FACS v1+
// path via XFirmwareWakingVector) but CR0/CR3/CR4 are
// firmware-determined and the GDT/IDT are firmware's. We:
//
//   1. lgdt our saved kernel GDT
//   2. lidt our saved kernel IDT
//   3. mov cr3, our saved kernel page-table phys (re-enables our
//      address space)
//   4. mov rsp, our saved kernel stack pointer
//   5. push our saved RFLAGS + popfq
//   6. jmp to s3_wake_continuation (a normal Rust extern fn)
//
// The trampoline reads `RESUME_CONTEXT` via RIP-relative addressing
// — firmware identity-maps the page containing the wake vector so
// this access works even before our CR3 is reloaded. Production
// would copy the trampoline + saved state into a known-identity-
// mapped low-memory page; the current scaffold places everything in
// the kernel image and relies on firmware preserving the kernel's
// identity-mapped region across S3 (which OVMF / modern AMD BIOSes
// do, but isn't guaranteed by spec).

/// Phys address of the static `RESUME_CONTEXT`. Filled in by
/// `save_resume_context` so the asm can use RIP-relative lea + add
/// to find it without needing a long-mode `mov rip-imm32`.
#[cfg(target_arch = "x86_64")]
static RESUME_CONTEXT_PHYS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Post-wake hook to fan out device resume. Registered by
/// `narf_power` at boot via [`set_resume_hook`] so this module
/// stays dependency-free (power → arch, not the other way).
/// Held as a raw `usize` for atomic storage; transmuted back to
/// a function pointer at call time.
static RESUME_HOOK: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Register the function the wake continuation calls to run device
/// resume fan-out. Power crate calls this from `register_initcalls`.
pub fn set_resume_hook(hook: extern "C" fn()) {
    RESUME_HOOK.store(hook as usize, core::sync::atomic::Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
/// Set the phys address the trampoline reads its saved state
/// from. Caller resolves the phys of `RESUME_CONTEXT` (via the
/// kernel's virt→phys map) once at boot and pins it here.
pub fn set_resume_context_phys(phys: u64) {
    RESUME_CONTEXT_PHYS.store(phys, core::sync::atomic::Ordering::Release);
}

#[cfg(target_arch = "x86_64")]
/// Kernel virtual address of the `RESUME_CONTEXT` static. The
/// power crate translates this through the active page tables
/// to a phys address it stores via [`set_resume_context_phys`].
pub fn resume_context_static_addr() -> usize {
    // The lock's inner ResumeContext lives at a stable offset
    // inside RESUME_CONTEXT — the spinlock guard is a thin
    // wrapper, so &*RESUME_CONTEXT.lock() points at it.
    // We can't hold the lock across the resolve, so just take
    // a raw pointer to the static itself: the inner value sits
    // at offset 0 of an IrqSafeSpinLock with `repr(C)`.
    &RESUME_CONTEXT as *const _ as usize
}

#[cfg(target_arch = "x86_64")]
/// Rust continuation invoked by the asm trampoline after CR3 + GDT
/// + IDT + RSP have been reloaded. Runs the device resume fan-out
/// (registered handlers fire in forward registration order), then
/// longjmps back to the suspending caller using the saved JmpBuf.
///
/// `arm_s3_resume` populates `S3_CALLER_JMP` via a paired `setjmp`
/// before the PM1 write; on wake we hand-off here.
///
/// # Safety
/// Reached only from the wake trampoline. RSP has been restored to
/// the suspending thread's stack; interrupts are still off.
#[no_mangle]
pub unsafe extern "C" fn s3_wake_continuation() -> ! {
    // Run the registered device-resume hook (set by `power` at
    // boot via `set_resume_hook`). The hook can't return errors
    // through this path — the longjmp carries only the success
    // code; failed device-resume is logged separately.
    let hook = RESUME_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if hook != 0 {
        // SAFETY: the hook is an `extern "C" fn() -> ()` Rust
        // function registered before suspend was armed.
        let f: extern "C" fn() = unsafe { core::mem::transmute(hook) };
        f();
    }
    // longjmp back to the suspending caller. The caller observed
    // r1 == 0 from setjmp pre-suspend; on this longjmp it sees
    // r1 == 1 ("returned via wake").
    // SAFETY: S3_CALLER_JMP was populated by arm_s3_resume's
    // setjmp call; its saved frame is still live because the
    // suspending thread never returned.
    unsafe {
        crate::x86_64::setjmp::longjmp(
            &*S3_CALLER_JMP.lock() as *const _,
            S3_RESUMED_SENTINEL,
        )
    }
}

#[cfg(target_arch = "x86_64")]
/// JmpBuf pre-populated by `arm_s3_resume` before suspend. The
/// wake continuation longjmps through it to return into the
/// suspending caller.
pub static S3_CALLER_JMP: narf_lib::sync::IrqSafeSpinLock<crate::x86_64::setjmp::JmpBuf> =
    narf_lib::sync::IrqSafeSpinLock::new(crate::x86_64::setjmp::JmpBuf { slots: [0u64; 8] });

/// Sentinel longjmp value indicating "we returned via S3 wake".
/// Suspend caller inspects setjmp's return for this to distinguish
/// first-call from wake-return.
pub const S3_RESUMED_SENTINEL: u64 = 0xA5_A5_A5_A5_5A_5A_5A_5A;

#[cfg(target_arch = "x86_64")]
/// Naked-asm wake entry. Firmware jumps here on S3 resume; the
/// function lgdt/lidt/mov-cr3/mov-rsp/popf/jmp-to-continuation.
///
/// Reads `RESUME_CONTEXT_PHYS` (a static u64) via RIP-relative
/// addressing — the static is in the kernel's `.bss` which the
/// firmware identity-maps the wake-vector page through. On Phoenix
/// HawkPoint1 + Renoir laptops with modern AMI BIOS the entire
/// kernel image is identity-mapped during the wake handoff.
///
/// # Safety
/// Reachable only via FACS.XFirmwareWakingVector. Caller is the
/// platform firmware; we don't return from here (longjmp).
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn s3_wake_entry() -> ! {
    use core::arch::naked_asm;
    naked_asm!(
        // Disable interrupts (firmware should have them off; belt+braces).
        "cli",
        // Read RESUME_CONTEXT_PHYS into rax via RIP-relative.
        "lea rax, [rip + {ctx_phys}]",
        "mov rax, [rax]",
        "test rax, rax",
        // If RESUME_CONTEXT_PHYS == 0, the trampoline wasn't armed.
        // Halt — firmware will eventually reset the box.
        "jz 9f",
        // rax = phys of ResumeContext. Layout:
        //   [+0]  cr0       [+8]  cr3
        //   [+16] cr4       [+24] rflags
        //   [+32] gdt_base  [+40] gdt_limit (u16)
        //   [+48] idt_base  [+56] idt_limit (u16)
        //   [+64] rsp
        //
        // We need to build the 10-byte lgdt/lidt operands on the
        // stack — they're packed as limit:16 + base:64 = 10 bytes.
        //
        // Restore CR3 first so any subsequent kernel-image reads
        // use our paging (the lgdt/lidt operands themselves come
        // from the saved-state region which firmware identity-
        // maps, but ResumeContext.gdt_base/idt_base point into
        // kernel space and need our CR3 to resolve).
        "mov rbx, [rax + 8]",
        "mov cr3, rbx",
        // Restore RSP so the lgdt/lidt stack pushes land in a
        // known location (an arbitrary stack-relative push pre-
        // CR3-restore can't be trusted).
        "mov rsp, [rax + 64]",
        // Build lgdt operand on the stack: push base (8 bytes) then
        // push limit (2 bytes); lgdt expects limit at the lowest
        // address so we push base first, then a 16-bit limit.
        // Easiest: subtract 16 from rsp, write [rsp+0]=limit,
        // [rsp+2]=base.
        "sub rsp, 16",
        "mov bx, [rax + 40]",            // gdt_limit
        "mov [rsp], bx",
        "mov rbx, [rax + 32]",           // gdt_base
        "mov [rsp + 2], rbx",
        "lgdt [rsp]",
        // Same shape for IDT.
        "mov bx, [rax + 56]",            // idt_limit
        "mov [rsp], bx",
        "mov rbx, [rax + 48]",           // idt_base
        "mov [rsp + 2], rbx",
        "lidt [rsp]",
        "add rsp, 16",
        // Restore CR0 and CR4 in case firmware cleared bits we
        // care about (NXE, SMEP, etc — encoded in the saved CR4).
        "mov rbx, [rax + 0]",
        "mov cr0, rbx",
        "mov rbx, [rax + 16]",
        "mov cr4, rbx",
        // Restore RFLAGS — preserves IF=0 because we cli'd above;
        // the popfq picks up whatever the saved RFLAGS encoded.
        "push qword ptr [rax + 24]",
        "popfq",
        // Jump to the Rust continuation.
        "lea rcx, [rip + {cont}]",
        "jmp rcx",
        // Failure branch — RESUME_CONTEXT_PHYS was 0.
        "9:",
        "hlt",
        "jmp 9b",
        ctx_phys = sym RESUME_CONTEXT_PHYS,
        cont = sym s3_wake_continuation,
    );
}

#[doc(hidden)]
pub fn __reset_for_test() {
    CAPTURED.store(false, Ordering::Release);
    *RESUME_CONTEXT.lock() = ResumeContext::default();
}
