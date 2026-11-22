//! aarch64 hibernation (S4): Linux's `swsusp_arch_suspend`,
//! `swsusp_arch_suspend_exit` and `_cpu_resume` (`arch/arm64/kernel/
//! hibernate.c`, `hibernate-asm.S`), reduced to what NARF's EL1 needs.
//!
//! - [`s4_save`] stores the callee-saved registers, the stack, the link
//!   register and the EL1 system state in [`S4_CONTEXT`] and returns 0, like
//!   `setjmp`. The restored image comes back out of it with 1.
//! - [`jump`] runs in the boot kernel. It points TTBR0 at a temporary
//!   table that identity-maps RAM, executable at EL1, and branches to the
//!   relocated [`copy_loop`] there. TTBR1, where the boot kernel runs, is
//!   untouched until the loop is done.
//! - The loop copies every page to its original frame, using no stack. It
//!   cleans each destination to the Point of Unification (instructions live
//!   there) and invalidates the instruction caches. It then installs the
//!   image's TTBR1, flushes the TLB, and branches to [`s4_wake_entry`] at its
//!   virtual address.
//! - The wake entry reloads the saved system registers (TCR, MAIR, TTBR0,
//!   SCTLR, VBAR, the thread pointers, SP_EL0, CPACR, CNTKCTL, MDSCR,
//!   CONTEXTIDR, DAIF), then the stack and the callee-saved registers, and
//!   returns 1 from [`s4_save`].

use core::cell::UnsafeCell;

/// The state [`s4_save`] stores and [`s4_wake_entry`] reloads.
#[repr(C)]
#[derive(Debug)]
pub struct S4Context {
    /// x19..=x30.
    pub gprs: [u64; 12],
    pub sp: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub tcr: u64,
    pub mair: u64,
    pub sctlr: u64,
    pub vbar: u64,
    pub tpidr_el1: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub sp_el0: u64,
    pub cpacr: u64,
    pub cntkctl: u64,
    pub mdscr: u64,
    pub contextidr: u64,
    pub daif: u64,
}

/// One CPU saves, with interrupts masked; the asm is the only accessor.
pub struct ContextCell(UnsafeCell<S4Context>);
// SAFETY: written only by `s4_save` on the CPU taking the snapshot, read
// only by `s4_wake_entry` in the image restored from it.
unsafe impl Sync for ContextCell {}

impl ContextCell {
    /// The saved context, for diagnostics; only the asm writes it.
    pub fn as_ptr(&self) -> *mut S4Context {
        self.0.get()
    }
}

impl core::fmt::Debug for ContextCell {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ContextCell")
    }
}

#[unsafe(no_mangle)]
pub static S4_CONTEXT: ContextCell = ContextCell(UnsafeCell::new(S4Context {
    gprs: [0; 12],
    sp: 0,
    ttbr0: 0,
    ttbr1: 0,
    tcr: 0,
    mair: 0,
    sctlr: 0,
    vbar: 0,
    tpidr_el1: 0,
    tpidr_el0: 0,
    tpidrro_el0: 0,
    sp_el0: 0,
    cpacr: 0,
    cntkctl: 0,
    mdscr: 0,
    contextidr: 0,
    daif: 0,
}));

const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(S4Context, sp) == 96);
    assert!(offset_of!(S4Context, ttbr0) == 104);
    assert!(offset_of!(S4Context, tcr) == 120);
    assert!(offset_of!(S4Context, mair) == 128);
    assert!(offset_of!(S4Context, sctlr) == 136);
    assert!(offset_of!(S4Context, vbar) == 144);
    assert!(offset_of!(S4Context, tpidr_el1) == 152);
    assert!(offset_of!(S4Context, tpidr_el0) == 160);
    assert!(offset_of!(S4Context, tpidrro_el0) == 168);
    assert!(offset_of!(S4Context, sp_el0) == 176);
    assert!(offset_of!(S4Context, cpacr) == 184);
    assert!(offset_of!(S4Context, cntkctl) == 192);
    assert!(offset_of!(S4Context, mdscr) == 200);
    assert!(offset_of!(S4Context, contextidr) == 208);
    assert!(offset_of!(S4Context, daif) == 216);
};

/// Save the state the image resumes into. Returns 0 now and 1 in the
/// restored image.
///
/// # Safety
/// Interrupts are masked on the only CPU running. The caller's frame stays
/// live until the snapshot is taken; the restore returns into it. Like
/// `setjmp`, only callee-saved registers and memory survive the second
/// return.
#[unsafe(naked)]
pub unsafe extern "C" fn s4_save() -> u64 {
    core::arch::naked_asm!(
        "adrp x9, {ctx}",
        "add x9, x9, :lo12:{ctx}",
        "stp x19, x20, [x9, #0]",
        "stp x21, x22, [x9, #16]",
        "stp x23, x24, [x9, #32]",
        "stp x25, x26, [x9, #48]",
        "stp x27, x28, [x9, #64]",
        "stp x29, x30, [x9, #80]",
        "mov x10, sp",
        "str x10, [x9, #96]",
        "mrs x10, ttbr0_el1",
        "str x10, [x9, #104]",
        "mrs x10, ttbr1_el1",
        "str x10, [x9, #112]",
        "mrs x10, tcr_el1",
        "str x10, [x9, #120]",
        "mrs x10, mair_el1",
        "str x10, [x9, #128]",
        "mrs x10, sctlr_el1",
        "str x10, [x9, #136]",
        "mrs x10, vbar_el1",
        "str x10, [x9, #144]",
        "mrs x10, tpidr_el1",
        "str x10, [x9, #152]",
        "mrs x10, tpidr_el0",
        "str x10, [x9, #160]",
        "mrs x10, tpidrro_el0",
        "str x10, [x9, #168]",
        "mrs x10, sp_el0",
        "str x10, [x9, #176]",
        "mrs x10, cpacr_el1",
        "str x10, [x9, #184]",
        "mrs x10, cntkctl_el1",
        "str x10, [x9, #192]",
        "mrs x10, mdscr_el1",
        "str x10, [x9, #200]",
        "mrs x10, contextidr_el1",
        "str x10, [x9, #208]",
        "mrs x10, daif",
        "str x10, [x9, #216]",
        "mov x0, #0",
        "ret",
        ctx = sym S4_CONTEXT,
    )
}

/// The restored image's entry, at its virtual address under its own TTBR1,
/// with the boot kernel's temporary identity table still in TTBR0. Returns
/// 1 from [`s4_save`].
///
/// # Safety
/// Reached only from the copy loop, interrupts masked, with every image
/// page in place.
#[unsafe(naked)]
pub unsafe extern "C" fn s4_wake_entry() -> ! {
    core::arch::naked_asm!(
        "adrp x9, {ctx}",
        "add x9, x9, :lo12:{ctx}",
        "ldr x10, [x9, #120]",
        "msr tcr_el1, x10",
        "ldr x10, [x9, #128]",
        "msr mair_el1, x10",
        "isb",
        "ldr x10, [x9, #104]",
        "msr ttbr0_el1, x10",
        "isb",
        "tlbi vmalle1",
        "dsb ish",
        "isb",
        "ldr x10, [x9, #136]",
        "msr sctlr_el1, x10",
        "isb",
        "ldr x10, [x9, #144]",
        "msr vbar_el1, x10",
        "ldr x10, [x9, #152]",
        "msr tpidr_el1, x10",
        "ldr x10, [x9, #160]",
        "msr tpidr_el0, x10",
        "ldr x10, [x9, #168]",
        "msr tpidrro_el0, x10",
        "ldr x10, [x9, #176]",
        "msr sp_el0, x10",
        "ldr x10, [x9, #184]",
        "msr cpacr_el1, x10",
        "ldr x10, [x9, #192]",
        "msr cntkctl_el1, x10",
        "ldr x10, [x9, #200]",
        "msr mdscr_el1, x10",
        "ldr x10, [x9, #208]",
        "msr contextidr_el1, x10",
        "isb",
        "ldp x19, x20, [x9, #0]",
        "ldp x21, x22, [x9, #16]",
        "ldp x23, x24, [x9, #32]",
        "ldp x25, x26, [x9, #48]",
        "ldp x27, x28, [x9, #64]",
        "ldp x29, x30, [x9, #80]",
        "ldr x10, [x9, #96]",
        "mov sp, x10",
        "ldr x10, [x9, #216]",
        "msr daif, x10",
        "mov x0, #1",
        "ret",
        ctx = sym S4_CONTEXT,
    )
}

// The copy loop. Position-independent: relative branches only, no data. It
// is entered under the identity map with x0 = the first restore-list page
// (physical), x1 = the image's wake entry (virtual) and x2 = the image's
// TTBR1. The list layout is the x86_64 one: next, count, then (copy,
// original) physical pairs.
core::arch::global_asm!(
    ".pushsection .text.narf_s4_restore,\"ax\"",
    ".global narf_s4_a64_copy_loop",
    "narf_s4_a64_copy_loop:",
    // No TTBR1 walks while the copy may overwrite the boot kernel's tables
    // under it: TCR_EL1.EPD1 (bit 23). The loop runs in TTBR0 alone.
    "mrs x14, tcr_el1",
    "orr x14, x14, #(1 << 23)",
    "msr tcr_el1, x14",
    "isb",
    // The data cache line size, for the clean to PoU.
    "mrs x12, ctr_el0",
    "ubfx x12, x12, #16, #4",
    "mov x13, #4",
    "lsl x13, x13, x12",
    "2:",
    "cbz x0, 6f",
    "ldr x3, [x0, #8]",
    "add x4, x0, #16",
    "3:",
    "cbz x3, 5f",
    "ldp x5, x6, [x4], #16",
    "mov x7, x6",
    "mov x8, #4096",
    "4:",
    "ldp x10, x11, [x5], #16",
    "stp x10, x11, [x6], #16",
    "subs x8, x8, #16",
    "b.ne 4b",
    // Clean the copy to PoU: the image's text is among the pages.
    "add x8, x7, #4096",
    "7:",
    "dc cvau, x7",
    "add x7, x7, x13",
    "cmp x7, x8",
    "b.lo 7b",
    "sub x3, x3, #1",
    "b 3b",
    "5:",
    "ldr x0, [x0]",
    "b 2b",
    "6:",
    "dsb ish",
    "ic ialluis",
    "dsb ish",
    "isb",
    // The image's kernel half, walks back on, then the image.
    "msr ttbr1_el1, x2",
    "bic x14, x14, #(1 << 23)",
    "msr tcr_el1, x14",
    "isb",
    "tlbi vmalle1",
    "dsb ish",
    "isb",
    "br x1",
    ".global narf_s4_a64_copy_loop_end",
    "narf_s4_a64_copy_loop_end:",
    ".popsection",
);

unsafe extern "C" {
    static narf_s4_a64_copy_loop: u8;
    static narf_s4_a64_copy_loop_end: u8;
}

/// The copy loop's code, to be copied into a safe page.
pub fn copy_loop() -> &'static [u8] {
    // SAFETY: both symbols bound the loop in one text section.
    unsafe {
        let start = &raw const narf_s4_a64_copy_loop;
        let end = &raw const narf_s4_a64_copy_loop_end;
        core::slice::from_raw_parts(start, end as usize - start as usize)
    }
}

/// Point TTBR0 at `temp_ttbr0` and branch to the relocated copy loop at
/// `loop_phys` (its identity address).
///
/// # Safety
/// Interrupts are masked on the only CPU running. `temp_ttbr0` identity-maps
/// all RAM, executable at EL1. `loop_phys` holds [`copy_loop`], cleaned to
/// PoU with the instruction cache invalidated. The restore list, the loop
/// and the table are in frames no pair writes. Nothing returns.
pub unsafe fn jump(
    temp_ttbr0: u64,
    loop_phys: u64,
    first_page_phys: u64,
    entry_virt: u64,
    image_ttbr1: u64,
) -> ! {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the caller's contract. The boot kernel keeps running in TTBR1
    // until the branch.
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {t0}",
            "isb",
            "tlbi vmalle1",
            "dsb ish",
            "isb",
            "br {lp}",
            t0 = in(reg) temp_ttbr0,
            lp = in(reg) loop_phys,
            in("x0") first_page_phys,
            in("x1") entry_virt,
            in("x2") image_ttbr1,
            options(noreturn),
        )
    }
}
