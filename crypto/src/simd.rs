//! Kernel use of the x86 SSE register file, for the AES-NI and SHA-NI
//! paths.
//!
//! The kernel builds soft-float and `kernel_switch` saves no XMM state. A
//! user task's FP/SIMD image is restored lazily under CR0.TS
//! (`narf_scheduler::stackful`). So while kernel code runs, `xmm0`-`xmm15`
//! either hold the current user task's live values, or TS is armed and the
//! first SSE instruction raises `#NM`, which kernel mode treats as a fault.
//! [`section`] is the one way this crate's assembly may touch them. It
//! does the job of Linux's `kernel_fpu_begin`/`kernel_fpu_end`
//! (`arch/x86/kernel/fpu/core.c`), in a different way:
//!
//! 1. Interrupts are masked for the whole section: no preemption, no
//!    migration, and nothing else on this CPU runs between the save and the
//!    restore.
//! 2. `materialize_current_user_fpu` is the scheduler's sanctioned boundary
//!    for clearing TS. It makes the user image live in the registers, or
//!    just clears TS when no user task owns them.
//! 3. `xmm0`-`xmm15` are saved to a stack buffer, `f` runs, and they are
//!    restored. Then the buffer is zeroed, so no key material is left in a
//!    register or on the stack.
//!
//! Linux saves the whole XSAVE image to the task and restores it on return
//! to user. Saving only `xmm0`-`xmm15` is enough here because every
//! instruction run inside a section is legacy-SSE encoded: those
//! instructions leave the upper YMM/ZMM bits, `xmm16`-`xmm31`, the mask
//! registers and MXCSR untouched. VEX/EVEX-encoded code (AVX, VAES) would
//! zero the upper bits and must never run in a section.
//!
//! Sections are meant to be short. Callers split long work so that
//! interrupts stay masked for tens of microseconds at most.
//!
//! Loadable modules link this crate without the `kernel` feature and have
//! no scheduler to ask, so there [`available`] is false and every caller
//! takes its portable path. Host unit tests run in user mode, where the
//! process owns its registers: the section only saves and restores them.

// A loadable module (no `kernel` feature) and aarch64 never enter a section,
// so their builds read none of this.
#![cfg_attr(
    not(all(target_arch = "x86_64", any(test, feature = "kernel"))),
    allow(dead_code)
)]

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::{AtomicU8, Ordering};

/// The SSE extensions the accelerated paths need.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Caps {
    /// AES-NI (CPUID.01H:ECX bit 25).
    pub aes: bool,
    /// SHA-NI (CPUID.(EAX=07H,ECX=0):EBX bit 29) together with SSSE3
    /// (`pshufb`, `palignr`; CPUID.01H:ECX bit 9) and SSE4.1 (`pblendw`;
    /// CPUID.01H:ECX bit 19).
    pub sha256: bool,
}

/// 0: not probed yet; otherwise 0x80 | aes | sha256 << 1.
#[cfg(target_arch = "x86_64")]
static CAPS: AtomicU8 = AtomicU8::new(0);

/// Test hook: force the portable paths even where the CPU has the
/// extensions, so both paths can be compared on one machine.
#[cfg(target_arch = "x86_64")]
static FORCE_PORTABLE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// What this CPU offers, probed once. All false where no section can be
/// entered ([`available`]).
pub(crate) fn caps() -> Caps {
    if !available() {
        return Caps::default();
    }
    #[cfg(target_arch = "x86_64")]
    {
        if FORCE_PORTABLE.load(Ordering::Relaxed) {
            return Caps::default();
        }
        let mut bits = CAPS.load(Ordering::Relaxed);
        if bits == 0 {
            bits = 0x80 | probe();
            CAPS.store(bits, Ordering::Relaxed);
        }
        Caps {
            aes: bits & 1 != 0,
            sha256: bits & 2 != 0,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    Caps::default()
}

#[cfg(target_arch = "x86_64")]
fn probe() -> u8 {
    // SAFETY: CPUID leaves 0, 1 and 7 exist on every x86_64 CPU (leaf 7 is
    // checked against the maximum leaf first). `__cpuid_count` saves and
    // restores rbx around the instruction.
    let (max_leaf, leaf1_ecx, leaf7_ebx) = unsafe {
        let max = core::arch::x86_64::__cpuid_count(0, 0).eax;
        let ecx = core::arch::x86_64::__cpuid_count(1, 0).ecx;
        let ebx = if max >= 7 {
            core::arch::x86_64::__cpuid_count(7, 0).ebx
        } else {
            0
        };
        (max, ecx, ebx)
    };
    let _ = max_leaf;
    let aes = leaf1_ecx & (1 << 25) != 0;
    let ssse3 = leaf1_ecx & (1 << 9) != 0;
    let sse41 = leaf1_ecx & (1 << 19) != 0;
    let sha = leaf7_ebx & (1 << 29) != 0;
    u8::from(aes) | (u8::from(sha && ssse3 && sse41) << 1)
}

/// Whether this build may enter a section at all: the kernel with its
/// scheduler, or a host unit test.
pub(crate) const fn available() -> bool {
    cfg!(all(target_arch = "x86_64", any(test, feature = "kernel")))
}

/// Test hook: while set, [`caps`] reports nothing, so every caller takes
/// its portable path.
#[doc(hidden)]
pub fn force_portable_for_test(on: bool) {
    #[cfg(target_arch = "x86_64")]
    FORCE_PORTABLE.store(on, Ordering::Relaxed);
    #[cfg(not(target_arch = "x86_64"))]
    let _ = on;
}

/// Sixteen saved XMM registers. 16-byte aligned for `movdqa`.
#[cfg(all(target_arch = "x86_64", any(test, feature = "kernel")))]
#[repr(C, align(16))]
struct XmmSave([u8; 256]);

/// Run `f` with `xmm0`-`xmm15` free for this crate's legacy-SSE assembly.
/// Only call it when [`caps`] reported the extension `f` uses.
#[cfg(all(target_arch = "x86_64", any(test, feature = "kernel")))]
pub(crate) fn section<R>(f: impl FnOnce() -> R) -> R {
    #[cfg(all(feature = "kernel", not(test)))]
    {
        narf_lib::sync::without_interrupts(|| {
            // Clears CR0.TS through the scheduler, keeping its mirror in
            // step, and makes the current user image live if there is one.
            let _ = narf_scheduler::stackful::materialize_current_user_fpu();
            run_saved(f)
        })
    }
    #[cfg(test)]
    {
        run_saved(f)
    }
}

#[cfg(all(target_arch = "x86_64", any(test, feature = "kernel")))]
fn run_saved<R>(f: impl FnOnce() -> R) -> R {
    let mut save = XmmSave([0; 256]);
    let p = save.0.as_mut_ptr();
    // SAFETY: `p` names 256 writable bytes, 16-byte aligned. TS is clear
    // (the kernel section materialized first; user mode never has it set),
    // so the stores cannot fault.
    unsafe {
        core::arch::asm!(
            "movdqa [{p}], xmm0",
            "movdqa [{p} + 16], xmm1",
            "movdqa [{p} + 32], xmm2",
            "movdqa [{p} + 48], xmm3",
            "movdqa [{p} + 64], xmm4",
            "movdqa [{p} + 80], xmm5",
            "movdqa [{p} + 96], xmm6",
            "movdqa [{p} + 112], xmm7",
            "movdqa [{p} + 128], xmm8",
            "movdqa [{p} + 144], xmm9",
            "movdqa [{p} + 160], xmm10",
            "movdqa [{p} + 176], xmm11",
            "movdqa [{p} + 192], xmm12",
            "movdqa [{p} + 208], xmm13",
            "movdqa [{p} + 224], xmm14",
            "movdqa [{p} + 240], xmm15",
            p = in(reg) p,
            options(nostack, preserves_flags),
        );
    }
    let r = f();
    // SAFETY: as above; every XMM register is declared clobbered, so the
    // compiler (on the host target, the only one that allocates them) keeps
    // nothing live in them across the restore.
    unsafe {
        core::arch::asm!(
            "movdqa xmm0, [{p}]",
            "movdqa xmm1, [{p} + 16]",
            "movdqa xmm2, [{p} + 32]",
            "movdqa xmm3, [{p} + 48]",
            "movdqa xmm4, [{p} + 64]",
            "movdqa xmm5, [{p} + 80]",
            "movdqa xmm6, [{p} + 96]",
            "movdqa xmm7, [{p} + 112]",
            "movdqa xmm8, [{p} + 128]",
            "movdqa xmm9, [{p} + 144]",
            "movdqa xmm10, [{p} + 160]",
            "movdqa xmm11, [{p} + 176]",
            "movdqa xmm12, [{p} + 192]",
            "movdqa xmm13, [{p} + 208]",
            "movdqa xmm14, [{p} + 224]",
            "movdqa xmm15, [{p} + 240]",
            p = in(reg) p,
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
            options(nostack, preserves_flags),
        );
    }
    zeroize::Zeroize::zeroize(&mut save.0);
    r
}
