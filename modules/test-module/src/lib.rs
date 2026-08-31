//! Reference NARF kernel module.
//!
//! This crate is the human-readable shape of a NARF module — the
//! same shape every out-of-tree driver lives in. It is also the
//! reference that `modules/src/tests_e2e.rs` mirrors when it
//! synthesizes a test ELF in-line.
//!
//! The module:
//!   * Declares the `.modinfo` lines (via `#[link_section]`).
//!   * Exposes the lifecycle C-ABI symbols `narf_module_init` and
//!     `narf_module_exit`, written directly — there is no macro, and the
//!     plumbing is six lines.
//!   * Calls `narf_printk`, so the built object carries an undefined symbol
//!     the loader has to resolve through KSYMTAB — which is the part that
//!     exercises relocation, and on aarch64 the PLT veneers too.
//!   * Records init/exit firing in two `AtomicBool`s the kernel side
//!     could observe.
//!   * Defines `test_module_alive`, a `#[no_mangle]` global returning a
//!     constant. Note this is an ELF-level global, NOT a KSYMTAB export —
//!     a module publishes to KSYMTAB by registering at run time, the way
//!     Linux's `EXPORT_SYMBOL` does, and this module registers nothing.
//!
//! Linux refs:
//!   * `lib/test_modload.c` — kernel-side analogue.
//!   * `include/linux/module.h::MODULE_INFO` — the macro family that
//!     emits the `.modinfo` key=value strings at compile time.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

use core::sync::atomic::{AtomicBool, Ordering};

/// Set true by `narf_module_init`. The loader smoke reads this to
/// confirm init actually fired.
pub static MODULE_INIT_RAN: AtomicBool = AtomicBool::new(false);

/// Set true by `narf_module_exit`. The loader smoke reads this to
/// confirm exit actually fired.
pub static MODULE_EXIT_RAN: AtomicBool = AtomicBool::new(false);

/// Constant returned by the `test_module_alive` symbol.
/// Smoke 2 (symbol export visible) calls the exported address and
/// expects this value back.
pub const TEST_MODULE_ALIVE_MAGIC: u32 = 0xDEAD_C0DE;

// ── modinfo section ─────────────────────────────────────────────────
//
// The loader reads `.modinfo` as NUL-separated `key=value` strings.
// Linux's MODULE_INFO macros emit one static per line into the
// same section; we do the same here. `kernel_abi` is a placeholder —
// real builds get it from `/sys/kernel/abi_hash`.

#[used]
#[link_section = ".modinfo"]
static MODINFO_NAME: [u8; 17] = *b"name=test_module\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_VERSION: [u8; 14] = *b"version=0.1.0\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_LICENSE: [u8; 25] = *b"license=GPL-2.0-or-later\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_AUTHOR: [u8; 17] = *b"author=narf-test\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_DESCRIPTION: [u8; 47] = *b"description=NARF loader end-to-end test module\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_TARGET_DOMAIN: [u8; 22] = *b"target_domain=scratch\0";

#[used]
#[link_section = ".modinfo"]
static MODINFO_KERNEL_ABI: [u8; 22] = *b"kernel_abi=0x00000000\0";

// ── Lifecycle ABI ───────────────────────────────────────────────────
//
// The kernel calls `narf_module_init` once after relocations are
// applied and the module's memory is in its final mapping. A 0 return
// promotes the module from Loading to Live. Any non-zero return is
// surfaced verbatim through `sys_init_module`'s errno path.
//
// `narf_module_exit` is optional. If present, the kernel calls it on
// `rmmod` after the refcount has dropped to zero.

// ── Kernel ABI ──────────────────────────────────────────────────────
//
// What the module calls in the kernel. These stay UNDEFINED in the object
// this crate builds to; the loader resolves them against KSYMTAB and patches
// the call sites. That is what makes this example an exercise of the
// mechanism rather than just its shape: it produces a real
// `R_X86_64_PLT32` relocation on x86_64, and `R_AARCH64_CALL26` on aarch64 —
// which needs a PLT veneer, because kernel text is further away than that
// relocation reaches.
//
// Every export is `unsafe`: the boundary is unsafe as a whole, since nothing
// has verified the arguments. See `modules/src/kabi.rs` for the kernel side.
unsafe extern "C" {
    /// Write `len` bytes of UTF-8 at `ptr` to the kernel console.
    fn narf_printk(ptr: *const u8, len: usize) -> i32;
}

/// Safe wrapper: a `&str` is by construction valid UTF-8 over readable
/// bytes, which is the whole of `narf_printk`'s contract.
fn printk(s: &str) {
    // SAFETY: `s` is a live `&str` for the duration of the call, so
    // `s.as_ptr()` names `s.len()` readable bytes of valid UTF-8.
    unsafe {
        let _ = narf_printk(s.as_ptr(), s.len());
    }
}

/// Module entry point. C-ABI, called by the kernel from
/// `crate::loader::invoke_init` once relocations are applied and the image
/// is sealed. Zero promotes the module to Live; a negative errno is
/// surfaced verbatim through `sys_init_module`.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_init() -> i32 {
    MODULE_INIT_RAN.store(true, Ordering::Release);
    printk("narf-test-module: init\n");
    0
}

/// Module teardown. C-ABI, called by the kernel from
/// `crate::loader::invoke_exit` after the refcount reaches 0.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    MODULE_EXIT_RAN.store(true, Ordering::Release);
    printk("narf-test-module: exit\n");
}

/// Exported symbol. The kernel smoke looks this up via
/// `narf_modules::symbols::resolve` (or `lookup`, depending on the
/// loader's KSYMTAB API) and calls it through the returned address to
/// verify the magic round-trips.
#[unsafe(no_mangle)]
pub extern "C" fn test_module_alive() -> u32 {
    TEST_MODULE_ALIVE_MAGIC
}

// ── Panic handler ───────────────────────────────────────────────────
//
// A staticlib for `x86_64-unknown-none` needs its own `#[panic_handler]`
// since it doesn't pull in std's. The kernel never invokes this — it
// would only fire if the module itself panicked. We loop forever so a
// real-HW failure is at least quiescent.

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
