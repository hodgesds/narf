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
//!     `narf_module_exit`.
//!   * Records init/exit firing in two `AtomicBool`s the kernel side
//!     could observe.
//!   * Exposes one ABI-stable export (`test_module_alive`) returning
//!     a constant the loader smoke verifies.
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

/// Constant returned by the exported `test_module_alive` symbol.
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

/// Module entry point. C-ABI, called by the kernel from
/// `crate::loader::invoke_init`.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_init() -> i32 {
    MODULE_INIT_RAN.store(true, Ordering::Release);
    0
}

/// Module teardown. C-ABI, called by the kernel from
/// `crate::loader::invoke_exit` after refcount reaches 0.
#[unsafe(no_mangle)]
pub extern "C" fn narf_module_exit() {
    MODULE_EXIT_RAN.store(true, Ordering::Release);
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
