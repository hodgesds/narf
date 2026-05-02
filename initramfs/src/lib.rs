//! narf-initramfs — initramfs staging static + boot-path handoff.
//!
//! Spec: `initramfs/specification/spec.md`.
//!
//! Owns the process-global staging static (`install` / `staged`),
//! the `Stage::Early` `initramfs-stage` initcall, and the
//! `mount_at_boot` helper that mounts the staged initramfs at
//! `/boot` through the standard VFS surface.
//!
//! The CPIO newc parser + `Initramfs` value still live in
//! `narf-filesystem` (for the orphan-rule reasons documented in
//! the spec §6 migration plan). This crate re-exports them so
//! consumers can import everything from one place:
//!
//! ```ignore
//! use narf_initramfs::{Initramfs, CpioError, install, staged};
//! ```

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use narf_lib::sync::IrqSafeSpinLock;

mod tests;

// Re-exports of the CPIO parser surface that lives in
// `narf-filesystem`. New code should import from
// `narf_initramfs::*` so the eventual move (spec §6 step 3) is
// invisible to call sites.
pub use narf_filesystem::{CpioError, Initramfs};

// ── Process-global staging static ──────────────────────────────────
//
// The boot path stages the parsed `Initramfs` here exactly once;
// later consumers (firmware, init binary loader, etc.) borrow
// `&'static Initramfs` from `staged()` thereafter. There is no
// unstaging — initramfs is a boot artifact that lives until
// kernel shutdown.

static STAGED: IrqSafeSpinLock<Option<&'static Initramfs>>
    = IrqSafeSpinLock::new(None);

/// Stage a parsed initramfs for later consumers. Idempotent —
/// first install wins.
pub fn install(fs: &'static Initramfs) {
    let mut g = STAGED.lock();
    if g.is_none() {
        *g = Some(fs);
    }
}

/// Borrow the staged initramfs. `None` until `install` runs.
pub fn staged() -> Option<&'static Initramfs> {
    *STAGED.lock()
}

/// `true` once an initramfs has been staged.
pub fn is_staged() -> bool {
    STAGED.lock().is_some()
}

#[doc(hidden)]
pub fn __reset_staged() {
    *STAGED.lock() = None;
}

/// Stage::Early initcall. Today a no-op marker — the boot
/// path's bootloader-handoff parser (multiboot2 module / PVH
/// modlist / FDT chosen-node) lives in `boot/`; once it lands
/// it stages the parsed `Initramfs` here directly. The slot
/// exists so consumers registered AFTER `initramfs-stage` at
/// `Stage::Early` can rely on `staged()` returning
/// `Some(_)` if the build profile expects an initramfs.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Early, "initramfs-stage", || {
        if is_staged() { InitResult::Ok } else { InitResult::NotPresent }
    });
}
