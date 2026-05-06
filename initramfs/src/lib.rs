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

static STAGED: IrqSafeSpinLock<Option<&'static Initramfs>> = IrqSafeSpinLock::new(None);

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

/// Stage the parsed initramfs from a bootloader-supplied phys
/// region, then call `install` so subsequent consumers see it.
///
/// The boot path calls this once, immediately after constructing
/// `BootInfo`, with `boot_info.initramfs` if present. The phys
/// range is identity-mapped at this point in boot. The parsed
/// `Initramfs` is allocated on the heap and leaked via
/// `Box::leak` so it lives for the kernel's lifetime, matching
/// the spec's "stage once, borrow forever" principle.
///
/// # Safety
/// `phys` + `len` must point at a readable, identity-mapped CPIO
/// newc archive of exactly `len` bytes. The bootloader contract
/// guarantees both for the region it advertises in
/// `BootInfo::initramfs`.
pub unsafe fn stage_from_phys(name: &'static str, phys: u64, len: u64) -> Result<(), CpioError> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: caller-asserted readability + identity mapping.
    let archive: &'static [u8] =
        unsafe { core::slice::from_raw_parts(phys as *const u8, len as usize) };
    let fs = Initramfs::from_cpio(name, archive)?;
    let leaked: &'static Initramfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
    install(leaked);
    Ok(())
}

/// Mount the staged initramfs at `/boot` through the standard
/// VFS surface. Idempotent — the FS registry rejects duplicate
/// mount points, so a second call is a structural no-op. Returns
/// `Ok(())` on successful mount, `Err(())` when no initramfs has
/// been staged or the mount call rejected the request.
pub fn mount_at_boot(
    auth: &narf_capabilities::Cap<narf_filesystem::MountPoint, narf_capabilities::Grant>,
) -> Result<(), ()> {
    let fs = staged().ok_or(())?;
    let proxy = MountProxy { fs };
    narf_filesystem::registry()
        .mount(auth, "/boot", proxy)
        .map(|_handle| ())
        .map_err(|_| ())
}

/// Newtype around `&'static Initramfs` that re-implements
/// `FsInstance` by delegating to the underlying value. Used so
/// `mount_at_boot` can hand the registry an owned value while
/// preserving the canonical `'static` reference held by `STAGED`.
#[derive(Debug)]
struct MountProxy {
    fs: &'static Initramfs,
}

impl narf_filesystem::FsInstance for MountProxy {
    fn root(&self) -> alloc::sync::Arc<dyn narf_filesystem::DirOps> {
        self.fs.root()
    }
    fn name(&self) -> &str {
        self.fs.name()
    }
}

/// Stage::Early `initramfs-stage` initcall reports whether
/// `staged()` is populated by the boot-path handoff. Stage::Late
/// `initramfs-mount-at-boot` mounts the staged FS at `/boot` so
/// in-kernel + userspace consumers can resolve paths through the
/// VFS rather than reaching `staged()` directly.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Early, "initramfs-stage", || {
        if is_staged() {
            InitResult::Ok
        } else {
            InitResult::NotPresent
        }
    });
    narf_init::register(Stage::Late, "initramfs-mount-at-boot", || {
        if !is_staged() {
            return InitResult::NotPresent;
        }
        let auth = narf_filesystem::bootstrap_mount_authority();
        match mount_at_boot(&auth) {
            Ok(()) => InitResult::Ok,
            Err(()) => InitResult::Error("mount_at_boot rejected"),
        }
    });
}
