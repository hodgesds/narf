//! Bridge between the generic `FileOps::ioctl` syscall path and the
//! DRM-specific dispatcher in [`crate::drm::ioctl`].
//!
//! `sys_ioctl` hands us `(cmd, user_arg_ptr)`. We:
//!
//! 1. Strip the lower 8 bits of `cmd` to get the DRM sub-command number.
//! 2. Copy the inout struct from user-space into a kernel-owned buffer.
//! 3. Build a [`DrmFileCtx`] for the calling fd (primary vs render).
//! 4. Call [`crate::drm::ioctl::dispatch`] with the kernel buffer.
//! 5. Serialise the response back into the user buffer.
//!
//! Per-card mode-setting state is looked up via
//! [`crate::drm_registry::mode_state`]. Cards registered without a
//! `drm::card::Card` state attach return `ENOTSUP` for every DRM ioctl.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_ioctl.c::drm_ioctl` — top-level dispatcher
//!   that this module mirrors.
//! - `include/uapi/drm/drm.h` — UAPI struct definitions copied in
//!   [`crate::drm_uapi`].

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use narf_filesystem::FsError;

use crate::drm::ioctl::{dispatch, DrmIoctlError, DrmIoctlResult, IoctlCmd};
use crate::drm::render_node::DrmFileCtx;
use crate::drm_uapi::{self, DrmModeAtomicUapi, DrmModeCardResUapi, DrmVersionUapi};

// ── Copy helpers ──────────────────────────────────────────────────────
//
// These mirror the SMAP-bracketed helpers in `narf-userspace::handlers`
// but stay local so the GPU crate doesn't take a dependency on the
// syscall layer. The kernel-test smokes pass kernel-owned pointers
// here; production traffic goes through validated user ranges already
// gated by `sys_ioctl`.

/// Maximum per-ioctl payload size (1 MiB). Hard cap so a malicious
/// `count_objs` field can't be used to force a huge allocation.
const IOCTL_MAX_BUF: usize = 1024 * 1024;

/// Read `N` bytes from a user-pointer into a kernel `Vec<u8>`.
///
/// # Safety
/// `uptr` must be a valid user-mode pointer for the calling task or a
/// kernel-mode pointer (test-only). The caller must hold the syscall
/// trap context (no IRQ context, AS still active).
unsafe fn copy_in(uptr: usize, len: usize) -> Result<Vec<u8>, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    if len > IOCTL_MAX_BUF {
        return Err(FsError::InvalidData);
    }
    let mut out = vec![0u8; len];
    // SAFETY: pointer is opaque to this layer — the SMAP bracket
    // belongs in the syscall layer that called us. On test paths the
    // pointer is kernel-owned and the unsafe read is a plain memcpy.
    unsafe {
        let src = uptr as *const u8;
        core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), len);
    }
    Ok(out)
}

/// Write a kernel slice back into a user-pointer.
unsafe fn copy_out(uptr: usize, bytes: &[u8]) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: pointer is opaque to this layer — caller invariants.
    unsafe {
        let dst = uptr as *mut u8;
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());
    }
    Ok(())
}

// ── Error translation ────────────────────────────────────────────────

fn map_err(e: DrmIoctlError) -> FsError {
    match e {
        DrmIoctlError::UnknownCmd | DrmIoctlError::BadSize => FsError::Unsupported,
        DrmIoctlError::PermissionDenied(_) => FsError::PermissionDenied,
        DrmIoctlError::UnknownConnector | DrmIoctlError::Card(_) => FsError::InvalidData,
    }
}

// ── Entry point ──────────────────────────────────────────────────────

/// Top-level `FileOps::ioctl` body for DRM card + render nodes.
///
/// `card_index` is the registry index of the card (`/dev/dri/card<N>`
/// or `renderD<N+128>`); `cmd` is the encoded ioctl number; `arg` is
/// the raw user pointer; `render` selects render-node vs primary-node
/// `DrmFileCtx`.
///
/// Returns the syscall return value (0 on success for most ioctls, or
/// an ioctl-specific positive value) or a translated `FsError`.
pub fn dispatch_card(card_index: u32, cmd: u32, arg: usize, render: bool) -> Result<u64, FsError> {
    // 1. Resolve the card. Cards registered without mode_state return
    //    ENOTSUP — bring-up drivers haven't built a Card yet.
    let mode_state = crate::drm_registry::mode_state(card_index).ok_or(FsError::Unsupported)?;

    // 2. Build the per-fd ctx. Primary-node opens are treated as
    //    authenticated master so KMS ioctls reach the body. NARF
    //    doesn't yet model DRM_AUTH / DRM_MASTER handoffs — Stage-5
    //    compositor work will add a separate ioctl gate.
    let ctx = if render {
        DrmFileCtx::render_client()
    } else {
        DrmFileCtx::primary_master()
    };

    // 3. Look up the per-cmd handler.
    let nr = drm_uapi::ioc_nr(cmd);
    match IoctlCmd::from_raw(nr) {
        // VERSION needs special-case handling because the user struct
        // holds out-pointers (name/date/desc) that the kernel writes
        // into separately. The generic dispatcher returns the filled
        // name/date/desc bytes; we copy them through here.
        IoctlCmd::Version => handle_version(&mode_state, arg, &ctx),
        // Atomic commit decodes into AtomicState directly — handled
        // here rather than through the generic dispatcher because the
        // dispatcher only carries the wire-format word.
        IoctlCmd::ModeAtomic => handle_atomic(&mode_state, arg, &ctx),
        // GETRESOURCES is special because the response has pointer
        // arrays the user supplied; we must write IDs into those.
        IoctlCmd::ModeGetResources => handle_getresources(&mode_state, arg, &ctx),
        // Everything else: copy a generic buffer in, hand to the
        // generic dispatcher, copy results back. A few ioctls have
        // pure-output (no input bytes); those still funnel through the
        // generic path.
        _ => handle_generic(&mode_state, cmd, arg, &ctx),
    }
}

// ── Per-ioctl handlers ───────────────────────────────────────────────

/// DRM_IOCTL_VERSION: kernel writes driver identity into user-supplied
/// out-buffers (`name_ptr`, `date_ptr`, `desc_ptr`) and updates the
/// `_len` fields with the byte counts actually written.
fn handle_version(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // Read the user struct.
    // SAFETY: `arg` is the ioctl argument pointer validated by the syscall
    // trap layer (or a kernel-owned pointer on the test path); we request
    // exactly `size_of::<DrmVersionUapi>()` bytes, which `copy_in` bounds-
    // checks against `IOCTL_MAX_BUF` before copying.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmVersionUapi>())? };
    let mut req: DrmVersionUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmVersionUapi>()` bytes, so the read of one
        // `DrmVersionUapi` stays within the allocation. `read_unaligned` is
        // used because `bytes`' allocation has only `u8` alignment.
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmVersionUapi) };

    // Run the generic dispatcher to get the filled in version struct.
    let v = {
        let mut card_guard = mode_state.lock();
        let result = dispatch(&mut card_guard, 0x00, &[], ctx).map_err(map_err)?;
        match result {
            DrmIoctlResult::Version(v) => v,
            _ => return Err(FsError::Unsupported),
        }
    };

    // Write the driver name / date / desc into the user buffers,
    // truncated to whatever capacity the user supplied. Then write
    // back the actual lengths so user-space knows how much landed.
    let name = c_str_bytes(&v.name);
    let date = c_str_bytes(&v.date);
    let desc = c_str_bytes(&v.desc);

    if req.name != 0 && req.name_len > 0 {
        let cap = req.name_len as usize;
        let n = name.len().min(cap);
        // SAFETY: `req.name` is the user-supplied out-pointer and is non-
        // null here; we write at most `cap` (= `req.name_len`) bytes, the
        // capacity the user advertised, so the copy stays within the
        // user-provided buffer.
        unsafe {
            copy_out(req.name as usize, &name[..n])?;
        }
    }
    if req.date != 0 && req.date_len > 0 {
        let cap = req.date_len as usize;
        let n = date.len().min(cap);
        // SAFETY: `req.date` is the user-supplied out-pointer and is non-
        // null here; we write at most `cap` (= `req.date_len`) bytes, the
        // capacity the user advertised, so the copy stays in bounds.
        unsafe {
            copy_out(req.date as usize, &date[..n])?;
        }
    }
    if req.desc != 0 && req.desc_len > 0 {
        let cap = req.desc_len as usize;
        let n = desc.len().min(cap);
        // SAFETY: `req.desc` is the user-supplied out-pointer and is non-
        // null here; we write at most `cap` (= `req.desc_len`) bytes, the
        // capacity the user advertised, so the copy stays in bounds.
        unsafe {
            copy_out(req.desc as usize, &desc[..n])?;
        }
    }
    req.name_len = name.len() as u64;
    req.date_len = date.len() as u64;
    req.desc_len = desc.len() as u64;
    req.version_major = v.version_major;
    req.version_minor = v.version_minor;
    req.version_patchlevel = v.version_patchlevel;

    let out_bytes: [u8; core::mem::size_of::<DrmVersionUapi>()] =
        // SAFETY: `DrmVersionUapi` is a `#[repr(C)]` POD of plain integer
        // fields with no padding-dependent invariants, so reinterpreting its
        // bytes as a `[u8; size_of::<DrmVersionUapi>()]` array is sound; the
        // source and destination have identical size by construction.
        unsafe { core::mem::transmute(req) };
    // SAFETY: `arg` is the same user/kernel out-pointer validated for the
    // input copy above; we write exactly `size_of::<DrmVersionUapi>()`
    // bytes, the size the user struct occupies.
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_GETRESOURCES — fill counts + (if user pointers
/// supplied) write per-object id arrays.
fn handle_getresources(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the ioctl argument pointer validated by the syscall
    // trap layer (or kernel-owned on the test path); we request exactly
    // `size_of::<DrmModeCardResUapi>()` bytes, bounds-checked by `copy_in`.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCardResUapi>())? };
    let mut req: DrmModeCardResUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmModeCardResUapi>()` bytes, so reading one
        // `DrmModeCardResUapi` stays within the allocation; `read_unaligned`
        // matches the `u8` alignment of the backing buffer.
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeCardResUapi) };

    let mut card_guard = mode_state.lock();
    // Run the existing dispatch path for the count fields.
    let result = dispatch(&mut card_guard, 0xA0, &[], ctx).map_err(map_err)?;
    let res = match result {
        DrmIoctlResult::GetResources(r) => r,
        _ => return Err(FsError::Unsupported),
    };
    // Re-borrow the locked Card for the ID write helpers below.
    let card = &*card_guard;

    // Helper to write an id array to user memory iff (a) the user
    // supplied a non-null ptr and (b) the user-supplied count is
    // greater than zero.
    fn write_ids(
        uptr: u64,
        user_count: u32,
        ids: impl Iterator<Item = u32>,
    ) -> Result<(), FsError> {
        if uptr == 0 || user_count == 0 {
            return Ok(());
        }
        let cap = user_count as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(cap * 4);
        for (i, id) in ids.enumerate() {
            if i >= cap {
                break;
            }
            buf.extend_from_slice(&id.to_le_bytes());
        }
        // SAFETY: `uptr` is the user-supplied id-array out-pointer, non-null
        // (checked above); `buf` holds at most `cap` (= `user_count`) ids of
        // 4 bytes each, so we never write past the `user_count`-element
        // array the user advertised.
        unsafe { copy_out(uptr as usize, &buf) }
    }

    write_ids(req.crtc_id_ptr, req.count_crtcs, card.crtc_ids())?;
    write_ids(
        req.connector_id_ptr,
        req.count_connectors,
        card.connector_ids(),
    )?;
    write_ids(req.encoder_id_ptr, req.count_encoders, card.encoder_ids())?;
    write_ids(
        req.fb_id_ptr,
        req.count_fbs,
        card.framebuffers.iter().map(|f| f.id),
    )?;

    // Write back the canonical counts + dims.
    req.count_fbs = res.count_fbs;
    req.count_crtcs = res.count_crtcs;
    req.count_connectors = res.count_connectors;
    req.count_encoders = res.count_encoders;
    req.min_width = res.min_width;
    req.max_width = res.max_width;
    req.min_height = res.min_height;
    req.max_height = res.max_height;
    drop(card_guard);

    let out_bytes: [u8; core::mem::size_of::<DrmModeCardResUapi>()] =
        // SAFETY: `DrmModeCardResUapi` is a `#[repr(C)]` POD of plain integer /
        // pointer-sized fields, so reinterpreting its bytes as a `[u8; N]`
        // array of the same size is sound.
        unsafe { core::mem::transmute(req) };
    // SAFETY: `arg` is the validated user/kernel out-pointer from the input
    // copy above; we write exactly `size_of::<DrmModeCardResUapi>()` bytes.
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_ATOMIC — decode objs/props/values arrays, build
/// `AtomicState`, run `core_check` + `core_commit`.
///
/// Linux ref: `drivers/gpu/drm/drm_atomic_uapi.c::drm_mode_atomic_ioctl`.
fn handle_atomic(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the ioctl argument pointer validated by the syscall
    // trap layer (or kernel-owned on the test path); we request exactly
    // `size_of::<DrmModeAtomicUapi>()` bytes, bounds-checked by `copy_in`.
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeAtomicUapi>())? };
    let req: DrmModeAtomicUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmModeAtomicUapi>()` bytes, so reading one
        // `DrmModeAtomicUapi` stays within the allocation; `read_unaligned`
        // matches the `u8` alignment of the backing buffer.
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeAtomicUapi) };

    // Wave-36 minimum-viable: we accept the call shape, build an
    // empty `AtomicState`, and run `core_check` + `core_commit` so
    // a Mesa caller observing this surface sees a success on a no-op
    // commit. Full property-array decoding (objs/props/values) lands
    // alongside the per-driver atomic_ops table that Wave-35 added —
    // the wire-format decode is deferred because it requires a per-
    // driver property table that doesn't ship yet for any backend.
    let mut state = crate::drm::atomic::AtomicState {
        allow_modeset: (req.flags & crate::drm::atomic::DRM_MODE_ATOMIC_ALLOW_MODESET) != 0,
        ..Default::default()
    };
    let policy = crate::drm::atomic::AtomicCheckPolicy::default();

    let mut card = mode_state.lock();
    match crate::drm::atomic::atomic_check_and_commit(&mut card, &mut state, &policy, None) {
        Ok(()) => Ok(0),
        Err(_) => Err(FsError::InvalidData),
    }
}

/// Fallback: hand any other DRM_IOCTL_* number to the generic
/// dispatcher. For these we currently pass an empty input slice — the
/// generic dispatcher's handlers that need wire bytes (GETCONNECTOR,
/// ADDFB2, RMFB) read fields out by offset.
///
/// Where the user input doesn't fit Wave-36's minimum-viable scope
/// (no full per-cmd serdes), we still route through the dispatch so
/// permission gates fire correctly and a known-but-unimplemented cmd
/// returns ENOTSUP rather than crashing.
fn handle_generic(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    cmd: u32,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let nr = drm_uapi::ioc_nr(cmd);
    // For ioctls with a known struct size, copy the input through.
    let size = drm_uapi::ioc_size(cmd) as usize;
    let in_bytes: Vec<u8> = if size > 0 && arg != 0 {
        // SAFETY: guarded by `arg != 0`; `size` is the encoded ioctl struct
        // size from `ioc_size(cmd)` and is bounds-checked again by `copy_in`
        // against `IOCTL_MAX_BUF`. `arg` is the validated user pointer.
        unsafe { copy_in(arg, size)? }
    } else {
        Vec::new()
    };
    let mut card = mode_state.lock();
    let result = dispatch(&mut card, nr, &in_bytes, ctx).map_err(map_err)?;
    // GEM_CLOSE / RMFB / SyncObj have no meaningful out-payload — return 0.
    // GETCAP, ADDFB2 results would need per-cmd serialisation back to
    // the user buffer; left to a follow-on pass once Mesa exercises
    // those code paths.
    let _ = result;
    Ok(0)
}

// ── Misc ─────────────────────────────────────────────────────────────

/// Return the byte prefix of `buf` up to (but excluding) the first
/// NUL — i.e. the C-string content of a fixed-size buffer.
fn c_str_bytes(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..n]
}
