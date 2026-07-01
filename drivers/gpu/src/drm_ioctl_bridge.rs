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
use crate::drm_uapi::{
    self, DrmModeAtomicUapi, DrmModeCardResUapi, DrmModeCreateDumbUapi, DrmModeCrtcUapi,
    DrmModeDestroyDumbUapi, DrmModeMapDumbUapi, DrmModePageFlipUapi, DrmVersionUapi,
};

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
    // SAFETY: `uptr` is the user (or test-kernel) ioctl arg; `user_memcpy`
    // SMAP-brackets the read so a real user pointer doesn't #PF under SMAP.
    unsafe {
        user_memcpy(out.as_mut_ptr(), uptr as *const u8, len);
    }
    Ok(out)
}

/// Write a kernel slice back into a user-pointer.
unsafe fn copy_out(uptr: usize, bytes: &[u8]) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: `uptr` is the user (or test-kernel) ioctl arg; `user_memcpy`
    // SMAP-brackets the write.
    unsafe {
        user_memcpy(uptr as *mut u8, bytes.as_ptr(), bytes.len());
    }
    Ok(())
}

/// `copy_nonoverlapping` bracketed by a SMAP user-access window so the
/// kernel may touch user memory through the raw ioctl pointer. The DRM
/// ioctl path reaches here from `sys_ioctl`, which passes the user `arg`
/// straight through without clearing SMAP. Harmless on kernel pointers
/// (the test smokes): `stac` only relaxes the U/S check, it never breaks
/// a supervisor access.
///
/// # Safety
/// `dst`/`src` must be valid for `len` bytes; one side may be user memory.
#[cfg(target_arch = "x86_64")]
unsafe fn user_memcpy(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: caller guarantees the ranges; with_user_access toggles AC.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(src, dst, len);
        });
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn user_memcpy(dst: *mut u8, src: *const u8, len: usize) {
    // SAFETY: caller guarantees the ranges.
    unsafe { core::ptr::copy_nonoverlapping(src, dst, len) };
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
        // GETCONNECTOR fills user mode/encoder arrays + the two-pass
        // count protocol; the generic path would discard the result.
        IoctlCmd::ModeGetConnector => handle_getconnector(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetEncoder => handle_getencoder(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetCrtc => handle_getcrtc(&mode_state, arg, &ctx),
        IoctlCmd::ModeObjGetProperties => handle_obj_getproperties(&mode_state, arg, &ctx),
        // Universal planes (synthesised PRIMARY plane per CRTC) — weston
        // needs these to find an output's primary plane on the legacy path.
        IoctlCmd::ModeGetPlaneRes => handle_getplane_res(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetPlane => handle_getplane(&mode_state, arg, &ctx),
        IoctlCmd::ModeGetProperty => handle_getproperty(arg),
        // SETGAMMA — accept + no-op. We scan out the framebuffer verbatim
        // (no hardware gamma LUT), so modetest's post-modeset gamma reset
        // succeeds silently instead of warning `failed to set gamma`.
        IoctlCmd::ModeSetGamma => Ok(0),
        // SET_MASTER / DROP_MASTER — primary-node fds are already treated
        // as authenticated master (single-client model); accept + no-op.
        IoctlCmd::SetMaster | IoctlCmd::DropMaster => Ok(0),
        // SET_CLIENT_CAP — opt into UAPI behaviours. We accept
        // UNIVERSAL_PLANES (weston REQUIRES it — it enumerates the
        // primary plane through the universal-planes UAPI) but reject
        // ATOMIC so weston falls back to legacy SETCRTC modeset, which
        // narf-drm implements (full atomic-commit is not wired yet).
        IoctlCmd::SetClientCap => handle_set_client_cap(arg),
        // Dumb-buffer ioctls — new in Rung 3.
        IoctlCmd::ModeCreateDumb => handle_create_dumb(&mode_state, arg, &ctx),
        IoctlCmd::ModeMapDumb => handle_map_dumb(&mode_state, arg, &ctx),
        IoctlCmd::ModeDestroyDumb => handle_destroy_dumb(&mode_state, arg, &ctx),
        // SETCRTC / PAGE_FLIP — blit dumb buffer into the active scanout.
        IoctlCmd::ModeSetCrtc => handle_setcrtc(&mode_state, arg, &ctx),
        IoctlCmd::ModePageFlip => handle_page_flip(&mode_state, arg, &ctx),
        // CURSOR / CURSOR2 — no hardware cursor plane; funnel the pointer
        // position + visibility into narf_console so narf_fb's cursor
        // renderer composites a sprite onto the scanout. Without this the
        // compositor's pointer is invisible (the ioctl would otherwise be a
        // silent no-op through the generic path).
        IoctlCmd::ModeCursor => handle_cursor(arg, false),
        IoctlCmd::ModeCursor2 => handle_cursor(arg, true),
        // GEM_CLOSE — free dumb backing if present.
        IoctlCmd::GemClose => handle_gem_close(&mode_state, arg, &ctx),
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
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmVersionUapi>())? };
    let mut req: DrmVersionUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmVersionUapi>()` bytes, so the read of one
        // `DrmVersionUapi` stays within the allocation. `read_unaligned` is
        // used because `bytes`' allocation has only `u8` alignment.
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: `arg` is the same user/kernel out-pointer validated for the
    // input copy above; we write exactly `size_of::<DrmVersionUapi>()`
    // bytes, the size the user struct occupies.
    // SAFETY: Valid MMIO bounds or trusted driver environment
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
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCardResUapi>())? };
    let mut req: DrmModeCardResUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmModeCardResUapi>()` bytes, so reading one
        // `DrmModeCardResUapi` stays within the allocation; `read_unaligned`
        // matches the `u8` alignment of the backing buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: `arg` is the validated user/kernel out-pointer from the input
    // copy above; we write exactly `size_of::<DrmModeCardResUapi>()` bytes.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// Serialise one `drm_mode_modeinfo` (68 bytes) into `out`.
/// Layout: clock u32, {h,v}* u16×10, vrefresh u32, flags u32, type u32,
/// name[32]. `DrmModeModeInfo` isn't repr(C), so we lay it out by hand.
fn mode_to_bytes(m: &crate::drm::ioctl::DrmModeModeInfo) -> [u8; 68] {
    let mut b = [0u8; 68];
    b[0..4].copy_from_slice(&m.clock.to_le_bytes());
    let u16s = [
        m.hdisplay,
        m.hsync_start,
        m.hsync_end,
        m.htotal,
        m.hskew,
        m.vdisplay,
        m.vsync_start,
        m.vsync_end,
        m.vtotal,
        m.vscan,
    ];
    for (i, v) in u16s.iter().enumerate() {
        b[4 + i * 2..6 + i * 2].copy_from_slice(&v.to_le_bytes());
    }
    b[24..28].copy_from_slice(&m.vrefresh.to_le_bytes());
    b[28..32].copy_from_slice(&m.flags.to_le_bytes());
    b[32..36].copy_from_slice(&m.r#type.to_le_bytes());
    b[36..68].copy_from_slice(&m.name);
    b
}

/// DRM_IOCTL_MODE_GETCONNECTOR — connector info + the libdrm two-pass
/// count protocol: pass 1 (zero out-ptrs) returns counts; pass 2 (ptrs +
/// matching counts) fills the modes/encoders arrays. handle_generic can't
/// do this (it discards the result), so it's a dedicated handler.
///
/// Linux ref: `drivers/gpu/drm/drm_connector.c::drm_mode_getconnector`.
fn handle_getconnector(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // struct drm_mode_get_connector is 80 bytes. Read the user's
    // out-pointers + advertised counts before dispatch.
    // SAFETY: `arg` is the validated user/kernel ioctl pointer.
    let in_bytes = unsafe { copy_in(arg, 80)? };
    let rd = |o: usize| u64::from_le_bytes(in_bytes[o..o + 8].try_into().unwrap());
    let rd32 = |o: usize| u32::from_le_bytes(in_bytes[o..o + 4].try_into().unwrap());
    let encoders_ptr = rd(0);
    let modes_ptr = rd(8);
    let user_count_modes = rd32(32);
    let user_count_encoders = rd32(40);

    let result = {
        let mut card = mode_state.lock();
        dispatch(&mut card, 0xA7, &in_bytes, ctx).map_err(map_err)?
    };
    let (info, modes) = match result {
        DrmIoctlResult::GetConnector(i, m) => (i, m),
        _ => return Err(FsError::Unsupported),
    };

    // Pass 2: fill the modes array when the user gave a buffer big enough.
    if modes_ptr != 0 && (user_count_modes as usize) >= modes.len() && !modes.is_empty() {
        let mut buf: Vec<u8> = Vec::with_capacity(modes.len() * 68);
        for m in &modes {
            buf.extend_from_slice(&mode_to_bytes(m));
        }
        // SAFETY: user-supplied modes_ptr, sized for >= modes.len() entries.
        unsafe { copy_out(modes_ptr as usize, &buf)? };
    }
    // Single encoder id into the encoders array.
    if encoders_ptr != 0 && user_count_encoders >= 1 && info.encoder_id != 0 {
        // SAFETY: user-supplied encoders_ptr with >= 1 slot.
        unsafe { copy_out(encoders_ptr as usize, &info.encoder_id.to_le_bytes())? };
    }

    // Write the struct back, preserving the user's out-pointers (first 32
    // bytes) and updating counts + connector fields (offsets 32..76).
    let mut out = in_bytes;
    out[32..36].copy_from_slice(&info.count_modes.to_le_bytes());
    out[36..40].copy_from_slice(&0u32.to_le_bytes()); // count_props
    out[40..44].copy_from_slice(&info.count_encoders.to_le_bytes());
    out[44..48].copy_from_slice(&info.encoder_id.to_le_bytes());
    out[48..52].copy_from_slice(&info.connector_id.to_le_bytes());
    out[52..56].copy_from_slice(&info.connector_type.to_le_bytes());
    out[56..60].copy_from_slice(&info.connector_type_id.to_le_bytes());
    out[60..64].copy_from_slice(&info.connection.to_le_bytes());
    out[64..68].copy_from_slice(&info.mm_width.to_le_bytes());
    out[68..72].copy_from_slice(&info.mm_height.to_le_bytes());
    out[72..76].copy_from_slice(&info.subpixel.to_le_bytes());
    // SAFETY: `arg` is the validated user/kernel out-pointer (80 bytes).
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETENCODER — struct drm_mode_get_encoder (20 bytes):
/// encoder_id, encoder_type, crtc_id, possible_crtcs, possible_clones.
///
/// Linux ref: `drivers/gpu/drm/drm_encoder.c::drm_mode_getencoder`.
fn handle_getencoder(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated user/kernel ioctl pointer (20 bytes).
    let in_bytes = unsafe { copy_in(arg, 20)? };
    let encoder_id = u32::from_le_bytes(in_bytes[0..4].try_into().unwrap());
    let mut out = [0u8; 20];
    {
        let card = mode_state.lock();
        let enc = card.encoder(encoder_id).map_err(|_| FsError::InvalidData)?;
        out[0..4].copy_from_slice(&enc.id.to_le_bytes());
        out[4..8].copy_from_slice(&(enc.encoder_type as u32).to_le_bytes());
        out[8..12].copy_from_slice(&enc.crtc_id.unwrap_or(0).to_le_bytes());
        out[12..16].copy_from_slice(&enc.possible_crtcs.to_le_bytes());
        out[16..20].copy_from_slice(&enc.possible_clones.to_le_bytes());
    }
    // SAFETY: `arg` is the validated user/kernel out-pointer (20 bytes).
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETCRTC — struct drm_mode_crtc (104 bytes). Reports the
/// crtc's current fb/x/y/mode; `set_connectors_ptr`/`count_connectors` are
/// input-only (zero on a get) and preserved.
///
/// Linux ref: `drivers/gpu/drm/drm_crtc.c::drm_mode_getcrtc`.
fn handle_getcrtc(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated user/kernel ioctl pointer (104 bytes).
    let in_bytes = unsafe { copy_in(arg, 104)? };
    let crtc_id = u32::from_le_bytes(in_bytes[12..16].try_into().unwrap());
    let mut out = in_bytes;
    {
        let card = mode_state.lock();
        let crtc = card.crtc(crtc_id).map_err(|_| FsError::InvalidData)?;
        out[12..16].copy_from_slice(&crtc.id.to_le_bytes());
        out[16..20].copy_from_slice(&crtc.primary_fb.unwrap_or(0).to_le_bytes()); // fb_id
        out[20..24].copy_from_slice(&crtc.x.to_le_bytes());
        out[24..28].copy_from_slice(&crtc.y.to_le_bytes());
        out[28..32].copy_from_slice(&0u32.to_le_bytes()); // gamma_size
        let mode_valid: u32 = crtc.mode.is_some() as u32;
        out[32..36].copy_from_slice(&mode_valid.to_le_bytes());
        match &crtc.mode {
            Some(m) => {
                let wire = crate::drm::ioctl::mode_to_wire(m);
                out[36..104].copy_from_slice(&mode_to_bytes(&wire));
            }
            None => out[36..104].fill(0),
        }
    }
    // SAFETY: `arg` is the validated user/kernel out-pointer (104 bytes).
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_SET_CLIENT_CAP — `struct drm_set_client_cap { __u64
/// capability; __u64 value; }` (16 bytes).
///
/// We mirror Linux `drm_setclientcap` for a driver WITHOUT `DRIVER_ATOMIC`:
/// the pure client opt-in flags that need no driver support are accepted
/// (STEREO_3D, UNIVERSAL_PLANES, ASPECT_RATIO), with `value > 1` rejected
/// as EINVAL exactly as Linux does. ATOMIC and WRITEBACK_CONNECTORS require
/// atomic modeset, which narf-drm lacks, so they're rejected — weston then
/// drives modeset through the legacy SETCRTC path. UNIVERSAL_PLANES is the
/// one weston hard-requires (it enumerates the primary plane through it).
///
/// Linux ref: `drivers/gpu/drm/drm_ioctl.c::drm_setclientcap`.
fn handle_set_client_cap(arg: usize) -> Result<u64, FsError> {
    // include/uapi/drm/drm.h DRM_CLIENT_CAP_*.
    const DRM_CLIENT_CAP_STEREO_3D: u64 = 1;
    const DRM_CLIENT_CAP_UNIVERSAL_PLANES: u64 = 2;
    const DRM_CLIENT_CAP_ASPECT_RATIO: u64 = 4;
    // SAFETY: `arg` is the validated 16-byte ioctl argument pointer.
    let bytes = unsafe { copy_in(arg, 16)? };
    let cap = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let value = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    match cap {
        DRM_CLIENT_CAP_STEREO_3D
        | DRM_CLIENT_CAP_UNIVERSAL_PLANES
        | DRM_CLIENT_CAP_ASPECT_RATIO => {
            // Boolean opt-in: Linux rejects any value > 1.
            if value > 1 {
                Err(FsError::InvalidData)
            } else {
                Ok(0)
            }
        }
        // ATOMIC, WRITEBACK_CONNECTORS, and every other cap need atomic
        // modeset (absent here) → EINVAL. A non-zero return tells the client
        // the cap isn't available; weston falls back to the legacy path.
        _ => Err(FsError::InvalidData),
    }
}

// ── Universal planes (legacy-modeset minimum) ─────────────────────────
//
// weston's drm-backend enumerates a CRTC's PRIMARY plane through the
// universal-planes UAPI even on the legacy modeset path — without it,
// `Failed to find primary plane for output` and the output won't enable.
// narf-drm has no real plane objects, so synthesise exactly one immutable
// PRIMARY plane per CRTC: plane `PLANE_ID_BASE + i` serves CRTC index `i`
// (possible_crtcs = 1<<i). Linux ref: drivers/gpu/drm/drm_plane.c.
const PLANE_ID_BASE: u32 = 0x40;
/// Property id of the plane "type" enum (a separate id space from objects).
const PLANE_TYPE_PROP_ID: u32 = 0x50;
const DRM_PLANE_TYPE_PRIMARY: u64 = 1;
const DRM_MODE_PROP_IMMUTABLE: u32 = 1 << 1;
const DRM_MODE_PROP_ENUM: u32 = 1 << 3;
/// DRM_FORMAT_XRGB8888 — the one scanout format the pixman path uses.
const DRM_FORMAT_XRGB8888: u32 = 0x3432_5258;

/// `(plane_id, crtc_index)` for the synthesised primary planes.
fn synth_planes(card: &crate::drm::card::Card) -> alloc::vec::Vec<(u32, u32)> {
    (0..card.crtcs.len() as u32)
        .map(|i| (PLANE_ID_BASE + i, i))
        .collect()
}

/// DRM_IOCTL_MODE_GETPLANERESOURCES — `struct drm_mode_get_plane_res
/// { __u64 plane_id_ptr; __u32 count_planes; }` (16 bytes). Two-pass:
/// fill the id array iff the caller's count is large enough, always
/// report the real count.
fn handle_getplane_res(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated 16-byte ioctl pointer.
    let mut bytes = unsafe { copy_in(arg, 16)? };
    let plane_id_ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let user_count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let planes = synth_planes(&mode_state.lock());
    if plane_id_ptr != 0 && user_count as usize >= planes.len() {
        let mut buf: Vec<u8> = Vec::with_capacity(planes.len() * 4);
        for (id, _) in &planes {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        // SAFETY: `plane_id_ptr` is the user out-array; we write exactly
        // `planes.len()` <= `user_count` ids of 4 bytes each.
        unsafe { copy_out(plane_id_ptr as usize, &buf)? };
    }
    bytes[8..12].copy_from_slice(&(planes.len() as u32).to_le_bytes());
    // SAFETY: `arg` is the validated 16-byte out-pointer.
    unsafe { copy_out(arg, &bytes)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETPLANE — `struct drm_mode_get_plane` (32 bytes):
/// plane_id, crtc_id, fb_id, possible_crtcs, gamma_size,
/// count_format_types, format_type_ptr.
fn handle_getplane(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated 32-byte ioctl pointer.
    let mut out = unsafe { copy_in(arg, 32)? };
    let plane_id = u32::from_le_bytes(out[0..4].try_into().unwrap());
    let user_fmt_count = u32::from_le_bytes(out[20..24].try_into().unwrap());
    let fmt_ptr = u64::from_le_bytes(out[24..32].try_into().unwrap());
    let possible_crtcs = {
        let card = mode_state.lock();
        match synth_planes(&card)
            .into_iter()
            .find(|(id, _)| *id == plane_id)
        {
            Some((_, crtc_idx)) => 1u32 << crtc_idx,
            None => return Err(FsError::InvalidData),
        }
    };
    out[4..8].copy_from_slice(&0u32.to_le_bytes()); // crtc_id (unbound)
    out[8..12].copy_from_slice(&0u32.to_le_bytes()); // fb_id
    out[12..16].copy_from_slice(&possible_crtcs.to_le_bytes());
    out[16..20].copy_from_slice(&0u32.to_le_bytes()); // gamma_size

    // One supported format (XRGB8888); fill the array two-pass.
    if fmt_ptr != 0 && user_fmt_count >= 1 {
        // SAFETY: `fmt_ptr` is the user format-array out-pointer with room
        // for >=1 u32 (checked above).
        unsafe { copy_out(fmt_ptr as usize, &DRM_FORMAT_XRGB8888.to_le_bytes())? };
    }
    out[20..24].copy_from_slice(&1u32.to_le_bytes()); // count_format_types

    // SAFETY: `arg` is the validated 32-byte out-pointer.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_GETPROPERTY — `struct drm_mode_get_property` (size from
/// the ioctl). We only describe the plane "type" enum property. weston
/// reads its `name` ("type") to identify the primary plane; the enum
/// entries (Overlay/Primary/Cursor) round out a well-formed reply.
fn handle_getproperty(arg: usize) -> Result<u64, FsError> {
    // struct drm_mode_get_property:
    //   u64 values_ptr;        // 0   (enum entries write here for ENUM props)
    //   u64 enum_blob_ptr;     // 8
    //   u32 prop_id;           // 16  (in)
    //   u32 flags;             // 20  (out)
    //   char name[32];         // 24  (out)
    //   u32 count_values;      // 56  (in/out)
    //   u32 count_enum_blobs;  // 60  (in/out)
    // = 64 bytes.
    // SAFETY: `arg` is the validated 64-byte ioctl pointer.
    let mut out = unsafe { copy_in(arg, 64)? };
    let prop_id = u32::from_le_bytes(out[16..20].try_into().unwrap());
    if prop_id != PLANE_TYPE_PROP_ID {
        return Err(FsError::InvalidData);
    }
    out[20..24].copy_from_slice(&(DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE).to_le_bytes());
    out[24..56].fill(0);
    let name = b"type";
    out[24..24 + name.len()].copy_from_slice(name);
    // For an ENUM property the entries go to ENUM_BLOB_PTR (offset 8) and
    // are counted by count_enum_blobs (offset 60); values_ptr/count_values
    // are for range properties and stay zero. Each entry is
    // `drm_mode_property_enum { __u64 value; char name[32]; }` = 40 bytes.
    let enums: [(u64, &[u8]); 3] = [(0, b"Overlay"), (1, b"Primary"), (2, b"Cursor")];
    let enum_blob_ptr = u64::from_le_bytes(out[8..16].try_into().unwrap());
    let user_enum_count = u32::from_le_bytes(out[60..64].try_into().unwrap());
    if enum_blob_ptr != 0 && user_enum_count as usize >= enums.len() {
        let mut buf = alloc::vec![0u8; enums.len() * 40];
        for (i, (val, nm)) in enums.iter().enumerate() {
            let base = i * 40;
            buf[base..base + 8].copy_from_slice(&val.to_le_bytes());
            buf[base + 8..base + 8 + nm.len()].copy_from_slice(nm);
        }
        // SAFETY: `enum_blob_ptr` is the user enum-array out-pointer sized
        // for `user_enum_count` >= 3 entries of 40 bytes each.
        unsafe { copy_out(enum_blob_ptr as usize, &buf)? };
    }
    out[56..60].copy_from_slice(&0u32.to_le_bytes()); // count_values (range only)
    out[60..64].copy_from_slice(&(enums.len() as u32).to_le_bytes()); // count_enum_blobs

    // SAFETY: `arg` is the validated 64-byte out-pointer.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}

/// DRM_IOCTL_MODE_OBJ_GETPROPERTIES — `struct drm_mode_obj_get_properties`
/// (28 bytes): props_ptr, prop_values_ptr, count_props@16, obj_id@20,
/// obj_type@24. A synthesised plane carries exactly one property — the
/// immutable "type" = PRIMARY that weston reads to pick a primary plane.
/// Every other object exposes none (`count_props = 0`); returning ENOTTY
/// made libdrm hand modetest a NULL property set it dereferenced (SIGSEGV).
///
/// Linux ref: `drivers/gpu/drm/drm_mode_object.c::drm_mode_obj_get_properties_ioctl`.
fn handle_obj_getproperties(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    _ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // SAFETY: `arg` is the validated 28-byte ioctl pointer.
    let mut bytes = unsafe { copy_in(arg, 28)? };
    let props_ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let values_ptr = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let user_count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let obj_id = u32::from_le_bytes(bytes[20..24].try_into().unwrap());

    let is_plane = synth_planes(&mode_state.lock())
        .iter()
        .any(|(id, _)| *id == obj_id);
    if is_plane {
        if props_ptr != 0 && values_ptr != 0 && user_count >= 1 {
            // props_ptr is a u32 array (property ids); prop_values_ptr is a
            // u64 array (values).
            // SAFETY: both are user out-pointers with room for >=1 entry.
            unsafe {
                copy_out(props_ptr as usize, &PLANE_TYPE_PROP_ID.to_le_bytes())?;
                copy_out(values_ptr as usize, &DRM_PLANE_TYPE_PRIMARY.to_le_bytes())?;
            }
        }
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes()); // count_props = 1
    } else {
        bytes[16..20].copy_from_slice(&0u32.to_le_bytes()); // no properties
    }
    // SAFETY: `arg` is the validated 28-byte out-pointer.
    unsafe { copy_out(arg, &bytes)? };
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
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeAtomicUapi>())? };
    let req: DrmModeAtomicUapi =
        // SAFETY: `bytes` is a freshly allocated `Vec<u8>` of exactly
        // `size_of::<DrmModeAtomicUapi>()` bytes, so reading one
        // `DrmModeAtomicUapi` stays within the allocation; `read_unaligned`
        // matches the `u8` alignment of the backing buffer.
        // SAFETY: Valid MMIO bounds or trusted driver environment
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

/// DRM_IOCTL_MODE_CURSOR / CURSOR2 — set the pointer sprite + position.
///
/// `struct drm_mode_cursor` is `{ flags, crtc_id, x, y, width, height,
/// handle }` (7 × u32 = 28 bytes); CURSOR2 appends `{ hot_x, hot_y }`
/// (36 bytes). We have no hardware cursor plane, so we don't consume the
/// BO bitmap — instead we drive narf_fb's software cursor sprite from the
/// position + visibility. `DRM_MODE_CURSOR_BO` with handle 0 hides the
/// pointer; a non-zero handle shows it; `DRM_MODE_CURSOR_MOVE` repositions.
///
/// Linux ref: `drivers/gpu/drm/drm_plane.c::drm_mode_cursor_common`.
fn handle_cursor(arg: usize, with_hotspot: bool) -> Result<u64, FsError> {
    const DRM_MODE_CURSOR_BO: u32 = 0x01;
    const DRM_MODE_CURSOR_MOVE: u32 = 0x02;
    let want = if with_hotspot { 36 } else { 28 };
    // SAFETY: `arg` is the validated ioctl argument pointer; `copy_in`
    // bounds-checks `want` against IOCTL_MAX_BUF before copying.
    let bytes = unsafe { copy_in(arg, want)? };
    let rd_u32 = |off: usize| {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    let rd_i32 = |off: usize| rd_u32(off) as i32;
    let flags = rd_u32(0);
    let x = rd_i32(8);
    let y = rd_i32(12);
    let handle = rd_u32(24);
    // CURSOR2 reports the hotspot — the active point inside the BO. Our
    // sprite's tip is at its own top-left, so shift the draw position by the
    // hotspot to keep the tip under the true pointer.
    let (hot_x, hot_y) = if with_hotspot {
        (rd_i32(28), rd_i32(32))
    } else {
        (0, 0)
    };

    if flags & DRM_MODE_CURSOR_BO != 0 {
        if handle == 0 {
            narf_console::user_cursor_hide();
        } else {
            narf_console::user_cursor_show();
        }
    }
    if flags & DRM_MODE_CURSOR_MOVE != 0 {
        let px = (x + hot_x).max(0) as u32;
        let py = (y + hot_y).max(0) as u32;
        narf_console::user_cursor_move(px, py);
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_CREATE_DUMB — allocate a dumb buffer (physically
/// contiguous pages) for a scanout-capable surface.
///
/// Linux ref: `drivers/gpu/drm/drm_dumb_buffers.c::drm_mode_create_dumb`.
fn handle_create_dumb(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // Permission: CREATE_DUMB is RENDER_ALLOW in Linux; the ioctl_flags
    // table already gates render-node access, so this just needs primary.
    let _ = ctx;

    // SAFETY: arg is the ioctl arg pointer; copy_in bounds-checks.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCreateDumbUapi>())? };
    let mut req: DrmModeCreateDumbUapi =
        // SAFETY: bytes is freshly allocated of exactly the right size.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeCreateDumbUapi) };

    if req.width == 0 || req.height == 0 || req.bpp == 0 {
        return Err(FsError::InvalidData);
    }
    // Compute pitch (round up to 64-byte stride for alignment).
    let bpp_bytes = req.bpp.div_ceil(8);
    let pitch = req.width * bpp_bytes;
    let raw_size = pitch as u64 * req.height as u64;
    // Round up to page size.
    let page_size: u64 = 4096;
    let size = (raw_size + page_size - 1) & !(page_size - 1);

    // Compute buddy order (smallest power-of-two page count >= pages_needed).
    let pages_needed = size / page_size;
    let order = {
        let mut o = 0u8;
        while (1u64 << o) < pages_needed {
            o += 1;
        }
        o
    };

    // Allocate contiguous physical pages via the buddy allocator.
    let frame = narf_memory::frame::alloc_pages_on(0, order).map_err(|_| FsError::InvalidData)?;
    let phys = frame.start_address().raw();

    // Zero the buffer so userspace doesn't see stale kernel data.
    // SAFETY: phys is identity-mapped (KERNEL_PHYS_OFFSET==0 on x86_64);
    // the allocation covers `size` bytes at `phys`.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, size as usize);
    }

    // Register in the card's dumb_backings table.
    let handle = {
        let mut card = mode_state.lock();
        card.register_dumb_backing(phys, size as usize, order)
            .map_err(|_| FsError::InvalidData)?
    };

    // Write back the result.
    req.handle = handle;
    req.pitch = pitch;
    req.size = size;

    let out_bytes: [u8; core::mem::size_of::<DrmModeCreateDumbUapi>()] =
        // SAFETY: DrmModeCreateDumbUapi is #[repr(C)] POD.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: arg is the validated user/kernel pointer.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_MAP_DUMB — return a fake mmap offset encoding the
/// GEM handle so `sys_mmap` can later resolve it back to the buffer.
///
/// Linux ref: `drivers/gpu/drm/drm_dumb_buffers.c::drm_mode_mmap_dumb`.
fn handle_map_dumb(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let _ = ctx;

    // SAFETY: as above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeMapDumbUapi>())? };
    let mut req: DrmModeMapDumbUapi =
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeMapDumbUapi) };

    let mmap_offset = {
        let card = mode_state.lock();
        card.dumb_backing(req.handle)
            .map(|b| b.mmap_offset)
            .ok_or(FsError::InvalidData)?
    };

    req.offset = mmap_offset;

    let out_bytes: [u8; core::mem::size_of::<DrmModeMapDumbUapi>()] =
        // SAFETY: #[repr(C)] POD.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::mem::transmute(req) };
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        copy_out(arg, &out_bytes)?;
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_DESTROY_DUMB — free a dumb buffer's physical pages.
///
/// Linux ref: `drivers/gpu/drm/drm_dumb_buffers.c::drm_mode_destroy_dumb`.
fn handle_destroy_dumb(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let _ = ctx;

    // SAFETY: as above.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeDestroyDumbUapi>())? };
    let req: DrmModeDestroyDumbUapi =
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeDestroyDumbUapi) };

    free_dumb_backing(mode_state, req.handle);
    Ok(0)
}

/// GEM_CLOSE — close a GEM handle and free its backing if it's a dumb buffer.
fn handle_gem_close(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    let _ = ctx;
    if arg == 0 {
        return Err(FsError::InvalidData);
    }
    // GEM_CLOSE struct: u32 handle + u32 pad.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, 8)? };
    let handle = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    free_dumb_backing(mode_state, handle);
    Ok(0)
}

/// Free a dumb buffer's physical backing pages (helper shared by DESTROY_DUMB + GEM_CLOSE).
fn free_dumb_backing(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    gem_handle: u32,
) {
    let phys_order = {
        let mut card = mode_state.lock();
        card.remove_dumb_backing(gem_handle)
    };
    if let Some((phys, order)) = phys_order {
        let frame = narf_memory::frame::PhysFrame::new(narf_memory::addr::PhysAddr::new(phys));
        narf_memory::frame::free_pages(frame, order);
    }
}

/// DRM_IOCTL_MODE_SETCRTC — blit the named framebuffer's dumb buffer
/// into the active scanout via `narf_fb::fbdev_info` + memcpy.
///
/// Linux ref: `drivers/gpu/drm/drm_crtc.c::drm_mode_setcrtc`.
fn handle_setcrtc(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // Modeset is primary-node only — render nodes (Mesa/Vulkan) carry no
    // DRM master and must be rejected with EACCES (DRM_MASTER in Linux).
    if ctx.is_render_client() {
        return Err(FsError::PermissionDenied);
    }

    // SAFETY: arg is the ioctl argument pointer.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModeCrtcUapi>())? };
    let req: DrmModeCrtcUapi =
        // SAFETY: #[repr(C)] POD of right size.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModeCrtcUapi) };

    // Look up the framebuffer → GEM handle → dumb backing phys.
    let src_phys: Option<u64>;
    let src_pitch: u32;
    let src_w: u32;
    let src_h: u32;
    {
        let mut card = mode_state.lock();

        // Record the mode and active fb on the crtc.
        if let Ok(crtc) = card.crtc_mut(req.crtc_id) {
            crtc.primary_fb = if req.fb_id != 0 {
                Some(req.fb_id)
            } else {
                None
            };
            crtc.enabled = req.fb_id != 0;
        }

        if req.fb_id == 0 {
            return Ok(0);
        }

        let fb = card
            .framebuffer(req.fb_id)
            .map_err(|_| FsError::InvalidData)?;
        src_pitch = fb.pitch;
        src_w = fb.width;
        src_h = fb.height;
        let gem_handle = fb.gem_handle;
        src_phys = card.dumb_backing(gem_handle).map(|b| b.phys);
    }

    // Perform the blit if we have a valid source and a live scanout.
    if let Some(src) = src_phys {
        blit_to_scanout(src, src_pitch, src_w, src_h);
    }
    Ok(0)
}

/// DRM_IOCTL_MODE_PAGE_FLIP — same blit as SETCRTC, no vblank event.
///
/// Linux ref: `drivers/gpu/drm/drm_crtc.c::drm_mode_page_flip_ioctl`.
fn handle_page_flip(
    mode_state: &alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<crate::drm::card::Card>>,
    arg: usize,
    ctx: &DrmFileCtx,
) -> Result<u64, FsError> {
    // Page flip is a modeset op — primary-node only (see handle_setcrtc).
    if ctx.is_render_client() {
        return Err(FsError::PermissionDenied);
    }

    // SAFETY: arg is the ioctl argument pointer.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let bytes = unsafe { copy_in(arg, core::mem::size_of::<DrmModePageFlipUapi>())? };
    let req: DrmModePageFlipUapi =
        // SAFETY: #[repr(C)] POD of right size.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DrmModePageFlipUapi) };

    // DRM_MODE_PAGE_FLIP_EVENT — queue a flip-complete event the client
    // reads off the DRM fd after poll/select (the compositor render loop).
    const DRM_MODE_PAGE_FLIP_EVENT: u32 = 0x01;

    let src_phys: Option<u64>;
    let src_pitch: u32;
    let src_w: u32;
    let src_h: u32;
    {
        let mut card = mode_state.lock();

        // Update the crtc's active fb.
        if let Ok(crtc) = card.crtc_mut(req.crtc_id) {
            crtc.primary_fb = if req.fb_id != 0 {
                Some(req.fb_id)
            } else {
                None
            };
        }

        let fb = card
            .framebuffer(req.fb_id)
            .map_err(|_| FsError::InvalidData)?;
        src_pitch = fb.pitch;
        src_w = fb.width;
        src_h = fb.height;
        let gem_handle = fb.gem_handle;
        src_phys = card.dumb_backing(gem_handle).map(|b| b.phys);

        // Deliver the completion event immediately — we blit synchronously,
        // so the new scanout is live by the time the client wakes. A real
        // vblank-paced delivery is a later refinement.
        if req.flags & DRM_MODE_PAGE_FLIP_EVENT != 0 {
            card.queue_flip_event(req.user_data, req.crtc_id);
        }
    }

    if let Some(src) = src_phys {
        blit_to_scanout(src, src_pitch, src_w, src_h);
    }
    Ok(0)
}

/// Blit pixels from a dumb buffer at `src_phys` into the active scanout.
///
/// Both source and destination are XRGB8888 linear; we copy row-by-row
/// up to `min(src_w, scanout_w)` × `min(src_h, scanout_h)`. After the
/// blit, `flush_scanout()` pushes the pixels to the host display on
/// virtio-gpu; it is a no-op on bochs (direct MMIO).
///
/// The scanout geometry is fetched through the DRM fbdev hook installed
/// by `narf_fb` at `Stage::Late` — avoids a circular crate dependency.
fn blit_to_scanout(src_phys: u64, src_pitch: u32, src_w: u32, src_h: u32) {
    let info = match crate::drm_fb_hook::query_scanout() {
        Some(i) => i,
        None => return,
    };
    // A real DRM client is now driving the scanout — hand the framebuffer
    // over to it: detach the kernel console FB hook and suppress the FB
    // status-panel / cursor painters so they stop bleeding kernel chrome
    // over the compositor's pixels. Idempotent, so calling it on every
    // SETCRTC / page flip is cheap. Released when the last card node closes
    // (see `DriCardFile`'s Drop).
    narf_console::fb_take_for_user();
    let dst_w = info.width.min(src_w);
    let dst_h = info.height.min(src_h);
    let row_bytes = (dst_w as usize) * 4;
    for row in 0..dst_h as usize {
        let src_row = src_phys + (row * src_pitch as usize) as u64;
        let dst_row = info.phys + (row * info.stride_bytes as usize) as u64;
        // SAFETY: Both src and dst are identity-mapped physical addresses
        // validated by their respective allocators; `row_bytes` is within
        // the allocation bounds (row < dst_h <= src_h, dst_w <= src_w).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::ptr::copy_nonoverlapping(src_row as *const u8, dst_row as *mut u8, row_bytes);
        }
    }
    crate::drm_fb_hook::flush_scanout();
}

/// Return the physical frames backing a dumb buffer for `sys_mmap`.
///
/// Called from `DriCardFile::mmap_frames`. `offset` is the fake mmap
/// offset returned by MAP_DUMB (= gem_handle << 12); `len` is the
/// requested mapping length.
pub fn dispatch_mmap(card_index: u32, offset: u64, len: usize) -> Result<Vec<u64>, FsError> {
    let mode_state = crate::drm_registry::mode_state(card_index).ok_or(FsError::Unsupported)?;
    let card = mode_state.lock();
    let backing = card
        .dumb_backing_by_offset(offset)
        .ok_or(FsError::InvalidData)?;
    if len > backing.byte_len {
        return Err(FsError::InvalidData);
    }
    let pages = len / 4096;
    let mut frames = Vec::with_capacity(pages);
    for i in 0..pages {
        frames.push(backing.phys + (i as u64) * 4096);
    }
    Ok(frames)
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
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { copy_in(arg, size)? }
    } else {
        Vec::new()
    };
    let result = {
        let mut card = mode_state.lock();
        dispatch(&mut card, nr, &in_bytes, ctx).map_err(map_err)?
    };
    // Serialise the out-payload back to the user buffer for the ioctls
    // that carry one. GEM_CLOSE / RMFB / SyncObj have none → return 0.
    match result {
        // drm_get_cap = { __u64 capability; __u64 value; } — write `value`.
        crate::drm::ioctl::DrmIoctlResult::GetCap(cap) if arg != 0 => {
            let mut out = [0u8; 16];
            out[0..8].copy_from_slice(&cap.capability.to_le_bytes());
            out[8..16].copy_from_slice(&cap.value.to_le_bytes());
            // SAFETY: `arg` is the validated user drm_get_cap pointer (16 bytes).
            unsafe { copy_out(arg, &out)? };
        }
        // fb_id is the first __u32 of struct drm_mode_fb_cmd2.
        crate::drm::ioctl::DrmIoctlResult::AddFb2(fb_id) if arg != 0 => {
            // SAFETY: `arg` is the validated user drm_mode_fb_cmd2 pointer.
            unsafe { copy_out(arg, &fb_id.to_le_bytes())? };
        }
        _ => {}
    }
    Ok(0)
}

// ── Misc ─────────────────────────────────────────────────────────────

/// Return the byte prefix of `buf` up to (but excluding) the first
/// NUL — i.e. the C-string content of a fixed-size buffer.
fn c_str_bytes(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    &buf[..n]
}
