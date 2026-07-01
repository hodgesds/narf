//! DRM ioctl dispatch + wire-format structs.
//!
//! Implements the minimal set of DRM ioctls needed to drive a
//! mode-setting session from userspace:
//!
//! | ioctl                    | Linux define            | purpose                      |
//! |--------------------------|-------------------------|------------------------------|
//! | `DRM_IOCTL_VERSION`      | `0x00`                  | driver identity + version    |
//! | `DRM_IOCTL_GET_CAP`      | `0x0C`                  | query capability bits        |
//! | `DRM_IOCTL_MODE_GETRESOURCES` | `0xA0`           | list CRTCs / connectors      |
//! | `DRM_IOCTL_MODE_GETPLANE_RES` | `0xB5`           | list planes (stub)           |
//! | `DRM_IOCTL_MODE_GETCONNECTOR` | `0xA7`           | connector + mode list        |
//! | `DRM_IOCTL_MODE_ADDFB2`  | `0xB8`                  | register framebuffer         |
//! | `DRM_IOCTL_MODE_RMFB`    | `0xA8`                  | remove framebuffer           |
//!
//! Wire-format structs match the ABI in `include/uapi/drm/drm.h` and
//! `include/uapi/drm/drm_mode.h` (Linux).  All fields are little-endian
//! as on x86-64.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_ioctl.c` — dispatch table + permission checks.
//! - `drivers/gpu/drm/drm_crtc.c` / `drm_connector.c` — GETRESOURCES,
//!   GETCONNECTOR.
//! - `drivers/gpu/drm/drm_framebuffer.c` — ADDFB2 / RMFB.
//! - `include/uapi/drm/drm_mode.h` — all mode-setting wire structs.

use super::card::{Card, CardError, ConnectorType};
use super::render_node::{check_permission, ioctl_flags, DrmFileCtx, PermError};

// ── Ioctl command codes ────────────────────────────────────────────────

/// DRM ioctl command (matches `_IOC` encoding from `include/uapi/drm/drm.h`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum IoctlCmd {
    Version = 0x00,
    GemClose = 0x09,
    GetCap = 0x0C,
    SetClientCap = 0x0D,
    SetMaster = 0x1E,
    DropMaster = 0x1F,
    PrimeHandleToFd = 0x2D,
    PrimeFdToHandle = 0x2E,
    ModeGetResources = 0xA0,
    ModeGetCrtc = 0xA1,
    ModeSetCrtc = 0xA2,
    ModeCursor = 0xA3,
    ModeSetGamma = 0xA5,
    ModeGetEncoder = 0xA6,
    ModeGetConnector = 0xA7,
    ModeRmFb = 0xA8,
    ModePageFlip = 0xB0,
    ModeCreateDumb = 0xB2,
    ModeMapDumb = 0xB3,
    ModeDestroyDumb = 0xB4,
    ModeAddFb2 = 0xB8,
    ModeObjGetProperties = 0xB9,
    ModeGetProperty = 0xAA,
    ModeGetPlaneRes = 0xB5,
    ModeGetPlane = 0xB6,
    ModeCursor2 = 0xBB,
    ModeAtomic = 0xBC,
    SyncobjCreate = 0xBF,
    SyncobjDestroy = 0xC0,
    SyncobjWait = 0xC3,
    SyncobjSignal = 0xC5,
    /// Unrecognised ioctl — returned as an error.
    Unknown = 0xFF,
}

impl IoctlCmd {
    /// Decode from the raw ioctl number (lower 8 bits after stripping direction/size).
    pub fn from_raw(raw: u32) -> Self {
        match raw & 0xFF {
            0x00 => IoctlCmd::Version,
            0x09 => IoctlCmd::GemClose,
            0x0C => IoctlCmd::GetCap,
            0x0D => IoctlCmd::SetClientCap,
            0x1E => IoctlCmd::SetMaster,
            0x1F => IoctlCmd::DropMaster,
            0x2D => IoctlCmd::PrimeHandleToFd,
            0x2E => IoctlCmd::PrimeFdToHandle,
            0xA0 => IoctlCmd::ModeGetResources,
            0xA1 => IoctlCmd::ModeGetCrtc,
            0xA2 => IoctlCmd::ModeSetCrtc,
            0xA3 => IoctlCmd::ModeCursor,
            0xA5 => IoctlCmd::ModeSetGamma,
            0xA6 => IoctlCmd::ModeGetEncoder,
            0xA7 => IoctlCmd::ModeGetConnector,
            0xA8 => IoctlCmd::ModeRmFb,
            0xB9 => IoctlCmd::ModeObjGetProperties,
            0xAA => IoctlCmd::ModeGetProperty,
            0xB6 => IoctlCmd::ModeGetPlane,
            0xB0 => IoctlCmd::ModePageFlip,
            0xB2 => IoctlCmd::ModeCreateDumb,
            0xB3 => IoctlCmd::ModeMapDumb,
            0xB4 => IoctlCmd::ModeDestroyDumb,
            0xB8 => IoctlCmd::ModeAddFb2,
            0xB5 => IoctlCmd::ModeGetPlaneRes,
            0xBB => IoctlCmd::ModeCursor2,
            0xBC => IoctlCmd::ModeAtomic,
            0xBF => IoctlCmd::SyncobjCreate,
            0xC0 => IoctlCmd::SyncobjDestroy,
            0xC3 => IoctlCmd::SyncobjWait,
            0xC5 => IoctlCmd::SyncobjSignal,
            _ => IoctlCmd::Unknown,
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────────

/// Errors from the ioctl layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DrmIoctlError {
    /// Unknown ioctl command.
    UnknownCmd,
    /// Argument buffer is too small for the requested struct.
    BadSize,
    /// The operation failed at the card level.
    Card(CardError),
    /// Connector id not found.
    UnknownConnector,
    /// Permission denied per render-node / DRM_AUTH / DRM_MASTER gate.
    ///
    /// Linux: `-EACCES` returned from `drm_ioctl_permit`
    /// (`drivers/gpu/drm/drm_ioctl.c`).
    PermissionDenied(PermError),
}

impl From<CardError> for DrmIoctlError {
    fn from(e: CardError) -> Self {
        DrmIoctlError::Card(e)
    }
}

impl From<PermError> for DrmIoctlError {
    fn from(e: PermError) -> Self {
        DrmIoctlError::PermissionDenied(e)
    }
}

// ── Wire-format structs ────────────────────────────────────────────────

/// `struct drm_version` — DRM_IOCTL_VERSION.
///
/// Linux: `include/uapi/drm/drm.h`.
#[derive(Clone, Debug)]
pub struct DrmVersion {
    pub version_major: i32,
    pub version_minor: i32,
    pub version_patchlevel: i32,
    pub name: [u8; 32],
    pub date: [u8; 32],
    pub desc: [u8; 64],
}

impl Default for DrmVersion {
    fn default() -> Self {
        DrmVersion {
            version_major: 0,
            version_minor: 0,
            version_patchlevel: 0,
            name: [0u8; 32],
            date: [0u8; 32],
            desc: [0u8; 64],
        }
    }
}

/// `struct drm_get_cap` — DRM_IOCTL_GET_CAP.
///
/// Linux: `include/uapi/drm/drm.h`.
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmGetCap {
    pub capability: u64,
    pub value: u64,
}

/// DRM capability IDs (subset).
///
/// Linux: `DRM_CAP_*` in `include/uapi/drm/drm.h`.
pub mod drm_cap {
    pub const DUMB_BUFFER: u64 = 0x01;
    pub const VBLANK_HIGH_CRTC: u64 = 0x02;
    pub const DUMB_PREFERRED_DEPTH: u64 = 0x03;
    pub const DUMB_PREFER_SHADOW: u64 = 0x04;
    pub const PRIME: u64 = 0x05;
    pub const TIMESTAMP_MONOTONIC: u64 = 0x06;
    pub const ASYNC_PAGE_FLIP: u64 = 0x07;
    pub const CURSOR_WIDTH: u64 = 0x08;
    pub const CURSOR_HEIGHT: u64 = 0x09;
    pub const ADDFB2_MODIFIERS: u64 = 0x10;
    pub const PAGE_FLIP_TARGET: u64 = 0x11;
    pub const CRTC_IN_VBLANK_EVENT: u64 = 0x12;
    pub const SYNCOBJ: u64 = 0x13;
    pub const SYNCOBJ_TIMELINE: u64 = 0x14;
}

/// `struct drm_mode_card_res` — DRM_IOCTL_MODE_GETRESOURCES.
///
/// Linux: `include/uapi/drm/drm_mode.h`.
#[derive(Clone, Debug, Default)]
pub struct DrmModeCardRes {
    pub fb_id_ptr: u64,
    pub crtc_id_ptr: u64,
    pub connector_id_ptr: u64,
    pub encoder_id_ptr: u64,
    pub count_fbs: u32,
    pub count_crtcs: u32,
    pub count_connectors: u32,
    pub count_encoders: u32,
    pub min_width: u32,
    pub max_width: u32,
    pub min_height: u32,
    pub max_height: u32,
}

/// `struct drm_mode_modeinfo` — one display mode entry.
///
/// Linux: `include/uapi/drm/drm_mode.h`.
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeModeInfo {
    pub clock: u32,
    pub hdisplay: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub hskew: u16,
    pub vdisplay: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub vscan: u16,
    pub vrefresh: u32,
    pub flags: u32,
    pub r#type: u32,
    pub name: [u8; 32],
}

/// `struct drm_mode_get_connector` — DRM_IOCTL_MODE_GETCONNECTOR.
///
/// Linux: `include/uapi/drm/drm_mode.h`.
#[derive(Clone, Debug, Default)]
pub struct DrmModeGetConnector {
    pub encoders_ptr: u64,
    pub modes_ptr: u64,
    pub props_ptr: u64,
    pub prop_values_ptr: u64,
    pub count_modes: u32,
    pub count_props: u32,
    pub count_encoders: u32,
    pub encoder_id: u32,
    pub connector_id: u32,
    pub connector_type: u32,
    pub connector_type_id: u32,
    pub connection: u32,
    pub mm_width: u32,
    pub mm_height: u32,
    pub subpixel: u32,
    pub pad: u32,
}

/// `struct drm_mode_fb_cmd2` — DRM_IOCTL_MODE_ADDFB2.
///
/// Linux: `include/uapi/drm/drm_mode.h`.
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeFbCmd2 {
    pub fb_id: u32,
    pub width: u32,
    pub height: u32,
    pub pixel_format: u32,
    pub flags: u32,
    pub handles: [u32; 4],
    pub pitches: [u32; 4],
    pub offsets: [u32; 4],
    pub modifier: [u64; 4],
}

/// `struct drm_mode_rmfb` (just a u32 fb_id).
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeRmFb {
    pub fb_id: u32,
}

// ── Dispatch ──────────────────────────────────────────────────────────

/// Typed result returned from the dispatcher to the caller.
///
/// Each variant wraps the filled-out response struct; the caller
/// serialises it back to the userspace buffer.
#[derive(Debug)]
pub enum DrmIoctlResult {
    Version(DrmVersion),
    GetCap(DrmGetCap),
    GetResources(DrmModeCardRes),
    GetConnector(DrmModeGetConnector, alloc::vec::Vec<DrmModeModeInfo>),
    AddFb2(u32),
    RmFb,
    GetPlaneRes {
        count_planes: u32,
    },
    /// CREATE_DUMB result: (handle, pitch, size).
    CreateDumb {
        handle: u32,
        pitch: u32,
        size: u64,
    },
    /// MAP_DUMB result: fake mmap offset.
    MapDumb {
        offset: u64,
    },
    /// Generic success with no output payload.
    Ok,
}

/// Dispatch a DRM ioctl against `card` for the calling `ctx`.
///
/// `cmd` is the ioctl number (lower 8 bits used).
/// `arg` is the ioctl argument — an opaque byte buffer whose layout
/// is determined by `cmd`.
/// `ctx` carries the per-fd identity (render-node vs primary,
/// auth/master/root status); permission is checked before dispatch.
///
/// Returns a typed result or an error.
///
/// Linux equivalent: `drm_ioctl()` in `drivers/gpu/drm/drm_ioctl.c`
/// (which calls `drm_ioctl_permit` first, then the per-ioctl func).
pub fn dispatch(
    card: &mut Card,
    cmd: u32,
    arg: &[u8],
    ctx: &DrmFileCtx,
) -> Result<DrmIoctlResult, DrmIoctlError> {
    // Permission gate — mirrors drm_ioctl.c::drm_ioctl_permit.
    // Unknown commands skip the gate and fall through to UnknownCmd.
    if let Some(flags) = ioctl_flags(cmd) {
        check_permission(flags, ctx)?;
    }
    match IoctlCmd::from_raw(cmd) {
        IoctlCmd::Version => handle_version(card),
        IoctlCmd::GetCap => handle_get_cap(arg),
        IoctlCmd::ModeGetResources => handle_getresources(card),
        IoctlCmd::ModeGetConnector => handle_getconnector(card, arg),
        IoctlCmd::ModeAddFb2 => handle_addfb2(card, arg),
        IoctlCmd::ModeRmFb => handle_rmfb(card, arg),
        IoctlCmd::ModeGetPlaneRes => handle_getplane_res(card),
        // GemClose: handled in the bridge where we can free the backing.
        // Return Ok here so the permission gate fires correctly.
        IoctlCmd::GemClose => handle_gem_close(card, arg),
        // Atomic / syncobj / prime ioctls are dispatched via the
        // higher-level entry points in their own modules (the per-fd
        // tables don't live on `Card`); the dispatcher just returns
        // UnknownCmd for now so callers route them explicitly.
        IoctlCmd::ModeAtomic
        | IoctlCmd::SyncobjCreate
        | IoctlCmd::SyncobjDestroy
        | IoctlCmd::SyncobjWait
        | IoctlCmd::SyncobjSignal
        | IoctlCmd::PrimeHandleToFd
        | IoctlCmd::PrimeFdToHandle => Err(DrmIoctlError::UnknownCmd),
        // Dumb-buffer / modeset ioctls — handled in the bridge with
        // full serialisation of the in/out structs.
        IoctlCmd::ModeSetCrtc
        | IoctlCmd::ModeGetCrtc
        | IoctlCmd::ModeGetEncoder
        | IoctlCmd::ModeSetGamma
        | IoctlCmd::SetMaster
        | IoctlCmd::DropMaster
        | IoctlCmd::SetClientCap
        | IoctlCmd::ModeObjGetProperties
        | IoctlCmd::ModeGetProperty
        | IoctlCmd::ModeGetPlane
        | IoctlCmd::ModePageFlip
        | IoctlCmd::ModeCreateDumb
        | IoctlCmd::ModeMapDumb
        // CURSOR / CURSOR2 are handled in the bridge (they drive narf_fb's
        // software cursor); they never reach this generic dispatcher.
        | IoctlCmd::ModeCursor
        | IoctlCmd::ModeCursor2
        | IoctlCmd::ModeDestroyDumb => Err(DrmIoctlError::UnknownCmd),
        IoctlCmd::Unknown => Err(DrmIoctlError::UnknownCmd),
    }
}

// ── Handlers ──────────────────────────────────────────────────────────

fn handle_version(card: &Card) -> Result<DrmIoctlResult, DrmIoctlError> {
    let mut v = DrmVersion {
        version_major: card.version.0 as i32,
        version_minor: card.version.1 as i32,
        version_patchlevel: card.version.2 as i32,
        ..Default::default()
    };
    copy_str_to_buf(&mut v.name, card.driver_name);
    copy_str_to_buf(&mut v.desc, card.driver_desc);
    Ok(DrmIoctlResult::Version(v))
}

fn handle_get_cap(arg: &[u8]) -> Result<DrmIoctlResult, DrmIoctlError> {
    if arg.len() < 16 {
        return Err(DrmIoctlError::BadSize);
    }
    let capability = u64::from_le_bytes(arg[0..8].try_into().unwrap());
    let value = match capability {
        drm_cap::DUMB_BUFFER => 1u64, // dumb-buffer alloc supported
        // DRM_PRIME_CAP_EXPORT (1) | DRM_PRIME_CAP_IMPORT (2): both
        // supported via drm/prime.rs PrimeTable.
        drm_cap::PRIME => 3,
        // SYNCOBJ (timeline=0) — drm/syncobj.rs implements binary
        // syncobjs; timelines are deferred.
        drm_cap::SYNCOBJ => 1,
        drm_cap::SYNCOBJ_TIMELINE => 0,
        drm_cap::TIMESTAMP_MONOTONIC => 1,
        drm_cap::ADDFB2_MODIFIERS => 0, // no format modifiers yet
        drm_cap::CURSOR_WIDTH => 64,
        drm_cap::CURSOR_HEIGHT => 64,
        _ => 0,
    };
    Ok(DrmIoctlResult::GetCap(DrmGetCap { capability, value }))
}

fn handle_getresources(card: &Card) -> Result<DrmIoctlResult, DrmIoctlError> {
    let res = DrmModeCardRes {
        count_fbs: card.framebuffers.len() as u32,
        count_crtcs: card.crtcs.len() as u32,
        count_connectors: card.connectors.len() as u32,
        count_encoders: card.encoders.len() as u32,
        min_width: 1,
        max_width: 16384,
        min_height: 1,
        max_height: 16384,
        // Pointer fields are filled by the userspace layer; we return
        // the counts so callers can allocate the right-sized arrays.
        ..Default::default()
    };
    Ok(DrmIoctlResult::GetResources(res))
}

fn handle_getconnector(card: &Card, arg: &[u8]) -> Result<DrmIoctlResult, DrmIoctlError> {
    // `connector_id` is at offset 48 of struct drm_mode_get_connector
    // (after encoders_ptr/modes_ptr/props_ptr/prop_values_ptr = 4×u64 and
    // count_modes/count_props/count_encoders/encoder_id = 4×u32). On a
    // libdrm count-probe pass the four out-pointers are zero, so reading
    // the id from offset 0 looked up connector 0 → UnknownConnector → EINVAL.
    if arg.len() < 52 {
        return Err(DrmIoctlError::BadSize);
    }
    let connector_id = u32::from_le_bytes(arg[48..52].try_into().unwrap());
    let conn = card
        .connector(connector_id)
        .map_err(|_| DrmIoctlError::UnknownConnector)?;

    let modes: alloc::vec::Vec<DrmModeModeInfo> = conn.modes.iter().map(mode_to_wire).collect();

    let info = DrmModeGetConnector {
        count_modes: modes.len() as u32,
        count_props: 0,
        count_encoders: conn.encoder_id.map(|_| 1).unwrap_or(0),
        encoder_id: conn.encoder_id.unwrap_or(0),
        connector_id: conn.id,
        connector_type: conn.connector_type as u32,
        connector_type_id: conn.connector_type_id,
        connection: conn.status as u32,
        mm_width: 0,
        mm_height: 0,
        subpixel: 1, // SubPixelHorizontalRGB
        ..Default::default()
    };
    Ok(DrmIoctlResult::GetConnector(info, modes))
}

fn handle_addfb2(card: &mut Card, arg: &[u8]) -> Result<DrmIoctlResult, DrmIoctlError> {
    // struct drm_mode_fb_cmd2 is at least 68 bytes.
    if arg.len() < 68 {
        return Err(DrmIoctlError::BadSize);
    }
    // fb_id is at offset 0 (output) — skip; width at 4, height at 8.
    let width = u32::from_le_bytes(arg[4..8].try_into().unwrap());
    let height = u32::from_le_bytes(arg[8..12].try_into().unwrap());
    let pixel_format = u32::from_le_bytes(arg[12..16].try_into().unwrap());
    // flags at 16 (ignored for now).
    // handles[0] at 20.
    let gem_handle = u32::from_le_bytes(arg[20..24].try_into().unwrap());
    // pitches[0] at 36.
    let pitch = u32::from_le_bytes(arg[36..40].try_into().unwrap());

    let fb_id = card.addfb2(width, height, pixel_format, pitch, gem_handle)?;
    Ok(DrmIoctlResult::AddFb2(fb_id))
}

fn handle_rmfb(card: &mut Card, arg: &[u8]) -> Result<DrmIoctlResult, DrmIoctlError> {
    if arg.len() < 4 {
        return Err(DrmIoctlError::BadSize);
    }
    let fb_id = u32::from_le_bytes(arg[0..4].try_into().unwrap());
    card.rmfb(fb_id)?;
    Ok(DrmIoctlResult::RmFb)
}

fn handle_gem_close(card: &mut Card, arg: &[u8]) -> Result<DrmIoctlResult, DrmIoctlError> {
    if arg.len() < 4 {
        return Err(DrmIoctlError::BadSize);
    }
    let handle = u32::from_le_bytes(arg[0..4].try_into().unwrap());
    // Remove dumb backing if one exists (frees the physical pages).
    // Physical memory freeing is deferred to the bridge layer that has
    // access to narf_memory (this ioctl layer is pure logic).
    // We just remove from the GEM table here; bridge calls the physical free.
    let _ = card.gem.free(handle);
    Ok(DrmIoctlResult::Ok)
}

fn handle_getplane_res(card: &Card) -> Result<DrmIoctlResult, DrmIoctlError> {
    // We have no plane objects yet (atomic KMS is deferred).
    // Return count = 0; userspace compositors tolerate this and fall
    // back to legacy CRTC/connector path.
    let _ = card;
    Ok(DrmIoctlResult::GetPlaneRes { count_planes: 0 })
}

// ── Helpers ───────────────────────────────────────────────────────────

fn copy_str_to_buf(buf: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let copy_len = bytes.len().min(buf.len().saturating_sub(1));
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    if copy_len < buf.len() {
        buf[copy_len] = 0;
    }
}

pub(crate) fn mode_to_wire(m: &crate::Mode) -> DrmModeModeInfo {
    let mut info = DrmModeModeInfo {
        hdisplay: m.width as u16,
        vdisplay: m.height as u16,
        vrefresh: m.refresh_hz as u32,
        ..Default::default()
    };
    // Fill htotal/vtotal with minimal plausible values if unknown.
    info.htotal = info.hdisplay + 160;
    info.vtotal = info.vdisplay + 45;
    info.hsync_start = info.hdisplay + 32;
    info.hsync_end = info.hdisplay + 64;
    info.vsync_start = info.vdisplay + 3;
    info.vsync_end = info.vdisplay + 8;
    // Approximate pixel clock: h × v × refresh / 1000 = kHz.
    let dot_clk_khz = (info.htotal as u32) * (info.vtotal as u32) * m.refresh_hz as u32;
    info.clock = dot_clk_khz / 1000;
    // Mode name — libdrm/modetest match a requested mode by this string
    // (e.g. `1280x800`). An empty name means `modetest -s 3@1:1280x800`
    // can't find the mode and falls through to a 0×0 dumb buffer (EINVAL).
    let name = alloc::format!("{}x{}", m.width, m.height);
    copy_str_to_buf(&mut info.name, &name);
    info
}

/// Convert a `ConnectorType` to its Linux uapi u32 discriminant.
///
/// Kept public so `tests.rs` can assert the wire value independently.
pub fn connector_type_wire(ct: ConnectorType) -> u32 {
    ct as u32
}
