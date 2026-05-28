//! DRM render nodes — `/dev/dri/renderDN`.
//!
//! Linux splits each DRM device into two character-device minors:
//!
//! - **Primary node** (`cardN`, minor `0..63`) — full ioctl access
//!   including modeset authority (`DRM_MASTER`), legacy mode-setting,
//!   and DRM_AUTH-gated calls.
//! - **Render node** (`renderD<128+N>`, minor `128..191`) — buffer
//!   allocation, command-buffer submission, and any ioctl marked
//!   `DRM_RENDER_ALLOW`.  No modeset, no auth, no master.
//!
//! Mesa/Vulkan/VAAPI render clients want only the second.  A
//! compositor (Wayland server, X server) holds the first.  This split
//! lets unprivileged GPU clients run without holding the display.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_drv.c::drm_minor_alloc` — minor-number
//!   allocation; ranges `64*type..64*type+63` for type
//!   `DRM_MINOR_PRIMARY` (0) or `DRM_MINOR_RENDER` (2).
//! - `drivers/gpu/drm/drm_ioctl.c::drm_ioctl_permit` — `DRM_AUTH` /
//!   `DRM_RENDER_ALLOW` gate (lines around 600-620).
//! - `include/drm/drm_file.h::drm_is_render_client` — returns true
//!   when the file's `minor->type == DRM_MINOR_RENDER`.

use super::card::Card;

/// Type of a DRM character-device minor.
///
/// Linux: `enum drm_minor_type` in `include/drm/drm_file.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MinorType {
    /// `/dev/dri/cardN` — full ioctl access (modeset, AUTH, MASTER).
    Primary,
    /// `/dev/dri/renderD<128+N>` — render-only (`DRM_RENDER_ALLOW`).
    Render,
}

/// A DRM minor — one character-device node for a single card.
///
/// Linux: `struct drm_minor` in `include/drm/drm_file.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DrmMinor {
    /// `Primary` or `Render`.
    pub kind: MinorType,
    /// Minor index assigned to this node.  Primary nodes get
    /// `card_index` (0..63); render nodes get `128 + card_index`
    /// (128..191).  Matches Linux's allocation scheme in
    /// `drm_minor_alloc`.
    pub index: u32,
    /// The card this minor maps onto.
    pub card_index: u32,
}

impl DrmMinor {
    /// Path under `/dev/dri/` for this minor.
    ///
    /// `Primary` → `cardN`, `Render` → `renderD<128+N>`.
    ///
    /// We return a stack `(prefix, idx)` tuple — the devfs layer
    /// formats the final name to avoid an alloc in this no_std crate.
    pub fn dev_path_parts(&self) -> (&'static str, u32) {
        match self.kind {
            MinorType::Primary => ("card", self.card_index),
            // Render-node names are the literal `renderD<128+N>` —
            // Linux gates on minor number, not the file name, but the
            // devfs path is what userspace opens.
            MinorType::Render => ("renderD", 128 + self.card_index),
        }
    }
}

// ── Ioctl permission flags ────────────────────────────────────────────

/// Per-ioctl permission flags.
///
/// Linux: `DRM_AUTH`, `DRM_MASTER`, `DRM_ROOT_ONLY`, `DRM_RENDER_ALLOW`
/// in `include/drm/drm_ioctl.h`.
#[derive(Copy, Clone, Debug, Default)]
pub struct IoctlFlags {
    /// Caller must be authenticated (or a render client).
    pub auth: bool,
    /// Caller must hold the device master lock.
    pub master: bool,
    /// Caller must be CAP_SYS_ADMIN.
    pub root_only: bool,
    /// Ioctl is allowed from render-node fds.  If this is `false` and
    /// the caller is a render client, the ioctl is rejected.
    pub render_allow: bool,
}

impl IoctlFlags {
    pub const fn render_allow() -> Self {
        IoctlFlags { auth: false, master: false, root_only: false, render_allow: true }
    }
    pub const fn auth_only() -> Self {
        IoctlFlags { auth: true, master: false, root_only: false, render_allow: false }
    }
    pub const fn master_only() -> Self {
        IoctlFlags { auth: false, master: true, root_only: false, render_allow: false }
    }
    pub const fn root_only() -> Self {
        IoctlFlags { auth: false, master: false, root_only: true, render_allow: false }
    }
    pub const fn unrestricted() -> Self {
        IoctlFlags { auth: false, master: false, root_only: false, render_allow: true }
    }
}

/// Per-open-file context — caller identity for ioctl permission checks.
///
/// Linux: a subset of `struct drm_file` — the fields needed to drive
/// `drm_ioctl_permit`.
#[derive(Copy, Clone, Debug)]
pub struct DrmFileCtx {
    /// Which minor this file was opened against.
    pub minor: MinorType,
    /// Whether the caller has run `DRM_IOCTL_AUTH_MAGIC`.
    pub authenticated: bool,
    /// Whether the caller holds the device master lock.
    pub is_master: bool,
    /// Whether the caller is CAP_SYS_ADMIN.
    pub is_root: bool,
}

impl DrmFileCtx {
    /// File context for a render-node open.  No master, no auth, no
    /// root — the kernel relies on the render-node minor's reduced
    /// ioctl surface, not on uid checks.
    pub const fn render_client() -> Self {
        DrmFileCtx {
            minor: MinorType::Render,
            authenticated: false,
            is_master: false,
            is_root: false,
        }
    }

    /// File context for a primary-node open by an authenticated master
    /// (e.g. a Wayland compositor).
    pub const fn primary_master() -> Self {
        DrmFileCtx {
            minor: MinorType::Primary,
            authenticated: true,
            is_master: true,
            is_root: false,
        }
    }

    /// Returns `true` when this file is a render client per
    /// `drm_is_render_client` in `include/drm/drm_file.h`.
    pub const fn is_render_client(&self) -> bool {
        matches!(self.minor, MinorType::Render)
    }
}

/// Ioctl permission errors.
///
/// Linux returns `-EACCES` for all four; we keep the discriminant
/// so the dispatcher can log which gate fired.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PermError {
    /// Caller is a render client and the ioctl is not `DRM_RENDER_ALLOW`.
    RenderDenied,
    /// `DRM_AUTH` set but caller isn't authenticated (or a render client).
    NotAuthenticated,
    /// `DRM_MASTER` set but caller isn't the master.
    NotMaster,
    /// `DRM_ROOT_ONLY` set but caller isn't root.
    NotRoot,
}

/// Gate an ioctl against `ctx` per Linux's `drm_ioctl_permit`.
///
/// Mirrors `drivers/gpu/drm/drm_ioctl.c::drm_ioctl_permit` line-for-line.
pub fn check_permission(flags: IoctlFlags, ctx: &DrmFileCtx) -> Result<(), PermError> {
    // ROOT_ONLY first — root override.
    if flags.root_only && !ctx.is_root {
        return Err(PermError::NotRoot);
    }
    // AUTH: render clients are implicitly authenticated.
    if flags.auth && !ctx.is_render_client() && !ctx.authenticated {
        return Err(PermError::NotAuthenticated);
    }
    // MASTER: only the master can run mastering ioctls.
    if flags.master && !ctx.is_master {
        return Err(PermError::NotMaster);
    }
    // Render clients are only allowed RENDER_ALLOW ioctls.
    if !flags.render_allow && ctx.is_render_client() {
        return Err(PermError::RenderDenied);
    }
    Ok(())
}

// ── Card registration ─────────────────────────────────────────────────

impl Card {
    /// Compute the primary node for a card at `card_index`.
    ///
    /// Linux equivalent: `drm_minor_alloc(dev, DRM_MINOR_PRIMARY)`.
    pub fn primary_node(card_index: u32) -> DrmMinor {
        DrmMinor { kind: MinorType::Primary, index: card_index, card_index }
    }

    /// Compute the render node for a card at `card_index`.
    ///
    /// Linux equivalent: `drm_minor_alloc(dev, DRM_MINOR_RENDER)`.
    pub fn render_node(card_index: u32) -> DrmMinor {
        DrmMinor { kind: MinorType::Render, index: 128 + card_index, card_index }
    }
}

/// Look up the per-ioctl flags table — what permission each DRM ioctl
/// needs.  Matches `drm_ioctls[]` in `drivers/gpu/drm/drm_ioctl.c`.
///
/// Only the ioctls implemented in this kernel are listed; unknown
/// ioctls return `None` (the dispatcher then yields `UnknownCmd`).
pub fn ioctl_flags(cmd: u32) -> Option<IoctlFlags> {
    match cmd & 0xFF {
        // VERSION + GET_CAP are RENDER_ALLOW per Linux.
        0x00 => Some(IoctlFlags::render_allow()),
        0x0C => Some(IoctlFlags::render_allow()),
        // GETRESOURCES, GETCONNECTOR, GETPLANE_RES — display-side, NOT
        // RENDER_ALLOW in upstream.  Linux marks them DRM_AUTH (a
        // legacy auth gate); we keep the auth flag so render clients
        // are blocked but plain (non-master, authenticated) clients
        // can still enumerate.
        0xA0 | 0xA7 | 0xB5 => Some(IoctlFlags::auth_only()),
        // ADDFB2 / RMFB — DRM_MASTER (display authority).
        0xB8 | 0xA8 => Some(IoctlFlags::master_only()),
        // ATOMIC commit — DRM_MASTER.
        0xBC => Some(IoctlFlags::master_only()),
        // PRIME handle ↔ fd — RENDER_ALLOW (no display authority needed).
        0x2D | 0x2E => Some(IoctlFlags::render_allow()),
        // SYNCOBJ create/destroy/wait/signal — RENDER_ALLOW.
        0xBF | 0xC0 | 0xC3 | 0xC5 => Some(IoctlFlags::render_allow()),
        _ => None,
    }
}
