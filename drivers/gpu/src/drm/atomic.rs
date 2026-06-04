//! Atomic mode-setting state machine.
//!
//! KMS userspace (Wayland, KWin, mutter, sway, libinput-tests) drives
//! the display via *atomic* state submissions: each commit names the
//! complete set of CRTC / connector / plane state for a single frame.
//! The kernel either rejects the whole commit (`atomic_check`) or
//! applies the whole commit (`atomic_commit`) — never a partial.
//!
//! Linux's atomic model:
//!
//! - `struct drm_atomic_state` carries arrays of [(old, new)] state
//!   per object (CRTC, connector, plane, colorop, private).
//! - `drm_atomic_check_only` walks each object kind, calls the per-kind
//!   core check (`drm_atomic_plane_check`, `_crtc_check`, `_connector_check`),
//!   then delegates to the driver's `mode_config.funcs->atomic_check`.
//! - On a successful check, `drm_atomic_commit` writes the new state to
//!   the live device.  `allow_modeset` gates whether the commit can
//!   change CRTC enable/mode (a "nuclear" page-flip caller asks for
//!   page-flip only; a modeset caller may change enable).
//!
//! What lands:
//!
//! - [`AtomicState`] — the in-flight transaction.
//! - [`ConnectorState`] / [`CrtcState`] / [`PlaneState`] — one
//!   per-object delta entry.
//! - [`AtomicCheckPolicy`] — bandwidth + plane-to-CRTC reachability
//!   carried as input to `atomic_check`.
//! - `atomic_check` / `atomic_commit` — driver-implemented hooks via
//!   the [`AtomicOps`] trait.  The core helpers
//!   [`AtomicState::core_check`] and [`AtomicState::core_commit`]
//!   run the kind-by-kind validation that Linux's atomic-core does
//!   before/after the driver hook.
//!
//! ## Deferred
//!
//! - DRM properties on the state (we only carry the data fields).
//! - PROP_OUT_FENCE_PTR / page-flip event delivery.  These hook into
//!   the syncobj + fb-event layers once the userspace fd table is up.
//!
//! ## Linux references
//!
//! - `drivers/gpu/drm/drm_atomic.c::drm_atomic_check_only`
//! - `drivers/gpu/drm/drm_atomic.c::drm_atomic_commit`
//! - `drivers/gpu/drm/drm_atomic.c::drm_atomic_plane_check`
//! - `drivers/gpu/drm/drm_atomic_uapi.c::drm_mode_atomic_ioctl`

use super::card::Card;
use alloc::vec::Vec;

// ── Errors ─────────────────────────────────────────────────────────────

/// Errors from atomic check / commit.
///
/// Linux returns negative errnos (`-EINVAL`, `-ENOSPC`, `-ERANGE`); we
/// give each gate a discriminant so the dispatcher can surface a
/// useful kernel-log line.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AtomicError {
    /// CRTC id not registered.
    UnknownCrtc,
    /// Connector id not registered.
    UnknownConnector,
    /// Plane id not registered.
    UnknownPlane,
    /// Mode-line is missing or unsupported on the target connector.
    InvalidMode,
    /// Plane is not in the CRTC's `possible_crtcs` bitmask.
    PlaneNotInRange,
    /// Plane has a CRTC set but no FB, or vice versa — Linux returns
    /// -EINVAL.
    PlaneFbCrtcMismatch,
    /// Plane source/dst rectangle is out of bounds.
    PlaneOutOfRange,
    /// FB id does not resolve on this card.
    UnknownFb,
    /// Bandwidth budget would be exceeded (driver-side gate).
    OverBandwidth,
    /// CRTC enable changed but `allow_modeset` is `false`.
    ModesetNotAllowed,
    /// `core_commit` ran before `core_check`.
    NotChecked,
}

// ── Per-object state ───────────────────────────────────────────────────

/// Delta state for a single CRTC.
///
/// Linux: `struct drm_crtc_state`.  We carry just the fields the
/// core check + driver check need; properties / color-mgmt / vblank
/// hooks land later.
#[derive(Clone, Debug, Default)]
pub struct CrtcState {
    /// CRTC id this state applies to.
    pub id: u32,
    /// Whether the CRTC should be enabled.
    pub enable: bool,
    /// Whether the CRTC is currently scanning out (transient: driver
    /// fills this in during the commit).
    pub active: bool,
    /// Mode-line for the CRTC; `None` if the CRTC is disabled.
    pub mode: Option<crate::Mode>,
    /// Was the mode changed in this commit?  Tracked so the dispatcher
    /// can reject page-flip-only commits that try to switch modes.
    pub mode_changed: bool,
    /// Was the connector binding changed?
    pub connectors_changed: bool,
}

impl CrtcState {
    /// Did this commit ask for a full modeset?  Linux uses
    /// `drm_atomic_crtc_needs_modeset` for the same predicate.
    pub fn needs_modeset(&self) -> bool {
        self.mode_changed || self.connectors_changed
    }
}

/// Delta state for a single connector.
///
/// Linux: `struct drm_connector_state`.
#[derive(Clone, Debug, Default)]
pub struct ConnectorState {
    pub id: u32,
    /// Target CRTC; `None` means the connector is disconnected from
    /// any CRTC for this commit.
    pub crtc_id: Option<u32>,
}

/// Delta state for a single plane.
///
/// Linux: `struct drm_plane_state`.  Coordinates are in pixel-space
/// (CRTC) and Q16.16 fixed-point (source) on Linux; we use plain ints
/// because we don't yet have a scanline-pipeline-rate model.
#[derive(Clone, Debug, Default)]
pub struct PlaneState {
    pub id: u32,
    pub crtc_id: Option<u32>,
    pub fb_id: Option<u32>,
    /// Destination on the CRTC.
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    /// Source within the FB (pixels).
    pub src_x: u32,
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
}

// ── AtomicState ────────────────────────────────────────────────────────

/// One in-flight atomic transaction.
///
/// Built up by `DRM_IOCTL_MODE_ATOMIC` decode; passed by reference to
/// the driver's `atomic_check` and `atomic_commit` hooks.
///
/// Linux equivalent: `struct drm_atomic_state`.
#[derive(Clone, Debug, Default)]
pub struct AtomicState {
    pub connectors: Vec<ConnectorState>,
    pub crtcs: Vec<CrtcState>,
    pub planes: Vec<PlaneState>,
    /// Whether this commit is allowed to do a full modeset.  Mirrors
    /// `drm_atomic_state::allow_modeset` — set by the dispatcher from
    /// the `DRM_MODE_ATOMIC_ALLOW_MODESET` flag.
    pub allow_modeset: bool,
    /// `true` once `core_check` succeeded — Linux's `state->checked`.
    pub checked: bool,
}

/// Per-card limits the core check enforces — replaces Linux's
/// per-object property bitmasks for the fields we don't yet have.
#[derive(Copy, Clone, Debug)]
pub struct AtomicCheckPolicy {
    /// `1 << crtc_index` ⇒ plane is reachable on that CRTC.
    pub plane_possible_crtcs: u32,
    /// Maximum bandwidth in plane-pixels per commit.  0 disables the
    /// check (driver may impose a tighter cap in its `atomic_check`
    /// hook).
    pub max_pixel_budget: u64,
}

impl Default for AtomicCheckPolicy {
    fn default() -> Self {
        AtomicCheckPolicy {
            plane_possible_crtcs: 0xFFFF_FFFF,
            max_pixel_budget: 0,
        }
    }
}

// ── Driver-implemented hooks ───────────────────────────────────────────

/// Trait implemented by per-driver atomic hooks.
///
/// Linux equivalent: `struct drm_mode_config_funcs` fields
/// `atomic_check` and `atomic_commit`.  A driver registers a
/// `&'static dyn AtomicOps` with the card; the core dispatcher calls
/// these after the kind-by-kind core check / before the kind-by-kind
/// core commit.
pub trait AtomicOps: Send + Sync {
    /// Driver-side check (called after `core_check`).
    fn atomic_check(&self, card: &Card, state: &AtomicState) -> Result<(), AtomicError>;
    /// Driver-side commit (called before `core_commit` writes the new
    /// state into the card).
    fn atomic_commit(&self, card: &mut Card, state: &AtomicState) -> Result<(), AtomicError>;
}

// ── Core check / commit ────────────────────────────────────────────────

impl AtomicState {
    /// Run the core atomic check — the kind-by-kind validation Linux's
    /// `drm_atomic_check_only` does before delegating to the driver.
    ///
    /// On success, sets `self.checked = true`.
    pub fn core_check(
        &mut self,
        card: &Card,
        policy: &AtomicCheckPolicy,
    ) -> Result<(), AtomicError> {
        // 1. Object existence — every id in our deltas must resolve on
        //    the card.
        for c in &self.crtcs {
            if !card.crtcs.iter().any(|x| x.id == c.id) {
                return Err(AtomicError::UnknownCrtc);
            }
        }
        for c in &self.connectors {
            if !card.connectors.iter().any(|x| x.id == c.id) {
                return Err(AtomicError::UnknownConnector);
            }
            if let Some(crtc_id) = c.crtc_id {
                if !card.crtcs.iter().any(|x| x.id == crtc_id) {
                    return Err(AtomicError::UnknownCrtc);
                }
            }
        }
        // 2. drm_atomic_plane_check — CRTC ↔ FB both-or-neither;
        //    plane in CRTC's possible_crtcs; coordinate bounds.
        for p in &self.planes {
            // Either both crtc_id and fb_id are set or neither.
            match (p.crtc_id, p.fb_id) {
                (Some(_), Some(_)) | (None, None) => {}
                _ => return Err(AtomicError::PlaneFbCrtcMismatch),
            }
            if let Some(crtc_id) = p.crtc_id {
                let crtc_idx = card
                    .crtcs
                    .iter()
                    .position(|c| c.id == crtc_id)
                    .ok_or(AtomicError::UnknownCrtc)? as u32;
                let mask = 1u32 << crtc_idx;
                if (policy.plane_possible_crtcs & mask) == 0 {
                    return Err(AtomicError::PlaneNotInRange);
                }
            }
            if let Some(fb_id) = p.fb_id {
                let fb = card
                    .framebuffer(fb_id)
                    .map_err(|_| AtomicError::UnknownFb)?;
                // Source rect inside the FB.
                let src_end_x = p.src_x.checked_add(p.src_w);
                let src_end_y = p.src_y.checked_add(p.src_h);
                let (ex, ey) = match (src_end_x, src_end_y) {
                    (Some(x), Some(y)) => (x, y),
                    _ => return Err(AtomicError::PlaneOutOfRange),
                };
                if ex > fb.width || ey > fb.height {
                    return Err(AtomicError::PlaneOutOfRange);
                }
            }
        }
        // 3. Mode-set vs allow_modeset gate — Linux refuses to modeset
        //    when the caller didn't ask for it.
        if !self.allow_modeset {
            for c in &self.crtcs {
                if c.needs_modeset() {
                    return Err(AtomicError::ModesetNotAllowed);
                }
            }
        }
        // 4. Bandwidth budget — sum CRTC pixels-per-frame across
        //    enabled planes and reject if over budget.
        if policy.max_pixel_budget > 0 {
            let mut bw: u64 = 0;
            for p in &self.planes {
                if p.fb_id.is_some() && p.crtc_id.is_some() {
                    bw = bw.saturating_add(u64::from(p.crtc_w) * u64::from(p.crtc_h));
                }
            }
            if bw > policy.max_pixel_budget {
                return Err(AtomicError::OverBandwidth);
            }
        }
        self.checked = true;
        Ok(())
    }

    /// Apply this transaction's state to the card.  Linux's atomic-core
    /// equivalent runs after the driver hook returns; we run it after a
    /// successful driver hook.
    pub fn core_commit(&self, card: &mut Card) -> Result<(), AtomicError> {
        if !self.checked {
            return Err(AtomicError::NotChecked);
        }
        // CRTCs first — mode + enable.
        for cs in &self.crtcs {
            let crtc = card
                .crtcs
                .iter_mut()
                .find(|c| c.id == cs.id)
                .ok_or(AtomicError::UnknownCrtc)?;
            crtc.mode = cs.mode;
            crtc.enabled = cs.enable;
        }
        // Connectors — encoder binding.  Linux walks encoders too;
        // we keep encoder choice fixed (one encoder per connector).
        for cs in &self.connectors {
            let conn = card
                .connectors
                .iter_mut()
                .find(|c| c.id == cs.id)
                .ok_or(AtomicError::UnknownConnector)?;
            // No-op: we don't track which CRTC a connector is bound to
            // in `Card`; we just verify the binding is consistent.
            let _ = conn;
        }
        // Planes — write primary plane FB into the bound CRTC's
        // primary_fb so the legacy CRTC fbs reflect the atomic commit.
        for ps in &self.planes {
            if let (Some(crtc_id), Some(fb_id)) = (ps.crtc_id, ps.fb_id) {
                let crtc = card
                    .crtcs
                    .iter_mut()
                    .find(|c| c.id == crtc_id)
                    .ok_or(AtomicError::UnknownCrtc)?;
                crtc.primary_fb = Some(fb_id);
                crtc.x = ps.crtc_x.max(0) as u32;
                crtc.y = ps.crtc_y.max(0) as u32;
            }
        }
        Ok(())
    }
}

/// Run a full atomic transaction — `atomic_check` then `atomic_commit`.
///
/// Mirrors `drm_atomic_commit` in `drivers/gpu/drm/drm_atomic.c` which
/// invokes `drm_atomic_check_only` first.
pub fn atomic_check_and_commit(
    card: &mut Card,
    state: &mut AtomicState,
    policy: &AtomicCheckPolicy,
    ops: Option<&dyn AtomicOps>,
) -> Result<(), AtomicError> {
    state.core_check(card, policy)?;
    if let Some(ops) = ops {
        ops.atomic_check(card, state)?;
        ops.atomic_commit(card, state)?;
    }
    state.core_commit(card)
}

// ── Wire decode for DRM_MODE_ATOMIC ────────────────────────────────────

/// `struct drm_mode_atomic` wire format.
///
/// Linux: `include/uapi/drm/drm_mode.h`.  We surface the fields needed
/// by the dispatcher; the kernel-side dispatcher de-serialises the
/// per-object property arrays into [`AtomicState`].
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeAtomic {
    pub flags: u32,
    pub count_objs: u32,
    pub objs_ptr: u64,
    pub count_props_ptr: u64,
    pub props_ptr: u64,
    pub prop_values_ptr: u64,
    pub reserved: u64,
    pub user_data: u64,
}

/// `DRM_MODE_ATOMIC_ALLOW_MODESET` — caller permits modeset.
pub const DRM_MODE_ATOMIC_ALLOW_MODESET: u32 = 0x0400;
/// `DRM_MODE_ATOMIC_TEST_ONLY` — run `atomic_check` only, don't commit.
pub const DRM_MODE_ATOMIC_TEST_ONLY: u32 = 0x0200;
/// `DRM_MODE_ATOMIC_NONBLOCK` — return without waiting for pageflip.
pub const DRM_MODE_ATOMIC_NONBLOCK: u32 = 0x0100;
/// `DRM_MODE_PAGE_FLIP_EVENT` — emit a flip-complete event.
pub const DRM_MODE_PAGE_FLIP_EVENT: u32 = 0x0001;
