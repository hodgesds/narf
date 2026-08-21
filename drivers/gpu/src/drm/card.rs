//! DRM card — one logical GPU as seen by userspace.
//!
//! In Linux this lives in `drivers/gpu/drm/drm_drv.c` and
//! `drivers/gpu/drm/drm_mode_config.c`.  A `Card` groups:
//!
//! - **Connectors** — physical output ports (eDP, HDMI, DP, VGA).
//! - **Encoders** — signal conversion hardware (TMDS, LVDS, DAC).
//! - **CRTCs** — programmable display timing controllers.
//! - **GEM handle table** — per-card buffer-object registry.
//! - **Driver name** — reported back by DRM_IOCTL_VERSION.
//!
//! The `Card` struct is cheap to store in a `static` spin-lock because
//! it owns all state by value (no heap pointers from global statics).
//!
//! ## Linux references
//!
//! - `struct drm_device` in `include/drm/drm_device.h`.
//! - `struct drm_mode_config` in `include/drm/drm_mode_config.h`.
//! - `struct drm_connector` in `include/drm/drm_connector.h`.
//! - `struct drm_crtc` in `include/drm/drm_crtc.h`.

use super::gem::GemTable;
use alloc::vec::Vec;

// ── Connector ──────────────────────────────────────────────────────────

/// Physical connector type.
///
/// Linux: `DRM_MODE_CONNECTOR_*` defines in `include/uapi/drm/drm_mode.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectorType {
    Unknown = 0,
    Vga = 1,
    Dvii = 2,
    Dvid = 3,
    Dvia = 4,
    Composite = 5,
    Svideo = 6,
    Lvds = 7,
    Component = 8,
    NinePinDin = 9,
    DisplayPort = 10,
    HdmiA = 11,
    HdmiB = 12,
    Tv = 13,
    Edp = 14,
    Virtual = 15,
    Dsi = 16,
    Dpi = 17,
    Writeback = 18,
    Spi = 19,
    Usb = 20,
}

/// Physical link status of a connector.
///
/// Linux: `DRM_MODE_CONNECTOR_Connected` etc.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ConnectorStatus {
    Connected = 1,
    Disconnected = 2,
    Unknown = 3,
}

/// A physical display output port.
///
/// Linux analogue: `struct drm_connector`.
#[derive(Clone, Debug)]
pub struct Connector {
    /// Connector index within the card (0-based).
    pub id: u32,
    /// Physical connector type.
    pub connector_type: ConnectorType,
    /// Type-within-type index (e.g. second HDMI port = 1).
    pub connector_type_id: u32,
    /// Current link status.
    pub status: ConnectorStatus,
    /// Encoder currently driving this connector (index into `Card::encoders`).
    pub encoder_id: Option<u32>,
    /// Supported display modes (populated by EDID read / driver probe).
    pub modes: Vec<crate::Mode>,
}

// ── Encoder ────────────────────────────────────────────────────────────

/// Encoder type.
///
/// Linux: `DRM_MODE_ENCODER_*` in `include/uapi/drm/drm_mode.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EncoderType {
    None = 0,
    Dac = 1,
    Tmds = 2,
    Lvds = 3,
    Tvdac = 4,
    Virtual = 5,
    Dsi = 6,
    Dpmst = 7,
    Dpi = 8,
}

/// Signal-conversion block between a CRTC and a connector.
///
/// Linux analogue: `struct drm_encoder`.
#[derive(Clone, Debug)]
pub struct Encoder {
    /// Encoder index within the card (0-based).
    pub id: u32,
    /// Encoder type.
    pub encoder_type: EncoderType,
    /// Bitmask of CRTCs this encoder can be attached to.
    pub possible_crtcs: u32,
    /// Bitmask of other encoders this can clone with.
    pub possible_clones: u32,
    /// Currently attached CRTC index.
    pub crtc_id: Option<u32>,
}

// ── CRTC ───────────────────────────────────────────────────────────────

/// Programmable display timing controller.
///
/// Linux analogue: `struct drm_crtc`.
#[derive(Clone, Debug)]
pub struct Crtc {
    /// CRTC index within the card (0-based).
    pub id: u32,
    /// Currently programmed display mode (None = disabled).
    pub mode: Option<crate::Mode>,
    /// Whether the CRTC is currently active.
    pub enabled: bool,
    /// GEM handle of the framebuffer currently scanned out (None = blank).
    pub primary_fb: Option<u32>,
    /// X/Y offset of the primary plane within the framebuffer.
    pub x: u32,
    pub y: u32,
}

// ── Framebuffer ────────────────────────────────────────────────────────

/// Colour encoding (pixel format).
///
/// Subset of Linux's `DRM_FORMAT_*` (only what ADDFB2 needs).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    Xrgb8888 = 0x3432_5258, // "XR24" little-endian
    Argb8888 = 0x3432_5241, // "AR24"
    Rgb565 = 0x3631_4752,   // "RG16"
}

/// Kernel-side framebuffer descriptor (result of ADDFB2).
///
/// Linux analogue: `struct drm_framebuffer`.
#[derive(Clone, Debug)]
pub struct Framebuffer {
    /// Per-card framebuffer id (assigned by ADDFB2).
    pub id: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Pixel format.
    pub format: PixelFormat,
    /// Byte pitch of the primary plane.
    pub pitch: u32,
    /// GEM handle of the backing buffer object.
    pub gem_handle: u32,
}

// ── Card ───────────────────────────────────────────────────────────────

/// Errors from card operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CardError {
    /// No CRTC with the given id.
    UnknownCrtc,
    /// No connector with the given id.
    UnknownConnector,
    /// No encoder with the given id.
    UnknownEncoder,
    /// No framebuffer with the given id.
    UnknownFb,
    /// Framebuffer ID already in use.
    FbIdCollision,
    /// The pixel format code is not recognised.
    UnknownFormat,
    /// GEM handle does not exist.
    BadGemHandle,
    /// Invalid dimensions (zero width or height).
    InvalidDimensions,
    /// Maximum number of framebuffers reached.
    TooManyFbs,
}

/// Dumb-buffer allocation: physical frames + size kept alive on the Card
/// so the memory is freed when the GEM handle is closed.
///
/// Stored as `(gem_handle, base_phys_addr, num_pages)`.
/// The physical memory is contiguous; `num_pages` is the buddy-allocator
/// order (number of pages = 2^order would be cleaner but we store raw
/// page count since alloc_pages_anywhere isn't yet wired; instead we
/// store the base phys + byte_len and free on GEM close).
#[derive(Debug)]
pub struct DumbBacking {
    /// GEM handle that owns this allocation.
    pub gem_handle: u32,
    /// Physical base address (page-aligned).
    pub phys: u64,
    /// Allocation size in bytes (page-rounded).
    pub byte_len: usize,
    /// Buddy order used for the allocation.
    pub order: u8,
    /// Fake mmap offset returned by MAP_DUMB (gem_handle << 12).
    pub mmap_offset: u64,
    /// Reference count — Linux GEM objects are refcounted so a buffer
    /// survives handle close while a framebuffer (ADDFB2) still points at
    /// it. Starts at 1 (the GEM handle); ADDFB2 increments, GEM_CLOSE /
    /// DESTROY_DUMB and RMFB decrement; the frames are freed only when it
    /// reaches 0. Without this a compositor that closes its GEM handle
    /// right after ADDFB2 (kwin via Mesa GBM) loses its scanout buffer
    /// mid-flight and SETCRTC finds no source to blit.
    pub refcount: u32,
}

/// A single GPU presented to userspace as `/dev/dri/card0` (or cardN).
///
/// Linux analogue: `struct drm_device` + `drm_mode_config`.
///
/// The `Card` is intentionally `Clone`-able (all fields are `Clone`)
/// so it can live behind a spin-lock and be copied out for inspection
/// without holding the lock.
#[derive(Debug)]
pub struct Card {
    /// Human-readable driver name (e.g. `"narf-i915"` or `"narf-amdgpu"`).
    pub driver_name: &'static str,
    /// Driver version triple.
    pub version: (u32, u32, u32),
    /// Description string for DRM_IOCTL_VERSION.
    pub driver_desc: &'static str,
    /// Connectors — one entry per physical output port.
    pub connectors: Vec<Connector>,
    /// Encoders.
    pub encoders: Vec<Encoder>,
    /// CRTCs.
    pub crtcs: Vec<Crtc>,
    /// Registered framebuffers (created by ADDFB2, removed by RMFB).
    pub framebuffers: Vec<Framebuffer>,
    /// Next framebuffer id to assign.
    pub(crate) next_fb_id: u32,
    /// GEM object table for this card.
    pub gem: GemTable,
    /// Dumb-buffer physical backings. Kept alive here so the memory
    /// is freed when the GEM handle is destroyed (DESTROY_DUMB / GEM_CLOSE).
    pub dumb_backings: Vec<DumbBacking>,
    /// Pending DRM events (`drm_event_vblank` for PAGE_FLIP completion),
    /// drained by `read(/dev/dri/cardN)`. A compositor render loop
    /// PAGE_FLIPs with DRM_MODE_PAGE_FLIP_EVENT, then poll/read()s these.
    ///
    /// Each entry is `(deliver_at_ns, bytes)`: the monotonic-ns simulated-vblank
    /// time at/after which the event becomes visible to poll/read, and the raw
    /// 32-byte `drm_event_vblank`. Gating delivery on the vblank time is what
    /// paces the compositor's repaint loop to the refresh rate (see
    /// `queue_flip_event` / `DriCardFile::poll_deadline`) instead of letting it
    /// spin at 100% CPU on instantly-completed flips. Queued in nondecreasing
    /// `deliver_at_ns` order.
    pub events: alloc::collections::VecDeque<(u64, Vec<u8>)>,
    /// Monotonic vblank sequence reported in flip-complete events.
    pub vblank_seq: u32,
    /// Monotonic-ns time of the next simulated vblank at/after which a queued
    /// flip event may be delivered. Advances one refresh interval per flip so
    /// back-to-back PAGE_FLIPs land on successive vblanks — the Linux/VKMS
    /// hrtimer-per-frame pacing, derived from the CRTC mode's refresh rate.
    pub next_vblank_ns: u64,
}

/// System-wide vblank "slack" offset in nanoseconds. A flip-complete event is
/// made deliverable this many ns BEFORE its true simulated vblank, so the
/// compositor wakes a little early and has time to render + resubmit the next
/// frame before the scanout — absorbing scheduler wake latency and per-frame
/// overhead. Default 0 (deliver exactly at the vblank). Tunable at runtime via
/// `/sys/class/drm/card<N>/vblank_offset_ns`.
///
/// It shifts only the delivery PHASE, never the frame RATE: `queue_flip_event`
/// advances `next_vblank_ns` from the true vblank, and derives the (earlier)
/// delivery time from it — so successive flips stay exactly one refresh
/// interval apart regardless of the offset. It compensates for SCHEDULER
/// overhead (a system property), hence one global knob mirrored onto every
/// card node rather than per-card state.
static VBLANK_OFFSET_NS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Current vblank slack offset (ns). See [`VBLANK_OFFSET_NS`].
pub fn vblank_offset_ns() -> u64 {
    VBLANK_OFFSET_NS.load(core::sync::atomic::Ordering::Relaxed)
}

/// Set the vblank slack offset (ns). See [`VBLANK_OFFSET_NS`]. Called from the
/// `/sys/class/drm/card<N>/vblank_offset_ns` store path.
pub fn set_vblank_offset_ns(ns: u64) {
    VBLANK_OFFSET_NS.store(ns, core::sync::atomic::Ordering::Relaxed);
}

impl Card {
    /// Construct a new card with the given driver identity.
    pub fn new(
        driver_name: &'static str,
        driver_desc: &'static str,
        version: (u32, u32, u32),
    ) -> Self {
        Card {
            driver_name,
            version,
            driver_desc,
            connectors: Vec::new(),
            encoders: Vec::new(),
            crtcs: Vec::new(),
            framebuffers: Vec::new(),
            next_fb_id: 1,
            gem: GemTable::new(),
            dumb_backings: Vec::new(),
            events: alloc::collections::VecDeque::new(),
            vblank_seq: 0,
            next_vblank_ns: 0,
        }
    }

    /// Refresh rate (Hz) of a CRTC's currently programmed mode, for vblank
    /// pacing. Falls back to 60 Hz when the CRTC is unknown or has no mode set
    /// (or a bogus 0 Hz mode), so pacing degrades to a sane default rather than
    /// dividing by zero.
    pub fn crtc_refresh_hz(&self, crtc_id: u32) -> u32 {
        self.crtcs
            .iter()
            .find(|c| c.id == crtc_id)
            .and_then(|c| c.mode.as_ref())
            .map(|m| m.refresh_hz as u32)
            .filter(|hz| *hz > 0)
            .unwrap_or(60)
    }

    /// Queue a `drm_event_vblank` flip-complete event (32 bytes) carrying
    /// `user_data` + `crtc_id`, to be drained by `read(/dev/dri/cardN)`.
    /// Linux: `drivers/gpu/drm/drm_vblank.c::send_vblank_event`.
    ///
    /// The event is stamped with a simulated-vblank delivery time one refresh
    /// interval past the previous flip (`next_vblank_ns`) — so a compositor that
    /// PAGE_FLIPs, waits for completion, then repaints is throttled to the
    /// mode's refresh rate (60 Hz → 16.67 ms, 120 Hz → 8.33 ms, 144 Hz →
    /// 6.94 ms) instead of getting an instant completion and spinning its
    /// repaint loop at 100% CPU. This mirrors how Linux paces a *virtual* vblank
    /// (vkms arms an hrtimer at `drm_mode_vrefresh(mode)`); real hardware paces
    /// on the physical vblank IRQ.
    pub fn queue_flip_event(&mut self, user_data: u64, crtc_id: u32) {
        const DRM_EVENT_FLIP_COMPLETE: u32 = 2;
        let refresh_hz = self.crtc_refresh_hz(crtc_id);
        let interval_ns = 1_000_000_000u64 / refresh_hz as u64;
        let now = narf_time::wall::monotonic_ns();
        // The frame completes at the next simulated vblank, never sooner than
        // one interval after the previous flip. A long idle gap (next_vblank_ns
        // in the past) collapses to `now`, so the first flip after idle is not
        // delayed. `next_vblank_ns` advances from THIS true vblank so the rate
        // is exactly the refresh rate regardless of the slack offset below.
        let present_at = now.max(self.next_vblank_ns);
        self.next_vblank_ns = present_at.saturating_add(interval_ns);
        // Render-slack: make the event deliverable up to `vblank_offset_ns`
        // before the true vblank so the compositor wakes early enough to render
        // and resubmit before scanout. Shifts phase only, not rate.
        let deliver_at = present_at.saturating_sub(vblank_offset_ns());

        self.vblank_seq = self.vblank_seq.wrapping_add(1);
        // CLOCK_MONOTONIC vblank timestamp = the TRUE vblank time (present_at),
        // not the possibly-earlier delivery time — the client schedules its next
        // repaint against the vblank it is rendering for. weston (and any DRM
        // client that sets DRM_CAP_TIMESTAMP_MONOTONIC) reads tv_sec/tv_usec off
        // the flip-complete event to pace its repaint loop and to stamp
        // wl_surface frame callbacks.
        let tv_sec = (present_at / 1_000_000_000) as u32;
        let tv_usec = ((present_at % 1_000_000_000) / 1_000) as u32;
        let mut e = Vec::with_capacity(32);
        e.extend_from_slice(&DRM_EVENT_FLIP_COMPLETE.to_le_bytes()); // base.type
        e.extend_from_slice(&32u32.to_le_bytes()); // base.length
        e.extend_from_slice(&user_data.to_le_bytes());
        e.extend_from_slice(&tv_sec.to_le_bytes()); // tv_sec
        e.extend_from_slice(&tv_usec.to_le_bytes()); // tv_usec
        e.extend_from_slice(&self.vblank_seq.to_le_bytes());
        e.extend_from_slice(&crtc_id.to_le_bytes());
        self.events.push_back((deliver_at, e));
    }

    /// Delivery time of the earliest queued flip event that is still in the
    /// FUTURE, for `DriCardFile::poll_deadline` — a DRM-fd poll parks until this
    /// simulated vblank and wakes to read the completion. Events are queued in
    /// nondecreasing delivery order, so the front is the earliest. `None` when
    /// the queue is empty or its front is already deliverable.
    pub fn next_event_deadline_ns(&self, now: u64) -> Option<u64> {
        self.events
            .front()
            .map(|(deliver_at, _)| *deliver_at)
            .filter(|deliver_at| *deliver_at > now)
    }

    /// Whether the front flip event's simulated-vblank time has arrived, i.e.
    /// poll should report POLL_IN and read should return it.
    pub fn has_deliverable_event(&self, now: u64) -> bool {
        self.events
            .front()
            .map(|(deliver_at, _)| *deliver_at <= now)
            .unwrap_or(false)
    }

    /// Pop the front flip event iff its simulated-vblank time has arrived;
    /// otherwise leave it queued (the reader sees "no event yet" and re-parks
    /// until `next_event_deadline_ns`).
    pub fn pop_deliverable_event(&mut self, now: u64) -> Option<Vec<u8>> {
        if self.has_deliverable_event(now) {
            self.events.pop_front().map(|(_, e)| e)
        } else {
            None
        }
    }

    // ── Connector / CRTC getters ──────────────────────────────────────

    /// All CRTC ids on this card.
    pub fn crtc_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.crtcs.iter().map(|c| c.id)
    }

    /// All connector ids on this card.
    pub fn connector_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.connectors.iter().map(|c| c.id)
    }

    /// All encoder ids on this card.
    pub fn encoder_ids(&self) -> impl Iterator<Item = u32> + '_ {
        self.encoders.iter().map(|e| e.id)
    }

    /// Look up a connector by id.
    pub fn connector(&self, id: u32) -> Result<&Connector, CardError> {
        self.connectors
            .iter()
            .find(|c| c.id == id)
            .ok_or(CardError::UnknownConnector)
    }

    /// Look up a CRTC by id.
    pub fn crtc(&self, id: u32) -> Result<&Crtc, CardError> {
        self.crtcs
            .iter()
            .find(|c| c.id == id)
            .ok_or(CardError::UnknownCrtc)
    }

    /// Look up an encoder by id.
    pub fn encoder(&self, id: u32) -> Result<&Encoder, CardError> {
        self.encoders
            .iter()
            .find(|e| e.id == id)
            .ok_or(CardError::UnknownCrtc)
    }

    /// Look up a CRTC mutably by id.
    pub fn crtc_mut(&mut self, id: u32) -> Result<&mut Crtc, CardError> {
        self.crtcs
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(CardError::UnknownCrtc)
    }

    /// Look up a dumb backing by GEM handle.
    pub fn dumb_backing(&self, gem_handle: u32) -> Option<&DumbBacking> {
        self.dumb_backings
            .iter()
            .find(|b| b.gem_handle == gem_handle)
    }

    /// Look up a dumb backing by mmap offset.
    pub fn dumb_backing_by_offset(&self, mmap_offset: u64) -> Option<&DumbBacking> {
        self.dumb_backings
            .iter()
            .find(|b| b.mmap_offset == mmap_offset)
    }

    /// Register a new dumb backing. Returns the gem handle.
    pub fn register_dumb_backing(
        &mut self,
        phys: u64,
        byte_len: usize,
        order: u8,
    ) -> Result<u32, CardError> {
        let handle = self
            .gem
            .alloc(phys, byte_len)
            .map_err(|_| CardError::TooManyFbs)?;
        // Fake mmap offset = handle << 12. Must not alias a real file offset.
        let mmap_offset = (handle as u64) << 12;
        self.dumb_backings.push(DumbBacking {
            gem_handle: handle,
            phys,
            byte_len,
            order,
            mmap_offset,
            refcount: 1,
        });
        Ok(handle)
    }

    /// Drop one reference on the dumb backing named by `gem_handle`
    /// (GEM_CLOSE / DESTROY_DUMB / RMFB). Returns `Some((phys, order))`
    /// for the caller to buddy-free ONLY when the last reference is
    /// dropped; `None` while other references (a live framebuffer, another
    /// handle) keep the buffer alive. The GEM handle stays allocated until
    /// the buffer is truly freed so its number can't be reused for a
    /// different backing while lookups still key on it.
    pub fn remove_dumb_backing(&mut self, gem_handle: u32) -> Option<(u64, u8)> {
        let pos = self
            .dumb_backings
            .iter()
            .position(|b| b.gem_handle == gem_handle)?;
        let b = &mut self.dumb_backings[pos];
        b.refcount = b.refcount.saturating_sub(1);
        if b.refcount > 0 {
            return None;
        }
        let b = self.dumb_backings.swap_remove(pos);
        let _ = self.gem.free(gem_handle);
        Some((b.phys, b.order))
    }

    // ── ADDFB2 / RMFB ────────────────────────────────────────────────

    /// Register a new framebuffer backed by an existing GEM handle.
    ///
    /// Returns the assigned framebuffer id.
    ///
    /// Linux equivalent: `drm_mode_addfb2` in
    /// `drivers/gpu/drm/drm_framebuffer.c`.
    pub fn addfb2(
        &mut self,
        width: u32,
        height: u32,
        format: u32,
        pitch: u32,
        gem_handle: u32,
    ) -> Result<u32, CardError> {
        if width == 0 || height == 0 {
            return Err(CardError::InvalidDimensions);
        }
        // Validate GEM handle exists.
        if self.gem.lookup(gem_handle).is_none() {
            return Err(CardError::BadGemHandle);
        }
        // Validate pixel format.
        let format = match format {
            0x3432_5258 => PixelFormat::Xrgb8888,
            0x3432_5241 => PixelFormat::Argb8888,
            0x3631_4752 => PixelFormat::Rgb565,
            _ => return Err(CardError::UnknownFormat),
        };
        if self.framebuffers.len() >= 4096 {
            return Err(CardError::TooManyFbs);
        }
        let id = self.next_fb_id;
        self.next_fb_id = self.next_fb_id.wrapping_add(1).max(1);
        // The framebuffer takes a reference on its backing buffer so it
        // survives the client closing the GEM handle (Linux drm_framebuffer
        // holds a gem object ref). Non-dumb handles have no backing to pin.
        if let Some(b) = self
            .dumb_backings
            .iter_mut()
            .find(|b| b.gem_handle == gem_handle)
        {
            b.refcount = b.refcount.saturating_add(1);
        }
        self.framebuffers.push(Framebuffer {
            id,
            width,
            height,
            format,
            pitch,
            gem_handle,
        });
        Ok(id)
    }

    /// Remove a previously registered framebuffer (RMFB). Drops the
    /// framebuffer's reference on its backing buffer; returns
    /// `Some((phys, order))` for the caller to buddy-free if that was the
    /// buffer's last reference.
    ///
    /// Linux equivalent: `drm_mode_rmfb`.
    pub fn rmfb(&mut self, fb_id: u32) -> Result<Option<(u64, u8)>, CardError> {
        let pos = self
            .framebuffers
            .iter()
            .position(|fb| fb.id == fb_id)
            .ok_or(CardError::UnknownFb)?;
        let fb = self.framebuffers.swap_remove(pos);
        Ok(self.remove_dumb_backing(fb.gem_handle))
    }

    /// Look up a framebuffer by id.
    pub fn framebuffer(&self, fb_id: u32) -> Result<&Framebuffer, CardError> {
        self.framebuffers
            .iter()
            .find(|fb| fb.id == fb_id)
            .ok_or(CardError::UnknownFb)
    }
}
