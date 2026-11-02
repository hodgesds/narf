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
use alloc::collections::VecDeque;
use alloc::sync::Arc;
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
/// Subset of Linux's `DRM_FORMAT_*` (only what ADDFB2 needs): packed RGB
/// and the two-plane 4:2:0 NV12 / P010. A card's `plane_formats` narrows
/// what its ADDFB2 takes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    Xrgb8888 = 0x3432_5258,      // "XR24" little-endian
    Argb8888 = 0x3432_5241,      // "AR24"
    Xbgr8888 = 0x3432_4258,      // "XB24"
    Abgr8888 = 0x3432_4241,      // "AB24"
    Xrgb2101010 = 0x3033_5258,   // "XR30"
    Argb2101010 = 0x3033_5241,   // "AR30"
    Xbgr2101010 = 0x3033_4258,   // "XB30"
    Abgr2101010 = 0x3033_4241,   // "AB30"
    Rgb565 = 0x3631_4752,        // "RG16"
    Xrgb16161616f = 0x4834_5258, // "XR4H"
    Argb16161616f = 0x4834_5241, // "AR4H"
    Xbgr16161616f = 0x4834_4258, // "XB4H"
    Abgr16161616f = 0x4834_4241, // "AB4H"
    Xrgb16161616 = 0x3834_5258,  // "XR48"
    Argb16161616 = 0x3834_5241,  // "AR48"
    Xbgr16161616 = 0x3834_4258,  // "XB48"
    Abgr16161616 = 0x3834_4241,  // "AB48"
    Nv12 = 0x3231_564e,          // "NV12": Y plane, then interleaved CbCr
    P010 = 0x3031_3050,          // "P010": 10-bit (MSB-aligned 16-bit) NV12
}
impl PixelFormat {
    /// The format of a DRM fourcc, if ADDFB2 knows it.
    pub fn from_fourcc(fourcc: u32) -> Option<Self> {
        [
            Self::Xrgb8888,
            Self::Argb8888,
            Self::Xbgr8888,
            Self::Abgr8888,
            Self::Xrgb2101010,
            Self::Argb2101010,
            Self::Xbgr2101010,
            Self::Abgr2101010,
            Self::Rgb565,
            Self::Xrgb16161616f,
            Self::Argb16161616f,
            Self::Xbgr16161616f,
            Self::Abgr16161616f,
            Self::Xrgb16161616,
            Self::Argb16161616,
            Self::Xbgr16161616,
            Self::Abgr16161616,
            Self::Nv12,
            Self::P010,
        ]
        .into_iter()
        .find(|f| *f as u32 == fourcc)
    }
    /// Bytes per pixel (drm_format_info's cpp[0]; the luma plane's for
    /// NV12 and P010).
    pub const fn cpp(self) -> u32 {
        match self {
            Self::Nv12 => 1,
            Self::Rgb565 | Self::P010 => 2,
            Self::Xrgb16161616f
            | Self::Argb16161616f
            | Self::Xbgr16161616f
            | Self::Abgr16161616f
            | Self::Xrgb16161616
            | Self::Argb16161616
            | Self::Xbgr16161616
            | Self::Abgr16161616 => 8,
            _ => 4,
        }
    }
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
    /// GEM handle of the backing buffer object (every plane's: amdgpu
    /// refuses planes in different BOs).
    pub gem_handle: u32,
    /// Each plane's byte offset into the BO (plane 1 is NV12/P010's CbCr
    /// plane; 0 for single-plane formats).
    pub offsets: [u32; 2],
    /// Plane 1's byte pitch (0 for single-plane formats).
    pub chroma_pitch: u32,
    /// The format modifier: DRM_FORMAT_MOD_LINEAR, or a GFX12 one on the
    /// native amdgpu card (passed with DRM_MODE_FB_MODIFIERS or converted
    /// from the BO's tiling flags).
    pub modifier: u64,
    /// On the native amdgpu card, the amdgpu GEM buffer behind a
    /// framebuffer made from one of an open's GEM handles (none for a dumb
    /// or imported buffer): `drm_framebuffer.obj[0]`, which the
    /// framebuffer holds.
    pub bo: Option<FbBo>,
    /// The Intel GEM buffer behind a framebuffer made from one of an open's
    /// Intel GEM handles (`drm_framebuffer.obj[0]`).
    #[cfg(feature = "intel")]
    pub intel: Option<IntelFb>,
}

impl Framebuffer {
    /// The open that made this framebuffer from one of its GEM handles
    /// (drm_fb_release removes it with that open); `None` for a dumb or
    /// imported buffer.
    pub fn gem_owner(&self) -> Option<u64> {
        #[cfg(feature = "intel")]
        if let Some(intel) = &self.intel {
            return Some(intel.owner);
        }
        self.bo.as_ref().map(|bo| bo.owner)
    }
}

/// An Intel GEM buffer a framebuffer holds, and the open that made it.
#[cfg(feature = "intel")]
#[derive(Clone, Debug)]
pub struct IntelFb {
    pub object: Arc<crate::intel_gpu_gem::GemObject>,
    pub owner: u64,
}

/// An amdgpu GEM buffer a framebuffer holds, and the open that made it:
/// drm_fb_release removes an open's framebuffers when it closes.
#[derive(Clone, Debug)]
pub struct FbBo {
    /// The buffer itself. Only the amdgpu driver has GEM objects, so
    /// the field exists only with it; a framebuffer's `bo` is `None`
    /// in every other build, exactly as it is for a dumb or imported
    /// buffer here.
    #[cfg(feature = "amdgpu")]
    pub object: Arc<crate::amdgpu_gem::GemObject>,
    pub owner: u64,
}

/// The scanout pin a presented frame holds on its GEM buffer, as
/// `amdgpu_dm_plane_helper_prepare_fb` took it. Only the amdgpu
/// driver pins buffers, so without it the pin type is uninhabited:
/// a frame's `bo` is `None` in every such build, exactly as it is
/// for a dumb buffer here.
#[cfg(feature = "amdgpu")]
pub type ScanoutPin = Arc<crate::amdgpu_gem::ScanoutPin>;
#[cfg(not(feature = "amdgpu"))]
pub type ScanoutPin = Arc<core::convert::Infallible>;

/// One plane's DRM framebuffer: a kernel-mapped dumb buffer, or (`bo`)
/// an amdgpu GEM buffer pinned in VRAM for scanout; its pitch, size and
/// fourcc, each plane's offset (a 4:2:0 framebuffer's chroma plane at
/// `offsets[1]` with `chroma_pitch`) and its modifier. A pinned buffer is
/// scanned out in place (`external`), as amdgpu_dm hands DC the
/// framebuffer's address: no copy. Dumb buffers are such GEM buffers in
/// VRAM once the card's client heap is up (amdgpu_mode_dumb_create:
/// `drm_ioctl_bridge::amdgpu_dumb`). A dumb buffer of the card's own table
/// (`phys`, made while no heap was up) lives in system memory, which
/// display fetch on this dGPU never reads (amdgpu_display_supported_domains
/// is VRAM alone), so the presenter copies it into the plane's staged VRAM
/// back buffer, as amdgpu_bo_pin would migrate it: a linear RGB plane's
/// source rectangle, a tiled or 4:2:0 one whole.
///
/// The type is the DRM present layer's currency — every card's
/// presenter consumes it — so it lives in the DRM core; the AMD
/// platform module re-exports it and keeps the DC-specific methods.
#[derive(Clone, Debug)]
pub struct PlaneFrame {
    pub phys: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub format: u32,
    pub offsets: [u32; 2],
    pub chroma_pitch: u32,
    pub modifier: u64,
    /// The pin amdgpu_dm_plane_helper_prepare_fb took on the framebuffer's
    /// GEM buffer; it lasts until a flip latches past it.
    pub bo: Option<ScanoutPin>,
}
impl PlaneFrame {
    /// A linear single-plane framebuffer at `phys`.
    pub const fn linear(phys: u64, pitch: u32, width: u32, height: u32, format: u32) -> Self {
        Self {
            phys,
            pitch,
            width,
            height,
            format,
            offsets: [0; 2],
            chroma_pitch: 0,
            modifier: 0,
            bo: None,
        }
    }
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
    /// The buffer's dma-buf reservation and name. Every PRIME export of
    /// this handle (and the handle an import resolves back to) shares it,
    /// as Linux shares one `dma_resv` per GEM object.
    pub dma_buf: Arc<narf_filesystem::dma_buf::DmaBufObject>,
}

/// A VirGL object imported through PRIME into the primary node's GEM
/// namespace. The GEM handle contributes one reference and every framebuffer
/// created from it contributes another, matching Linux GEM ownership.
#[derive(Debug)]
pub(crate) struct VirtGpuImport {
    pub(crate) gem_handle: u32,
    pub(crate) resource: Arc<crate::drm_ioctl_bridge::VirtGpuResource>,
    pub(crate) refcount: u32,
}

/// Userspace-created KMS property blob. Atomic modesets use these to pass a
/// `drm_mode_modeinfo` through the CRTC `MODE_ID` property.
#[derive(Debug)]
pub(crate) struct PropertyBlob {
    pub(crate) id: u32,
    pub(crate) data: Vec<u8>,
    /// Still owned by its creator: DESTROYPROPBLOB not yet called. A blob a
    /// committed property still names outlives its creator's reference, as
    /// a refcounted `drm_property_blob` does (`Card::collect_blobs`).
    pub(crate) user: bool,
}

/// `drm_crtc::gamma_size` of every color-managed CRTC: Intel and AMD both
/// initialize the legacy store with 256 entries, independently of native LUT size.
pub const LEGACY_GAMMA_SIZE: usize = 256;

/// A CRTC's color management as amdgpu_dm attaches it on DCN 4.0.1
/// (`drm_crtc_enable_color_mgmt(crtc, 0, true, MAX_COLOR_LUT_ENTRIES)`:
/// CTM, GAMMA_LUT and GAMMA_LUT_SIZE, no degamma) with the blobs DRM last
/// committed (0 for none) and the legacy gamma store GETGAMMA reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrtcColor {
    pub crtc: u32,
    pub ctm: u32,
    pub gamma_lut: u32,
    /// `drm_crtc::gamma_store`: `LEGACY_GAMMA_SIZE` red, then green, then
    /// blue entries, initialised to the identity ramp (`i << 8`).
    pub gamma_store: Vec<u16>,
}
impl CrtcColor {
    pub fn new(crtc: u32) -> Self {
        let ramp = (0..LEGACY_GAMMA_SIZE as u16).map(|i| i << 8);
        Self {
            crtc,
            ctm: 0,
            gamma_lut: 0,
            gamma_store: ramp.clone().chain(ramp.clone()).chain(ramp).collect(),
        }
    }
}

/// Flip-complete events owned by one open DRM primary-node file.
///
/// Linux keeps `pending_event_list` and `event_list` on `struct drm_file`, not
/// on `struct drm_device`. Keeping the queue per open is load-bearing: the
/// event's `user_data` is an opaque pointer in the submitting process, so a
/// later compositor must never consume an event left by the greeter.
#[derive(Debug)]
pub(crate) struct DrmEventQueue {
    events: VecDeque<QueuedEvent>,
    event_space: usize,
    #[cfg(feature = "intel")]
    closed: bool,
}

/// One queued `drm_event`, deliverable at `deliver_at_ns` or when what it
/// waits for has happened.
#[derive(Debug)]
struct QueuedEvent {
    deliver_at_ns: u64,
    wait: Wait,
    bytes: [u8; 32],
}

/// What a queued event waits for besides its delivery time.
#[derive(Debug)]
enum Wait {
    /// Only `deliver_at_ns` (a simulated vblank).
    Time,
    /// A hardware flip of a display: (display, ticket, refresh period in ns).
    Flip(u8, u64, u64),
    /// A hardware vblank count on a CRTC (WAIT_VBLANK with an event, or
    /// CRTC_QUEUE_SEQUENCE when `sequence` is set).
    Vblank {
        source: VblankSource,
        crtc_id: u32,
        target: u64,
        sequence: bool,
    },
}

/// One CRTC's hardware vblank clock: `count` vblanks have begun, the last
/// at `start_ns`; it ends at `ns`, when the next frame's first pixel goes
/// out (DRM's vblank timestamp). CLOCK_MONOTONIC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VblankTime {
    pub count: u64,
    pub start_ns: u64,
    pub ns: u64,
    pub period_ns: u64,
}

/// A driver's hardware vblank clock for a CRTC id; `None` while that CRTC
/// has no running timing. Cards without one have no vblank support, as
/// Linux drivers that never call drm_vblank_init.
pub type VblankSource = fn(u32) -> Option<VblankTime>;

/// `drm_vblank_passed`: whether vblank `seq` is at or past `target`.
pub fn vblank_passed(seq: u64, target: u64) -> bool {
    seq.wrapping_sub(target) <= 1 << 23
}

/// Look again this soon while a vblank count is about to be reached.
const VBLANK_RECHECK_NS: u64 = 250_000;

impl QueuedEvent {
    /// The event as `read` returns it at `now`, or `None` while it is not
    /// yet due. A hardware flip's event carries that flip's time and count.
    fn due(&self, now: u64) -> Option<[u8; 32]> {
        let mut bytes = self.bytes;
        match self.wait {
            Wait::Time => return (self.deliver_at_ns <= now).then_some(bytes),
            Wait::Flip(display, ticket, _) => {
                let stamp = flips(display).lock().stamp(ticket)?;
                patch_vblank_event(&mut bytes, stamp.ns, stamp.sequence);
            }
            Wait::Vblank {
                source,
                crtc_id,
                target,
                sequence,
            } => {
                // A CRTC turned off sends its pending events at once in the
                // vblank they asked for (drm_crtc_vblank_off).
                let t = match source(crtc_id) {
                    Some(t) if vblank_passed(t.count, target) => t,
                    Some(_) => return None,
                    None => VblankTime {
                        count: target,
                        start_ns: now,
                        ns: now,
                        period_ns: 0,
                    },
                };
                if sequence {
                    bytes[16..24].copy_from_slice(&t.ns.to_le_bytes());
                    bytes[24..32].copy_from_slice(&t.count.to_le_bytes());
                } else {
                    patch_vblank_event(&mut bytes, t.ns, t.count as u32);
                }
            }
        }
        Some(bytes)
    }

    /// When a poller should look at this event again.
    fn deadline(&self, now: u64) -> u64 {
        match self.wait {
            Wait::Time => self.deliver_at_ns,
            Wait::Flip(display, ticket, period_ns) => {
                flips(display).lock().recheck_at(ticket, now, period_ns)
            }
            Wait::Vblank {
                source,
                crtc_id,
                target,
                ..
            } => match source(crtc_id) {
                Some(t) if !vblank_passed(t.count, target) => {
                    // When vblank `target` begins, predicted from the last.
                    let ahead = target.wrapping_sub(t.count).min(1 << 23);
                    let at = t.start_ns.saturating_add(ahead.saturating_mul(t.period_ns));
                    at.max(now.saturating_add(VBLANK_RECHECK_NS))
                }
                _ => now,
            },
        }
    }
}

/// `drm_event_vblank`'s time and sequence.
fn patch_vblank_event(bytes: &mut [u8; 32], ns: u64, sequence: u32) {
    bytes[16..20].copy_from_slice(&((ns / 1_000_000_000) as u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&(((ns % 1_000_000_000) / 1_000) as u32).to_le_bytes());
    bytes[24..28].copy_from_slice(&sequence.to_le_bytes());
}

impl DrmEventQueue {
    const EVENT_SPACE_BYTES: usize = 4096;
    pub(crate) const FLIP_EVENT_BYTES: usize = 32;

    pub(crate) fn new() -> Self {
        Self {
            events: VecDeque::new(),
            event_space: Self::EVENT_SPACE_BYTES,
            #[cfg(feature = "intel")]
            closed: false,
        }
    }

    #[cfg(feature = "intel")]
    pub(crate) fn close(&mut self) {
        self.closed = true;
    }

    #[cfg(feature = "intel")]
    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    fn push(&mut self, event: QueuedEvent) -> Result<(), DrmEventQueueFull> {
        if event.bytes.len() > self.event_space {
            return Err(DrmEventQueueFull);
        }
        self.event_space -= event.bytes.len();
        self.events.push_back(event);
        Ok(())
    }

    pub(crate) fn ensure_flip_event_space(
        &self,
        event_count: usize,
    ) -> Result<(), DrmEventQueueFull> {
        let needed = event_count
            .checked_mul(Self::FLIP_EVENT_BYTES)
            .ok_or(DrmEventQueueFull)?;
        if needed > self.event_space {
            Err(DrmEventQueueFull)
        } else {
            Ok(())
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn back_delivery_ns(&self) -> Option<u64> {
        self.events.back().map(|e| e.deliver_at_ns)
    }

    /// When the earliest queued event should next be looked at: its
    /// simulated-vblank time, or for a hardware flip still in progress the
    /// next expected flip (see [`FlipLog::recheck_at`]).
    ///
    /// Keep returning an already-due deadline until the event is consumed.
    /// A poller's readiness scan can race the deadline becoming due; returning
    /// `None` after that race would let the caller park forever even though the
    /// fd is now readable and no later edge will wake it.
    pub(crate) fn next_event_deadline_ns(&self, now: u64) -> Option<u64> {
        self.events.front().map(|e| e.deadline(now))
    }

    /// Whether the front event is due: its simulated vblank has arrived, or
    /// its hardware flip has completed.
    pub(crate) fn has_deliverable_event(&self, now: u64) -> bool {
        self.events.front().is_some_and(|e| e.due(now).is_some())
    }

    /// Pop the front event iff it is due.
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn pop_deliverable_event(&mut self, now: u64) -> Option<[u8; 32]> {
        let bytes = self.events.front()?.due(now)?;
        self.events.pop_front();
        self.event_space += bytes.len();
        Some(bytes)
    }

    /// Copy one complete deliverable event into `buf`.
    ///
    /// Linux `drm_read` never truncates an event. If the buffer is too small it
    /// returns zero and puts the event back at the head of this `drm_file`'s
    /// queue. `None` means no event is currently deliverable.
    pub(crate) fn read_deliverable_event(&mut self, now: u64, buf: &mut [u8]) -> Option<usize> {
        let bytes = self.events.front()?.due(now)?;
        if bytes.len() > buf.len() {
            return Some(0);
        }
        self.events.pop_front();
        self.event_space += bytes.len();
        buf[..bytes.len()].copy_from_slice(&bytes);
        Some(bytes.len())
    }
}

impl Default for DrmEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Linux reports `ENOMEM` when one `drm_file` exhausts its 4 KiB event space.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DrmEventQueueFull;

/// Event space reserved before an async Intel display transaction starts.
/// Waiting or cancellation neither exposes a success event nor lets another
/// ioctl consume the space this transaction needs after its hardware latch.
#[cfg(feature = "intel")]
#[derive(Debug)]
pub(crate) struct FlipEventReservation {
    queue: Arc<narf_lib::sync::IrqSafeSpinLock<DrmEventQueue>>,
    pending: bool,
}

#[cfg(feature = "intel")]
impl FlipEventReservation {
    pub(crate) fn reserve(
        queue: &Arc<narf_lib::sync::IrqSafeSpinLock<DrmEventQueue>>,
    ) -> Result<Self, DrmEventQueueFull> {
        {
            let mut events = queue.lock();
            if events.closed {
                return Err(DrmEventQueueFull);
            }
            events.ensure_flip_event_space(1)?;
            // Reserve storage for every charged event, including reservations
            // not yet published by the asynchronous display worker.
            let charged = (DrmEventQueue::EVENT_SPACE_BYTES - events.event_space)
                / DrmEventQueue::FLIP_EVENT_BYTES
                + 1;
            events
                .events
                .try_reserve(charged)
                .map_err(|_| DrmEventQueueFull)?;
            events.event_space -= DrmEventQueue::FLIP_EVENT_BYTES;
        }
        Ok(Self {
            queue: queue.clone(),
            pending: true,
        })
    }

    /// Publish only the actual completed latch, without simulated render
    /// slack or an additional event-space allocation.
    pub(crate) fn complete(mut self, user_data: u64, crtc_id: u32, stamp: FlipStamp) {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&32u32.to_le_bytes());
        bytes[8..16].copy_from_slice(&user_data.to_le_bytes());
        bytes[28..32].copy_from_slice(&crtc_id.to_le_bytes());
        patch_vblank_event(&mut bytes, stamp.ns, stamp.sequence);
        let mut queue = self.queue.lock();
        if queue.closed {
            queue.event_space += DrmEventQueue::FLIP_EVENT_BYTES;
            self.pending = false;
            return;
        }
        queue.events.push_back(QueuedEvent {
            deliver_at_ns: stamp.ns,
            wait: Wait::Time,
            bytes,
        });
        self.pending = false;
    }
}

#[cfg(feature = "intel")]
impl Drop for FlipEventReservation {
    fn drop(&mut self) {
        if self.pending {
            self.queue.lock().event_space += DrmEventQueue::FLIP_EVENT_BYTES;
        }
    }
}

/// When and in which vblank a hardware flip completed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlipStamp {
    /// CLOCK_MONOTONIC ns at which the new buffer was seen latched.
    pub ns: u64,
    /// The CRTC's vblank count then.
    pub sequence: u32,
}

const FLIP_HISTORY: usize = 16;
/// Look again this soon while a flip may be landing.
const FLIP_RECHECK_NS: u64 = 250_000;
/// A flip is expected to land within this long after its vblank.
const FLIP_LANDING_NS: u64 = 2_000_000;

/// Flip-complete events of a display that flips in hardware wait for the
/// flip itself, as Linux sends them from the pageflip interrupt, rather than
/// for a simulated vblank. The presenter takes a ticket per submitted frame
/// and completes tickets in order as flips latch. A frame replaced before it
/// was shown completes with the flip that replaced it, as its buffer is then
/// free again too.
#[derive(Debug)]
pub struct FlipLog {
    reserved: u64,
    completed: u64,
    /// Recent completions as (highest ticket covered, stamp), oldest first.
    recent: [(u64, FlipStamp); FLIP_HISTORY],
    len: usize,
}

impl Default for FlipLog {
    fn default() -> Self {
        Self::new()
    }
}

impl FlipLog {
    pub const fn new() -> Self {
        Self {
            reserved: 0,
            completed: 0,
            recent: [(0, FlipStamp { ns: 0, sequence: 0 }); FLIP_HISTORY],
            len: 0,
        }
    }

    /// The ticket of the next submitted frame.
    pub fn reserve(&mut self) -> u64 {
        self.reserved += 1;
        self.reserved
    }

    /// Every ticket up to `upto` completed at `stamp`.
    pub fn complete(&mut self, upto: u64, stamp: FlipStamp) {
        let upto = upto.min(self.reserved);
        if upto <= self.completed {
            return;
        }
        self.completed = upto;
        if self.len == FLIP_HISTORY {
            self.recent.copy_within(1.., 0);
            self.len -= 1;
        }
        self.recent[self.len] = (upto, stamp);
        self.len += 1;
    }

    /// Complete every reserved ticket at `ns` in the last known vblank: no
    /// flip is coming for them (presentation stopped or failed).
    pub fn complete_all(&mut self, ns: u64) {
        let sequence = self.last().map_or(0, |s| s.sequence);
        self.complete(self.reserved, FlipStamp { ns, sequence });
    }

    /// The completion of `ticket`, once it has completed. A ticket older than
    /// the retained history reports the oldest retained flip.
    pub fn stamp(&self, ticket: u64) -> Option<FlipStamp> {
        if ticket > self.completed {
            return None;
        }
        let recent = &self.recent[..self.len];
        recent
            .iter()
            .find(|(upto, _)| *upto >= ticket)
            .or(recent.first())
            .map(|(_, stamp)| *stamp)
    }

    pub fn last(&self) -> Option<FlipStamp> {
        self.len.checked_sub(1).map(|i| self.recent[i].1)
    }

    /// When a poller waiting on `ticket` should look again: at once when it
    /// has completed; shortly while a flip may be landing (just after a
    /// vblank, phase-locked to the last completed flip); otherwise just after
    /// the next vblank. Without a completed flip to lock to, shortly.
    pub fn recheck_at(&self, ticket: u64, now: u64, period_ns: u64) -> u64 {
        if let Some(stamp) = self.stamp(ticket) {
            return stamp.ns.min(now);
        }
        let Some(last) = self.last().filter(|_| period_ns > 0) else {
            return now + FLIP_RECHECK_NS;
        };
        let since = now.saturating_sub(last.ns) % period_ns;
        if since < FLIP_LANDING_NS {
            now + FLIP_RECHECK_NS
        } else {
            now + (period_ns - since) + FLIP_RECHECK_NS
        }
    }
}

/// Hardware flips of the native displays, one log per display (pipe).
pub static FLIPS: [narf_lib::sync::IrqSafeSpinLock<FlipLog>; 4] = [
    narf_lib::sync::IrqSafeSpinLock::new(FlipLog::new()),
    narf_lib::sync::IrqSafeSpinLock::new(FlipLog::new()),
    narf_lib::sync::IrqSafeSpinLock::new(FlipLog::new()),
    narf_lib::sync::IrqSafeSpinLock::new(FlipLog::new()),
];

/// Display `display`'s flip log (the last one for an out-of-range index).
pub fn flips(display: u8) -> &'static narf_lib::sync::IrqSafeSpinLock<FlipLog> {
    &FLIPS[usize::from(display).min(FLIPS.len() - 1)]
}

/// A single GPU presented to userspace as `/dev/dri/card0` (or cardN).
///
/// Linux analogue: `struct drm_device` + `drm_mode_config`.
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
    /// Excludes synchronous KMS writes while an Intel async transaction has
    /// dropped the mode-state lock to wait for the real display latch.
    #[cfg(feature = "intel")]
    intel_transaction: bool,
    #[cfg(feature = "intel")]
    intel_deferred_owners: Vec<u64>,
    /// Registered Intel native display owner; independent of color capability
    /// and of native_atomic, which other DRM vendors also use.
    #[cfg(feature = "intel")]
    pub(crate) intel_display: bool,
    /// Installed fixed-mode Intel color owner (native CTM, gamma1024/legacy256).
    #[cfg(feature = "intel")]
    pub(crate) intel_ctm: bool,
    #[cfg(feature = "intel")]
    intel_blob_pins: Vec<(u32, usize)>,
    /// A released master still owns hardware until serialized restoration.
    #[cfg(feature = "intel")]
    intel_restore_pending: bool,
    /// GEM object table for this card.
    pub gem: GemTable,
    /// Dumb-buffer physical backings. Kept alive here so the memory
    /// is freed when the GEM handle is destroyed (DESTROY_DUMB / GEM_CLOSE).
    pub dumb_backings: Vec<DumbBacking>,
    /// VirGL resources imported from a render-node dma-buf for KMS scanout.
    pub(crate) virtgpu_imports: Vec<VirtGpuImport>,
    /// KMS property blobs created through MODE_CREATEPROPBLOB.
    pub(crate) property_blobs: Vec<PropertyBlob>,
    /// Next non-zero property-blob id.
    pub(crate) next_property_blob_id: u32,
    /// Monotonic vblank sequence reported in flip-complete events.
    pub vblank_seq: u32,
    /// Monotonic-ns time of the next simulated vblank at/after which a queued
    /// flip event may be delivered. Advances one refresh interval per flip so
    /// back-to-back PAGE_FLIPs land on successive vblanks — the Linux/VKMS
    /// hrtimer-per-frame pacing, derived from the CRTC mode's refresh rate.
    pub next_vblank_ns: u64,
    /// The open-file that currently holds DRM master, if any. `None` means the
    /// device master is free — the next `SET_MASTER` (or first primary open, via
    /// [`Card::master_open`]) claims it. Each `/dev/dri/cardN` open is tagged
    /// with a unique `open_id` (see `drm_devfs_bridge::DriCardFile`); a primary
    /// fd is master iff its id equals this.
    ///
    /// Linux analogue: `struct drm_device::master` (guarded by `master_mutex`).
    /// Modeset ioctls (SETCRTC/PAGE_FLIP/ADDFB2/ATOMIC) require the caller be the
    /// current master; a second client's `SET_MASTER` fails with `EBUSY` while
    /// this is held. Replaces the old "every primary fd is implicitly master"
    /// model, which let a greeter and a user-session compositor both drive the
    /// same scanout with no handoff.
    pub(crate) current_master: Option<u64>,
    /// Issued DRM magic tokens: `(magic, open_id, authenticated)`. One magic
    /// per open, allocated on its first `GET_MAGIC` and kept for the life of
    /// the fd (a repeat `GET_MAGIC` returns the same value). `AUTH_MAGIC`
    /// consumes an entry by setting `authenticated`, so the same magic cannot
    /// authenticate twice. Linux analogue: `drm_master::magic_map` (an idr
    /// based at 1) plus `drm_file::magic`.
    magics: Vec<(u32, u64, bool)>,
    /// Next magic to hand out. Starts at 1: magic 0 is never valid, matching
    /// `idr_init_base(&master->magic_map, 1)`.
    next_magic: u32,
    /// Real sink data for native-driver connectors (see [`NativeOutput`]).
    pub native: Vec<NativeOutput>,
    /// The hardware vblank clock of a driver that scans out natively;
    /// without one the vblank ioctls are unsupported.
    pub vblank_source: Option<VblankSource>,
    /// The fourccs a natively scanned-out card's primary planes take. With
    /// them, ADDFB2 refuses any other format (Linux's
    /// `drm_any_plane_has_format`) and its planes are checked against what
    /// the hardware scans (see `NativePlane`). `None` keeps the CPU-copy
    /// cards' formats.
    pub plane_formats: Option<&'static [u32]>,
    /// A native display backend that implements DRIVER_ATOMIC through the
    /// bridge's native atomic path (the Navi48 card sets it on publish).
    pub native_atomic: bool,
    /// The CRTCs (by id) carrying the "VRR_ENABLED" property, with the value
    /// DRM last committed. Empty on cards that do not expose it.
    pub vrr_enabled: Vec<(u32, bool)>,
    /// The CRTCs carrying color management properties. Empty on cards that
    /// do not expose them.
    pub crtc_color: Vec<CrtcColor>,
    /// A native card's planes with amdgpu_dm's plane properties: every
    /// CRTC's primary, the overlay planes and every CRTC's cursor plane.
    /// Empty on cards without them.
    pub native_planes: Vec<NativePlane>,
    /// The fourccs the native overlay planes take.
    pub overlay_formats: Option<&'static [u32]>,
    /// The native amdgpu card: its planes list the GFX12 modifiers
    /// (`amdgpu_dm_modifiers::PLANE_MODIFIERS`) and ADDFB2 runs amdgpu's
    /// framebuffer checks (amdgpu_display_user_framebuffer_create).
    pub gfx12_modifiers: bool,
    /// Each dumb BO's GEM_METADATA tiling flags and GFX12_DCC creation flag
    /// (amdgpu_bo_get_tiling_flags), by handle; a BO not listed has none.
    pub bo_tiling: Vec<(u32, u64, bool)>,
}

/// drm_plane_state's blending and orientation as amdgpu_dm attaches them:
/// "alpha" (overlays; 0xffff opaque), "pixel blend mode"
/// (DRM_MODE_BLEND_*), "zpos" and "rotation" (one DRM_MODE_ROTATE_* bit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaneProps {
    pub alpha: u16,
    pub blend: u8,
    pub zpos: u8,
    pub rotation: u8,
    /// "COLOR_ENCODING" (DRM_COLOR_YCBCR_BT601/709/2020) and "COLOR_RANGE"
    /// (DRM_COLOR_YCBCR_LIMITED/FULL_RANGE): only YCbCr formats use them.
    pub color_encoding: u8,
    pub color_range: u8,
}
impl PlaneProps {
    /// DRM_MODE_BLEND_PREMULTI, DRM_MODE_BLEND_COVERAGE, DRM_MODE_BLEND_PIXEL_NONE.
    pub const PREMULTI: u8 = 0;
    pub const COVERAGE: u8 = 1;
    pub const PIXEL_NONE: u8 = 2;
    /// enum drm_color_encoding and enum drm_color_range.
    pub const BT601: u8 = 0;
    pub const BT709: u8 = 1;
    pub const BT2020: u8 = 2;
    pub const LIMITED: u8 = 0;
    pub const FULL: u8 = 1;
    /// A plane's defaults: opaque, pre-multiplied, unrotated, at `zpos`.
    pub const fn new(zpos: u8) -> Self {
        Self {
            alpha: 0xffff,
            blend: Self::PREMULTI,
            zpos,
            rotation: 1,
            // amdgpu_dm_plane_init's defaults: BT.709, limited range.
            color_encoding: Self::BT709,
            color_range: Self::LIMITED,
        }
    }
}

/// One plane of a native card: its id, the CRTC whose primary or cursor
/// it is (an overlay has neither and may go on any), its committed CRTC and
/// framebuffer (a primary's mirror its CRTC's `primary_fb`), source
/// rectangle (whole pixels: amdgpu_dm ignores the 16.16 fraction) and CRTC
/// rectangle, and its properties. A primary whose rectangles no atomic
/// commit or SETPLANE set (`placed` false) shows the whole mode, as legacy
/// SETCRTC sets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativePlane {
    pub id: u32,
    pub primary_of: Option<u32>,
    /// The CRTC whose DRM_PLANE_TYPE_CURSOR plane this is
    /// (amdgpu_dm_crtc_init); None for a primary or an overlay.
    pub cursor_of: Option<u32>,
    pub crtc_id: Option<u32>,
    pub fb_id: Option<u32>,
    pub src: (u32, u32, u32, u32),
    pub dst: (i32, i32, u32, u32),
    pub placed: bool,
    pub props: PlaneProps,
    /// A cursor plane's framebuffer is one the legacy CURSOR ioctl wrapped
    /// around a BO (drm_internal_framebuffer_create): it goes away when the
    /// plane lets go of it.
    pub internal_fb: bool,
    /// A cursor plane's CRTC's legacy cursor position (drm_crtc's
    /// cursor_x/cursor_y), which a CURSOR ioctl without MOVE keeps.
    pub legacy_position: (i32, i32),
}
impl NativePlane {
    /// An overlay: neither a primary nor a cursor plane.
    pub fn is_overlay(&self) -> bool {
        self.primary_of.is_none() && self.cursor_of.is_none()
    }
    pub fn is_cursor(&self) -> bool {
        self.cursor_of.is_some()
    }
}

/// DRM's connector "color format" values (drm_connector_color_format).
/// AUTO preserves the HDMI helper policy: RGB, then declared 4:2:0.
/// A vendor-neutral property value: it lives in the DRM core, and the
/// AMD display code maps it onto its DC pixel encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum ColorFormat {
    #[default]
    Auto = 0,
    Rgb = 1,
    Ycbcr444 = 2,
    Ycbcr422 = 3,
    Ycbcr420 = 4,
}
impl ColorFormat {
    pub const fn from_linux(value: u64) -> Option<Self> {
        Some(match value {
            0 => Self::Auto,
            1 => Self::Rgb,
            2 => Self::Ycbcr444,
            3 => Self::Ycbcr422,
            4 => Self::Ycbcr420,
            _ => return None,
        })
    }
}

/// A connector whose modes and EDID come from a real sink, published by a
/// native display driver. GETCONNECTOR reports these timings and this EDID
/// instead of synthesizing them from `Connector::modes`.
#[derive(Clone, Debug)]
pub struct NativeOutput {
    /// The connector (id) this describes.
    pub connector: u32,
    /// The sink's base EDID block, reported verbatim; None when unplugged.
    pub edid: Option<[u8; 128]>,
    /// Exact driver-admitted timings, authoritative for GETCONNECTOR.
    /// Several may share a size and rounded refresh represented by only
    /// one entry in the connector's simplified `modes` list.
    pub timings: Vec<crate::drm::ioctl::DrmModeModeInfo>,
    /// The connector's "Broadcast RGB" value (0 Automatic, 1 Full,
    /// 2 Limited 16:235), when it has the property.
    pub broadcast_rgb: Option<u8>,
    /// The connector's immutable "vrr_capable" value, when it has the
    /// property (drm_connector_attach_vrr_capable_property).
    pub vrr_capable: Option<bool>,
    /// The connector's "Colorspace" value (a DRM_MODE_COLORIMETRY_*), when
    /// it has the property. amdgpu_dm's supported set gives HDMI and DP
    /// connectors the same list.
    pub colorspace: Option<u32>,
    /// The connector's "HDR_OUTPUT_METADATA" blob id (0 for none), when it
    /// has the property (drm_connector_attach_hdr_output_metadata_property).
    pub hdr_output_metadata: Option<u32>,
    /// The connector's "max bpc" (max_requested_bpc, 8..=16), when it has
    /// the property (drm_connector_attach_max_bpc_property).
    pub max_bpc: Option<u8>,
    /// Standard HDMI connector "color format" (AUTO=0, RGB=1, YUV444=2,
    /// YUV422=3, YUV420=4). None on transports without this native path.
    pub color_format: Option<ColorFormat>,
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

/// `SET_MASTER` denied because another open already holds DRM master.
/// The bridge maps this to `EBUSY`, matching `drm_setmaster_ioctl`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MasterBusy;

/// `DROP_MASTER` denied because the caller was not the current master.
/// The bridge maps this to `EINVAL`, matching `drm_dropmaster_ioctl`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NotCurrentMaster;

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
            #[cfg(feature = "intel")]
            intel_transaction: false,
            #[cfg(feature = "intel")]
            intel_deferred_owners: Vec::new(),
            #[cfg(feature = "intel")]
            intel_ctm: false,
            #[cfg(feature = "intel")]
            intel_display: false,
            #[cfg(feature = "intel")]
            intel_blob_pins: Vec::new(),
            #[cfg(feature = "intel")]
            intel_restore_pending: false,
            gem: GemTable::new(),
            dumb_backings: Vec::new(),
            virtgpu_imports: Vec::new(),
            property_blobs: Vec::new(),
            next_property_blob_id: 1,
            vblank_seq: 0,
            next_vblank_ns: 0,
            current_master: None,
            magics: Vec::new(),
            next_magic: 1,
            native: Vec::new(),
            vblank_source: None,
            plane_formats: None,
            native_atomic: false,
            vrr_enabled: Vec::new(),
            crtc_color: Vec::new(),
            native_planes: Vec::new(),
            overlay_formats: None,
            gfx12_modifiers: false,
            bo_tiling: Vec::new(),
        }
    }
    /// The native plane `id`, if this card has one.
    pub fn native_plane(&self, id: u32) -> Option<&NativePlane> {
        self.native_planes.iter().find(|p| p.id == id)
    }
    /// Wire form of a CRTC mode: the exact native timing when a published
    /// connector carries this mode, otherwise the synthesized one.
    pub fn mode_wire(&self, mode: &crate::Mode) -> crate::drm::ioctl::DrmModeModeInfo {
        self.native
            .iter()
            .flat_map(|n| n.timings.iter())
            .find(|t| {
                (u32::from(t.hdisplay), u32::from(t.vdisplay), t.vrefresh)
                    == (mode.width, mode.height, u32::from(mode.refresh_hz))
            })
            .copied()
            .unwrap_or_else(|| crate::drm::ioctl::mode_to_wire(mode))
    }
    /// Whether a SETCRTC mode may be applied. A card with native outputs can
    /// only show the exact timings its driver published (it cannot program
    /// an arbitrary mode yet); other cards accept any mode as before.
    pub fn accepts_mode(&self, m: &crate::drm::ioctl::DrmModeModeInfo) -> bool {
        let geometry = |t: &crate::drm::ioctl::DrmModeModeInfo| {
            (
                t.clock,
                [t.hdisplay, t.hsync_start, t.hsync_end, t.htotal],
                [t.vdisplay, t.vsync_start, t.vsync_end, t.vtotal],
            )
        };
        self.native.is_empty()
            || self
                .native
                .iter()
                .flat_map(|n| n.timings.iter())
                .any(|t| geometry(t) == geometry(m))
    }
    /// `accepts_mode` for an atomic MODE_ID blob: on a card with native
    /// outputs only a published timing (the driver cannot switch a live
    /// display to another), as SETCRTC already enforces.
    pub fn accepts_mode_blob(&self, blob: &[u8]) -> bool {
        crate::drm::ioctl::DrmModeModeInfo::from_bytes(blob).is_some_and(|m| self.accepts_mode(&m))
    }
    /// The native sink data of a connector, if a driver published it.
    pub fn native_output(&self, connector: u32) -> Option<&NativeOutput> {
        self.native.iter().find(|n| n.connector == connector)
    }

    // ── DRM master arbitration ────────────────────────────────────────
    //
    // `open_id` uniquely identifies one open `/dev/dri/cardN` file. These
    // mirror `drivers/gpu/drm/drm_auth.c`: exactly one open holds master at
    // a time, the first opener auto-acquires it, and it is released on
    // DROP_MASTER or fd close so the next session can take over.

    /// `drm_master_open`: the first primary open of a master-free device
    /// becomes its master automatically. No-op if a master already exists —
    /// a later opener stays non-master until it runs `SET_MASTER`.
    pub fn master_open(&mut self, open_id: u64) {
        if self.current_master.is_none() {
            self.current_master = Some(open_id);
        }
    }

    /// Whether `open_id` is the current DRM master. Drives `DrmFileCtx`'s
    /// `is_master` for the per-ioctl permission gate.
    pub fn is_master(&self, open_id: u64) -> bool {
        self.current_master == Some(open_id)
    }

    #[cfg(feature = "intel")]
    pub(crate) fn has_master(&self) -> bool {
        self.current_master.is_some()
    }

    /// `DRM_IOCTL_SET_MASTER`. `Ok` if `open_id` already holds master or the
    /// device master was free (it now holds it); `Err` (→ `EBUSY`) if another
    /// open currently holds master. Mirrors `drm_setmaster_ioctl`.
    pub fn set_master(&mut self, open_id: u64) -> Result<(), MasterBusy> {
        match self.current_master {
            Some(m) if m == open_id => Ok(()),
            Some(_) => Err(MasterBusy),
            None => {
                self.current_master = Some(open_id);
                Ok(())
            }
        }
    }

    /// `DRM_IOCTL_DROP_MASTER`. `Ok` if `open_id` held master (now released);
    /// `Err` (→ `EINVAL`) if it was not the current master. Mirrors
    /// `drm_dropmaster_ioctl`, which returns `-EINVAL` for a non-master caller.
    pub fn drop_master(&mut self, open_id: u64) -> Result<(), NotCurrentMaster> {
        if self.current_master == Some(open_id) {
            self.current_master = None;
            Ok(())
        } else {
            Err(NotCurrentMaster)
        }
    }

    /// `drm_master_release`: called when a card fd closes. Auto-drops master
    /// if this open held it, freeing the device for the next `SET_MASTER`
    /// (the greeter→user-session handoff path).
    pub fn master_release(&mut self, open_id: u64) {
        if self.current_master == Some(open_id) {
            self.current_master = None;
            #[cfg(feature = "intel")]
            {
                self.intel_restore_pending |= self.intel_display;
                self.intel_clear_ctm();
            }
        }
    }

    /// `DRM_IOCTL_GET_MAGIC`: this open's magic token, allocated on first use.
    /// Mirrors `drm_getmagic`, which reuses `file_priv->magic` once set.
    pub fn get_magic(&mut self, open_id: u64) -> u32 {
        if let Some(&(magic, _, _)) = self.magics.iter().find(|m| m.1 == open_id) {
            return magic;
        }
        let magic = self.next_magic;
        self.next_magic = self.next_magic.wrapping_add(1).max(1);
        self.magics.push((magic, open_id, false));
        magic
    }

    /// `DRM_IOCTL_AUTH_MAGIC` body, run only for the current master: marks the
    /// open holding `magic` authenticated. `false` (→ `EINVAL`) when no open
    /// holds it or it was already consumed. Mirrors `drm_authmagic`, whose
    /// `idr_replace(.., NULL, magic)` makes a second auth of one magic fail.
    pub fn auth_magic(&mut self, magic: u32) -> bool {
        match self.magics.iter_mut().find(|m| m.0 == magic && !m.2) {
            Some(entry) => {
                entry.2 = true;
                true
            }
            None => false,
        }
    }

    /// `drm_file_free`: forget a closing open's magic.
    pub fn magic_release(&mut self, open_id: u64) {
        self.magics.retain(|m| m.1 != open_id);
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
    pub(crate) fn queue_flip_event(
        &mut self,
        events: &mut DrmEventQueue,
        user_data: u64,
        crtc_id: u32,
    ) -> Result<u64, DrmEventQueueFull> {
        let present_at = self.advance_vblank(crtc_id);
        self.queue_flip_event_at(events, user_data, crtc_id, present_at)?;
        Ok(present_at)
    }

    /// Advance the simulated vblank for `crtc_id` and return the TRUE
    /// vblank time this commit presents at. Split out of
    /// [`Card::queue_flip_event`] so a commit that carries `OUT_FENCE_PTR`
    /// but no PAGE_FLIP_EVENT (kmscube's atomic loop) paces on the same
    /// clock, and a commit carrying BOTH advances it exactly once.
    pub(crate) fn advance_vblank(&mut self, crtc_id: u32) -> u64 {
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
        present_at
    }

    /// Queue the flip-complete event for a commit whose vblank was already
    /// advanced to `present_at` (see [`Card::advance_vblank`]).
    pub(crate) fn queue_flip_event_at(
        &mut self,
        events: &mut DrmEventQueue,
        user_data: u64,
        crtc_id: u32,
        present_at: u64,
    ) -> Result<(), DrmEventQueueFull> {
        const DRM_EVENT_FLIP_COMPLETE: u32 = 2;
        const EVENT_LEN: usize = DrmEventQueue::FLIP_EVENT_BYTES;
        if events.event_space < EVENT_LEN {
            return Err(DrmEventQueueFull);
        }
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
        let mut e = [0u8; EVENT_LEN];
        e[0..4].copy_from_slice(&DRM_EVENT_FLIP_COMPLETE.to_le_bytes()); // base.type
        e[4..8].copy_from_slice(&(EVENT_LEN as u32).to_le_bytes()); // base.length
        e[8..16].copy_from_slice(&user_data.to_le_bytes());
        e[16..20].copy_from_slice(&tv_sec.to_le_bytes());
        e[20..24].copy_from_slice(&tv_usec.to_le_bytes());
        e[24..28].copy_from_slice(&self.vblank_seq.to_le_bytes());
        e[28..32].copy_from_slice(&crtc_id.to_le_bytes());
        events.push(QueuedEvent {
            deliver_at_ns: deliver_at,
            wait: Wait::Time,
            bytes: e,
        })
    }

    /// Queue the flip-complete event of a frame `display` flips in hardware
    /// under `ticket` (see [`FlipLog`]): it becomes readable when that flip
    /// completes and carries the flip's time and vblank count, as Linux's
    /// pageflip interrupt handler sends it.
    pub(crate) fn queue_hw_flip_event(
        &mut self,
        events: &mut DrmEventQueue,
        user_data: u64,
        crtc_id: u32,
        display: u8,
        ticket: u64,
    ) -> Result<(), DrmEventQueueFull> {
        const DRM_EVENT_FLIP_COMPLETE: u32 = 2;
        const EVENT_LEN: usize = DrmEventQueue::FLIP_EVENT_BYTES;
        let period_ns = 1_000_000_000u64 / u64::from(self.crtc_refresh_hz(crtc_id));
        let mut e = [0u8; EVENT_LEN];
        e[0..4].copy_from_slice(&DRM_EVENT_FLIP_COMPLETE.to_le_bytes());
        e[4..8].copy_from_slice(&(EVENT_LEN as u32).to_le_bytes());
        e[8..16].copy_from_slice(&user_data.to_le_bytes());
        e[28..32].copy_from_slice(&crtc_id.to_le_bytes());
        events.push(QueuedEvent {
            deliver_at_ns: 0,
            wait: Wait::Flip(display, ticket, period_ns),
            bytes: e,
        })
    }

    /// The hardware vblank clock of `crtc_id`: `Err(None)` when this card
    /// has no vblank support, `Err(Some(()))` when the CRTC is unknown or
    /// off (its vblank cannot be enabled).
    pub fn vblank_time(&self, crtc_id: u32) -> Result<VblankTime, Option<()>> {
        let source = self.vblank_source.ok_or(None)?;
        let crtc = self.crtc(crtc_id).map_err(|_| Some(()))?;
        if !crtc.enabled {
            return Err(Some(()));
        }
        source(crtc_id).ok_or(Some(()))
    }

    /// Queue a vblank event for vblank `target` on `crtc_id`: a
    /// `drm_event_vblank` (WAIT_VBLANK) or, with `sequence`, a
    /// `drm_event_crtc_sequence` (CRTC_QUEUE_SEQUENCE). It is delivered once
    /// the CRTC's count reaches `target`, with that vblank's time and count.
    /// The card must have a vblank source.
    pub(crate) fn queue_vblank_event(
        &self,
        events: &mut DrmEventQueue,
        user_data: u64,
        crtc_id: u32,
        target: u64,
        sequence: bool,
    ) -> Result<(), DrmEventQueueFull> {
        const DRM_EVENT_VBLANK: u32 = 1;
        const DRM_EVENT_CRTC_SEQUENCE: u32 = 3;
        let Some(source) = self.vblank_source else {
            return Err(DrmEventQueueFull);
        };
        let mut e = [0u8; 32];
        let kind = if sequence {
            DRM_EVENT_CRTC_SEQUENCE
        } else {
            DRM_EVENT_VBLANK
        };
        e[0..4].copy_from_slice(&kind.to_le_bytes());
        e[4..8].copy_from_slice(&32u32.to_le_bytes());
        e[8..16].copy_from_slice(&user_data.to_le_bytes());
        if !sequence {
            e[28..32].copy_from_slice(&crtc_id.to_le_bytes());
        }
        events.push(QueuedEvent {
            deliver_at_ns: 0,
            wait: Wait::Vblank {
                source,
                crtc_id,
                target,
                sequence,
            },
            bytes: e,
        })
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

    /// Look up a PRIME-imported VirGL resource by its local GEM handle.
    pub(crate) fn virtgpu_import(
        &self,
        gem_handle: u32,
    ) -> Option<&Arc<crate::drm_ioctl_bridge::VirtGpuResource>> {
        self.virtgpu_imports
            .iter()
            .find(|entry| entry.gem_handle == gem_handle)
            .map(|entry| &entry.resource)
    }

    /// Register a shared VirGL object under an exact per-open handle.
    pub(crate) fn register_virtgpu_import(
        &mut self,
        handle: u32,
        resource: Arc<crate::drm_ioctl_bridge::VirtGpuResource>,
    ) -> Result<(), CardError> {
        self.gem
            .alloc_at(handle, 0, resource.len())
            .map_err(|_| CardError::BadGemHandle)?;
        self.virtgpu_imports.push(VirtGpuImport {
            gem_handle: handle,
            resource,
            refcount: 1,
        });
        Ok(())
    }

    /// Drop one GEM/framebuffer reference to an imported VirGL object.
    pub(crate) fn remove_virtgpu_import(&mut self, handle: u32) -> bool {
        let Some(pos) = self
            .virtgpu_imports
            .iter()
            .position(|entry| entry.gem_handle == handle)
        else {
            return false;
        };
        let entry = &mut self.virtgpu_imports[pos];
        entry.refcount = entry.refcount.saturating_sub(1);
        if entry.refcount != 0 {
            return true;
        }
        self.virtgpu_imports.swap_remove(pos);
        let _ = self.gem.free(handle);
        true
    }

    /// Register a userspace KMS property blob and return its object id.
    pub(crate) fn create_property_blob(&mut self, data: Vec<u8>) -> Result<u32, CardError> {
        if data.is_empty() {
            return Err(CardError::InvalidDimensions);
        }
        if self.property_blobs.len() >= 4096 {
            return Err(CardError::TooManyFbs);
        }
        let mut id = self.next_property_blob_id.max(1);
        while self.property_blobs.iter().any(|blob| blob.id == id) {
            id = id.wrapping_add(1).max(1);
        }
        self.next_property_blob_id = id.wrapping_add(1).max(1);
        self.property_blobs.push(PropertyBlob {
            id,
            data,
            user: true,
        });
        Ok(id)
    }

    /// Look up a KMS property blob by id.
    pub(crate) fn property_blob(&self, id: u32) -> Option<&[u8]> {
        self.property_blobs
            .iter()
            .find(|blob| blob.id == id)
            .map(|blob| blob.data.as_slice())
    }

    /// Destroy a KMS property blob. Returns false for an unknown id (or one
    /// already destroyed). A blob a committed property still names stays
    /// readable until that property lets it go, as Linux's reference does.
    pub(crate) fn destroy_property_blob(&mut self, id: u32) -> bool {
        let Some(blob) = self
            .property_blobs
            .iter_mut()
            .find(|blob| blob.id == id && blob.user)
        else {
            return false;
        };
        blob.user = false;
        self.collect_blobs();
        true
    }

    /// Whether a committed color or HDR property names blob `id`.
    fn blob_referenced(&self, id: u32) -> bool {
        #[cfg(feature = "intel")]
        if self
            .intel_blob_pins
            .iter()
            .any(|&(blob, count)| blob == id && count != 0)
        {
            return true;
        }
        id != 0
            && (self
                .crtc_color
                .iter()
                .any(|c| c.ctm == id || c.gamma_lut == id)
                || self
                    .native
                    .iter()
                    .any(|n| n.hdr_output_metadata == Some(id)))
    }

    pub(crate) fn intel_color(&self, crtc: u32) -> bool {
        #[cfg(feature = "intel")]
        {
            self.intel_ctm && self.crtc_color(crtc).is_some()
        }
        #[cfg(not(feature = "intel"))]
        {
            let _ = crtc;
            false
        }
    }
    #[cfg(feature = "intel")]
    pub(crate) fn intel_retain_blob(&mut self, id: u32) -> bool {
        if self.property_blob(id).is_none() {
            return false;
        }
        if let Some((_, count)) = self
            .intel_blob_pins
            .iter_mut()
            .find(|(blob, _)| *blob == id)
        {
            let Some(next) = count.checked_add(1) else {
                return false;
            };
            *count = next;
        } else {
            self.intel_blob_pins.push((id, 1));
        }
        true
    }
    #[cfg(feature = "intel")]
    pub(crate) fn intel_release_blob(&mut self, id: u32) {
        if let Some(at) = self
            .intel_blob_pins
            .iter()
            .position(|(blob, _)| *blob == id)
        {
            self.intel_blob_pins[at].1 -= 1;
            if self.intel_blob_pins[at].1 == 0 {
                self.intel_blob_pins.swap_remove(at);
            }
        }
        self.collect_blobs();
    }
    #[cfg(feature = "intel")]
    pub(crate) fn intel_master_restore_pending(&self) -> bool {
        self.intel_restore_pending
    }
    /// Called only under the display Session after original console/color
    /// restoration and current authority have been verified. A later stale
    /// close task must then leave a replacement master's new state untouched.
    #[cfg(feature = "intel")]
    pub(crate) fn intel_master_restored(&mut self) {
        self.intel_clear_ctm();
        self.intel_restore_pending = false;
    }
    #[cfg(feature = "intel")]
    pub(crate) fn intel_clear_ctm(&mut self) {
        if self.intel_ctm {
            for color in &mut self.crtc_color {
                color.ctm = 0;
                color.gamma_lut = 0;
            }
        }
        self.collect_blobs();
    }

    /// Free destroyed blobs no committed property names any more (the last
    /// `drm_property_blob_put`).
    pub(crate) fn collect_blobs(&mut self) {
        let keep: Vec<bool> = self
            .property_blobs
            .iter()
            .map(|b| b.user || self.blob_referenced(b.id))
            .collect();
        let mut keep = keep.into_iter();
        self.property_blobs.retain(|_| keep.next().unwrap_or(true));
    }

    /// The color management of CRTC `crtc`, when it has the properties.
    pub fn crtc_color(&self, crtc: u32) -> Option<&CrtcColor> {
        self.crtc_color.iter().find(|c| c.crtc == crtc)
    }

    /// Look up a dumb backing by mmap offset.
    pub fn dumb_backing_by_offset(&self, mmap_offset: u64) -> Option<&DumbBacking> {
        self.dumb_backings
            .iter()
            .find(|b| b.mmap_offset == mmap_offset)
    }

    /// Retain the dumb backing named by `gem_handle` and return the physical
    /// snapshot needed to build a dma-buf file. The reference must later be
    /// balanced with [`Self::remove_dumb_backing`].
    pub fn retain_dumb_backing(
        &mut self,
        gem_handle: u32,
    ) -> Option<(u64, usize, Arc<narf_filesystem::dma_buf::DmaBufObject>)> {
        let backing = self
            .dumb_backings
            .iter_mut()
            .find(|b| b.gem_handle == gem_handle)?;
        backing.refcount = backing.refcount.checked_add(1)?;
        Some((backing.phys, backing.byte_len, Arc::clone(&backing.dma_buf)))
    }

    /// Retain the dumb backing selected by a `MAP_DUMB` offset. This is the
    /// atomic lookup-plus-pin used before exposing its raw physical frames to
    /// `mmap(2)`, so a concurrent `GEM_CLOSE` cannot recycle them between the
    /// lookup and mapping publication.
    pub fn retain_dumb_backing_by_offset(&mut self, mmap_offset: u64, len: usize) -> Option<u32> {
        let backing = self
            .dumb_backings
            .iter_mut()
            .find(|b| b.mmap_offset == mmap_offset)?;
        if len > backing.byte_len {
            return None;
        }
        backing.refcount = backing.refcount.checked_add(1)?;
        Some(backing.gem_handle)
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
            dma_buf: Default::default(),
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
        // The refcount reached zero, but the buffer's pages may still be mapped
        // into a userspace address space — an mmap-lifetime reference can be
        // dropped (GEM_CLOSE/DESTROY_DUMB/RMFB) before the mapping is torn down.
        // Returning still-mapped frames to the buddy is a use-after-free: they
        // recycle into unrelated allocations (a filesystem page cache was the
        // observed victim) while a live user PTE keeps writing to them. Match
        // Linux, which frees a folio only once its mapcount/refcount is zero: if
        // any backing page still has a reverse-map owner, DEFER — keep the
        // backing registered (refcount stays 0) and free nothing now. The mmap
        // teardown's lifetime drop calls back here after the mapping and its
        // rmap are gone, and the free then proceeds.
        let phys = b.phys;
        let order = b.order;
        let pages = 1u64 << order;
        let still_mapped = (0..pages).any(|i| {
            narf_memory::rmap::owner_count(narf_memory::PhysAddr::new(phys + i * 4096)) != 0
        });
        if still_mapped {
            return None;
        }
        let removed = self.dumb_backings.swap_remove(pos);
        let _ = self.gem.free(gem_handle);
        Some((removed.phys, removed.order))
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
        let mut cmd = crate::drm::fb_cmd::FbCmd {
            width,
            height,
            pixel_format: format,
            ..Default::default()
        };
        cmd.handles[0] = gem_handle;
        cmd.pitches[0] = pitch;
        self.addfb2_cmd(&cmd)
    }

    /// ADDFB2 with the whole `drm_mode_fb_cmd2`: handles, pitches, offsets
    /// and modifiers. The native amdgpu card (`gfx12_modifiers`) runs
    /// drm_internal_framebuffer_create's and amdgpu's checks
    /// (`amdgpu_dm_modifiers::check_fb_cmd` / `check_amdgpu_fb`: format and
    /// modifier on a plane, one BO, tiling flags without modifiers, sizes);
    /// other cards take one plane, LINEAR only.
    pub fn addfb2_cmd(&mut self, cmd: &crate::drm::fb_cmd::FbCmd) -> Result<u32, CardError> {
        let (width, height, gem_handle) = (cmd.width, cmd.height, cmd.handles[0]);
        let pitch = cmd.pitches[0];
        let (offsets, chroma_pitch, modifier) = if self.gfx12_modifiers {
            #[cfg(feature = "amdgpu")]
            {
                use crate::amdgpu_dm_modifiers as m;
                let info = m::check_fb_cmd(cmd).map_err(|_| CardError::InvalidDimensions)?;
                let object = self.gem.lookup(gem_handle).ok_or(CardError::BadGemHandle)?;
                let bo_size = self
                    .dumb_backings
                    .iter()
                    .find(|b| b.gem_handle == gem_handle)
                    .map_or(object.size as u64, |b| b.byte_len as u64);
                let (tiling, dcc) = self
                    .bo_tiling
                    .iter()
                    .find(|t| t.0 == gem_handle)
                    .map_or((0, false), |t| (t.1, t.2));
                let formats = self.plane_formats.unwrap_or(&[]);
                let modifier = m::check_amdgpu_fb(cmd, &info, formats, tiling, dcc, bo_size)
                    .map_err(|_| CardError::UnknownFormat)?;
                let two = info.num_planes == 2;
                (
                    [cmd.offsets[0], if two { cmd.offsets[1] } else { 0 }],
                    if two { cmd.pitches[1] } else { 0 },
                    modifier,
                )
            }
            #[cfg(not(feature = "amdgpu"))]
            {
                // Only the amdgpu native KMS sets `gfx12_modifiers`
                // (its cards are the ones with GFX12 modifier checks);
                // without the driver the flag is never set.
                return Err(CardError::UnknownFormat);
            }
        } else {
            // DRM_MODE_FB_MODIFIERS with anything but LINEAR, or an unknown
            // flag, is refused (framebuffer_check / drm_mode_addfb2).
            if cmd.flags & !3 != 0 || (cmd.flags & 2 != 0 && cmd.modifier[0] != 0) {
                return Err(CardError::UnknownFormat);
            }
            if width == 0 || height == 0 {
                return Err(CardError::InvalidDimensions);
            }
            // Validate GEM handle exists.
            if self.gem.lookup(gem_handle).is_none() {
                return Err(CardError::BadGemHandle);
            }
            let format = cmd.pixel_format;
            // Validate pixel format: a format no plane takes is refused.
            if self
                .plane_formats
                .is_some_and(|formats| !formats.contains(&format))
            {
                return Err(CardError::UnknownFormat);
            }
            // A card without native planes keeps the formats it always took.
            let legacy = matches!(format, 0x3432_5258 | 0x3432_5241 | 0x3631_4752);
            if self.plane_formats.is_none() && !legacy {
                return Err(CardError::UnknownFormat);
            }
            let format = PixelFormat::from_fourcc(format).ok_or(CardError::UnknownFormat)?;
            // Two-plane formats need the native amdgpu card's checks.
            if matches!(format, PixelFormat::Nv12 | PixelFormat::P010) {
                return Err(CardError::UnknownFormat);
            }
            // drm_framebuffer's framebuffer_check: the pitch holds a line of
            // the format's pixels; drm_gem_fb_init_with_funcs: a dumb-backed
            // object holds every line (EINVAL either way).
            let line = u64::from(width) * u64::from(format.cpp());
            if u64::from(pitch) < line {
                return Err(CardError::InvalidDimensions);
            }
            if let Some(b) = self
                .dumb_backings
                .iter()
                .find(|b| b.gem_handle == gem_handle)
            {
                if (b.byte_len as u64) < u64::from(height - 1) * u64::from(pitch) + line {
                    return Err(CardError::InvalidDimensions);
                }
            }
            ([0, 0], 0, 0)
        };
        let format = PixelFormat::from_fourcc(cmd.pixel_format).ok_or(CardError::UnknownFormat)?;
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
        } else if let Some(imported) = self
            .virtgpu_imports
            .iter_mut()
            .find(|entry| entry.gem_handle == gem_handle)
        {
            imported.refcount = imported.refcount.saturating_add(1);
        }
        self.framebuffers.push(Framebuffer {
            id,
            width,
            height,
            format,
            pitch,
            gem_handle,
            offsets,
            chroma_pitch,
            modifier,
            bo: None,
            #[cfg(feature = "intel")]
            intel: None,
        });
        Ok(id)
    }

    /// ADDFB2 on the native amdgpu card naming one of open `owner`'s amdgpu
    /// GEM handles (amdgpu_display_user_framebuffer_create's
    /// drm_gem_object_lookup): amdgpu's checks as for a dumb buffer, with
    /// the buffer's own size, `GEM_METADATA` tiling flags and
    /// AMDGPU_GEM_CREATE_GFX12_DCC (amdgpu_display_get_fb_info). The
    /// framebuffer holds the buffer until it is removed. The DCN30 native
    /// atomic card accepts only LINEAR 8888 without DCC; other cards without
    /// a native amdgpu presenter have no GEM handles (`BadGemHandle`).
    #[cfg(feature = "amdgpu")]
    pub fn addfb2_bo(
        &mut self,
        cmd: &crate::drm::fb_cmd::FbCmd,
        object: Arc<crate::amdgpu_gem::GemObject>,
        owner: u64,
    ) -> Result<u32, CardError> {
        use crate::amdgpu_dm_modifiers as m;
        let linear = crate::amdgpu_native_kms::linear_gem_card(self);
        if !self.gfx12_modifiers && !linear {
            return Err(CardError::BadGemHandle);
        }
        let info = m::check_fb_cmd(cmd).map_err(|_| CardError::InvalidDimensions)?;
        let dcc = object.flags & u64::from(crate::amdgpu_uapi::AMDGPU_GEM_CREATE_GFX12_DCC) != 0;
        let formats = self.plane_formats.unwrap_or(&[]);
        let modifier = m::check_amdgpu_fb(
            cmd,
            &info,
            formats,
            object.tiling_flags(),
            dcc,
            object.byte_len,
        )
        .map_err(|_| CardError::UnknownFormat)?;
        if linear
            && (modifier != 0 || dcc || !matches!(cmd.pixel_format, 0x3432_5258 | 0x3432_5241))
        {
            return Err(CardError::UnknownFormat);
        }
        let format = PixelFormat::from_fourcc(cmd.pixel_format).ok_or(CardError::UnknownFormat)?;
        if self.framebuffers.len() >= 4096 {
            return Err(CardError::TooManyFbs);
        }
        let two = info.num_planes == 2;
        let id = self.next_fb_id;
        self.next_fb_id = self.next_fb_id.wrapping_add(1).max(1);
        self.framebuffers.push(Framebuffer {
            id,
            width: cmd.width,
            height: cmd.height,
            format,
            pitch: cmd.pitches[0],
            gem_handle: cmd.handles[0],
            offsets: [cmd.offsets[0], if two { cmd.offsets[1] } else { 0 }],
            chroma_pitch: if two { cmd.pitches[1] } else { 0 },
            modifier,
            bo: Some(FbBo { object, owner }),
            #[cfg(feature = "intel")]
            intel: None,
        });
        Ok(id)
    }

    /// ADDFB2 naming one of open `owner`'s Intel GEM handles: drm core's
    /// framebuffer_check and Linux intel_framebuffer_init, in their order.
    /// Only LINEAR is taken (no tiled presentation exists here); plane 0 has
    /// no offset; the pitch is 64-byte aligned (4 KiB past the plane's
    /// 128 KiB native limit) and at most 256 KiB; the object holds every
    /// line. On native Xe (`xe`), an object not created SCANOUT may not be
    /// VM-bound and becomes SCANOUT (intel_fb_bo_framebuffer_init).
    #[cfg(feature = "intel")]
    pub fn addfb2_intel(
        &mut self,
        cmd: &crate::drm::fb_cmd::FbCmd,
        object: Arc<crate::intel_gpu_gem::GemObject>,
        owner: u64,
        xe: bool,
    ) -> Result<u32, CardError> {
        use crate::drm::fb_cmd::{FB_INTERLACED, FB_MODIFIERS};
        // framebuffer_check.
        if cmd.flags & !(FB_INTERLACED | FB_MODIFIERS) != 0
            || (cmd.flags & FB_MODIFIERS != 0 && cmd.modifier[0] != 0)
        {
            return Err(CardError::UnknownFormat);
        }
        let legacy = matches!(cmd.pixel_format, 0x3432_5258 | 0x3432_5241 | 0x3631_4752);
        let format = PixelFormat::from_fourcc(cmd.pixel_format)
            .filter(|_| legacy)
            .ok_or(CardError::UnknownFormat)?;
        if cmd.width == 0 || cmd.height == 0 {
            return Err(CardError::InvalidDimensions);
        }
        let line = u64::from(cmd.width) * u64::from(format.cpp());
        if u64::from(cmd.pitches[0]) < line {
            return Err(CardError::InvalidDimensions);
        }
        // Unused planes carry nothing (checked when FB_MODIFIERS is set,
        // as older userspace left them uncleared).
        for i in 1..4 {
            if cmd.modifier[i] != 0
                || (cmd.flags & FB_MODIFIERS != 0
                    && (cmd.handles[i] != 0 || cmd.pitches[i] != 0 || cmd.offsets[i] != 0))
            {
                return Err(CardError::InvalidDimensions);
            }
        }
        // VRAM pages have no CPU physical address for the scanout copy, and
        // no display reads them here.
        if object.is_vram() {
            return Err(CardError::InvalidDimensions);
        }
        if xe && !object.scanout() {
            if object.vm_bound() {
                return Err(CardError::InvalidDimensions);
            }
            object.mark_scanout();
        }
        let pitch = cmd.pitches[0];
        const MAX_STRIDE: u32 = 256 * 1024; // intel_fb_max_stride, remapped
        const PLANE_STRIDE: u32 = 128 * 1024; // adl_plane_max_stride bytes
        let alignment = if pitch > PLANE_STRIDE { 4096 } else { 64 };
        if pitch > MAX_STRIDE || cmd.offsets[0] != 0 || pitch % alignment != 0 {
            return Err(CardError::InvalidDimensions);
        }
        if u64::from(pitch) * u64::from(cmd.height) > object.size() {
            return Err(CardError::InvalidDimensions);
        }
        if self.framebuffers.len() >= 4096 {
            return Err(CardError::TooManyFbs);
        }
        let id = self.next_fb_id;
        self.next_fb_id = self.next_fb_id.wrapping_add(1).max(1);
        self.framebuffers.push(Framebuffer {
            id,
            width: cmd.width,
            height: cmd.height,
            format,
            pitch,
            gem_handle: cmd.handles[0],
            offsets: [0, 0],
            chroma_pitch: 0,
            modifier: 0,
            bo: None,
            intel: Some(IntelFb { object, owner }),
        });
        Ok(id)
    }

    /// drm_fb_release for open `owner`: remove every framebuffer it made
    /// from one of its GEM handles (as RMFB does, turning off what shows
    /// it). Returns how many went.
    pub fn release_file_framebuffers(&mut self, owner: u64) -> usize {
        #[cfg(feature = "intel")]
        if self.intel_transaction {
            if !self.intel_deferred_owners.contains(&owner) {
                self.intel_deferred_owners.push(owner);
            }
            return 0;
        }
        let ids: Vec<u32> = self
            .framebuffers
            .iter()
            .filter(|fb| fb.gem_owner() == Some(owner))
            .map(|fb| fb.id)
            .collect();
        for &id in &ids {
            let _ = self.rmfb(id);
        }
        ids.len()
    }

    #[cfg(feature = "intel")]
    pub(crate) fn intel_transaction_busy(&self) -> bool {
        self.intel_transaction
    }

    #[cfg(feature = "intel")]
    pub(crate) fn intel_begin_transaction(
        &mut self,
        open: u64,
    ) -> Result<(), narf_filesystem::FsError> {
        if !self.is_master(open) {
            return Err(narf_filesystem::FsError::PermissionDenied);
        }
        if self.intel_transaction {
            return Err(narf_filesystem::FsError::Busy);
        }
        self.intel_transaction = true;
        Ok(())
    }

    #[cfg(feature = "intel")]
    pub(crate) fn intel_owner_closed(&self, owner: u64) -> bool {
        self.intel_deferred_owners.contains(&owner)
    }

    #[cfg(feature = "intel")]
    pub(crate) fn intel_finish_transaction(&mut self) {
        self.intel_transaction = false;
        let owners = core::mem::take(&mut self.intel_deferred_owners);
        for owner in owners {
            self.release_file_framebuffers(owner);
        }
    }

    /// `AMDGPU_GEM_METADATA` SET on a dumb BO of this card: record its
    /// tiling flags, which a later ADDFB2 without modifiers converts
    /// (amdgpu_bo_set_tiling_flags). False for a handle that is not one of
    /// this card's BOs.
    pub fn set_bo_tiling(&mut self, gem_handle: u32, tiling_flags: u64, gfx12_dcc: bool) -> bool {
        if self.gem.lookup(gem_handle).is_none() {
            return false;
        }
        self.bo_tiling.retain(|t| t.0 != gem_handle);
        if tiling_flags != 0 || gfx12_dcc {
            self.bo_tiling.push((gem_handle, tiling_flags, gfx12_dcc));
        }
        true
    }

    /// Remove a previously registered framebuffer (RMFB), turning off any
    /// CRTC that still shows it. Drops the
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
        // drm_framebuffer_remove: a plane still scanning this framebuffer is
        // disabled, and with the primary plane its CRTC (atomic_remove_fb
        // also clears the CRTC's mode).
        for crtc in self
            .crtcs
            .iter_mut()
            .filter(|c| c.primary_fb == Some(fb_id))
        {
            crtc.primary_fb = None;
            crtc.enabled = false;
            crtc.mode = None;
        }
        for p in self
            .native_planes
            .iter_mut()
            .filter(|p| p.fb_id == Some(fb_id))
        {
            p.fb_id = None;
            p.crtc_id = None;
        }
        // A GEM buffer's reference goes with the framebuffer; a scanout pin
        // (amdgpu_dm_plane_helper_prepare_fb's) keeps it while fetched. Its
        // handle names no dumb buffer or import of this card.
        if fb.gem_owner().is_some() {
            return Ok(None);
        }
        let freed = self.remove_dumb_backing(fb.gem_handle);
        if freed.is_none() {
            self.remove_virtgpu_import(fb.gem_handle);
        }
        Ok(freed)
    }

    /// Look up a framebuffer by id.
    pub fn framebuffer(&self, fb_id: u32) -> Result<&Framebuffer, CardError> {
        self.framebuffers
            .iter()
            .find(|fb| fb.id == fb_id)
            .ok_or(CardError::UnknownFb)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A dumb buffer whose last GEM/fb reference is dropped (GEM_CLOSE /
    /// DESTROY_DUMB / RMFB) while a userspace mmap of it is STILL live must not
    /// return its frames to the buddy: `free_pages` bypasses the rmap check, so a
    /// still-mapped frame recycles into an unrelated allocation (a filesystem
    /// page cache was the observed victim) and corrupts the desktop. Freeing must
    /// be DEFERRED until no reverse-map owner remains.
    fn smoke_dumb_backing_defers_free_while_mapped() -> TestResult {
        narf_memory::rmap::__reset_for_test();
        let mut card = Card::new("test", "test", (1, 0, 0));
        let phys = 0x40_000u64; // synthetic, page-aligned, nonzero
        let order = 2u8; // 16 KiB — cursor-sized
        let byte_len = (1usize << order) * 4096;
        let handle = match card.register_dumb_backing(phys, byte_len, order) {
            Ok(h) => h,
            Err(_) => return TestResult::Fail("register_dumb_backing failed"),
        };
        // Simulate a live userspace mapping of the first backing page.
        let root = narf_memory::PhysAddr::new(0x1000);
        let va = narf_memory::VirtAddr::new(0x4000_0000);
        narf_memory::rmap::add(narf_memory::PhysAddr::new(phys), root, va);
        // GEM_CLOSE / DESTROY_DUMB while mapped: must DEFER (no frames returned).
        if card.remove_dumb_backing(handle).is_some() {
            narf_memory::rmap::remove(narf_memory::PhysAddr::new(phys), root, va);
            narf_memory::rmap::__reset_for_test();
            return TestResult::Fail("freed a dumb buffer while a user PTE still mapped it");
        }
        // The mapping is torn down (munmap): the deferred free must now proceed
        // on the next drop (the mmap lifetime's release calls back in here).
        narf_memory::rmap::remove(narf_memory::PhysAddr::new(phys), root, va);
        let out = card.remove_dumb_backing(handle);
        narf_memory::rmap::__reset_for_test();
        match out {
            Some((p, o)) if p == phys && o == order => TestResult::Pass,
            Some(_) => TestResult::Fail("deferred free returned the wrong phys/order"),
            None => TestResult::Fail("deferred free never proceeded after unmap"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/drm/card",
        smoke_dumb_backing_defers_free_while_mapped
    );

    /// Baseline: an UNMAPPED dumb buffer frees immediately when its last
    /// reference drops — the defer guard must not withhold a genuinely free
    /// buffer.
    fn smoke_dumb_backing_frees_when_unmapped() -> TestResult {
        narf_memory::rmap::__reset_for_test();
        let mut card = Card::new("test", "test", (1, 0, 0));
        let phys = 0x50_000u64;
        let order = 0u8;
        let handle = match card.register_dumb_backing(phys, 4096, order) {
            Ok(h) => h,
            Err(_) => return TestResult::Fail("register_dumb_backing failed"),
        };
        // No rmap owner → the last-ref drop frees immediately.
        match card.remove_dumb_backing(handle) {
            Some((p, o)) if p == phys && o == order => TestResult::Pass,
            _ => TestResult::Fail("unmapped dumb buffer did not free on last ref"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/drm/card",
        smoke_dumb_backing_frees_when_unmapped
    );

    /// ADDFB2 of an Intel GEM handle follows drm's framebuffer_check and
    /// Linux intel_framebuffer_init in order: LINEAR 8888/565 only, no
    /// plane-0 offset, a 64-byte aligned pitch (4 KiB past the plane's
    /// 128 KiB limit) of at most 256 KiB, every line inside the object, and
    /// unused planes empty. On native Xe a VM-bound object not created
    /// SCANOUT is refused (intel_fb_bo_framebuffer_init); otherwise it
    /// becomes SCANOUT. An open's framebuffers leave with it.
    #[cfg(feature = "intel")]
    fn smoke_intel_framebuffers_follow_intel_framebuffer_init() -> TestResult {
        use crate::drm::fb_cmd::{FbCmd, FB_MODIFIERS};
        use crate::intel_gpu_gem::GemState;
        let gem = GemState::new();
        let create = |size| {
            let mut handle = 0;
            gem.create(size, |h, _| {
                handle = h;
                Ok(())
            })
            .unwrap();
            handle
        };
        let (handle, other) = (create(1 << 20), create(1 << 20));
        let object = gem.object(handle).unwrap();
        let cmd = |width, height, pitch| {
            let mut cmd = FbCmd {
                width,
                height,
                pixel_format: 0x3432_5258, // XR24
                ..Default::default()
            };
            cmd.handles[0] = handle;
            cmd.pitches[0] = pitch;
            cmd
        };
        let mut card = Card::new("test", "test", (1, 0, 0));
        let mut refused = |cmd: FbCmd, error: CardError| {
            card.addfb2_intel(&cmd, object.clone(), 7, false) == Err(error)
        };
        let mut nv12 = cmd(256, 256, 1024);
        nv12.pixel_format = 0x3231_564e;
        let mut tiled = cmd(256, 256, 1024);
        tiled.flags = FB_MODIFIERS;
        tiled.modifier[0] = 0x0100_0000_0000_0001; // I915_FORMAT_MOD_X_TILED
        let mut offset = cmd(256, 256, 1024);
        offset.offsets[0] = 64;
        let mut stray = cmd(256, 256, 1024);
        stray.flags = FB_MODIFIERS;
        stray.handles[1] = handle;
        let checks = [
            refused(nv12, CardError::UnknownFormat),
            refused(tiled, CardError::UnknownFormat),
            refused(cmd(0, 256, 1024), CardError::InvalidDimensions),
            refused(cmd(256, 256, 512), CardError::InvalidDimensions), // < a line
            refused(cmd(256, 256, 1056), CardError::InvalidDimensions), // 64 B
            refused(offset, CardError::InvalidDimensions),
            refused(stray, CardError::InvalidDimensions),
            refused(cmd(256, 1, 256 * 1024 + 4096), CardError::InvalidDimensions),
            refused(cmd(256, 1, 128 * 1024 + 1024), CardError::InvalidDimensions), // 4 KiB
            refused(cmd(256, 1100, 1024), CardError::InvalidDimensions),           // > object
        ];
        if checks.contains(&false) {
            return TestResult::Fail("an Intel framebuffer Linux refuses was accepted");
        }
        // Pre-modifier userspace may leave unused plane fields uncleared.
        let mut legacy = cmd(256, 256, 1024);
        legacy.handles[1] = handle;
        let ids = [
            card.addfb2_intel(&legacy, object.clone(), 7, false),
            card.addfb2_intel(&cmd(256, 1, 128 * 1024 + 4096), object.clone(), 7, false),
            card.addfb2_intel(&cmd(256, 256, 1024), object.clone(), 8, false),
        ];
        let [Ok(a), Ok(_), Ok(c)] = ids else {
            return TestResult::Fail("a valid Intel framebuffer was refused");
        };
        let fb = card.framebuffer(a).unwrap();
        if fb.gem_owner() != Some(7) || fb.bo.is_some() || fb.modifier != 0 {
            return TestResult::Fail("Intel framebuffer recorded the wrong buffer");
        }
        // drm_fb_release: only the closing open's framebuffers go.
        if card.release_file_framebuffers(7) != 2 || card.framebuffer(c).is_err() {
            return TestResult::Fail("fb release removed the wrong framebuffers");
        }
        if card.rmfb(c) != Ok(None) {
            return TestResult::Fail("RMFB of an Intel framebuffer freed card backing");
        }

        // Xe: a VM-bound object not created SCANOUT cannot become one.
        let bound = gem.object(other).unwrap();
        let mut state = crate::intel_gpu_xe_vm::State {
            mappings: Vec::new(),
            active: Vec::new(),
        };
        state.publish(alloc::vec![crate::intel_gpu_exec::VmMapping {
            object: Some(bound.clone()),
            va: 0x10000,
            offset: 0,
            length: 4096,
            writable: true,
            pat: 3,
        }]);
        let mut bound_cmd = cmd(256, 256, 1024);
        bound_cmd.handles[0] = other;
        if card.addfb2_intel(&bound_cmd, bound.clone(), 7, true)
            != Err(CardError::InvalidDimensions)
            || bound.scanout()
        {
            return TestResult::Fail("Xe accepted a VM-bound non-scanout framebuffer");
        }
        // i915 has no such rule; once unbound, Xe makes it SCANOUT.
        if card
            .addfb2_intel(&bound_cmd, bound.clone(), 7, false)
            .is_err()
        {
            return TestResult::Fail("i915 refused a VM-bound framebuffer");
        }
        drop(state);
        if bound.vm_bound()
            || card
                .addfb2_intel(&bound_cmd, bound.clone(), 7, true)
                .is_err()
            || !bound.scanout()
        {
            return TestResult::Fail("an unbound object did not become a scanout");
        }
        // A SCANOUT object stays admissible while bound.
        let mut state = crate::intel_gpu_xe_vm::State {
            mappings: Vec::new(),
            active: Vec::new(),
        };
        state.publish(alloc::vec![crate::intel_gpu_exec::VmMapping {
            object: Some(bound.clone()),
            va: 0x10000,
            offset: 0,
            length: 4096,
            writable: true,
            pat: 3,
        }]);
        if card
            .addfb2_intel(&bound_cmd, bound.clone(), 7, true)
            .is_err()
        {
            return TestResult::Fail("Xe refused a bound SCANOUT framebuffer");
        }
        drop(state);
        TestResult::Pass
    }
    #[cfg(feature = "intel")]
    kernel_test_in!(
        "drivers/gpu/drm/card",
        smoke_intel_framebuffers_follow_intel_framebuffer_init
    );

    /// The scanout copy reads each line across the object's scattered pages
    /// and never past the object's end.
    #[cfg(feature = "intel")]
    fn smoke_intel_framebuffer_row_copy_spans_pages() -> TestResult {
        let gem = crate::intel_gpu_gem::GemState::new();
        let mut handle = 0;
        gem.create(3 * 4096, |h, _| {
            handle = h;
            Ok(())
        })
        .unwrap();
        let object = gem.object(handle).unwrap();
        let pattern: Vec<u8> = (0..3 * 4096u32).map(|i| (i * 7 + i / 4096) as u8).collect();
        if object.write(0, &pattern).is_err() {
            return TestResult::Fail("fixture write failed");
        }
        let pages: Vec<u64> = object.pages().collect();
        let pitch = 4160; // 64-byte aligned, crossing every page boundary
        let mut line = alloc::vec![0u8; pitch as usize];
        for (row, want) in [(0u32, 4160usize), (1, 4160), (2, 3 * 4096 - 2 * 4160)] {
            line.fill(0xee);
            // SAFETY: the object's frames are retained by `object`; `line`
            // holds `pitch` bytes.
            let copied = unsafe {
                crate::drm_ioctl_bridge::copy_object_row(
                    &pages,
                    object.size(),
                    pitch,
                    row,
                    line.as_mut_ptr(),
                    pitch as usize,
                )
            };
            let start = (row * pitch) as usize;
            if copied != want || line[..want] != pattern[start..start + want] {
                return TestResult::Fail("row copy lost bytes across a page boundary");
            }
            if line[want..].iter().any(|b| *b != 0xee) {
                return TestResult::Fail("row copy read past the object's end");
            }
        }
        TestResult::Pass
    }
    #[cfg(feature = "intel")]
    kernel_test_in!(
        "drivers/gpu/drm/card",
        smoke_intel_framebuffer_row_copy_spans_pages
    );
}
