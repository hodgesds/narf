//! DRM UAPI — ioctl number encoding + struct sizes ported from
//! `linux/include/uapi/drm/drm.h` + `drm_mode.h`.
//!
//! The constants here are the *full* ioctl-number words (32-bit, with
//! direction + size + type + nr already encoded). They're consumed by
//! the per-fd `FileOps::ioctl` impl on `/dev/dri/card<N>` and
//! `/dev/dri/renderD<N+128>`, which strips the lower 8 bits to dispatch
//! against the [`crate::drm::ioctl::IoctlCmd`] table.
//!
//! The `_IOC*` helpers follow Linux's `include/uapi/asm-generic/ioctl.h`
//! encoding exactly (asm-generic is what user-space Mesa is compiled
//! against on x86_64 / aarch64).
//!
//! ## Encoding
//!
//! ```text
//! bits 31..30  direction (00 = none, 01 = write, 10 = read, 11 = read+write)
//! bits 29..16  size of the ioctl arg struct
//! bits 15..8   type byte — 'd' (0x64) for all DRM ioctls
//! bits 7..0    nr — sub-command number
//! ```
//!
//! ## Linux references
//!
//! - `include/uapi/asm-generic/ioctl.h` — `_IOC`, `_IO`, `_IOR`,
//!   `_IOW`, `_IOWR` macros; `_IOC_DIR`, `_IOC_SIZE`, `_IOC_TYPE`,
//!   `_IOC_NR` decoders.
//! - `include/uapi/drm/drm.h` — `DRM_IOCTL_*` defines + struct
//!   shapes.
//! - `include/uapi/drm/drm_mode.h` — KMS-side defines + struct
//!   shapes for the DRM_IOCTL_MODE_* family.

// ── _IOC direction bits ────────────────────────────────────────────────

/// `_IOC_NONE` — neither read nor write user pointer.
pub const IOC_NONE: u32 = 0;
/// `_IOC_WRITE` — kernel reads from user.
pub const IOC_WRITE: u32 = 1;
/// `_IOC_READ` — kernel writes to user.
pub const IOC_READ: u32 = 2;

// Linux: `include/uapi/asm-generic/ioctl.h`.
pub const IOC_NRBITS: u32 = 8;
pub const IOC_TYPEBITS: u32 = 8;
pub const IOC_SIZEBITS: u32 = 14;
pub const IOC_DIRBITS: u32 = 2;

pub const IOC_NRMASK: u32 = (1 << IOC_NRBITS) - 1;
pub const IOC_TYPEMASK: u32 = (1 << IOC_TYPEBITS) - 1;
pub const IOC_SIZEMASK: u32 = (1 << IOC_SIZEBITS) - 1;
pub const IOC_DIRMASK: u32 = (1 << IOC_DIRBITS) - 1;

pub const IOC_NRSHIFT: u32 = 0;
pub const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
pub const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
pub const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

// ── _IOC encoders ─────────────────────────────────────────────────────

/// Build an ioctl number from `(dir, type, nr, size)`. Mirrors Linux
/// `_IOC` in `include/uapi/asm-generic/ioctl.h`.
#[inline]
pub const fn ioc(dir: u32, type_: u32, nr: u32, size: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (type_ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
}

/// `_IO(type, nr)` — no-arg ioctl.
#[inline]
pub const fn io(type_: u32, nr: u32) -> u32 {
    ioc(IOC_NONE, type_, nr, 0)
}

/// `_IOR(type, nr, sz)` — kernel writes to user.
#[inline]
pub const fn ior(type_: u32, nr: u32, size: u32) -> u32 {
    ioc(IOC_READ, type_, nr, size)
}

/// `_IOW(type, nr, sz)` — kernel reads from user.
#[inline]
pub const fn iow(type_: u32, nr: u32, size: u32) -> u32 {
    ioc(IOC_WRITE, type_, nr, size)
}

/// `_IOWR(type, nr, sz)` — kernel both reads and writes the user
/// pointer (most DRM ioctls are this shape).
#[inline]
pub const fn iowr(type_: u32, nr: u32, size: u32) -> u32 {
    ioc(IOC_READ | IOC_WRITE, type_, nr, size)
}

// ── _IOC decoders ─────────────────────────────────────────────────────

/// Extract the direction bits (0..=3).
#[inline]
pub const fn ioc_dir(cmd: u32) -> u32 {
    (cmd >> IOC_DIRSHIFT) & IOC_DIRMASK
}

/// Extract the type byte.
#[inline]
pub const fn ioc_type(cmd: u32) -> u32 {
    (cmd >> IOC_TYPESHIFT) & IOC_TYPEMASK
}

/// Extract the sub-command number (the byte the per-driver dispatcher
/// keys on).
#[inline]
pub const fn ioc_nr(cmd: u32) -> u32 {
    (cmd >> IOC_NRSHIFT) & IOC_NRMASK
}

/// Extract the arg-struct size (bits 16..30).
#[inline]
pub const fn ioc_size(cmd: u32) -> u32 {
    (cmd >> IOC_SIZESHIFT) & IOC_SIZEMASK
}

// ── DRM ioctl type byte ────────────────────────────────────────────────

/// Linux DRM ioctl type byte — `DRM_IOCTL_BASE` in `drm.h`.
pub const DRM_IOCTL_BASE: u32 = b'd' as u32;

// ── Struct sizes (from `linux/include/uapi/drm/drm.h`) ────────────────
//
// These are the byte counts encoded into the upper bits of each
// DRM_IOCTL_* number. They match the Linux uapi struct layout
// (#[repr(C)]) on x86_64.

pub const SZ_DRM_VERSION: u32 = 64; // drm_version
pub const SZ_DRM_GET_CAP: u32 = 16; // drm_get_cap
pub const SZ_DRM_PRIME_HANDLE: u32 = 16; // drm_prime_handle
pub const SZ_DRM_MODE_CARD_RES: u32 = 64; // drm_mode_card_res
pub const SZ_DRM_MODE_CRTC: u32 = 104; // drm_mode_crtc
pub const SZ_DRM_MODE_GET_PLANE: u32 = 48; // drm_mode_get_plane
pub const SZ_DRM_MODE_GET_PLANE_RES: u32 = 16; // drm_mode_get_plane_res
pub const SZ_DRM_MODE_GET_ENCODER: u32 = 20; // drm_mode_get_encoder
pub const SZ_DRM_MODE_GET_CONNECTOR: u32 = 80; // drm_mode_get_connector
pub const SZ_DRM_MODE_GET_PROPERTY: u32 = 64; // drm_mode_get_property
pub const SZ_DRM_MODE_FB_CMD2: u32 = 80; // drm_mode_fb_cmd2
pub const SZ_DRM_MODE_RMFB: u32 = 4; // drm_mode_rmfb
pub const SZ_DRM_MODE_ATOMIC: u32 = 56; // drm_mode_atomic
pub const SZ_DRM_MODE_CREATE_BLOB: u32 = 32; // drm_mode_create_blob
pub const SZ_DRM_MODE_DESTROY_BLOB: u32 = 4; // drm_mode_destroy_blob
pub const SZ_DRM_GEM_CLOSE: u32 = 16; // drm_gem_close
pub const SZ_DRM_SYNCOBJ_CREATE: u32 = 8; // drm_syncobj_create
pub const SZ_DRM_SYNCOBJ_DESTROY: u32 = 8; // drm_syncobj_destroy
pub const SZ_DRM_SYNCOBJ_WAIT: u32 = 32; // drm_syncobj_wait
pub const SZ_DRM_SYNCOBJ_HANDLE: u32 = 24; // drm_syncobj_handle

// ── Dumb-buffer / modesetting struct sizes ─────────────────────────────

pub const SZ_DRM_MODE_CREATE_DUMB: u32 = 32; // drm_mode_create_dumb
pub const SZ_DRM_MODE_MAP_DUMB: u32 = 16; // drm_mode_map_dumb
pub const SZ_DRM_MODE_DESTROY_DUMB: u32 = 4; // drm_mode_destroy_dumb
pub const SZ_DRM_MODE_CRTC_PAGE_FLIP: u32 = 24; // drm_mode_crtc_page_flip

// ── DRM_IOCTL_* numbers ────────────────────────────────────────────────
//
// Each constant matches `include/uapi/drm/drm.h` 1:1 — the numeric
// values are stable wire-ABI so userspace (Mesa, libdrm, Wayland
// compositors) hardcodes them.
//
// Where Linux uses `_IOWR(DRM_IOCTL_BASE, nr, struct)` we use
// `iowr(DRM_IOCTL_BASE, nr, SZ_*)`. Equivalent encoding.

/// DRM_IOCTL_VERSION = _IOWR('d', 0x00, struct drm_version).
pub const DRM_IOCTL_VERSION: u32 = iowr(DRM_IOCTL_BASE, 0x00, SZ_DRM_VERSION);

/// DRM_IOCTL_GET_CAP = _IOWR('d', 0x0c, struct drm_get_cap).
pub const DRM_IOCTL_GET_CAP: u32 = iowr(DRM_IOCTL_BASE, 0x0C, SZ_DRM_GET_CAP);

/// DRM_IOCTL_GEM_CLOSE = _IOW('d', 0x09, struct drm_gem_close).
pub const DRM_IOCTL_GEM_CLOSE: u32 = iow(DRM_IOCTL_BASE, 0x09, SZ_DRM_GEM_CLOSE);

/// DRM_IOCTL_PRIME_HANDLE_TO_FD = _IOWR('d', 0x2d, struct drm_prime_handle).
pub const DRM_IOCTL_PRIME_HANDLE_TO_FD: u32 = iowr(DRM_IOCTL_BASE, 0x2D, SZ_DRM_PRIME_HANDLE);

/// DRM_IOCTL_PRIME_FD_TO_HANDLE = _IOWR('d', 0x2e, struct drm_prime_handle).
pub const DRM_IOCTL_PRIME_FD_TO_HANDLE: u32 = iowr(DRM_IOCTL_BASE, 0x2E, SZ_DRM_PRIME_HANDLE);

/// DRM_IOCTL_MODE_GETRESOURCES = _IOWR('d', 0xa0, struct drm_mode_card_res).
pub const DRM_IOCTL_MODE_GETRESOURCES: u32 = iowr(DRM_IOCTL_BASE, 0xA0, SZ_DRM_MODE_CARD_RES);

/// DRM_IOCTL_MODE_GETCONNECTOR = _IOWR('d', 0xb0, struct drm_mode_crtc_page_flip).
pub const DRM_IOCTL_MODE_PAGE_FLIP: u32 = iowr(DRM_IOCTL_BASE, 0xB0, SZ_DRM_MODE_CRTC_PAGE_FLIP);

/// DRM_IOCTL_MODE_CREATE_DUMB = _IOWR('d', 0xb2, struct drm_mode_create_dumb).
pub const DRM_IOCTL_MODE_CREATE_DUMB: u32 = iowr(DRM_IOCTL_BASE, 0xB2, SZ_DRM_MODE_CREATE_DUMB);

/// DRM_IOCTL_MODE_MAP_DUMB = _IOWR('d', 0xb3, struct drm_mode_map_dumb).
pub const DRM_IOCTL_MODE_MAP_DUMB: u32 = iowr(DRM_IOCTL_BASE, 0xB3, SZ_DRM_MODE_MAP_DUMB);

/// DRM_IOCTL_MODE_DESTROY_DUMB = _IOWR('d', 0xb4, struct drm_mode_destroy_dumb).
pub const DRM_IOCTL_MODE_DESTROY_DUMB: u32 = iowr(DRM_IOCTL_BASE, 0xB4, SZ_DRM_MODE_DESTROY_DUMB);

/// DRM_IOCTL_MODE_GETCRTC = _IOWR('d', 0xa1, struct drm_mode_crtc).
pub const DRM_IOCTL_MODE_GETCRTC: u32 = iowr(DRM_IOCTL_BASE, 0xA1, SZ_DRM_MODE_CRTC);

/// DRM_IOCTL_MODE_SETCRTC = _IOWR('d', 0xa2, struct drm_mode_crtc).
pub const DRM_IOCTL_MODE_SETCRTC: u32 = iowr(DRM_IOCTL_BASE, 0xA2, SZ_DRM_MODE_CRTC);

/// DRM_IOCTL_SET_CLIENT_CAP = _IOW('d', 0x0d, struct drm_set_client_cap)
/// — `{ __u64 capability; __u64 value; }` (16 bytes).
pub const DRM_IOCTL_SET_CLIENT_CAP: u32 = iow(DRM_IOCTL_BASE, 0x0D, 16);

/// DRM_IOCTL_MODE_GETENCODER = _IOWR('d', 0xa6, struct drm_mode_get_encoder).
pub const DRM_IOCTL_MODE_GETENCODER: u32 = iowr(DRM_IOCTL_BASE, 0xA6, SZ_DRM_MODE_GET_ENCODER);

/// DRM_IOCTL_MODE_GETCONNECTOR = _IOWR('d', 0xa7, struct drm_mode_get_connector).
pub const DRM_IOCTL_MODE_GETCONNECTOR: u32 = iowr(DRM_IOCTL_BASE, 0xA7, SZ_DRM_MODE_GET_CONNECTOR);

/// DRM_IOCTL_MODE_RMFB = _IOWR('d', 0xaf, struct drm_mode_rmfb).
pub const DRM_IOCTL_MODE_RMFB: u32 = iowr(DRM_IOCTL_BASE, 0xAF, SZ_DRM_MODE_RMFB);

/// DRM_IOCTL_MODE_GETPROPERTY = _IOWR('d', 0xaa, struct drm_mode_get_property).
pub const DRM_IOCTL_MODE_GETPROPERTY: u32 = iowr(DRM_IOCTL_BASE, 0xAA, SZ_DRM_MODE_GET_PROPERTY);

/// DRM_IOCTL_MODE_GETPLANERESOURCES = _IOWR('d', 0xb5, struct drm_mode_get_plane_res).
pub const DRM_IOCTL_MODE_GETPLANERESOURCES: u32 =
    iowr(DRM_IOCTL_BASE, 0xB5, SZ_DRM_MODE_GET_PLANE_RES);

/// DRM_IOCTL_MODE_GETPLANE = _IOWR('d', 0xb6, struct drm_mode_get_plane).
pub const DRM_IOCTL_MODE_GETPLANE: u32 = iowr(DRM_IOCTL_BASE, 0xB6, SZ_DRM_MODE_GET_PLANE);

/// DRM_IOCTL_MODE_ADDFB2 = _IOWR('d', 0xb8, struct drm_mode_fb_cmd2).
pub const DRM_IOCTL_MODE_ADDFB2: u32 = iowr(DRM_IOCTL_BASE, 0xB8, SZ_DRM_MODE_FB_CMD2);

/// DRM_IOCTL_MODE_ATOMIC = _IOWR('d', 0xbc, struct drm_mode_atomic).
pub const DRM_IOCTL_MODE_ATOMIC: u32 = iowr(DRM_IOCTL_BASE, 0xBC, SZ_DRM_MODE_ATOMIC);

/// DRM_IOCTL_MODE_CREATEPROPBLOB = _IOWR('d', 0xbd, struct drm_mode_create_blob).
pub const DRM_IOCTL_MODE_CREATEPROPBLOB: u32 = iowr(DRM_IOCTL_BASE, 0xBD, SZ_DRM_MODE_CREATE_BLOB);

/// DRM_IOCTL_MODE_DESTROYPROPBLOB = _IOWR('d', 0xbe, struct drm_mode_destroy_blob).
pub const DRM_IOCTL_MODE_DESTROYPROPBLOB: u32 =
    iowr(DRM_IOCTL_BASE, 0xBE, SZ_DRM_MODE_DESTROY_BLOB);

/// DRM_IOCTL_SYNCOBJ_CREATE = _IOWR('d', 0xbf, struct drm_syncobj_create).
pub const DRM_IOCTL_SYNCOBJ_CREATE: u32 = iowr(DRM_IOCTL_BASE, 0xBF, SZ_DRM_SYNCOBJ_CREATE);

/// DRM_IOCTL_SYNCOBJ_DESTROY = _IOWR('d', 0xc0, struct drm_syncobj_destroy).
pub const DRM_IOCTL_SYNCOBJ_DESTROY: u32 = iowr(DRM_IOCTL_BASE, 0xC0, SZ_DRM_SYNCOBJ_DESTROY);

/// DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD = _IOWR('d', 0xc1, struct drm_syncobj_handle).
pub const DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD: u32 = iowr(DRM_IOCTL_BASE, 0xC1, SZ_DRM_SYNCOBJ_HANDLE);

/// DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE = _IOWR('d', 0xc2, struct drm_syncobj_handle).
pub const DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE: u32 = iowr(DRM_IOCTL_BASE, 0xC2, SZ_DRM_SYNCOBJ_HANDLE);

/// DRM_IOCTL_SYNCOBJ_WAIT = _IOWR('d', 0xc3, struct drm_syncobj_wait).
pub const DRM_IOCTL_SYNCOBJ_WAIT: u32 = iowr(DRM_IOCTL_BASE, 0xC3, SZ_DRM_SYNCOBJ_WAIT);

// ── DRM_IOCTL_* wire-format struct mirrors ─────────────────────────────
//
// All `#[repr(C)]` and tightly packed to match Linux's uapi structs.
// Sizes are asserted by const _ = ... below so any future drift fires
// a compile error.

/// `struct drm_version` from `include/uapi/drm/drm.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmVersionUapi {
    pub version_major: i32,
    pub version_minor: i32,
    pub version_patchlevel: i32,
    /// In: capacity of `name`. Out: actual length (excluding NUL).
    pub name_len: u64, // __kernel_size_t — 8 bytes on LP64.
    /// User-pointer to writable buffer for the driver name.
    pub name: u64,
    pub date_len: u64,
    pub date: u64,
    pub desc_len: u64,
    pub desc: u64,
}

const _: () = assert!(core::mem::size_of::<DrmVersionUapi>() == SZ_DRM_VERSION as usize);

/// `struct drm_mode_card_res` from `include/uapi/drm/drm_mode.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeCardResUapi {
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

const _: () = assert!(core::mem::size_of::<DrmModeCardResUapi>() == SZ_DRM_MODE_CARD_RES as usize);

/// `struct drm_mode_atomic` from `include/uapi/drm/drm_mode.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeAtomicUapi {
    pub flags: u32,
    pub count_objs: u32,
    pub objs_ptr: u64,
    pub count_props_ptr: u64,
    pub props_ptr: u64,
    pub prop_values_ptr: u64,
    pub reserved: u64,
    pub user_data: u64,
}

const _: () = assert!(core::mem::size_of::<DrmModeAtomicUapi>() == SZ_DRM_MODE_ATOMIC as usize);

/// `struct drm_gem_close` from `include/uapi/drm/drm.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmGemCloseUapi {
    pub handle: u32,
    pub pad: u32,
}

/// `struct drm_syncobj_create` from `include/uapi/drm/drm.h`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmSyncobjCreateUapi {
    pub handle: u32,
    pub flags: u32,
}

// ── Dumb-buffer + modesetting UAPI structs ─────────────────────────────
//
// From `include/uapi/drm/drm_mode.h` + `drm.h` (Linux).

/// `struct drm_mode_modeinfo` — one display mode entry.
/// Linux: `include/uapi/drm/drm_mode.h`.
/// Size: 68 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeModeInfoUapi {
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

const _: () = assert!(core::mem::size_of::<DrmModeModeInfoUapi>() == 68);

/// `struct drm_mode_crtc` — DRM_IOCTL_MODE_SETCRTC / GETCRTC.
/// Linux: `include/uapi/drm/drm_mode.h`.
/// Size: 104 bytes (8 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 68 = 104).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeCrtcUapi {
    pub set_connectors_ptr: u64,
    pub count_connectors: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub x: u32,
    pub y: u32,
    pub gamma_size: u32,
    pub mode_valid: u32,
    pub mode: DrmModeModeInfoUapi,
}

const _: () = assert!(core::mem::size_of::<DrmModeCrtcUapi>() == SZ_DRM_MODE_CRTC as usize);

/// `struct drm_mode_create_dumb` — DRM_IOCTL_MODE_CREATE_DUMB.
/// Linux: `include/uapi/drm/drm_mode.h`.
/// Size: 32 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeCreateDumbUapi {
    pub height: u32,
    pub width: u32,
    pub bpp: u32,
    pub flags: u32,
    pub handle: u32,
    pub pitch: u32,
    pub size: u64,
}

const _: () =
    assert!(core::mem::size_of::<DrmModeCreateDumbUapi>() == SZ_DRM_MODE_CREATE_DUMB as usize);

/// `struct drm_mode_map_dumb` — DRM_IOCTL_MODE_MAP_DUMB.
/// Linux: `include/uapi/drm/drm_mode.h`.
/// Size: 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeMapDumbUapi {
    pub handle: u32,
    pub pad: u32,
    pub offset: u64,
}

const _: () = assert!(core::mem::size_of::<DrmModeMapDumbUapi>() == SZ_DRM_MODE_MAP_DUMB as usize);

/// `struct drm_mode_destroy_dumb` — DRM_IOCTL_MODE_DESTROY_DUMB.
/// Linux: `include/uapi/drm/drm_mode.h`.
/// Size: 4 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModeDestroyDumbUapi {
    pub handle: u32,
}

const _: () =
    assert!(core::mem::size_of::<DrmModeDestroyDumbUapi>() == SZ_DRM_MODE_DESTROY_DUMB as usize);

/// `struct drm_mode_crtc_page_flip` — DRM_IOCTL_MODE_PAGE_FLIP.
/// Linux: `include/uapi/drm/drm_mode.h`.
/// Size: 24 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct DrmModePageFlipUapi {
    pub crtc_id: u32,
    pub fb_id: u32,
    pub flags: u32,
    pub reserved: u32,
    pub user_data: u64,
}

const _: () =
    assert!(core::mem::size_of::<DrmModePageFlipUapi>() == SZ_DRM_MODE_CRTC_PAGE_FLIP as usize);
