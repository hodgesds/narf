//! `/dev/input/` subdirectory and per-device event-file nodes.
//!
//! Bridges the `narf-input` evdev event-routing layer (Wave 12) to
//! userspace.  Each registered `DeviceId` in the global `ROUTER` is
//! exposed as `/dev/input/eventN` where N = `DeviceId.0 - 1` (ids
//! start at 1 and are issued monotonically).
//!
//! Linux reference: `drivers/input/evdev.c`
//!   — `evdev_read` (line ~441): block until events available, then
//!     drain the per-client ring into the user buffer in fixed-size
//!     `input_event` chunks.
//!
//! # ABI
//!
//! On the wire each read/write returns a multiple of the **24-byte**
//! Linux `struct input_event` (64-bit kernel layout) so unmodified
//! evdev programs (evtest, libinput) work unchanged.  The internal
//! `EvdevEvent` stays 16 bytes; `read` packs each into a 24-byte Linux
//! record and `write` unpacks the 24-byte records back.
//!
//! ```c
//! struct input_event {
//!     struct timeval time;  // { long tv_sec; long tv_usec; } = 16 bytes
//!     __u16 type; __u16 code; __s32 value;   // 8 bytes
//! };                                          // 24 bytes total
//! ```
//!
//! If the ring is empty and `buf` is non-zero, the read awaits one
//! `WaitEventFuture` and then drains whatever arrived — matching Linux
//! blocking-fd semantics (O_RDONLY with no O_NONBLOCK).  A non-blocking
//! caller sets buf to length 0, which returns 0 immediately.
//!
//! # Layout
//!
//! ```text
//! /dev/input/
//!   event0   ← DeviceId(1), bound to ROUTER
//!   event1   ← DeviceId(2)
//!   ...
//! ```
//!
//! `/dev/input/mice` (multiplexed mouse) is deferred to a later wave.
//! The `EVIOCG*` capability ioctls evdev readers issue at startup are
//! implemented here (`ioctl`).

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;

use narf_input::evdev::{DeviceId, EvdevEvent, EventType, ROUTER};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN};

/// Owner and permission bits of one evdev node.
#[derive(Clone, Copy)]
struct EvdevNodeMeta {
    uid: u32,
    gid: u32,
    perms: u16,
}

impl EvdevNodeMeta {
    /// Linux `drivers/input/evdev.c` creates event nodes root-owned at 0660;
    /// udev assigns the `input` group afterwards.
    const DEFAULT: Self = Self {
        uid: 0,
        gid: 0,
        perms: 0o660,
    };
}

/// Per-event-node ownership and permissions, keyed by event number. A node
/// absent from the table carries [`EvdevNodeMeta::DEFAULT`].
///
/// This CANNOT live on `InputEventFile`: every `open("/dev/input/eventN")`
/// builds a fresh one (see the type's docs), so a chown recorded on the
/// instance would vanish when udev's fd closed and be invisible to the next
/// opener. Linux keeps it on the inode; this table is that inode state.
///
/// Why it matters: udev applies `GROUP="input", MODE="0660"` to every evdev
/// node (50-udev-default.rules). Without a writable owner, `set_owners`
/// returned the trait default `Unsupported`, which udev reported as
///
/// ```text
/// event1: Failed to set owner/mode of /dev/input/event1 to uid=0,
///         gid=104, mode=0660: Operation not supported
/// ```
///
/// and the node stayed root:root. The mode was already 0660, so the failure
/// looked cosmetic — but 0660 root:root is unopenable by the compositor
/// running as uid 1000, which is the same shape as the DRM-node EACCES that
/// supplementary-group DAC support was added for.
///
/// Entries are never removed. That is safe only because `narf-input` issues
/// device ids monotonically and never recycles them, so a replugged device
/// gets a fresh node rather than inheriting the previous occupant's uid/gid —
/// an invariant pinned by `smoke_evdev_device_ids_are_never_recycled`.
static EVDEV_NODE_META: IrqSafeSpinLock<Vec<(u32, EvdevNodeMeta)>> =
    IrqSafeSpinLock::new(Vec::new());

fn evdev_meta(event_num: u32) -> EvdevNodeMeta {
    EVDEV_NODE_META
        .lock()
        .iter()
        .find(|(n, _)| *n == event_num)
        .map(|(_, meta)| *meta)
        .unwrap_or(EvdevNodeMeta::DEFAULT)
}

fn evdev_meta_update(event_num: u32, f: impl FnOnce(&mut EvdevNodeMeta)) {
    let mut table = EVDEV_NODE_META.lock();
    if let Some(entry) = table.iter_mut().find(|(n, _)| *n == event_num) {
        f(&mut entry.1);
        return;
    }
    let mut meta = EvdevNodeMeta::DEFAULT;
    f(&mut meta);
    table.push((event_num, meta));
}

// ── Event-record sizes ────────────────────────────────────────────────────────

/// In-memory size of one internal `EvdevEvent` (16 bytes).
/// `size_of::<EvdevEvent>()` = 8 (time) + 2 (type) + 2 (code) + 4 (value).
const EVDEV_EVENT_SIZE: usize = mem::size_of::<EvdevEvent>();

// The internal event must stay 16 bytes; the wire format is the 24-byte
// Linux record built by `pack_linux_event`.  This const assertion fails
// the build if the internal layout ever drifts.
const _: () = assert!(EVDEV_EVENT_SIZE == 16);

/// Wire size of one Linux `struct input_event` on a 64-bit kernel (24 bytes):
/// `timeval` (2 × 8-byte long = 16) + type (2) + code (2) + value (4).
/// Ref: `include/uapi/linux/input.h` `struct input_event`.
pub(crate) const LINUX_INPUT_EVENT_SIZE: usize = 24;

// ── Linux input_event packing ─────────────────────────────────────────────────

/// Pack one internal `EvdevEvent` into a 24-byte Linux `input_event`.
///
/// The internal `time` is monotonic **nanoseconds** (`narf_time::monotonic_ns`);
/// we split it into the `timeval` seconds/microseconds fields:
/// `tv_sec = ns / 1e9`, `tv_usec = (ns % 1e9) / 1000`.
///
/// Getting the UNIT right matters: libinput derives pointer velocity from the
/// time delta between consecutive events. If `time` were raw TSC cycles
/// (~3.3e9/s) packed as if it were microseconds, every dt would be ~3300×
/// too large, velocity ~3300× too small, and the pointer-accel curve would
/// map it to ~0 px — input is read but the cursor never moves.
fn pack_linux_event(ev: &EvdevEvent) -> [u8; LINUX_INPUT_EVENT_SIZE] {
    let mut out = [0u8; LINUX_INPUT_EVENT_SIZE];
    let tv_sec = (ev.time / 1_000_000_000) as i64;
    let tv_usec = ((ev.time % 1_000_000_000) / 1_000) as i64;
    out[0..8].copy_from_slice(&tv_sec.to_le_bytes());
    out[8..16].copy_from_slice(&tv_usec.to_le_bytes());
    out[16..18].copy_from_slice(&(ev.type_ as u16).to_le_bytes());
    out[18..20].copy_from_slice(&ev.code.to_le_bytes());
    out[20..24].copy_from_slice(&ev.value.to_le_bytes());
    out
}

/// Unpack a 24-byte Linux `input_event` into an internal `EvdevEvent`.
///
/// Returns `None` if the `type` field is not a recognised `EV_*` code.
/// The `timeval` is collapsed back to a monotonic-ns u64
/// (`tv_sec * 1e9 + tv_usec * 1000`); uinput callers normally zero it and
/// let the kernel timestamp, but we preserve whatever they sent.
fn unpack_linux_event(buf: &[u8]) -> Option<EvdevEvent> {
    if buf.len() < LINUX_INPUT_EVENT_SIZE {
        return None;
    }
    let tv_sec = i64::from_le_bytes(buf[0..8].try_into().ok()?);
    let tv_usec = i64::from_le_bytes(buf[8..16].try_into().ok()?);
    let raw_type = u16::from_le_bytes(buf[16..18].try_into().ok()?);
    let code = u16::from_le_bytes(buf[18..20].try_into().ok()?);
    let value = i32::from_le_bytes(buf[20..24].try_into().ok()?);
    let type_ = EventType::from_raw(raw_type)?;
    let time = (tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add((tv_usec as u64).wrapping_mul(1_000));
    Some(EvdevEvent {
        time,
        type_,
        code,
        value,
    })
}

// ── User-pointer copy (ioctl out) ─────────────────────────────────────────────
//
// Mirrors the pattern in `devfs_pty.rs`: the SMAP/STAC bracket is opened
// per access so a CPL=0 store into a user-only PTE doesn't fault once
// CR4.SMAP=1.  See `[[project_user_cstr_page_safety]]`.

/// Copy `src` into the user buffer at `uptr`.  Returns the number of
/// bytes written.  `src.len()` is the caller's responsibility to bound
/// (the ioctl handlers truncate to the request's `size` field).
///
/// # Safety
/// `uptr` must be a valid user-space pointer with at least `src.len()`
/// bytes writable, or null (rejected).
#[cfg(target_arch = "x86_64")]
unsafe fn copy_to_user_bytes(uptr: usize, src: &[u8]) -> Result<usize, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees `uptr` is a valid writable user pointer of
    // at least `src.len()` bytes; `with_user_access` opens the SMAP window
    // and the byte copy stays within that range.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(src.as_ptr(), uptr as *mut u8, src.len());
        });
    }
    Ok(src.len())
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn copy_to_user_bytes(uptr: usize, src: &[u8]) -> Result<usize, FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees `uptr` is a valid writable user pointer of
    // at least `src.len()` bytes (no SMAP outside x86_64).
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), uptr as *mut u8, src.len());
    }
    Ok(src.len())
}

/// Copy `dst.len()` bytes from the user buffer at `uptr` — the mirror
/// of [`copy_to_user_bytes`], used by the uinput setup ioctls.
///
/// # Safety
/// `uptr` must be a valid user-space pointer with at least `dst.len()`
/// readable bytes, or null (rejected).
#[cfg(target_arch = "x86_64")]
unsafe fn copy_from_user_bytes(uptr: usize, dst: &mut [u8]) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees `uptr` is a valid readable user pointer
    // of at least `dst.len()` bytes; `with_user_access` opens the SMAP
    // window and the byte copy stays within that range.
    unsafe {
        narf_arch::x86_64::smap::with_user_access(|| {
            core::ptr::copy_nonoverlapping(uptr as *const u8, dst.as_mut_ptr(), dst.len());
        });
    }
    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn copy_from_user_bytes(uptr: usize, dst: &mut [u8]) -> Result<(), FsError> {
    if uptr == 0 {
        return Err(FsError::InvalidData);
    }
    // SAFETY: caller guarantees `uptr` is a valid readable user pointer
    // of at least `dst.len()` bytes (no SMAP outside x86_64).
    unsafe {
        core::ptr::copy_nonoverlapping(uptr as *const u8, dst.as_mut_ptr(), dst.len());
    }
    Ok(())
}

/// Read a NUL-terminated user string of at most `max` bytes (the
/// `UI_SET_PHYS` argument shape). Stops at the first NUL; a string
/// with no NUL in `max` bytes is truncated, matching how the kernel
/// bounds `strncpy_from_user` for this ioctl.
fn read_user_c_string(uptr: usize, max: usize) -> Result<String, FsError> {
    let mut out = Vec::new();
    for i in 0..max {
        let mut byte = [0u8; 1];
        // SAFETY: `uptr + i` walks the caller's string one byte at a
        // time and stops at its NUL; the caller (the ioctl layer) has
        // validated `uptr` as a user pointer for this request.
        unsafe { copy_from_user_bytes(uptr + i, &mut byte)? };
        if byte[0] == 0 {
            break;
        }
        out.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// Apply a `struct uinput_setup` image (92 bytes: `input_id` +
/// `name[80]` + `ff_effects_max`) to `caps`. Pure over the byte image
/// so kernel tests can pin the wire layout without a user pointer.
fn apply_uinput_setup(caps: &mut DeviceCaps, setup: &[u8]) -> Result<(), FsError> {
    if setup.len() < 92 {
        return Err(FsError::InvalidData);
    }
    let le16 = |off: usize| u16::from_le_bytes([setup[off], setup[off + 1]]);
    let name_bytes = &setup[8..88];
    let stop = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let name = String::from_utf8_lossy(&name_bytes[..stop]).into_owned();
    // Direct field assignment (not `set_identity`): a uinput setup
    // carries no phys/uniq, so those keep whatever UI_SET_PHYS set.
    caps.name = name;
    caps.id = narf_input::evdev::InputId::new(le16(0), le16(2), le16(4), le16(6));
    Ok(())
}

// ── EVIOC* ioctl decoding ─────────────────────────────────────────────────────

/// Linux `_IOC` field accessors.  An ioctl `cmd` packs
/// `dir(2) | size(14) | type(8) | nr(8)`.
/// Ref: `include/uapi/asm-generic/ioctl.h`.
mod ioc {
    // Completes the `_IOC` field set for reference/symmetry with the
    // size/typ/nr accessors below; not all callers decode the direction.
    #[allow(dead_code)]
    pub const fn dir(cmd: u32) -> u32 {
        (cmd >> 30) & 0x3
    }
    pub const fn size(cmd: u32) -> u32 {
        (cmd >> 16) & 0x3FFF
    }
    pub const fn typ(cmd: u32) -> u32 {
        (cmd >> 8) & 0xFF
    }
    pub const fn nr(cmd: u32) -> u32 {
        cmd & 0xFF
    }
}

/// evdev ioctl type byte (`'E'`).  Ref: `include/uapi/linux/input.h`.
const EVIOC_TYPE: u32 = b'E' as u32;

/// `EV_VERSION` reported by `EVIOCGVERSION`.
/// Ref: `include/uapi/linux/input.h:53`.
const EV_VERSION: i32 = 0x01_0001;

/// Fixed `nr` values for the non-parametric evdev ioctls.
const EVIOC_NR_GVERSION: u32 = 0x01; // EVIOCGVERSION
const EVIOC_NR_GID: u32 = 0x02; // EVIOCGID
const EVIOC_NR_GPHYS: u32 = 0x07; // EVIOCGPHYS(len) — physical location string
const EVIOC_NR_GUNIQ: u32 = 0x08; // EVIOCGUNIQ(len) — unique id string
const EVIOC_NR_GPROP: u32 = 0x09; // EVIOCGPROP(len) — INPUT_PROP_* bitmap
const EVIOC_NR_GMTSLOTS: u32 = 0x0a; // EVIOCGMTSLOTS(len) — MT slot state
const EVIOC_NR_GNAME: u32 = 0x06; // EVIOCGNAME(len)
const EVIOC_NR_GKEY: u32 = 0x18; // EVIOCGKEY(len) — current key state
const EVIOC_NR_GLED: u32 = 0x19; // EVIOCGLED(len) — current LED state
const EVIOC_NR_GSND: u32 = 0x1a; // EVIOCGSND(len) — current sound state
const EVIOC_NR_GSW: u32 = 0x1b; // EVIOCGSW(len) — current switch state
const EVIOC_NR_GBIT_BASE: u32 = 0x20; // EVIOCGBIT(ev, len) → 0x20 + ev
const EVIOC_NR_GABS_BASE: u32 = 0x40; // EVIOCGABS(abs) → 0x40 + abs
const EVIOC_NR_GRAB: u32 = 0x90; // EVIOCGRAB
const EVIOC_NR_REVOKE: u32 = 0x91; // EVIOCREVOKE
const EVIOC_NR_SCLOCKID: u32 = 0xa0; // EVIOCSCLOCKID — set the event clock

/// Render an identity string the way the string `EVIOCG*` ioctls do:
/// bytes plus a trailing NUL, truncated by the caller to the user's
/// requested length. An empty stored string falls back so a device
/// never reports an empty name.
fn identity_bytes(value: &str, fallback: &str) -> Vec<u8> {
    let text = if value.is_empty() { fallback } else { value };
    let mut bytes = Vec::with_capacity(text.len() + 1);
    bytes.extend_from_slice(text.as_bytes());
    bytes.push(0);
    bytes
}

// ── InputEventFile ────────────────────────────────────────────────────────────

/// Whether the underlying device was created by uinput or by a
/// hardware driver. `write()` differs by kind: uinput files accept
/// event injection; hardware files accept only the LED-output
/// records of `write_hardware_led`. The kind also keys the
/// `/dev/input/by-*` alias naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    Hardware,
    UserDevice,
}

/// One open file bound to a single evdev `DeviceId`.
///
/// Each `open("/dev/input/eventN")` creates a fresh `InputEventFile`
/// wrapping a new `Reader` allocated from `ROUTER`.  The reader
/// shares the per-device ring with all other open fds on the same
/// device (single shared ring, Linux-like fan-out semantics).
///
/// Ref: `evdev.c` `struct evdev_client` (line 36).
pub struct InputEventFile {
    device_id: DeviceId,
    /// Minor number (0-based index) — stored for `stat()`.
    event_num: u32,
    kind: DeviceKind,
    /// Mutex-wrapped Reader so `read()` and `poll_readiness()` can
    /// share the file over concurrent tasks.  `IrqSafeSpinLock` is
    /// used here because `narf_input::evdev::Reader` is `Send` and
    /// we need a lock that is safe across async suspension points
    /// in this crate's environment.
    reader: IrqSafeSpinLock<Option<narf_input::evdev::Reader>>,
}

impl core::fmt::Debug for InputEventFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InputEventFile")
            .field("device_id", &self.device_id)
            .field("event_num", &self.event_num)
            .field("kind", &self.kind)
            .finish()
    }
}

impl InputEventFile {
    /// Create a new file bound to `device_id`.
    ///
    /// Returns `None` if the device is not found in `ROUTER` (e.g.
    /// it was removed between enumeration and open).
    pub fn open(device_id: DeviceId, kind: DeviceKind) -> Option<Self> {
        let reader = ROUTER.open_reader(device_id)?;
        let event_num = device_id.0.saturating_sub(1);
        Some(Self {
            device_id,
            event_num,
            kind,
            reader: IrqSafeSpinLock::new(Some(reader)),
        })
    }

    /// Non-blocking drain: pop up to `n` events from the reader into
    /// the raw byte slice, packing each into a 24-byte Linux
    /// `input_event`.  Returns the number of *bytes* written.
    fn drain_into(&self, buf: &mut [u8]) -> usize {
        let max_events = buf.len() / LINUX_INPUT_EVENT_SIZE;
        if max_events == 0 {
            return 0;
        }
        let mut written = 0usize;
        let mut g = self.reader.lock();
        let reader = match g.as_mut() {
            Some(r) => r,
            None => return 0,
        };
        for i in 0..max_events {
            match reader.poll_event() {
                Some(ev) => {
                    let packed = pack_linux_event(&ev);
                    let dst =
                        &mut buf[i * LINUX_INPUT_EVENT_SIZE..(i + 1) * LINUX_INPUT_EVENT_SIZE];
                    dst.copy_from_slice(&packed);
                    written += LINUX_INPUT_EVENT_SIZE;
                }
                None => break,
            }
        }
        written
    }
}

impl FileOps for InputEventFile {
    /// Read events from the device ring into `buf`.
    ///
    /// - `buf` must hold at least `LINUX_INPUT_EVENT_SIZE` (24) bytes;
    ///   smaller buffers return `Ok(0)` immediately (non-blocking).
    /// - Fast path: drain whatever is already queued (non-blocking).
    /// - Slow path: if the ring is empty, open a temporary reader and
    ///   await `WaitEventFuture` for one event, then return that event.
    ///   Any further events that arrived are left in the ring for the
    ///   next read call.
    /// - Every returned event is packed into the 24-byte Linux
    ///   `input_event` wire format.
    /// - `offset` is ignored (event stream, not seekable).
    ///
    /// Ref: `evdev.c::evdev_read` lines ~441-490.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.len() < LINUX_INPUT_EVENT_SIZE {
                // Non-blocking or zero-size: return immediately.
                return Ok(0);
            }

            // Fast path: drain whatever is already queued.
            let n = self.drain_into(buf);
            if n > 0 {
                return Ok(n);
            }

            // Slow path: ring is empty — block until an event arrives.
            //
            // We open a temporary reader for the await because
            // `IrqSafeSpinLock` guards cannot be held across `await`
            // suspension points.  The temporary reader shares the same
            // device node ring, so the first event dispatched while we
            // park will be returned by `wait_event_async`.
            //
            // Ref: `evdev.c::evdev_read` `wait_event_interruptible` path.
            let wait_reader = ROUTER.open_reader(self.device_id);
            if let Some(wr) = wait_reader {
                // Block until one event or device-removal.
                if let Some(ev) = wr.wait_event_async().await {
                    // `wait_event_async` consumed the event from the ring.
                    // Pack it into the 24-byte Linux record at buf[0..24].
                    let packed = pack_linux_event(&ev);
                    buf[..LINUX_INPUT_EVENT_SIZE].copy_from_slice(&packed);
                    return Ok(LINUX_INPUT_EVENT_SIZE);
                }
            }

            // Device was removed or not found.
            Ok(0)
        })
    }

    /// Write events into the device.
    ///
    /// UserDevice (uinput) files accept a buffer of 24-byte Linux
    /// `input_event` records, unpack each into an internal
    /// `EvdevEvent`, and inject them via `ROUTER.dispatch` — that
    /// injection is the uinput contract. Records with an
    /// unrecognised `EV_*` type are skipped but still counted as
    /// consumed (Linux uinput is equally lenient).
    ///
    /// Hardware devices take the narrow exception in
    /// [`Self::write_hardware_led`]: LED output records only.
    /// Arbitrary input injection into a hardware device stays
    /// impossible — the pre-#768 blanket denial is preserved for
    /// everything except that one path. (Linux's own `evdev_write`
    /// injects any event type into hardware devices; NARF
    /// deliberately narrows this, with access already gated by the
    /// device node's permissions.)
    ///
    /// Ref: `uinput.c::uinput_write` (line ~502);
    /// `evdev.c::evdev_write` + `input.c::input_inject_event`.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if self.kind == DeviceKind::Hardware {
                return self.write_hardware_led(buf);
            }
            if buf.len() % LINUX_INPUT_EVENT_SIZE != 0 {
                return Err(FsError::InvalidPath);
            }
            let mut consumed = 0usize;
            let count = buf.len() / LINUX_INPUT_EVENT_SIZE;
            for i in 0..count {
                let src = &buf[i * LINUX_INPUT_EVENT_SIZE..(i + 1) * LINUX_INPUT_EVENT_SIZE];
                if let Some(ev) = unpack_linux_event(src) {
                    ROUTER.dispatch(self.device_id, ev);
                }
                consumed += LINUX_INPUT_EVENT_SIZE;
            }
            Ok(consumed)
        })
    }

    /// The hardware-device write path: keyboard LED output, and
    /// nothing else.
    ///
    /// The buffer must consist *solely* of `EV_LED` records whose
    /// codes the device declares in its ledbit. The whole buffer is
    /// validated before any record is dispatched, so a denied write
    /// changes no state. Anything else — an `EV_KEY` record above
    /// all, a mixed buffer, an LED code the device does not declare,
    /// an LED record for a device with no LED capability, or a
    /// malformed length — is `PermissionDenied`, exactly as every
    /// hardware write was before the LED path existed. Accepted
    /// records flow through `ROUTER.dispatch`, which updates the
    /// core LED bitmap and fires the producer's output hook (the
    /// i8042 Set-LEDs exchange / I2C-HID Output report sync).
    fn write_hardware_led(&self, buf: &[u8]) -> Result<usize, FsError> {
        if buf.len() % LINUX_INPUT_EVENT_SIZE != 0 {
            return Err(FsError::PermissionDenied);
        }
        let caps = ROUTER.caps(self.device_id).ok_or(FsError::NotFound)?;
        let count = buf.len() / LINUX_INPUT_EVENT_SIZE;
        let mut events = alloc::vec::Vec::with_capacity(count);
        for i in 0..count {
            let src = &buf[i * LINUX_INPUT_EVENT_SIZE..(i + 1) * LINUX_INPUT_EVENT_SIZE];
            let ev = unpack_linux_event(src).ok_or(FsError::PermissionDenied)?;
            if ev.type_ != EventType::Led || !caps.ledbit.get(ev.code) {
                return Err(FsError::PermissionDenied);
            }
            events.push(ev);
        }
        for ev in events {
            ROUTER.dispatch(self.device_id, ev);
        }
        Ok(buf.len())
    }

    /// Stat: character device, mode 0o060660 (device file, input group
    /// convention rw-rw----).  Major 13 = Linux input (evdev) major.
    ///
    /// Ref: Linux `drivers/input/evdev.c` — evdev uses major 13.
    fn stat(&self) -> Stat {
        let meta = evdev_meta(self.event_num);
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                // 0o060660: device file (0o060000) | rw-rw---- (0o660).
                // Linux assigns gid=input (typically 999) and mode 0660.
                // Read from the shared node table so a udev chmod sticks.
                perms: meta.perms,
            },
            mtime_cycles: 0,
        }
    }

    fn owners(&self) -> (u32, u32) {
        let meta = evdev_meta(self.event_num);
        (meta.uid, meta.gid)
    }

    /// `chown` — udev's `GROUP="input"` assignment. Persisted in
    /// [`EVDEV_NODE_META`] so it survives this fd's close and is visible to
    /// the compositor's later open.
    fn set_owners<'a>(&'a self, uid: u32, gid: u32) -> FsFuture<'a, ()> {
        evdev_meta_update(self.event_num, |meta| {
            meta.uid = uid;
            meta.gid = gid;
        });
        Box::pin(async { Ok(()) })
    }

    /// `chmod` — udev's `MODE="0660"`. Masked to the permission bits;
    /// the file type is fixed by the node.
    fn set_perms<'a>(&'a self, perms: u16) -> FsFuture<'a, ()> {
        evdev_meta_update(self.event_num, |meta| meta.perms = perms & 0o7777);
        Box::pin(async { Ok(()) })
    }

    fn rdev(&self) -> u64 {
        // Linux INPUT_MAJOR = 13; evdev minors start at 64 (event<N> = 64+N).
        // dev_t = (major << 8) | minor for this small-number range. libinput
        // matches this against udev's MAJOR:MINOR for the opened fd.
        let major = 13u64;
        let minor = 64 + self.event_num as u64;
        (major << 8) | minor
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }

    /// Poll readiness: `POLL_IN` if the ring has any events queued.
    ///
    /// Uses `has_pending()` (non-destructive) so the check does not
    /// consume events as a side effect.
    ///
    /// Ref: `evdev.c::evdev_poll` — `POLLIN|POLLRDNORM` when
    /// `evdev_client_events()` is non-zero.
    fn poll_readiness(&self) -> u32 {
        let g = self.reader.lock();
        if let Some(r) = g.as_ref() {
            if r.has_pending() {
                return POLL_IN;
            }
        }
        0
    }

    /// The router owns the device cell, while this file owns its Reader
    /// behind a lock. Delegate through the Reader rather than returning a
    /// borrowed cell so the FileOps reference never outlives that lock.
    fn arm_readiness(
        &self,
        task_id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<core::task::Poll<u32>> {
        self.reader
            .lock()
            .as_ref()
            .map(|reader| reader.arm_readiness(task_id, interest, waker))
    }

    fn arm_readiness_persistent(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        self.reader
            .lock()
            .as_ref()
            .map(|reader| reader.arm_readiness_persistent(id, interest, waker))
    }

    fn arm_readiness_persistent_exclusive(
        &self,
        id: u64,
        interest: u32,
        waker: &core::task::Waker,
    ) -> Option<u32> {
        self.reader
            .lock()
            .as_ref()
            .map(|reader| reader.arm_readiness_persistent_exclusive(id, interest, waker))
    }

    fn disarm_readiness(&self, task_id: u64) -> bool {
        if let Some(reader) = self.reader.lock().as_ref() {
            reader.disarm_readiness(task_id);
            true
        } else {
            false
        }
    }

    /// evdev's `read()` blocks internally on an empty ring (matching Linux
    /// blocking-fd semantics). A non-blocking caller — libinput opens the
    /// node `O_RDWR|O_NONBLOCK` — must get `EAGAIN` instead. Opting in here
    /// makes `sys_read` poll the read future once and return `EAGAIN` on an
    /// empty ring rather than spin-pumping `poll_blocking` for millions of
    /// iterations and surfacing the wrong errno.
    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    /// `EVIOCG*` capability ioctls — what evdev readers (evtest,
    /// libinput) issue right after `open()` to learn the device's
    /// version, id, name, and supported event/key/axis bits.
    ///
    /// All handlers decode the `_IOC` `cmd` word into `dir/size/type/nr`
    /// (see `ioc`), answer from the device's `DeviceCaps` pulled out of
    /// `ROUTER`, and copy the result into the user pointer `arg`.  The
    /// requested length (`_IOC` size, or the EVIOCGABS struct length) is
    /// the upper bound on bytes written; we return the actual count.
    ///
    /// Unknown requests return `Unsupported` → `-ENOTTY`, matching Linux.
    ///
    /// Ref: `drivers/input/evdev.c::evdev_do_ioctl`.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        // Only the evdev ('E') type is handled here.
        if ioc::typ(cmd) != EVIOC_TYPE {
            return Err(FsError::Unsupported);
        }
        let nr = ioc::nr(cmd);
        let size = ioc::size(cmd) as usize;

        match nr {
            EVIOC_NR_GVERSION => {
                // EVIOCGVERSION → i32 EV_VERSION.
                // SAFETY: `arg` is the user `int *` validated by the
                // syscall layer before dispatch.
                let n = unsafe { copy_to_user_bytes(arg, &EV_VERSION.to_le_bytes())? };
                Ok(n as u64)
            }
            EVIOC_NR_GID => {
                // EVIOCGID → struct input_id { bustype, vendor, product,
                // version } — the identity the producing transport
                // registered, not a synthetic all-virtual id.
                let caps = ROUTER.caps(self.device_id).ok_or(FsError::NotFound)?;
                let mut id = [0u8; 8];
                id[0..2].copy_from_slice(&caps.id.bustype.to_le_bytes());
                id[2..4].copy_from_slice(&caps.id.vendor.to_le_bytes());
                id[4..6].copy_from_slice(&caps.id.product.to_le_bytes());
                id[6..8].copy_from_slice(&caps.id.version.to_le_bytes());
                // SAFETY: `arg` is the user `struct input_id *`.
                let n = unsafe { copy_to_user_bytes(arg, &id)? };
                Ok(n as u64)
            }
            EVIOC_NR_GNAME => {
                // EVIOCGNAME(len) → NUL-terminated device name, truncated
                // to the requested length.  Returns the byte count copied.
                let caps = ROUTER.caps(self.device_id).ok_or(FsError::NotFound)?;
                let name = identity_bytes(&caps.name, "narf-input");
                let take = name.len().min(size.max(1));
                // SAFETY: `arg` is the user name buffer of `size` bytes.
                let n = unsafe { copy_to_user_bytes(arg, &name[..take])? };
                Ok(n as u64)
            }
            EVIOC_NR_GPHYS | EVIOC_NR_GUNIQ => {
                // EVIOCGPHYS / EVIOCGUNIQ(len) → the device's topology /
                // unique strings, same wire shape as EVIOCGNAME.
                let caps = ROUTER.caps(self.device_id).ok_or(FsError::NotFound)?;
                let value = if nr == EVIOC_NR_GPHYS {
                    &caps.phys
                } else {
                    &caps.uniq
                };
                let bytes = identity_bytes(value, "");
                let take = bytes.len().min(size.max(1));
                // SAFETY: `arg` is the user string buffer of `size` bytes.
                let n = unsafe { copy_to_user_bytes(arg, &bytes[..take])? };
                Ok(n as u64)
            }
            EVIOC_NR_GPROP => {
                // EVIOCGPROP(len) → the INPUT_PROP_* bitmap. libinput
                // reads BUTTONPAD/DIRECT from here to classify the
                // device; an all-zero answer misclassifies touchpads.
                let caps = ROUTER.caps(self.device_id).ok_or(FsError::NotFound)?;
                let src = caps.propbit.as_bytes();
                let take = src.len().min(size);
                // SAFETY: `arg` is the user bitmap buffer of `size` bytes.
                let n = unsafe { copy_to_user_bytes(arg, &src[..take])? };
                Ok(n as u64)
            }
            EVIOC_NR_GRAB => {
                // EVIOCGRAB — accept and no-op (single-reader anyway).
                Ok(0)
            }
            EVIOC_NR_REVOKE => {
                // EVIOCREVOKE. Linux `drivers/input/evdev.c`:
                //   case EVIOCREVOKE:
                //       if (p)  return -EINVAL;     // p == the arg as a pointer
                //       else    return evdev_revoke(...);   // returns 0
                // systemd-logind calls `ioctl(fd, EVIOCREVOKE, NULL)` on session
                // stop. Without this arm it fell to the generic `Unsupported`
                // relay, which — because EVIOCREVOKE is `_IOW('E',0x91,int)` —
                // copy_from_user'd the NULL arg and returned EFAULT, so logind
                // logged "Failed to revoke evdev device ... Bad address".
                // Accept the revoke (no-op: NARF is single-reader and logind
                // revokes only when tearing the session down); a non-NULL arg is
                // -EINVAL exactly as the kernel returns it.
                if arg != 0 {
                    return Err(FsError::InvalidData); // -EINVAL
                }
                Ok(0)
            }
            EVIOC_NR_SCLOCKID => {
                // EVIOCSCLOCKID — libinput selects CLOCK_MONOTONIC at startup.
                // Our event timestamps are already monotonic; accept + no-op.
                Ok(0)
            }
            EVIOC_NR_GLED => {
                // EVIOCGLED(len) → the device's current LED bitmap,
                // maintained by the input core (`dev->led`) — bit N
                // set means LED code N is lit. The bitmap is copied
                // out little-endian (LED codes 0..16 fit the first
                // two bytes); the rest of the requested length is
                // zeros, matching the fixed-size bitmap copy Linux
                // performs.
                let leds = ROUTER.led_state(self.device_id).ok_or(FsError::NotFound)?;
                let mut bytes = alloc::vec![0u8; size];
                let le = leds.to_le_bytes();
                let take = le.len().min(size);
                bytes[..take].copy_from_slice(&le[..take]);
                // SAFETY: `arg` is the user buffer of `size` bytes, validated
                // by the syscall layer before dispatch.
                let n = unsafe { copy_to_user_bytes(arg, &bytes)? };
                Ok(n as u64)
            }
            EVIOC_NR_GMTSLOTS | EVIOC_NR_GKEY | EVIOC_NR_GSND | EVIOC_NR_GSW => {
                // Multitouch-slot state and current key/sound/switch
                // state. We synthesise none of these, but libevdev
                // (libinput's backend) issues them at device init and
                // treats a FAILURE as fatal, rejecting the device.
                // Report an all-zero buffer of the requested length: no
                // keys/sounds/switches active. (LED state is real —
                // see the GLED arm above; properties and the phys/uniq
                // strings are real too — see the GPROP / GPHYS / GUNIQ
                // arms.) Linux ref: `libevdev_set_fd`.
                let zeros = alloc::vec![0u8; size];
                // SAFETY: `arg` is the user buffer of `size` bytes, validated
                // by the syscall layer before dispatch.
                let n = unsafe { copy_to_user_bytes(arg, &zeros)? };
                Ok(n as u64)
            }
            nr if (EVIOC_NR_GBIT_BASE..EVIOC_NR_GABS_BASE).contains(&nr) => {
                // EVIOCGBIT(ev, len): nr = 0x20 + ev.  ev == 0 asks for
                // the EV_* type bitmask; otherwise the per-type code bits.
                let caps = ROUTER.caps(self.device_id).ok_or(FsError::NotFound)?;
                let ev = (nr - EVIOC_NR_GBIT_BASE) as u16;
                if ev == 0 {
                    // EV_* type bitmask: evbit is a u32 little-endian word.
                    let bytes = caps.evbit.to_le_bytes();
                    let take = bytes.len().min(size);
                    // SAFETY: `arg` is the user bitmask buffer of `size` bytes.
                    let n = unsafe { copy_to_user_bytes(arg, &bytes[..take])? };
                    Ok(n as u64)
                } else {
                    let src: &[u8] = match EventType::from_raw(ev) {
                        Some(EventType::Key) => caps.keybit.as_bytes(),
                        Some(EventType::Rel) => caps.relbit.as_bytes(),
                        Some(EventType::Abs) => caps.absbit.as_bytes(),
                        Some(EventType::Led) => caps.ledbit.as_bytes(),
                        // No bitmap tracked for other types — report none.
                        _ => &[],
                    };
                    let take = src.len().min(size);
                    // SAFETY: `arg` is the user bitmask buffer of `size` bytes.
                    let n = unsafe { copy_to_user_bytes(arg, &src[..take])? };
                    Ok(n as u64)
                }
            }
            nr if (EVIOC_NR_GABS_BASE..EVIOC_NR_GABS_BASE + 0x40).contains(&nr) => {
                // EVIOCGABS(abs): nr = 0x40 + abs.  struct input_absinfo is six
                // i32s { value, minimum, maximum, fuzz, flat, resolution }.
                // Report the device's real range so libinput can map an
                // absolute pointer onto the output — an all-zero range makes
                // libinput discard the axis and the pointer never moves.
                let axis = (nr - EVIOC_NR_GABS_BASE) as u16;
                let caps = ROUTER.caps(self.device_id).ok_or(FsError::NotFound)?;
                let mut absinfo = [0u8; 24];
                if let Some(info) = caps.abs_info(axis) {
                    absinfo[0..4].copy_from_slice(&0i32.to_le_bytes()); // value
                    absinfo[4..8].copy_from_slice(&info.min.to_le_bytes());
                    absinfo[8..12].copy_from_slice(&info.max.to_le_bytes());
                    absinfo[12..16].copy_from_slice(&info.fuzz.to_le_bytes());
                    absinfo[16..20].copy_from_slice(&info.flat.to_le_bytes());
                    absinfo[20..24].copy_from_slice(&info.res.to_le_bytes());
                }
                // SAFETY: `arg` is the user `struct input_absinfo *`.
                let n = unsafe { copy_to_user_bytes(arg, &absinfo)? };
                Ok(n as u64)
            }
            _ => Err(FsError::Unsupported),
        }
    }
}

// ── UinputControlFile (/dev/uinput) ────────────────────────────────────────────
//
// The userspace input-injection control device.  Tools like ydotool/wtype
// open `/dev/uinput`, declare the device's capabilities via a sequence of
// `UI_SET_*BIT` ioctls, then `UI_DEV_CREATE` to register a virtual device.
// Afterwards they `write()` packed 24-byte Linux `input_event` records,
// which are routed through `ROUTER.dispatch()` to whichever reader opened
// the newly-created `/dev/input/eventN` node.
//
// Linux ref: `drivers/input/misc/uinput.c`, `include/uapi/linux/uinput.h`.

use narf_input::evdev::{DeviceCaps, DeviceNode};

/// uinput ioctl type byte (`'U'` = 0x55). `UINPUT_IOCTL_BASE` in
/// `include/uapi/linux/uinput.h`.
const UINPUT_TYPE: u32 = b'U' as u32; // 0x55

/// uinput ioctl `nr` values. Ref: `include/uapi/linux/uinput.h`.
const UI_DEV_CREATE: u32 = 1; // _IO('U', 1)
const UI_DEV_DESTROY: u32 = 2; // _IO('U', 2)
const UI_DEV_SETUP: u32 = 3; // _IOW('U', 3, struct uinput_setup)
const UI_SET_EVBIT: u32 = 100; // _IOW('U', 100, int)
const UI_SET_KEYBIT: u32 = 101; // _IOW('U', 101, int)
const UI_SET_RELBIT: u32 = 102; // _IOW('U', 102, int)
const UI_SET_ABSBIT: u32 = 103; // _IOW('U', 103, int)
const UI_SET_MSCBIT: u32 = 104; // _IOW('U', 104, int)
const UI_SET_PHYS: u32 = 108; // _IOW('U', 108, char*)
const UI_SET_PROPBIT: u32 = 110; // _IOW('U', 110, int)

/// Mutable state behind the control file's lock.
struct UinputInner {
    /// Capabilities accumulated via `UI_SET_*BIT` before `UI_DEV_CREATE`.
    caps: DeviceCaps,
    /// `Some` once `UI_DEV_CREATE` has registered the virtual device with
    /// `ROUTER`; `None` before creation or after `UI_DEV_DESTROY`.
    created: Option<(DeviceId, Arc<DeviceNode>)>,
}

/// `/dev/uinput` — the userspace input-injection control device.
///
/// A single top-level character node (not a directory).  One open file
/// owns one virtual input device for its lifetime: capability ioctls
/// build up `DeviceCaps`, `UI_DEV_CREATE` registers it with `ROUTER`
/// (so it appears as `/dev/input/eventN`), `write()` injects events, and
/// `UI_DEV_DESTROY` tears it down.
///
/// State is held behind an `IrqSafeSpinLock`; the lock scope is kept tight
/// and is never held across an `.await` (the ioctl path is synchronous and
/// `write` only takes the lock to read the stored id, never across dispatch
/// suspension — `dispatch` itself is synchronous).
///
/// Ref: `drivers/input/misc/uinput.c`.
pub struct UinputControlFile {
    inner: IrqSafeSpinLock<UinputInner>,
}

impl core::fmt::Debug for UinputControlFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let g = self.inner.lock();
        f.debug_struct("UinputControlFile")
            .field("created", &g.created.as_ref().map(|(id, _)| *id))
            .finish_non_exhaustive()
    }
}

impl Default for UinputControlFile {
    fn default() -> Self {
        Self::new()
    }
}

impl UinputControlFile {
    /// Create a fresh, un-set-up control file (no device registered yet).
    /// Each `open("/dev/uinput")` produces one of these.
    pub fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(UinputInner {
                caps: DeviceCaps::new(),
                created: None,
            }),
        }
    }
}

impl FileOps for UinputControlFile {
    /// Inject events into the created virtual device.
    ///
    /// Mirrors `InputEventFile::write` for `UserDevice`: requires a device
    /// to have been created (else `PermissionDenied`, as Linux returns
    /// `-ENODEV` before `UI_DEV_CREATE`), requires `buf.len()` to be a
    /// multiple of 24, and routes each unpacked record via `ROUTER.dispatch`.
    ///
    /// The stored `DeviceId` is read under the lock and the lock is dropped
    /// before any dispatch loop — the lock is never held across `.await`.
    ///
    /// Ref: `uinput.c::uinput_write` → `uinput_inject_events`.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // Snapshot the created device id under a tight lock, then release.
            let id = {
                let g = self.inner.lock();
                match g.created.as_ref() {
                    Some((id, _)) => *id,
                    None => return Err(FsError::PermissionDenied),
                }
            };
            if buf.len() % LINUX_INPUT_EVENT_SIZE != 0 {
                return Err(FsError::InvalidPath);
            }
            let mut consumed = 0usize;
            let count = buf.len() / LINUX_INPUT_EVENT_SIZE;
            for i in 0..count {
                let src = &buf[i * LINUX_INPUT_EVENT_SIZE..(i + 1) * LINUX_INPUT_EVENT_SIZE];
                if let Some(ev) = unpack_linux_event(src) {
                    ROUTER.dispatch(id, ev);
                }
                consumed += LINUX_INPUT_EVENT_SIZE;
            }
            Ok(consumed)
        })
    }

    /// Reads drain pending force-feedback requests. NARF never synthesises
    /// any, so this always comes back empty — but "empty" must NOT be
    /// reported as a 0-byte read.
    ///
    /// `read() == 0` on a character device means END OF FILE: the reader
    /// concludes the device went away and stops. Linux's uinput blocks an
    /// empty read (or returns EAGAIN on an O_NONBLOCK fd) and only ever
    /// returns 0 at a genuine hangup. The old comment here called EOF "the
    /// safe answer"; it is the opposite — it is a phantom hangup, exactly
    /// the bug that left the `foot` terminal blank when PtyMaster::read
    /// returned 0 on an empty ring, and that broke GLib's dbus line-read
    /// when a pipe did the same.
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        // uinput has no end-of-file: an empty read waits for a force-feedback
        // request. NARF synthesises none, so this is always would-block —
        // deliberately, and matching Linux, where the wait is equally
        // unbounded until a client uploads an effect. Reporting a hangup that
        // did not happen is the worse failure: the reader tears the device
        // down.
        Box::pin(async move { Err(FsError::WouldBlock) })
    }

    /// An O_NONBLOCK reader must get EAGAIN, not a phantom EOF. `sys_read`
    /// turns a 0-byte result into EAGAIN when this is set, which is what an
    /// FF-aware client polling the control fd expects.
    fn nonblock_read_eagain(&self) -> bool {
        true
    }

    /// Stat: character device, mode 0660 (matches `/dev/uinput` on Linux,
    /// owned by root:input, crw-rw----).  Major 10, minor 223 on Linux;
    /// we report a generic Special node.
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }

    fn rdev(&self) -> u64 {
        crate::devfs::linux_makedev(10, 223)
    }

    fn ino(&self) -> u64 {
        0xd001_0000_0000_0000 | self.rdev().wrapping_add(1)
    }

    /// uinput control ioctls.
    ///
    /// Decodes the `_IOC` word; only the `'U'` (0x55) type is handled.
    /// `UI_SET_*BIT` arguments are passed by *value* (the keycode/axis
    /// itself), not as a user pointer — so no user memory is dereferenced
    /// for those.  Unknown `'U'` requests are accepted (return 0) to match
    /// uinput's lenient setup contract; non-`'U'` types return `Unsupported`.
    ///
    /// Ref: `uinput.c::uinput_ioctl_handler`.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        if ioc::typ(cmd) != UINPUT_TYPE {
            return Err(FsError::Unsupported);
        }
        let nr = ioc::nr(cmd);
        let mut g = self.inner.lock();
        match nr {
            UI_DEV_CREATE => {
                // Register the accumulated caps with ROUTER. Idempotent: if a
                // device is already created, leave it in place (Linux returns
                // -EINVAL on double-create, but accepting is harmless here).
                if g.created.is_none() {
                    let caps = g.caps.clone();
                    let (id, node) = ROUTER.register_device(caps);
                    g.created = Some((id, node));
                }
                Ok(0)
            }
            UI_DEV_DESTROY => {
                if let Some((id, _node)) = g.created.take() {
                    ROUTER.unregister_device(id);
                }
                // Reset caps so the same fd can build a fresh device.
                g.caps = DeviceCaps::new();
                Ok(0)
            }
            UI_SET_EVBIT => {
                // EV_* type bit: the evbit is derived implicitly from the
                // per-type SET_*BIT calls, so accept and no-op here.
                let _ = arg;
                Ok(0)
            }
            UI_SET_KEYBIT => {
                // arg IS the keycode (passed by value, not a pointer).
                g.caps.add_key(arg as u16);
                Ok(0)
            }
            UI_SET_RELBIT => {
                g.caps.add_rel(arg as u16);
                Ok(0)
            }
            UI_SET_ABSBIT => {
                g.caps.add_abs(arg as u16);
                Ok(0)
            }
            UI_SET_PROPBIT => {
                // arg IS the INPUT_PROP_* code (passed by value).
                g.caps.add_prop(arg as u16);
                Ok(0)
            }
            UI_SET_PHYS => {
                // arg is a `char *` to the device's phys string.
                let phys = read_user_c_string(arg, 128)?;
                g.caps.phys = phys;
                Ok(0)
            }
            UI_DEV_SETUP => {
                // arg is a `struct uinput_setup *`: input_id + name[80]
                // + ff_effects_max. The name/id land on the created
                // device's identity instead of being discarded.
                let mut setup = [0u8; 92];
                // SAFETY: `arg` is the user `struct uinput_setup *`
                // validated by the syscall layer before dispatch.
                unsafe { copy_from_user_bytes(arg, &mut setup)? };
                apply_uinput_setup(&mut g.caps, &setup)?;
                Ok(0)
            }
            UI_SET_MSCBIT => {
                // Accept; misc bits aren't modelled in DeviceCaps.
                Ok(0)
            }
            // uinput is lenient about unknown setup-style requests.
            _ => Ok(0),
        }
    }
}

// ── DevInputDir ───────────────────────────────────────────────────────────────

/// `/dev/input/` directory node.
///
/// `lookup("eventN")` maps to `DeviceId(N+1)` and creates a fresh
/// `InputEventFile` bound to that id if the device is still alive.
///
/// Device kind defaults to `Hardware`; the `UserDevice` path is wired
/// separately when a uinput device is created (future work — for now
/// all devices opened via path are `Hardware` unless the caller
/// explicitly marks them via `open_with_kind`).
#[derive(Debug)]
pub struct DevInputDir;

/// Which alias namespace a `/dev/input/by-*` directory serves.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum InputAliasKind {
    ById,
    ByPath,
}

/// Sanitize one alias component the way udev does: anything outside
/// `[A-Za-z0-9._-]` becomes `_`.
fn sanitize_alias(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    while out.starts_with('_') {
        out.remove(0);
    }
    while out.ends_with('_') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("narf-input");
    }
    out
}

/// The class suffix udev-style alias names carry (`-event-touchpad`,
/// `-event-kbd`, …), derived from the device's properties/caps.
fn alias_class_suffix(caps: &narf_input::evdev::DeviceCaps) -> &'static str {
    use narf_input::evdev::{key, prop};
    if caps.has_prop(prop::BUTTONPAD) {
        "-event-touchpad"
    } else if caps.has_prop(prop::DIRECT) && caps.keybit.get(key::BTN_TOOL_PEN) {
        "-event-tablet"
    } else if caps.has_prop(prop::DIRECT) && caps.keybit.get(key::BTN_TOUCH) {
        "-event-touchscreen"
    } else if caps.evbit & (1 << (narf_input::evdev::EventType::Rel as u16)) != 0
        || caps.keybit.get(key::BTN_LEFT)
    {
        "-event-mouse"
    } else if caps.evbit & (1 << (narf_input::evdev::EventType::Key as u16)) != 0 {
        "-event-kbd"
    } else {
        "-event"
    }
}

/// The alias name for one registered device in one namespace, or
/// `None` when the namespace cannot name it (by-path needs a phys).
fn input_alias_name(kind: InputAliasKind, caps: &narf_input::evdev::DeviceCaps) -> Option<String> {
    match kind {
        InputAliasKind::ById => {
            let bus_name = match caps.id.bustype {
                narf_input::evdev::bus::USB => "usb",
                narf_input::evdev::bus::I2C => "i2c",
                narf_input::evdev::bus::I8042 => "serio",
                narf_input::evdev::bus::PCI => "pci",
                _ => "virtual",
            };
            let mut name = alloc::format!("{}-", bus_name);
            if caps.id.vendor != 0 || caps.id.product != 0 {
                name.push_str(&alloc::format!(
                    "{:04x}-{:04x}-",
                    caps.id.vendor,
                    caps.id.product
                ));
            }
            name.push_str(&sanitize_alias(&caps.name));
            if !caps.uniq.is_empty() {
                name.push('-');
                name.push_str(&sanitize_alias(&caps.uniq));
            }
            name.push_str(alias_class_suffix(caps));
            Some(name)
        }
        InputAliasKind::ByPath => {
            if caps.phys.is_empty() {
                return None;
            }
            let mut name = sanitize_alias(&caps.phys);
            name.push_str(alias_class_suffix(caps));
            Some(name)
        }
    }
}

/// One `/dev/input/by-id` or `/dev/input/by-path` directory. Entries
/// are symlinks to `../eventN`, regenerated from the live router on
/// every lookup/enumeration so replug + removal stay consistent.
#[derive(Debug)]
struct DevInputAliasDir {
    kind: InputAliasKind,
}

impl DevInputAliasDir {
    fn entries(&self) -> Vec<(String, DeviceId)> {
        narf_input::evdev::snapshot_devices()
            .iter()
            .filter_map(|snap| input_alias_name(self.kind, &snap.caps).map(|name| (name, snap.id)))
            .collect()
    }
}

impl DirOps for DevInputAliasDir {
    fn ino(&self) -> u64 {
        match self.kind {
            InputAliasKind::ById => 21,
            InputAliasKind::ByPath => 22,
        }
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        let (_, id) = self.entries().into_iter().find(|(n, _)| n == name)?;
        let event_n = id.0.saturating_sub(1);
        Some(crate::devfs::symlink_file(
            name,
            alloc::format!("../event{}", event_n),
        ))
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        self.entries()
            .into_iter()
            .skip(cursor)
            .take(max)
            .map(|(name, _)| (name, FileType::Symlink))
            .collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }
}

impl DirOps for DevInputDir {
    fn ino(&self) -> u64 {
        20
    }

    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Accept "eventN" where N is the 0-based device index.
        let n_str = name.strip_prefix("event")?;
        let n: u32 = n_str.parse().ok()?;
        let device_id = DeviceId(n + 1);
        let file = InputEventFile::open(device_id, DeviceKind::Hardware)?;
        Some(Arc::new(file) as Arc<dyn FileOps>)
    }

    fn lookup_dir(&self, name: &str) -> Option<Arc<dyn DirOps>> {
        match name {
            "by-id" => Some(Arc::new(DevInputAliasDir {
                kind: InputAliasKind::ById,
            })),
            "by-path" => Some(Arc::new(DevInputAliasDir {
                kind: InputAliasKind::ByPath,
            })),
            _ => None,
        }
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move { self.lookup(name).ok_or(FsError::NotFound) })
    }

    fn lookup_dir_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { self.lookup_dir(name).ok_or(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // `DirEntry` requires `&'static str`; for dynamically-named
        // entries we return empty from `iter()` and override `enumerate()`.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let mut entries: Vec<(String, FileType)> = alloc::vec![
            (String::from("by-id"), FileType::Dir),
            (String::from("by-path"), FileType::Dir),
        ];
        for id in ROUTER.device_ids() {
            let n = id.0.saturating_sub(1);
            entries.push((alloc::format!("event{}", n), FileType::Special));
        }
        entries.into_iter().skip(cursor).take(max).collect()
    }

    fn enumerate_async<'a>(
        &'a self,
        cursor: usize,
        max: usize,
    ) -> FsFuture<'a, Vec<(String, FileType)>> {
        Box::pin(async move { Ok(self.enumerate(cursor, max)) })
    }
}

// ── EVIOCREVOKE errno parity (kernel test) ────────────────────────────────────
// Constructed in-module because `InputEventFile`'s fields are private and
// `InputEventFile::open` needs a ROUTER-registered device (absent in a test).
// The REVOKE ioctl arm is pure argument logic — it never touches the reader.
fn smoke_evdev_eviocrevoke_errno() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    // EVIOCREVOKE = _IOW('E', 0x91, int) = 0x4004_4591.
    const EVIOCREVOKE: u32 = 0x4004_4591;
    if ioc::nr(EVIOCREVOKE) != EVIOC_NR_REVOKE {
        return TestResult::Fail("EVIOCREVOKE nr must decode to 0x91");
    }
    let f = InputEventFile {
        device_id: DeviceId(1),
        event_num: 0,
        kind: DeviceKind::Hardware,
        reader: IrqSafeSpinLock::new(None),
    };
    // Linux drivers/input/evdev.c: a NULL arg revokes and returns 0 — this is
    // what systemd-logind issues on session stop. Must NOT fall to the generic
    // Unsupported relay (which copy_from_user'd the NULL arg → EFAULT).
    if !matches!(f.ioctl(EVIOCREVOKE, 0), Ok(0)) {
        return TestResult::Fail("EVIOCREVOKE(NULL) must return Ok(0), not EFAULT/ENOTTY");
    }
    // `if (p) return -EINVAL;` — a non-NULL arg is -EINVAL (FsError::InvalidData).
    if !matches!(f.ioctl(EVIOCREVOKE, 1), Err(FsError::InvalidData)) {
        return TestResult::Fail("EVIOCREVOKE(non-NULL) must return -EINVAL");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!("filesystem/devfs_input", smoke_evdev_eviocrevoke_errno);

// ── Identity publication (issues #764/#769) ───────────────────────────────────
// A registered device with a real transport identity must surface
// by-id / by-path aliases that resolve to its event node, and a
// uinput setup image must land its name/id on the caps.
fn smoke_evdev_identity_aliases_and_uinput_setup() -> narf_kernel_test::TestResult {
    use narf_input::evdev::{bus, prop, DeviceCaps, InputId, ROUTER};
    use narf_kernel_test::TestResult;

    let mut caps = DeviceCaps::new();
    caps.set_identity(
        "ELAN09BD I2C-HID Touchpad",
        "i2c-ELAN0001/input0",
        "",
        InputId::new(bus::I2C, 0x04F3, 0x3045, 0x0001),
    );
    caps.add_prop(prop::POINTER);
    caps.add_prop(prop::BUTTONPAD);
    caps.add_key(narf_input::evdev::key::BTN_TOUCH);
    let (id, _node) = ROUTER.register_device(caps);

    let dir = DevInputDir;
    let names: Vec<String> = dir.enumerate(0, 64).into_iter().map(|(n, _)| n).collect();
    if !names.iter().any(|n| n == "by-id") || !names.iter().any(|n| n == "by-path") {
        ROUTER.unregister_device(id);
        return TestResult::Fail("/dev/input must enumerate by-id and by-path");
    }

    let by_id = match dir.lookup_dir("by-id") {
        Some(d) => d,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("by-id directory missing");
        }
    };
    let aliases: Vec<String> = by_id.enumerate(0, 64).into_iter().map(|(n, _)| n).collect();
    let alias = match aliases
        .iter()
        .find(|n| n.contains("04f3-3045") && n.ends_with("-event-touchpad"))
    {
        Some(a) => a.clone(),
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("by-id touchpad alias missing");
        }
    };
    match by_id.lookup(&alias) {
        Some(f) if f.stat().mode.file_type == FileType::Symlink => {}
        _ => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("by-id alias must resolve to a symlink");
        }
    }

    let by_path = match dir.lookup_dir("by-path") {
        Some(d) => d,
        None => {
            ROUTER.unregister_device(id);
            return TestResult::Fail("by-path directory missing");
        }
    };
    if !by_path
        .enumerate(0, 64)
        .iter()
        .any(|(n, _)| n.starts_with("i2c-ELAN0001_input0") && n.ends_with("-event-touchpad"))
    {
        ROUTER.unregister_device(id);
        return TestResult::Fail("by-path touchpad alias missing");
    }
    ROUTER.unregister_device(id);

    // uinput_setup wire image: input_id{0x1234,0x5678,0x9abc,0x0001} +
    // name "Test Virtual Pad" + ff_effects_max.
    let mut setup = [0u8; 92];
    setup[0..2].copy_from_slice(&0x1234u16.to_le_bytes());
    setup[2..4].copy_from_slice(&0x5678u16.to_le_bytes());
    setup[4..6].copy_from_slice(&0x9abcu16.to_le_bytes());
    setup[6..8].copy_from_slice(&0x0001u16.to_le_bytes());
    setup[8..8 + 16].copy_from_slice(b"Test Virtual Pad");
    let mut ucaps = DeviceCaps::new();
    if apply_uinput_setup(&mut ucaps, &setup).is_err() {
        return TestResult::Fail("uinput setup image rejected");
    }
    if ucaps.name != "Test Virtual Pad" || ucaps.id != InputId::new(0x1234, 0x5678, 0x9abc, 0x0001)
    {
        return TestResult::Fail("uinput setup name/id did not land on caps");
    }
    TestResult::Pass
}
narf_kernel_test::kernel_test_in!(
    "filesystem/devfs_input",
    smoke_evdev_identity_aliases_and_uinput_setup
);

// ── USB identity publication (issue #874) ───────────────────────────────────
// A USB HID device whose caps carry descriptor identity (BUS_USB +
// idVendor/idProduct/bcdDevice, product name, usb-{port} phys) must
// surface by-id / by-path aliases built from that identity — not from
// the synthetic fallback. Two identical devices on different ports
// share one by-id alias (uniq is empty, mirroring I2C-HID) but must
// get DISTINCT by-path aliases: a name-only identity would collide.
fn smoke_evdev_usb_identity_aliases() -> narf_kernel_test::TestResult {
    use narf_input::evdev::{bus, DeviceCaps, InputId, ROUTER};
    use narf_kernel_test::TestResult;

    // Mouse 1: Logitech receiver on root port 2.
    let mut caps = DeviceCaps::new();
    caps.set_identity(
        "Logitech USB Receiver",
        "usb-2",
        "",
        InputId::new(bus::USB, 0x046D, 0xC52B, 0x0111),
    );
    caps.add_rel(narf_input::evdev::rel::REL_X);
    caps.add_rel(narf_input::evdev::rel::REL_Y);
    caps.add_key(narf_input::evdev::key::BTN_LEFT);
    let (id1, _node) = ROUTER.register_device(caps);

    // Mouse 2: identical vendor/product/name, different port.
    let mut caps2 = DeviceCaps::new();
    caps2.set_identity(
        "Logitech USB Receiver",
        "usb-3",
        "",
        InputId::new(bus::USB, 0x046D, 0xC52B, 0x0111),
    );
    caps2.add_rel(narf_input::evdev::rel::REL_X);
    caps2.add_rel(narf_input::evdev::rel::REL_Y);
    caps2.add_key(narf_input::evdev::key::BTN_LEFT);
    let (id2, _node) = ROUTER.register_device(caps2);

    let mut fail: Option<&str> = None;
    let dir = DevInputDir;
    let names: Vec<String> = dir.enumerate(0, 64).into_iter().map(|(n, _)| n).collect();
    if !names.iter().any(|n| n == "by-id") || !names.iter().any(|n| n == "by-path") {
        fail = Some("/dev/input must enumerate by-id and by-path");
    }
    let mut by_id_alias: Option<String> = None;
    if fail.is_none() {
        match dir.lookup_dir("by-id") {
            Some(d) => {
                let aliases: Vec<String> = d.enumerate(0, 64).into_iter().map(|(n, _)| n).collect();
                by_id_alias = aliases
                    .iter()
                    .find(|n| n.contains("046d-c52b") && n.ends_with("-event-mouse"))
                    .cloned();
                if by_id_alias.is_none() {
                    fail = Some("by-id USB mouse alias missing");
                }
            }
            None => fail = Some("by-id directory missing"),
        }
    }
    if fail.is_none() {
        match dir.lookup_dir("by-path") {
            Some(d) => {
                let by_path_aliases: Vec<String> =
                    d.enumerate(0, 64).into_iter().map(|(n, _)| n).collect();
                if !by_path_aliases
                    .iter()
                    .any(|n| n.starts_with("usb-2") && n.ends_with("-event-mouse"))
                {
                    fail = Some("by-path alias for port-2 mouse missing");
                } else if !by_path_aliases
                    .iter()
                    .any(|n| n.starts_with("usb-3") && n.ends_with("-event-mouse"))
                {
                    fail = Some("by-path alias for port-3 mouse missing");
                }
            }
            None => fail = Some("by-path directory missing"),
        }
    }
    if fail.is_none() {
        // The shared by-id alias must resolve to a symlink.
        let by_id = dir.lookup_dir("by-id").expect("by-id checked above");
        match by_id.lookup(by_id_alias.as_deref().unwrap_or("")) {
            Some(f) if f.stat().mode.file_type == FileType::Symlink => {}
            _ => fail = Some("by-id alias must resolve to a symlink"),
        }
    }
    ROUTER.unregister_device(id1);
    ROUTER.unregister_device(id2);
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
narf_kernel_test::kernel_test_in!("filesystem/devfs_input", smoke_evdev_usb_identity_aliases);

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod devfs_input_unit {
    use super::*;

    /// Verify the event file size constant matches Linux's `struct input_event`.
    #[test]
    fn evdev_event_size_is_16() {
        assert_eq!(
            EVDEV_EVENT_SIZE, 16,
            "EvdevEvent must be 16 bytes to match Linux ABI"
        );
    }
}
