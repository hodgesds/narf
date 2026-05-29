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
//! Each read returns a multiple of `size_of::<EvdevEvent>()` (16 bytes).
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
//! `/dev/input/mice` (multiplexed mouse) and EVIOCG* ioctls are
//! deferred to a later wave.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem;

use narf_input::evdev::{DeviceId, EvdevEvent, ROUTER};
use narf_lib::sync::IrqSafeSpinLock;

use crate::{DirEntry, DirOps, FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN};

// ── EvdevEvent size constant ──────────────────────────────────────────────────

/// Wire size of one evdev event on the userspace ABI (16 bytes).
/// `size_of::<EvdevEvent>()` = 8 (time) + 2 (type) + 2 (code) + 4 (value).
/// Ref: `include/uapi/linux/input.h` `struct input_event` (64-bit kernel).
const EVDEV_EVENT_SIZE: usize = mem::size_of::<EvdevEvent>();

// ── InputEventFile ────────────────────────────────────────────────────────────

/// Whether the underlying device was created by uinput (writes allowed)
/// or a hardware driver (writes denied).
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
    /// the raw byte slice.  Returns the number of *bytes* written.
    fn drain_into(&self, buf: &mut [u8]) -> usize {
        let max_events = buf.len() / EVDEV_EVENT_SIZE;
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
                    let dst = &mut buf[i * EVDEV_EVENT_SIZE..(i + 1) * EVDEV_EVENT_SIZE];
                    // SAFETY: EvdevEvent is repr(C), size_of matches EVDEV_EVENT_SIZE,
                    // and we're copying exactly that many bytes into a properly sized slice.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            &ev as *const EvdevEvent as *const u8,
                            dst.as_mut_ptr(),
                            EVDEV_EVENT_SIZE,
                        );
                    }
                    written += EVDEV_EVENT_SIZE;
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
    /// - `buf` must hold at least `EVDEV_EVENT_SIZE` (16) bytes; smaller
    ///   buffers return `Ok(0)` immediately (non-blocking semantics).
    /// - Fast path: drain whatever is already queued (non-blocking).
    /// - Slow path: if the ring is empty, open a temporary reader and
    ///   await `WaitEventFuture` for one event, then return that event.
    ///   Any further events that arrived are left in the ring for the
    ///   next read call.
    /// - `offset` is ignored (event stream, not seekable).
    ///
    /// Ref: `evdev.c::evdev_read` lines ~441-490.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if buf.len() < EVDEV_EVENT_SIZE {
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
                    // Serialize it into `buf[0..EVDEV_EVENT_SIZE]`.
                    let dst = &mut buf[..EVDEV_EVENT_SIZE];
                    // SAFETY: `EvdevEvent` is `repr(C)` and exactly
                    // `EVDEV_EVENT_SIZE` bytes; `dst` is that size.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            &ev as *const EvdevEvent as *const u8,
                            dst.as_mut_ptr(),
                            EVDEV_EVENT_SIZE,
                        );
                    }
                    return Ok(EVDEV_EVENT_SIZE);
                }
            }

            // Device was removed or not found.
            Ok(0)
        })
    }

    /// Write events into the device (uinput path).
    ///
    /// Hardware devices return `FsError::PermissionDenied`.
    /// UserDevice files accept a buffer of packed `EvdevEvent` structs
    /// and inject them via `DeviceNode::dispatch`.
    ///
    /// Ref: `uinput.c::uinput_write` (line ~502).
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            if self.kind == DeviceKind::Hardware {
                return Err(FsError::PermissionDenied);
            }
            if buf.len() % EVDEV_EVENT_SIZE != 0 {
                return Err(FsError::InvalidPath);
            }
            let mut injected = 0usize;
            let count = buf.len() / EVDEV_EVENT_SIZE;
            for i in 0..count {
                let src = &buf[i * EVDEV_EVENT_SIZE..(i + 1) * EVDEV_EVENT_SIZE];
                // SAFETY: EvdevEvent is repr(C), src is exactly EVDEV_EVENT_SIZE bytes.
                let ev: EvdevEvent = unsafe {
                    let mut v = core::mem::MaybeUninit::<EvdevEvent>::uninit();
                    core::ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        v.as_mut_ptr() as *mut u8,
                        EVDEV_EVENT_SIZE,
                    );
                    v.assume_init()
                };
                ROUTER.dispatch(self.device_id, ev);
                injected += EVDEV_EVENT_SIZE;
            }
            Ok(injected)
        })
    }

    /// Stat: character device, mode 0o060660 (device file, input group
    /// convention rw-rw----).  Major 13 = Linux input (evdev) major.
    ///
    /// Ref: Linux `drivers/input/evdev.c` — evdev uses major 13.
    fn stat(&self) -> Stat {
        Stat {
            // Size = minor number packed as 32-bit; not meaningful for
            // char devices but harmless to report.
            size: self.event_num as u64,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                // 0o060660: device file (0o060000) | rw-rw---- (0o660).
                // Linux assigns gid=input (typically 999) and mode 0660.
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
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

impl DirOps for DevInputDir {
    fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
        // Accept "eventN" where N is the 0-based device index.
        let n_str = name.strip_prefix("event")?;
        let n: u32 = n_str.parse().ok()?;
        let device_id = DeviceId(n + 1);
        let file = InputEventFile::open(device_id, DeviceKind::Hardware)?;
        Some(Arc::new(file) as Arc<dyn FileOps>)
    }

    fn lookup_async<'a>(&'a self, name: &'a str) -> FsFuture<'a, Arc<dyn FileOps>> {
        Box::pin(async move {
            self.lookup(name).ok_or(FsError::NotFound)
        })
    }

    fn lookup_dir_async<'a>(&'a self, _name: &'a str) -> FsFuture<'a, Arc<dyn DirOps>> {
        Box::pin(async move { Err(FsError::NotFound) })
    }

    fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
        // `DirEntry` requires `&'static str`; for dynamically-named
        // entries we return empty from `iter()` and override `enumerate()`.
        Box::new(core::iter::empty())
    }

    fn enumerate(&self, cursor: usize, max: usize) -> Vec<(String, FileType)> {
        let ids = ROUTER.device_ids();
        ids.iter()
            .skip(cursor)
            .take(max)
            .map(|id| {
                let n = id.0.saturating_sub(1);
                (alloc::format!("event{}", n), FileType::Special)
            })
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod devfs_input_unit {
    use super::*;

    /// Verify the event file size constant matches Linux's `struct input_event`.
    #[test]
    fn evdev_event_size_is_16() {
        assert_eq!(EVDEV_EVENT_SIZE, 16, "EvdevEvent must be 16 bytes to match Linux ABI");
    }
}
