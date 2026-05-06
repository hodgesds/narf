//! Per-process FB connection registry.
//!
//! Each `(pid, scanout)` connection gets a unique `FbHandleId`. The
//! registry owns the consumer half of the SharedRing<DrawCmd>; the
//! producer half lives in userspace once the process maps the ring
//! page via `SYS_FB_RING_MAP`. The kernel-side drain task walks
//! every active handle on its tick.
//!
//! Storage is an `IrqSafeSpinLock<Vec<Entry>>`. The list is tiny —
//! one per connected process — so a linear scan is fine.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_ipc::shared_ring::SharedConsumer;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

use crate::cmd_ring::{self, DrawCmd, DrawRing, RING_DEPTH};
use crate::{select_active, FbWriter};

/// One live FB connection. The handle id is the public name; pid
/// + scanout are kept for reverse-lookup on process exit.
pub struct Entry {
    pub handle: u64,
    pub pid: u64,
    pub scanout_id: u32,
    pub phys: u64,
    pub consumer: SharedConsumer<DrawCmd, RING_DEPTH>,
    /// Cumulative drain count for this handle. Updated by
    /// `drain_all`; observed by `flush_wait`.
    pub drained: u64,
}

impl core::fmt::Debug for Entry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Entry")
            .field("handle", &self.handle)
            .field("pid", &self.pid)
            .field("scanout_id", &self.scanout_id)
            .field("phys", &format_args!("{:#x}", self.phys))
            .field("drained", &self.drained)
            .finish_non_exhaustive()
    }
}

static REGISTRY: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

/// Errors from `connect`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectError {
    OutOfMemory,
    NoBackend,
}

/// Open an FB connection for `pid` against `scanout_id`. Today
/// `scanout_id` must be `0` (the active picker-selected scanout);
/// multi-scanout selection lands when virtio-gpu exposes more than
/// one head.
///
/// Returns a non-zero `FbHandleId` on success. The same `pid` may
/// open multiple connections — handles are independent. Each
/// connection owns one 4 KiB ring page.
pub fn connect(pid: u64, scanout_id: u32) -> Result<u64, ConnectError> {
    if select_active().is_none() {
        return Err(ConnectError::NoBackend);
    }
    if scanout_id != 0 {
        // Until multi-scanout support exists, anything other than
        // the active scanout is rejected.
        return Err(ConnectError::NoBackend);
    }

    let frame = narf_memory::alloc_frame().map_err(|_| ConnectError::OutOfMemory)?;
    let phys = frame.start_address();

    let ring_ptr = phys.raw() as *mut DrawRing;
    // SAFETY: identity-mapped 4 KiB region; we own this freshly-
    // allocated frame.
    unsafe {
        core::ptr::write_bytes(ring_ptr as *mut u8, 0, 4096);
        cmd_ring::init_in(ring_ptr);
    }
    // SAFETY: SPSC contract — the producer half goes to userspace
    // once it `SYS_FB_RING_MAP`s; the consumer stays here.
    let (_prod, consumer) = unsafe { cmd_ring::split(ring_ptr) };

    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    REGISTRY.lock().push(Entry {
        handle,
        pid,
        scanout_id,
        phys: phys.raw(),
        consumer,
        drained: 0,
    });
    Ok(handle)
}

/// Geometry + format of the scanout this handle is connected to.
/// Returned through the syscall vtable as a `[u32; 6]`.
pub fn info(handle: u64) -> Option<[u32; 6]> {
    {
        let g = REGISTRY.lock();
        if !g.iter().any(|e| e.handle == handle) {
            return None;
        }
    }
    let s = select_active()?;
    let format_tag = match s.format() {
        crate::PixelFormat::XRGB8888 => 1u32,
    };
    // stride is in bytes; XRGB8888 = 4 bytes per pixel.
    let stride_bytes = s.stride().checked_mul(4)?;
    Some([s.width(), s.height(), stride_bytes, format_tag, 0, 0])
}

/// Phys backing this handle's ring. The userspace syscall handler
/// is responsible for installing it in the caller's VA.
pub fn ring_phys(handle: u64) -> Option<u64> {
    REGISTRY
        .lock()
        .iter()
        .find(|e| e.handle == handle)
        .map(|e| e.phys)
}

/// Snapshot of the cumulative drain count for `handle`. Returns
/// `None` on bad handle.
pub fn drain_count(handle: u64) -> Option<u64> {
    REGISTRY
        .lock()
        .iter()
        .find(|e| e.handle == handle)
        .map(|e| e.drained)
}

/// Tear down a connection. Removes the entry, drops the consumer.
/// The backing frame stays in the freelist's "leaked" set today —
/// `narf_memory` doesn't have `free_frame` plumbing yet. Returns
/// `true` if a matching handle was found.
pub fn disconnect(handle: u64) -> bool {
    let mut g = REGISTRY.lock();
    if let Some(idx) = g.iter().position(|e| e.handle == handle) {
        g.remove(idx);
        true
    } else {
        false
    }
}

/// Disconnect every handle owned by `pid`. Called from process-
/// exit cleanup so a crashed userspace doesn't leak handles.
pub fn disconnect_all_for_pid(pid: u64) -> u32 {
    let mut g = REGISTRY.lock();
    let before = g.len();
    g.retain(|e| e.pid != pid);
    (before - g.len()) as u32
}

/// Walk every registered ring; drain each through the supplied
/// FbWriter. Returns `(executed, errors)` summed across rings.
pub fn drain_all(writer: &FbWriter) -> (u32, u32) {
    let mut total_ok = 0u32;
    let mut total_err = 0u32;
    let mut g = REGISTRY.lock();
    for e in g.iter_mut() {
        let (ok, err) = cmd_ring::drain(&mut e.consumer, writer);
        e.drained = e.drained.saturating_add(ok as u64);
        total_ok += ok;
        total_err += err;
    }
    (total_ok, total_err)
}

/// Number of registered connections — for diagnostics + tests.
pub fn count() -> usize {
    REGISTRY.lock().len()
}

/// Test-only reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    REGISTRY.lock().clear();
    NEXT_HANDLE.store(1, Ordering::Relaxed);
}

/// Test-only constructor of the syscall vtable. Returns a
/// `&'static FbSyscallVtable` so callers can install it directly.
#[doc(hidden)]
pub fn syscall_vtable() -> &'static narf_userspace::handlers::FbSyscallVtable {
    use narf_userspace::handlers::FbSyscallVtable;
    static V: FbSyscallVtable = FbSyscallVtable {
        connect: fb_vt_connect,
        info: fb_vt_info,
        ring_map: fb_vt_ring_map,
        flush_wait: fb_vt_flush_wait,
        disconnect: fb_vt_disconnect,
    };
    &V
}

fn fb_vt_connect(pid: u64, scanout_id: u64) -> u64 {
    if scanout_id > u32::MAX as u64 {
        return 0;
    }
    match connect(pid, scanout_id as u32) {
        Ok(h) => h,
        Err(_) => 0,
    }
}

fn fb_vt_info(handle: u64, out: &mut [u32; 6]) -> bool {
    match info(handle) {
        Some(arr) => {
            *out = arr;
            true
        }
        None => false,
    }
}

fn fb_vt_ring_map(handle: u64) -> u64 {
    ring_phys(handle).unwrap_or(0)
}

fn fb_vt_flush_wait(handle: u64) -> u64 {
    drain_count(handle).unwrap_or(0)
}

fn fb_vt_disconnect(handle: u64) -> bool {
    disconnect(handle)
}
