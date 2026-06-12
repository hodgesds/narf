//! Userspace graphics SDK — thin handle-oriented wrapper around the
//! NARF FB syscalls.
//!
//! Rather than hand-rolling the Connect → Info → RingMap chain and
//! the SharedRing<DrawCmd, 16> wire format, userspace constructs an
//! [`FbContext`] and calls `fill` / `flush`. Drop closes the
//! connection. Each context owns one scanout connection and one
//! producer-side ring view.
//!
//! Wire format kept in sync with `narf-fb::cmd_ring`:
//!
//! ```text
//! SharedRing<DrawCmd, 16> page (4 KiB):
//!   +0  head:   AtomicU32  (producer cursor)
//!   +4  tail:   AtomicU32  (consumer cursor)
//!   +8  closed: u32
//!   +64 slots[16] of DrawCmd (32 bytes each):
//!         tag:u32 / pad:u32 / x:u32 / y:u32 /
//!         w:u32   / h:u32   / pixel:u32 / pad:u32
//!
//!   Tags: 1 = FILL, 2 = FLUSH.
//! ```
//!
//! No `alloc` — the SDK is consumable from any `no_std` userspace
//! binary including the testbin / relibc shim.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::{fb_connect, fb_disconnect, fb_flush_wait, fb_info, fb_ring_map, FbInfo};

const TAG_FILL: u32 = 1;
const TAG_FLUSH: u32 = 2;
const RING_DEPTH: u32 = 16;
const SLOT_BASE: usize = 64;
const SLOT_BYTES: usize = 32;

/// Errors a [`FbContext`] operation can return. The connection
/// stays usable after a `RingFull` — the caller can retry after a
/// drain — but `BadHandle` / `NoBackend` mean the kernel rejected
/// the open.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FbError {
    /// Kernel rejected `fb_connect` — no FB backend, OOM, or the
    /// scanout id is out of range.
    NoBackend,
    /// `fb_info` / `fb_ring_map` failed against an open handle.
    /// Most often means the kernel torn down the handle out from
    /// under us.
    BadHandle,
    /// Producer ring is full (16 commands queued); the kernel-side
    /// drain hasn't caught up. Caller should yield + retry.
    RingFull,
}

/// Open FB connection bound to one scanout. Drop disconnects.
#[derive(Debug)]
pub struct FbContext {
    handle: u64,
    info: FbInfo,
    ring: *mut u8,
}

// `*mut u8` to a kernel-mapped ring page. The kernel guarantees the
// region stays valid for the lifetime of the handle; Send/Sync are
// fine — no cross-thread aliasing in single-threaded userspace
// today, and the SharedRing's atomics protect the head/tail cursor
// when SMP userspace lands.
// SAFETY: the mapped scanout region is owned by this handle for its lifetime; single-threaded userspace has no cross-thread aliasing.
unsafe impl Send for FbContext {}
// SAFETY: the mapped scanout region is owned by this handle for its lifetime; single-threaded userspace has no cross-thread aliasing.
unsafe impl Sync for FbContext {}

impl FbContext {
    /// Open the active scanout (id 0). The shorthand most apps want.
    pub fn open() -> Result<Self, FbError> {
        Self::open_scanout(0)
    }

    /// Open a specific scanout by id. Today only `0` is accepted;
    /// multi-scanout selection lands when virtio-gpu exposes more
    /// than one head and the API doesn't break.
    pub fn open_scanout(scanout_id: u32) -> Result<Self, FbError> {
        // SAFETY: pure syscalls; no preconditions.
        let handle = unsafe { fb_connect(scanout_id) };
        if handle == 0 {
            return Err(FbError::NoBackend);
        }
        // SAFETY: handle is live (we just got it).
        let info = match unsafe { fb_info(handle) } {
            Ok(i) => i,
            Err(_) => {
                // SAFETY: handle is live; clean up.
                let _ = unsafe { fb_disconnect(handle) };
                return Err(FbError::BadHandle);
            }
        };
        // SAFETY: handle is live.
        let ring = unsafe { fb_ring_map(handle) };
        if ring.is_null() {
            // SAFETY: handle is live; clean up.
            let _ = unsafe { fb_disconnect(handle) };
            return Err(FbError::BadHandle);
        }
        Ok(Self { handle, info, ring })
    }

    /// Geometry + format of the connected scanout. Cached at open;
    /// the kernel's view is stable for the connection's lifetime
    /// today (modesetting lands later).
    pub fn info(&self) -> &FbInfo {
        &self.info
    }

    /// Raw kernel handle — for code that wants to call additional
    /// syscalls directly. The handle is only valid while `&self`
    /// is alive; storing it past Drop is undefined behaviour.
    pub fn handle(&self) -> u64 {
        self.handle
    }

    /// Enqueue a fill: `(x, y, w, h)` in scanout pixels, `pixel` in
    /// the connection's format (XRGB8888 today). Returns
    /// `FbError::RingFull` if the producer ring has no free slot;
    /// the kernel-side drain task will eventually advance the tail.
    pub fn fill(&mut self, x: u32, y: u32, w: u32, h: u32, pixel: u32) -> Result<(), FbError> {
        self.enqueue(TAG_FILL, x, y, w, h, pixel)
    }

    /// Enqueue a flush rect: `(x, y, w, h)` is the dirty region
    /// the device should push to the host. No-op on direct-MMIO
    /// backends (bochs); on virtio-gpu it issues TRANSFER + FLUSH.
    /// Today the kernel ignores the rect and flushes the full
    /// scanout — a future damage-tracking pass will honour it.
    pub fn flush(&mut self, x: u32, y: u32, w: u32, h: u32) -> Result<(), FbError> {
        // pixel field unused for flush; kept zero so it can't be
        // mis-read by an over-eager consumer.
        self.enqueue(TAG_FLUSH, x, y, w, h, 0)
    }

    /// Snapshot the cumulative drain count — every command the
    /// kernel-side drain task has executed against this handle.
    /// Useful as a poor-man's "did my flush land?" check until
    /// per-flush completion arrives.
    pub fn drained(&self) -> u64 {
        // SAFETY: handle is live.
        unsafe { fb_flush_wait(self.handle) }
    }

    fn enqueue(
        &mut self,
        tag: u32,
        x: u32,
        y: u32,
        w: u32,
        h: u32,
        pixel: u32,
    ) -> Result<(), FbError> {
        // SAFETY: ring is a 4 KiB kernel-mapped page; layout matches
        // narf-fb::cmd_ring::DrawRing exactly.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let head_p = self.ring as *const AtomicU32;
            let tail_p = self.ring.add(4) as *const AtomicU32;
            let head = (*head_p).load(Ordering::Relaxed);
            let tail = (*tail_p).load(Ordering::Acquire);
            if head.wrapping_sub(tail) >= RING_DEPTH {
                return Err(FbError::RingFull);
            }
            let slot_idx = (head & (RING_DEPTH - 1)) as usize;
            let slot = self.ring.add(SLOT_BASE + slot_idx * SLOT_BYTES);
            // Field offsets from the wire layout. Volatile writes
            // so an optimistic re-read from the kernel doesn't tear
            // a half-written slot.
            core::ptr::write_volatile(slot as *mut u32, tag);
            core::ptr::write_volatile(slot.add(4) as *mut u32, 0);
            core::ptr::write_volatile(slot.add(8) as *mut u32, x);
            core::ptr::write_volatile(slot.add(12) as *mut u32, y);
            core::ptr::write_volatile(slot.add(16) as *mut u32, w);
            core::ptr::write_volatile(slot.add(20) as *mut u32, h);
            core::ptr::write_volatile(slot.add(24) as *mut u32, pixel);
            core::ptr::write_volatile(slot.add(28) as *mut u32, 0);
            (*head_p).store(head.wrapping_add(1), Ordering::Release);
        }
        Ok(())
    }
}

impl Drop for FbContext {
    fn drop(&mut self) {
        // SAFETY: handle is live (we own it). Kernel will tear down
        // the ring + reap the entry. The user-VA mapping stays in
        // the address space for now; munmap of FB pages is future
        // work.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { fb_disconnect(self.handle) };
    }
}
