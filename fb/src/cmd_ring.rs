//! Wire-format draw command + SPSC ring connecting producers
//! (userspace, kernel-resident drawing tasks, future compositors)
//! to a kernel-side consumer that executes against the active
//! `FbWriter`.
//!
//! Layout note: `DrawCmd` is `#[repr(C)]` with a u32 discriminant
//! tag and inline payload fields; we cannot use Rust enums
//! (their layout is implementation-defined, and userspace +
//! kernel must see the same bytes). The whole struct is 48 bytes
//! — large enough for `TAG_BLIT`'s 64-bit shmem handle + offset +
//! stride alongside the existing FILL/FLUSH fields, and 16
//! commands × 48 bytes + the 64-byte SharedRing header still
//! fits comfortably in one 4 KiB page (832 / 4096 used).
//!
//! Pixel value is XRGB8888 packed into a u32 to match
//! `narf_graphics::Pixel32`.

use core::sync::atomic::Ordering;

use narf_ipc::shared_ring::{SharedConsumer, SharedProducer, SharedRing, TrySendError};

use crate::{FbWriteError, FbWriter, Rect};

/// Wire-stable draw-command tags.
pub const TAG_FILL: u32 = 1;
pub const TAG_FLUSH: u32 = 2;
pub const TAG_BLIT: u32 = 3;

/// 48-byte wire-format command. `tag` selects which fields are
/// meaningful; the consumer matches on it.
///
/// Field semantics by tag:
/// - `TAG_FILL`:  `(x, y, w, h)` rect; `pixel` = XRGB8888.
/// - `TAG_FLUSH`: `(x, y, w, h)` rect to push; other fields zero.
/// - `TAG_BLIT`:  `(x, y, w, h)` = dst rect on scanout;
///   `buffer` = `narf-shmem` handle owned by the
///   same pid as the connection's `FbHandle`;
///   `src_offset` = byte offset into the shmem
///   where the row-major XRGB8888 source begins;
///   `src_stride` = bytes per source row (typically
///   `w * 4`, but caller may set larger to blit a
///   sub-rect of a wider image).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DrawCmd {
    pub tag: u32,
    pub _pad: u32,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    /// XRGB8888 pixel for FILL; ignored for FLUSH/BLIT.
    pub pixel: u32,
    pub _pad2: u32,
    /// Shmem handle for BLIT; ignored for FILL/FLUSH.
    pub buffer: u64,
    /// Byte offset into the shmem buffer for BLIT.
    pub src_offset: u32,
    /// Bytes per row in the source buffer for BLIT.
    pub src_stride: u32,
}

impl core::fmt::Debug for DrawCmd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.tag {
            TAG_FILL => write!(
                f,
                "Fill {{ rect: ({},{}, {}x{}), px: {:#010x} }}",
                self.x, self.y, self.w, self.h, self.pixel
            ),
            TAG_FLUSH => write!(
                f,
                "Flush {{ rect: ({},{}, {}x{}) }}",
                self.x, self.y, self.w, self.h
            ),
            TAG_BLIT => write!(
                f,
                "Blit {{ rect: ({},{}, {}x{}), shmem: {}, off: {}, stride: {} }}",
                self.x, self.y, self.w, self.h, self.buffer, self.src_offset, self.src_stride
            ),
            _ => write!(f, "DrawCmd {{ unknown tag {:#x} }}", self.tag),
        }
    }
}

impl DrawCmd {
    pub const fn fill(rect: Rect, pixel: u32) -> Self {
        Self {
            tag: TAG_FILL,
            _pad: 0,
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
            pixel,
            _pad2: 0,
            buffer: 0,
            src_offset: 0,
            src_stride: 0,
        }
    }
    pub const fn flush(rect: Rect) -> Self {
        Self {
            tag: TAG_FLUSH,
            _pad: 0,
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
            pixel: 0,
            _pad2: 0,
            buffer: 0,
            src_offset: 0,
            src_stride: 0,
        }
    }
    pub const fn blit(rect: Rect, buffer: u64, src_offset: u32, src_stride: u32) -> Self {
        Self {
            tag: TAG_BLIT,
            _pad: 0,
            x: rect.x,
            y: rect.y,
            w: rect.w,
            h: rect.h,
            pixel: 0,
            _pad2: 0,
            buffer,
            src_offset,
            src_stride,
        }
    }
}

/// Ring depth. 16 in-flight commands is plenty for a single
/// userspace producer; future compositors will allocate one ring
/// per client.
pub const RING_DEPTH: usize = 16;

/// Concrete ring type. Sized to live in the first ~640 bytes of
/// one 4 KiB page (16 × 32 bytes + 64-byte header).
pub type DrawRing = SharedRing<DrawCmd, RING_DEPTH>;

/// In-place-initialise a 4 KiB-aligned buffer as a `DrawRing`.
/// Caller is responsible for sourcing the page (`alloc_coherent`,
/// a kernel-side static, or a userspace mmap region).
///
/// # Safety
/// `ptr` must point at zero-fillable storage of at least
/// `size_of::<DrawRing>()` bytes, 8-byte aligned.
pub unsafe fn init_in(ptr: *mut DrawRing) {
    // SAFETY: caller-asserted preconditions.
    unsafe {
        DrawRing::init_in(ptr);
    }
}

/// Construct producer + consumer halves over the same backing.
///
/// # Safety
/// `ring` must have been `init_in`-initialised; only one
/// producer + one consumer may exist per ring (SPSC contract).
pub unsafe fn split(
    ring: *mut DrawRing,
) -> (
    SharedProducer<DrawCmd, RING_DEPTH>,
    SharedConsumer<DrawCmd, RING_DEPTH>,
) {
    // SAFETY: per the fn contract `ring` was `init_in`-initialised and this is
    // the sole producer; we hand out exactly one producer half here.
    let p = unsafe { SharedProducer::from_raw(ring) };
    // SAFETY: same `init_in`-initialised `ring`; this is the sole consumer
    // half, upholding the SPSC contract.
    let c = unsafe { SharedConsumer::from_raw(ring) };
    (p, c)
}

/// Drain the consumer side, executing each command against
/// `writer`. Returns `(executed, errors)` — `errors` counts
/// commands rejected by the writer (cap revoked, OutOfBounds,
/// unknown tag).
///
/// Call from any kernel context that holds an exclusive borrow of
/// `writer` (a kernel-resident task, the boot path, an IRQ-driven
/// scheduler tick).
pub fn drain(consumer: &mut SharedConsumer<DrawCmd, RING_DEPTH>, writer: &FbWriter) -> (u32, u32) {
    let mut executed = 0u32;
    let mut errors = 0u32;
    // Loop ends when `try_recv` returns `Empty` or `Closed`.
    while let Ok(cmd) = consumer.try_recv() {
        let rect = Rect::new(cmd.x, cmd.y, cmd.w, cmd.h);
        let res: Result<(), FbWriteError> = match cmd.tag {
            TAG_FILL => writer.fill(rect, narf_graphics::Pixel32(cmd.pixel)),
            TAG_FLUSH => writer.flush(rect),
            TAG_BLIT => writer.blit_from_shmem(rect, cmd.buffer, cmd.src_offset, cmd.src_stride),
            _ => Err(FbWriteError::OutOfBounds),
        };
        if res.is_err() {
            errors += 1;
        } else {
            executed += 1;
        }
    }
    (executed, errors)
}

/// Helper for tests + producers that want to enqueue without
/// caring about the SharedProducer plumbing.
pub fn try_send(
    producer: &mut SharedProducer<DrawCmd, RING_DEPTH>,
    cmd: DrawCmd,
) -> Result<(), TrySendError<DrawCmd>> {
    producer.try_send(cmd)
}

/// Mark the ring closed from the producer side — consumer will
/// see no further commands. Useful for orderly shutdown of a
/// userspace client.
///
/// # Safety
/// `ring` must point at a live, `init_in`-initialised `DrawRing`
/// that stays valid for the duration of this call, and must be
/// invoked from the producer side only (the SPSC contract).
pub unsafe fn close(ring: *mut DrawRing) {
    // SAFETY: `closed` is at a fixed offset; safe to write any time.
    unsafe {
        (*ring).closed.store(1, Ordering::Release);
    }
}
