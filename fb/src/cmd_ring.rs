//! Wire-format draw command + SPSC ring connecting producers
//! (userspace, kernel-resident drawing tasks, future compositors)
//! to a kernel-side consumer that executes against the active
//! `FbWriter`.
//!
//! Layout note: `DrawCmd` is `#[repr(C)]` with a u32 discriminant
//! tag and a fixed-size payload union represented as inline fields.
//! The whole struct is 32 bytes — small enough that 16 commands
//! plus the 64-byte SharedRing header fit in the first ~640 bytes
//! of one page. Userspace and kernel see the same bytes, so we
//! cannot use `Rust` enums (their layout is implementation-defined).
//!
//! Pixel value is XRGB8888 packed into a u32 to match
//! `narf_graphics::Pixel32`.

use core::sync::atomic::Ordering;

use narf_ipc::shared_ring::{
    SharedConsumer, SharedProducer, SharedRing, TryRecvError, TrySendError,
};

use crate::{FbWriter, FbWriteError, Rect};

/// Wire-stable draw-command tags.
pub const TAG_FILL:  u32 = 1;
pub const TAG_FLUSH: u32 = 2;

/// 32-byte wire-format command. `tag` selects which fields are
/// meaningful; the consumer matches on it.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DrawCmd {
    pub tag:    u32,
    pub _pad:   u32,
    pub x:      u32,
    pub y:      u32,
    pub w:      u32,
    pub h:      u32,
    /// XRGB8888 pixel for FILL; ignored for FLUSH.
    pub pixel:  u32,
    pub _pad2:  u32,
}

impl core::fmt::Debug for DrawCmd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.tag {
            TAG_FILL  => write!(f, "Fill {{ rect: ({},{}, {}x{}), px: {:#010x} }}",
                                   self.x, self.y, self.w, self.h, self.pixel),
            TAG_FLUSH => write!(f, "Flush {{ rect: ({},{}, {}x{}) }}",
                                   self.x, self.y, self.w, self.h),
            _         => write!(f, "DrawCmd {{ unknown tag {:#x} }}", self.tag),
        }
    }
}

impl DrawCmd {
    pub const fn fill(rect: Rect, pixel: u32) -> Self {
        Self {
            tag: TAG_FILL, _pad: 0,
            x: rect.x, y: rect.y, w: rect.w, h: rect.h,
            pixel, _pad2: 0,
        }
    }
    pub const fn flush(rect: Rect) -> Self {
        Self {
            tag: TAG_FLUSH, _pad: 0,
            x: rect.x, y: rect.y, w: rect.w, h: rect.h,
            pixel: 0, _pad2: 0,
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
    unsafe { DrawRing::init_in(ptr); }
}

/// Construct producer + consumer halves over the same backing.
///
/// # Safety
/// `ring` must have been `init_in`-initialised; only one
/// producer + one consumer may exist per ring (SPSC contract).
pub unsafe fn split(ring: *mut DrawRing)
    -> (SharedProducer<DrawCmd, RING_DEPTH>, SharedConsumer<DrawCmd, RING_DEPTH>)
{
    // SAFETY: caller asserts SPSC + initialised.
    let p = unsafe { SharedProducer::from_raw(ring) };
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
pub fn drain(consumer: &mut SharedConsumer<DrawCmd, RING_DEPTH>,
             writer:   &FbWriter)
    -> (u32, u32)
{
    let mut executed = 0u32;
    let mut errors   = 0u32;
    loop {
        match consumer.try_recv() {
            Ok(cmd) => {
                let rect = Rect::new(cmd.x, cmd.y, cmd.w, cmd.h);
                let res: Result<(), FbWriteError> = match cmd.tag {
                    TAG_FILL  => writer.fill(rect, narf_graphics::Pixel32(cmd.pixel)),
                    TAG_FLUSH => writer.flush(rect),
                    _         => Err(FbWriteError::OutOfBounds),
                };
                if res.is_err() { errors += 1; } else { executed += 1; }
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
        }
    }
    (executed, errors)
}

/// Helper for tests + producers that want to enqueue without
/// caring about the SharedProducer plumbing.
pub fn try_send(producer: &mut SharedProducer<DrawCmd, RING_DEPTH>, cmd: DrawCmd)
    -> Result<(), TrySendError<DrawCmd>>
{
    producer.try_send(cmd)
}

/// Mark the ring closed from the producer side — consumer will
/// see no further commands. Useful for orderly shutdown of a
/// userspace client.
pub fn close(ring: *mut DrawRing) {
    // SAFETY: `closed` is at a fixed offset; safe to write any time.
    unsafe { (*ring).closed.store(1, Ordering::Release); }
}
