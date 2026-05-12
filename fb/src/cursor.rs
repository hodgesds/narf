//! Pointer-cursor renderer.
//!
//! Consumes `PointerEvent`s from the global input ring, accumulates
//! a cursor position (clamped to the active scanout's dimensions),
//! and draws a small sprite at that position. The pixels under the
//! sprite are saved before each draw and restored on the next move
//! so the cursor doesn't permanently overwrite whatever's beneath
//! it (FB console output, future window contents, etc).
//!
//! Why direct ring-consumption: there is no input-dispatch fan-out
//! today — the i8042/i2c-hid drivers push to a single global ring
//! that nobody else pops. This task is currently the sole consumer.
//! When a keyboard subscriber appears the right move is to split
//! the ring into per-event-class channels rather than to filter
//! here. Until then we drain everything and drop non-pointer
//! events.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_graphics::Pixel32;
use narf_input::InputEvent;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{FbWriter, Rect};

/// Sprite footprint. Keep small — every move costs `W*H` MMIO
/// writes for save + draw + (eventual) restore.
const W: u32 = 8;
const H: u32 = 12;

/// Solid-fill cursor colour (XRGB8888 white).
const CURSOR_COLOUR: Pixel32 = Pixel32(0xFFFF_FFFF);

/// Diagnostics — bumped every frame the renderer actually moves the
/// cursor or processes a button. Tests + future "is the input pipe
/// alive" probes read this.
static MOVES: AtomicU32 = AtomicU32::new(0);
static EVENTS_DROPPED_NO_FB: AtomicU32 = AtomicU32::new(0);

/// Saved-pixels buffer + last-drawn rect. `None` until the first
/// pointer event arrives — that lets us do a "first paint" cleanly
/// without restoring uninitialised data.
struct SavedRect {
    pixels: Vec<Pixel32>,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
}

static SAVED: IrqSafeSpinLock<Option<SavedRect>> = IrqSafeSpinLock::new(None);

/// Cursor logical position in pixels. Initialised at first FB-attach
/// to the centre of the scanout.
static POS_X: AtomicU32 = AtomicU32::new(u32::MAX);
static POS_Y: AtomicU32 = AtomicU32::new(u32::MAX);

/// Read the move counter — visible to smokes that exercise the
/// pump end-to-end.
pub fn moves() -> u32 {
    MOVES.load(Ordering::Acquire)
}

/// Number of pointer events dropped because no FB was active. Live
/// ISO without a working scanout still drains the ring (so it
/// doesn't fill); the counter just lets observability spot it.
pub fn dropped_for_no_fb() -> u32 {
    EVENTS_DROPPED_NO_FB.load(Ordering::Acquire)
}

/// Test-only: clear all renderer state. Hermetic isolation between
/// smokes that share the global input ring.
#[doc(hidden)]
pub fn __reset_for_test() {
    POS_X.store(u32::MAX, Ordering::Release);
    POS_Y.store(u32::MAX, Ordering::Release);
    MOVES.store(0, Ordering::Release);
    EVENTS_DROPPED_NO_FB.store(0, Ordering::Release);
    *SAVED.lock() = None;
}

/// Initialise cursor position to the FB centre (called the first
/// time we have a valid `FbWriter`).
fn init_centre(fb: &FbWriter) {
    if POS_X.load(Ordering::Relaxed) == u32::MAX {
        POS_X.store(fb.width() / 2, Ordering::Release);
        POS_Y.store(fb.height() / 2, Ordering::Release);
    }
}

/// Clamp `(x + dx, y + dy)` to `[0, max-W)`. Saturating so a wild
/// touchpad delta can't underflow into a huge unsigned position.
fn clamp_pos(cur: u32, delta: i32, max: u32, sprite: u32) -> u32 {
    let signed = cur as i64 + delta as i64;
    let upper = (max.saturating_sub(sprite)) as i64;
    if signed < 0 {
        0
    } else if signed > upper {
        upper.max(0) as u32
    } else {
        signed as u32
    }
}

/// Save the WxH region at (x,y) into a Vec for later restore.
fn snapshot(fb: &FbWriter, x: u32, y: u32) -> Vec<Pixel32> {
    let mut pixels = Vec::with_capacity((W * H) as usize);
    // SAFETY: FbWriter::new validated the cap; framebuffer() is
    // exclusive for the lifetime of `fbm`.
    let fbm = unsafe { fb.scanout_for_cursor() };
    for row in 0..H {
        for col in 0..W {
            let p = fbm
                .read_pixel(x + col, y + row)
                .unwrap_or(Pixel32(0xFF00_0000));
            pixels.push(p);
        }
    }
    pixels
}

/// Restore previously-saved pixels at their original position.
fn restore(fb: &FbWriter, save: &SavedRect) -> Result<(), crate::FbWriteError> {
    fb.blit(
        Rect::new(save.x, save.y, save.w, save.h),
        &save.pixels,
    )
}

/// Pop everything currently in the input ring, apply pointer
/// events to the cursor state, and re-draw if anything changed.
/// Idempotent on empty rings — the polling loop calls this at its
/// own cadence.
pub fn drain_and_render(fb: &FbWriter) {
    init_centre(fb);
    let mut moved = false;
    while let Some(ev) = narf_input::pop_global() {
        if let InputEvent::Pointer(p) = ev {
            let cx = POS_X.load(Ordering::Relaxed);
            let cy = POS_Y.load(Ordering::Relaxed);
            let nx = clamp_pos(cx, p.dx, fb.width(), W);
            let ny = clamp_pos(cy, p.dy, fb.height(), H);
            if nx != cx || ny != cy {
                POS_X.store(nx, Ordering::Release);
                POS_Y.store(ny, Ordering::Release);
                moved = true;
            }
            // Future: paint the click-state into the sprite. For now
            // p.buttons is observable via narf_input::pop_global by a
            // future consumer.
        }
        // Key + Scroll events are dropped here — see module doc.
    }
    if !moved {
        return;
    }
    // Snapshot-restore-then-draw cycle.
    let mut g = SAVED.lock();
    if let Some(prev) = g.take() {
        let _ = restore(fb, &prev);
    }
    let x = POS_X.load(Ordering::Relaxed);
    let y = POS_Y.load(Ordering::Relaxed);
    let saved_pixels = snapshot(fb, x, y);
    if fb.fill(Rect::new(x, y, W, H), CURSOR_COLOUR).is_ok() {
        let _ = fb.flush(Rect::new(x, y, W, H));
        *g = Some(SavedRect {
            pixels: saved_pixels,
            x,
            y,
            w: W,
            h: H,
        });
        MOVES.fetch_add(1, Ordering::Release);
    }
}

/// Cursor pump. Loops forever, pulling from the input ring + the
/// active FB writer. Falls back to silently dropping events when
/// no FB is up so the input ring never fills.
pub async fn pump(fb: FbWriter) {
    loop {
        drain_and_render(&fb);
        narf_scheduler::yield_now().await;
    }
}

/// Sleep-pump variant for the userspace `sys_sleep` busy-wait,
/// matching the FB-drain pump pattern. Reads the boot-cached
/// writer; callable as a `fn()` from the syscall path.
pub fn sleep_pump_tick() {
    if let Some(fb) = crate::pump_writer_ref() {
        drain_and_render(fb);
    } else {
        // Drain anyway so the input ring doesn't fill while we wait
        // for an FB to come up.
        while let Some(ev) = narf_input::pop_global() {
            if matches!(ev, InputEvent::Pointer(_)) {
                EVENTS_DROPPED_NO_FB.fetch_add(1, Ordering::Release);
            }
        }
    }
}
