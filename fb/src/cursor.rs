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
    // SAFETY: Valid memory or trusted environment
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
    fb.blit(Rect::new(save.x, save.y, save.w, save.h), &save.pixels)
}

/// Drain the Pointer event ring, apply each event to the cursor
/// state, and re-draw the sprite if anything moved. Per-class
/// rings (audit #6) mean we no longer need the re-push hack —
/// Key / AsciiByte / Scroll go to their own consumers via
/// `narf_input::pop_key` / `pop_ascii_byte` / `pop_scroll`.
pub fn drain_and_render(fb: &FbWriter) {
    init_centre(fb);
    // Publish the live scanout size so the absolute-pointer driver
    // (virtio-tablet) maps each axis onto its true on-screen extent
    // instead of a square nominal span (which stretches the shorter axis).
    narf_input::set_scanout_dims(fb.width(), fb.height());
    let mut moved = false;
    // Bound the drain by ring capacity (256) so a producer that's
    // outpacing us doesn't trap the loop.
    for _ in 0..256 {
        let p = match narf_input::pop_pointer() {
            Some(p) => p,
            None => break,
        };
        let cx = POS_X.load(Ordering::Relaxed);
        let cy = POS_Y.load(Ordering::Relaxed);
        let nx = clamp_pos(cx, p.dx, fb.width(), W);
        let ny = clamp_pos(cy, p.dy, fb.height(), H);
        if nx != cx || ny != cy {
            POS_X.store(nx, Ordering::Release);
            POS_Y.store(ny, Ordering::Release);
            moved = true;
        }
        // p.buttons is dropped on the floor — future click
        // handling will read PointerButtons from the same channel.
    }
    // An absolute pointer (virtio-tablet) publishes a true screen position;
    // prefer it over the relative accumulation so the cursor sits exactly under
    // the host pointer (no origin drift). Clamp the sprite fully on-screen.
    if let Some((ax, ay)) = narf_input::cursor_abs_px() {
        let nx = ax.min(fb.width().saturating_sub(W));
        let ny = ay.min(fb.height().saturating_sub(H));
        if nx != POS_X.load(Ordering::Relaxed) || ny != POS_Y.load(Ordering::Relaxed) {
            POS_X.store(nx, Ordering::Release);
            POS_Y.store(ny, Ordering::Release);
            moved = true;
        }
    }
    // A userspace compositor owns the scanout. Don't paint the kernel
    // console sprite over the desktop — but DO render the compositor's
    // own pointer from the DRM cursor-ioctl state. weston (drm-backend)
    // sets the cursor via DRM_IOCTL_MODE_CURSOR; without a HW cursor
    // plane the move is otherwise a no-op and the pointer is invisible.
    // render_user_cursor short-circuits when nothing changed, so it's
    // cheap to call every pump tick.
    if narf_console::fb_user_owned() {
        render_user_cursor(fb);
        return;
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

// ---------------------------------------------------------------------------
// Compositor ("user") cursor.
//
// A userspace compositor (weston drm-backend) owns the scanout and draws its
// own UI, but it expects the kernel/HW to draw the pointer via the DRM cursor
// ioctl (DRM_IOCTL_MODE_CURSOR{,2}). NARF synthesises a single CRTC with no
// real hardware cursor plane, so the DRM bridge funnels the cursor state here
// and we composite a sprite onto the scanout ourselves — same snapshot /
// restore discipline as the console cursor, just driven by ioctl state instead
// of the global pointer ring, and active *while* the FB is user-owned.
// ---------------------------------------------------------------------------

/// Arrow sprite footprint.
const ARROW_W: u32 = 12;
const ARROW_H: u32 = 19;

/// Left-tip pointer arrow as a row-major bitmap. Bit `c` (LSB = leftmost
/// column) set ⇒ draw a white pixel; clear ⇒ transparent (background shows
/// through). A solid wedge with a short tail — recognisable as a pointer
/// without needing per-pixel alpha.
const ARROW_FILL: [u16; ARROW_H as usize] = [
    0b0000_0000_0001,
    0b0000_0000_0011,
    0b0000_0000_0111,
    0b0000_0000_1111,
    0b0000_0001_1111,
    0b0000_0011_1111,
    0b0000_0111_1111,
    0b0000_1111_1111,
    0b0001_1111_1111,
    0b0011_1111_1111,
    0b0000_0111_1111,
    0b0000_0111_0011,
    0b0000_0010_0011,
    0b0000_0000_0011,
    0b0000_0000_0001,
    0,
    0,
    0,
    0,
];

/// Renderer-private state. The cursor *position / visibility* lives in
/// `narf_console` (the neutral crate the DRM bridge and this renderer share);
/// here we only track the saved background under the last-drawn sprite and
/// the last position we drew at (to skip redundant redraws of an idle
/// pointer).
static USER_SAVED: IrqSafeSpinLock<Option<SavedRect>> = IrqSafeSpinLock::new(None);
static USER_LAST_X: AtomicU32 = AtomicU32::new(u32::MAX);
static USER_LAST_Y: AtomicU32 = AtomicU32::new(u32::MAX);

/// Render the pointer over a user-owned (compositor) scanout. When the
/// compositor drives the cursor through the DRM cursor ioctl we honour its
/// position + visibility; otherwise we fall back to the kernel pointer
/// position accumulated from the global input ring, so the user still gets a
/// tracking pointer even when the compositor's own input path isn't wired up
/// (e.g. weston failing to create its libinput devices).
fn render_user_cursor(fb: &FbWriter) {
    let (ux, uy, visible, managed) = narf_console::user_cursor_state();
    if managed {
        if visible {
            render_cursor_at(fb, ux, uy);
        } else {
            erase_cursor(fb);
        }
    } else {
        // Fall back to the global-ring pointer position. POS_X/POS_Y is
        // u32::MAX until the first event / FB-attach centring.
        let x = POS_X.load(Ordering::Relaxed);
        let y = POS_Y.load(Ordering::Relaxed);
        if x != u32::MAX {
            render_cursor_at(fb, x, y);
        }
    }
}

/// Erase the currently-drawn cursor sprite (restore the saved background).
fn erase_cursor(fb: &FbWriter) {
    let mut g = USER_SAVED.lock();
    if let Some(prev) = g.take() {
        let _ = restore(fb, &prev);
    }
    USER_LAST_X.store(u32::MAX, Ordering::Release);
    USER_LAST_Y.store(u32::MAX, Ordering::Release);
}

/// Composite the arrow sprite at `(ux, uy)` onto the scanout, snapshotting
/// the pixels underneath so the next move can restore them. No-op when the
/// sprite is already drawn at that position (idle pointer = zero MMIO).
fn render_cursor_at(fb: &FbWriter, ux: u32, uy: u32) {
    // Clamp the sprite box fully on-screen.
    let x = ux.min(fb.width().saturating_sub(ARROW_W));
    let y = uy.min(fb.height().saturating_sub(ARROW_H));
    if USER_LAST_X.load(Ordering::Acquire) == x && USER_LAST_Y.load(Ordering::Acquire) == y {
        return;
    }

    let mut g = USER_SAVED.lock();
    // Erase the previous sprite first.
    if let Some(prev) = g.take() {
        let _ = restore(fb, &prev);
    }

    // Snapshot the background under the new box, then overlay the arrow.
    let mut buf = {
        // SAFETY: same exclusivity contract as snapshot() above.
        // SAFETY: Valid memory or trusted environment
        let fbm = unsafe { fb.scanout_for_cursor() };
        let mut v = Vec::with_capacity((ARROW_W * ARROW_H) as usize);
        for row in 0..ARROW_H {
            for col in 0..ARROW_W {
                v.push(
                    fbm.read_pixel(x + col, y + row)
                        .unwrap_or(Pixel32(0xFF00_0000)),
                );
            }
        }
        v
    };
    let saved_pixels = buf.clone();
    for row in 0..ARROW_H {
        let fill = ARROW_FILL[row as usize];
        for col in 0..ARROW_W {
            if (fill >> col) & 1 != 0 {
                buf[(row * ARROW_W + col) as usize] = CURSOR_COLOUR;
            }
        }
    }
    if fb.blit(Rect::new(x, y, ARROW_W, ARROW_H), &buf).is_ok() {
        let _ = fb.flush(Rect::new(x, y, ARROW_W, ARROW_H));
        *g = Some(SavedRect {
            pixels: saved_pixels,
            x,
            y,
            w: ARROW_W,
            h: ARROW_H,
        });
        USER_LAST_X.store(x, Ordering::Release);
        USER_LAST_Y.store(y, Ordering::Release);
        MOVES.fetch_add(1, Ordering::Release);
    }
}

/// Cycle period between cursor pump passes. ~50M @ 3.3 GHz ≈
/// 15 ms ≈ 60 Hz — the cursor refresh rate any eye can
/// distinguish. Timer-driven sleep (not `yield_now`) so other
/// tasks (init / shell / driver pumps) get full slices between
/// frames. The old `yield_now` pattern busy-looped on QEMU's
/// fast scheduler interleaving and starved init on real HW
/// where MMIO + AML walks made each drain noticeably costlier.
const PUMP_PERIOD_CYCLES: u64 = 50_000_000;

/// Cursor pump. Loops forever, pulling from the input ring + the
/// active FB writer, then sleeping. Falls back to silently
/// dropping events when no FB is up so the input ring never
/// fills.
pub async fn pump(fb: FbWriter) {
    loop {
        drain_and_render(&fb);
        narf_time::sleep_cycles(PUMP_PERIOD_CYCLES).await;
    }
}

/// Sleep-pump variant for the userspace `sys_sleep` busy-wait,
/// matching the FB-drain pump pattern. Reads the boot-cached
/// writer; callable as a `fn()` from the syscall path.
pub fn sleep_pump_tick() {
    if let Some(fb) = crate::pump_writer_ref() {
        drain_and_render(fb);
    } else {
        // Drain pointer events anyway so the per-class ring
        // doesn't fill while we wait for an FB to come up.
        while narf_input::pop_pointer().is_some() {
            EVENTS_DROPPED_NO_FB.fetch_add(1, Ordering::Release);
        }
    }
}
