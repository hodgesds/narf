//! Boot-progress beacons — small colored squares painted directly to
//! framebuffer phys memory at well-known boot waypoints. Useful for
//! diagnosing real-HW bring-up failures where serial isn't available
//! and the kernel never reaches a state where a real FB console is up.
//!
//! Lives in `narf-memory` because it's the lowest-level crate every
//! other one depends on; that lets *any* boot-time code (including
//! `mmu::init_mmu` itself) paint without a circular dep on
//! `narf-graphics` / `narf-fb`.
//!
//! Slot geometry: 32 × 16 pixels with a 4 px gap, drawn left-to-right
//! at the top of the FB. Slots stack horizontally; expect 32 to fit
//! in a 1024-px-wide FB.
//!
//! Phys-write only; no allocator, no MMU dep beyond the early identity
//! map (currently 4 GiB; see `frame/src/x86_64/boot.S`). Skips
//! silently if no FB is registered or the FB phys is above the
//! caller's identity-map cap.
//!
//! ## Slot reservation conventions
//!
//! Reserve slots so different stages don't overpaint each other.
//! Current usage:
//!
//! | slot | color    | meaning                              |
//! |------|----------|--------------------------------------|
//! |   0  | RED      | _start_rust entered                  |
//! |   1  | ORANGE   | UART early init done                 |
//! |   2  | PURPLE   | pre-parse_raw                        |
//! |   3  | BLUE     | parse_raw returned (Ok or Err)       |
//! |   4  | YELLOW   | parse_raw Ok branch                  |
//! |   5  | WHITE    | parse_raw Err branch                 |
//! |   6  | GREEN    | frame allocator init done            |
//! |   7  | CYAN     | MMU init done                        |
//! |   8  | DIM RED  | pre-init_mmu                         |
//! |   9  | DIM GRN  | post-init_mmu (CR3 swapped)          |
//! |  10  | DIM CYN  | mmu::alloc page tables               |
//! |  11  | DIM YEL  | mmu::populate identity 0..4 GiB      |
//! |  12  | DIM ORG  | mmu::populate hi-MMIO                |
//! |  13  | DIM MAG  | mmu::populate higher-half            |
//! |  14  | DIM WHT  | mmu::write_cr3 reached               |
//! |  15  | LIME     | ACPI parsed                          |
//! |  16  | TEAL     | SMP brought up                       |
//! |  17  | PINK     | initcalls Stage::Subsys done         |
//! |  18  | GOLD     | initcalls Stage::Device done         |
//! |  19  | SKY      | initcalls Stage::Late done           |
//! |  20  | LAVENDER | userspace spawn requested            |

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static FB_PHYS: AtomicU64 = AtomicU64::new(0);
static FB_STRIDE_PX: AtomicU32 = AtomicU32::new(0);
static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);

/// Cap on the phys address we'll write to. Set by the registrar to
/// match the caller's identity-map ceiling (usually 4 GiB during
/// early boot).
static FB_PHYS_CEILING: AtomicU64 = AtomicU64::new(0);

/// Register the framebuffer that beacons paint into. After this,
/// `paint(slot, color)` writes to `phys_addr`. Idempotent — last
/// caller wins. `phys_ceiling` should be the caller's identity-map
/// upper bound (the beacon will skip writes that fall above this).
///
/// Pass `stride_px` in PIXELS per row, not bytes.
pub fn register(phys_addr: u64, stride_px: u32, width: u32, height: u32, phys_ceiling: u64) {
    FB_PHYS.store(phys_addr, Ordering::Release);
    FB_STRIDE_PX.store(stride_px, Ordering::Release);
    FB_WIDTH.store(width, Ordering::Release);
    FB_HEIGHT.store(height, Ordering::Release);
    FB_PHYS_CEILING.store(phys_ceiling, Ordering::Release);
}

/// Diagnostic accessor: raw FB phys for direct-write debugging.
#[doc(hidden)]
pub fn __fb_phys() -> u64 {
    FB_PHYS.load(Ordering::Acquire)
}

/// Diagnostic accessor: stride in pixels.
#[doc(hidden)]
pub fn __fb_stride() -> u32 {
    FB_STRIDE_PX.load(Ordering::Acquire)
}

/// Paint a HUGE diagonal stripe across the FB — a build-marker
/// of last resort. Covers the top 32 px × 1024 px so it's
/// impossible to mistake for any per-slot beacon. Use a single
/// distinctive color and bump it across builds to prove the
/// running kernel matches what was just compiled.
pub fn paint_build_stripe(color: u32) {
    let phys = FB_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    let stride = FB_STRIDE_PX.load(Ordering::Acquire) as u64;
    let width = FB_WIDTH.load(Ordering::Acquire);
    let height = FB_HEIGHT.load(Ordering::Acquire);
    let h: u32 = 32;
    let y_max = h.min(height);
    let x_max = width;
    let base = phys as *mut u32;
    for y in 0..y_max {
        for x in 0..x_max {
            let off = (y as u64) * stride + (x as u64);
            // SAFETY: registrar asserts FB phys is identity-mapped
            // and writable; bounds checked above.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                base.add(off as usize).write_volatile(color);
            }
        }
    }
}

/// Paint a colored square at horizontal slot `slot_idx`, ROW
/// `row_idx`. Each row is 20 px tall (16 px square + 4 px gap)
/// so up to ~38 rows fit in a 768-px-tall FB.
#[inline(never)]
pub fn paint_at(slot_idx: u32, row_idx: u32, color: u32) {
    let phys = FB_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    let ceiling = FB_PHYS_CEILING.load(Ordering::Acquire);
    if ceiling != 0 && phys >= ceiling {
        return;
    }
    let stride = FB_STRIDE_PX.load(Ordering::Acquire) as u64;
    let width = FB_WIDTH.load(Ordering::Acquire);
    let height = FB_HEIGHT.load(Ordering::Acquire);
    let slot_w: u32 = 32;
    let slot_h: u32 = 16;
    let gap: u32 = 4;
    let row_pitch: u32 = slot_h + gap;
    let x0 = slot_idx * (slot_w + gap);
    let y0 = row_idx * row_pitch;
    if x0 >= width || y0 >= height {
        return;
    }
    let x1 = (x0 + slot_w).min(width);
    let y1 = (y0 + slot_h).min(height);
    let base = phys as *mut u32;
    for y in y0..y1 {
        for x in x0..x1 {
            let off = (y as u64) * stride + (x as u64);
            // SAFETY: registrar asserts FB phys is identity-mapped
            // and writable; bounds checked above.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                base.add(off as usize).write_volatile(color);
            }
        }
    }
    // Note: previously had SFENCE here to flush WC buffers, but
    // that wasn't the actual bug and removing it doesn't matter.
}

/// Paint a vertical bar inside slot `(slot_idx, row_idx)` whose
/// height (1..=16 px) encodes a hex nibble. The whole 32×16 slot is
/// cleared to `bg` first, then a 32-wide bar `nibble+1` px tall is
/// drawn in `fg` flush against the slot's BOTTOM. Read across a row
/// of nibble bars like a histogram: 0 = thin sliver, F = full slot.
///
/// Font-free by design — works on any FB the firmware handed us,
/// regardless of console font scaling / GTK pixel-doubling /
/// whatever else might make text unreadable on the target panel.
#[inline(never)]
pub fn paint_nibble(slot_idx: u32, row_idx: u32, nibble: u8, fg: u32, bg: u32) {
    let phys = FB_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    let ceiling = FB_PHYS_CEILING.load(Ordering::Acquire);
    if ceiling != 0 && phys >= ceiling {
        return;
    }
    let stride = FB_STRIDE_PX.load(Ordering::Acquire) as u64;
    let width = FB_WIDTH.load(Ordering::Acquire);
    let height = FB_HEIGHT.load(Ordering::Acquire);
    let slot_w: u32 = 32;
    let slot_h: u32 = 16;
    let gap: u32 = 4;
    let row_pitch: u32 = slot_h + gap;
    let x0 = slot_idx * (slot_w + gap);
    let y0 = row_idx * row_pitch;
    if x0 >= width || y0 >= height {
        return;
    }
    let x1 = (x0 + slot_w).min(width);
    let y1 = (y0 + slot_h).min(height);
    let nib = (nibble & 0xF) as u32 + 1; // 1..=16, never empty
    let bar_top = y1.saturating_sub(nib);
    let base = phys as *mut u32;
    for y in y0..y1 {
        let row_color = if y >= bar_top { fg } else { bg };
        for x in x0..x1 {
            let off = (y as u64) * stride + (x as u64);
            // SAFETY: bounds checked against width/height/stride above;
            // FB is identity-mapped per registrar contract.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                base.add(off as usize).write_volatile(row_color);
            }
        }
    }
}

/// Paint an 8×8 monochrome glyph, scaled 2×, at exact pixel
/// coordinates `(px_x, px_y)`. The glyph format matches
/// `narf-graphics::font8x8::lookup` output: byte `n` is row `n`
/// (top→bottom), bit 7 is the leftmost pixel of that row.
///
/// `fg` painted where the glyph bit is set, `bg` elsewhere. The
/// 2× scale (16×16 final pixels) gives enough on-screen real
/// estate to read hex digits comfortably even on a 1920-wide
/// FB seen from across the room. Caller-driven layout — beacon
/// doesn't enforce any per-character spacing, just put each
/// glyph 18 px apart (16 px char + 2 px gap) or whatever you
/// like.
///
/// Lives here (rather than in graphics) so the trap handler can
/// paint hex diagnostics without depending on the FB console
/// being up. Same skipping-when-FB-not-registered behaviour as
/// the rest of beacon.
#[inline(never)]
pub fn paint_glyph_2x_at(px_x: u32, px_y: u32, glyph: &[u8; 8], fg: u32, bg: u32) {
    let phys = FB_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    let ceiling = FB_PHYS_CEILING.load(Ordering::Acquire);
    if ceiling != 0 && phys >= ceiling {
        return;
    }
    let stride = FB_STRIDE_PX.load(Ordering::Acquire) as u64;
    let width = FB_WIDTH.load(Ordering::Acquire);
    let height = FB_HEIGHT.load(Ordering::Acquire);
    if px_x + 16 > width || px_y + 16 > height {
        return;
    }
    let base = phys as *mut u32;
    for row in 0..8u32 {
        let bits = glyph[row as usize];
        for dy in 0..2u32 {
            let y = px_y + row * 2 + dy;
            for col in 0..8u32 {
                let on = (bits >> (7 - col)) & 1 != 0;
                let color = if on { fg } else { bg };
                for dx in 0..2u32 {
                    let x = px_x + col * 2 + dx;
                    let off = (y as u64) * stride + (x as u64);
                    // SAFETY: bounds checked above; FB phys is
                    // identity-mapped per the registrar contract.
                    // SAFETY: Valid memory or trusted environment
                    unsafe {
                        base.add(off as usize).write_volatile(color);
                    }
                }
            }
        }
    }
}

/// Paint `value` as 16 hex nibbles, MS-first, starting at
/// `(start_slot, row_idx)`. Adjacent bytes alternate `fg_even` /
/// `fg_odd` so you can group nibble-pairs visually without counting
/// slots. Wraps `paint_nibble` for each nibble; same legibility
/// properties.
pub fn paint_u64_hex(
    start_slot: u32,
    row_idx: u32,
    value: u64,
    fg_even: u32,
    fg_odd: u32,
    bg: u32,
) {
    for i in 0..16u32 {
        let shift = 60 - (i * 4);
        let nib = ((value >> shift) & 0xF) as u8;
        // Byte index = i/2; alternate fg per byte. So nibbles within
        // one byte share a color, adjacent bytes contrast.
        let fg = if (i / 2) & 1 == 0 { fg_even } else { fg_odd };
        paint_nibble(start_slot + i, row_idx, nib, fg, bg);
    }
}

/// Paint a colored square at horizontal slot `slot_idx` (top of FB).
/// 32 × 16 px with 4 px gap; up to 32 slots in a 1024-px-wide FB.
/// Skips silently if no FB is registered or the FB phys exceeds the
/// registered ceiling.
#[inline(never)]
pub fn paint(slot_idx: u32, color: u32) {
    let phys = FB_PHYS.load(Ordering::Acquire);
    if phys == 0 {
        return;
    }
    let ceiling = FB_PHYS_CEILING.load(Ordering::Acquire);
    if ceiling != 0 && phys >= ceiling {
        return;
    }
    let stride = FB_STRIDE_PX.load(Ordering::Acquire) as u64;
    let width = FB_WIDTH.load(Ordering::Acquire);
    let height = FB_HEIGHT.load(Ordering::Acquire);
    let slot_w: u32 = 32;
    let slot_h: u32 = 16;
    let gap: u32 = 4;
    let x0 = slot_idx * (slot_w + gap);
    if x0 >= width {
        return;
    }
    let x1 = (x0 + slot_w).min(width);
    let y_max = slot_h.min(height);
    let base = phys as *mut u32;
    for y in 0..y_max {
        for x in x0..x1 {
            let off = (y as u64) * stride + (x as u64);
            // SAFETY: registrar asserts FB phys is identity-mapped
            // and writable; bounds checked above.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                base.add(off as usize).write_volatile(color);
            }
        }
    }
}
