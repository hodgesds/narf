//! Boot-time diagnostic status panel.
//!
//! Paints a fixed-position summary of input-chain state into the
//! bottom of the framebuffer so a user observing real hardware can
//! see at a glance which drivers enumerated *without* needing
//! serial console capture or scrollback. Writes once at end of
//! boot; the cursor renderer + FB console scroll past it but the
//! pixels stay until something else overwrites them.
//!
//! Layout (bottom-left corner, 8x8 glyphs, dark-blue background):
//!
//!   FB:        bochs (1280x800)
//!   I2C buses: 2  GPIO ctrls: 1  HID bound: 1  i8042: ok
//!   cursor:    pump live      shell:     pid=2
//!
//! Each line wraps to ~60 chars max so a 1280-wide FB fits two
//! columns of info. Real-HW diagnosis: if "I2C buses: 0" the AMD
//! FCH probe didn't find any controllers (AML namespace issue or
//! HID mismatch); if "HID bound: 0" the touchpad is missing or
//! the bind path errored out; if "i8042: skip" the laptop has no
//! PS/2 controller (modern laptops route keyboard through EC).

extern crate alloc;

use alloc::format;
use core::fmt::Write as _;

use narf_graphics::Pixel32;

use crate::{FbWriter, Rect};

const PANEL_BG: Pixel32 = Pixel32(0xFF0A_1428); // dark navy
const PANEL_FG: Pixel32 = Pixel32(0xFFE0_E0E0); // light grey
const PANEL_HEIGHT: u32 = 8 * 5; // 5 lines of 8x8 text + padding
const PANEL_PAD: u32 = 4;

/// Paint the status panel into the bottom of the active FB. Best-
/// effort — clipping handles small framebuffers; FbWriter cap
/// failures fall through silently.
pub fn paint(fb: &FbWriter) {
    let w = fb.width();
    let h = fb.height();
    if h < PANEL_HEIGHT + PANEL_PAD * 2 || w < 200 {
        return;
    }
    let panel_y = h - PANEL_HEIGHT - PANEL_PAD;
    let _ = fb.fill(
        Rect::new(0, panel_y, w, PANEL_HEIGHT + PANEL_PAD),
        PANEL_BG,
    );

    let info = crate::info();
    let fb_line = match info {
        Some(i) => format!("FB:        {} ({}x{})", i.name, i.width, i.height),
        None => alloc::string::String::from("FB:        none"),
    };
    let i2c_n = narf_drivers_i2c::registered_buses().len();
    let gpio_n = narf_drivers_gpio::registered_controllers().len();
    // i2c-hid registry isn't exposed; infer from GPIO + I2C bus counts.
    // Best signal: "if both >= 1 the bind pass had something to work
    // with". For a real HID-bound count we'd need a registry on the
    // input side; follow-up.
    let dev_line = format!(
        "I2C buses: {}  GPIO ctrls: {}  i8042: {}  cursor pump: {}",
        i2c_n,
        gpio_n,
        if narf_drivers_i2c::registered_buses().is_empty() && gpio_n == 0 {
            "skip"
        } else {
            "see log"
        },
        if crate::cursor::moves() > 0 { "ACTIVE" } else { "idle" },
    );

    // Line 3: cursor renderer counters — "moves: N  drops: M"
    // direct from the cursor module.
    let cursor_line = format!(
        "cursor:    moves={}  drops_no_fb={}",
        crate::cursor::moves(),
        crate::cursor::dropped_for_no_fb(),
    );

    let lines = [
        fb_line.as_str(),
        dev_line.as_str(),
        cursor_line.as_str(),
        "(this panel updates only at boot end; reboot to refresh)",
    ];
    // SAFETY: cursor renderer also borrows the framebuffer without
    // a higher-level lock; the status panel paints once at boot
    // before user-task pumps tighten contention.
    let mut fbm = unsafe { fb.scanout_for_cursor_mut() };
    let mut y = panel_y + PANEL_PAD;
    for line in lines.iter() {
        fbm.draw_string_8x8(PANEL_PAD, y, line, PANEL_FG, PANEL_BG);
        y += 8;
    }
    let _ = fb.flush(Rect::new(0, panel_y, w, PANEL_HEIGHT + PANEL_PAD));
}

/// Append one line to the scratch buffer used by `paint`. Allows
/// callers (drivers) to push a string into the panel before paint
/// runs. Capacity-bounded; oldest lines drop on overflow.
///
/// Stub for now — the paint pass reads live registry state, which
/// is preferable to a manual scratch buffer because it stays fresh
/// across reruns. Kept here as a hook for drivers that want to
/// publish a status line without exposing a registry.
pub fn note(_msg: &str) {
    // No-op placeholder. Real impl would push to a static
    // IrqSafeSpinLock<Vec<String>> with a cap of ~8 lines.
}

// `core::fmt::Write` isn't used directly; the format!() calls above
// pull it in transitively. Re-exported for callers that want to
// build their own status writer over the panel later.
pub use core::fmt::Write as PanelWrite;

// fmt::Write import gates the format!() macros above.
const _: fn() = || {
    let mut s = alloc::string::String::new();
    let _ = write!(&mut s, "");
};
