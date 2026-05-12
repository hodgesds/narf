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
/// Number of klog tail lines displayed under the live-state lines.
/// 12 fits comfortably under a 1280×800 FB while leaving room for
/// a little headroom + padding above the panel.
const KLOG_TAIL_LINES: usize = 12;
const HEADER_LINES: u32 = 4;
const PANEL_HEIGHT: u32 = 8 * (HEADER_LINES + KLOG_TAIL_LINES as u32 + 1); // header + klog tail + separator
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
    let xhci_up = narf_drivers_usb::xhci::is_probed();
    let kbd_n = narf_drivers_usb::hid::attached_keyboard_count();
    let mouse_n = narf_drivers_usb::hid::mouse::attached_mouse_count();
    let connected_ports = if xhci_up {
        narf_drivers_usb::xhci::with_controller(|c| c.connected_ports().len()).unwrap_or(0)
    } else {
        0
    };
    let dev_line = format!(
        "I2C: {}  GPIO: {}  xHCI: {}  ports: {}  kbd: {}  mouse: {}  cursor: {}",
        i2c_n,
        gpio_n,
        if xhci_up { "up" } else { "no" },
        connected_ports,
        kbd_n,
        mouse_n,
        if crate::cursor::moves() > 0 { "ACTIVE" } else { "idle" },
    );

    // Line 3: AML namespace + i2c-hid bind state. Tells us
    // whether the touchpad path even saw its target devices.
    let aml_node_count = narf_aml::node_count();
    let mut amdi001x_count = 0u32;
    for &hid in &["AMDI0010", "AMDI0019", "AMDI0510", "AMDI0011"] {
        amdi001x_count += narf_aml::find_all_devices_by_hid(hid).len() as u32;
    }
    let pnp0c50_count = narf_aml::find_all_devices_by_hid("PNP0C50").len();
    let cursor_line = format!(
        "AML: {} nodes  AMDI001x: {}  PNP0C50: {}  cursor moves: {}",
        aml_node_count,
        amdi001x_count,
        pnp0c50_count,
        crate::cursor::moves(),
    );

    // Pinned diagnostic slot for the latest xHCI Address Device
    // failure, so the user can read the exact PORTSC + USBSTS
    // values off-screen on bare-metal where serial / scrollback
    // aren't available. Empty until the first failure.
    let xhci_diag = match narf_drivers_usb::xhci::ADDR_DEV_LAST_FAIL.snapshot() {
        Some((seq, slot, port, ccode, portsc, usbsts)) => format!(
            "xhci-ad LAST: #{} slot={} port={} ccode={} PORTSC={:08x} USBSTS={:08x}",
            seq, slot, port, ccode, portsc, usbsts,
        ),
        None => alloc::string::String::from("xhci-ad LAST: (no failure)"),
    };

    let header = [
        fb_line.as_str(),
        dev_line.as_str(),
        cursor_line.as_str(),
        xhci_diag.as_str(),
    ];
    // SAFETY: cursor renderer also borrows the framebuffer without
    // a higher-level lock; the status panel paints once at boot
    // before user-task pumps tighten contention.
    let mut fbm = unsafe { fb.scanout_for_cursor_mut() };
    let mut y = panel_y + PANEL_PAD;
    for line in header.iter() {
        fbm.draw_string_8x8(PANEL_PAD, y, line, PANEL_FG, PANEL_BG);
        y += 8;
    }
    // Separator + klog tail. Truncates each line to ~150 chars so a
    // wide log line doesn't overflow the FB width (1280 / 8 = 160
    // glyphs, leaves a small margin).
    fbm.draw_string_8x8(
        PANEL_PAD,
        y,
        "--- recent log (klog tail) ----------------------------------",
        PANEL_FG,
        PANEL_BG,
    );
    y += 8;
    let max_chars = ((w - PANEL_PAD * 2) / 8) as usize;
    for line in narf_console::klog::tail(KLOG_TAIL_LINES).iter() {
        let truncated = if line.len() > max_chars {
            &line[..max_chars]
        } else {
            line.as_str()
        };
        fbm.draw_string_8x8(PANEL_PAD, y, truncated, PANEL_FG, PANEL_BG);
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
