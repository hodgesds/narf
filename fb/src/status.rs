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

use narf_graphics::Pixel32;

use crate::{FbWriter, Rect};

const PANEL_BG: Pixel32 = Pixel32(0xFF0A_1428); // dark navy
const PANEL_FG: Pixel32 = Pixel32(0xFFE0_E0E0); // light grey
/// Number of klog tail lines displayed under the live-state lines.
/// 12 fits comfortably under a 1280×800 FB while leaving room for
/// a little headroom + padding above the panel.
const KLOG_TAIL_LINES: usize = 12;
const HEADER_LINES: u32 = 5;
const PANEL_HEIGHT: u32 = 8 * (HEADER_LINES + KLOG_TAIL_LINES as u32 + 1); // header + klog tail + separator
const PANEL_PAD: u32 = 4;

/// Paint the status panel into the bottom of the active FB. Best-
/// effort — clipping handles small framebuffers; FbWriter cap
/// failures fall through silently.
///
/// LOCK-FREE: every value rendered here is read from an atomic
/// snapshot maintained by the subsystem that owns the data. No
/// `IrqSafeSpinLock` is acquired across the paint. Rationale: a
/// previous version (registry::list, with_controller, AML walks,
/// power-source method calls) deadlocked on real silicon — drivers
/// hold their registries' locks for tens of ms during MMIO, and
/// IrqSafeSpinLock disables IF on the waiter, so the executor's
/// entire CPU froze.
///
/// Trade-off: the paint shows less DETAIL than before (e.g. we
/// drop per-battery percent, per-thermal-zone temps, xHCI
/// connected-port count). Those need refreshable snapshots that
/// subsystems publish; until they do, the paint omits them rather
/// than risk wedging the system. The COUNTERS that ARE shown are
/// the most useful diagnostic signal for input bring-up (kbd /
/// mouse / pump / report / key-push counts).
pub fn paint(fb: &FbWriter) {
    use core::sync::atomic::Ordering;
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

    // All counts are atomic loads — no registry / namespace /
    // controller locks held during paint.
    let i2c_n = narf_drivers_i2c::registered_bus_count();
    let gpio_n = narf_drivers_gpio::registered_controller_count();
    let xhci_up = narf_drivers_usb::xhci::is_probed();
    let kbd_n = narf_drivers_usb::hid::ATTACHED_KEYBOARD_COUNT.load(Ordering::Acquire);
    let mouse_n = narf_drivers_usb::hid::mouse::ATTACHED_MOUSE_COUNT.load(Ordering::Acquire);
    let dev_line = format!(
        "I2C: {}  GPIO: {}  xHCI: {}  kbd: {}  mouse: {}  cursor: {}",
        i2c_n,
        gpio_n,
        if xhci_up { "up" } else { "no" },
        kbd_n,
        mouse_n,
        if crate::cursor::moves() > 0 { "ACTIVE" } else { "idle" },
    );

    // USB HID pump telemetry. All three are AtomicU32; reading
    // them never blocks on the supervisor's pump cycle.
    let usb_pumps = narf_drivers_usb::hid::PUMP_ALL_CALLS.load(Ordering::Relaxed);
    let usb_reports = narf_drivers_usb::hid::REPORTS_READ.load(Ordering::Relaxed);
    let supervisor_ticks = narf_drivers_usb::SUPERVISOR_TICKS.load(Ordering::Relaxed);
    let supervisor_phase = narf_drivers_usb::SUPERVISOR_PHASE.load(Ordering::Relaxed);
    let supervisor_port = narf_drivers_usb::SUPERVISOR_ATTACHING_PORT.load(Ordering::Relaxed);
    let usb_hid_line = format!(
        "USB-HID: sup-ticks={} ph={} port={}  pumps={}  reports={}  keys={}",
        supervisor_ticks,
        supervisor_phase,
        supervisor_port,
        usb_pumps,
        usb_reports,
        narf_input::KEY_PUSH_COUNT.load(Ordering::Relaxed),
    );

    // AML namespace + i2c-hid HID counts: ALL from the boot-time
    // snapshot atomics. The previous version called
    // find_all_devices_by_hid 5 times — each call took
    // NAMESPACE.lock and cloned every device path. capture_boot_snapshot
    // now computes these once at boot under a single lock and
    // exposes the counts as atomics.
    let (aml_nodes, _aml_devices) = narf_aml::boot_snapshot();
    let amdi001x_count = narf_aml::boot_amdi001x_count();
    let pnp0c50_count = narf_aml::boot_pnp0c50_count();
    let amdi_children = narf_aml::boot_amdi_children_count();
    let i2c_hid_line = format!(
        "AML: {} nodes  AMDI001x: {} (children: {})  PNP0C50: {}",
        aml_nodes, amdi001x_count, amdi_children, pnp0c50_count,
    );

    // i8042 + KEY_RING traffic — all atomics already.
    let i8042_diag = {
        let kbd_init = narf_input::I8042_KBD_INIT_OK.load(Ordering::Acquire);
        let kbd_irq = narf_input::I8042_KBD_IRQ_ROUTED.load(Ordering::Acquire);
        let kbd_scan = narf_input::I8042_KBD_SCANNING_OK.load(Ordering::Acquire);
        let kbd_pushes = narf_input::KEY_PUSH_COUNT.load(Ordering::Relaxed);
        let kbd_pops = narf_input::KEY_POP_COUNT.load(Ordering::Relaxed);
        let ascii_pushes = narf_input::ASCII_PUSH_COUNT.load(Ordering::Relaxed);
        let ascii_pops = narf_input::ASCII_POP_COUNT.load(Ordering::Relaxed);
        format!(
            "input: kbd init={}/irq={}/scan={} key push/pop={}/{} ascii={}/{}",
            if kbd_init { "ok" } else { "FAIL" },
            if kbd_irq { "ok" } else { "FAIL" },
            if kbd_scan { "ok" } else { "FAIL" },
            kbd_pushes,
            kbd_pops,
            ascii_pushes,
            ascii_pops,
        )
    };

    let header = [
        fb_line.as_str(),
        dev_line.as_str(),
        usb_hid_line.as_str(),
        i2c_hid_line.as_str(),
        i8042_diag.as_str(),
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
