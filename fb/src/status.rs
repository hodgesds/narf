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
/// Background used when the diag layer reports a latched panic.
/// Switching the panel to deep red makes "the kernel paniced"
/// unmissable to a bare-metal operator across the room.
const PANEL_BG_PANIC: Pixel32 = Pixel32(0xFF40_0000); // dark red
/// Number of klog tail lines displayed under the live-state lines.
/// 16 keeps recent boot output visible on a 1280×800 FB. Below
/// that height the panel self-suppresses (line 65 guard).
const KLOG_TAIL_LINES: usize = 16;
/// Number of header lines: the 5 input/USB/AML/i8042 lines PLUS
/// one diag line (boot phase + IRQ + heap + #PF/panic). Adding the
/// diag line at the top is intentional — it's the densest
/// real-HW-diagnostic line and operators read top-down.
const HEADER_LINES: u32 = 6;
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

    // Pull a coherent snapshot of the diag state BEFORE the rest
    // of the per-subsystem reads — operators care most about the
    // boot-phase / IRQ / panic line, and a coherent snapshot
    // means the diag fields don't drift across the render.
    //
    // Low-rate poll: push the kernel-heap KB into diag so the
    // snapshot has fresh numbers. The render runs at ~1.25 Hz so
    // the slab::stats() call (an N_CLASSES-long fold) is cheap.
    let heap_used_b = narf_memory::heap::used_bytes() as u64;
    let slab = narf_memory::slab::stats();
    let mut slab_in_use_b: u64 = 0;
    for c in slab.classes.iter() {
        slab_in_use_b = slab_in_use_b.saturating_add((c.in_use * c.block_size) as u64);
    }
    let used_kb = ((heap_used_b + slab_in_use_b) / 1024) as u32;
    let total_kb = (narf_memory::heap::capacity_bytes() / 1024) as u32;
    narf_memory::diag::set_heap_kb(used_kb, total_kb);
    let diag = narf_memory::diag::snapshot();

    let panel_y = h - PANEL_HEIGHT - PANEL_PAD;
    // Panic-latched: paint the panel red. A bare-metal operator
    // sees the bottom of the screen flip from navy to red at the
    // first panic — unmissable without serial.
    let bg = if diag.panic_latched {
        PANEL_BG_PANIC
    } else {
        PANEL_BG
    };
    let _ = fb.fill(Rect::new(0, panel_y, w, PANEL_HEIGHT + PANEL_PAD), bg);

    let info = crate::info();
    let fb_line = match info {
        Some(i) => format!(
            "FB: {} ({}x{})  tsc-cpns: {}",
            i.name,
            i.width,
            i.height,
            narf_time::cycles_per_ns(),
        ),
        None => format!("FB: none  tsc-cpns: {}", narf_time::cycles_per_ns(),),
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
        if crate::cursor::moves() > 0 {
            "ACTIVE"
        } else {
            "idle"
        },
    );

    // USB HID pump telemetry. All three are AtomicU32; reading
    // them never blocks on the supervisor's pump cycle.
    let usb_pumps = narf_drivers_usb::hid::PUMP_ALL_CALLS.load(Ordering::Relaxed);
    let usb_reports = narf_drivers_usb::hid::REPORTS_READ.load(Ordering::Relaxed);
    let supervisor_ticks = narf_drivers_usb::SUPERVISOR_TICKS.load(Ordering::Relaxed);
    let supervisor_phase = narf_drivers_usb::SUPERVISOR_PHASE.load(Ordering::Relaxed);
    let supervisor_port = narf_drivers_usb::SUPERVISOR_ATTACHING_PORT.load(Ordering::Relaxed);
    // Clockevent diagnostics. `primary()` returns the selected
    // tick source (LAPIC or HPET). Its tick_count is the
    // platform-agnostic "did the timer fire" signal — replaces
    // the LAPIC-specific `tt=` that misled us into thinking the
    // wheel was broken when really the LAPIC timer was just dead.
    let (clk_name, clk_ticks) = match narf_time::clockevent::primary() {
        Some(d) => (d.name(), d.tick_count()),
        None => ("none", 0u64),
    };
    let usb_hid_line = format!(
        "USB: sup={} yt={} wakes={} clk={}:{} cpns={} irq1={}",
        supervisor_ticks,
        narf_drivers_usb::YIELD_TIMEOUT_POLLS.load(Ordering::Relaxed),
        narf_scheduler::WAKE_BY_REF_CALLS.load(Ordering::Relaxed),
        clk_name,
        clk_ticks,
        narf_time::cycles_per_ns(),
        {
            let v = narf_input::I8042_KBD_IRQ_VECTOR.load(Ordering::Acquire);
            if v == 0 {
                0
            } else {
                narf_interrupts::fire_count(v)
            }
        },
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
        // IRQ1 fire count — distinguishes "EC never raised IRQ"
        // (irq1=0, push=1 — boot leftover only) from "IRQ fires but
        // handler drops" (irq1=N, push=1) from "fully working"
        // (irq1=N, push=N+1).
        let kbd_irq_vec = narf_input::I8042_KBD_IRQ_VECTOR.load(Ordering::Acquire);
        let irq1_fires = if kbd_irq_vec == 0 {
            0
        } else {
            narf_interrupts::fire_count(kbd_irq_vec)
        };
        format!(
            "input: kbd init={}/irq={}/scan={} irq1-fires={} push/pop={}/{} ascii={}/{}",
            if kbd_init { "ok" } else { "FAIL" },
            if kbd_irq { "ok" } else { "FAIL" },
            if kbd_scan { "ok" } else { "FAIL" },
            irq1_fires,
            kbd_pushes,
            kbd_pops,
            narf_input::ASCII_PUSH_COUNT.load(Ordering::Relaxed),
            narf_input::ASCII_POP_COUNT.load(Ordering::Relaxed),
        )
    };

    // Diag line: boot phase + IRQ + heap + first-PF + panic
    // marker. Designed to be parseable-by-eye on a bare-metal
    // panel — every operator-visible bring-up signal in 60-80
    // chars. Order: phase first (forward progress), then IRQ
    // (timer alive?), then heap (alloc storm?), then any latched
    // fault (CR2/panic).
    let diag_line = if diag.panic_latched {
        format!(
            "PANIC: marker={:016x} phase={} irq#{}={} heap={}/{} KB",
            diag.panic_marker,
            diag.phase.as_str(),
            diag.last_irq_vector,
            diag.irq_total,
            diag.heap_used_kb,
            diag.heap_total_kb,
        )
    } else if diag.first_pf_seen {
        format!(
            "phase={} irq#{}={} heap={}/{} KB #PF cr2={:x} rip={:x}",
            diag.phase.as_str(),
            diag.last_irq_vector,
            diag.irq_total,
            diag.heap_used_kb,
            diag.heap_total_kb,
            diag.first_pf_cr2,
            diag.first_pf_rip,
        )
    } else {
        format!(
            "phase={} irq#{}={} heap={}/{} KB",
            diag.phase.as_str(),
            diag.last_irq_vector,
            diag.irq_total,
            diag.heap_used_kb,
            diag.heap_total_kb,
        )
    };

    let header = [
        diag_line.as_str(),
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
        fbm.draw_string_8x8(PANEL_PAD, y, line, PANEL_FG, bg);
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
        bg,
    );
    y += 8;
    let max_chars = ((w - PANEL_PAD * 2) / 8) as usize;
    for line in narf_console::klog::tail(KLOG_TAIL_LINES).iter() {
        let truncated = if line.len() > max_chars {
            &line[..max_chars]
        } else {
            line.as_str()
        };
        fbm.draw_string_8x8(PANEL_PAD, y, truncated, PANEL_FG, bg);
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
