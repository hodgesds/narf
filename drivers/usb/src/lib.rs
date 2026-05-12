//! USB host controllers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod cdc;
pub mod ehci;
pub mod ohci;
pub mod uhci;
pub mod cdc_acm;
pub mod cdc_ncm;
pub mod dfu;
pub mod hid;
pub mod hub;
pub mod msc;
pub mod uac;
pub mod uvc;
pub mod uvc_stream;
pub mod xhci;

mod tests;

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "xhci", || {
        xhci::register_pci_driver();
        InitResult::Ok
    });
    // Stage::Device runs after Stage::Subsys, so the xHCI controller
    // (probed by the bus walker once `register_pci_driver` runs) is
    // up by the time this fires. If no xHCI is present, skip.
    // One Stage::Device initcall arms the USB HID pipeline. It used
    // to be split into "keyboard" + "mouse" and each ran a one-shot
    // `enumerate_and_attach_*` plus a per-class pump task — but USB
    // device-detection lags xHCI bring-up: PORTSC.CCS for an attached
    // device hasn't necessarily flipped to 1 by the time
    // `Stage::Device` initcalls run. The result was a perfectly-
    // cabled keyboard / mouse silently NotPresent. The new shape
    // spawns one long-running supervisor task that:
    //
    //   1. retries `enumerate_and_attach_*` whenever the controller
    //      reports a port we haven't bound yet, and
    //   2. drains every already-bound device's interrupt-IN endpoint
    //      via `pump_all`, pushing translated events onto the
    //      `narf_input` global ring.
    //
    // The retry loop runs every ~16 ms (HID `bInterval` ballpark);
    // a real device that finishes its USB reset before the Nth tick
    // gets attached then. On real silicon devices typically appear
    // within ~50 ms of run-bit go.
    // Stage::Late so this runs AFTER `pci-probe-all` in
    // Stage::Device — `xhci::is_probed()` is then accurate. Per
    // the no-block-on-missing-hardware rule we early-return
    // NotPresent when no xHCI controller is bound, which avoids
    // spawning a forever-sleeping supervisor task on systems
    // without USB 3.0.
    narf_init::register(Stage::Late, "usb-hid-supervisor", || {
        if !xhci::is_probed() {
            return InitResult::NotPresent;
        }
        spawn_supervisor_task();
        InitResult::Ok
    });
    narf_init::register(Stage::Device, "usb-mass-storage", || {
        if !xhci::is_probed() {
            return InitResult::NotPresent;
        }
        let attached = xhci::with_controller(|c| msc::enumerate_and_attach_msc(c)).unwrap_or(0);
        if attached == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
}

/// Spawn the long-running USB HID supervisor task. Walks every
/// xHCI port the controller reports as connected, attempts to
/// bind a HID Boot Keyboard and Boot Mouse on each, then loops
/// pumping interrupt-IN reports onto the global input ring.
fn spawn_supervisor_task() {
    narf_scheduler::spawn(async {
        const PUMP_CYCLES: u64 = 16_000_000;
        // Cap per-port enumeration attempts. After this many
        // consecutive failures (typically all PortResetTimeout on a
        // dead USB3 port that the rate-matching hub has internally
        // routed elsewhere, OR a port whose attached device
        // genuinely doesn't speak HID), give up to stop burning
        // cycles + log noise. 8 retries × ~16 ms supervisor cadence
        // = ~125 ms of grace before we move on.
        const MAX_PER_PORT_RETRIES: u8 = 8;
        let mut irq_vector: Option<u8> = None;
        // Per-port claimed-by-keyboard / claimed-by-mouse
        // bitmasks (audit #9 fix).
        let mut claimed_kbd: u128 = 0;
        let mut claimed_mouse: u128 = 0;
        // Per-port retry counters. Indexed by port id (1..=128).
        let mut kbd_fail_count = [0u8; 128];
        let mut mouse_fail_count = [0u8; 128];
        loop {
            if !xhci::is_probed() {
                narf_time::sleep_cycles(PUMP_CYCLES).await;
                continue;
            }
            if irq_vector.is_none() {
                irq_vector = xhci::with_controller(|c| c.irq_vector).flatten();
            }
            let connected_ports: alloc::vec::Vec<u8> = xhci::with_controller(|c| {
                c.connected_ports().iter().map(|(p, _)| *p).collect()
            })
            .unwrap_or_default();
            // Audit F-87: avoid double port_reset per cycle. Each
            // try_attach_*_on_port unconditionally calls port_reset
            // and a second reset within the same cycle disturbs the
            // device's link state — some FS keyboards re-enter
            // Default state and reject the next Address Device. If
            // the kbd attach already failed on a port this cycle,
            // skip the mouse attempt; conversely if kbd already
            // claimed it, mouse skip is automatic via claimed_mouse.
            let mut tried_this_cycle: u128 = 0;
            for &p in &connected_ports {
                let bit = 1u128 << (p as u32 & 127);
                let pi = (p as usize) & 127;
                if claimed_kbd & bit == 0 && kbd_fail_count[pi] < MAX_PER_PORT_RETRIES {
                    tried_this_cycle |= bit;
                    let attached = xhci::with_controller(|c| {
                        hid::try_attach_keyboard_on_port(c, p).is_ok()
                    })
                    .unwrap_or(false);
                    if attached {
                        claimed_kbd |= bit;
                        kbd_fail_count[pi] = 0;
                    } else {
                        kbd_fail_count[pi] = kbd_fail_count[pi].saturating_add(1);
                    }
                }
                // Skip mouse if kbd was attempted this cycle (success
                // or fail) — both helpers issue their own port_reset,
                // and back-to-back resets disturb the device. The
                // alternate-class interface gets retried next tick if
                // still unclaimed.
                if claimed_mouse & bit == 0
                    && tried_this_cycle & bit == 0
                    && mouse_fail_count[pi] < MAX_PER_PORT_RETRIES
                {
                    let attached = xhci::with_controller(|c| {
                        hid::mouse::try_attach_mouse_on_port(c, p).is_ok()
                    })
                    .unwrap_or(false);
                    if attached {
                        claimed_mouse |= bit;
                        mouse_fail_count[pi] = 0;
                    } else {
                        mouse_fail_count[pi] = mouse_fail_count[pi].saturating_add(1);
                    }
                }
            }
            let _ = xhci::with_controller(|c| hid::pump_all(c));
            let _ = xhci::with_controller(|c| hid::mouse::pump_all(c));
            if let Some(v) = irq_vector {
                let _ = narf_interrupts::wait_for_irq(v).await;
            } else {
                narf_time::sleep_cycles(PUMP_CYCLES).await;
            }
        }
    });
}
