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
    // No `usb-hid-supervisor` initcall: the supervisor is spawned
    // by `spawn_usb_hid_supervisor()` from bare_main *after* the
    // second `narf_scheduler::init()`. That init wipes the ready
    // queue for hermetic test isolation; a task spawned here would
    // be silently dropped (same shape as fb-cursor-pump).
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
///
/// Called by bare_main *after* the second `narf_scheduler::init()`
/// so the spawn survives — the Stage::Late initcall point is too
/// early because that init wipes the ready queue.
///
/// No-op (returns false) when no xHCI controller has probed.
pub fn spawn_usb_hid_supervisor() -> bool {
    if !xhci::is_probed() {
        return false;
    }
    narf_scheduler::spawn(async {
        const PUMP_CYCLES: u64 = 16_000_000;
        let mut irq_vector: Option<u8> = None;
        // Per-port claimed-by-keyboard / claimed-by-mouse
        // bitmasks (audit #9 fix).
        let mut claimed_kbd: u128 = 0;
        let mut claimed_mouse: u128 = 0;
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
            for &p in &connected_ports {
                let bit = 1u128 << (p as u32 & 127);
                if claimed_kbd & bit == 0 {
                    let attached = xhci::with_controller(|c| {
                        hid::try_attach_keyboard_on_port(c, p).is_ok()
                    })
                    .unwrap_or(false);
                    if attached {
                        claimed_kbd |= bit;
                    }
                }
                if claimed_mouse & bit == 0 {
                    let attached = xhci::with_controller(|c| {
                        hid::mouse::try_attach_mouse_on_port(c, p).is_ok()
                    })
                    .unwrap_or(false);
                    if attached {
                        claimed_mouse |= bit;
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
    true
}
