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
    narf_init::register(Stage::Device, "usb-hid-supervisor", || {
        // Spawn unconditionally — the supervisor's poll loop picks
        // up xHCI as soon as it probes (Stage::Device's
        // `pci-probe-all` runs after this initcall in registration
        // order). The body short-circuits while `is_probed()` is
        // false so we don't burn cycles on every tick.
        narf_scheduler::spawn(async {
            // ~16 ms at 1 GHz. Calibration drifts the actual cadence
            // up to ~5 ms on faster TSCs but the device-side report
            // queue absorbs that. Used as a fallback when the
            // controller didn't expose MSI-X (no enable_msix path)
            // or as a hot-plug poll bound when MSI-X is live (port
            // arrivals don't generate xHCI events on their own —
            // PORTSC needs to be sampled).
            const PUMP_CYCLES: u64 = 16_000_000;
            // Snapshot the controller's MSI-X vector once on first
            // probe; if present, the pump replaces its sleep with
            // `wait_for_irq(v)` so HID drains happen on demand
            // instead of every 16 ms. Falls through to sleep cadence
            // when MSI-X bring-up failed (no MSI-X cap, etc.).
            let mut irq_vector: Option<u8> = None;
            // Track how many keyboards / mice we've already attached
            // so the retry-attach call only walks ports we haven't
            // claimed. Using `>` here means "more ports may have
            // shown up" — `enumerate_and_attach_*` is idempotent for
            // already-bound devices today (it tries port_reset which
            // succeeds twice), so the retry is benign even when the
            // count hasn't changed; a future port-mask snapshot
            // would tighten this.
            let mut last_kbd = 0usize;
            let mut last_mouse = 0usize;
            loop {
                if !xhci::is_probed() {
                    narf_time::sleep_cycles(PUMP_CYCLES).await;
                    continue;
                }
                // First-time vector snapshot once xHCI is probed.
                if irq_vector.is_none() {
                    irq_vector = xhci::with_controller(|c| c.irq_vector).flatten();
                }
                // Look for newly-arrived devices on every tick.
                if let Some(connected) =
                    xhci::with_controller(|c| c.connected_ports().len())
                {
                    if connected > last_kbd {
                        last_kbd = xhci::with_controller(|c| {
                            hid::enumerate_and_attach_keyboards(c)
                        })
                        .unwrap_or(0)
                        .max(last_kbd);
                    }
                    if connected > last_mouse {
                        last_mouse = xhci::with_controller(|c| {
                            hid::mouse::enumerate_and_attach_mice(c)
                        })
                        .unwrap_or(0)
                        .max(last_mouse);
                    }
                }
                // Drain whatever we've bound.
                let _ = xhci::with_controller(|c| hid::pump_all(c));
                let _ = xhci::with_controller(|c| hid::mouse::pump_all(c));
                // IRQ-driven wake when MSI-X is live. We still cap
                // the wait at PUMP_CYCLES so port hot-plug (which
                // doesn't fire an xHCI event) gets re-sampled even
                // when no HID activity is happening. wait_for_irq
                // returns immediately if a fire happened since the
                // baseline snapshot, so a busy keyboard won't park.
                if let Some(v) = irq_vector {
                    // race-free: the future captures a fire-count
                    // baseline at construction; an IRQ that lands
                    // before .await still wakes us on the next
                    // executor tick. The select-with-timeout shape
                    // a future scheduler change might want to
                    // express is approximated by polling on a
                    // sleep-cycles bound: we await the IRQ but the
                    // outer loop falls back through if no fire
                    // happens within the cycle budget.
                    let _ = narf_interrupts::wait_for_irq(v).await;
                } else {
                    narf_time::sleep_cycles(PUMP_CYCLES).await;
                }
            }
        });
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
