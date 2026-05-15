//! USB host controllers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod attach;
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
/// xHCI root-hub port the controller reports as connected, then
/// every downstream port of every bound USB hub, attempting to
/// bind one of {HID Boot Keyboard, HID Boot Mouse, USB Hub} per
/// device. Loops pumping interrupt-IN reports onto the global
/// input ring between wakes.
fn spawn_supervisor_task() {
    narf_scheduler::spawn(async {
        use crate::attach::{self, AttachOutcome, HUBS};
        const PUMP_CYCLES: u64 = 16_000_000;
        // Cap per-port enumeration attempts. After this many
        // consecutive failures (typically all PortResetTimeout on a
        // dead USB3 port the rate-matching hub has internally
        // routed elsewhere, OR a port whose attached device doesn't
        // match any class driver we have), give up to stop burning
        // cycles + log noise.
        const MAX_PER_PORT_RETRIES: u8 = 8;
        let mut irq_vector: Option<u8> = None;
        // Per-root-port claimed mask: 1 = something is bound to
        // that port and we don't need to re-try.
        let mut claimed_root: u128 = 0;
        // Per-root-port consecutive-failure counter.
        let mut root_fail_count = [0u8; 128];
        loop {
            if !xhci::is_probed() {
                narf_time::sleep_cycles(PUMP_CYCLES).await;
                continue;
            }
            if irq_vector.is_none() {
                irq_vector = xhci::with_controller(|c| c.irq_vector).flatten();
            }

            // ── Phase 1: root-hub ports ────────────────────────────
            //
            // Each port's reset+enumerate path inside
            // `try_attach_root` runs sync (PORTSC debounce + Address
            // Device + descriptor reads) and can take several
            // hundred ms to ~1 s per port on real silicon. With a
            // dozen connected ports the first supervisor iteration
            // would block the executor for 10+ s — long enough for
            // the cursor pump, FB drain task, and shell prompt
            // task to never appear to make progress.
            //
            // Yield to the scheduler between every port so other
            // tasks get to poll. The yield is cheap (no IO; just
            // re-enqueues the supervisor) and the actual port work
            // still happens at the same wall-clock rate.
            let connected_root: alloc::vec::Vec<u8> = xhci::with_controller(|c| {
                c.connected_ports().iter().map(|(p, _)| *p).collect()
            })
            .unwrap_or_default();
            for &p in &connected_root {
                let bit = 1u128 << (p as u32 & 127);
                let pi = (p as usize) & 127;
                if claimed_root & bit != 0 {
                    continue;
                }
                if root_fail_count[pi] >= MAX_PER_PORT_RETRIES {
                    continue;
                }
                let outcome =
                    xhci::with_controller(|c| attach::try_attach_root(c, p)).unwrap_or(
                        AttachOutcome::UnknownClass,
                    );
                match outcome {
                    AttachOutcome::Keyboard
                    | AttachOutcome::Mouse
                    | AttachOutcome::Touchpad
                    | AttachOutcome::SerialAcm
                    | AttachOutcome::Hub => {
                        claimed_root |= bit;
                        root_fail_count[pi] = 0;
                    }
                    AttachOutcome::UnknownClass => {
                        root_fail_count[pi] = root_fail_count[pi].saturating_add(1);
                    }
                }
                narf_scheduler::yield_now().await;
            }

            // ── Phase 2: walk every bound hub's downstream ports ───
            // BFS ordering: HUBS append-only, so iterating linearly
            // visits a parent hub before any child it spawns this
            // cycle. Snapshot the (route, tier, root_port, hub_slot,
            // num_ports) tuples up front so the registry lock isn't
            // held across the per-port enumeration attempts.
            let walks: alloc::vec::Vec<(u32, u32, u8, u8, u8, u64)> = {
                let g = HUBS.lock();
                g.iter()
                    .map(|h| {
                        (
                            h.route_string,
                            h.tier,
                            h.root_hub_port,
                            h.hub.slot_id,
                            h.hub.descriptor.num_ports,
                            h.bound_downstream,
                        )
                    })
                    .collect()
            };
            for (idx, (route, tier, root_port, _hub_slot, num_ports, bound_mask)) in
                walks.iter().enumerate()
            {
                // Per-cycle: enumerate the hub's connected
                // downstream ports + try to attach an unbound one.
                let connected = xhci::with_controller(|c| {
                    let g = HUBS.lock();
                    g.get(idx).map(|h| h.hub.connected_downstream_ports(c)).unwrap_or_default()
                })
                .unwrap_or_default();
                let mut new_bound_bits: u64 = 0;
                for &dp in &connected {
                    if (*num_ports != 0) && dp > *num_ports {
                        continue;
                    }
                    let dpb = 1u64 << (dp as u32 & 63);
                    if (bound_mask | new_bound_bits) & dpb != 0 {
                        continue;
                    }
                    let outcome = xhci::with_controller(|c| {
                        let g = HUBS.lock();
                        match g.get(idx) {
                            Some(h) => attach::try_attach_via_hub(
                                c,
                                &h.hub,
                                *route,
                                *tier,
                                *root_port,
                                dp,
                            ),
                            None => AttachOutcome::UnknownClass,
                        }
                    })
                    .unwrap_or(AttachOutcome::UnknownClass);
                    match outcome {
                        AttachOutcome::Keyboard
                        | AttachOutcome::Mouse
                        | AttachOutcome::Touchpad
                        | AttachOutcome::SerialAcm
                        | AttachOutcome::Hub => {
                            new_bound_bits |= dpb;
                        }
                        AttachOutcome::UnknownClass => {}
                    }
                }
                if new_bound_bits != 0 {
                    let mut g = HUBS.lock();
                    if let Some(h) = g.get_mut(idx) {
                        h.bound_downstream |= new_bound_bits;
                    }
                }
                // Same starvation reasoning as Phase 1 — yield
                // between hubs so a long downstream-port walk on
                // one hub doesn't block other tasks.
                narf_scheduler::yield_now().await;
            }

            let _ = xhci::with_controller(|c| hid::pump_all(c));
            narf_scheduler::yield_now().await;
            let _ = xhci::with_controller(|c| hid::mouse::pump_all(c));
            narf_scheduler::yield_now().await;
            let _ = xhci::with_controller(|c| hid::touchpad::pump_all(c));
            narf_scheduler::yield_now().await;
            let _ = xhci::with_controller(|c| cdc_acm::pump_all(c));
            // Wake on either:
            //   (a) the next xHCI IRQ — a Transfer Event for a bound
            //       endpoint or a Port Status Change Event (hot-plug),
            //   (b) a 100 ms wall-clock timeout — re-tries enumeration
            //       on unattached ports + handles the case where IRQs
            //       never fire (no MSI-X / device that never sends).
            if let Some(v) = irq_vector {
                let deadline = narf_time::Deadline::after_ms(100);
                let _ = narf_interrupts::wait_for_irq_until(v, deadline).await;
            } else {
                narf_time::sleep_cycles(PUMP_CYCLES).await;
            }
        }
    });
}
