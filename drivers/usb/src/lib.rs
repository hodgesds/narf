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
    // The legacy "usb-mass-storage" Stage::Device initcall used to
    // call msc::enumerate_and_attach_msc once. That path was a
    // one-shot: USB sticks plugged in after boot never got bound.
    // The HID supervisor's per-port try_attach now handles MSC via
    // AttachOutcome::MassStorage — same retry / hot-plug semantics
    // as keyboard and mouse. Removed cleanly per the no-shims rule.
}

/// Liveness counter for the USB HID supervisor. Incremented at the
/// VERY TOP of every loop iteration, before any controller lookup,
/// any lock acquisition, any MMIO. A stuck 0 with `xhci::is_probed()
/// == true` is conclusive evidence that the supervisor task was
/// either (a) never enqueued, (b) enqueued on a CPU that isn't
/// polling, or (c) preempted at every dispatch before reaching
/// this increment. Surfaced on the FB status panel.
pub static SUPERVISOR_TICKS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Most-recent phase marker the supervisor reached inside the
/// current loop iteration. Updated as the supervisor crosses each
/// internal boundary. Combined with `SUPERVISOR_TICKS` this
/// pinpoints WHERE the iteration wedges if `pumps` doesn't grow.
///
/// 0 = not entered yet
/// 1 = entered loop body
/// 2 = got Arc<Xhci> handle
/// 3 = about to call connected_ports()
/// 4 = connected_ports returned; about to enter Phase 1 for-loop
/// 5 = inside Phase 1 for-loop, about to try_attach_root
/// 6 = Phase 1 done; about to take HUBS snapshot for Phase 2
/// 7 = Phase 2 done; about to call hid::pump_all
/// 8 = pump_all done; about to call idle_suspend_pass
/// 9 = about to .await wait_for_irq_until / sleep_cycles
pub static SUPERVISOR_PHASE: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

/// Port number the supervisor is currently trying to attach (if
/// inside try_attach_root). 0 = not in try_attach_root. Lets us
/// see which specific port wedged when phase=5.
pub static SUPERVISOR_ATTACHING_PORT: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

/// Spawn the long-running USB HID supervisor task. Walks every
/// xHCI root-hub port the controller reports as connected, then
/// every downstream port of every bound USB hub, attempting to
/// bind one of {HID Boot Keyboard, HID Boot Mouse, USB Hub} per
/// device. Loops pumping interrupt-IN reports onto the global
/// input ring between wakes.
fn spawn_supervisor_task() {
    // Stackful: USB HID supervisor's enumeration loop polls xHCI
    // MMIO + per-port reset state. Preemption-capped at the
    // default 10 ms slice so a stuck port can't starve init.
    narf_scheduler::spawn_stackful(async {
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
            SUPERVISOR_TICKS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            SUPERVISOR_PHASE.store(1, core::sync::atomic::Ordering::Relaxed);
            // Acquire the controller handle once per loop iteration.
            // The Arc clone takes the registry lock for microseconds;
            // the rest of the iteration runs against `&*c` with no
            // outer lock held. Phase 1 / Phase 2 / pump_all calls all
            // operate on the same `&Xhci` borrow.
            let c = match xhci::controller() {
                Some(c) => c,
                None => {
                    narf_time::sleep_cycles(PUMP_CYCLES).await;
                    continue;
                }
            };
            let c: &xhci::Xhci = &c;
            SUPERVISOR_PHASE.store(2, core::sync::atomic::Ordering::Relaxed);
            if irq_vector.is_none() {
                irq_vector = c.irq_vector;
            }

            // ── Phase 1: root-hub ports ────────────────────────────
            SUPERVISOR_PHASE.store(3, core::sync::atomic::Ordering::Relaxed);
            let connected_root: alloc::vec::Vec<u8> =
                c.connected_ports().iter().map(|(p, _)| *p).collect();
            SUPERVISOR_PHASE.store(4, core::sync::atomic::Ordering::Relaxed);
            for &p in &connected_root {
                let bit = 1u128 << (p as u32 & 127);
                let pi = (p as usize) & 127;
                if claimed_root & bit != 0 {
                    continue;
                }
                if root_fail_count[pi] >= MAX_PER_PORT_RETRIES {
                    continue;
                }
                SUPERVISOR_PHASE.store(5, core::sync::atomic::Ordering::Relaxed);
                SUPERVISOR_ATTACHING_PORT.store(p, core::sync::atomic::Ordering::Relaxed);
                let outcome = attach::try_attach_root(c, p).await;
                SUPERVISOR_ATTACHING_PORT.store(0, core::sync::atomic::Ordering::Relaxed);
                match outcome {
                    AttachOutcome::Keyboard
                    | AttachOutcome::Mouse
                    | AttachOutcome::Touchpad
                    | AttachOutcome::SerialAcm
                    | AttachOutcome::MassStorage
                    | AttachOutcome::AudioClass
                    | AttachOutcome::VideoClass
                    | AttachOutcome::NetworkClass
                    | AttachOutcome::Hub => {
                        claimed_root |= bit;
                        root_fail_count[pi] = 0;
                    }
                    AttachOutcome::UnknownClass => {
                        root_fail_count[pi] = root_fail_count[pi].saturating_add(1);
                    }
                }
            }

            // ── Phase 2: walk every bound hub's downstream ports ───
            SUPERVISOR_PHASE.store(6, core::sync::atomic::Ordering::Relaxed);
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
                // Snapshot the UsbHub copy out of the registry lock so
                // both connected_downstream_ports() and try_attach_via_hub
                // can run their now-async control transfers without
                // holding an IrqSafeSpinLock across the .await.
                let hub_copy: Option<crate::hub::UsbHub> = {
                    let g = HUBS.lock();
                    g.get(idx).map(|h| h.hub)
                };
                let hub_copy = match hub_copy {
                    Some(h) => h,
                    None => continue,
                };
                let connected = hub_copy.connected_downstream_ports(c).await;
                let mut new_bound_bits: u64 = 0;
                for &dp in &connected {
                    if (*num_ports != 0) && dp > *num_ports {
                        continue;
                    }
                    let dpb = 1u64 << (dp as u32 & 63);
                    if (bound_mask | new_bound_bits) & dpb != 0 {
                        continue;
                    }
                    let outcome = attach::try_attach_via_hub(
                        c,
                        &hub_copy,
                        *route,
                        *tier,
                        *root_port,
                        dp,
                    ).await;
                    match outcome {
                        AttachOutcome::Keyboard
                        | AttachOutcome::Mouse
                        | AttachOutcome::Touchpad
                        | AttachOutcome::SerialAcm
                        | AttachOutcome::MassStorage
                        | AttachOutcome::AudioClass
                        | AttachOutcome::VideoClass
                        | AttachOutcome::NetworkClass
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
            }

            SUPERVISOR_PHASE.store(7, core::sync::atomic::Ordering::Relaxed);
            hid::pump_all(c);
            hid::mouse::pump_all(c);
            hid::touchpad::pump_all(c);
            cdc_acm::pump_all(c);
            SUPERVISOR_PHASE.store(8, core::sync::atomic::Ordering::Relaxed);
            // Power management: suspend any downstream port whose
            // last activity is older than IDLE_SUSPEND_NS. Pumps
            // above touch `last_activity_tick` via mark_port_activity
            // on each completed transfer, so an actively-used keyboard
            // never gets suspended; an idle USB stick / hub does.
            attach::idle_suspend_pass(c).await;
            SUPERVISOR_PHASE.store(9, core::sync::atomic::Ordering::Relaxed);
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
