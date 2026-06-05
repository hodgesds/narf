//! USB host controllers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod attach;
pub mod btusb;
pub mod bulk;
pub mod ccid;
pub mod cdc;
pub mod cdc_acm;
pub mod cdc_ncm;
pub mod class_registry;
pub mod control;
pub mod device;
pub mod dfu;
pub mod ehci;
pub mod fingerprint;
pub mod firmware;
pub mod hid;
pub mod hub;
pub mod intr;
pub mod iso;
pub mod msc;
pub mod ohci;
pub mod serial;
pub mod uac;
pub mod uhci;
pub mod uvc;
pub mod uvc_stream;
pub mod wbdi;
pub mod xhci;
pub mod xpad;

#[cfg(feature = "kernel-test")]
mod e2e_tests;
mod tests;

/// Stage::Subsys initcalls for this driver crate.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    // Install devfs hooks so /dev/ttyUSB<N> nodes resolve.
    // Linux ref: `drivers/usb/serial/usb-serial.c:usb_serial_register_drivers`.
    narf_init::register(Stage::Subsys, "usb-serial-devfs", || {
        narf_filesystem::devfs::install_tty_usb_hooks(
            serial::devfs_bridge::lookup_tty_usb,
            serial::devfs_bridge::enumerate_tty_usb,
        );
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "xhci", || {
        xhci::register_pci_driver();
        InitResult::Ok
    });
    // EHCI / OHCI / UHCI structural binding — Stage-0 probe paths
    // that map BARs + log + return ProbeError::Other("not
    // implemented"). Renoir / Phoenix don't carry these silicon
    // blocks (everything's xHCI) but the registrations let
    // expansion cards / desktop boards / future SoCs get a
    // recognised log line instead of an "unbound device" trace.
    narf_init::register(Stage::Subsys, "ehci", || {
        ehci::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "ohci", || {
        ohci::register_pci_driver();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "uhci", || {
        uhci::register_pci_driver();
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
    // Stage::Subsys banner for the HID vendor quirk tables (Apple /
    // Microsoft / Logitech DJ + HID++). These modules don't bind
    // their own xHCI / interrupt-IN endpoints — they hang off the
    // standard HID supervisor's per-port attach via VID/PID lookups
    // into their device tables. The initcall just emits a one-line
    // klog banner so a real-HW boot makes the vendor coverage
    // visible.
    narf_init::register(Stage::Subsys, "usb-hid-vendor-quirks", || {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  usb-hid-vendor: apple={} ms={} logi-recv={} (HID++ table-driven)",
            hid::apple::APPLE_DEVICES.len(),
            hid::microsoft::MICROSOFT_DEVICES.len(),
            hid::logitech_dj::LOGITECH_RECEIVERS.len(),
        );
        InitResult::Ok
    });
    // The legacy "usb-mass-storage" Stage::Device initcall used to
    // call msc::enumerate_and_attach_msc once. That path was a
    // one-shot: USB sticks plugged in after boot never got bound.
    // The HID supervisor's per-port try_attach now handles MSC via
    // AttachOutcome::MassStorage — same retry / hot-plug semantics
    // as keyboard and mouse. Removed cleanly per the no-shims rule.
}

/// Number of times YieldTimeout::poll was entered (across the
/// supervisor's lifetime). Increments on every poll regardless of
/// inner future / deadline state. Surfaced on the FB panel as
/// `yt=N`. Three diagnostic outcomes:
///   - yt=0   → task never polled (executor isn't scheduling it)
///   - yt=1   → first poll happened, never re-polled (waker bug)
///   - yt>>1  → polled many times but deadline never fires
///              (Instant::now frozen, or stuck inner spin loop)
pub static YIELD_TIMEOUT_POLLS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Wheel-bypass timeout. Polls the inner future on every executor
/// round and checks a TSC-driven wall-clock deadline. No
/// `timer_wheel::register` call. Self-wakes via
/// `cx.waker().wake_by_ref()` so the slot's `awake` flag is kept
/// true through the executor's swap(false, Acquire) gate.
///
/// Used by the USB HID supervisor because `narf_time::timeout` /
/// `narf_time::sleep_cycles` register with the timer wheel, and on
/// real HW the supervisor's wheel-registered wakers were not being
/// fired even though the panel paint task (which uses the same
/// `sleep_cycles` primitive) was being woken correctly. Bypassing
/// the wheel entirely localizes that bug.
pub struct YieldTimeout<F> {
    fut: F,
    deadline: narf_time::Deadline,
}

impl<F> core::fmt::Debug for YieldTimeout<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("YieldTimeout")
            .field("deadline", &self.deadline)
            .finish()
    }
}

impl<F: core::future::Future> core::future::Future for YieldTimeout<F> {
    type Output = Result<F::Output, ()>;
    fn poll(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        YIELD_TIMEOUT_POLLS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        // SAFETY: structural pin projection — `fut` is never moved
        // out, only re-pinned for the inner poll call.
        let this = unsafe { self.get_unchecked_mut() };
        let fut = unsafe { core::pin::Pin::new_unchecked(&mut this.fut) };
        match fut.poll(cx) {
            core::task::Poll::Ready(v) => return core::task::Poll::Ready(Ok(v)),
            core::task::Poll::Pending => {}
        }
        if this.deadline.expired() {
            return core::task::Poll::Ready(Err(()));
        }
        cx.waker().wake_by_ref();
        core::task::Poll::Pending
    }
}

/// Liveness counter for the USB HID supervisor. Incremented at the
/// VERY TOP of every loop iteration, before any controller lookup,
/// any lock acquisition, any MMIO. A stuck 0 with `xhci::is_probed()
/// == true` is conclusive evidence that the supervisor task was
/// either (a) never enqueued, (b) enqueued on a CPU that isn't
/// polling, or (c) preempted at every dispatch before reaching
/// this increment. Surfaced on the FB status panel.
pub static SUPERVISOR_TICKS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

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
pub static SUPERVISOR_PHASE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

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
        // match any class driver we have), back off — but never
        // permanently. A port stuck in Polling for a while can
        // recover (cable wiggle, dock re-energise, hub re-train),
        // so the supervisor checks PORTSC.PLS each iteration: a
        // transition to U0 (link active, 0x0) clears the fail
        // counter so enumeration retries the now-healthy port.
        // Without this a port that fails 8 reset attempts during
        // a power-glitch is dead until reboot.
        //
        // Linux's equivalent flow lives in `drivers/usb/core/hub.c`:
        // `hub_port_connect_change` re-runs `hub_port_init` every
        // time the connect-status bit toggles. We don't have
        // PORTSC-change interrupts wired up cleanly today, so we
        // poll PORTSC.PLS each supervisor cycle as a near-equivalent.
        const MAX_PER_PORT_RETRIES: u8 = 8;
        /// PORTSC.PLS shift (bits 5..8 — xHCI 1.2 §5.4.8 Table 5-27).
        const PORTSC_PLS_SHIFT: u32 = 5;
        const PORTSC_PLS_MASK: u32 = 0xF << PORTSC_PLS_SHIFT;
        // xHCI 1.2 §5.4.8 PLS values. Only the ones we care about
        // for the supervisor's hot-plug-vs-our-reset disambiguation.
        const PORTSC_PLS_DISABLED: u8 = 0x4;
        const PORTSC_PLS_RXDETECT: u8 = 0x5;
        /// PORTSC.PLS encoding for U0 — link active, ready to transfer.
        const PORTSC_PLS_U0: u32 = 0x0;
        let mut irq_vector: Option<u8> = None;
        // Per-root-port claimed mask: 1 = something is bound to
        // that port and we don't need to re-try.
        let mut claimed_root: u128 = 0;
        // Per-root-port consecutive-failure counter.
        let mut root_fail_count = [0u8; 128];
        // Per-root-port last-observed PLS encoding. Sentinel value
        // 0xFF means "not yet sampled" so the first sample doesn't
        // trip a spurious "PLS changed" reset.
        let mut last_pls = [0xFFu8; 128];
        // Cursor into the connected-ports list — try ONE port per
        // loop iteration, then advance + pump + sleep. The earlier
        // "for &p in &connected_root" body ran try_attach_root for
        // every connected port BEFORE pump_all, so the first
        // iteration on a laptop with N connected ports took N ×
        // (~430ms port_reset + several × ~250ms command waits) =
        // multiple seconds wall-clock with sup-ticks stuck at 1.
        // Moving to one-port-per-iteration: sup-ticks advances
        // visibly, pump_all runs after every port attempt, and a
        // long-stalling port can't starve pump_all for other,
        // already-bound devices.
        let mut next_root_idx: usize = 0;
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

            // ── Phase 1: try ONE root-hub port, then move on. ──────
            SUPERVISOR_PHASE.store(3, core::sync::atomic::Ordering::Relaxed);
            let connected_root: alloc::vec::Vec<u8> =
                c.connected_ports().iter().map(|(p, _)| *p).collect();
            SUPERVISOR_PHASE.store(4, core::sync::atomic::Ordering::Relaxed);
            // PLS-transition decay pass: for every connected port,
            // sample PORTSC.PLS. If it transitioned into U0 (link
            // active) since we last looked, clear the per-port fail
            // counter so the now-healthy port gets a fresh round of
            // enumeration attempts. Without this, a transient
            // failure (port in Polling for too long, cable wiggle
            // mid-reset, dock re-energise) permanently burned the
            // port out at 8 retries.
            for &p in connected_root.iter() {
                let pi = (p as usize) & 127;
                if let Some(v) = c.portsc(p) {
                    let pls = ((v & PORTSC_PLS_MASK) >> PORTSC_PLS_SHIFT) as u8;
                    let prev = last_pls[pi];
                    // Reset the per-port retry counter ONLY when the
                    // port has gone through a real hot-plug cycle —
                    // that is, the previous PLS was Disabled (4) or
                    // RxDetect (5), the two states a disconnected
                    // port sits in. Polling → U0 transitions also
                    // hit U0, but those are produced by our own
                    // `try_attach_root` calling `port_reset`; if we
                    // cleared the counter there, a device like a
                    // USB-HID tablet that legitimately fails
                    // `find_boot_kbd` would retry forever and burn
                    // CPU on a sub-1s loop.
                    if prev != 0xFF
                        && prev != pls
                        && pls == PORTSC_PLS_U0 as u8
                        && (prev == PORTSC_PLS_DISABLED || prev == PORTSC_PLS_RXDETECT)
                        && root_fail_count[pi] != 0
                    {
                        use core::fmt::Write as _;
                        let _ = writeln!(
                            narf_console::Writer,
                            "  usb-supervisor: port {} PLS {:x}→U0 (hot-plug), retry budget reset",
                            p,
                            prev
                        );
                        root_fail_count[pi] = 0;
                    }
                    last_pls[pi] = pls;
                }
            }
            // Find the next unbound, not-yet-burned port starting
            // from `next_root_idx`. Wrap at end so on later passes
            // we revisit ports whose `root_fail_count` reset.
            let mut attempted = false;
            for step in 0..connected_root.len() {
                let idx = (next_root_idx + step) % connected_root.len();
                let p = connected_root[idx];
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
                // Per-port hard wall-clock cap. Individual sub-awaits
                // (port_reset, await_event, control transfers) have
                // their own 250ms bounds, but a misbehaving port can
                // chain enough of them that the supervisor sits on a
                // single port for 5-10s. Wrapping the whole call in a
                // 3s timeout guarantees forward progress: a wedged
                // port burns its retry budget instead of stalling the
                // whole supervisor.
                // Short per-port budget so sup-ticks advances visibly
                // on the panel. 500 ms is enough for a healthy port
                // (~100 ms port_reset + a few 250 ms command waits)
                // but small enough that a wedged port can't hide
                // forward progress.
                let outcome = match (YieldTimeout {
                    fut: attach::try_attach_root(c, p),
                    deadline: narf_time::Deadline::after_ms(500),
                })
                .await
                {
                    Ok(o) => o,
                    Err(()) => AttachOutcome::UnknownClass,
                };
                SUPERVISOR_ATTACHING_PORT.store(0, core::sync::atomic::Ordering::Relaxed);
                match outcome {
                    AttachOutcome::Keyboard
                    | AttachOutcome::Mouse
                    | AttachOutcome::Touchpad
                    | AttachOutcome::ConsumerControl
                    | AttachOutcome::SerialAcm
                    | AttachOutcome::MassStorage
                    | AttachOutcome::AudioClass
                    | AttachOutcome::VideoClass
                    | AttachOutcome::NetworkClass
                    | AttachOutcome::Bluetooth
                    | AttachOutcome::WbdiFingerprint
                    | AttachOutcome::Fingerprint
                    | AttachOutcome::CcidReader
                    | AttachOutcome::UsbClassDriver
                    | AttachOutcome::Hub => {
                        claimed_root |= bit;
                        root_fail_count[pi] = 0;
                    }
                    AttachOutcome::UnknownClass => {
                        root_fail_count[pi] = root_fail_count[pi].saturating_add(1);
                    }
                }
                next_root_idx = idx + 1;
                attempted = true;
                break;
            }
            if !attempted && !connected_root.is_empty() {
                // All ports either bound or burned out; reset
                // cursor so a hot-plug rescan still happens.
                next_root_idx = 0;
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
                    let outcome =
                        attach::try_attach_via_hub(c, &hub_copy, *route, *tier, *root_port, dp)
                            .await;
                    match outcome {
                        AttachOutcome::Keyboard
                        | AttachOutcome::Mouse
                        | AttachOutcome::Touchpad
                        | AttachOutcome::ConsumerControl
                        | AttachOutcome::SerialAcm
                        | AttachOutcome::MassStorage
                        | AttachOutcome::AudioClass
                        | AttachOutcome::VideoClass
                        | AttachOutcome::NetworkClass
                        | AttachOutcome::Bluetooth
                        | AttachOutcome::WbdiFingerprint
                        | AttachOutcome::Fingerprint
                        | AttachOutcome::CcidReader
                        | AttachOutcome::UsbClassDriver
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
            // Wheel-bypass inter-cycle delay. yield_now self-wakes
            // and the slot is re-polled on the next round; a TSC
            // deadline check provides the ~100 ms cadence so we
            // don't busy-loop pump_all at full preemption speed.
            // (The xHCI IRQ wait path was wheel-based and not firing
            // for this task; same workaround as elsewhere in the
            // supervisor.)
            let _ = irq_vector; // unused while wheel is suspected
            let pause = narf_time::Deadline::after_ms(100);
            while !pause.expired() {
                narf_scheduler::yield_now().await;
            }
        }
    });
}
