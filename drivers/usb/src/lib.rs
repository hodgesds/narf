//! USB host controllers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod attach;
pub mod ax88179;
mod boot_root;
pub mod btusb;
mod btusb_bcm;
mod btusb_intel;
mod btusb_mtk;
mod btusb_qca;
mod btusb_rtl;
pub mod bulk;
pub mod ccid;
pub mod cdc;
pub mod cdc_acm;
pub mod cdc_acm_bridge;
pub mod cdc_ecm;
pub mod cdc_ncm;
pub mod class_registry;
pub mod control;
pub mod ctap;
pub mod device;
pub mod dfu;
pub mod ehci;
mod enumeration_wait;
pub mod fingerprint;
pub mod firmware;
pub mod hid;
pub mod hub;
pub mod intr;
pub mod iso;
pub mod lan95xx;
pub mod msc;
pub mod ohci;
pub mod r8152;
pub mod rndis;
pub mod serial;
pub mod uac;
pub mod uac_card;
pub mod uhci;
pub mod uvc;
pub mod wbdi;
pub mod xhci;
pub mod xpad;

#[cfg(feature = "kernel-test")]
mod e2e_tests;
#[cfg(test)]
mod host_test_shims;
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
    // Suspend/resume state replay for the serial classes (#763):
    // async system-PM hooks whose prepare quiesces the pumps and
    // whose resume replays each bound device's saved line/modem
    // state after the controller fan-out restores xHCI.
    narf_init::register(Stage::Subsys, "usb-serial-pm", || {
        cdc_acm::register_pm();
        serial::port::register_pm();
        InitResult::Ok
    });
    // Install devfs hooks so /dev/ccid<N> nodes resolve for every
    // reader the CCID class driver binds.
    narf_init::register(Stage::Subsys, "usb-ccid-devfs", || {
        narf_filesystem::devfs::install_ccid_hooks(
            ccid::devfs_bridge::lookup_ccid,
            ccid::devfs_bridge::enumerate_ccid,
        );
        InitResult::Ok
    });
    // Install devfs hooks so /dev/fp<N> nodes resolve for every
    // bound fingerprint reader (#920). The provider lookup builds
    // nodes on demand from the fingerprint registry, so no
    // first-only special case remains.
    narf_init::register(Stage::Subsys, "usb-fp-devfs", || {
        narf_filesystem::devfs::install_fp_hooks(
            crate::fingerprint::lookup_fp,
            crate::fingerprint::enumerate_fp,
        );
        InitResult::Ok
    });
    // Install devfs hooks so /dev/ttyACM<N> nodes resolve for
    // every CDC-ACM function the class driver binds (#753).
    narf_init::register(Stage::Subsys, "usb-cdc-acm-devfs", || {
        narf_filesystem::devfs::install_tty_acm_hooks(
            cdc_acm_bridge::lookup_tty_acm,
            cdc_acm_bridge::enumerate_tty_acm,
        );
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-uac", || {
        uac::register_initcalls();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-uvc", || {
        uvc::register_initcalls();
        InitResult::Ok
    });
    // UVC suspend/resume (#807): the class suspend hook for the
    // supervisor's hub idle-suspend pass (vetoes gating a live
    // stream) and the system-PM hooks (prepare quiesces, resume
    // re-negotiates) plus the synchronous device-PM backstop.
    narf_init::register(Stage::Subsys, "usb-uvc-suspend", || {
        uvc::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-uvc-pm", || {
        uvc::register_pm();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-r8152", || {
        r8152::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-btusb", || {
        btusb::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-ax88179", || {
        ax88179::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-lan95xx", || {
        lan95xx::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-cdc-ncm", || {
        cdc_ncm::register_initcalls();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-cdc-ecm", || {
        cdc_ecm::register_initcalls();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-rndis", || {
        rndis::register_initcalls();
        InitResult::Ok
    });
    // MSC binds through the attach cascade, not the class registry;
    // this registration exists so the registry's unbind dispatch
    // (detach path) can reach msc::detach_msc.
    narf_init::register(Stage::Subsys, "usb-msc", || {
        msc::register_initcalls();
        InitResult::Ok
    });
    // btusb binds through the attach cascade, not the class registry;
    // this registration exists so the registry's unbind dispatch
    // (detach path) can reach btusb::detach_btusb_slot (#890).
    narf_init::register(Stage::Subsys, "usb-btusb", || {
        btusb::register_initcalls();
        InitResult::Ok
    });
    // Fingerprint binds through the attach cascade, not the class
    // registry; this registration exists so the registry's unbind
    // dispatch (detach path) can reach fingerprint::detach_fp for
    // both vendor-matched and WBDI-bridged readers. The async system-PM
    // hook re-arms ELAN devices on resume (#922).
    narf_init::register(Stage::Subsys, "usb-fp-lifecycle", || {
        fingerprint::register_initcalls();
        fingerprint::register_pm();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-xpad", || {
        xpad::register_initcalls();
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
        start_supervisors();
        InitResult::Ok
    });
    // CCID slot-change pump: services the readers' Interrupt-IN
    // endpoints (NotifySlotChange) so card insert/remove reaches
    // the /dev/ccid<N> presence state. Same NotPresent rule as the
    // HID supervisor when no xHCI controller is bound.
    narf_init::register(Stage::Late, "usb-ccid-supervisor", || {
        if !xhci::is_probed() {
            return InitResult::NotPresent;
        }
        ccid::devfs_bridge::spawn_slot_change_pump();
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
    narf_init::register(Stage::Subsys, "usb-r8152", || {
        r8152::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-ax88179", || {
        ax88179::register();
        InitResult::Ok
    });
    narf_init::register(Stage::Subsys, "usb-lan95xx", || {
        lan95xx::register();
        InitResult::Ok
    });
}

/// Number of enumeration-future polls across the supervisor's lifetime.
/// Surfaced on the FB panel under the historical `yt` label. A growing
/// count while phase=5 distinguishes a pending hardware operation from a
/// supervisor that is never polled. Hardware operations own their deadlines;
/// the supervisor keeps their future alive through terminal cleanup.
pub static YIELD_TIMEOUT_POLLS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

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

/// Nonblocking report pumps; callers resume suspended bound ports first.
fn pump_bound_devices(controller: &xhci::Xhci) {
    hid::pump_all(controller);
    hid::mouse::pump_all(controller);
    hid::touchpad::pump_all(controller);
    hid::rmi_elan::pump_all(controller);
    hid::consumer::pump_all(controller);
    // Generic HID was bound but never pumped until #1681 wired it
    // in: the RMI/Elan vendor-probe fallback binds generic devices,
    // and a bound-but-unpumped generic device would be silently
    // dead. Pump it alongside the other HID classes.
    hid::generic::pump_all(controller);
    cdc_acm::pump_all(controller);
    serial::port::pump_all(controller);
    xpad::pump_all(controller);
}

async fn resume_bound_ports(controller: &xhci::Xhci) {
    hid::resume_suspended_hub_ports(controller).await;
    cdc_acm::resume_suspended_hub_ports(controller).await;
    serial::port::resume_suspended_hub_ports(controller).await;
}

/// One boxed supervisor future.
type Supervisor = core::pin::Pin<alloc::boxed::Box<dyn core::future::Future<Output = ()> + Send>>;

/// Start one supervisor per bound xHCI controller, and arrange for a
/// controller bound later to get its own. Every supervisor owns its
/// controller's ports, hubs and bindings; slot ids and port numbers are
/// only unique within a controller.
fn start_supervisors() {
    let mut supervisors: alloc::vec::Vec<Supervisor> =
        xhci::on_controller_bound(spawn_supervisor_for)
            .into_iter()
            .map(supervisor)
            .collect();
    // Root mounting runs before the executor. Prime these same futures
    // when the requested root has not appeared yet (it may sit behind any
    // controller), then retain them for hot-plug.
    boot_root::prepare(&mut supervisors);
    for supervisor in supervisors {
        narf_scheduler::spawn_stackful(supervisor);
    }
}

/// Spawn the supervisor of a controller bound after
/// [`start_supervisors`].
fn spawn_supervisor_for(controller: alloc::sync::Arc<xhci::Xhci>) {
    narf_scheduler::spawn_stackful(supervisor(controller));
}

/// NIC wake-watch (#1256): resume parked NIC ports that
/// signaled a remote-wakeup edge. Each family's step reads its
/// own parked ports and resumes only on an observed edge;
/// without this step, WoL arming would be unobservable — the
/// device would wake, but the host would never notice until
/// TX demand. See the supervisor-cycle comment at the call
/// site for why this step is conditional while
/// `resume_bound_ports` is unconditional.
async fn wake_suspended_nic_ports(controller: &xhci::Xhci) {
    r8152::wake_suspended_ports(controller).await;
    cdc_ncm::wake_suspended_ports(controller).await;
    cdc_ecm::wake_suspended_ports(controller).await;
}

/// The long-running USB supervisor of one controller. Walks every
/// root-hub port the controller reports as connected, then every
/// downstream port of every hub bound on it, attempting to bind one
/// of {HID Boot Keyboard, HID Boot Mouse, USB Hub, ...} per device.
/// Loops pumping interrupt-IN reports onto the global input ring
/// between wakes.
fn supervisor(controller: alloc::sync::Arc<xhci::Xhci>) -> Supervisor {
    // Stackful: USB HID supervisor's enumeration loop polls xHCI
    // MMIO + per-port reset state. Preemption-capped at the
    // default 10 ms slice so a stuck port can't starve init.
    alloc::boxed::Box::pin(async move {
        use crate::attach::{self, AttachOutcome, HUBS};
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
        // Downstream hub ports get the same retry budget as root ports;
        // keyed by (hub slot, port), forgotten when the port disconnects.
        let mut hub_fail_count: alloc::collections::BTreeMap<(u8, u8), u8> =
            alloc::collections::BTreeMap::new();
        // Per-root-port last-observed PLS encoding. Sentinel value
        // 0xFF means "not yet sampled" so the first sample doesn't
        // trip a spurious "PLS changed" reset.
        let mut last_pls = [0xFFu8; 128];
        // Last controller recovery epoch observed. u64::MAX is the
        // not-yet-sampled sentinel: the first sample just records
        // the epoch (bindings are empty at boot anyway). A later
        // change means `recover_controller` wiped every slot, so
        // all bindings + claims are dropped wholesale.
        let mut last_epoch: u64 = u64::MAX;
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
            // This supervisor's own controller; Phase 1 / Phase 2 /
            // pump_all calls all operate on the same `&Xhci` borrow.
            let c: &xhci::Xhci = &controller;
            let hubs = HUBS.of(c.id());
            SUPERVISOR_PHASE.store(2, core::sync::atomic::Ordering::Relaxed);
            if irq_vector.is_none() {
                irq_vector = c.irq_vector;
            }

            // ── Controller recovery (HCE) + epoch invalidation ───
            // If the controller signalled an internal error, drive
            // the with-devices recovery (queue 10): it invalidates
            // every generation and resets the hardware. Its epoch
            // bump then tells us every binding/claim we hold names
            // a dead slot — drop them all and let the normal attach
            // phases re-enumerate from scratch.
            if c.needs_recovery() {
                let _ = c.recover_controller();
            }
            let epoch = c.recovery_epoch();
            if epoch != last_epoch {
                if last_epoch != u64::MAX {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  usb-supervisor: controller recovery epoch {}→{} — dropping all bindings for re-enumeration",
                        last_epoch,
                        epoch
                    );
                    attach::detach_all_bindings(c.id());
                    claimed_root = 0;
                    root_fail_count = [0u8; 128];
                    last_pls = [0xFFu8; 128];
                    next_root_idx = 0;
                }
                last_epoch = epoch;
            }

            // ── Phase 1: try ONE root-hub port, then move on. ──────
            SUPERVISOR_PHASE.store(3, core::sync::atomic::Ordering::Relaxed);
            let connected_root: alloc::vec::Vec<u8> =
                c.connected_ports().iter().map(|(p, _)| *p).collect();
            SUPERVISOR_PHASE.store(4, core::sync::atomic::Ordering::Relaxed);
            // Disconnect pass: a claimed root port that no longer
            // reports a connection was unplugged. Tear the binding
            // down (class unbind → Disable Slot → slot reclaim) and
            // clear the claim + retry budget, so a replug re-runs
            // attach from scratch. The bit position in
            // `claimed_root` IS the port number (attach claims
            // `1 << (port & 127)`).
            if claimed_root != 0 {
                let mut gone: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
                let mut mask = claimed_root;
                while mask != 0 {
                    let p = mask.trailing_zeros() as u8;
                    mask &= mask - 1;
                    if !connected_root.contains(&p) {
                        gone.push(p);
                    }
                }
                for p in gone {
                    use core::fmt::Write as _;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  usb-supervisor: root port {} disconnected — detaching",
                        p
                    );
                    if let Some(slot) = c.slot_for_route(p, 0) {
                        attach::detach_slot(c, slot).await;
                    }
                    claimed_root &= !(1u128 << (p as u32 & 127));
                    root_fail_count[(p as usize) & 127] = 0;
                }
            }
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
            // Enumeration also pumps existing bindings while waiting. Resume
            // their ports before the first such pump, just as in Phase 7.
            resume_bound_ports(c).await;
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
                let outcome = enumeration_wait::run(attach::try_attach_root(c, p), || {
                    pump_bound_devices(c);
                })
                .await;
                SUPERVISOR_ATTACHING_PORT.store(0, core::sync::atomic::Ordering::Relaxed);
                match outcome {
                    AttachOutcome::Keyboard
                    | AttachOutcome::Mouse
                    | AttachOutcome::Touchpad
                    | AttachOutcome::RmiElanTouchpad
                    | AttachOutcome::GenericHid
                    | AttachOutcome::ConsumerControl
                    | AttachOutcome::SerialAcm
                    | AttachOutcome::SerialVendor
                    | AttachOutcome::MassStorage
                    | AttachOutcome::AudioClass
                    | AttachOutcome::VideoClass
                    | AttachOutcome::NetworkClass
                    | AttachOutcome::Bluetooth
                    | AttachOutcome::WbdiFingerprint
                    | AttachOutcome::Fingerprint
                    | AttachOutcome::CcidReader
                    | AttachOutcome::CtapToken
                    | AttachOutcome::UsbClassDriver
                    | AttachOutcome::Hub => {
                        claimed_root |= bit;
                        root_fail_count[pi] = 0;
                    }
                    AttachOutcome::UnknownClass => {
                        root_fail_count[pi] = root_fail_count[pi].saturating_add(1);
                        if root_fail_count[pi] == MAX_PER_PORT_RETRIES {
                            use core::fmt::Write as _;
                            let _ = writeln!(
                                narf_console::Writer,
                                "  usb-supervisor: root port {} gave up after {} attempts (portsc={:?})",
                                p,
                                MAX_PER_PORT_RETRIES,
                                c.portsc(p)
                            );
                        }
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
                let g = hubs.lock();
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
            for (idx, (route, tier, root_port, hub_slot, num_ports, bound_mask)) in
                walks.iter().enumerate()
            {
                // Snapshot the UsbHub copy out of the registry lock so
                // both connected_downstream_ports() and try_attach_via_hub
                // can run their now-async control transfers without
                // holding an IrqSafeSpinLock across the .await. The
                // slot check matters now that detach can REMOVE a
                // HUBS entry between the walks snapshot and here:
                // without it, a shifted index would hand us the
                // wrong hub for this (route, tier) pair.
                let hub_copy: Option<crate::hub::UsbHub> = {
                    let g = hubs.lock();
                    g.get(idx)
                        .filter(|h| h.hub.slot_id == *hub_slot)
                        .map(|h| h.hub)
                };
                let hub_copy = match hub_copy {
                    Some(h) => h,
                    None => continue,
                };
                let connected =
                    enumeration_wait::run(hub_copy.connected_downstream_ports(c), || {
                        pump_bound_devices(c);
                    })
                    .await;
                // Downstream disconnect pass: bound ports that left
                // the connected set were unplugged. Detach each
                // (class unbind → Disable Slot → reclaim) and clear
                // its bound/suspended bits so a replug re-attaches.
                let mut cleared_bits: u64 = 0;
                {
                    let mut scan = *bound_mask;
                    while scan != 0 {
                        let dp = scan.trailing_zeros() as u8;
                        scan &= scan - 1;
                        if !connected.contains(&dp) {
                            let child_route =
                                xhci::Topology::for_downstream(*route, *tier, dp).route_string;
                            if let Some(slot) = c.slot_for_route(*root_port, child_route) {
                                attach::detach_slot(c, slot).await;
                            }
                            cleared_bits |= 1u64 << (dp as u32 & 63);
                        }
                    }
                }
                if cleared_bits != 0 {
                    let mut g = hubs.lock();
                    if let Some(h) = g.get_mut(idx) {
                        h.bound_downstream &= !cleared_bits;
                        h.suspended_downstream &= !cleared_bits;
                    }
                }
                let mut new_bound_bits: u64 = 0;
                hub_fail_count
                    .retain(|&(slot, port), _| slot != *hub_slot || connected.contains(&port));
                for &dp in &connected {
                    if (*num_ports != 0) && dp > *num_ports {
                        continue;
                    }
                    let dpb = 1u64 << (dp as u32 & 63);
                    if (bound_mask | new_bound_bits) & dpb != 0 {
                        continue;
                    }
                    if hub_fail_count.get(&(*hub_slot, dp)).copied().unwrap_or(0)
                        >= MAX_PER_PORT_RETRIES
                    {
                        continue;
                    }
                    let outcome = enumeration_wait::run(
                        attach::try_attach_via_hub(c, &hub_copy, *route, *tier, *root_port, dp),
                        || pump_bound_devices(c),
                    )
                    .await;
                    match outcome {
                        AttachOutcome::Keyboard
                        | AttachOutcome::Mouse
                        | AttachOutcome::Touchpad
                        | AttachOutcome::RmiElanTouchpad
                        | AttachOutcome::GenericHid
                        | AttachOutcome::ConsumerControl
                        | AttachOutcome::SerialAcm
                        | AttachOutcome::SerialVendor
                        | AttachOutcome::MassStorage
                        | AttachOutcome::AudioClass
                        | AttachOutcome::VideoClass
                        | AttachOutcome::NetworkClass
                        | AttachOutcome::Bluetooth
                        | AttachOutcome::WbdiFingerprint
                        | AttachOutcome::Fingerprint
                        | AttachOutcome::CcidReader
                        | AttachOutcome::CtapToken
                        | AttachOutcome::UsbClassDriver
                        | AttachOutcome::Hub => {
                            new_bound_bits |= dpb;
                            hub_fail_count.remove(&(*hub_slot, dp));
                        }
                        AttachOutcome::UnknownClass => {
                            let fails = hub_fail_count.entry((*hub_slot, dp)).or_insert(0);
                            *fails = fails.saturating_add(1);
                            if *fails == MAX_PER_PORT_RETRIES {
                                use core::fmt::Write as _;
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "  usb-supervisor: xhci{} hub slot {} port {} gave up after {} attempts",
                                    c.id(),
                                    hub_slot,
                                    dp,
                                    MAX_PER_PORT_RETRIES
                                );
                            }
                        }
                    }
                }
                if new_bound_bits != 0 {
                    // Sets the bound bits AND stamps each newly
                    // bound port's activity tick — a port's idle
                    // window runs from bind, not from the boot
                    // epoch its tick initialised to (#840).
                    attach::mark_ports_bound(c.id(), *hub_slot, new_bound_bits);
                }
            }

            SUPERVISOR_PHASE.store(7, core::sync::atomic::Ordering::Relaxed);
            // Wake hub ports a live HID binding sits on before
            // the pumps poll them: a suspended port gates the
            // device's interrupt endpoint, so without this a hub
            // keyboard that idled into suspend would stay dead
            // even though it is bound and pumped every cycle
            // (#840). The wake opens a fresh idle window; see
            // `hid::resume_suspended_hub_ports`. The serial
            // classes get the same wake before their pumps: an
            // ACM console or USB-serial dongle behind an
            // autosuspended port is exactly as dead as the
            // keyboard was (#763).
            resume_bound_ports(c).await;
            // NIC wake-watch (#1256): unlike the unconditional
            // wake above, a suspended NIC port is resumed ONLY
            // on an observed remote-wakeup edge (the
            // C_PORT_SUSPEND change bit). Resuming every
            // suspended NIC port each cycle would defeat
            // autosuspend and WoL: the port must STAY
            // suspended while idle so the device can signal,
            // and TX demand wakes it through the send path
            // instead. Runs before the pumps so a woken
            // device's pump transfers on its next turn.
            // Bluetooth gets the same edge-triggered wake-watch
            // (#820): a parked BT controller resumes only when
            // it signals remote wakeup, or when host TX demand
            // resumes its port through the transport.
            wake_suspended_nic_ports(c).await;
            btusb::wake_suspended_ports(c).await;
            pump_bound_devices(c);
            SUPERVISOR_PHASE.store(8, core::sync::atomic::Ordering::Relaxed);
            // Power management: suspend any downstream port whose
            // last activity is older than IDLE_SUSPEND_NS. Pumps
            // above touch `last_activity_tick` via mark_port_activity
            // on each completed transfer, suspended HID ports are
            // resumed just before the pumps (opening a fresh idle
            // window), and the MSC BOT path feeds activity on each
            // completed transaction (resuming its port first if
            // suspended), so an actively-used device never gets
            // suspended; an idle USB stick / hub does.
            attach::idle_suspend_pass(c).await;
            SUPERVISOR_PHASE.store(9, core::sync::atomic::Ordering::Relaxed);
            // Inter-cycle delay: PARK on the timer wheel for ~100 ms
            // instead of busy-yielding. The old `while !pause.expired()
            // { yield_now().await }` form self-woke every executor round
            // for the full 100 ms — a perpetual runnable task that kept
            // the executor from ever halting (nr_running never hit 0),
            // pinned the CPU at 100%, and paced every scheduler round at
            // the cost of that spin. On an otherwise-idle single-flight
            // workload (off-box redis) that turned a sub-round wake into
            // a ~one-round (~230 µs) latency hit on EVERY request, since a
            // freshly-woken peer (the epoll-parked server) waited out a
            // full spinning round to be re-polled. The timer wheel now
            // fires reliably (one-shot TSC-deadline), so a real parked
            // sleep wakes this task on time AND lets the executor halt
            // between USB pump cycles.
            let _ = irq_vector;
            narf_time::sleep_ms(100).await;
        }
    })
}
