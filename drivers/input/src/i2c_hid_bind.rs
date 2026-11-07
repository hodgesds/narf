//! Auto-binding + input pump for HID-over-I2C devices.
//!
//! What this module does
//! ---------------------
//! 1. Walks every PNP0C50 child in the AML namespace.
//! 2. Decodes that child's `_CRS`, extracting the `I2cSerialBus`
//!    item (parent bus path + 7-bit slave address) and any
//!    `GpioInt` item (parent GPIO path + pin) that wires the
//!    device's attention line.
//! 3. Looks up the parent I2C controller in
//!    `narf_drivers_i2c::registry` by the `ResourceSource` AML path
//!    decoded from the bus item. If the bus isn't registered (no
//!    AMD FCH controller, controller not yet probed, etc.) the
//!    child is skipped with a log line.
//! 4. Tries to evaluate `<child>._DSM` with the Microsoft
//!    HID-over-I2C UUID to discover the device's HID descriptor
//!    register. Falls back to 0x0001 — the conventional default
//!    used by AMD touchpad firmware when `_DSM` is absent. This is
//!    a workable bring-up shortcut; once `_DSM` evaluation against
//!    Buffer + Package args lands in narf-aml the fallback turns
//!    into the rare case.
//! 5. Constructs an `I2cHidDriver`, registers a GPIO IRQ handler
//!    that flips the device's wake flag (when `GpioInt` was
//!    decoded and the parent GPIO controller is registered), and
//!    spawns an async pump task per device.
//!
//! Pump task
//! ---------
//! For each bound device the pump:
//! - Calls `I2cHidDriver::bring_up()` (read descriptor + RESET
//!   with bounded retry/backoff + POWER_ON).
//! - Reads the Report Descriptor and parses it via `narf_hid`.
//! - Detects a Microsoft Precision Touchpad profile via
//!   `narf_hid::ptp::detect`. When present, pump-decoded contact
//!   deltas are pushed as `narf_input::PointerEvent`s on the
//!   global ring.
//! - Loops: wait on the wake flag (set by the GPIO ISR) — or, if
//!   no GPIO IRQ is wired, yield + retry — read one input report,
//!   decode, push. Bus errors back off, then escalate to a
//!   RESET/re-bind; a device that cannot RESET after the bounded
//!   budget is unregistered (router + sysfs) and the pump exits
//!   (issue #771).
//!
//! Sources:
//! - Microsoft "HID over I2C Protocol Specification" v1.0 — _DSM
//!   UUID + descriptor register convention + SET_FEATURE shape.
//! - Microsoft "Windows Precision Touchpad Required HID Top-Level
//!   Collections" — Device Mode Feature report wire format.
//! - ACPI 6.5 §6.4.3.8 — `_CRS` `I2cSerialBus` and `GpioInt`
//!   resource template encoding.
//! - Linux `drivers/hid/hid-multitouch.c::mt_set_input_mode` —
//!   reference for SET_FEATURE(Device Mode = MULTI_TOUCH) at
//!   driver-probe time. Read post-relicense (GPL-2.0-or-later).

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_aml::resource::ResourceItem;
use narf_drivers_gpio::{GpioIrqConfig, GpioPull};
use narf_drivers_i2c::{registry as i2c_registry, I2cBus};
use narf_input::evdev::{DeviceId, DeviceNode};
use narf_lib::sync::IrqSafeSpinLock;

use crate::i2c_hid::{I2cHidDriver, I2cHidError, RetryPolicy, POWER_ON};

/// Default HID descriptor register used when `_DSM` evaluation is
/// unavailable. The Microsoft spec leaves this device-defined; AMD
/// touchpad firmware ships with 0x0001 as the de-facto convention.
const DEFAULT_HID_DESC_REGISTER: u16 = 0x0001;

/// Consecutive bus errors in the report loop before the pump
/// escalates to a RESET/re-bind attempt. Grounded in the tree's
/// standing transient-error bound: USB CCID `MAX_RETRIES = 3`.
const MAX_CONSECUTIVE_BUS_ERRORS: u32 = 3;

/// RESET/re-bind attempts per recovery epoch before the pump
/// gives up, unregisters the device and exits. Same CCID bound:
/// a device that cannot RESET three times is wedged, not glitchy.
const MAX_RESET_ATTEMPTS: u32 = 3;

/// What the pump should do after a bus error in the report loop
/// (issue #771). Pure decision — see `PumpRecovery`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Transient error: sleep this long, then re-read.
    Backoff(u64),
    /// Wedged device: RESET + re-bring-up (re-bind), then re-read.
    Reset,
    /// Recovery budget spent: unregister + exit the pump.
    GiveUp,
}

/// Report-loop recovery state machine (issue #771). Pure logic —
/// no I/O, no sleep — so fixtures can drive it through the full
/// error → backoff → RESET → give-up sequence without a bus.
///
/// Epochs: a successful report clears the consecutive-error
/// count; a successful RESET clears both counts, starting a
/// fresh epoch. The total work per epoch is bounded:
/// `MAX_CONSECUTIVE_BUS_ERRORS` backoffs + `MAX_RESET_ATTEMPTS`
/// resets, then `GiveUp` — the pump never spins forever on a
/// wedged device again.
#[derive(Copy, Clone, Debug, Default)]
pub struct PumpRecovery {
    consecutive_errors: u32,
    reset_attempts: u32,
    policy: RetryPolicy,
}

impl PumpRecovery {
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            consecutive_errors: 0,
            reset_attempts: 0,
            policy,
        }
    }

    /// One bus error arrived. Returns the next action.
    pub fn on_bus_error(&mut self) -> RecoveryAction {
        self.consecutive_errors += 1;
        if self.consecutive_errors <= MAX_CONSECUTIVE_BUS_ERRORS {
            return RecoveryAction::Backoff(self.policy.backoff_ms(self.consecutive_errors - 1));
        }
        if self.reset_attempts < MAX_RESET_ATTEMPTS {
            self.reset_attempts += 1;
            self.consecutive_errors = 0;
            return RecoveryAction::Reset;
        }
        RecoveryAction::GiveUp
    }

    /// A report read cleanly: transient errors are forgiven.
    pub fn on_report_ok(&mut self) {
        self.consecutive_errors = 0;
    }

    /// A RESET/re-bind recovered the device: fresh epoch.
    pub fn on_reset_ok(&mut self) {
        self.consecutive_errors = 0;
        self.reset_attempts = 0;
    }
}

/// The evdev nodes one bound I2C-HID device owns (issue #771).
/// The pump used to discard every `DeviceId` `register_device`
/// returned, so no production path could ever unregister the
/// device — the router + sysfs entries leaked for the life of the
/// boot. `BoundNodes` keeps the ids and unregisters all of them
/// when the pump gives up on a wedged device; the router's
/// `DeviceChange::Removed` hook then unpublishes the sysfs
/// `inputN`/`eventN` entries (see `filesystem::sysfs`).
#[derive(Debug)]
pub struct BoundNodes {
    ids: Vec<DeviceId>,
}

impl BoundNodes {
    pub fn new() -> Self {
        Self { ids: Vec::new() }
    }

    /// Register a node and remember its id for later unregister.
    pub fn register(
        &mut self,
        caps: narf_input::evdev::DeviceCaps,
    ) -> alloc::sync::Arc<DeviceNode> {
        let (id, node) = narf_input::evdev::ROUTER.register_device(caps);
        self.ids.push(id);
        node
    }

    /// Unregister every node this device owns. Idempotent —
    /// `unregister_device` is a no-op for unknown ids.
    pub fn unregister_all(&mut self) {
        for id in self.ids.drain(..) {
            narf_input::evdev::ROUTER.unregister_device(id);
        }
    }

    /// Ids currently owned (test visibility).
    pub fn ids(&self) -> &[DeviceId] {
        &self.ids
    }
}

impl Default for BoundNodes {
    fn default() -> Self {
        Self::new()
    }
}

/// ACPI paths with a live pump task. `bind_all()` is re-runnable
/// (it is the re-bind entry point after a pump gives up), so a
/// second run must not spawn a duplicate pump for a device whose
/// pump is still alive — two pumps would both read the same
/// device and double-deliver every report. The pump removes its
/// path on exit.
static BOUND_PATHS: IrqSafeSpinLock<Vec<String>> = IrqSafeSpinLock::new(Vec::new());

/// Pin → wake-flag table consulted by the GPIO ISR. Single AMD FCH
/// GPIO block per system, so the pin number alone keys the lookup;
/// extending to multi-controller systems would key on
/// `(controller_name_hash, pin)`.
static PIN_WAKES: IrqSafeSpinLock<Vec<(u16, &'static AtomicBool)>> =
    IrqSafeSpinLock::new(Vec::new());

/// GPIO ISR shim. Sets every wake flag whose pin matches.
fn on_gpio_irq(pin: u16) {
    let g = PIN_WAKES.lock();
    for (p, flag) in g.iter() {
        if *p == pin {
            flag.store(true, Ordering::Release);
        }
    }
}

/// Drop one pin → wake-flag entry (pump exit, or the
/// `register_irq` failure path in `bind_one`). The flag itself is
/// leaked by design (`Box::leak` in `bind_one`); only the lookup
/// entry is removed so a rebound device does not accumulate stale
/// entries.
fn remove_pin_wake(pin: u16, flag: &'static AtomicBool) {
    let mut g = PIN_WAKES.lock();
    if let Some(idx) = g
        .iter()
        .position(|(p, f)| *p == pin && core::ptr::eq(*f, flag))
    {
        g.swap_remove(idx);
    }
}

/// Walk + bind every HID-over-I2C device in the AML namespace.
///
/// Matches what Linux's `i2c-hid-acpi.c` does:
///   - `_HID == "PNP0C50"` (legacy HID-over-I2C ID)
///   - `_HID == "ACPI0C50"` (newer ACPI-spec ID; Phoenix-era
///     firmware tends to use this)
///   - Vendor `_HID` (e.g. `ELAN09BD`, `SYNA8002`) with
///     `PNP0C50` or `ACPI0C50` in the `_CID` list — Linux's
///     ACPI bus matcher walks both _HID and _CID; we replicate
///     that here.
///
/// Returns the number of devices successfully bound. Devices
/// missing their parent I2C bus, or missing `I2cSerialBus` in
/// `_CRS` entirely, are logged + skipped.
pub fn bind_all() -> usize {
    use alloc::collections::BTreeSet;
    use alloc::string::String;
    let mut bound = 0usize;
    let mut seen: BTreeSet<String> = BTreeSet::new();

    // Real-HW diagnostic: dump every AMDI*/AMD0* controller + its
    // direct children with _HID/_CID UNCONDITIONALLY. The dump
    // (a) logs to klog so the FB panel's klog tail shows the
    // device list, and (b) populates the AMDI-children count atom
    // so the panel can surface "are there any I2C slaves at all"
    // independent of klog visibility.
    let i2c_n = narf_aml::boot_i2c_ctrl_count();
    let pnp_n = narf_aml::boot_pnp0c50_count();
    let _ = writeln!(
        narf_console::Writer,
        "i2c-hid-bind: I2C-ctrl={} PNP0C50={} — subtree dump follows",
        i2c_n,
        pnp_n
    );
    narf_aml::dump_i2c_subtree();
    // Also enumerate every device in the namespace that has an
    // `I2cSerialBus` resource — covers touchpads / sensor hubs
    // whose parent I2C controller doesn't have a `_HID` we
    // recognise (Renoir 4700U: AMDI0005 is PEP, not I2C; the real
    // I2C controller has either no `_HID` or one not in our list).
    // The dump tells us which device is the touchpad + which
    // controller node we need to match.
    narf_aml::dump_i2c_slaves();
    // Full namespace dump — every device with its _HID/_CID.
    // Used to identify touchpads / fingerprint readers / sensor
    // hubs by vendor _HID prefix (ELAN, SYNA, GDIX, WCOM, etc.)
    // when their parent doesn't have a recognisable controller
    // HID. Verbose but it's one-shot at boot.
    narf_aml::dump_all_devices();
    // First pass: devices whose _HID matches directly.
    for &hid in &["PNP0C50", "ACPI0C50"] {
        for child in narf_aml::find_all_devices_by_hid(hid) {
            if seen.insert(child.path.clone()) && bind_one(&child.path) {
                bound += 1;
            }
        }
    }
    // Second pass: devices whose vendor _HID isn't PNP0C50 /
    // ACPI0C50 but whose _CID list includes one of them, OR
    // whose _HID has a known i2c-hid touchpad/touchscreen vendor
    // prefix. The Phoenix HawkPoint1 laptops in the bring-up
    // target group ship touchpads with vendor _HIDs (ELANxxxx,
    // SYNAxxxx, ETDxxxx, GDIXxxxx) — some declare PNP0C50 in
    // _CID, but firmware bugs / minimal DSDTs sometimes omit the
    // _CID. Whitelisting the vendor prefixes catches both cases.
    //
    // Risk: a vendor _HID doesn't guarantee the device speaks
    // i2c-hid (Synaptics RMI4 has its own wire format). In
    // practice modern laptops ship i2c-hid-compatible firmware
    // even from these vendors; a mismatch surfaces as
    // `read_descriptor failed` in the pump task and the pump
    // exits cleanly without crashing the kernel.
    const VENDOR_HID_PREFIXES: &[&str] = &[
        "ELAN", // Elan touchpads / touchscreens
        "SYNA", // Synaptics (most newer parts are i2c-hid)
        "ETD",  // Elantech (alternate Elan prefix)
        "GDIX", // Goodix touchscreens
        "WCOM", // Wacom digitizers
        "FTLX", // FocalTech
    ];
    let all_devices = narf_aml::list_all_device_paths();
    for path in all_devices {
        if seen.contains(&path) {
            continue;
        }
        let cids = narf_aml::device_cids(&path);
        let cid_match = cids.iter().any(|c| c == "PNP0C50" || c == "ACPI0C50");
        let hid_match = match narf_aml::device_hid(&path) {
            Some(h) => VENDOR_HID_PREFIXES.iter().any(|p| h.starts_with(p)),
            None => false,
        };
        if cid_match || hid_match {
            seen.insert(path.clone());
            if bind_one(&path) {
                bound += 1;
            }
        }
    }
    bound
}

fn bind_one(path: &str) -> bool {
    // A live pump already owns this path — `bind_all()` is
    // re-runnable (the re-bind entry point after a pump gives up),
    // but a second pump for the same device would double-deliver
    // every report.
    if BOUND_PATHS.lock().iter().any(|p| p == path) {
        return false;
    }
    let items = match narf_aml::prt_crs::evaluate_crs_for(path) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-bind: {}: _CRS eval failed ({:?})",
                path,
                e
            );
            return false;
        }
    };

    let mut bus_path: Option<String> = None;
    let mut slave_addr: Option<u8> = None;
    let mut gpio_path: Option<String> = None;
    let mut gpio_pin: Option<u16> = None;
    let mut gpio_irq_cfg: Option<GpioIrqConfig> = None;
    let mut gpio_pull: GpioPull = GpioPull::Default;

    for it in &items {
        match it {
            ResourceItem::I2cSerialBus {
                slave_address,
                resource_source,
                ..
            } => {
                bus_path = Some(resource_source.clone());
                slave_addr = Some((*slave_address & 0x7f) as u8);
            }
            ResourceItem::GpioInt {
                level_triggered,
                polarity,
                pin_config,
                pins,
                resource_source,
                ..
            } => {
                gpio_path = Some(resource_source.clone());
                gpio_pin = pins.first().copied();
                gpio_irq_cfg = Some(GpioIrqConfig {
                    level_triggered: *level_triggered,
                    polarity: *polarity,
                });
                gpio_pull = match pin_config {
                    1 => GpioPull::Up,
                    2 => GpioPull::Down,
                    3 => GpioPull::None,
                    _ => GpioPull::Default,
                };
            }
            _ => {}
        }
    }

    let (bus_name, addr) = match (bus_path.as_deref(), slave_addr) {
        (Some(b), Some(a)) => (b, a),
        _ => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-bind: {}: no I2cSerialBus in _CRS, skipping",
                path
            );
            return false;
        }
    };

    let bus: Arc<dyn I2cBus> = match i2c_registry::find(bus_name) {
        Some(b) => b,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-bind: {}: parent bus {:?} not registered, skipping",
                path,
                bus_name
            );
            return false;
        }
    };

    let hid_desc_register = resolve_hid_desc_register(path).unwrap_or(DEFAULT_HID_DESC_REGISTER);

    // Allocate the per-device wake flag. Leak it so the GPIO ISR can
    // borrow it for &'static (one of these per HID device, max ~5).
    let wake_flag: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));

    let mut wired_irq = false;
    if let (Some(gp), Some(pin), Some(cfg)) = (gpio_path.as_deref(), gpio_pin, gpio_irq_cfg) {
        if let Some(gpio) = narf_drivers_gpio::registry::find(gp) {
            PIN_WAKES.lock().push((pin, wake_flag));
            match gpio.register_irq(pin, gpio_pull, cfg, on_gpio_irq) {
                Ok(()) => {
                    wired_irq = true;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  i2c-hid-bind: {} → bus={} addr={:#04x} hid_desc_reg={:#06x} gpio={}:{} (irq)",
                        path, bus_name, addr, hid_desc_register, gp, pin
                    );
                }
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  i2c-hid-bind: {}: GPIO register_irq failed ({:?}); polling",
                        path,
                        e
                    );
                    // Drop the dangling wake registration since the
                    // ISR will never fire — keeps the lookup table
                    // tidy.
                    remove_pin_wake(pin, wake_flag);
                }
            }
        }
    }

    if !wired_irq {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-bind: {} → bus={} addr={:#04x} hid_desc_reg={:#06x} (polled)",
            path,
            bus_name,
            addr,
            hid_desc_register
        );
    }

    let device_path = path.to_string();
    let driver = I2cHidDriver::new(bus, addr, hid_desc_register);
    // Identity context for the evdev nodes the pump registers: the
    // ACPI _HID names the device, the ACPI leaf names its slot in the
    // I2C topology. Vendor/product/version join them once the pump
    // reads the HID descriptor.
    let identity = I2cHidIdentity {
        acpi_hid: narf_aml::device_hid(path).unwrap_or_else(|| String::from("PNP0C50")),
        phys: {
            let leaf = path
                .trim_end_matches('\\')
                .rsplit(['\\', '.'])
                .next()
                .unwrap_or("hid");
            alloc::format!("i2c-{leaf}/input0")
        },
    };
    // Stackful: per-device i2c-hid input pump.
    BOUND_PATHS.lock().push(device_path.clone());
    narf_scheduler::spawn_stackful(pump_task(
        device_path,
        identity,
        driver,
        wake_flag,
        wired_irq,
        gpio_pin,
    ));
    true
}

/// ACPI-derived identity shared by every evdev collection one
/// HID-over-I2C device presents.
#[derive(Clone, Debug)]
struct I2cHidIdentity {
    acpi_hid: String,
    phys: String,
}

impl I2cHidIdentity {
    /// A caps template carrying this device's real identity for one
    /// collection class (`"Touchpad"`, `"Touchscreen"`, `"Pen"`,
    /// `"Keyboard"`): `<_HID> <class>` as the name, the I2C topology
    /// string as phys, and the HID descriptor's vendor/product/version
    /// on `BUS_I2C`.
    fn caps(
        &self,
        class: &str,
        desc: &crate::i2c_hid::HidDescriptor,
    ) -> narf_input::evdev::DeviceCaps {
        let mut caps = narf_input::evdev::DeviceCaps::new();
        caps.set_identity(
            &alloc::format!("{} I2C-HID {}", self.acpi_hid, class),
            &self.phys,
            "",
            narf_input::evdev::InputId::new(
                narf_input::evdev::bus::I2C,
                desc.w_vendor_id,
                desc.w_product_id,
                desc.w_version_id,
            ),
        );
        caps
    }
}

/// One probed sensor collection on an I2C-HID device: its decode
/// profile plus the descriptor unit exponent its reports carry.
pub(crate) struct SensorRoute {
    profile: crate::hid_sensor::HidSensorProfile,
    unit_exp: i32,
}

/// Per-device publication key source. Each bound PNP0C50 device
/// takes a unique key so its sensors never alias another hub's in
/// the `hid_sensor_pub` registry.
static NEXT_SENSOR_DEVICE_KEY: AtomicU32 = AtomicU32::new(0);

/// Route one raw input report to a sensor collection, if it carries
/// one of the routes' report IDs. On a successful decode the reading
/// is unit-rescaled and published through `hid_sensor_pub`; returns
/// `true` when the report was consumed as a sensor report.
///
/// A report whose ID matches a route but fails to decode is dropped
/// (`false`, no fall-through aliasing onto another class). Reports
/// on a no-report-ID descriptor are tried against each route in
/// order until one decodes.
pub(crate) fn route_sensor_report(
    routes: &[SensorRoute],
    device_key: u32,
    payload: &[u8],
    timestamp_ns: u64,
) -> bool {
    for route in routes {
        let rid = route.profile.input_report_id;
        if rid != 0 && payload.first() != Some(&rid) {
            continue;
        }
        match crate::hid_sensor::decode_report(&route.profile, payload, timestamp_ns) {
            Ok(ev) => {
                let ev = crate::hid_sensor::rescale_event(ev, route.unit_exp);
                crate::hid_sensor_pub::publish(
                    crate::hid_sensor_pub::SensorSource::I2cHid,
                    device_key,
                    route.profile.kind,
                    ev,
                );
                return true;
            }
            Err(_) => {
                if rid != 0 {
                    return false;
                }
            }
        }
    }
    false
}

/// Push the keyboard node's LED state to the device when it moved
/// since the last successful send. Runs in pump (task) context —
/// the pump owns the driver, so unlike the i8042 path no sink hook
/// is registered on the node; the input core still owns the state
/// (lock-key presses toggle it in `DeviceNode::dispatch`, evdev
/// `write()`s of `EV_LED` records set it). A userspace-driven change
/// is picked up at the next keyboard/consumer report. A failed send
/// leaves `sent` stale so the next report retries.
async fn sync_kbd_leds(
    driver: &I2cHidDriver,
    node: &narf_input::evdev::DeviceNode,
    profile: &Option<narf_hid::keyboard::LedOutputProfile>,
    sent: &mut u16,
) {
    let want = node.led_state();
    if want == *sent {
        return;
    }
    match profile {
        Some(lp) => {
            let body = crate::i2c_hid_keyboard::led_report_body(lp, want);
            if driver.set_output_report(lp.report_id, &body).await.is_ok() {
                *sent = want;
            }
        }
        // No LED Output field in this descriptor: latch the state
        // so we don't re-check on every report; the core bitmap
        // (EVIOCGLED) still reflects reality.
        None => *sent = want,
    }
}

/// Push the Elan touchpad node's mute-LED state to the device
/// when it moved since the last successful send. Runs in pump
/// (task) context — the pump owns the driver. Mirrors
/// `sync_kbd_leds`: the input core owns the mute state (`EV_LED`
/// `LED_MUTE` bit on the node's bitmap, written by userspace
/// `EV_LED` writes or by the `elan:red:mute` LED class device);
/// the pump diffs it against the last driven state after every
/// Elan report and issues the 0xBC feature report only on change.
/// A failed send leaves the driven state stale so the next report
/// retries. Non-LED devices never reach here — their
/// `ElanMuteLed` answers `None` to every decision — but the
/// guard holds even if one did.
pub(crate) async fn sync_elan_mute_led(
    driver: &I2cHidDriver,
    node: &narf_input::evdev::DeviceNode,
    led: &mut crate::hid_elan::ElanMuteLed,
) {
    let Some(on) = led.pending_drive(crate::hid_elan::mute_from_led_bitmap(node.led_state()))
    else {
        return;
    };
    let body = crate::hid_elan::encode_mute_led(on);
    if driver
        .set_feature_report(crate::hid_elan::ELAN_MUTE_LED_REPORT, &body[1..])
        .await
        .is_ok()
    {
        led.mark_driven(on);
    }
}

/// Per-device pump future. Owns the driver. Loops forever — exits
/// only if the bus returns a fatal error.
///
/// Lifecycle teardown lives here, not in the inner pump: on any
/// exit the GPIO wake entry and the bound-path record are removed
/// so a later `bind_all()` re-run can re-bind the device fresh.
/// (Evdev nodes are unregistered by the inner pump's give-up arm —
/// the only exit that runs after nodes exist; every earlier exit
/// happens before registration.)
async fn pump_task(
    path: String,
    identity: I2cHidIdentity,
    driver: I2cHidDriver,
    wake: &'static AtomicBool,
    irq_wired: bool,
    gpio_pin: Option<u16>,
) {
    pump_task_inner(path.clone(), identity, driver, wake, irq_wired).await;
    if let Some(pin) = gpio_pin {
        remove_pin_wake(pin, wake);
    }
    BOUND_PATHS.lock().retain(|p| *p != path);
}

async fn pump_task_inner(
    path: String,
    identity: I2cHidIdentity,
    mut driver: I2cHidDriver,
    wake: &'static AtomicBool,
    irq_wired: bool,
) {
    // Bounded bring-up (issue #771): descriptor + RESET with
    // retry/backoff + POWER_ON. A device that cannot RESET after
    // the bounded budget is wedged — the pump exits instead of
    // limping on with a half-initialised device, as the old code
    // did by swallowing the RESET failure.
    let hid_desc = match driver.bring_up(&RetryPolicy::default()).await {
        Ok(d) => d,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-pump: {}: bring-up failed ({:?}); pump exiting",
                path,
                e
            );
            return;
        }
    };

    let report_desc_blob = match driver.read_report_descriptor().await {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-pump: {}: read_report_descriptor failed ({:?}); pump exiting",
                path,
                e
            );
            return;
        }
    };
    let parsed = match narf_hid::parse(&report_desc_blob) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-pump: {}: HID descriptor parse failed ({:?}); pump exiting",
                path,
                e
            );
            return;
        }
    };
    let ptp = narf_hid::ptp::detect(&parsed);
    let touchscreen = narf_hid::touchscreen::detect(&parsed);
    let pen = narf_hid::pen::detect(&parsed);
    // Sensor collections (HID Usage Page 0x20). A generic I2C-HID
    // sensor hub's collections were previously never probed at all
    // (issue #773): enumerate them here, register each with the
    // publication layer, and let the report loop route their
    // reports through `route_sensor_report`.
    let sensor_device_key = NEXT_SENSOR_DEVICE_KEY.fetch_add(1, Ordering::Relaxed);
    let sensor_routes: Vec<SensorRoute> = crate::hid_sensor::enumerate_sensors(&parsed)
        .into_iter()
        .map(|profile| {
            crate::hid_sensor_pub::register_sensor(
                crate::hid_sensor_pub::SensorSource::I2cHid,
                sensor_device_key,
                profile.kind,
            );
            let unit_exp = profile.fields.first().map(|f| f.unit_exp).unwrap_or(0);
            SensorRoute { profile, unit_exp }
        })
        .collect();
    if !sensor_routes.is_empty() {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-pump: {}: {} sensor collection(s) published via hid_sensor_pub",
            path,
            sensor_routes.len()
        );
    }
    // Keyboard + Fn/media collections. A laptop's built-in keyboard
    // attaches over this same i2c-HID transport; a 2-in-1 device may
    // present BOTH a keyboard and a touch collection on one PNP0C50
    // node, so detection is additive and independent of the touch
    // routing above.
    let keyboard = narf_hid::keyboard::detect(&parsed);
    let consumer = narf_hid::keyboard::detect_consumer(&parsed);
    let _ = writeln!(
        narf_console::Writer,
        "  i2c-hid-pump: {}: descriptor parsed, fields={}, ptp={}, touchscreen={}, pen={}, keyboard={}, consumer={}",
        path,
        parsed.fields.len(),
        ptp.is_some(),
        touchscreen.is_some(),
        pen.is_some(),
        keyboard.is_some(),
        consumer.is_some(),
    );

    // Vendor touchpad transports (issue #765). A Synaptics RMI4
    // or Elan device in vendor format presents no PTP collection,
    // so the generic branches below would never fire for it —
    // without this step the pad binds as a silent generic device.
    // Detection keys off the ACPI _HID prefix and the HID
    // descriptor VID/PID; a failed vendor probe falls back to
    // the generic routing instead of dropping the device.
    let mut rmi_session: Option<crate::hid_rmi::HidRmiSession<'_>> = None;
    let mut rmi_probe: Option<crate::rmi4_core::Rmi4DeviceProbe> = None;
    let mut rmi_node: Option<Arc<narf_input::evdev::DeviceNode>> = None;
    let mut rmi_state = crate::rmi4_core::Rmi4PumpState::new();
    let mut elan_params: Option<crate::hid_elan::ElanDeviceParams> = None;
    let mut elan_node: Option<Arc<narf_input::evdev::DeviceNode>> = None;
    let mut elan_mute_led: Option<crate::hid_elan::ElanMuteLed> = None;
    let mut elan_state = crate::rmi4_core::Rmi4PumpState::new();
    if let Some(quirks) = crate::hid_rmi::classify_device(
        &identity.acpi_hid,
        hid_desc.w_vendor_id,
        hid_desc.w_product_id,
    ) {
        let mut session = crate::hid_rmi::HidRmiSession::new(
            &driver,
            hid_desc.w_max_output_length as usize,
            quirks,
        );
        match session.probe().await {
            Ok(probe) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  i2c-hid-pump: {}: RMI4-over-HID bound (manufacturer={}, f11={}, f12={}, f30={})",
                    path,
                    probe.product.manufacturer_id,
                    probe.f11.is_some(),
                    probe.f12.is_some(),
                    probe.f30.is_some(),
                );
                let caps = crate::i2c_hid_touch::build_rmi_caps(
                    &probe,
                    &identity.caps("Touchpad", &hid_desc),
                );
                let (_id, node) = narf_input::evdev::ROUTER.register_device(caps);
                rmi_node = Some(node);
                rmi_probe = Some(probe);
                rmi_session = Some(session);
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  i2c-hid-pump: {}: RMI4 probe failed ({:?}); falling back to generic HID",
                    path,
                    e
                );
            }
        }
    } else if let Some(elan_match) = crate::hid_elan::classify_device(
        &identity.acpi_hid,
        hid_desc.w_vendor_id,
        hid_desc.w_product_id,
    ) {
        match elan_probe(&driver).await {
            Ok(params) => {
                // HAS_LED comes from the device-id row (Linux
                // `ELAN_HAS_LED` driver_data); the prefix/VID
                // fallback rows carry no quirks, so an unlisted
                // Elan VID never gets an LED it may not have.
                let elan_has_led = elan_match
                    .quirks
                    .contains(crate::hid_elan::ElanQuirks::HAS_LED);
                let _ = writeln!(
                    narf_console::Writer,
                    "  i2c-hid-pump: {}: Elan vendor-format bound (max_x={}, max_y={}, mute_led={})",
                    path,
                    params.max_x,
                    params.max_y,
                    elan_has_led,
                );
                let caps = crate::i2c_hid_touch::build_elan_caps(
                    &params,
                    &identity.caps("Touchpad", &hid_desc),
                    elan_has_led,
                );
                let (_id, node) = narf_input::evdev::ROUTER.register_device(caps);
                if elan_has_led {
                    // Publishes /sys/class/leds/elan:red:mute/;
                    // brightness writes land on the node's LED_MUTE
                    // bit, which the pump syncs to hardware below.
                    crate::hid_elan::register_mute_led(node.clone());
                }
                elan_mute_led = Some(crate::hid_elan::ElanMuteLed::new(elan_has_led));
                elan_node = Some(node);
                elan_params = Some(params);
            }
            Err(e) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  i2c-hid-pump: {}: Elan probe failed ({:?}); falling back to generic HID",
                    path,
                    e
                );
            }
        }
    }

    // Register an evdev device node for the keyboard (and, if present,
    // the consumer row) so EV_KEY events reach `/dev/input/event*`
    // consumers — the same path the i8042 PS/2 driver uses. Every
    // node is owned by `bound`: if the pump later gives up on a
    // wedged device, `bound.unregister_all()` removes them all
    // (issue #771).
    let mut bound = BoundNodes::new();
    let kbd_node = if keyboard.is_some() || consumer.is_some() {
        let mut caps = crate::i2c_hid_keyboard::build_keyboard_caps();
        if consumer.is_some() {
            crate::i2c_hid_keyboard::add_consumer_caps(&mut caps);
        }
        let template = identity.caps("Keyboard", &hid_desc);
        caps.set_identity(&template.name, &template.phys, &template.uniq, template.id);
        let node = bound.register(caps);
        if let Some(kp) = &keyboard {
            crate::i2c_hid_keyboard::log_boot_summary(
                &path,
                kp.keys.report_count,
                kp.modifiers.is_some(),
                consumer.is_some(),
            );
        }
        Some(node)
    } else {
        None
    };

    // Register evdev nodes for the digitizer collections so userspace
    // (libinput) enumerates a real touchpad / touchscreen / pen with
    // this device's identity — previously these collections reached
    // only the in-kernel global ring and no `/dev/input/event*` node
    // existed for them at all (issue #764).
    let ptp_node = ptp.as_ref().map(|profile| {
        let caps =
            crate::i2c_hid_touch::build_ptp_caps(profile, &identity.caps("Touchpad", &hid_desc));
        bound.register(caps)
    });
    let touch_node = touchscreen.as_ref().map(|profile| {
        let caps = crate::i2c_hid_touch::build_touchscreen_caps(
            profile,
            &identity.caps("Touchscreen", &hid_desc),
        );
        bound.register(caps)
    });
    let pen_node = pen.as_ref().map(|profile| {
        let caps = crate::i2c_hid_touch::build_pen_caps(profile, &identity.caps("Pen", &hid_desc));
        bound.register(caps)
    });

    if let Some(profile) = &ptp {
        log_ptp_mode_set_result(&path, set_ptp_multi_touch_mode(&driver, profile).await);
    }

    // Record the device for system suspend/resume (#770): the PM
    // hooks rebuild a throwaway driver from this snapshot (bus +
    // descriptor + precomputed PTP mode report) because the pump
    // owns its driver instance. The mode bytes are recomputed
    // here rather than plumbed out of `set_ptp_multi_touch_mode`
    // so that helper's signature stays untouched.
    crate::i2c_hid_pm::record_device(
        &driver,
        ptp.as_ref().and_then(|p| {
            narf_hid::ptp::build_mode_feature_report(p, narf_hid::ptp::mode::MULTI_TOUCH)
        }),
    );

    if let Some(ts_profile) = &touchscreen {
        // One-line boot summary per the touchscreen Stage-0 spec.
        crate::i2c_hid_touch::log_boot_summary(&path, ts_profile);
    }

    if pen.is_some() {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-pump: {}: pen/stylus digitizer detected",
            path
        );
    }

    let max_input = driver
        .descriptor()
        .map(|d| d.w_max_input_length as usize)
        .unwrap_or(64);
    let mut buf: Vec<u8> = alloc::vec![0; max_input];

    // Per-device delta tracking (PTP path emits PointerEvent based
    // on first contact movement).
    let mut last_x: Option<i32> = None;
    let mut last_y: Option<i32> = None;
    let mut last_button = false;
    // Per-device PTP evdev slot tracker (the evdev node gets every
    // contact; the global-ring feed above it keeps first-contact
    // relative-pointer semantics for in-kernel consumers).
    let mut ptp_state =
        crate::i2c_hid_touch::PtpPumpState::new(ptp.as_ref().map(|p| p.contacts_max).unwrap_or(1));
    // Per-device touchscreen slot tracker (touchscreen path emits
    // TouchEvent per contact with normalised coordinates).
    let mut touch_state = crate::i2c_hid_touch::TouchPumpState::new();
    // Per-device pen/stylus state tracker.
    let mut pen_state = crate::i2c_hid_touch::PenPumpState::default();
    // Per-device keyboard + consumer report-diff trackers.
    let mut kbd_state = crate::i2c_hid_keyboard::KeyboardPumpState::new();
    let mut consumer_state = crate::i2c_hid_keyboard::ConsumerPumpState::new();
    // Keyboard LED Output profile (descriptor LED-page Output
    // field), resolved once; `kbd_led_sent` is the last LED bitmap
    // the device was successfully sent. The pump diffs the node's
    // core LED state against it after every keyboard/consumer
    // report — the same pattern as virtio-input's `sync_leds`.
    let led_profile = if keyboard.is_some() {
        narf_hid::keyboard::detect_led_output(&parsed)
    } else {
        None
    };
    let mut kbd_led_sent: u16 = 0;

    // Report-loop recovery state (issue #771). A wedged device
    // used to spin this loop forever on bus errors; now transient
    // errors back off, persistent ones escalate to RESET/re-bind,
    // and a device that cannot RESET gives up boundedly — the
    // pump unregisters its nodes and exits.
    let mut recovery = PumpRecovery::new(RetryPolicy::default());
    // Set while recovering: the next read must be attempted
    // immediately, not gated on the GPIO wake flag — a wedged
    // device never raises INT.
    let mut recovery_pending = false;

    loop {
        if irq_wired && !recovery_pending {
            // Wait for ISR to flip the flag. Yield each poll so peer
            // tasks (i8042, FB drain, init) make progress.
            while !wake.swap(false, Ordering::Acquire) {
                narf_scheduler::yield_now().await;
            }
        } else {
            narf_scheduler::yield_now().await;
        }
        recovery_pending = false;

        let n = match driver.read_input_report(&mut buf).await {
            Ok(n) => {
                recovery.on_report_ok();
                n
            }
            Err(I2cHidError::Bus(_)) => {
                match recovery.on_bus_error() {
                    RecoveryAction::Backoff(ms) => {
                        narf_time::sleep_ms(ms).await;
                        recovery_pending = true;
                        continue;
                    }
                    RecoveryAction::Reset => {
                        // NOTE: this is `bring_up` minus the descriptor
                        // re-read. `bring_up` takes `&mut self` only
                        // for `read_descriptor` (it writes
                        // `self.descriptor`); the vendor sessions
                        // (`rmi_session`, `elan_*`) borrow `driver`
                        // for the whole pump loop, so a `&mut` borrow
                        // cannot coexist here. The descriptor is
                        // static firmware data already read at bind
                        // time, so the Reset path performs bring_up's
                        // remaining steps — RESET with bounded retry
                        // + best-effort POWER_ON — through the `&self`
                        // methods.
                        match driver.reset_with_retry(&RetryPolicy::default()).await {
                            Ok(_) => {
                                // SET_POWER is best-effort (same as
                                // `bring_up`): some devices ignore it
                                // and still report.
                                if let Err(e) = driver.set_power(POWER_ON).await {
                                    let _ = writeln!(
                                        narf_console::Writer,
                                        "  i2c-hid-pump: {}: RESET/re-bind SET_POWER(ON) failed ({:?}); continuing",
                                        path,
                                        e
                                    );
                                }
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "  i2c-hid-pump: {}: RESET/re-bind recovered the device",
                                    path
                                );
                                recovery.on_reset_ok();
                            }
                            Err(e) => {
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "  i2c-hid-pump: {}: RESET/re-bind failed ({:?})",
                                    path,
                                    e
                                );
                                // Fall through to the next read: the
                                // state machine advances toward GiveUp
                                // on the next bus error.
                            }
                        }
                        recovery_pending = true;
                        continue;
                    }
                    RecoveryAction::GiveUp => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  i2c-hid-pump: {}: recovery budget spent; unregistering device, pump exiting",
                            path
                        );
                        bound.unregister_all();
                        return;
                    }
                }
            }
            Err(I2cHidError::BufferTooSmall) => {
                // Resize once, retry next loop.
                buf.resize(buf.len().saturating_mul(2).min(4096), 0);
                continue;
            }
            Err(_) => continue,
        };
        if n == 0 {
            continue;
        }

        let payload = &buf[..n];
        // Route by report id when the descriptor uses them. Keyboard,
        // consumer, PTP, Touch Screen and pen are distinct top-level
        // collections with distinct report ids, so the branches are
        // mutually exclusive per report.
        //
        // Keyboard first: a laptop's built-in keyboard shares this
        // transport, and a 2-in-1 may present keyboard + touch on one
        // node — routing the keyboard report here doesn't disturb the
        // touch branches below.
        if let (Some(profile), Some(node)) = (&keyboard, &kbd_node) {
            if profile.input_report_id == 0 || payload.first() == Some(&profile.input_report_id) {
                if let Ok(decoded) = narf_hid::keyboard::decode_input(profile, payload) {
                    crate::i2c_hid_keyboard::pump_report(node, &mut kbd_state, &decoded);
                    sync_kbd_leds(&driver, node, &led_profile, &mut kbd_led_sent).await;
                    continue;
                }
            }
        }
        if let (Some(profile), Some(node)) = (&consumer, &kbd_node) {
            if payload.first() == Some(&profile.input_report_id) {
                if let Ok(active) = narf_hid::keyboard::decode_consumer(profile, payload) {
                    crate::i2c_hid_keyboard::pump_consumer_report(
                        node,
                        &mut consumer_state,
                        &active,
                    );
                    sync_kbd_leds(&driver, node, &led_profile, &mut kbd_led_sent).await;
                    continue;
                }
            }
        }
        // Vendor transports: their report IDs never collide with
        // PTP / touchscreen / pen IDs on the same device, and a
        // vendor-format device must not fall through to the
        // generic PTP decoder (its bytes are not PTP reports).
        // A report the vendor path does not recognise falls
        // through to the generic branches below (combo devices).
        if let (Some(session), Some(probe), Some(node)) = (&mut rmi_session, &rmi_probe, &rmi_node)
        {
            if payload.first() == Some(&crate::hid_rmi::RMI_ATTN_REPORT_ID) {
                if let Some(attn) = crate::hid_rmi::AttnReport::decode(payload) {
                    pump_rmi_attn(session, probe, &attn, &mut rmi_state, node).await;
                }
                continue;
            }
        }
        if let (Some(params), Some(node)) = (&elan_params, &elan_node) {
            if payload.first() == Some(&crate::hid_elan::ELAN_MT_I2C) {
                if let Some(report) = crate::hid_elan::ElanReport::decode_i2c(payload, params.max_y)
                {
                    let contacts: Vec<crate::rmi4_core::Rmi4Contact> = report
                        .fingers
                        .iter()
                        .map(|f| crate::rmi4_core::Rmi4Contact {
                            present: f.present,
                            x: f.x as i32,
                            y: f.y as i32,
                            pressure: f.pressure as i32,
                        })
                        .collect();
                    elan_state.pump_contacts(
                        Some(node.as_ref()),
                        &contacts,
                        Some(report.btn_left),
                        crate::rmi4_core::Rmi4PumpBounds {
                            x_min: 0,
                            x_max: params.max_x as i32,
                            y_min: 0,
                            y_max: params.max_y as i32,
                        },
                    );
                    // Mute LED follows the node's LED_MUTE bit
                    // (issue #1684); a change since the last send
                    // issues the 0xBC feature report, a failure
                    // retries on the next Elan report.
                    if let Some(mute) = elan_mute_led.as_mut() {
                        sync_elan_mute_led(&driver, node, mute).await;
                    }
                }
                continue;
            }
        }
        if let Some(profile) = &ptp {
            if payload.first() == Some(&profile.input_report_id) {
                if let Ok(decoded) = narf_hid::ptp::decode_input(profile, payload) {
                    push_ptp_pointer(&decoded, &mut last_x, &mut last_y, &mut last_button);
                    if let Some(node) = &ptp_node {
                        crate::i2c_hid_touch::pump_ptp_report_to_evdev(
                            profile,
                            &mut ptp_state,
                            node,
                            &decoded,
                        );
                    }
                }
                continue;
            }
        }
        if let Some(ts_profile) = &touchscreen {
            // Touchscreen descriptors with Report ID prefix every
            // wire report with one byte; descriptors without IDs
            // deliver bytes directly. `decode_input` accepts both.
            if ts_profile.input_report_id == 0
                || payload.first() == Some(&ts_profile.input_report_id)
            {
                if let Ok(decoded) = narf_hid::touchscreen::decode_input(ts_profile, payload) {
                    crate::i2c_hid_touch::pump_report_to_evdev(
                        ts_profile,
                        &mut touch_state,
                        &decoded,
                        touch_node.as_deref(),
                    );
                }
                continue;
            }
        }
        if let Some(pen_profile) = &pen {
            // Pen report IDs are always non-zero for spec-compliant
            // devices; the decode rejects mismatched IDs for us.
            if payload.first() == Some(&pen_profile.input_report_id) {
                if let Ok(decoded) = narf_hid::pen::decode_input(pen_profile, payload) {
                    crate::i2c_hid_touch::pump_pen_report_to_evdev(
                        &mut pen_state,
                        &decoded,
                        pen_node.as_deref(),
                    );
                }
            }
        }
        // Sensor collections last: their report IDs are distinct
        // from every class above in a well-formed descriptor, and an
        // unrouted report simply falls off the end of the loop.
        if !sensor_routes.is_empty()
            && route_sensor_report(
                &sensor_routes,
                sensor_device_key,
                payload,
                narf_time::monotonic_ns(),
            )
        {
            continue;
        }
    }
}

/// Translate a PTP `DecodedReport` to a single `PointerEvent` and
/// push it to the global input ring. First active contact (or
/// contact 0 when no contact is active) drives the cursor — relative
/// motion derived from the previous position.
fn push_ptp_pointer(
    decoded: &narf_hid::ptp::DecodedReport,
    last_x: &mut Option<i32>,
    last_y: &mut Option<i32>,
    last_button: &mut bool,
) {
    let active = decoded
        .contacts
        .iter()
        .take(decoded.contact_count as usize)
        .find(|c| c.tip_switch && c.in_range && c.confidence);
    let (dx, dy) = match active {
        Some(c) => {
            let dx = match *last_x {
                Some(prev) => c.x - prev,
                None => 0,
            };
            let dy = match *last_y {
                Some(prev) => c.y - prev,
                None => 0,
            };
            *last_x = Some(c.x);
            *last_y = Some(c.y);
            (dx, dy)
        }
        None => {
            *last_x = None;
            *last_y = None;
            (0, 0)
        }
    };
    let buttons = if decoded.button1 {
        narf_input::PointerButtons::LEFT
    } else {
        narf_input::PointerButtons::EMPTY
    };
    // Emit on any motion or any button transition; suppress
    // zero-delta no-button-change frames so the ring doesn't fill
    // with idle hover noise.
    let button_changed = decoded.button1 != *last_button;
    *last_button = decoded.button1;
    if dx == 0 && dy == 0 && !button_changed {
        return;
    }
    let _ = narf_input::push_global(narf_input::InputEvent::Pointer(narf_input::PointerEvent {
        dx,
        dy,
        buttons,
    }));
}

/// Microsoft HID-over-I2C `_DSM` UUID, in the byte order ACPI
/// expects (mixed-endian Microsoft GUID): the first 4-byte group is
/// little-endian, the next two 2-byte groups are little-endian, and
/// the trailing 8 bytes are big-endian. Source UUID:
/// 3CDFF6F7-4267-4555-AD05-B30A3D8938DE — the UUID real-HW DSDTs
/// publish for HID-over-I2C (matches Linux
/// `drivers/hid/i2c-hid/i2c-hid-acpi.c::i2c_hid_acpi_dsm_uuid`,
/// referenced here post-relicense for the byte order only).
const HID_OVER_I2C_DSM_UUID: [u8; 16] = [
    0xF7, 0xF6, 0xDF, 0x3C, // 3CDFF6F7 (LE)
    0x67, 0x42, // 4267      (LE)
    0x55, 0x45, // 4555      (LE)
    0xAD, 0x05, // AD05      (BE)
    0xB3, 0x0A, 0x3D, 0x89, 0x38, 0xDE, // B30A3D8938DE (BE)
];

/// Function index for "return the HID descriptor register address",
/// per the Microsoft spec §3.1.1.
const HID_OVER_I2C_DSM_FUNC_DESC_REG: u64 = 1;

/// Try to evaluate `<path>._DSM(HID-over-I2C UUID, rev=1, func=1, ())`
/// to discover the device's HID descriptor register. Returns `None`
/// when `_DSM` is absent, when it returns a non-Integer value (the
/// AML idiom for "function not implemented"), or when the integer
/// doesn't fit in u16.
fn resolve_hid_desc_register(path: &str) -> Option<u16> {
    let r = narf_aml::eval::evaluate_dsm(
        path,
        HID_OVER_I2C_DSM_UUID,
        1,
        HID_OVER_I2C_DSM_FUNC_DESC_REG,
        narf_aml::Value::Package(alloc::vec::Vec::new()),
    )
    .ok()?;
    let n = r.as_integer();
    if n == 0 || n > u16::MAX as u64 {
        return None;
    }
    Some(n as u16)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    PIN_WAKES.lock().clear();
    BOUND_PATHS.lock().clear();
}

/// Outcome of the PTP multi-touch mode-set request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PtpModeSetResult {
    /// SET_FEATURE was issued and the bus accepted it. The touchpad
    /// should now be emitting full multi-touch contact reports.
    Set,
    /// The PTP profile didn't expose a Device Mode feature item, so
    /// no SET_FEATURE was issued. The device runs in whatever mode
    /// its firmware default picks — usually legacy mouse-emulation.
    NoDeviceMode,
    /// SET_FEATURE write hit a bus error. The device probably stays
    /// in mouse-emulation mode; caller may retry.
    BusFailed(I2cHidError),
}

// ── Vendor-transport probe + pump helpers (issue #765) ─────────────

/// Elan probe over the async I2C-HID driver: switch the device
/// into absolute multi-touch mode, then run the SET+GET parameter
/// cycle for max-X / max-Y / resolution. Mirrors
/// `hid_elan::read_device_params` / `enable_absolute_mode`, which
/// are written against the sync `ElanHidIo` trait the async
/// driver cannot implement. A failure here means the device does
/// not answer the vendor protocol; the caller falls back to
/// generic HID routing.
pub(crate) async fn elan_probe(
    driver: &I2cHidDriver,
) -> Result<crate::hid_elan::ElanDeviceParams, I2cHidError> {
    use crate::hid_elan::{
        convert_resolution, encode_absolute_mode_feature, encode_param_query, param,
        ElanDeviceParams, ELAN_FEATURE_REPORT, ELAN_FEATURE_SIZE,
    };
    let abs_body = encode_absolute_mode_feature();
    driver
        .set_feature_report(ELAN_FEATURE_REPORT, &abs_body[1..])
        .await?;
    let max_x = elan_read_one_param(driver, param::MAX_X).await?;
    let max_y = elan_read_one_param(driver, param::MAX_Y).await?;
    let set = encode_param_query(param::RES);
    driver
        .set_feature_report(ELAN_FEATURE_REPORT, &set[1..])
        .await?;
    let resp = driver.get_feature_report(ELAN_FEATURE_REPORT).await?;
    if resp.len() < ELAN_FEATURE_SIZE {
        return Err(I2cHidError::ShortReport);
    }
    let res_x = convert_resolution(resp[3]);
    let res_y = convert_resolution(resp[4]);
    Ok(ElanDeviceParams {
        max_x,
        max_y,
        res_x_dots_per_mm: res_x,
        res_y_dots_per_mm: res_y,
    })
}

/// One SET+GET parameter cycle (Linux `elan_get_device_param()`,
/// `hid-elan.c:79-107`). The GET response is the 5-byte feature
/// report with the value LE at bytes [4:3].
async fn elan_read_one_param(driver: &I2cHidDriver, param_code: u8) -> Result<u16, I2cHidError> {
    use crate::hid_elan::{decode_param_response_le16, encode_param_query, ELAN_FEATURE_REPORT};
    let set = encode_param_query(param_code);
    driver
        .set_feature_report(ELAN_FEATURE_REPORT, &set[1..])
        .await?;
    let resp = driver.get_feature_report(ELAN_FEATURE_REPORT).await?;
    decode_param_response_le16(&resp).ok_or(I2cHidError::ShortReport)
}

/// Route one RMI4 ATTN report through the F$11 / F$12 decoders
/// and the shared contact pump.
///
/// Packing contract: an ATTN report whose interrupt mask has
/// exactly one bit set — the 2D sensor's — carries only that
/// function's packed data, decoded in place from `attn.data`.
/// When several functions fired at once (touch + button, or a
/// status change alongside the touch), the packed layout depends
/// on PDT order, so the 2D data is read back from its data
/// register instead — correct regardless of packing. Buttons
/// always come from an F$30 register read when the F$30 source
/// bit is set, never from the packed tail.
pub(crate) async fn pump_rmi_attn(
    session: &mut crate::hid_rmi::HidRmiSession<'_>,
    probe: &crate::rmi4_core::Rmi4DeviceProbe,
    attn: &crate::hid_rmi::AttnReport<'_>,
    state: &mut crate::rmi4_core::Rmi4PumpState,
    node: &narf_input::evdev::DeviceNode,
) {
    use crate::rmi4_core::{
        decode_f12_data1, Rmi4Contact, F11_2D_TOUCHPAD, F12_2D_TOUCHPAD_NEXT, F12_OBJECT_SIZE,
    };
    use narf_input::rmi4::TouchpadReport;

    let sources = attn.interrupt_sources;
    let f12_mask = probe.source_mask_for(F12_2D_TOUCHPAD_NEXT);
    let f11_mask = probe.source_mask_for(F11_2D_TOUCHPAD);
    let btn_left = read_rmi_buttons(session, probe, sources).await;

    // F$12 (modern 2D sensor) takes precedence — a device never
    // exposes both F$11 and F$12 as its touch sensor.
    if f12_mask != 0 && sources & f12_mask != 0 {
        if let Some(f12) = &probe.f12 {
            let single_source = sources == f12_mask;
            let nobj = attn.data.len() / F12_OBJECT_SIZE;
            let decoded = if single_source && nobj > 0 {
                decode_f12_data1(attn.data, nobj).ok()
            } else {
                // Multi-source ATTN: read Data 1 back from the
                // register (5 objects; the true object count
                // comes from the F$12 query at probe time —
                // remainder).
                let mut buf = alloc::vec![0u8; 5 * F12_OBJECT_SIZE];
                match session.read_block(f12.data_base as u16, &mut buf).await {
                    Ok(()) => decode_f12_data1(&buf, 5).ok(),
                    Err(_) => None,
                }
            };
            if let Some(objs) = decoded {
                let contacts: Vec<Rmi4Contact> = objs
                    .iter()
                    .map(|o| Rmi4Contact {
                        present: o.present && o.is_touching_finger(),
                        x: o.x as i32,
                        y: o.y as i32,
                        pressure: o.z as i32,
                    })
                    .collect();
                state.pump_contacts(
                    Some(node),
                    &contacts,
                    btn_left,
                    crate::rmi4_core::Rmi4PumpBounds {
                        x_min: 0,
                        x_max: 0xFFFF,
                        y_min: 0,
                        y_max: 0xFFFF,
                    },
                );
            }
        }
        return;
    }
    if f11_mask != 0 && sources & f11_mask != 0 {
        if let Some(f11) = &probe.f11 {
            let single_source = sources == f11_mask;
            // F$11 frame: 1 finger-state byte + 5 bytes per finger.
            let max_fingers = 5usize;
            let decoded = if single_source {
                TouchpadReport::parse(attn.data, max_fingers).ok()
            } else {
                let mut buf = alloc::vec![0u8; 1 + max_fingers * 5];
                match session.read_block(f11.data_base as u16, &mut buf).await {
                    Ok(()) => TouchpadReport::parse(&buf, max_fingers).ok(),
                    Err(_) => None,
                }
            };
            if let Some(rep) = decoded {
                let contacts: Vec<Rmi4Contact> = rep
                    .fingers
                    .iter()
                    .map(|f| Rmi4Contact {
                        present: f.present,
                        x: f.x as i32,
                        y: f.y as i32,
                        pressure: 0,
                    })
                    .collect();
                state.pump_contacts(
                    Some(node),
                    &contacts,
                    btn_left,
                    crate::rmi4_core::Rmi4PumpBounds {
                        x_min: 0,
                        x_max: 0x0FFF,
                        y_min: 0,
                        y_max: 0x0FFF,
                    },
                );
            }
        }
    }
}

/// Read the F$30 button bitmap when the F$30 source bit fired in
/// this ATTN. Returns `Some(BTN_LEFT)` on a successful read and
/// `None` when the button state is unknown this frame (no F$30
/// function, no F$30 source, or the register read failed) — the
/// pump then holds the previous button state instead of
/// synthesising a release.
async fn read_rmi_buttons(
    session: &mut crate::hid_rmi::HidRmiSession<'_>,
    probe: &crate::rmi4_core::Rmi4DeviceProbe,
    sources: u8,
) -> Option<bool> {
    use crate::hid_rmi::clickpad_btn_left;
    use crate::rmi4_core::{decode_f30_buttons, F30_GPIO_LED};
    let f30 = probe.f30.as_ref()?;
    if sources & probe.source_mask_for(F30_GPIO_LED) == 0 {
        return None;
    }
    // F$30 data registers: one bit per GPIO, active-low. Read
    // enough bytes for the probe-time GPIO/LED line count
    // (capped at 32 lines / 4 bytes).
    let nbytes = (probe.f30_gpio_count.min(32) as usize).div_ceil(8).max(1);
    let mut buf = alloc::vec![0u8; nbytes];
    if session
        .read_block(f30.data_base as u16, &mut buf)
        .await
        .is_err()
    {
        return None;
    }
    match decode_f30_buttons(&buf, probe.f30_gpio_count) {
        Ok(bitmap) => Some(clickpad_btn_left(bitmap)),
        Err(_) => None,
    }
}

/// Send the Microsoft Precision Touchpad SET_FEATURE(Device Mode =
/// MULTI_TOUCH) request that switches a PTP-capable touchpad out
/// of legacy mouse-emulation mode and into multi-touch reporting.
///
/// Without this the touchpad emits a 3-byte boot-style mouse report
/// instead of the full per-contact array — two-finger gestures /
/// multi-touch are lost. Linux's equivalent is
/// `drivers/hid/hid-multitouch.c::mt_set_input_mode`. Microsoft's
/// "Windows Precision Touchpad Required HID Top-Level Collections"
/// §3.1.6 "Device Mode Feature Report" specifies the wire format.
///
/// Returns `PtpModeSetResult::NoDeviceMode` when the descriptor
/// lacks a Device Mode feature (Windows treats those as non-PTP),
/// `Set` on success, or `BusFailed` if the SET_FEATURE write
/// errored on the bus.
pub async fn set_ptp_multi_touch_mode(
    driver: &I2cHidDriver,
    profile: &narf_hid::ptp::PtpProfile,
) -> PtpModeSetResult {
    let Some(buf) =
        narf_hid::ptp::build_mode_feature_report(profile, narf_hid::ptp::mode::MULTI_TOUCH)
    else {
        return PtpModeSetResult::NoDeviceMode;
    };
    // Wire buffer is [report_id, body...]; SET_REPORT takes them as
    // separate args.
    let report_id = buf[0];
    let body = &buf[1..];
    match driver.set_feature_report(report_id, body).await {
        Ok(()) => PtpModeSetResult::Set,
        Err(e) => PtpModeSetResult::BusFailed(e),
    }
}

fn log_ptp_mode_set_result(path: &str, r: PtpModeSetResult) {
    match r {
        PtpModeSetResult::Set => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-pump: {}: PTP multi-touch mode set",
                path
            );
        }
        PtpModeSetResult::NoDeviceMode => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-pump: {}: PTP profile lacks Device Mode feature; staying in default mode",
                path
            );
        }
        PtpModeSetResult::BusFailed(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-pump: {}: PTP mode-set failed ({:?}); device may stay in mouse-emulation mode",
                path, e
            );
        }
    }
}

#[doc(hidden)]
pub fn __push_ptp_pointer_for_test(
    decoded: &narf_hid::ptp::DecodedReport,
    last_x: &mut Option<i32>,
    last_y: &mut Option<i32>,
    last_button: &mut bool,
) {
    push_ptp_pointer(decoded, last_x, last_y, last_button);
}

// ── Tests ────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // Publication round trip for the I2C-HID sensor path (issue
    // #773), exercising exactly the pump's sequence — parse →
    // enumerate → register → route — minus the I2C read. The
    // descriptor is built from the HID Sensor Usages shapes (accel
    // collection, report ID 1, usages 0x0453..=0x0455; ALS
    // collection, report ID 2, usage 0x04D1) via the decode layer's
    // spec-shaped builder, concatenated as one two-collection hub
    // descriptor. No unit exponent is declared, so the rescale is
    // the exponent-0 case of the unit contract:
    //   accel milli-g = raw × 10^6 / 9807 (truncating)
    //     raw  10 → 1019, raw −20 → −2039, raw 30 → 3059
    //   ALS lux passes through whole.
    fn smoke_i2c_hid_sensor_publication_round_trip() -> TestResult {
        crate::hid_sensor_pub::__reset_for_test();
        narf_filesystem::sysfs::__reset_for_test();
        crate::hid_sensor::init_sensor_ring();
        crate::hid_sensor::__reset_sensor_ring_for_test();

        let mut desc = crate::hid_sensor::build_test_descriptor(
            0x0073, // ACCEL_3D
            &[0x0453, 0x0454, 0x0455],
            1,
            true,
        );
        desc.extend_from_slice(&crate::hid_sensor::build_test_descriptor(
            0x0041, // ALS
            &[0x04D1],
            2,
            false,
        ));
        let parsed = match narf_hid::parse(&desc) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("hub descriptor did not parse"),
        };
        // Mirror the pump: register every enumerated collection and
        // build the route table under one device key.
        let device_key = 4242;
        let routes: Vec<SensorRoute> = crate::hid_sensor::enumerate_sensors(&parsed)
            .into_iter()
            .map(|profile| {
                crate::hid_sensor_pub::register_sensor(
                    crate::hid_sensor_pub::SensorSource::I2cHid,
                    device_key,
                    profile.kind,
                );
                let unit_exp = profile.fields.first().map(|f| f.unit_exp).unwrap_or(0);
                SensorRoute { profile, unit_exp }
            })
            .collect();
        if routes.len() != 2 {
            return TestResult::Fail("hub descriptor did not yield two sensor routes");
        }
        let infos = crate::hid_sensor_pub::sensors();
        let find = |kind: crate::hid_sensor::HidSensorKind| {
            infos.iter().find(|i| i.kind == kind).map(|i| i.id)
        };
        let (Some(accel), Some(als)) = (
            find(crate::hid_sensor::HidSensorKind::Accelerometer3D),
            find(crate::hid_sensor::HidSensorKind::AmbientLight),
        ) else {
            return TestResult::Fail("routes were not registered");
        };
        let show = |id: crate::hid_sensor_pub::SensorId, attr: &str| {
            narf_filesystem::sysfs::class_register("iio")
                .get_child(&alloc::format!("iio:device{}", id.0))
                .and_then(|k| k.attr_show(attr))
        };

        // Accel report: [rid=1][x=10][y=−20][z=30] as i16 LE.
        let mut accel_report = alloc::vec![1u8];
        for v in [10i16, -20, 30] {
            accel_report.extend_from_slice(&v.to_le_bytes());
        }
        if !route_sensor_report(&routes, device_key, &accel_report, 99) {
            return TestResult::Fail("accel report not routed");
        }
        if crate::hid_sensor_pub::latest(accel)
            != Some(crate::hid_sensor::SensorEvent::Accel3d {
                x_milli_g: 1019,
                y_milli_g: -2039,
                z_milli_g: 3059,
                timestamp_ns: 99,
            })
        {
            return TestResult::Fail("accel reading wrong after route + rescale");
        }
        if show(accel, "in_accel_z_raw").as_deref() != Some("3059\n") {
            return TestResult::Fail("accel reading not on the sysfs surface");
        }
        // ALS report: [rid=2][250 u16 LE] → 250 lux, accel untouched.
        if !route_sensor_report(&routes, device_key, &[2, 250, 0], 100) {
            return TestResult::Fail("ALS report not routed");
        }
        if show(als, "in_illuminance_raw").as_deref() != Some("250\n") {
            return TestResult::Fail("ALS reading not on the sysfs surface");
        }
        if show(accel, "in_accel_z_raw").as_deref() != Some("3059\n") {
            return TestResult::Fail("ALS publish aliased onto the accel device");
        }
        // Unknown report ID: not consumed, nothing changes.
        if route_sensor_report(&routes, device_key, &[9, 1, 2, 3], 101) {
            return TestResult::Fail("unknown report ID was consumed as a sensor report");
        }
        // Truncated report for a known ID: dropped, not published.
        if route_sensor_report(&routes, device_key, &[1, 5], 102) {
            return TestResult::Fail("truncated report was consumed");
        }
        if show(accel, "in_accel_x_raw").as_deref() != Some("1019\n") {
            return TestResult::Fail("truncated report disturbed the published reading");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/input", smoke_i2c_hid_sensor_publication_round_trip);

    // ── Issue #771: pump recovery + unregister ───────────────────
    //
    // Fixtures built from the lifecycle semantics themselves: the
    // recovery state machine is driven through its full
    // error → backoff → RESET → give-up sequence with no bus at
    // all, and `BoundNodes` is proven to remove a device from the
    // router + sysfs (the hook chain into `unpublish_input_device`
    // is exercised end to end).

    fn smoke_pump_recovery_backoff_then_reset_then_give_up() -> TestResult {
        let policy = RetryPolicy {
            max_attempts: 3,
            base_backoff_ms: 100,
            max_backoff_ms: 30_000,
        };
        let mut r = PumpRecovery::new(policy);
        // One wedged epoch, driven to exhaustion: 3 backoffs
        // (100/200/400), RESET, 3 backoffs, RESET, 3 backoffs,
        // RESET, 3 backoffs, then GiveUp. Exactly 3 RESETs —
        // the pump never spins forever on a wedged device.
        let want = [
            RecoveryAction::Backoff(100),
            RecoveryAction::Backoff(200),
            RecoveryAction::Backoff(400),
            RecoveryAction::Reset,
            RecoveryAction::Backoff(100),
            RecoveryAction::Backoff(200),
            RecoveryAction::Backoff(400),
            RecoveryAction::Reset,
            RecoveryAction::Backoff(100),
            RecoveryAction::Backoff(200),
            RecoveryAction::Backoff(400),
            RecoveryAction::Reset,
            RecoveryAction::Backoff(100),
            RecoveryAction::Backoff(200),
            RecoveryAction::Backoff(400),
            RecoveryAction::GiveUp,
        ];
        for w in want.iter() {
            if r.on_bus_error() != *w {
                return TestResult::Fail("recovery action sequence wrong");
            }
        }
        // A successful report forgives transient errors: the
        // next error backs off from 100 again, not 800.
        let mut r2 = PumpRecovery::new(policy);
        let _ = r2.on_bus_error();
        let _ = r2.on_bus_error();
        r2.on_report_ok();
        if r2.on_bus_error() != RecoveryAction::Backoff(100) {
            return TestResult::Fail("successful report did not reset the error count");
        }
        // A successful RESET starts a fresh epoch: the next
        // error backs off from 100 and a full 3 RESETs are
        // available again.
        let mut r3 = PumpRecovery::new(policy);
        let _ = r3.on_bus_error();
        let _ = r3.on_bus_error();
        let _ = r3.on_bus_error();
        if r3.on_bus_error() != RecoveryAction::Reset {
            return TestResult::Fail("expected Reset after 3 consecutive errors");
        }
        r3.on_reset_ok();
        if r3.on_bus_error() != RecoveryAction::Backoff(100) {
            return TestResult::Fail("successful RESET did not start a fresh epoch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input",
        smoke_pump_recovery_backoff_then_reset_then_give_up
    );

    fn smoke_bound_nodes_unregister_removes_router_and_sysfs() -> TestResult {
        use narf_input::evdev::{DeviceCaps, InputId, ROUTER};
        crate::i2c_hid_bind::__reset_for_test();
        narf_filesystem::sysfs::__reset_for_test();
        narf_filesystem::sysfs::populate_input_class();

        let mut bound = BoundNodes::new();
        let mut caps = DeviceCaps::new();
        caps.set_identity(
            "test i2c-hid touchpad",
            "i2c-TEST/input0",
            "",
            InputId::new(narf_input::evdev::bus::I2C, 0x04F3, 0x3045, 0x0001),
        );
        caps.add_key(30);
        let node = bound.register(caps);
        if bound.ids().len() != 1 {
            return TestResult::Fail("bound node id was not recorded");
        }
        let id = bound.ids()[0];
        let n = id.0 - 1;
        let sysfs_input_present = || {
            narf_filesystem::sysfs::get_root()
                .get_child("devices")
                .and_then(|d| d.get_child("platform"))
                .and_then(|p| p.get_child("narf-input"))
                .and_then(|ni| ni.get_child(&alloc::format!("input{}", n)))
                .is_some()
        };
        if ROUTER.caps(id).is_none() || !node.is_alive() || !sysfs_input_present() {
            return TestResult::Fail("registered node missing from router or sysfs");
        }
        // The give-up path: unregister everything the device owns.
        bound.unregister_all();
        if !bound.ids().is_empty() {
            return TestResult::Fail("unregister_all did not drain the id list");
        }
        if ROUTER.caps(id).is_some()
            || ROUTER.device_ids().contains(&id)
            || node.is_alive()
            || sysfs_input_present()
        {
            return TestResult::Fail("unregistered node still visible in router or sysfs");
        }
        // Idempotent: a second call is a no-op, not a panic.
        bound.unregister_all();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input",
        smoke_bound_nodes_unregister_removes_router_and_sysfs
    );
}
