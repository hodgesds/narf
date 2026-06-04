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
//! - Calls `I2cHidDriver::start()` (read descriptor + RESET +
//!   POWER_ON).
//! - Reads the Report Descriptor and parses it via `narf_hid`.
//! - Detects a Microsoft Precision Touchpad profile via
//!   `narf_hid::ptp::detect`. When present, pump-decoded contact
//!   deltas are pushed as `narf_input::PointerEvent`s on the
//!   global ring.
//! - Loops: wait on the wake flag (set by the GPIO ISR) — or, if
//!   no GPIO IRQ is wired, yield + retry — read one input report,
//!   decode, push.
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
use core::sync::atomic::{AtomicBool, Ordering};

use narf_aml::resource::ResourceItem;
use narf_drivers_gpio::{GpioIrqConfig, GpioPull};
use narf_drivers_i2c::{registry as i2c_registry, I2cBus};
use narf_lib::sync::IrqSafeSpinLock;

use crate::i2c_hid::{I2cHidDriver, I2cHidError, POWER_ON};

/// Default HID descriptor register used when `_DSM` evaluation is
/// unavailable. The Microsoft spec leaves this device-defined; AMD
/// touchpad firmware ships with 0x0001 as the de-facto convention.
const DEFAULT_HID_DESC_REGISTER: u16 = 0x0001;

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
    let amdi_n = narf_aml::boot_amdi001x_count();
    let pnp_n = narf_aml::boot_pnp0c50_count();
    let _ = writeln!(
        narf_console::Writer,
        "i2c-hid-bind: AMDI={} PNP0C50={} — subtree dump follows",
        amdi_n,
        pnp_n
    );
    narf_aml::dump_amd_i2c_subtree();
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
                    let mut g = PIN_WAKES.lock();
                    if let Some(idx) = g
                        .iter()
                        .position(|(p, f)| *p == pin && core::ptr::eq(*f, wake_flag))
                    {
                        g.swap_remove(idx);
                    }
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
    // Stackful: per-device i2c-hid input pump.
    narf_scheduler::spawn_stackful(pump_task(device_path, driver, wake_flag, wired_irq));
    true
}

/// Per-device pump future. Owns the driver. Loops forever — exits
/// only if the bus returns a fatal error.
async fn pump_task(
    path: String,
    mut driver: I2cHidDriver,
    wake: &'static AtomicBool,
    irq_wired: bool,
) {
    if let Err(e) = driver.read_descriptor().await {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-pump: {}: read_descriptor failed ({:?}); pump exiting",
            path,
            e
        );
        return;
    }
    if let Err(e) = driver.reset().await {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-pump: {}: RESET failed ({:?})",
            path,
            e
        );
    }
    if let Err(e) = driver.set_power(POWER_ON).await {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-pump: {}: SET_POWER(ON) failed ({:?})",
            path,
            e
        );
    }

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
    let _ = writeln!(
        narf_console::Writer,
        "  i2c-hid-pump: {}: descriptor parsed, fields={}, ptp={}, touchscreen={}, pen={}",
        path,
        parsed.fields.len(),
        ptp.is_some(),
        touchscreen.is_some(),
        pen.is_some(),
    );

    if let Some(profile) = &ptp {
        log_ptp_mode_set_result(&path, set_ptp_multi_touch_mode(&driver, profile).await);
    }

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
    let mut buf: Vec<u8> = Vec::new();
    buf.resize(max_input, 0);

    // Per-device delta tracking (PTP path emits PointerEvent based
    // on first contact movement).
    let mut last_x: Option<i32> = None;
    let mut last_y: Option<i32> = None;
    let mut last_button = false;
    // Per-device touchscreen slot tracker (touchscreen path emits
    // TouchEvent per contact with normalised coordinates).
    let mut touch_state = crate::i2c_hid_touch::TouchPumpState::new();
    // Per-device pen/stylus state tracker.
    let mut pen_state = crate::i2c_hid_touch::PenPumpState::default();

    loop {
        if irq_wired {
            // Wait for ISR to flip the flag. Yield each poll so peer
            // tasks (i8042, FB drain, init) make progress.
            while !wake.swap(false, Ordering::Acquire) {
                narf_scheduler::yield_now().await;
            }
        } else {
            narf_scheduler::yield_now().await;
        }

        let n = match driver.read_input_report(&mut buf).await {
            Ok(n) => n,
            Err(I2cHidError::Bus(_)) => {
                // Transient bus error: yield + retry. Persistent
                // errors burn CPU but don't crash; we'd like a
                // backoff here once the scheduler exposes one.
                continue;
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
        // Route by report id when the descriptor uses them. PTP
        // and Touch Screen are normally distinct top-level
        // collections with distinct report ids, so the two
        // branches are mutually exclusive per report.
        if let Some(profile) = &ptp {
            if payload.first() == Some(&profile.input_report_id) {
                if let Ok(decoded) = narf_hid::ptp::decode_input(profile, payload) {
                    push_ptp_pointer(&decoded, &mut last_x, &mut last_y, &mut last_button);
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
                    crate::i2c_hid_touch::pump_report(ts_profile, &mut touch_state, &decoded);
                }
                continue;
            }
        }
        if let Some(pen_profile) = &pen {
            // Pen report IDs are always non-zero for spec-compliant
            // devices; the decode rejects mismatched IDs for us.
            if payload.first() == Some(&pen_profile.input_report_id) {
                if let Ok(decoded) = narf_hid::pen::decode_input(pen_profile, payload) {
                    crate::i2c_hid_touch::pump_pen_report(&mut pen_state, &decoded);
                }
            }
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
/// 4F1C8DA2-D5A0-4C7B-8169-3D2DBFCA3C03 (Microsoft HID-over-I2C
/// spec §3.1).
const HID_OVER_I2C_DSM_UUID: [u8; 16] = [
    0xA2, 0x8D, 0x1C, 0x4F, // 4F1C8DA2 (LE)
    0xA0, 0xD5, // D5A0      (LE)
    0x7B, 0x4C, // 4C7B      (LE)
    0x81, 0x69, // 8169      (BE)
    0x3D, 0x2D, 0xBF, 0xCA, 0x3C, 0x03, // 3D2DBFCA3C03 (BE)
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
