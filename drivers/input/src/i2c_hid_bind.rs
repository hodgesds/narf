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
//! Sources (public, non-GPL only):
//! - Microsoft "HID over I2C Protocol Specification" v1.0 — _DSM
//!   UUID + descriptor register convention.
//! - ACPI 6.5 §6.4.3.8 — `_CRS` `I2cSerialBus` and `GpioInt`
//!   resource template encoding.

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

/// Walk + bind every PNP0C50 child. Returns the number of devices
/// that were successfully bound (driver instance constructed +
/// pump task spawned). Devices missing their parent I2C bus, or
/// missing `I2cSerialBus` in `_CRS` entirely, are logged + skipped.
pub fn bind_all() -> usize {
    let mut bound = 0usize;
    for child in narf_aml::find_all_devices_by_hid("PNP0C50") {
        if bind_one(&child.path) {
            bound += 1;
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
                path, e
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
                path, bus_name
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
                        path, e
                    );
                    // Drop the dangling wake registration since the
                    // ISR will never fire — keeps the lookup table
                    // tidy.
                    let mut g = PIN_WAKES.lock();
                    if let Some(idx) = g.iter().position(|(p, f)| *p == pin && core::ptr::eq(*f, wake_flag)) {
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
            path, bus_name, addr, hid_desc_register
        );
    }

    let device_path = path.to_string();
    let driver = I2cHidDriver::new(bus, addr, hid_desc_register);
    narf_scheduler::spawn(pump_task(device_path, driver, wake_flag, wired_irq));
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
            path, e
        );
        return;
    }
    if let Err(e) = driver.reset().await {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-pump: {}: RESET failed ({:?})",
            path, e
        );
    }
    if let Err(e) = driver.set_power(POWER_ON).await {
        let _ = writeln!(
            narf_console::Writer,
            "  i2c-hid-pump: {}: SET_POWER(ON) failed ({:?})",
            path, e
        );
    }

    let report_desc_blob = match driver.read_report_descriptor().await {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-pump: {}: read_report_descriptor failed ({:?}); pump exiting",
                path, e
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
                path, e
            );
            return;
        }
    };
    let ptp = narf_hid::ptp::detect(&parsed);
    let _ = writeln!(
        narf_console::Writer,
        "  i2c-hid-pump: {}: descriptor parsed, fields={}, ptp={}",
        path,
        parsed.fields.len(),
        ptp.is_some(),
    );

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

        if let Some(profile) = &ptp {
            // The wire payload here lacks the 1-byte report-id
            // prefix (the i2c-hid layer strips the length prefix
            // but the report id is part of payload byte 0 already
            // when descriptors use Report IDs — match what
            // ptp::decode_input expects, which is "report id at
            // byte 0 followed by body").
            let payload = &buf[..n];
            if payload.first() == Some(&profile.input_report_id) {
                if let Ok(decoded) = narf_hid::ptp::decode_input(profile, payload) {
                    push_ptp_pointer(
                        &decoded,
                        &mut last_x,
                        &mut last_y,
                        &mut last_button,
                    );
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
    let _ = narf_input::push_global(narf_input::InputEvent::Pointer(
        narf_input::PointerEvent { dx, dy, buttons },
    ));
}

/// Try to evaluate `<path>._DSM` with the Microsoft HID-over-I2C
/// UUID + function index 1, which returns the device's HID
/// descriptor register. Currently a stub — the AML evaluator does
/// not yet support Buffer + Package method args, so we always
/// return None and the caller falls back to
/// `DEFAULT_HID_DESC_REGISTER`. Keeping the hook here so the wire-up
/// is one Edit away when narf-aml grows the plumbing.
fn resolve_hid_desc_register(_path: &str) -> Option<u16> {
    // TODO: build Value::Buffer(uuid_bytes) + Value::Integer(rev) +
    // Value::Integer(func_idx) + Value::Package([]) and call
    // narf_aml::eval::evaluate_method("<path>._DSM", &args). Decode
    // the returned Value::Integer as the descriptor register.
    None
}

#[doc(hidden)]
pub fn __reset_for_test() {
    PIN_WAKES.lock().clear();
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
