//! SMBus RMI4 attention pump (issue #1682).
//!
//! Follow-up to the transport in [`crate::smbus_rmi`]: the
//! transport can probe and read registers, but a bound SMBus
//! touchpad produced no input events — nothing serviced the
//! attention line that signals "data ready". This module routes
//! that line and pumps the reports.
//!
//! ## Attention source
//!
//! Linux gets the ATTN interrupt from the PS/2 companion driver
//! (`drivers/input/mouse/psmouse-smbus.c` hands the Synaptics
//! SMBus client its IRQ); NARF has no such companion. The line
//! is routed here from firmware instead: the touchpad's ACPI
//! node declares the attention line as a `_CRS` `GpioInt`
//! resource (ACPI 6.5 §6.4.3.8), exactly the resource
//! `i2c-hid-bind` already decodes for HID touchpads. The scan
//! ([`resolve_attn_gpio`]) takes the first `SYNA*` node whose
//! `_CRS` carries a `GpioInt` and *no* `I2cSerialBus` — a node
//! with an `I2cSerialBus` belongs to the I2C-HID path, which
//! owns that node's IRQ already — and registers the pin through
//! the shared GPIO registry
//! (`narf_drivers_gpio::registry::find` +
//! `GpioController::register_irq`), mirroring `i2c-hid-bind`.
//! No IRQ number, GPIO pin, or `_CRS` interpretation is
//! invented: every value comes from the firmware's own `_CRS`
//! decode, and a failed registration falls back to polling
//! instead of claiming a line that isn't there.
//!
//! ## Pump
//!
//! The ISR ([`on_smbus_rmi_attn`]) only flips a wake flag —
//! the same wake-flag shape `i2c-hid-bind` uses. The pump task
//! ([`pump_task`]) waits on the flag, then runs one synchronous
//! service pass ([`service_attn`]) against the shared SMBus
//! controller:
//!
//! 1. Read the F$01 interrupt-status byte. F$01 data byte 0 is
//!    the device status (`F01DeviceStatus`, app notes §4.5.5);
//!    the interrupt-status bytes follow at `data_base + 1`
//!    (Linux `rmi_driver.c` `rmi_process_interrupt_requests`
//!    reads `f01->data_base_addr + 1`). The read also
//!    acknowledges the interrupt at the device, so a status
//!    byte of zero means "spurious wake, nothing to do".
//! 2. Dispatch on the source bitmap via the probe's
//!    interrupt map (the same `source_mask_for` the HID pump
//!    uses): F$12 (or F$11) data is read back through the
//!    transport and decoded with the shared `rmi4_core`
//!    decoders; F$30 buttons are read when the F$30 source
//!    fired. Frames are delivered through the shared
//!    [`Rmi4PumpState::pump_contacts`].
//!
//! One deliberate divergence from the HID pump
//! (`i2c_hid_bind::pump_rmi_attn`): a buttons-only ATTN still
//! pumps (with an empty contact list) so a click with no
//! finger down updates BTN_LEFT instead of being dropped.
//!
//! ## Shared-controller coordination
//!
//! The platform SMBus controller is shared with hwmon (JC42)
//! and the SBS battery driver, all through
//! `smbus::with_controller` — one short lock-protected
//! transaction at a time, never held across an await. The pump
//! keeps that contract: every service pass runs inside a
//! single `with_controller` closure, the transport is rebuilt
//! per pass from pump-carried session state (see
//! [`SmbusRmiSessionState`]), and no pass ever bypasses the
//! shared ownership to touch the bus. The coordinated-poll
//! fallback samples only the one F$01 status byte per tick
//! (16 ms); full F$12/F$30 reads happen only when a source bit
//! is set, so the steady-state bus cost is one byte-read per
//! tick — the same order as a hwmon sample.
//!
//! ## Bring-up
//!
//! The pump task first writes the F$01 device-control byte
//! (sleep normal, `CONFIGURED`) via the in-tree
//! [`f01_device_control_byte`] helper — the standard
//! "host has configured the device" handshake Linux's
//! `rmi_f01` config performs during probe, without which the
//! silicon is not required to assert ATTN. A failed write is
//! logged, not fatal: the pump still runs and services
//! whatever ATTNs arrive.
//!
//! ## Remainders
//!
//! - F$12 object count is 5, mirroring the HID pump's
//!   multi-source fallback — the true count comes from the
//!   F$12 Query 1 register at probe time (same remainder as
//!   the HID path).
//! - F$01-only ATTNs (device-status changes, e.g. "reset
//!   occurred") are acknowledged by the status read and
//!   otherwise ignored; reset recovery (re-probe) is a
//!   follow-up, not part of this pump.
//! - Axis ranges are the decoder field widths (F$12 u16,
//!   F$11 12-bit), as in the HID pump — the true sensor
//!   maxima from the F$11/F$12 queries would narrow them.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_aml::resource::ResourceItem;
use narf_drivers_gpio::{GpioIrqConfig, GpioPull};
use narf_input::evdev::{bus, DeviceCaps, DeviceNode, InputId, ROUTER};
use narf_input::rmi4::{f01_device_control_byte, TouchpadReport};

use crate::hid_rmi::{clickpad_btn_left, USB_VENDOR_ID_SYNAPTICS};
use crate::i2c_hid_touch::build_rmi_caps;
use crate::rmi4_core::{
    decode_f12_data1, decode_f30_buttons, find_function, Rmi4Contact, Rmi4DeviceProbe,
    Rmi4PumpState, Rmi4Transport, TransportError, F01_DEVICE_CONTROL, F01_SLEEP_NORMAL,
    F11_2D_TOUCHPAD, F12_2D_TOUCHPAD_NEXT, F12_OBJECT_SIZE, F30_GPIO_LED,
};
use crate::smbus_rmi::{
    probe_smbus_rmi_with_state, SmbusRmiSessionState, SmbusRmiTransport, SMBUS_RMI_DEFAULT_ADDR,
};

/// Coordinated-poll fallback interval (issue #1682): with no
/// routable ATTN IRQ the pump samples the F$01 interrupt-status
/// byte at this cadence. 16 ms ≈ 60 Hz touch rate; the
/// steady-state cost is one SMBus byte-read per tick through
/// the shared controller (see the module docs).
pub const SMBUS_RMI_POLL_INTERVAL_MS: u64 = 16;

/// F$12 objects decoded per service pass — mirrors the HID
/// pump's multi-source fallback (true count from the F$12
/// Query 1 register is a remainder).
pub const SMBUS_RMI_F12_MAX_OBJECTS: usize = 5;

/// F$11 fingers decoded per service pass — mirrors the HID
/// pump (1 finger-state byte + 5 bytes per finger).
pub const SMBUS_RMI_F11_MAX_FINGERS: usize = 5;

// ── Attention GPIO routing ─────────────────────────────────────────

/// Wake flag flipped by the ATTN GPIO ISR. The pump task waits
/// on it; the ISR never touches the bus or the pump state.
static ATTN_WAKE: AtomicBool = AtomicBool::new(false);

/// GPIO ISR shim for the SMBus RMI4 ATTN line. The controller
/// dispatches this only for the registered pin, so the pin
/// argument needs no check — set the flag and return.
fn on_smbus_rmi_attn(_pin: u16) {
    ATTN_WAKE.store(true, Ordering::Release);
}

/// A routable ATTN line, decoded from a touchpad ACPI node's
/// `_CRS` `GpioInt` resource. Every field comes from firmware;
/// nothing here is a hard-coded pin or IRQ number.
#[derive(Clone, Debug)]
pub struct AttnGpio {
    /// ACPI path of the touchpad node (e.g. `\_SB.PCI0.TPAD`).
    pub acpi_path: String,
    /// The node's `_HID` (a `SYNAxxxx` id).
    pub acpi_hid: String,
    /// `GpioInt::resource_source` — ACPI path of the parent
    /// GPIO block, resolved via the GPIO registry.
    pub gpio_path: String,
    /// First pin listed in the `GpioInt` resource.
    pub pin: u16,
    /// Pull configuration from the `GpioInt` pin-config byte.
    pub pull: GpioPull,
    /// Trigger / polarity from the `GpioInt` flags.
    pub cfg: GpioIrqConfig,
}

/// Locate the SMBus touchpad's attention line in the ACPI
/// namespace: the first `SYNA*` node whose `_CRS` carries a
/// `GpioInt` and no `I2cSerialBus`. A node with an
/// `I2cSerialBus` is an I2C-HID device — `i2c-hid-bind` owns
/// that node's IRQ already, so it is skipped, not double
/// claimed. Returns `None` when no such node exists (firmware
/// without a touchpad ACPI node, or a node the AML resource
/// decoder cannot evaluate) — the caller then falls back to
/// the coordinated poll.
pub fn resolve_attn_gpio() -> Option<AttnGpio> {
    for path in narf_aml::list_all_device_paths() {
        let Some(hid) = narf_aml::device_hid(&path) else {
            continue;
        };
        if !hid.starts_with("SYNA") {
            continue;
        }
        let Ok(items) = narf_aml::prt_crs::evaluate_crs_for(&path) else {
            continue;
        };
        let mut gpio: Option<(String, Option<u16>, bool, u8, u8)> = None;
        let mut has_i2c = false;
        for it in &items {
            match it {
                ResourceItem::I2cSerialBus { .. } => has_i2c = true,
                ResourceItem::GpioInt {
                    level_triggered,
                    polarity,
                    pin_config,
                    pins,
                    resource_source,
                    ..
                } => {
                    gpio = Some((
                        resource_source.clone(),
                        pins.first().copied(),
                        *level_triggered,
                        *polarity,
                        *pin_config,
                    ));
                }
                _ => {}
            }
        }
        if has_i2c {
            continue;
        }
        let Some((gpio_path, Some(pin), level_triggered, polarity, pin_config)) = gpio else {
            continue;
        };
        return Some(AttnGpio {
            acpi_path: path,
            acpi_hid: hid,
            gpio_path,
            pin,
            pull: match pin_config {
                1 => GpioPull::Up,
                2 => GpioPull::Down,
                3 => GpioPull::None,
                _ => GpioPull::Default,
            },
            cfg: GpioIrqConfig {
                level_triggered,
                polarity,
            },
        });
    }
    None
}

// ── ATTN service (sync, transport-neutral) ─────────────────────────

/// Read the F$30 button bitmap when the F$30 source bit fired
/// in this ATTN. Returns `Some(BTN_LEFT)` on a successful read
/// and `None` when the button state is unknown this frame (no
/// F$30 function, no F$30 source, or the register read failed)
/// — the pump then holds the previous button state instead of
/// synthesising a release. Sync mirror of the HID pump's
/// `read_rmi_buttons`.
fn read_smbus_rmi_buttons(
    transport: &mut dyn Rmi4Transport,
    probe: &Rmi4DeviceProbe,
    sources: u8,
) -> Option<bool> {
    let f30 = probe.f30.as_ref()?;
    if sources & probe.source_mask_for(F30_GPIO_LED) == 0 {
        return None;
    }
    // F$30 data registers: one bit per GPIO, active-low. Read
    // enough bytes for the probe-time GPIO/LED line count
    // (capped at 32 lines / 4 bytes).
    let nbytes = (probe.f30_gpio_count.min(32) as usize).div_ceil(8).max(1);
    let mut buf = alloc::vec![0u8; nbytes];
    if transport
        .read_block(f30.data_base as u16, &mut buf)
        .is_err()
    {
        return None;
    }
    match decode_f30_buttons(&buf, probe.f30_gpio_count) {
        Ok(bitmap) => Some(clickpad_btn_left(bitmap)),
        Err(_) => None,
    }
}

/// Service one attention: read the F$01 interrupt-status byte
/// and pump whatever it reports through the shared
/// [`Rmi4PumpState`].
///
/// The status read acknowledges the interrupt at the device,
/// so a zero byte means "spurious wake" (`Ok(0)`). A failed
/// status read is the only `Err` — the bus is wedged and the
/// caller retries on the next wake/poll. A failed data read
/// after a successful status read returns `Ok(0)`: the ATTN
/// was already acknowledged and the next ATTN carries current
/// state (same rationale as the HID pump's interleaved-ATTN
/// note).
///
/// Returns the number of `TouchEvent`s pushed to the global
/// ring. F$12 takes precedence over F$11 (a device never
/// exposes both as its touch sensor); a buttons-only ATTN
/// still pumps with an empty contact list so BTN_LEFT updates.
pub fn service_attn(
    transport: &mut dyn Rmi4Transport,
    probe: &Rmi4DeviceProbe,
    state: &mut Rmi4PumpState,
    node: Option<&DeviceNode>,
) -> Result<usize, TransportError> {
    let f01 = find_function(&probe.table, F01_DEVICE_CONTROL)
        .copied()
        .ok_or(TransportError::Protocol)?;
    // F$01 data byte 0 is the device status; the
    // interrupt-status bytes follow at `data_base + 1` (see the
    // module docs). The probe maps at most 8 sources, so one
    // status byte covers the whole interrupt map.
    let mut status = [0u8; 1];
    transport.read_block(f01.data_base as u16 + 1, &mut status)?;
    let sources = status[0];
    if sources == 0 {
        return Ok(0);
    }
    let btn_left = read_smbus_rmi_buttons(transport, probe, sources);

    let f12_mask = probe.source_mask_for(F12_2D_TOUCHPAD_NEXT);
    let f11_mask = probe.source_mask_for(F11_2D_TOUCHPAD);
    if f12_mask != 0 && sources & f12_mask != 0 {
        if let Some(f12) = &probe.f12 {
            let mut buf = [0u8; SMBUS_RMI_F12_MAX_OBJECTS * F12_OBJECT_SIZE];
            if transport.read_block(f12.data_base as u16, &mut buf).is_ok() {
                if let Ok(objs) = decode_f12_data1(&buf, SMBUS_RMI_F12_MAX_OBJECTS) {
                    let contacts: Vec<Rmi4Contact> = objs
                        .iter()
                        .map(|o| Rmi4Contact {
                            present: o.present && o.is_touching_finger(),
                            x: o.x as i32,
                            y: o.y as i32,
                            pressure: o.z as i32,
                        })
                        .collect();
                    return Ok(state.pump_contacts(
                        node,
                        &contacts,
                        btn_left,
                        crate::rmi4_core::Rmi4PumpBounds {
                            x_min: 0,
                            x_max: 0xFFFF,
                            y_min: 0,
                            y_max: 0xFFFF,
                        },
                    ));
                }
            }
            return Ok(0);
        }
    }
    if f11_mask != 0 && sources & f11_mask != 0 {
        if let Some(f11) = &probe.f11 {
            // F$11 frame: 1 finger-state byte + 5 bytes per finger.
            let mut buf = [0u8; 1 + SMBUS_RMI_F11_MAX_FINGERS * 5];
            if transport.read_block(f11.data_base as u16, &mut buf).is_ok() {
                if let Ok(rep) = TouchpadReport::parse(&buf, SMBUS_RMI_F11_MAX_FINGERS) {
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
                    return Ok(state.pump_contacts(
                        node,
                        &contacts,
                        btn_left,
                        crate::rmi4_core::Rmi4PumpBounds {
                            x_min: 0,
                            x_max: 0x0FFF,
                            y_min: 0,
                            y_max: 0x0FFF,
                        },
                    ));
                }
            }
            return Ok(0);
        }
    }
    // Buttons-only ATTN (or an F$01-only status change with a
    // coincident button bit): pump the button state with no
    // contacts rather than dropping the frame.
    if sources & probe.source_mask_for(F30_GPIO_LED) != 0 {
        return Ok(state.pump_contacts(
            node,
            &[],
            btn_left,
            crate::rmi4_core::Rmi4PumpBounds {
                x_min: 0,
                x_max: 0xFFFF,
                y_min: 0,
                y_max: 0xFFFF,
            },
        ));
    }
    Ok(0)
}

/// F$01 bring-up for the pump: write the device-control byte
/// (sleep normal, `CONFIGURED`) so the silicon asserts ATTN.
/// See the module docs; a failure is logged by the caller, not
/// fatal.
pub(crate) fn f01_bringup(
    transport: &mut dyn Rmi4Transport,
    probe: &Rmi4DeviceProbe,
) -> Result<(), TransportError> {
    let f01 = find_function(&probe.table, F01_DEVICE_CONTROL)
        .copied()
        .ok_or(TransportError::Protocol)?;
    let ctrl = f01_device_control_byte(F01_SLEEP_NORMAL, true, false);
    transport.write_block(f01.control_base as u16, &[ctrl])
}

// ── Pump task + bind ───────────────────────────────────────────────

/// Run one synchronous transaction set against the shared SMBus
/// controller, rebuilding the transport from pump-carried
/// session state and writing the state back afterwards. Returns
/// `None` when no controller is registered. The closure runs
/// synchronously inside `with_controller`, so the controller
/// lock is never held across an await.
fn with_smbus_rmi<F, R>(state: &mut SmbusRmiSessionState, f: F) -> Option<R>
where
    F: FnOnce(&mut SmbusRmiTransport<&narf_drivers_platform::smbus::Smbus>) -> R,
{
    narf_drivers_platform::smbus::with_controller(|c| {
        let mut t =
            SmbusRmiTransport::from_state(c, SMBUS_RMI_DEFAULT_ADDR, core::mem::take(state));
        let r = f(&mut t);
        *state = t.into_state();
        r
    })
}

/// Per-device pump future. Owns the probe, the session state,
/// and the evdev node. Loops forever — exits only if the SMBus
/// controller goes away.
async fn pump_task(
    probe: Rmi4DeviceProbe,
    mut session_state: SmbusRmiSessionState,
    node: Arc<DeviceNode>,
    irq_wired: bool,
) {
    // F$01 bring-up first: mark the device configured + awake
    // so it asserts ATTN. A failure is logged, not fatal.
    match with_smbus_rmi(&mut session_state, |t| f01_bringup(t, &probe)) {
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  smbus-rmi-pump: controller gone before bring-up; pump exiting",
            );
            return;
        }
        Some(Ok(())) => {}
        Some(Err(e)) => {
            let _ = writeln!(
                narf_console::Writer,
                "  smbus-rmi-pump: F$01 bring-up failed ({:?}); pumping anyway",
                e
            );
        }
    }

    let mut pump_state = Rmi4PumpState::new();
    let mut consec_errors: u32 = 0;
    loop {
        // Service first, then wait: the line may already be
        // asserted when the pump spawns (finger down at boot,
        // or a level-triggered line high before registration),
        // and a wait-first loop would sit on it until the next
        // edge.
        match with_smbus_rmi(&mut session_state, |t| {
            service_attn(t, &probe, &mut pump_state, Some(node.as_ref()))
        }) {
            None => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  smbus-rmi-pump: controller gone; pump exiting",
                );
                return;
            }
            Some(Err(e)) => {
                consec_errors += 1;
                if consec_errors == 1 || consec_errors % 512 == 0 {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  smbus-rmi-pump: ATTN service failed ({:?}; {} consecutive)",
                        e,
                        consec_errors
                    );
                }
            }
            Some(Ok(_)) => {
                consec_errors = 0;
            }
        }

        if irq_wired {
            // Wait for the ISR to flip the flag. Yield each poll
            // so peer tasks make progress (same shape as the
            // i2c-hid pump).
            while !ATTN_WAKE.swap(false, Ordering::Acquire) {
                narf_scheduler::yield_now().await;
            }
        } else {
            // Coordinated poll: one F$01 status-byte read per
            // tick through the shared controller (see the module
            // docs); full report reads only when a source fires.
            narf_time::sleep_ms(SMBUS_RMI_POLL_INTERVAL_MS).await;
        }
    }
}

/// Outcome of [`bind_and_spawn`], for the initcall result.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttnBindOutcome {
    /// Pump spawned with a routed ATTN IRQ.
    BoundIrq,
    /// Pump spawned on the coordinated-poll fallback.
    BoundPolled,
    /// No SMBus RMI4 touchpad answered — nothing to pump.
    NotPresent,
}

/// Bind the ATTN pump: re-probe the SMBus RMI4 transport
/// (capturing probe + session state together), route the ATTN
/// GPIO from the touchpad's ACPI `GpioInt` when one resolves,
/// register the evdev node, and spawn the pump task.
///
/// Runs at Stage::Late — after the Stage::Device GPIO
/// controller probes and the `smbus-rmi-probe` initcall, so
/// the registry lookup and the controller borrow both have
/// something to find. `NotPresent` when no touchpad answers;
/// a missing or unregistrable ATTN line degrades to the
/// coordinated poll, never to a silent bind.
pub fn bind_and_spawn() -> AttnBindOutcome {
    let Some((probe, session_state)) = probe_smbus_rmi_with_state() else {
        return AttnBindOutcome::NotPresent;
    };

    let attn = resolve_attn_gpio();
    let mut irq_wired = false;
    match &attn {
        Some(g) => match narf_drivers_gpio::registry::find(&g.gpio_path) {
            Some(gpio) => match gpio.register_irq(g.pin, g.pull, g.cfg, on_smbus_rmi_attn) {
                Ok(()) => {
                    irq_wired = true;
                    let _ = writeln!(
                        narf_console::Writer,
                        "  smbus-rmi-attn: {} → gpio={}:{} (irq)",
                        g.acpi_path,
                        g.gpio_path,
                        g.pin
                    );
                }
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  smbus-rmi-attn: {}: GPIO register_irq failed ({:?}); polling",
                        g.acpi_path,
                        e
                    );
                }
            },
            None => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  smbus-rmi-attn: {}: GPIO controller {} not registered; polling",
                    g.acpi_path,
                    g.gpio_path
                );
            }
        },
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  smbus-rmi-attn: no ATTN GpioInt in ACPI; polling",
            );
        }
    }

    // Evdev identity: the ACPI _HID when the node resolved,
    // else the transport name. The product id is synthetic —
    // the SMBus path has no enumerable product id (same
    // precedent as the i8042 driver's 0x0001/0x0002 products);
    // the vendor is the in-tree Synaptics VID.
    let (name, phys) = match &attn {
        Some(g) => {
            let leaf = g
                .acpi_path
                .trim_end_matches('\\')
                .rsplit(['\\', '.'])
                .next()
                .unwrap_or("smbus");
            (
                format!("{} SMBus RMI4 Touchpad", g.acpi_hid),
                format!("smbus-{leaf}/input0"),
            )
        }
        None => (
            String::from("Synaptics SMBus RMI4 Touchpad"),
            String::from("smbus-2c/input0"),
        ),
    };
    let mut identity = DeviceCaps::new();
    identity.set_identity(
        &name,
        &phys,
        "",
        InputId::new(bus::I2C, USB_VENDOR_ID_SYNAPTICS, 0x0001, 0),
    );
    let caps = build_rmi_caps(&probe, &identity);
    let (_id, node) = ROUTER.register_device(caps);
    let _ = writeln!(
        narf_console::Writer,
        "  smbus-rmi-attn: pump spawned ({})",
        if irq_wired { "irq" } else { "polled" }
    );
    narf_scheduler::spawn_stackful(pump_task(probe, session_state, node, irq_wired));
    if irq_wired {
        AttnBindOutcome::BoundIrq
    } else {
        AttnBindOutcome::BoundPolled
    }
}

/// Stage::Late initcall — see [`bind_and_spawn`]. The 3 s
/// budget covers the AML namespace walk + `_CRS` evaluations
/// in [`resolve_attn_gpio`] (the i2c-hid bind pass budgets the
/// same).
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register_with_budget(
        Stage::Late,
        "smbus-rmi-attn",
        || match bind_and_spawn() {
            AttnBindOutcome::BoundIrq | AttnBindOutcome::BoundPolled => InitResult::Ok,
            AttnBindOutcome::NotPresent => InitResult::NotPresent,
        },
        3000,
    );
}
