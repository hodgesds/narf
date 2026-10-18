//! ACPI power button → `KEY_POWER` — Linux `drivers/acpi/button.c`.
//!
//! ```text
//! static void acpi_button_notify(acpi_handle handle, u32 event, void *data)
//! {
//!         ...
//!         keycode = test_bit(KEY_SLEEP, input->keybit) ? KEY_SLEEP : KEY_POWER;
//!         input_report_key(input, keycode, 1);
//!         input_sync(input);
//!         input_report_key(input, keycode, 0);
//!         input_sync(input);
//! }
//! ```
//!
//! The kernel never powers off on a button press: it reports the key on an
//! input device ("Power Button") and systemd-logind, which opens every input
//! device that can emit `KEY_POWER`, runs `HandlePowerKey=` (by default an
//! orderly `poweroff.target`: services stopped, filesystems unmounted).
//!
//! NARF adds one fallback Linux does not need: when nothing has the device
//! open (no logind — e.g. not booted under systemd PID 1), the press becomes
//! an orderly kernel power-off ([`crate::orderly`]): every filesystem synced
//! from task context, then the device shutdown hooks. Never a power-off from
//! the notifying context.

use alloc::sync::Arc;

use narf_input::evdev::{self, DeviceCaps, DeviceNode};
use narf_lib::sync::IrqSafeSpinLock;

/// Linux `KEY_POWER`.
pub const KEY_POWER: u16 = evdev::key::KEY_POWER;

static NODE: IrqSafeSpinLock<Option<Arc<DeviceNode>>> = IrqSafeSpinLock::new(None);

/// What one press did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PressOutcome {
    /// `KEY_POWER` was delivered to `readers` open handle(s); userspace
    /// decides what happens.
    Delivered { readers: u32 },
    /// Nothing listens: an orderly kernel power-off was requested
    /// (`first` = this press made the request).
    OrderlyPowerOff { first: bool },
}

/// The capability set of the power-button input device: `EV_KEY` +
/// `KEY_POWER` (and `EV_SYN`), exactly what `acpi_button_add` declares.
pub fn power_button_caps() -> DeviceCaps {
    let mut caps = DeviceCaps::new();
    caps.add_key(KEY_POWER);
    caps
}

/// Register the power-button input device (idempotent). Returns its node.
pub fn register_input_device() -> Arc<DeviceNode> {
    let mut g = NODE.lock();
    if let Some(node) = g.as_ref() {
        if node.is_alive() {
            return node.clone();
        }
    }
    let (_id, node) = evdev::ROUTER.register_device(power_button_caps());
    *g = Some(node.clone());
    node
}

/// The registered power-button device, if any.
pub fn input_device() -> Option<Arc<DeviceNode>> {
    NODE.lock().clone()
}

/// Report one press on `node`: deliver press + release (each followed by
/// `SYN_REPORT`); with no reader, request the orderly power-off instead.
///
/// Safe from interrupt context: event dispatch and the orderly request are
/// both IRQ-safe and neither blocks.
pub fn report_press_on(node: &DeviceNode) -> PressOutcome {
    let readers = node.reader_count();
    if readers == 0 {
        let first =
            crate::orderly::orderly_poweroff(crate::orderly::OrderlyReason::PowerButton, None);
        return PressOutcome::OrderlyPowerOff { first };
    }
    evdev::dispatch_key_to_node(node, KEY_POWER, true);
    evdev::dispatch_key_to_node(node, KEY_POWER, false);
    PressOutcome::Delivered { readers }
}

/// The ACPI power-button notify path: report one press on the registered
/// device (registering it first if the button fires before the initcall).
pub fn report_power_button() -> PressOutcome {
    use core::fmt::Write as _;
    let node = match input_device() {
        Some(n) => n,
        None => register_input_device(),
    };
    let outcome = report_press_on(&node);
    match outcome {
        PressOutcome::Delivered { readers } => {
            let _ = writeln!(
                narf_console::Writer,
                "  acpi: power button -> KEY_POWER delivered to {readers} reader(s)"
            );
        }
        PressOutcome::OrderlyPowerOff { .. } => {
            let _ = writeln!(
                narf_console::Writer,
                "  acpi: power button, no KEY_POWER consumer -> orderly power-off"
            );
        }
    }
    outcome
}
