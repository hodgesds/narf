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
//! With nothing listening, Linux does nothing more: powering off is
//! userspace's job. NARF keeps one fallback for a system with no logind
//! (e.g. not booted under systemd): the press becomes
//! `orderly_poweroff(false)` ([`crate::orderly`]), which runs the userspace
//! `kernel.poweroff_cmd` (default `/sbin/poweroff`) — what logind would have
//! started — and does nothing more if that command cannot be started. The
//! kernel never syncs or shuts devices down on a button press while user
//! tasks keep running, and never powers off from the notifying context.

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
    /// Nothing listens: an orderly power-off (the userspace poweroff
    /// command, unforced) was requested (`first` = this press made the
    /// request).
    OrderlyPowerOff { first: bool },
}

/// The power-button input device, as `acpi_button_add` declares it for the
/// fixed-feature button (PM1 `PWRBTN_STS`, ACPI HID `LNXPWRBN` — the event
/// NARF's SCI dispatcher reports): name "Power Button", phys
/// `LNXPWRBN/button/input0`, `BUS_HOST` with product
/// `ACPI_BUTTON_TYPE_POWER` (1), and `EV_KEY` `KEY_POWER` + `KEY_WAKEUP`
/// (with `EV_SYN`). udev / logind key their power-switch handling off this
/// identity.
pub fn power_button_caps() -> DeviceCaps {
    let mut caps = DeviceCaps::new();
    caps.name = alloc::string::String::from("Power Button");
    caps.phys = alloc::string::String::from("LNXPWRBN/button/input0");
    caps.id = narf_input::evdev::InputId::new(narf_input::evdev::bus::HOST, 0, 1, 0);
    caps.add_key(KEY_POWER);
    caps.add_key(evdev::key::KEY_WAKEUP);
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
/// `SYN_REPORT`); with no reader, request the unforced orderly power-off
/// instead.
///
/// Safe from interrupt context: event dispatch and the orderly request are
/// both IRQ-safe and neither blocks.
pub fn report_press_on(node: &DeviceNode) -> PressOutcome {
    let readers = node.reader_count();
    if readers == 0 {
        let first =
            crate::orderly::orderly_poweroff(crate::orderly::OrderlyReason::PowerButton, false);
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
                "  acpi: power button, no KEY_POWER consumer -> orderly power-off (poweroff_cmd)"
            );
        }
    }
    outcome
}
