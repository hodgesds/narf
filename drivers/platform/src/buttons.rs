//! ACPI Power / Sleep button drivers — clean-room.
//!
//! Two delivery paths per ACPI 6.5 §4.8.3.1 (Fixed Hardware) and
//! §9.5 (Control-Method Power/Sleep Buttons):
//!
//! - **Fixed hardware** — PWRBTN_STS / SLPBTN_STS bits in the PM1
//!   status register fire on press; the SCI dispatcher in `ec.rs`
//!   forwards them as [`PlatformEvent::PowerButton`] /
//!   [`PlatformEvent::SleepButton`]. Wake handling for these buttons
//!   is mandatory on every ACPI-compliant platform.
//! - **Control-Method** — `PNP0C0C` (power) and `PNP0C0E` (sleep)
//!   AML devices. The firmware fires `Notify(<dev>, 0x80)` from a
//!   `_Qxx` handler; we re-evaluate `_PSW` opt-in wake control if
//!   present. (Notify dispatch lands once the AML evaluator grows
//!   `Notify` opcode support; today we trust the fixed-hardware
//!   bits, which every laptop also wires.)
//!
//! Subscribers can register either coarse (`subscribe_any`) for "any
//! button press, regardless of source" or per-event (`subscribe_power`,
//! `subscribe_sleep`).

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_aml::find_device_by_hid;
use narf_lib::sync::IrqSafeSpinLock;

use crate::ec::{subscribe_platform_event, PlatformEvent};

/// Which button the press came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Button {
    Power,
    Sleep,
}

type Subscriber = Box<dyn Fn(Button) + Send + Sync + 'static>;

static POWER_SUBS: IrqSafeSpinLock<Vec<Subscriber>> = IrqSafeSpinLock::new(Vec::new());
static SLEEP_SUBS: IrqSafeSpinLock<Vec<Subscriber>> = IrqSafeSpinLock::new(Vec::new());
static ANY_SUBS: IrqSafeSpinLock<Vec<Subscriber>> = IrqSafeSpinLock::new(Vec::new());

static POWER_PRESSES: AtomicU64 = AtomicU64::new(0);
static SLEEP_PRESSES: AtomicU64 = AtomicU64::new(0);
static SUBSCRIBED_TO_EC: AtomicBool = AtomicBool::new(false);

/// Install a callback for power-button presses.
pub fn subscribe_power<F: Fn(Button) + Send + Sync + 'static>(cb: F) {
    POWER_SUBS.lock().push(Box::new(cb));
}

/// Install a callback for sleep-button presses.
pub fn subscribe_sleep<F: Fn(Button) + Send + Sync + 'static>(cb: F) {
    SLEEP_SUBS.lock().push(Box::new(cb));
}

/// Install a callback that fires for either button.
pub fn subscribe_any<F: Fn(Button) + Send + Sync + 'static>(cb: F) {
    ANY_SUBS.lock().push(Box::new(cb));
}

/// Total power-button presses observed since boot.
pub fn power_press_count() -> u64 {
    POWER_PRESSES.load(Ordering::Acquire)
}

/// Total sleep-button presses observed since boot.
pub fn sleep_press_count() -> u64 {
    SLEEP_PRESSES.load(Ordering::Acquire)
}

fn dispatch(button: Button) {
    match button {
        Button::Power => POWER_PRESSES.fetch_add(1, Ordering::Release),
        Button::Sleep => SLEEP_PRESSES.fetch_add(1, Ordering::Release),
    };
    let any = ANY_SUBS.lock();
    for s in any.iter() {
        s(button);
    }
    let specific = match button {
        Button::Power => POWER_SUBS.lock(),
        Button::Sleep => SLEEP_SUBS.lock(),
    };
    for s in specific.iter() {
        s(button);
    }
}

/// Discover Control-Method button devices and subscribe to the EC
/// platform-event feed for fixed-hardware button bits.
pub fn init() {
    let mut found = 0u32;
    if find_device_by_hid("PNP0C0C").is_some() {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-buttons: power-button (PNP0C0C) present"
        );
        found += 1;
    }
    if find_device_by_hid("PNP0C0E").is_some() {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-buttons: sleep-button (PNP0C0E) present"
        );
        found += 1;
    }
    if found == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-buttons: no control-method buttons found; relying on fixed-hardware bits"
        );
    }

    if !SUBSCRIBED_TO_EC.swap(true, Ordering::AcqRel) {
        subscribe_platform_event(|event| match event {
            PlatformEvent::PowerButton => dispatch(Button::Power),
            PlatformEvent::SleepButton => dispatch(Button::Sleep),
            _ => {}
        });
    }
}

/// Test-only entrypoint used by smokes and the SCI dispatcher to
/// inject a synthetic press into the subscriber chain. Kept public
/// (rather than `pub(crate)`) so kernel tests in `tests.rs` can drive
/// it from outside the module without an extra hidden surface.
#[doc(hidden)]
pub fn __test_inject(button: Button) {
    dispatch(button);
}

/// Test helper: drain registries.
#[doc(hidden)]
pub fn __test_reset() {
    POWER_SUBS.lock().clear();
    SLEEP_SUBS.lock().clear();
    ANY_SUBS.lock().clear();
    POWER_PRESSES.store(0, Ordering::Release);
    SLEEP_PRESSES.store(0, Ordering::Release);
    SUBSCRIBED_TO_EC.store(false, Ordering::Release);
}
