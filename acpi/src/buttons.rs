//! ACPI fixed-feature buttons — power + sleep.
//!
//! ACPI 6.5 §4.8: the platform exposes two fixed-feature buttons
//! through the FADT's PM1 control / status registers and (on
//! modern systems) through Control Method buttons:
//!
//! - **Power button** — Notify code 0x80 = "user pressed power";
//!   the OS-side power-button service runs the configured policy
//!   (shutdown / sleep / nothing).
//! - **Sleep button** — Notify code 0x80 = "user pressed sleep";
//!   the OS enters the configured sleep state (usually S3 or S4).
//!
//! Both buttons can also fire via PM1 status bits PWRBTN_STS
//! (bit 8 of PM1A_STS) and SLPBTN_STS (bit 9) when implemented
//! as fixed-features rather than control-method devices. The
//! SCI handler observes those bits and dispatches the event the
//! same way as the control-method form.

use core::sync::atomic::{AtomicU8, Ordering};

/// Press-count for the power button — incremented every time
/// the host observes a power-button event. The userland power
/// service reads + clears this to debounce / batch.
static POWER_PRESSES: AtomicU8 = AtomicU8::new(0);
static SLEEP_PRESSES: AtomicU8 = AtomicU8::new(0);

/// Record a power-button press. Called from the AML notify
/// dispatcher or the PM1_STS-bit decoder.
pub fn record_power_button_press() {
    POWER_PRESSES.fetch_add(1, Ordering::AcqRel);
}

/// Drain accumulated power-button presses. Returns the count
/// since the last drain.
pub fn drain_power_button_presses() -> u8 {
    POWER_PRESSES.swap(0, Ordering::AcqRel)
}

/// Record a sleep-button press.
pub fn record_sleep_button_press() {
    SLEEP_PRESSES.fetch_add(1, Ordering::AcqRel);
}

/// Drain accumulated sleep-button presses.
pub fn drain_sleep_button_presses() -> u8 {
    SLEEP_PRESSES.swap(0, Ordering::AcqRel)
}

/// Notify code for "fixed-feature button pressed" (ACPI 6.5 §4.8).
pub const NOTIFY_BUTTON_PRESSED: u8 = 0x80;

/// PM1_STS bit positions for fixed-feature buttons.
pub const PM1_STS_PWRBTN: u16 = 1 << 8;
pub const PM1_STS_SLPBTN: u16 = 1 << 9;

#[doc(hidden)]
pub fn __reset_for_test() {
    POWER_PRESSES.store(0, Ordering::Release);
    SLEEP_PRESSES.store(0, Ordering::Release);
}
