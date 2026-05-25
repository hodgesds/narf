//! GPIO controller trait + AMD FCH / Intel PCH GPIO drivers.
//!
//! Layered design:
//! - `GpioController` trait + name-keyed registry of controllers, so
//!   a HID-over-I2C client (or any other driver decoded from
//!   `_CRS::GpioInt`) can locate the parent GPIO block by ACPI path.
//! - `amd_fch` — AMD FCH GPIO controller driver (Zen1-Zen4 laptops).
//!   Per pin: 32-bit register at `pin * 4`; interrupt status /
//!   enable / level / polarity all in that single dword. The whole
//!   block shares one GSI; the ISR scans pin status registers and
//!   dispatches.
//! - `intel_pch` — Intel PCH GPIO Stage-0 scaffold (Tiger Lake +
//!   Alder Lake + Raptor Lake + Meteor Lake). Discovery only:
//!   decodes `_CRS` `Memory32Fixed` per community, reads `REVID` /
//!   `PADBAR`, registers the controller into the shared registry
//!   so i2c-hid-bind can resolve a `GpioInt::resource_source`
//!   referring to a PCH GPIO block. Pin programming is Stage-1.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod amd_fch;
pub mod intel_pch;
pub mod registry;

use alloc::vec::Vec;

/// Direction of a GPIO pin.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpioDirection {
    Input,
    Output,
}

/// Pull-up / pull-down configuration. Mirrors ACPI `_CRS::GpioInt`'s
/// PinConfiguration byte: 0=default, 1=PullUp, 2=PullDown, 3=PullNone.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpioPull {
    Default,
    Up,
    Down,
    None,
}

/// Trigger / polarity for an interrupt-configured pin. Mirrors the
/// `level_triggered` + `polarity` fields decoded out of
/// `ResourceItem::GpioInt`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GpioIrqConfig {
    /// `true` = level-triggered, `false` = edge-triggered.
    pub level_triggered: bool,
    /// 0=ActiveHigh, 1=ActiveLow, 2=ActiveBoth.
    pub polarity: u8,
}

/// Synchronous interrupt handler invoked by the ISR when a pin
/// fires. Runs in IRQ context — must be allocator-safe and brief.
pub type GpioIrqHandler = fn(pin: u16);

/// GPIO controller error surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpioError {
    /// Pin index out of range for this controller.
    InvalidPin,
    /// Asked to set an output value on a pin currently configured as
    /// input (or vice-versa).
    WrongDirection,
    /// Interrupt handler slot already in use for this pin.
    AlreadyRegistered,
    /// Hardware register read returned an impossible value.
    BadHardware,
}

/// One GPIO controller. Methods take `&self` because each controller
/// guards its own MMIO / handler table internally with a spinlock —
/// callers don't need a mutable handle.
pub trait GpioController: Send + Sync + core::fmt::Debug {
    /// Identifier — typically the ACPI path (`\_SB.GPIO`).
    fn name(&self) -> &str;

    /// Number of pins this controller exposes. Pin indices `0..pin_count()`
    /// are valid arguments to all other methods.
    fn pin_count(&self) -> u16;

    /// Read the current logical state of `pin` (works in both input
    /// and output configurations — AMD FCH always reflects the pin
    /// value in the status bit).
    fn read_pin(&self, pin: u16) -> Result<bool, GpioError>;

    /// Drive `pin` to `value`. Returns `WrongDirection` if the pin
    /// is currently configured as input.
    fn set_pin(&self, pin: u16, value: bool) -> Result<(), GpioError>;

    /// Configure `pin` as an interrupt input with the given pull
    /// configuration + trigger / polarity, then install `handler`.
    /// Idempotent in the sense that a duplicate registration with
    /// the same handler succeeds; a different handler returns
    /// `AlreadyRegistered`.
    fn register_irq(
        &self,
        pin: u16,
        pull: GpioPull,
        irq: GpioIrqConfig,
        handler: GpioIrqHandler,
    ) -> Result<(), GpioError>;

    /// Mask the pin's interrupt + drop its handler. Idempotent.
    fn unregister_irq(&self, pin: u16);
}

/// Register all known GPIO controllers. Stage::Device entry — runs
/// once during boot. `NotPresent` on systems without either an AMD
/// FCH or an Intel PCH GPIO block (most QEMU TCG configs); the
/// only consumer of GPIO controllers today is the i2c-hid driver,
/// which handles the absence gracefully via the `_CRS::GpioInt::
/// resource_source` lookup returning `None`.
///
/// The two probes run as separate initcalls so a no-match in one
/// doesn't gate the other — the Stage-1 bring-up target group has
/// both AMD Zen2 / Zen4 laptops (FCH path) and Intel laptops (PCH
/// path). Either initcall registering at least one controller is
/// enough to let i2c-hid-bind resolve `GpioInt::resource_source`.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "amd-fch-gpio", || {
        let n = amd_fch::probe_all();
        if n == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
    narf_init::register(Stage::Device, "intel-pch-gpio", || {
        let n = intel_pch::probe_all();
        if n == 0 {
            InitResult::NotPresent
        } else {
            InitResult::Ok
        }
    });
}

/// Snapshot of every registered GPIO controller.
pub fn registered_controllers() -> Vec<alloc::sync::Arc<dyn GpioController>> {
    registry::list()
}

/// Lock-free count of registered controllers — for diagnostics that
/// must not contend with driver-probe locks.
pub fn registered_controller_count() -> u32 {
    registry::REGISTERED_COUNT.load(core::sync::atomic::Ordering::Acquire)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
