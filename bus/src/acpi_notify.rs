//! ACPI Notify listener — Stage-4 structural shape.
//!
//! Spec: `bus/specification/spec.md` (Stage-4 ACPI notify
//! integration). The platform firmware delivers Notify events to
//! kernel via ACPI (e.g. battery state change, power-button press,
//! hot-plug, thermal) through the interpreter's `Notify` method.
//! NARF routes these through a cap-gated registry of listeners so
//! only authorized subsystems observe them.
//!
//! Without an ACPI interpreter linked in (a Stage-4+ piece),
//! `dispatch_notify()` is called by test code to prove the
//! subscribe/dispatch shape; production wiring comes when the
//! interpreter lands.

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant, NoopOp};
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker for ACPI notify subscribers.
/// `Cap<AcpiNotify, Grant>` authorises installation of a listener.
#[derive(Copy, Clone, Debug)]
pub struct AcpiNotify;

impl CapType for AcpiNotify {
    const KIND: CapKind = CapKind::BusRegistry;
}

/// ACPI notify value — 8-bit per ACPI spec. Named variants cover
/// the fixed device classes; `Device(u8)` carries device-specific
/// codes verbatim.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NotifyKind {
    /// 0x00 — Bus Check (device configuration may have changed).
    BusCheck,
    /// 0x01 — Device Check (re-enumerate a specific device).
    DeviceCheck,
    /// 0x02 — Device Wake.
    DeviceWake,
    /// 0x03 — Eject Request (user pressed eject).
    EjectRequest,
    /// 0x80 — Power-source change (AC plug/unplug).
    PowerSource,
    /// 0x81 — Battery information change.
    BatteryInfo,
    /// 0x82 — Thermal-zone threshold crossed.
    Thermal,
    /// Fallback for device-class-specific notify codes.
    Device(u8),
}

impl NotifyKind {
    pub const fn from_raw(code: u8) -> Self {
        match code {
            0x00 => NotifyKind::BusCheck,
            0x01 => NotifyKind::DeviceCheck,
            0x02 => NotifyKind::DeviceWake,
            0x03 => NotifyKind::EjectRequest,
            0x80 => NotifyKind::PowerSource,
            0x81 => NotifyKind::BatteryInfo,
            0x82 => NotifyKind::Thermal,
            c => NotifyKind::Device(c),
        }
    }

    pub const fn raw(&self) -> u8 {
        match self {
            NotifyKind::BusCheck => 0x00,
            NotifyKind::DeviceCheck => 0x01,
            NotifyKind::DeviceWake => 0x02,
            NotifyKind::EjectRequest => 0x03,
            NotifyKind::PowerSource => 0x80,
            NotifyKind::BatteryInfo => 0x81,
            NotifyKind::Thermal => 0x82,
            NotifyKind::Device(c) => *c,
        }
    }
}

/// Event delivered to subscribers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NotifyEvent {
    pub acpi_handle: u64,
    pub kind: NotifyKind,
}

/// Errors from the ACPI notify surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NotifyError {
    AuthorityRevoked,
    NotInitialised,
}

impl From<CapError> for NotifyError {
    fn from(_: CapError) -> Self {
        NotifyError::AuthorityRevoked
    }
}

type Subscriber = Box<dyn Fn(&NotifyEvent) + Send + Sync + 'static>;

struct Registry {
    subs: Vec<Subscriber>,
}

impl core::fmt::Debug for Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Registry")
            .field("subs", &self.subs.len())
            .finish()
    }
}

static REG: IrqSafeSpinLock<Option<Registry>> = IrqSafeSpinLock::new(None);

/// Initialise the ACPI notify registry.
pub fn init() {
    *REG.lock() = Some(Registry { subs: Vec::new() });
}

/// Install a notify subscriber. Cap-gated; called by each subsystem
/// at boot after it has received its `Cap<AcpiNotify, Grant>`.
pub fn subscribe<F>(cap: &Cap<AcpiNotify, Grant>, cb: F) -> Result<(), NotifyError>
where
    F: Fn(&NotifyEvent) + Send + Sync + 'static,
{
    cap.invoke(NoopOp)?;
    let mut r = REG.lock();
    let reg = r.as_mut().ok_or(NotifyError::NotInitialised)?;
    reg.subs.push(Box::new(cb));
    Ok(())
}

/// Dispatch a synthetic notify event to every subscriber. Production
/// callers come from the ACPI interpreter; tests can call directly.
pub fn dispatch_notify(ev: NotifyEvent) -> Result<(), NotifyError> {
    let r = REG.lock();
    let reg = r.as_ref().ok_or(NotifyError::NotInitialised)?;
    for cb in &reg.subs {
        cb(&ev);
    }
    Ok(())
}

/// Count of registered subscribers.
pub fn subscriber_count() -> usize {
    REG.lock().as_ref().map(|r| r.subs.len()).unwrap_or(0)
}

/// Test helper.
#[doc(hidden)]
pub fn __test_reset() {
    *REG.lock() = None;
}
