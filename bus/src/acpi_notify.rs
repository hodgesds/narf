//! ACPI Notify event-bus topic — migrated to `narf-event-bus`.
//!
//! Stage-4 structural shape. The platform firmware delivers Notify
//! events to the kernel via ACPI (e.g. battery state change,
//! power-button press, hot-plug, thermal) through the interpreter's
//! `Notify` method. NARF routes these onto the
//! `acpi.notify` event-bus topic; subscribers attach via
//! `event_bus::lookup_topic::<NotifyEvent>` and consume async.
//!
//! Without an ACPI interpreter linked in (a Stage-4+ piece),
//! `dispatch_notify()` is called by test code to prove the publish
//! shape; production wiring comes when the interpreter lands.
//!
//! Migration note (Phase 1 hard cutover): the previous
//! `Vec<Box<dyn Fn(&NotifyEvent)>>` callback list + spinlock was
//! removed in this commit. Subsystems that registered callbacks now
//! `lookup_topic::<NotifyEvent>` and spawn an async task that drains
//! `Subscriber::next().await`. The previous `subscribe(cap, cb)` and
//! `subscriber_count()` symbols no longer exist.

use narf_capabilities::{Cap, CapKind, CapType, Read, Write};
use narf_event_bus::{
    create_topic, lookup_topic, CreateError, LookupError, PublishError, Publisher, Subscriber,
    TopicRegistry,
};
use narf_lib::sync::IrqSafeSpinLock;

/// Cap-type marker retained for in-tree subsystems that still spell
/// their authority as `Cap<AcpiNotify, R>`. The new event-bus path
/// uses `Cap<TopicRegistry, R>` directly; this is preserved so
/// callers that hold an `AcpiNotify` cap can transparently mint the
/// matching registry cap.
#[derive(Copy, Clone, Debug)]
pub struct AcpiNotify;

impl CapType for AcpiNotify {
    const KIND: CapKind = CapKind::BusRegistry;
}

/// ACPI notify value — 8-bit per ACPI spec. Named variants cover
/// the fixed device classes; `Device(u8)` carries device-specific
/// codes verbatim. The Rust enum's discriminant layout is the
/// compiler's choice; the bit-level mapping to/from the ACPI byte
/// is in `from_raw` / `raw`.
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

/// Event delivered to subscribers via the `acpi.notify` topic.
/// `Copy + 'static + Send + Sync` so it fits a fixed-size bus slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct NotifyEvent {
    pub acpi_handle: u64,
    pub kind: NotifyKind,
}

// SAFETY: NotifyEvent is plain data with no interior mutability and
// no references; Copy. The bus's `Event` trait is automatically
// implemented for any `T: Copy + Send + Sync + 'static`.

/// Errors surfaced by this module's wrappers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NotifyError {
    AuthorityRevoked,
    NotInitialised,
    CreateFailed,
    LookupFailed,
}

/// Topic name used for ACPI Notify events. Picked from the reserved-
/// root `acpi.` namespace so only kernel can mint.
pub const TOPIC: &str = "acpi.notify";

/// Default ring capacity (slots). Notify-rate is human-driven (button
/// presses, AC plug/unplug, occasional thermal crossings); 64 slots
/// covers any reasonable burst.
pub const CAPACITY: usize = 64;

/// Cached publisher handle minted during `init`. `IrqSafeSpinLock`
/// because the SCI bottom-half may publish from interrupt context.
static PUBLISHER: IrqSafeSpinLock<Option<Publisher<NotifyEvent>>> = IrqSafeSpinLock::new(None);

/// Initialise the topic. Mints a `Cap<TopicRegistry, Write>`,
/// creates `acpi.notify` with `NotifyEvent` payload, and caches the
/// publisher. Idempotent.
pub fn init() {
    let g = PUBLISHER.lock();
    if g.is_some() {
        return;
    }
    drop(g);

    // Ensure the bus is initialised before we mint a topic on it.
    narf_event_bus::init();

    let reg: Cap<TopicRegistry, Write> = Cap::bootstrap();
    match create_topic::<NotifyEvent>(&reg, TOPIC, CAPACITY) {
        Ok((_id, publisher)) => {
            *PUBLISHER.lock() = Some(publisher);
        }
        Err(CreateError::NameTaken) => {
            // Another path raced us — fine, just no-op.
        }
        Err(_) => {
            // Could log here; for Phase 1 silently leave PUBLISHER
            // = None so dispatch_notify reports NotInitialised.
        }
    }
}

/// Mint a fresh `Subscriber<NotifyEvent>` for the topic. The caller
/// holds a `Cap<TopicRegistry, Read>` (the lookup-only authority);
/// the registry checks liveness. Drives the per-task drain via
/// `Subscriber::next().await`.
pub fn subscribe(reg: &Cap<TopicRegistry, Read>) -> Result<Subscriber<NotifyEvent>, NotifyError> {
    match lookup_topic::<NotifyEvent>(reg, TOPIC) {
        Ok(s) => Ok(s),
        Err(LookupError::CapRevoked) => Err(NotifyError::AuthorityRevoked),
        Err(LookupError::NotFound) => Err(NotifyError::NotInitialised),
        Err(_) => Err(NotifyError::LookupFailed),
    }
}

/// Publish a synthetic notify event. Production callers come from
/// the ACPI interpreter; tests can call directly.
pub fn dispatch_notify(ev: NotifyEvent) -> Result<(), NotifyError> {
    let g = PUBLISHER.lock();
    let p = g.as_ref().ok_or(NotifyError::NotInitialised)?;
    match p.publish(ev) {
        Ok(_) => Ok(()),
        Err(PublishError::CapRevoked) => Err(NotifyError::AuthorityRevoked),
        Err(_) => Err(NotifyError::CreateFailed),
    }
}

/// Test helper.
#[doc(hidden)]
pub fn __test_reset() {
    *PUBLISHER.lock() = None;
    narf_event_bus::registry::__reset_for_test();
}
