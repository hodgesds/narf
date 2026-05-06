//! ACPI Lid Switch driver — clean-room.
//!
//! Spec: ACPI 6.5 §9.4.1 (Control-Method Lid Device, `_HID = "PNP0C0D"`).
//!
//! The lid is a binary "open/closed" switch. Its state is queried via
//! the device's `_LID` method (returns 0 for closed, 1 for open).
//! Lid transitions are reported as Notify(0x80) events delivered
//! through the platform's SCI/GPE path; this driver subscribes to the
//! [`PlatformEvent::EcQuery`] feed so the EC's `_Qxx` handler — which
//! the firmware writes to call `Notify(\_SB.LID, 0x80)` — wakes our
//! state cache and fires user-installed subscribers.
//!
//! Today the namespace's `Notify(...)` opcode is parsed but not yet
//! evaluated, so we close the loop by **re-evaluating `_LID`** on
//! every EC query and emitting [`LidEvent`]s when the cached value
//! changes. Once `Notify` lands, lid devices register a per-target
//! callback directly.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use narf_aml::eval::evaluate_method;
use narf_aml::find_device_by_hid;
use narf_lib::sync::IrqSafeSpinLock;

use crate::ec::{subscribe_platform_event, PlatformEvent};

/// Lid state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LidState {
    Closed,
    Open,
    /// `_LID` is missing or returned a non-{0,1} value.
    Unknown,
}

/// Lid transition event.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LidEvent {
    Opened,
    Closed,
}

/// Bookkeeping for one lid device. Most laptops ship exactly one;
/// convertibles can ship two.
#[derive(Debug)]
pub struct LidDevice {
    pub path: String,
    /// 0 = unknown, 1 = closed, 2 = open. We use a u8 so the field
    /// is `Sync` without an extra mutex.
    state: AtomicU8,
}

impl LidDevice {
    fn new(path: String) -> Self {
        Self {
            path,
            state: AtomicU8::new(0),
        }
    }

    pub fn state(&self) -> LidState {
        match self.state.load(Ordering::Acquire) {
            1 => LidState::Closed,
            2 => LidState::Open,
            _ => LidState::Unknown,
        }
    }

    /// Re-evaluate `_LID`. Returns the new state and a `LidEvent`
    /// when the value changed.
    pub fn refresh(&self) -> (LidState, Option<LidEvent>) {
        let path = alloc::format!("{}._LID", self.path);
        let raw = match evaluate_method(&path, &[]) {
            Ok(v) => v.as_integer(),
            Err(_) => return (LidState::Unknown, None),
        };
        let new = match raw {
            0 => LidState::Closed,
            1 => LidState::Open,
            _ => LidState::Unknown,
        };
        let new_code = match new {
            LidState::Closed => 1,
            LidState::Open => 2,
            LidState::Unknown => 0,
        };
        let prev_code = self.state.swap(new_code, Ordering::AcqRel);
        let event = if prev_code != new_code {
            match new {
                LidState::Open => Some(LidEvent::Opened),
                LidState::Closed => Some(LidEvent::Closed),
                LidState::Unknown => None,
            }
        } else {
            None
        };
        (new, event)
    }
}

type LidSubscriber = Box<dyn Fn(LidEvent) + Send + Sync + 'static>;

static LIDS: IrqSafeSpinLock<Vec<Arc<LidDevice>>> = IrqSafeSpinLock::new(Vec::new());
static SUBSCRIBERS: IrqSafeSpinLock<Vec<LidSubscriber>> = IrqSafeSpinLock::new(Vec::new());
static SUBSCRIBED_TO_EC: AtomicBool = AtomicBool::new(false);

/// All discovered lid devices.
pub fn lids() -> Vec<Arc<LidDevice>> {
    LIDS.lock().clone()
}

/// Install a subscriber for lid open/close transitions.
pub fn subscribe<F: Fn(LidEvent) + Send + Sync + 'static>(cb: F) {
    SUBSCRIBERS.lock().push(Box::new(cb));
}

fn notify(event: LidEvent) {
    let subs = SUBSCRIBERS.lock();
    for s in subs.iter() {
        s(event);
    }
}

fn refresh_all() {
    let lids = LIDS.lock().clone();
    for lid in lids {
        let (_, event) = lid.refresh();
        if let Some(e) = event {
            notify(e);
        }
    }
}

/// Walk the AML namespace, register every PNP0C0D as a lid device,
/// subscribe to the EC platform event feed.
pub fn init() {
    let mut count = 0u32;
    if let Some(dev) = find_device_by_hid("PNP0C0D") {
        let lid = Arc::new(LidDevice::new(dev.path.clone()));
        // Prime the cache with the boot-time state.
        let _ = lid.refresh();
        LIDS.lock().push(lid);
        count += 1;
    }

    // Some laptops list multiple lid devices (convertibles); the
    // current AML walker only exposes a single `find_device_by_hid`,
    // so for now we capture the first. A full multi-device walk
    // lands when AML grows a `for_each_device_by_hid`.

    if count == 0 {
        let _ = writeln!(
            narf_console::Writer,
            "  acpi-lid: no PNP0C0D device discovered"
        );
        return;
    }

    let _ = writeln!(
        narf_console::Writer,
        "  acpi-lid: {} device(s) registered",
        count
    );

    if !SUBSCRIBED_TO_EC.swap(true, Ordering::AcqRel) {
        subscribe_platform_event(|event| {
            // Any EC query may have triggered Notify(LID, 0x80); the
            // cheapest correct response without a full Notify
            // evaluator is to re-read `_LID` on every EC event.
            // Power/sleep buttons don't touch lid state, so we ignore
            // them.
            if let PlatformEvent::EcQuery(_) = event {
                refresh_all();
            }
        });
    }
}

/// Test helper: drain registry + subscribers.
#[doc(hidden)]
pub fn __test_reset() {
    LIDS.lock().clear();
    SUBSCRIBERS.lock().clear();
    SUBSCRIBED_TO_EC.store(false, Ordering::Release);
}
