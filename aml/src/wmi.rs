//! Windows Management Instrumentation (WMI) ACPI mapping.
//!
//! WMI is the vendor-specific extension surface every modern
//! laptop OEM uses to expose hotkeys, fan-control profiles,
//! battery thresholds, and chassis sensors. The ACPI/WMI mapper
//! (Microsoft spec, observed in every Windows laptop DSDT) lives
//! at PNP IDs like `PNP0C14`.
//!
//! Each WMI device exposes:
//!
//! - **`_WDG`** — "WMI Device Data" — a Buffer returning a packed
//!   array of 20-byte descriptors. Each descriptor is
//!   `(guid: 16 bytes, object_id: 2 bytes, instance_count: 1 byte,
//!   flags: 1 byte)`. The `object_id` is two ASCII characters that
//!   form part of the AML method name to invoke for that GUID.
//! - **`WMxx`** — method to query/set data for an object. Name is
//!   `WM` + `object_id` (e.g. object `AA` → method `WMAA`).
//! - **`WExx`** — event method for asynchronous notification.
//! - **`_WED`** — translate a notification value into a GUID.
//!
//! For laptop hotkey support, the standard flow is:
//!   1. EC fires `_Qxx` →
//!   2. AML invokes `Notify(\_SB.WMI, value)` →
//!   3. Notify handler calls `_WED(value)` to translate to GUID →
//!   4. Host looks up a registered Rust handler for that GUID →
//!   5. Handler decodes the WMI-method return value into a key event.
//!
//! This module owns the registry side of that chain. Per-vendor
//! GUID → keycode tables live in laptop-specific driver crates.
//!
//! Reference: Microsoft "ACPI/WMI Mapping" spec + observed DSDTs
//! across Dell / HP / Lenovo / ThinkPad / ASUS / Framework.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

// ── _WDG descriptor format ─────────────────────────────────────────

/// Bit positions for the `flags` byte of a `_WDG` descriptor.
pub const WDG_FLAG_EXPENSIVE: u8 = 1 << 0;
pub const WDG_FLAG_METHOD: u8 = 1 << 1;
pub const WDG_FLAG_STRING: u8 = 1 << 2;
pub const WDG_FLAG_EVENT: u8 = 1 << 3;

/// One _WDG descriptor — a single WMI object/event mapping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WdgDescriptor {
    /// 16-byte little-endian GUID identifying the WMI surface.
    pub guid: [u8; 16],
    /// Two ASCII bytes that form part of the AML method name.
    /// E.g. `[b'A', b'A']` → `WMAA` for the method form.
    pub object_id: [u8; 2],
    /// Instance count (number of independent objects with this GUID).
    pub instance_count: u8,
    /// Flag byte — see WDG_FLAG_* constants above.
    pub flags: u8,
}

impl WdgDescriptor {
    /// True iff this descriptor describes an event (not a data
    /// object or method). Event handlers fire via `Notify`.
    pub fn is_event(&self) -> bool {
        self.flags & WDG_FLAG_EVENT != 0
    }

    /// AML method name for this WMI object — `WM` + object_id for
    /// data/methods, `WE` + object_id for events. Returns None if
    /// the object_id bytes aren't printable ASCII.
    pub fn method_name(&self) -> Option<String> {
        if !self.object_id[0].is_ascii_graphic() || !self.object_id[1].is_ascii_graphic() {
            return None;
        }
        let prefix = if self.is_event() { "WE" } else { "WM" };
        Some(alloc::format!(
            "{}{}{}",
            prefix,
            self.object_id[0] as char,
            self.object_id[1] as char
        ))
    }
}

/// Errors decoding a `_WDG` buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WdgError {
    /// Buffer length isn't a multiple of 20 (the per-descriptor size).
    BadLength(usize),
}

/// Decode a `_WDG` buffer into an array of descriptors.
pub fn decode_wdg(buf: &[u8]) -> Result<Vec<WdgDescriptor>, WdgError> {
    if buf.len() % 20 != 0 {
        return Err(WdgError::BadLength(buf.len()));
    }
    let count = buf.len() / 20;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 20;
        let e = &buf[off..off + 20];
        out.push(WdgDescriptor {
            guid: e[0..16].try_into().unwrap(),
            object_id: [e[16], e[17]],
            instance_count: e[18],
            flags: e[19],
        });
    }
    Ok(out)
}

// ── Event-handler registry (GUID → keycode dispatcher) ─────────────

/// A handler invoked when a WMI event with the registered GUID
/// fires. Receives the notification value (passed by the AML
/// `Notify`) so multi-press / multi-key WMI events can fan out.
pub type WmiEventHandler = fn(notify_value: u64);

struct WmiRegistration {
    guid: [u8; 16],
    handler: WmiEventHandler,
}

static WMI_HANDLERS: IrqSafeSpinLock<Vec<WmiRegistration>> = IrqSafeSpinLock::new(Vec::new());

/// Register a Rust handler to fire whenever WMI signals an event
/// for `guid`. Multiple handlers for the same GUID are all called.
pub fn register_wmi_event_handler(guid: [u8; 16], handler: WmiEventHandler) {
    WMI_HANDLERS.lock().push(WmiRegistration { guid, handler });
}

/// Look up + invoke every handler registered for `guid`. Called by
/// the AML notify dispatcher after `_WED` resolves a notification
/// value into a GUID. Returns the number of handlers invoked.
pub fn dispatch_wmi_event(guid: &[u8; 16], notify_value: u64) -> usize {
    // Collect under the lock, dispatch outside so handlers can
    // re-enter the WMI surface (e.g. read state via WMxx) without
    // deadlocking.
    let handlers: Vec<WmiEventHandler> = {
        let g = WMI_HANDLERS.lock();
        g.iter()
            .filter(|r| r.guid == *guid)
            .map(|r| r.handler)
            .collect()
    };
    let n = handlers.len();
    for h in handlers {
        h(notify_value);
    }
    n
}

#[doc(hidden)]
pub fn __reset_for_test() {
    WMI_HANDLERS.lock().clear();
}
