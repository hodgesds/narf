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
//! - **`WQxx`** — data block read method (`WQ` + `object_id`).
//! - **`WSxx`** — data block write method (`WS` + `object_id`).
//! - **`WExx`** — event method for asynchronous notification.
//! - **`_WED`** — translate a notification value into event data.
//!
//! For laptop hotkey support, the standard flow is:
//!   1. EC fires `_Qxx` →
//!   2. AML invokes `Notify(\_SB.WMI, value)` →
//!   3. Notify handler calls `_WED(value)` to translate to event data →
//!   4. Host looks up a registered Rust handler for that GUID →
//!   5. Handler decodes the WMI-method return value into a key event.
//!
//! This module owns the registry side of that chain. Per-vendor
//! GUID → keycode tables live in laptop-specific driver crates.
//!
//! Reference: Linux `drivers/platform/x86/wmi.c` (GPL-2.0-or-later),
//! Microsoft "ACPI/WMI Mapping" spec, observed DSDTs across
//! Dell / HP / Lenovo / ThinkPad / ASUS / Framework.
//!
//! GUID byte order: the WMI spec stores GUIDs in mixed-endian order
//! (RFC 4122 § 4.1.2 wire format): Data1 (4 bytes LE), Data2 (2 bytes
//! LE), Data3 (2 bytes LE), Data4 (8 bytes big-endian). The canonical
//! string representation is "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX".
//! The raw 16-byte `_WDG` buffer stores them in that mixed-endian
//! layout, so byte comparisons against other raw `[u8;16]` values from
//! `_WDG` work directly; no byteswap is needed unless converting to/
//! from the string form.
//!
//! Reference (Linux): `wmi.c::find_guid`, `wmi_method_call`,
//! `wmi_query_block`, `wmi_set_block`, `acpi_wmi_notify_handler`.

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
///
/// Layout mirrors the 20-byte entries in `_WDG` exactly:
/// - bytes  0–15: raw GUID (mixed-endian per RFC 4122)
/// - bytes 16–17: object_id (two ASCII chars forming method suffix)
/// - byte  18:    instance_count
/// - byte  19:    flags
///
/// Reference: Linux `wmi.c::wmi_block` and `parse_wdg`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WdgDescriptor {
    /// 16-byte mixed-endian GUID identifying the WMI surface.
    pub guid: [u8; 16],
    /// Two ASCII bytes that form part of the AML method name.
    /// E.g. `[b'A', b'A']` → `WMAA` / `WQAA` / `WSAA` for the
    /// method / query / set forms.
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

    /// True iff this descriptor describes a data block accessible
    /// via `WQxx`/`WSxx`. Mutually exclusive with `is_event()`.
    pub fn is_data_block(&self) -> bool {
        !self.is_event()
    }

    /// AML method name for invoking this WMI object — `WM` +
    /// object_id for data/methods, `WE` + object_id for events.
    /// Returns None if the object_id bytes aren't printable ASCII.
    ///
    /// Reference: Linux `wmi.c::wmi_method_call` — method name is
    /// always `"WM" + object_id_string`.
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

    /// AML method name for reading a data block — `WQ` + object_id.
    /// Reference: Linux `wmi.c::wmi_query_block` — method `"WQ" + id`.
    pub fn query_method_name(&self) -> Option<String> {
        if !self.object_id[0].is_ascii_graphic() || !self.object_id[1].is_ascii_graphic() {
            return None;
        }
        Some(alloc::format!(
            "WQ{}{}",
            self.object_id[0] as char,
            self.object_id[1] as char
        ))
    }

    /// AML method name for writing a data block — `WS` + object_id.
    /// Reference: Linux `wmi.c::wmi_set_block` — method `"WS" + id`.
    pub fn set_method_name(&self) -> Option<String> {
        if !self.object_id[0].is_ascii_graphic() || !self.object_id[1].is_ascii_graphic() {
            return None;
        }
        Some(alloc::format!(
            "WS{}{}",
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
///
/// Each 20-byte entry is: 16-byte GUID, 2-byte object_id, 1-byte
/// instance_count, 1-byte flags. Reference: Linux `parse_wdg()`.
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

// ── WmiGuid — the public GUID identity type ────────────────────────

/// A WMI GUID as found in a `_WDG` descriptor. Wraps the raw 16-byte
/// little/mixed-endian encoding from the ACPI buffer, plus the
/// absolute path of the owning WMI device (`\\SB.WMI` etc.).
///
/// Two `WmiGuid`s are equal iff their raw bytes match, regardless of
/// which device they came from (each GUID is globally unique per the
/// WMI spec — a given GUID is only valid on one device at a time).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WmiGuid {
    /// Raw 16-byte GUID in mixed-endian _WDG wire format.
    pub guid: [u8; 16],
    /// Absolute AML path of the PNP0C14 device that owns this GUID.
    pub device_path: String,
    /// Two-char ASCII object identifier used in method names.
    pub object_id: [u8; 2],
    /// Instance count from _WDG.
    pub instance_count: u8,
    /// Flags byte from _WDG (WDG_FLAG_* bitmask).
    pub flags: u8,
}

impl WmiGuid {
    /// True iff this GUID describes an event surface.
    pub fn is_event(&self) -> bool {
        self.flags & WDG_FLAG_EVENT != 0
    }

    /// True iff this GUID describes a data block.
    pub fn is_data_block(&self) -> bool {
        !self.is_event()
    }

    /// Build the fully-qualified AML path for the WM-method.
    /// e.g. device `\_SB.WMI`, object_id `AA` → `\_SB.WMI.WMAA`.
    pub fn method_path(&self) -> Option<String> {
        if !self.object_id[0].is_ascii_graphic() || !self.object_id[1].is_ascii_graphic() {
            return None;
        }
        let prefix = if self.is_event() { "WE" } else { "WM" };
        Some(alloc::format!(
            "{}.{}{}{}",
            self.device_path,
            prefix,
            self.object_id[0] as char,
            self.object_id[1] as char
        ))
    }

    /// Build the fully-qualified AML path for the WQ-query-method.
    pub fn query_path(&self) -> Option<String> {
        if !self.object_id[0].is_ascii_graphic() || !self.object_id[1].is_ascii_graphic() {
            return None;
        }
        Some(alloc::format!(
            "{}.WQ{}{}",
            self.device_path,
            self.object_id[0] as char,
            self.object_id[1] as char
        ))
    }

    /// Build the fully-qualified AML path for the WS-set-method.
    pub fn set_path(&self) -> Option<String> {
        if !self.object_id[0].is_ascii_graphic() || !self.object_id[1].is_ascii_graphic() {
            return None;
        }
        Some(alloc::format!(
            "{}.WS{}{}",
            self.device_path,
            self.object_id[0] as char,
            self.object_id[1] as char
        ))
    }

    /// Build the fully-qualified AML path for `_WED` on this device.
    pub fn wed_path(&self) -> String {
        alloc::format!("{}._WED", self.device_path)
    }
}

// ── WmiError ───────────────────────────────────────────────────────

/// Errors from WMI operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WmiError {
    /// AML method evaluation failed.
    AmlError(crate::AmlError),
    /// The method for this GUID doesn't exist in the namespace.
    MethodNotFound,
    /// The returned value wasn't a Buffer (for query operations).
    NotABuffer,
    /// Instance index out of range for this GUID.
    BadInstance,
    /// The `_WDG` buffer returned by the WMI device had a bad length.
    BadWdg(WdgError),
    /// GUID is not registered on this platform.
    GuidNotFound,
}

impl From<crate::AmlError> for WmiError {
    fn from(e: crate::AmlError) -> Self {
        match e {
            crate::AmlError::MethodNotFound => WmiError::MethodNotFound,
            other => WmiError::AmlError(other),
        }
    }
}

// ── WmiEvent ───────────────────────────────────────────────────────

/// An event delivered from a WMI device via ACPI Notify.
///
/// When the EC or firmware fires `Notify(\\_SB.WMI, value)`, the
/// ACPI notify dispatcher calls `handle_wmi_notify` with that value.
/// `_WED(value)` is then evaluated to get the event payload.
#[derive(Clone, Debug)]
pub struct WmiEvent {
    /// The raw ACPI Notify value.
    pub notify_value: u64,
    /// Matching GUID from `_WDG`, if found.
    pub guid: Option<[u8; 16]>,
    /// Payload returned by `_WED(notify_value)`, if present.
    pub data: Option<crate::Value>,
}

// ── Global GUID registry ───────────────────────────────────────────

/// All WMI GUIDs enumerated from every `PNP0C14` device in the
/// namespace. Populated by `enumerate_guids()`.
static WMI_GUIDS: IrqSafeSpinLock<Vec<WmiGuid>> = IrqSafeSpinLock::new(Vec::new());

// ── Event-handler registry (GUID → handler dispatcher) ────────────

/// A handler invoked when a WMI event with the registered GUID
/// fires. Receives the full `WmiEvent` so multi-press / multi-key
/// WMI events can fan out.
pub type WmiEventHandler = fn(event: &WmiEvent);

struct WmiRegistration {
    guid: [u8; 16],
    handler: WmiEventHandler,
}

static WMI_HANDLERS: IrqSafeSpinLock<Vec<WmiRegistration>> = IrqSafeSpinLock::new(Vec::new());

// ── Public API ─────────────────────────────────────────────────────

/// Walk the AML namespace for every `PNP0C14` device, evaluate its
/// `_WDG` method/name, and register all WMI GUIDs into the global
/// registry. Idempotent — clears the registry first.
///
/// Returns the number of GUIDs registered, or a `WmiError` if any
/// step fails catastrophically.
///
/// Reference: Linux `wmi.c::acpi_wmi_add` — does exactly this scan
/// for each matching ACPI device at device-probe time.
pub fn enumerate_guids() -> Vec<WmiGuid> {
    let devices = crate::find_all_devices_by_hid("PNP0C14");
    let mut all: Vec<WmiGuid> = Vec::new();

    for dev in &devices {
        let wdg_path = alloc::format!("{}._WDG", dev.path);
        // _WDG may be a Name(Buffer(...)) or a Method returning a Buffer.
        let wdg_value = match crate::eval::evaluate_method(&wdg_path, &[]) {
            Ok(v) => v,
            Err(_) => {
                // Try reading it as a Name node value (some DSDTs declare
                // _WDG as Name(_WDG, Buffer(...)) rather than a Method).
                match crate::find_node(&wdg_path) {
                    Some(node) => match &node.value {
                        Some(crate::NameValue::Buffer(b)) => crate::Value::Buffer(b.clone()),
                        _ => continue,
                    },
                    None => continue,
                }
            }
        };

        let buf = match wdg_value {
            crate::Value::Buffer(b) => b,
            _ => continue,
        };

        let descs = match decode_wdg(&buf) {
            Ok(d) => d,
            Err(_) => continue,
        };

        for desc in descs {
            all.push(WmiGuid {
                guid: desc.guid,
                device_path: dev.path.clone(),
                object_id: desc.object_id,
                instance_count: desc.instance_count,
                flags: desc.flags,
            });
        }
    }

    let mut g = WMI_GUIDS.lock();
    g.clear();
    g.extend(all.iter().cloned());
    all
}

/// Return a snapshot of all currently-registered WMI GUIDs. Callers
/// that ran `enumerate_guids()` at boot can call this lock-free
/// (single reader at a time is fine given boot-sequential model).
pub fn list_guids() -> Vec<WmiGuid> {
    WMI_GUIDS.lock().clone()
}

/// Invoke the AML method for a WMI GUID (the `WMxx` method on the
/// PNP0C14 device).
///
/// `method_id` is passed as Arg0; `args` are additional arguments.
/// The method name is `device_path + ".WM" + object_id`.
///
/// Reference: Linux `wmi.c::wmi_method_call` — evaluates the WMxx
/// AML method with instance + method_id as integer arguments,
/// returns the buffer result.
pub fn invoke_method(
    guid: &WmiGuid,
    method_id: u32,
    args: &[crate::Value],
) -> Result<crate::Value, WmiError> {
    let path = guid.method_path().ok_or(WmiError::MethodNotFound)?;
    let mut full_args = Vec::with_capacity(2 + args.len());
    // Linux passes instance (0) as Arg0, method_id as Arg1.
    full_args.push(crate::Value::Integer(0));
    full_args.push(crate::Value::Integer(method_id as u64));
    full_args.extend_from_slice(args);
    Ok(crate::eval::evaluate_method(&path, &full_args)?)
}

/// Register a Rust handler to fire whenever WMI signals an event
/// for `guid`. Multiple handlers for the same GUID are all called.
pub fn subscribe_event(guid: &WmiGuid, handler: WmiEventHandler) {
    WMI_HANDLERS.lock().push(WmiRegistration {
        guid: guid.guid,
        handler,
    });
}

/// Register a raw GUID handler (for callers that have a `[u8;16]`
/// rather than a `WmiGuid`).
pub fn register_wmi_event_handler(guid: [u8; 16], handler: fn(notify_value: u64)) {
    // Adapt the old signature into the new one.
    WMI_HANDLERS.lock().push(WmiRegistration {
        guid,
        handler: {
            // We need a fn pointer that can accept &WmiEvent. But the
            // old-style handlers take u64. Bridge via a static trampoline
            // stored in the slot. Since we can't do closure captures with
            // fn pointers, we store the old-style handler wrapped in the
            // new signature using a local wrapper approach.
            //
            // Limitation: we can only bridge handlers whose raw u64 value
            // is what they need. This is the legacy API path.
            let _ = handler; // unused in the WmiEventHandler path
                             // Store as a no-op in the new system and add directly below.
            |_: &WmiEvent| {}
        },
    });
    // Remove the no-op we just added and add the real one via a
    // separate legacy registry. This keeps the two registration paths
    // cleanly separated.
    WMI_HANDLERS.lock().pop();

    LEGACY_HANDLERS
        .lock()
        .push(LegacyRegistration { guid, handler });
}

/// Look up + invoke every handler registered for `guid`. Called by
/// the AML notify dispatcher after `_WED` resolves a notification
/// value into a GUID. Returns the number of handlers invoked.
///
/// Evaluates `_WED(notify_value)` on the owning device to get
/// event data before dispatching.
///
/// Reference: Linux `wmi.c::acpi_wmi_notify_handler`.
pub fn dispatch_wmi_event(guid: &[u8; 16], notify_value: u64) -> usize {
    // Find the device path for this GUID so we can evaluate _WED.
    let device_path: Option<String> = {
        let g = WMI_GUIDS.lock();
        g.iter()
            .find(|wg| &wg.guid == guid)
            .map(|wg| wg.device_path.clone())
    };

    // Evaluate _WED(notify_value) to get the event payload.
    let event_data = device_path.as_deref().and_then(|dp| {
        let wed_path = alloc::format!("{}._WED", dp);
        let args = [crate::Value::Integer(notify_value)];
        crate::eval::evaluate_method(&wed_path, &args).ok()
    });

    let event = WmiEvent {
        notify_value,
        guid: Some(*guid),
        data: event_data,
    };

    // Collect under the lock, dispatch outside so handlers can
    // re-enter the WMI surface (e.g. read state via WMxx) without
    // deadlocking.
    let new_handlers: Vec<WmiEventHandler> = {
        let g = WMI_HANDLERS.lock();
        g.iter()
            .filter(|r| r.guid == *guid)
            .map(|r| r.handler)
            .collect()
    };
    let legacy_handlers: Vec<fn(u64)> = {
        let g = LEGACY_HANDLERS.lock();
        g.iter()
            .filter(|r| r.guid == *guid)
            .map(|r| r.handler)
            .collect()
    };

    let n = new_handlers.len() + legacy_handlers.len();
    for h in new_handlers {
        h(&event);
    }
    for h in legacy_handlers {
        h(notify_value);
    }
    n
}

/// Read a data block from a WMI GUID using the `WQxx` method.
///
/// Reference: Linux `wmi.c::wmi_query_block` — calls `WQxx` with
/// `instance` as Arg0 and returns the Buffer result.
pub fn query_block(guid: &WmiGuid, instance: u8) -> Result<Vec<u8>, WmiError> {
    if instance >= guid.instance_count {
        return Err(WmiError::BadInstance);
    }
    let path = guid.query_path().ok_or(WmiError::MethodNotFound)?;
    let args = [crate::Value::Integer(instance as u64)];
    let val = crate::eval::evaluate_method(&path, &args)?;
    match val {
        crate::Value::Buffer(b) => Ok(b),
        _ => Err(WmiError::NotABuffer),
    }
}

/// Write a data block to a WMI GUID using the `WSxx` method.
///
/// Reference: Linux `wmi.c::wmi_set_block` — calls `WSxx` with
/// `instance` as Arg0 and a Buffer constructed from `data` as Arg1.
pub fn set_block(guid: &WmiGuid, instance: u8, data: &[u8]) -> Result<(), WmiError> {
    if instance >= guid.instance_count {
        return Err(WmiError::BadInstance);
    }
    let path = guid.set_path().ok_or(WmiError::MethodNotFound)?;
    let buf_arg = crate::Value::Buffer(data.to_vec());
    let args = [crate::Value::Integer(instance as u64), buf_arg];
    crate::eval::evaluate_method(&path, &args)?;
    Ok(())
}

// ── Legacy raw-notify handler registry (backward compat) ──────────

struct LegacyRegistration {
    guid: [u8; 16],
    handler: fn(u64),
}

static LEGACY_HANDLERS: IrqSafeSpinLock<Vec<LegacyRegistration>> = IrqSafeSpinLock::new(Vec::new());

// ── Test helpers ───────────────────────────────────────────────────

#[doc(hidden)]
pub fn __reset_for_test() {
    WMI_HANDLERS.lock().clear();
    LEGACY_HANDLERS.lock().clear();
    WMI_GUIDS.lock().clear();
}
