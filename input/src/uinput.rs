//! Userspace synthetic input device — NARF analogue of Linux `uinput`.
//!
//! `UserDevice::create(caps)` registers a virtual input device in the
//! global `ROUTER`.  Writes to the handle inject events into the routing
//! layer, making them visible to any `Reader` attached to the device.
//!
//! Dropping the `UserDevice` removes the device from the router and
//! synthesises `EV_SYN/SYN_DROPPED` so readers can detect the
//! end-of-stream cleanly.
//!
//! Linux ref: `drivers/input/misc/uinput.c::uinput_create_device` (line 309)
//! and `uinput_setup` (line 462).

use alloc::sync::Arc;

use crate::evdev::{DeviceCaps, DeviceId, DeviceNode, EvdevEvent, ROUTER};

/// Handle to a userspace-created synthetic input device.
///
/// The device is alive for the lifetime of this struct.
/// On drop it calls `ROUTER.unregister_device`.
///
/// Analogous to `struct uinput_device` in Linux `uinput.c`.
pub struct UserDevice {
    id: DeviceId,
    node: Arc<DeviceNode>,
}

impl core::fmt::Debug for UserDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserDevice")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl UserDevice {
    /// Register a new synthetic device with the given capability set.
    ///
    /// Ref: `uinput_create_device` (`uinput.c:309`).
    pub fn create(caps: DeviceCaps) -> Self {
        let (id, node) = ROUTER.register_device(caps);
        Self { id, node }
    }

    /// `DeviceId` assigned to this device.
    pub fn id(&self) -> DeviceId {
        self.id
    }

    /// Inject one raw `EvdevEvent` into the routing layer.
    ///
    /// Callers typically:
    /// 1. Inject one or more `EV_KEY` / `EV_REL` / `EV_ABS` events.
    /// 2. Follow with an `EV_SYN SYN_REPORT` end-of-frame marker.
    ///
    /// Returns `false` if the device has already been removed (which
    /// should not happen while `self` is still alive).
    pub fn inject(&self, ev: EvdevEvent) -> bool {
        self.node.dispatch(ev)
    }

    /// Convenience: inject a key press (`value = 1`) or release (`value = 0`)
    /// followed by `EV_SYN SYN_REPORT`.
    pub fn inject_key(&self, code: u16, pressed: bool) {
        let now = narf_time::now_cycles();
        use crate::evdev::EventType;
        let ev = EvdevEvent {
            time: now,
            type_: EventType::Key,
            code,
            value: if pressed { 1 } else { 0 },
        };
        let syn = EvdevEvent::syn_report(now);
        self.node.dispatch(ev);
        self.node.dispatch(syn);
    }

    /// Convenience: inject a relative motion event on two axes followed by
    /// `EV_SYN SYN_REPORT`.  Axes that are zero are skipped (no point
    /// generating noise in the stream).
    pub fn inject_rel(&self, rel_x: i32, rel_y: i32) {
        use crate::evdev::{rel, EventType};
        let now = narf_time::now_cycles();
        if rel_x != 0 {
            self.node.dispatch(EvdevEvent {
                time: now,
                type_: EventType::Rel,
                code: rel::REL_X,
                value: rel_x,
            });
        }
        if rel_y != 0 {
            self.node.dispatch(EvdevEvent {
                time: now,
                type_: EventType::Rel,
                code: rel::REL_Y,
                value: rel_y,
            });
        }
        self.node.dispatch(EvdevEvent::syn_report(now));
    }
}

impl Drop for UserDevice {
    fn drop(&mut self) {
        ROUTER.unregister_device(self.id);
    }
}
