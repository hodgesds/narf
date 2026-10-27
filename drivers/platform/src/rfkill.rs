// SPDX-License-Identifier: GPL-2.0-or-later
//! Generic rfkill state surface — radios as state, not keycodes.
//!
//! Before this module, the laptop drivers decoded the airplane-mode
//! key (ASUS 0x5C, IdeaPad 0x0B, EC `_Q31`) into `KeyCode::RfKill`
//! and stopped there: no radio state existed anywhere, nothing tied
//! the key to the radios, and HP's rfkill2 firmware state block was
//! decoded into a private cache no consumer could read. This module
//! is the vendor-neutral registry those paths now share.
//!
//! ## Userspace surface (Linux rfkill ABI)
//!
//! `/sys/class/rfkill/rfkill<N>/` per registered radio:
//!
//! | file   | access | semantics                                             |
//! |--------|--------|-------------------------------------------------------|
//! | `name` | ro     | driver-provided radio name                            |
//! | `type` | ro     | `wlan` / `bluetooth` / `wwan` / `gps`                 |
//! | `state`| ro     | 0 = soft-blocked, 1 = unblocked, 2 = hard-blocked     |
//! | `soft` | rw     | software block; store drives the vendor radio switch  |
//! | `hard` | ro     | hardware block (firmware / kill-switch reported)      |
//!
//! Reference: `Documentation/ABI/stable/sysfs-class-rfkill`,
//! `net/rfkill/core.c` (GPL-2.0-or-later). The `state` encoding is
//! `RFKILL_STATE_*` from `include/uapi/linux/rfkill.h`:
//! SOFT_BLOCKED = 0, UNBLOCKED = 1, HARD_BLOCKED = 2.
//!
//! ## Airplane-mode key
//!
//! [`toggle_all`] implements the rfkill-input behaviour for
//! `KEY_RFKILL`: if any radio is unblocked, block all; otherwise
//! unblock all. Vendor event handlers that decode the airplane key
//! call it in addition to pushing the keycode, so the key now has
//! an observable effect on radio state.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

// ── Radio identity ────────────────────────────────────────────────────

/// Radio class, mirroring `enum rfkill_type` names on the sysfs
/// `type` attribute.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RadioType {
    Wlan,
    Bluetooth,
    Wwan,
    Gps,
}

impl RadioType {
    /// The string Linux reports on `/sys/class/rfkill/*/type`.
    pub fn as_str(&self) -> &'static str {
        match self {
            RadioType::Wlan => "wlan",
            RadioType::Bluetooth => "bluetooth",
            RadioType::Wwan => "wwan",
            RadioType::Gps => "gps",
        }
    }
}

/// Block state of one radio. `hard_blocked` is firmware-reported
/// (kill switch / BIOS state) and cannot be cleared from software;
/// `soft_blocked` is the software block this subsystem owns.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RadioState {
    pub soft_blocked: bool,
    pub hard_blocked: bool,
}

impl RadioState {
    /// Linux `state` attribute encoding: hard block dominates.
    pub fn state_value(&self) -> u32 {
        if self.hard_blocked {
            2
        } else if self.soft_blocked {
            0
        } else {
            1
        }
    }

    /// True when the radio can transmit (neither block set).
    pub fn unblocked(&self) -> bool {
        !self.soft_blocked && !self.hard_blocked
    }
}

/// Vendor radio-switch callback: drives the firmware radio off
/// (`blocked = true`) or on. Returns true when the firmware call
/// was issued without error.
pub type SetBlockFn = fn(blocked: bool) -> bool;

#[derive(Debug)]
struct Radio {
    name: String,
    rtype: RadioType,
    state: RadioState,
    set_block: Option<SetBlockFn>,
    published: bool,
}

static RADIOS: IrqSafeSpinLock<Vec<Radio>> = IrqSafeSpinLock::new(Vec::new());
static SYSFS_PUBLISHED: AtomicBool = AtomicBool::new(false);

// ── Registry API ──────────────────────────────────────────────────────

/// Register a radio with the rfkill core. Idempotent by name: a
/// second registration under the same name returns the existing
/// index (vendor drivers can be initialised by both the WMI
/// dispatch layer and the registry probe without duplicating
/// sysfs entries). Returns the radio's index, which is also its
/// `rfkill<N>` number.
pub fn register_radio(name: &str, rtype: RadioType, set_block: Option<SetBlockFn>) -> usize {
    let idx = {
        let mut radios = RADIOS.lock();
        if let Some(i) = radios.iter().position(|r| r.name == name) {
            i
        } else {
            radios.push(Radio {
                name: String::from(name),
                rtype,
                state: RadioState::default(),
                set_block,
                published: false,
            });
            radios.len() - 1
        }
    };
    if SYSFS_PUBLISHED.load(Ordering::Acquire) {
        publish_one(idx);
    }
    idx
}

/// Number of registered radios.
pub fn radio_count() -> usize {
    RADIOS.lock().len()
}

/// Current cached state of radio `idx`.
pub fn radio_state(idx: usize) -> Option<RadioState> {
    RADIOS.lock().get(idx).map(|r| r.state)
}

/// Radio name of `idx`.
pub fn radio_name(idx: usize) -> Option<String> {
    RADIOS.lock().get(idx).map(|r| r.name.clone())
}

/// Update the cached state of a radio from a firmware refresh
/// (e.g. HP rfkill2). Does not call the vendor switch — this is
/// the firmware→core direction.
pub fn update_state(idx: usize, state: RadioState) {
    let mut radios = RADIOS.lock();
    if let Some(r) = radios.get_mut(idx) {
        r.state = state;
    }
}

/// Set (or clear) the software block on one radio: drives the
/// vendor switch first, and only caches the new state when the
/// firmware call succeeded (or no switch is registered). Returns
/// true on success. A hard-blocked radio stays blocked regardless
/// — clearing the soft block is still recorded, matching Linux,
/// where `soft` and `hard` are independent.
pub fn set_soft_block(idx: usize, blocked: bool) -> bool {
    let set_block = {
        let radios = RADIOS.lock();
        match radios.get(idx) {
            Some(r) => r.set_block,
            None => return false,
        }
    };
    if let Some(f) = set_block {
        if !f(blocked) {
            return false;
        }
    }
    let mut radios = RADIOS.lock();
    if let Some(r) = radios.get_mut(idx) {
        r.state.soft_blocked = blocked;
    }
    true
}

/// Set the software block on every registered radio. Used by the
/// airplane-mode key path and by a global `soft` store.
pub fn set_all_soft_blocked(blocked: bool) {
    for i in 0..radio_count() {
        let _ = set_soft_block(i, blocked);
    }
}

/// `KEY_RFKILL` toggle semantics (Linux `rfkill-input`): if any
/// radio is currently unblocked, soft-block all of them; if all
/// are blocked, clear the soft block on all. Hard blocks are
/// firmware-owned and untouched either way.
pub fn toggle_all() {
    let any_unblocked = {
        let radios = RADIOS.lock();
        radios.iter().any(|r| r.state.unblocked())
    };
    set_all_soft_blocked(any_unblocked);
}

// ── Sysfs publication ─────────────────────────────────────────────────

fn publish_one(idx: usize) {
    use narf_filesystem::sysfs::{
        class_device_register, class_register, kobject_add_attr, kobject_add_writable_attr,
    };
    use narf_filesystem::FsError;

    let (name, rtype) = {
        let mut radios = RADIOS.lock();
        match radios.get_mut(idx) {
            Some(r) if !r.published => {
                r.published = true;
                (r.name.clone(), r.rtype)
            }
            _ => return,
        }
    };

    let class = class_register("rfkill");
    let kobj = class_device_register(class, &alloc::format!("rfkill{}", idx));

    kobject_add_attr(&kobj, "name", move || alloc::format!("{}\n", name));
    kobject_add_attr(&kobj, "type", move || {
        alloc::format!("{}\n", rtype.as_str())
    });
    kobject_add_attr(&kobj, "state", move || {
        let v = radio_state(idx).map(|s| s.state_value()).unwrap_or(1);
        alloc::format!("{}\n", v)
    });
    kobject_add_attr(&kobj, "hard", move || {
        let v = radio_state(idx).map(|s| s.hard_blocked as u32).unwrap_or(0);
        alloc::format!("{}\n", v)
    });
    kobject_add_writable_attr(
        &kobj,
        "soft",
        move || {
            let v = radio_state(idx).map(|s| s.soft_blocked as u32).unwrap_or(0);
            alloc::format!("{}\n", v)
        },
        move |buf| {
            let s = core::str::from_utf8(buf)
                .map_err(|_| FsError::InvalidData)?
                .trim();
            let blocked = match s {
                "0" => false,
                "1" => true,
                _ => return Err(FsError::InvalidData),
            };
            if set_soft_block(idx, blocked) {
                Ok(())
            } else {
                Err(FsError::InvalidData)
            }
        },
    );
}

/// Publish `/sys/class/rfkill/rfkill<N>/` for every registered
/// radio. Called from a Stage::Late initcall, after the vendor
/// drivers (Stage::Subsys) have registered their radios. Radios
/// registered after publication are published on registration.
pub fn publish_sysfs() {
    SYSFS_PUBLISHED.store(true, Ordering::Release);
    for i in 0..radio_count() {
        publish_one(i);
    }
}

// ── Test helpers ────────────────────────────────────────────────────────

/// Reset the rfkill registry for tests.
#[doc(hidden)]
pub fn __test_reset() {
    RADIOS.lock().clear();
    SYSFS_PUBLISHED.store(false, Ordering::Relaxed);
}
