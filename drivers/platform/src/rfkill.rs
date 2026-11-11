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

    /// `enum rfkill_type` as `/dev/rfkill` events carry it.
    pub fn uapi(&self) -> u8 {
        match self {
            RadioType::Wlan => 1,
            RadioType::Bluetooth => 2,
            RadioType::Wwan => 5,
            RadioType::Gps => 6,
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

/// A radio switch that needs to know which radio it drives (one callback
/// for several radios, e.g. every wiphy): called with the radio's index.
pub type SetIndexedBlockFn = fn(idx: usize, blocked: bool) -> bool;

#[derive(Clone, Copy, Debug)]
enum Switch {
    Plain(SetBlockFn),
    Indexed(SetIndexedBlockFn),
}
impl Switch {
    fn set(self, idx: usize, blocked: bool) -> bool {
        match self {
            Switch::Plain(f) => f(blocked),
            Switch::Indexed(f) => f(idx, blocked),
        }
    }
}

#[derive(Debug)]
struct Radio {
    name: String,
    rtype: RadioType,
    state: RadioState,
    set_block: Option<Switch>,
    published: bool,
    /// Unregistered (`rfkill_unregister`): its index is never reused, as
    /// Linux never reuses an rfkill idx.
    removed: bool,
}

impl Radio {
    fn event(&self, idx: usize, op: u8) -> [u8; crate::rfkill_dev::EVENT_SIZE] {
        crate::rfkill_dev::encode(
            idx as u32,
            self.rtype.uapi(),
            op,
            self.state.soft_blocked,
            self.state.hard_blocked,
        )
    }
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
    register(name, rtype, set_block.map(Switch::Plain))
}

/// [`register_radio`] with a switch that is told the radio's index.
pub fn register_radio_indexed(name: &str, rtype: RadioType, set_block: SetIndexedBlockFn) -> usize {
    register(name, rtype, Some(Switch::Indexed(set_block)))
}

fn register(name: &str, rtype: RadioType, set_block: Option<Switch>) -> usize {
    let idx = {
        let mut radios = RADIOS.lock();
        if let Some(i) = radios.iter().position(|r| r.name == name && !r.removed) {
            i
        } else {
            radios.push(Radio {
                name: String::from(name),
                rtype,
                state: RadioState::default(),
                set_block,
                published: false,
                removed: false,
            });
            let idx = radios.len() - 1;
            crate::rfkill_dev::broadcast(radios[idx].event(idx, crate::rfkill_dev::OP_ADD));
            idx
        }
    };
    if SYSFS_PUBLISHED.load(Ordering::Acquire) {
        publish_one(idx);
    }
    idx
}

/// `rfkill_unregister`: the radio is gone (its device was removed). Every
/// `/dev/rfkill` reader gets `RFKILL_OP_DEL`; the index is not reused.
pub fn unregister_radio(idx: usize) {
    let mut radios = RADIOS.lock();
    if let Some(radio) = radios.get_mut(idx).filter(|r| !r.removed) {
        radio.removed = true;
        radio.set_block = None;
        crate::rfkill_dev::broadcast(radio.event(idx, crate::rfkill_dev::OP_DEL));
    }
}

/// Number of radio indices ever assigned (removed ones included).
pub fn radio_count() -> usize {
    RADIOS.lock().len()
}

/// Current cached state of radio `idx`; `None` once it is unregistered.
pub fn radio_state(idx: usize) -> Option<RadioState> {
    RADIOS
        .lock()
        .get(idx)
        .filter(|r| !r.removed)
        .map(|r| r.state)
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
    if let Some(r) = radios.get_mut(idx).filter(|r| !r.removed) {
        if r.state != state {
            r.state = state;
            crate::rfkill_dev::broadcast(r.event(idx, crate::rfkill_dev::OP_CHANGE));
        }
    }
}

/// Report (or clear) a hard block on radio `idx`: the kill switch, BIOS or
/// firmware state (`rfkill_set_hw_state`). Userspace cannot clear it.
pub fn set_hard_block(idx: usize, blocked: bool) {
    let state = {
        let radios = RADIOS.lock();
        match radios.get(idx) {
            Some(r) => r.state,
            None => return,
        }
    };
    update_state(
        idx,
        RadioState {
            hard_blocked: blocked,
            ..state
        },
    );
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
            Some(r) if !r.removed => r.set_block,
            _ => return false,
        }
    };
    if let Some(f) = set_block {
        if !f.set(idx, blocked) {
            return false;
        }
    }
    let mut radios = RADIOS.lock();
    if let Some(r) = radios.get_mut(idx).filter(|r| !r.removed) {
        if r.state.soft_blocked != blocked {
            r.state.soft_blocked = blocked;
            crate::rfkill_dev::broadcast(r.event(idx, crate::rfkill_dev::OP_CHANGE));
        }
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
        radios.iter().any(|r| !r.removed && r.state.unblocked())
    };
    set_all_soft_blocked(any_unblocked);
}

// ── /dev/rfkill ───────────────────────────────────────────────────────

/// A new `/dev/rfkill` reader, its queue holding one `ADD` per live radio
/// (`rfkill_fop_open`), subscribed under the registry lock.
pub(crate) fn open_reader() -> alloc::sync::Arc<crate::rfkill_dev::RfkillFile> {
    let radios = RADIOS.lock();
    let initial = radios
        .iter()
        .enumerate()
        .filter(|(_, r)| !r.removed)
        .map(|(idx, r)| r.event(idx, crate::rfkill_dev::OP_ADD))
        .collect();
    crate::rfkill_dev::RfkillFile::open_with(initial)
}

/// A `/dev/rfkill` write (`rfkill_fop_write`): soft-block radio `idx`, or
/// with `all` every radio, whose type is `rtype` or any for
/// `RFKILL_TYPE_ALL`.
pub(crate) fn apply_user_change(idx: u32, rtype: u8, all: bool, soft: bool) {
    let targets: Vec<usize> = {
        let radios = RADIOS.lock();
        radios
            .iter()
            .enumerate()
            .filter(|(i, r)| {
                !r.removed
                    && (all || *i as u32 == idx)
                    && (rtype == crate::rfkill_dev::TYPE_ALL || r.rtype.uapi() == rtype)
            })
            .map(|(i, _)| i)
            .collect()
    };
    for i in targets {
        let _ = set_soft_block(i, soft);
    }
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
    crate::rfkill_dev::register();
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
