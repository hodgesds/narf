//! Linux Bluetooth Management (mgmt) API — the `HCI_CHANNEL_CONTROL` protocol
//! that `bluetoothd` / `btmgmt` drive adapters through.
//!
//! Settings are no longer fiction (issue #815): every set-mode op
//! issues its HCI command through the controller's transport and
//! only records the setting once the controller accepts it. When
//! the controller is powered off, a setting is recorded and applied
//! on the next power-on (the Linux model, mgmt(7)); power-on runs
//! HCI_Reset + the event mask + a re-apply of every recorded
//! HCI-backed setting, so the bitmap and the controller agree.
//! READ_INFO reports the dev_class / name / short_name the
//! controller (or userspace, via SET_DEV_CLASS / SET_LOCAL_NAME)
//! actually holds. Discovery is the landed GAP central initiator
//! (#1312); pairing is the landed SMP initiator (#888) with the
//! MITM methods of #818: the IO capability is settable
//! (SET_IO_CAPABILITY, or per-pairing via PAIR_DEVICE) and the
//! user-confirm / passkey flows run through the mgmt
//! USER_CONFIRM / USER_PASSKEY request events and reply commands,
//! with the async Linux completion model (Command Status now,
//! Command Complete when the pairing finishes).
//! CANCEL_PAIR_DEVICE (0x001a, #1528) aborts an in-flight
//! mgmt-started pairing: the pump sends Pairing Failed and the
//! pending PAIR_DEVICE completes with CANCELLED (0x10); a
//! cancel with no pending pairing for that peer is
//! INVALID_PARAMS, as in the kernel.
//!
//! Wire format and status codes follow `/usr/src/linux`
//! `net/bluetooth/mgmt.c` + `include/net/bluetooth/mgmt.h`.
//! Behavioural notes cite `mgmt(7)` (BlueZ) where the reply or
//! error shape is not obvious from the header alone.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::controller::{self, BringupError};
use crate::opcode as op;

/// `struct mgmt_hdr` size: opcode(le16) + index(le16) + len(le16).
pub const MGMT_HDR_SIZE: usize = 6;
/// Adapter-independent command index (`MGMT_INDEX_NONE`).
pub const MGMT_INDEX_NONE: u16 = 0xffff;

// Commands we implement (mgmt.h MGMT_OP_*).
const OP_READ_VERSION: u16 = 0x0001;
const OP_READ_COMMANDS: u16 = 0x0002;
const OP_READ_INDEX_LIST: u16 = 0x0003;
const OP_READ_INFO: u16 = 0x0004;
const OP_SET_POWERED: u16 = 0x0005;
const OP_SET_DISCOVERABLE: u16 = 0x0006;
const OP_SET_CONNECTABLE: u16 = 0x0007;
const OP_SET_FAST_CONNECTABLE: u16 = 0x0008;
const OP_SET_BONDABLE: u16 = 0x0009;
const OP_SET_LINK_SECURITY: u16 = 0x000a;
const OP_SET_SSP: u16 = 0x000b;
const OP_SET_LE: u16 = 0x000d;
const OP_SET_DEV_CLASS: u16 = 0x000e;
const OP_SET_LOCAL_NAME: u16 = 0x000f;
const OP_LOAD_LONG_TERM_KEYS: u16 = 0x0013;
const OP_DISCONNECT: u16 = 0x0014;
const OP_GET_CONNECTIONS: u16 = 0x0015;
const OP_PIN_CODE_REPLY: u16 = 0x0016;
const OP_PIN_CODE_NEG_REPLY: u16 = 0x0017;
const OP_SET_IO_CAPABILITY: u16 = 0x0018;
const OP_PAIR_DEVICE: u16 = 0x0019;
const OP_CANCEL_PAIR_DEVICE: u16 = 0x001a;
const OP_UNPAIR_DEVICE: u16 = 0x001b;
const OP_USER_CONFIRM_REPLY: u16 = 0x001c;
const OP_USER_CONFIRM_NEG_REPLY: u16 = 0x001d;
const OP_USER_PASSKEY_REPLY: u16 = 0x001e;
const OP_USER_PASSKEY_NEG_REPLY: u16 = 0x001f;
const OP_READ_LOCAL_OOB_DATA: u16 = 0x0020;
const OP_ADD_REMOTE_OOB_DATA: u16 = 0x0021;
const OP_REMOVE_REMOTE_OOB_DATA: u16 = 0x0022;
const OP_START_DISCOVERY: u16 = 0x0023;
const OP_STOP_DISCOVERY: u16 = 0x0024;
const OP_SET_ADVERTISING: u16 = 0x0029;
const OP_SET_BREDR: u16 = 0x002a;
const OP_SET_STATIC_ADDRESS: u16 = 0x002b;
const OP_SET_SCAN_PARAMS: u16 = 0x002c;
const OP_SET_SECURE_CONN: u16 = 0x002d;
const OP_SET_PRIVACY: u16 = 0x002f;
const OP_LOAD_IRKS: u16 = 0x0030;

// Events (mgmt.h MGMT_EV_*).
const EV_CMD_COMPLETE: u16 = 0x0001;
const EV_CMD_STATUS: u16 = 0x0002;
const EV_INDEX_ADDED: u16 = 0x0004;
const EV_INDEX_REMOVED: u16 = 0x0005;
const EV_NEW_SETTINGS: u16 = 0x0006;
const EV_CLASS_OF_DEV_CHANGED: u16 = 0x0007;
const EV_LOCAL_NAME_CHANGED: u16 = 0x0008;
const EV_PIN_CODE_REQUEST: u16 = 0x000e;
const EV_USER_CONFIRM_REQUEST: u16 = 0x000f;
const EV_USER_PASSKEY_REQUEST: u16 = 0x0010;
const EV_AUTH_FAILED: u16 = 0x0011;
const EV_DEVICE_FOUND: u16 = 0x0012;
const EV_DISCOVERING: u16 = 0x0013;
const EV_DEVICE_UNPAIRED: u16 = 0x0016;
const EV_PASSKEY_NOTIFY: u16 = 0x0017;

// Status codes (mgmt.h MGMT_STATUS_*). The three the pump's
// pairing-completion hooks report are `pub(crate)`.
pub(crate) const STATUS_SUCCESS: u8 = 0x00;
const STATUS_UNKNOWN_COMMAND: u8 = 0x01;
const STATUS_NOT_CONNECTED: u8 = 0x02;
pub(crate) const STATUS_FAILED: u8 = 0x03;
pub(crate) const STATUS_AUTH_FAILED: u8 = 0x05;
const STATUS_TIMEOUT: u8 = 0x08;
const STATUS_BUSY: u8 = 0x0a;
const STATUS_REJECTED: u8 = 0x0b;
const STATUS_NOT_SUPPORTED: u8 = 0x0c;
const STATUS_INVALID_PARAMS: u8 = 0x0d;
pub(crate) const STATUS_DISCONNECTED: u8 = 0x0e;
const STATUS_NOT_POWERED: u8 = 0x0f;
/// `MGMT_STATUS_CANCELLED` (mgmt.h): the status a pending
/// PAIR_DEVICE completes with when userspace cancels it via
/// CANCEL_PAIR_DEVICE (issue #1528).
pub(crate) const STATUS_CANCELLED: u8 = 0x10;
const STATUS_INVALID_INDEX: u8 = 0x11;
const STATUS_ALREADY_PAIRED: u8 = 0x13;

// Address types (mgmt.h `struct mgmt_addr_info`, mgmt(7)).
const ADDR_BREDR: u8 = 0x00;
const ADDR_LE_PUBLIC: u8 = 0x01;
const ADDR_LE_RANDOM: u8 = 0x02;

// Discovery types (mgmt(7) Start Discovery): a bitmask, not an
// enum — bit 0 BR/EDR, bit 1 LE public, bit 2 LE random.
const DISC_BREDR: u8 = 0x01;
const DISC_LE_RANDOM: u8 = 0x04;

// Device Found flags (mgmt.h MGMT_DEV_FOUND_*).
const DEV_FOUND_NOT_CONNECTABLE: u32 = 0x04;

// Controller settings bitmap (mgmt.h MGMT_SETTING_*).
const SETTING_POWERED: u32 = 1 << 0;
const SETTING_CONNECTABLE: u32 = 1 << 1;
const SETTING_FAST_CONNECTABLE: u32 = 1 << 2;
const SETTING_DISCOVERABLE: u32 = 1 << 3;
const SETTING_BONDABLE: u32 = 1 << 4;
const SETTING_LINK_SECURITY: u32 = 1 << 5;
const SETTING_SSP: u32 = 1 << 6;
const SETTING_BREDR: u32 = 1 << 7;
const SETTING_LE: u32 = 1 << 9;
const SETTING_ADVERTISING: u32 = 1 << 10;
const SETTING_SECURE_CONN: u32 = 1 << 11;
const SETTING_PRIVACY: u32 = 1 << 13;
const SETTING_STATIC_ADDRESS: u32 = 1 << 15;

/// Per-controller current settings bitmap, keyed by HCI index. A controller
/// comes up configured (BR/EDR + LE capable) but not powered, matching how
/// mgmt reports an adapter before SET_POWERED.
static SETTINGS: IrqSafeSpinLock<BTreeMap<u16, u32>> = IrqSafeSpinLock::new(BTreeMap::new());
const DEFAULT_SETTINGS: u32 = SETTING_BREDR | SETTING_LE;

/// Active mgmt discovery, keyed by HCI index: the discovery type
/// byte passed to START_DISCOVERY. The pump's central scan is the
/// mechanism; this map is the mgmt-level record (it gates
/// DEVICE_FOUND publication and validates STOP_DISCOVERY).
static DISCOVERING: IrqSafeSpinLock<BTreeMap<u16, u8>> = IrqSafeSpinLock::new(BTreeMap::new());

/// LE scan parameters recorded by SET_SCAN_PARAMS, keyed by HCI
/// index: (interval, window) in 0.625 ms units. Used by the next
/// START_DISCOVERY; unset means the GAP default (30 ms / 30 ms).
static SCAN_PARAMS: IrqSafeSpinLock<BTreeMap<u16, (u16, u16)>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Pairings started by mgmt PAIR_DEVICE and still awaiting their
/// async completion: (index, peer `[address_type, bd_addr]`). The
/// pump clears an entry (and publishes the Command Complete) when
/// the initiator session ends; responder pairings and direct
/// `pump::smp_initiate_pairing` calls never create one.
static PENDING_PAIR: IrqSafeSpinLock<BTreeSet<(u16, [u8; 7])>> =
    IrqSafeSpinLock::new(BTreeSet::new());

/// IO capability per controller, set by SET_IO_CAPABILITY
/// (mgmt-api 0x0018) and used for responder pairings and
/// Security-Request-triggered initiations; PAIR_DEVICE carries
/// its own io_cap, which temporarily overrides this for that one
/// pairing. Defaults to NoInputNoOutput (0x03) — the Just Works
/// behaviour all earlier pairings had.
static IO_CAPABILITY: IrqSafeSpinLock<BTreeMap<u16, u8>> = IrqSafeSpinLock::new(BTreeMap::new());

/// Remote OOB data per controller, set by ADD_REMOTE_OOB_DATA
/// (mgmt-api 0x0021): peer address → the peer's P-256 OOB
/// hash + randomizer. The pump reads it when a session for that
/// peer starts; REMOVE_REMOTE_OOB_DATA clears it.
static REMOTE_OOB: IrqSafeSpinLock<BTreeMap<u16, BTreeMap<[u8; 7], crate::smp::OobData>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// IO capability the pump advertises for controller `index`:
/// the SET_IO_CAPABILITY value, or NoInputNoOutput when unset.
pub(crate) fn io_capability(index: u16) -> u8 {
    *IO_CAPABILITY
        .lock()
        .get(&index)
        .unwrap_or(&(crate::smp::IoCapability::NoInputNoOutput as u8))
}

/// Remote OOB data held for `peer` on controller `index`, if any.
pub(crate) fn remote_oob(index: u16, peer: &[u8; 7]) -> Option<crate::smp::OobData> {
    REMOTE_OOB
        .lock()
        .get(&index)
        .and_then(|m| m.get(peer).copied())
}

/// Disconnects started by mgmt DISCONNECT and still awaiting
/// their async completion: (index, handle) → the mgmt addr_info
/// (`bd_addr` + type) to echo in the Command Complete (issue
/// #1527). The pump clears an entry (and publishes the Command
/// Complete) when the Disconnection Complete lands, or when the
/// HCI Disconnect is refused by Command Status; direct
/// `pump::disconnect` calls (e.g. UNPAIR_DEVICE disconnect=1)
/// never create one. At most one disconnect is pending per
/// controller — a second DISCONNECT while one is pending is BUSY
/// (Linux `pending_find(MGMT_OP_DISCONNECT, hdev)`).
static PENDING_DISCONNECT: IrqSafeSpinLock<BTreeMap<(u16, u16), [u8; 7]>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Controllers whose local name / Class of Device userspace set via
/// mgmt (SET_LOCAL_NAME / SET_DEV_CLASS). Power-on re-writes those
/// stored values after HCI_Reset instead of re-reading the
/// controller's defaults (mgmt(7): the values "will be remembered
/// when switching the controller off and back on again").
static NAME_SET: IrqSafeSpinLock<BTreeSet<u16>> = IrqSafeSpinLock::new(BTreeSet::new());
static CLASS_SET: IrqSafeSpinLock<BTreeSet<u16>> = IrqSafeSpinLock::new(BTreeSet::new());

/// Controllers whose discoverable was enabled with a timeout
/// (mgmt(7): a timeout-based discoverable expires when the
/// controller is powered off). The timeout itself is accepted but
/// never enforced — there is no mgmt timer yet; see the remainder
/// note on the issue.
static DISCOV_TIMEOUT: IrqSafeSpinLock<BTreeSet<u16>> = IrqSafeSpinLock::new(BTreeSet::new());

/// Advertising mode recorded by SET_ADVERTISING (0x0029), keyed by
/// HCI index: 0 = off, 1 = on respecting the connectable setting,
/// 2 = connectable. The settings bitmap carries only the on/off
/// bit (SETTING_ADVERTISING); the mode lives here because the
/// bitmap cannot distinguish 0x01 from 0x02.
static ADVERTISING: IrqSafeSpinLock<BTreeMap<u16, u8>> = IrqSafeSpinLock::new(BTreeMap::new());

/// Static random address recorded by SET_STATIC_ADDRESS (0x002b),
/// keyed by HCI index. Present only while a non-ANY address is
/// configured; removing the entry disables it. The address is
/// programmed into the controller at power-on (LE Set Random
/// Address), never at set time — the kernel programs it during
/// setup, and setting it is limited to the powered-off state.
static STATIC_ADDR: IrqSafeSpinLock<BTreeMap<u16, [u8; 6]>> = IrqSafeSpinLock::new(BTreeMap::new());

/// Privacy mode + local IRK recorded by SET_PRIVACY (0x002f),
/// keyed by HCI index: (mode, local IRK). Present only while
/// privacy is on (mode 0x01 or 0x02); mode 0x00 removes the entry
/// and zeroes the IRK, as the kernel does. The IRK is the local
/// key for the resolvable private address — never a peer's key.
static PRIVACY: IrqSafeSpinLock<BTreeMap<u16, (u8, [u8; 16])>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Peer identity resolving keys loaded by LOAD_IRKS (0x0030),
/// keyed by HCI index. A load replaces the whole list (the
/// kernel clears its IRK list first); entries are also mirrored
/// into existing bonds' `peer_irk` where one exists, but an IRK
/// for a peer with no bond yet lives only here — it is never
/// fabricated into a bond.
static IRKS: IrqSafeSpinLock<BTreeMap<u16, Vec<IrkEntry>>> = IrqSafeSpinLock::new(BTreeMap::new());

/// One loaded IRK: the peer's identity address (`[address-type,
/// bd_addr]`, the same 7-byte shape the pump tracks) and the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IrkEntry {
    peer: [u8; 7],
    irk: [u8; 16],
}

/// Resolvable private address currently in use on a controller,
/// keyed by HCI index, as generated by [`generate_rpa`] from the
/// stored local IRK. Cached across advertising (re-)applies so a
/// power-on does not generate two RPAs (one for the random-address
/// step, one for advertising); cleared on power-off and on any
/// SET_PRIVACY, so a new epoch always gets a fresh RPA. RPA
/// rotation on a timer (the spec's 15-minute recommendation) is
/// future work — there is no mgmt timer yet.
static CURRENT_RPA: IrqSafeSpinLock<BTreeMap<u16, [u8; 6]>> = IrqSafeSpinLock::new(BTreeMap::new());

/// Random address currently programmed into the controller, keyed
/// by HCI index. Lets [`program_random_address`] skip a redundant
/// LE Set Random Address when the desired address is already the
/// programmed one (e.g. advertising re-apply under privacy reuses
/// the cached RPA). Cleared on power-off and whenever the desired
/// address can change (SET_PRIVACY / SET_STATIC_ADDRESS).
static PROGRAMMED_RANDOM_ADDR: IrqSafeSpinLock<BTreeMap<u16, [u8; 6]>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Test-only: drain all mgmt state (settings, discovery, scan
/// parameters, pending pairings, pending disconnects,
/// userspace-set identity, IO capability, remote OOB data,
/// advertising / static-address / privacy / loaded-key state).
#[doc(hidden)]
pub fn __test_reset() {
    SETTINGS.lock().clear();
    DISCOVERING.lock().clear();
    SCAN_PARAMS.lock().clear();
    PENDING_PAIR.lock().clear();
    IO_CAPABILITY.lock().clear();
    REMOTE_OOB.lock().clear();
    PENDING_DISCONNECT.lock().clear();
    NAME_SET.lock().clear();
    CLASS_SET.lock().clear();
    DISCOV_TIMEOUT.lock().clear();
    ADVERTISING.lock().clear();
    STATIC_ADDR.lock().clear();
    PRIVACY.lock().clear();
    IRKS.lock().clear();
    CURRENT_RPA.lock().clear();
    PROGRAMMED_RANDOM_ADDR.lock().clear();
}

fn current_settings(index: u16) -> u32 {
    *SETTINGS.lock().entry(index).or_insert(DEFAULT_SETTINGS)
}

fn set_setting_bit(index: u16, bit: u32, on: bool) -> u32 {
    let mut table = SETTINGS.lock();
    let settings = table.entry(index).or_insert(DEFAULT_SETTINGS);
    if on {
        *settings |= bit;
    } else {
        *settings &= !bit;
    }
    *settings
}

/// A mode-setting command (`SET_CONNECTABLE` / `SET_SSP` / …):
/// validate the index + the mode value, then push the new state to
/// the controller and record it only once the controller accepts
/// it. `max_val` is 1 for on/off modes, 2 for limited discoverable
/// (SET_SECURE_CONN also takes 2, but 0x02 SC-Only is rejected as
/// NOT_SUPPORTED below — the SMP side cannot enforce it, #818 area).
///
/// Couplings, from mgmt(7):
/// - SET_DISCOVERABLE(on) while connectable is off → REJECTED.
/// - SET_CONNECTABLE(0) also switches discoverable off (and
///   expires a discoverable timeout); switching connectable back
///   on does not restore discoverable.
/// - When the controller is not powered, the setting is recorded
///   and applied on the next power-on (no HCI now) — except a
///   discoverable-with-timeout, which is NOT_POWERED while off.
///
/// A failed HCI write leaves the bitmap unchanged and replies
/// CMD_STATUS with the failure (FAILED, or TIMEOUT when the
/// Command Complete never arrived).
fn set_mode(index: u16, opcode: u16, params: &[u8], bit: u32, max_val: u8) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, opcode, STATUS_INVALID_INDEX);
    }
    if params.is_empty() || params[0] > max_val {
        return cmd_status(index, opcode, STATUS_INVALID_PARAMS);
    }
    let on = params[0] != 0;
    if bit == SETTING_SECURE_CONN && params[0] == 2 {
        // SC-Only mode: valid value, but the SMP side cannot enforce
        // "Secure Connections only" yet — NOT_SUPPORTED, not a lie.
        return cmd_status(index, opcode, STATUS_NOT_SUPPORTED);
    }
    if bit == SETTING_FAST_CONNECTABLE && current_settings(index) & SETTING_BREDR == 0 {
        // Fast connectable needs BR/EDR (kernel set_fast_connectable
        // returns NOT_SUPPORTED without HCI_BREDR_ENABLED).
        return cmd_status(index, opcode, STATUS_NOT_SUPPORTED);
    }
    let current = current_settings(index);
    if bit == SETTING_DISCOVERABLE && on && current & SETTING_CONNECTABLE == 0 {
        return cmd_status(index, opcode, STATUS_REJECTED);
    }
    // Prospective bitmap, couplings included.
    let mut new = current;
    if on {
        new |= bit;
    } else {
        new &= !bit;
    }
    if bit == SETTING_CONNECTABLE && !on {
        new &= !SETTING_DISCOVERABLE;
    }
    let powered = current & SETTING_POWERED != 0;
    // Turning LE off also switches advertising off: advertising
    // without LE host support is meaningless, and the recorded
    // mode is dropped with the commit below (powered: the live
    // advertisement is disabled first; unpowered: nothing is live).
    let clear_advertising = bit == SETTING_LE && !on && advertising_mode(index) != 0;
    if powered {
        // Issue the HCI first; record only on success.
        let mut result = if bit == SETTING_DISCOVERABLE || bit == SETTING_CONNECTABLE {
            apply_scan_enable(index, new)
        } else if bit == SETTING_BONDABLE {
            // Host policy only — no HCI command exists for bondable.
            Ok(())
        } else {
            apply_single_setting(index, bit, on)
        };
        if result.is_ok() && clear_advertising {
            result = issue(index, op::HCI_LE_SET_ADVERTISING_ENABLE, &[0]).map(|_| ());
        }
        // Connectable / discoverable change the advertising flags
        // (and, for mode 0x01, the advertising type): refresh the
        // live advertisement with the prospective bitmap so the air
        // matches the settings, still before the commit.
        if result.is_ok()
            && (bit == SETTING_DISCOVERABLE || bit == SETTING_CONNECTABLE)
            && advertising_mode(index) != 0
            && !DISCOVERING.lock().contains_key(&index)
        {
            result = apply_advertising_with(index, new);
        }
        if let Err(status) = result {
            return cmd_status(index, opcode, status);
        }
    } else if bit == SETTING_DISCOVERABLE && on && params.len() >= 3 {
        // Discoverable with a timeout while unpowered → NOT_POWERED
        // (mgmt(7)). A timeout-less discoverable is recorded like
        // any other setting.
        let timeout = u16::from_le_bytes([params[1], params[2]]);
        if timeout != 0 {
            return cmd_status(index, opcode, STATUS_NOT_POWERED);
        }
    }
    // Commit the prospective bitmap (the coupling may have changed
    // two bits) and tell every mgmt socket the new state.
    if clear_advertising {
        new &= !SETTING_ADVERTISING;
    }
    {
        let mut table = SETTINGS.lock();
        *table.entry(index).or_insert(DEFAULT_SETTINGS) = new;
    }
    if clear_advertising {
        ADVERTISING.lock().remove(&index);
    }
    if bit == SETTING_DISCOVERABLE {
        if on && params.len() >= 3 && u16::from_le_bytes([params[1], params[2]]) != 0 {
            DISCOV_TIMEOUT.lock().insert(index);
        } else {
            DISCOV_TIMEOUT.lock().remove(&index);
        }
    } else if bit == SETTING_CONNECTABLE && !on {
        // The coupling switched discoverable off: its timeout (if
        // any) expires with it.
        DISCOV_TIMEOUT.lock().remove(&index);
    }
    narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, new));
    cmd_complete(index, opcode, STATUS_SUCCESS, &new.to_le_bytes())
}

/// Power the controller on: HCI_Reset, the default event mask, the
/// identity (re-written when userspace set it, else re-read from
/// the controller — a reset restores the controller's defaults),
/// then every HCI-backed setting recorded in the bitmap. Any
/// failure aborts the power-on; POWERED stays off.
fn power_on_apply(index: u16) -> Result<(), u8> {
    issue(index, op::HCI_RESET, &[])?;
    issue(
        index,
        op::HCI_SET_EVENT_MASK,
        &controller::DEFAULT_EVENT_MASK,
    )?;
    let Some(ctrl) = controller(index) else {
        return Err(STATUS_INVALID_INDEX);
    };
    // Identity: re-write what userspace set (and re-announce it),
    // else re-read what the reset left and refresh the stored copy
    // (announcing only a change).
    if NAME_SET.lock().contains(&index) {
        let info = ctrl.info();
        issue(index, op::HCI_WRITE_LOCAL_NAME, &info.local_name)?;
        let mut name249 = [0u8; 249];
        name249[..248].copy_from_slice(&info.local_name);
        narf_filesystem::bluetooth::publish_mgmt_event(&local_name_changed(index, &name249));
    } else {
        let ret = issue(index, op::HCI_READ_LOCAL_NAME, &[])?;
        if ret.len() < 249 {
            return Err(STATUS_FAILED);
        }
        let mut name = [0u8; 248];
        name.copy_from_slice(&ret[1..249]);
        let old = ctrl.info();
        let short = old.short_name;
        if old.local_name != name {
            let mut name249 = [0u8; 249];
            name249[..248].copy_from_slice(&name);
            narf_filesystem::bluetooth::publish_mgmt_event(&local_name_changed(index, &name249));
        }
        ctrl.set_local_name(name, short);
    }
    if CLASS_SET.lock().contains(&index) {
        let class = ctrl.info().dev_class;
        issue(index, op::HCI_WRITE_CLASS_OF_DEVICE, &class)?;
        narf_filesystem::bluetooth::publish_mgmt_event(&class_of_dev_changed(index, class));
    } else {
        let ret = issue(index, op::HCI_READ_CLASS_OF_DEVICE, &[])?;
        if ret.len() < 4 {
            return Err(STATUS_FAILED);
        }
        let mut class = [0u8; 3];
        class.copy_from_slice(&ret[1..4]);
        if ctrl.info().dev_class != class {
            narf_filesystem::bluetooth::publish_mgmt_event(&class_of_dev_changed(index, class));
        }
        ctrl.set_dev_class(class);
    }
    // Recorded settings, in one place so power-on and set-mode
    // cannot drift apart: scan state, then the single settings.
    let settings = current_settings(index);
    apply_scan_enable(index, settings)?;
    apply_single_setting(
        index,
        SETTING_LINK_SECURITY,
        settings & SETTING_LINK_SECURITY != 0,
    )?;
    apply_single_setting(index, SETTING_SSP, settings & SETTING_SSP != 0)?;
    apply_single_setting(index, SETTING_LE, settings & SETTING_LE != 0)?;
    apply_single_setting(
        index,
        SETTING_SECURE_CONN,
        settings & SETTING_SECURE_CONN != 0,
    )?;
    apply_single_setting(
        index,
        SETTING_FAST_CONNECTABLE,
        settings & SETTING_FAST_CONNECTABLE != 0,
    )?;
    // Static address / privacy, then advertising: the random
    // address must be programmed before advertising starts (an
    // RPA when privacy is on, else the static address when one is
    // in use), the resolving list before address resolution is
    // enabled, and a recorded advertisement is re-started last.
    // Each step is a no-op (no HCI) unless its feature is on, so
    // the default power-on issues no extra commands.
    program_random_address(index, settings)?;
    apply_resolving_list(index)?;
    if settings & SETTING_ADVERTISING != 0 {
        apply_advertising_with(index, settings)?;
    }
    Ok(())
}

/// Stop an active mgmt discovery without reporting a failure:
/// the LE scan must not outlive power-off. Best-effort — the scan
/// may already be stopped (a connect is in flight, or the pump is
/// gone); the mgmt state is cleared either way.
fn stop_discovery_quiet(index: u16) {
    if let Some(disc_type) = DISCOVERING.lock().remove(&index) {
        let _ = crate::pump::central_stop_scan(index as usize);
        narf_filesystem::bluetooth::publish_mgmt_event(&discovering(index, disc_type, false));
    }
}

/// The power transition behind SET_POWERED and the HCIDEVUP/DOWN
/// ioctls. `Ok(settings)` is the post-transition bitmap;
/// `Err(status)` leaves the bitmap untouched (a failed power-on
/// keeps POWERED off; a failed power-off never happens — power-off
/// is host-side state, and its HCI is best-effort).
fn set_powered_inner(index: u16, on: bool) -> Result<u32, u8> {
    if (index as usize) >= controller::controller_count() {
        return Err(STATUS_INVALID_INDEX);
    }
    let current = current_settings(index);
    let powered = current & SETTING_POWERED != 0;
    if on == powered {
        return Ok(current);
    }
    if on {
        power_on_apply(index)?;
        let settings = set_setting_bit(index, SETTING_POWERED, true);
        // #820: power-on clears the mgmt park (power-off parks it below).
        apply_powered(index, true);
        narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, settings));
        Ok(settings)
    } else {
        stop_discovery_quiet(index);
        // Quiesce BR/EDR scans; best-effort — there is no HCI
        // power-off command in Core 5.3, and power-off must succeed
        // even against a wedged controller.
        let _ = issue(index, op::HCI_WRITE_SCAN_ENABLE, &[0]);
        let mut settings = set_setting_bit(index, SETTING_POWERED, false);
        // #820: power-off parks the controller (its pump stops
        // touching the transport).
        apply_powered(index, false);
        // A timeout-based discoverable expires on power-off (mgmt(7)).
        if DISCOV_TIMEOUT.lock().remove(&index) {
            settings = set_setting_bit(index, SETTING_DISCOVERABLE, false);
        }
        // The RPA epoch ends with the power epoch: the next
        // power-on generates a fresh RPA, and any programmed
        // random address is forgotten with the controller state.
        CURRENT_RPA.lock().remove(&index);
        PROGRAMMED_RANDOM_ADDR.lock().remove(&index);
        narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, settings));
        Ok(settings)
    }
}

/// SET_DEV_CLASS (0x000e): `major, minor` (2 bytes). The stored
/// service byte is kept — the mgmt command carries no service
/// classes. Powered: write to the controller, store, announce,
/// reply the 3-byte class. Unpowered: store only; the reply is
/// 0x000000 and the value is announced on power-on (mgmt(7)).
fn set_dev_class(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_DEV_CLASS, STATUS_INVALID_INDEX);
    }
    if params.len() < 2 {
        return cmd_status(index, OP_SET_DEV_CLASS, STATUS_INVALID_PARAMS);
    }
    let Some(ctrl) = controller(index) else {
        return cmd_status(index, OP_SET_DEV_CLASS, STATUS_INVALID_INDEX);
    };
    let mut class = ctrl.info().dev_class;
    class[1] = params[0];
    class[2] = params[1];
    if current_settings(index) & SETTING_POWERED != 0 {
        if let Err(status) = issue(index, op::HCI_WRITE_CLASS_OF_DEVICE, &class) {
            return cmd_status(index, OP_SET_DEV_CLASS, status);
        }
        ctrl.set_dev_class(class);
        CLASS_SET.lock().insert(index);
        narf_filesystem::bluetooth::publish_mgmt_event(&class_of_dev_changed(index, class));
    } else {
        ctrl.set_dev_class(class);
        CLASS_SET.lock().insert(index);
        // No event, no HCI: the reply is the zeroed class and the
        // value is announced when the controller powers on.
        return cmd_complete(index, OP_SET_DEV_CLASS, STATUS_SUCCESS, &[0, 0, 0]);
    }
    cmd_complete(index, OP_SET_DEV_CLASS, STATUS_SUCCESS, &class)
}

/// SET_LOCAL_NAME (0x000f): 249-byte name + 11-byte short name.
/// Both must be NUL-terminated (mgmt(7)) or the command is
/// INVALID_PARAMS. Powered: write to the controller, store,
/// announce, echo both. Unpowered: store only, echo both, no
/// HCI/event — the name is announced on power-on.
fn set_local_name(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_LOCAL_NAME, STATUS_INVALID_INDEX);
    }
    if params.len() < MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH {
        return cmd_status(index, OP_SET_LOCAL_NAME, STATUS_INVALID_PARAMS);
    }
    let name = &params[..MGMT_MAX_NAME_LENGTH];
    let short = &params[MGMT_MAX_NAME_LENGTH..MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH];
    if name[MGMT_MAX_NAME_LENGTH - 1] != 0 || short[MGMT_MAX_SHORT_NAME_LENGTH - 1] != 0 {
        return cmd_status(index, OP_SET_LOCAL_NAME, STATUS_INVALID_PARAMS);
    }
    let Some(ctrl) = controller(index) else {
        return cmd_status(index, OP_SET_LOCAL_NAME, STATUS_INVALID_INDEX);
    };
    let mut name248 = [0u8; 248];
    name248.copy_from_slice(&name[..248]);
    let mut short10 = [0u8; 10];
    short10.copy_from_slice(&short[..10]);
    if current_settings(index) & SETTING_POWERED != 0 {
        if let Err(status) = issue(index, op::HCI_WRITE_LOCAL_NAME, &name248) {
            return cmd_status(index, OP_SET_LOCAL_NAME, status);
        }
        ctrl.set_local_name(name248, short10);
        NAME_SET.lock().insert(index);
        let mut name249 = [0u8; 249];
        name249.copy_from_slice(name);
        narf_filesystem::bluetooth::publish_mgmt_event(&local_name_changed(index, &name249));
    } else {
        ctrl.set_local_name(name248, short10);
        NAME_SET.lock().insert(index);
    }
    // Echo: name (249) + short name (11), exactly as sent.
    let mut echo = Vec::with_capacity(MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH);
    echo.extend_from_slice(name);
    echo.extend_from_slice(short);
    cmd_complete(index, OP_SET_LOCAL_NAME, STATUS_SUCCESS, &echo)
}

/// SET_SCAN_PARAMS (0x002c): `interval, window` (LE, 0.625 ms
/// units). Bounds are the HCI LE scan bounds (§7.8.10):
/// 0x0004..=0x4000, window ≤ interval. No power gate — the
/// parameters are stored for the next START_DISCOVERY.
fn set_scan_params(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_SCAN_PARAMS, STATUS_INVALID_INDEX);
    }
    if params.len() < 4 {
        return cmd_status(index, OP_SET_SCAN_PARAMS, STATUS_INVALID_PARAMS);
    }
    let interval = u16::from_le_bytes([params[0], params[1]]);
    let window = u16::from_le_bytes([params[2], params[3]]);
    if !(0x0004..=0x4000).contains(&interval)
        || !(0x0004..=0x4000).contains(&window)
        || window > interval
    {
        return cmd_status(index, OP_SET_SCAN_PARAMS, STATUS_INVALID_PARAMS);
    }
    SCAN_PARAMS.lock().insert(index, (interval, window));
    cmd_complete(index, OP_SET_SCAN_PARAMS, STATUS_SUCCESS, &[])
}

/// START_DISCOVERY (0x0023): `type` is a bitmask (mgmt(7)):
/// 0x01 BR/EDR, 0x02 LE public, 0x04 LE random; 0x06 is the
/// usual LE scan, 0x07 interleaved. Powered-only. BR/EDR and LE
/// random are NOT_SUPPORTED (Classic inquiry/EIR is lane 1's,
/// #1315; there is no random-address backend). LE public goes to
/// the GAP central initiator (#1312) with the stored scan
/// parameters; a second start while discovering is BUSY.
fn start_discovery(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_START_DISCOVERY, STATUS_INVALID_INDEX);
    }
    if params.is_empty() {
        return cmd_status(index, OP_START_DISCOVERY, STATUS_INVALID_PARAMS);
    }
    let disc_type = params[0];
    if disc_type == 0 || disc_type > 0x07 {
        return cmd_status(index, OP_START_DISCOVERY, STATUS_INVALID_PARAMS);
    }
    if disc_type & DISC_BREDR != 0 || disc_type & DISC_LE_RANDOM != 0 {
        return cmd_status(index, OP_START_DISCOVERY, STATUS_NOT_SUPPORTED);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, OP_START_DISCOVERY, STATUS_NOT_POWERED);
    }
    if DISCOVERING.lock().contains_key(&index) {
        return cmd_status(index, OP_START_DISCOVERY, STATUS_BUSY);
    }
    let mut scan_params = crate::gap::ScanParameters::default();
    if let Some((interval, window)) = SCAN_PARAMS.lock().get(&index).copied() {
        scan_params.scan_interval = interval;
        scan_params.scan_window = window;
    }
    match crate::pump::central_start_scan(index as usize, scan_params) {
        Ok(()) => {
            DISCOVERING.lock().insert(index, disc_type);
            narf_filesystem::bluetooth::publish_mgmt_event(&discovering(index, disc_type, true));
            cmd_complete(index, OP_START_DISCOVERY, STATUS_SUCCESS, &[disc_type])
        }
        Err(crate::pump::CentralError::NoPump) | Err(crate::pump::CentralError::Transport) => {
            cmd_status(index, OP_START_DISCOVERY, STATUS_FAILED)
        }
        Err(crate::pump::CentralError::WrongPhase) => {
            cmd_status(index, OP_START_DISCOVERY, STATUS_BUSY)
        }
        Err(crate::pump::CentralError::Busy) => cmd_status(index, OP_START_DISCOVERY, STATUS_BUSY),
        // BadParams is only produced by `central_connect_ext` — unreachable here.
        Err(crate::pump::CentralError::BadParams) => {
            cmd_status(index, OP_START_DISCOVERY, STATUS_INVALID_PARAMS)
        }
        // BadData is only produced by `ext_adv_start` — unreachable here.
        Err(crate::pump::CentralError::BadData) => {
            cmd_status(index, OP_START_DISCOVERY, STATUS_INVALID_PARAMS)
        }
    }
}

/// STOP_DISCOVERY (0x0024): `type` must match the active
/// discovery. Powered-only. A pump that already stopped the scan
/// (e.g. a connect is in flight) counts as stopped: the state is
/// cleared and the reply is still success.
fn stop_discovery(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_STOP_DISCOVERY, STATUS_INVALID_INDEX);
    }
    if params.is_empty() {
        return cmd_status(index, OP_STOP_DISCOVERY, STATUS_INVALID_PARAMS);
    }
    let disc_type = params[0];
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, OP_STOP_DISCOVERY, STATUS_NOT_POWERED);
    }
    match DISCOVERING.lock().get(&index).copied() {
        None => cmd_status(index, OP_STOP_DISCOVERY, STATUS_REJECTED),
        Some(active) if active != disc_type => {
            cmd_status(index, OP_STOP_DISCOVERY, STATUS_INVALID_PARAMS)
        }
        Some(active) => {
            // WrongPhase here usually means the central is no
            // longer scanning (a connect took over, or power-off
            // already stopped it) — treat as already stopped. The
            // exception is a scan still starting (parameters sent,
            // enable pending): the disable cannot be issued yet, so
            // the stop is BUSY and the DISCOVERING record stays —
            // a retry lands once the scan is up (or fails, and the
            // phase returns to Idle).
            match crate::pump::central_stop_scan(index as usize) {
                Ok(()) | Err(crate::pump::CentralError::NoPump) => {
                    DISCOVERING.lock().remove(&index);
                    narf_filesystem::bluetooth::publish_mgmt_event(&discovering(
                        index, active, false,
                    ));
                    cmd_complete(index, OP_STOP_DISCOVERY, STATUS_SUCCESS, &[disc_type])
                }
                Err(crate::pump::CentralError::Busy) => {
                    cmd_status(index, OP_STOP_DISCOVERY, STATUS_BUSY)
                }
                Err(crate::pump::CentralError::Transport) => {
                    cmd_status(index, OP_STOP_DISCOVERY, STATUS_FAILED)
                }
                // BadParams is only produced by `central_connect_ext` — unreachable here.
                Err(crate::pump::CentralError::BadParams) => {
                    cmd_status(index, OP_STOP_DISCOVERY, STATUS_INVALID_PARAMS)
                }
                // BadData is only produced by `ext_adv_start` — unreachable here.
                Err(crate::pump::CentralError::BadData) => {
                    cmd_status(index, OP_STOP_DISCOVERY, STATUS_INVALID_PARAMS)
                }
                Err(crate::pump::CentralError::WrongPhase) => {
                    if crate::pump::central_phase(index as usize)
                        == Some(crate::gap::CentralPhase::ParametersSent)
                    {
                        cmd_status(index, OP_STOP_DISCOVERY, STATUS_BUSY)
                    } else {
                        DISCOVERING.lock().remove(&index);
                        narf_filesystem::bluetooth::publish_mgmt_event(&discovering(
                            index, active, false,
                        ));
                        cmd_complete(index, OP_STOP_DISCOVERY, STATUS_SUCCESS, &[disc_type])
                    }
                }
            }
        }
    }
}

/// GET_CONNECTIONS (0x0015): count + one mgmt_addr_info per live
/// pump connection (mgmt.h `mgmt_rp_get_connections`). Powered-only;
/// an unattached pump reports an empty list.
fn get_connections(index: u16) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_GET_CONNECTIONS, STATUS_INVALID_INDEX);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, OP_GET_CONNECTIONS, STATUS_NOT_POWERED);
    }
    let conns = crate::pump::connections(index as usize).unwrap_or_default();
    let mut data = Vec::with_capacity(2 + 7 * conns.len());
    data.extend_from_slice(&(conns.len() as u16).to_le_bytes());
    for conn in conns {
        data.extend_from_slice(&conn.peer_addr[1..7]);
        data.push(if conn.le {
            match conn.peer_addr[0] {
                0 => ADDR_LE_PUBLIC,
                _ => ADDR_LE_RANDOM,
            }
        } else {
            ADDR_BREDR
        });
    }
    cmd_complete(index, OP_GET_CONNECTIONS, STATUS_SUCCESS, &data)
}

/// Handle of the live pump connection for `peer`
/// (`[address_type, bd_addr]`, HCI address type in [0]) on
/// transport `le`, if any. `None` covers both "no pump" and
/// "no such connection".
fn connection_handle(index: u16, peer: &[u8; 7], le: bool) -> Option<u16> {
    crate::pump::connections(index as usize).and_then(|conns| {
        conns
            .iter()
            .find(|c| c.peer_addr == *peer && c.le == le)
            .map(|c| c.handle)
    })
}

/// DISCONNECT (0x0014): `addr (6) + type (1)`. Powered-only;
/// the reply echoes the address (BlueZ mgmt-api.txt,
/// "Disconnect Command"; Linux `disconnect()` in
/// net/bluetooth/mgmt.c). The reply is a Command Complete on
/// success *or* failure: synchronous failures (bad type, not
/// powered, a disconnect already pending, not connected) are
/// Command Completes carrying the error status and echoing the
/// address. The success path is async like PAIR_DEVICE: no
/// reply now; the pump issues HCI Disconnect (reason Remote
/// User Terminated Connection 0x13) and [`disconnect_complete`]
/// publishes the Command Complete when the Disconnection
/// Complete lands (or FAILED when the controller refuses the
/// HCI command). A second DISCONNECT while one is pending on
/// the controller is BUSY.
fn disconnect_device(index: u16, params: &[u8]) -> Vec<Vec<u8>> {
    if (index as usize) >= controller::controller_count() {
        return alloc::vec![cmd_status(index, OP_DISCONNECT, STATUS_INVALID_INDEX)];
    }
    if params.len() < 7 {
        return alloc::vec![cmd_status(index, OP_DISCONNECT, STATUS_INVALID_PARAMS)];
    }
    let mut addr_info = [0u8; 7];
    addr_info[..6].copy_from_slice(&params[..6]);
    addr_info[6] = params[6];
    let echo = |status: u8| alloc::vec![cmd_complete(index, OP_DISCONNECT, status, &addr_info)];
    let addr_type = params[6];
    if addr_type != ADDR_BREDR && addr_type != ADDR_LE_PUBLIC && addr_type != ADDR_LE_RANDOM {
        return echo(STATUS_INVALID_PARAMS);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return echo(STATUS_NOT_POWERED);
    }
    if PENDING_DISCONNECT
        .lock()
        .keys()
        .any(|(idx, _)| *idx == index)
    {
        return echo(STATUS_BUSY);
    }
    let is_le = addr_type != ADDR_BREDR;
    let mut peer = [0u8; 7];
    peer[0] = match addr_type {
        ADDR_LE_PUBLIC => 0,
        ADDR_LE_RANDOM => 1,
        _ => 0,
    };
    peer[1..7].copy_from_slice(&params[..6]);
    let Some(handle) = connection_handle(index, &peer, is_le) else {
        return echo(STATUS_NOT_CONNECTED);
    };
    match crate::pump::disconnect(index as usize, handle) {
        Some(Ok(())) => {
            PENDING_DISCONNECT.lock().insert((index, handle), addr_info);
            Vec::new()
        }
        Some(Err(crate::pump::DisconnectError::UnknownHandle)) => {
            // Raced: the connection dropped between the lookup
            // and the disconnect.
            echo(STATUS_NOT_CONNECTED)
        }
        Some(Err(crate::pump::DisconnectError::AlreadyDisconnecting)) => echo(STATUS_BUSY),
        // No pump, or the core is owned by a pump step right
        // now: the disconnect could not be issued.
        Some(Err(crate::pump::DisconnectError::Transport)) | None => echo(STATUS_FAILED),
    }
}

/// PAIR_DEVICE (0x0019): `addr (6) + type (1) + io_cap (1)`.
/// Powered-only; LE setting off → REJECTED. BR/EDR is
/// NOT_SUPPORTED (no legacy pairing initiator; Classic is lane
/// 1's, #1315). The io_cap temporarily overrides the controller's
/// SET_IO_CAPABILITY value for this one pairing (mgmt-api) and is
/// what the SMP initiator advertises — any of the five §3.5.1
/// values is accepted, so MITM methods (Numeric Comparison,
/// Passkey Entry) are reachable, not just Just Works (#818). A
/// peer that is not connected is NOT_CONNECTED. A bonded peer is
/// ALREADY_PAIRED. Success is asynchronous per mgmt(7): the reply
/// is Command Status now, and the Command Complete arrives via
/// [`pairing_complete`] when the SMP session ends.
fn pair_device(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_INVALID_INDEX);
    }
    if params.len() < 8 {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    let addr_type = params[6];
    let io_cap = params[7];
    if addr_type == ADDR_BREDR {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_NOT_SUPPORTED);
    }
    if addr_type != ADDR_LE_PUBLIC && addr_type != ADDR_LE_RANDOM {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    if crate::smp::IoCapability::from_u8(io_cap).is_none() {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_NOT_POWERED);
    }
    if current_settings(index) & SETTING_LE == 0 {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_REJECTED);
    }
    let mut peer = [0u8; 7];
    peer[0] = match addr_type {
        ADDR_LE_PUBLIC => 0,
        _ => 1,
    };
    peer[1..7].copy_from_slice(&params[..6]);
    match crate::pump::has_bond(index as usize, &peer) {
        Some(true) => return cmd_status(index, OP_PAIR_DEVICE, STATUS_ALREADY_PAIRED),
        None => return cmd_status(index, OP_PAIR_DEVICE, STATUS_FAILED),
        Some(false) => {}
    }
    // The SMP initiator takes a connection handle: resolve the
    // peer first. A peer with no live connection is NOT_CONNECTED
    // (mgmt pairs an existing connection; connect-then-pair is a
    // remainder).
    let conns = match crate::pump::connections(index as usize) {
        Some(conns) => conns,
        None => return cmd_status(index, OP_PAIR_DEVICE, STATUS_FAILED),
    };
    let Some(handle) = conns.iter().find(|c| c.peer_addr == peer).map(|c| c.handle) else {
        return cmd_status(index, OP_PAIR_DEVICE, STATUS_NOT_CONNECTED);
    };
    match crate::pump::smp_initiate_pairing_with_io(index as usize, handle, io_cap) {
        Some(Ok(())) => {
            PENDING_PAIR.lock().insert((index, peer));
            cmd_status(index, OP_PAIR_DEVICE, STATUS_SUCCESS)
        }
        Some(Err(crate::pump::SmpInitiateError::AlreadyPairing)) => {
            cmd_status(index, OP_PAIR_DEVICE, STATUS_BUSY)
        }
        Some(Err(crate::pump::SmpInitiateError::UnknownHandle)) => {
            // Raced: the connection dropped between the snapshot
            // and the initiation.
            cmd_status(index, OP_PAIR_DEVICE, STATUS_NOT_CONNECTED)
        }
        Some(Err(crate::pump::SmpInitiateError::NotLe)) => {
            cmd_status(index, OP_PAIR_DEVICE, STATUS_NOT_SUPPORTED)
        }
        Some(Err(crate::pump::SmpInitiateError::InvalidIoCap)) => {
            // Unreachable from here: io_cap was validated against
            // `IoCapability::from_u8` above, but the pump refuses
            // out-of-range bytes with this error.
            cmd_status(index, OP_PAIR_DEVICE, STATUS_INVALID_PARAMS)
        }
        None => cmd_status(index, OP_PAIR_DEVICE, STATUS_FAILED),
    }
}

/// CANCEL_PAIR_DEVICE (0x001a): `addr (6) + type (1)` (BlueZ
/// `doc/mgmt-api.txt`; kernel `cancel_pair_device` in
/// `net/bluetooth/mgmt.c`). Powered-only. The address must match
/// a pending PAIR_DEVICE — no pending pairing, or a different
/// peer, is INVALID_PARAMS (Command Status), exactly as the
/// kernel answers when `pending_find(MGMT_OP_PAIR_DEVICE)`
/// comes up empty or the address mismatches. BR/EDR can never
/// match: pending pairings are LE-only (BR/EDR is rejected at
/// PAIR_DEVICE), so it is INVALID_PARAMS too. On a match the
/// pump aborts the SMP session (Pairing Failed, Unspecified
/// Reason, Vol 3 Part H §3.5.5), the pending PAIR_DEVICE
/// completes with CANCELLED (0x10) on the mgmt event sink, and
/// this command completes with SUCCESS echoing the addr_info.
fn cancel_pair_device(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_INDEX);
    }
    if params.len() < 7 {
        return cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    let addr_type = params[6];
    if addr_type != ADDR_LE_PUBLIC && addr_type != ADDR_LE_RANDOM {
        return cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_NOT_POWERED);
    }
    let mut peer = [0u8; 7];
    peer[0] = match addr_type {
        ADDR_LE_PUBLIC => 0,
        _ => 1,
    };
    peer[1..7].copy_from_slice(&params[..6]);
    // The kernel gate: cancel only matches a *pending
    // PAIR_DEVICE*. A responder pairing or a direct
    // `pump::smp_initiate_pairing` call never creates one, so
    // cancelling those is INVALID_PARAMS — and the session is
    // left alone, not aborted behind userspace's back.
    if !PENDING_PAIR.lock().contains(&(index, peer)) {
        return cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    // Resolve the live connection for the peer (mgmt pairs an
    // existing connection). A disconnect already completed the
    // pending pairing as DISCONNECTED and dropped the entry, so
    // a missing connection here is unreachable in practice; the
    // NOT_CONNECTED is defensive, mirroring PAIR_DEVICE.
    let handle = match crate::pump::connections(index as usize) {
        Some(conns) => conns.iter().find(|c| c.peer_addr == peer).map(|c| c.handle),
        None => None,
    };
    let Some(handle) = handle else {
        return cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_NOT_CONNECTED);
    };
    match crate::pump::smp_cancel_pairing(index as usize, handle) {
        Some(Ok(())) => {
            let mut data = Vec::with_capacity(7);
            data.extend_from_slice(&params[..6]);
            data.push(addr_type);
            cmd_complete(index, OP_CANCEL_PAIR_DEVICE, STATUS_SUCCESS, &data)
        }
        // Raced: the session ended between the pending-entry
        // check and the cancel, and its terminal path already
        // completed the pairing — nothing left to cancel.
        Some(Err(crate::pump::SmpCancelError::NotPairing)) => {
            cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS)
        }
        Some(Err(crate::pump::SmpCancelError::UnknownHandle)) => {
            cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_NOT_CONNECTED)
        }
        None => cmd_status(index, OP_CANCEL_PAIR_DEVICE, STATUS_FAILED),
    }
}

/// UNPAIR_DEVICE (0x001b): `addr (6) + type (1) + disconnect (1)`.
/// Powered-only. Removing a bond is idempotent — an unknown peer
/// still replies success. `disconnect=1` with a live connection
/// disconnects it first via the pump backend (issue #1527) and
/// then forgets the bond; the unpair reply does not wait for the
/// link to come down. A disconnect that cannot be issued
/// (transport failure, pump busy) fails the unpair and leaves
/// the bond untouched, so userspace can retry.
fn unpair_device(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_UNPAIR_DEVICE, STATUS_INVALID_INDEX);
    }
    if params.len() < 8 {
        return cmd_status(index, OP_UNPAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    let addr_type = params[6];
    let disconnect = params[7];
    if addr_type != ADDR_BREDR && addr_type != ADDR_LE_PUBLIC && addr_type != ADDR_LE_RANDOM {
        return cmd_status(index, OP_UNPAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    if disconnect > 1 {
        return cmd_status(index, OP_UNPAIR_DEVICE, STATUS_INVALID_PARAMS);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, OP_UNPAIR_DEVICE, STATUS_NOT_POWERED);
    }
    // The bond store is keyed by the LE peer `[hci_addr_type,
    // addr]`; BR/EDR bonds are never stored (no legacy pairing
    // backend), so a BR/EDR unpair has nothing to forget and must
    // never touch an LE bond for the same address.
    let is_le = addr_type != ADDR_BREDR;
    let mut peer = [0u8; 7];
    peer[0] = match addr_type {
        ADDR_LE_PUBLIC => 0,
        ADDR_LE_RANDOM => 1,
        _ => 0,
    };
    peer[1..7].copy_from_slice(&params[..6]);
    if disconnect == 1 {
        if let Some(handle) = connection_handle(index, &peer, is_le) {
            match crate::pump::disconnect(index as usize, handle) {
                Some(Ok(())) => {}
                // Raced: the connection dropped between the
                // lookup and the disconnect — nothing left to
                // tear down; forget the bond as requested.
                Some(Err(crate::pump::DisconnectError::UnknownHandle)) => {}
                // A disconnect is already in flight for this
                // handle: the link is going away; forget the
                // bond as requested.
                Some(Err(crate::pump::DisconnectError::AlreadyDisconnecting)) => {}
                Some(Err(crate::pump::DisconnectError::Transport)) | None => {
                    return cmd_status(index, OP_UNPAIR_DEVICE, STATUS_FAILED);
                }
            }
        }
    }
    let had_bond = if is_le {
        crate::pump::forget_bond(index as usize, &peer).unwrap_or(false)
    } else {
        false
    };
    if had_bond {
        let mut addr_info = [0u8; 7];
        addr_info[..6].copy_from_slice(&params[..6]);
        addr_info[6] = addr_type;
        narf_filesystem::bluetooth::publish_mgmt_event(&device_unpaired(index, &addr_info));
    }
    let mut data = Vec::with_capacity(7);
    data.extend_from_slice(&params[..6]);
    data.push(addr_type);
    cmd_complete(index, OP_UNPAIR_DEVICE, STATUS_SUCCESS, &data)
}

/// SET_IO_CAPABILITY (0x0018): `io_cap (1)`. Usable while the
/// controller is powered off (mgmt-api). The value is the §3.5.1
/// IO capability the pump advertises for responder pairings and
/// Security-Request-triggered initiations; PAIR_DEVICE's io_cap
/// overrides it for one pairing. Returns Command Complete with
/// no return parameters on success.
fn set_io_capability(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_IO_CAPABILITY, STATUS_INVALID_INDEX);
    }
    if params.is_empty() || crate::smp::IoCapability::from_u8(params[0]).is_none() {
        return cmd_status(index, OP_SET_IO_CAPABILITY, STATUS_INVALID_PARAMS);
    }
    IO_CAPABILITY.lock().insert(index, params[0]);
    cmd_complete(index, OP_SET_IO_CAPABILITY, STATUS_SUCCESS, &[])
}

/// Parse an `addr (6) + type (1)` parameter prefix into the
/// pump's `[address_type, bd_addr]` shape. BR/EDR is
/// NOT_SUPPORTED (no legacy pairing backend); any other type
/// byte is INVALID_PARAMS.
fn le_peer(params: &[u8]) -> Result<[u8; 7], u8> {
    if params.len() < 7 {
        return Err(STATUS_INVALID_PARAMS);
    }
    let addr_type = params[6];
    if addr_type == ADDR_BREDR {
        return Err(STATUS_NOT_SUPPORTED);
    }
    if addr_type != ADDR_LE_PUBLIC && addr_type != ADDR_LE_RANDOM {
        return Err(STATUS_INVALID_PARAMS);
    }
    let mut peer = [0u8; 7];
    peer[0] = if addr_type == ADDR_LE_PUBLIC { 0 } else { 1 };
    peer[1..7].copy_from_slice(&params[..6]);
    Ok(peer)
}

/// `addr (6) + type (1)` return parameters for `peer`.
fn addr_reply(peer: &[u8; 7]) -> Vec<u8> {
    let mut data = Vec::with_capacity(7);
    data.extend_from_slice(&peer[1..7]);
    data.push(if peer[0] == 0 {
        ADDR_LE_PUBLIC
    } else {
        ADDR_LE_RANDOM
    });
    data
}

/// PIN_CODE_REPLY (0x0016) / PIN_CODE_NEG_REPLY (0x0017):
/// `addr (6) + type (1) [+ pin_len (1) + pin (16)]`. The PIN
/// Code Request event is BR/EDR-only and this stack has no BR/EDR
/// pairing backend; LE passkey flows use USER_PASSKEY_REPLY.
/// The commands are recognised and validated, then refused as
/// NOT_SUPPORTED rather than answered UNKNOWN_COMMAND.
fn pin_code_reply(index: u16, opcode: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, opcode, STATUS_INVALID_INDEX);
    }
    let need = if opcode == OP_PIN_CODE_REPLY { 24 } else { 7 };
    if params.len() < need {
        return cmd_status(index, opcode, STATUS_INVALID_PARAMS);
    }
    if let Err(status) = le_peer(params) {
        return cmd_status(index, opcode, status);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, opcode, STATUS_NOT_POWERED);
    }
    cmd_status(index, opcode, STATUS_NOT_SUPPORTED)
}

/// USER_CONFIRM_REPLY (0x001c) / USER_CONFIRM_NEG_REPLY (0x001d):
/// `addr (6) + type (1)`. Answers a pending Numeric Comparison
/// park for that peer. No parked confirm → NOT_CONNECTED; no
/// pump → FAILED. Success is Command Complete with the
/// address back.
fn user_confirm_reply(index: u16, opcode: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, opcode, STATUS_INVALID_INDEX);
    }
    let peer = match le_peer(params) {
        Ok(peer) => peer,
        Err(status) => return cmd_status(index, opcode, status),
    };
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, opcode, STATUS_NOT_POWERED);
    }
    match crate::pump::smp_user_confirm(index as usize, &peer, opcode == OP_USER_CONFIRM_REPLY) {
        Some(true) => cmd_complete(index, opcode, STATUS_SUCCESS, &addr_reply(&peer)),
        Some(false) => cmd_status(index, opcode, STATUS_NOT_CONNECTED),
        None => cmd_status(index, opcode, STATUS_FAILED),
    }
}

/// USER_PASSKEY_REPLY (0x001e): `addr (6) + type (1) + passkey
/// (4, LE)`; USER_PASSKEY_NEG_REPLY (0x001f): `addr (6) +
/// type (1)`. The passkey is six decimal digits — anything above
/// 999999 is INVALID_PARAMS. A negative reply fails the parked
/// passkey entry (Pairing Failed 0x01 at the pump).
fn user_passkey_reply(index: u16, opcode: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, opcode, STATUS_INVALID_INDEX);
    }
    let peer = match le_peer(params) {
        Ok(peer) => peer,
        Err(status) => return cmd_status(index, opcode, status),
    };
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, opcode, STATUS_NOT_POWERED);
    }
    if opcode == OP_USER_PASSKEY_REPLY {
        if params.len() < 11 {
            return cmd_status(index, opcode, STATUS_INVALID_PARAMS);
        }
        let passkey = u32::from_le_bytes([params[7], params[8], params[9], params[10]]);
        if passkey > 999_999 {
            return cmd_status(index, opcode, STATUS_INVALID_PARAMS);
        }
        match crate::pump::smp_user_passkey(index as usize, &peer, passkey) {
            Some(true) => cmd_complete(index, opcode, STATUS_SUCCESS, &addr_reply(&peer)),
            Some(false) => cmd_status(index, opcode, STATUS_NOT_CONNECTED),
            None => cmd_status(index, opcode, STATUS_FAILED),
        }
    } else {
        match crate::pump::smp_user_passkey_cancel(index as usize, &peer) {
            Some(true) => cmd_complete(index, opcode, STATUS_SUCCESS, &addr_reply(&peer)),
            Some(false) => cmd_status(index, opcode, STATUS_NOT_CONNECTED),
            None => cmd_status(index, opcode, STATUS_FAILED),
        }
    }
}

/// READ_LOCAL_OOB_DATA (0x0020): refused as NOT_SUPPORTED.
/// Minting local OOB data means committing a public key in the
/// OOB hash (`f4(PK, PK, r, 0)`) that the pairing must then use,
/// and sessions generate a fresh keypair per pairing — there is
/// no stable local SC keypair to hash yet. Emitting OOB data
/// for a key that will never be used would silently break the
/// peer's authentication, so the command is refused until the
/// stable-keypair gap is closed (remainder).
fn read_local_oob_data(index: u16) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_READ_LOCAL_OOB_DATA, STATUS_INVALID_INDEX);
    }
    if current_settings(index) & SETTING_POWERED == 0 {
        return cmd_status(index, OP_READ_LOCAL_OOB_DATA, STATUS_NOT_POWERED);
    }
    cmd_status(index, OP_READ_LOCAL_OOB_DATA, STATUS_NOT_SUPPORTED)
}

/// ADD_REMOTE_OOB_DATA (0x0021): `addr (6) + type (1) +
/// hash_192 (16) + rand_192 (16) [+ hash_256 (16) + rand_256
/// (16)]`. For LE the P-256 pair is the OOB data and the P-192
/// fields must be zero (mgmt-api); a 39-byte call carries no LE
/// OOB data and is INVALID_PARAMS. Usable while unpowered; the
/// data is held until a session for that peer starts.
fn add_remote_oob_data(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_ADD_REMOTE_OOB_DATA, STATUS_INVALID_INDEX);
    }
    if params.len() != 39 && params.len() != 71 {
        return cmd_status(index, OP_ADD_REMOTE_OOB_DATA, STATUS_INVALID_PARAMS);
    }
    let peer = match le_peer(params) {
        Ok(peer) => peer,
        Err(status) => return cmd_status(index, OP_ADD_REMOTE_OOB_DATA, status),
    };
    if params.len() != 71 {
        return cmd_status(index, OP_ADD_REMOTE_OOB_DATA, STATUS_INVALID_PARAMS);
    }
    if params[7..39] != [0u8; 32] {
        return cmd_status(index, OP_ADD_REMOTE_OOB_DATA, STATUS_INVALID_PARAMS);
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&params[39..55]);
    let mut randomizer = [0u8; 16];
    randomizer.copy_from_slice(&params[55..71]);
    REMOTE_OOB
        .lock()
        .entry(index)
        .or_default()
        .insert(peer, crate::smp::OobData { hash, randomizer });
    cmd_complete(
        index,
        OP_ADD_REMOTE_OOB_DATA,
        STATUS_SUCCESS,
        &addr_reply(&peer),
    )
}

/// REMOVE_REMOTE_OOB_DATA (0x0022): `addr (6) + type (1)`.
/// An all-zero address clears every entry for the controller.
/// Usable while unpowered.
fn remove_remote_oob_data(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_REMOVE_REMOTE_OOB_DATA, STATUS_INVALID_INDEX);
    }
    let peer = match le_peer(params) {
        Ok(peer) => peer,
        Err(status) => return cmd_status(index, OP_REMOVE_REMOTE_OOB_DATA, status),
    };
    if params[..6] == [0u8; 6] {
        let _ = REMOTE_OOB.lock().remove(&index);
    } else if let Some(map) = REMOTE_OOB.lock().get_mut(&index) {
        map.remove(&peer);
    }
    cmd_complete(
        index,
        OP_REMOVE_REMOTE_OOB_DATA,
        STATUS_SUCCESS,
        &addr_reply(&peer),
    )
}

/// Advertised mgmt protocol version/revision (`MGMT_VERSION` / `MGMT_REVISION`).
const MGMT_VERSION: u8 = 1;
const MGMT_REVISION: u16 = 22;

/// `HCI_MAX_NAME_LENGTH + 1` (mgmt.h MGMT_MAX_NAME_LENGTH).
const MGMT_MAX_NAME_LENGTH: usize = 249;
/// `HCI_MAX_SHORT_NAME_LENGTH + 1` (mgmt.h MGMT_MAX_SHORT_NAME_LENGTH).
const MGMT_MAX_SHORT_NAME_LENGTH: usize = 11;

/// Frame a mgmt message: `mgmt_hdr` (opcode/index/len, LE) + params.
fn frame(opcode: u16, index: u16, params: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MGMT_HDR_SIZE + params.len());
    out.extend_from_slice(&opcode.to_le_bytes());
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&(params.len() as u16).to_le_bytes());
    out.extend_from_slice(params);
    out
}

/// `MGMT_EV_CMD_COMPLETE`: body = command opcode(le16) + status + data.
fn cmd_complete(index: u16, opcode: u16, status: u8, data: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(3 + data.len());
    body.extend_from_slice(&opcode.to_le_bytes());
    body.push(status);
    body.extend_from_slice(data);
    frame(EV_CMD_COMPLETE, index, &body)
}

/// `MGMT_EV_CMD_STATUS`: body = command opcode(le16) + status.
fn cmd_status(index: u16, opcode: u16, status: u8) -> Vec<u8> {
    let mut body = [0u8; 3];
    body[0..2].copy_from_slice(&opcode.to_le_bytes());
    body[2] = status;
    frame(EV_CMD_STATUS, index, &body)
}

/// `mgmt_rp_read_info` for a controller: bdaddr(6) version(1) manufacturer(2)
/// supported_settings(4) current_settings(4) dev_class(3) name(249)
/// short_name(11).
/// Settings this profile lets userspace toggle (supported_settings).
const SUPPORTED_SETTINGS: u32 = SETTING_POWERED
    | SETTING_CONNECTABLE
    | SETTING_FAST_CONNECTABLE
    | SETTING_DISCOVERABLE
    | SETTING_BONDABLE
    | SETTING_LINK_SECURITY
    | SETTING_SSP
    | SETTING_BREDR
    | SETTING_LE
    | SETTING_ADVERTISING
    | SETTING_SECURE_CONN
    | SETTING_PRIVACY
    | SETTING_STATIC_ADDRESS;

fn read_info_rp(info: &controller::ControllerInfo, current: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(
        6 + 1 + 2 + 4 + 4 + 3 + MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH,
    );
    d.extend_from_slice(&info.bd_addr);
    d.push(info.hci_version);
    d.extend_from_slice(&info.manufacturer.to_le_bytes());
    d.extend_from_slice(&SUPPORTED_SETTINGS.to_le_bytes());
    d.extend_from_slice(&current.to_le_bytes());
    // Real identity, not zeros: the Class of Device and local name
    // the bring-up read from the controller (or userspace wrote via
    // SET_DEV_CLASS / SET_LOCAL_NAME). A zeroed field here means the
    // value was never learned, never a fabricated one.
    d.extend_from_slice(&info.dev_class);
    d.extend_from_slice(&info.local_name);
    d.push(0); // NUL-terminate the 248-byte name into 249 bytes.
    d.extend_from_slice(&info.short_name);
    d.push(0); // NUL-terminate the 10-byte short name into 11 bytes.
    d
}

/// Map a controller HCI failure onto a mgmt status. A command that
/// timed out waiting for its Command Complete is TIMEOUT; every
/// other issuance failure (transport error, bad status, opcode
/// mismatch) is FAILED.
fn hci_status(err: &BringupError) -> u8 {
    match err {
        BringupError::Transport(crate::transport::TransportError::Timeout) => STATUS_TIMEOUT,
        _ => STATUS_FAILED,
    }
}

/// Resolve a controller by mgmt index.
fn controller(index: u16) -> Option<Arc<controller::Controller>> {
    controller::controllers().get(index as usize).cloned()
}

/// Issue one HCI command on controller `index` and wait for its
/// Command Complete. `Err` is the mgmt status to report (see
/// [`hci_status`]).
fn issue(index: u16, opcode: u16, params: &[u8]) -> Result<Vec<u8>, u8> {
    let Some(ctrl) = controller(index) else {
        return Err(STATUS_INVALID_INDEX);
    };
    ctrl.issue_command(opcode, params)
        .map_err(|e| hci_status(&e))
}

/// The Write_Scan_Enable byte for a settings bitmap (Core 5.3
/// §7.3.14): bit 0 inquiry scan (discoverable), bit 1 page scan
/// (connectable).
fn scan_enable_byte(settings: u32) -> u8 {
    let mut byte = 0u8;
    if settings & SETTING_DISCOVERABLE != 0 {
        byte |= 0x01;
    }
    if settings & SETTING_CONNECTABLE != 0 {
        byte |= 0x02;
    }
    byte
}

/// Push a settings bitmap's scan state to the controller
/// (HCI_Write_Scan_Enable). The discoverable/connectable pair
/// shares this one command, so both ops (and power-on) go through
/// here with the *prospective* bitmap.
fn apply_scan_enable(index: u16, settings: u32) -> Result<(), u8> {
    issue(
        index,
        op::HCI_WRITE_SCAN_ENABLE,
        &[scan_enable_byte(settings)],
    )
    .map(|_| ())
}

/// Push one HCI-backed single setting to the controller. `bit` is
/// one of FAST_CONNECTABLE / LINK_SECURITY / SSP / LE /
/// SECURE_CONN; BONDABLE has no HCI command and never reaches here.
fn apply_single_setting(index: u16, bit: u32, on: bool) -> Result<(), u8> {
    let v = on as u8;
    match bit {
        SETTING_FAST_CONNECTABLE => {
            // Interlaced page scan (§7.3.44) when fast-connectable.
            issue(index, op::HCI_WRITE_PAGE_SCAN_TYPE, &[v]).map(|_| ())
        }
        SETTING_LINK_SECURITY => {
            issue(index, op::HCI_WRITE_AUTHENTICATION_ENABLE, &[v]).map(|_| ())
        }
        SETTING_SSP => issue(index, op::HCI_WRITE_SIMPLE_PAIRING_MODE, &[v]).map(|_| ()),
        SETTING_LE => {
            // LE_Host_Supported + Simultaneous_LE_Host_Supported
            // (always 0: no simultaneous LE host, §7.3.66).
            issue(index, op::HCI_WRITE_LE_HOST_SUPPORT, &[v, 0]).map(|_| ())
        }
        SETTING_SECURE_CONN => {
            issue(index, op::HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT, &[v]).map(|_| ())
        }
        _ => Ok(()),
    }
}

/// Advertising mode recorded by SET_ADVERTISING (0 = off).
fn advertising_mode(index: u16) -> u8 {
    ADVERTISING.lock().get(&index).copied().unwrap_or(0)
}

/// Whether a configured static address is the address the
/// controller actually uses (mgmt(7)): a dual-mode controller
/// with a public address keeps using the public address, so the
/// static address is in use only when there is no public address
/// (READ_INFO reports BDADDR_ANY) or BR/EDR is off.
fn static_in_use(index: u16, settings: u32) -> bool {
    if STATIC_ADDR.lock().get(&index).is_none() {
        return false;
    }
    let Some(ctrl) = controller(index) else {
        return false;
    };
    ctrl.info().bd_addr == [0; 6] || settings & SETTING_BREDR == 0
}

/// Privacy mode recorded by SET_PRIVACY (0 = off).
fn privacy_mode(index: u16) -> u8 {
    PRIVACY
        .lock()
        .get(&index)
        .map(|(mode, _)| *mode)
        .unwrap_or(0)
}

/// Local IRK recorded by SET_PRIVACY, if privacy is on.
fn local_irk(index: u16) -> Option<[u8; 16]> {
    PRIVACY.lock().get(&index).map(|(_, irk)| *irk)
}

/// True when `addr` is a static random address: the two most
/// significant bits set (Core 5.3 Vol 6 Part B §1.3.2.1). The
/// kernel checks exactly this (`(bdaddr.b[5] & 0xc0) == 0xc0`)
/// for SET_STATIC_ADDRESS and for LE-random LTK/IRK entries.
fn is_static_random(addr: &[u8; 6]) -> bool {
    addr[5] & 0xc0 == 0xc0
}

/// Flags AD type bits (Core 5.3 Vol 3 Part C §11.1.3): bit 1 LE
/// General Discoverable, bit 2 BR/EDR Not Supported. (Bit 0 LE
/// Limited Discoverable is not tracked: SET_DISCOVERABLE records
/// only the bit, and limited vs general is already a known
/// remainder for discoverable.)
const ADV_FLAG_GENERAL_DISCOVERABLE: u8 = 0x02;
const ADV_FLAG_BREDR_NOT_SUPPORTED: u8 = 0x04;

/// Advertising flags for a settings bitmap.
fn adv_flags(settings: u32) -> u8 {
    let mut flags = 0u8;
    if settings & SETTING_DISCOVERABLE != 0 {
        flags |= ADV_FLAG_GENERAL_DISCOVERABLE;
    }
    if settings & SETTING_BREDR == 0 {
        flags |= ADV_FLAG_BREDR_NOT_SUPPORTED;
    }
    flags
}

/// Maximum legacy advertising / scan-response payload (§7.8.7/§7.8.8).
const ADV_MAX_DATA_LEN: usize = 31;

/// Build the legacy advertising data + scan response for the
/// controller's current name and settings (gap AD builders).
/// The layout is an implementation choice, not a spec mandate —
/// the Core Spec requires only the Flags record in advertising
/// data (Vol 3 Part C §11.1.3): advertising data carries Flags
/// plus the complete local name when it fits, else a shortened
/// name; the scan response then carries the complete name when
/// it fits there (≤ 29 bytes of name); a name that fits nowhere
/// is shortened in advertising data and omitted from the scan
/// response. An unset (all-zero) name contributes no name record
/// at all.
fn build_adv_data(index: u16, settings: u32) -> (Vec<u8>, Vec<u8>) {
    let mut adv = Vec::with_capacity(ADV_MAX_DATA_LEN);
    crate::gap::append_flags(&mut adv, adv_flags(settings));
    let mut scan_rsp = Vec::new();
    let Some(ctrl) = controller(index) else {
        return (adv, scan_rsp);
    };
    let name_bytes = ctrl.info().local_name;
    let name_len = name_bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(name_bytes.len());
    if name_len == 0 {
        return (adv, scan_rsp);
    }
    let name = &name_bytes[..name_len];
    // Complete-name record needs 2 header bytes + the name.
    if adv.len() + 2 + name.len() <= ADV_MAX_DATA_LEN {
        crate::gap::append_record(&mut adv, crate::gap::AD_COMPLETE_LOCAL_NAME, name);
        return (adv, scan_rsp);
    }
    // Shortened name fills the advertising data; the complete
    // name goes in the scan response when it fits there.
    let short_len = ADV_MAX_DATA_LEN - adv.len() - 2;
    if short_len > 0 {
        crate::gap::append_record(
            &mut adv,
            crate::gap::AD_SHORTENED_LOCAL_NAME,
            &name[..short_len],
        );
    }
    if name.len() + 2 <= ADV_MAX_DATA_LEN {
        crate::gap::append_record(&mut scan_rsp, crate::gap::AD_COMPLETE_LOCAL_NAME, name);
    }
    (adv, scan_rsp)
}

/// Frame a ≤ 31-byte payload for Set Advertising Data / Set Scan
/// Response Data (§7.8.7/§7.8.8): length (1) + 31 bytes,
/// zero-padded.
fn adv_data_param(data: &[u8]) -> Vec<u8> {
    debug_assert!(data.len() <= ADV_MAX_DATA_LEN);
    let mut params = Vec::with_capacity(32);
    params.push(data.len() as u8);
    params.extend_from_slice(data);
    params.resize(32, 0);
    params
}

/// Generate a fresh resolvable private address from the stored
/// local IRK (Core 5.3 Vol 3 Part H §2.2.2 `ah` + Vol 6 Part B
/// §1.3.2.2): `prand` is 24 bits with the two most significant
/// bits `0b01` and at least one 0 and one 1 in the random part;
/// `hash = AES-128(IRK, 0x00*13 || prand)` truncated to its 24
/// least significant bits; the address on the wire (LSB first)
/// is `hash || prand`.
///
/// Both crypto inputs come from the controller itself — the
/// randomness from HCI LE Rand (§7.8.23) and the AES from HCI LE
/// Encrypt (§7.8.22) — so no host crypto is needed and a fixture
/// can script both. A degenerate `prand` is redrawn (bounded:
/// three attempts, then FAILED rather than an invalid address).
fn generate_rpa(index: u16) -> Result<[u8; 6], u8> {
    let Some(irk) = local_irk(index) else {
        return Err(STATUS_FAILED);
    };
    for _ in 0..3 {
        let rand = issue(index, op::HCI_LE_RAND, &[])?;
        if rand.len() < 9 {
            return Err(STATUS_FAILED);
        }
        // prand, MSB first: top two bits 0b01, 22 random bits.
        // `issue` returns [status, rand0..rand7]; the prand bytes
        // are rand[2], rand[1], rand[0].
        let prand = [(rand[3] & 0x3f) | 0x40, rand[2], rand[1]];
        // Random part (22 bits) must contain at least one 0 and
        // one 1 — all-zero or all-one is not a prand.
        let random_part =
            ((u32::from(prand[0] & 0x3f)) << 16) | (u32::from(prand[1]) << 8) | u32::from(prand[2]);
        if random_part == 0 || random_part == (1 << 22) - 1 {
            continue;
        }
        // r' = padding || r: 13 zero octets, then prand MSB first
        // (§2.2.2: r = 0x423456 gives r' = 0x0000...00423456).
        let mut plaintext = [0u8; 16];
        plaintext[13..16].copy_from_slice(&prand);
        let mut params = Vec::with_capacity(32);
        params.extend_from_slice(&irk);
        params.extend_from_slice(&plaintext);
        let ct = issue(index, op::HCI_LE_ENCRYPT, &params)?;
        if ct.len() < 17 {
            return Err(STATUS_FAILED);
        }
        // ah = the 24 least significant bits of the ciphertext:
        // ct[14] is the most significant hash octet, ct[16] the
        // least (ct[0] is the Command Complete status). The wire
        // address is LSB first: hash || prand.
        return Ok([ct[16], ct[15], ct[14], prand[2], prand[1], prand[0]]);
    }
    Err(STATUS_FAILED)
}

/// Generate a fresh non-resolvable private address (Vol 6 Part B
/// §1.3.2.1): the two most significant bits `0b00`, at least one
/// 0 and one 1 among the rest. Randomness comes from HCI LE Rand.
fn generate_non_resolvable(index: u16) -> Result<[u8; 6], u8> {
    for _ in 0..3 {
        let rand = issue(index, op::HCI_LE_RAND, &[])?;
        if rand.len() < 7 {
            return Err(STATUS_FAILED);
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&rand[1..7]);
        addr[5] &= 0x3f;
        if addr != [0; 6] && addr != [0xff, 0xff, 0xff, 0xff, 0xff, 0x3f] {
            return Ok(addr);
        }
    }
    Err(STATUS_FAILED)
}

/// Program the random address the controller must use, for
/// `settings`: the cached RPA when privacy is on (generated once
/// per power epoch), the static address when one is in use,
/// otherwise nothing — the controller keeps its public identity
/// address and no HCI is issued. A redundant Set Random Address
/// is skipped when the desired address is already programmed.
fn program_random_address(index: u16, settings: u32) -> Result<(), u8> {
    let desired = if privacy_mode(index) != 0 {
        match CURRENT_RPA.lock().get(&index).copied() {
            Some(rpa) => Some(rpa),
            None => {
                let rpa = generate_rpa(index)?;
                CURRENT_RPA.lock().insert(index, rpa);
                Some(rpa)
            }
        }
    } else if static_in_use(index, settings) {
        STATIC_ADDR.lock().get(&index).copied()
    } else {
        None
    };
    let Some(addr) = desired else {
        return Ok(());
    };
    if PROGRAMMED_RANDOM_ADDR.lock().get(&index).copied() == Some(addr) {
        return Ok(());
    }
    issue(index, op::HCI_LE_SET_RANDOM_ADDRESS, &addr)?;
    PROGRAMMED_RANDOM_ADDR.lock().insert(index, addr);
    Ok(())
}

/// Program the controller's resolving list from the loaded IRKs
/// (LE Add Device To Resolving List §7.8.38, Clear §7.8.40,
/// Address Resolution Enable §7.8.44). Only when privacy is on:
/// without privacy the list is never consulted, and no HCI is
/// issued. The list is cleared first so a reload replaces the
/// controller copy exactly like it replaces the host copy.
fn apply_resolving_list(index: u16) -> Result<(), u8> {
    if privacy_mode(index) == 0 {
        return Ok(());
    }
    let Some(irk) = local_irk(index) else {
        return Err(STATUS_FAILED);
    };
    issue(index, op::HCI_LE_CLEAR_RESOLVING_LIST, &[])?;
    let irks = IRKS.lock().get(&index).cloned().unwrap_or_default();
    for entry in &irks {
        let mut params = Vec::with_capacity(39);
        // Peer identity address type: the stored 0/1 shape is
        // already the HCI LE address type (0 public / 1 random).
        params.push(entry.peer[0]);
        params.extend_from_slice(&entry.peer[1..7]);
        params.extend_from_slice(&entry.irk);
        params.extend_from_slice(&irk);
        issue(index, op::HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST, &params)?;
    }
    issue(index, op::HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE, &[1]).map(|_| ())
}

/// (Re-)program legacy advertising for the recorded mode, using
/// `settings` for the flags / connectable decisions (callers pass
/// the prospective bitmap so a refresh lands before the commit).
/// Mode 0 only disables. Otherwise: the random address when the
/// own address type is random, then Set Advertising Parameters
/// (§7.8.5), Set Advertising Data (§7.8.7), Set Scan Response
/// Data (§7.8.8), Set Advertise Enable (§7.8.9).
///
/// Advertising interval is an implementation choice, not a spec
/// constant: 0x0800 (1.28 s) for both min and max, the slow,
/// low-duty-cycle default a host stack wants for a mostly-idle
/// peripheral; channel map 0x07 (all three channels), filter
/// policy 0x00 (accept all). The advertising type follows
/// mgmt(7): mode 0x02 is always connectable (ADV_IND); mode 0x01
/// is connectable (ADV_IND) only when the connectable setting is
/// on, else non-connectable (ADV_NONCONN_IND) with a
/// non-resolvable random address when privacy is off and no
/// static address is in use.
fn apply_advertising_with(index: u16, settings: u32) -> Result<(), u8> {
    let mode = advertising_mode(index);
    if mode == 0 {
        return issue(index, op::HCI_LE_SET_ADVERTISING_ENABLE, &[0]).map(|_| ());
    }
    let connectable = mode == 2 || settings & SETTING_CONNECTABLE != 0;
    let adv_type = if connectable { 0x00 } else { 0x02 };
    let privacy_on = privacy_mode(index) != 0;
    let own_random = privacy_on || static_in_use(index, settings) || !connectable;
    if own_random {
        if privacy_on || static_in_use(index, settings) {
            program_random_address(index, settings)?;
        } else {
            // Non-connectable without privacy or a static address:
            // a fresh non-resolvable random address per apply.
            let addr = generate_non_resolvable(index)?;
            issue(index, op::HCI_LE_SET_RANDOM_ADDRESS, &addr)?;
            PROGRAMMED_RANDOM_ADDR.lock().insert(index, addr);
        }
    }
    let mut params = Vec::with_capacity(15);
    params.extend_from_slice(&0x0800u16.to_le_bytes());
    params.extend_from_slice(&0x0800u16.to_le_bytes());
    params.push(adv_type);
    params.push(u8::from(own_random));
    params.push(0); // peer address type: undirected
    params.extend_from_slice(&[0; 6]);
    params.push(0x07); // all advertising channels
    params.push(0); // accept all scan/connect requests
    issue(index, op::HCI_LE_SET_ADVERTISING_PARAMETERS, &params)?;
    let (adv_data, scan_rsp) = build_adv_data(index, settings);
    issue(
        index,
        op::HCI_LE_SET_ADVERTISING_DATA,
        &adv_data_param(&adv_data),
    )?;
    issue(
        index,
        op::HCI_LE_SET_SCAN_RESPONSE_DATA,
        &adv_data_param(&scan_rsp),
    )?;
    issue(index, op::HCI_LE_SET_ADVERTISING_ENABLE, &[1]).map(|_| ())
}

/// SET_ADVERTISING (0x0029): `val` 0x00/0x01/0x02 (mgmt(7)).
/// LE off → REJECTED (kernel `mgmt_le_support`); other values →
/// INVALID_PARAMS. While unpowered the mode is recorded and
/// applied on the next power-on. While powered and already in
/// the requested mode, no HCI is issued (kernel short-circuit).
/// While a discovery is running or a live LE connection exists
/// the mode is recorded with no HCI (kernel record-only
/// conditions); it is applied on the next SET_ADVERTISING or on
/// power-on. Otherwise the HCI sequence runs first and the mode
/// is recorded only on success.
fn set_advertising(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_ADVERTISING, STATUS_INVALID_INDEX);
    }
    if params.is_empty() {
        return cmd_status(index, OP_SET_ADVERTISING, STATUS_INVALID_PARAMS);
    }
    let val = params[0];
    if val > 2 {
        return cmd_status(index, OP_SET_ADVERTISING, STATUS_INVALID_PARAMS);
    }
    let settings = current_settings(index);
    if settings & SETTING_LE == 0 {
        return cmd_status(index, OP_SET_ADVERTISING, STATUS_REJECTED);
    }
    let mode = advertising_mode(index);
    if val == mode {
        return cmd_complete(
            index,
            OP_SET_ADVERTISING,
            STATUS_SUCCESS,
            &settings.to_le_bytes(),
        );
    }
    let powered = settings & SETTING_POWERED != 0;
    let record_only = !powered
        || DISCOVERING.lock().contains_key(&index)
        || crate::pump::connections(index as usize)
            .map(|conns| conns.iter().any(|c| c.le))
            .unwrap_or(false);
    if record_only {
        ADVERTISING.lock().insert(index, val);
        let new = set_setting_bit(index, SETTING_ADVERTISING, val != 0);
        narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, new));
        return cmd_complete(
            index,
            OP_SET_ADVERTISING,
            STATUS_SUCCESS,
            &new.to_le_bytes(),
        );
    }
    // Live path: run the HCI first, record only on success.
    ADVERTISING.lock().insert(index, val);
    match apply_advertising_with(index, settings) {
        Ok(()) => {
            let new = set_setting_bit(index, SETTING_ADVERTISING, val != 0);
            narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, new));
            cmd_complete(
                index,
                OP_SET_ADVERTISING,
                STATUS_SUCCESS,
                &new.to_le_bytes(),
            )
        }
        Err(status) => {
            if mode == 0 {
                ADVERTISING.lock().remove(&index);
            } else {
                ADVERTISING.lock().insert(index, mode);
            }
            cmd_status(index, OP_SET_ADVERTISING, status)
        }
    }
}

/// SET_BREDR (0x002a): `val` 0x00/0x01 (mgmt(7)). LE off →
/// REJECTED; other values → INVALID_PARAMS. Disabling while
/// powered is REJECTED; re-enabling while powered is REJECTED
/// when a static address is configured or Secure Connections is
/// on (kernel set_bredr). Disabling while unpowered also clears
/// discoverable / SSP / link-security / fast-connectable
/// (kernel). Enabling while powered writes the page-scan type
/// for the (cleared) fast-connectable state and refreshes live
/// advertising flags; the bit is recorded only on success.
fn set_bredr(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_BREDR, STATUS_INVALID_INDEX);
    }
    if params.is_empty() {
        return cmd_status(index, OP_SET_BREDR, STATUS_INVALID_PARAMS);
    }
    let val = params[0];
    if val > 1 {
        return cmd_status(index, OP_SET_BREDR, STATUS_INVALID_PARAMS);
    }
    let settings = current_settings(index);
    if settings & SETTING_LE == 0 {
        return cmd_status(index, OP_SET_BREDR, STATUS_REJECTED);
    }
    let on = val != 0;
    let bredr_on = settings & SETTING_BREDR != 0;
    if on == bredr_on {
        return cmd_complete(index, OP_SET_BREDR, STATUS_SUCCESS, &settings.to_le_bytes());
    }
    let powered = settings & SETTING_POWERED != 0;
    if !powered {
        let mut new = settings;
        if on {
            new |= SETTING_BREDR;
        } else {
            new &= !SETTING_BREDR;
            new &= !SETTING_DISCOVERABLE;
            new &= !SETTING_SSP;
            new &= !SETTING_LINK_SECURITY;
            new &= !SETTING_FAST_CONNECTABLE;
        }
        {
            let mut table = SETTINGS.lock();
            *table.entry(index).or_insert(DEFAULT_SETTINGS) = new;
        }
        narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, new));
        return cmd_complete(index, OP_SET_BREDR, STATUS_SUCCESS, &new.to_le_bytes());
    }
    if !on {
        return cmd_status(index, OP_SET_BREDR, STATUS_REJECTED);
    }
    // Re-enabling while powered: rejected with a static address
    // configured or Secure Connections on (kernel set_bredr).
    if STATIC_ADDR.lock().contains_key(&index) || settings & SETTING_SECURE_CONN != 0 {
        return cmd_status(index, OP_SET_BREDR, STATUS_REJECTED);
    }
    let new = settings | SETTING_BREDR;
    // Kernel set_bredr_sync: fast-connectable (cleared on the
    // unpowered disable) is re-written, the scan is updated and
    // the advertising data flags refresh. The scan-enable byte
    // itself is unchanged (discoverable/connectable untouched).
    let mut result = issue(
        index,
        op::HCI_WRITE_PAGE_SCAN_TYPE,
        &[u8::from(new & SETTING_FAST_CONNECTABLE != 0)],
    )
    .map(|_| ());
    if result.is_ok() && advertising_mode(index) != 0 && !DISCOVERING.lock().contains_key(&index) {
        result = apply_advertising_with(index, new);
    }
    if let Err(status) = result {
        return cmd_status(index, OP_SET_BREDR, status);
    }
    {
        let mut table = SETTINGS.lock();
        *table.entry(index).or_insert(DEFAULT_SETTINGS) = new;
    }
    narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, new));
    cmd_complete(index, OP_SET_BREDR, STATUS_SUCCESS, &new.to_le_bytes())
}

/// SET_STATIC_ADDRESS (0x002b): 6-byte address (mgmt(7)). Only
/// for LE controllers (assumed here — there is no LE-capability
/// flag in `ControllerInfo`); powered → REJECTED; BDADDR_NONE
/// (FF:FF:FF:FF:FF:FF) → INVALID_PARAMS; a non-ANY address must
/// be a static random address (two most significant bits set) or
/// INVALID_PARAMS (kernel set_static_address). BDADDR_ANY clears
/// the configured address. No HCI at set time: the address is
/// programmed at power-on. The Static Address settings bit
/// tracks whether an address is configured.
fn set_static_address(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_STATIC_ADDRESS, STATUS_INVALID_INDEX);
    }
    if params.len() < 6 {
        return cmd_status(index, OP_SET_STATIC_ADDRESS, STATUS_INVALID_PARAMS);
    }
    if current_settings(index) & SETTING_POWERED != 0 {
        return cmd_status(index, OP_SET_STATIC_ADDRESS, STATUS_REJECTED);
    }
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&params[..6]);
    if addr == [0xff; 6] {
        return cmd_status(index, OP_SET_STATIC_ADDRESS, STATUS_INVALID_PARAMS);
    }
    if addr != [0; 6] && !is_static_random(&addr) {
        return cmd_status(index, OP_SET_STATIC_ADDRESS, STATUS_INVALID_PARAMS);
    }
    let settings = if addr == [0; 6] {
        STATIC_ADDR.lock().remove(&index);
        set_setting_bit(index, SETTING_STATIC_ADDRESS, false)
    } else {
        STATIC_ADDR.lock().insert(index, addr);
        set_setting_bit(index, SETTING_STATIC_ADDRESS, true)
    };
    // A new static address invalidates any programmed random
    // address: the next power-on (or advertising apply) programs
    // the new one.
    PROGRAMMED_RANDOM_ADDR.lock().remove(&index);
    narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, settings));
    cmd_complete(
        index,
        OP_SET_STATIC_ADDRESS,
        STATUS_SUCCESS,
        &settings.to_le_bytes(),
    )
}

/// SET_PRIVACY (0x002f): `mode` (1) + local IRK (16) (mgmt(7)).
/// Modes 0x00 (off), 0x01 (privacy), 0x02 (limited privacy —
/// the identity address is exposed while bondable+discoverable
/// or during initiated pairing); other values → INVALID_PARAMS.
/// Powered → REJECTED (kernel set_privacy: privacy can only
/// change while powered off). The mode + IRK are recorded and
/// take effect at power-on (fresh RPA, resolving list,
/// address-resolution enable); mode 0x00 clears the stored IRK.
fn set_privacy(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_SET_PRIVACY, STATUS_INVALID_INDEX);
    }
    if params.len() < 17 {
        return cmd_status(index, OP_SET_PRIVACY, STATUS_INVALID_PARAMS);
    }
    let mode = params[0];
    if mode > 2 {
        return cmd_status(index, OP_SET_PRIVACY, STATUS_INVALID_PARAMS);
    }
    if current_settings(index) & SETTING_POWERED != 0 {
        return cmd_status(index, OP_SET_PRIVACY, STATUS_REJECTED);
    }
    let settings = if mode == 0 {
        PRIVACY.lock().remove(&index);
        set_setting_bit(index, SETTING_PRIVACY, false)
    } else {
        let mut irk = [0u8; 16];
        irk.copy_from_slice(&params[1..17]);
        PRIVACY.lock().insert(index, (mode, irk));
        set_setting_bit(index, SETTING_PRIVACY, true)
    };
    // A privacy change invalidates the cached RPA and any
    // programmed random address: the next power-on generates a
    // fresh RPA from the new IRK (or none, when privacy is off).
    CURRENT_RPA.lock().remove(&index);
    PROGRAMMED_RANDOM_ADDR.lock().remove(&index);
    narf_filesystem::bluetooth::publish_mgmt_event(&new_settings(index, settings));
    cmd_complete(
        index,
        OP_SET_PRIVACY,
        STATUS_SUCCESS,
        &settings.to_le_bytes(),
    )
}

/// LOAD_LONG_TERM_KEYS (0x0013): `count` (2) + `count` entries
/// of { address (6), type (1), key type (1), master (1),
/// encryption size (1), EDIV (2), Rand (8), value (16) } — 36
/// bytes each (mgmt(7)). The length must match the count exactly
/// or INVALID_PARAMS (kernel). Entries are validated like the
/// kernel (`ltk_is_valid` + key-type switch): initiator must be
/// 0/1, the address must be LE public or a static LE random, key
/// types 0x00/0x01 (unauth/auth) and 0x02/0x03 (P-256 unauth/auth)
/// are accepted, 0x04 (debug) and anything else is skipped —
/// the kernel skips invalid entries with a warning and still
/// replies success, and this does the same (there is no warning
/// channel here). Accepted keys are stored as bonds in the
/// pump's BondStore — the same store pairing fills, so a loaded
/// LTK answers a later LE LTK Request — replacing any bond for
/// the same peer. Unlike the kernel (which clears its LTK list
/// first), the load merges: clearing would drop bonds created by
/// live pairings, which the kernel's list never holds separately.
/// The encryption-size byte and the initiator/responder
/// distinction are accepted and dropped: BondStore carries
/// neither, and LTK lookup keys on address + EDIV/Rand only.
/// Usable while unpowered; a controller with no pump reports FAILED.
fn load_long_term_keys(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_LOAD_LONG_TERM_KEYS, STATUS_INVALID_INDEX);
    }
    if params.len() < 2 {
        return cmd_status(index, OP_LOAD_LONG_TERM_KEYS, STATUS_INVALID_PARAMS);
    }
    let count = u16::from_le_bytes([params[0], params[1]]) as usize;
    if params.len() != 2 + 36 * count {
        return cmd_status(index, OP_LOAD_LONG_TERM_KEYS, STATUS_INVALID_PARAMS);
    }
    for i in 0..count {
        let e = &params[2 + 36 * i..2 + 36 * (i + 1)];
        let addr_type = e[6];
        let key_type = e[7];
        let master = e[8];
        if master > 1 {
            continue;
        }
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&e[..6]);
        let peer_type = match addr_type {
            ADDR_LE_PUBLIC => 0u8,
            ADDR_LE_RANDOM => {
                if !is_static_random(&addr) {
                    continue;
                }
                1u8
            }
            _ => continue,
        };
        let authenticated = match key_type {
            0x00 => false,
            0x01 => true,
            0x02 => false,
            0x03 => true,
            _ => continue,
        };
        let mut peer = [0u8; 7];
        peer[0] = peer_type;
        peer[1..7].copy_from_slice(&addr);
        let mut ltk = [0u8; 16];
        ltk.copy_from_slice(&e[20..36]);
        let mut rand = [0u8; 8];
        rand.copy_from_slice(&e[12..20]);
        let bond = crate::bond_store::Bond {
            peer_addr: peer,
            ltk,
            ediv: u16::from_le_bytes([e[10], e[11]]),
            rand,
            authenticated,
            peer_irk: None,
            peer_identity_addr: None,
            peer_csrk: None,
        };
        if crate::pump::store_bond(index as usize, bond).is_none() {
            return cmd_status(index, OP_LOAD_LONG_TERM_KEYS, STATUS_FAILED);
        }
    }
    cmd_complete(index, OP_LOAD_LONG_TERM_KEYS, STATUS_SUCCESS, &[])
}

/// LOAD_IRKS (0x0030): `count` (2) + `count` entries of
/// { address (6), type (1), value (16) } — 23 bytes each
/// (mgmt(7)). The length must match the count exactly or
/// INVALID_PARAMS (kernel). Every entry is validated first
/// (`irk_is_valid`: LE public, or LE random with the static bits
/// set) — one invalid entry fails the whole command and nothing
/// is stored, as the kernel does. The load replaces the stored
/// list; each entry is also mirrored into an existing bond's
/// `peer_irk` where one exists. While powered with privacy on,
/// the controller copy is re-programmed too (clear + add +
/// address-resolution enable); an HCI failure there reports
/// FAILED but the stored list stands — the kernel likewise
/// stores keys host-side regardless of controller programming,
/// and power-on re-syncs the controller copy.
fn load_irks(index: u16, params: &[u8]) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, OP_LOAD_IRKS, STATUS_INVALID_INDEX);
    }
    if params.len() < 2 {
        return cmd_status(index, OP_LOAD_IRKS, STATUS_INVALID_PARAMS);
    }
    let count = u16::from_le_bytes([params[0], params[1]]) as usize;
    if params.len() != 2 + 23 * count {
        return cmd_status(index, OP_LOAD_IRKS, STATUS_INVALID_PARAMS);
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let e = &params[2 + 23 * i..2 + 23 * (i + 1)];
        let addr_type = e[6];
        let mut addr = [0u8; 6];
        addr.copy_from_slice(&e[..6]);
        let peer_type = match addr_type {
            ADDR_LE_PUBLIC => 0u8,
            ADDR_LE_RANDOM => {
                if !is_static_random(&addr) {
                    return cmd_status(index, OP_LOAD_IRKS, STATUS_INVALID_PARAMS);
                }
                1u8
            }
            _ => return cmd_status(index, OP_LOAD_IRKS, STATUS_INVALID_PARAMS),
        };
        let mut peer = [0u8; 7];
        peer[0] = peer_type;
        peer[1..7].copy_from_slice(&addr);
        let mut irk = [0u8; 16];
        irk.copy_from_slice(&e[7..23]);
        entries.push(IrkEntry { peer, irk });
    }
    IRKS.lock().insert(index, entries.clone());
    for entry in &entries {
        let _ = crate::pump::set_peer_irk(index as usize, &entry.peer, entry.irk);
    }
    if current_settings(index) & SETTING_POWERED != 0 && privacy_mode(index) != 0 {
        if let Err(status) = apply_resolving_list(index) {
            return cmd_status(index, OP_LOAD_IRKS, status);
        }
    }
    cmd_complete(index, OP_LOAD_IRKS, STATUS_SUCCESS, &[])
}

/// `MGMT_EV_NEW_SETTINGS` carrying the controller's current settings bitmap.
pub fn new_settings(index: u16, settings: u32) -> Vec<u8> {
    frame(EV_NEW_SETTINGS, index, &settings.to_le_bytes())
}

/// `MGMT_EV_DISCOVERING`: discovery type + whether discovery is
/// running (mgmt.h `mgmt_ev_discovering`).
pub fn discovering(index: u16, disc_type: u8, active: bool) -> Vec<u8> {
    frame(EV_DISCOVERING, index, &[disc_type, active as u8])
}

/// `MGMT_EV_CLASS_OF_DEV_CHANGED` carrying the 3-byte class.
pub fn class_of_dev_changed(index: u16, class: [u8; 3]) -> Vec<u8> {
    frame(EV_CLASS_OF_DEV_CHANGED, index, &class)
}

/// `MGMT_EV_LOCAL_NAME_CHANGED` carrying the 249-byte (NUL-ended)
/// name.
pub fn local_name_changed(index: u16, name: &[u8; 249]) -> Vec<u8> {
    frame(EV_LOCAL_NAME_CHANGED, index, name)
}

/// `MGMT_EV_DEVICE_UNPAIRED` for `addr` (mgmt_addr_info).
pub fn device_unpaired(index: u16, addr: &[u8; 7]) -> Vec<u8> {
    frame(EV_DEVICE_UNPAIRED, index, addr)
}

/// Whether controller `index` has an active mgmt discovery, and its
/// type byte. The pump consults this before publishing
/// DEVICE_FOUND for a scan report.
pub fn discovery_active(index: usize) -> Option<u8> {
    DISCOVERING.lock().get(&(index as u16)).copied()
}

/// Publish a `MGMT_EV_DEVICE_FOUND` for one LE advertising report,
/// when (and only when) an mgmt discovery is active on this
/// controller. `address_type` / `event_type` are the HCI LE report
/// values; the frame carries the mgmt addr_info + rssi + flags +
/// EIR (the report's advertising data, already EIR-formatted).
pub fn publish_device_found(
    index: usize,
    address_type: u8,
    address: [u8; 6],
    rssi: i8,
    event_type: u8,
    eir: &[u8],
) {
    if DISCOVERING.lock().get(&(index as u16)).is_none() {
        return;
    }
    // HCI LE report address type (0 public / 1 random) → mgmt.
    let mgmt_type = match address_type {
        0 => ADDR_LE_PUBLIC,
        _ => ADDR_LE_RANDOM,
    };
    // LE Advertising Report event types (§7.7.65.2): 0x00 ADV_IND,
    // 0x01 ADV_DIRECT_IND, 0x02 ADV_SCAN_IND, 0x03 ADV_NONCONN_IND,
    // 0x04 SCAN_RSP. Scan-ind and non-connectable reports are the
    // not-connectable ones.
    let flags = if event_type == 0x02 || event_type == 0x03 {
        DEV_FOUND_NOT_CONNECTABLE
    } else {
        0
    };
    let mut body = Vec::with_capacity(6 + 1 + 1 + 4 + 2 + eir.len());
    body.extend_from_slice(&address);
    body.push(mgmt_type);
    body.push(rssi as u8);
    body.extend_from_slice(&flags.to_le_bytes());
    body.extend_from_slice(&(eir.len() as u16).to_le_bytes());
    body.extend_from_slice(eir);
    narf_filesystem::bluetooth::publish_mgmt_event(&frame(EV_DEVICE_FOUND, index as u16, &body));
}

/// Complete a mgmt-initiated disconnect: called by the pump
/// when the Disconnection Complete for a disconnecting handle
/// lands, or when the HCI Disconnect is refused by Command
/// Status. Only a disconnect DISCONNECT started (an entry in
/// PENDING_DISCONNECT) gets a Command Complete — direct
/// `pump::disconnect` calls (e.g. UNPAIR_DEVICE disconnect=1)
/// do not. `status` is SUCCESS when the link came down, FAILED
/// when the controller refused the disconnect.
pub fn disconnect_complete(index: usize, handle: u16, status: u8) {
    let Some(addr_info) = PENDING_DISCONNECT.lock().remove(&(index as u16, handle)) else {
        return;
    };
    narf_filesystem::bluetooth::publish_mgmt_event(&cmd_complete(
        index as u16,
        OP_DISCONNECT,
        status,
        &addr_info,
    ));
}

/// Complete a mgmt-initiated pairing: called by the pump when an
/// initiator session ends. Only a pairing PAIR_DEVICE started (an
/// entry in PENDING_PAIR) gets a Command Complete — responder
/// pairings and direct `pump::smp_initiate_pairing` calls do not.
/// `status` is SUCCESS on a completed pairing, AUTH_FAILED on an
/// SMP failure, DISCONNECTED when the link died mid-pairing, and
/// CANCELLED when userspace cancelled it via CANCEL_PAIR_DEVICE
/// (issue #1528).
pub fn pairing_complete(index: usize, peer: [u8; 7], status: u8) {
    if !PENDING_PAIR.lock().remove(&(index as u16, peer)) {
        return;
    }
    // Pending pairings are LE-only (BR/EDR is rejected at
    // PAIR_DEVICE), so peer[0] is the LE address type.
    let mut data = Vec::with_capacity(7);
    data.extend_from_slice(&peer[1..7]);
    data.push(match peer[0] {
        0 => ADDR_LE_PUBLIC,
        _ => ADDR_LE_RANDOM,
    });
    narf_filesystem::bluetooth::publish_mgmt_event(&cmd_complete(
        index as u16,
        OP_PAIR_DEVICE,
        status,
        &data,
    ));
}

/// USER_CONFIRM_REQUEST event (0x000f): `addr (6) + type (1) +
/// confirm_hint (1) + value (4, LE)`. Raised when an SMP
/// session parks at Numeric Comparison — the user confirms the
/// displayed value matches the peer's, via USER_CONFIRM_REPLY,
/// or rejects it via USER_CONFIRM_NEG_REPLY. `confirm_hint` 0
/// means a full numeric comparison (not a simple Yes/No).
pub fn user_confirm_request(index: usize, peer: [u8; 7], value: u32) {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&peer[1..7]);
    data.push(if peer[0] == 0 {
        ADDR_LE_PUBLIC
    } else {
        ADDR_LE_RANDOM
    });
    data.push(0);
    data.extend_from_slice(&value.to_le_bytes());
    narf_filesystem::bluetooth::publish_mgmt_event(&frame(
        EV_USER_CONFIRM_REQUEST,
        index as u16,
        &data,
    ));
}

/// USER_PASSKEY_REQUEST event (0x0010): `addr (6) + type (1)`.
/// Raised when an SMP session parks for a typed-in passkey —
/// answered by USER_PASSKEY_REPLY (or cancelled by
/// USER_PASSKEY_NEG_REPLY).
pub fn user_passkey_request(index: usize, peer: [u8; 7]) {
    narf_filesystem::bluetooth::publish_mgmt_event(&frame(
        EV_USER_PASSKEY_REQUEST,
        index as u16,
        &addr_reply(&peer),
    ));
}

/// PASSKEY_NOTIFY event (0x0017): `addr (6) + type (1) +
/// passkey (4, LE) + entered (1)`. Informational — the session
/// generated a passkey to display on this device, and the peer
/// is typing it in. `entered` counts the digits the peer has
/// entered so far; this stack never sets the keypress bit, so
/// it is always 0.
pub fn passkey_notify(index: usize, peer: [u8; 7], passkey: u32) {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&peer[1..7]);
    data.push(if peer[0] == 0 {
        ADDR_LE_PUBLIC
    } else {
        ADDR_LE_RANDOM
    });
    data.extend_from_slice(&passkey.to_le_bytes());
    data.push(0);
    narf_filesystem::bluetooth::publish_mgmt_event(&frame(EV_PASSKEY_NOTIFY, index as u16, &data));
}

/// Handle one mgmt command frame (as received on an `HCI_CHANNEL_CONTROL`
/// socket) and return the reply frame(s) to queue back to userspace. A
/// malformed (too-short) frame yields no reply — the socket layer rejects
/// that with -EINVAL before calling here.
pub fn handle(command: &[u8]) -> Vec<Vec<u8>> {
    if command.len() < MGMT_HDR_SIZE {
        return Vec::new();
    }
    let opcode = u16::from_le_bytes([command[0], command[1]]);
    let index = u16::from_le_bytes([command[2], command[3]]);
    let len = u16::from_le_bytes([command[4], command[5]]) as usize;
    if command.len() < MGMT_HDR_SIZE + len {
        return alloc::vec![cmd_status(index, opcode, STATUS_INVALID_PARAMS)];
    }
    let params = &command[MGMT_HDR_SIZE..MGMT_HDR_SIZE + len];

    match opcode {
        OP_READ_VERSION => {
            if index != MGMT_INDEX_NONE {
                return alloc::vec![cmd_status(index, opcode, STATUS_INVALID_INDEX)];
            }
            let mut data = [0u8; 3];
            data[0] = MGMT_VERSION;
            data[1..3].copy_from_slice(&MGMT_REVISION.to_le_bytes());
            alloc::vec![cmd_complete(index, opcode, STATUS_SUCCESS, &data)]
        }
        OP_READ_COMMANDS => {
            if index != MGMT_INDEX_NONE {
                return alloc::vec![cmd_status(index, opcode, STATUS_INVALID_INDEX)];
            }
            let ops = [
                OP_READ_VERSION,
                OP_READ_COMMANDS,
                OP_READ_INDEX_LIST,
                OP_READ_INFO,
                OP_SET_POWERED,
                OP_SET_DISCOVERABLE,
                OP_SET_CONNECTABLE,
                OP_SET_FAST_CONNECTABLE,
                OP_SET_BONDABLE,
                OP_SET_LINK_SECURITY,
                OP_SET_SSP,
                OP_SET_LE,
                OP_SET_DEV_CLASS,
                OP_SET_LOCAL_NAME,
                OP_LOAD_LONG_TERM_KEYS,
                OP_DISCONNECT,
                OP_GET_CONNECTIONS,
                OP_PIN_CODE_REPLY,
                OP_PIN_CODE_NEG_REPLY,
                OP_SET_IO_CAPABILITY,
                OP_PAIR_DEVICE,
                OP_CANCEL_PAIR_DEVICE,
                OP_UNPAIR_DEVICE,
                OP_USER_CONFIRM_REPLY,
                OP_USER_CONFIRM_NEG_REPLY,
                OP_USER_PASSKEY_REPLY,
                OP_USER_PASSKEY_NEG_REPLY,
                OP_READ_LOCAL_OOB_DATA,
                OP_ADD_REMOTE_OOB_DATA,
                OP_REMOVE_REMOTE_OOB_DATA,
                OP_START_DISCOVERY,
                OP_STOP_DISCOVERY,
                OP_SET_ADVERTISING,
                OP_SET_BREDR,
                OP_SET_STATIC_ADDRESS,
                OP_SET_SCAN_PARAMS,
                OP_SET_SECURE_CONN,
                OP_SET_PRIVACY,
                OP_LOAD_IRKS,
            ];
            let events = [
                EV_CMD_COMPLETE,
                EV_CMD_STATUS,
                EV_INDEX_ADDED,
                EV_INDEX_REMOVED,
                EV_NEW_SETTINGS,
                EV_CLASS_OF_DEV_CHANGED,
                EV_LOCAL_NAME_CHANGED,
                EV_PIN_CODE_REQUEST,
                EV_USER_CONFIRM_REQUEST,
                EV_USER_PASSKEY_REQUEST,
                EV_AUTH_FAILED,
                EV_DEVICE_FOUND,
                EV_DISCOVERING,
                EV_DEVICE_UNPAIRED,
                EV_PASSKEY_NOTIFY,
            ];
            let mut data = Vec::new();
            data.extend_from_slice(&(ops.len() as u16).to_le_bytes());
            data.extend_from_slice(&(events.len() as u16).to_le_bytes());
            for op in ops {
                data.extend_from_slice(&op.to_le_bytes());
            }
            for ev in events {
                data.extend_from_slice(&ev.to_le_bytes());
            }
            alloc::vec![cmd_complete(index, opcode, STATUS_SUCCESS, &data)]
        }
        OP_READ_INDEX_LIST => {
            if index != MGMT_INDEX_NONE {
                return alloc::vec![cmd_status(index, opcode, STATUS_INVALID_INDEX)];
            }
            // Live ordinals only: a detached controller disappears
            // from the list instead of shifting later ordinals.
            let live = controller::live_indices();
            let mut data = Vec::with_capacity(2 + 2 * live.len());
            data.extend_from_slice(&(live.len() as u16).to_le_bytes());
            for i in live {
                data.extend_from_slice(&(i as u16).to_le_bytes());
            }
            alloc::vec![cmd_complete(index, opcode, STATUS_SUCCESS, &data)]
        }
        OP_READ_INFO => match controller::get_live(index as usize) {
            Some(c) => {
                let data = read_info_rp(&c.info(), current_settings(index));
                alloc::vec![cmd_complete(index, opcode, STATUS_SUCCESS, &data)]
            }
            None => alloc::vec![cmd_status(index, opcode, STATUS_INVALID_INDEX)],
        },
        OP_SET_POWERED => {
            if params.is_empty() || params[0] > 1 {
                return alloc::vec![cmd_status(index, opcode, STATUS_INVALID_PARAMS)];
            }
            match set_powered_inner(index, params[0] != 0) {
                Ok(settings) => {
                    alloc::vec![cmd_complete(
                        index,
                        opcode,
                        STATUS_SUCCESS,
                        &settings.to_le_bytes()
                    )]
                }
                Err(status) => alloc::vec![cmd_status(index, opcode, status)],
            }
        }
        OP_SET_CONNECTABLE => {
            alloc::vec![set_mode(index, opcode, params, SETTING_CONNECTABLE, 1)]
        }
        OP_SET_FAST_CONNECTABLE => {
            alloc::vec![set_mode(index, opcode, params, SETTING_FAST_CONNECTABLE, 1)]
        }
        OP_SET_BONDABLE => alloc::vec![set_mode(index, opcode, params, SETTING_BONDABLE, 1)],
        OP_SET_LINK_SECURITY => {
            alloc::vec![set_mode(index, opcode, params, SETTING_LINK_SECURITY, 1)]
        }
        OP_SET_SSP => alloc::vec![set_mode(index, opcode, params, SETTING_SSP, 1)],
        OP_SET_LE => alloc::vec![set_mode(index, opcode, params, SETTING_LE, 1)],
        OP_SET_SECURE_CONN => {
            // Valid values 0x00/0x01/0x02; 0x02 (SC-Only) is rejected
            // as NOT_SUPPORTED inside set_mode.
            alloc::vec![set_mode(index, opcode, params, SETTING_SECURE_CONN, 2)]
        }
        OP_SET_DISCOVERABLE => {
            // `val (1) + timeout (2)`: val 0x00 with a timeout, and
            // val 0x02 (limited) without one, are INVALID_PARAMS
            // (mgmt(7)); the timeout itself is accepted but never
            // enforced — see DISCOV_TIMEOUT.
            if params.len() < 3 {
                return alloc::vec![cmd_status(index, opcode, STATUS_INVALID_PARAMS)];
            }
            let timeout = u16::from_le_bytes([params[1], params[2]]);
            if (params[0] == 0 && timeout != 0) || (params[0] == 2 && timeout == 0) {
                return alloc::vec![cmd_status(index, opcode, STATUS_INVALID_PARAMS)];
            }
            alloc::vec![set_mode(index, opcode, params, SETTING_DISCOVERABLE, 2)]
        }
        OP_SET_DEV_CLASS => alloc::vec![set_dev_class(index, params)],
        OP_SET_LOCAL_NAME => alloc::vec![set_local_name(index, params)],
        OP_SET_ADVERTISING => alloc::vec![set_advertising(index, params)],
        OP_SET_BREDR => alloc::vec![set_bredr(index, params)],
        OP_SET_STATIC_ADDRESS => alloc::vec![set_static_address(index, params)],
        OP_SET_PRIVACY => alloc::vec![set_privacy(index, params)],
        OP_LOAD_LONG_TERM_KEYS => alloc::vec![load_long_term_keys(index, params)],
        OP_LOAD_IRKS => alloc::vec![load_irks(index, params)],
        OP_SET_SCAN_PARAMS => alloc::vec![set_scan_params(index, params)],
        OP_START_DISCOVERY => alloc::vec![start_discovery(index, params)],
        OP_STOP_DISCOVERY => alloc::vec![stop_discovery(index, params)],
        OP_DISCONNECT => disconnect_device(index, params),
        OP_GET_CONNECTIONS => alloc::vec![get_connections(index)],
        OP_PIN_CODE_REPLY => alloc::vec![pin_code_reply(index, opcode, params)],
        OP_PIN_CODE_NEG_REPLY => alloc::vec![pin_code_reply(index, opcode, params)],
        OP_SET_IO_CAPABILITY => alloc::vec![set_io_capability(index, params)],
        OP_PAIR_DEVICE => alloc::vec![pair_device(index, params)],
        OP_CANCEL_PAIR_DEVICE => alloc::vec![cancel_pair_device(index, params)],
        OP_UNPAIR_DEVICE => alloc::vec![unpair_device(index, params)],
        OP_USER_CONFIRM_REPLY => alloc::vec![user_confirm_reply(index, opcode, params)],
        OP_USER_CONFIRM_NEG_REPLY => alloc::vec![user_confirm_reply(index, opcode, params)],
        OP_USER_PASSKEY_REPLY => alloc::vec![user_passkey_reply(index, opcode, params)],
        OP_USER_PASSKEY_NEG_REPLY => alloc::vec![user_passkey_reply(index, opcode, params)],
        OP_READ_LOCAL_OOB_DATA => alloc::vec![read_local_oob_data(index)],
        OP_ADD_REMOTE_OOB_DATA => alloc::vec![add_remote_oob_data(index, params)],
        OP_REMOVE_REMOTE_OOB_DATA => alloc::vec![remove_remote_oob_data(index, params)],
        _ => alloc::vec![cmd_status(index, opcode, STATUS_UNKNOWN_COMMAND)],
    }
}

/// Whether controller `index` is currently powered (mgmt POWERED setting).
/// Used by the legacy HCIGETDEVINFO ioctl to report the HCI_UP flag.
///
/// Truthful, not bitmap-only (#820): the `POWERED` setting bit is the
/// *requested* state; the controller is actually powered only when it
/// is not parked for a power reason (mgmt power-off or system
/// suspend — see `crate::pm`). A runtime (USB autosuspend) park does
/// not clear this: Linux keeps `HCI_UP` across runtime suspend.
pub fn is_powered(index: u16) -> bool {
    current_settings(index) & SETTING_POWERED != 0 && !crate::pm::parked_for_power(index as usize)
}

/// Apply the mgmt power state to the pump park flags: power-off
/// parks the controller (its pump stops touching the transport),
/// power-on clears the mgmt park. A system-suspend park is
/// independent and is not cleared here.
fn apply_powered(index: u16, on: bool) {
    if on {
        crate::pm::unpark_mgmt(index as usize);
    } else {
        crate::pm::park_mgmt(index as usize);
    }
}

/// Set controller `index`'s powered setting (the legacy HCIDEVUP/HCIDEVDOWN
/// ioctls map onto the same state as mgmt SET_POWERED). Returns
/// false for an unknown index or a failed transition — the caller
/// (HCIDEVUP) reports that as an ioctl error instead of claiming
/// the controller is up.
pub fn set_powered(index: u16, on: bool) -> bool {
    set_powered_inner(index, on).is_ok()
}

/// Forget controller `index`'s settings on detach, so a later
/// controller reusing the ordinal starts from the defaults instead
/// of inheriting the detached controller's POWERED / discoverable
/// state. Called by [`controller::unregister_controller`].
pub fn forget_settings(index: u16) {
    SETTINGS.lock().remove(&index);
    ADVERTISING.lock().remove(&index);
    STATIC_ADDR.lock().remove(&index);
    PRIVACY.lock().remove(&index);
    IRKS.lock().remove(&index);
    CURRENT_RPA.lock().remove(&index);
    PROGRAMMED_RANDOM_ADDR.lock().remove(&index);
}

/// `MGMT_EV_INDEX_ADDED` for a newly-registered controller (no parameters).
pub fn index_added(index: u16) -> Vec<u8> {
    frame(EV_INDEX_ADDED, index, &[])
}

/// `MGMT_EV_INDEX_REMOVED` for a removed controller.
pub fn index_removed(index: u16) -> Vec<u8> {
    frame(EV_INDEX_REMOVED, index, &[])
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::event::EventCode;
    use crate::hci::Event;
    use crate::transport::LoopbackTransport;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn mgmt_cmd(opcode: u16, index: u16, params: &[u8]) -> Vec<u8> {
        frame(opcode, index, params)
    }

    /// Command Complete event for `opcode` (`ret` follows the
    /// status byte, as on the wire).
    fn cc(opcode: u16, status: u8, ret: &[u8]) -> Event {
        let mut params = alloc::vec![0x01u8];
        params.extend_from_slice(&opcode.to_le_bytes());
        params.push(status);
        params.extend_from_slice(ret);
        Event {
            code: EventCode::CommandComplete as u8,
            params,
        }
    }

    /// Command Status event for `opcode` (`status`, 1 Num_HCI_
    /// Command_Packets, opcode LE) — the HCI_Disconnect (§7.1.6)
    /// response shape, built from the spec, not from impl
    /// constants.
    fn command_status_event(opcode: u16, status: u8) -> Event {
        Event {
            code: EventCode::CommandStatus as u8,
            params: alloc::vec![status, 0x01, (opcode & 0xFF) as u8, (opcode >> 8) as u8],
        }
    }

    /// Enqueue the Command Completes a power-on consumes, in order
    /// (Reset, Set Event Mask, identity, then the six setting
    /// writes). The identity is re-read (`rewrite_* = false`,
    /// `name`/`class` are what the reads return) or re-written
    /// (`rewrite_* = true`, the write's CC is enqueued instead)
    /// depending on whether userspace set it.
    fn enqueue_power_on_ccs(
        lt: &LoopbackTransport,
        name: &[u8; 248],
        class: &[u8; 3],
        rewrite_name: bool,
        rewrite_class: bool,
    ) {
        lt.enqueue_event(cc(op::HCI_RESET, 0, &[]));
        lt.enqueue_event(cc(op::HCI_SET_EVENT_MASK, 0, &[]));
        if rewrite_name {
            lt.enqueue_event(cc(op::HCI_WRITE_LOCAL_NAME, 0, &[]));
        } else {
            lt.enqueue_event(cc(op::HCI_READ_LOCAL_NAME, 0, name));
        }
        if rewrite_class {
            lt.enqueue_event(cc(op::HCI_WRITE_CLASS_OF_DEVICE, 0, &[]));
        } else {
            lt.enqueue_event(cc(op::HCI_READ_CLASS_OF_DEVICE, 0, class));
        }
        lt.enqueue_event(cc(op::HCI_WRITE_SCAN_ENABLE, 0, &[]));
        lt.enqueue_event(cc(op::HCI_WRITE_AUTHENTICATION_ENABLE, 0, &[]));
        lt.enqueue_event(cc(op::HCI_WRITE_SIMPLE_PAIRING_MODE, 0, &[]));
        lt.enqueue_event(cc(op::HCI_WRITE_LE_HOST_SUPPORT, 0, &[]));
        lt.enqueue_event(cc(op::HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT, 0, &[]));
        lt.enqueue_event(cc(op::HCI_WRITE_PAGE_SCAN_TYPE, 0, &[]));
    }

    /// Enqueue the Command Complete a power-off consumes (the
    /// best-effort Write_Scan_Enable quiesce).
    fn enqueue_power_off_cc(lt: &LoopbackTransport) {
        lt.enqueue_event(cc(op::HCI_WRITE_SCAN_ENABLE, 0, &[]));
    }

    /// Fresh controller + mgmt state for a fixture: registers `info`
    /// on a LoopbackTransport and returns the transport (for
    /// scripting CCs and reading sent commands) and the mgmt index.
    /// The pump is reset too, so the slot `register_ready_transport`
    /// creates is fresh.
    fn setup_controller(info: controller::ControllerInfo) -> (Arc<LoopbackTransport>, u16) {
        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        crate::pump::__test_reset();
        __test_reset();
        CAPTURED.lock().clear();
        let lb = Arc::new(LoopbackTransport::new("mgmt-fixture"));
        let transport: Arc<dyn crate::transport::HciTransport> = lb.clone();
        crate::transport::register(transport.clone());
        let index = controller::register_ready_transport(transport, info) as u16;
        (lb, index)
    }

    fn cleanup_mgmt() {
        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        crate::pump::__test_reset();
        __test_reset();
        CAPTURED.lock().clear();
    }

    /// Power `index` on (enqueueing the CCs first) and check the
    /// reply is CMD_COMPLETE/SUCCESS with POWERED set.
    fn power_on(
        lt: &LoopbackTransport,
        index: u16,
        name: &[u8; 248],
        class: &[u8; 3],
        rewrite_name: bool,
        rewrite_class: bool,
    ) -> bool {
        enqueue_power_on_ccs(lt, name, class, rewrite_name, rewrite_class);
        let r = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        is_cmd_complete(&r, OP_SET_POWERED, STATUS_SUCCESS)
            && u32::from_le_bytes([r[0][9], r[0][10], r[0][11], r[0][12]]) & SETTING_POWERED != 0
    }

    /// True when `reply` is a single CMD_COMPLETE for `opcode` with
    /// `status`.
    fn is_cmd_complete(reply: &[Vec<u8>], opcode: u16, status: u8) -> bool {
        reply.len() == 1
            && reply[0].len() >= 9
            && u16::from_le_bytes([reply[0][0], reply[0][1]]) == EV_CMD_COMPLETE
            && u16::from_le_bytes([reply[0][6], reply[0][7]]) == opcode
            && reply[0][8] == status
    }

    /// True when `reply` is a single CMD_STATUS for `opcode` with
    /// `status`.
    fn is_cmd_status(reply: &[Vec<u8>], opcode: u16, status: u8) -> bool {
        reply.len() == 1
            && reply[0].len() >= 9
            && u16::from_le_bytes([reply[0][0], reply[0][1]]) == EV_CMD_STATUS
            && u16::from_le_bytes([reply[0][6], reply[0][7]]) == opcode
            && reply[0][8] == status
    }

    /// LE Connection Complete (LeMeta 0x01) for `peer`, role
    /// Peripheral (we accepted) — the pump tracks it as an LE
    /// connection.
    fn le_conn_complete_event(handle: u16, peer: [u8; 6]) -> Event {
        let mut params = alloc::vec![0x01, 0x00];
        params.extend_from_slice(&handle.to_le_bytes());
        params.push(0x01); // role: Peripheral
        params.push(0x00); // peer address type: public
        params.extend_from_slice(&peer);
        params.extend_from_slice(&0x0028u16.to_le_bytes());
        params.extend_from_slice(&0u16.to_le_bytes());
        params.extend_from_slice(&0x01F4u16.to_le_bytes());
        params.push(0x00); // central clock accuracy
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    /// Disconnection Complete (§7.7.5): status, handle, reason
    /// (0x13 Remote User Terminated Connection).
    fn disconnection_complete_event(handle: u16) -> Event {
        Event {
            code: EventCode::DisconnectionComplete as u8,
            params: alloc::vec![0x00, (handle & 0xFF) as u8, (handle >> 8) as u8, 0x13],
        }
    }

    /// LE Advertising Report (LeMeta 0x02) with one ADV_IND report.
    fn le_advertising_report_event(peer: [u8; 6], data: &[u8], rssi: i8) -> Event {
        let mut params = alloc::vec![
            crate::event::LeSubevent::AdvertisingReport as u8,
            0x01, // num_reports
            0x00, // event_type: ADV_IND
            0x00, // address_type: public
        ];
        params.extend_from_slice(&peer);
        params.push(data.len() as u8);
        params.extend_from_slice(data);
        params.push(rssi as u8);
        Event {
            code: EventCode::LeMeta as u8,
            params,
        }
    }

    fn smoke_mgmt_read_version() -> TestResult {
        let replies = handle(&mgmt_cmd(OP_READ_VERSION, MGMT_INDEX_NONE, &[]));
        let r = &replies[0];
        // CMD_COMPLETE(index NONE) wrapping READ_VERSION, status 0, {ver, rev}.
        if u16::from_le_bytes([r[0], r[1]]) != EV_CMD_COMPLETE
            || u16::from_le_bytes([r[2], r[3]]) != MGMT_INDEX_NONE
            || u16::from_le_bytes([r[6], r[7]]) != OP_READ_VERSION
            || r[8] != STATUS_SUCCESS
            || r[9] != MGMT_VERSION
        {
            return TestResult::Fail("READ_VERSION reply shape mismatch");
        }
        // Wrong index on an adapter-independent command → INVALID_INDEX status.
        let bad = handle(&mgmt_cmd(OP_READ_VERSION, 0, &[]));
        if u16::from_le_bytes([bad[0][0], bad[0][1]]) != EV_CMD_STATUS
            || bad[0][8] != STATUS_INVALID_INDEX
        {
            return TestResult::Fail("READ_VERSION with an index must be INVALID_INDEX");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_read_version);

    fn smoke_mgmt_unknown_command_and_index_list() -> TestResult {
        // READ_INDEX_LIST: count matches the controller registry.
        let replies = handle(&mgmt_cmd(OP_READ_INDEX_LIST, MGMT_INDEX_NONE, &[]));
        let r = &replies[0];
        if u16::from_le_bytes([r[6], r[7]]) != OP_READ_INDEX_LIST || r[8] != STATUS_SUCCESS {
            return TestResult::Fail("READ_INDEX_LIST not CMD_COMPLETE/success");
        }
        let count = u16::from_le_bytes([r[9], r[10]]) as usize;
        if count != controller::controller_count() {
            return TestResult::Fail("READ_INDEX_LIST count mismatch");
        }
        // READ_INFO for a non-existent index → INVALID_INDEX.
        let info = handle(&mgmt_cmd(OP_READ_INFO, 0x00ff, &[]));
        if u16::from_le_bytes([info[0][0], info[0][1]]) != EV_CMD_STATUS
            || info[0][8] != STATUS_INVALID_INDEX
        {
            return TestResult::Fail("READ_INFO bad index must be INVALID_INDEX");
        }
        // An unknown opcode → UNKNOWN_COMMAND status.
        let unknown = handle(&mgmt_cmd(0x7fff, MGMT_INDEX_NONE, &[]));
        if u16::from_le_bytes([unknown[0][0], unknown[0][1]]) != EV_CMD_STATUS
            || unknown[0][8] != STATUS_UNKNOWN_COMMAND
        {
            return TestResult::Fail("unknown opcode must be UNKNOWN_COMMAND");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_unknown_command_and_index_list);

    fn smoke_mgmt_set_powered_toggles_settings() -> TestResult {
        use crate::transport::LoopbackTransport;
        use alloc::sync::Arc;

        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        crate::pump::__test_reset();
        __test_reset();

        let lb = Arc::new(LoopbackTransport::new("mgmt-set"));
        let transport: Arc<dyn crate::transport::HciTransport> = lb.clone();
        crate::transport::register(transport.clone());
        let index =
            controller::register_ready_transport(transport, controller::ControllerInfo::default())
                as u16;

        let cleanup = || {
            crate::transport::__test_reset();
            controller::__test_reset_controllers();
            crate::pump::__test_reset();
            __test_reset();
        };

        // SET_POWERED(1) → CMD_COMPLETE carrying the new settings with POWERED.
        // Power-on issues real HCI now (issue #815): the CCs are
        // scripted first (identity re-reads return zeros, matching
        // the default ControllerInfo).
        enqueue_power_on_ccs(&lb, &[0u8; 248], &[0u8; 3], false, false);
        let on = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        let r = &on[0];
        let powered_on = u16::from_le_bytes([r[0], r[1]]) == EV_CMD_COMPLETE
            && u16::from_le_bytes([r[6], r[7]]) == OP_SET_POWERED
            && r[8] == STATUS_SUCCESS
            && u32::from_le_bytes([r[9], r[10], r[11], r[12]]) & SETTING_POWERED != 0;

        // READ_INFO current_settings (offset 22) reflects POWERED.
        let info = handle(&mgmt_cmd(OP_READ_INFO, index, &[]));
        let ib = &info[0];
        let current = u32::from_le_bytes([ib[22], ib[23], ib[24], ib[25]]);
        let info_powered = current & SETTING_POWERED != 0;

        // SET_POWERED(0) clears it.
        enqueue_power_off_cc(&lb);
        let off = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let o = &off[0];
        let powered_off = u32::from_le_bytes([o[9], o[10], o[11], o[12]]) & SETTING_POWERED == 0;

        // An out-of-range mode value is INVALID_PARAMS.
        let bad = handle(&mgmt_cmd(OP_SET_POWERED, index, &[5]));
        let bad_params = u16::from_le_bytes([bad[0][0], bad[0][1]]) == EV_CMD_STATUS
            && bad[0][8] == STATUS_INVALID_PARAMS;

        cleanup();

        if !powered_on {
            return TestResult::Fail("SET_POWERED(1) did not set POWERED in the reply");
        }
        if !info_powered {
            return TestResult::Fail("READ_INFO current_settings did not reflect POWERED");
        }
        if !powered_off {
            return TestResult::Fail("SET_POWERED(0) did not clear POWERED");
        }
        if !bad_params {
            return TestResult::Fail("SET_POWERED with a bad value was not INVALID_PARAMS");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_set_powered_toggles_settings);

    // #820: `is_powered` is truthful, not bitmap-only. A system
    // suspend clears the powered report even though the mgmt
    // POWERED bit stays set; a resume restores it. Mgmt
    // power-off parks the pump and clears the report; power-on
    // unparks. A runtime (autosuspend) park leaves HCI_UP alone.
    fn smoke_mgmt_powered_is_truthful_across_parks() -> TestResult {
        use crate::transport::LoopbackTransport;
        use alloc::sync::Arc;

        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        SETTINGS.lock().clear();
        crate::pm::__reset_for_test();

        let transport: Arc<dyn crate::transport::HciTransport> =
            Arc::new(LoopbackTransport::new("mgmt-truthful"));
        crate::transport::register(transport.clone());
        let index =
            controller::register_ready_transport(transport, controller::ControllerInfo::default())
                as u16;

        let cleanup = || {
            crate::transport::__test_reset();
            controller::__test_reset_controllers();
            SETTINGS.lock().clear();
            crate::pm::__reset_for_test();
        };

        // Fresh controller: not powered (default settings), unparked.
        if is_powered(index) || crate::pm::is_parked(index as usize) {
            cleanup();
            return TestResult::Fail("fresh controller reads powered or parked");
        }
        // SET_POWERED(1) → powered and unparked.
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        if !is_powered(index) || crate::pm::is_parked(index as usize) {
            cleanup();
            return TestResult::Fail("SET_POWERED(1) did not power the controller");
        }
        // System suspend: the POWERED bit stays set, but the
        // truthful report clears while the pump is parked.
        crate::pm::suspend_controller(index as usize);
        if is_powered(index) || !crate::pm::parked_for_power(index as usize) {
            cleanup();
            return TestResult::Fail("system suspend did not clear the powered report");
        }
        crate::pm::resume_controller(index as usize);
        if !is_powered(index) {
            cleanup();
            return TestResult::Fail("system resume did not restore the powered report");
        }
        // Runtime (autosuspend) park: HCI_UP stays up.
        crate::pm::park_autosuspend(index as usize);
        if !is_powered(index) || !crate::pm::is_runtime_suspended(index as usize) {
            cleanup();
            return TestResult::Fail("autosuspend park cleared HCI_UP");
        }
        crate::pm::unpark_autosuspend(index as usize);
        // SET_POWERED(0) → not powered, pump parked.
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        if is_powered(index) || !crate::pm::is_parked(index as usize) {
            cleanup();
            return TestResult::Fail("SET_POWERED(0) did not park the controller");
        }
        // Power back on → powered, unparked.
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        if !is_powered(index) || crate::pm::is_parked(index as usize) {
            cleanup();
            return TestResult::Fail("SET_POWERED(1) did not unpark the controller");
        }
        cleanup();
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/mgmt",
        smoke_mgmt_powered_is_truthful_across_parks
    );

    static CAPTURED: narf_lib::sync::IrqSafeSpinLock<Vec<Vec<u8>>> =
        narf_lib::sync::IrqSafeSpinLock::new(Vec::new());
    fn capture_sink(event: &[u8]) {
        CAPTURED.lock().push(event.to_vec());
    }

    fn smoke_mgmt_event_fanout() -> TestResult {
        use crate::transport::LoopbackTransport;
        use alloc::sync::Arc;

        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        crate::pump::__test_reset();
        __test_reset();
        CAPTURED.lock().clear();
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);

        // Registering a controller publishes MGMT_EV_INDEX_ADDED.
        let lb = Arc::new(LoopbackTransport::new("mgmt-ev"));
        let transport: Arc<dyn crate::transport::HciTransport> = lb.clone();
        crate::transport::register(transport.clone());
        let index =
            controller::register_ready_transport(transport, controller::ControllerInfo::default())
                as u16;
        let saw_index_added = CAPTURED.lock().iter().any(|e| {
            e.len() >= 6
                && u16::from_le_bytes([e[0], e[1]]) == EV_INDEX_ADDED
                && u16::from_le_bytes([e[2], e[3]]) == index
        });

        // SET_POWERED publishes MGMT_EV_NEW_SETTINGS with the POWERED bit.
        // (Power-on issues real HCI now: script its CCs first.)
        CAPTURED.lock().clear();
        enqueue_power_on_ccs(&lb, &[0u8; 248], &[0u8; 3], false, false);
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        let saw_new_settings = CAPTURED.lock().iter().any(|e| {
            e.len() >= 10
                && u16::from_le_bytes([e[0], e[1]]) == EV_NEW_SETTINGS
                && u16::from_le_bytes([e[2], e[3]]) == index
                && u32::from_le_bytes([e[6], e[7], e[8], e[9]]) & SETTING_POWERED != 0
        });

        // Restore the production sink and clean up.
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        crate::transport::__test_reset();
        controller::__test_reset_controllers();
        crate::pump::__test_reset();
        __test_reset();

        if !saw_index_added {
            return TestResult::Fail("INDEX_ADDED was not published on controller registration");
        }
        if !saw_new_settings {
            return TestResult::Fail("NEW_SETTINGS was not published on SET_POWERED");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_event_fanout);

    /// #815: READ_INFO reports the controller's real identity — the
    /// dev_class and name the bring-up read (or userspace wrote),
    /// not zeros. A controller that never learned a name reports
    /// zeros: truthful, never fabricated.
    fn smoke_mgmt_read_info_real_identity() -> TestResult {
        let mut name = [0u8; 248];
        name[..9].copy_from_slice(b"narf-mgmt");
        let mut short = [0u8; 10];
        short[..4].copy_from_slice(b"narf");
        let info = controller::ControllerInfo {
            bd_addr: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            dev_class: [0x04, 0x0C, 0x02],
            local_name: name,
            short_name: short,
            ..controller::ControllerInfo::default()
        };
        let (_lt, index) = setup_controller(info);
        let r = handle(&mgmt_cmd(OP_READ_INFO, index, &[]));
        let f = &r[0];
        // Frame: [ev(2), index(2), len(2), opcode(2), status(1),
        // bd_addr(6), version(1), manufacturer(2), supported(4),
        // current(4), dev_class(3), name(249), short_name(11)].
        let ok = is_cmd_complete(&r, OP_READ_INFO, STATUS_SUCCESS)
            && f[9..15] == [0x11, 0x22, 0x33, 0x44, 0x55, 0x66][..]
            && f[26..29] == [0x04, 0x0C, 0x02][..]
            && f[29..38] == b"narf-mgmt"[..]
            && f[278..282] == b"narf"[..];
        let (_lt2, index2) = setup_controller(controller::ControllerInfo::default());
        let r2 = handle(&mgmt_cmd(OP_READ_INFO, index2, &[]));
        let g = &r2[0];
        let zero_ok = g[26..29] == [0, 0, 0][..] && g[29..278].iter().all(|b| *b == 0);
        cleanup_mgmt();
        if !ok {
            return TestResult::Fail("READ_INFO did not report the real dev_class/name");
        }
        if !zero_ok {
            return TestResult::Fail("READ_INFO on a default controller was not zeroed");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_read_info_real_identity);

    /// #815: set-mode ops issue their HCI commands and record the
    /// setting only once the controller accepts it; a failed HCI
    /// write leaves the bitmap unchanged. While unpowered a setting
    /// is recorded with no HCI and programmed on the next power-on.
    fn smoke_mgmt_set_mode_issues_hci() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        // SET_CONNECTABLE(1) → WRITE_SCAN_ENABLE [0x02] (page only).
        let r = handle(&mgmt_cmd(OP_SET_CONNECTABLE, index, &[1]));
        let conn_ok = is_cmd_complete(&r, OP_SET_CONNECTABLE, STATUS_SUCCESS);
        let scan_conn = lt
            .sent_commands()
            .last()
            .map(|c| c.opcode == op::HCI_WRITE_SCAN_ENABLE && c.params == [0x02])
            .unwrap_or(false);
        // SET_SSP(1) → WRITE_SIMPLE_PAIRING_MODE [0x01].
        let r = handle(&mgmt_cmd(OP_SET_SSP, index, &[1]));
        let ssp_ok = is_cmd_complete(&r, OP_SET_SSP, STATUS_SUCCESS);
        let ssp_sent = lt
            .sent_commands()
            .last()
            .map(|c| c.opcode == op::HCI_WRITE_SIMPLE_PAIRING_MODE && c.params == [0x01])
            .unwrap_or(false);
        // SET_DISCOVERABLE(1, timeout 0) → WRITE_SCAN_ENABLE [0x03].
        let r = handle(&mgmt_cmd(OP_SET_DISCOVERABLE, index, &[1, 0, 0]));
        let disc_ok = is_cmd_complete(&r, OP_SET_DISCOVERABLE, STATUS_SUCCESS);
        let scan_both = lt
            .sent_commands()
            .last()
            .map(|c| c.opcode == op::HCI_WRITE_SCAN_ENABLE && c.params == [0x03])
            .unwrap_or(false);
        // SET_CONNECTABLE(0) also switches discoverable off:
        // WRITE_SCAN_ENABLE [0x00].
        let r = handle(&mgmt_cmd(OP_SET_CONNECTABLE, index, &[0]));
        let conn_off_ok = is_cmd_complete(&r, OP_SET_CONNECTABLE, STATUS_SUCCESS);
        let scan_none = lt
            .sent_commands()
            .last()
            .map(|c| c.opcode == op::HCI_WRITE_SCAN_ENABLE && c.params == [0x00])
            .unwrap_or(false);
        // HCI failure: a refused Write_Authentication_Enable leaves
        // LINK_SECURITY clear in the bitmap.
        lt.enqueue_event(cc(op::HCI_WRITE_AUTHENTICATION_ENABLE, 0x0C, &[]));
        let bad = handle(&mgmt_cmd(OP_SET_LINK_SECURITY, index, &[1]));
        let fail_ok = is_cmd_status(&bad, OP_SET_LINK_SECURITY, STATUS_FAILED);
        let info = handle(&mgmt_cmd(OP_READ_INFO, index, &[]));
        let current = u32::from_le_bytes([info[0][22], info[0][23], info[0][24], info[0][25]]);
        let bit_unchanged = current & SETTING_LINK_SECURITY == 0;
        // Unpowered: SET_SSP is recorded with no HCI, and the
        // recorded value is programmed on the next power-on.
        enqueue_power_off_cc(&lt);
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let sent_before = lt.sent_commands().len();
        let r = handle(&mgmt_cmd(OP_SET_SSP, index, &[1]));
        let recorded = is_cmd_complete(&r, OP_SET_SSP, STATUS_SUCCESS)
            && lt.sent_commands().len() == sent_before;
        let powered2 = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let ssp_applied = lt.sent_commands()[sent_before..]
            .iter()
            .any(|c| c.opcode == op::HCI_WRITE_SIMPLE_PAIRING_MODE && c.params == [0x01]);
        cleanup_mgmt();
        if !powered || !powered2 {
            return TestResult::Fail("power-on failed");
        }
        if !conn_ok || !scan_conn {
            return TestResult::Fail("SET_CONNECTABLE did not issue WRITE_SCAN_ENABLE [0x02]");
        }
        if !ssp_ok || !ssp_sent {
            return TestResult::Fail("SET_SSP did not issue WRITE_SIMPLE_PAIRING_MODE [0x01]");
        }
        if !disc_ok || !scan_both {
            return TestResult::Fail("SET_DISCOVERABLE did not issue WRITE_SCAN_ENABLE [0x03]");
        }
        if !conn_off_ok || !scan_none {
            return TestResult::Fail("SET_CONNECTABLE(0) did not clear discoverable (scan [0x00])");
        }
        if !fail_ok || !bit_unchanged {
            return TestResult::Fail("failed HCI write changed the settings bitmap");
        }
        if !recorded {
            return TestResult::Fail("unpowered SET_SSP issued HCI instead of recording");
        }
        if !ssp_applied {
            return TestResult::Fail("recorded SSP was not programmed on power-on");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_set_mode_issues_hci);

    /// #815: settings recorded while unpowered are programmed on
    /// power-on, in order; discoverable while connectable is off
    /// is REJECTED; a power-on whose Reset is refused fails closed
    /// (POWERED stays off).
    fn smoke_mgmt_set_powered_reapplies_settings() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let rej = handle(&mgmt_cmd(OP_SET_DISCOVERABLE, index, &[1, 0, 0]));
        let rejected = is_cmd_status(&rej, OP_SET_DISCOVERABLE, STATUS_REJECTED);
        let _ = handle(&mgmt_cmd(OP_SET_CONNECTABLE, index, &[1]));
        let _ = handle(&mgmt_cmd(OP_SET_DISCOVERABLE, index, &[1, 0, 0]));
        let _ = handle(&mgmt_cmd(OP_SET_SSP, index, &[1]));
        let _ = handle(&mgmt_cmd(OP_SET_LINK_SECURITY, index, &[1]));
        let recorded_quiet = lt.sent_commands().is_empty();
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let sent = lt.sent_commands();
        let want: [(u16, &[u8]); 10] = [
            (op::HCI_RESET, &[]),
            (
                op::HCI_SET_EVENT_MASK,
                &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x00, 0x00],
            ),
            (op::HCI_READ_LOCAL_NAME, &[]),
            (op::HCI_READ_CLASS_OF_DEVICE, &[]),
            (op::HCI_WRITE_SCAN_ENABLE, &[0x03]),
            (op::HCI_WRITE_AUTHENTICATION_ENABLE, &[0x01]),
            (op::HCI_WRITE_SIMPLE_PAIRING_MODE, &[0x01]),
            (op::HCI_WRITE_LE_HOST_SUPPORT, &[0x01, 0x00]),
            (op::HCI_WRITE_SECURE_CONNECTIONS_HOST_SUPPORT, &[0x00]),
            (op::HCI_WRITE_PAGE_SCAN_TYPE, &[0x00]),
        ];
        let order_ok = sent.len() == want.len()
            && sent
                .iter()
                .zip(want.iter())
                .all(|(c, (o, p))| c.opcode == *o && c.params.as_slice() == *p);
        cleanup_mgmt();
        let (lt2, index2) = setup_controller(controller::ControllerInfo::default());
        lt2.enqueue_event(cc(op::HCI_RESET, 0x0C, &[]));
        let failed = handle(&mgmt_cmd(OP_SET_POWERED, index2, &[1]));
        let failed_closed = is_cmd_status(&failed, OP_SET_POWERED, STATUS_FAILED);
        let info = handle(&mgmt_cmd(OP_READ_INFO, index2, &[]));
        let current = u32::from_le_bytes([info[0][22], info[0][23], info[0][24], info[0][25]]);
        let still_off = current & SETTING_POWERED == 0;
        cleanup_mgmt();
        if !rejected {
            return TestResult::Fail("SET_DISCOVERABLE with connectable off was not REJECTED");
        }
        if !recorded_quiet {
            return TestResult::Fail("unpowered settings issued HCI");
        }
        if !powered || !order_ok {
            return TestResult::Fail("power-on did not program the recorded settings in order");
        }
        if !failed_closed || !still_off {
            return TestResult::Fail("refused power-on did not fail closed");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_set_powered_reapplies_settings);

    /// #815: SET_DEV_CLASS / SET_LOCAL_NAME write the controller
    /// while powered (announcing the change), store with no HCI
    /// while unpowered (zeroed class reply), and are re-written —
    /// not re-read — on the next power-on.
    fn smoke_mgmt_set_dev_class_and_local_name() -> TestResult {
        let mut name = [0u8; 248];
        name[..9].copy_from_slice(b"narf-mgmt");
        let info = controller::ControllerInfo {
            dev_class: [0x04, 0x0C, 0x02],
            local_name: name,
            ..controller::ControllerInfo::default()
        };
        let (lt, index) = setup_controller(info);
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        let powered = power_on(&lt, index, &name, &[0x04, 0x0C, 0x02], false, false);
        CAPTURED.lock().clear();
        let r = handle(&mgmt_cmd(OP_SET_DEV_CLASS, index, &[0x0C, 0x02]));
        let class_ok = is_cmd_complete(&r, OP_SET_DEV_CLASS, STATUS_SUCCESS)
            && r[0][9..12] == [0x04, 0x0C, 0x02][..];
        let wrote_class = lt
            .sent_commands()
            .iter()
            .any(|c| c.opcode == op::HCI_WRITE_CLASS_OF_DEVICE && c.params == [0x04, 0x0C, 0x02]);
        let announced_class = CAPTURED.lock().iter().any(|e| {
            e.len() >= 9
                && u16::from_le_bytes([e[0], e[1]]) == EV_CLASS_OF_DEV_CHANGED
                && e[6..9] == [0x04, 0x0C, 0x02][..]
        });
        let mut params = [0u8; 260];
        params[..12].copy_from_slice(b"narf-renamed");
        params[249..253].copy_from_slice(b"narf");
        CAPTURED.lock().clear();
        let r = handle(&mgmt_cmd(OP_SET_LOCAL_NAME, index, &params));
        let name_ok = is_cmd_complete(&r, OP_SET_LOCAL_NAME, STATUS_SUCCESS)
            && r[0][9..21] == b"narf-renamed"[..]
            && r[0][258..262] == b"narf"[..];
        let wrote_name = lt
            .sent_commands()
            .iter()
            .any(|c| c.opcode == op::HCI_WRITE_LOCAL_NAME && c.params[..12] == b"narf-renamed"[..]);
        let announced_name = CAPTURED.lock().iter().any(|e| {
            e.len() >= 6 + 249
                && u16::from_le_bytes([e[0], e[1]]) == EV_LOCAL_NAME_CHANGED
                && e[6..18] == b"narf-renamed"[..]
        });
        let mut bad_params = [0u8; 260];
        bad_params[..249].fill(b'x');
        let bad = handle(&mgmt_cmd(OP_SET_LOCAL_NAME, index, &bad_params));
        let bad_rejected = is_cmd_status(&bad, OP_SET_LOCAL_NAME, STATUS_INVALID_PARAMS);
        enqueue_power_off_cc(&lt);
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let sent_before = lt.sent_commands().len();
        CAPTURED.lock().clear();
        let r = handle(&mgmt_cmd(OP_SET_DEV_CLASS, index, &[0x08, 0x01]));
        let unpowered_class = is_cmd_complete(&r, OP_SET_DEV_CLASS, STATUS_SUCCESS)
            && r[0][9..12] == [0, 0, 0][..]
            && lt.sent_commands().len() == sent_before
            && CAPTURED.lock().is_empty();
        let r = handle(&mgmt_cmd(OP_SET_LOCAL_NAME, index, &params));
        let unpowered_name = is_cmd_complete(&r, OP_SET_LOCAL_NAME, STATUS_SUCCESS)
            && lt.sent_commands().len() == sent_before;
        let powered2 = power_on(&lt, index, &[0u8; 248], &[0u8; 3], true, true);
        let rewrote = lt.sent_commands()[sent_before..]
            .iter()
            .any(|c| c.opcode == op::HCI_WRITE_LOCAL_NAME && c.params[..12] == b"narf-renamed"[..])
            && lt.sent_commands()[sent_before..].iter().any(|c| {
                c.opcode == op::HCI_WRITE_CLASS_OF_DEVICE && c.params == [0x04, 0x08, 0x01]
            });
        let info = handle(&mgmt_cmd(OP_READ_INFO, index, &[]));
        let read_back =
            info[0][26..29] == [0x04, 0x08, 0x01][..] && info[0][29..41] == b"narf-renamed"[..];
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        cleanup_mgmt();
        if !powered || !powered2 {
            return TestResult::Fail("power-on failed");
        }
        if !class_ok || !wrote_class || !announced_class {
            return TestResult::Fail("powered SET_DEV_CLASS did not write + announce + reply");
        }
        if !name_ok || !wrote_name || !announced_name {
            return TestResult::Fail("powered SET_LOCAL_NAME did not write + announce + echo");
        }
        if !bad_rejected {
            return TestResult::Fail("unterminated SET_LOCAL_NAME was not INVALID_PARAMS");
        }
        if !unpowered_class || !unpowered_name {
            return TestResult::Fail(
                "unpowered SET_DEV_CLASS/SET_LOCAL_NAME issued HCI or an event",
            );
        }
        if !rewrote || !read_back {
            return TestResult::Fail("stored name/class were not re-written on power-on");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_set_dev_class_and_local_name);

    /// #815: START_DISCOVERY drives the GAP central scan
    /// (parameters → enable → reports → disable), with
    /// DISCOVERING / DEVICE_FOUND published; a stop while the scan
    /// is still starting is BUSY; reports after the stop are dropped.
    fn smoke_mgmt_discovery_start_stop() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        let np = handle(&mgmt_cmd(OP_START_DISCOVERY, index, &[0x02]));
        let not_powered = is_cmd_status(&np, OP_START_DISCOVERY, STATUS_NOT_POWERED);
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let bad0 = handle(&mgmt_cmd(OP_START_DISCOVERY, index, &[0x00]));
        let bad0_ok = is_cmd_status(&bad0, OP_START_DISCOVERY, STATUS_INVALID_PARAMS);
        let bredr = handle(&mgmt_cmd(OP_START_DISCOVERY, index, &[0x01]));
        let bredr_ok = is_cmd_status(&bredr, OP_START_DISCOVERY, STATUS_NOT_SUPPORTED);
        let rand = handle(&mgmt_cmd(OP_START_DISCOVERY, index, &[0x04]));
        let rand_ok = is_cmd_status(&rand, OP_START_DISCOVERY, STATUS_NOT_SUPPORTED);
        CAPTURED.lock().clear();
        let start = handle(&mgmt_cmd(OP_START_DISCOVERY, index, &[0x02]));
        let start_ok =
            is_cmd_complete(&start, OP_START_DISCOVERY, STATUS_SUCCESS) && start[0][9] == 0x02;
        // Default scan parameters: passive, 0x0030/0x0030, public,
        // accept-all (ScanParameters::encode: type, interval LE,
        // window LE, own type, filter policy).
        let params_sent = lt.sent_commands().iter().any(|c| {
            c.opcode == op::HCI_LE_SET_SCAN_PARAMETERS
                && c.params == [0x00, 0x30, 0x00, 0x30, 0x00, 0x00, 0x00]
        });
        let discovering_on = CAPTURED.lock().iter().any(|e| {
            e.len() >= 8
                && u16::from_le_bytes([e[0], e[1]]) == EV_DISCOVERING
                && e[6] == 0x02
                && e[7] == 1
        });
        let phase_starting = crate::pump::central_phase(index as usize)
            == Some(crate::gap::CentralPhase::ParametersSent);
        let busy = handle(&mgmt_cmd(OP_STOP_DISCOVERY, index, &[0x02]));
        let busy_ok = is_cmd_status(&busy, OP_STOP_DISCOVERY, STATUS_BUSY);
        lt.enqueue_event(cc(op::HCI_LE_SET_SCAN_PARAMETERS, 0, &[]));
        let _ = crate::pump::pump_once(index as usize);
        let phase_scanning =
            crate::pump::central_phase(index as usize) == Some(crate::gap::CentralPhase::Scanning);
        let enable_sent = lt
            .sent_commands()
            .iter()
            .any(|c| c.opcode == op::HCI_LE_SET_SCAN_ENABLE && c.params == [0x01, 0x00]);
        CAPTURED.lock().clear();
        let peer = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let ad = [0x02, 0x01, 0x06];
        lt.enqueue_event(le_advertising_report_event(peer, &ad, -50));
        let _ = crate::pump::pump_once(index as usize);
        let found = CAPTURED.lock().iter().any(|e| {
            e.len() >= 23
                && u16::from_le_bytes([e[0], e[1]]) == EV_DEVICE_FOUND
                && e[6..12] == peer[..]
                && e[12] == 0x01
                && e[13] == (-50i8) as u8
                && u32::from_le_bytes([e[14], e[15], e[16], e[17]]) == 0
                && u16::from_le_bytes([e[18], e[19]]) == 3
                && e[20..23] == ad[..]
        });
        let stop = handle(&mgmt_cmd(OP_STOP_DISCOVERY, index, &[0x02]));
        let stop_ok = is_cmd_complete(&stop, OP_STOP_DISCOVERY, STATUS_SUCCESS);
        let disable_sent = lt
            .sent_commands()
            .iter()
            .any(|c| c.opcode == op::HCI_LE_SET_SCAN_ENABLE && c.params == [0x00, 0x00]);
        let discovering_off = CAPTURED.lock().iter().any(|e| {
            e.len() >= 8
                && u16::from_le_bytes([e[0], e[1]]) == EV_DISCOVERING
                && e[6] == 0x02
                && e[7] == 0
        });
        lt.enqueue_event(cc(op::HCI_LE_SET_SCAN_ENABLE, 0, &[]));
        let _ = crate::pump::pump_once(index as usize);
        let phase_idle =
            crate::pump::central_phase(index as usize) == Some(crate::gap::CentralPhase::Idle);
        CAPTURED.lock().clear();
        lt.enqueue_event(le_advertising_report_event(peer, &ad, -50));
        let _ = crate::pump::pump_once(index as usize);
        let dropped_after_stop = !CAPTURED
            .lock()
            .iter()
            .any(|e| e.len() >= 2 && u16::from_le_bytes([e[0], e[1]]) == EV_DEVICE_FOUND);
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        cleanup_mgmt();
        if !not_powered || !powered {
            return TestResult::Fail("START_DISCOVERY power gating failed");
        }
        if !bad0_ok || !bredr_ok || !rand_ok {
            return TestResult::Fail("START_DISCOVERY type validation failed");
        }
        if !start_ok || !params_sent || !discovering_on || !phase_starting {
            return TestResult::Fail("START_DISCOVERY did not start the central scan");
        }
        if !busy_ok {
            return TestResult::Fail("STOP_DISCOVERY during scan-start was not BUSY");
        }
        if !phase_scanning || !enable_sent {
            return TestResult::Fail("scan did not reach Scanning on parameters complete");
        }
        if !found {
            return TestResult::Fail("DEVICE_FOUND was not published for a scan report");
        }
        if !stop_ok || !disable_sent || !discovering_off || !phase_idle {
            return TestResult::Fail("STOP_DISCOVERY did not stop the scan");
        }
        if !dropped_after_stop {
            return TestResult::Fail("DEVICE_FOUND published after discovery stopped");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_discovery_start_stop);

    /// #815: GET_CONNECTIONS lists live pump connections;
    /// PAIR_DEVICE is async (Command Status now, Command Complete
    /// on terminal outcome) with the Linux error map; UNPAIR_DEVICE
    /// is idempotent, and disconnect=1 on a live connection
    /// issues HCI Disconnect and succeeds (issue #1527).
    fn smoke_mgmt_pair_unpair_and_get_connections() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        crate::pump::test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut pair_params = [0u8; 8];
        pair_params[..6].copy_from_slice(&peer6);
        pair_params[6] = 0x01; // LE public
        pair_params[7] = 0x03; // NoInputNoOutput
        let np = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &pair_params));
        let np_ok = is_cmd_status(&np, OP_PAIR_DEVICE, STATUS_NOT_POWERED);
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let conns = handle(&mgmt_cmd(OP_GET_CONNECTIONS, index, &[]));
        let conns_empty = is_cmd_complete(&conns, OP_GET_CONNECTIONS, STATUS_SUCCESS)
            && u16::from_le_bytes([conns[0][9], conns[0][10]]) == 0;
        let nc = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &pair_params));
        let nc_ok = is_cmd_status(&nc, OP_PAIR_DEVICE, STATUS_NOT_CONNECTED);
        let mut bredr_params = pair_params;
        bredr_params[6] = 0x00;
        let br = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &bredr_params));
        let br_ok = is_cmd_status(&br, OP_PAIR_DEVICE, STATUS_NOT_SUPPORTED);
        let mut mitm_params = pair_params;
        mitm_params[7] = 0x01; // DisplayYesNo — accepted now (#818):
                               // without a connection the pairing cannot start, so the
                               // refusal is NOT_CONNECTED, not NOT_SUPPORTED.
        let mitm = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &mitm_params));
        let mitm_ok = is_cmd_status(&mitm, OP_PAIR_DEVICE, STATUS_NOT_CONNECTED);
        let mut unpair_params = [0u8; 8];
        unpair_params[..6].copy_from_slice(&peer6);
        unpair_params[6] = 0x01;
        unpair_params[7] = 0x00;
        let un = handle(&mgmt_cmd(OP_UNPAIR_DEVICE, index, &unpair_params));
        let un_ok = is_cmd_complete(&un, OP_UNPAIR_DEVICE, STATUS_SUCCESS);
        lt.enqueue_event(le_conn_complete_event(0x0040, peer6));
        let _ = crate::pump::pump_once(index as usize);
        let connected = crate::pump::connection_count(index as usize) == Some(1);
        let conns = handle(&mgmt_cmd(OP_GET_CONNECTIONS, index, &[]));
        let conns_one = is_cmd_complete(&conns, OP_GET_CONNECTIONS, STATUS_SUCCESS)
            && u16::from_le_bytes([conns[0][9], conns[0][10]]) == 1
            && conns[0][11..17] == peer6[..]
            && conns[0][17] == 0x01;
        CAPTURED.lock().clear();
        let pair = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &pair_params));
        let pair_ok = is_cmd_status(&pair, OP_PAIR_DEVICE, STATUS_SUCCESS);
        let pair2 = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &pair_params));
        let pair_busy = is_cmd_status(&pair2, OP_PAIR_DEVICE, STATUS_BUSY);
        let mut unpair_disc = unpair_params;
        unpair_disc[7] = 0x01;
        let ud = handle(&mgmt_cmd(OP_UNPAIR_DEVICE, index, &unpair_disc));
        let ud_ok = is_cmd_complete(&ud, OP_UNPAIR_DEVICE, STATUS_SUCCESS)
            && lt
                .sent_commands()
                .last()
                .map(|c| c.opcode == op::HCI_DISCONNECT && c.params == [0x40, 0x00, 0x13])
                .unwrap_or(false);
        lt.enqueue_event(disconnection_complete_event(0x0040));
        let _ = crate::pump::pump_once(index as usize);
        let disconnected = CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == OP_PAIR_DEVICE
                && e[8] == STATUS_DISCONNECTED
                && e[9..15] == peer6[..]
                && e[15] == 0x01
        });
        crate::pump::test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        cleanup_mgmt();
        if !np_ok || !powered {
            return TestResult::Fail("PAIR_DEVICE power gating failed");
        }
        if !conns_empty || !nc_ok {
            return TestResult::Fail("PAIR_DEVICE without a connection was not NOT_CONNECTED");
        }
        if !br_ok || !mitm_ok {
            return TestResult::Fail(
                "PAIR_DEVICE BR/EDR not NOT_SUPPORTED / MITM io_cap not accepted",
            );
        }
        if !un_ok {
            return TestResult::Fail("UNPAIR_DEVICE of an unknown peer was not success");
        }
        if !connected || !conns_one {
            return TestResult::Fail("GET_CONNECTIONS did not list the live connection");
        }
        if !pair_ok || !pair_busy {
            return TestResult::Fail("PAIR_DEVICE did not start / was not BUSY on a repeat");
        }
        if !ud_ok {
            return TestResult::Fail(
                "UNPAIR_DEVICE disconnect=1 on a live connection did not issue HCI Disconnect + succeed",
            );
        }
        if !disconnected {
            return TestResult::Fail("PAIR_DEVICE did not complete DISCONNECTED on link loss");
        }
        TestResult::Pass
    }
    /// #818: SET_IO_CAPABILITY stores the controller's IO
    /// capability (default NoInputNoOutput), the user-confirm /
    /// passkey replies refuse cleanly with no parked session, and
    /// the BR/EDR-only / unimplemented replies are NOT_SUPPORTED
    /// rather than UNKNOWN_COMMAND.
    fn smoke_mgmt_io_capability_and_user_replies() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        // Default capability before any SET is NoInputNoOutput.
        if io_capability(index) != crate::smp::IoCapability::NoInputNoOutput as u8 {
            cleanup_mgmt();
            return TestResult::Fail("default IO capability is not NoInputNoOutput");
        }
        let set = handle(&mgmt_cmd(OP_SET_IO_CAPABILITY, index, &[0x04]));
        let set_ok = is_cmd_complete(&set, OP_SET_IO_CAPABILITY, STATUS_SUCCESS)
            && io_capability(index) == 0x04;
        let bad = handle(&mgmt_cmd(OP_SET_IO_CAPABILITY, index, &[0x05]));
        let bad_ok = is_cmd_status(&bad, OP_SET_IO_CAPABILITY, STATUS_INVALID_PARAMS);
        let empty = handle(&mgmt_cmd(OP_SET_IO_CAPABILITY, index, &[]));
        let empty_ok = is_cmd_status(&empty, OP_SET_IO_CAPABILITY, STATUS_INVALID_PARAMS);
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut addr_params = [0u8; 7];
        addr_params[..6].copy_from_slice(&peer6);
        addr_params[6] = 0x01; // LE public
        let confirm = handle(&mgmt_cmd(OP_USER_CONFIRM_REPLY, index, &addr_params));
        let confirm_ok = is_cmd_status(&confirm, OP_USER_CONFIRM_REPLY, STATUS_NOT_CONNECTED);
        let confirm_neg = handle(&mgmt_cmd(OP_USER_CONFIRM_NEG_REPLY, index, &addr_params));
        let confirm_neg_ok = is_cmd_status(
            &confirm_neg,
            OP_USER_CONFIRM_NEG_REPLY,
            STATUS_NOT_CONNECTED,
        );
        let mut passkey_params = [0u8; 11];
        passkey_params[..7].copy_from_slice(&addr_params);
        passkey_params[7..11].copy_from_slice(&123456u32.to_le_bytes());
        let passkey = handle(&mgmt_cmd(OP_USER_PASSKEY_REPLY, index, &passkey_params));
        let passkey_ok = is_cmd_status(&passkey, OP_USER_PASSKEY_REPLY, STATUS_NOT_CONNECTED);
        let passkey_neg = handle(&mgmt_cmd(OP_USER_PASSKEY_NEG_REPLY, index, &addr_params));
        let passkey_neg_ok = is_cmd_status(
            &passkey_neg,
            OP_USER_PASSKEY_NEG_REPLY,
            STATUS_NOT_CONNECTED,
        );
        passkey_params[7..11].copy_from_slice(&1_000_000u32.to_le_bytes());
        let too_big = handle(&mgmt_cmd(OP_USER_PASSKEY_REPLY, index, &passkey_params));
        let too_big_ok = is_cmd_status(&too_big, OP_USER_PASSKEY_REPLY, STATUS_INVALID_PARAMS);
        let short = handle(&mgmt_cmd(OP_USER_PASSKEY_REPLY, index, &addr_params));
        let short_ok = is_cmd_status(&short, OP_USER_PASSKEY_REPLY, STATUS_INVALID_PARAMS);
        let mut pin_params = [0u8; 24];
        pin_params[..7].copy_from_slice(&addr_params);
        pin_params[7] = 4;
        let pin = handle(&mgmt_cmd(OP_PIN_CODE_REPLY, index, &pin_params));
        let pin_ok = is_cmd_status(&pin, OP_PIN_CODE_REPLY, STATUS_NOT_SUPPORTED);
        let pin_neg = handle(&mgmt_cmd(OP_PIN_CODE_NEG_REPLY, index, &addr_params));
        let pin_neg_ok = is_cmd_status(&pin_neg, OP_PIN_CODE_NEG_REPLY, STATUS_NOT_SUPPORTED);
        let oob = handle(&mgmt_cmd(OP_READ_LOCAL_OOB_DATA, index, &[]));
        let oob_ok = is_cmd_status(&oob, OP_READ_LOCAL_OOB_DATA, STATUS_NOT_SUPPORTED);
        // Power off: the user replies are power-gated.
        enqueue_power_off_cc(&lt);
        let off = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let off_ok = is_cmd_complete(&off, OP_SET_POWERED, STATUS_SUCCESS);
        let gated = handle(&mgmt_cmd(OP_USER_CONFIRM_REPLY, index, &addr_params));
        let gated_ok = is_cmd_status(&gated, OP_USER_CONFIRM_REPLY, STATUS_NOT_POWERED);
        cleanup_mgmt();
        if !set_ok || !bad_ok || !empty_ok || !powered {
            return TestResult::Fail("SET_IO_CAPABILITY store/validation failed");
        }
        if !confirm_ok || !confirm_neg_ok || !passkey_ok || !passkey_neg_ok {
            return TestResult::Fail("user reply with no parked session was not NOT_CONNECTED");
        }
        if !too_big_ok || !short_ok {
            return TestResult::Fail("USER_PASSKEY_REPLY validation failed");
        }
        if !pin_ok || !pin_neg_ok || !oob_ok {
            return TestResult::Fail("PIN / local-OOB replies were not NOT_SUPPORTED");
        }
        if !off_ok || !gated_ok {
            return TestResult::Fail("user replies were not power-gated");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_io_capability_and_user_replies);

    /// #818: ADD/REMOVE_REMOTE_OOB_DATA validation and round-trip
    /// through the pump-facing accessor. ADD works unpowered; LE
    /// needs the 71-byte form with zero P-192 fields.
    fn smoke_mgmt_remote_oob_data() -> TestResult {
        let (_lt, index) = setup_controller(controller::ControllerInfo::default());
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut peer = [0u8; 7];
        peer[1..7].copy_from_slice(&peer6);
        let mut add_params = [0u8; 71];
        add_params[..6].copy_from_slice(&peer6);
        add_params[6] = 0x01; // LE public
                              // P-192 fields (bytes 7..39) stay zero for LE.
        add_params[39..55].copy_from_slice(&[0xAB; 16]);
        add_params[55..71].copy_from_slice(&[0xCD; 16]);
        let add = handle(&mgmt_cmd(OP_ADD_REMOTE_OOB_DATA, index, &add_params));
        let add_ok = is_cmd_complete(&add, OP_ADD_REMOTE_OOB_DATA, STATUS_SUCCESS)
            && add[0][9..15] == peer6[..]
            && add[0][15] == 0x01;
        let stored = remote_oob(index, &peer);
        let stored_ok = stored
            == Some(crate::smp::OobData {
                hash: [0xAB; 16],
                randomizer: [0xCD; 16],
            });
        let short = handle(&mgmt_cmd(OP_ADD_REMOTE_OOB_DATA, index, &add_params[..39]));
        let short_ok = is_cmd_status(&short, OP_ADD_REMOTE_OOB_DATA, STATUS_INVALID_PARAMS);
        let mut nonzero192 = add_params;
        nonzero192[7] = 1;
        let nz = handle(&mgmt_cmd(OP_ADD_REMOTE_OOB_DATA, index, &nonzero192));
        let nz_ok = is_cmd_status(&nz, OP_ADD_REMOTE_OOB_DATA, STATUS_INVALID_PARAMS);
        let mut bredr = add_params;
        bredr[6] = 0x00;
        let br = handle(&mgmt_cmd(OP_ADD_REMOTE_OOB_DATA, index, &bredr));
        let br_ok = is_cmd_status(&br, OP_ADD_REMOTE_OOB_DATA, STATUS_NOT_SUPPORTED);
        let mut rm_params = [0u8; 7];
        rm_params[..6].copy_from_slice(&peer6);
        rm_params[6] = 0x01;
        let rm = handle(&mgmt_cmd(OP_REMOVE_REMOTE_OOB_DATA, index, &rm_params));
        let rm_ok = is_cmd_complete(&rm, OP_REMOVE_REMOTE_OOB_DATA, STATUS_SUCCESS)
            && remote_oob(index, &peer).is_none();
        let rm_unknown = handle(&mgmt_cmd(OP_REMOVE_REMOTE_OOB_DATA, index, &rm_params));
        let rm_unknown_ok = is_cmd_complete(&rm_unknown, OP_REMOVE_REMOTE_OOB_DATA, STATUS_SUCCESS);
        // Re-add, then an all-zero address clears every entry.
        let _ = handle(&mgmt_cmd(OP_ADD_REMOTE_OOB_DATA, index, &add_params));
        let mut clear_params = [0u8; 7];
        clear_params[6] = 0x01;
        let clear = handle(&mgmt_cmd(OP_REMOVE_REMOTE_OOB_DATA, index, &clear_params));
        let clear_ok = is_cmd_complete(&clear, OP_REMOVE_REMOTE_OOB_DATA, STATUS_SUCCESS)
            && remote_oob(index, &peer).is_none();
        cleanup_mgmt();
        if !add_ok || !stored_ok {
            return TestResult::Fail("ADD_REMOTE_OOB_DATA store failed");
        }
        if !short_ok || !nz_ok || !br_ok {
            return TestResult::Fail("ADD_REMOTE_OOB_DATA validation failed");
        }
        if !rm_ok || !rm_unknown_ok || !clear_ok {
            return TestResult::Fail("REMOVE_REMOTE_OOB_DATA failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_remote_oob_data);
    /// #1528: CANCEL_PAIR_DEVICE aborts an in-flight mgmt
    /// pairing — the pending PAIR_DEVICE completes with
    /// CANCELLED on the event sink and the cancel itself
    /// completes with SUCCESS echoing the addr_info — and a
    /// cancel with no pending pairing for that peer is
    /// INVALID_PARAMS (Command Status), as in the kernel.
    /// Fixture layout is from BlueZ `doc/mgmt-api.txt` (opcode
    /// 0x001a, params addr(6)+type(1), return addr(6)+type(1)),
    /// not from the implementation's constants.
    fn smoke_mgmt_cancel_pair_device() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        crate::pump::test_entropy::install_stream(0x0123_4567_89AB_CDEF);
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        // Fixture opcodes from mgmt-api.txt, not from the impl:
        // CANCEL_PAIR_DEVICE 0x001a, params addr(6) + type(1);
        // error code 0x10 Cancelled.
        const OP_CANCEL_PAIR_DEVICE: u16 = 0x001a;
        const STATUS_CANCELLED: u8 = 0x10;
        let mut cancel_params = [0u8; 7];
        cancel_params[..6].copy_from_slice(&peer6);
        cancel_params[6] = 0x01; // LE public
        let np = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &cancel_params));
        let np_ok = is_cmd_status(&np, OP_CANCEL_PAIR_DEVICE, STATUS_NOT_POWERED);
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        // No pending pairing for this peer (or any peer) yet.
        let none = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &cancel_params));
        let none_ok = is_cmd_status(&none, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
        let short = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &cancel_params[..6]));
        let short_ok = is_cmd_status(&short, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
        let mut bad_type = cancel_params;
        bad_type[6] = 0x03;
        let bt = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &bad_type));
        let bt_ok = is_cmd_status(&bt, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
        let mut bredr = cancel_params;
        bredr[6] = 0x00;
        let br = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &bredr));
        let br_ok = is_cmd_status(&br, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
        let bad_index = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, 0x00ff, &cancel_params));
        let bad_index_ok = is_cmd_status(&bad_index, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_INDEX);
        // 0x001a is advertised by READ_COMMANDS now (39 opcodes:
        // main's 33 incl. OP_DISCONNECT + this branch's 6
        // SET_* opcodes).
        let cmds = handle(&mgmt_cmd(OP_READ_COMMANDS, MGMT_INDEX_NONE, &[]));
        let cmds_ok = cmds.len() == 1
            && u16::from_le_bytes([cmds[0][9], cmds[0][10]]) == 39
            && cmds[0].len() >= 13 + 39 * 2
            && (0..39).any(|i| {
                u16::from_le_bytes([cmds[0][13 + 2 * i], cmds[0][14 + 2 * i]])
                    == OP_CANCEL_PAIR_DEVICE
            });
        // Bring the peer's connection up, then start a pairing.
        lt.enqueue_event(le_conn_complete_event(0x0040, peer6));
        let _ = crate::pump::pump_once(index as usize);
        let connected = crate::pump::connection_count(index as usize) == Some(1);
        let mut pair_params = [0u8; 8];
        pair_params[..6].copy_from_slice(&peer6);
        pair_params[6] = 0x01; // LE public
        pair_params[7] = 0x03; // NoInputNoOutput
        CAPTURED.lock().clear();
        let pair = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &pair_params));
        let pair_ok = is_cmd_status(&pair, OP_PAIR_DEVICE, STATUS_SUCCESS);
        let pair2 = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &pair_params));
        let pair_busy = is_cmd_status(&pair2, OP_PAIR_DEVICE, STATUS_BUSY);
        // Cancel the in-flight pairing: Command Complete SUCCESS
        // echoing addr(6) + type(1), and the pending PAIR_DEVICE
        // completes with CANCELLED on the event sink.
        let cancel = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &cancel_params));
        let cancel_ok = is_cmd_complete(&cancel, OP_CANCEL_PAIR_DEVICE, STATUS_SUCCESS)
            && cancel[0].len() >= 16
            && cancel[0][9..15] == peer6[..]
            && cancel[0][15] == 0x01;
        let cancelled = CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == OP_PAIR_DEVICE
                && e[8] == STATUS_CANCELLED
                && e[9..15] == peer6[..]
                && e[15] == 0x01
        });
        // The pairing is gone: a second cancel has nothing to
        // cancel, and a fresh PAIR_DEVICE starts again.
        let cancel2 = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &cancel_params));
        let cancel2_ok = is_cmd_status(&cancel2, OP_CANCEL_PAIR_DEVICE, STATUS_INVALID_PARAMS);
        let pair3 = handle(&mgmt_cmd(OP_PAIR_DEVICE, index, &pair_params));
        let pair3_ok = is_cmd_status(&pair3, OP_PAIR_DEVICE, STATUS_SUCCESS);
        let cancel3 = handle(&mgmt_cmd(OP_CANCEL_PAIR_DEVICE, index, &cancel_params));
        let cancel3_ok = is_cmd_complete(&cancel3, OP_CANCEL_PAIR_DEVICE, STATUS_SUCCESS);
        crate::pump::test_entropy::clear();
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        cleanup_mgmt();
        if !np_ok || !powered {
            return TestResult::Fail("CANCEL_PAIR_DEVICE power gating failed");
        }
        if !none_ok || !short_ok || !bt_ok || !br_ok || !bad_index_ok {
            return TestResult::Fail("CANCEL_PAIR_DEVICE validation failed");
        }
        if !cmds_ok {
            return TestResult::Fail("READ_COMMANDS does not advertise CANCEL_PAIR_DEVICE");
        }
        if !connected || !pair_ok || !pair_busy {
            return TestResult::Fail("PAIR_DEVICE async start / BUSY failed");
        }
        if !cancel_ok || !cancelled {
            return TestResult::Fail("CANCEL_PAIR_DEVICE did not cancel the pending pairing");
        }
        if !cancel2_ok {
            return TestResult::Fail("second CANCEL_PAIR_DEVICE was not INVALID_PARAMS");
        }
        if !pair3_ok || !cancel3_ok {
            return TestResult::Fail("pairing did not restart cleanly after cancel");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_cancel_pair_device);

    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_pair_unpair_and_get_connections);

    /// #1527: mgmt DISCONNECT tears a connection down by
    /// handle. The command is async: no immediate reply, HCI
    /// Disconnect (0x0406, handle + reason 0x13) on the wire, a
    /// second DISCONNECT while one is pending is BUSY, the
    /// Command Status alone does not complete it, and the
    /// Disconnection Complete publishes the Command Complete
    /// echoing the address. A later DISCONNECT for the now-gone
    /// peer is NOT_CONNECTED.
    fn smoke_mgmt_disconnect_by_handle() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let peer6 = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
        let mut disc_params = [0u8; 7];
        disc_params[..6].copy_from_slice(&peer6);
        disc_params[6] = 0x01; // LE public
        lt.enqueue_event(le_conn_complete_event(0x0040, peer6));
        let _ = crate::pump::pump_once(index as usize);
        let connected = crate::pump::connection_count(index as usize) == Some(1);
        CAPTURED.lock().clear();
        let reply = handle(&mgmt_cmd(OP_DISCONNECT, index, &disc_params));
        let no_immediate_reply = reply.is_empty();
        let hci_sent = lt
            .sent_commands()
            .last()
            .map(|c| c.opcode == op::HCI_DISCONNECT && c.params == [0x40, 0x00, 0x13])
            .unwrap_or(false);
        // A second DISCONNECT while one is pending is BUSY
        // (Command Complete, echoing the address).
        let busy = handle(&mgmt_cmd(OP_DISCONNECT, index, &disc_params));
        let busy_ok = is_cmd_complete(&busy, OP_DISCONNECT, STATUS_BUSY)
            && busy[0][9..15] == peer6[..]
            && busy[0][15] == 0x01;
        // The Command Status (accepted) does not complete it.
        lt.enqueue_event(command_status_event(op::HCI_DISCONNECT, 0x00));
        let _ = crate::pump::pump_once(index as usize);
        let still_pending = !CAPTURED.lock().iter().any(|e| {
            e.len() >= 8
                && u16::from_le_bytes([e[0], e[1]]) == EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == OP_DISCONNECT
        }) && crate::pump::connection_count(index as usize) == Some(1);
        // The Disconnection Complete lands the Command Complete.
        lt.enqueue_event(disconnection_complete_event(0x0040));
        let _ = crate::pump::pump_once(index as usize);
        let completed = CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == OP_DISCONNECT
                && e[8] == STATUS_SUCCESS
                && e[9..15] == peer6[..]
                && e[15] == 0x01
        });
        let gone = crate::pump::connection_count(index as usize) == Some(0);
        let conns = handle(&mgmt_cmd(OP_GET_CONNECTIONS, index, &[]));
        let conns_empty = is_cmd_complete(&conns, OP_GET_CONNECTIONS, STATUS_SUCCESS)
            && u16::from_le_bytes([conns[0][9], conns[0][10]]) == 0;
        let again = handle(&mgmt_cmd(OP_DISCONNECT, index, &disc_params));
        let nc_ok = is_cmd_complete(&again, OP_DISCONNECT, STATUS_NOT_CONNECTED)
            && again[0][9..15] == peer6[..]
            && again[0][15] == 0x01;
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        cleanup_mgmt();
        if !powered || !connected {
            return TestResult::Fail("fixture connection did not come up");
        }
        if !no_immediate_reply || !hci_sent {
            return TestResult::Fail("DISCONNECT did not issue HCI Disconnect with no reply");
        }
        if !busy_ok {
            return TestResult::Fail("second DISCONNECT while pending was not BUSY");
        }
        if !still_pending {
            return TestResult::Fail("Command Status completed the pending DISCONNECT early");
        }
        if !completed || !gone || !conns_empty {
            return TestResult::Fail("Disconnection Complete did not land the disconnect");
        }
        if !nc_ok {
            return TestResult::Fail("DISCONNECT for a gone peer was not NOT_CONNECTED");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_disconnect_by_handle);

    /// #1527: DISCONNECT rejections are Command Completes
    /// echoing the address (Linux `disconnect()`): bad address
    /// type → INVALID_PARAMS, unpowered → NOT_POWERED, no
    /// connection → NOT_CONNECTED. A bad index / short params
    /// stay Command Status (the general mgmt rule). DISCONNECT
    /// is advertised in READ_COMMANDS.
    fn smoke_mgmt_disconnect_rejections() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let peer6 = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
        let mut disc_params = [0u8; 7];
        disc_params[..6].copy_from_slice(&peer6);
        disc_params[6] = 0x01; // LE public
        let echo_ok = |r: &[Vec<u8>]| r[0][9..15] == peer6[..] && r[0][15] == 0x01;
        let bad_idx = handle(&mgmt_cmd(OP_DISCONNECT, 0x00ff, &disc_params));
        let bad_idx_ok = is_cmd_status(&bad_idx, OP_DISCONNECT, STATUS_INVALID_INDEX);
        let short = handle(&mgmt_cmd(OP_DISCONNECT, index, &[0xA0, 0xA1, 0xA2]));
        let short_ok = is_cmd_status(&short, OP_DISCONNECT, STATUS_INVALID_PARAMS);
        let mut bad_type = disc_params;
        bad_type[6] = 0x03;
        let bt = handle(&mgmt_cmd(OP_DISCONNECT, index, &bad_type));
        let bt_ok = is_cmd_complete(&bt, OP_DISCONNECT, STATUS_INVALID_PARAMS) && echo_ok(&bt);
        let np = handle(&mgmt_cmd(OP_DISCONNECT, index, &disc_params));
        let np_ok = is_cmd_complete(&np, OP_DISCONNECT, STATUS_NOT_POWERED) && echo_ok(&np);
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let nc = handle(&mgmt_cmd(OP_DISCONNECT, index, &disc_params));
        let nc_ok = is_cmd_complete(&nc, OP_DISCONNECT, STATUS_NOT_CONNECTED) && echo_ok(&nc);
        let cmds = handle(&mgmt_cmd(OP_READ_COMMANDS, MGMT_INDEX_NONE, &[]));
        let advertised = {
            let c = &cmds[0];
            let n = u16::from_le_bytes([c[9], c[10]]) as usize;
            (0..n).any(|i| u16::from_le_bytes([c[13 + 2 * i], c[14 + 2 * i]]) == OP_DISCONNECT)
        };
        cleanup_mgmt();
        if !bad_idx_ok || !short_ok {
            return TestResult::Fail("DISCONNECT bad index / short params was not CMD_STATUS");
        }
        if !bt_ok {
            return TestResult::Fail("DISCONNECT bad address type was not INVALID_PARAMS echo");
        }
        if !np_ok || !powered {
            return TestResult::Fail("DISCONNECT power gating failed");
        }
        if !nc_ok {
            return TestResult::Fail("DISCONNECT with no connection was not NOT_CONNECTED");
        }
        if !advertised {
            return TestResult::Fail("READ_COMMANDS does not advertise DISCONNECT");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_disconnect_rejections);

    /// #1527: a refused HCI Disconnect Command Status
    /// completes the pending DISCONNECT as FAILED (no
    /// Disconnection Complete follows a refusal) and the
    /// connection stays up; a later DISCONNECT is accepted
    /// again once the refusal cleared the pending record.
    fn smoke_mgmt_disconnect_refused_command_status() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        let previous = narf_filesystem::bluetooth::install_mgmt_event_sink(capture_sink);
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let peer6 = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
        let mut disc_params = [0u8; 7];
        disc_params[..6].copy_from_slice(&peer6);
        disc_params[6] = 0x01; // LE public
        lt.enqueue_event(le_conn_complete_event(0x0040, peer6));
        let _ = crate::pump::pump_once(index as usize);
        let connected = crate::pump::connection_count(index as usize) == Some(1);
        CAPTURED.lock().clear();
        let reply = handle(&mgmt_cmd(OP_DISCONNECT, index, &disc_params));
        let accepted = reply.is_empty();
        // Refused (Unknown Connection 0x02): FAILED, link stays up.
        lt.enqueue_event(command_status_event(op::HCI_DISCONNECT, 0x02));
        let _ = crate::pump::pump_once(index as usize);
        let failed = CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == OP_DISCONNECT
                && e[8] == STATUS_FAILED
                && e[9..15] == peer6[..]
                && e[15] == 0x01
        });
        let still_up = crate::pump::connection_count(index as usize) == Some(1);
        // A fresh DISCONNECT is accepted again after the refusal.
        CAPTURED.lock().clear();
        let reply2 = handle(&mgmt_cmd(OP_DISCONNECT, index, &disc_params));
        let accepted2 = reply2.is_empty();
        lt.enqueue_event(command_status_event(op::HCI_DISCONNECT, 0x00));
        let _ = crate::pump::pump_once(index as usize);
        let still_pending = !CAPTURED.lock().iter().any(|e| {
            e.len() >= 8
                && u16::from_le_bytes([e[0], e[1]]) == EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == OP_DISCONNECT
        });
        lt.enqueue_event(disconnection_complete_event(0x0040));
        let _ = crate::pump::pump_once(index as usize);
        let completed = CAPTURED.lock().iter().any(|e| {
            e.len() >= 16
                && u16::from_le_bytes([e[0], e[1]]) == EV_CMD_COMPLETE
                && u16::from_le_bytes([e[6], e[7]]) == OP_DISCONNECT
                && e[8] == STATUS_SUCCESS
                && e[9..15] == peer6[..]
                && e[15] == 0x01
        });
        let gone = crate::pump::connection_count(index as usize) == Some(0);
        if let Some(prev) = previous {
            narf_filesystem::bluetooth::install_mgmt_event_sink(prev);
        }
        cleanup_mgmt();
        if !powered || !connected {
            return TestResult::Fail("fixture connection did not come up");
        }
        if !accepted || !failed || !still_up {
            return TestResult::Fail("refused Command Status did not fail the DISCONNECT");
        }
        if !accepted2 || !still_pending {
            return TestResult::Fail("DISCONNECT was not accepted again after the refusal");
        }
        if !completed || !gone {
            return TestResult::Fail("retry DISCONNECT did not land on Disconnection Complete");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/mgmt",
        smoke_mgmt_disconnect_refused_command_status
    );

    /// #815 (remainder tranche): SET_ADVERTISING issues the legacy
    /// advertising HCI sequence (parameters + data + scan response
    /// + enable) while powered, validates the value, rejects with
    /// LE off, records while unpowered and applies on power-on,
    /// and no-ops on a repeat of the same mode. Mode 0x01 with
    /// connectable off advertises non-connectable from a fresh
    /// non-resolvable random address.
    fn smoke_mgmt_set_advertising_issues_hci() -> TestResult {
        let mut name = [0u8; 248];
        name[..9].copy_from_slice(b"narf-mgmt");
        let info = controller::ControllerInfo {
            local_name: name,
            ..controller::ControllerInfo::default()
        };
        let (lt, index) = setup_controller(info);
        // Unpowered: recorded with no HCI.
        let sent_before = lt.sent_commands().len();
        let r = handle(&mgmt_cmd(OP_SET_ADVERTISING, index, &[0x02]));
        let recorded = is_cmd_complete(&r, OP_SET_ADVERTISING, STATUS_SUCCESS)
            && lt.sent_commands().len() == sent_before;
        // Power-on applies the recorded advertisement after the
        // base sequence: params, data, scan response, enable.
        enqueue_power_on_ccs(&lt, &name, &[0u8; 3], false, false);
        lt.enqueue_event(cc(op::HCI_LE_SET_ADVERTISING_PARAMETERS, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADVERTISING_DATA, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_SCAN_RESPONSE_DATA, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADVERTISING_ENABLE, 0, &[]));
        let r = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        let powered = is_cmd_complete(&r, OP_SET_POWERED, STATUS_SUCCESS);
        let sent = lt.sent_commands();
        // Last four are the advertising sequence, in order.
        // Params: interval 0x0800/0x0800, ADV_IND, public, no
        // peer, channels 0x07, filter 0x00. Data: flags [0x02,
        // 0x01, 0x00] (discoverable off, BR/EDR on) + complete
        // name "narf-mgmt"; scan response empty; enable [0x01].
        let mut adv_params = [0u8; 32];
        adv_params[0] = 15;
        adv_params[1..4].copy_from_slice(&[0x02, 0x01, 0x00]);
        adv_params[4] = 0x0A;
        adv_params[5] = 0x09;
        adv_params[6..15].copy_from_slice(b"narf-mgmt");
        let want: [(u16, &[u8]); 4] = [
            (
                op::HCI_LE_SET_ADVERTISING_PARAMETERS,
                &[
                    0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x07, 0x00,
                ],
            ),
            (op::HCI_LE_SET_ADVERTISING_DATA, &adv_params),
            (op::HCI_LE_SET_SCAN_RESPONSE_DATA, &[0u8; 32]),
            (op::HCI_LE_SET_ADVERTISING_ENABLE, &[0x01]),
        ];
        let applied = sent.len() >= 4
            && sent[sent.len() - 4..]
                .iter()
                .zip(want.iter())
                .all(|(c, (o, p))| c.opcode == *o && c.params.as_slice() == *p);
        // Advertising bit set in READ_INFO.
        let info = handle(&mgmt_cmd(OP_READ_INFO, index, &[]));
        let bit_set = u32::from_le_bytes([info[0][22], info[0][23], info[0][24], info[0][25]])
            & SETTING_ADVERTISING
            != 0;
        // Repeat of the same mode issues no HCI.
        let sent_len = lt.sent_commands().len();
        let again = handle(&mgmt_cmd(OP_SET_ADVERTISING, index, &[0x02]));
        let no_op = is_cmd_complete(&again, OP_SET_ADVERTISING, STATUS_SUCCESS)
            && lt.sent_commands().len() == sent_len;
        // Bad value → INVALID_PARAMS.
        let bad = handle(&mgmt_cmd(OP_SET_ADVERTISING, index, &[0x03]));
        let bad_ok = is_cmd_status(&bad, OP_SET_ADVERTISING, STATUS_INVALID_PARAMS);
        // Disable → Set Advertise Enable [0x00] only.
        lt.enqueue_event(cc(op::HCI_LE_SET_ADVERTISING_ENABLE, 0, &[]));
        let off = handle(&mgmt_cmd(OP_SET_ADVERTISING, index, &[0x00]));
        let off_ok = is_cmd_complete(&off, OP_SET_ADVERTISING, STATUS_SUCCESS)
            && lt
                .sent_commands()
                .last()
                .map(|c| c.opcode == op::HCI_LE_SET_ADVERTISING_ENABLE && c.params == [0x00])
                .unwrap_or(false);
        // LE off → REJECTED (and SET_LE(0) with advertising off
        // issues only the LE host-support write).
        lt.enqueue_event(cc(op::HCI_WRITE_LE_HOST_SUPPORT, 0, &[]));
        let le_off = handle(&mgmt_cmd(OP_SET_LE, index, &[0]));
        let le_off_ok = is_cmd_complete(&le_off, OP_SET_LE, STATUS_SUCCESS);
        let rej = handle(&mgmt_cmd(OP_SET_ADVERTISING, index, &[0x02]));
        let rej_ok = is_cmd_status(&rej, OP_SET_ADVERTISING, STATUS_REJECTED);
        // LE back on, then mode 0x01 with connectable off:
        // non-connectable from a fresh non-resolvable random.
        lt.enqueue_event(cc(op::HCI_WRITE_LE_HOST_SUPPORT, 0, &[]));
        let _ = handle(&mgmt_cmd(OP_SET_LE, index, &[1]));
        lt.enqueue_event(cc(
            op::HCI_LE_RAND,
            0,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ));
        lt.enqueue_event(cc(op::HCI_LE_SET_RANDOM_ADDRESS, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADVERTISING_PARAMETERS, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADVERTISING_DATA, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_SCAN_RESPONSE_DATA, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADVERTISING_ENABLE, 0, &[]));
        let sent_len = lt.sent_commands().len();
        let nr = handle(&mgmt_cmd(OP_SET_ADVERTISING, index, &[0x01]));
        let nr_ok = is_cmd_complete(&nr, OP_SET_ADVERTISING, STATUS_SUCCESS);
        let nr_sent = lt.sent_commands();
        let nr_want: [(u16, &[u8]); 6] = [
            (op::HCI_LE_RAND, &[]),
            (
                op::HCI_LE_SET_RANDOM_ADDRESS,
                &[0x11, 0x22, 0x33, 0x44, 0x55, 0x26],
            ),
            (
                op::HCI_LE_SET_ADVERTISING_PARAMETERS,
                &[
                    0x00, 0x08, 0x00, 0x08, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0x07, 0x00,
                ],
            ),
            (op::HCI_LE_SET_ADVERTISING_DATA, &adv_params),
            (op::HCI_LE_SET_SCAN_RESPONSE_DATA, &[0u8; 32]),
            (op::HCI_LE_SET_ADVERTISING_ENABLE, &[0x01]),
        ];
        let nr_seq = nr_sent.len() == sent_len + 6
            && nr_sent[sent_len..]
                .iter()
                .zip(nr_want.iter())
                .all(|(c, (o, p))| c.opcode == *o && c.params.as_slice() == *p);
        cleanup_mgmt();
        if !recorded {
            return TestResult::Fail("unpowered SET_ADVERTISING issued HCI instead of recording");
        }
        if !powered || !applied {
            return TestResult::Fail("power-on did not apply the recorded advertisement");
        }
        if !bit_set {
            return TestResult::Fail("READ_INFO did not show the ADVERTISING bit");
        }
        if !no_op {
            return TestResult::Fail("repeat SET_ADVERTISING issued HCI");
        }
        if !bad_ok {
            return TestResult::Fail("SET_ADVERTISING(0x03) was not INVALID_PARAMS");
        }
        if !off_ok {
            return TestResult::Fail("SET_ADVERTISING(0x00) did not disable advertising");
        }
        if !nr_ok || !nr_seq {
            return TestResult::Fail("SET_ADVERTISING(0x01) did not advertise from a fresh non-resolvable random address");
        }
        if !le_off_ok || !rej_ok {
            return TestResult::Fail("SET_ADVERTISING with LE off was not REJECTED");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_set_advertising_issues_hci);

    /// #815 (remainder tranche): SET_STATIC_ADDRESS validates the
    /// static-random shape and is rejected while powered;
    /// SET_PRIVACY records mode + local IRK and is rejected while
    /// powered; power-on programs the RPA (privacy wins over the
    /// static address) and the resolving list, and a later
    /// power-on with privacy off programs the static address.
    fn smoke_mgmt_static_address_and_privacy() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        // SET_STATIC_ADDRESS validation (unpowered).
        let bad_bits = handle(&mgmt_cmd(
            OP_SET_STATIC_ADDRESS,
            index,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x01],
        ));
        let bad_bits_ok = is_cmd_status(&bad_bits, OP_SET_STATIC_ADDRESS, STATUS_INVALID_PARAMS);
        let bad_none = handle(&mgmt_cmd(OP_SET_STATIC_ADDRESS, index, &[0xff; 6]));
        let bad_none_ok = is_cmd_status(&bad_none, OP_SET_STATIC_ADDRESS, STATUS_INVALID_PARAMS);
        let static_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0xC1];
        let ok = handle(&mgmt_cmd(OP_SET_STATIC_ADDRESS, index, &static_addr));
        let static_ok = is_cmd_complete(&ok, OP_SET_STATIC_ADDRESS, STATUS_SUCCESS)
            && u32::from_le_bytes([ok[0][9], ok[0][10], ok[0][11], ok[0][12]])
                & SETTING_STATIC_ADDRESS
                != 0;
        // SET_PRIVACY validation (unpowered).
        let bad_len = handle(&mgmt_cmd(OP_SET_PRIVACY, index, &[0x01; 16]));
        let bad_len_ok = is_cmd_status(&bad_len, OP_SET_PRIVACY, STATUS_INVALID_PARAMS);
        let mut bad_val = [0u8; 17];
        bad_val[0] = 0x03;
        let bad_val_r = handle(&mgmt_cmd(OP_SET_PRIVACY, index, &bad_val));
        let bad_val_ok = is_cmd_status(&bad_val_r, OP_SET_PRIVACY, STATUS_INVALID_PARAMS);
        let mut priv_params = [0u8; 17];
        priv_params[0] = 0x01;
        priv_params[1..17].copy_from_slice(&[0xAA; 16]);
        let priv_ok_r = handle(&mgmt_cmd(OP_SET_PRIVACY, index, &priv_params));
        let priv_ok = is_cmd_complete(&priv_ok_r, OP_SET_PRIVACY, STATUS_SUCCESS)
            && u32::from_le_bytes([
                priv_ok_r[0][9],
                priv_ok_r[0][10],
                priv_ok_r[0][11],
                priv_ok_r[0][12],
            ]) & SETTING_PRIVACY
                != 0;
        // Power-on programs the RPA (privacy wins over static),
        // then the resolving list (empty: clear + enable).
        // LE Rand returns fixed bytes; LE Encrypt a fixed
        // ciphertext; the programmed RPA is hash || prand from
        // those scripted bytes (prand = [0x73, 0x22, 0x11],
        // hash = ct[13..16] LSB-first = [0x0F, 0x0E, 0x0D]).
        enqueue_power_on_ccs(&lt, &[0u8; 248], &[0u8; 3], false, false);
        lt.enqueue_event(cc(
            op::HCI_LE_RAND,
            0,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ));
        lt.enqueue_event(cc(
            op::HCI_LE_ENCRYPT,
            0,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ],
        ));
        lt.enqueue_event(cc(op::HCI_LE_SET_RANDOM_ADDRESS, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_CLEAR_RESOLVING_LIST, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE, 0, &[]));
        let sent_len = lt.sent_commands().len();
        let r = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        let powered = is_cmd_complete(&r, OP_SET_POWERED, STATUS_SUCCESS);
        let sent = lt.sent_commands();
        // The LE Encrypt params are IRK || plaintext; check them
        // separately (plaintext = 13 zero octets + prand MSB first).
        let mut enc_params = [0u8; 32];
        enc_params[..16].copy_from_slice(&[0xAA; 16]);
        enc_params[16..29].copy_from_slice(&[0u8; 13]);
        enc_params[29..32].copy_from_slice(&[0x73, 0x22, 0x11]);
        let priv_seq = sent.len() == sent_len + 5
            && sent[sent_len].opcode == op::HCI_LE_RAND
            && sent[sent_len + 1].opcode == op::HCI_LE_ENCRYPT
            && sent[sent_len + 1].params.as_slice() == enc_params
            && sent[sent_len + 2].opcode == op::HCI_LE_SET_RANDOM_ADDRESS
            && sent[sent_len + 2].params == [0x0F, 0x0E, 0x0D, 0x11, 0x22, 0x73]
            && sent[sent_len + 3].opcode == op::HCI_LE_CLEAR_RESOLVING_LIST
            && sent[sent_len + 4].opcode == op::HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE
            && sent[sent_len + 4].params == [0x01];
        // READ_INFO shows both bits while powered.
        let info = handle(&mgmt_cmd(OP_READ_INFO, index, &[]));
        let bits = u32::from_le_bytes([info[0][22], info[0][23], info[0][24], info[0][25]]);
        let bits_ok = bits & SETTING_PRIVACY != 0 && bits & SETTING_STATIC_ADDRESS != 0;
        // Powered: both commands are REJECTED.
        let priv_rej = handle(&mgmt_cmd(OP_SET_PRIVACY, index, &priv_params));
        let priv_rej_ok = is_cmd_status(&priv_rej, OP_SET_PRIVACY, STATUS_REJECTED);
        let static_rej = handle(&mgmt_cmd(OP_SET_STATIC_ADDRESS, index, &static_addr));
        let static_rej_ok = is_cmd_status(&static_rej, OP_SET_STATIC_ADDRESS, STATUS_REJECTED);
        // Power off, privacy off, power on: the static address is
        // programmed (no RPA, no resolving list).
        enqueue_power_off_cc(&lt);
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let mut priv_off = [0u8; 17];
        priv_off[0] = 0x00;
        let po = handle(&mgmt_cmd(OP_SET_PRIVACY, index, &priv_off));
        let po_ok = is_cmd_complete(&po, OP_SET_PRIVACY, STATUS_SUCCESS)
            && u32::from_le_bytes([po[0][9], po[0][10], po[0][11], po[0][12]]) & SETTING_PRIVACY
                == 0;
        enqueue_power_on_ccs(&lt, &[0u8; 248], &[0u8; 3], false, false);
        lt.enqueue_event(cc(op::HCI_LE_SET_RANDOM_ADDRESS, 0, &[]));
        let sent_len = lt.sent_commands().len();
        let r = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        let powered2 = is_cmd_complete(&r, OP_SET_POWERED, STATUS_SUCCESS);
        let sent = lt.sent_commands();
        let static_seq = sent.len() == sent_len + 1
            && sent[sent_len].opcode == op::HCI_LE_SET_RANDOM_ADDRESS
            && sent[sent_len].params == static_addr;
        cleanup_mgmt();
        if !bad_bits_ok || !bad_none_ok {
            return TestResult::Fail("SET_STATIC_ADDRESS validation failed");
        }
        if !static_ok {
            return TestResult::Fail("SET_STATIC_ADDRESS did not set the STATIC_ADDRESS bit");
        }
        if !bad_len_ok || !bad_val_ok {
            return TestResult::Fail("SET_PRIVACY validation failed");
        }
        if !priv_ok {
            return TestResult::Fail("SET_PRIVACY did not set the PRIVACY bit");
        }
        if !powered || !priv_seq {
            return TestResult::Fail("power-on did not program the RPA + resolving list");
        }
        if !bits_ok {
            return TestResult::Fail("READ_INFO did not show PRIVACY + STATIC_ADDRESS");
        }
        if !priv_rej_ok || !static_rej_ok {
            return TestResult::Fail("powered SET_PRIVACY / SET_STATIC_ADDRESS was not REJECTED");
        }
        if !po_ok || !powered2 {
            return TestResult::Fail("SET_PRIVACY(0x00) / power-on with privacy off failed");
        }
        if !static_seq {
            return TestResult::Fail(
                "power-on with privacy off did not program the static address",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_static_address_and_privacy);

    /// #815 (remainder tranche): LOAD_LONG_TERM_KEYS validates
    /// length, skips invalid entries, and stores accepted LTKs as
    /// real bonds (visible via bond_count/has_bond, removable via
    /// UNPAIR_DEVICE); LOAD_IRKS validates the whole list first,
    /// replaces it, and programs the controller resolving list
    /// when powered with privacy on.
    fn smoke_mgmt_load_keys() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        // LOAD_LONG_TERM_KEYS: length must match the count.
        let short = handle(&mgmt_cmd(
            OP_LOAD_LONG_TERM_KEYS,
            index,
            &[0x01, 0x00, 0xAA],
        ));
        let short_ok = is_cmd_status(&short, OP_LOAD_LONG_TERM_KEYS, STATUS_INVALID_PARAMS);
        // One entry with an invalid address type (BR/EDR) is
        // skipped: success, no bond.
        let mut bad_entry = [0u8; 2 + 36];
        bad_entry[0] = 1;
        bad_entry[2 + 6] = 0x00; // type BR/EDR
        let bad = handle(&mgmt_cmd(OP_LOAD_LONG_TERM_KEYS, index, &bad_entry));
        let bad_ok = is_cmd_complete(&bad, OP_LOAD_LONG_TERM_KEYS, STATUS_SUCCESS)
            && crate::pump::bond_count(index as usize) == Some(0);
        // One valid entry (LE public, authenticated, ediv/rand).
        let peer6 = [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5];
        let mut entry = [0u8; 2 + 36];
        entry[0] = 1;
        entry[2..8].copy_from_slice(&peer6);
        entry[2 + 6] = 0x01; // LE public
        entry[2 + 7] = 0x01; // authenticated
        entry[2 + 8] = 0x00; // master (initiator)
        entry[2 + 9] = 16; // encryption size
        entry[2 + 10..2 + 12].copy_from_slice(&0x1234u16.to_le_bytes());
        entry[2 + 12..2 + 20].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        entry[2 + 20..2 + 36].copy_from_slice(&[0x5A; 16]);
        let good = handle(&mgmt_cmd(OP_LOAD_LONG_TERM_KEYS, index, &entry));
        let mut peer = [0u8; 7];
        peer[0] = 0;
        peer[1..7].copy_from_slice(&peer6);
        let loaded = is_cmd_complete(&good, OP_LOAD_LONG_TERM_KEYS, STATUS_SUCCESS)
            && crate::pump::bond_count(index as usize) == Some(1)
            && crate::pump::has_bond(index as usize, &peer) == Some(true);
        // Debug key type 0x04 is skipped (kernel skips it too).
        let mut dbg = entry;
        dbg[2 + 7] = 0x04;
        let _ = handle(&mgmt_cmd(OP_LOAD_LONG_TERM_KEYS, index, &dbg));
        let dbg_skipped = crate::pump::bond_count(index as usize) == Some(1);
        // A reload for the same peer replaces the bond (count stays 1).
        let _ = handle(&mgmt_cmd(OP_LOAD_LONG_TERM_KEYS, index, &entry));
        let replaced = crate::pump::bond_count(index as usize) == Some(1);
        // The loaded bond is a real bond: UNPAIR_DEVICE forgets it
        // (UNPAIR needs power).
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        let mut unpair_params = [0u8; 8];
        unpair_params[..6].copy_from_slice(&peer6);
        unpair_params[6] = 0x01;
        unpair_params[7] = 0x00;
        let un = handle(&mgmt_cmd(OP_UNPAIR_DEVICE, index, &unpair_params));
        let unpaired = is_cmd_complete(&un, OP_UNPAIR_DEVICE, STATUS_SUCCESS)
            && crate::pump::bond_count(index as usize) == Some(0);
        // LOAD_IRKS: one invalid entry fails the whole command.
        let mut irk_bad = [0u8; 2 + 23];
        irk_bad[0] = 1;
        irk_bad[2 + 6] = 0x00; // BR/EDR type → invalid
        let ib = handle(&mgmt_cmd(OP_LOAD_IRKS, index, &irk_bad));
        let ib_ok = is_cmd_status(&ib, OP_LOAD_IRKS, STATUS_INVALID_PARAMS);
        // Two valid entries (LE public + static LE random),
        // stored while powered with privacy off: no HCI.
        let mut irks = [0u8; 2 + 2 * 23];
        irks[0] = 2;
        irks[2..8].copy_from_slice(&peer6);
        irks[2 + 6] = 0x01;
        irks[2 + 7..2 + 23].copy_from_slice(&[0x11; 16]);
        let o2 = 2 + 23;
        irks[o2..o2 + 6].copy_from_slice(&[0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5]);
        irks[o2 + 6] = 0x02; // LE random, static bits set
        irks[o2 + 7..o2 + 23].copy_from_slice(&[0x22; 16]);
        let sent_len = lt.sent_commands().len();
        let ir = handle(&mgmt_cmd(OP_LOAD_IRKS, index, &irks));
        let ir_ok = is_cmd_complete(&ir, OP_LOAD_IRKS, STATUS_SUCCESS)
            && lt.sent_commands().len() == sent_len;
        // Power off, privacy on, power on: the resolving list is
        // programmed from the loaded IRKs (clear + add x2 + enable,
        // after the RPA: Rand + Encrypt + Set Random Address).
        enqueue_power_off_cc(&lt);
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let mut priv_params = [0u8; 17];
        priv_params[0] = 0x01;
        priv_params[1..17].copy_from_slice(&[0xAA; 16]);
        let _ = handle(&mgmt_cmd(OP_SET_PRIVACY, index, &priv_params));
        enqueue_power_on_ccs(&lt, &[0u8; 248], &[0u8; 3], false, false);
        lt.enqueue_event(cc(
            op::HCI_LE_RAND,
            0,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ));
        lt.enqueue_event(cc(
            op::HCI_LE_ENCRYPT,
            0,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ],
        ));
        lt.enqueue_event(cc(op::HCI_LE_SET_RANDOM_ADDRESS, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_CLEAR_RESOLVING_LIST, 0, &[]));
        let mut add1 = [0u8; 39];
        add1[0] = 0x00; // peer identity type: public
        add1[1..7].copy_from_slice(&peer6);
        add1[7..23].copy_from_slice(&[0x11; 16]);
        add1[23..39].copy_from_slice(&[0xAA; 16]);
        lt.enqueue_event(cc(op::HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST, 0, &[]));
        let mut add2 = [0u8; 39];
        add2[0] = 0x01; // peer identity type: random
        add2[1..7].copy_from_slice(&[0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5]);
        add2[7..23].copy_from_slice(&[0x22; 16]);
        add2[23..39].copy_from_slice(&[0xAA; 16]);
        lt.enqueue_event(cc(op::HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE, 0, &[]));
        let sent_len = lt.sent_commands().len();
        let r = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        let powered2 = is_cmd_complete(&r, OP_SET_POWERED, STATUS_SUCCESS);
        let sent = lt.sent_commands();
        let list_seq = sent.len() == sent_len + 7
            && sent[sent_len].opcode == op::HCI_LE_RAND
            && sent[sent_len + 1].opcode == op::HCI_LE_ENCRYPT
            && sent[sent_len + 2].opcode == op::HCI_LE_SET_RANDOM_ADDRESS
            && sent[sent_len + 2].params == [0x0F, 0x0E, 0x0D, 0x11, 0x22, 0x73]
            && sent[sent_len + 3].opcode == op::HCI_LE_CLEAR_RESOLVING_LIST
            && sent[sent_len + 4].opcode == op::HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST
            && sent[sent_len + 4].params.as_slice() == add1
            && sent[sent_len + 5].opcode == op::HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST
            && sent[sent_len + 5].params.as_slice() == add2
            && sent[sent_len + 6].opcode == op::HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE
            && sent[sent_len + 6].params == [0x01];
        // While powered with privacy on, a LOAD_IRKS re-programs
        // the controller copy immediately (clear + add x1 + enable).
        let mut one_irk = [0u8; 2 + 23];
        one_irk[0] = 1;
        one_irk[2..8].copy_from_slice(&peer6);
        one_irk[2 + 6] = 0x01;
        one_irk[2 + 7..2 + 23].copy_from_slice(&[0x33; 16]);
        lt.enqueue_event(cc(op::HCI_LE_CLEAR_RESOLVING_LIST, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST, 0, &[]));
        lt.enqueue_event(cc(op::HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE, 0, &[]));
        let sent_len = lt.sent_commands().len();
        let one = handle(&mgmt_cmd(OP_LOAD_IRKS, index, &one_irk));
        let mut add_one = [0u8; 39];
        add_one[0] = 0x00;
        add_one[1..7].copy_from_slice(&peer6);
        add_one[7..23].copy_from_slice(&[0x33; 16]);
        add_one[23..39].copy_from_slice(&[0xAA; 16]);
        let sent = lt.sent_commands();
        let live_ok = is_cmd_complete(&one, OP_LOAD_IRKS, STATUS_SUCCESS)
            && sent.len() == sent_len + 3
            && sent[sent_len].opcode == op::HCI_LE_CLEAR_RESOLVING_LIST
            && sent[sent_len + 1].opcode == op::HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST
            && sent[sent_len + 1].params.as_slice() == add_one
            && sent[sent_len + 2].opcode == op::HCI_LE_SET_ADDRESS_RESOLUTION_ENABLE
            && sent[sent_len + 2].params == [0x01];
        cleanup_mgmt();
        if !short_ok || !bad_ok {
            return TestResult::Fail("LOAD_LONG_TERM_KEYS length / entry validation failed");
        }
        if !loaded {
            return TestResult::Fail("LOAD_LONG_TERM_KEYS did not store the bond");
        }
        if !dbg_skipped || !replaced {
            return TestResult::Fail("LOAD_LONG_TERM_KEYS debug/replace handling failed");
        }
        if !powered || !unpaired {
            return TestResult::Fail("loaded LTK bond was not removable via UNPAIR_DEVICE");
        }
        if !ib_ok {
            return TestResult::Fail("LOAD_IRKS with an invalid entry was not INVALID_PARAMS");
        }
        if !ir_ok {
            return TestResult::Fail("LOAD_IRKS (privacy off) issued HCI instead of storing");
        }
        if !powered2 || !list_seq {
            return TestResult::Fail(
                "power-on did not program the resolving list from loaded IRKs",
            );
        }
        if !live_ok {
            return TestResult::Fail("LOAD_IRKS while powered+privacy did not re-program the list");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_load_keys);

    /// #815 (remainder tranche): SET_BREDR disables with its
    /// couplings while unpowered, is rejected while powered, and
    /// re-enables while powered only without a static address;
    /// SET_FAST_CONNECTABLE without BR/EDR is NOT_SUPPORTED.
    fn smoke_mgmt_set_bredr_couplings() -> TestResult {
        let (lt, index) = setup_controller(controller::ControllerInfo::default());
        // Unpowered: set the coupled bits, then disable BREDR.
        let _ = handle(&mgmt_cmd(OP_SET_CONNECTABLE, index, &[1]));
        let _ = handle(&mgmt_cmd(OP_SET_SSP, index, &[1]));
        let _ = handle(&mgmt_cmd(OP_SET_LINK_SECURITY, index, &[1]));
        let _ = handle(&mgmt_cmd(OP_SET_DISCOVERABLE, index, &[1, 0, 0]));
        let r = handle(&mgmt_cmd(OP_SET_BREDR, index, &[0]));
        let settings = u32::from_le_bytes([r[0][9], r[0][10], r[0][11], r[0][12]]);
        let cleared = is_cmd_complete(&r, OP_SET_BREDR, STATUS_SUCCESS)
            && settings & SETTING_BREDR == 0
            && settings & SETTING_DISCOVERABLE == 0
            && settings & SETTING_SSP == 0
            && settings & SETTING_LINK_SECURITY == 0
            && settings & SETTING_FAST_CONNECTABLE == 0
            && settings & SETTING_CONNECTABLE != 0;
        // Bad value → INVALID_PARAMS.
        let bad = handle(&mgmt_cmd(OP_SET_BREDR, index, &[0x02]));
        let bad_ok = is_cmd_status(&bad, OP_SET_BREDR, STATUS_INVALID_PARAMS);
        // Re-enable while unpowered, then power on.
        let _ = handle(&mgmt_cmd(OP_SET_BREDR, index, &[1]));
        let powered = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        // Powered disable → REJECTED.
        let dis = handle(&mgmt_cmd(OP_SET_BREDR, index, &[0]));
        let dis_ok = is_cmd_status(&dis, OP_SET_BREDR, STATUS_REJECTED);
        // Power off, disable, power on, re-enable while powered:
        // Write_Page_Scan_Type [0x00] (fast-connectable cleared).
        enqueue_power_off_cc(&lt);
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let _ = handle(&mgmt_cmd(OP_SET_BREDR, index, &[0]));
        let powered2 = power_on(&lt, index, &[0u8; 248], &[0u8; 3], false, false);
        lt.enqueue_event(cc(op::HCI_WRITE_PAGE_SCAN_TYPE, 0, &[]));
        let en = handle(&mgmt_cmd(OP_SET_BREDR, index, &[1]));
        let en_ok = is_cmd_complete(&en, OP_SET_BREDR, STATUS_SUCCESS)
            && u32::from_le_bytes([en[0][9], en[0][10], en[0][11], en[0][12]]) & SETTING_BREDR != 0
            && lt
                .sent_commands()
                .last()
                .map(|c| c.opcode == op::HCI_WRITE_PAGE_SCAN_TYPE && c.params == [0x00])
                .unwrap_or(false);
        // Static address blocks the powered re-enable: power off,
        // set a static address, disable, power on (static is
        // programmed), re-enable → REJECTED. Fast-connectable
        // without BR/EDR is NOT_SUPPORTED.
        enqueue_power_off_cc(&lt);
        let _ = handle(&mgmt_cmd(OP_SET_POWERED, index, &[0]));
        let static_addr = [0x11, 0x22, 0x33, 0x44, 0x55, 0xC1];
        let _ = handle(&mgmt_cmd(OP_SET_STATIC_ADDRESS, index, &static_addr));
        let _ = handle(&mgmt_cmd(OP_SET_BREDR, index, &[0]));
        enqueue_power_on_ccs(&lt, &[0u8; 248], &[0u8; 3], false, false);
        lt.enqueue_event(cc(op::HCI_LE_SET_RANDOM_ADDRESS, 0, &[]));
        let r = handle(&mgmt_cmd(OP_SET_POWERED, index, &[1]));
        let powered3 = is_cmd_complete(&r, OP_SET_POWERED, STATUS_SUCCESS);
        let en2 = handle(&mgmt_cmd(OP_SET_BREDR, index, &[1]));
        let en2_ok = is_cmd_status(&en2, OP_SET_BREDR, STATUS_REJECTED);
        let fc = handle(&mgmt_cmd(OP_SET_FAST_CONNECTABLE, index, &[1]));
        let fc_ok = is_cmd_status(&fc, OP_SET_FAST_CONNECTABLE, STATUS_NOT_SUPPORTED);
        cleanup_mgmt();
        if !cleared {
            return TestResult::Fail("unpowered SET_BREDR(0) did not clear the coupled bits");
        }
        if !bad_ok {
            return TestResult::Fail("SET_BREDR(0x02) was not INVALID_PARAMS");
        }
        if !powered || !dis_ok {
            return TestResult::Fail("powered SET_BREDR(0) was not REJECTED");
        }
        if !powered2 || !en_ok {
            return TestResult::Fail("powered SET_BREDR(1) did not re-enable BREDR");
        }
        if !powered3 || !en2_ok {
            return TestResult::Fail("powered SET_BREDR(1) with a static address was not REJECTED");
        }
        if !fc_ok {
            return TestResult::Fail("SET_FAST_CONNECTABLE without BR/EDR was not NOT_SUPPORTED");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/mgmt", smoke_mgmt_set_bredr_couplings);
}
