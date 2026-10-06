//! Linux Bluetooth Management (mgmt) API — the `HCI_CHANNEL_CONTROL` protocol
//! that `bluetoothd` / `btmgmt` drive adapters through.
//!
//! This is a software-contract implementation over the native controller
//! registry ([`crate::controller`]); real HCI remains hardware-gated. The
//! read commands (adapter enumeration + info) let userspace discover the
//! controllers the native stack brought up.
//!
//! Wire format and status codes follow `/usr/src/linux`
//! `net/bluetooth/mgmt.c` + `include/net/bluetooth/mgmt.h`.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::controller;

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
const OP_SET_SECURE_CONN: u16 = 0x002d;

// Events (mgmt.h MGMT_EV_*).
const EV_CMD_COMPLETE: u16 = 0x0001;
const EV_CMD_STATUS: u16 = 0x0002;
const EV_INDEX_ADDED: u16 = 0x0004;
const EV_INDEX_REMOVED: u16 = 0x0005;
const EV_NEW_SETTINGS: u16 = 0x0006;

// Status codes (mgmt.h MGMT_STATUS_*).
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_UNKNOWN_COMMAND: u8 = 0x01;
const STATUS_INVALID_PARAMS: u8 = 0x0d;
const STATUS_INVALID_INDEX: u8 = 0x11;

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
const SETTING_SECURE_CONN: u32 = 1 << 11;

/// Per-controller current settings bitmap, keyed by HCI index. A controller
/// comes up configured (BR/EDR + LE capable) but not powered, matching how
/// mgmt reports an adapter before SET_POWERED.
static SETTINGS: IrqSafeSpinLock<BTreeMap<u16, u32>> = IrqSafeSpinLock::new(BTreeMap::new());
const DEFAULT_SETTINGS: u32 = SETTING_BREDR | SETTING_LE;

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
    | SETTING_SECURE_CONN;

fn read_info_rp(info: &controller::ControllerInfo, current: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(
        6 + 1 + 2 + 4 + 4 + 3 + MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH,
    );
    d.extend_from_slice(&info.bd_addr);
    d.push(info.hci_version);
    d.extend_from_slice(&info.manufacturer.to_le_bytes());
    d.extend_from_slice(&SUPPORTED_SETTINGS.to_le_bytes());
    d.extend_from_slice(&current.to_le_bytes());
    d.extend_from_slice(&[0u8; 3]); // dev_class
    d.extend_from_slice(&[0u8; MGMT_MAX_NAME_LENGTH]);
    d.extend_from_slice(&[0u8; MGMT_MAX_SHORT_NAME_LENGTH]);
    d
}

/// A mode-setting command (`SET_POWERED`/`SET_CONNECTABLE`/…): validate the
/// index + the `mgmt_mode` value, toggle `bit`, and reply with the new
/// current-settings bitmap. `max_val` is 1 for on/off modes, 2 for the
/// limited-discoverable case.
fn set_mode(index: u16, opcode: u16, params: &[u8], bit: u32, max_val: u8) -> Vec<u8> {
    if (index as usize) >= controller::controller_count() {
        return cmd_status(index, opcode, STATUS_INVALID_INDEX);
    }
    if params.is_empty() || params[0] > max_val {
        return cmd_status(index, opcode, STATUS_INVALID_PARAMS);
    }
    let settings = set_setting_bit(index, bit, params[0] != 0);
    cmd_complete(index, opcode, STATUS_SUCCESS, &settings.to_le_bytes())
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
                OP_SET_SECURE_CONN,
            ];
            let events = [
                EV_CMD_COMPLETE,
                EV_CMD_STATUS,
                EV_INDEX_ADDED,
                EV_INDEX_REMOVED,
                EV_NEW_SETTINGS,
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
            let count = controller::controller_count();
            let mut data = Vec::with_capacity(2 + 2 * count);
            data.extend_from_slice(&(count as u16).to_le_bytes());
            for i in 0..count {
                data.extend_from_slice(&(i as u16).to_le_bytes());
            }
            alloc::vec![cmd_complete(index, opcode, STATUS_SUCCESS, &data)]
        }
        OP_READ_INFO => {
            let controllers = controller::controllers();
            match controllers.get(index as usize) {
                Some(c) => {
                    let data = read_info_rp(&c.info(), current_settings(index));
                    alloc::vec![cmd_complete(index, opcode, STATUS_SUCCESS, &data)]
                }
                None => alloc::vec![cmd_status(index, opcode, STATUS_INVALID_INDEX)],
            }
        }
        OP_SET_POWERED => alloc::vec![set_mode(index, opcode, params, SETTING_POWERED, 1)],
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
            alloc::vec![set_mode(index, opcode, params, SETTING_SECURE_CONN, 1)]
        }
        // Limited discoverable (val 2) is accepted; the timeout field is ignored.
        OP_SET_DISCOVERABLE => {
            alloc::vec![set_mode(index, opcode, params, SETTING_DISCOVERABLE, 2)]
        }
        _ => alloc::vec![cmd_status(index, opcode, STATUS_UNKNOWN_COMMAND)],
    }
}

/// Whether controller `index` is currently powered (mgmt POWERED setting).
/// Used by the legacy HCIGETDEVINFO ioctl to report the HCI_UP flag.
pub fn is_powered(index: u16) -> bool {
    current_settings(index) & SETTING_POWERED != 0
}

/// Set controller `index`'s powered setting (the legacy HCIDEVUP/HCIDEVDOWN
/// ioctls map onto the same state as mgmt SET_POWERED).
pub fn set_powered(index: u16, on: bool) {
    set_setting_bit(index, SETTING_POWERED, on);
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
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn mgmt_cmd(opcode: u16, index: u16, params: &[u8]) -> Vec<u8> {
        frame(opcode, index, params)
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
        SETTINGS.lock().clear();

        let transport: Arc<dyn crate::transport::HciTransport> =
            Arc::new(LoopbackTransport::new("mgmt-set"));
        crate::transport::register(transport.clone());
        let index =
            controller::register_ready_transport(transport, controller::ControllerInfo::default())
                as u16;

        let cleanup = || {
            crate::transport::__test_reset();
            controller::__test_reset_controllers();
            SETTINGS.lock().clear();
        };

        // SET_POWERED(1) → CMD_COMPLETE carrying the new settings with POWERED.
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
}
