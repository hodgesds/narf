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

use alloc::vec::Vec;

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

// Events (mgmt.h MGMT_EV_*).
const EV_CMD_COMPLETE: u16 = 0x0001;
const EV_CMD_STATUS: u16 = 0x0002;
const EV_INDEX_ADDED: u16 = 0x0004;
const EV_INDEX_REMOVED: u16 = 0x0005;

// Status codes (mgmt.h MGMT_STATUS_*).
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_UNKNOWN_COMMAND: u8 = 0x01;
const STATUS_INVALID_PARAMS: u8 = 0x0d;
const STATUS_INVALID_INDEX: u8 = 0x11;

// Controller settings bitmap (mgmt.h MGMT_SETTING_*).
const SETTING_POWERED: u32 = 1 << 0;
const SETTING_CONNECTABLE: u32 = 1 << 1;
const SETTING_BONDABLE: u32 = 1 << 4;
const SETTING_SSP: u32 = 1 << 6;
const SETTING_BREDR: u32 = 1 << 7;
const SETTING_LE: u32 = 1 << 9;
const SETTING_SECURE_CONN: u32 = 1 << 11;

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
fn read_info_rp(info: &controller::ControllerInfo) -> Vec<u8> {
    let mut d = Vec::with_capacity(
        6 + 1 + 2 + 4 + 4 + 3 + MGMT_MAX_NAME_LENGTH + MGMT_MAX_SHORT_NAME_LENGTH,
    );
    d.extend_from_slice(&info.bd_addr);
    d.push(info.hci_version);
    d.extend_from_slice(&info.manufacturer.to_le_bytes());
    let supported = SETTING_POWERED
        | SETTING_CONNECTABLE
        | SETTING_BONDABLE
        | SETTING_SSP
        | SETTING_BREDR
        | SETTING_LE
        | SETTING_SECURE_CONN;
    d.extend_from_slice(&supported.to_le_bytes());
    // Not powered until SET_POWERED (wired in the next stage).
    let current = SETTING_BREDR | SETTING_LE;
    d.extend_from_slice(&current.to_le_bytes());
    d.extend_from_slice(&[0u8; 3]); // dev_class
    d.extend_from_slice(&[0u8; MGMT_MAX_NAME_LENGTH]);
    d.extend_from_slice(&[0u8; MGMT_MAX_SHORT_NAME_LENGTH]);
    d
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
            ];
            let events = [
                EV_CMD_COMPLETE,
                EV_CMD_STATUS,
                EV_INDEX_ADDED,
                EV_INDEX_REMOVED,
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
                    let data = read_info_rp(&c.info());
                    alloc::vec![cmd_complete(index, opcode, STATUS_SUCCESS, &data)]
                }
                None => alloc::vec![cmd_status(index, opcode, STATUS_INVALID_INDEX)],
            }
        }
        _ => alloc::vec![cmd_status(index, opcode, STATUS_UNKNOWN_COMMAND)],
    }
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
}
