//! virtio-scsi wire format — pure-data encode/decode (VirtIO 1.2
//! §5.6.6).
//!
//! Default sizes from §5.6.4: `cdb_size = 32`, `sense_size = 96`
//! unless renegotiated via the device-config write path. Stage 2 hard-
//! codes the defaults.

use core::mem::size_of;

/// `cdb_size` default (§5.6.4).
pub const CDB_SIZE:   usize = 32;
/// `sense_size` default (§5.6.4).
pub const SENSE_SIZE: usize = 96;

// ── §5.6.6.1 Device operation: command queue ──────────────────────

/// Task-attribute values (§5.6.6.1 — `task_attr`).
pub const VIRTIO_SCSI_S_SIMPLE:        u8 = 0;
pub const VIRTIO_SCSI_S_ORDERED:       u8 = 1;
pub const VIRTIO_SCSI_S_HEAD:          u8 = 2;
pub const VIRTIO_SCSI_S_ACA:           u8 = 3;

/// `response` byte (§5.6.6.1).
pub const VIRTIO_SCSI_S_OK:               u8 = 0;
pub const VIRTIO_SCSI_S_OVERRUN:          u8 = 1;
pub const VIRTIO_SCSI_S_ABORTED:          u8 = 2;
pub const VIRTIO_SCSI_S_BAD_TARGET:       u8 = 3;
pub const VIRTIO_SCSI_S_RESET:            u8 = 4;
pub const VIRTIO_SCSI_S_BUSY:             u8 = 5;
pub const VIRTIO_SCSI_S_TRANSPORT_FAILURE:u8 = 6;
pub const VIRTIO_SCSI_S_TARGET_FAILURE:   u8 = 7;
pub const VIRTIO_SCSI_S_NEXUS_FAILURE:    u8 = 8;
pub const VIRTIO_SCSI_S_FAILURE:          u8 = 9;

/// SCSI REPORT LUNS opcode (SPC-4 §6.33).
pub const SCSI_OP_REPORT_LUNS: u8 = 0xA0;

/// Command request header (§5.6.6.1, `virtio_scsi_cmd_req`).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct VirtioScsiCmdReq {
    pub lun:       [u8; 8],
    pub id:        u64,
    pub task_attr: u8,
    pub prio:      u8,
    pub crn:       u8,
    pub cdb:       [u8; CDB_SIZE],
}

const _: () = assert!(size_of::<VirtioScsiCmdReq>() == 8 + 8 + 3 + CDB_SIZE);

/// Command response (§5.6.6.1, `virtio_scsi_cmd_resp`).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct VirtioScsiCmdResp {
    pub sense_len:        u32,
    pub residual:          u32,
    pub status_qualifier:  u16,
    pub status:            u8,
    pub response:          u8,
    pub sense:            [u8; SENSE_SIZE],
}

const _: () = assert!(size_of::<VirtioScsiCmdResp>() == 4 + 4 + 2 + 1 + 1 + SENSE_SIZE);

/// Build a SCSI LUN field per SAM-5: byte 0 = bus, byte 1 = target,
/// bytes 2-3 = LUN (single-level, peripheral addressing 0b00). The
/// virtio-scsi spec (§5.6.6.1) requires `lun[0] = 1`, then target/LUN.
pub fn build_lun(target: u8, lun: u16) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = 1;
    out[1] = target;
    // Single-level LUN, 14-bit value (MSB zero = peripheral addressing).
    out[2] = ((lun >> 8) & 0x3F) as u8;
    out[3] = (lun & 0xFF) as u8;
    out
}

/// Build a REPORT LUNS CDB (SPC-4 §6.33). 12-byte CDB padded into
/// the `CDB_SIZE` slot.
pub fn build_report_luns_cdb(alloc_len: u32) -> [u8; CDB_SIZE] {
    let mut cdb = [0u8; CDB_SIZE];
    cdb[0] = SCSI_OP_REPORT_LUNS;
    // SELECT REPORT = 0 (all logical units).
    cdb[2] = 0;
    cdb[6] = ((alloc_len >> 24) & 0xFF) as u8;
    cdb[7] = ((alloc_len >> 16) & 0xFF) as u8;
    cdb[8] = ((alloc_len >>  8) & 0xFF) as u8;
    cdb[9] = ( alloc_len        & 0xFF) as u8;
    cdb
}

/// Encode a `virtio_scsi_cmd_req` to its on-wire byte sequence.
/// Returns the request header — virtqueue chaining bolts the data-out
/// segment after this header.
pub fn encode_cmd_req(
    target:    u8,
    lun:       u16,
    id:        u64,
    task_attr: u8,
    cdb:       [u8; CDB_SIZE],
) -> VirtioScsiCmdReq {
    VirtioScsiCmdReq {
        lun: build_lun(target, lun),
        id,
        task_attr,
        prio: 0,
        crn:  0,
        cdb,
    }
}

/// Decoded command response.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmdRespDecoded {
    pub sense_len:        u32,
    pub residual:          u32,
    pub status_qualifier:  u16,
    pub status:            u8,
    pub response:          u8,
}

/// Decode a `virtio_scsi_cmd_resp` header — the sense bytes are not
/// copied (caller can read them directly out of the response buffer).
pub fn decode_cmd_resp(buf: &VirtioScsiCmdResp) -> CmdRespDecoded {
    // `repr(C, packed)` — all fields require an unaligned read.
    let sense_len        = buf.sense_len;
    let residual         = buf.residual;
    let status_qualifier = buf.status_qualifier;
    let status           = buf.status;
    let response         = buf.response;
    CmdRespDecoded {
        sense_len, residual, status_qualifier, status, response,
    }
}

// ── §5.6.6.2 Device operation: control queue (TMF) ────────────────

/// `type` field (§5.6.6.2).
pub const VIRTIO_SCSI_T_TMF:           u32 = 0;
pub const VIRTIO_SCSI_T_AN_QUERY:      u32 = 1;
pub const VIRTIO_SCSI_T_AN_SUBSCRIBE:  u32 = 2;

/// TMF `subtype` values (§5.6.6.2).
pub const VIRTIO_SCSI_T_TMF_ABORT_TASK:           u32 = 0;
pub const VIRTIO_SCSI_T_TMF_ABORT_TASK_SET:       u32 = 1;
pub const VIRTIO_SCSI_T_TMF_CLEAR_ACA:            u32 = 2;
pub const VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET:       u32 = 3;
pub const VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET:      u32 = 4;
pub const VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET:   u32 = 5;
pub const VIRTIO_SCSI_T_TMF_QUERY_TASK:           u32 = 6;
pub const VIRTIO_SCSI_T_TMF_QUERY_TASK_SET:       u32 = 7;

/// Task-management request (§5.6.6.2, `virtio_scsi_ctrl_tmf_req`).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct VirtioScsiCtrlTmfReq {
    pub r#type:  u32,
    pub subtype: u32,
    pub lun:     [u8; 8],
    pub id:      u64,
}

const _: () = assert!(size_of::<VirtioScsiCtrlTmfReq>() == 4 + 4 + 8 + 8);

/// Task-management response (§5.6.6.2, `virtio_scsi_ctrl_tmf_resp`).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct VirtioScsiCtrlTmfResp {
    pub response: u8,
}

/// Build a TMF request targeting `target / lun`.
pub fn encode_tmf_req(
    subtype: u32,
    target:  u8,
    lun:     u16,
    id:      u64,
) -> VirtioScsiCtrlTmfReq {
    VirtioScsiCtrlTmfReq {
        r#type: VIRTIO_SCSI_T_TMF,
        subtype,
        lun: build_lun(target, lun),
        id,
    }
}
