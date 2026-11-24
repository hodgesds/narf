//! Firmware-mailbox decoders — `QUERY_FW`, `QUERY_DEV_CAP`, `QUERY_ADAPTER`.
//!
//! Each HCR command returns its result in a 4-KiB output mailbox whose bytes
//! are big-endian on the wire (ConnectX-3 PRM §9). These pure functions lift
//! the raw mailbox bytes into typed Rust structs. They assume the caller
//! passes a correctly-sized buffer (see [`super::cmd::MAILBOX_SIZE`]); the
//! byte offsets below are taken directly from the PRM field tables.
//!
//! Reference: ConnectX-3 PRM §9.4 — command reference (QUERY_FW §9.4.4,
//! QUERY_DEV_CAP §9.4.3, QUERY_ADAPTER §9.4.6).
//!
//! | command          | field table offset range |
//! |------------------|--------------------------|
//! | QUERY_FW         | 0x00 – 0x0a              |
//! | QUERY_DEV_CAP    | 0x11 – 0x92              |
//! | QUERY_ADAPTER    | 0x10 – 0x60              |

use super::wire::{get_be16, get_u8};

// ── QUERY_FW ──────────────────────────────────────────────────────────────────

/// Decoded output of `QUERY_FW`.
///
/// The firmware version triple `(major, minor, subminor)` follows the
/// ConnectX-3 PRM convention: the u64 at byte 0 carries `fw_pages` in its
/// most-significant 16 bits, then `major`, then `subminor`, then `minor`
/// in descending significance — subminor sits at a more-significant position
/// than minor.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FwInfo {
    /// Firmware major version number.
    pub major: u16,
    /// Firmware minor version number.
    pub minor: u16,
    /// Firmware sub-minor version number.
    pub subminor: u16,
    /// Command-interface revision.
    pub cmd_iface_rev: u16,
    /// Number of firmware pages the driver must map.
    pub fw_pages: u32,
}

/// Decode a `QUERY_FW` output mailbox.
///
/// Byte layout (big-endian, PRM §9.4.4):
///
/// | offset | field          | width |
/// |--------|----------------|-------|
/// | 0x00   | fw_pages       | u16   |
/// | 0x02   | major          | u16   |
/// | 0x04   | subminor       | u16   |
/// | 0x06   | minor          | u16   |
/// | 0x0a   | cmd_iface_rev  | u16   |
pub fn decode_query_fw(mb: &[u8]) -> FwInfo {
    FwInfo {
        fw_pages: get_be16(mb, 0x00) as u32,
        major: get_be16(mb, 0x02),
        subminor: get_be16(mb, 0x04),
        minor: get_be16(mb, 0x06),
        cmd_iface_rev: get_be16(mb, 0x0a),
    }
}

// ── QUERY_DEV_CAP ─────────────────────────────────────────────────────────────

/// Decoded output of `QUERY_DEV_CAP`.
///
/// All `log2_*` fields are the firmware-reported log₂ of the corresponding
/// hardware limit or reservation. `*_entry_sz` fields are context-block sizes
/// in bytes, returned as `u16` BE values directly from the mailbox.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DevCap {
    /// Number of physical ports (1 or 2).
    pub num_ports: u8,

    /// Log₂ of reserved QP count.
    pub log2_rsvd_qps: u8,
    /// Log₂ of maximum QP count.
    pub log2_max_qps: u8,

    /// Log₂ of reserved CQ count.
    pub log2_rsvd_cqs: u8,
    /// Log₂ of maximum CQ count.
    pub log2_max_cqs: u8,

    /// Log₂ of reserved EQ count.
    pub log2_rsvd_eqs: u8,
    /// Log₂ of maximum EQ count.
    pub log2_max_eqs: u8,

    /// Log₂ of reserved MTT-segment count.
    pub log2_rsvd_mtts: u8,
    /// Log₂ of maximum MPT (memory protection table) entry count.
    pub log2_max_mpts: u8,
    /// Log₂ of reserved MRW (memory-region/window) count.
    pub log2_rsvd_mrws: u8,

    /// Log₂ of maximum QP WQE depth (entries per QP).
    pub log2_max_qp_sz: u8,
    /// Log₂ of maximum CQ depth (entries per CQ).
    pub log2_max_cq_sz: u8,

    /// QP context entry size in bytes.
    pub qpc_entry_sz: u16,
    /// CQ context entry size in bytes.
    pub cqc_entry_sz: u16,
    /// EQ context entry size in bytes.
    pub eqc_entry_sz: u16,
    /// Auxiliary context entry size in bytes.
    pub auxc_entry_sz: u16,
    /// Alternate-path context entry size in bytes.
    pub altc_entry_sz: u16,
    /// RDMA-RC context entry size in bytes.
    pub rdmarc_entry_sz: u16,
    /// cMPT (completion MPT) entry size in bytes.
    pub cmpt_entry_sz: u16,
    /// MTT entry size in bytes.
    pub mtt_entry_sz: u16,
    /// dMPT (data MPT) entry size in bytes.
    pub dmpt_entry_sz: u16,

    /// Log₂ of the UAR region size; the raw 6-bit value is biased by +20
    /// so the minimum legal value maps to 1 MiB.
    pub log2_uar_sz: u8,
    /// Number of firmware-reserved UAR pages at the low end of the UAR
    /// region; the driver's own doorbell UAR is the first page past them.
    pub reserved_uars: u8,
}

/// Decode a `QUERY_DEV_CAP` output mailbox.
///
/// Selected byte offsets (PRM §9.4.3).  Bit-masked sub-fields carry a mask
/// comment showing which bits the PRM assigns to the value:
///
/// | offset | mask | field             |
/// |--------|------|-------------------|
/// | 0x11   | —    | log2_max_qp_sz    |
/// | 0x12   | 0x0f | log2_rsvd_qps     |
/// | 0x13   | 0x1f | log2_max_qps      |
/// | 0x19   | —    | log2_max_cq_sz    |
/// | 0x1a   | 0x0f | log2_rsvd_cqs     |
/// | 0x1b   | 0x1f | log2_max_cqs      |
/// | 0x1d   | 0x3f | log2_max_mpts     |
/// | 0x1e   | 0x0f | log2_rsvd_eqs     |
/// | 0x1f   | 0x0f | log2_max_eqs      |
/// | 0x20   | hi4  | log2_rsvd_mtts    |
/// | 0x22   | 0x0f | log2_rsvd_mrws    |
/// | 0x37   | 0x0f | num_ports         |
/// | 0x48   | hi4  | reserved_uars     |
/// | 0x49   | 0x3f | log2_uar_sz (+20) |
/// | 0x80   | —    | rdmarc_entry_sz   |
/// | 0x82   | —    | qpc_entry_sz      |
/// | 0x84   | —    | auxc_entry_sz     |
/// | 0x86   | —    | altc_entry_sz     |
/// | 0x88   | —    | eqc_entry_sz      |
/// | 0x8a   | —    | cqc_entry_sz      |
/// | 0x8e   | —    | cmpt_entry_sz     |
/// | 0x90   | —    | mtt_entry_sz      |
/// | 0x92   | —    | dmpt_entry_sz     |
pub fn decode_query_dev_cap(mb: &[u8]) -> DevCap {
    DevCap {
        log2_max_qp_sz: get_u8(mb, 0x11),
        log2_rsvd_qps: get_u8(mb, 0x12) & 0x0f,
        log2_max_qps: get_u8(mb, 0x13) & 0x1f,
        log2_max_cq_sz: get_u8(mb, 0x19),
        log2_rsvd_cqs: get_u8(mb, 0x1a) & 0x0f,
        log2_max_cqs: get_u8(mb, 0x1b) & 0x1f,
        log2_max_mpts: get_u8(mb, 0x1d) & 0x3f,
        log2_rsvd_eqs: get_u8(mb, 0x1e) & 0x0f,
        log2_max_eqs: get_u8(mb, 0x1f) & 0x0f,
        log2_rsvd_mtts: get_u8(mb, 0x20) >> 4,
        log2_rsvd_mrws: get_u8(mb, 0x22) & 0x0f,
        num_ports: get_u8(mb, 0x37) & 0x0f,
        reserved_uars: get_u8(mb, 0x48) >> 4,
        log2_uar_sz: (get_u8(mb, 0x49) & 0x3f) + 20,
        rdmarc_entry_sz: get_be16(mb, 0x80),
        qpc_entry_sz: get_be16(mb, 0x82),
        auxc_entry_sz: get_be16(mb, 0x84),
        altc_entry_sz: get_be16(mb, 0x86),
        eqc_entry_sz: get_be16(mb, 0x88),
        cqc_entry_sz: get_be16(mb, 0x8a),
        cmpt_entry_sz: get_be16(mb, 0x8e),
        mtt_entry_sz: get_be16(mb, 0x90),
        dmpt_entry_sz: get_be16(mb, 0x92),
    }
}

// ── QUERY_ADAPTER ─────────────────────────────────────────────────────────────

/// Decoded output of `QUERY_ADAPTER`.
///
/// The 64-byte `board_id` is a firmware-assigned opaque identifier for the
/// board SKU; it is typically an ASCII string padded with null bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterInfo {
    /// INTx interrupt pin assignment (PCI `INTA#`..`INTD#` encoded as 0..3).
    pub inta_pin: u8,
    /// Board identifier string, 64 bytes, firmware-defined encoding.
    pub board_id: [u8; 64],
}

/// Decode a `QUERY_ADAPTER` output mailbox.
///
/// Byte layout (PRM §9.4.6):
///
/// | offset    | field      | width   |
/// |-----------|------------|---------|
/// | 0x10      | inta_pin   | u8      |
/// | 0x20–0x5f | board_id   | 64 B    |
pub fn decode_query_adapter(mb: &[u8]) -> AdapterInfo {
    let inta_pin = get_u8(mb, 0x10);
    let mut board_id = [0u8; 64];
    board_id.copy_from_slice(&mb[0x20..0x60]);
    AdapterInfo { inta_pin, board_id }
}
