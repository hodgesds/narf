//! Ethernet port command encoders / decoders — `SET_PORT` and `QUERY_PORT`.
//!
//! Reference: ConnectX-3 PRM §9.4 (command reference), specifically
//! SET_PORT §9.4.19 and QUERY_PORT §9.4.18.
//!
//! `SET_PORT` programs per-port Ethernet configuration. The firmware
//! selects between IB and Ethernet opcode variants through the
//! `op_modifier` field (`SET_PORT_ETH_OPCODE`). Within the Ethernet
//! variant three sub-commands exist, selected by the high byte of the
//! 32-bit input modifier (`in_mod = ((sub as u32) << 8) | port`):
//!
//! | sub-command          | constant              | purpose                |
//! |----------------------|-----------------------|------------------------|
//! | GENERAL (`0x00`)     | `SET_PORT_GENERAL`    | MTU + pause config     |
//! | RQP\_CALC (`0x01`)   | `SET_PORT_RQP_CALC`   | RSS / QP count config  |
//! | MAC\_TABLE (`0x02`)  | `SET_PORT_MAC_TABLE`  | write MAC address table|
//!
//! `QUERY_PORT` (opcode `0x43`) returns a 32-byte port-info context in
//! the output mailbox. This module decodes the Ethernet-relevant fields
//! from that context into [`PortInfo`].
//!
//! All multi-byte fields in both mailboxes are big-endian (PRM §1.4).
//!
//! | SET_PORT GENERAL offset | field      | width   |
//! |-------------------------|------------|---------|
//! | 0x03                    | flags      | u8      |
//! | 0x06..0x07              | mtu        | BE u16  |
//!
//! | QUERY_PORT offset | field       | width   |
//! |-------------------|-------------|---------|
//! | 0x00              | link / flags| u8      |
//! | 0x02..0x03        | eth_mtu     | BE u16  |
//! | 0x05              | link_speed  | u8      |
//! | 0x10..0x17        | mac (BE64)  | BE u64  |

use alloc::vec::Vec;

use super::wire::{get_be16, get_be64, get_u8, put_be16, put_be64, put_u8};

// ── SET_PORT op_modifier ──────────────────────────────────────────────────────

/// `op_modifier` value that selects the Ethernet opcode variant of SET_PORT.
pub const SET_PORT_ETH_OPCODE: u8 = 1;

// ── SET_PORT Ethernet sub-commands ───────────────────────────────────────────

/// SET_PORT sub-command: program MTU and pause parameters (high byte of
/// `in_mod`).
pub const SET_PORT_GENERAL: u8 = 0;
/// SET_PORT sub-command: configure RSS QP count / base (high byte of `in_mod`).
pub const SET_PORT_RQP_CALC: u8 = 1;
/// SET_PORT sub-command: write the per-port MAC address table (high byte of
/// `in_mod`).
pub const SET_PORT_MAC_TABLE: u8 = 2;

// ── SET_PORT GENERAL flags ────────────────────────────────────────────────────

/// Validity flags for the GENERAL mailbox — set all three fields valid:
/// MTU valid (bit 0), pause RX valid (bit 1), pause TX valid (bit 2).
pub const SET_PORT_GEN_ALL_VALID: u8 = 0x7;

// ── MAC table entry encoding ──────────────────────────────────────────────────

/// Entry-valid bit for a MAC table slot (bit 63 of the BE64 entry).
pub const MLX4_MAC_VALID: u64 = 1 << 63;
/// Mask for the 48-bit MAC value within a MAC table entry.
pub const MLX4_MAC_MASK: u64 = 0xffff_ffff_ffff;

// ── SET_PORT GENERAL mailbox ──────────────────────────────────────────────────

/// Length in bytes of the SET_PORT GENERAL input mailbox.
pub const SET_PORT_GENERAL_LEN: usize = 0x20;

/// Build a SET_PORT GENERAL input mailbox that programs the Ethernet port MTU.
///
/// The returned buffer is `SET_PORT_GENERAL_LEN` (0x20) bytes long. All
/// bytes are zero-initialised; the validity flags are written at offset
/// 0x03 and the wire MTU (big-endian) at offset 0x06.
///
/// Reference: ConnectX-3 PRM §9.4.19, SET_PORT (Ethernet, sub-command 0).
pub fn build_set_port_general(wire_mtu: u16) -> [u8; SET_PORT_GENERAL_LEN] {
    let mut mb = [0u8; SET_PORT_GENERAL_LEN];
    put_u8(&mut mb, 0x03, SET_PORT_GEN_ALL_VALID);
    put_be16(&mut mb, 0x06, wire_mtu);
    mb
}

// ── SET_PORT MAC_TABLE mailbox ────────────────────────────────────────────────

/// Build a SET_PORT MAC_TABLE input mailbox from a list of MAC addresses.
///
/// The mailbox is `table_slots * 8` bytes, one BE64 entry per slot. Each
/// occupied slot encodes `(mac_to_u64(mac) & MLX4_MAC_MASK) | MLX4_MAC_VALID`.
/// Slots beyond the supplied MAC list are left as zero (invalid).
///
/// Reference: ConnectX-3 PRM §9.4.19, SET_PORT (Ethernet, sub-command 2).
pub fn build_mac_table(macs: &[[u8; 6]], table_slots: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; table_slots * 8];
    for (i, mac) in macs.iter().take(table_slots).enumerate() {
        let entry = (mac_to_u64(*mac) & MLX4_MAC_MASK) | MLX4_MAC_VALID;
        put_be64(&mut out, i * 8, entry);
    }
    out
}

// ── MAC ↔ u64 helpers ─────────────────────────────────────────────────────────

/// Pack a 6-byte big-endian MAC address into the low 48 bits of a `u64`.
///
/// `mac[0]` occupies bits 47..40 (most significant); `mac[5]` occupies
/// bits 7..0 (least significant).
#[inline]
pub fn mac_to_u64(mac: [u8; 6]) -> u64 {
    ((mac[0] as u64) << 40)
        | ((mac[1] as u64) << 32)
        | ((mac[2] as u64) << 24)
        | ((mac[3] as u64) << 16)
        | ((mac[4] as u64) << 8)
        | (mac[5] as u64)
}

/// Unpack the low 48 bits of a `u64` into a 6-byte big-endian MAC address.
#[inline]
pub fn u64_to_mac(v: u64) -> [u8; 6] {
    [
        ((v >> 40) & 0xff) as u8,
        ((v >> 32) & 0xff) as u8,
        ((v >> 24) & 0xff) as u8,
        ((v >> 16) & 0xff) as u8,
        ((v >> 8) & 0xff) as u8,
        (v & 0xff) as u8,
    ]
}

// ── QUERY_PORT decoder ────────────────────────────────────────────────────────

/// Decoded fields from a QUERY_PORT (opcode `0x43`) output mailbox.
///
/// Reference: ConnectX-3 PRM §9.4.18 (QUERY_PORT Ethernet port-info context).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortInfo {
    /// `true` when the physical link is up (bit 7 of byte 0x00).
    pub link_up: bool,
    /// Current MAC address of the port (from the low 48 bits of the BE64
    /// at offset 0x10).
    pub mac: [u8; 6],
    /// Negotiated Ethernet MTU reported by firmware (offset 0x02).
    pub eth_mtu: u16,
    /// Link speed in Mbit/s, decoded from the speed/type byte at offset
    /// 0x05.  `None` when the firmware reports an unrecognised speed code.
    pub speed_mbps: Option<u32>,
}

/// Decode a QUERY_PORT output mailbox into a [`PortInfo`].
///
/// The caller must pass the full firmware output buffer; relevant offsets:
///
/// | offset | field        | encoding                   |
/// |--------|--------------|----------------------------|
/// | 0x00   | link / flags | bit 7 = link up            |
/// | 0x02   | eth_mtu      | BE u16                     |
/// | 0x05   | link_speed   | lower 7 bits (mask 0x6f)   |
/// | 0x10   | mac (BE64)   | low 48 bits = MAC address  |
///
/// Reference: ConnectX-3 PRM §9.4.18.
pub fn decode_query_port(mb: &[u8]) -> PortInfo {
    let link_up = (get_u8(mb, 0x00) & 0x80) != 0;
    let eth_mtu = get_be16(mb, 0x02);
    let link_speed = get_u8(mb, 0x05) & 0x6f;
    let mac = u64_to_mac(get_be64(mb, 0x10));

    let speed_mbps = match link_speed {
        0x00 => Some(10_000), // 10G XAUI
        0x01 => Some(10_000), // 10G XFI
        0x02 => Some(1_000),  // 1G
        0x04 => Some(100),    // 100M
        0x08 => Some(20_000), // 20G
        0x20 => Some(56_000), // 56G
        0x40 => Some(40_000), // 40G
        _ => None,
    };

    PortInfo {
        link_up,
        mac,
        eth_mtu,
        speed_mbps,
    }
}

/// Legacy A0 single-QP receive steering (Linux mlx4_SET_PORT_qpn_calc).
/// MAC table slot zero selects base_qpn; n_mac/n_vlan/n_prio are all zero.
/// Multicast defaults to that QP, including broadcast ARP/DHCP.
pub fn build_rqp_calc(base_qpn: u32) -> [u8; 28] {
    let mut context = [0u8; 28];
    super::wire::put_be32(&mut context, 0, base_qpn);
    context[13] = 0; // MLX4_NO_VLAN_IDX
    context[15] = 1; // MLX4_VLAN_MISS_IDX
    super::wire::put_be32(&mut context, 20, base_qpn);
    super::wire::put_be32(&mut context, 24, (2 << 30) | base_qpn);
    context
}
