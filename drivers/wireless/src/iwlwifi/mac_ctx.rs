//! MAC context command — iwlwifi firmware MAC_CONTEXT_CMD (0x28) and
//! TIME_EVENT_CMD (0x29).
//!
//! After the ALIVE handshake the MVM firmware requires a MAC context
//! before it will pass any frames. The host builds and sends:
//!
//!   1. `MAC_CONTEXT_CMD (0x28)` — writes the MAC address, sets the
//!      context type (STATION / IBSS), and configures EDCA/QoS.
//!   2. `TIME_EVENT_CMD (0x29)` — schedules a beacon-monitor time
//!      event so the chip listens at the expected TBTT interval.
//!
//! Commands are dispatched through the existing `CmdQueue` (TX queue 0
//! in NARF's iwlwifi driver) using `IwlMmio::write` to the PRPH
//! doorbell. The 8-byte command response path is out of scope for this
//! stage — we only build + encode the command bodies.
//!
//! ## References (Linux `drivers/net/wireless/intel/iwlwifi/`)
//!
//! - `fw/api/mac.h::iwl_mac_ctx_cmd` (line 295–351) — MAC_CONTEXT_CMD
//!   layout, MAC type enum, filter flags.
//! - `fw/api/mac.h::iwl_ac_qos` (line 269-291) — per-AC QoS params.
//! - `fw/api/time-event.h::iwl_time_event_cmd` (line 214-228) —
//!   TIME_EVENT_CMD layout.
//! - `fw/api/context.h::iwl_ctxt_action` — ADD/MODIFY/REMOVE values.
//! - `fw/api/commands.h` line 208 — MAC_CONTEXT_CMD = 0x28.
//! - `fw/api/commands.h` line 214 — TIME_EVENT_CMD = 0x29.
//! - `mvm/mac-ctxt.c::iwl_mvm_mac_ctxt_add` (line 1380) — Linux caller.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Command IDs ────────────────────────────────────────────────────

/// `MAC_CONTEXT_CMD` command id — `fw/api/commands.h` line 208.
pub const MAC_CONTEXT_CMD: u8 = 0x28;

/// `TIME_EVENT_CMD` command id — `fw/api/commands.h` line 214.
pub const TIME_EVENT_CMD: u8 = 0x29;

// ── Context action (FW_CTXT_ACTION_*) ─────────────────────────────
//
// Source: `fw/api/context.h::enum iwl_ctxt_action`.

/// Context action values from `fw/api/context.h`.
pub mod ctxt_action {
    /// Stub — reserved zero value; never used.
    pub const STUB: u32 = 0;
    /// Add a new context.
    pub const ADD: u32 = 1;
    /// Modify an existing context.
    pub const MODIFY: u32 = 2;
    /// Remove a context.
    pub const REMOVE: u32 = 3;
}

// ── MAC types ──────────────────────────────────────────────────────
//
// Source: `fw/api/mac.h::enum iwl_mac_types`.

pub mod mac_type {
    /// Internal auxiliary MAC (not used by host).
    pub const AUX: u32 = 1;
    /// Monitor (listen-only) interface.
    pub const LISTENER: u32 = 2;
    /// Pseudo-IBSS.
    pub const PIBSS: u32 = 3;
    /// Ad-hoc (IBSS) network.
    pub const IBSS: u32 = 4;
    /// Managed BSS station (STA mode).
    pub const BSS_STA: u32 = 5;
    /// P2P device.
    pub const P2P_DEVICE: u32 = 6;
    /// P2P client station.
    pub const P2P_STA: u32 = 7;
    /// P2P Group Owner.
    pub const GO: u32 = 8;
}

// ── MAC filter flags ───────────────────────────────────────────────
//
// Source: `fw/api/mac.h::enum iwl_mac_filter_flags`.

pub mod filter_flags {
    /// Accept all data frames (promiscuous).
    pub const IN_PROMISC: u32 = 1 << 0;
    /// Pass all control + management frames to host.
    pub const IN_CONTROL_AND_MGMT: u32 = 1 << 1;
    /// Accept frames addressed to this MAC (unicast filter).
    pub const IN_NON_MCAST: u32 = 1 << 3;
    /// Accept multicast frames.
    pub const IN_MCAST: u32 = 1 << 5;
    /// Transfer foreign BSS beacons to host.
    pub const IN_BEACON: u32 = 1 << 6;
    /// Extract FCS and append to frames.
    pub const IN_CRC32: u32 = 1 << 11;
    /// Pass probe requests to host.
    pub const IN_PROBE_REQUEST: u32 = 1 << 12;
}

// ── Per-AC QoS parameters ─────────────────────────────────────────
//
// `fw/api/mac.h::struct iwl_ac_qos` — 8 bytes per AC, 4 ACs + 1
// management = 5 entries (AC_NUM + 1).

/// Number of QoS access categories + management.
pub const AC_COUNT: usize = 5;

/// Per-AC QoS parameter block. Layout sourced from
/// `fw/api/mac.h::struct iwl_ac_qos` (line 286).
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct AcQos {
    /// Minimum contention window (`CW_MIN`). Power-of-2 minus 1.
    pub cw_min: u16,
    /// Maximum contention window (`CW_MAX`). Power-of-2 minus 1.
    pub cw_max: u16,
    /// Arbitration interframe space slots.
    pub aifsn: u8,
    /// FIFOs mask (unused since _VER_3; write 0).
    pub fifos_mask: u8,
    /// EDCA TX opportunity in microseconds.
    pub edca_txop: u16,
}

impl AcQos {
    /// Default EDCA parameters for best-effort (AC_BE).
    pub const fn best_effort() -> Self {
        Self { cw_min: 15, cw_max: 63, aifsn: 3, fifos_mask: 0, edca_txop: 0 }
    }
    /// Management queue defaults.
    pub const fn management() -> Self {
        Self { cw_min: 15, cw_max: 63, aifsn: 2, fifos_mask: 0, edca_txop: 0 }
    }
}

// ── MAC_CONTEXT_CMD body ───────────────────────────────────────────
//
// Wire layout of `struct iwl_mac_ctx_cmd` (`fw/api/mac.h` line 321):
//
//   __le32 id_and_color           (4)
//   __le32 action                 (4)
//   __le32 mac_type               (4)
//   __le32 tsf_id                 (4)
//   u8     node_addr[6]           (6)
//   __le16 reserved_for_node_addr (2)
//   u8     bssid_addr[6]          (6)
//   __le16 reserved_for_bssid_addr(2)
//   __le32 cck_rates              (4)
//   __le32 ofdm_rates             (4)
//   __le32 protection_flags       (4)
//   __le32 cck_short_preamble     (4)
//   __le32 short_slot             (4)
//   __le32 filter_flags           (4)
//   __le32 qos_flags              (4)
//   struct iwl_ac_qos ac[5]       (5×8 = 40)
//   union type_data               (variable; we emit minimum IBSS = 4)
//
// Total fixed part = 4+4+4+4+6+2+6+2+4+4+4+4+4+4+4+40 = 108 bytes.

/// Command ID byte to embed in the iwlwifi cmd header.
/// Source: `fw/api/commands.h` line 208.
pub const MAC_CONTEXT_CMD_ID: u8 = MAC_CONTEXT_CMD;

/// Minimum size of the type-specific data union we emit (IBSS / STA
/// stub — 4 bytes of beacon-interval). The production path would fill
/// in the full `iwl_mac_data_sta` or `iwl_mac_data_ibss` struct.
const MAC_TYPE_DATA_STUB_LEN: usize = 4;

/// Fixed overhead: everything before the union.
const MAC_CTX_FIXED_LEN: usize = 108;

/// Build an encoded `MAC_CONTEXT_CMD` payload.
///
/// `id_and_color` — MAC context slot index + color (use 0 for the
///   first context).
/// `mac_type_` — one of `mac_type::BSS_STA / IBSS` for the interface
///   mode.
/// `node_addr` — the 6-byte MAC address to program.
/// `bssid` — the BSSID (set to `node_addr` for STA pre-association
///   or broadcast for IBSS).
/// `filter` — combination of `filter_flags::*` bitmask values.
///
/// Returns a `Vec<u8>` with a 4-byte iwlwifi command header prepended:
/// `[cmd_id=0x28][flags=0][seq=0][seq_hi=0]` followed by the body.
///
/// Reference: `mvm/mac-ctxt.c::iwl_mvm_mac_ctxt_add` (line 1380).
pub fn build_mac_context_cmd(
    id_and_color: u32,
    mac_type_: u32,
    node_addr: [u8; 6],
    bssid: [u8; 6],
    filter: u32,
) -> Vec<u8> {
    let body_len = MAC_CTX_FIXED_LEN + MAC_TYPE_DATA_STUB_LEN;
    let mut out = Vec::with_capacity(4 + body_len);

    // iwlwifi command header: [cmd_id][flags][seq_lo][seq_hi].
    out.push(MAC_CONTEXT_CMD);
    out.push(0u8); // flags
    out.push(0u8); // seq_lo
    out.push(0u8); // seq_hi

    // id_and_color
    out.extend_from_slice(&id_and_color.to_le_bytes());
    // action = ADD
    out.extend_from_slice(&ctxt_action::ADD.to_le_bytes());
    // mac_type
    out.extend_from_slice(&mac_type_.to_le_bytes());
    // tsf_id = 0
    out.extend_from_slice(&0u32.to_le_bytes());
    // node_addr[6] + pad[2]
    out.extend_from_slice(&node_addr);
    out.extend_from_slice(&0u16.to_le_bytes());
    // bssid_addr[6] + pad[2]
    out.extend_from_slice(&bssid);
    out.extend_from_slice(&0u16.to_le_bytes());
    // cck_rates: 0x000F (1/2/5.5/11 Mbps basic rates)
    out.extend_from_slice(&0x000Fu32.to_le_bytes());
    // ofdm_rates: 0x00FF (all OFDM basic rates)
    out.extend_from_slice(&0x00FFu32.to_le_bytes());
    // protection_flags = 0
    out.extend_from_slice(&0u32.to_le_bytes());
    // cck_short_preamble = 0x20 (enable short preamble)
    out.extend_from_slice(&0x20u32.to_le_bytes());
    // short_slot = 0x10 (enable short slots)
    out.extend_from_slice(&0x10u32.to_le_bytes());
    // filter_flags
    out.extend_from_slice(&filter.to_le_bytes());
    // qos_flags = 0
    out.extend_from_slice(&0u32.to_le_bytes());
    // ac[5] — 5 × AcQos structs
    let default_ac = AcQos::best_effort();
    for i in 0..AC_COUNT {
        let ac = if i == 4 { AcQos::management() } else { default_ac };
        out.extend_from_slice(&ac.cw_min.to_le_bytes());
        out.extend_from_slice(&ac.cw_max.to_le_bytes());
        out.push(ac.aifsn);
        out.push(ac.fifos_mask);
        out.extend_from_slice(&ac.edca_txop.to_le_bytes());
    }
    // type_data stub: beacon_interval (u32) = 100 TU
    out.extend_from_slice(&100u32.to_le_bytes());

    out
}

// ── TIME_EVENT_CMD body ────────────────────────────────────────────
//
// Wire layout of `struct iwl_time_event_cmd`
// (`fw/api/time-event.h` line 214):
//
//   __le32 id_and_color     (4)
//   __le32 action           (4)
//   __le32 id               (4)  — TE type when action=ADD
//   __le32 apply_time       (4)  — GP2 time (0 = ASAP)
//   __le32 max_delay        (4)
//   __le32 depends_on       (4)
//   __le32 interval         (4)
//   __le32 duration         (4)
//   u8     repeat           (1)
//   u8     max_frags        (1)
//   __le16 policy           (2)
//                          = 36 bytes body.

/// Time event types from `fw/api/time-event.h`.
pub mod te_type {
    /// Beacon monitoring time event (for normal STA operation).
    pub const BSS_STA_ASSOC: u32 = 1;
    /// Aggressive association time event.
    pub const BSS_STA_AGGRESSIVE_ASSOC: u32 = 0;
    /// P2P device ROC (remain-on-channel).
    pub const P2P_DEVICE_DISCOV: u32 = 9;
}

/// `TE_REPEAT_ENDLESS` — repeat indefinitely.
pub const TE_REPEAT_ENDLESS: u8 = 0xFF;

/// Build an encoded `TIME_EVENT_CMD` payload.
///
/// `id_and_color` — MAC context id + color (must match the
///   `MAC_CONTEXT_CMD` id_and_color used above).
/// `te_id` — one of `te_type::*` constants.
/// `duration_tu` — event duration in Time Units (1 TU = 1024 µs).
///
/// Returns a `Vec<u8>` with 4-byte iwlwifi command header prepended.
///
/// Reference: `mvm/mac-ctxt.c` indirectly via `iwl_mvm_time_event_*`;
/// struct defined in `fw/api/time-event.h` (line 214).
pub fn build_time_event_cmd(id_and_color: u32, te_id: u32, duration_tu: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 36);

    // iwlwifi command header.
    out.push(TIME_EVENT_CMD);
    out.push(0u8);
    out.push(0u8);
    out.push(0u8);

    // id_and_color
    out.extend_from_slice(&id_and_color.to_le_bytes());
    // action = ADD
    out.extend_from_slice(&ctxt_action::ADD.to_le_bytes());
    // id = te_id (type when action=ADD)
    out.extend_from_slice(&te_id.to_le_bytes());
    // apply_time = 0 (ASAP)
    out.extend_from_slice(&0u32.to_le_bytes());
    // max_delay = 500 TU
    out.extend_from_slice(&500u32.to_le_bytes());
    // depends_on = 0
    out.extend_from_slice(&0u32.to_le_bytes());
    // interval = 0 (no repetition interval for one-shot)
    out.extend_from_slice(&0u32.to_le_bytes());
    // duration
    out.extend_from_slice(&duration_tu.to_le_bytes());
    // repeat = endless (continuous beacon monitoring)
    out.push(TE_REPEAT_ENDLESS);
    // max_frags = 0xFF (no fragmentation limit)
    out.push(0xFF);
    // policy = 0
    out.extend_from_slice(&0u16.to_le_bytes());

    out
}

// ── CmdQueue dispatch stub ─────────────────────────────────────────
//
// The production path posts the encoded command bytes through
// `TxQueue` (queue 0) and writes the doorbell via `tx_doorbell`.
// The function below wires through the existing NARF TxQueue API
// without pulling in the real DMA + firmware machinery — it just
// demonstrates the dispatch shape for Stage 3.
//
// A full production dispatch would:
//   1. Copy `bytes` into the DMA-coherent TFD ring slot.
//   2. Build a `Tfd` with a single scatter-gather entry pointing
//      at the DMA copy.
//   3. Call `tx_q.enqueue(tfd)` and `tx_doorbell(mmio, 0, slot)`.

use super::transport::IwlMmio;
use super::tx::{tx_doorbell, Tfd, TxQueue};

/// Dispatch a pre-built command frame through the command queue
/// (TX queue 0). For Stage 3 this is a structural stub — it builds
/// the TFD with a fake phys address sourced from the slice pointer
/// (which is NOT DMA-safe on real HW; replace with a coherent
/// allocation before running on silicon).
pub fn cmd_queue_send<M: IwlMmio>(
    mmio: &mut M,
    tx_q: &mut TxQueue,
    cmd_bytes: &[u8],
) {
    let mut tfd = Tfd::default();
    // In the real path: dma_copy = alloc_coherent(cmd_bytes.len()),
    // copy_nonoverlapping, tfd.push_seg(dma_phys, len).
    // Here we use the stack pointer as a structural placeholder.
    let pseudo_phys = cmd_bytes.as_ptr() as u64;
    tfd.push_seg(pseudo_phys, cmd_bytes.len() as u16);
    let slot = tx_q.enqueue(tfd);
    tx_doorbell(mmio, 0, slot);
}
