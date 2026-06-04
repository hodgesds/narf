//! xHCI 1.2 Slot Context + Endpoint Context + Input Context (§6.2).
//!
//! The Slot Context (§6.2.2) describes a single USB device's
//! controller-side state: route string, speed, hub topology, address,
//! number of active endpoints. The Endpoint Context (§6.2.3) describes
//! one endpoint: type, max packet size, transfer-ring pointer.
//!
//! An Input Context (§6.2.5) is what the host writes to the Address
//! Device + Configure Endpoint + Evaluate Context commands. It is an
//! Input Control Context (Add Context Flags + Drop Context Flags)
//! followed by a Slot Context + 31 Endpoint Contexts.

#![allow(dead_code)]

/// USB Endpoint Type values for the EP Context (§6.2.3 Table 6-9).
/// Bits[5:3] of EP Context dword1.
pub const EP_TYPE_ISOCH_OUT: u32 = 1;
pub const EP_TYPE_BULK_OUT: u32 = 2;
pub const EP_TYPE_INT_OUT: u32 = 3;
pub const EP_TYPE_CONTROL: u32 = 4;
pub const EP_TYPE_ISOCH_IN: u32 = 5;
pub const EP_TYPE_BULK_IN: u32 = 6;
pub const EP_TYPE_INT_IN: u32 = 7;

/// Slot Context dword0 fields.
pub const SLOT_CTX_ROUTE_STRING_MASK: u32 = 0x000F_FFFF;
pub const SLOT_CTX_SPEED_SHIFT: u32 = 20;
pub const SLOT_CTX_SPEED_MASK: u32 = 0xF << SLOT_CTX_SPEED_SHIFT;
pub const SLOT_CTX_MTT_BIT: u32 = 1 << 25;
pub const SLOT_CTX_HUB_BIT: u32 = 1 << 26;
pub const SLOT_CTX_CTX_ENTRIES_SHIFT: u32 = 27;
pub const SLOT_CTX_CTX_ENTRIES_MASK: u32 = 0x1F << SLOT_CTX_CTX_ENTRIES_SHIFT;

/// Slot Context dword3 fields (§6.2.2 Table 6-6).
pub const SLOT_CTX_DEV_ADDR_MASK: u32 = 0xFF;
pub const SLOT_CTX_STATE_SHIFT: u32 = 27;
pub const SLOT_CTX_STATE_MASK: u32 = 0x1F << SLOT_CTX_STATE_SHIFT;

/// Slot Context state machine values (§4.5.3, Table 4-7).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlotState {
    /// DisabledOrEnabled before Address Device runs.
    DisabledOrEnabled = 0,
    /// Default — Address Device with BSR=1 has run.
    Default = 1,
    /// Addressed — Address Device with BSR=0 has run.
    Addressed = 2,
    /// Configured — Configure Endpoint has run.
    Configured = 3,
}

impl SlotState {
    pub fn from_dword3(d3: u32) -> Option<Self> {
        Some(match (d3 & SLOT_CTX_STATE_MASK) >> SLOT_CTX_STATE_SHIFT {
            0 => SlotState::DisabledOrEnabled,
            1 => SlotState::Default,
            2 => SlotState::Addressed,
            3 => SlotState::Configured,
            _ => return None,
        })
    }
}

/// Encode a 32-byte Slot Context dword 0 (§6.2.2 Table 6-4):
/// route_string in bits[19:0], speed in bits[23:20], MTT bit 25, Hub
/// bit 26, Context Entries in bits[31:27].
pub fn encode_slot_ctx_dword0(
    route_string: u32,
    speed: u8,
    mtt: bool,
    hub: bool,
    ctx_entries: u8,
) -> u32 {
    (route_string & SLOT_CTX_ROUTE_STRING_MASK)
        | (((speed as u32) << SLOT_CTX_SPEED_SHIFT) & SLOT_CTX_SPEED_MASK)
        | (if mtt { SLOT_CTX_MTT_BIT } else { 0 })
        | (if hub { SLOT_CTX_HUB_BIT } else { 0 })
        | (((ctx_entries as u32) << SLOT_CTX_CTX_ENTRIES_SHIFT) & SLOT_CTX_CTX_ENTRIES_MASK)
}

/// Encode Slot Context dword 1 (§6.2.2 Table 6-5):
/// MaxExitLatency in bits[15:0], root_hub_port in bits[23:16], number
/// of downstream ports if hub in bits[31:24].
pub fn encode_slot_ctx_dword1(max_exit_lat: u16, root_hub_port: u8, num_ports: u8) -> u32 {
    (max_exit_lat as u32) | ((root_hub_port as u32) << 16) | ((num_ports as u32) << 24)
}

/// Encode Slot Context dword 2 (§6.2.2 Table 6-6 — LS/FS-behind-HS-hub
/// fields). All zero for HS+ devices on root hub.
pub fn encode_slot_ctx_dword2(parent_hub_slot: u8, parent_port: u8, tt_think_time: u8) -> u32 {
    (parent_hub_slot as u32) | ((parent_port as u32) << 8) | (((tt_think_time as u32) & 0x3) << 16)
}

/// Encode an Endpoint Context dword 1 (§6.2.3 Table 6-9):
/// CErr in bits[2:1] (Max Error Count), EP Type in bits[5:3],
/// HID bit 7, MaxBurstSize in bits[15:8], MaxPacketSize in bits[31:16].
pub fn encode_ep_ctx_dword1(c_err: u8, ep_type: u32, max_burst: u8, max_packet: u16) -> u32 {
    (((c_err as u32) & 0x3) << 1)
        | ((ep_type & 0x7) << 3)
        | ((max_burst as u32) << 8)
        | ((max_packet as u32) << 16)
}

/// Encode an Endpoint Context dword 2 — TR Dequeue Pointer low (§6.2.3).
/// Bit 0 carries the initial DCS (Dequeue Cycle State); bits[3:1] MBZ.
pub fn encode_ep_ctx_dword2_tr_lo(tr_phys: u64, dcs: u32) -> u32 {
    let lo = (tr_phys & 0xFFFF_FFFF) as u32;
    (lo & !0xF) | (dcs & 1)
}

/// Encode an Endpoint Context dword 4 (§6.2.3 Table 6-10):
/// AverageTRBLength in bits[15:0], MaxESITPayload low in bits[31:16].
pub fn encode_ep_ctx_dword4(avg_trb_len: u16, max_esit_payload_lo: u16) -> u32 {
    (avg_trb_len as u32) | ((max_esit_payload_lo as u32) << 16)
}

/// Input Control Context dword 1 — Add Context Flags (§6.2.5.1).
/// Set bit N to mark device-context entry N as one the command should
/// update. Bit 0 (A0) = Slot Context, bit 1 (A1) = EP0, bits 2..31 =
/// non-default endpoints by DCI.
pub fn input_ctx_add_flag(dci: u32) -> u32 {
    1u32 << dci
}

/// Input Control Context dword 0 — Drop Context Flags (§6.2.5.1).
/// Set bit N (N >= 2) to mark device-context entry N as one the
/// command should DROP. Bits 0/1 MBZ — you can't drop slot or EP0.
pub fn input_ctx_drop_flag(dci: u32) -> u32 {
    if dci < 2 {
        0
    } else {
        1u32 << dci
    }
}

/// One Endpoint Context — five 32-bit fields = 20 bytes, followed by
/// 12 bytes of reserved space to round out to the 32-byte minimum.
/// 64-byte contexts pad the end with another 32 zero bytes.
pub const EP_CTX_BYTES_32: usize = 32;
pub const EP_CTX_BYTES_64: usize = 64;
pub const SLOT_CTX_BYTES_32: usize = 32;
pub const SLOT_CTX_BYTES_64: usize = 64;
pub const INPUT_CTX_HEADER_BYTES_32: usize = 32;
pub const INPUT_CTX_HEADER_BYTES_64: usize = 64;

/// Total Input Context size for a controller with `csz_64byte` setting.
/// The Input Context = Input Control Context + Device Context, so:
///   32-byte: 32 + 32 + 31*32 = 1056 bytes
///   64-byte: 64 + 64 + 31*64 = 2112 bytes
pub fn input_context_size(csz_64byte: bool) -> usize {
    if csz_64byte {
        INPUT_CTX_HEADER_BYTES_64 + SLOT_CTX_BYTES_64 + 31 * EP_CTX_BYTES_64
    } else {
        INPUT_CTX_HEADER_BYTES_32 + SLOT_CTX_BYTES_32 + 31 * EP_CTX_BYTES_32
    }
}
