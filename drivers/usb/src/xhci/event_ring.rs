//! xHCI 1.2 Event Ring + Event Ring Segment Table (§4.9.4 + §6.5).
//!
//! Each interrupter consumes events from a single Event Ring assembled
//! from one or more segments. The Event Ring Segment Table (ERST) is
//! an array of 16-byte entries that points at each segment + carries
//! the segment's TRB count.
//!
//! Software programs the ERST base into `IR.ERSTBA`, the segment count
//! into `IR.ERSTSZ`, and reads the ring at `IR.ERDP` (Event Ring
//! Dequeue Pointer). EHB (Event Handler Busy) in `ERDP` bit 3 is RW1C
//! and must be cleared after draining a batch of events.

#![allow(dead_code)]

use super::cmd_ring::{Trb, TRB_CYCLE_BIT, TRB_TYPE_MASK, TRB_TYPE_SHIFT};

/// Event-Ring segment size in TRBs (§4.9.4 — implementation chooses,
/// host minimum 16). 64 is plenty for bring-up; sizing up follows
/// scaling work.
pub const ER_SEG_TRBS: usize = 64;

/// One ERST entry (§6.5). Carries the ring-segment base and TRB count.
#[repr(C, align(64))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ErstEntry {
    /// 64-bit physical base of this segment (low 6 bits MBZ — 64-byte
    /// aligned).
    pub ring_seg_base: u64,
    /// Number of TRBs in this segment (low 16 bits used).
    pub ring_seg_size: u32,
    pub reserved: u32,
}

impl ErstEntry {
    pub const SIZE: usize = 16;

    /// Encode for DMA. `seg_base` must be 64-byte aligned (xHCI §6.5
    /// requires bits[5:0] zero).
    pub fn encode(seg_base: u64, seg_trbs: u16) -> Self {
        Self {
            ring_seg_base: seg_base & !0x3F,
            ring_seg_size: seg_trbs as u32,
            reserved: 0,
        }
    }

    /// Serialize as little-endian bytes for verifier tests.
    pub fn to_le_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.ring_seg_base.to_le_bytes());
        b[8..12].copy_from_slice(&self.ring_seg_size.to_le_bytes());
        b[12..16].copy_from_slice(&self.reserved.to_le_bytes());
        b
    }
}

// Event TRB Types (§6.4.2 Table 6-90 / 6-91).
pub const EVT_TRANSFER: u32 = 32;
pub const EVT_CMD_COMPLETION: u32 = 33;
pub const EVT_PORT_STATUS_CHANGE: u32 = 34;
pub const EVT_BANDWIDTH_REQUEST: u32 = 35;
pub const EVT_DOORBELL: u32 = 36;
pub const EVT_HOST_CONTROLLER: u32 = 37;
pub const EVT_DEVICE_NOTIFICATION: u32 = 38;
pub const EVT_MFINDEX_WRAP: u32 = 39;

/// Decoded Transfer Event (§6.4.2.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransferEvent {
    /// Physical address (LSB) of the TRB that generated this event,
    /// or the Event Data data field if the source was an Event Data
    /// TRB (control bit 2 / ED set).
    pub trb_pointer: u64,
    /// Bytes NOT transferred from the source TRB length.
    pub transfer_length: u32,
    /// Completion code, bits[31:24] of status.
    pub completion_code: u8,
    /// Slot ID generating the event (1-based).
    pub slot_id: u8,
    /// Endpoint ID (DCI), bits[20:16] of control.
    pub endpoint_id: u8,
    /// ED — Event Data, bit 2 of control. When set, `trb_pointer`
    /// carries the 64-bit Event Data payload instead of a TRB
    /// physical address.
    pub event_data: bool,
}

/// Decoded Command Completion Event (§6.4.2.2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmdCompletionEvent {
    /// Physical address of the command-ring TRB that this completion
    /// references.
    pub cmd_trb_pointer: u64,
    /// Completion-code in bits[31:24] of status.
    pub completion_code: u8,
    /// Slot ID created or referenced. 0 for non-slot commands.
    pub slot_id: u8,
    /// CPID — Command Parameter (bits[23:0] of status).
    pub command_parameter: u32,
}

/// Decoded Port Status Change Event (§6.4.2.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PortStatusChangeEvent {
    /// Port number, bits[31:24] of parameter (per spec).
    pub port_id: u8,
    /// Completion code (always Success on real silicon; spec leaves
    /// it set in case future use).
    pub completion_code: u8,
}

/// Decoded view of any Event Ring TRB.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DecodedEvent {
    Transfer(TransferEvent),
    CmdCompletion(CmdCompletionEvent),
    PortStatusChange(PortStatusChangeEvent),
    Other { ty: u32, raw: [u32; 4] },
}

impl DecodedEvent {
    /// Decode an event TRB from its four little-endian dwords.
    pub fn from_dwords(d: [u32; 4]) -> Self {
        let parameter = (d[0] as u64) | ((d[1] as u64) << 32);
        let status = d[2];
        let control = d[3];
        let ty = (control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT;
        let completion_code = ((status >> 24) & 0xFF) as u8;
        match ty {
            EVT_TRANSFER => DecodedEvent::Transfer(TransferEvent {
                trb_pointer: parameter,
                transfer_length: status & 0x00FF_FFFF,
                completion_code,
                slot_id: ((control >> 24) & 0xFF) as u8,
                endpoint_id: ((control >> 16) & 0x1F) as u8,
                event_data: (control & (1 << 2)) != 0,
            }),
            EVT_CMD_COMPLETION => DecodedEvent::CmdCompletion(CmdCompletionEvent {
                cmd_trb_pointer: parameter & !0xF,
                completion_code,
                slot_id: ((control >> 24) & 0xFF) as u8,
                command_parameter: status & 0x00FF_FFFF,
            }),
            EVT_PORT_STATUS_CHANGE => {
                // Port ID lives in parameter bits[31:24] (xHCI §6.4.2.3).
                let port_id = ((parameter >> 24) & 0xFF) as u8;
                DecodedEvent::PortStatusChange(PortStatusChangeEvent {
                    port_id,
                    completion_code,
                })
            }
            _ => DecodedEvent::Other { ty, raw: d },
        }
    }

    /// Decode a raw `Trb` value.
    pub fn from_trb(trb: &Trb) -> Self {
        Self::from_dwords(trb.to_dwords())
    }

    /// Was the underlying TRB's cycle bit set?
    pub fn cycle(d: [u32; 4]) -> bool {
        (d[3] & TRB_CYCLE_BIT) != 0
    }
}
