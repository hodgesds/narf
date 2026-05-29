//! xHCI 1.2 Command Ring (§4.9.3 + §6.4.3).
//!
//! The Command Ring is a single segment of 16-byte Transfer Request
//! Blocks (TRBs). Software is the producer; the controller is the
//! consumer. A Link TRB at the last slot wraps the ring back to slot
//! 0. The Producer Cycle State (PCS) flips on every wrap so the
//! controller can tell whether a slot has been written this round.

#![allow(dead_code)]

/// Command-Ring segment size in TRBs (§4.9.3). 256 is the canonical
/// size matching Linux's xhci-hcd.
pub const CMD_RING_TRBS: usize = 256;

/// TRB Type field is bits[15:10] of TRB.dword3 (§4.11.1).
pub const TRB_TYPE_SHIFT: u32 = 10;
pub const TRB_TYPE_MASK: u32 = 0x3F << TRB_TYPE_SHIFT;
/// Cycle bit — TRB.dword3 bit 0 (§4.11.1).
pub const TRB_CYCLE_BIT: u32 = 1 << 0;
/// CH — Chain bit, bit 4 of dword3.
pub const TRB_CH: u32 = 1 << 4;
/// IOC — Interrupt On Completion, bit 5 of dword3.
pub const TRB_IOC: u32 = 1 << 5;
/// IDT — Immediate Data, bit 6 of dword3.
pub const TRB_IDT: u32 = 1 << 6;
/// TC — Toggle Cycle (Link TRB only, §6.4.4.1).
pub const TRB_TC: u32 = 1 << 1;

// TRB Type values relevant to the Command Ring (§6.4.3 / Table 6-91).
pub const TRB_TYPE_NORMAL: u32 = 1;
pub const TRB_TYPE_SETUP_STAGE: u32 = 2;
pub const TRB_TYPE_DATA_STAGE: u32 = 3;
pub const TRB_TYPE_STATUS_STAGE: u32 = 4;
pub const TRB_TYPE_ISOCH: u32 = 5;
pub const TRB_TYPE_LINK: u32 = 6;
pub const TRB_TYPE_EVENT_DATA: u32 = 7;
pub const TRB_TYPE_NOOP: u32 = 8;
pub const TRB_TYPE_ENABLE_SLOT_CMD: u32 = 9;
pub const TRB_TYPE_DISABLE_SLOT_CMD: u32 = 10;
pub const TRB_TYPE_ADDRESS_DEVICE_CMD: u32 = 11;
pub const TRB_TYPE_CONFIGURE_ENDPOINT_CMD: u32 = 12;
pub const TRB_TYPE_EVAL_CONTEXT_CMD: u32 = 13;
pub const TRB_TYPE_RESET_ENDPOINT_CMD: u32 = 14;
pub const TRB_TYPE_STOP_ENDPOINT_CMD: u32 = 15;
pub const TRB_TYPE_SET_TR_DEQUEUE_CMD: u32 = 16;
pub const TRB_TYPE_RESET_DEVICE_CMD: u32 = 17;
pub const TRB_TYPE_NO_OP_CMD: u32 = 23;

/// Generic 16-byte TRB. All command/event/transfer TRBs share this
/// shape (§4.11.1).
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Trb {
    pub parameter: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    pub const SIZE: usize = 16;

    /// Type field (bits[15:10] of `control`).
    pub fn ty(&self) -> u32 {
        (self.control & TRB_TYPE_MASK) >> TRB_TYPE_SHIFT
    }

    /// Cycle bit (`control` bit 0).
    pub fn cycle(&self) -> bool {
        (self.control & TRB_CYCLE_BIT) != 0
    }

    /// Encode as little-endian dwords for verifier / DMA write tests.
    pub fn to_dwords(&self) -> [u32; 4] {
        [
            (self.parameter & 0xFFFF_FFFF) as u32,
            (self.parameter >> 32) as u32,
            self.status,
            self.control,
        ]
    }

    /// Construct from raw dwords.
    pub fn from_dwords(d: [u32; 4]) -> Self {
        Self {
            parameter: (d[0] as u64) | ((d[1] as u64) << 32),
            status: d[2],
            control: d[3],
        }
    }
}

/// Encode an Enable Slot command TRB (§6.4.3.2). `slot_type` selects
/// the Protocol Slot Type from a Supported Protocol Capability; 0 is
/// the default (USB 2.0 / USB 3.x stock).
pub fn encode_enable_slot(slot_type: u8, cycle: u32) -> Trb {
    let control = (TRB_TYPE_ENABLE_SLOT_CMD << TRB_TYPE_SHIFT)
        | ((slot_type as u32) << 16)
        | (cycle & 1);
    Trb {
        parameter: 0,
        status: 0,
        control,
    }
}

/// Encode a Disable Slot command TRB (§6.4.3.3).
pub fn encode_disable_slot(slot_id: u8, cycle: u32) -> Trb {
    let control = (TRB_TYPE_DISABLE_SLOT_CMD << TRB_TYPE_SHIFT)
        | ((slot_id as u32) << 24)
        | (cycle & 1);
    Trb {
        parameter: 0,
        status: 0,
        control,
    }
}

/// Encode an Address Device command TRB (§6.4.3.4). `input_ctx_pa` is
/// the 16-byte-aligned physical address of the Input Context. `bsr`
/// (Block Set Address Request) sets the BSR flag — if set the
/// controller does the Set Address PHASE but doesn't issue the actual
/// SetAddress to the device, used during initial speed/MPS evaluation.
pub fn encode_address_device(input_ctx_pa: u64, slot_id: u8, bsr: bool, cycle: u32) -> Trb {
    let mut control = (TRB_TYPE_ADDRESS_DEVICE_CMD << TRB_TYPE_SHIFT)
        | ((slot_id as u32) << 24)
        | (cycle & 1);
    if bsr {
        control |= 1 << 9; // BSR bit per §6.4.3.4
    }
    Trb {
        parameter: input_ctx_pa & !0xF,
        status: 0,
        control,
    }
}

/// Encode a Configure Endpoint command TRB (§6.4.3.5). `dc`
/// (Deconfigure) clears all non-default endpoints and returns the
/// Slot to the Addressed state; otherwise the Input Context add/drop
/// flags select which endpoints to configure.
pub fn encode_configure_endpoint(
    input_ctx_pa: u64,
    slot_id: u8,
    dc: bool,
    cycle: u32,
) -> Trb {
    let mut control = (TRB_TYPE_CONFIGURE_ENDPOINT_CMD << TRB_TYPE_SHIFT)
        | ((slot_id as u32) << 24)
        | (cycle & 1);
    if dc {
        control |= 1 << 9;
    }
    Trb {
        parameter: input_ctx_pa & !0xF,
        status: 0,
        control,
    }
}

/// Encode an Evaluate Context command TRB (§6.4.3.6).
pub fn encode_eval_context(input_ctx_pa: u64, slot_id: u8, cycle: u32) -> Trb {
    let control = (TRB_TYPE_EVAL_CONTEXT_CMD << TRB_TYPE_SHIFT)
        | ((slot_id as u32) << 24)
        | (cycle & 1);
    Trb {
        parameter: input_ctx_pa & !0xF,
        status: 0,
        control,
    }
}

/// Encode a Link TRB pointing at `next_pa` with toggle-cycle on.
/// Sits at the last slot of the ring so the controller wraps back to
/// slot 0 and flips its consumer cycle when it crosses.
pub fn encode_link(next_pa: u64, toggle_cycle: bool, cycle: u32) -> Trb {
    let mut control = (TRB_TYPE_LINK << TRB_TYPE_SHIFT) | (cycle & 1);
    if toggle_cycle {
        control |= TRB_TC;
    }
    Trb {
        parameter: next_pa & !0xF,
        status: 0,
        control,
    }
}

/// Encode a No-Op Command TRB (§6.4.3.1).
pub fn encode_noop_cmd(cycle: u32) -> Trb {
    let control = (TRB_TYPE_NO_OP_CMD << TRB_TYPE_SHIFT) | (cycle & 1);
    Trb {
        parameter: 0,
        status: 0,
        control,
    }
}
