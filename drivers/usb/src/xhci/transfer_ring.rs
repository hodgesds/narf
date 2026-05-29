//! Per-endpoint xHCI Transfer Ring (§4.9 + §6.4.1).
//!
//! A Transfer Ring carries Normal / Setup-Stage / Data-Stage /
//! Status-Stage / Isoch TRBs queued by software for a single endpoint
//! Doorbell wakes the controller; it consumes TRBs in cycle order and
//! posts a Transfer Event onto the interrupter's Event Ring when the
//! TRB completes (or chains complete via IOC).

#![allow(dead_code)]

use super::cmd_ring::{
    Trb, TRB_CYCLE_BIT, TRB_IDT, TRB_IOC, TRB_TYPE_DATA_STAGE, TRB_TYPE_NORMAL,
    TRB_TYPE_SETUP_STAGE, TRB_TYPE_SHIFT, TRB_TYPE_STATUS_STAGE,
};

/// Default control-endpoint Transfer Ring size in TRBs. Slot N-1 is
/// reserved for the Link TRB.
pub const CTRL_TR_TRBS: usize = 64;

// Setup Stage TRT (Transfer Type) field, bits[17:16] of dword3.
pub const TRT_NO_DATA: u32 = 0;
pub const TRT_OUT_DATA: u32 = 2;
pub const TRT_IN_DATA: u32 = 3;
/// DIR — Stage Direction (Data Stage / Status Stage), bit 16.
/// 1 = IN, 0 = OUT.
pub const TRB_DIR_IN: u32 = 1 << 16;
/// SIA — Start Isochronous As Soon As Possible. Set on the first
/// isoch TRB of each interval.
pub const TRB_SIA: u32 = 1 << 31;

/// Default Control Endpoint = DCI 1 (§4.8.1).
pub const DCI_CONTROL_EP: u32 = 1;

/// Encode a Normal TRB for a bulk-OUT or bulk-IN transfer (§6.4.1.1).
/// `data_pa` is the physical buffer address; `len` is the TD size up
/// to 64 KiB (the xHCI Normal TRB length field is bits[16:0] of
/// `status`).
pub fn encode_normal(data_pa: u64, len: u32, ioc: bool, chain: bool, cycle: u32) -> Trb {
    let status = len & 0x0001_FFFF;
    let mut control = (TRB_TYPE_NORMAL << TRB_TYPE_SHIFT) | (cycle & 1);
    if ioc {
        control |= TRB_IOC;
    }
    if chain {
        control |= 1 << 4;
    }
    Trb {
        parameter: data_pa,
        status,
        control,
    }
}

/// Encode the Setup Stage TRB of a control transfer (§6.4.1.2.1).
///
/// The 8-byte SETUP packet is packed into `parameter` (low8) so
/// `IDT=1`. `trt` selects the transfer-type:
/// - `TRT_NO_DATA` for SET_ADDRESS / SET_CONFIGURATION
/// - `TRT_IN_DATA` for GET_DESCRIPTOR (host reads from device)
/// - `TRT_OUT_DATA` for class-specific writes
///
/// `length` is always 8 (the SETUP packet size).
pub fn encode_setup_stage(setup: [u8; 8], trt: u32, cycle: u32) -> Trb {
    let parameter = u64::from_le_bytes(setup);
    let status: u32 = 8;
    let control = (TRB_TYPE_SETUP_STAGE << TRB_TYPE_SHIFT)
        | TRB_IDT
        | ((trt & 0x3) << 16)
        | (cycle & 1);
    Trb {
        parameter,
        status,
        control,
    }
}

/// Encode the Data Stage TRB of a control transfer (§6.4.1.2.2).
///
/// `dir_in` selects DIR=1 for IN (device-to-host data) or DIR=0 for
/// OUT (host-to-device data).
pub fn encode_data_stage(
    data_pa: u64,
    length: u32,
    dir_in: bool,
    ioc: bool,
    cycle: u32,
) -> Trb {
    let status = length & 0x0001_FFFF;
    let mut control = (TRB_TYPE_DATA_STAGE << TRB_TYPE_SHIFT) | (cycle & 1);
    if dir_in {
        control |= TRB_DIR_IN;
    }
    if ioc {
        control |= TRB_IOC;
    }
    Trb {
        parameter: data_pa,
        status,
        control,
    }
}

/// Encode the Status Stage TRB of a control transfer (§6.4.1.2.3).
///
/// Status direction is the OPPOSITE of Data Stage direction (host
/// acknowledges the data phase). For a no-data control transfer the
/// Status Stage is always IN.
pub fn encode_status_stage(dir_in: bool, ioc: bool, cycle: u32) -> Trb {
    let mut control = (TRB_TYPE_STATUS_STAGE << TRB_TYPE_SHIFT) | (cycle & 1);
    if dir_in {
        control |= TRB_DIR_IN;
    }
    if ioc {
        control |= TRB_IOC;
    }
    Trb {
        parameter: 0,
        status: 0,
        control,
    }
}

/// Check the cycle bit of a freshly-read TRB to verify the controller
/// has filled it in this round.
pub fn trb_cycle_owned_by_software(t: &Trb, expected_pcs: u32) -> bool {
    (t.control & TRB_CYCLE_BIT) == (expected_pcs & 1)
}
