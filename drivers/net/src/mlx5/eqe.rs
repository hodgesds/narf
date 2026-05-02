//! Event Queue Entry (EQE) — Stage 15.
//!
//! Reference: public Mellanox PRM §16.4 (Event Queue) + §16.4.5
//! (Async Event Codes).
//!
//! An EQE is a 64-byte structure firmware writes into the EQ buffer
//! when an async event fires (CQ-arm completion, port up/down,
//! command-iface error, …). Software polls by walking the buffer at
//! its consumer cursor and checking byte 0x3F bit 0 (owner bit).
//!
//! ## Layout (Stage-15 committed subset)
//!
//! ```text
//! +0x00       reserved
//! +0x01       event_type     u8   — async-event class
//! +0x02       reserved
//! +0x03       event_sub_type u8   — sub-class within event_type
//! +0x04..0x1C event-specific payload (24 B)
//! +0x3F bit 0 owner (1 = HW owns, 0 = SW)
//! ```

pub const EQE_LEN: usize = 64;

pub const EQE_OFF_EVENT_TYPE:     usize = 0x01;
pub const EQE_OFF_EVENT_SUB_TYPE: usize = 0x03;
pub const EQE_OFF_OWNER:          usize = 0x3F;

pub const EQE_OWNER_BIT: u8 = 1 << 0;

/// Async-event class. PRM §16.4.5 Table 105.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    CompletionEvent,
    PathMigrated,
    CommErrorReceived,
    SendQueueDrained,
    SrqLimitReached,
    SrqLastWqeReached,
    PortStateChange,
    CommandInterfaceCompletion,
    PageRequest,
    NicVportChange,
    Unknown(u8),
}

impl EventType {
    pub fn from_raw(b: u8) -> Self {
        match b {
            0x00 => EventType::CompletionEvent,
            0x01 => EventType::PathMigrated,
            0x02 => EventType::CommErrorReceived,
            0x03 => EventType::SendQueueDrained,
            0x05 => EventType::SrqLastWqeReached,
            0x09 => EventType::PortStateChange,
            0x0A => EventType::CommandInterfaceCompletion,
            0x0B => EventType::PageRequest,
            0x0C => EventType::SrqLimitReached,
            0x0D => EventType::NicVportChange,
            other => EventType::Unknown(other),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EqeView {
    pub event_type:     EventType,
    pub event_sub_type: u8,
    pub owner:          bool,
}

pub fn is_hw_owned(eqe: &[u8; EQE_LEN]) -> bool {
    eqe[EQE_OFF_OWNER] & EQE_OWNER_BIT != 0
}

pub fn decode_eqe(eqe: &[u8; EQE_LEN]) -> EqeView {
    EqeView {
        event_type:     EventType::from_raw(eqe[EQE_OFF_EVENT_TYPE]),
        event_sub_type: eqe[EQE_OFF_EVENT_SUB_TYPE],
        owner:          (eqe[EQE_OFF_OWNER] & EQE_OWNER_BIT) != 0,
    }
}

/// Test-harness helper: write a synthetic completed EQE in place
/// (clears the owner bit).
pub fn simulate_event(
    eqe:            &mut [u8; EQE_LEN],
    event_type:     u8,
    event_sub_type: u8,
) {
    eqe[EQE_OFF_EVENT_TYPE]     = event_type;
    eqe[EQE_OFF_EVENT_SUB_TYPE] = event_sub_type;
    eqe[EQE_OFF_OWNER] &= !EQE_OWNER_BIT;
}

/// Walk the EQ ring at `consumer` and return the first SW-owned
/// EQE if any. Mirrors `ring::pop_completion`.
pub fn pop_event(
    eq_bytes: &[u8],
    capacity: u32,
    consumer: u32,
) -> Option<(EqeView, u32)> {
    let off = ((consumer % capacity) as usize) * EQE_LEN;
    if off + EQE_LEN > eq_bytes.len() { return None; }
    let mut buf = [0u8; EQE_LEN];
    buf.copy_from_slice(&eq_bytes[off..off + EQE_LEN]);
    if is_hw_owned(&buf) { return None; }
    Some((decode_eqe(&buf), consumer.wrapping_add(1)))
}
