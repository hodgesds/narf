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
//! +0x04..0x1F rsvd2          7×BE-u32 (28 B)
//! +0x20..0x3B data union     32 B
//!   CompletionEvent (type 0x00):
//!     mlx5_eqe_comp — 6×BE-u32 reserved, then BE-u32 cqn at +0x18
//!     → cqn at EQE byte 0x20 + 0x18 = 0x38
//! +0x3F bit 0 owner (1 = HW owns, 0 = SW)
//! ```

pub const EQE_LEN: usize = 64;

pub const EQE_OFF_EVENT_TYPE: usize = 0x01;
pub const EQE_OFF_EVENT_SUB_TYPE: usize = 0x03;
/// Byte offset of the CompletionEvent CQN (BE u32, low 24 bits used).
/// Linux: `be32_to_cpu(eqe->data.comp.cqn) & 0xffffff` (eq.c:125).
/// data union starts at 0x20; mlx5_eqe_comp has 6 × 4 = 24 bytes
/// reserved before cqn → 0x20 + 0x18 = 0x38.
pub const EQE_OFF_COMP_CQN: usize = 0x38;
pub const EQE_OFF_OWNER: usize = 0x3F;

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
    pub event_type: EventType,
    pub event_sub_type: u8,
    /// CQ number from a CompletionEvent EQE (low 24 bits, decoded from
    /// BE u32 at EQE_OFF_COMP_CQN). Only meaningful when
    /// `event_type == EventType::CompletionEvent`; zero for all others.
    pub cqn: u32,
    pub owner: bool,
}

pub fn is_hw_owned(eqe: &[u8; EQE_LEN]) -> bool {
    eqe[EQE_OFF_OWNER] & EQE_OWNER_BIT != 0
}

pub fn decode_eqe(eqe: &[u8; EQE_LEN]) -> EqeView {
    let event_type = EventType::from_raw(eqe[EQE_OFF_EVENT_TYPE]);
    // Extract CQN only for CompletionEvent; zero for all others.
    // Linux eq.c:125: `be32_to_cpu(eqe->data.comp.cqn) & 0xffffff`.
    let cqn = if event_type == EventType::CompletionEvent {
        let b = &eqe[EQE_OFF_COMP_CQN..EQE_OFF_COMP_CQN + 4];
        let raw = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        raw & 0x00FF_FFFF
    } else {
        0
    };
    EqeView {
        event_type,
        event_sub_type: eqe[EQE_OFF_EVENT_SUB_TYPE],
        cqn,
        owner: (eqe[EQE_OFF_OWNER] & EQE_OWNER_BIT) != 0,
    }
}

/// Test-harness helper: write a synthetic completed EQE in place
/// (clears the owner bit).
pub fn simulate_event(eqe: &mut [u8; EQE_LEN], event_type: u8, event_sub_type: u8) {
    eqe[EQE_OFF_EVENT_TYPE] = event_type;
    eqe[EQE_OFF_EVENT_SUB_TYPE] = event_sub_type;
    eqe[EQE_OFF_OWNER] &= !EQE_OWNER_BIT;
}

/// Test-harness helper: write a synthetic CompletionEvent EQE with
/// the given CQN encoded at `EQE_OFF_COMP_CQN` in BE. Clears owner bit.
pub fn simulate_comp_event(eqe: &mut [u8; EQE_LEN], cqn: u32) {
    eqe[EQE_OFF_EVENT_TYPE] = 0x00; // CompletionEvent
    eqe[EQE_OFF_EVENT_SUB_TYPE] = 0x00;
    let be = (cqn & 0x00FF_FFFF).to_be_bytes();
    eqe[EQE_OFF_COMP_CQN..EQE_OFF_COMP_CQN + 4].copy_from_slice(&be);
    eqe[EQE_OFF_OWNER] &= !EQE_OWNER_BIT;
}

/// Walk the EQ ring at `consumer` and return the first SW-owned
/// EQE if any. Mirrors `ring::pop_completion`.
pub fn pop_event(eq_bytes: &[u8], capacity: u32, consumer: u32) -> Option<(EqeView, u32)> {
    let off = ((consumer % capacity) as usize) * EQE_LEN;
    if off + EQE_LEN > eq_bytes.len() {
        return None;
    }
    let mut buf = [0u8; EQE_LEN];
    buf.copy_from_slice(&eq_bytes[off..off + EQE_LEN]);
    if is_hw_owned(&buf) {
        return None;
    }
    Some((decode_eqe(&buf), consumer.wrapping_add(1)))
}
