//! Event Queue (EQ) context, EQE decoder, and consumer-index doorbell.
//!
//! Reference: ConnectX-3 PRM §16.3 ("Event Queue Context") +
//! §15.4 ("SW2HW_EQ") + §16.3.2 ("Event Queue Entry").
//!
//! ## EQ context layout (SW2HW_EQ input mailbox)
//!
//! The EQ context is 64 bytes. Fields written by `build_eq_context`:
//!
//! | offset | width   | field            | notes                            |
//! |--------|---------|------------------|----------------------------------|
//! | 0x00   | BE u32  | flags            | status=OK(0) + state=ARMED(9)    |
//! | 0x0c   | u8      | log_eq_size      | log2 depth in EQEs               |
//! | 0x17   | u8      | intr             | MSI-X / interrupt vector index   |
//! | 0x18   | u8      | log_page_size    | log2 of backing-page size        |
//! | 0x1b   | u8      | mtt_base_addr_h  | bits [39:32] of MTT base         |
//! | 0x1c   | BE u32  | mtt_base_addr_l  | bits [31:0] of MTT base          |
//! | 0x28   | BE u32  | consumer_index   | 0 on creation                    |
//! | 0x2c   | BE u32  | producer_index   | 0 on creation                    |
//!
//! ## EQE layout (32 bytes)
//!
//! | offset | field       | notes                                      |
//! |--------|-------------|--------------------------------------------|
//! | 0x01   | event_type  | see ASYNC_EVENT_MASK for the set we arm    |
//! | 0x03   | subtype     | event-specific sub-classification          |
//! | 0x04   | event_data  | BE u32; CQN in bits [23:0], port in [31:28]|
//! | 0x1f   | owner_byte  | bit 7 is the hardware ownership bit        |

use super::wire::{get_be32, get_u8, put_be32, put_u8};

/// Length of the SW2HW_EQ input mailbox context structure (bytes).
pub const EQ_CONTEXT_LEN: usize = 0x40;

/// Size of one Event Queue Entry (bytes).
pub const EQE_SIZE: usize = 32;

/// Async-event mask: OR of 1-bit per event type the EQ is armed for.
///
/// Events included (ConnectX-3 PRM §16.3.2):
///   - PORT_CHANGE          (0x09)
///   - CQ_ERROR             (0x04)
///   - CMD                  (0x0a)
///   - WQ_CATAS_ERROR       (0x05)
///   - LOCAL_WQ_INVALID_REQ (0x10)
///   - LOCAL_WQ_ACCESS_VIOL (0x11)
pub const ASYNC_EVENT_MASK: u64 =
    (1 << 0x09) | (1 << 0x04) | (1 << 0x0a) | (1 << 0x05) | (1 << 0x10) | (1 << 0x11);

/// Parameters for constructing an EQ context via `build_eq_context`.
#[derive(Copy, Clone, Debug)]
pub struct EqParams {
    /// log2 of the EQ depth in EQEs (e.g. 7 → 128 entries).
    pub log_eq_size: u8,
    /// Interrupt vector / MSI-X index to route this EQ's events to.
    pub intr: u8,
    /// Physical base address of the MTT backing the EQ buffer.
    pub mtt_base: u64,
    /// log2 of the EQ-buffer page size (e.g. 12 for 4-KiB pages).
    pub log_page_size: u8,
}

/// Build the 64-byte EQ context for the SW2HW_EQ mailbox.
///
/// Returns a zeroed array stamped with the PRM-defined field layout.
/// The caller places this into the HCR mailbox and issues SW2HW_EQ.
pub fn build_eq_context(p: &EqParams) -> [u8; EQ_CONTEXT_LEN] {
    let mut b = [0u8; EQ_CONTEXT_LEN];

    // flags @0x00: status=OK(0) in bits [31:28], state=ARMED(9) in bits [11:8].
    // Encodes as 0x0000_0900.
    put_be32(&mut b, 0x00, 9u32 << 8);

    // log_eq_size @0x0c: log2 of EQ depth.
    put_u8(&mut b, 0x0c, p.log_eq_size);

    // intr @0x17: interrupt vector index.
    put_u8(&mut b, 0x17, p.intr);

    // log_page_size @0x18: log2 of backing-page size.
    put_u8(&mut b, 0x18, p.log_page_size);

    // mtt_base_addr split across two fields:
    //   mtt_base_addr_h @0x1b: bits [39:32].
    //   mtt_base_addr_l @0x1c: bits [31:0].
    put_u8(&mut b, 0x1b, (p.mtt_base >> 32) as u8);
    put_be32(&mut b, 0x1c, (p.mtt_base & 0xffff_ffff) as u32);

    // consumer_index @0x28 and producer_index @0x2c: both 0 on creation.
    put_be32(&mut b, 0x28, 0);
    put_be32(&mut b, 0x2c, 0);

    b
}

/// Decoded fields from one 32-byte Event Queue Entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EqeView {
    /// Event type (PRM §16.3.2, e.g. 0x09 = PORT_CHANGE, 0x04 = CQ_ERROR).
    pub event_type: u8,
    /// Event sub-type, meaning is event-type-specific.
    pub subtype: u8,
    /// CQ number from the completion-event payload (bits [23:0] of dword at 0x04).
    pub cqn: u32,
    /// Port number from the port-change event payload (bits [31:28] of dword at 0x04).
    pub port: u8,
    /// Raw ownership byte at offset 0x1f; bit 7 is the hardware/software toggle.
    pub owner_byte: u8,
}

/// Decode one EQE from a 32-byte buffer.
///
/// The same dword at 0x04 carries both the CQN (for completion events)
/// and the port indicator (for port-change events); the caller selects
/// the relevant field based on `event_type`.
pub fn decode_eqe(b: &[u8; EQE_SIZE]) -> EqeView {
    let event_type = get_u8(b, 0x01);
    let subtype = get_u8(b, 0x03);
    let data_dw = get_be32(b, 0x04);
    let cqn = data_dw & 0x00ff_ffff;
    let port = (data_dw >> 28) as u8;
    let owner_byte = get_u8(b, 0x1f);

    EqeView {
        event_type,
        subtype,
        cqn,
        port,
        owner_byte,
    }
}

/// Return `true` when this EQE is software-owned (ready to consume).
///
/// ConnectX-3 PRM §16.3.2: ownership flips on each pass through the
/// ring. The EQE is SW-owned when the owner bit (bit 7 of byte 0x1f)
/// equals the wrap bit derived from the consumer index — specifically
/// when `owner_bit XOR (cons_index & nent) == 0`, i.e. they are equal.
///
/// `nent` should be the EQ depth (number of entries) so that
/// `cons_index & nent` captures the wrap toggle.
pub fn eqe_is_sw_owned(owner_byte: u8, cons_index: u32, nent: u32) -> bool {
    let o = (owner_byte & 0x80) != 0;
    let c = (cons_index & nent) != 0;
    // SW-owned when the two toggle bits agree (not XOR'd).
    !(o ^ c)
}

/// Build the EQ consumer-index doorbell word.
///
/// The host writes this value big-endian to `UAR + 0x800 + 8 * (eqn % 4)`.
/// When `arm` is true the ARM bit (bit 31) requests a new interrupt on
/// the next event arrival; without it the write just advances the index.
pub fn eq_doorbell_word(cons_index: u32, arm: bool) -> u32 {
    (cons_index & 0x00ff_ffff) | (if arm { 1u32 << 31 } else { 0 })
}
