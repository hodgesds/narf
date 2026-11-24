//! Queue Pair (QP) context (Ethernet MLX transport) + MODIFY_QP state
//! machine helpers.
//!
//! Reference: ConnectX-3 PRM §16.5 ("Queue Pair Context") +
//! §15.4 ("RST2INIT_QP", "INIT2RTR_QP", "RTR2RTS_QP" command family).
//!
//! A QP couples a Send Queue and a Receive Queue to a protection domain,
//! a pair of CQs and an address path. ConnectX-3 Ethernet uses service
//! type 7 (MLX raw-Ethernet transport). The state machine walks:
//!
//! ```text
//! RST  ──RstToInit──►  INIT  ──InitToRtr──►  RTR  ──RtrToRts──►  RTS
//! ```
//!
//! ## QP context byte layout (256 bytes, Stage subset)
//!
//! | offset | width   | field            | notes                            |
//! |--------|---------|------------------|----------------------------------|
//! | 0x00   | BE u32  | flags            | svc_type in bits [19:16]; state  |
//! |        |         |                  | nibble in bits [31:28] (0 = RST) |
//! | 0x04   | BE u32  | pd               | protection-domain number         |
//! | 0x08   | u8      | mtu_msgmax       | 0xff on creation                 |
//! | 0x09   | u8      | rq_size_stride   | (log_rq_size<<3) | (stride-4)   |
//! | 0x0a   | u8      | sq_size_stride   | (log_sq_size<<3) | (stride-4)   |
//! | 0x0c   | BE u32  | usr_page         | UAR page index                   |
//! | 0x20   | u8      | ackto            | 1 (pri_path+0x08)                |
//! | 0x25   | u8      | sched_queue      | 0x83 | ((port-1)<<6)            |
//! | 0x5c   | BE u32  | cqn_send         | send CQ number                   |
//! | 0x7c   | BE u32  | cqn_recv         | receive CQ number                |
//! | 0x80   | BE u64  | db_rec_addr      | DMA addr of doorbell record <<2  |
//! | 0xa8   | u8      | log_page_size    | log2 of backing-page size        |
//! | 0xab   | u8      | mtt_base_addr_h  | bits [39:32] of MTT base         |
//! | 0xac   | BE u32  | mtt_base_addr_l  | bits [31:0] of MTT base          |

use alloc::vec::Vec;

use super::wire::{get_be32, put_be32, put_be64, put_u8};

/// Length of the QP context structure (bytes).
pub const QP_CONTEXT_LEN: usize = 256;

/// Parameters for constructing an Ethernet MLX QP context.
#[derive(Copy, Clone, Debug)]
pub struct QpEthParams {
    /// Protection-domain number.
    pub pd: u32,
    /// UAR page index for SQ/RQ doorbells.
    pub uar_index: u32,
    /// Send completion queue number.
    pub cqn_send: u32,
    /// Receive completion queue number.
    pub cqn_recv: u32,
    /// Physical base address of the MTT backing the QP buffer.
    pub mtt_base: u64,
    /// log2 of the QP-buffer page size (e.g. 12 for 4-KiB pages).
    pub log_page_size: u8,
    /// log2 of the receive queue depth in WQEs.
    pub log_rq_size: u8,
    /// log2 of the receive WQE stride in bytes; field encodes `(log2 - 4)`.
    /// Must be >= 4 (16-byte minimum stride).
    pub log_rq_stride: u8,
    /// log2 of the send queue depth in WQEs.
    pub log_sq_size: u8,
    /// log2 of the send WQE stride in bytes; field encodes `(log2 - 4)`.
    /// Must be >= 4.
    pub log_sq_stride: u8,
    /// 1-based port number (1 or 2 on dual-port ConnectX-3).
    pub port: u8,
    /// DMA address of the QP doorbell record page (shifted left 2 by HW
    /// convention; `build_qp_context` applies the shift).
    pub db_rec_addr: u64,
}

/// Build the base 256-byte QP context for SW2HW_QP / RST2INIT_QP.
///
/// The state nibble in flags[31:28] is left 0 (RST); `build_modify_mailbox`
/// stamps it to the target state at transition time.
pub fn build_qp_context(p: &QpEthParams) -> [u8; QP_CONTEXT_LEN] {
    let mut b = [0u8; QP_CONTEXT_LEN];

    // flags @0x00: service type 7 = MLX raw-Ethernet in bits [19:16];
    // state nibble (bits [31:28]) left 0 (RST).
    put_be32(&mut b, 0x00, 7u32 << 16);

    // pd @0x04: protection-domain number.
    put_be32(&mut b, 0x04, p.pd);

    // mtu_msgmax @0x08: set to 0xff (unlimited, firmware enforces MTU).
    put_u8(&mut b, 0x08, 0xff);

    // rq_size_stride @0x09: packed log-size and stride.
    // stride field = log_rq_stride - 4; saturating_sub guards debug builds.
    let rq_stride_field = p.log_rq_stride.saturating_sub(4) & 0x7;
    put_u8(&mut b, 0x09, (p.log_rq_size << 3) | rq_stride_field);

    // sq_size_stride @0x0a: packed log-size and stride.
    let sq_stride_field = p.log_sq_stride.saturating_sub(4) & 0x7;
    put_u8(&mut b, 0x0a, (p.log_sq_size << 3) | sq_stride_field);

    // usr_page @0x0c: UAR page index for SQ/RQ doorbells.
    put_be32(&mut b, 0x0c, p.uar_index);

    // pri_path sub-struct begins at 0x18 (28 bytes).
    // ackto @0x20 (pri_path+0x08): ACK timeout; 1 is the smallest non-zero
    // value and suits initial bring-up before path tuning.
    put_u8(&mut b, 0x20, 1);

    // sched_queue @0x25 (pri_path+0x0d): scheduler queue selector.
    // Bits [7:6] select the port (0-based); bits [1:0] = 0x3 selects the
    // default Ethernet QoS class; bit 7 is always set.
    // port is >=1 by contract; saturating_sub prevents any underflow.
    let port0 = p.port.saturating_sub(1);
    put_u8(&mut b, 0x25, 0x83 | (port0 << 6));

    // cqn_send @0x5c and cqn_recv @0x7c.
    put_be32(&mut b, 0x5c, p.cqn_send);
    put_be32(&mut b, 0x7c, p.cqn_recv);

    // db_rec_addr @0x80: DMA address of the doorbell record, shifted left 2.
    put_be64(&mut b, 0x80, p.db_rec_addr << 2);

    // log_page_size @0xa8.
    put_u8(&mut b, 0xa8, p.log_page_size);

    // mtt_base_addr split:
    //   mtt_base_addr_h @0xab: bits [39:32].
    //   mtt_base_addr_l @0xac: bits [31:0].
    put_u8(&mut b, 0xab, (p.mtt_base >> 32) as u8);
    put_be32(&mut b, 0xac, (p.mtt_base & 0xffff_ffff) as u32);

    b
}

/// QP state values, encoded in flags bits [31:28] of the QP context.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QpState {
    Rst = 0,
    Init = 1,
    Rtr = 2,
    Rts = 3,
}

/// MODIFY_QP transitions for the Ethernet bring-up path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QpTransition {
    /// RST → INIT. HCR opcode RST2INIT_QP (0x019).
    RstToInit,
    /// INIT → RTR. HCR opcode INIT2RTR_QP (0x01a).
    InitToRtr,
    /// RTR → RTS. HCR opcode RTR2RTS_QP (0x01b).
    RtrToRts,
}

impl QpTransition {
    /// The QP state that this transition moves the QP into.
    pub fn target_state(self) -> QpState {
        match self {
            QpTransition::RstToInit => QpState::Init,
            QpTransition::InitToRtr => QpState::Rtr,
            QpTransition::RtrToRts => QpState::Rts,
        }
    }
}

/// Build the MODIFY_QP input mailbox: 4-byte BE `optpar`, 4 bytes
/// reserved, then the 256-byte context with the target-state nibble
/// stamped into flags[31:28].
///
/// Returns 8 + 256 = 264 bytes; the caller places this into the HCR
/// mailbox and issues the appropriate transition opcode.
pub fn build_modify_mailbox(
    ctx: &[u8; QP_CONTEXT_LEN],
    trans: QpTransition,
    optpar: u32,
) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 8 + QP_CONTEXT_LEN];

    // optpar @0x00 (BE u32): optional-parameter mask.
    put_be32(&mut out, 0x00, optpar);
    // bytes 4..7: reserved, left 0.

    // Copy the base context into out[8..264].
    out[8..8 + QP_CONTEXT_LEN].copy_from_slice(ctx);

    // Stamp the target-state nibble into flags[31:28] within the
    // embedded context (at out[8 + 0x00]).
    let flags_off = 8;
    let flags = get_be32(&out[flags_off..], 0x00);
    let state_nibble = trans.target_state() as u32;
    put_be32(&mut out, flags_off, (flags & 0x0fff_ffff) | (state_nibble << 28));

    out
}

/// Extract the state nibble from flags bits [31:28] of a QP context.
///
/// Used by round-trip tests to confirm that `build_modify_mailbox`
/// stamped the correct target state.
pub fn decode_state(ctx: &[u8; QP_CONTEXT_LEN]) -> u8 {
    ((get_be32(ctx, 0x00) >> 28) & 0xf) as u8
}

/// Extract the service-type nibble from flags bits [19:16] of a QP context.
///
/// For contexts built by `build_qp_context` this always returns 7
/// (MLX raw-Ethernet transport).
pub fn decode_service_type(ctx: &[u8; QP_CONTEXT_LEN]) -> u8 {
    ((get_be32(ctx, 0x00) >> 16) & 0xf) as u8
}
