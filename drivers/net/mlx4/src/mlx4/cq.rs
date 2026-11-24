//! Completion Queue (CQ) context + CQE decoder + doorbell encoders.
//!
//! The CQ carries both send and receive completions for the Ethernet
//! datapath. `build_cq_context` encodes the 64-byte `SW2HW_CQ` input
//! mailbox; `decode_cqe` decodes the 32-byte completion entry including
//! the Ethernet RX checksum-offload status; the doorbell helpers encode
//! the consumer-index / arm words the driver writes to the UAR and the
//! host-memory doorbell record. Clean-room from the ConnectX-3 PRM §17
//! ("Completion Queues").

use super::wire;

/// `SW2HW_CQ` input-mailbox / CQ context length.
pub const CQ_CONTEXT_LEN: usize = 0x40;

/// One completion entry is 32 bytes (the base, non-timestamp form).
pub const CQE_SIZE: usize = 32;

/// Byte offset of the CQ doorbell within a UAR page (PRM §17.4).
pub const CQ_DOORBELL_UAR_OFFSET: u64 = 0x20;

/// `cmd` field for the arm doorbell: request notification on the next
/// solicited completion (`REQ_NOT_SOL`) or on any completion (`REQ_NOT`).
pub const CQ_DB_REQ_NOT_SOL: u32 = 1 << 24;
pub const CQ_DB_REQ_NOT: u32 = 2 << 24;

// ── CQE owner / opcode bits (owner_sr_opcode byte at 0x1f) ─────────

/// Hardware owns the CQE until it flips this bit to match the
/// consumer-index phase.
pub const CQE_OWNER_MASK: u8 = 0x80;
/// Set on a send (requester) completion; clear on a receive.
pub const CQE_IS_SEND_MASK: u8 = 0x40;
/// Opcode occupies the low 5 bits; `0x1e` flags an error completion.
pub const CQE_OPCODE_MASK: u8 = 0x1f;
pub const CQE_OPCODE_ERROR: u8 = 0x1e;

// ── Ethernet RX checksum status bits (status be16 at 0x10) ─────────

pub const CQE_STATUS_IPV4: u16 = 1 << 6;
pub const CQE_STATUS_IPV4F: u16 = 1 << 7;
pub const CQE_STATUS_IPV6: u16 = 1 << 8;
pub const CQE_STATUS_IPV4OPT: u16 = 1 << 9;
pub const CQE_STATUS_TCP: u16 = 1 << 10;
pub const CQE_STATUS_UDP: u16 = 1 << 11;
pub const CQE_STATUS_IPOK: u16 = 1 << 12;
/// L4 checksum-validated flag — lives in the `badfcs_enc` byte at 0x13.
pub const CQE_STATUS_L4_CSUM: u8 = 1 << 2;
/// Bad frame-check-sequence flag — also in `badfcs_enc`.
pub const CQE_BAD_FCS: u8 = 1 << 4;

/// Low 24 bits of `vlan_my_qpn` are the QP number.
pub const CQE_QPN_MASK: u32 = 0x00ff_ffff;

/// Parameters for a CQ context (`SW2HW_CQ`).
#[derive(Copy, Clone, Debug)]
pub struct CqParams {
    pub log_cq_size: u8,
    /// UAR page index this CQ's doorbell lives in.
    pub uar_index: u32,
    /// Device address of the CQ's MTT base.
    pub mtt_base: u64,
    /// `page_shift - 12`.
    pub log_page_size: u8,
    /// EQ number bound to this CQ for completion events.
    pub comp_eqn: u8,
    /// DMA address of the host-memory doorbell record.
    pub db_rec_addr: u64,
}

/// Encode the 64-byte CQ context.
pub fn build_cq_context(p: &CqParams) -> [u8; CQ_CONTEXT_LEN] {
    let mut c = [0u8; CQ_CONTEXT_LEN];
    // flags @0x00: status/state left 0 (firmware owns the state machine);
    // collapsed = 0.
    wire::put_be32(&mut c, 0x0c, (u32::from(p.log_cq_size) << 24) | (p.uar_index & 0x00ff_ffff));
    wire::put_u8(&mut c, 0x17, p.comp_eqn);
    wire::put_u8(&mut c, 0x18, p.log_page_size);
    wire::put_u8(&mut c, 0x1b, (p.mtt_base >> 32) as u8);
    wire::put_be32(&mut c, 0x1c, (p.mtt_base & 0xffff_ffff) as u32);
    wire::put_be64(&mut c, 0x38, p.db_rec_addr);
    c
}

/// A decoded completion entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CqeView {
    /// Completing QP number (low 24 bits of `vlan_my_qpn`).
    pub qpn: u32,
    /// Received byte count (meaningful for RX completions).
    pub byte_cnt: u32,
    /// Index of the completed WQE in its SQ/RQ.
    pub wqe_index: u16,
    /// Hardware-computed L4 checksum value (RX).
    pub checksum: u16,
    /// Ethernet status word (IP/TCP/UDP/IPOK bits).
    pub status: u16,
    /// `badfcs_enc` byte (L4-csum + bad-FCS flags).
    pub badfcs_enc: u8,
    /// True on a send (requester) completion.
    pub is_send: bool,
    /// Low-5-bit opcode.
    pub opcode: u8,
    /// Raw owner/opcode byte, so the caller can run the phase check.
    pub owner_byte: u8,
}

impl CqeView {
    /// True when this completion retired with an error.
    #[inline]
    pub fn is_error(&self) -> bool {
        self.opcode == CQE_OPCODE_ERROR
    }

    /// True when the hardware verified the L4 (TCP/UDP) checksum and it
    /// passed — the PRM fast path: an IP-OK TCP/UDP frame whose running
    /// checksum folds to `0xffff`.
    #[inline]
    pub fn l4_csum_ok(&self) -> bool {
        self.status & (CQE_STATUS_TCP | CQE_STATUS_UDP) != 0
            && self.status & CQE_STATUS_IPOK != 0
            && self.checksum == 0xffff
    }

    /// True when the IP header checksum was verified OK.
    #[inline]
    pub fn ip_csum_ok(&self) -> bool {
        self.status & CQE_STATUS_IPOK != 0
    }

    /// True when the frame failed its FCS check and must be dropped.
    #[inline]
    pub fn bad_fcs(&self) -> bool {
        self.badfcs_enc & CQE_BAD_FCS != 0
    }
}

/// Decode a 32-byte CQE.
pub fn decode_cqe(b: &[u8; CQE_SIZE]) -> CqeView {
    let owner_byte = wire::get_u8(b, 0x1f);
    CqeView {
        qpn: wire::get_be32(b, 0x00) & CQE_QPN_MASK,
        byte_cnt: wire::get_be32(b, 0x14),
        wqe_index: wire::get_be16(b, 0x18),
        checksum: wire::get_be16(b, 0x1a),
        status: wire::get_be16(b, 0x10),
        badfcs_enc: wire::get_u8(b, 0x13),
        is_send: owner_byte & CQE_IS_SEND_MASK != 0,
        opcode: owner_byte & CQE_OPCODE_MASK,
        owner_byte,
    }
}

/// True when the CQE at `cons_index` is software-owned (ready to
/// consume): the owner bit matches the consumer-index phase.
/// `cqe_count` is the CQ depth (a power of two).
#[inline]
pub fn cqe_is_sw_owned(owner_byte: u8, cons_index: u32, cqe_count: u32) -> bool {
    let hw = owner_byte & CQE_OWNER_MASK != 0;
    let phase = cons_index & cqe_count != 0;
    hw == phase
}

/// The non-arming consumer-index doorbell-record word (written to
/// `set_ci_db`): low 24 bits of the consumer index, big-endian.
#[inline]
pub fn cq_set_ci_word(cons_index: u32) -> u32 {
    cons_index & 0x00ff_ffff
}

/// The arm doorbell-record word (written to `arm_db`): sequence number
/// in bits 29:28, command, consumer index.
#[inline]
pub fn cq_arm_db_word(cons_index: u32, sn: u32, cmd: u32) -> u32 {
    ((sn & 3) << 28) | cmd | (cons_index & 0x00ff_ffff)
}

/// The two 32-bit words written (as a 64-bit pair) to the UAR CQ
/// doorbell to arm the CQ: `[ (sn<<28)|cmd|cqn , cons_index ]`.
#[inline]
pub fn cq_arm_uar_words(cqn: u32, cons_index: u32, sn: u32, cmd: u32) -> [u32; 2] {
    [
        ((sn & 3) << 28) | cmd | (cqn & 0x00ff_ffff),
        cons_index & 0x00ff_ffff,
    ]
}
