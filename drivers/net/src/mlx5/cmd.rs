//! mlx5 command-mailbox interface — Stage 2.
//!
//! The HCA's bring-up + steady-state control plane runs through a
//! single Command Queue (CQ) of 64-byte Command Queue Entries (CQEs)
//! placed at the host-physical address advertised by the init
//! segment's `cmdq_addr`. Software writes a CQE, sets the ownership
//! bit, rings the `cmd_dbell` doorbell at BAR0+0x18, and polls the
//! ownership bit until firmware clears it.
//!
//! Reference: public Mellanox PRM §3.5 ("Command Interface"). No GPL
//! Linux source consulted.
//!
//! ## CQE layout (64 bytes, all BE on wire)
//!
//! ```text
//! +0x00  type          u8   (0x07 = mailbox)
//! +0x01  reserved      u24
//! +0x04  input_length  u32  bytes of in-DMA input mailbox (0 if inline)
//! +0x08  input_mb_h    u32  high 32 bits of input mailbox phys addr
//! +0x0C  input_mb_l    u32  low 32 bits (low 9 bits reserved → 512-B align)
//! +0x10  command_input_inline   16 B
//!        +0x10  opcode               u16
//!        +0x12  op_mod_high          u16  (reserved)
//!        +0x14  input_modifier       u32
//!        +0x18  inline input data    8 B
//! +0x20  command_output_inline  16 B
//!        +0x20  status               u8   (0 = OK)
//!        +0x21  syndrome             u24
//!        +0x24  output_modifier      u32
//!        +0x28  inline output data   8 B
//! +0x30  output_mb_h     u32
//! +0x34  output_mb_l     u32
//! +0x38  output_length   u32
//! +0x3C  token           u8
//! +0x3D  signature       u8
//! +0x3E  reserved        u8
//! +0x3F  status_own      u8   bit 0 = ownership (1 = HW, 0 = SW/done)
//! ```
//!
//! Stage 2 scope: pure layout + builder + decoder + opcode catalog.
//! No DMA mailboxes yet — Stage 2 only carries inline-mode commands
//! (opcode + ≤8 B input + ≤8 B output), which is enough for NOP and
//! the inline reply portion of QUERY_HCA_CAP. Full DMA-mailbox
//! transport for long QUERY_HCA_CAP responses lands in Stage 3.

/// Length of one Command Queue Entry, in bytes.
pub const CQE_LEN: usize = 64;

/// CQE field offsets.
pub const CQE_OFF_TYPE:           usize = 0x00;
pub const CQE_OFF_INPUT_LEN:      usize = 0x04;
pub const CQE_OFF_INPUT_MB_H:     usize = 0x08;
pub const CQE_OFF_INPUT_MB_L:     usize = 0x0C;
pub const CQE_OFF_OPCODE:         usize = 0x10;
pub const CQE_OFF_OP_MOD_HIGH:    usize = 0x12;
pub const CQE_OFF_INPUT_MOD:      usize = 0x14;
pub const CQE_OFF_INPUT_INLINE:   usize = 0x18;
pub const CQE_OFF_STATUS:         usize = 0x20;
pub const CQE_OFF_OUTPUT_MOD:     usize = 0x24;
pub const CQE_OFF_OUTPUT_INLINE:  usize = 0x28;
pub const CQE_OFF_OUTPUT_MB_H:    usize = 0x30;
pub const CQE_OFF_OUTPUT_MB_L:    usize = 0x34;
pub const CQE_OFF_OUTPUT_LEN:     usize = 0x38;
pub const CQE_OFF_TOKEN:          usize = 0x3C;
pub const CQE_OFF_SIGNATURE:      usize = 0x3D;
pub const CQE_OFF_STATUS_OWN:     usize = 0x3F;

/// CQE `type` field: mailbox transaction type.
pub const CQE_TYPE_MAILBOX: u8 = 0x07;

/// Ownership bit in `status_own` (bit 0). `1` while HW owns the CQE;
/// `0` once HW has completed the command.
pub const STATUS_OWN_BIT: u8 = 1 << 0;

/// PRM-documented command opcodes. Stage 2 surfaces the two we care
/// about for transport bring-up; the full catalog gets added as
/// later stages need it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CmdOp {
    /// `QUERY_HCA_CAP` — read HCA capability tables. Opcode `0x100`.
    QueryHcaCap = 0x100,
    /// `NOP` — no-op; firmware echoes the response with status 0.
    /// Opcode `0x101`. Useful as the very first command exchanged
    /// after bring-up to confirm the cmd-mailbox transport works.
    Nop         = 0x101,
}

/// Status codes the firmware writes into byte 0x20 of the CQE.
/// Stage 2 surfaces the common ones; full enumeration in PRM §3.5.4.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmdStatus {
    Ok,
    InternalErr,
    BadOp,
    BadParam,
    BadSysState,
    BadResource,
    ResourceBusy,
    ExceedLim,
    BadResState,
    BadIndex,
    NoResources,
    BadInputLen,
    BadOutputLen,
    /// Any code we haven't mapped is preserved as-is.
    Unknown(u8),
}

impl CmdStatus {
    pub fn from_raw(b: u8) -> Self {
        match b {
            0x00 => CmdStatus::Ok,
            0x01 => CmdStatus::InternalErr,
            0x02 => CmdStatus::BadOp,
            0x03 => CmdStatus::BadParam,
            0x04 => CmdStatus::BadSysState,
            0x05 => CmdStatus::BadResource,
            0x06 => CmdStatus::ResourceBusy,
            0x08 => CmdStatus::ExceedLim,
            0x09 => CmdStatus::BadResState,
            0x0A => CmdStatus::BadIndex,
            0x0F => CmdStatus::NoResources,
            0x50 => CmdStatus::BadInputLen,
            0x51 => CmdStatus::BadOutputLen,
            other => CmdStatus::Unknown(other),
        }
    }
}

/// Errors from building or decoding a CQE.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmdError {
    /// Inline payload too long (> 8 bytes for input or output).
    InlineOverflow,
    /// CQE was decoded while still owned by HW.
    NotComplete,
    /// Firmware returned non-OK status.
    FwStatus(CmdStatus, u32 /* syndrome */),
    /// Wrong CQE type field (expected 0x07).
    BadType(u8),
}

/// Decoded inline portion of a CQE response.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmdResponse {
    pub status:          CmdStatus,
    pub syndrome:        u32,
    pub output_modifier: u32,
    pub inline_output:   [u8; 8],
    pub token:           u8,
}

/// Build an inline-mode CQE. The DMA-mailbox pointer fields are left
/// zero; callers supplying long inputs/outputs use the (Stage-3)
/// `build_cqe_with_mailboxes` variant.
pub fn build_cqe_inline(
    op:             CmdOp,
    input_modifier: u32,
    inline_input:   &[u8],
    token:          u8,
) -> Result<[u8; CQE_LEN], CmdError> {
    if inline_input.len() > 8 { return Err(CmdError::InlineOverflow); }
    let mut cqe = [0u8; CQE_LEN];
    cqe[CQE_OFF_TYPE] = CQE_TYPE_MAILBOX;
    // No DMA mailboxes; input_length/output_length stay 0.
    cqe[CQE_OFF_OPCODE..CQE_OFF_OPCODE + 2]
        .copy_from_slice(&(op as u16).to_be_bytes());
    cqe[CQE_OFF_INPUT_MOD..CQE_OFF_INPUT_MOD + 4]
        .copy_from_slice(&input_modifier.to_be_bytes());
    cqe[CQE_OFF_INPUT_INLINE..CQE_OFF_INPUT_INLINE + inline_input.len()]
        .copy_from_slice(inline_input);
    cqe[CQE_OFF_TOKEN]      = token;
    cqe[CQE_OFF_SIGNATURE]  = compute_signature(&cqe);
    cqe[CQE_OFF_STATUS_OWN] = STATUS_OWN_BIT;
    Ok(cqe)
}

/// Compute the byte-XOR signature over the CQE excluding the
/// signature byte itself. PRM §3.5.2 documents this as a simple
/// 8-bit XOR checksum.
pub fn compute_signature(cqe: &[u8; CQE_LEN]) -> u8 {
    let mut acc = 0u8;
    for (i, &b) in cqe.iter().enumerate() {
        if i == CQE_OFF_SIGNATURE { continue; }
        acc ^= b;
    }
    acc
}

/// `true` if firmware has cleared the ownership bit, indicating the
/// CQE response is ready to read.
pub fn is_complete(cqe: &[u8; CQE_LEN]) -> bool {
    (cqe[CQE_OFF_STATUS_OWN] & STATUS_OWN_BIT) == 0
}

/// Decode the inline response portion of a completed CQE. Returns
/// `Err(NotComplete)` if HW still owns the entry.
pub fn decode_response(cqe: &[u8; CQE_LEN]) -> Result<CmdResponse, CmdError> {
    if !is_complete(cqe) { return Err(CmdError::NotComplete); }
    let ty = cqe[CQE_OFF_TYPE];
    if ty != CQE_TYPE_MAILBOX { return Err(CmdError::BadType(ty)); }
    let raw_status = cqe[CQE_OFF_STATUS];
    let status     = CmdStatus::from_raw(raw_status);
    // syndrome is a 24-bit BE field at +0x21..+0x24.
    let syn = u32::from_be_bytes([
        0,
        cqe[CQE_OFF_STATUS + 1],
        cqe[CQE_OFF_STATUS + 2],
        cqe[CQE_OFF_STATUS + 3],
    ]);
    let output_mod = u32::from_be_bytes([
        cqe[CQE_OFF_OUTPUT_MOD],
        cqe[CQE_OFF_OUTPUT_MOD + 1],
        cqe[CQE_OFF_OUTPUT_MOD + 2],
        cqe[CQE_OFF_OUTPUT_MOD + 3],
    ]);
    let mut inline_out = [0u8; 8];
    inline_out.copy_from_slice(
        &cqe[CQE_OFF_OUTPUT_INLINE .. CQE_OFF_OUTPUT_INLINE + 8]);
    let resp = CmdResponse {
        status, syndrome: syn,
        output_modifier: output_mod,
        inline_output:   inline_out,
        token:           cqe[CQE_OFF_TOKEN],
    };
    if !matches!(status, CmdStatus::Ok) {
        return Err(CmdError::FwStatus(status, syn));
    }
    Ok(resp)
}

/// Convenience: simulate firmware completing `cqe` in place by
/// clearing the ownership bit and writing a status / syndrome /
/// output payload. Used by smokes to drive the decoder against
/// realistic CQE bytes without a live HCA.
pub fn simulate_completion(
    cqe:             &mut [u8; CQE_LEN],
    raw_status:      u8,
    syndrome:        u32,
    output_modifier: u32,
    inline_output:   &[u8],
) {
    cqe[CQE_OFF_STATUS]    = raw_status;
    let syn_bytes = syndrome.to_be_bytes();
    cqe[CQE_OFF_STATUS + 1] = syn_bytes[1];
    cqe[CQE_OFF_STATUS + 2] = syn_bytes[2];
    cqe[CQE_OFF_STATUS + 3] = syn_bytes[3];
    cqe[CQE_OFF_OUTPUT_MOD..CQE_OFF_OUTPUT_MOD + 4]
        .copy_from_slice(&output_modifier.to_be_bytes());
    let n = inline_output.len().min(8);
    cqe[CQE_OFF_OUTPUT_INLINE..CQE_OFF_OUTPUT_INLINE + n]
        .copy_from_slice(&inline_output[..n]);
    cqe[CQE_OFF_STATUS_OWN] &= !STATUS_OWN_BIT;
}
