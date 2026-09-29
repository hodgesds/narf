//! iwlwifi transmit descriptors for gen2 and gen3 devices.
//!
//! The descriptor format changed completely at 22000-series silicon.
//! [`super::tx`] models the original one: a large `iwl_tx_cmd` with
//! station id and security fields inline, a TFD whose scatter-gather
//! entries lead with a 64-bit address, and a doorbell written through
//! the PRPH scheduler window. None of that is what a Scorpius Peak
//! (the MS-03's BE211, `iwlwifi-sc-a0-wh-b0`) expects.
//!
//! What changed, and why each one matters:
//!
//! - **The TFD is the TFH format.** `num_tbs` is 16 bits, not a byte
//!   plus padding, and each transmit buffer is `{ len, addr }` —
//!   length *first*, then the 64-bit address, packed to 10 bytes.
//!   The old model put the address first and let the compiler pad
//!   each entry to 16, so both the field order and the stride were
//!   wrong.
//!
//! - **The TX command shrank and reordered.** AX210+ uses `len`,
//!   `flags` (16-bit), `offload_assist` (32-bit), a `dram_info`
//!   block for the PN, `rate_n_flags`, and 8 reserved bytes. The
//!   22000-series version has the same fields with `offload_assist`
//!   and `flags` *swapped*, which is the trap: a struct that decodes
//!   cleanly on one generation is silently garbage on the other.
//!
//! - **The byte-count table is mandatory.** Gen2 hardware fetches
//!   the TFD in 64-byte chunks and needs to be told, per slot, both
//!   the frame length and how many chunks to pull.
//!
//! - **The doorbell moved.** Gen2 writes the queue id and write
//!   pointer to a single CSR, `HBUS_TARG_WRPTR`, rather than to a
//!   per-queue PRPH scheduler register.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `iwl-fh.h` — `iwl_tfh_tb`, `iwl_tfh_tfd`, `iwl_bc_tbl_entry`,
//!   `IWL_TFH_NUM_TBS`.
//! - `fw/api/tx.h` — `iwl_tx_cmd` (AX210+), `iwl_tx_cmd_v9`,
//!   `iwl_dram_sec_info`.
//! - `pcie/gen1_2/tx-gen2.c` — `iwl_txq_gen2_set_tb`,
//!   `iwl_txq_gen2_get_num_tbs`, `iwl_pcie_gen2_update_byte_tbl`,
//!   and the `HBUS_TARG_WRPTR` doorbell write.
//! - `pcie/gen1_2/internal.h` — `iwl_txq_crosses_4g_boundary`.
//! - `iwl-csr.h` — `HBUS_TARG_WRPTR`, `HBUS_TARG_WRPTR_Q_SHIFT`.

#![allow(dead_code)]

// ── TFH transfer-frame descriptor ───────────────────────────────────

/// `IWL_TFH_NUM_TBS` — transmit buffers one TFD can point at.
pub const IWL_TFH_NUM_TBS: usize = 25;

/// Only the low five bits of `num_tbs` are the count; the rest are
/// reserved and must be masked off before use.
pub const NUM_TBS_MASK: u16 = 0x1F;

/// One transmit buffer: length first, then the 64-bit address.
///
/// Packed to 10 bytes. Writing this as `{ addr, len }` — the natural
/// order, and what the gen1 model used — both transposes the fields
/// and grows the stride to 16, so the device reads a length where an
/// address should be from the second entry onward.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TfhTb {
    /// Buffer length in bytes.
    pub tb_len: u16,
    /// Host physical address of the buffer.
    pub addr: u64,
}

/// A gen2/gen3 transmit frame descriptor.
///
/// 2 + 25*10 + 4 = 256 bytes, which is the documented per-TFD size
/// for 22000-series hardware and later ("256 x 256 bytes-per-TFD").
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct TfhTfd {
    /// Active transmit-buffer count in bits 0..4.
    pub num_tbs: u16,
    /// The transmit buffers themselves.
    pub tbs: [TfhTb; IWL_TFH_NUM_TBS],
    /// Tail padding to the 256-byte descriptor size.
    pub _pad: u32,
}

impl Default for TfhTfd {
    fn default() -> Self {
        Self {
            num_tbs: 0,
            tbs: [TfhTb::default(); IWL_TFH_NUM_TBS],
            _pad: 0,
        }
    }
}

/// Why a transmit buffer could not be appended.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TfdError {
    /// The descriptor already holds [`IWL_TFH_NUM_TBS`] buffers.
    Full,
    /// The buffer would straddle a 4 GiB boundary.
    ///
    /// The DMA engine computes the end address without carrying into
    /// the upper half, so such a buffer is read from the wrong place.
    /// Linux only warns and carries on, because several of its
    /// callers do not check the return; there is no such legacy here,
    /// so it is refused outright.
    CrossesFourGiB {
        /// The offending physical address.
        addr: u64,
        /// The length that would carry past the boundary.
        len: u16,
    },
}

/// Whether `[addr, addr + len)` straddles a 4 GiB boundary.
///
/// `iwl_txq_crosses_4g_boundary`: compares the upper 32 bits of the
/// first and last byte.
pub const fn crosses_4gib(addr: u64, len: u16) -> bool {
    (addr >> 32) != ((addr + len as u64) >> 32)
}

impl TfhTfd {
    /// Active transmit-buffer count.
    pub const fn num_tbs(&self) -> u8 {
        (self.num_tbs & NUM_TBS_MASK) as u8
    }

    /// Append one transmit buffer, returning its index.
    ///
    /// Mirrors `iwl_txq_gen2_set_tb`.
    pub fn push_tb(&mut self, addr: u64, len: u16) -> Result<usize, TfdError> {
        if crosses_4gib(addr, len) {
            return Err(TfdError::CrossesFourGiB { addr, len });
        }
        let idx = self.num_tbs() as usize;
        if idx >= IWL_TFH_NUM_TBS {
            return Err(TfdError::Full);
        }
        self.tbs[idx] = TfhTb { tb_len: len, addr };
        // Only the count bits are rewritten; the reserved bits above
        // them are left as the device found them.
        self.num_tbs = (self.num_tbs & !NUM_TBS_MASK) | ((idx as u16) + 1);
        Ok(idx)
    }

    /// Bytes of this descriptor the device must fetch to see every
    /// populated buffer: the `num_tbs` field plus the active entries.
    ///
    /// `offsetof(struct iwl_tfh_tfd, tbs) + num_tbs * sizeof(struct
    /// iwl_tfh_tb)` in `iwl_pcie_gen2_update_byte_tbl`.
    pub const fn filled_bytes(&self) -> usize {
        TBS_OFFSET + (self.num_tbs() as usize) * core::mem::size_of::<TfhTb>()
    }
}

/// Byte offset of `tbs` within [`TfhTfd`] — the size of `num_tbs`.
pub const TBS_OFFSET: usize = 2;

// ── Scheduler byte-count table ──────────────────────────────────────

/// How the device fetches a TFD: 64 bytes at a time.
pub const TFD_FETCH_CHUNK_BYTES: usize = 64;

/// Largest frame length an AX210+ byte-count entry can carry, since
/// the top two bits hold the chunk count.
pub const BC_MAX_LEN_AX210: u16 = 0x3FFF;
/// Largest *dword* count a pre-AX210 entry can carry, the top four
/// bits holding the chunk count.
pub const BC_MAX_LEN_PRE_AX210: u16 = 0x0FFF;

/// Chunk-count shift for AX210+ (two bits at the top).
pub const BC_CHUNK_SHIFT_AX210: u16 = 14;
/// Chunk-count shift for pre-AX210 (four bits at the top).
pub const BC_CHUNK_SHIFT_PRE_AX210: u16 = 12;

/// One `iwl_bc_tbl_entry` — a single 16-bit word per ring slot.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct BcTblEntry {
    /// Packed length and fetch-chunk count.
    pub tfd_offset: u16,
}

/// Why a byte-count entry could not be built.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BcError {
    /// The frame is longer than the entry's length field can hold.
    LengthTooLarge(u16),
}

/// Number of 64-byte chunks the device must fetch to read `filled`
/// bytes of a TFD, encoded as Linux does it: zero means one chunk.
pub const fn fetch_chunks(filled_bytes: usize) -> u16 {
    // DIV_ROUND_UP(filled, 64) - 1. `filled` is never zero: a TFD
    // always has at least the `num_tbs` field.
    (filled_bytes.div_ceil(TFD_FETCH_CHUNK_BYTES) as u16).saturating_sub(1)
}

/// Build the byte-count entry for a frame on AX210-or-later silicon.
///
/// The length is carried in bytes, unscaled. This is the encoding
/// Scorpius Peak uses.
pub const fn bc_entry_ax210(frame_len: u16, filled_bytes: usize) -> Result<BcTblEntry, BcError> {
    if frame_len > BC_MAX_LEN_AX210 {
        return Err(BcError::LengthTooLarge(frame_len));
    }
    Ok(BcTblEntry {
        tfd_offset: frame_len | (fetch_chunks(filled_bytes) << BC_CHUNK_SHIFT_AX210),
    })
}

/// Build the byte-count entry for pre-AX210 gen2 silicon.
///
/// Here the length is rounded *up* to whole dwords before packing,
/// and the chunk count sits four bits higher.
pub const fn bc_entry_pre_ax210(
    frame_len: u16,
    filled_bytes: usize,
) -> Result<BcTblEntry, BcError> {
    let dwords = frame_len.div_ceil(4);
    if dwords > BC_MAX_LEN_PRE_AX210 {
        return Err(BcError::LengthTooLarge(frame_len));
    }
    Ok(BcTblEntry {
        tfd_offset: dwords | (fetch_chunks(filled_bytes) << BC_CHUNK_SHIFT_PRE_AX210),
    })
}

// ── Doorbell ────────────────────────────────────────────────────────

/// `HBUS_BASE` — base of the host-bus target window in BAR0.
pub const HBUS_BASE: u32 = 0x400;
/// `HBUS_TARG_WRPTR` — the gen2/gen3 doorbell. One CSR for every
/// queue; the queue is encoded in the value, not the address.
pub const HBUS_TARG_WRPTR: u32 = HBUS_BASE + 0x060;
/// `HBUS_TARG_WRPTR_Q_SHIFT` — where the queue id sits in the value.
pub const HBUS_TARG_WRPTR_Q_SHIFT: u32 = 16;
/// RX queues are addressed through the same register, offset by 512
/// so they cannot collide with a TX queue id.
pub const HBUS_TARG_WRPTR_RX_Q_BASE: u32 = 512;

/// Value to write to [`HBUS_TARG_WRPTR`] to ring a TX queue.
///
/// `iwl_write32(trans, HBUS_TARG_WRPTR, txq->write_ptr | (txq->id << 16))`.
pub const fn tx_doorbell(queue_id: u32, write_ptr: u32) -> u32 {
    write_ptr | (queue_id << HBUS_TARG_WRPTR_Q_SHIFT)
}

/// Value to write to [`HBUS_TARG_WRPTR`] to ring an RX queue.
///
/// `HBUS_TARG_WRPTR_RX_Q(q)` adds 512 to the queue id first, which is
/// what keeps RX queue 0 from ringing TX queue 0.
pub const fn rx_doorbell(queue_id: u32, write_actual: u32) -> u32 {
    write_actual | ((queue_id + HBUS_TARG_WRPTR_RX_Q_BASE) << HBUS_TARG_WRPTR_Q_SHIFT)
}

// ── TX command ──────────────────────────────────────────────────────

/// `iwl_dram_sec_info` — where the firmware keeps the packet number
/// for hardware crypto.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DramSecInfo {
    /// Low 32 bits of the PN.
    pub pn_low: u32,
    /// High 16 bits of the PN.
    pub pn_high: u16,
    /// Key-slot and cipher selector.
    pub aux_info: u16,
}

/// `iwl_tx_cmd` as AX210-and-later firmware expects it.
///
/// Note the order: `flags` sits between `len` and `offload_assist`.
/// On 22000-series silicon those two are the other way round (see
/// [`TxCmdV9`]), and nothing on the wire distinguishes them — the
/// firmware simply misreads the frame.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxCmdAx210 {
    /// Payload length in bytes.
    pub len: u16,
    /// `iwl_tx_cmd_flags`.
    pub flags: u16,
    /// TX offload configuration.
    pub offload_assist: u32,
    /// Firmware-internal DRAM storage for the PN.
    pub dram_info: DramSecInfo,
    /// Rate and modulation for every attempt.
    pub rate_n_flags: u32,
    /// Reserved; the 802.11 header follows this.
    pub reserved: [u8; 8],
}

/// `iwl_tx_cmd_v9` — the 22000-series layout, kept so the difference
/// is visible and so a gen2 part that is not AX210+ can be driven
/// correctly.
///
/// The two layouts are not a field swap, which is what makes this
/// worth spelling out: here `offload_assist` is 16 bits and `flags`
/// is 32, and on AX210+ it is the other way round. Both structs put
/// something at offset 2 and something at offset 4, so a wrong choice
/// produces a plausible-looking command that means something else.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxCmdV9 {
    /// Payload length in bytes.
    pub len: u16,
    /// TX offload configuration.
    pub offload_assist: u16,
    /// `iwl_tx_cmd_flags`.
    pub flags: u32,
    /// Firmware-internal DRAM storage for the PN.
    pub dram_info: DramSecInfo,
    /// Rate and modulation for every attempt.
    pub rate_n_flags: u32,
}

/// Size of the AX210+ TX command that precedes the 802.11 header.
pub const TX_CMD_AX210_BYTES: usize = core::mem::size_of::<TxCmdAx210>();
/// Size of the 22000-series TX command.
pub const TX_CMD_V9_BYTES: usize = core::mem::size_of::<TxCmdV9>();

impl TxCmdAx210 {
    /// A command for a frame the firmware should rate-control itself.
    pub fn new(payload_len: u16, rate_n_flags: u32, flags: u16) -> Self {
        Self {
            len: payload_len,
            flags,
            offload_assist: 0,
            dram_info: DramSecInfo::default(),
            rate_n_flags,
            reserved: [0; 8],
        }
    }
}

// ── Queue configuration ─────────────────────────────────────────────
//
// Gen2 queues do not exist until the host asks for them. After ALIVE
// the driver sends one `SCD_QUEUE_CFG` per queue, handing the
// firmware the TFD ring and byte-count table it just allocated; the
// response says which hardware queue it got. That is why none of the
// descriptor work above can be exercised by simply writing a
// doorbell — until this command is answered there is no queue behind
// it.

/// `TX_QUEUE_CFG_ENABLE_QUEUE`.
pub const TX_QUEUE_CFG_ENABLE_QUEUE: u16 = 1 << 0;
/// `TX_QUEUE_CFG_TFD_SHORT_FORMAT`.
pub const TX_QUEUE_CFG_TFD_SHORT_FORMAT: u16 = 1 << 1;

/// `IWL_DEFAULT_QUEUE_SIZE` — TFDs in a normal data queue.
pub const IWL_DEFAULT_QUEUE_SIZE: usize = 256;
/// `IWL_MGMT_QUEUE_SIZE`.
pub const IWL_MGMT_QUEUE_SIZE: usize = 16;
/// `IWL_CMD_QUEUE_SIZE`.
pub const IWL_CMD_QUEUE_SIZE: usize = 32;

/// `TFD_QUEUE_BC_SIZE_AX210` — entries in an AX210+ byte-count
/// table. Fixed, and unrelated to the ring depth: a 16-slot
/// management queue still gets a 1024-entry table.
pub const TFD_QUEUE_BC_SIZE_AX210: usize = 1024;
/// `TFD_QUEUE_SIZE_BC_DUP` — the duplicate region older parts append
/// to their byte-count table.
pub const TFD_QUEUE_SIZE_BC_DUP: usize = 64;

/// Bytes to allocate for an AX210+ byte-count table.
pub const BC_TABLE_BYTES_AX210: usize =
    TFD_QUEUE_BC_SIZE_AX210 * core::mem::size_of::<BcTblEntry>();

/// Bytes to allocate for a pre-AX210 byte-count table serving a ring
/// of `ring_len` TFDs.
pub const fn bc_table_bytes_pre_ax210(ring_len: usize) -> usize {
    (ring_len + TFD_QUEUE_SIZE_BC_DUP) * core::mem::size_of::<BcTblEntry>()
}

/// Why a queue could not be described to the firmware.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QueueCfgError {
    /// The ring depth is not a power of two.
    NotPowerOfTwo(usize),
    /// The ring depth is outside the 8..=256 the `cb_size` field can
    /// encode.
    DepthOutOfRange(usize),
}

/// Smallest ring the `cb_size` exponent can describe.
pub const MIN_QUEUE_DEPTH: usize = 8;
/// Largest ring the `cb_size` exponent can describe.
pub const MAX_QUEUE_DEPTH: usize = 256;

/// `TFD_QUEUE_CB_SIZE` — encode a ring depth as `log2(depth) - 3`.
///
/// The bias is why 8 TFDs encodes as 0 and 256 as 5. A depth that is
/// not a power of two has no encoding at all, so it is refused rather
/// than rounded: silently serving a 200-slot ring as 128 would leave
/// the firmware and host disagreeing about where the ring wraps.
pub const fn cb_size_for(depth: usize) -> Result<u32, QueueCfgError> {
    if !depth.is_power_of_two() {
        return Err(QueueCfgError::NotPowerOfTwo(depth));
    }
    if depth < MIN_QUEUE_DEPTH || depth > MAX_QUEUE_DEPTH {
        return Err(QueueCfgError::DepthOutOfRange(depth));
    }
    Ok(depth.trailing_zeros() - 3)
}

/// `iwl_tx_queue_cfg_cmd` — asks the firmware to stand up one queue.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxQueueCfgCmd {
    /// Station this queue serves.
    pub sta_id: u8,
    /// Traffic identifier.
    pub tid: u8,
    /// `TX_QUEUE_CFG_*`.
    pub flags: u16,
    /// Ring depth as `log2(depth) - 3`.
    pub cb_size: u32,
    /// Host physical address of the byte-count table.
    pub byte_cnt_addr: u64,
    /// Host physical address of the TFD ring.
    pub tfdq_addr: u64,
}

/// `iwl_tx_queue_cfg_rsp` — which hardware queue the firmware gave us.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxQueueCfgRsp {
    /// Hardware queue number to ring the doorbell for.
    pub queue_number: u16,
    /// Non-zero on failure.
    pub flags: u16,
    /// Initial write pointer the host must adopt.
    pub write_pointer: u16,
    /// Reserved.
    pub reserved: u16,
}

impl TxQueueCfgCmd {
    /// Describe an enabled queue.
    ///
    /// `depth` is the TFD ring depth; both DMA addresses are host
    /// physical. They are taken in the same order the wire struct
    /// carries them — byte-count table, then TFD ring — so that a
    /// call site reads in the same order as the bytes it produces.
    /// Taking them the other way round is an easy transposition to
    /// make and an impossible one to see at the call site, since
    /// both are just addresses.
    pub const fn enable(
        sta_id: u8,
        tid: u8,
        depth: usize,
        byte_cnt_addr: u64,
        tfdq_addr: u64,
    ) -> Result<Self, QueueCfgError> {
        let cb_size = match cb_size_for(depth) {
            Ok(v) => v,
            Err(e) => return Err(e),
        };
        Ok(Self {
            sta_id,
            tid,
            flags: TX_QUEUE_CFG_ENABLE_QUEUE,
            cb_size,
            byte_cnt_addr,
            tfdq_addr,
        })
    }
}
