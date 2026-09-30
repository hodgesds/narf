//! i40e TX/RX rings — descriptor formats, queue contexts, and the
//! data path.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 (GPL-2.0; NARF is GPL-2.0-or-later so adaptation
//! is permitted):
//!
//! - `i40e_type.h` — `struct i40e_tx_desc`,
//!   `union i40e_16byte_rx_desc`, the `I40E_TX_DESC_CMD_*` /
//!   `I40E_TXD_QW1_*` / `I40E_RXD_QW1_*` bit positions.
//! - `i40e_main.c` — `i40e_configure_tx_ring`,
//!   `i40e_configure_rx_ring`, `i40e_control_tx_q`,
//!   `i40e_control_rx_q`.
//! - `i40e_common.c` — `i40e_pre_tx_queue_cfg`.
//!
//! ## Two things that bite
//!
//! **The context `base` is in 128-byte units.** Both
//! `i40e_configure_tx_ring` and `i40e_configure_rx_ring` store
//! `ring->dma / 128`, not the physical address. Writing the raw
//! address into a 57-bit field looks plausible and points the device
//! 128× too far into memory.
//!
//! **RX `dbuff` is in 128-byte units too**, via
//! `I40E_RXQ_CTX_DBUFF_SHIFT`. A 2 KiB buffer is `dbuff = 16`.
//!
//! ## Head writeback
//!
//! TX completion is reported by **head writeback**, not by a
//! per-descriptor done bit: the device DMAs its current head index
//! into a driver-supplied address. Linux puts that address
//! immediately after the ring (`ring->dma + count * sizeof(desc)`)
//! and this does the same, allocating the ring one descriptor longer
//! so the writeback word has somewhere to land. A descriptor is
//! complete once head has advanced past it.

use super::dma_barrier;
use narf_net::{RxMeta, TxMeta};

use narf_bus::MmioRegion;
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

use super::hmc::{
    ctx_field, write_ctx_field, LanHmc, OBJ_SIZE_RXQ, OBJ_SIZE_TXQ, RXQ_CTX_FIELDS, TXQ_CTX_FIELDS,
};
use super::I40eError;

// ── Ring geometry ───────────────────────────────────────────────────

/// Descriptors per ring. The datasheet requires a multiple of 32 and
/// at least 64 (`I40E_MIN_NUM_DESCRIPTORS`,
/// `I40E_REQ_DESCRIPTOR_MULTIPLE`); `qlen` is 13 bits so the ceiling
/// is 8160.
pub const RING_LEN: u16 = 64;
/// Both descriptor formats this driver uses are 16 bytes: the TX data
/// descriptor, and the RX descriptor with `dsize = 0`.
pub const DESC_BYTES: u64 = 16;
/// Ring bytes, plus one descriptor's worth of slack for the TX
/// head-writeback word.
pub const RING_BYTES: u64 = RING_LEN as u64 * DESC_BYTES + DESC_BYTES;
/// RX buffer size per descriptor.
pub const RX_BUF_BYTES: usize = 2048;
/// Largest frame the RX queue accepts.
pub const RX_MAX_FRAME: u16 = 1522;
/// `I40E_RXQ_CTX_DBUFF_SHIFT` — `dbuff` counts 128-byte units.
pub const RXQ_CTX_DBUFF_SHIFT: u32 = 7;

/// Initial `QRX_TAIL`.
///
/// The device owns the descriptors in `[head, tail)`, so `tail` names
/// the first slot it may **not** touch. With `head` at 0 after reset,
/// handing over every descriptor would need `tail == RING_LEN`, which
/// is not a legal index — and `tail == head` reads as an empty ring,
/// not a full one. So one slot is always held back, exactly as
/// Linux's `i40e_alloc_rx_buffers` does by arming
/// `I40E_DESC_UNUSED()` = `count - 1` descriptors and leaving
/// `next_to_use` (and therefore the tail) at `count - 1`.
pub const RX_TAIL_INIT: u16 = RING_LEN - 1;
/// The context `base` field counts 128-byte units.
pub const CTX_BASE_UNIT: u64 = 128;

// ── TX descriptor (i40e_type.h) ─────────────────────────────────────

/// `I40E_TXD_QW1_DTYPE` occupies the low 4 bits of qword 1.
pub const TXD_QW1_DTYPE_SHIFT: u32 = 0;
/// `I40E_TX_DESC_DTYPE_DATA`.
pub const TX_DESC_DTYPE_DATA: u64 = 0x0;
/// `I40E_TX_DESC_DTYPE_DESC_DONE`.
pub const TX_DESC_DTYPE_DESC_DONE: u64 = 0xF;
/// `I40E_TXD_QW1_CMD_SHIFT`.
pub const TXD_QW1_CMD_SHIFT: u32 = 4;
/// `I40E_TXD_QW1_OFFSET_SHIFT`.
pub const TXD_QW1_OFFSET_SHIFT: u32 = 16;
/// `I40E_TXD_QW1_TX_BUF_SZ_SHIFT`.
pub const TXD_QW1_TX_BUF_SZ_SHIFT: u32 = 34;
/// `I40E_TXD_QW1_L2TAG1_SHIFT`.
pub const TXD_QW1_L2TAG1_SHIFT: u32 = 48;

/// `I40E_TX_DESC_CMD_EOP` — end of packet.
pub const TX_DESC_CMD_EOP: u64 = 0x0001;
/// `I40E_TX_DESC_CMD_RS` — report status.
pub const TX_DESC_CMD_RS: u64 = 0x0002;
/// `I40E_TX_DESC_CMD_ICRC` — insert CRC.
pub const TX_DESC_CMD_ICRC: u64 = 0x0004;

/// Build a single-buffer TX data descriptor.
///
/// Returns `(buffer_addr, cmd_type_offset_bsz)`, both little-endian
/// qwords.
pub const fn build_tx_desc(phys: u64, len: u16) -> (u64, u64) {
    let cmd = TX_DESC_CMD_EOP | TX_DESC_CMD_RS | TX_DESC_CMD_ICRC;
    let qw1 = (TX_DESC_DTYPE_DATA << TXD_QW1_DTYPE_SHIFT)
        | (cmd << TXD_QW1_CMD_SHIFT)
        | ((len as u64) << TXD_QW1_TX_BUF_SZ_SHIFT);
    (phys, qw1)
}

// ── RX descriptor (i40e_type.h) ─────────────────────────────────────

/// `I40E_RX_DESC_STATUS_DD_SHIFT` — descriptor done.
pub const RX_DESC_STATUS_DD_SHIFT: u32 = 0;
/// `I40E_RX_DESC_STATUS_EOF_SHIFT` — end of frame.
pub const RX_DESC_STATUS_EOF_SHIFT: u32 = 1;
/// `I40E_RXD_QW1_STATUS_SHIFT`.
pub const RXD_QW1_STATUS_SHIFT: u32 = 0;
/// `I40E_RXD_QW1_ERROR_SHIFT`.
pub const RXD_QW1_ERROR_SHIFT: u32 = 19;
/// `I40E_RXD_QW1_ERROR_MASK`, after shifting down.
pub const RXD_QW1_ERROR_MASK: u64 = 0xFF;
/// `I40E_RXD_QW1_LENGTH_PBUF_SHIFT`.
pub const RXD_QW1_LENGTH_PBUF_SHIFT: u32 = 38;
/// `I40E_RXD_QW1_LENGTH_PBUF_MASK`, after shifting down.
pub const RXD_QW1_LENGTH_PBUF_MASK: u64 = 0x3FFF;

/// `true` when firmware has written this descriptor back.
pub const fn rx_desc_done(status_error_len: u64) -> bool {
    (status_error_len >> RXD_QW1_STATUS_SHIFT) & (1 << RX_DESC_STATUS_DD_SHIFT) != 0
}

/// `true` when this descriptor holds the end of a frame.
pub const fn rx_desc_eof(status_error_len: u64) -> bool {
    (status_error_len >> RXD_QW1_STATUS_SHIFT) & (1 << RX_DESC_STATUS_EOF_SHIFT) != 0
}

/// Payload length from an RX writeback.
pub const fn rx_desc_len(status_error_len: u64) -> u16 {
    ((status_error_len >> RXD_QW1_LENGTH_PBUF_SHIFT) & RXD_QW1_LENGTH_PBUF_MASK) as u16
}

/// Raw RX error bits. Frame/parser errors require a drop; checksum errors
/// clear verification metadata so software can decide whether to accept.
pub const fn rx_desc_errors(status_error_len: u64) -> u8 {
    ((status_error_len >> RXD_QW1_ERROR_SHIFT) & RXD_QW1_ERROR_MASK) as u8
}

// ── Queue registers (i40e_register.h) ───────────────────────────────

/// `I40E_QTX_ENA(q)`.
pub const fn reg_qtx_ena(q: u16) -> u64 {
    0x0010_0000 + (q as u64) * 4
}
/// `I40E_QTX_TAIL(q)`.
pub const fn reg_qtx_tail(q: u16) -> u64 {
    0x0010_8000 + (q as u64) * 4
}
/// `I40E_QTX_HEAD(q)`.
pub const fn reg_qtx_head(q: u16) -> u64 {
    0x000E_4000 + (q as u64) * 4
}
/// `I40E_QTX_CTL(q)`.
pub const fn reg_qtx_ctl(q: u16) -> u64 {
    0x0010_4000 + (q as u64) * 4
}
/// `I40E_QRX_ENA(q)`.
pub const fn reg_qrx_ena(q: u16) -> u64 {
    0x0012_0000 + (q as u64) * 4
}
/// `I40E_QRX_TAIL(q)`.
pub const fn reg_qrx_tail(q: u16) -> u64 {
    0x0012_8000 + (q as u64) * 4
}
/// `I40E_GLLAN_TXPRE_QDIS(block)`.
pub const fn reg_gllan_txpre_qdis(block: u32) -> u64 {
    0x000E_6500 + (block as u64) * 4
}
/// `I40E_PFLAN_QALLOC`.
pub const REG_PFLAN_QALLOC: u64 = 0x001C_0400;

/// `QENA_REQ` — the driver's request bit.
pub const QENA_REQ: u32 = 1 << 0;
/// `QENA_STAT` — the device's acknowledgement bit. Note it is bit
/// **2**, not bit 1: polling the wrong bit makes every enable look
/// like it timed out.
pub const QENA_STAT: u32 = 1 << 2;

/// `I40E_QTX_CTL_PF_QUEUE` — this queue belongs to a PF.
pub const QTX_CTL_PF_QUEUE: u32 = 0x2;
/// `I40E_QTX_CTL_PF_INDX_SHIFT`.
pub const QTX_CTL_PF_INDX_SHIFT: u32 = 2;
/// `I40E_QTX_CTL_PF_INDX_MASK`, before shifting.
pub const QTX_CTL_PF_INDX_MASK: u32 = 0xF;

/// `GLLAN_TXPRE_QDIS_QINDX_MASK`.
pub const TXPRE_QDIS_QINDX_MASK: u32 = 0x7FF;
/// `GLLAN_TXPRE_QDIS_SET_QDIS`.
pub const TXPRE_QDIS_SET_QDIS: u32 = 1 << 30;
/// `GLLAN_TXPRE_QDIS_CLEAR_QDIS`.
pub const TXPRE_QDIS_CLEAR_QDIS: u32 = 1 << 31;

/// `PFLAN_QALLOC_FIRSTQ_MASK`.
pub const PFLAN_QALLOC_FIRSTQ_MASK: u32 = 0x7FF;
/// `PFLAN_QALLOC_LASTQ_SHIFT`.
pub const PFLAN_QALLOC_LASTQ_SHIFT: u32 = 16;

/// Decode `PFLAN_QALLOC` into the PF's `(first, last)` absolute queue
/// indices, inclusive.
pub const fn decode_qalloc(qalloc: u32) -> (u16, u16) {
    (
        (qalloc & PFLAN_QALLOC_FIRSTQ_MASK) as u16,
        ((qalloc >> PFLAN_QALLOC_LASTQ_SHIFT) & PFLAN_QALLOC_FIRSTQ_MASK) as u16,
    )
}

/// Budget for `QENA_STAT` to follow `QENA_REQ`. Linux polls 50 times
/// at ~1 ms (`I40E_QTX_ENA_WAIT_COUNT`).
pub const QUEUE_ENA_TIMEOUT_MS: u64 = 60;

// ── Queue contexts ──────────────────────────────────────────────────

/// Everything needed to pack a TX queue context.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxQueueContext {
    /// Ring physical base, in bytes. Packed as `/ 128`.
    pub ring_phys: u64,
    /// Descriptors in the ring.
    pub qlen: u16,
    /// Head-writeback target, in bytes. Packed whole.
    pub head_wb_phys: u64,
    /// `qs_handle[tc]` from the VSI context — the arbitration queue
    /// set the scheduler services this queue from.
    pub rdylist: u16,
}

/// Pack a TX queue context into its 128 bytes.
pub fn pack_tx_context(cfg: TxQueueContext) -> [u8; OBJ_SIZE_TXQ as usize] {
    let mut ctx = [0u8; OBJ_SIZE_TXQ as usize];
    let set = |ctx: &mut [u8], name: &str, v: u64| {
        if let Some(f) = ctx_field(TXQ_CTX_FIELDS, name) {
            write_ctx_field(ctx, f, v);
        }
    };
    // `new_context = 1` tells firmware this is a fresh context rather
    // than a resumed one.
    set(&mut ctx, "new_context", 1);
    set(&mut ctx, "base", cfg.ring_phys / CTX_BASE_UNIT);
    set(&mut ctx, "qlen", cfg.qlen as u64);
    set(&mut ctx, "head_wb_ena", 1);
    set(&mut ctx, "head_wb_addr", cfg.head_wb_phys);
    set(&mut ctx, "rdylist", cfg.rdylist as u64);
    set(&mut ctx, "rdylist_act", 0);
    ctx
}

/// Everything needed to pack an RX queue context.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxQueueContext {
    /// Ring physical base, in bytes. Packed as `/ 128`.
    pub ring_phys: u64,
    /// Descriptors in the ring.
    pub qlen: u16,
    /// Per-descriptor data buffer size, in bytes. Packed as `/ 128`.
    pub buf_bytes: u16,
    /// Largest frame to accept.
    pub max_frame: u16,
}

/// Pack an RX queue context into its 32 bytes.
pub fn pack_rx_context(cfg: RxQueueContext) -> [u8; OBJ_SIZE_RXQ as usize] {
    let mut ctx = [0u8; OBJ_SIZE_RXQ as usize];
    let set = |ctx: &mut [u8], name: &str, v: u64| {
        if let Some(f) = ctx_field(RXQ_CTX_FIELDS, name) {
            write_ctx_field(ctx, f, v);
        }
    };
    set(&mut ctx, "base", cfg.ring_phys / CTX_BASE_UNIT);
    set(&mut ctx, "qlen", cfg.qlen as u64);
    set(
        &mut ctx,
        "dbuff",
        (cfg.buf_bytes as u64) >> RXQ_CTX_DBUFF_SHIFT,
    );
    // hbuff stays 0: header split is off, so there is no header
    // buffer to size.
    // dtype 0 = no header split; dsize 0 = 16-byte descriptors.
    set(&mut ctx, "crcstrip", 1);
    set(&mut ctx, "l2tsel", 1);
    set(&mut ctx, "rxmax", cfg.max_frame as u64);
    // The datasheet requires lrxqthresh >= 1 on every stepping past
    // A0, and prefena set at init.
    set(&mut ctx, "lrxqthresh", 1);
    set(&mut ctx, "prefena", 1);
    ctx
}

// ── Live rings ──────────────────────────────────────────────────────

/// A configured and enabled TX/RX queue pair.
#[derive(Debug)]
pub struct QueuePair {
    /// PF-relative queue index.
    pub pf_q: u16,
    tx_ring: DmaBuffer,
    tx_bufs: alloc::vec::Vec<Option<DmaBuffer>>,
    tx_clean: u16,
    tx_completed: u64,
    /// Next TX descriptor to fill.
    tx_next: u16,
    rx_ring: DmaBuffer,
    rx_bufs: alloc::vec::Vec<DmaBuffer>,
    /// Next RX descriptor to inspect.
    rx_next: u16,
    rx_discard: bool,
}

impl QueuePair {
    /// Allocate both rings and their buffers.
    pub fn alloc(pf_q: u16) -> Result<Self, I40eError> {
        let tx_ring = alloc_coherent(RING_BYTES as usize, DomainId::DRIVER_0)
            .map_err(|_| I40eError::NoMemory)?;
        let rx_ring = alloc_coherent(RING_BYTES as usize, DomainId::DRIVER_0)
            .map_err(|_| I40eError::NoMemory)?;
        // The context `base` is stored in 128-byte units, so a ring
        // that is not 128-byte aligned cannot be described at all.
        if tx_ring.dma_addr().raw() % CTX_BASE_UNIT != 0
            || rx_ring.dma_addr().raw() % CTX_BASE_UNIT != 0
        {
            return Err(I40eError::NoMemory);
        }

        let mut tx_bufs = alloc::vec::Vec::with_capacity(RING_LEN as usize);
        let mut rx_bufs = alloc::vec::Vec::with_capacity(RING_LEN as usize);
        for _ in 0..RING_LEN {
            tx_bufs.push(None);
            rx_bufs.push(
                alloc_coherent(RX_BUF_BYTES, DomainId::DRIVER_0)
                    .map_err(|_| I40eError::NoMemory)?,
            );
        }

        let pair = Self {
            pf_q,
            tx_ring,
            tx_bufs,
            tx_next: 0,
            tx_clean: 0,
            tx_completed: 0,
            rx_ring,
            rx_bufs,
            rx_next: 0,
            rx_discard: false,
        };
        pair.zero_rings();
        pair.arm_rx_descriptors();
        Ok(pair)
    }

    fn zero_rings(&self) {
        for i in 0..RING_BYTES {
            // SAFETY: both rings are identity-mapped DMA buffers of
            // `RING_BYTES` and `i < RING_BYTES`.
            unsafe {
                core::ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at::<u8>(i), 0);
                core::ptr::write_volatile(self.rx_ring.cpu_mut_ptr_at::<u8>(i), 0);
            }
        }
    }

    /// Point every RX descriptor at its buffer. In the read format a
    /// descriptor is just `(pkt_addr, hdr_addr)`; `hdr_addr` stays 0
    /// because header split is off.
    fn arm_rx_descriptors(&self) {
        for i in 0..RING_LEN {
            let phys = self.rx_bufs[i as usize].dma_addr().raw();
            let off = i as u64 * DESC_BYTES;
            // SAFETY: `off + 16 <= RING_BYTES`; the ring is an
            // identity-mapped DMA buffer.
            unsafe {
                core::ptr::write_volatile(self.rx_ring.cpu_mut_ptr_at::<u64>(off), phys);
                core::ptr::write_volatile(self.rx_ring.cpu_mut_ptr_at::<u64>(off + 8), 0);
            }
        }
    }

    /// Physical base of the TX ring.
    pub fn tx_ring_phys(&self) -> u64 {
        self.tx_ring.dma_addr().raw()
    }

    /// Physical base of the RX ring.
    pub fn rx_ring_phys(&self) -> u64 {
        self.rx_ring.dma_addr().raw()
    }

    /// Head-writeback address: the slot just past the last
    /// descriptor, which is why the ring is allocated one descriptor
    /// longer than `RING_LEN`.
    pub fn tx_head_wb_phys(&self) -> u64 {
        self.tx_ring.dma_addr().raw() + RING_LEN as u64 * DESC_BYTES
    }

    /// Read the head index the device wrote back.
    pub fn tx_head(&self) -> u32 {
        let off = RING_LEN as u64 * DESC_BYTES;
        // SAFETY: the writeback slot is inside the ring allocation.
        unsafe { core::ptr::read_volatile(self.tx_ring.cpu_ptr_at::<u32>(off)) }
    }

    /// Install both queue contexts into the HMC and associate the TX
    /// queue with this PF.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0.
    pub unsafe fn configure(
        &self,
        csr: &MmioRegion,
        hmc: &LanHmc,
        queue_index: u32,
        pf_id: u8,
        rdylist: u16,
    ) -> Result<(), I40eError> {
        let tx_ctx = pack_tx_context(TxQueueContext {
            ring_phys: self.tx_ring_phys(),
            qlen: RING_LEN,
            head_wb_phys: self.tx_head_wb_phys(),
            rdylist,
        });
        hmc.set_tx_context(queue_index, &tx_ctx)?;

        let rx_ctx = pack_rx_context(RxQueueContext {
            ring_phys: self.rx_ring_phys(),
            qlen: RING_LEN,
            buf_bytes: RX_BUF_BYTES as u16,
            max_frame: RX_MAX_FRAME,
        });
        hmc.set_rx_context(queue_index, &rx_ctx)?;

        // `i40e_configure_tx_ring`'s tail: associate the queue with
        // this PCI function.
        let qtx_ctl =
            QTX_CTL_PF_QUEUE | ((pf_id as u32 & QTX_CTL_PF_INDX_MASK) << QTX_CTL_PF_INDX_SHIFT);
        // SAFETY: caller-asserted mapped CSR window.
        unsafe {
            csr.write32(reg_qtx_ctl(self.pf_q), qtx_ctl);
            // Clear both tails before the queues are enabled.
            csr.write32(reg_qtx_tail(self.pf_q), 0);
            csr.write32(reg_qrx_tail(self.pf_q), 0);
        }
        dma_barrier();
        Ok(())
    }

    /// Enable both queues and wait for the device to acknowledge.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0.
    pub unsafe fn enable(&self, csr: &MmioRegion, base_queue: u16) -> Result<(), I40eError> {
        // SAFETY: caller-asserted mapped CSR window.
        unsafe {
            pre_tx_queue_cfg(csr, base_queue, self.pf_q, true);
            // Let any enable/disable already in flight finish before
            // asking for a new state — a REQ written while STAT is
            // still catching up is lost.
            wait_queue_settled(csr, reg_qtx_ena(self.pf_q));
            csr.write32(reg_qtx_head(self.pf_q), 0);
            set_queue_enable(csr, reg_qtx_ena(self.pf_q), true)?;
            wait_queue_state(csr, reg_qtx_ena(self.pf_q), true)
                .map_err(|_| I40eError::TxQueueEnableTimeout)?;

            wait_queue_settled(csr, reg_qrx_ena(self.pf_q));
            set_queue_enable(csr, reg_qrx_ena(self.pf_q), true)?;
            wait_queue_state(csr, reg_qrx_ena(self.pf_q), true)
                .map_err(|_| I40eError::RxQueueEnableTimeout)?;

            // Hand the device the RX ring, less the one slot that
            // keeps a full ring distinguishable from an empty one.
            csr.write32(reg_qrx_tail(self.pf_q), RX_TAIL_INIT as u32);
        }
        dma_barrier();
        Ok(())
    }

    /// Disable both queues. Errors are swallowed — this runs on the
    /// teardown path where there is nothing useful to do with them.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0.
    pub unsafe fn disable(&self, csr: &MmioRegion, base_queue: u16) {
        // SAFETY: caller-asserted mapped CSR window.
        unsafe {
            wait_queue_settled(csr, reg_qrx_ena(self.pf_q));
            let _ = set_queue_enable(csr, reg_qrx_ena(self.pf_q), false);
            let _ = wait_queue_state(csr, reg_qrx_ena(self.pf_q), false);
            pre_tx_queue_cfg(csr, base_queue, self.pf_q, false);
            wait_queue_settled(csr, reg_qtx_ena(self.pf_q));
            let _ = set_queue_enable(csr, reg_qtx_ena(self.pf_q), false);
            let _ = wait_queue_state(csr, reg_qtx_ena(self.pf_q), false);
        }
    }

    /// Reclaim only a validated prefix of the submitted descriptors. Packet
    /// buffers sit on EOP slots, so a partial head advance cannot release them.
    pub fn reclaim(&mut self) -> Result<(), I40eError> {
        let head = self.tx_head();
        dma_barrier();
        let outstanding = (self.tx_next + RING_LEN - self.tx_clean) % RING_LEN;
        if head >= RING_LEN as u32 {
            return Err(I40eError::InvalidTxHead);
        }
        let completed = (head as u16 + RING_LEN - self.tx_clean) % RING_LEN;
        if completed > outstanding {
            return Err(I40eError::InvalidTxHead);
        }
        while self.tx_clean != head as u16 {
            self.tx_bufs[self.tx_clean as usize].take();
            self.tx_clean = (self.tx_clean + 1) % RING_LEN;
            self.tx_completed = self.tx_completed.wrapping_add(1);
        }
        Ok(())
    }

    /// Monotonic progress avoids mistaking a full lap for a stalled head.
    pub fn tx_progress(&self) -> u64 {
        self.tx_completed
    }

    pub fn tx_pending(&self) -> bool {
        self.tx_clean != self.tx_next
    }

    /// Publish a whole packet atomically, including a TSO context when needed.
    /// Success transfers a private DMA copy to the ring until EOP completes.
    /// No waiting occurs under the queue lock.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0 with this queue enabled.
    pub unsafe fn submit(
        &mut self,
        csr: &MmioRegion,
        frame: &[u8],
        meta: TxMeta,
    ) -> Result<(), I40eError> {
        let plan = super::offload::TxPlan::parse(frame, meta)?;
        self.reclaim()?;
        // 4-KiB chunks stay within i40e's 16-KiB buffer limit and DMA read
        // boundary restrictions. The entire header is in the first chunk.
        let count = frame.len().div_ceil(4096) + usize::from(plan.context.is_some());
        let free = (self.tx_clean + RING_LEN - self.tx_next - 1) % RING_LEN;
        if count > free as usize {
            return Err(I40eError::TxRingFull);
        }
        let mut buffer =
            alloc_coherent(frame.len(), DomainId::DRIVER_0).map_err(|_| I40eError::NoMemory)?;
        buffer.as_mut_slice()[..frame.len()].copy_from_slice(frame);
        plan.prepare(&mut buffer.as_mut_slice()[..frame.len()]);
        let mut slot = self.tx_next;
        if let Some((word0, word1)) = plan.context {
            self.write_tx(slot, word0, word1);
            slot = (slot + 1) % RING_LEN;
        }
        let mut offset = 0;
        while offset < frame.len() {
            let len = (frame.len() - offset).min(4096);
            let last = offset + len == frame.len();
            let command = plan.command
                | TX_DESC_CMD_ICRC
                | if last {
                    TX_DESC_CMD_EOP | TX_DESC_CMD_RS
                } else {
                    0
                };
            let qw1 = (command << TXD_QW1_CMD_SHIFT)
                | (plan.offset << TXD_QW1_OFFSET_SHIFT)
                | ((len as u64) << TXD_QW1_TX_BUF_SZ_SHIFT);
            self.write_tx(slot, buffer.dma_addr().raw() + offset as u64, qw1);
            if last {
                self.tx_bufs[slot as usize] = Some(buffer);
                break;
            }
            slot = (slot + 1) % RING_LEN;
            offset += len;
        }
        self.tx_next = (slot + 1) % RING_LEN;
        dma_barrier();
        // SAFETY: caller owns the enabled queue; all referenced buffers are
        // retained in tx_bufs before the device is allowed to fetch.
        unsafe { csr.write32(reg_qtx_tail(self.pf_q), self.tx_next as u32) };
        Ok(())
    }

    fn write_tx(&self, slot: u16, word0: u64, word1: u64) {
        let off = slot as u64 * DESC_BYTES;
        // SAFETY: slot is reduced modulo RING_LEN at every transition.
        unsafe {
            core::ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at::<u64>(off), word0.to_le());
            core::ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at::<u64>(off + 8), word1.to_le());
        }
    }

    /// Compatibility entry point; returns after submission, not wire completion.
    /// # Safety
    /// Same queue ownership requirements as `submit`.
    pub unsafe fn transmit(&mut self, csr: &MmioRegion, frame: &[u8]) -> Result<(), I40eError> {
        // SAFETY: forwarded from caller.
        unsafe { self.submit(csr, frame, TxMeta::plain()) }
    }

    /// Pop one received frame, if any.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0.
    pub unsafe fn receive_with_meta(
        &mut self,
        csr: &MmioRegion,
    ) -> Option<Option<(alloc::vec::Vec<u8>, RxMeta)>> {
        let slot = self.rx_next;
        let off = slot as u64 * DESC_BYTES;
        // SAFETY: `off + 16 <= RING_BYTES`; in the writeback format
        // qword 1 holds status/error/length.
        let status = unsafe { core::ptr::read_volatile(self.rx_ring.cpu_ptr_at::<u64>(off + 8)) };
        if !rx_desc_done(status) {
            return None;
        }

        dma_barrier();
        let len = rx_desc_len(status) as usize;
        let errors = rx_desc_errors(status);
        // Reject every fragment of an unsupported multi-buffer packet, including
        // its final EOF descriptor. Checksum failures still go to software.
        let discard = self.rx_discard || !rx_desc_eof(status);
        self.rx_discard = !rx_desc_eof(status);
        let payload = if !discard && errors & 0x07 == 0 && len > 0 && len <= RX_MAX_FRAME as usize {
            let mut packet = alloc::vec![0u8; len];
            for (i, byte) in packet.iter_mut().enumerate() {
                // SAFETY: DD plus DMA barrier makes the completed RX buffer CPU-owned.
                *byte = unsafe {
                    core::ptr::read_volatile(self.rx_bufs[slot as usize].cpu_ptr_at::<u8>(i as u64))
                };
            }
            Some((packet, super::offload::rx_metadata(status)))
        } else {
            None
        };

        // Re-arm: back to the read format, pointing at the same
        // buffer.
        let phys = self.rx_bufs[slot as usize].dma_addr().raw();
        // SAFETY: as above.
        unsafe {
            core::ptr::write_volatile(self.rx_ring.cpu_mut_ptr_at::<u64>(off), phys);
            core::ptr::write_volatile(self.rx_ring.cpu_mut_ptr_at::<u64>(off + 8), 0);
        }
        dma_barrier();

        self.rx_next = (slot + 1) % RING_LEN;
        // The re-armed slot becomes the new held-back one: publishing
        // `tail = slot` gives the device everything from its current
        // head up to (but not including) this slot, which is the same
        // one-slot gap the ring started with.
        // SAFETY: caller-asserted mapped CSR window.
        unsafe { csr.write32(reg_qrx_tail(self.pf_q), slot as u32) };
        dma_barrier();

        Some(payload)
    }

    /// Compatibility helper that discards RX checksum metadata.
    /// # Safety
    /// Same requirements as `receive_with_meta`.
    pub unsafe fn receive(&mut self, csr: &MmioRegion) -> Option<alloc::vec::Vec<u8>> {
        // SAFETY: forwarded from caller.
        unsafe { self.receive_with_meta(csr) }
            .flatten()
            .map(|(packet, _)| packet)
    }
}

/// `i40e_pre_tx_queue_cfg` — tell the TX unit a queue is about to be
/// enabled or disabled.
///
/// The register is indexed by *absolute* queue number, which is the
/// PF's base queue plus the relative index, and the block is that
/// number divided by 128.
///
/// # Safety
/// `csr` must be this PF's mapped BAR0.
pub unsafe fn pre_tx_queue_cfg(csr: &MmioRegion, base_queue: u16, pf_q: u16, enable: bool) {
    let abs = base_queue as u32 + pf_q as u32;
    let block = abs / 128;
    let index = abs % 128;
    // SAFETY: caller-asserted mapped CSR window.
    let mut val = unsafe { csr.read32(reg_gllan_txpre_qdis(block)) };
    val &= !TXPRE_QDIS_QINDX_MASK;
    val |= index & TXPRE_QDIS_QINDX_MASK;
    val |= if enable {
        TXPRE_QDIS_CLEAR_QDIS
    } else {
        TXPRE_QDIS_SET_QDIS
    };
    // SAFETY: same.
    unsafe { csr.write32(reg_gllan_txpre_qdis(block), val) };
}

/// Set or clear a queue's `QENA_REQ` bit, preserving the rest.
///
/// # Safety
/// `csr` must be this PF's mapped BAR0 and `reg` a queue-enable
/// register offset within it.
unsafe fn set_queue_enable(csr: &MmioRegion, reg: u64, enable: bool) -> Result<(), I40eError> {
    // SAFETY: caller-asserted.
    let mut val = unsafe { csr.read32(reg) };
    if enable {
        val |= QENA_REQ;
    } else {
        val &= !QENA_REQ;
    }
    // SAFETY: same.
    unsafe { csr.write32(reg, val) };
    dma_barrier();
    Ok(())
}

/// Wait for `QENA_STAT` to catch up with whatever `QENA_REQ` already
/// holds, so a fresh request is not written over an in-flight one.
///
/// The result is deliberately discarded: Linux's loop also falls
/// through on timeout and lets the subsequent state wait report the
/// real failure, which names the queue direction.
///
/// # Safety
/// As [`set_queue_enable`].
unsafe fn wait_queue_settled(csr: &MmioRegion, reg: u64) {
    let _ = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller-asserted.
            let v = unsafe { csr.read32(reg) };
            ((v & QENA_REQ) != 0) == ((v & QENA_STAT) != 0)
        },
        narf_time::Deadline::after_ms(QUEUE_ENA_TIMEOUT_MS),
    );
}

/// Wait for `QENA_STAT` to match the requested state.
///
/// # Safety
/// As [`set_queue_enable`].
unsafe fn wait_queue_state(csr: &MmioRegion, reg: u64, enabled: bool) -> Result<(), ()> {
    let ok = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller-asserted.
            let v = unsafe { csr.read32(reg) };
            (v & QENA_STAT != 0) == enabled
        },
        narf_time::Deadline::after_ms(QUEUE_ENA_TIMEOUT_MS),
    );
    if ok {
        Ok(())
    } else {
        Err(())
    }
}

mod runtime_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn fake_csr() -> (DmaBuffer, MmioRegion) {
        let mut memory = alloc_coherent(0x130000, DomainId::DRIVER_0).unwrap();
        memory.as_mut_slice().fill(0);
        let csr = MmioRegion {
            phys: memory.phys_addr(),
            virt: memory.as_mut_ptr() as u64,
            len: memory.len() as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        (memory, csr)
    }
    fn complete(queue: &QueuePair, head: u32) {
        // SAFETY: simulated device writes only the dedicated head-writeback word.
        unsafe {
            core::ptr::write_volatile(
                queue
                    .tx_ring
                    .cpu_mut_ptr_at::<u32>(RING_LEN as u64 * DESC_BYTES),
                head,
            );
        }
    }
    fn descriptor(queue: &QueuePair, slot: u16) -> (u64, u64) {
        // SAFETY: test slot bounded by RING_LEN.
        unsafe {
            (
                core::ptr::read_volatile(queue.tx_ring.cpu_ptr_at::<u64>(slot as u64 * DESC_BYTES)),
                core::ptr::read_volatile(
                    queue
                        .tx_ring
                        .cpu_ptr_at::<u64>(slot as u64 * DESC_BYTES + 8),
                ),
            )
        }
    }

    fn smoke_i40e_tso_wrap_and_dma_ownership() -> TestResult {
        let (_memory, csr) = fake_csr();
        let mut queue = QueuePair::alloc(0).unwrap();
        let small = super::super::tests::tcp_packet(false, 0);
        for index in 0..62 {
            // SAFETY: MMIO and DMA are backed by test-owned memory, no live device.
            unsafe {
                queue.submit(&csr, &small, TxMeta::plain()).unwrap();
            }
            complete(&queue, index + 1);
            queue.reclaim().unwrap();
        }
        let packet = super::super::tests::tcp_packet(false, 9000);
        // SAFETY: test-owned simulated queue.
        unsafe {
            queue.submit(&csr, &packet, TxMeta::with_tso(1460)).unwrap();
        }
        if queue.tx_next != 2
            || descriptor(&queue, 62).1 & 15 != 1
            || descriptor(&queue, 63).1 >> 34 & 0x3fff != 4096
            || descriptor(&queue, 0).1 >> 34 & 0x3fff != 4096
            || descriptor(&queue, 1).1 >> 34 & 0x3fff != 862
            || descriptor(&queue, 63).1 & (3 << 4) != 0
            || descriptor(&queue, 1).1 & (3 << 4) != 3 << 4
        {
            return TestResult::Fail("wrapped TSO context/data/EOP descriptor sequence wrong");
        }
        if queue.tx_bufs[1].is_none() {
            return TestResult::Fail("EOP does not own DMA buffer");
        }
        complete(&queue, 1);
        queue.reclaim().unwrap();
        if queue.tx_bufs[1].is_none() {
            return TestResult::Fail("partial completion freed packet DMA");
        }
        complete(&queue, 2);
        queue.reclaim().unwrap();
        if queue.tx_pending()
            || queue.tx_progress() != 66
            || queue.tx_bufs.iter().any(Option::is_some)
        {
            return TestResult::Fail("completed packet leaked ring credits/DMA ownership");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_tso_wrap_and_dma_ownership);

    fn smoke_i40e_tx_credit_and_bad_head() -> TestResult {
        let (_memory, csr) = fake_csr();
        let mut queue = QueuePair::alloc(0).unwrap();
        let packet = super::super::tests::tcp_packet(false, 10);
        for _ in 0..RING_LEN - 1 {
            // SAFETY: test-owned simulated MMIO and descriptors.
            unsafe {
                queue.submit(&csr, &packet, TxMeta::plain()).unwrap();
            }
        }
        let saved = descriptor(&queue, 63);
        // SAFETY: test-owned simulated queue.
        if unsafe { queue.submit(&csr, &packet, TxMeta::plain()) } != Err(I40eError::TxRingFull)
            || queue.tx_next != 63
            || descriptor(&queue, 63) != saved
        {
            return TestResult::Fail("full ring modified descriptors/tail");
        }
        complete(&queue, 64);
        if queue.reclaim() != Err(I40eError::InvalidTxHead)
            || queue.tx_bufs.iter().filter(|slot| slot.is_some()).count() != 63
        {
            return TestResult::Fail("out-of-bounds head released DMA buffers");
        }
        complete(&queue, 63);
        queue.reclaim().unwrap();
        complete(&queue, 0);
        if queue.reclaim() != Err(I40eError::InvalidTxHead) {
            return TestResult::Fail("head beyond submitted interval accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_tx_credit_and_bad_head);

    fn smoke_i40e_rx_fragment_discard_and_metadata() -> TestResult {
        let (_memory, csr) = fake_csr();
        let mut queue = QueuePair::alloc(0).unwrap();
        for slot in 0..3u16 {
            let status = 1 | if slot == 0 { 0 } else { 2 } | (1 << 3) | (26 << 30) | (64u64 << 38);
            // SAFETY: simulated device completes these RX slots in order.
            unsafe {
                core::ptr::write_volatile(
                    queue
                        .rx_ring
                        .cpu_mut_ptr_at::<u64>(slot as u64 * DESC_BYTES + 8),
                    status,
                );
            }
        }
        // SAFETY: all descriptor/buffer pointers belong to the simulated queue.
        unsafe {
            if queue.receive_with_meta(&csr) != Some(None)
                || queue.receive_with_meta(&csr) != Some(None)
            {
                return TestResult::Fail("multi-buffer packet leaked a fragment");
            }
            match queue.receive_with_meta(&csr) {
                Some(Some((bytes, meta))) if bytes.len() == 64 && meta.csum_l3 && meta.csum_l4 => {}
                _ => return TestResult::Fail("valid RX lost payload/checksum metadata"),
            }
            if queue.receive_with_meta(&csr).is_some() || csr.read32(reg_qrx_tail(0)) != 2 {
                return TestResult::Fail("RX drain/rearm did not preserve held-back slot");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/i40e",
        smoke_i40e_rx_fragment_discard_and_metadata
    );
}
