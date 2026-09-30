//! Intel PCIe Bluetooth DMA rings — the HCI transport.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 `drivers/bluetooth/btintel_pcie.{c,h}` (GPL-2.0;
//! NARF is GPL-2.0-or-later so adaptation is permitted):
//! `struct ctx_info`, `tfd`, `urbd0`, `frbd`, `urbd1`, `rfh_hdr`,
//! `btintel_pcie_alloc`, `btintel_pcie_init_ci`,
//! `btintel_pcie_prepare_tx` / `_rx`, `btintel_pcie_send_sync`,
//! `btintel_pcie_submit_rx`, `btintel_pcie_msix_rx_handle`,
//! `btintel_pcie_submit_rx_work`.
//!
//! ## Shape of the interface
//!
//! There is no register-level HCI port. The host publishes a
//! **context information** block — 38 dwords the device DMAs once at
//! `MAC_INIT` — that names every ring, and from then on the two
//! sides pass buffers:
//!
//! - **TX**: a `tfd` (transfer descriptor) names a buffer; the
//!   device retires it by writing a `urbd0` completion.
//! - **RX**: the host posts an `frbd` (free-buffer descriptor); the
//!   device fills the buffer and writes a `urbd1` naming which one.
//!
//! Progress on all four is tracked in **index arrays** in host
//! memory, not registers: `tr_hia` / `tr_tia` for the transfer rings
//! and `cr_hia` / `cr_tia` for the completion rings, each indexed by
//! queue number. The driver advances the `hia` halves and the device
//! advances the `tia` halves, so a ring is empty when the two agree.
//!
//! Two details are easy to get backwards:
//!
//! - **The RX completion names a buffer by tag, not by position.**
//!   `urbd1.frbd_tag` is the index of the *FRBD* whose buffer holds
//!   the data, which is not the completion's own slot. Reading the
//!   buffer at `cr_tia` instead delivers whatever was in an unrelated
//!   slot.
//! - **Received data starts with an 8-byte RFH header**, then the
//!   4-byte PCIe packet type, then the HCI payload. The RFH
//!   `packet_len` counts from *after* the RFH header, so it includes
//!   the 4-byte type.
//!
//! ## Scope
//!
//! This carries HCI packets to and from whatever the controller is
//! currently running — after [`super::BtIntelPcie::bring_up`] that
//! is the ROM bootloader. Downloading operational firmware
//! (`intel/ibt-*.sfi`) is a separate, larger job that rides on top
//! of this transport as a series of HCI commands; until it lands the
//! controller answers vendor and version queries but has no
//! Bluetooth radio behind it.

use alloc::vec::Vec;

use narf_bus::MmioRegion;
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

use super::{BtPcieError, CSR_HBUS_TARG_WRPTR};

// ── Geometry (btintel_pcie.h) ───────────────────────────────────────

/// `BTINTEL_PCIE_TX_DESCS_COUNT`.
pub const TX_DESCS: u16 = 32;
/// `BTINTEL_PCIE_RX_DESCS_COUNT`.
pub const RX_DESCS: u16 = 64;
/// `BTINTEL_PCIE_BUFFER_SIZE` — per-descriptor DMA buffer.
pub const BUFFER_SIZE: usize = 4096;
/// `BTINTEL_PCIE_DMA_ALIGN_128B`.
pub const DMA_ALIGN: u64 = 128;

/// `BTINTEL_PCIE_TXQ_NUM` — index of the TX queue in the index
/// arrays.
pub const TXQ_NUM: usize = 0;
/// `BTINTEL_PCIE_RXQ_NUM`.
pub const RXQ_NUM: usize = 1;
/// `BTINTEL_PCIE_NUM_QUEUES`.
pub const NUM_QUEUES: usize = 2;

/// `BTINTEL_PCIE_TX_DB_VEC` — doorbell vector for the TFD queue.
pub const TX_DB_VEC: u32 = 0;
/// `BTINTEL_PCIE_RX_DB_VEC` — doorbell vector for the FRBD queue.
pub const RX_DB_VEC: u32 = 513;
/// `BTINTEL_PCIE_RBD_SIZE_4K`.
pub const RBD_SIZE_4K: u32 = 0x04;

/// `BTINTEL_PCIE_HCI_TYPE_LEN` — Intel prefixes each packet with a
/// *4-byte* type word, not the 1-byte BT SIG indicator.
pub const HCI_TYPE_LEN: usize = 4;
/// `BTINTEL_PCIE_HCI_CMD_PKT`.
pub const HCI_CMD_PKT: u32 = 0x0000_0001;
/// `BTINTEL_PCIE_HCI_ACL_PKT`.
pub const HCI_ACL_PKT: u32 = 0x0000_0002;
/// `BTINTEL_PCIE_HCI_SCO_PKT`.
pub const HCI_SCO_PKT: u32 = 0x0000_0003;
/// `BTINTEL_PCIE_HCI_EVT_PKT`.
pub const HCI_EVT_PKT: u32 = 0x0000_0004;
/// `BTINTEL_PCIE_HCI_ISO_PKT`.
pub const HCI_ISO_PKT: u32 = 0x0000_0005;

/// `BTINTEL_PCIE_TX_WAIT_TIMEOUT_MS`.
pub const TX_WAIT_TIMEOUT_MS: u64 = 500;

/// `struct rfh_hdr` — 8 bytes ahead of every received packet.
pub const RFH_HDR_BYTES: usize = 8;

/// Round `n` up to the 128-byte alignment every sub-region uses.
pub const fn align_dma(n: u64) -> u64 {
    n.div_ceil(DMA_ALIGN) * DMA_ALIGN
}

// ── Descriptor sizes ────────────────────────────────────────────────

/// `struct tfd` — `type:u8`, `size:u16`, `reserved:u8`, `addr:u64`,
/// `reserved1:u32`. Packed, so 16 bytes with no padding.
pub const TFD_BYTES: u64 = 16;
/// `struct urbd0` — one dword of bitfields.
pub const URBD0_BYTES: u64 = 4;
/// `struct frbd` — `tag:u16` + reserved, `reserved2:u32`, `addr:u64`.
pub const FRBD_BYTES: u64 = 16;
/// `struct urbd1` — one dword of bitfields.
pub const URBD1_BYTES: u64 = 4;
/// One index array: `u16` per queue.
pub const INDEX_ARRAY_BYTES: u64 = 2 * NUM_QUEUES as u64;
/// `struct ctx_info` — 38 dwords.
pub const CTX_INFO_BYTES: u64 = 152;

// ── Context-information field offsets ───────────────────────────────
//
// `struct ctx_info` is `__packed`, so every offset is the running sum
// of the preceding fields. They are spelled out rather than derived
// because a miscount here silently points the device at the wrong
// ring.

/// `version:u16`.
pub const CI_OFF_VERSION: u64 = 0;
/// `size:u16`.
pub const CI_OFF_SIZE: u64 = 2;
/// `config:u32`.
pub const CI_OFF_CONFIG: u64 = 4;
/// `addr_tr_hia:u64`.
pub const CI_OFF_ADDR_TR_HIA: u64 = 16;
/// `addr_tr_tia:u64`.
pub const CI_OFF_ADDR_TR_TIA: u64 = 24;
/// `addr_cr_hia:u64`.
pub const CI_OFF_ADDR_CR_HIA: u64 = 32;
/// `addr_cr_tia:u64`.
pub const CI_OFF_ADDR_CR_TIA: u64 = 40;
/// `num_tr_ia:u16`.
pub const CI_OFF_NUM_TR_IA: u64 = 48;
/// `num_cr_ia:u16`.
pub const CI_OFF_NUM_CR_IA: u64 = 50;
/// `rbd_size:4` within its dword.
pub const CI_OFF_RBD_SIZE: u64 = 52;
/// `addr_tfdq:u64`.
pub const CI_OFF_ADDR_TFDQ: u64 = 56;
/// `addr_urbdq0:u64`.
pub const CI_OFF_ADDR_URBDQ0: u64 = 64;
/// `num_tfdq:u16`.
pub const CI_OFF_NUM_TFDQ: u64 = 72;
/// `num_urbdq0:u16`.
pub const CI_OFF_NUM_URBDQ0: u64 = 74;
/// `tfdq_db_vec:u16`.
pub const CI_OFF_TFDQ_DB_VEC: u64 = 76;
/// `urbdq0_db_vec:u16`.
pub const CI_OFF_URBDQ0_DB_VEC: u64 = 78;
/// `addr_frbdq:u64`.
pub const CI_OFF_ADDR_FRBDQ: u64 = 80;
/// `addr_urbdq1:u64`.
pub const CI_OFF_ADDR_URBDQ1: u64 = 88;
/// `num_frbdq:u16`.
pub const CI_OFF_NUM_FRBDQ: u64 = 96;
/// `frbdq_db_vec:u16`.
pub const CI_OFF_FRBDQ_DB_VEC: u64 = 98;
/// `num_urbdq1:u16`.
pub const CI_OFF_NUM_URBDQ1: u64 = 100;
/// `urbdq_db_vec:u16`.
pub const CI_OFF_URBDQ_DB_VEC: u64 = 102;
/// `tr_msi_vec:u16`.
pub const CI_OFF_TR_MSI_VEC: u64 = 104;
/// `cr_msi_vec:u16`.
pub const CI_OFF_CR_MSI_VEC: u64 = 106;
/// `dbg_output_mode` lives in the dword at this offset, bits 7:4.
pub const CI_OFF_DBG_FLAGS: u64 = 124;

/// Context-information version this driver publishes.
pub const CI_VERSION: u16 = 1;

// ── Doorbells ───────────────────────────────────────────────────────

/// Encode a doorbell write: index in the low half, vector in the
/// high half.
pub const fn doorbell(index: u16, vector: u32) -> u32 {
    index as u32 | (vector << 16)
}

// ── Layout ──────────────────────────────────────────────────────────

/// Byte offsets of each sub-region inside the single DMA allocation.
///
/// Linux allocates one chunk and carves it up with each piece aligned
/// to 128 bytes; doing the same keeps the whole descriptor set inside
/// one physically contiguous buffer, which is what
/// [`narf_io::alloc_coherent`] provides.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingLayout {
    pub tfds: u64,
    pub urbd0s: u64,
    pub frbds: u64,
    pub urbd1s: u64,
    pub tr_hia: u64,
    pub tr_tia: u64,
    pub cr_hia: u64,
    pub cr_tia: u64,
    pub ctx_info: u64,
    pub total: u64,
}

impl RingLayout {
    /// Compute the layout for the fixed queue sizes.
    pub const fn new() -> Self {
        let tfds = 0;
        let urbd0s = tfds + align_dma(TFD_BYTES * TX_DESCS as u64);
        let frbds = urbd0s + align_dma(URBD0_BYTES * TX_DESCS as u64);
        let urbd1s = frbds + align_dma(FRBD_BYTES * RX_DESCS as u64);
        let tr_hia = urbd1s + align_dma(URBD1_BYTES * RX_DESCS as u64);
        let ia = align_dma(INDEX_ARRAY_BYTES);
        let tr_tia = tr_hia + ia;
        let cr_hia = tr_tia + ia;
        let cr_tia = cr_hia + ia;
        let ctx_info = cr_tia + ia;
        Self {
            tfds,
            urbd0s,
            frbds,
            urbd1s,
            tr_hia,
            tr_tia,
            cr_hia,
            cr_tia,
            ctx_info,
            total: ctx_info + align_dma(CTX_INFO_BYTES),
        }
    }
}

impl Default for RingLayout {
    fn default() -> Self {
        Self::new()
    }
}

// ── Live rings ──────────────────────────────────────────────────────

/// The descriptor set, index arrays, context information, and data
/// buffers for one controller.
#[derive(Debug)]
pub struct Rings {
    /// Descriptors, index arrays and the context-info block.
    desc: DmaBuffer,
    /// TX data buffers, one per TFD.
    tx_bufs: Vec<DmaBuffer>,
    /// RX data buffers, one per FRBD.
    rx_bufs: Vec<DmaBuffer>,
    layout: RingLayout,
}

impl Rings {
    /// Allocate everything and fill in the context-information block.
    pub fn alloc() -> Result<Self, BtPcieError> {
        let layout = RingLayout::new();
        let desc = alloc_coherent(layout.total as usize, DomainId::DRIVER_0)
            .map_err(|_| BtPcieError::NoMemory)?;
        if desc.dma_addr().raw() % DMA_ALIGN != 0 {
            return Err(BtPcieError::NoMemory);
        }
        // The device reads the whole block; leftover heap bytes would
        // decode as ring addresses.
        for i in 0..layout.total {
            // SAFETY: `desc` is an identity-mapped DMA buffer of
            // `layout.total` bytes and `i < layout.total`.
            unsafe { core::ptr::write_volatile(desc.cpu_mut_ptr_at::<u8>(i), 0) };
        }

        let mut tx_bufs = Vec::with_capacity(TX_DESCS as usize);
        let mut rx_bufs = Vec::with_capacity(RX_DESCS as usize);
        for _ in 0..TX_DESCS {
            tx_bufs.push(
                alloc_coherent(BUFFER_SIZE, DomainId::DRIVER_0)
                    .map_err(|_| BtPcieError::NoMemory)?,
            );
        }
        for _ in 0..RX_DESCS {
            rx_bufs.push(
                alloc_coherent(BUFFER_SIZE, DomainId::DRIVER_0)
                    .map_err(|_| BtPcieError::NoMemory)?,
            );
        }

        let rings = Self {
            desc,
            tx_bufs,
            rx_bufs,
            layout,
        };
        rings.init_ctx_info();
        rings.arm_all_rx();
        Ok(rings)
    }

    fn phys_at(&self, off: u64) -> u64 {
        self.desc.dma_addr().raw() + off
    }

    fn write_u16(&self, off: u64, v: u16) {
        // SAFETY: every caller passes an offset inside the
        // `layout.total`-byte descriptor allocation.
        unsafe { core::ptr::write_volatile(self.desc.cpu_mut_ptr_at::<u16>(off), v) };
    }

    fn read_u16(&self, off: u64) -> u16 {
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile(self.desc.cpu_ptr_at::<u16>(off)) }
    }

    fn write_u32(&self, off: u64, v: u32) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.desc.cpu_mut_ptr_at::<u32>(off), v) };
    }

    fn read_u32(&self, off: u64) -> u32 {
        // SAFETY: as above.
        unsafe { core::ptr::read_volatile(self.desc.cpu_ptr_at::<u32>(off)) }
    }

    fn write_u64(&self, off: u64, v: u64) {
        // SAFETY: as above.
        unsafe { core::ptr::write_volatile(self.desc.cpu_mut_ptr_at::<u64>(off), v) };
    }

    /// `btintel_pcie_init_ci`.
    fn init_ctx_info(&self) {
        let l = &self.layout;
        let ci = l.ctx_info;
        self.write_u16(ci + CI_OFF_VERSION, CI_VERSION);
        self.write_u16(ci + CI_OFF_SIZE, CTX_INFO_BYTES as u16);
        self.write_u32(ci + CI_OFF_CONFIG, 0);

        self.write_u64(ci + CI_OFF_ADDR_TR_HIA, self.phys_at(l.tr_hia));
        self.write_u64(ci + CI_OFF_ADDR_TR_TIA, self.phys_at(l.tr_tia));
        self.write_u64(ci + CI_OFF_ADDR_CR_HIA, self.phys_at(l.cr_hia));
        self.write_u64(ci + CI_OFF_ADDR_CR_TIA, self.phys_at(l.cr_tia));
        self.write_u16(ci + CI_OFF_NUM_TR_IA, NUM_QUEUES as u16);
        self.write_u16(ci + CI_OFF_NUM_CR_IA, NUM_QUEUES as u16);
        self.write_u32(ci + CI_OFF_RBD_SIZE, RBD_SIZE_4K);

        self.write_u64(ci + CI_OFF_ADDR_TFDQ, self.phys_at(l.tfds));
        self.write_u64(ci + CI_OFF_ADDR_URBDQ0, self.phys_at(l.urbd0s));
        self.write_u16(ci + CI_OFF_NUM_TFDQ, TX_DESCS);
        self.write_u16(ci + CI_OFF_NUM_URBDQ0, TX_DESCS);
        self.write_u16(ci + CI_OFF_TFDQ_DB_VEC, TXQ_NUM as u16);
        self.write_u16(ci + CI_OFF_URBDQ0_DB_VEC, TXQ_NUM as u16);

        self.write_u64(ci + CI_OFF_ADDR_FRBDQ, self.phys_at(l.frbds));
        self.write_u64(ci + CI_OFF_ADDR_URBDQ1, self.phys_at(l.urbd1s));
        self.write_u16(ci + CI_OFF_NUM_FRBDQ, RX_DESCS);
        self.write_u16(ci + CI_OFF_FRBDQ_DB_VEC, RXQ_NUM as u16);
        self.write_u16(ci + CI_OFF_NUM_URBDQ1, RX_DESCS);
        self.write_u16(ci + CI_OFF_URBDQ_DB_VEC, RXQ_NUM as u16);

        // Single MSI-X vector, so both rings report on vector 0.
        self.write_u16(ci + CI_OFF_TR_MSI_VEC, 0);
        self.write_u16(ci + CI_OFF_CR_MSI_VEC, 0);

        // `dbg_output_mode = 1`, bits 7:4 of this dword. The debug
        // buffer address is left null: this driver does not collect
        // firmware traces, and a null address disables the sink.
        self.write_u32(ci + CI_OFF_DBG_FLAGS, 0x1 << 4);
    }

    /// Physical address of the context-information block.
    pub fn ctx_info_phys(&self) -> u64 {
        self.phys_at(self.layout.ctx_info)
    }

    // ── Index arrays ────────────────────────────────────────────────

    fn ia_off(base: u64, queue: usize) -> u64 {
        base + queue as u64 * 2
    }

    /// Transfer-ring head index for `queue` — advanced by the driver.
    pub fn tr_hia(&self, queue: usize) -> u16 {
        self.read_u16(Self::ia_off(self.layout.tr_hia, queue))
    }

    fn set_tr_hia(&self, queue: usize, v: u16) {
        self.write_u16(Self::ia_off(self.layout.tr_hia, queue), v);
    }

    /// Transfer-ring tail index — advanced by the device.
    pub fn tr_tia(&self, queue: usize) -> u16 {
        self.read_u16(Self::ia_off(self.layout.tr_tia, queue))
    }

    /// Completion-ring head index — advanced by the device.
    pub fn cr_hia(&self, queue: usize) -> u16 {
        self.read_u16(Self::ia_off(self.layout.cr_hia, queue))
    }

    /// Completion-ring tail index — advanced by the driver.
    pub fn cr_tia(&self, queue: usize) -> u16 {
        self.read_u16(Self::ia_off(self.layout.cr_tia, queue))
    }

    fn set_cr_tia(&self, queue: usize, v: u16) {
        self.write_u16(Self::ia_off(self.layout.cr_tia, queue), v);
    }

    /// `btintel_pcie_is_txackq_empty`.
    pub fn tx_completions_pending(&self) -> bool {
        self.cr_tia(TXQ_NUM) != self.cr_hia(TXQ_NUM)
    }

    /// `btintel_pcie_is_rxq_empty`, inverted.
    pub fn rx_completions_pending(&self) -> bool {
        self.cr_tia(RXQ_NUM) != self.cr_hia(RXQ_NUM)
    }

    // ── TX ──────────────────────────────────────────────────────────

    /// `btintel_pcie_prepare_tx` — point TFD `index` at its buffer and
    /// copy `payload` into it, prefixed by the 4-byte packet type.
    fn prepare_tx(&self, index: u16, pkt_type: u32, payload: &[u8]) {
        let tfd = self.layout.tfds + index as u64 * TFD_BYTES;
        // Clear the whole descriptor first: the reserved fields must
        // not carry a previous transmission's bits.
        for i in 0..TFD_BYTES {
            // SAFETY: `tfd + i` is inside the descriptor allocation.
            unsafe { core::ptr::write_volatile(self.desc.cpu_mut_ptr_at::<u8>(tfd + i), 0) };
        }

        let buf = &self.tx_bufs[index as usize];
        let total = HCI_TYPE_LEN + payload.len();
        let type_bytes = pkt_type.to_le_bytes();
        for (i, b) in type_bytes.iter().chain(payload.iter()).enumerate() {
            // SAFETY: the slot buffer is `BUFFER_SIZE` and the caller
            // checked `total <= BUFFER_SIZE`.
            unsafe { core::ptr::write_volatile(buf.cpu_mut_ptr_at::<u8>(i as u64), *b) };
        }

        // `type` stays 0; `size` is at byte 1 and `addr` at byte 4.
        self.write_u16(tfd + 1, total as u16);
        self.write_u64(tfd + 4, buf.dma_addr().raw());
    }

    /// Post one packet and ring the TX doorbell.
    ///
    /// # Safety
    /// `csr` must be this controller's mapped BAR0.
    pub unsafe fn transmit(
        &self,
        csr: &MmioRegion,
        pkt_type: u32,
        payload: &[u8],
    ) -> Result<(), BtPcieError> {
        if HCI_TYPE_LEN + payload.len() > BUFFER_SIZE {
            return Err(BtPcieError::PacketTooLarge);
        }
        let index = self.tr_hia(TXQ_NUM);
        if index >= TX_DESCS {
            return Err(BtPcieError::RingIndexOutOfRange);
        }

        self.prepare_tx(index, pkt_type, payload);
        let next = (index + 1) % TX_DESCS;
        self.set_tr_hia(TXQ_NUM, next);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // SAFETY: caller-asserted mapped CSR window.
        unsafe { csr.write32(CSR_HBUS_TARG_WRPTR, doorbell(next, TX_DB_VEC)) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // The device retires the TFD by advancing the TX completion
        // ring's head. Polled rather than waiting on the MSI-X
        // completion interrupt.
        let done = narf_scheduler::responsive_spin_until(
            || self.tx_completions_pending(),
            narf_time::Deadline::after_ms(TX_WAIT_TIMEOUT_MS),
        );
        if !done {
            return Err(BtPcieError::TxTimeout);
        }
        // Consume every completion the device posted.
        let hia = self.cr_hia(TXQ_NUM);
        self.set_cr_tia(TXQ_NUM, hia);
        Ok(())
    }

    // ── RX ──────────────────────────────────────────────────────────

    /// `btintel_pcie_prepare_rx` — point FRBD `index` at its buffer.
    fn prepare_rx(&self, index: u16) {
        let frbd = self.layout.frbds + index as u64 * FRBD_BYTES;
        for i in 0..FRBD_BYTES {
            // SAFETY: inside the descriptor allocation.
            unsafe { core::ptr::write_volatile(self.desc.cpu_mut_ptr_at::<u8>(frbd + i), 0) };
        }
        // `tag` is the low 16 bits; the completion echoes it back so
        // the driver knows which buffer holds the data.
        self.write_u16(frbd, index);
        self.write_u64(frbd + 8, self.rx_bufs[index as usize].dma_addr().raw());
    }

    /// Fill every FRBD before the device is started. The doorbell is
    /// not rung here — [`Self::start_rx`] does that once the device
    /// is alive.
    fn arm_all_rx(&self) {
        for i in 0..RX_DESCS {
            self.prepare_rx(i);
        }
        self.set_tr_hia(RXQ_NUM, 0);
    }

    /// Hand the device the RX ring.
    ///
    /// # Safety
    /// `csr` must be this controller's mapped BAR0.
    pub unsafe fn start_rx(&self, csr: &MmioRegion) {
        // Every descriptor is armed, so the head wraps back to 0 and
        // the doorbell publishes the full ring.
        self.set_tr_hia(RXQ_NUM, 0);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: caller-asserted mapped CSR window.
        unsafe { csr.write32(CSR_HBUS_TARG_WRPTR, doorbell(0, RX_DB_VEC)) };
    }

    /// Pop one received packet, if the device has completed one.
    ///
    /// Returns `(pcie_packet_type, payload)` with the RFH header and
    /// the 4-byte type already stripped.
    ///
    /// # Safety
    /// `csr` must be this controller's mapped BAR0.
    pub unsafe fn receive(&self, csr: &MmioRegion) -> Option<(u32, Vec<u8>)> {
        let cr_tia = self.cr_tia(RXQ_NUM);
        let cr_hia = self.cr_hia(RXQ_NUM);
        if cr_tia == cr_hia || cr_tia >= RX_DESCS {
            return None;
        }

        // `urbd1.frbd_tag` names which FRBD's buffer holds the data.
        // It is *not* the completion's own index — using `cr_tia` to
        // find the buffer delivers an unrelated slot's contents.
        let urbd1 = self.read_u32(self.layout.urbd1s + cr_tia as u64 * URBD1_BYTES);
        let tag = (urbd1 & 0xFFFF) as u16;

        let payload = if tag < RX_DESCS {
            self.read_rx_buffer(tag)
        } else {
            None
        };

        // Re-arm the buffer and hand it back regardless of whether
        // the packet decoded: leaving it out would shrink the ring
        // every time a malformed packet arrived.
        self.prepare_rx(tag.min(RX_DESCS - 1));
        let next_tia = (cr_tia + 1) % RX_DESCS;
        self.set_cr_tia(RXQ_NUM, next_tia);

        let frbd_next = (self.tr_hia(RXQ_NUM) + 1) % RX_DESCS;
        self.set_tr_hia(RXQ_NUM, frbd_next);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: caller-asserted mapped CSR window.
        unsafe { csr.write32(CSR_HBUS_TARG_WRPTR, doorbell(frbd_next, RX_DB_VEC)) };

        payload
    }

    /// Decode one RX buffer: RFH header, then the 4-byte PCIe packet
    /// type, then the HCI payload.
    fn read_rx_buffer(&self, tag: u16) -> Option<(u32, Vec<u8>)> {
        let buf = &self.rx_bufs[tag as usize];
        let byte = |i: u64| {
            // SAFETY: the slot buffer is `BUFFER_SIZE` and every
            // caller below bounds `i` against it.
            unsafe { core::ptr::read_volatile(buf.cpu_ptr_at::<u8>(i)) }
        };

        // `rfh_hdr.packet_len` is the low 16 bits and counts the
        // bytes *after* the RFH header — so it includes the 4-byte
        // packet type.
        let packet_len = u16::from_le_bytes([byte(0), byte(1)]) as usize;
        if !(HCI_TYPE_LEN..=BUFFER_SIZE - RFH_HDR_BYTES).contains(&packet_len) {
            return None;
        }

        let base = RFH_HDR_BYTES as u64;
        let pkt_type =
            u32::from_le_bytes([byte(base), byte(base + 1), byte(base + 2), byte(base + 3)]);

        let payload_len = packet_len - HCI_TYPE_LEN;
        let mut out = Vec::with_capacity(payload_len);
        for i in 0..payload_len {
            out.push(byte(base + HCI_TYPE_LEN as u64 + i as u64));
        }
        Some((pkt_type, out))
    }
}
