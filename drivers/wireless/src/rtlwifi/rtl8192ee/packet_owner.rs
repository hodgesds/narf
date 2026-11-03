// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EE buffer-descriptor branch of the retained packet owner.
//!
//! Mounted as `prepare::packet::ee92` (it needs the owner's private ring
//! storage); the chip facts it composes live beside it in `rtl8192ee/`.
//! Linux `use_new_trx_flow` (`pci.c`, `rtl8192ee/trx.c`, `hw.c`):
//!
//! - Allocation (`_rtl_pci_init_trx_var`, `_rtl_pci_init_tx_ring`,
//!   `_rtl_pci_init_rx_ring`): per TX queue a 64-byte buffer-descriptor ring
//!   and a 64-byte TX-descriptor ring of the same length (`TX_DESC_NUM_92E`
//!   512, beacon 2), both 256-byte aligned; one RX ring of 512 16-byte
//!   buffer descriptors prepared with `HW_DESC_RX_PREPARE` over 9100-byte
//!   buffers (`rxbuffersize`). DMA32 (`dma64` is false). The owner's `tx`
//!   holds the seven BD rings (`prepare::TX_BASES` order: BCN, MGQ, VO, VI,
//!   BE, BK, HQ) followed by the seven descriptor rings in the same order.
//! - Publication (`rtl92ee_hw_init` → `_rtl92ee_init_mac`): the
//!   `_rtl8192ee_check_pcie_dma_hang` probe of `REG_BACKDOOR_DBI_DATA + 3`
//!   (a hung DMA engine is refused: `_rtl8192ee_reset_pcie_interface_dma` is
//!   not implemented), then `rtl8192ee::mac::init_mac` (auto LLT, BD ring
//!   bases, `TXBD_NUM`/`RXBD_NUM`) with host DMA stopped (`0x301 = 0xff`),
//!   CR DMA/MAC gates and IRQ masks closed. Unlike Linux this runs after the
//!   firmware owner's download, as for the 88EE/8821AE profiles.
//! - Release (packet owner start): bus mastering, then `REG_CR` word `0x2ff`
//!   (`mac::release_cr`, deferred from `_rtl92ee_init_mac`) and
//!   `REG_PCIE_CTRL_REG` word `0x8000` (`rtl92ee_hw_init` before the
//!   firmware download; it clears the `0x301` TX DMA stops).
//! - TX (`rtl_pci_tx`, `rtl92ee_tx_fill_desc`, `rtl92ee_pre_fill_tx_bd_desc`,
//!   `rtl92ee_set_desc(HW_DESC_OWN)`): the descriptor at `cur_tx_wp`, the BD
//!   naming it and the frame, then the `REG_*_TXBD_IDX` doorbell with the
//!   advanced write point. Completion is `rtl92ee_is_tx_desc_closed` over
//!   the device read point (`[27:16]`).
//! - RX (`_rtl_pci_rx_interrupt`, `rtl92ee_rx_desc_buff_remained_cnt`,
//!   `rtl92ee_rx_check_dma_ok`): the remaining count from
//!   `REG_RXQ_TXBD_IDX` once the device read point has left 0 (`start_rx`,
//!   kept per owner instead of Linux's function static), each entry
//!   acknowledged by writing the advanced `next_rx_rp` to `0x3b4`.
//!
//! Deliberate differences: a BD that never shows completion within the 21
//! `rx_check_dma_ok` reads is not consumed (Linux processes it anyway); the
//! BD is re-prepared before the `0x3b4` acknowledgement (Linux acknowledges
//! first); a host/device write-point disagreement is a fault rather than a
//! silent resynchronisation. Station profile here: one outstanding frame,
//! forced legacy driver rate, fallback disabled, `RATR_INX_WIRELESS_MC`
//! (8192EE has no `RTL_SPEC_NEW_RATEID`), no protection, aggregation or
//! short GI; received HT/A-MPDU frames are consumed and dropped; C2H packets
//! are parsed (`rtl8192ee/c2h.rs`). Interrupts use the 8192EE profile
//! (`rtl8192ee/h2c.rs`) and a stopped owner's DMA is released only after
//! the card-disable retirement proof (`ee92_quiesce`). The owner cannot reach `MacConfigured` until the 8192EE
//! PHY/RF/channel steps exist, so none of this is reachable from probe.
use super::super::super::rtl8192ee::{c2h, h2c, mac, rsvd_page, trx};
use super::{
    extent, queue, Delivery, Error, Io, Memory, Mpdu, Pending, Phase, Port, Prepared, ReceiveStep,
    RX_BASE, RX_BUFFER, TX_BASES,
};
use alloc::vec::Vec;

/// `TX_DESC_NUM_92E` / `RTL_PCI_MAX_RX_COUNT`: the BD counts `init_mac`
/// programs and `calc_fifo_space` wraps at.
pub(crate) const DEPTH: usize = trx::TX_DESC_NUM as usize;
/// `REG_BACKDOOR_DBI_DATA` (`rtl8192ee/reg.h`).
const REG_BACKDOOR_DBI_DATA: u16 = 0x03f0;
/// `RATR_INX_WIRELESS_MC` (`_rtl_txrate_selectmode` without a station).
const RATR_INX_WIRELESS_MC: u8 = 7;
/// `rtl92ee_rx_check_dma_ok`: the first read plus up to 21 re-reads.
const DMA_OK_READS: usize = 22;
/// `TX_BASES`-order `get_desc_addr_fr_q_idx` doorbells (beacon: none, it
/// is owned through the BD OWN bit).
const INDEX: [Option<u16>; 7] = [
    None,
    Some(trx::REG_MGQ_TXBD_IDX),
    Some(trx::REG_VOQ_TXBD_IDX),
    Some(trx::REG_VIQ_TXBD_IDX),
    Some(trx::REG_BEQ_TXBD_IDX),
    Some(trx::REG_BKQ_TXBD_IDX),
    Some(trx::REG_HI0Q_TXBD_IDX),
];

/// `txringcount[]` in `TX_BASES` order.
pub(crate) const fn entries(queue: usize) -> usize {
    if queue == 0 {
        trx::BEACON_DESC_NUM as usize
    } else {
        DEPTH
    }
}

/// Exact allocation shape, in the order `allocate_rtl8192ee` requests it:
/// seven BD rings, seven descriptor rings, the RX BD ring, RX buffers.
pub(crate) fn blocks() -> impl Iterator<Item = usize> {
    (0..7)
        .map(|q| entries(q) * trx::TX_BD_SIZE)
        .chain((0..7).map(|q| entries(q) * trx::TX_DESC_SIZE))
        .chain(core::iter::once(DEPTH * trx::RX_BD_SIZE))
        .chain(core::iter::repeat_n(RX_BUFFER, DEPTH))
}

/// RX read-pointer state of `rtl92ee_rx_desc_buff_remained_cnt`.
pub(in super::super) struct State {
    /// Linux `start_rx`: the device read point has left 0 once.
    started: bool,
    /// `rx_remained_cnt` of the current batch.
    remained: u16,
    /// Programmed station channel (set by the 8192EE channel step).
    pub(in super::super) channel: Option<u8>,
    /// `rtl8192ee/fw.c` H2C mailbox (`last_hmeboxnum`, power-save gate).
    pub(in super::super) mailbox: h2c::Mailbox,
    /// `rtlpriv->tx_report` sequence state (V1 reports).
    pub(in super::super) reports: c2h::TxReportState,
    /// Latest C2H TX report `(sn, acked, retry)`.
    pub(in super::super) tx_report: Option<(u16, bool, u8)>,
    /// Pending C2H RA report `(rate, collision)` for the DM step's
    /// `rtl92ee_dm_dynamic_arfb_select` (Linux: `c2hcmd_wq`).
    pub(in super::super) ra_report: Option<(u8, bool)>,
    /// `rtlpci->reg_bcn_ctrl_val` (`_rtl92ee_hw_configure` leaves `0x1d`).
    pub(in super::super) bcn_ctrl: u8,
}
impl State {
    pub(in super::super) fn new() -> Self {
        Self {
            started: false,
            remained: 0,
            channel: None,
            mailbox: h2c::Mailbox::default(),
            reports: c2h::TxReportState::default(),
            tx_report: None,
            ra_report: None,
            bcn_ctrl: 0x1d,
        }
    }
    /// `rtl_c2h_content_parsing` for the packets this profile consumes.
    /// Malformed packets are consumed without effect, as Linux logs them.
    fn c2h(&mut self, packet: &[u8]) {
        match c2h::parse(packet) {
            Ok(c2h::Event::TxReport { sn, st, retry }) => {
                self.reports.record(sn);
                self.tx_report = Some((sn, st == 0, retry));
            }
            Ok(c2h::Event::RaReport { rate, collision }) => {
                self.ra_report = Some((rate, collision));
            }
            _ => {}
        }
    }
}

/// Bytes of a C2H packet the owner copies out of an RX buffer (the V1 TX
/// report needs 9, the RA report 6).
const C2H_COPY: usize = 32;
/// `RTL8192E_TRANS_ACT_TO_LPS` 0x5f8..0x5fb polls (`rtl_hal_pwrseqcmdparsing`
/// polling bound, 5000 × 10 us).
const TX_EMPTY_POLLS: usize = 5000;
/// `REG_RXDMA_CONTROL` and its RX DMA pause bit (`0x284[18]`,
/// `_rtl8192ee_reset_pcie_interface_dma` step 2).
const REG_RXDMA_CONTROL: u16 = 0x0286;
const RXDMA_PAUSE: u8 = 1 << 2;

fn write_words(ring: &mut impl Memory, offset: usize, words: &[u32]) -> Result<(), Error> {
    for (word, value) in words.iter().copied().enumerate() {
        ring.write32(offset + word * 4, value)?;
    }
    Ok(())
}

impl<I: Io, M: Memory> Prepared<I, M> {
    /// Allocate and build the two-ring layout. Every block is validated
    /// (DMA32 extent, alignment, no overlap) and every descriptor built
    /// before any BAR side effect.
    pub fn allocate_rtl8192ee(
        io: I,
        mut allocate: impl FnMut(usize) -> Result<M, Error>,
    ) -> Result<Self, Error> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        ranges
            .try_reserve_exact(DEPTH + 15)
            .map_err(|_| Error::Memory)?;
        let mut reserve = |needed: usize, alignment| -> Result<M, Error> {
            let block = allocate(needed)?;
            let address = u64::from(extent(&block, needed, alignment)?);
            let end = address + needed as u64;
            if ranges.iter().any(|&(a, b)| address < b && a < end) {
                return Err(Error::Address);
            }
            ranges.push((address, end));
            Ok(block)
        };
        let mut tx = Vec::new();
        tx.try_reserve_exact(14).map_err(|_| Error::Memory)?;
        for size in [trx::TX_BD_SIZE, trx::TX_DESC_SIZE] {
            for q in 0..7 {
                let bytes = entries(q) * size;
                let mut ring = reserve(bytes, 256)?;
                for word in 0..bytes / 4 {
                    ring.write32(word * 4, 0)?;
                }
                ring.sync();
                tx.push(ring);
            }
        }
        let mut receive = reserve(DEPTH * trx::RX_BD_SIZE, 256)?;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(DEPTH)
            .map_err(|_| Error::Memory)?;
        for slot in 0..DEPTH {
            let buffer = reserve(RX_BUFFER, 4)?;
            let bd = trx::RxBufferDesc::prepare(extent(&buffer, RX_BUFFER, 4)?);
            write_words(&mut receive, slot * trx::RX_BD_SIZE, &bd.dw)?;
            buffer.sync();
            buffers.push(buffer);
        }
        receive.sync();
        Ok(Self::assemble(
            super::super::Chip::Rtl8192ee,
            io,
            tx,
            receive,
            buffers,
            DEPTH,
        ))
    }

    fn ee92_rings(&self) -> Result<mac::Rings, Error> {
        let base = |q: usize| extent(&self.tx[q], entries(q) * trx::TX_BD_SIZE, 256);
        Ok(mac::Rings {
            beacon: base(0)?,
            mgnt: base(1)?,
            vo: base(2)?,
            vi: base(3)?,
            be: base(4)?,
            bk: base(5)?,
            high: base(6)?,
            rx: extent(
                self.receive.as_ref().ok_or(Error::State)?,
                DEPTH * trx::RX_BD_SIZE,
                256,
            )?,
        })
    }

    /// `_rtl8192ee_check_pcie_dma_hang`, closed gates, then the
    /// `_rtl92ee_init_mac` remainder over the owned BD rings.
    pub(in super::super) async fn ee92_prepare(&mut self) -> Result<(), Error> {
        if self.tx.len() != 14 || self.depth != DEPTH || self.buffers.len() != DEPTH {
            return Err(Error::Geometry);
        }
        let dbi = self.io.read8(REG_BACKDOOR_DBI_DATA + 3)?;
        if dbi & (1 << 2) == 0 {
            self.io.write8(REG_BACKDOOR_DBI_DATA + 3, dbi | (1 << 2))?;
            self.io.delay_us(100_000).await; // mdelay(100), "DD Justin_tsai".
        }
        // BIT(25) RX hang / BIT(24) TX hang: Linux resets the PCIe DMA
        // interface; that reset is not implemented, so the board is refused.
        if self.io.read8(REG_BACKDOOR_DBI_DATA + 3)? & 3 != 0 {
            return Err(Error::Readback);
        }
        self.io.write8(mac::REG_PCIE_CTRL_REG + 1, 0xff)?;
        if self.io.read8(mac::REG_PCIE_CTRL_REG + 1)? != 0xff {
            return Err(Error::Readback);
        }
        let cr = self.io.read8(mac::REG_CR)?;
        self.io.write8(mac::REG_CR, cr & !0xcf)?;
        if self.io.read8(mac::REG_CR)? & 0xcf != 0 {
            return Err(Error::Readback);
        }
        for address in [0xb0, 0xb8] {
            self.io.write32(address, 0)?;
            if self.io.read32(address)? != 0 {
                return Err(Error::Readback);
            }
        }
        let rings = self.ee92_rings()?;
        // init_mac publishes the bases: retain everything before it starts.
        self.published = true;
        mac::init_mac(&self.io, &rings).await?;
        let bases = [
            rings.beacon,
            rings.mgnt,
            rings.vo,
            rings.vi,
            rings.be,
            rings.bk,
            rings.high,
        ];
        for (address, base) in TX_BASES.iter().zip(bases) {
            if self.io.read32(*address)? != base {
                return Err(Error::Readback);
            }
        }
        if self.io.read32(RX_BASE)? != rings.rx {
            return Err(Error::Readback);
        }
        let tx = u32::from(mac::TXBD_NUM);
        if self.io.read32(mac::REG_MGQ_TXBD_NUM)? != tx | u32::from(mac::RXBD_NUM) << 16 {
            return Err(Error::Readback);
        }
        for reg in (mac::REG_VOQ_TXBD_NUM..=0x398).step_by(4) {
            if self.io.read32(reg)? != tx | tx << 16 {
                return Err(Error::Readback);
            }
        }
        if self.io.read8(mac::REG_PCIE_CTRL_REG + 1)? != 0xff
            || self.io.read8(mac::REG_CR)? & 0xcf != 0
            || self.io.read32(0xb0)? != 0
            || self.io.read32(0xb8)? != 0
        {
            return Err(Error::Readback);
        }
        Ok(())
    }
}

impl<I: Port<Buffer = M>, M: Memory> Prepared<I, M> {
    /// Published bases, idle BD rings, prepared RX BDs and zero hardware
    /// pointers: the exact state a fresh `init_mac` leaves.
    fn ee92_validate_rings(&self) -> Result<(), Error> {
        let rings = self.ee92_rings()?;
        let bases = [
            rings.beacon,
            rings.mgnt,
            rings.vo,
            rings.vi,
            rings.be,
            rings.bk,
            rings.high,
        ];
        for (q, (address, base)) in TX_BASES.iter().zip(bases).enumerate() {
            if self.io.read32(*address)? != base {
                return Err(Error::Readback);
            }
            let ring = &self.tx[q];
            ring.sync();
            for slot in 0..entries(q) {
                for word in 0..trx::TX_BD_SIZE / 4 {
                    if ring.read32(slot * trx::TX_BD_SIZE + word * 4)? != 0 {
                        return Err(Error::Descriptor);
                    }
                }
            }
            if let Some(index) = INDEX[q] {
                if self.io.read32(index)? != 0 {
                    return Err(Error::Readback);
                }
            }
        }
        let receive = self.receive.as_ref().ok_or(Error::State)?;
        receive.sync();
        if self.io.read32(RX_BASE)? != rings.rx || self.io.read32(trx::REG_RXQ_TXBD_IDX)? != 0 {
            return Err(Error::Readback);
        }
        for (slot, buffer) in self.buffers.iter().enumerate() {
            let bd = trx::RxBufferDesc::prepare(extent(buffer, RX_BUFFER, 4)?);
            for (word, value) in bd.dw.iter().enumerate() {
                if receive.read32(slot * trx::RX_BD_SIZE + word * 4)? != *value {
                    return Err(Error::Descriptor);
                }
            }
        }
        Ok(())
    }

    /// Open the owned BD rings: bus mastering, then the deferred
    /// `REG_CR = 0x2ff` and `REG_PCIE_CTRL_REG = 0x8000` releases.
    /// Interrupt masks stay clear (polled owner).
    pub(super) fn ee92_start_packets(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured
            || self.packet.local.is_none()
            || self.packet.ee92.channel.is_none()
        {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(false, || self.ee92_validate_rings())?;
        if self.io.read32(0xb0)? != 0 || self.io.read32(0xb8)? != 0 {
            return Err(Error::Readback);
        }
        self.io.master(true)?;
        mac::release_cr(&self.io)?;
        self.io.write16(mac::REG_PCIE_CTRL_REG, 0x8000)?;
        if self.io.read8(mac::REG_CR)? != 0xff
            || self.io.read8(mac::REG_CR + 1)? != 0x02
            || self.io.read8(mac::REG_PCIE_CTRL_REG)? != 0
            || self.io.read8(mac::REG_PCIE_CTRL_REG + 1)? != 0x80
        {
            return Err(Error::Readback);
        }
        self.packet.next = [0; 7];
        self.packet.receive = 0;
        self.packet.ee92.started = false;
        self.packet.ee92.remained = 0;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_pci_tx` for one forced-rate legacy frame: descriptor, BD, then
    /// the `TXBD_IDX` doorbell (`rtl92ee_set_desc(HW_DESC_OWN)`).
    pub(super) fn ee92_submit(&mut self, frame: &[u8], rate: u8) -> Result<u64, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_some() {
            return Err(Error::State);
        }
        if rate > trx::DESC_RATE54M
            || self.packet.protection != super::super::super::protection::Mode::None
        {
            return Err(Error::Packet);
        }
        let (queue, _, selector) = queue(
            frame,
            self.packet.local.ok_or(Error::State)?,
            self.packet.qos,
        )?;
        let index = INDEX[queue].ok_or(Error::Packet)?;
        let id = self.packet.serial.checked_add(1).ok_or(Error::State)?;
        let slot = self.packet.next[queue];
        // rtl92ee_get_available_desc: the device must agree on the write
        // point and leave space (`calc_fifo_space`).
        let value = self.io.read32(index)?;
        if value == u32::MAX {
            return Err(Error::Access(super::super::AccessError::Gone));
        }
        let (rp, wp) = trx::tx_points(value);
        if usize::from(wp) != slot || usize::from(rp) >= DEPTH {
            return Err(Error::Readback);
        }
        if trx::fifo_space(rp, wp, trx::TX_DESC_NUM) == 0 {
            return Err(Error::Descriptor);
        }
        let mut buffer = self.io.allocate_packet(frame.len())?;
        let address = extent(&buffer, frame.len(), 4)?;
        let end = u64::from(address) + frame.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        let destination = if (2..=5).contains(&queue) {
            &frame[16..22]
        } else {
            &frame[4..10]
        };
        let descriptor = trx::TxDesc::fill(&trx::TxParams {
            pkt_size: frame.len() as u16,
            queue_sel: selector,
            macid: 0,
            rate_id: RATR_INX_WIRELESS_MC,
            hw_rate: rate,
            use_driver_rate: true,
            disable_fallback: true,
            data_bw: 0,
            sub_carrier: 0,
            ampdu: false,
            ampdu_density: 0,
            sec_type: 0,
            seq: u16::from_le_bytes([frame[22], frame[23]]) >> 4,
            multicast: destination[0] & 1 != 0,
            protection: 0,
            rts_rate: 0,
            tx_report: None,
            buffer_addr: address,
        });
        let desc_addr = extent(&self.tx[7 + queue], DEPTH * trx::TX_DESC_SIZE, 256)?
            + (slot * trx::TX_DESC_SIZE) as u32;
        let bd = trx::TxBufferDesc::fill(desc_addr, address, frame.len() as u16);
        self.io.authority(true, || {
            buffer.write_bytes(0, frame)?;
            buffer.sync();
            Ok(())
        })?;
        let mut prefix = [0u32; 10];
        prefix.copy_from_slice(&descriptor.dw[..10]);
        self.packet.pending = Some(Pending {
            buffer,
            id,
            queue,
            slot,
            length: frame.len(),
            prefix,
        });
        self.packet.serial = id;
        self.phase = Phase::Failed;
        let (rings, rest) = self.tx.split_at_mut(7);
        let (bds, descs) = (&mut rings[queue], &mut rest[queue]);
        self.io.authority(true, || {
            write_words(descs, slot * trx::TX_DESC_SIZE, &descriptor.dw)?;
            descs.sync();
            write_words(bds, slot * trx::TX_BD_SIZE, &bd.dw)?;
            bds.sync();
            Ok(())
        })?;
        let next = (slot + 1) % DEPTH;
        self.packet.next[queue] = next;
        self.io.write16(index, next as u16)?;
        self.phase = Phase::Running;
        Ok(id)
    }

    /// `rtl92ee_is_tx_desc_closed` for the pending slot, then the host
    /// receipt with the BD and stable descriptor words intact.
    pub(super) fn ee92_delivery(&mut self) -> Result<Option<Delivery>, Error> {
        let Some(pending) = self.packet.pending.as_ref() else {
            return Ok(None);
        };
        let index = INDEX[pending.queue].ok_or(Error::State)?;
        let value = self.io.read32(index)?;
        if value == u32::MAX {
            return Err(Error::Access(super::super::AccessError::Gone));
        }
        let (rp, wp) = trx::tx_points(value);
        if usize::from(wp) != self.packet.next[pending.queue] {
            return Err(Error::Readback);
        }
        if !trx::tx_desc_closed(rp, wp, pending.slot as u16) {
            return Ok(None);
        }
        let bds = &self.tx[pending.queue];
        let descs = &self.tx[7 + pending.queue];
        let address = extent(&pending.buffer, pending.length, 4)?;
        let desc_addr = extent(descs, DEPTH * trx::TX_DESC_SIZE, 256)?
            + (pending.slot * trx::TX_DESC_SIZE) as u32;
        let bd = trx::TxBufferDesc::fill(desc_addr, address, pending.length as u16);
        let delivery = self.io.authority(true, || {
            bds.sync();
            descs.sync();
            for word in [0, 1, 4, 5] {
                if bds.read32(pending.slot * trx::TX_BD_SIZE + word * 4)? != bd.dw[word] {
                    return Err(Error::Descriptor);
                }
            }
            for word in [0, 1, 7] {
                if descs.read32(pending.slot * trx::TX_DESC_SIZE + word * 4)?
                    != pending.prefix[word]
                {
                    return Err(Error::Descriptor);
                }
            }
            if descs.read32(pending.slot * trx::TX_DESC_SIZE + 40)? != address {
                return Err(Error::Descriptor);
            }
            pending.buffer.sync();
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(pending.length)
                .map_err(|_| Error::Memory)?;
            bytes.resize(pending.length, 0);
            pending.buffer.read_bytes(0, &mut bytes)?;
            Ok(Delivery {
                id: pending.id,
                bytes,
            })
        })?;
        self.packet.pending = None;
        Ok(Some(delivery))
    }

    /// One `_rtl_pci_rx_interrupt` iteration of the new TRX flow.
    pub(super) fn ee92_receive_step(&mut self) -> Result<ReceiveStep, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let channel = self.packet.ee92.channel.ok_or(Error::State)?;
        let idle = ReceiveStep {
            consumed: false,
            packet: None,
        };
        if self.packet.ee92.remained == 0 {
            let mut value = self.io.read32(trx::REG_RXQ_TXBD_IDX)?;
            if value == u32::MAX {
                return Err(Error::Access(super::super::AccessError::Gone));
            }
            if usize::from(trx::rx_points(value).1) != self.packet.receive {
                value = self.io.read32(trx::REG_RXQ_TXBD_IDX)?;
            }
            let (rp, wp) = trx::rx_points(value);
            if usize::from(wp) != self.packet.receive || usize::from(rp) >= DEPTH {
                return Err(Error::Readback);
            }
            if rp > 0 {
                self.packet.ee92.started = true;
            }
            let remained = if self.packet.ee92.started {
                trx::fifo_space(rp, wp, trx::RX_DESC_NUM)
            } else {
                0
            };
            if remained == 0 {
                self.phase = Phase::Running;
                return Ok(idle);
            }
            self.packet.ee92.remained = remained;
        }
        let slot = self.packet.receive;
        let ring = self.receive.as_mut().ok_or(Error::State)?;
        let buffer = &self.buffers[slot];
        let buffer_addr = extent(buffer, RX_BUFFER, 4)?;
        let offset = slot * trx::RX_BD_SIZE;
        let consumed = self.io.authority(true, || {
            let mut bd = trx::RxBufferDesc::default();
            for _ in 0..DMA_OK_READS {
                ring.sync();
                for (word, value) in bd.dw.iter_mut().enumerate() {
                    *value = ring.read32(offset + word * 4)?;
                }
                if bd.dma_done() {
                    break;
                }
            }
            if !bd.dma_done() {
                return Ok(None);
            }
            if bd.dw[1] != buffer_addr || bd.dw[2] != 0 {
                return Err(Error::Descriptor);
            }
            buffer.sync();
            let mut raw = [0u8; trx::RX_DESC_SIZE];
            buffer.read_bytes(0, &mut raw)?;
            let status = trx::RxStatus::decode(&raw);
            let length = usize::from(status.pkt_len);
            let start = status.payload_offset();
            let limit = trx::RX_DESC_SIZE + trx::MAX_RECEIVE_BUFFER_SIZE as usize;
            if start.checked_add(length).is_none_or(|n| n > limit) {
                return Err(Error::Descriptor);
            }
            let mut packet = None;
            let mut report = None;
            if status.c2h && length >= c2h::C2H_DATA_OFFSET {
                let mut bytes = [0u8; C2H_COPY];
                let take = length.min(C2H_COPY);
                buffer.read_bytes(start, &mut bytes[..take])?;
                report = Some((bytes, take));
            }
            if !status.c2h
                && !status.crc
                && !status.icv
                && !status.ampdu
                && status.rate <= trx::DESC_RATE54M
                && (24..=2304 + 4).contains(&length)
            {
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(length - 4)
                    .map_err(|_| Error::Memory)?;
                bytes.resize(length - 4, 0);
                buffer.read_bytes(start, &mut bytes)?;
                let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
                // Software CCMP: protected frames keep IV/ciphertext/MIC.
                if fc & 0x400 == 0 && bytes[22] & 15 == 0 && (fc & 0x4000 == 0 || !status.decrypted)
                {
                    packet = Some(Mpdu {
                        bytes,
                        channel,
                        ht: false,
                        short_gi: false,
                        width40: false,
                        aggregated: false,
                        pwdb: None,
                        antenna_mux: None,
                    });
                }
            }
            write_words(ring, offset, &trx::RxBufferDesc::prepare(buffer_addr).dw)?;
            ring.sync();
            Ok(Some((packet, report)))
        })?;
        let Some((packet, report)) = consumed else {
            self.phase = Phase::Running;
            return Ok(idle);
        };
        if let Some((bytes, take)) = report {
            self.packet.ee92.c2h(&bytes[..take]);
        }
        let next = (slot + 1) % DEPTH;
        self.packet.receive = next;
        self.packet.ee92.remained -= 1;
        self.io.write16(trx::REG_RXQ_TXBD_IDX, next as u16)?;
        self.phase = Phase::Running;
        Ok(ReceiveStep {
            consumed: true,
            packet,
        })
    }

    /// `rtl92ee_enable_interrupt` (HIMR/HIMRE = `irq_mask[0]`/`[1]`; no
    /// status clear, HSIMR or C2H-event write on this chip). Only a running
    /// owner whose vector is bound may unmask; the polling fallback keeps
    /// every mask clear.
    pub(super) fn ee92_enable_interrupts(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        self.io.authority(true, || Ok(()))?;
        self.packet.interrupts = true;
        h2c::enable_interrupt(&self.io)?;
        if self.io.read32(h2c::REG_HIMR)? != h2c::IRQ_MASK0
            || self.io.read32(h2c::REG_HIMRE)? != h2c::IRQ_MASK1
        {
            return Err(Error::Readback);
        }
        self.phase = Phase::Running;
        Ok(())
    }

    /// One `_rtl_pci_interrupt` recognition pass for the 8192EE profile
    /// (`rtl92ee_interrupt_recognized`).
    pub(super) fn ee92_recognize_interrupts(
        &mut self,
    ) -> Result<super::super::super::irq::Recognized, Error> {
        if self.phase != Phase::Running || !self.packet.interrupts {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let (inta, intb) = h2c::service_interrupt(&self.io)?;
        self.phase = Phase::Running;
        Ok(super::super::super::irq::Recognized { inta, intb })
    }

    /// Card-disable DMA retirement proof for a stopped 8192EE owner, from
    /// the `rtl92ee_card_disable` sources: with TX paused (`0x522 = 0xff`),
    /// host DMA stopped (`0x301 = 0xff`) and bus mastering cleared by
    /// `stop_packets`, the `RTL8192E_TRANS_ACT_TO_LPS` TX packet-buffer polls
    /// (0x5f8..=0x5fb zero, 5000 × 10 us); every TX queue's device read
    /// point at the host write point (`rtl92ee_is_tx_desc_closed` for every
    /// published BD: nothing left for the engine to fetch); then RX DMA
    /// paused by `REG_RXDMA_CONTROL` BIT(2) (`_rtl8192ee_reset_pcie_
    /// interface_dma` step 2) and read back. The 8192EE sources have no RX
    /// DMA idle bit (the 88EE `0x286` BIT(1) poll is not applied); the RX
    /// side rests on that pause plus the cleared bus mastering. Any timeout
    /// or disagreement leaves every mapping retained. Success allows the
    /// published rings and buffers to be unmapped.
    pub(super) async fn ee92_quiesce(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Stopped || !self.published {
            return Err(Error::State);
        }
        if self.io.read8(0x522)? != 0xff || self.io.read8(0x301)? != 0xff {
            return Err(Error::Readback);
        }
        let mut empty = false;
        for _ in 0..TX_EMPTY_POLLS {
            if self.io.read32(0x5f8)? == u32::MAX {
                return Err(Error::Access(super::super::AccessError::Gone));
            }
            let mut busy = false;
            for reg in 0x5f8..=0x5fb {
                busy |= self.io.read8(reg)? != 0;
            }
            if !busy {
                empty = true;
                break;
            }
            self.io.delay_us(10).await;
        }
        if !empty {
            return Err(Error::PacketTimeout);
        }
        for (queue, index) in INDEX.iter().enumerate() {
            let Some(index) = *index else { continue };
            let (rp, wp) = trx::tx_points(self.io.read32(index)?);
            if usize::from(wp) != self.packet.next[queue] || rp != wp {
                return Err(Error::PacketTimeout);
            }
        }
        let control = self.io.read8(REG_RXDMA_CONTROL)?;
        self.io.write8(REG_RXDMA_CONTROL, control | RXDMA_PAUSE)?;
        if self.io.read8(REG_RXDMA_CONTROL)? & RXDMA_PAUSE == 0 {
            return Err(Error::Readback);
        }
        self.published = false;
        Ok(())
    }

    /// The pending C2H RA report's `rtl92ee_dm_dynamic_arfb_select`
    /// (`REG_DARFRC` pair), run by the DM step inside the owner's current
    /// authority (Linux runs it from `c2hcmd_wq`). Returns whether a report
    /// was applied.
    pub(super) fn ee92_apply_ra_report(&mut self) -> Result<bool, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        let Some((rate, collision)) = self.packet.ee92.ra_report.take() else {
            return Ok(false);
        };
        self.phase = Phase::Failed;
        c2h::apply_dynamic_arfb(&self.io, rate, collision)?;
        self.phase = Phase::Running;
        Ok(true)
    }

    /// Take the latest C2H TX report `(sn, acked, retry)`.
    pub(super) fn ee92_take_tx_report(&mut self) -> Option<(u16, bool, u8)> {
        self.packet.ee92.tx_report.take()
    }

    /// `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)` for 8192EE
    /// (`rtl92ee_set_hw_reg`): `HW_VAR_AID`, `_rtl92ee_download_rsvd_page`
    /// over the [`rsvd_page::pages`] body, then the MSRRPT connect report.
    /// The body stays owned by the claim (`packet.reserved`) until a
    /// quiescence proof: the beacon BD naming it may keep its OWN bit.
    /// Linux logs and continues when BCN_VALID never sets; here that is a
    /// terminal `CommandTimeout`.
    pub(super) async fn ee92_join_report(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        admission: Option<&super::super::station::Admission>,
        policy: &impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() {
            return Err(Error::State);
        }
        let local = self.packet.local.ok_or(Error::State)?;
        let pages = rsvd_page::pages(local, peer, aid).ok_or(Error::Packet)?;
        let mut buffer = self.io.allocate_packet(pages.len())?;
        let address = extent(&buffer, pages.len(), 4)?;
        let end = u64::from(address) + pages.len() as u64;
        if self
            .tx
            .iter()
            .chain(self.receive.iter())
            .chain(self.buffers.iter())
            .any(|other| {
                u64::from(address) < other.address() + other.len() as u64 && other.address() < end
            })
        {
            return Err(Error::Address);
        }
        self.io.authority(true, || {
            buffer.write_bytes(0, &pages)?;
            buffer.sync();
            Ok(())
        })?;
        self.packet.reserved = Some(buffer);
        self.phase = Phase::Failed;
        let previous = u16::from_le_bytes([
            self.io.read8(rsvd_page::REG_BCN_PSR_RPT)?,
            self.io.read8(rsvd_page::REG_BCN_PSR_RPT + 1)?,
        ]);
        self.io.write16(
            rsvd_page::REG_BCN_PSR_RPT,
            rsvd_page::psr_with_aid(previous, aid),
        )?;
        self.ee92_download_rsvd_page(address, pages.len() as u16, admission, policy)
            .await?;
        if admission.is_some_and(|c| c.closed.load(core::sync::atomic::Ordering::Acquire)) {
            return Err(Error::State);
        }
        policy(self)?;
        self.packet
            .ee92
            .mailbox
            .fill(&self.io, h2c::H2C_MSRRPT, &h2c::media_status(true))
            .await?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `_rtl92ee_download_rsvd_page`: `REG_CR + 1` BIT(0), BCN_CTRL
    /// `(0, BIT(3))` / `(BIT(4), 0)`, `0x422` BIT(6) cleared; then up to five
    /// uploads, each clearing BCN_VALID, `rtl92ee_set_fw_rsvdpagepkt`
    /// (`rtl_cmd_send_packet` on BEACON_QUEUE descriptor 0 with
    /// `rtl92ee_tx_fill_cmddesc`, then the `H2C_92E_RSVDPAGE` location),
    /// waiting `REG_MGQ_TXBD_NUM + 3` BIT(4) clear (20 × 10 us) before
    /// setting it, and BCN_VALID (20 × 50 us; acknowledged with BIT(0)). The
    /// beacon controls, `0x422` (when it had BIT(6)) and `REG_CR + 1` are
    /// restored after.
    ///
    /// Deliberate difference: on the new TRX flow Linux's
    /// `rtl_cmd_send_packet` writes only `ring->desc[0]` (and
    /// `rtl92ee_tx_polling` is empty), leaving the beacon buffer descriptor
    /// the hardware fetches from `REG_BCNQ_DESA` untouched. Here beacon BD 0
    /// is filled the way Linux's own beacon path does
    /// (`_rtl_pci_prepare_bcn_tasklet`: `rtl92ee_pre_fill_tx_bd_desc` naming
    /// descriptor 0 and the body, `HW_DESC_OWN` on `BEACON_QUEUE` setting
    /// the BD OWN bit), so the upload is well defined.
    async fn ee92_download_rsvd_page(
        &mut self,
        address: u32,
        length: u16,
        admission: Option<&super::super::station::Admission>,
        policy: &impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let closed = |a: Option<&super::super::station::Admission>| {
            a.is_some_and(|c| c.closed.load(core::sync::atomic::Ordering::Acquire))
        };
        let cr = self.io.read8(rsvd_page::REG_CR_1)?;
        self.io.write8(rsvd_page::REG_CR_1, cr | 1)?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ee92.bcn_ctrl, 0, 1 << 3)?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ee92.bcn_ctrl, 1 << 4, 0)?;
        let txq = self.io.read8(rsvd_page::REG_FWHW_TXQ_CTRL_2)?;
        self.io.write8(
            rsvd_page::REG_FWHW_TXQ_CTRL_2,
            txq & !rsvd_page::TXQ_REAL_BEACON,
        )?;
        let descriptor = trx::TxDesc::command(length, address);
        let desc_addr = extent(&self.tx[7], entries(0) * trx::TX_DESC_SIZE, 256)?;
        let mut bd = trx::TxBufferDesc::fill(desc_addr, address, length);
        bd.set_own();
        // A rejoin reuses beacon BD 0, whose earlier upload BCN_VALID proved;
        // within one download Linux overwrites descriptor 0 too.
        let mut proven = !self.packet.retired.is_empty();
        let mut valid = false;
        for _ in 0..rsvd_page::ATTEMPTS {
            let status = self.io.read8(rsvd_page::REG_BCN_VALID)?;
            if status == 0xff {
                return Err(Error::Access(super::super::AccessError::Gone));
            }
            self.io.write8(rsvd_page::REG_BCN_VALID, status | 1)?;
            {
                let _publication = admission.map(|control| control.publication.lock());
                if closed(admission) {
                    return Err(Error::State);
                }
                policy(self)?;
                let (bds, descs) = self.tx.split_at_mut(7);
                let (bds, descs) = (&mut bds[0], &mut descs[0]);
                self.io.authority(true, || {
                    bds.sync();
                    if bds.read32(0)? & (1 << 31) != 0 && !proven {
                        return Err(Error::Descriptor);
                    }
                    write_words(descs, 0, &descriptor.dw)?;
                    descs.sync();
                    write_words(bds, 4, &bd.dw[1..])?;
                    bds.sync();
                    bds.write32(0, bd.dw[0])?;
                    bds.sync();
                    Ok(())
                })?;
            }
            proven = true;
            self.packet
                .ee92
                .mailbox
                .fill(&self.io, h2c::H2C_RSVDPAGE, &h2c::RSVDPAGE_LOCATION)
                .await?;
            let mut kick = self.io.read8(rsvd_page::REG_BCNQ_KICK)?;
            let mut count = 0;
            while kick & rsvd_page::BCNQ_KICK != 0 && count < rsvd_page::KICK_POLLS {
                count += 1;
                self.io.delay_us(rsvd_page::KICK_DELAY_US).await;
                kick = self.io.read8(rsvd_page::REG_BCNQ_KICK)?;
            }
            if kick == 0xff {
                return Err(Error::Access(super::super::AccessError::Gone));
            }
            self.io
                .write8(rsvd_page::REG_BCNQ_KICK, kick | rsvd_page::BCNQ_KICK)?;
            let mut status = self.io.read8(rsvd_page::REG_BCN_VALID)?;
            let mut count = 0;
            while status & 1 == 0 && count < rsvd_page::VALID_POLLS {
                count += 1;
                self.io.delay_us(rsvd_page::VALID_DELAY_US).await;
                status = self.io.read8(rsvd_page::REG_BCN_VALID)?;
            }
            if status == 0xff {
                return Err(Error::Access(super::super::AccessError::Gone));
            }
            if status & 1 != 0 {
                self.io.write8(rsvd_page::REG_BCN_VALID, 1)?;
                valid = true;
                break;
            }
        }
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ee92.bcn_ctrl, 1 << 3, 0)?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ee92.bcn_ctrl, 0, 1 << 4)?;
        if txq & rsvd_page::TXQ_REAL_BEACON != 0 {
            self.io.write8(rsvd_page::REG_FWHW_TXQ_CTRL_2, txq)?;
        }
        let cr = self.io.read8(rsvd_page::REG_CR_1)?;
        self.io.write8(rsvd_page::REG_CR_1, cr & !1)?;
        if valid {
            Ok(())
        } else {
            Err(Error::CommandTimeout)
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "packet_owner_tests.rs"]
pub(crate) mod tests;

/// Radio/channel steps of the retained 8192EE owner (`rtl8192ee/init.rs`,
/// `rtl8192ee/channel.rs`). Packet DMA, CR gates and IRQs stay closed.
impl<I: Io, M: Memory> Prepared<I, M> {
    /// The configured RTL8192EE radio facts, if any.
    pub fn rtl8192ee_radio(&self) -> Option<&super::super::super::rtl8192ee::init::Radio> {
        self.rtl8192ee.as_deref().map(|(_, radio)| radio)
    }

    /// Prepared → RadioConfigured: the `rtl92ee_hw_init` steps after the
    /// firmware download over the retained factory map. Adapter facts are
    /// re-derived from live `REG_SYS_CFG1`/`REG_9346CR`; test chips,
    /// unprovisioned maps, BT-coexist boards and maps without TX power
    /// are refused before the first table write.
    pub async fn configure_rtl8192ee(
        &mut self,
        factory: &super::super::super::efuse::Factory,
    ) -> Result<(), Error> {
        use super::super::super::rtl8192ee::{adapter, init, txpower};
        if self.phase != Phase::Prepared || self.chip != super::super::Chip::Rtl8192ee {
            return Err(Error::State);
        }
        let facts = adapter::Adapter::from_hardware(
            self.io.read32(adapter::REG_SYS_CFG1)?,
            self.io.read8(adapter::REG_9346CR)?,
            &factory.logical,
        )
        .map_err(|_| Error::State)?;
        if facts.bt_coexist || facts.mac != factory.mac {
            return Err(Error::State);
        }
        txpower::Efuse::from_logical(&factory.logical)?;
        self.phase = Phase::Failed;
        let radio = init::configure(&self.io, &facts, &factory.logical).await?;
        let identity = super::super::super::radio::factory_identity(factory);
        self.rtl8192ee = Some(alloc::boxed::Box::new((identity, radio)));
        self.phase = Phase::RadioConfigured;
        Ok(())
    }

    /// RadioConfigured/ChannelConfigured → ChannelConfigured: `rtl_op_config`
    /// channel switch and 20/40 MHz bandwidth with the factory TX power.
    pub async fn configure_rtl8192ee_channel(
        &mut self,
        op: super::super::super::rtl8192ee::channel::Operating,
    ) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::RadioConfigured | Phase::ChannelConfigured
        ) || self.chip != super::super::Chip::Rtl8192ee
        {
            return Err(Error::State);
        }
        let mut state = self.rtl8192ee.take().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        let radio = &mut state.1;
        let (power, by_rate) = (radio.power, radio.phy.by_rate);
        super::super::super::rtl8192ee::channel::configure(
            &self.io,
            &power,
            &by_rate,
            &op,
            &mut radio.chnlval,
        )
        .await?;
        self.rtl8192ee = Some(state);
        self.phase = Phase::ChannelConfigured;
        Ok(())
    }
}
