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
//! short GI; received HT/A-MPDU frames and C2H packets are consumed and
//! dropped. The owner cannot reach `MacConfigured` until the 8192EE
//! PHY/RF/channel steps exist, so none of this is reachable from probe.
use super::super::super::rtl8192ee::{mac, trx};
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
}
impl State {
    pub(in super::super) fn new() -> Self {
        Self {
            started: false,
            remained: 0,
            channel: None,
        }
    }
}

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
            Ok(Some(packet))
        })?;
        let Some(packet) = consumed else {
            self.phase = Phase::Running;
            return Ok(idle);
        };
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
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "packet_owner_tests.rs"]
pub(crate) mod tests;
