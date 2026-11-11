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
//!   holds the seven BD rings (`TX_BASES` order: BCN, MGQ, VO, VI,
//!   BE, BK, HQ) followed by the seven descriptor rings in the same order.
//! - Publication (`rtl92ee_hw_init` → `_rtl92ee_init_mac`): the
//!   `_rtl8192ee_check_pcie_dma_hang` probe of `REG_BACKDOOR_DBI_DATA + 3`
//!   (a hung DMA engine runs `_rtl8192ee_reset_pcie_interface_dma`
//!   below; only a still-hung engine after recovery refuses the board),
//!   then `rtl8192ee::mac::init_mac` (auto LLT, BD ring
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
use super::super::super::rtl8192ee::{c2h, dm, h2c, mac, rsvd_page, station as hw, trx};
use super::{
    extent, queue, Delivery, Error, Io, Memory, Mpdu, Pending, Phase, Port, Prepared, ReceiveStep,
    RX_BUFFER,
};
use alloc::vec::Vec;

/// The 92E `REG_*_DESA` map (`rtl8192ee/reg.h`: BCNQ 0x308, MGQ 0x310,
/// VOQ 0x318, VIQ 0x320, BEQ 0x328, BKQ 0x330, HQ0 0x340) in the owner's
/// queue order (BCN, MGQ, VO, VI, BE, BK, HQ). It differs from the 8188EE
/// linked-ring map `prepare::TX_BASES` uses (HQ 0x310, RX 0x340).
const TX_BASES: [u16; 7] = [
    mac::REG_BCNQ_DESA,
    mac::REG_MGQ_DESA,
    mac::REG_VOQ_DESA,
    mac::REG_VIQ_DESA,
    mac::REG_BEQ_DESA,
    mac::REG_BKQ_DESA,
    mac::REG_HQ0_DESA,
];
/// `rtl8192ee/reg.h` `REG_RX_DESA`.
const RX_BASE: u16 = mac::REG_RX_DESA;

/// `TX_DESC_NUM_92E` / `RTL_PCI_MAX_RX_COUNT`: the BD counts `init_mac`
/// programs and `calc_fifo_space` wraps at.
pub(crate) const DEPTH: usize = trx::TX_DESC_NUM as usize;
/// `REG_BACKDOOR_DBI_DATA` (`rtl8192ee/reg.h`).
const REG_BACKDOOR_DBI_DATA: u16 = 0x03f0;
/// `RATR_INX_WIRELESS_MC` (`_rtl_txrate_selectmode` without a station).
const RATR_INX_WIRELESS_MC: u8 = 7;
/// `RATR_INX_WIRELESS_NGB` / `_GB` / `_B` (`wifi.h`).
const RATR_INX_WIRELESS_NGB: u8 = 0;
const RATR_INX_WIRELESS_GB: u8 = 4;
const RATR_INX_WIRELESS_B: u8 = 6;
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
    /// `p_ra->ratr_state` (`rtl92ee_dm_init_rate_adaptive_mask`: INIT).
    pub(in super::super) ratr_state: u8,
    /// Peer and `mac->bw_40` of the installed `H2C_92E_RA_MASK`, with its
    /// `ratr_index` (`sta_entry->ratr_index`).
    pub(in super::super) link: Option<(h2c::Peer, bool, u8)>,
    /// `rtlpci->receive_config` cache (`HW_VAR_RCR`).
    pub(in super::super) receive: hw::ReceiveConfig,
    /// `bss_conf->use_short_preamble` / `use_short_slot` as last programmed
    /// at join (`hw::erp_timing`), for beacon `BSS_CHANGED_ERP_*` updates.
    pub(in super::super) erp_timing: Option<(bool, bool)>,
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
            ratr_state: 0,
            link: None,
            receive: hw::ReceiveConfig::default(),
            erp_timing: None,
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

/// `rtl_is_special_data(is_tx, is_enc = false)` (as `_rtl_rc_get_rate`
/// calls it): a DATA frame whose ethertype at `ieee80211_get_hdrlen +
/// SNAP_SIZE` is EAPOL, ARP or IPv4 UDP with BOOTP ports (the low port
/// bytes 67/68, as Linux compares them). Linux classifies before software
/// encryption; this driver receives the station's already protected
/// frames, so a protected frame (whose payload is ciphertext) is never
/// special here.
pub(in super::super) fn special_data(frame: &[u8]) -> bool {
    if frame.len() < 24 || frame[0] & 0x0c != 0x08 || frame[1] & 0x40 != 0 {
        return false;
    }
    let mut header = 24;
    if frame[0] & 0x80 != 0 {
        header += 2;
        if frame[1] & 0x80 != 0 {
            header += 4;
        }
    }
    if frame[1] & 0x03 == 0x03 {
        header += 6;
    }
    let Some(ether) = frame.get(header + 6..header + 8) else {
        return false;
    };
    match u16::from_be_bytes([ether[0], ether[1]]) {
        0x888e | 0x0806 => true,
        0x0800 => {
            let ip = header + 8;
            let Some(&[version_ihl]) = frame.get(ip..ip + 1) else {
                return false;
            };
            if frame.get(ip + 9) != Some(&17) {
                return false;
            }
            let udp = ip + (usize::from(version_ihl & 0x0f) << 2);
            match (frame.get(udp + 1), frame.get(udp + 3)) {
                (Some(&src), Some(&dst)) => src == 68 && dst == 67 || src == 67 && dst == 68,
                _ => false,
            }
        }
        _ => false,
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

    /// `_rtl8192ee_reset_pcie_interface_dma` as NARF implements it from
    /// in-tree primitives. Linux's exact register dance for this reset
    /// is not recorded in-tree and is not claimed here; every step below
    /// reuses a write this file (or the 8723BE release) already grounds:
    /// 1. Pause RX DMA (`REG_RXDMA_CONTROL` BIT(2), the step-2
    ///    primitive named in the module comment) with read-back.
    /// 2. Stop host DMA (`REG_PCIE_CTRL_REG + 1 = 0xff`), close the CR
    ///    DMA/MAC gates (`REG_CR & !0xcf`) and the IRQ masks
    ///    (`0xb0`/`0xb8 = 0`), each with read-back — the same writes
    ///    `ee92_prepare` performs after the check, so a recovered board
    ///    continues into the identical post-check state.
    /// 3. Re-probe the hang bits (set BIT(2) + 100 ms when clear, as the
    ///    check does). If the bits cleared, release the RX DMA pause
    ///    (inverse of step 1, cf. the 8723BE release) with read-back and
    ///    report recovered; a still-hung engine reports unrecovered and
    ///    the caller refuses the board as before. Any failed read-back
    ///    fails the prepare fail-closed.
    async fn ee92_reset_pcie_interface_dma(&self) -> Result<bool, Error> {
        let rxdma = self.io.read8(REG_RXDMA_CONTROL)?;
        self.io.write8(REG_RXDMA_CONTROL, rxdma | RXDMA_PAUSE)?;
        if self.io.read8(REG_RXDMA_CONTROL)? & RXDMA_PAUSE == 0 {
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
        let dbi = self.io.read8(REG_BACKDOOR_DBI_DATA + 3)?;
        if dbi & (1 << 2) == 0 {
            self.io.write8(REG_BACKDOOR_DBI_DATA + 3, dbi | (1 << 2))?;
            self.io.delay_us(100_000).await;
        }
        if self.io.read8(REG_BACKDOOR_DBI_DATA + 3)? & 3 != 0 {
            return Ok(false);
        }
        self.io.write8(REG_RXDMA_CONTROL, rxdma & !RXDMA_PAUSE)?;
        if self.io.read8(REG_RXDMA_CONTROL)? & RXDMA_PAUSE != 0 {
            return Err(Error::Readback);
        }
        Ok(true)
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
        // interface; only a still-hung engine after recovery is refused.
        if self.io.read8(REG_BACKDOOR_DBI_DATA + 3)? & 3 != 0
            && !self.ee92_reset_pcie_interface_dma().await?
        {
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
        // rtl_op_add_interface: rtl92ee_set_network_type(STATION) without
        // a link (MSR NOLINK, CBSSID off) over the `_rtl92ee_init_mac` RCR.
        self.packet.ee92.receive = hw::ReceiveConfig::default();
        hw::network_type_station(
            &self.io,
            &mut self.packet.ee92.receive,
            &mut self.packet.ee92.bcn_ctrl,
            false,
        )?;
        if self.io.read32(mac::REG_RCR)?
            != mac::RECEIVE_CONFIG & !(hw::RCR_CBSSID_DATA | hw::RCR_CBSSID_BCN)
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

    /// Linux `rtl92ee_hw_init` leaves the firmware awake
    /// (`fw_current_inpsmode` false, `dot11_psmode` EACTIVE); nothing is
    /// sent. Only a powered MAC (`REG_CR != 0xEA`) is accepted.
    pub(super) fn ee92_awake_station(&mut self) -> Result<(), Error> {
        if self.phase != Phase::MacConfigured {
            return Err(Error::State);
        }
        if self.io.read8(mac::REG_CR)? == 0xea {
            return Err(Error::RadioOff);
        }
        Ok(())
    }

    /// Authentication-time `BSS_CHANGED_BSSID` / `BASIC_RATES` / ERP and
    /// `update_channel_access_setting` / `set_qos`
    /// ([`hw::configure_rates`], `ht_enable` false until the association).
    pub(super) fn ee92_prepare_peer(
        &mut self,
        peer: [u8; 6],
        rates: u16,
        basic: u16,
        capability: u16,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.reserved.is_some() {
            return Err(Error::State);
        }
        if peer == [0; 6] || peer[0] & 1 != 0 {
            return Err(Error::Packet);
        }
        // `cur_40_prime_sc` of the programmed operating point (0 at 20 MHz;
        // MacConfigured implies the channel permission).
        let prime_sc = self
            .rtl8192ee_power
            .and_then(|p| p.operating().channel())
            .map_or(0, |c| c.prime_sc);
        self.phase = Phase::Failed;
        hw::set_bssid(&self.io, peer)?;
        hw::configure_rates(&self.io, rates, basic, capability, None, false, prime_sc)?;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `rtl_op_bss_info_changed(BSS_CHANGED_ASSOC)` for 8192EE:
    /// `rtl_cam_reset_all_entry`, `HW_VAR_KEEP_ALIVE` (10),
    /// `rtl92ee_set_network_type` with the link (MSR INFRA, CBSSID on),
    /// then `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_CONNECT)`
    /// ([`Self::ee92_join_report`]). The firmware RA mask follows
    /// separately (`ee92_install_rate_mask`, Linux's `update_rate_tbl`
    /// in the same branch).
    pub(super) async fn ee92_complete_peer(
        &mut self,
        peer: [u8; 6],
        aid: u16,
        admission: Option<&super::super::station::Admission>,
        policy: impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let closed = |a: Option<&super::super::station::Admission>| {
            a.is_some_and(|c| c.closed.load(core::sync::atomic::Ordering::Acquire))
        };
        if !self.transmit_ready() || self.packet.reserved.is_some() || self.packet.leisure {
            return Err(Error::State);
        }
        if !(1..=2007).contains(&aid) || peer == [0; 6] || peer[0] & 1 != 0 {
            return Err(Error::Packet);
        }
        self.phase = Phase::Failed;
        self.io.write32(hw::REG_CAMCMD, hw::CAM_RESET)?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.packet
            .ee92
            .mailbox
            .fill(&self.io, h2c::H2C_KEEP_ALIVE_CTRL, &[0xff, 10])
            .await?;
        hw::network_type_station(
            &self.io,
            &mut self.packet.ee92.receive,
            &mut self.packet.ee92.bcn_ctrl,
            true,
        )?;
        if closed(admission) {
            return Err(Error::State);
        }
        self.phase = Phase::Running;
        self.ee92_join_report(peer, aid, admission, &policy).await?;
        if closed(admission) {
            self.phase = Phase::Failed;
            return Err(Error::State);
        }
        Ok(())
    }

    /// `HW_VAR_FW_LPS_ACTION(true)` → `_rtl92ee_fwlps_enter`.
    pub(super) async fn ee92_enter_leisure(&mut self) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        h2c::fwlps_enter(&self.io, &mut self.packet.ee92.mailbox).await?;
        self.packet.leisure = true;
        self.phase = Phase::Running;
        Ok(())
    }

    /// `HW_VAR_FW_LPS_ACTION(false)` → `_rtl92ee_fwlps_leave`.
    pub(super) async fn ee92_leave_leisure(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Running || !self.packet.leisure {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        h2c::fwlps_leave(&self.io, &mut self.packet.ee92.mailbox).await?;
        self.packet.leisure = false;
        self.phase = Phase::Running;
        Ok(())
    }

    /// Disassociation registers and reports: leave LPS, then
    /// `rtl92ee_set_network_type(STATION)` without a link (MSR NOLINK,
    /// CBSSID off), `HW_VAR_H2C_FW_JOINBSSRPT(RT_MEDIA_DISCONNECT)` (MSRRPT
    /// only; AID and the reserved page are connect-only) and the mac80211
    /// `BSS_CHANGED_BSSID` zero BSSID. The installed RA link is withdrawn
    /// (no watchdog refresh without a station) and a pending RA report is
    /// dropped; `ratr_state` is kept, as Linux never resets it after
    /// `rtl92ee_dm_init_rate_adaptive_mask`.
    pub(super) async fn ee92_disconnected(&mut self) -> Result<(), Error> {
        if core::mem::take(&mut self.packet.leisure) {
            h2c::fwlps_leave(&self.io, &mut self.packet.ee92.mailbox).await?;
        }
        self.packet.ee92.link = None;
        self.packet.ee92.ra_report = None;
        self.packet.ee92.erp_timing = None;
        hw::network_type_station(
            &self.io,
            &mut self.packet.ee92.receive,
            &mut self.packet.ee92.bcn_ctrl,
            false,
        )?;
        self.packet
            .ee92
            .mailbox
            .fill(&self.io, h2c::H2C_MSRRPT, &h2c::media_status(false))
            .await?;
        hw::set_bssid(&self.io, [0; 6])
    }

    /// `rtl_pci_tx` for one frame: descriptor, BD, then the `TXBD_IDX`
    /// doorbell (`rtl92ee_set_desc(HW_DESC_OWN)`).
    ///
    /// `rtl_get_tcb_desc` + `rtl92ee_tx_fill_desc`: `adaptive` ordinary
    /// unicast DATA with an installed RA mask leaves USE_RATE and DISFB
    /// clear (`use_driver_rate = false` for every non-management frame,
    /// `disable_ratefallback` clear for a non-zero rix), so the firmware RA
    /// owns the rate inside the mask, from the initial `hw_rate` of
    /// `_rtl_get_highest_n_rate` (MCS15 for a 2T2R peer naming `rx_mask[1]`,
    /// else MCS7) or 11M (B) / 54M. Its RATE_ID is `_rtl_txrate_selectmode`
    /// with `dm.useramask` (`rtl92ee_dm_init_rate_adaptive_mask`, BYDRIVER)
    /// and no `RTL_SPEC_NEW_RATEID`: from `mac->mode` NGB (HT) / GB (G) / B
    /// (B), MACID 0. Special data ([`special_data`]: EAPOL, DHCP, ARP)
    /// is forced to `DESC_RATE11M` (`ra.is_special_data`). A (QoS) Null
    /// DATA frame with an installed RA mask clears USE_RATE with DISFB and
    /// `RATR_INX_WIRELESS_MC`, so the firmware RA picks its rate. Every
    /// other frame keeps the forced `rate` with USE_RATE, DISFB and
    /// `RATR_INX_WIRELESS_MC` (Linux clears USE_RATE for all non-management
    /// frames; here ordinary DATA leaves the driver rate only when the
    /// caller marks it adaptive, i.e. with an installed mask). The selected
    /// protection mode (`_rtl_query_protection_mode`) sets RTS_EN or
    /// CTS2SELF with `RTS_RATE = DESC_RATE24M`, independent of the RA; the
    /// RTS rate must be admitted too. On a `bw_40` link a packet
    /// above 54M to a unicast HT peer is a 40 MHz packet (`data_bw` 1, SC 3,
    /// `_rtl_query_bandwidth_mode`); every other packet names
    /// `cur_40_prime_sc`. `aggregate = (ampdu_density, operational)` sets
    /// the peer's density and, for an operational BA TID, AGG_EN with
    /// `max_agg_num 0x14`. `rtl92ee_tx_fill_desc` has no data SGI write
    /// (the RA mask's SGI bit selects it), so `short_gi` is only checked
    /// against the HT link. Every rate the descriptor can put on air (the
    /// forced/initial `hw_rate` and, via `ee92_install_rate_mask`, the RA
    /// mask) must be admitted by the current `N92E` permission.
    pub(super) fn ee92_submit(
        &mut self,
        frame: &[u8],
        rate: u8,
        aggregate: Option<(u8, bool)>,
        adaptive: bool,
        short_gi: bool,
    ) -> Result<u64, Error> {
        if self.phase != Phase::Running || self.packet.pending.is_some() {
            return Err(Error::State);
        }
        let ht = self.packet.ht;
        let highest = if ht {
            trx::DESC_RATEMCS15
        } else {
            trx::DESC_RATE54M
        };
        if !ht && (aggregate.is_some() || short_gi)
            || aggregate.is_some_and(|(density, _)| density > 7)
            || aggregate.is_some() && frame.first() != Some(&0x88)
            || rate > highest
        {
            return Err(Error::Packet);
        }
        let multicast_ra = frame.get(4).is_none_or(|b| b & 1 != 0);
        // `rtl_is_special_data` (EAPOL / DHCP / ARP) sets
        // `ra.is_special_data`, so `rtl92ee_tx_fill_desc` keeps USE_RATE
        // and forces `DESC_RATE11M`; `rtl_get_tcb_desc` gave it rix 0, so
        // DISFB and `RATR_INX_WIRELESS_MC` with it.
        let special = special_data(frame);
        let adaptive = adaptive && !special;
        let link = match self.packet.ee92.link {
            Some((peer, _, _)) if adaptive => {
                if multicast_ra || frame[0] & 0x0c != 0x08 || frame[0] & 0x40 != 0 {
                    return Err(Error::Packet);
                }
                Some(peer)
            }
            None if adaptive => return Err(Error::State),
            _ => None,
        };
        let hw_rate = match link {
            Some(peer) => match peer.ht {
                Some([_, two]) if two != 0 => trx::DESC_RATEMCS15,
                Some(_) => trx::DESC_RATEMCS0 + 7,
                None if peer.legacy <= 0xf => trx::DESC_RATE11M,
                None => trx::DESC_RATE54M,
            },
            None if special => trx::DESC_RATE11M,
            None => rate,
        };
        // `rtl_get_tcb_desc` for a (QoS) Null DATA frame: use_driver_rate,
        // DISFB and `RATR_INX_WIRELESS_MC`; `rtl92ee_tx_fill_desc` then
        // clears USE_RATE (not special data), so the firmware RA of MACID 0
        // picks the rate. Only with an installed RA mask, which
        // `ee92_install_rate_mask` bounds by the admitted rates; before it
        // the frame keeps the driver rate.
        let null_ra = !special
            && self.packet.ee92.link.is_some()
            && !multicast_ra
            && frame[0] & 0x0c == 0x08
            && matches!(frame[0] & 0xf0, 0x40 | 0xc0);
        // `_rtl_query_protection_mode`: RTS/CTS or CTS-to-self, both at
        // `RTL_RC_OFDM_RATE24M` with long preamble (`rts_use_shortpreamble`
        // false, so RTS_SHORT stays clear), RTS_SC 0, HW_RTS clear.
        let protection = match self.packet.protection {
            super::super::super::protection::Mode::None => 0,
            super::super::super::protection::Mode::RtsCts => 1,
            super::super::super::protection::Mode::CtsToSelf => 2,
        };
        let permission = self.rtl8192ee_power.ok_or(Error::State)?;
        if permission.admitted_rates() & (1u64 << hw_rate) == 0
            || protection != 0 && permission.admitted_rates() & (1u64 << trx::DESC_RATE24M) == 0
        {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        let rate_id = match link {
            Some(peer) if peer.ht.is_some() => RATR_INX_WIRELESS_NGB,
            Some(peer) if peer.legacy <= 0xf => RATR_INX_WIRELESS_B,
            Some(_) => RATR_INX_WIRELESS_GB,
            None => RATR_INX_WIRELESS_MC,
        };
        let bw40 = self.packet.width.is_some();
        let prime_sc = permission.operating().channel().map_or(0, |c| c.prime_sc);
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
        // rtl_get_tcb_desc `use_spe_rpt` for EAPOL and (QoS) Null frames:
        // rtl_set_tx_report's SPE_RPT + SW_DEFINE (`rtl_get_tx_report_sn`).
        let tx_report = super::ae::wants_report(frame).then(|| self.packet.ee92.reports.next_sn());
        let multicast = destination[0] & 1 != 0;
        let wide = bw40 && ht && !multicast && hw_rate > trx::DESC_RATE54M;
        let descriptor = trx::TxDesc::fill(&trx::TxParams {
            pkt_size: frame.len() as u16,
            queue_sel: selector,
            macid: 0,
            rate_id,
            hw_rate,
            use_driver_rate: link.is_none() && !null_ra,
            disable_fallback: link.is_none(),
            data_bw: u8::from(wide),
            sub_carrier: match (bw40, wide) {
                (true, true) => 3,
                (true, false) => prime_sc,
                _ => 0,
            },
            ampdu: aggregate.is_some_and(|(_, operational)| operational),
            ampdu_density: aggregate.map_or(0, |(density, _)| density),
            sec_type: 0,
            seq: u16::from_le_bytes([frame[22], frame[23]]) >> 4,
            multicast,
            protection,
            rts_rate: if protection != 0 {
                trx::DESC_RATE24M
            } else {
                0
            },
            tx_report,
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
        // `rtlphy->cck_high_power` for `_rtl92ee_query_rxphystatus`.
        let cck_highpwr = self
            .rtl8192ee
            .as_ref()
            .is_some_and(|state| state.1.phy.cck_high_power);
        // HT link (`packet.ht`, set at Configuring): MCS0-15 (2T2R RX) and
        // A-MPDU members (the station BA owner gates them) up to a
        // 7935-byte A-MSDU MPDU.
        let ht = self.packet.ht;
        let longest = if ht {
            26 + 16 + narf_wireless::amsdu::Limit::Ht7935.bytes() + 4
        } else {
            2304 + 4
        };
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
            let is_ht = (trx::DESC_RATEMCS0..=trx::DESC_RATEMCS15).contains(&status.rate);
            if !status.c2h
                && !status.crc
                && !status.icv
                && (!status.ampdu || ht)
                && (status.rate <= trx::DESC_RATE54M || ht && is_ht)
                && (24..=longest).contains(&length)
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
                    // `_rtl92ee_query_rxphystatus` `rx_pwdb_all` (the
                    // `rtl_process_phyinfo` sample) from the driver-info
                    // PHY status that precedes the frame.
                    let pwdb = if status.physt && status.drvinfo >= 8 {
                        let mut phy = [0u8; 8];
                        buffer.read_bytes(trx::RX_DESC_SIZE, &mut phy)?;
                        dm::rx_pwdb(&phy, status.rate <= trx::DESC_RATE11M, cck_highpwr)
                    } else {
                        None
                    };
                    // `rtl92ee_rx_query_desc` never sets `is_ht`,
                    // `rx_is40mhzpacket` or `is_short_gi` (the 8192EE RX
                    // status has no BW/SGI field; the PHY-status `sgi_en`/
                    // `rxsc` are not read by Linux): HT is the MCS rate, and
                    // nothing is gated on the width or GI.
                    packet = Some(Mpdu {
                        bytes,
                        channel,
                        ht: is_ht,
                        short_gi: false,
                        width40: false,
                        aggregated: status.ampdu,
                        pwdb,
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

    /// `rtl92ee_update_hal_rate_mask` (`update_rate_tbl`): the 2T2R
    /// `H2C_92E_RA_MASK` for `peer` at `level`, then
    /// `_rtl92ee_set_bcn_ctrl_reg(BIT(3), 0)`. The firmware RA may only pick
    /// rates whose power the owner's permission admits: a mask that is not
    /// a non-empty subset of `admitted` (full-order rate bits,
    /// [`h2c::mask_rates`]) is refused, never narrowed, so the Linux
    /// mask/`ratr_index` pair stays exact. Skipped in leisure power save
    /// (the watchdog does not run with `fw_current_inpsmode`).
    pub(super) async fn ee92_install_rate_mask(
        &mut self,
        peer: h2c::Peer,
        bw40: bool,
        level: u8,
        admitted: u32,
    ) -> Result<(), Error> {
        if !self.transmit_ready() || self.packet.leisure || self.packet.local.is_none() {
            return Err(Error::State);
        }
        let payload = h2c::rate_mask(&peer, bw40, level, true);
        let rates = h2c::mask_rates(&payload).ok_or(Error::Packet)?;
        if rates == 0 || rates & !admitted != 0 {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Policy,
            ));
        }
        self.phase = Phase::Failed;
        self.packet
            .ee92
            .mailbox
            .fill(&self.io, h2c::H2C_RA_MASK, &payload)
            .await?;
        h2c::set_bcn_ctrl(&self.io, &mut self.packet.ee92.bcn_ctrl, 1 << 3, 0)?;
        self.packet.ee92.link = Some((peer, bw40, payload[1] & 0x7f));
        self.phase = Phase::Running;
        Ok(())
    }

    /// The composed part of `rtl92ee_dm_watchdog` (only while the firmware
    /// is out of power save): `rtl92ee_dm_refresh_rate_adaptive_mask` —
    /// `_rtl92ee_dm_ra_state_check` on the smoothed `undec_sm_pwdb` and,
    /// on a level change, `update_rate_tbl(sta, ratr_state, true)` — then
    /// the pending C2H RA report's `rtl92ee_dm_dynamic_arfb_select`
    /// ([`Self::ee92_apply_ra_report`]). Returns whether the mask was
    /// refreshed. `use_ldpc`/`lower_rts_rate` are not consumed by this
    /// profile (no LDPC TX, no protection) and are not tracked.
    pub(super) async fn ee92_dm_watchdog(
        &mut self,
        undec_sm_pwdb: i64,
        admitted: u32,
    ) -> Result<bool, Error> {
        if self.phase != Phase::Running {
            return Err(Error::State);
        }
        if self.packet.leisure {
            return Ok(false);
        }
        let mut refreshed = false;
        if let Some((peer, bw40, _)) = self.packet.ee92.link {
            if let Some(state) = dm::ra_state(undec_sm_pwdb, self.packet.ee92.ratr_state) {
                self.ee92_install_rate_mask(peer, bw40, state, admitted)
                    .await?;
                self.packet.ee92.ratr_state = state;
                refreshed = true;
            }
        }
        self.ee92_apply_ra_report()?;
        Ok(refreshed)
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

    /// Admitted 8192EE operating point committed by
    /// [`Self::configure_rtl8192ee_channel`].
    pub fn rtl8192ee_permission(
        &self,
    ) -> Option<super::super::super::rtl8192ee::envelope::Permission> {
        self.rtl8192ee_power
    }

    /// RadioConfigured/ChannelConfigured/MacConfigured/Running →
    /// the same phase (ChannelConfigured from RadioConfigured):
    /// `rtl_op_config` channel switch at the wide channel with the
    /// envelope-admitted per-path TXAGC indices, then the 20/40 MHz
    /// bandwidth (`rtl8192ee/channel.rs::configure_admitted`). The
    /// permission must have been minted for this owner's factory identity.
    /// A station retune (MacConfigured/Running) keeps the packet phase; any
    /// I/O failure fails the owner.
    pub async fn configure_rtl8192ee_channel(
        &mut self,
        permission: super::super::super::rtl8192ee::envelope::Permission,
    ) -> Result<(), Error> {
        let resume = match self.phase {
            Phase::RadioConfigured | Phase::ChannelConfigured => Phase::ChannelConfigured,
            Phase::MacConfigured | Phase::Running => self.phase,
            _ => return Err(Error::State),
        };
        if self.chip != super::super::Chip::Rtl8192ee {
            return Err(Error::State);
        }
        if self.rtl8192ee.as_ref().map(|state| state.0) != Some(permission.identity()) {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Identity,
            ));
        }
        let mut state = self.rtl8192ee.take().ok_or(Error::State)?;
        self.phase = Phase::Failed;
        self.rtl8192ee_power = None;
        super::super::super::rtl8192ee::channel::configure_admitted(
            &self.io,
            &permission,
            &mut state.1.chnlval,
        )
        .await?;
        self.rtl8192ee = Some(state);
        self.rtl8192ee_power = Some(permission);
        self.packet.ee92.channel = Some(permission.channel());
        self.phase = resume;
        Ok(())
    }

    /// ChannelConfigured → MacConfigured: the station address
    /// (`configure_rtl8192ee` wrote `HW_VAR_ETHER_ADDR`) for the factory
    /// identity the channel permission was minted for. BT-coexist boards were
    /// refused by [`Self::configure_rtl8192ee`]. Packet DMA, CR gates and
    /// IRQs stay closed.
    pub fn configure_rtl8192ee_mac(
        &mut self,
        factory: &super::super::super::efuse::Factory,
    ) -> Result<(), Error> {
        if self.phase != Phase::ChannelConfigured || self.chip != super::super::Chip::Rtl8192ee {
            return Err(Error::State);
        }
        let identity = super::super::super::radio::factory_identity(factory);
        if self.rtl8192ee.as_ref().map(|state| state.0) != Some(identity)
            || self.rtl8192ee_power.map(|p| p.identity()) != Some(identity)
            || self.rtl8192ee_radio().is_none()
        {
            return Err(Error::Power(
                super::super::super::channel_power::Error::Identity,
            ));
        }
        self.packet.local = Some(factory.mac);
        self.phase = Phase::MacConfigured;
        Ok(())
    }
}
