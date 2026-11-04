// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B reversible Wake-on-WLAN TRX halt and restart.
//!
//! Linux 7.3-rc4 `wow.c::{rtw89_wow_enable_trx_pre,rtw89_wow_enable_trx_post,
//! rtw89_wow_disable_trx_pre,rtw89_wow_disable_trx_post}` composed from
//! `pci.c::{rtw89_pci_ctrl_txdma_ch_ax,rtw89_pci_ctrl_txdma_fw_ch_ax,
//! rtw89_pci_poll_txdma_ch_idle_ax,rtw89_pci_ctrl_dma_trx,
//! rtw89_pci_reset_trx_rings,rtw89_pci_clr_idx_all_ax,rtw89_pci_rst_bdram_ax}`
//! and `mac.c::{rtw89_mac_ptk_drop_by_band_and_wait,mac_is_txq_empty_ax,
//! rtw89_mac_dle_dfi_cfg,rtw89_mac_typ_fltr_opt_ax,
//! rtw89_mac_cfg_ppdu_status_ax,rtw89_wow_config_mac_ax,
//! rtw89_mac_resize_ple_rx_quota}` with the `rtw8852be.c` PCI info.
//!
//! Unlike the terminal [`super::dma_stop`] proof this never clears PCI bus
//! mastering and never releases a mapping: the device keeps every published
//! ring base while the WoW firmware runs, and the host ring indices are
//! rewound exactly as `rtw89_pci_ops_reset` rewinds `bd_ring->wp/rp`.
//!
//! Deliberate differences, all failing closed into the caller's cold path:
//! - `ptk_drop_by_band_and_wait` sends `H2C_PKT_DROP` when the WDE queues
//!   stay busy; NARF requires a transmit-quiet owner before the halt, so a
//!   busy queue after the 50 ms window is [`Error::Queue`].
//! - `ctrl_txdma_ch(true)` on resume opens all of `B_AX_TX_STOP1_MASK_V1`;
//!   NARF publishes only a subset of the channels and re-opens exactly the
//!   channels that were open before the halt.
//! - `rtw89_wow_config_mac(false)` writes the init-time forwarding and
//!   PPDU-status defaults; NARF restores the values it observed before the
//!   halt (the same registers, programmed by `mac_runtime`/`track`).
//! - CPU IO RX: every admitted RTL8852B image is older than 0.29.30.0, so
//!   `NO_WOW_CPU_IO_RX` holds (`fw.c` feature table) and neither the
//!   `WOW_CPUIO_RX_CTRL` H2C register message nor `R_BE_DBG_WOW_READY` is
//!   used; the caller must pass that fact as [`CpuIoRx::Absent`].
use super::{
    dma::{RxRingRegs, TxRingRegs},
    power::{self, Io},
};

/// `R_AX_PCIE_INIT_CFG1`.
pub(super) const INIT_CFG1: u32 = 0x1000;
/// `B_AX_RST_BDRAM`.
pub(super) const RST_BDRAM: u32 = 1 << 3;
/// `B_AX_TXHCI_EN | B_AX_RXHCI_EN` (`rtw89_pci_ctrl_dma_trx`).
pub(super) const HCI_EN: u32 = 1 << 11 | 1 << 13;
/// `R_AX_PCIE_DMA_STOP1`.
pub(super) const STOP1: u32 = 0x1010;
/// `B_AX_TX_STOP1_MASK_V1`: ACH0..3, CH8, CH9, CH12.
pub(super) const TX_STOP1_MASK_V1: u32 = 0x0007_0f00;
/// `B_AX_STOP_CH12`.
pub(super) const STOP_CH12: u32 = 1 << 18;
/// `R_AX_TXBD_RWPTR_CLR1` and the RTL8852B `clr_idx_all` mask
/// (ACH0..3, CH8, CH9, CH12).
pub(super) const TXBD_RWPTR_CLR1: u32 = 0x1014;
pub(super) const CLR_TX_IDX: u32 = 0xf | 1 << 8 | 1 << 9 | 1 << 10;
/// `R_AX_RXBD_RWPTR_CLR`: `B_AX_CLR_RXQ_IDX | B_AX_CLR_RPQ_IDX`.
pub(super) const RXBD_RWPTR_CLR: u32 = 0x1018;
pub(super) const CLR_RX_IDX: u32 = 3;
/// RTL8852C `rtw89_pci_clr_idx_all_ax` (rtw8852ce.c `rtw8852c_pci_info`):
/// ACH4..7 join `R_AX_TXBD_RWPTR_CLR1`, CH10/CH11 clear through
/// `txbd_rwptr_clr2_reg` = `R_AX_TXBD_RWPTR_CLR2_V1`, and RXQ/RPQ through
/// `rxbd_rwptr_clr_reg` = `R_AX_RXBD_RWPTR_CLR_V1`.
pub(super) const C_CLR_TX_IDX: u32 = 0x7ff;
pub(super) const C_TXBD_RWPTR_CLR2: u32 = 0x11c4;
pub(super) const C_RXBD_RWPTR_CLR: u32 = 0x1200;
/// One chip's `rtw89_pci_clr_idx_all_ax` registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Rewind {
    tx_clr1: u32,
    tx_clr2: Option<u32>,
    rx_clr: u32,
}
impl Rewind {
    pub(super) const B: Self = Self {
        tx_clr1: CLR_TX_IDX,
        tx_clr2: None,
        rx_clr: RXBD_RWPTR_CLR,
    };
    pub(super) const C: Self = Self {
        tx_clr1: C_CLR_TX_IDX,
        tx_clr2: Some(C_TXBD_RWPTR_CLR2),
        rx_clr: C_RXBD_RWPTR_CLR,
    };
    pub(super) fn for_chip(chip: super::mac::ChipId) -> Option<Self> {
        match chip {
            super::mac::ChipId::Rtl8852B => Some(Self::B),
            super::mac::ChipId::Rtl8852C => Some(Self::C),
            _ => None,
        }
    }
    /// `rtw89_pci_clr_idx_all_ax`: TX CLR1, CLR2 (CH10/CH11) when present,
    /// then RX, each `rtw89_write32_set`.
    fn clear(self, a: &mut Access<'_, impl Io>) -> Result<(), Error> {
        a.modify(TXBD_RWPTR_CLR1, 0, self.tx_clr1)?;
        if let Some(clr2) = self.tx_clr2 {
            a.modify(clr2, 0, 3)?;
        }
        a.modify(self.rx_clr, 0, CLR_RX_IDX)
    }
}
/// `R_AX_PCIE_DMA_BUSY1` with `DMA_BUSY1_CHECK_V1`.
pub(super) const BUSY1: u32 = 0x101c;
pub(super) const TX_BUSY: u32 = 0x0007_0f00;
/// `R_AX_WDE_DBG_FUN_INTF_CTL`/`_DATA`, `B_AX_WDE_DFI_ACTIVE`,
/// `DLE_DFI_TYPE_QEMPTY` (target in bits 19:16).
pub(super) const WDE_DFI_CTL: u32 = 0x8d10;
pub(super) const WDE_DFI_DATA: u32 = 0x8d14;
pub(super) const DFI_ACTIVE: u32 = 1 << 31;
pub(super) const DFI_QEMPTY: u32 = 7 << 16;
/// RTL8852B `wde_qempty_acq_grpnum` / `wde_qempty_mgq_grpsel`.
pub(super) const ACQ_GROUPS: u32 = 4;
pub(super) const MGQ_GROUP: u32 = 4;
/// `B_CMAC0_MGQ_NORMAL | B_CMAC0_MGQ_NO_PWRSAV | B_CMAC0_CPUMGQ`.
pub(super) const MGQ_EMPTY: u32 = 1 << 2 | 1 << 3 | 1 << 4;
/// `R_AX_DLE_EMPTY0` and the `mac_is_txq_empty_ax` mask (WDE/PLE quota and
/// queue empty bits 7..10 and 16..26).
pub(super) const DLE_EMPTY0: u32 = 0x8430;
pub(super) const DLE_EMPTY_MASK: u32 = 0x07ff_0780;
/// `R_AX_{CTRL,MGNT,DATA}_FLTR` (band 0) and `RX_FLTR_FRAME_{DROP,TO_HOST}`.
pub(super) const CTRL_FLTR: u32 = 0xce24;
pub(super) const MGNT_FLTR: u32 = 0xce28;
pub(super) const DATA_FLTR: u32 = 0xce2c;
pub(super) const FLTR_DROP: u32 = 0;
pub(super) const FLTR_TO_HOST: u32 = 0x5555_5555;
/// `R_AX_RX_FLTR_OPT` (`mac->rx_fltr`) and `B_AX_SNIFFER_MODE`.
pub(super) const RX_FLTR_OPT: u32 = 0xce20;
pub(super) const SNIFFER_MODE: u32 = 1;
/// `R_AX_PPDU_STAT` and `B_AX_PPDU_STAT_RPT_EN`.
pub(super) const PPDU_STAT: u32 = 0xce40;
pub(super) const PPDU_STAT_RPT_EN: u32 = 1;
/// `R_AX_RX_FUNCTION_STOP` / `B_AX_HDR_RX_STOP`.
pub(super) const RX_FUNCTION_STOP: u32 = 0x8920;
pub(super) const HDR_RX_STOP: u32 = 1;
/// `R_AX_ACTION_FWD0`, `R_AX_ACTION_FWD1`, `R_AX_TF_FWD`, `R_AX_HW_RPT_FWD`.
pub(super) const ACTION_FWD0: u32 = 0x9c04;
pub(super) const ACTION_FWD1: u32 = 0x9c08;
pub(super) const TF_FWD: u32 = 0x9c14;
pub(super) const HW_RPT_FWD: u32 = 0x9c18;
/// `R_AX_PLE_QTA6_CFG` / `R_AX_PLE_QTA7_CFG` (`cma0_dma`, `cma1_dma`).
pub(super) const PLE_QTA6: u32 = 0x9058;
pub(super) const PLE_QTA7: u32 = 0x905c;
/// `ple_qt18` minimum with `ple_qt58` (SCC) / `ple_qt_52b_wow` (WOW) maxima.
pub(super) const QTA6_SCC: u32 = 229 << 16 | 89;
pub(super) const QTA6_WOW: u32 = 133 << 16 | 89;
/// TX channels of `rtw89_bd_ram_table_single` that RTL8852B does not mask
/// out (`tx_dma_ch_mask`), with their (start, max, min) BD-RAM partition.
pub(super) const BDRAM: [(usize, u32); 7] = [
    (0, 5 << 8 | 2 << 16),
    (1, 5 | 5 << 8 | 2 << 16),
    (2, 10 | 5 << 8 | 2 << 16),
    (3, 15 | 5 << 8 | 2 << 16),
    (8, 20 | 4 << 8 | 1 << 16),
    (9, 24 | 4 << 8 | 1 << 16),
    (12, 28 | 4 << 8 | 1 << 16),
];
/// `read_poll_timeout(.., 10, 100, ..)` on the TX DMA busy register.
const IDLE_POLL_US: u64 = 10;
const IDLE_TIMEOUT_US: u64 = 100;
/// `read_poll_timeout(mac->is_txq_empty, .., 50, 50000, ..)`.
const QUEUE_POLL_US: u64 = 50;
const QUEUE_TIMEOUT_US: u64 = 50_000;
/// `rtw89_mac_dle_dfi_cfg`: 1 us, 1000 us.
const DFI_POLL_US: u64 = 1;
const DFI_TIMEOUT_US: u64 = 1000;
/// `RTW89_PCI_POLL_BDRAM_RST_CNT` with a 1 us interval.
const BDRAM_POLL_US: u64 = 1;
const BDRAM_TIMEOUT_US: u64 = 100;
const INDEX_MASK: u32 = 0x0fff_0fff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    /// A precondition register does not hold the awake station value.
    State,
    /// A write did not read back.
    Ignored,
    /// `rtw89_err(.., "txdma ch busy\n")`.
    TxBusy,
    /// The WDE/PLE TX queues did not drain (Linux would `H2C_PKT_DROP`).
    Queue,
    /// `"reset bdram busy"` or a DLE DFI timeout.
    Timeout,
    /// A ring index did not clear on resume.
    Index,
    /// Firmware needs `WOW_CPUIO_RX_CTRL`, which is not ported.
    Unsupported,
}
impl From<power::Error> for Error {
    fn from(error: power::Error) -> Self {
        Self::Register(error)
    }
}

/// `RTW89_CHK_FW_FEATURE(NO_WOW_CPU_IO_RX, ..)`, derived by the caller from
/// the verified running image's version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CpuIoRx {
    /// RTL8852B firmware older than 0.29.30.0.
    Absent,
    Required,
}
impl CpuIoRx {
    /// `__CFG_FW_FEAT(RTL8852B, lt, 0, 29, 30, 0, NO_WOW_CPU_IO_RX)`.
    pub(super) fn for_8852b(version: [u8; 4]) -> Self {
        if version < [0, 29, 30, 0] {
            Self::Absent
        } else {
            Self::Required
        }
    }
}

/// One ring this owner published, re-written by `rtw89_pci_reset_trx_rings`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ring {
    Tx {
        channel: usize,
        regs: TxRingRegs,
        address: u64,
        depth: u16,
    },
    Rx {
        regs: RxRingRegs,
        address: u64,
        depth: u16,
    },
}
impl Ring {
    fn index(&self) -> u32 {
        match self {
            Self::Tx { regs, .. } => regs.idx as u32,
            Self::Rx { regs, .. } => regs.idx as u32,
        }
    }
}

/// Awake-station register values observed before the halt; restored on
/// resume so the halt is reversible. Not `Clone`: one per WoW window.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    stop1: u32,
    filters: [u32; 3],
    rx_fltr_opt: u32,
    ppdu_stat: u32,
    hw_rpt_fwd: u32,
    action_fwd: [u32; 2],
    tf_fwd: u32,
}
impl Snapshot {
    /// Channels of `B_AX_TX_STOP1_MASK_V1` that were open while awake.
    pub(super) fn open_channels(&self) -> u32 {
        !self.stop1 & TX_STOP1_MASK_V1
    }
}

struct Access<'a, I>(&'a mut I);
impl<I: Io> Access<'_, I> {
    fn read(&mut self, address: u32) -> Result<u32, Error> {
        match self.0.read32(address)? {
            u32::MAX => Err(power::Error::Gone.into()),
            value => Ok(value),
        }
    }
    fn write(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.0.write32(address, value)?;
        Ok(())
    }
    fn set_check(&mut self, address: u32, value: u32) -> Result<(), Error> {
        self.write(address, value)?;
        if self.read(address)? != value {
            return Err(Error::Ignored);
        }
        Ok(())
    }
    fn modify(&mut self, address: u32, clear: u32, set: u32) -> Result<(), Error> {
        let value = self.read(address)?;
        self.write(address, (value & !clear) | set)
    }
    async fn poll<T>(
        &mut self,
        interval: u64,
        timeout: u64,
        failure: Error,
        mut done: impl FnMut(&mut Self) -> Result<Option<T>, Error>,
    ) -> Result<T, Error> {
        let start = self.0.now_us();
        loop {
            if let Some(value) = done(self)? {
                return Ok(value);
            }
            if self.0.now_us().saturating_sub(start) >= timeout {
                return Err(failure);
            }
            self.0.delay_us(interval).await;
        }
    }
    /// `rtw89_pci_poll_txdma_ch_idle_ax` (no `dma_busy2` on RTL8852B).
    async fn tx_idle(&mut self) -> Result<(), Error> {
        self.poll(IDLE_POLL_US, IDLE_TIMEOUT_US, Error::TxBusy, |a| {
            Ok((a.read(BUSY1)? & TX_BUSY == 0).then_some(()))
        })
        .await
    }
    /// `rtw89_mac_dle_dfi_qempty_cfg` for one WDE group.
    async fn qempty(&mut self, group: u32) -> Result<u32, Error> {
        self.write(WDE_DFI_CTL, DFI_QEMPTY | group | DFI_ACTIVE)?;
        self.poll(DFI_POLL_US, DFI_TIMEOUT_US, Error::Timeout, |a| {
            Ok((a.read(WDE_DFI_CTL)? & DFI_ACTIVE == 0).then_some(()))
        })
        .await?;
        // The data word is a bitmap; all-ones is a legitimate value here.
        Ok(self.0.read32(WDE_DFI_DATA)?)
    }
    /// `mac_is_txq_empty_ax` (single band, no DBCC).
    async fn txq_empty(&mut self) -> Result<bool, Error> {
        for group in 0..ACQ_GROUPS {
            // Eight MAC IDs per group, each a 4-bit QSEL-empty nibble.
            if self.qempty(group).await? != u32::MAX {
                return Ok(false);
            }
        }
        if self.qempty(MGQ_GROUP).await? & MGQ_EMPTY != MGQ_EMPTY {
            return Ok(false);
        }
        Ok(self.read(DLE_EMPTY0)? & DLE_EMPTY_MASK == DLE_EMPTY_MASK)
    }
    /// `rtw89_wow_set_rx_filter` (`typ_fltr_opt` for MGNT, CTRL, DATA).
    fn filters(&mut self, value: [u32; 3]) -> Result<(), Error> {
        for (address, value) in [MGNT_FLTR, CTRL_FLTR, DATA_FLTR]
            .into_iter()
            .zip([value[1], value[0], value[2]])
        {
            self.set_check(address, value)?;
        }
        Ok(())
    }
}

/// `rtw89_wow_enable_trx_pre`. The caller has already stopped and retired
/// every host TX producer and holds the IRQ binding; CH12 stays open for the
/// firmware swap.
pub(super) async fn enter_pre(io: &mut impl Io) -> Result<Snapshot, Error> {
    let mut a = Access(io);
    let snapshot = Snapshot {
        stop1: a.read(STOP1)?,
        filters: [a.read(CTRL_FLTR)?, a.read(MGNT_FLTR)?, a.read(DATA_FLTR)?],
        rx_fltr_opt: a.read(RX_FLTR_OPT)?,
        ppdu_stat: a.read(PPDU_STAT)?,
        hw_rpt_fwd: a.read(HW_RPT_FWD)?,
        action_fwd: [a.read(ACTION_FWD0)?, a.read(ACTION_FWD1)?],
        tf_fwd: a.read(TF_FWD)?,
    };
    // Awake SCC station: HCI on, CH12 open, header RX running, SCC quota.
    if snapshot.stop1 & STOP_CH12 != 0
        || a.read(INIT_CFG1)? & HCI_EN != HCI_EN
        || a.read(RX_FUNCTION_STOP)? & HDR_RX_STOP != 0
        || a.read(PLE_QTA6)? != QTA6_SCC
        || a.0.read32(PLE_QTA7)? != 0
    {
        return Err(Error::State);
    }
    // rtw89_hci_ctrl_txdma_ch(false) then rtw89_hci_ctrl_txdma_fw_ch(true).
    a.modify(STOP1, 0, TX_STOP1_MASK_V1)?;
    a.modify(STOP1, STOP_CH12, 0)?;
    if a.read(STOP1)? & TX_STOP1_MASK_V1 != TX_STOP1_MASK_V1 & !STOP_CH12 {
        return Err(Error::Ignored);
    }
    // rtw89_mac_ptk_drop_by_band_and_wait: one 50 ms window, no PKT_DROP.
    let start = a.0.now_us();
    loop {
        if a.txq_empty().await? {
            break;
        }
        if a.0.now_us().saturating_sub(start) >= QUEUE_TIMEOUT_US {
            return Err(Error::Queue);
        }
        a.0.delay_us(QUEUE_POLL_US).await;
    }
    a.tx_idle().await?;
    a.filters([FLTR_DROP; 3])?;
    // rtw89_mac_cfg_ppdu_status_ax(.., false).
    a.modify(PPDU_STAT, PPDU_STAT_RPT_EN, 0)?;
    Ok(snapshot)
}

/// `rtw89_wow_enable_trx_post` after the WoW firmware started; the caller
/// has masked the HCI interrupts (`rtw89_hci_disable_intr`) and rewound the
/// host side of every ring in `rings` (`rtw89_pci_ops_reset`).
pub(super) async fn enter_post(
    io: &mut impl Io,
    cpu_io_rx: CpuIoRx,
    rings: &[Ring],
) -> Result<(), Error> {
    if cpu_io_rx != CpuIoRx::Absent {
        return Err(Error::Unsupported);
    }
    let mut a = Access(io);
    a.modify(INIT_CFG1, HCI_EN, 0)?;
    if a.read(INIT_CFG1)? & HCI_EN != 0 {
        return Err(Error::Ignored);
    }
    a.tx_idle().await?;
    // rtw89_wow_config_mac_ax(true) up to the NO_WOW_CPU_IO_RX return.
    a.set_check(PLE_QTA6, QTA6_WOW)?;
    a.set_check(PLE_QTA7, 0)?;
    a.modify(RX_FUNCTION_STOP, 0, HDR_RX_STOP)?;
    a.modify(RX_FLTR_OPT, SNIFFER_MODE, 0)?;
    a.modify(PPDU_STAT, PPDU_STAT_RPT_EN, 0)?;
    for address in [ACTION_FWD0, ACTION_FWD1, TF_FWD, HW_RPT_FWD] {
        a.set_check(address, 0)?;
    }
    a.filters([FLTR_TO_HOST; 3])?;
    reset_trx_rings(&mut a, rings)
}

/// `rtw89_pci_reset_trx_rings` for RTL8852B (no group BD address, RX ring
/// not "eq is full", no 16-select write pointer). Unpublished channels get
/// only their BD-RAM partition, exactly as the bring-up `bdram` owner did.
fn reset_trx_rings(a: &mut Access<'_, impl Io>, rings: &[Ring]) -> Result<(), Error> {
    for (channel, partition) in BDRAM {
        let published = rings.iter().find_map(|ring| match *ring {
            Ring::Tx {
                channel: c,
                regs,
                address,
                depth,
            } if c == channel => Some((regs, address, depth)),
            _ => None,
        });
        let regs = super::dma::addr_set_for_chip(super::mac::ChipId::Rtl8852B).tx[channel];
        if let Some((published, _, depth)) = published {
            if published != regs {
                return Err(Error::State);
            }
            a.0.write16(regs.num as u32, depth)?;
        }
        a.set_check(regs.bdram as u32, partition)?;
        if let Some((_, address, depth)) = published {
            a.write(regs.desa_l as u32, address as u32)?;
            a.write(regs.desa_h as u32, (address >> 32) as u32)?;
            if a.0.read16(regs.num as u32)? & 0x0fff != depth
                || a.read(regs.desa_l as u32)? != address as u32
                || a.0.read32(regs.desa_h as u32)? != (address >> 32) as u32
            {
                return Err(Error::Ignored);
            }
        }
    }
    for ring in rings {
        let Ring::Rx {
            regs,
            address,
            depth,
        } = *ring
        else {
            continue;
        };
        a.0.write16(regs.num as u32, depth)?;
        a.write(regs.desa_l as u32, address as u32)?;
        a.write(regs.desa_h as u32, (address >> 32) as u32)?;
        if a.0.read16(regs.num as u32)? != depth
            || a.read(regs.desa_l as u32)? != address as u32
            || a.0.read32(regs.desa_h as u32)? != (address >> 32) as u32
        {
            return Err(Error::Ignored);
        }
    }
    Ok(())
}

/// `rtw89_wow_disable_trx_pre` up to (not including) the AOAC report and
/// `rtw89_hci_enable_intr`, which the caller owns. Leaves the HCI enabled,
/// the pre-halt channels open and every published ring index proven zero.
pub(super) async fn leave_pre(
    io: &mut impl Io,
    snapshot: &Snapshot,
    rings: &[Ring],
    rewind: Rewind,
) -> Result<(), Error> {
    let mut a = Access(io);
    // rtw89_pci_clr_idx_all_ax.
    rewind.clear(&mut a)?;
    // rtw89_pci_rst_bdram_ax.
    a.modify(INIT_CFG1, 0, RST_BDRAM)?;
    a.poll(BDRAM_POLL_US, BDRAM_TIMEOUT_US, Error::Timeout, |a| {
        Ok((a.read(INIT_CFG1)? & RST_BDRAM == 0).then_some(()))
    })
    .await?;
    // rtw89_hci_ctrl_trxhci(true), then ctrl_txdma_ch(true) limited to the
    // channels that were open while awake.
    a.modify(INIT_CFG1, 0, HCI_EN)?;
    a.modify(STOP1, TX_STOP1_MASK_V1, snapshot.stop1 & TX_STOP1_MASK_V1)?;
    if a.read(INIT_CFG1)? & HCI_EN != HCI_EN
        || a.read(STOP1)? & TX_STOP1_MASK_V1 != snapshot.stop1 & TX_STOP1_MASK_V1
    {
        return Err(Error::Ignored);
    }
    // rtw89_wow_config_mac_ax(false): SCC quota, header RX, then the awake
    // forwarding/PPDU values (NO_WOW_CPU_IO_RX: no CPU IO RX message).
    a.set_check(PLE_QTA6, QTA6_SCC)?;
    a.set_check(PLE_QTA7, 0)?;
    a.modify(RX_FUNCTION_STOP, HDR_RX_STOP, 0)?;
    a.set_check(ACTION_FWD0, snapshot.action_fwd[0])?;
    a.set_check(ACTION_FWD1, snapshot.action_fwd[1])?;
    a.set_check(TF_FWD, snapshot.tf_fwd)?;
    a.set_check(HW_RPT_FWD, snapshot.hw_rpt_fwd)?;
    a.set_check(RX_FLTR_OPT, snapshot.rx_fltr_opt)?;
    if a.read(RX_FUNCTION_STOP)? & HDR_RX_STOP != 0 {
        return Err(Error::Ignored);
    }
    for ring in rings {
        if a.read(ring.index())? & INDEX_MASK != 0 {
            return Err(Error::Index);
        }
    }
    Ok(())
}

/// `rtw89_wow_disable_trx_post`: `rtw89_mac_cfg_ppdu_status(.., true)` as
/// the awake owner had it, and the awake RX filters. NARF never enables the
/// firmware beacon filter, so `rtw89_fw_h2c_set_bcn_fltr_cfg` has no state
/// to restore.
pub(super) fn leave_post(io: &mut impl Io, snapshot: Snapshot) -> Result<(), Error> {
    let mut a = Access(io);
    a.set_check(PPDU_STAT, snapshot.ppdu_stat)?;
    a.filters(snapshot.filters)
}

#[cfg(feature = "kernel-test")]
#[path = "wow_trx/tests.rs"]
mod tests;
