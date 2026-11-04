// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B HCI DMA-stop proof for published-DMA reclamation.
//!
//! Linux v7.2 `pci.c::rtw89_pci_ops_mac_pre_init_ax` stops every engine with
//! bus mastering still on: `STOP_WPDMA`, then `rtw89_pci_ctrl_dma_all(false)`
//! (`B_AX_STOP_PCIEIO` plus INIT_CFG1 `TXHCI_EN`/`RXHCI_EN` clear), then
//! `rtw89_pci_poll_dma_all_idle` (`rtw89_pci_poll_txdma_ch_idle_ax` on
//! `dma_busy1` and `rtw89_pci_poll_rxdma_ch_idle_ax` on `dma_busy3`, each a
//! `read_poll_timeout(.., 10, 100, ..)`). This module adds the full TX stop
//! mask (`rtw89_pci_ctrl_txdma_ch_ax(false)`), the HCI_FUNC_EN DMA clear of
//! `rtw89_mac_ctrl_hci_dma_trx(false)` and RXQ/RPQ stop, then clears BME.
//! After verified BME-off, non-posted BAR reads order behind any earlier
//! device-originated posted write, so idle engines read back at that point
//! prove no outstanding access to host memory. Only that yields [`Idle`].
//!
//! RTL8852C ([`Layout::C`]) follows rtw8852ce.c `rtw8852c_pci_info`: the
//! HAXI block (`dma_stop1` = `R_AX_HAXI_DMA_STOP1` with `B_AX_TX_STOP1_MASK`
//! incl. ACH4..7, `dma_stop2` = `R_AX_HAXI_DMA_STOP2` CH10/CH11, `dma_io_stop`
//! = INIT_CFG1 `B_AX_STOP_AXI_MST`, `B_AX_TXHCI_EN_V1`/`B_AX_RXHCI_EN_V1`,
//! `R_AX_HCI_FUNC_EN_V1`, `dma_busy1` `DMA_BUSY1_CHECK`, `dma_busy2_reg`
//! CH10/CH11 and `dma_busy3_reg` RXQ/RPQ). HAXI_DMA_STOP1 has no RXQ/RPQ
//! stop bits; C RX closes through the HCI enables alone.
use super::{mac::ChipId, power};

/// `R_AX_PCIE_DMA_STOP1`.
pub(super) const STOP1: u32 = 0x1010;
/// `R_AX_PCIE_DMA_BUSY1` (`dma_busy1` and `dma_busy3_reg` on RTL8852BE).
pub(super) const BUSY1: u32 = 0x101c;
/// `R_AX_PCIE_INIT_CFG1`.
pub(super) const INIT_CFG1: u32 = 0x1000;
/// `R_AX_HCI_FUNC_EN` (`B_AX_HCI_TXDMA_EN | B_AX_HCI_RXDMA_EN`).
pub(super) const HCI_FUNC_EN: u32 = 0x8380;
/// `B_AX_STOP_PCIEIO | B_AX_STOP_WPDMA | B_AX_TX_STOP1_MASK_V1 |
/// B_AX_STOP_RPQ | B_AX_STOP_RXQ`.
pub(super) const STOPPED: u32 = 1 << 20 | 1 << 19 | TX_BUSY | RX_BUSY;
/// `B_AX_TXHCI_EN | B_AX_RXHCI_EN`.
pub(super) const HCI_EN: u32 = 1 << 11 | 1 << 13;
const HCI_DMA: u32 = 3;
/// `DMA_BUSY1_CHECK_V1`: ACH0..3, CH8, CH9, CH12 (same bit layout as the
/// `B_AX_TX_STOP1_MASK_V1` stop bits).
pub(super) const TX_BUSY: u32 = 0x0007_0f00;
/// `B_AX_RXQ_BUSY | B_AX_RPQ_BUSY`.
pub(super) const RX_BUSY: u32 = 3;
/// One chip's `rtw89_pci_info` DMA stop/busy registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Layout {
    /// Bits set in `dma_stop1` (0x1010).
    stop1: u32,
    /// `dma_stop2` register and mask, when the chip has CH10/CH11.
    stop2: Option<(u32, u32)>,
    /// `init_cfg_reg` bits cleared (HCI enables) and set (`dma_io_stop`).
    init_clear: u32,
    init_set: u32,
    /// `R_AX_HCI_FUNC_EN{,_V1}`.
    hci_func_en: u32,
    /// `dma_busy1` mask (register [`BUSY1`]).
    busy1: u32,
    /// `dma_busy2_reg` with CH10/CH11, when present.
    busy2: Option<(u32, u32)>,
    /// `dma_busy3_reg` with RXQ/RPQ.
    busy3: (u32, u32),
}
impl Layout {
    /// rtw8852be.c `rtw8852b_pci_info` (unchanged RTL8852B proof).
    pub(super) const B: Self = Self {
        stop1: STOPPED,
        stop2: None,
        init_clear: HCI_EN,
        init_set: 0,
        hci_func_en: HCI_FUNC_EN,
        busy1: TX_BUSY,
        busy2: None,
        busy3: (BUSY1, RX_BUSY),
    };
    /// rtw8852ce.c `rtw8852c_pci_info`.
    pub(super) const C: Self = Self {
        stop1: C_STOPPED,
        stop2: Some((C_STOP2, 3)),
        init_clear: C_HCI_EN,
        init_set: C_STOP_AXI_MST,
        hci_func_en: C_HCI_FUNC_EN,
        busy1: C_TX_BUSY,
        busy2: Some((C_BUSY2, 3)),
        busy3: (C_BUSY3, RX_BUSY),
    };
    pub(super) fn for_chip(chip: ChipId) -> Option<Self> {
        match chip {
            ChipId::Rtl8852B => Some(Self::B),
            ChipId::Rtl8852C => Some(Self::C),
            _ => None,
        }
    }
}
/// `B_AX_STOP_WPDMA | B_AX_TX_STOP1_MASK` (`R_AX_HAXI_DMA_STOP1`).
pub(super) const C_STOPPED: u32 = 1 << 19 | C_TX_BUSY;
/// `B_AX_TX_STOP1_MASK` / `DMA_BUSY1_CHECK`: ACH0..7, CH8, CH9, CH12.
pub(super) const C_TX_BUSY: u32 = 0x0007_ff00;
/// `R_AX_HAXI_DMA_STOP2` (`B_AX_TX_STOP2_ALL`).
pub(super) const C_STOP2: u32 = 0x11c0;
/// `B_AX_TXHCI_EN_V1 | B_AX_RXHCI_EN_V1`.
pub(super) const C_HCI_EN: u32 = 1 << 7 | 1 << 15;
/// `B_AX_STOP_AXI_MST` (`dma_io_stop`).
pub(super) const C_STOP_AXI_MST: u32 = 1 << 17;
/// `R_AX_HCI_FUNC_EN_V1`.
pub(super) const C_HCI_FUNC_EN: u32 = 0x7880;
/// `R_AX_HAXI_DMA_BUSY2` / `R_AX_HAXI_DMA_BUSY3`.
pub(super) const C_BUSY2: u32 = 0x11c8;
pub(super) const C_BUSY3: u32 = 0x1208;
/// `read_poll_timeout(rtw89_read32, .., 10, 100, ..)`.
const POLL_US: u64 = 10;
const POLLS: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Register(power::Error),
    /// A stop/HCI write did not read back.
    Ignored,
    /// `rtw89_err(.., "txdma ch busy\n")`.
    TxBusy,
    /// `rtw89_err(.., "rxdma ch busy\n")`.
    RxBusy,
    /// Bus mastering is still enabled (or unreadable).
    Master,
    /// Reclamation without a terminal-closure proof.
    Unproven,
}
impl From<power::Error> for Error {
    fn from(error: power::Error) -> Self {
        Self::Register(error)
    }
}
/// BAR and config access for one exclusively owned RTL8852B function. Every
/// operation must invoke the current device capability.
pub(super) trait Port {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error>;
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error>;
    /// PCI COMMAND `BUS_MASTER`; an all-ones read is `Gone`.
    fn bus_master(&mut self) -> Result<bool, power::Error>;
    fn clear_bus_master(&mut self) -> Result<(), power::Error>;
    /// Linux `udelay` between busy polls.
    fn delay_us(&mut self, us: u64) {
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(us));
    }
}
/// Proof that every RTL8852B HCI DMA engine was stopped and observed idle
/// with bus mastering off. Not `Clone`; only [`stop`] constructs it.
#[derive(Debug)]
pub(super) struct Idle {
    _private: (),
}
impl Idle {
    /// Inert-RAM fixtures only: there was never a device or DMA producer.
    #[cfg(feature = "kernel-test")]
    pub(super) fn inert() -> Self {
        Self { _private: () }
    }
}
fn read(port: &mut impl Port, address: u32) -> Result<u32, Error> {
    match port.read32(address)? {
        u32::MAX => Err(power::Error::Gone.into()),
        value => Ok(value),
    }
}
fn modify(port: &mut impl Port, address: u32, clear: u32, set: u32) -> Result<(), Error> {
    let value = read(port, address)?;
    port.write32(address, (value & !clear) | set)?;
    Ok(())
}
fn closed(port: &mut impl Port, layout: Layout) -> Result<(), Error> {
    if read(port, STOP1)? & layout.stop1 != layout.stop1
        || layout
            .stop2
            .map(|(address, mask)| read(port, address).map(|value| value & mask != mask))
            .transpose()?
            .unwrap_or(false)
        || read(port, INIT_CFG1)? & (layout.init_clear | layout.init_set) != layout.init_set
        || read(port, layout.hci_func_en)? & HCI_DMA != 0
    {
        return Err(Error::Ignored);
    }
    Ok(())
}
fn poll(port: &mut impl Port, address: u32, mask: u32, busy: Error) -> Result<(), Error> {
    for attempt in 0..=POLLS {
        if attempt != 0 {
            port.delay_us(POLL_US);
        }
        if read(port, address)? & mask == 0 {
            return Ok(());
        }
    }
    Err(busy)
}
/// RTL8852B [`stop_with`].
pub(super) fn stop(port: &mut impl Port) -> Result<Idle, Error> {
    stop_with(port, Layout::B)
}
/// Close and observe; BME is cleared even when an earlier step failed, as in
/// the existing terminal closure. Any failure keeps every mapping pinned.
pub(super) fn stop_with(port: &mut impl Port, layout: Layout) -> Result<Idle, Error> {
    let stop = modify(port, STOP1, 0, layout.stop1);
    let stop2 = layout
        .stop2
        .map_or(Ok(()), |(address, mask)| modify(port, address, 0, mask));
    let hci = modify(port, INIT_CFG1, layout.init_clear, layout.init_set);
    let dma = modify(port, layout.hci_func_en, HCI_DMA, 0);
    let idle = stop
        .and(stop2)
        .and(hci)
        .and(dma)
        .and_then(|()| closed(port, layout))
        .and_then(|()| poll(port, BUSY1, layout.busy1, Error::TxBusy))
        .and_then(|()| {
            layout.busy2.map_or(Ok(()), |(address, mask)| {
                poll(port, address, mask, Error::TxBusy)
            })
        })
        .and_then(|()| poll(port, layout.busy3.0, layout.busy3.1, Error::RxBusy));
    let master = port.clear_bus_master();
    idle?;
    master?;
    verify_with(port, layout)?;
    Ok(Idle { _private: () })
}
/// RTL8852B [`verify_with`].
pub(super) fn verify(port: &mut impl Port) -> Result<(), Error> {
    verify_with(port, Layout::B)
}
/// Flushing re-check behind verified BME-off. Reclamation repeats it under
/// its own current invocation immediately before releasing storage.
pub(super) fn verify_with(port: &mut impl Port, layout: Layout) -> Result<(), Error> {
    if port.bus_master()? {
        return Err(Error::Master);
    }
    closed(port, layout)?;
    let busy = read(port, BUSY1)?;
    if busy & layout.busy1 != 0 {
        return Err(Error::TxBusy);
    }
    if let Some((address, mask)) = layout.busy2 {
        if read(port, address)? & mask != 0 {
            return Err(Error::TxBusy);
        }
    }
    // RTL8852B reads RXQ/RPQ busy from the same BUSY1 word.
    let rx = if layout.busy3.0 == BUSY1 {
        busy
    } else {
        read(port, layout.busy3.0)?
    };
    if rx & layout.busy3.1 != 0 {
        return Err(Error::RxBusy);
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "dma_stop/tests.rs"]
pub(super) mod tests;
