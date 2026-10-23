// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AX DLE/HFC firmware-download configuration. No ring or PCI publication.
use super::fifo_regs::*;
use super::{
    mac::ChipId,
    power::{Error, Io},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    New,
    Configuring,
    Ready,
}
#[derive(Debug)]
pub struct Fifo {
    state: State,
}
impl Default for Fifo {
    fn default() -> Self {
        Self { state: State::New }
    }
}
struct Access<'a, I>(&'a mut I);
impl<I: Io> Access<'_, I> {
    fn read(&mut self, address: u32) -> Result<u32, Error> {
        let value = self.0.read32(address)?;
        if value == u32::MAX {
            Err(Error::Gone)
        } else {
            Ok(value)
        }
    }
    fn modify(&mut self, address: u32, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(address)?;
        self.0.write32(address, (old & !mask) | (value & mask))
    }
    fn set(&mut self, address: u32, mask: u32) -> Result<(), Error> {
        self.modify(address, mask, mask)
    }
    fn clear(&mut self, address: u32, mask: u32) -> Result<(), Error> {
        self.modify(address, mask, 0)
    }
    async fn ready(&mut self, address: u32, mask: u32) -> Result<(), Error> {
        let start = self.0.now_us();
        loop {
            if self.read(address)? & mask == mask {
                return Ok(());
            }
            if self.0.now_us().saturating_sub(start) >= 2000 {
                return Err(Error::Timeout);
            }
            self.0.delay_us(1).await;
        }
    }
}
impl Fifo {
    pub fn state(&self) -> State {
        self.state
    }
    /// # Safety
    /// Caller owns this powered AX device and serialized current register
    /// authority; PCI bus mastering is verified off, DMA is stopped/fenced and
    /// there are no concurrent firmware/ring/reset operations. A fresh Fifo may
    /// be constructed again only after an independently verified power reset.
    pub async unsafe fn prepare(&mut self, io: &mut impl Io, chip: ChipId) -> Result<(), Error> {
        if self.state != State::New {
            return Err(Error::Terminal);
        }
        let (wde_unlinked, ple_linked, ple_unlinked, wcpu_min, fifo_size) = match chip {
            ChipId::Rtl8852A => (4096, 64, 1472, 196, 458752),
            ChipId::Rtl8852B | ChipId::Rtl8851B => (1024, 64, 960, 48, 196608),
            ChipId::Rtl8852C => (2048, 2544, 16, 60, 458752),
            ChipId::Rtl8922A => return Err(Error::Unsupported),
        };
        if wde_unlinked * 64 + (ple_linked + ple_unlinked) * 128 != fifo_size {
            return Err(Error::Unsupported);
        }
        self.state = State::Configuring;
        let mut a = Access(io);
        // mac::hci_func_en_ax / dmac_func_pre_en_ax, not the old placeholder
        // mac_init masks. AX C has the internal HAXI function and stop layout.
        a.0.write32(
            R_AX_DMAC_FUNC_EN,
            B_AX_MAC_FUNC_EN
                | B_AX_DMAC_FUNC_EN
                | B_AX_DISPATCHER_EN
                | B_AX_PKT_BUF_EN
                | if chip == ChipId::Rtl8852C {
                    B_AX_H_AXIDMA_EN
                } else {
                    0
                },
        )?;
        a.0.write32(
            R_AX_DMAC_CLK_EN,
            B_AX_DISPATCHER_CLK_EN
                | if chip == ChipId::Rtl8851B {
                    B_AX_AXIDMA_CLK_EN
                } else {
                    0
                },
        )?;
        if chip == ChipId::Rtl8852C {
            a.modify(
                R_AX_HAXI_INIT_CFG1,
                B_AX_DMA_MODE_MASK | B_AX_STOP_AXI_MST | B_AX_TXHCI_EN_V1 | B_AX_RXHCI_EN_V1,
                B_AX_TXHCI_EN_V1 | B_AX_RXHCI_EN_V1,
            )?;
            a.clear(
                R_AX_HAXI_DMA_STOP1,
                B_AX_STOP_ACH0
                    | B_AX_STOP_ACH1
                    | B_AX_STOP_ACH2
                    | B_AX_STOP_ACH3
                    | B_AX_STOP_ACH4
                    | B_AX_STOP_ACH5
                    | B_AX_STOP_ACH6
                    | B_AX_STOP_ACH7
                    | B_AX_STOP_CH8
                    | B_AX_STOP_CH9
                    | B_AX_STOP_CH12,
            )?;
            a.clear(R_AX_HAXI_DMA_STOP2, B_AX_STOP_CH10 | B_AX_STOP_CH11)?;
            a.set(R_AX_PLATFORM_ENABLE, B_AX_AXIDMA_EN)?;
        }
        // RTW89_QTA_DLFW. The extended SCC WCPU minimum is deliberately
        // retained even though the DLFW WDE links and maximum are zero.
        a.clear(R_AX_DMAC_FUNC_EN, B_AX_DLE_WDE_EN | B_AX_DLE_PLE_EN)?;
        a.set(
            R_AX_DMAC_CLK_EN,
            B_AX_DLE_WDE_CLK_EN
                | B_AX_DLE_PLE_CLK_EN
                | if chip == ChipId::Rtl8851B {
                    B_AX_AXIDMA_CLK_EN
                } else {
                    0
                },
        )?;
        a.modify(
            R_AX_WDE_PKTBUF_CFG,
            B_AX_WDE_PAGE_SEL_MASK | B_AX_WDE_START_BOUND_MASK | B_AX_WDE_FREE_PAGE_NUM_MASK,
            0,
        )?;
        let ple = (1 << B_AX_PLE_PAGE_SEL_MASK.trailing_zeros())
            | ((wde_unlinked * 64 / 8192) << B_AX_PLE_START_BOUND_MASK.trailing_zeros())
            | (ple_linked << B_AX_PLE_FREE_PAGE_NUM_MASK.trailing_zeros());
        a.modify(
            R_AX_PLE_PKTBUF_CFG,
            B_AX_PLE_PAGE_SEL_MASK | B_AX_PLE_START_BOUND_MASK | B_AX_PLE_FREE_PAGE_NUM_MASK,
            ple,
        )?;
        for (address, minimum) in [
            (R_AX_WDE_QTA0_CFG, 0),
            (R_AX_WDE_QTA1_CFG, wcpu_min),
            (R_AX_WDE_QTA3_CFG, 0),
            (R_AX_WDE_QTA4_CFG, 0),
        ] {
            a.0.write32(address, minimum << B_AX_WDE_MIN_SIZE_MASK.trailing_zeros())?;
        }
        let quotas = [
            0,
            0,
            if chip == ChipId::Rtl8852C {
                32 << 16 | 16
            } else {
                16 << 16 | 16
            },
            if chip == ChipId::Rtl8852C {
                256 << 16 | 256
            } else {
                48 << 16 | 48
            },
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for (index, value) in
            quotas
                .iter()
                .enumerate()
                .take(if chip == ChipId::Rtl8852C { 12 } else { 11 })
        {
            a.0.write32(R_AX_PLE_QTA0_CFG + index as u32 * 4, *value)?;
        }
        a.set(R_AX_DMAC_FUNC_EN, B_AX_DLE_WDE_EN | B_AX_DLE_PLE_EN)?;
        a.ready(R_AX_WDE_INI_STATUS, WDE_MGN_INI_RDY).await?;
        a.ready(R_AX_PLE_INI_STATUS, PLE_MGN_INI_RDY).await?;
        // HFC DLFW only: normal packet flow stays disabled, CH12 precost40.
        let (hfc_ctrl, ch_page_ctrl) = if chip == ChipId::Rtl8852C {
            (R_AX_HCI_FC_CTRL_V1, R_AX_CH_PAGE_CTRL_V1)
        } else {
            (R_AX_HCI_FC_CTRL, R_AX_CH_PAGE_CTRL)
        };
        a.clear(hfc_ctrl, B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN)?;
        a.0.write32(
            ch_page_ctrl,
            40 << B_AX_PREC_PAGE_CH12_MASK.trailing_zeros(),
        )?;
        a.clear(hfc_ctrl, B_AX_HCI_FC_CH12_FULL_COND_MASK)?;
        a.modify(
            hfc_ctrl,
            B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN,
            B_AX_HCI_FC_CH12_EN,
        )?;
        self.state = State::Ready;
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "fifo_tests.rs"]
mod tests;
