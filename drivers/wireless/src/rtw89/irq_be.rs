// SPDX-License-Identifier: GPL-2.0-or-later
//! BE PCIe interrupt delivery for RTL8922A (`_v2` layout).
//!
//! Mirrors Linux `rtw89/pci.c`:
//! - `rtw89_pci_config_intr_mask_v2` (recovery / default / low-power),
//! - `rtw89_pci_enable_intr_v2` / `rtw89_pci_disable_intr_v2`,
//! - `rtw89_pci_recognize_intrs_v2` (gated read, write-1-clear ack).
//!
//! The v2 binding for 8922A is proven by `rtw89/rtw8922ae.c:68..71`
//! (torvalds/linux @ cbbddb6), which assigns exactly the `_v2`
//! functions. The `_v3` layout (newer BE parts: no HAXI read, RDU
//! status borrowed into `isrs[1]`) is deliberately NOT implemented
//! here — 8922A never binds it.
//!
//! Differences from the AX `irq::Mask`:
//! - Four mask values, not three: the indirect mask `ind` selects
//!   which indirect status registers are even read.
//! - `recognize` reads the HAXI status ONLY when the AXIDMA indirect
//!   bit is set, and the halt status ONLY when the HS0 indirect bit
//!   is set; the DMA status is always read. Acks write back only
//!   nonzero fields, except the indirect status, which is always
//!   written back.
//! - `disable` clears only the indirect enable and the DMA IMR, NOT
//!   the halt/HAXI enables — a faithful Linux asymmetry, not an
//!   oversight: re-enable restores all four from the mask.

use super::irq::Regs;
use super::power;

// Linux `reg.h` / `pci.h` BE v2 interrupt registers.
pub(super) const R_BE_HIMR0: u32 = 0x01a0;
pub(super) const R_BE_HISR0: u32 = 0x01a4;
pub(super) const R_BE_PCIE_HIMR0: u32 = 0x30b0;
pub(super) const R_BE_PCIE_HISR: u32 = 0x30b4;
pub(super) const R_BE_PCIE_DMA_IMR_0_V1: u32 = 0x30b8;
pub(super) const R_BE_PCIE_DMA_ISR: u32 = 0x30bc;
pub(super) const R_BE_HAXI_HIMR00: u32 = 0xb0b0;
pub(super) const R_BE_HAXI_HISR00: u32 = 0xb0b4;

/// `B_BE_HS0_IND_INT_EN0` (`pci.h:372`).
pub(super) const B_BE_HS0_IND_INT_EN0: u32 = 1 << 0;
/// `B_BE_HS1_IND_INT_EN0` (`pci.h:371`).
pub(super) const B_BE_HS1_IND_INT_EN0: u32 = 1 << 1;
/// `B_BE_HCI_AXIDMA_INT_EN0` (`pci.h:367`).
pub(super) const B_BE_HCI_AXIDMA_INT_EN0: u32 = 1 << 5;
/// `B_BE_HS0ISR_IND_INT` (`pci.h:387`).
pub(super) const B_BE_HS0ISR_IND_INT: u32 = 1 << 0;
/// `B_BE_HCI_AXIDMA_INT` (`pci.h:382`).
pub(super) const B_BE_HCI_AXIDMA_INT: u32 = 1 << 5;
/// `B_BE_HALT_C2H_INT_EN` (`reg.h:4482`).
pub(super) const B_BE_HALT_C2H_INT_EN: u32 = 1 << 21;
/// `B_BE_WDT_TIMEOUT_INT_EN` (`reg.h:4481`).
pub(super) const B_BE_WDT_TIMEOUT_INT_EN: u32 = 1 << 22;
/// `B_BE_RDU_CH0_INT_IMR_V1` (`pci.h:463`).
pub(super) const B_BE_RDU_CH0_INT_IMR_V1: u32 = 1 << 25;
/// `B_BE_RDU_CH1_INT_IMR_V1` (`pci.h:461`).
pub(super) const B_BE_RDU_CH1_INT_IMR_V1: u32 = 1 << 26;
/// `B_BE_PCIE_RX_RX0P2_IMR0_V1` (`pci.h:405`).
pub(super) const B_BE_PCIE_RX_RX0P2_IMR0_V1: u32 = 1 << 16;
/// `B_BE_PCIE_RX_RPQ0_IMR0_V1` (`pci.h:404`).
pub(super) const B_BE_PCIE_RX_RPQ0_IMR0_V1: u32 = 1 << 17;

/// `rtwpci->{ind_intrs, halt_c2h_intrs, intrs[2]}` for the v2 layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct MaskBe {
    pub(super) ind: u32,
    pub(super) halt_c2h: u32,
    pub(super) intrs: [u32; 2],
}

impl MaskBe {
    /// `rtw89_pci_config_intr_mask_v2` (`pci.c:4011..4022`).
    /// Recovery takes precedence over low-power, as in Linux
    /// (`under_recovery` is checked first).
    pub(super) fn config(recovery: bool, low_power: bool) -> Self {
        let halt_c2h = B_BE_HALT_C2H_INT_EN | B_BE_WDT_TIMEOUT_INT_EN;
        if recovery {
            return Self {
                ind: B_BE_HS0_IND_INT_EN0,
                halt_c2h,
                intrs: [0, 0],
            };
        }
        if low_power {
            return Self {
                ind: B_BE_HS0_IND_INT_EN0 | B_BE_HS1_IND_INT_EN0,
                halt_c2h,
                intrs: [0, B_BE_PCIE_RX_RX0P2_IMR0_V1 | B_BE_PCIE_RX_RPQ0_IMR0_V1],
            };
        }
        Self {
            ind: B_BE_HCI_AXIDMA_INT_EN0 | B_BE_HS0_IND_INT_EN0,
            halt_c2h,
            intrs: [
                B_BE_RDU_CH1_INT_IMR_V1 | B_BE_RDU_CH0_INT_IMR_V1,
                B_BE_PCIE_RX_RX0P2_IMR0_V1 | B_BE_PCIE_RX_RPQ0_IMR0_V1,
            ],
        }
    }

    /// `rtw89_pci_enable_intr_v2` (`pci.c:883..889`), in Linux's
    /// write order: halt, HAXI, DMA IMR, indirect.
    pub(super) fn enable(&self, io: &mut impl Regs) -> Result<(), power::Error> {
        io.write32(R_BE_HIMR0, self.halt_c2h)?;
        io.write32(R_BE_HAXI_HIMR00, self.intrs[0])?;
        io.write32(R_BE_PCIE_DMA_IMR_0_V1, self.intrs[1])?;
        io.write32(R_BE_PCIE_HIMR0, self.ind)
    }

    /// `rtw89_pci_disable_intr_v2` (`pci.c:893..897`): only the
    /// indirect enable and the DMA IMR are cleared. See the module
    /// docs for why the halt/HAXI enables are left alone.
    pub(super) fn disable(io: &mut impl Regs) -> Result<(), power::Error> {
        io.write32(R_BE_PCIE_HIMR0, 0)?;
        io.write32(R_BE_PCIE_DMA_IMR_0_V1, 0)
    }

    /// `rtw89_pci_recognize_intrs_v2` (`pci.c:809..828`).
    pub(super) fn recognize(&self, io: &mut impl Regs) -> Result<IsrsBe, power::Error> {
        let ind_isrs = io.read32(R_BE_PCIE_HISR)? & self.ind;
        let halt_c2h = if ind_isrs & B_BE_HS0ISR_IND_INT != 0 {
            io.read32(R_BE_HISR0)? & self.halt_c2h
        } else {
            0
        };
        let isr0 = if ind_isrs & B_BE_HCI_AXIDMA_INT != 0 {
            io.read32(R_BE_HAXI_HISR00)? & self.intrs[0]
        } else {
            0
        };
        let isr1 = io.read32(R_BE_PCIE_DMA_ISR)? & self.intrs[1];
        if halt_c2h != 0 {
            io.write32(R_BE_HISR0, halt_c2h)?;
        }
        if isr0 != 0 {
            io.write32(R_BE_HAXI_HISR00, isr0)?;
        }
        if isr1 != 0 {
            io.write32(R_BE_PCIE_DMA_ISR, isr1)?;
        }
        io.write32(R_BE_PCIE_HISR, ind_isrs)?;
        Ok(IsrsBe {
            ind: ind_isrs,
            halt_c2h,
            isrs: [isr0, isr1],
        })
    }
}

/// Recognized v2 interrupt sources, mirroring `irq::Isrs` plus the
/// indirect word (which the v2 handler reports to its caller).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct IsrsBe {
    pub(super) ind: u32,
    pub(super) halt_c2h: u32,
    pub(super) isrs: [u32; 2],
}
