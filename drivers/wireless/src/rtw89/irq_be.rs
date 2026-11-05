// SPDX-License-Identifier: GPL-2.0-or-later
//! BE PCIe interrupt delivery for RTL8922A (`_v2` layout).
//!
//! Mirrors Linux `rtw89/pci.c`:
//! - `rtw89_pci_config_intr_mask_v2` (recovery / default / low-power),
//! - `rtw89_pci_enable_intr_v2` / `rtw89_pci_disable_intr_v2`,
//! - `rtw89_pci_recognize_intrs_v2` (gated read, write-1-clear ack),
//! - `rtw89_pci_isr_be` (`pci_be.c:868`: which recognized sources
//!   the threaded handler and NAPI poll consume),
//! - `rtw89_pci_request_irq` + `rtw89_pci_ops_start` / `ops_stop`
//!   (`pci.c:4060`, `pci.c:1907`, `pci.c:1918`: one MSI vector,
//!   RESET mask at bind, mask enabled at start, disabled at stop).
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
//!
//! The `BindingBe` below is the BE mirror of AX `irq::Binding`: the
//! MSI vector + mask the admitted device arms so completions can
//! fire. The hard handler only records the MSI on the shared
//! [`super::irq::Line`]; the worker performs the same disable →
//! recognize/clear → RPQ/RXQ poll → enable sequence as AX.

use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};

use super::irq::{Error, Events, Line, Regs, Vector};
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

/// `B_BE_RDU_CH0_INT_V1` (`pci.h:499`): HAXI status bit for RX
/// descriptor-unavailable on channel 0. Linux `rtw89_pci_isr_be`
/// (`pci_be.c:868`) reads it as `isr_rdu` out of `isrs[0]`.
pub(super) const B_BE_RDU_CH0_INT_V1: u32 = 1 << 25;
/// `B_BE_RDU_CH1_INT_V1` (`pci.h:498`): same, channel 1.
pub(super) const B_BE_RDU_CH1_INT_V1: u32 = 1 << 26;
/// `B_BE_HALT_C2H_INT` (`reg.h:4509`): firmware system-error halt,
/// `isr_halt_c2h` of `rtw89_pci_isr_be`.
pub(super) const B_BE_HALT_C2H_INT: u32 = 1 << 21;
/// `B_BE_WDT_TIMEOUT_INT` (`reg.h:4508`): watchdog timeout,
/// `isr_wdt_timeout` of `rtw89_pci_isr_be`.
pub(super) const B_BE_WDT_TIMEOUT_INT: u32 = 1 << 22;
/// `B_BE_PCIE_RX_RPQ0_ISR_V1` (`pci.h:437`): DMA status bit NAPI
/// clears before polling the RPQ (`isr_clear_rpq`).
pub(super) const B_BE_PCIE_RX_RPQ0_ISR_V1: u32 = 1 << 17;
/// `B_BE_PCIE_RX_RX0P2_ISR_V1` (`pci.h:438`): DMA status bit NAPI
/// clears before polling the RXQ (`isr_clear_rxq`).
pub(super) const B_BE_PCIE_RX_RX0P2_ISR_V1: u32 = 1 << 16;

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

impl IsrsBe {
    /// Classify recognized sources the way Linux consumes them
    /// (`rtw89_pci_isr_be`, `pci_be.c:868`, read by the threaded
    /// handler `pci.c:951` and NAPI poll `pci.c:4517`):
    /// - `rx`: DMA RX0P2 bit — NAPI clears it before polling RXQ.
    /// - `rpq`: DMA RPQ0 bit — NAPI clears it before polling RPQ.
    /// - `rx_unavailable`: HAXI RDU CH0/CH1 bits — the threaded
    ///   handler's `isrs[0] & isr_rdu` branch.
    /// - `halt_c2h` / `watchdog`: halt-status bits — the threaded
    ///   handler's SER-notify branches; either one is fatal.
    /// - `stuck` is always false for BE: the v2 mask never enables
    ///   a TX/RXDMA-stuck source and the threaded handler never
    ///   reads one (unlike AX, whose mask enables both stuck bits).
    ///   `rtw89_pci_isr_be.isr_sps_ocp` is 0, so there is no SPS
    ///   OCP event either.
    pub(super) fn events(&self) -> Events {
        Events {
            rx: self.isrs[1] & B_BE_PCIE_RX_RX0P2_ISR_V1 != 0,
            rpq: self.isrs[1] & B_BE_PCIE_RX_RPQ0_ISR_V1 != 0,
            rx_unavailable: self.isrs[0] & (B_BE_RDU_CH1_INT_V1 | B_BE_RDU_CH0_INT_V1) != 0,
            stuck: false,
            halt_c2h: self.halt_c2h & B_BE_HALT_C2H_INT != 0,
            watchdog: self.halt_c2h & B_BE_WDT_TIMEOUT_INT != 0,
        }
    }
}

/// MSI delivery bound to the exact owned 8922A PCI function, the BE
/// mirror of AX `irq::Binding`.
#[derive(Debug)]
pub(super) struct BindingBe {
    vector: Vector,
    msi: narf_bus::msi::MsiConfig,
    mask: MaskBe,
}

impl BindingBe {
    /// Linux `rtw89_pci_request_irq` (single MSI vector) plus
    /// `rtw89_chip_config_intr_mask(RTW89_PCI_INTR_MASK_RESET)`.
    /// The RESET mask is the default (non-recovery, non-low-power)
    /// `MaskBe::config(false, false)`; HIMR stays zero until
    /// [`BindingBe::start`].
    pub(super) fn bind(
        device: &BusDevice,
        authority: &Cap<BusDeviceCap, Write>,
        line: &Arc<Line>,
    ) -> Result<Self, Error> {
        let mask = MaskBe::config(false, false);
        let mut msi = crate::rtw88::pci_park::invoke(authority, || {
            narf_bus::msi::enable_msi(authority, device, 1)
        })
        .map_err(|_| Error::Msi)?
        .map_err(|_| Error::Msi)?;
        let vector = Vector::install(line)?;
        let number = vector.number();
        let programmed = crate::rtw88::pci_park::invoke(authority, || {
            // SAFETY: the retained owner exclusively holds this function's
            // configuration space; the vector was reserved above.
            unsafe {
                narf_bus::msi::program_msi(&mut msi, 0, number)?;
                narf_bus::msi::enable(&msi)
            }
        });
        if !matches!(programmed, Ok(Ok(()))) {
            // A partially programmed message may still target the vector.
            let disabled = crate::rtw88::pci_park::invoke(authority, || {
                // SAFETY: same exclusive configuration owner.
                unsafe { narf_bus::msi::disable(&msi) }
            });
            if matches!(disabled, Ok(Ok(()))) {
                vector.release();
            } else {
                vector.quarantine();
            }
            return Err(Error::Msi);
        }
        Ok(Self { vector, msi, mask })
    }
    pub(super) fn mask(&self) -> MaskBe {
        self.mask
    }
    pub(super) fn vector(&self) -> u8 {
        self.vector.number()
    }
    /// `rtw89_pci_ops_start`: enable the interrupt mask.
    pub(super) fn start(&self, io: &mut impl Regs) -> Result<(), power::Error> {
        self.mask.enable(io)
    }
    /// Worker half of `rtw89_pci_interrupt_handler` + `threadfn`.
    pub(super) fn service(&self, io: &mut impl Regs) -> Result<IsrsBe, power::Error> {
        MaskBe::disable(io)?;
        self.mask.recognize(io)
    }
    /// `rtw89_pci_napi_poll` completion: re-enable after rings are drained.
    pub(super) fn rearm(&self, io: &mut impl Regs) -> Result<(), power::Error> {
        self.mask.enable(io)
    }
    /// `rtw89_pci_ops_stop` + `rtw89_pci_free_irq`: HIMR off, MSI off, then
    /// drain and return the vector. If the MSI capability cannot be proven
    /// disabled the vector is quarantined instead of recycled.
    pub(super) fn release(self, io: &mut impl Regs, authority: &Cap<BusDeviceCap, Write>) {
        let _ = MaskBe::disable(io);
        let disabled = crate::rtw88::pci_park::invoke(authority, || {
            // SAFETY: exclusive configuration owner of this function.
            unsafe { narf_bus::msi::disable(&self.msi) }
        });
        if matches!(disabled, Ok(Ok(()))) {
            self.vector.release();
        } else {
            self.vector.quarantine();
        }
    }
}
