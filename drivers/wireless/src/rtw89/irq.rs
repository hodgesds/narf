// SPDX-License-Identifier: GPL-2.0-or-later
//! AX PCIe interrupt delivery for the retained station owner.
//!
//! Mirrors Linux `rtw89/pci.c`:
//! - `rtw89_pci_config_intr_mask` (AX v0: RTL8852A/B and RTL8851B, the
//!   latter with the `B_AX_HS0ISR_IND_INT_EN_WKARND` workaround bit),
//! - `rtw89_pci_enable_intr` / `rtw89_pci_disable_intr`,
//! - `rtw89_pci_recognize_intrs` (read masked status, write-1-clear),
//! - `rtw89_pci_interrupt_handler` / `rtw89_pci_interrupt_threadfn` and
//!   `rtw89_pci_napi_poll` (`isr_clear_rpq` / `isr_clear_rxq` of
//!   `rtw89_pci_isr_ax`).
//!
//! Linux masks HIMR in the hard handler, recognizes in the threaded handler
//! and re-enables after NAPI drains RPQ/RXQ. Here the BAR belongs to the
//! retained async owner, so the hard handler only records the MSI and wakes
//! that owner's worker. The worker then performs the same disable →
//! recognize/clear → RPQ/RXQ poll → enable sequence. AX MSI is generated on
//! a new masked HISR assertion, so deferring the mask to the worker cannot
//! lose an event: status is cleared before rings are polled and any later
//! assertion raises a fresh message.
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

use super::mac::ChipId;
use super::power;

// Linux `pci.h` AX v0 interrupt registers.
pub(super) const R_AX_HIMR0: u32 = 0x01a0;
pub(super) const R_AX_HISR0: u32 = 0x01a4;
pub(super) const R_AX_PCIE_HIMR00: u32 = 0x10b0;
pub(super) const R_AX_PCIE_HISR00: u32 = 0x10b4;
pub(super) const R_AX_PCIE_HIMR10: u32 = 0x13b0;
pub(super) const R_AX_PCIE_HISR10: u32 = 0x13b4;

pub(super) const B_AX_WDT_TIMEOUT_INT_EN: u32 = 1 << 22;
pub(super) const B_AX_HALT_C2H_INT_EN: u32 = 1 << 21;
pub(super) const B_AX_HS0ISR_IND_INT_EN: u32 = 1 << 24;
pub(super) const B_AX_HS0ISR_IND_INT_EN_WKARND: u32 = 1 << 23;
pub(super) const B_AX_RPQBD_FULL_INT_EN: u32 = 1 << 20;
pub(super) const B_AX_RDU_INT_EN: u32 = 1 << 19;
pub(super) const B_AX_RXDMA_STUCK_INT_EN: u32 = 1 << 18;
pub(super) const B_AX_TXDMA_STUCK_INT_EN: u32 = 1 << 17;
pub(super) const B_AX_RPQDMA_INT_EN: u32 = 1 << 2;
pub(super) const B_AX_RXP1DMA_INT_EN: u32 = 1 << 1;
pub(super) const B_AX_RXDMA_INT_EN: u32 = 1 << 0;
pub(super) const B_AX_HC10ISR_IND_INT_EN: u32 = 1 << 28;

/// `rtw89_pci_isr_ax.isr_clear_rpq` data written to `R_AX_PCIE_HISR00`.
pub(super) const ISR_CLEAR_RPQ: u32 = B_AX_RPQDMA_INT_EN | B_AX_RPQBD_FULL_INT_EN;
/// `rtw89_pci_isr_ax.isr_clear_rxq` data written to `R_AX_PCIE_HISR00`.
pub(super) const ISR_CLEAR_RXQ: u32 = B_AX_RXP1DMA_INT_EN | B_AX_RXDMA_INT_EN | B_AX_RDU_INT_EN;

/// Register access needed by the interrupt programs.
pub(super) trait Regs {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error>;
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error>;
}
impl<T: power::Io> Regs for T {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        power::Io::read32(self, address)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        power::Io::write32(self, address, value)
    }
}

/// `rtwpci->{halt_c2h_intrs,intrs[2]}`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Mask {
    pub(super) halt_c2h: u32,
    pub(super) intrs: [u32; 2],
}
impl Mask {
    /// `rtw89_pci_config_intr_mask`. Only the AX v0 register layout is
    /// implemented; RTL8852C (`_v1`) and RTL8922A (`_v2`) use different
    /// indirect status registers and are rejected.
    pub(super) fn config(chip: ChipId, recovery: bool) -> Option<Self> {
        let hs0 = match chip {
            ChipId::Rtl8851B => B_AX_HS0ISR_IND_INT_EN_WKARND,
            ChipId::Rtl8852A | ChipId::Rtl8852B => B_AX_HS0ISR_IND_INT_EN,
            ChipId::Rtl8852C | ChipId::Rtl8922A => return None,
        };
        let halt_c2h = B_AX_HALT_C2H_INT_EN;
        Some(if recovery {
            Self {
                halt_c2h,
                intrs: [hs0, 0],
            }
        } else {
            Self {
                halt_c2h,
                intrs: [
                    B_AX_TXDMA_STUCK_INT_EN
                        | B_AX_RXDMA_INT_EN
                        | B_AX_RXP1DMA_INT_EN
                        | B_AX_RPQDMA_INT_EN
                        | B_AX_RXDMA_STUCK_INT_EN
                        | B_AX_RDU_INT_EN
                        | B_AX_RPQBD_FULL_INT_EN
                        | hs0,
                    B_AX_HC10ISR_IND_INT_EN,
                ],
            }
        })
    }
    /// `rtw89_pci_enable_intr`.
    pub(super) fn enable(&self, io: &mut impl Regs) -> Result<(), power::Error> {
        io.write32(R_AX_HIMR0, self.halt_c2h)?;
        io.write32(R_AX_PCIE_HIMR00, self.intrs[0])?;
        io.write32(R_AX_PCIE_HIMR10, self.intrs[1])
    }
    /// `rtw89_pci_disable_intr`.
    pub(super) fn disable(io: &mut impl Regs) -> Result<(), power::Error> {
        io.write32(R_AX_HIMR0, 0)?;
        io.write32(R_AX_PCIE_HIMR00, 0)?;
        io.write32(R_AX_PCIE_HIMR10, 0)
    }
    /// `rtw89_pci_recognize_intrs`: only enabled sources are reported and
    /// acknowledged; unrelated pending status is left for its owner.
    pub(super) fn recognize(&self, io: &mut impl Regs) -> Result<Isrs, power::Error> {
        let isrs = Isrs {
            halt_c2h: io.read32(R_AX_HISR0)? & self.halt_c2h,
            isrs: [
                io.read32(R_AX_PCIE_HISR00)? & self.intrs[0],
                io.read32(R_AX_PCIE_HISR10)? & self.intrs[1],
            ],
        };
        io.write32(R_AX_HISR0, isrs.halt_c2h)?;
        io.write32(R_AX_PCIE_HISR00, isrs.isrs[0])?;
        io.write32(R_AX_PCIE_HISR10, isrs.isrs[1])?;
        Ok(isrs)
    }
}

/// `struct rtw89_pci_isrs` for the AX v0 layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Isrs {
    pub(super) halt_c2h: u32,
    pub(super) isrs: [u32; 2],
}
impl Isrs {
    pub(super) fn events(&self) -> Events {
        Events {
            rx: self.isrs[0] & ISR_CLEAR_RXQ != 0,
            rpq: self.isrs[0] & ISR_CLEAR_RPQ != 0,
            rx_unavailable: self.isrs[0] & B_AX_RDU_INT_EN != 0,
            stuck: self.isrs[0] & (B_AX_TXDMA_STUCK_INT_EN | B_AX_RXDMA_STUCK_INT_EN) != 0,
            halt_c2h: self.halt_c2h & B_AX_HALT_C2H_INT_EN != 0,
            watchdog: self.halt_c2h & B_AX_WDT_TIMEOUT_INT_EN != 0,
        }
    }
}

/// Classified recognition result consumed by the station worker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Events {
    pub(super) rx: bool,
    pub(super) rpq: bool,
    pub(super) rx_unavailable: bool,
    pub(super) stuck: bool,
    /// `isr_halt_c2h`: firmware raised a system-error (SER) halt.
    pub(super) halt_c2h: bool,
    /// `isr_wdt_timeout`: `MAC_AX_ERR_L2_ERR_WDT_TIMEOUT_INT`.
    pub(super) watchdog: bool,
}
impl Events {
    /// Linux hands both to `rtw89_ser_notify`; the retained owner has no
    /// in-place SER L1 path, so either one terminates the current station.
    pub(super) fn fatal(&self) -> bool {
        self.halt_c2h || self.watchdog
    }
}

/// One wakeable interrupt line shared by the hard handler, software kicks
/// (TX enqueue) and the single station worker.
#[derive(Debug)]
pub(super) struct Line {
    raised: AtomicU64,
    delivered: AtomicU64,
    waker: IrqSafeSpinLock<Option<Waker>>,
}
impl Line {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            raised: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            waker: IrqSafeSpinLock::new(None),
        })
    }
    /// Record a source (hardware MSI or software kick) and wake the worker.
    pub(super) fn raise(&self) {
        self.raised.fetch_add(1, Ordering::AcqRel);
        let waker = self.waker.lock().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    fn hardware(&self) {
        self.delivered.fetch_add(1, Ordering::Relaxed);
        self.raise();
    }
    /// Count of hardware MSI deliveries on this line.
    pub(super) fn delivered(&self) -> u64 {
        self.delivered.load(Ordering::Relaxed)
    }
    pub(super) fn raised(&self) -> u64 {
        self.raised.load(Ordering::Acquire)
    }
    /// Wait for any raise after `seen`; returns the new raise count.
    pub(super) fn wait(&self, seen: u64) -> Wait<'_> {
        Wait { line: self, seen }
    }
}
pub(super) struct Wait<'a> {
    line: &'a Line,
    seen: u64,
}
impl Future for Wait<'_> {
    type Output = u64;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<u64> {
        let now = self.line.raised();
        if now != self.seen {
            return Poll::Ready(now);
        }
        *self.line.waker.lock() = Some(cx.waker().clone());
        // Recheck after publishing the waker; a raise between the first
        // load and the store would otherwise be lost.
        let now = self.line.raised();
        if now != self.seen {
            self.line.waker.lock().take();
            return Poll::Ready(now);
        }
        Poll::Pending
    }
}

/// Fixed handler slots: the cookie selects the line without any raw pointer
/// lifetime across the IRQ boundary.
const SLOTS: usize = 4;
static LINES: [IrqSafeSpinLock<Option<Arc<Line>>>; SLOTS] =
    [const { IrqSafeSpinLock::new(None) }; SLOTS];
const HANDLER: &str = "rtw89";

fn handler(cookie: u64) -> narf_interrupts::IrqStatus {
    let line = LINES
        .get(cookie as usize)
        .and_then(|slot| slot.lock().clone());
    match line {
        Some(line) => {
            line.hardware();
            narf_interrupts::IrqStatus::Handled
        }
        None => narf_interrupts::IrqStatus::None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Unsupported,
    NoSlot,
    NoVector,
    Msi,
}

/// Installed vector + handler slot, independent of the PCI MSI capability.
#[derive(Debug)]
pub(super) struct Vector {
    vector: u8,
    slot: usize,
}
impl Vector {
    pub(super) fn install(line: &Arc<Line>) -> Result<Self, Error> {
        let slot = LINES
            .iter()
            .position(|slot| {
                let mut slot = slot.lock();
                if slot.is_none() {
                    *slot = Some(line.clone());
                    true
                } else {
                    false
                }
            })
            .ok_or(Error::NoSlot)?;
        let vector = match narf_interrupts::vector::alloc() {
            Ok(vector) => vector,
            Err(_) => {
                *LINES[slot].lock() = None;
                return Err(Error::NoVector);
            }
        };
        narf_interrupts::install_handler_named(vector, HANDLER, slot as u64, handler);
        Ok(Self { vector, slot })
    }
    pub(super) fn number(&self) -> u8 {
        self.vector
    }
    /// Stop dispatch, drain an in-flight handler and return the vector.
    /// Only call once the device can no longer target this vector.
    pub(super) fn release(self) {
        narf_interrupts::disable_irq(self.vector);
        let _ = narf_interrupts::remove_handler(self.vector, HANDLER, self.slot as u64);
        narf_interrupts::synchronize_irq(self.vector);
        let _ = narf_interrupts::vector::free(self.vector);
        *LINES[self.slot].lock() = None;
    }
    /// The device may still target this vector: keep it reserved and masked
    /// for the rest of the boot, but detach the line.
    pub(super) fn quarantine(self) {
        narf_interrupts::disable_irq(self.vector);
        let _ = narf_interrupts::remove_handler(self.vector, HANDLER, self.slot as u64);
        narf_interrupts::synchronize_irq(self.vector);
        *LINES[self.slot].lock() = None;
    }
}

/// MSI delivery bound to the exact owned PCI function.
#[derive(Debug)]
pub(super) struct Binding {
    vector: Vector,
    msi: narf_bus::msi::MsiConfig,
    mask: Mask,
}
impl Binding {
    /// Linux `rtw89_pci_request_irq` (single MSI vector) plus
    /// `rtw89_chip_config_intr_mask(RTW89_PCI_INTR_MASK_RESET)`. HIMR stays
    /// zero until [`Binding::start`].
    pub(super) fn bind(
        chip: ChipId,
        device: &BusDevice,
        authority: &Cap<BusDeviceCap, Write>,
        line: &Arc<Line>,
    ) -> Result<Self, Error> {
        let mask = Mask::config(chip, false).ok_or(Error::Unsupported)?;
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
    pub(super) fn mask(&self) -> Mask {
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
    pub(super) fn service(&self, io: &mut impl Regs) -> Result<Isrs, power::Error> {
        Mask::disable(io)?;
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
        let _ = Mask::disable(io);
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

#[cfg(feature = "kernel-test")]
mod tests;
