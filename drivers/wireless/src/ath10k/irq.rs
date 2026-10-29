// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2005-2011 Atheros Communications Inc.
 * Copyright (c) 2011-2017 Qualcomm Atheros, Inc.
 * Copyright (c) 2018 The Linux Foundation. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
//! Copy-engine / firmware interrupt service for the PCIe owner.
//!
//! Linux references (v6.10): `pci.c::{ath10k_pci_interrupt_handler,
//! ath10k_pci_napi_poll, ath10k_pci_irq_pending,
//! ath10k_pci_disable_and_clear_intx_irq, ath10k_pci_enable_intx_irq,
//! ath10k_pci_irq_msi_fw_mask, ath10k_pci_irq_msi_fw_unmask,
//! ath10k_pci_has_fw_crashed, ath10k_pci_fw_crashed_clear,
//! ath10k_pci_irq_disable, ath10k_pci_irq_enable}`,
//! `ce.c::{ath10k_ce_per_engine_service_any, ath10k_ce_per_engine_service,
//! ath10k_ce_enable_interrupts, ath10k_ce_disable_interrupts}`,
//! `ce.h::ath10k_ce_interrupt_summary` and the `hw.c` register tables.
//!
//! Linux masks the PCIe line and firmware MSI in the hard handler and
//! schedules NAPI. Here the BAR belongs to the retained async owner, so the
//! vector handler only raises a [`Signal`]. The owner's next service performs
//! the same sequence the hard handler + NAPI poll would: firmware-crash check
//! first, then mask/clear, per-CE status clear, ring service, and re-enable
//! only when the CE summary is empty (otherwise it reschedules itself).
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;

use super::ce::Ath10kMmio;
use super::hw::{ce_off, HwRev, FW_IND_EVENT_PENDING};

/// `hw.h` `CORE_CTRL_ADDRESS` within the SoC core block.
const CORE_CTRL: u64 = 0x0000;
/// `hw.h` `CORE_CTRL_PCIE_REG_31_MASK`: firmware-to-host MSI gate.
pub(super) const CORE_CTRL_PCIE_REG_31: u32 = 0x0000_0800;
/// `hw.h` `PCIE_INTR_ENABLE_ADDRESS` / `PCIE_INTR_CAUSE_ADDRESS`.
const PCIE_INTR_ENABLE: u64 = 0x0008;
const PCIE_INTR_CAUSE: u64 = 0x000c;
/// `hw.c::qcax_wm_reg`: HOST_IS address, copy-complete and watermark bits.
const HOST_IS: u64 = 0x0030;
pub(super) const HOST_IS_COPY_COMPLETE: u32 = 0x0000_0001;
pub(super) const HOST_IS_WATERMARK: u32 = 0x0000_001e;
/// `hw.c::qcax_misc_reg.err_mask`.
pub(super) const MISC_IS_ERRORS: u32 = 0x0000_07e0;
/// `ce.h` `CE_WRAPPER_INTERRUPT_SUMMARY_ADDRESS`.
const CE_WRAPPER_SUMMARY: u64 = 0x0000;

/// Per-family PCIe interrupt registers (`hw.c::qca988x_regs`,
/// `qca6174_regs`, `qca99x0_regs`; QCA9887 uses the QCA988X map and
/// QCA9888/QCA9984 the QCA99X0 map in `core.c::ath10k_hw_params_list`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Program {
    pub soc_core: u64,
    pub ce_wrapper: u64,
    pub ce0: u64,
    pub ce_count: u8,
    pub fw_indicator: u64,
    pub intr_clear: u64,
    pub fw_mask: u32,
    pub ce_mask_all: u32,
    pub summary_lsb: u32,
    pub summary_mask: u32,
    /// `ath10k_pci_irq_msi_fw_{mask,unmask}` only program CORE_CTRL on
    /// QCA988X/QCA9887/QCA6174/QCA9377; Linux leaves QCA99X0-class as TODO.
    pub fw_msi_gate: bool,
}

/// Outcome of the NAPI-equivalent service prologue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Service {
    /// `ath10k_pci_has_fw_crashed`: FW_IND_EVENT_PENDING was set and cleared.
    Crashed,
    /// Summary bitmap of CE status that was cleared before ring service.
    Engines(u32),
}

impl Program {
    pub const fn for_hw(hw: HwRev) -> Option<Self> {
        let Some(regs) = hw.registers() else {
            return None;
        };
        Some(match hw {
            HwRev::Qca988x | HwRev::Qca9887 => Self {
                soc_core: regs.soc_core,
                ce_wrapper: 0x0005_7000,
                ce0: regs.ce0,
                ce_count: regs.ce_count,
                fw_indicator: regs.fw_indicator,
                intr_clear: 0x14,
                fw_mask: 0x0000_0400,
                ce_mask_all: 0x0007_f800,
                summary_lsb: 8,
                summary_mask: 0x0000_ff00,
                fw_msi_gate: true,
            },
            HwRev::Qca6174 | HwRev::Qca9377 => Self {
                soc_core: regs.soc_core,
                ce_wrapper: 0x0003_4000,
                ce0: regs.ce0,
                ce_count: regs.ce_count,
                fw_indicator: regs.fw_indicator,
                intr_clear: 0x14,
                fw_mask: 0x0000_0400,
                ce_mask_all: 0x0007_f800,
                summary_lsb: 8,
                summary_mask: 0x0000_ff00,
                fw_msi_gate: true,
            },
            HwRev::Qca99x0 | HwRev::Qca9888 | HwRev::Qca9984 => Self {
                soc_core: regs.soc_core,
                ce_wrapper: 0x0004_d000,
                ce0: regs.ce0,
                ce_count: regs.ce_count,
                fw_indicator: regs.fw_indicator,
                intr_clear: 0x10,
                fw_mask: 0x0010_0000,
                ce_mask_all: 0x000f_ff00,
                summary_lsb: 12,
                summary_mask: 0x00ff_f000,
                fw_msi_gate: false,
            },
            HwRev::Ar9462Legacy => return None,
        })
    }
    fn ce(self, pipe: u8) -> u64 {
        self.ce0 + pipe as u64 * 0x400
    }
    fn line_mask(self) -> u32 {
        self.fw_mask | self.ce_mask_all
    }
    /// `ath10k_pci_irq_pending`: INTx sharing check.
    pub fn pending(self, io: &mut impl Ath10kMmio) -> bool {
        let cause = io.read32(self.soc_core + PCIE_INTR_CAUSE);
        cause != u32::MAX && cause & self.line_mask() != 0
    }
    /// `ath10k_pci_disable_and_clear_intx_irq` + `ath10k_pci_irq_msi_fw_mask`
    /// (the hard-handler half, deferred to the owner).
    pub fn mask(self, io: &mut impl Ath10kMmio) {
        io.write32(self.soc_core + PCIE_INTR_ENABLE, 0);
        io.write32(self.soc_core + self.intr_clear, self.line_mask());
        // IMPORTANT: Linux reads back to flush the posted writes.
        let _ = io.read32(self.soc_core + PCIE_INTR_ENABLE);
        if self.fw_msi_gate {
            let control = io.read32(self.soc_core + CORE_CTRL);
            io.write32(self.soc_core + CORE_CTRL, control & !CORE_CTRL_PCIE_REG_31);
        }
    }
    /// `ath10k_pci_enable_intx_irq` + `ath10k_pci_irq_msi_fw_unmask`.
    pub fn unmask(self, io: &mut impl Ath10kMmio) {
        io.write32(self.soc_core + PCIE_INTR_ENABLE, self.line_mask());
        let _ = io.read32(self.soc_core + PCIE_INTR_ENABLE);
        if self.fw_msi_gate {
            let control = io.read32(self.soc_core + CORE_CTRL);
            io.write32(self.soc_core + CORE_CTRL, control | CORE_CTRL_PCIE_REG_31);
        }
    }
    /// `ath10k_pci_irq_disable`: every CE's copy-complete, error and
    /// watermark enables, then the PCIe line and firmware MSI gate.
    pub fn disable(self, io: &mut impl Ath10kMmio) {
        for pipe in 0..self.ce_count {
            let base = self.ce(pipe);
            let host = io.read32(base + ce_off::HOST_IE);
            io.write32(
                base + ce_off::HOST_IE,
                host & !(HOST_IS_COPY_COMPLETE | HOST_IS_WATERMARK),
            );
            let misc = io.read32(base + ce_off::MISC_IE);
            io.write32(base + ce_off::MISC_IE, misc & !MISC_IS_ERRORS);
        }
        self.mask(io);
    }
    /// `ath10k_pci_irq_enable`: `ath10k_ce_per_engine_handler_adjust` on
    /// every engine (copy-complete only for engines with a host callback and
    /// no `CE_ATTR_DIS_INTR`; watermark always off), then line + firmware.
    pub fn enable(self, io: &mut impl Ath10kMmio, serviced: &[u8]) {
        for pipe in 0..self.ce_count {
            let base = self.ce(pipe);
            let host = io.read32(base + ce_off::HOST_IE) & !HOST_IS_WATERMARK;
            let host = if serviced.contains(&pipe) {
                host | HOST_IS_COPY_COMPLETE
            } else {
                host & !HOST_IS_COPY_COMPLETE
            };
            io.write32(base + ce_off::HOST_IE, host);
        }
        self.unmask(io);
    }
    /// `ath10k_pci_has_fw_crashed` + `ath10k_pci_fw_crashed_clear`.
    pub fn take_crash(self, io: &mut impl Ath10kMmio) -> bool {
        let value = io.read32(self.fw_indicator);
        if value == u32::MAX || value & FW_IND_EVENT_PENDING == 0 {
            return false;
        }
        io.write32(self.fw_indicator, value & !FW_IND_EVENT_PENDING);
        true
    }
    /// `ath10k_ce_interrupt_summary`.
    pub fn summary(self, io: &mut impl Ath10kMmio) -> u32 {
        let raw = io.read32(self.ce_wrapper + CE_WRAPPER_SUMMARY);
        if raw == u32::MAX {
            return 0;
        }
        (raw & self.summary_mask) >> self.summary_lsb
    }
    /// NAPI prologue: crash check, hard-handler mask, then
    /// `ath10k_ce_per_engine_service_any` status clear (before the caller
    /// services the rings, so a later completion re-asserts the summary).
    pub fn begin(self, io: &mut impl Ath10kMmio) -> Service {
        if self.take_crash(io) {
            return Service::Crashed;
        }
        self.mask(io);
        let summary = self.summary(io);
        for pipe in 0..self.ce_count {
            if summary & (1 << pipe) != 0 {
                io.write32(
                    self.ce(pipe) + HOST_IS,
                    HOST_IS_COPY_COMPLETE | HOST_IS_WATERMARK,
                );
            }
        }
        Service::Engines(summary)
    }
    /// NAPI epilogue: if a CE re-asserted, keep the line masked and report a
    /// reschedule (`napi_schedule`); otherwise re-enable line + firmware.
    pub fn finish(self, io: &mut impl Ath10kMmio) -> bool {
        if self.summary(io) != 0 {
            return true;
        }
        self.unmask(io);
        false
    }
}

/// Host engines with Linux copy-complete callbacks (`host_ce_config_wlan`):
/// CE0/CE3 send, CE1/CE2/CE5/CE8 receive. CE4 is `CE_ATTR_DIS_INTR` and CE7
/// (diagnostics) has no callback. `present` excludes host-disabled engines.
pub(super) fn serviced_pipes(present: &[u8]) -> alloc::vec::Vec<u8> {
    let mut pipes = alloc::vec![0, 1];
    pipes.extend(
        present
            .iter()
            .copied()
            .filter(|p| matches!(p, 2 | 3 | 5 | 8)),
    );
    pipes
}

/// Edge-latched wake shared by the vector handler, host TX kicks and the
/// service owner.
pub(super) struct Signal {
    count: AtomicU64,
    waker: IrqSafeSpinLock<Option<Waker>>,
}
impl Signal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            count: AtomicU64::new(0),
            waker: IrqSafeSpinLock::new(None),
        })
    }
    /// Vector top half (and explicit kicks): count and wake; never touches
    /// the BAR.
    pub fn raise(&self) {
        self.count.fetch_add(1, Ordering::AcqRel);
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }
    /// Resolve once the count moves past `seen`, or when `fallback` ends.
    pub fn wait<F: Future<Output = ()> + Unpin>(&self, seen: u64, fallback: F) -> Wait<'_, F> {
        Wait {
            signal: self,
            seen,
            fallback,
        }
    }
}
impl core::fmt::Debug for Signal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signal")
            .field("count", &self.count())
            .finish()
    }
}
pub(super) struct Wait<'a, F> {
    signal: &'a Signal,
    seen: u64,
    fallback: F,
}
impl<F: Future<Output = ()> + Unpin> Future for Wait<'_, F> {
    /// `true` when an interrupt (or explicit wake) ended the wait.
    type Output = bool;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        if self.signal.count() != self.seen {
            return Poll::Ready(true);
        }
        *self.signal.waker.lock() = Some(cx.waker().clone());
        // Re-check after publishing the waker: a raise between the two loads
        // either saw the waker or left the count for us.
        if self.signal.count() != self.seen {
            return Poll::Ready(true);
        }
        match Pin::new(&mut self.fallback).poll(cx) {
            Poll::Ready(()) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Fallback service period: with a delivered vector the timer is only a
/// missed-edge backstop; without one the owner keeps its 1 ms poll.
pub(super) const fn fallback_ms(delivered: bool) -> u64 {
    if delivered {
        10
    } else {
        1
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "irq/tests.rs"]
mod tests;
