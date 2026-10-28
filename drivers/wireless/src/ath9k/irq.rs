// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2008-2011 Atheros Communications Inc.
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
//! AR9285 (AR9002 MAC, RAC-capable) interrupt mask, cause decode and MSI
//! re-arm. Linux references: `hw.c::ath9k_hw_init_interrupt_masks`,
//! `mac.c::{ath9k_hw_set_interrupts,__ath9k_hw_enable_interrupts,
//! ath9k_hw_kill_interrupts}`, `ar9002_mac.c::ar9002_hw_get_isr` and
//! `main.c::{ath_isr,ath9k_tasklet}`. The vector handler only latches a
//! wake; this bottom half reads/clears causes and re-enables IER afterwards,
//! exactly as Linux kills interrupts in `ath_isr` and resumes in the tasklet.
use super::packet::{Error, Port};
use alloc::sync::Arc;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
};
use narf_lib::sync::IrqSafeSpinLock;

pub(super) const IER: u64 = 0x0024;
const RIMT: u64 = 0x002c;
const INTCFG: u64 = 0x005c;
const ISR: u64 = 0x0080;
const ISR_S2: u64 = 0x008c;
pub(super) const IMR: u64 = 0x00a0;
const IMR_S0: u64 = 0x00a4;
const IMR_S1: u64 = 0x00a8;
const IMR_S2: u64 = 0x00ac;
const IMR_S5: u64 = 0x00b8;
const ISR_RAC: u64 = 0x00c0;
const ISR_S0_S: u64 = 0x00c4;
const ISR_S1_S: u64 = 0x00c8;
const ISR_S5_S: u64 = 0x00d8;
const RC: u64 = 0x4000;
const SYNC_CAUSE: u64 = 0x4028;
const SYNC_ENABLE: u64 = 0x402c;
const ASYNC_MASK: u64 = 0x4030;
const SYNC_MASK: u64 = 0x4034;
const ASYNC_CAUSE: u64 = 0x4038;
const ASYNC_ENABLE: u64 = 0x403c;
const PCIE_MSI: u64 = 0x4094;
const PRIO_ASYNC_MASK: u64 = 0x40c8;
const PRIO_ASYNC_ENABLE: u64 = 0x40d4;
const RTC_STATUS: u64 = 0x7044;

const MAC_IRQ: u32 = 0x2;
/// `AR_INTR_SYNC_DEFAULT`: HOST1 fatal/PERR, RADM completion errors and
/// timeouts, local timeout and MAC sleep access.
pub(super) const SYNC_DEFAULT: u32 = 0x0002_3f60;
const SYNC_FATAL: u32 = 0x20 | 0x40;
const SYNC_CPL_TIMEOUT: u32 = 0x1000;

const ISR_RXOK: u32 = 0x1;
const ISR_RXERR: u32 = 0x4;
const ISR_RXEOL: u32 = 0x10;
const ISR_RXORN: u32 = 0x20;
const ISR_TXOK: u32 = 0x40;
const ISR_TXDESC: u32 = 0x80;
const ISR_TXERR: u32 = 0x100;
const ISR_TXEOL: u32 = 0x400;
const ISR_BCNMISC: u32 = 0x0080_0000;
const ISR_RXMINTR: u32 = 0x0100_0000;
const ISR_GENTMR: u32 = 0x1000_0000;
const ISR_RXINTM: u32 = 0x8000_0000;
pub(super) const RX_EOL_ORN: u32 = ISR_RXEOL | ISR_RXORN;
const S2_CST: u32 = 0x0040_0000;
const S5_TIM_TIMER: u32 = 0x10;

/// `ath9k_start` imask for a non-EDMA station: TX | RXEOL | RXORN | FATAL |
/// GLOBAL | RX, with CST only on HT-capable silicon (`ATH9K_HW_CAP_HT`).
/// Queue 0 uses `TXQ_FLAG_TXEOLINT_ENABLE | TXQ_FLAG_TXDESCINT_ENABLE`
/// (`xmit.c::ath_txq_setup`) and RX mitigation is on (`hw.c` default).
pub(super) fn imr(ht: bool) -> u32 {
    let mut mask = ISR_RXEOL | ISR_RXORN | ISR_TXDESC | ISR_TXEOL;
    mask |= ISR_RXMINTR | ISR_RXINTM;
    // No ATH9K_HW_CAP_AUTOSLEEP on AR9285: RX also enables GENTMR.
    mask |= ISR_GENTMR;
    if ht {
        mask |= ISR_BCNMISC;
    }
    mask
}
/// `ath9k_hw_init_interrupt_masks` MSI interrupt config for RX mitigation
/// (`AR_INTCFG_MSI_RXINTM | AR_INTCFG_MSI_RXMINTR`) and plain TXOK.
const MSI_CFG: u32 = 0x4 | 0x6;
/// `AR_INTR_PRIO_TX | AR_INTR_PRIO_RXLP | AR_INTR_PRIO_RXHP`.
const MSI_MASK: u32 = 0x7;
const MSI_ENABLE: u32 = 0x1;
const MSI_DBI_WR_EN: u32 = 0x0200_0000;
const MSI_PENDING_64: u32 = 0xffa0_c9ff;
/// AR9002 RX mitigation (`hw.c`: rimt_last 250, rimt_first 700).
const RIMT_VALUE: u32 = (700 << 16) | 250;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Events {
    pub rx: bool,
    pub tx: bool,
    /// `ah->intr_txqs`: QCUs reporting TXOK/TXDESC/TXERR/TXEOL.
    pub txqs: u16,
    pub rx_eol: bool,
    pub rx_overrun: bool,
    pub fatal: bool,
    pub tim_timer: bool,
    pub sync_cause: u32,
}

/// Interrupt registers retained by the owner across kill/resume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Mask {
    pub imr: u32,
    pub msi: bool,
    pub msi_reg: u32,
}

/// `ath9k_hw_init_interrupt_masks` + `ath9k_hw_set_interrupts` +
/// `__ath9k_hw_enable_interrupts` for the queue-0 station owner.
pub(super) fn enable(port: &impl Port, ht: bool, msi: bool) -> Result<Mask, Error> {
    let imr = imr(ht);
    // init_interrupt_masks: IMR_S2 starts with GTT, then set_interrupts
    // clears TIM/DTIM/CAB/TSFOOR/GTT/CST and ORs only the requested mask2.
    let mut msi_reg = 0;
    if msi {
        msi_reg = (port.read(PCIE_MSI)? | MSI_DBI_WR_EN) & MSI_PENDING_64;
        port.write(INTCFG, MSI_CFG)?;
    }
    port.write(SYNC_CAUSE, u32::MAX)?;
    port.write(SYNC_ENABLE, SYNC_DEFAULT)?;
    port.write(SYNC_MASK, 0)?;
    port.write(RIMT, RIMT_VALUE)?;
    port.write(IMR, imr)?;
    port.write(IMR_S0, 1 << 16)?; // TXDESC for QCU0, no TXOK
    port.write(IMR_S1, 1 << 16)?; // TXEOL for QCU0, no TXERR
    port.write(IMR_S2, if ht { S2_CST } else { 0 })?;
    let s5 = port.read(IMR_S5)?;
    port.write(IMR_S5, s5 & !S5_TIM_TIMER)?;
    let mask = Mask { imr, msi, msi_reg };
    resume(port, mask)?;
    Ok(mask)
}

/// `__ath9k_hw_enable_interrupts`, including the bounded AR_PCIE_MSI re-arm.
pub(super) fn resume(port: &impl Port, mask: Mask) -> Result<(), Error> {
    port.write(IER, 1)?;
    port.write(ASYNC_ENABLE, MAC_IRQ)?;
    port.write(ASYNC_MASK, MAC_IRQ)?;
    port.write(SYNC_ENABLE, SYNC_DEFAULT)?;
    port.write(SYNC_MASK, SYNC_DEFAULT)?;
    if mask.msi {
        port.write(PRIO_ASYNC_ENABLE, MSI_MASK)?;
        port.write(PRIO_ASYNC_MASK, MSI_MASK)?;
        for _ in 0..200 {
            port.write(PCIE_MSI, (mask.msi_reg | MSI_ENABLE) & MSI_PENDING_64)?;
            if port.read(PCIE_MSI)? & MSI_ENABLE != 0 {
                return Ok(());
            }
        }
        return Err(Error::Timeout);
    }
    Ok(())
}

/// `ath9k_hw_kill_interrupts` (plus the MSI priority clear from
/// `ath9k_hw_set_interrupts`), each write flushed by a read.
pub(super) fn kill(port: &impl Port, msi: bool) -> Result<(), Error> {
    port.write(IER, 0)?;
    port.read(IER)?;
    port.write(ASYNC_ENABLE, 0)?;
    port.read(ASYNC_ENABLE)?;
    port.write(SYNC_ENABLE, 0)?;
    port.read(SYNC_ENABLE)?;
    if msi {
        port.write(PRIO_ASYNC_ENABLE, 0)?;
        port.read(PRIO_ASYNC_ENABLE)?;
    }
    Ok(())
}

/// `ar9002_hw_get_isr` for RAC-capable AR9280-2.0+ silicon, masked by imask
/// as `ath_isr` does. `None` means not pending (or a removed card).
pub(super) fn cause(port: &impl Port, imr: u32) -> Result<Option<Events>, Error> {
    let mut isr = 0;
    if port.read(ASYNC_CAUSE)? & MAC_IRQ != 0 && port.read(RTC_STATUS)? & 0xf == 2 {
        isr = port.read(ISR)?;
    }
    let sync = port.read(SYNC_CAUSE)? & SYNC_DEFAULT;
    if isr == 0 && sync == 0 {
        return Ok(None);
    }
    let mut events = Events::default();
    if isr != 0 {
        if isr & ISR_BCNMISC != 0 {
            // RAC clears the secondary; CST is consumed only as a cause.
            let _ = port.read(ISR_S2)?;
        }
        isr = port.read(ISR_RAC)?;
        if isr == u32::MAX {
            return Ok(None);
        }
        // ATH9K_INT_RX / ATH9K_INT_TX stay in imask for the owner's life;
        // RXEOL/RXORN follow the current IMR (ath_isr drops them on RXEOL).
        events.rx = isr & (ISR_RXMINTR | ISR_RXINTM | ISR_RXOK | ISR_RXERR) != 0;
        if isr & (ISR_TXOK | ISR_TXDESC | ISR_TXERR | ISR_TXEOL) != 0 {
            events.tx = true;
            let s0 = port.read(ISR_S0_S)?;
            let s1 = port.read(ISR_S1_S)?;
            events.txqs =
                ((s0 & 0x3ff) | ((s0 >> 16) & 0x3ff) | (s1 & 0x3ff) | ((s1 >> 16) & 0x3ff)) as u16;
        }
        events.rx_eol = isr & imr & ISR_RXEOL != 0;
        events.rx_overrun = isr & imr & ISR_RXORN != 0;
        if isr & ISR_GENTMR != 0 {
            let s5 = port.read(ISR_S5_S)?;
            events.tim_timer = s5 & S5_TIM_TIMER != 0;
        }
    }
    if sync != 0 {
        events.sync_cause = sync;
        events.fatal = sync & SYNC_FATAL != 0;
        if sync & SYNC_CPL_TIMEOUT != 0 {
            // AR_RC_HOSTIF pulse, then report fatal for chip reset.
            port.write(RC, 0x100)?;
            port.write(RC, 0)?;
            events.fatal = true;
        }
        port.write(SYNC_CAUSE, sync)?;
        port.read(SYNC_CAUSE)?;
    }
    Ok(Some(events))
}

/// Edge-latched wake shared by the vector handler and the service task.
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
    /// Vector top half: count and wake; never touches the BAR.
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
        // Re-check after publishing the waker: a raise between the two
        // loads either saw the waker or left the count for us.
        if self.signal.count() != self.seen {
            return Poll::Ready(true);
        }
        match Pin::new(&mut self.fallback).poll(cx) {
            Poll::Ready(()) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    }
}
