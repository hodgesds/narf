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
//! AR9300 (EDMA, `ATH9K_HW_CAP_RAC_SUPPORTED`, `ATH9K_HW_CAP_AUTOSLEEP`)
//! interrupt mask, cause decode and MSI re-arm, separate from the AR9002
//! `irq` path: `hw.c::ath9k_hw_init_interrupt_masks` (AR9300 branch, RX
//! mitigation 2000/500), `mac.c::{ath9k_hw_set_interrupts,
//! __ath9k_hw_enable_interrupts,ath9k_hw_kill_interrupts}` for the
//! `main.c::ath9k_start` EDMA station imask (TX | RXEOL | RXORN | FATAL |
//! GLOBAL | RXHP | RXLP | BB_WATCHDOG | GTT | CST) and
//! `ar9003_mac.c::ar9003_hw_get_isr`. `AR_PCIE_MSI` is 0x40a4 and
//! `AR_ISR_S5_S` 0xdc on this generation.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use crate::ath9k::irq::SYNC_DEFAULT;
use crate::ath9k::packet::{Error, Port};

pub(in crate::ath9k) const IER: u64 = 0x0024;
const RIMT: u64 = 0x002c;
const INTCFG: u64 = 0x005c;
const ISR: u64 = 0x0080;
const ISR_S2: u64 = 0x008c;
pub(in crate::ath9k) const IMR: u64 = 0x00a0;
const IMR_S0: u64 = 0x00a4;
const IMR_S1: u64 = 0x00a8;
const IMR_S2: u64 = 0x00ac;
const ISR_RAC: u64 = 0x00c0;
const ISR_S5_S: u64 = 0x00dc;
const RC: u64 = 0x4000;
const SYNC_CAUSE: u64 = 0x4028;
const SYNC_ENABLE: u64 = 0x402c;
const ASYNC_MASK: u64 = 0x4030;
const SYNC_MASK: u64 = 0x4034;
const ASYNC_CAUSE: u64 = 0x4038;
const ASYNC_ENABLE: u64 = 0x403c;
const PCIE_MSI: u64 = 0x40a4;
const PRIO_SYNC_ENABLE: u64 = 0x40c4;
const PRIO_ASYNC_MASK: u64 = 0x40c8;
const PRIO_SYNC_MASK: u64 = 0x40cc;
const PRIO_ASYNC_ENABLE: u64 = 0x40d4;
const RTC_STATUS: u64 = 0x7044;
/// `ar9003_phy.h::AR_PHY_WATCHDOG_STATUS` (`AR_SM_BASE + 0x5c0`).
const PHY_WATCHDOG_STATUS: u64 = 0xa7c0;
const PHY_WATCHDOG_STATUS_CLR: u32 = 0x8;

const MAC_IRQ: u32 = 0x2;
/// `reg.h::AR_INTR_ASYNC_CAUSE_MCI` / `AR_INTR_ASYNC_MASK_MCI` /
/// `AR_INTR_ASYNC_ENABLE_MCI` (all `0x80`): the async-cause bit
/// `ar9003_hw_get_isr` routes to `ar9003_mci_get_isr`.
const ASYNC_CAUSE_MCI: u32 = 0x80;
/// `hw.h::ATH9K_INT_MCI`: the `ath9k_int` bit `ar9003_mci_get_isr`
/// sets. In NARF the owner reads it as `Events::mci`.
pub(in crate::ath9k) const INT_MCI: u32 = 0x200;
const SYNC_FATAL: u32 = 0x20 | 0x40;
const SYNC_CPL_TIMEOUT: u32 = 0x1000;

const ISR_HP_RXOK: u32 = 0x1;
const ISR_LP_RXOK: u32 = 0x2;
const ISR_RXERR: u32 = 0x4;
const ISR_RXEOL: u32 = 0x10;
const ISR_RXORN: u32 = 0x20;
const ISR_TXOK: u32 = 0x40;
const ISR_TXERR: u32 = 0x100;
const ISR_TXEOL: u32 = 0x400;
const ISR_BMISS: u32 = 0x0004_0000;
const ISR_BCNMISC: u32 = 0x0080_0000;
const ISR_RXMINTR: u32 = 0x0100_0000;
const ISR_GENTMR: u32 = 0x1000_0000;
const ISR_RXINTM: u32 = 0x8000_0000;
pub(in crate::ath9k) const RX_EOL_ORN: u32 = ISR_RXEOL | ISR_RXORN;
const S2_BB_WATCHDOG: u32 = 0x0001_0000;
const S2_CST: u32 = 0x0040_0000;
const S2_GTT: u32 = 0x0080_0000;
const S2_TIM: u32 = 0x0100_0000;
const S2_CABEND: u32 = 0x0200_0000;
const S2_DTIMSYNC: u32 = 0x0400_0000;
const S2_DTIM: u32 = 0x2000_0000;
const S2_TSFOOR: u32 = 0x4000_0000;
/// `AR_ISR_S5_GENTIMER_TRIG`.
const S5_GENTIMER_TRIG: u32 = 0xff80;

/// `ath9k_hw_set_interrupts` IMR for the EDMA station imask: the
/// `ATH9K_INT_COMMON` RXEOL/RXORN, RX with mitigation (`AR_IMR_RXERR |
/// AR_IMR_RXOK_HP | AR_IMR_RXMINTR | AR_IMR_RXINTM`, LP RXOK cleared), TX
/// without mitigation through the `TXQ_FLAG_TXINT_ENABLE` queue's TXOK and
/// TXERR, no `AR_IMR_GENTMR` (`ATH9K_HW_CAP_AUTOSLEEP`) and `AR_IMR_BCNMISC`
/// for GTT/CST/BB_WATCHDOG.
pub(in crate::ath9k) const STATION_IMR: u32 = ISR_RXEOL
    | ISR_RXORN
    | ISR_RXERR
    | ISR_HP_RXOK
    | ISR_RXMINTR
    | ISR_RXINTM
    | ISR_TXOK
    | ISR_TXERR
    | ISR_BCNMISC;
/// `ah->imrs2_reg` after `ath9k_hw_set_interrupts` (GTT | CST |
/// BB_WATCHDOG; queue TXURN off).
pub(in crate::ath9k) const STATION_IMR_S2: u32 = S2_GTT | S2_CST | S2_BB_WATCHDOG;
/// `AR_INTCFG_MSI_RXINTM | AR_INTCFG_MSI_RXMINTR | AR_INTCFG_MSI_TXOK`.
const MSI_CFG: u32 = 0x4 | 0x6;
/// `AR_INTR_PRIO_TX | AR_INTR_PRIO_RXLP | AR_INTR_PRIO_RXHP`.
const MSI_MASK: u32 = 0x7;
const MSI_ENABLE: u32 = 0x1;
const MSI_DBI_WR_EN: u32 = 0x0200_0000;
const MSI_PENDING_64: u32 = 0xffa0_c9ff;
/// AR9300 RX mitigation (`hw.c`: rimt_last 500, rimt_first 2000).
const RIMT_VALUE: u32 = (2000 << 16) | 500;

/// The `ath9k_int` facts `ar9003_hw_get_isr` reports, masked as `ath_isr`
/// masks them by the current imask. Not every fact has a consumer yet;
/// the AR9300 station owner is still to be ported.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(in crate::ath9k) struct Events {
    pub rx_hp: bool,
    pub rx_lp: bool,
    pub tx: bool,
    pub rx_eol: bool,
    pub rx_overrun: bool,
    pub bmiss: bool,
    pub gen_timer: bool,
    pub tim: bool,
    pub dtim: bool,
    pub dtim_sync: bool,
    pub cab_end: bool,
    pub gtt: bool,
    pub cst: bool,
    pub tsf_oor: bool,
    /// `ATH9K_INT_BB_WATCHDOG` with the `ar9003_hw_bb_watchdog_read` status.
    pub bb_watchdog: Option<u32>,
    pub fatal: bool,
    pub sync_cause: u32,
    /// `ATH9K_INT_MCI`: the async cause carried the MCI bit while MCI
    /// was enabled. The owner runs `mci::get_isr` plus
    /// `mci::handle_interrupt` on its `RegisterIo` path when this is
    /// set (the live-owner wiring); `mci::sync_gpm_ring` runs first so
    /// the walk sees the DMA ring.
    pub mci: bool,
}

impl Events {
    /// `ath_isr`'s `goto chip_reset` causes: FATAL, or the BB watchdog
    /// (`HW_BB_WATCHDOG` is set for every AR9003 part).
    pub fn reset(&self) -> bool {
        self.fatal || self.bb_watchdog.is_some()
    }
}

/// Interrupt registers retained by the owner across kill/resume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct Mask {
    pub imr: u32,
    pub msi: bool,
    pub msi_reg: u32,
    /// The async-cause mask carries the MCI bit
    /// (`mac.c::__ath9k_hw_enable_interrupts` ORs
    /// `AR_INTR_ASYNC_MASK_MCI` in when `ATH9K_INT_MCI` is in the
    /// imask); without it BT never signals.
    pub mci: bool,
}

/// `ath9k_hw_init_interrupt_masks` + `ath9k_hw_set_interrupts` +
/// `__ath9k_hw_enable_interrupts` for the queue-0 EDMA station owner.
pub(in crate::ath9k) fn enable(
    port: &impl Port,
    msi: bool,
    mci_enabled: bool,
) -> Result<Mask, Error> {
    let mut msi_reg = 0;
    if msi {
        msi_reg = (port.read(PCIE_MSI)? | MSI_DBI_WR_EN) & MSI_PENDING_64;
        port.write(INTCFG, MSI_CFG)?;
    }
    port.write(SYNC_CAUSE, u32::MAX)?;
    port.write(SYNC_ENABLE, SYNC_DEFAULT)?;
    port.write(SYNC_MASK, 0)?;
    // AR_SREV_9300_20_OR_LATER: every priority route starts closed.
    port.write(PRIO_ASYNC_ENABLE, 0)?;
    port.write(PRIO_ASYNC_MASK, 0)?;
    port.write(PRIO_SYNC_ENABLE, 0)?;
    port.write(PRIO_SYNC_MASK, 0)?;
    // ath9k_hw_reset: both AR_RIMT fields (the whole register).
    port.write(RIMT, RIMT_VALUE)?;
    // ath9k_hw_set_txq_interrupts: TXOK and TXERR for QCU0 only.
    port.write(IMR_S0, 1)?;
    port.write(IMR_S1, 1)?;
    port.write(IMR, STATION_IMR)?;
    port.write(IMR_S2, STATION_IMR_S2)?;
    let mask = Mask {
        imr: STATION_IMR,
        msi,
        msi_reg,
        mci: mci_enabled,
    };
    resume(port, mask)?;
    Ok(mask)
}

/// `__ath9k_hw_enable_interrupts`, including the bounded AR_PCIE_MSI re-arm.
pub(in crate::ath9k) fn resume(port: &impl Port, mask: Mask) -> Result<(), Error> {
    resume_with(port, mask, MSI_MASK)
}

/// `AR_IMR_BMISS`: the only cause `wow.c::ath9k_suspend` leaves enabled.
pub(in crate::ath9k) const WOW_IMR: u32 = ISR_BMISS;

/// `wow.c::ath9k_suspend`'s interrupt switch: `ath9k_hw_disable_interrupts`,
/// `ath9k_hw_set_interrupts` with imask `ATH9K_INT_BMISS |
/// ATH9K_INT_GLOBAL` (IMR = `AR_IMR_BMISS`; `imrs2_reg` drops TIM..CST but
/// keeps `AR_IMR_S2_BB_WATCHDOG`, which `set_interrupts` only clears when
/// re-adding it; no TX/RX, so `msi_mask` 0) and
/// `ath9k_hw_enable_interrupts`.
pub(in crate::ath9k) fn wow(port: &impl Port, mask: Mask) -> Result<(), Error> {
    kill(port, mask.msi)?;
    port.write(IMR, WOW_IMR)?;
    port.write(IMR_S2, STATION_IMR_S2 & !(S2_GTT | S2_CST))?;
    resume_with(
        port,
        Mask {
            imr: WOW_IMR,
            ..mask
        },
        0,
    )
}

/// `wow.c::ath9k_resume`'s interrupt restore: disable, the saved
/// `wow_intr_before_sleep` imask (`mask`) through `ath9k_hw_set_interrupts`,
/// enable.
pub(in crate::ath9k) fn restore(port: &impl Port, mask: Mask) -> Result<(), Error> {
    kill(port, mask.msi)?;
    port.write(IMR, mask.imr)?;
    port.write(IMR_S2, STATION_IMR_S2)?;
    resume(port, mask)
}

fn resume_with(port: &impl Port, mask: Mask, msi_mask: u32) -> Result<(), Error> {
    port.write(IER, 1)?;
    let async_mask = if mask.mci {
        MAC_IRQ | ASYNC_CAUSE_MCI
    } else {
        MAC_IRQ
    };
    port.write(ASYNC_ENABLE, async_mask)?;
    port.write(ASYNC_MASK, async_mask)?;
    port.write(SYNC_ENABLE, SYNC_DEFAULT)?;
    port.write(SYNC_MASK, SYNC_DEFAULT)?;
    if mask.msi {
        port.write(PRIO_ASYNC_ENABLE, msi_mask)?;
        port.write(PRIO_ASYNC_MASK, msi_mask)?;
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
pub(in crate::ath9k) fn kill(port: &impl Port, msi: bool) -> Result<(), Error> {
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

/// `ar9003_hw_get_isr` (RAC supported, MCI routed when `mci_enabled`,
/// RX mitigation on, TX mitigation off), masked by `imr` as `ath_isr`
/// masks by imask. `None` is "not pending" (or a removed card returning
/// all ones from `AR_ISR_RAC`). When `events.mci` is set the owner runs
/// `mci::get_isr` plus `mci::handle_interrupt` on its `RegisterIo`
/// path (`ar9003_mci_get_isr` is the Linux half of that pair).
pub(in crate::ath9k) fn cause(
    port: &impl Port,
    imr: u32,
    mci_enabled: bool,
) -> Result<Option<Events>, Error> {
    let mut isr = 0;
    let async_cause = port.read(ASYNC_CAUSE)?;
    if async_cause & MAC_IRQ != 0 && port.read(RTC_STATUS)? & 0xf == 2 {
        isr = port.read(ISR)?;
    }
    let sync = port.read(SYNC_CAUSE)? & SYNC_DEFAULT;
    if isr == 0 && sync == 0 && async_cause == 0 {
        return Ok(None);
    }
    // `ar9003_mac.c`: the async mask gains MCI when enabled, and
    // `ar9003_mci_get_isr` runs whenever the async cause has the bit.
    let mut events = Events {
        mci: mci_enabled && async_cause & ASYNC_CAUSE_MCI != 0,
        ..Default::default()
    };
    if isr != 0 {
        if isr & ISR_BCNMISC != 0 {
            // RAC clears the secondary causes; no write-back here.
            let s2 = port.read(ISR_S2)?;
            let on = |bit: u32| s2 & bit != 0 && STATION_IMR_S2 & bit != 0;
            events.tim = s2 & S2_TIM != 0;
            events.dtim = s2 & S2_DTIM != 0;
            events.dtim_sync = s2 & S2_DTIMSYNC != 0;
            events.cab_end = s2 & S2_CABEND != 0;
            events.tsf_oor = s2 & S2_TSFOOR != 0;
            events.gtt = on(S2_GTT);
            events.cst = on(S2_CST);
            if on(S2_BB_WATCHDOG) {
                // ar9003_hw_bb_watchdog_read.
                let status = port.read(PHY_WATCHDOG_STATUS)?;
                port.write(PHY_WATCHDOG_STATUS, status & !PHY_WATCHDOG_STATUS_CLR)?;
                events.bb_watchdog = Some(status);
            }
        }
        isr = port.read(ISR_RAC)?;
        if isr == u32::MAX {
            return Ok(None);
        }
        // ATH9K_INT_RXDESC (0x2) is in ATH9K_INT_COMMON and is RXLP.
        events.rx_lp = isr & (ISR_RXMINTR | ISR_RXINTM | ISR_LP_RXOK | ISR_RXERR) != 0;
        events.rx_hp = isr & ISR_HP_RXOK != 0;
        events.tx = isr & (ISR_TXOK | ISR_TXERR | ISR_TXEOL) != 0;
        events.bmiss = isr & imr & ISR_BMISS != 0;
        events.rx_eol = isr & imr & ISR_RXEOL != 0;
        events.rx_overrun = isr & imr & ISR_RXORN != 0;
        if isr & ISR_GENTMR != 0 {
            events.gen_timer = port.read(ISR_S5_S)? & S5_GENTIMER_TRIG != 0;
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
