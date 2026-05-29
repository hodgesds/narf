//! rtlwifi IRQ routing — HISR0 / HISR1 + HIMR mask programming.
//!
//! The rtlwifi family routes interrupts through two 32-bit ISR
//! registers (`REG_HISR` + `REG_HISRE`) gated by matching mask
//! registers (`REG_HIMR` + `REG_HIMRE`).  MSI is preferred when
//! available; INTx is the fallback.
//!
//! The ISR drains by:
//! 1. Read `REG_HISR` + `REG_HISRE`.
//! 2. AND with `REG_HIMR` / `REG_HIMRE` to mask interrupts we didn't
//!    request.
//! 3. Acknowledge: write the same bits back to `REG_HISR{,E}`.
//! 4. Dispatch to per-bit handlers (RX-OK, TX-OK per queue, RDU = RX
//!    descriptor underflow, RXFOVW = RX FIFO overflow, etc.).
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtlwifi/pci.c::_rtl_pci_interrupt` (line ~700) — generic ISR
//! - `rtl8192ee/sw.c:98..109` — IMR bit selection for 8192EE
//! - `rtl8192ee/reg.h:527..573` — IMR / ISR bit definitions

#![allow(dead_code)]

use narf_bus::MmioRegion;

use super::regs::*;

// ── IMR / ISR bits (`REG_HIMR` + `REG_HISR`) ─────────────────────────────
//
// Source: `rtl8192ee/reg.h:527..548`.

/// `IMR_PSTIMEOUT` — power-state-machine timeout.
pub const IMR_PSTIMEOUT: u32 = 1 << 29;
/// `IMR_C2HCMD` — chip-to-host MCU command available.
pub const IMR_C2HCMD: u32 = 1 << 10;
/// `IMR_HIGHDOK` — high-priority queue TX done.
pub const IMR_HIGHDOK: u32 = 1 << 7;
/// `IMR_MGNTDOK` — management queue TX done.
pub const IMR_MGNTDOK: u32 = 1 << 6;
/// `IMR_BKDOK` — background queue TX done.
pub const IMR_BKDOK: u32 = 1 << 5;
/// `IMR_BEDOK` — best-effort queue TX done.
pub const IMR_BEDOK: u32 = 1 << 4;
/// `IMR_VIDOK` — video queue TX done.
pub const IMR_VIDOK: u32 = 1 << 3;
/// `IMR_VODOK` — voice queue TX done.
pub const IMR_VODOK: u32 = 1 << 2;
/// `IMR_RDU` — RX descriptor underflow.
pub const IMR_RDU: u32 = 1 << 1;
/// `IMR_ROK` — RX OK (data available).
pub const IMR_ROK: u32 = 1 << 0;

/// `IMR_RXFOVW` — RX FIFO overflow (in `REG_HIMRE`).
pub const IMRE_RXFOVW: u32 = 1 << 8;

/// Default `REG_HIMR` value used by 8192EE.  `sw.c:98..108`.
pub const HIMR_DEFAULT: u32 = IMR_PSTIMEOUT
    | IMR_C2HCMD
    | IMR_HIGHDOK
    | IMR_MGNTDOK
    | IMR_BKDOK
    | IMR_BEDOK
    | IMR_VIDOK
    | IMR_VODOK
    | IMR_RDU
    | IMR_ROK;

/// Default `REG_HIMRE` value used by 8192EE.  `sw.c:109`.
pub const HIMRE_DEFAULT: u32 = IMRE_RXFOVW;

// ── Mask programming ─────────────────────────────────────────────────────

/// Program the chip's HIMR/HIMRE mask registers to the family defaults.
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn enable_interrupts(mmio: &MmioRegion) {
    // SAFETY: caller-asserted.
    unsafe {
        // Clear any pending ISR bits before unmasking.
        mmio.write32(REG_HISR, 0xFFFF_FFFF);
        mmio.write32(REG_HISRE, 0xFFFF_FFFF);
        mmio.write32(REG_HIMR, HIMR_DEFAULT);
        mmio.write32(REG_HIMRE, HIMRE_DEFAULT);
    }
}

/// Disable all interrupts.  Used during teardown / firmware reload.
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn disable_interrupts(mmio: &MmioRegion) {
    // SAFETY: caller-asserted.
    unsafe {
        mmio.write32(REG_HIMR, 0);
        mmio.write32(REG_HIMRE, 0);
    }
}

// ── Per-IRQ accumulator ──────────────────────────────────────────────────

/// One ISR pass result.  Drives the per-queue completion handlers.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IsrStatus {
    /// Bits from `REG_HISR` that intersected `REG_HIMR`.
    pub hisr: u32,
    /// Bits from `REG_HISRE` that intersected `REG_HIMRE`.
    pub hisre: u32,
}

impl IsrStatus {
    /// True if the chip raised any RX data interrupt.
    #[inline]
    pub fn rx_ready(self) -> bool {
        self.hisr & IMR_ROK != 0
    }

    /// True if the BE TX queue completed.
    #[inline]
    pub fn tx_be_done(self) -> bool {
        self.hisr & IMR_BEDOK != 0
    }

    /// True if any TX queue completed.
    #[inline]
    pub fn tx_any_done(self) -> bool {
        self.hisr & (IMR_BEDOK | IMR_BKDOK | IMR_VIDOK | IMR_VODOK | IMR_MGNTDOK | IMR_HIGHDOK)
            != 0
    }

    /// True if the chip flagged an RX FIFO overflow (drop, recover).
    #[inline]
    pub fn rx_overflow(self) -> bool {
        self.hisre & IMRE_RXFOVW != 0
    }

    /// True if there's a pending C2H MCU command.
    #[inline]
    pub fn c2h_pending(self) -> bool {
        self.hisr & IMR_C2HCMD != 0
    }
}

/// Drain one ISR cycle: read + mask + ack.  Returns the masked
/// interrupt status; the caller dispatches per-bit handlers.
///
/// # Safety
/// Caller must own BAR0 exclusively.
pub unsafe fn drain_isr(mmio: &MmioRegion) -> IsrStatus {
    // SAFETY: caller-asserted.
    unsafe {
        let hisr_raw = mmio.read32(REG_HISR);
        let himr = mmio.read32(REG_HIMR);
        let hisre_raw = mmio.read32(REG_HISRE);
        let himre = mmio.read32(REG_HIMRE);

        let hisr = hisr_raw & himr;
        let hisre = hisre_raw & himre;

        // Acknowledge the bits we're processing by writing them back.
        // The chip W1C-clears the bit.
        if hisr != 0 {
            mmio.write32(REG_HISR, hisr);
        }
        if hisre != 0 {
            mmio.write32(REG_HISRE, hisre);
        }

        IsrStatus { hisr, hisre }
    }
}
