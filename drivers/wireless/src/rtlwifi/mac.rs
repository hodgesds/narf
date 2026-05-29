//! rtlwifi MAC-init layer — TRX FIFO boundary, queue mapping, CR open.
//!
//! Mirrors the chip-independent body of `_rtl<ver>_init_mac` and
//! `_rtl<ver>_llt_table_init` from each chip's `hw.c`.  The function pulled
//! into Rust is the *post-power-on* MAC enablement step:
//!
//! 1. Release MAC IO reset (`REG_CR = 0xFF; udelay(2); = 0x2FF`).
//! 2. Program the TRX-FIFO boundary (`REG_TRXFF_BNDY` + page boundaries).
//! 3. Program per-queue FIFO base pages.
//! 4. Clear the interrupt status registers.
//! 5. Enable TRXDMA + apply RCR / TCR receive/transmit configurations.
//! 6. Program ring descriptor counts (`REG_*_TXBD_NUM` family).
//!
//! Per-chip RCR / TCR / FIFO-page constants are kept here as named
//! tunables — the per-chip `hw.c` files supply the same numbers.
//!
//! ## Linux reference (GPL-2.0; NARF is GPL-2.0-or-later)
//!
//! - `rtl8192ee/hw.c::_rtl92ee_init_mac` (line 730) — canonical flow
//! - `rtl8192ee/hw.c::_rtl92ee_llt_table_init` (line 674)
//! - `rtl8188ee/hw.c::_rtl88ee_init_mac` (similar shape, fewer rings)
//! - `rtl8821ae/hw.c::_rtl8821ae_init_mac` (VHT + dual band)
//! - `rtl8192ee/sw.c::rtl92ee_init_sw_vars` (RCR/TCR seed values)

#![allow(dead_code)]

use narf_bus::MmioRegion;
use narf_time::Deadline;

use super::regs::*;

// ── Per-chip TRX-FIFO page boundary ──────────────────────────────────────
//
// `txpktbuf_bndy` separates the on-chip 64 KiB packet buffer between the
// TX FIFO (lower pages) and the RX FIFO + beacon/MGMT staging (upper
// pages).  Linux hardcodes 0xF7 (= 247 of 256 128-byte pages reserved for
// TX) on 8192EE; the other chips use distinct values, summarized below.
//
// Source: per-chip `_rtl<ver>_llt_table_init` in `hw.c`.

/// 8188EE TX/RX page boundary.
pub const TXPKTBUF_BNDY_8188EE: u8 = 0xE0;
/// 8192CE TX/RX page boundary.
pub const TXPKTBUF_BNDY_8192CE: u8 = 0xE6;
/// 8192EE TX/RX page boundary.  `rtl8192ee/hw.c:680`.
pub const TXPKTBUF_BNDY_8192EE: u8 = 0xF7;
/// 8723AE/BE TX/RX page boundary.  `rtl8723be/hw.c`.
pub const TXPKTBUF_BNDY_8723BE: u8 = 0xF7;
/// 8821AE TX/RX page boundary.  `rtl8821ae/hw.c`.
pub const TXPKTBUF_BNDY_8821AE: u8 = 0xF7;
/// 8822BE TX/RX page boundary.
pub const TXPKTBUF_BNDY_8822BE: u8 = 0xF7;

/// Pick the chip's TX/RX page boundary value.
pub const fn txpktbuf_bndy_for(did: u16) -> u8 {
    match did {
        RTL_DEV_8188EE => TXPKTBUF_BNDY_8188EE,
        RTL_DEV_8192CE | RTL_DEV_8192CE_ALT | RTL_DEV_8192DE => TXPKTBUF_BNDY_8192CE,
        RTL_DEV_8192EE => TXPKTBUF_BNDY_8192EE,
        RTL_DEV_8723AE | RTL_DEV_8723BE => TXPKTBUF_BNDY_8723BE,
        RTL_DEV_8821AE => TXPKTBUF_BNDY_8821AE,
        RTL_DEV_8822BE => TXPKTBUF_BNDY_8822BE,
        _ => TXPKTBUF_BNDY_8192EE,
    }
}

// ── Additional registers used by mac init ────────────────────────────────
//
// Source: `rtl8192ee/reg.h` (offsets shared family-wide).

/// `REG_RQPN` — receive queue page number, programmed by `llt_table_init`.
/// `rtl8192ee/reg.h:112` — `0x0200`.
pub const REG_RQPN: u64 = 0x0200;

/// Auto-LLT load trigger; `BIT(0)` of `REG_AUTO_LLT + 2` (0x0226).
/// `rtl8192ee/reg.h:118` — `0x0224`.
pub const REG_AUTO_LLT: u64 = 0x0224;

/// Per-queue page boundary registers.  `rtl8192ee/reg.h:221..236`.
pub const REG_BCNQ_BDNY: u64 = 0x0424;
pub const REG_MGQ_BDNY: u64 = 0x0425;
pub const REG_BCNQ1_BDNY: u64 = 0x0457;
pub const REG_DWBCN0_CTRL: u64 = 0x0208;
pub const REG_DWBCN1_CTRL: u64 = 0x0228;
pub const REG_HWSEQ_CTRL: u64 = 0x0423;
pub const REG_FWHW_TXQ_CTRL: u64 = 0x0420;

/// Receive control register.  `rtl8192ee/reg.h:309` — `0x0608`.
pub const REG_RCR: u64 = 0x0608;

/// Transmit control register.  `rtl8192ee/reg.h:308` — `0x0604`.
pub const REG_TCR: u64 = 0x0604;

/// Receive drvinfo size in 8-byte units (default 4).  `reg.h:312`.
pub const REG_RX_DRVINFO_SZ: u64 = 0x060F;

/// RX filter map 0..2.  `reg.h:342..344`.
pub const REG_RXFLTMAP0: u64 = 0x06A0;
pub const REG_RXFLTMAP1: u64 = 0x06A2;
pub const REG_RXFLTMAP2: u64 = 0x06A4;

/// PCIe control register.  `reg.h:143` — `0x0300`.  Bit selects on
/// `_REG + 3` toggle ASPM L0s/L1 power-state hints.
pub const REG_PCIE_CTRL_REG: u64 = 0x0300;

/// Coalescing / interrupt-mig register.  `reg.h:144` — `0x0304`.
pub const REG_INT_MIG: u64 = 0x0304;

/// `REG_MCUTST_1` — MCU test register.  `reg.h:90` — `0x01c0`.
pub const REG_MCUTST_1: u64 = 0x01c0;

/// 64-bit TSF timer programmed once at MAC init.  `reg.h:174` — `0x039C`.
pub const REG_TSFTIMER_HCI: u64 = 0x039C;

// ── DMA descriptor base address registers ────────────────────────────────
//
// Source: `rtl8192ee/reg.h:143..165`.

/// Beacon-queue descriptor-base low dword. `reg.h:145` — `0x0308`.
pub const REG_BCNQ_DESA: u64 = 0x0308;
/// Management-queue descriptor-base low dword. `reg.h:146` — `0x0310`.
pub const REG_MGQ_DESA: u64 = 0x0310;
/// Voice-queue descriptor-base low dword. `reg.h:147` — `0x0318`.
pub const REG_VOQ_DESA: u64 = 0x0318;
/// Video-queue descriptor-base low dword. `reg.h:148` — `0x0320`.
pub const REG_VIQ_DESA: u64 = 0x0320;
/// Best-effort-queue descriptor-base low dword. `reg.h:149` — `0x0328`.
pub const REG_BEQ_DESA: u64 = 0x0328;
/// Background-queue descriptor-base low dword. `reg.h:150` — `0x0330`.
pub const REG_BKQ_DESA: u64 = 0x0330;
/// High-priority queue descriptor-base low dword. `reg.h:152` — `0x0340`.
pub const REG_HQ0_DESA: u64 = 0x0340;
/// RX-queue descriptor-base low dword. `reg.h:151` — `0x0338`.
pub const REG_RX_DESA: u64 = 0x0338;

// ── Per-queue ring-size register (1 row per TX queue) ────────────────────
//
// Each holds (count | seg_num << 12).
// Source: `rtl8192ee/reg.h:160..170`.

pub const REG_MGQ_TXBD_NUM: u64 = 0x0380;
pub const REG_VOQ_TXBD_NUM: u64 = 0x0384;
pub const REG_VIQ_TXBD_NUM: u64 = 0x0386;
pub const REG_BEQ_TXBD_NUM: u64 = 0x0388;
pub const REG_BKQ_TXBD_NUM: u64 = 0x038A;
pub const REG_HI0Q_TXBD_NUM: u64 = 0x038C;

// ── Per-chip RCR receive-config seed value ───────────────────────────────
//
// Source: `rtl<ver>/sw.c::rtl<ver>_init_sw_vars`.  These bits are the
// post-init kernel-default; later code can OR/AND in promiscuous bits.

/// `RCR_AAP` — accept all packets (promiscuous; unicast & not-to-us).
pub const RCR_AAP: u32 = 1 << 0;
/// `RCR_APM` — accept physical match (unicast to our MAC).
pub const RCR_APM: u32 = 1 << 1;
/// `RCR_AM` — accept multicast.
pub const RCR_AM: u32 = 1 << 2;
/// `RCR_AB` — accept broadcast.
pub const RCR_AB: u32 = 1 << 3;
/// `RCR_ACRC32` — accept CRC-error packets (off in production).
pub const RCR_ACRC32: u32 = 1 << 5;
/// `RCR_ACF` — accept ctrl-frames.
pub const RCR_ACF: u32 = 1 << 6;
/// `RCR_AMF` — accept mgmt-frames.
pub const RCR_AMF: u32 = 1 << 7;
/// `RCR_HTC_LOC_CTRL` — leave at default.
pub const RCR_HTC_LOC_CTRL: u32 = 1 << 14;

/// Default RCR seed used by every chip (8192EE example).  All directed,
/// broadcast, multicast, control, and management traffic plus the
/// CRC-error tap kept off in production.  Source: `rtl8192ee/sw.c:85..96`.
pub const RCR_DEFAULT: u32 = RCR_APM | RCR_AM | RCR_AB | RCR_AMF | RCR_ACF;

/// Default TCR — `rtl8192ee/sw.c::transmit_config = 0x40404`.
pub const TCR_DEFAULT: u32 = 0x0004_0404;

/// Number of host-managed TX rings the rtlwifi family programs.
/// Beacon, MGT, HI, VO, VI, BE, BK, TXCMD, HCCA — but the driver only
/// programs the first 8 in the post-power-on init.
pub const TX_QUEUE_COUNT: usize = RTL_PCI_MAX_TX_QUEUE_COUNT;

// ── Errors ───────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MacInitError {
    /// `REG_AUTO_LLT` bit 0 never returned to 0 after the LLT-load
    /// trigger.  Hardware not powered or wrong cut.
    LltLoadTimeout,
}

// ── LLT-table init ───────────────────────────────────────────────────────

/// Program the LLT (linked-list table) that defines the on-chip TX
/// page-pool layout.  Mirrors `_rtl92ee_llt_table_init`
/// (`rtl8192ee/hw.c:674`).
///
/// # Safety
/// Caller must own BAR0 exclusively and the chip must already be powered
/// on (see [`super::power::power_on`]).
pub unsafe fn init_llt_table(mmio: &MmioRegion, did: u16) -> Result<(), MacInitError> {
    let bndy = txpktbuf_bndy_for(did);

    // SAFETY: caller-asserted.
    unsafe {
        // RQPN preset (TX queue page configuration).  `hw.c:682`.
        mmio.write32(REG_RQPN, 0x80E6_0808);

        // TX/RX FIFO boundary.  `hw.c:684..685`.
        mmio.write8(REG_TRXFF_BNDY, bndy);
        mmio.write16(REG_TRXFF_BNDY + 2, 0x3d00 - 1);

        // Per-beacon-queue page boundary.  `hw.c:687..691`.
        mmio.write8(REG_DWBCN0_CTRL + 1, bndy);
        mmio.write8(REG_DWBCN1_CTRL + 1, bndy);
        mmio.write8(REG_BCNQ_BDNY, bndy);
        mmio.write8(REG_BCNQ1_BDNY, bndy);

        // MGNT-queue page boundary.  `hw.c:693..694`.
        mmio.write8(REG_MGQ_BDNY, bndy);
        mmio.write8(0x045D, bndy);

        // Page-boundary pointer + RX drvinfo size.  `hw.c:696..697`.
        mmio.write8(REG_PBP, 0x31);
        mmio.write8(REG_RX_DRVINFO_SZ, 0x4);

        // Trigger auto-LLT load.  `hw.c:699..708`.
        let u8tmp = mmio.read8(REG_AUTO_LLT + 2);
        mmio.write8(REG_AUTO_LLT + 2, u8tmp | 0x01);
    }

    // Poll AUTO_LLT[+2] bit0 back to 0 (load complete).
    let offset = REG_AUTO_LLT + 2;
    let done = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: same.
            unsafe { mmio.read8(offset) & 0x01 == 0 }
        },
        Deadline::after_ms(10),
    );
    if !done {
        return Err(MacInitError::LltLoadTimeout);
    }
    Ok(())
}

/// Post-power-on MAC initialization sequence.  Walks
/// `_rtl92ee_init_mac` minus the platform-specific DMA-base programming
/// (that lands once the ring allocator has physical addresses).
///
/// Steps performed here:
/// 1. Release MAC IO reset (`REG_CR = 0xFF`, mdelay 2, `REG_CR = 0x2FF`).
/// 2. Call [`init_llt_table`].
/// 3. Clear `REG_HISR{,E}`.
/// 4. Enable TRX DMA via `REG_TRXDMA_CTRL`.
/// 5. Program RCR + TCR.
/// 6. Open `REG_FWHW_TXQ_CTRL+1` for rate-adaptive feedback.
///
/// DMA base addresses (`REG_BCNQ_DESA` etc.) and ring sizes
/// (`REG_*_TXBD_NUM`) are programmed once the DMA ring layer has
/// allocated buffers — see [`crate::rtlwifi::dma::program_ring_bases`].
///
/// # Safety
/// Caller must own BAR0 exclusively and the chip must be powered on.
pub unsafe fn init_mac(mmio: &MmioRegion, did: u16) -> Result<(), MacInitError> {
    // SAFETY: caller-asserted.
    unsafe {
        // 1. Release MAC IO reset.  `hw.c:780..794`.
        mmio.write8(REG_CR, 0xFF);
        narf_time::busy_wait_cycles(2_000_000 * narf_time::cycles_per_ns().max(1) as u64);
        mmio.write8(REG_HWSEQ_CTRL, 0x7F);
        narf_time::busy_wait_cycles(2_000_000 * narf_time::cycles_per_ns().max(1) as u64);

        // Wakeup-online bits: `hw.c:789..792`.
        let bytetmp = mmio.read8(REG_SYS_CLKR);
        mmio.write8(REG_SYS_CLKR, bytetmp | (1 << 3));
        let bytetmp = mmio.read8(0x0041);
        mmio.write8(0x0041, bytetmp & !(1 << 4));

        // Full CR open (TXDMA + RXDMA enabled).  `hw.c:794`.
        mmio.write16(REG_CR, 0x02FF);
    }

    // 2. LLT.
    // SAFETY: forwarded.
    unsafe { init_llt_table(mmio, did) }?;

    // SAFETY: caller-asserted.
    unsafe {
        // 3. Clear interrupt status.  `hw.c:804..805`.
        mmio.write32(REG_HISR, 0xFFFF_FFFF);
        mmio.write32(REG_HISRE, 0xFFFF_FFFF);

        // 4. TRXDMA_CTRL.  `hw.c:807..810`.
        let wordtmp = mmio.read16(REG_TRXDMA_CTRL);
        let wordtmp = (wordtmp & 0x000F) | 0xF5B1;
        mmio.write16(REG_TRXDMA_CTRL, wordtmp);

        // 5. RCR + TCR.  `hw.c:812..819`.
        mmio.write8(REG_FWHW_TXQ_CTRL + 1, 0x1F);
        mmio.write32(REG_RCR, RCR_DEFAULT);
        mmio.write16(REG_RXFLTMAP2, 0xFFFF);
        mmio.write32(REG_TCR, TCR_DEFAULT);

        // 6. Misc post-config: integration / TSF.
        mmio.write32(REG_INT_MIG, 0);
        mmio.write32(REG_MCUTST_1, 0);
        mmio.write32(REG_TSFTIMER_HCI, 0x3FFF_FFFF);
    }

    Ok(())
}

/// Convenience: per-queue (`REG_*_DESA`) DMA-base register table.
pub const fn desa_reg_for_queue(q: usize) -> Option<u64> {
    match q {
        BK_QUEUE => Some(REG_BKQ_DESA),
        BE_QUEUE => Some(REG_BEQ_DESA),
        VI_QUEUE => Some(REG_VIQ_DESA),
        VO_QUEUE => Some(REG_VOQ_DESA),
        BEACON_QUEUE => Some(REG_BCNQ_DESA),
        MGNT_QUEUE => Some(REG_MGQ_DESA),
        HIGH_QUEUE => Some(REG_HQ0_DESA),
        _ => None,
    }
}

/// Convenience: per-queue (`REG_*_TXBD_NUM`) ring-size register table.
pub const fn bd_num_reg_for_queue(q: usize) -> Option<u64> {
    match q {
        BK_QUEUE => Some(REG_BKQ_TXBD_NUM),
        BE_QUEUE => Some(REG_BEQ_TXBD_NUM),
        VI_QUEUE => Some(REG_VIQ_TXBD_NUM),
        VO_QUEUE => Some(REG_VOQ_TXBD_NUM),
        MGNT_QUEUE => Some(REG_MGQ_TXBD_NUM),
        HIGH_QUEUE => Some(REG_HI0Q_TXBD_NUM),
        _ => None,
    }
}
