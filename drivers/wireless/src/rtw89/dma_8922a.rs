// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A BE DMA ring programming + control sequencing.
//!
//! The transport half of the 8922A chip-row step 4. This module owns
//! the register writes Linux performs in `rtw89_pci_reset_trx_rings`
//! (`pci.c:1776`), `rtw89_pci_init_wp_16sel` (`pci.c:1722`), and the
//! BE DMA portions of `rtw89_pci_ops_mac_pre_init_be` /
//! `rtw89_pci_ops_mac_post_init_be` (`pci_be.c:493,631`) —
//! instantiated for 8922AE by `rtw8922a_pci_info`
//! (`rtw8922ae.c:23..77`), all torvalds/linux @ 05441d6.
//!
//! What this module deliberately does NOT own:
//! - Ring storage allocation (`alloc_coherent` composition lives
//!   with the probe owner; `pci.rs` already demonstrates the AX
//!   shape). Callers pass physical ring bases in.
//! - The MAC reset, debounce, LDO-low-power, PCIe-setting, and
//!   SER-setting steps between the pre-init halves (see
//!   [`pre_init_dma_before_reset`] / [`pre_init_dma_after_reset`]).
//! - Interrupt configuration (`irq_be`), the C2H completion path,
//!   and any production caller (Prepared wiring is a remainder).
//! - Timing: Linux polls with `read_poll_timeout` intervals
//!   (TX/RX idle 10 us / 1000 us, BDRAM bound 50 us / 500000 us,
//!   IO idle 10 us / 1000 us). This layer has no sleep primitive,
//!   so polls are bounded ATTEMPT counts derived from those
//!   intervals (100 / 10000 / 100 attempts); a caller that needs
//!   wall-time pacing wraps these calls in its own tick loop and
//!   retries on [`Error::PollTimeout`].
//!
//! Register bank: [`super::dma::BE_DMA_ADDR_SET`]; control words:
//! [`super::dma_be`]. 8922AE specifics pinned by `rtw8922a_pci_info`:
//! `rx_ring_eq_is_full = true` (RX doorbell seeded with `len - 1`),
//! `group_bd_addr = false` (NUM written as the plain length, never
//! the encoded group offset), `tx_dma_ch_mask = 0` (all 13 TX
//! channels programmed), `bd_ram_table = NULL` (no BDRAM_CTRL
//! writes — the BE set carries `bdram = 0`).

use super::dma::{BE_DMA_ADDR_SET, TXCH_NUM};
use super::dma_be::{
    self, clr_idx_all, ctrl_dma_all, io_idle, mode_op, rst_bdram_done, rst_bdram_set, rxdma_idle,
    trxdma, txdma_ch, txdma_fw_ch, txdma_idle, Ctrl, Regs, DMA_BUSY1, INIT_CFG1,
    MODE_PARAMS_8922AE,
};

/// Maximum TX BD ring depth (`RTW89_PCI_TXBD_NUM_MAX`,
/// `pci.h:1122`). Linux allocates this depth for every TX channel,
/// including the FW-command ring.
pub(super) const TXBD_NUM_MAX: u16 = 256;
/// Maximum RX BD ring depth (`RTW89_PCI_RXBD_NUM_MAX`,
/// `pci.h:1123`).
pub(super) const RXBD_NUM_MAX: u16 = 256;
/// `R_BE_WP_ADDR_H_SEL0_3_V1` (`pci.h:896`), the base of the
/// WP-address-high-select block (`rtw8922a_pci_info.wp_sel_addr`).
pub(super) const WP_SEL_BASE: u32 = 0xB420;

/// Poll attempts for TX/RX DMA idle (Linux 1000 us timeout at
/// 10 us intervals).
pub(super) const TXRX_IDLE_ATTEMPTS: u32 = 100;
/// Poll attempts for BDRAM-bound clear (Linux 500000 us timeout
/// at 50 us intervals).
pub(super) const BDRAM_ATTEMPTS: u32 = 10_000;
/// Poll attempts for IO idle (Linux 1000 us timeout at 10 us
/// intervals).
pub(super) const IO_IDLE_ATTEMPTS: u32 = 100;

/// Ring-programming / sequencing failures. Every variant is a
/// refusal: no partial ring state is left behind by the failing
/// call itself (earlier channels programmed by the same call keep
/// their writes — the caller re-runs programming after fixing the
/// input, as Linux re-runs reset after a failed start).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    /// Channel outside 0..13 (TX) or 0..2 (RX).
    BadChannel,
    /// Ring length zero or above the Linux maximum (256).
    BadLength,
    /// A bounded idle/bound poll exhausted its attempts.
    PollTimeout,
}

/// Program one TX ring: NUM then DESA_L/DESA_H, in Linux
/// `rtw89_pci_reset_trx_rings` order (BDRAM write skipped: the BE
/// set carries `bdram = 0` and 8922AE has no BDRAM table).
pub(super) fn program_tx_ring(
    regs: &mut impl Regs,
    channel: u8,
    phys: u64,
    len: u16,
) -> Result<(), Error> {
    let ring = BE_DMA_ADDR_SET
        .tx
        .get(channel as usize)
        .ok_or(Error::BadChannel)?;
    if len == 0 || len > TXBD_NUM_MAX {
        return Err(Error::BadLength);
    }
    regs.write16(ring.num as u32, len);
    regs.write32(ring.desa_l as u32, phys as u32);
    regs.write32(ring.desa_h as u32, (phys >> 32) as u32);
    Ok(())
}

/// Program one RX ring: NUM then DESA_L/DESA_H, then the doorbell
/// seed `len - 1` (`rx_ring_eq_is_full = true`).
pub(super) fn program_rx_ring(
    regs: &mut impl Regs,
    channel: u8,
    phys: u64,
    len: u16,
) -> Result<(), Error> {
    let ring = BE_DMA_ADDR_SET
        .rx
        .get(channel as usize)
        .ok_or(Error::BadChannel)?;
    if len == 0 || len > RXBD_NUM_MAX {
        return Err(Error::BadLength);
    }
    regs.write16(ring.num as u32, len);
    regs.write32(ring.desa_l as u32, phys as u32);
    regs.write32(ring.desa_h as u32, (phys >> 32) as u32);
    // Seed the RX doorbell: the chip starts consuming from slot 0
    // only once the host has published `len - 1` (eq-is-full ring).
    regs.write16(ring.idx as u32, len - 1);
    Ok(())
}

/// Program all 13 TX rings then both RX rings. Lengths are the
/// Linux maxima unless the caller deliberately sizes smaller.
pub(super) fn program_all_rings(
    regs: &mut impl Regs,
    tx_phys: &[u64; TXCH_NUM],
    rx_phys: &[u64; 2],
    tx_len: u16,
    rx_len: u16,
) -> Result<(), Error> {
    for (channel, phys) in tx_phys.iter().enumerate() {
        program_tx_ring(regs, channel as u8, *phys, tx_len)?;
    }
    for (channel, phys) in rx_phys.iter().enumerate() {
        program_rx_ring(regs, channel as u8, *phys, rx_len)?;
    }
    Ok(())
}

/// `rtw89_pci_init_wp_16sel` for BE: four writes starting at
/// [`WP_SEL_BASE`], each packing four consecutive channel indices
/// into the byte lanes (group `i` covers channels `i..i+4`).
pub(super) fn init_wp_16sel(regs: &mut impl Regs) {
    for group in [0u32, 4, 8, 12] {
        let val = group | ((group + 1) << 8) | ((group + 2) << 16) | ((group + 3) << 24);
        regs.write32(WP_SEL_BASE + group, val);
    }
}

/// `rtw89_pci_reset_trx_rings` for 8922A: program all rings, then
/// the WP-select block. Host wp/rp bookkeeping resets to 0 are the
/// caller's (see [`super::dma::RingState`]).
pub(super) fn reset_trx_rings(
    regs: &mut impl Regs,
    tx_phys: &[u64; TXCH_NUM],
    rx_phys: &[u64; 2],
    tx_len: u16,
    rx_len: u16,
) -> Result<(), Error> {
    program_all_rings(regs, tx_phys, rx_phys, tx_len, rx_len)?;
    init_wp_16sel(regs);
    Ok(())
}

/// Bounded poll of `DMA_BUSY1` until `pred` holds.
fn poll_busy1(regs: &mut impl Regs, pred: fn(u32) -> bool, attempts: u32) -> Result<(), Error> {
    for _ in 0..attempts {
        if pred(regs.read32(DMA_BUSY1)) {
            return Ok(());
        }
    }
    Err(Error::PollTimeout)
}

/// Bounded poll of `INIT_CFG1` until `pred` holds.
fn poll_init_cfg1(regs: &mut impl Regs, pred: fn(u32) -> bool, attempts: u32) -> Result<(), Error> {
    for _ in 0..attempts {
        if pred(regs.read32(INIT_CFG1)) {
            return Ok(());
        }
    }
    Err(Error::PollTimeout)
}

/// Pre-init DMA, first half (`pci_be.c:493`, before the caller's
/// MAC reset): `wpdma(false)` → `trxdma(Disable, Disable,
/// Disable)` → `clr_idx_all` → poll TX+RX DMA idle →
/// `mode_op` with the 8922AE tuning values. RX doorbells are
/// seeded with `len - 1` by `clr_idx_all`, matching the
/// eq-is-full ring convention.
pub(super) fn pre_init_dma_before_reset(
    regs: &mut impl Regs,
    rxq_len: u16,
    rpq_len: u16,
) -> Result<(), Error> {
    dma_be::wpdma(regs, false);
    trxdma(regs, Ctrl::Disable, Ctrl::Disable, Ctrl::Disable);
    clr_idx_all(regs, rxq_len, rpq_len).map_err(|_| Error::BadLength)?;
    poll_busy1(regs, txdma_idle, TXRX_IDLE_ATTEMPTS)?;
    poll_busy1(regs, rxdma_idle, TXRX_IDLE_ATTEMPTS)?;
    mode_op(regs, MODE_PARAMS_8922AE);
    Ok(())
}

/// Pre-init DMA, second half (`pci_be.c:493`, after the caller's
/// MAC reset, debounce, LDO-low-power, PCIe-setting, and
/// SER-setting): `rst_bdram_set` → poll bound clear →
/// `txdma_ch(false)` → `txdma_fw_ch(true)` →
/// `trxdma(Enable, Enable, Enable)`. The post-init tail is
/// [`dma_be::post_init_dma`] (LTR set → `trxdma(Ignore, Ignore,
/// Enable)` → `wpdma(true)` → `txdma_ch(true)` →
/// `txdma_fw_ch(true)` → `configure_mit`); it is not wrapped
/// here because it takes no parameters beyond the register bank.
pub(super) fn pre_init_dma_after_reset(regs: &mut impl Regs) -> Result<(), Error> {
    rst_bdram(regs)?;
    pre_init_dma_enable(regs);
    Ok(())
}

/// `rtw89_pci_rst_bdram_be`: `rst_bdram_set` then poll the bound
/// bit clear. Linux runs debounce / LDO / PCIe / SER settings
/// between this and [`pre_init_dma_enable`]
/// (`pci_pre_init_8922a::settings`).
pub(super) fn rst_bdram(regs: &mut impl Regs) -> Result<(), Error> {
    rst_bdram_set(regs);
    poll_init_cfg1(regs, rst_bdram_done, BDRAM_ATTEMPTS)
}

/// The `rtw89_pci_ops_mac_pre_init_be` tail: `txdma_ch(false)` →
/// `txdma_fw_ch(true)` → `trxdma(Enable, Enable, Enable)` — only
/// the CH12 FW-command channel may move until the post-init tail.
pub(super) fn pre_init_dma_enable(regs: &mut impl Regs) {
    txdma_ch(regs, false);
    txdma_fw_ch(regs, true);
    trxdma(regs, Ctrl::Enable, Ctrl::Enable, Ctrl::Enable);
}

/// LV1-reset stop half (`pci_be.c:669`): `ctrl_dma_all(false)` →
/// poll IO idle. The start half additionally toggles
/// `mac_ctrl_hci_dma_trx` off/on around `clr_idx_all` +
/// `rst_bdram_set` + `ctrl_dma_all(true)`; that toggle lives
/// outside the DMA block and stays with the reset owner.
pub(super) fn stop_dma(regs: &mut impl Regs) -> Result<(), Error> {
    ctrl_dma_all(regs, false);
    poll_busy1(regs, io_idle, IO_IDLE_ATTEMPTS)?;
    Ok(())
}

/// Ring the TX doorbell: publish host `wp` through the low-16-bit
/// index half. Never read-modify-write the index register — the
/// hardware read pointer lives in bits 27:16.
pub(super) fn doorbell_tx(regs: &mut impl Regs, channel: u8, wp: u16) -> Result<(), Error> {
    let ring = BE_DMA_ADDR_SET
        .tx
        .get(channel as usize)
        .ok_or(Error::BadChannel)?;
    regs.write16(ring.idx as u32, wp);
    Ok(())
}

/// Ring the RX doorbell (replenish acknowledgement).
pub(super) fn doorbell_rx(regs: &mut impl Regs, channel: u8, wp: u16) -> Result<(), Error> {
    let ring = BE_DMA_ADDR_SET
        .rx
        .get(channel as usize)
        .ok_or(Error::BadChannel)?;
    regs.write16(ring.idx as u32, wp);
    Ok(())
}

/// Read back a TX ring's full index word (HW RP in bits 27:16,
/// host WP in bits 11:0; split with [`super::dma::split_idx`]).
pub(super) fn read_tx_idx(regs: &mut impl Regs, channel: u8) -> Result<u32, Error> {
    let ring = BE_DMA_ADDR_SET
        .tx
        .get(channel as usize)
        .ok_or(Error::BadChannel)?;
    Ok(regs.read32(ring.idx as u32))
}

/// Read back an RX ring's full index word.
pub(super) fn read_rx_idx(regs: &mut impl Regs, channel: u8) -> Result<u32, Error> {
    let ring = BE_DMA_ADDR_SET
        .rx
        .get(channel as usize)
        .ok_or(Error::BadChannel)?;
    Ok(regs.read32(ring.idx as u32))
}
