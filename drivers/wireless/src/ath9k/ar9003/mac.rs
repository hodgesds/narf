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
//! AR9300 awake legacy station PCU/queue preparation, the AR9003 profile of
//! the shared `mac::prepare_chip` recipe (which stays byte-identical for
//! AR5008/AR9002): `hw.c::ath9k_hw_set_clockrate` (2 GHz
//! `ATH9K_CLOCK_RATE_2GHZ_OFDM`, 5 GHz `ATH9K_CLOCK_FAST_RATE_5GHZ_OFDM`
//! under `ATH9K_HW_CAP_FASTCLOCK`; `ath9k_hw_init_global_settings`
//! rewrites only `AR_USEC_USEC`, the fast-clock INI having set the
//! latencies), the `AR_SREV_9300_20_OR_LATER` branches of
//! `ath9k_hw_set_dma` (no AHB prefetch or `AR_FTRIG` write,
//! `AR_RXBP_THRESH` HP/LP 1; `AR_DATABUF_SIZE` and the status ring belong
//! to the EDMA packet owner) and `ath9k_hw_resettxqueue`
//! (`AR_Q_DESC_CRCCHK_EN`), `AR_PHY_ACTIVE` at 0xa20c, and the AR9300
//! GPIO block (`AR_GPIO_OE_OUT` 0x4050, `AR_GPIO_IN` 0x404c,
//! `AR9300_GPIO_MASK`) for the `EEP_RF_SILENT` input.
#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

use super::eeprom::Identity;
use crate::ath9k::mac::{self as shared, Clock};
use crate::ath9k::packet::{Error, Port};

const AR_CR: u64 = 0x0008;
const AR_CR_RXE: u32 = 0xc;
const AR_CFG: u64 = 0x0014;
const AR_RXBP_THRESH: u64 = 0x0018;
const AR_IER: u64 = 0x0024;
const AR_TXCFG: u64 = 0x0030;
const AR_RXCFG: u64 = 0x0034;
const AR_Q_TXE: u64 = 0x0840;
const AR_Q_DESC_CRCCHK: u64 = 0x0a44;
const AR_GPIO_IN: u64 = 0x404c;
const AR_GPIO_OE_OUT: u64 = 0x4050;
const AR_STA_ID1: u64 = 0x8004;
const AR_DIAG_SW: u64 = 0x8048;
const AR_DIAG_RX_PARK: u32 = 0x0200_0020;
const AR_RXFIFO_CFG: u64 = 0x8114;
const AR_PCU_TXBUF_CTRL: u64 = 0x8340;
/// `ar9003_phy.h::AR_PHY_ACTIVE`.
const AR_PHY_ACTIVE: u64 = 0xa20c;
/// `reg.h::AR9300_GPIO_MASK`: the pins `ath9k_hw_gpio_request` drives.
const AR9300_GPIO_MASK: u32 = 0xf4ff;
/// `ar9300_base_eep_hdr.rfSilent` in the restored image.
pub(in crate::ath9k) const RF_SILENT: usize = 35;

fn write(io: &impl Port, reg: u64, value: u32) -> Result<(), Error> {
    io.write(reg, value)?;
    if io.read(reg)? != value {
        return Err(Error::Descriptor);
    }
    Ok(())
}
fn modify(io: &impl Port, reg: u64, clear: u32, set: u32) -> Result<(), Error> {
    let value = io.read(reg)?;
    write(io, reg, (value & !clear) | set)
}

/// `ath9k_hw_set_clockrate` for a full-rate 20 MHz AR9300 channel.
pub(in crate::ath9k) fn clock(five_ghz: bool) -> Clock {
    if five_ghz {
        Clock::Fast5g
    } else {
        Clock::Ofdm2g
    }
}

/// `EEP_RFSILENT_GPIO_SEL` / `EEP_RFSILENT_POLARITY` of an enabled
/// RF-silent input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::ath9k) struct RfKill {
    pub gpio: u8,
    pub polarity: bool,
}

/// `ath9k_hw_fill_cap_info`'s `EEP_RF_SILENT` decode: `None` without
/// `EEP_RFSILENT_ENABLED`; reserved bits or a pin outside
/// `AR9300_GPIO_MASK` are refused.
pub(in crate::ath9k) fn rf_silent(image: &[u8]) -> Result<Option<RfKill>, Error> {
    let value = *image.get(RF_SILENT).ok_or(Error::Packet)?;
    if value & 1 == 0 {
        return Ok(None);
    }
    let gpio = (value >> 2) & 7;
    if value & !0x1f != 0 || AR9300_GPIO_MASK & (1 << gpio) == 0 {
        return Err(Error::Packet);
    }
    Ok(Some(RfKill {
        gpio,
        polarity: value & 2 != 0,
    }))
}

/// `main.c::ath_is_rfkill_set`: `ath9k_hw_gpio_get` (AR9300: the
/// `AR_GPIO_IN` bit) against the polarity.
pub(in crate::ath9k) fn rf_kill_asserted(io: &impl Port, kill: RfKill) -> Result<bool, Error> {
    let value = io.read(AR_GPIO_IN)?;
    if value == u32::MAX {
        return Err(Error::Access);
    }
    Ok((value & (1 << kill.gpio) != 0) == kill.polarity)
}

/// `ath9k_hw_set_dma` for `AR_SREV_9300_20_OR_LATER`: 128-byte TX/RX DMA,
/// `AR_RXFIFO_CFG` 0x200, `AR_RXBP_THRESH` HP/LP 1 and
/// `AR_PCU_TXBUF_CTRL_USABLE_SIZE`.
pub(in crate::ath9k) fn dma(io: &impl Port) -> Result<(), Error> {
    modify(io, AR_TXCFG, 7, 5)?;
    modify(io, AR_RXCFG, 7, 5)?;
    write(io, AR_RXFIFO_CFG, 0x200)?;
    modify(io, AR_RXBP_THRESH, 0xf, 1)?;
    modify(io, AR_RXBP_THRESH, 0x3f00, 1 << 8)?;
    write(io, AR_PCU_TXBUF_CTRL, 0x700)
}

fn parked(io: &impl Port) -> Result<bool, Error> {
    Ok(io.read(AR_CR)? & AR_CR_RXE == 0
        && io.read(AR_Q_TXE)? & 0x3ff == 0
        && io.read(AR_IER)? & 1 == 0
        && io.read(AR_DIAG_SW)? & AR_DIAG_RX_PARK == AR_DIAG_RX_PARK)
}

/// `ath9k_hw_reset` station PCU/queue preparation of a calibrated AR9300
/// on one band of its map, with the shared station steps (`mac::peer_clocked`
/// at the band's clock, `opmode`, `mfp` (`AR_SREV_9280_20_OR_LATER`),
/// `queue0`, `qos`). Returns the RF-silent input the map names.
pub(in crate::ath9k) fn prepare(
    io: &impl Port,
    identity: &Identity,
    image: &[u8],
    local: [u8; 6],
    five_ghz: bool,
) -> Result<Option<RfKill>, Error> {
    if local[0] & 1 != 0 || local == [0; 6] || identity.mac != local {
        return Err(Error::Packet);
    }
    let band = if five_ghz { 1 } else { 2 };
    if identity.op_flags & band == 0 {
        return Err(Error::Packet);
    }
    let kill = rf_silent(image)?;
    if !parked(io)? || io.read(AR_PHY_ACTIVE)? & 1 == 0 {
        return Err(Error::State);
    }
    // Single little-endian descriptor/packet format on both architectures.
    modify(io, AR_CFG, 0x3f, 0)?;
    let basic = io.read(AR_STA_ID1)? & 0x0200_0000;
    modify(io, AR_STA_ID1, !0xffff, basic | 0x0080_0000 | 0x8800_0000)?;
    write(
        io,
        0x8000,
        u32::from_le_bytes([local[0], local[1], local[2], local[3]]),
    )?;
    modify(
        io,
        AR_STA_ID1,
        0xffff,
        u32::from(u16::from_le_bytes([local[4], local[5]])),
    )?;
    write(io, 0x80e0, u32::MAX)?;
    write(io, 0x80e4, 0xffff)?;
    let antenna = io.read(0x8058)?;
    write(io, 0x8058, if antenna == 0 { 1 } else { antenna })?;
    let slot = if five_ghz { 9 } else { 20 };
    shared::peer_clocked(io, None, slot, clock(five_ghz))?;
    io.write(0x80, u32::MAX)?; // ISR is W1C; this is not an ordinary readback.
    write(io, 0x8018, 0x700)?;
    shared::opmode(io)?;
    shared::mfp(io)?;
    for entry in 0..128u64 {
        for field in 0..8u64 {
            write(
                io,
                0x8800 + entry * 32 + field * 4,
                if field == 5 { 7 } else { 0 },
            )?;
        }
    }
    for queue in 0..10u64 {
        write(io, 0x1000 + queue * 4, 1 << queue)?;
    }
    shared::queue0(io)?;
    write(io, AR_Q_DESC_CRCCHK, 1)?;
    shared::qos(io)?;
    if let Some(kill) = kill {
        // ath9k_hw_gpio_request_in: AR_GPIO_OE_OUT_DRV_NO.
        modify(io, AR_GPIO_OE_OUT, 3 << (u32::from(kill.gpio) * 2), 0)?;
    }
    // AR_STA_ID1_PRESERVE_SEQNUM.
    modify(io, AR_STA_ID1, 0, 0x2000_0000)?;
    dma(io)?;
    if !parked(io)? {
        return Err(Error::State);
    }
    Ok(kill)
}

#[cfg(feature = "kernel-test")]
mod tests;
