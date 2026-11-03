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
//! AR9285 awake legacy station PCU/queue preparation; packet DMA stays off.
use super::{
    packet::{Error, Port},
    EEPROM_4K_BYTES,
};
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
fn word(image: &[u8], offset: usize) -> u16 {
    let bytes = [image[offset], image[offset + 1]];
    if image[7] & 1 != 0 {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    }
}
/// Chip-specific pieces of the parked station MAC preparation. The factory
/// base header (MAC at 12, rxMask/txMask at 18/19, rfSilent at 20) is shared
/// by `ar5416_eeprom_4k` and `ar9287_eeprom`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    /// Factory `rxMask`/`txMask` the retained map must carry.
    pub rx_chainmask: u8,
    pub tx_chainmask: u8,
    pub clock: Clock,
    /// `AR_PCU_TXBUF_CTRL` usable size for `ath9k_hw_set_dma`.
    pub txbuf: u32,
}
impl Profile {
    /// The unchanged single-chain AR9285 profile.
    pub(super) const AR9285: Self = Self {
        rx_chainmask: 1,
        tx_chainmask: 1,
        clock: Clock::Ofdm2g,
        txbuf: 0x380,
    };
    /// AR9287 with its factory two-chain masks; 1.3+ runs the async FIFO.
    pub(super) fn ar9287(rx_chainmask: u8, tx_chainmask: u8, async_fifo: bool) -> Self {
        Self {
            rx_chainmask,
            tx_chainmask,
            clock: if async_fifo {
                Clock::AsyncFifo
            } else {
                Clock::Ofdm2g
            },
            txbuf: 0x700,
        }
    }
}
pub(super) fn prepare(
    io: &impl Port,
    image: &[u8; EEPROM_4K_BYTES],
    local: [u8; 6],
) -> Result<(), Error> {
    prepare_chip(io, image, local, Profile::AR9285)
}
/// `ath9k_hw_reset` station PCU/queue preparation for `profile`. The
/// AR9285 profile is byte-identical to the historical single-chain path.
pub(super) fn prepare_chip(
    io: &impl Port,
    image: &[u8],
    local: [u8; 6],
    profile: Profile,
) -> Result<(), Error> {
    if image.len() < 22
        || !(1..=3).contains(&profile.rx_chainmask)
        || !(1..=3).contains(&profile.tx_chainmask)
    {
        return Err(Error::Packet);
    }
    if local[0] & 1 != 0
        || local == [0; 6]
        || image[12..18] != local
        || image[18..20] != [profile.rx_chainmask, profile.tx_chainmask]
    {
        return Err(Error::Packet);
    }
    if io.read(8)? & 4 != 0
        || io.read(0x840)? & 0x3ff != 0
        || io.read(0x24)? & 1 != 0
        || io.read(0x8048)? & 0x0200_0020 != 0x0200_0020
        || io.read(0x981c)? & 1 == 0
    {
        return Err(Error::State);
    }
    // Single little-endian descriptor/packet format on both CPU architectures.
    modify(io, 0x14, 0x3f, 0)?;
    // Reset operating mode; preserve the hardware's11b basic-rate selection,
    // use the default antenna and retain software-assigned sequence numbers.
    let basic = io.read(0x8004)? & 0x0200_0000;
    modify(io, 0x8004, !0xffff, basic | 0x0080_0000 | 0x8800_0000)?;
    write(
        io,
        0x8000,
        u32::from_le_bytes(local[..4].try_into().map_err(|_| Error::Packet)?),
    )?;
    modify(
        io,
        0x8004,
        0xffff,
        u32::from(u16::from_le_bytes([local[4], local[5]])),
    )?;
    write(io, 0x80e0, u32::MAX)?;
    write(io, 0x80e4, 0xffff)?;
    let antenna = io.read(0x8058)?;
    write(io, 0x8058, if antenna == 0 { 1 } else { antenna })?;
    peer_clocked(io, None, 20, profile.clock)?;
    io.write(0x80, u32::MAX)?; // ISR is W1C; this is not an ordinary readback.
    write(io, 0x8018, 0x700)?;
    opmode(io)?;
    // AR9285 native MFP setup. No management key is installed by this profile.
    mfp(io)?;
    // Clear all128 complete hardware key entries, including possible MIC
    // halves. Do not follow an inherited TKIP type beyond the actual cache.
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
    queue0(io)?;
    qos(io)?;
    // Factory RF-silent pin is an input, never a guessed board GPIO output.
    let rf = word(image, 20);
    if rf & 1 != 0 {
        if rf & !31 != 0 {
            return Err(Error::Packet);
        }
        let pin = (rf >> 2) & 7;
        modify(io, 0x404c, 3 << (pin * 2), 0)?;
    }
    modify(io, 0x8004, 0, 0x2000_0000)?;
    // `ath9k_hw_reset`: the AR9287 1.3+ PCU block precedes `set_dma`.
    if profile.clock == Clock::AsyncFifo {
        async_fifo_pcu(io)?;
    }
    dma_txbuf(io, profile.txbuf)?;
    // Explicitly reject stale enable/configuration state before a packet
    // owner can publish any DMA base. The signed policy remains separate.
    if io.read(8)? & 4 != 0
        || io.read(0x840)? & 0x3ff != 0
        || io.read(0x24)? & 1 != 0
        || io.read(0x8048)? & 0x0200_0020 != 0x0200_0020
    {
        return Err(Error::State);
    }
    Ok(())
}
/// MAC clock of `hw.c::ath9k_hw_set_clockrate` for a full-rate 20 MHz
/// 2.4 GHz channel, as used by `ath9k_hw_init_global_settings`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Clock {
    /// `ATH9K_CLOCK_RATE_2GHZ_OFDM` (44 MHz); USEC latencies stay as the INI
    /// left them and only `AR_USEC_USEC` is rewritten.
    Ofdm2g,
    /// `AR_SREV_9287_13_OR_LATER`: async FIFO at 117 MHz with
    /// `AR_USEC_ASYNC_FIFO` latencies and `AR_D_GBL_IFS_EIFS_ASYNC_FIFO`.
    AsyncFifo,
}
impl Clock {
    pub(super) fn rate(self) -> u32 {
        match self {
            Self::Ofdm2g => 44,
            Self::AsyncFifo => 117,
        }
    }
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn peer(
    io: &impl Port,
    bssid: Option<([u8; 6], u16)>,
    slot_us: u32,
) -> Result<(), Error> {
    peer_clocked(io, bssid, slot_us, Clock::Ofdm2g)
}
pub(super) fn peer_clocked(
    io: &impl Port,
    bssid: Option<([u8; 6], u16)>,
    slot_us: u32,
    clock: Clock,
) -> Result<(), Error> {
    if !matches!(slot_us, 9 | 20) {
        return Err(Error::Packet);
    }
    let (bssid, aid) = bssid.unwrap_or(([0; 6], 0));
    if bssid != [0; 6] && (bssid[0] & 1 != 0 || !(1..=2007).contains(&aid)) {
        return Err(Error::Packet);
    }
    write(
        io,
        0x8008,
        u32::from_le_bytes(bssid[..4].try_into().map_err(|_| Error::Packet)?),
    )?;
    write(
        io,
        0x800c,
        u32::from(u16::from_le_bytes([bssid[4], bssid[5]])) | (u32::from(aid) << 16),
    )?;
    // Full-rate 2.4 GHz, zero coverage class: Linux's 2 GHz 64us ACK/48us
    // CTS workaround is independent of the selected slot time.
    let rate = clock.rate();
    write(io, 0x1030, (10 - 2) * rate)?;
    write(io, 0x1070, slot_us * rate)?;
    modify(io, 0x8014, 0x3fff_3fff, (64 * rate) | ((48 * rate) << 16))?;
    match clock {
        Clock::Ofdm2g => modify(io, 0x801c, 0x7f, rate - 1)?,
        Clock::AsyncFifo => {
            write(io, 0x10b0, 363 * rate)?;
            // TX_LAT | RX_LAT | USEC = AR_USEC_ASYNC_FIFO (USEC = 117 - 1).
            modify(io, 0x801c, 0x1fff_c07f, 0x12e0_0074)?;
        }
    }
    // All multicast is received for software peer/key admission, with no
    // PHY error, HT/aggregation/control offload or promiscuous data contract.
    write(io, 0x803c, 0x17)?;
    write(io, 0x810c, 0)?;
    modify(io, 0x34, 0x10, 0)?;
    write(io, 0x8040, u32::MAX)?;
    write(io, 0x8044, u32::MAX)?;
    Ok(())
}

pub(super) fn queue0(io: &impl Port) -> Result<(), Error> {
    // Only DATA queue0 is active in the host profile. Non-QoS11b defaults,
    // regular backoff, finite retry and zero TXOP; other queues stay parked.
    write(io, 0x1040, 31 | (1023 << 10) | (2 << 20))?;
    write(io, 0x1080, 10 | (32 << 8) | (32 << 14))?;
    write(io, 0x9c0, 0x800)?;
    write(io, 0x1100, 0x1102)?;
    write(io, 0x10c0, 0)?;
    // No per-queue interrupt source is enabled in the polling profile.
    write(io, 0xa4, 0)?;
    write(io, 0xa8, 0)?;
    modify(io, 0xac, 0x3ff, 0)?;
    Ok(())
}
/// Source queue0 BE continuation. TXOP stays zero; no new AC is enabled.
pub(super) fn edca(io: &impl Port, be: narf_wireless::wmm::Ac) -> Result<(), Error> {
    if be.admission_control
        || be.txop != 0
        || be.cw_min() > 1023
        || be.cw_max() > 1023
        || !(2..=15).contains(&be.aifsn)
    {
        return Err(Error::Packet);
    }
    write(
        io,
        0x1040,
        u32::from(be.cw_min()) | (u32::from(be.cw_max()) << 10) | (u32::from(be.aifsn) << 20),
    )?;
    write(io, 0x10c0, 0)
}
/// `mac.c::ath9k_hw_resettxqueue` for an additional DATA QCU/DCU `q`
/// (1..3) with the actual AP's AIFS/CW word: the same finite retry,
/// early-termination and backoff recipe as queue0, and zero channel time
/// (one MPDU per access stays within any advertised TXOP limit).
pub(super) fn data_queue(io: &impl Port, q: u64, ifs: u32) -> Result<(), Error> {
    if !(1..4).contains(&q) {
        return Err(Error::Packet);
    }
    write(io, 0x1000 + q * 4, 1 << q)?;
    write(io, 0x1040 + q * 4, ifs)?;
    write(io, 0x1080 + q * 4, 10 | (32 << 8) | (32 << 14))?;
    write(io, 0x9c0 + q * 4, 0x800)?;
    write(io, 0x1100 + q * 4, 0x1102)?;
    write(io, 0x10c0 + q * 4, 0)
}
/// Readback of every programmed data QCU/DCU (0..3).
pub(super) fn check_data_queues(io: &impl Port, words: &[u32; 4]) -> Result<(), Error> {
    for q in 0..4u64 {
        if io.read(0x1040 + q * 4)? != words[q as usize] || io.read(0x10c0 + q * 4)? != 0 {
            return Err(Error::Descriptor);
        }
        if q != 0
            && (io.read(0x1000 + q * 4)? != 1 << q
                || io.read(0x1080 + q * 4)? != 10 | (32 << 8) | (32 << 14)
                || io.read(0x9c0 + q * 4)? != 0x800
                || io.read(0x1100 + q * 4)? != 0x1102)
        {
            return Err(Error::Descriptor);
        }
    }
    Ok(())
}
pub(super) fn qos(io: &impl Port) -> Result<(), Error> {
    write(io, 0x8118, 0x100aa)?;
    write(io, 0x811c, 0x3210)?;
    write(io, 0x8108, 0x52)?;
    write(io, 0x81ec, 0xff)?;
    for reg in [0x81f0, 0x81f4, 0x81f8, 0x81fc] {
        write(io, reg, u32::MAX)?;
    }
    Ok(())
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn dma(io: &impl Port) -> Result<(), Error> {
    // Linux ath9k_hw_set_dma, AR9285's2KiB TX FIFO workaround and128B bursts.
    dma_txbuf(io, 0x380)
}
/// `ath9k_hw_set_dma` with the chip's `AR_PCU_TXBUF_CTRL` usable size
/// (`AR_9285_PCU_TXBUF_CTRL_USABLE_SIZE` 0x380, otherwise 0x700).
pub(super) fn dma_txbuf(io: &impl Port, txbuf: u32) -> Result<(), Error> {
    modify(io, 0x4024, 0, 4)?;
    modify(io, 0x30, 7, 5)?;
    modify(io, 0x30, 0x3f0, 4 << 4)?;
    modify(io, 0x34, 7, 5)?;
    write(io, 0x8114, 0x200)?;
    write(io, 0x8340, txbuf)?;
    Ok(())
}

/// `hw.c::ath9k_hw_reset` AR9287 1.3+ PCU settings that follow
/// `ath9k_hw_init_global_settings`: logic-analyzer bug-20768 disable, AHB
/// custom burst `AR_AHB_CUSTOM_BURST_ASYNC_FIFO_VAL` and MISC_MODE2 AGGWEP.
pub(super) fn async_fifo_pcu(io: &impl Port) -> Result<(), Error> {
    modify(io, 0x8264, 0, 0x2000_0000)?;
    modify(io, 0x4024, 0xc0, 3 << 6)?;
    modify(io, 0x8344, 0, 0x2_0000)
}

pub(super) fn opmode(io: &impl Port) -> Result<(), Error> {
    modify(io, 0x14, 0x20, 0)?;
    modify(io, 0x8004, 0x0003_0000, 0x1000_0000)
}

pub(super) fn mfp(io: &impl Port) -> Result<(), Error> {
    modify(io, 0x8060, 0xffff_0000, 0xc7ff_0000)
}

#[cfg(feature = "kernel-test")]
#[path = "mac/tests.rs"]
mod tests;
