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
    /// How the effective masks relate to the retained map's.
    pub masks: Masks,
    /// `hw.c::ath9k_hw_init_mfp` branch.
    pub mfp: Mfp,
}
/// Relation between the effective chain masks and the factory map's
/// `rxMask`/`txMask`.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Masks {
    /// Two-chain AR9002 parts: the effective masks are the map's (1..=3).
    Factory,
    /// AR5416/AR5418/AR9160 (three chains): `ath9k_hw_fill_cap_info` then
    /// `hw.c::fixup_chainmask` against 0x7. `cb71` is the PCI AR5416
    /// (`0x0023`) whose map lacks `AR5416_OPFLAGS_11A`: its RX mask is the
    /// GPIO 0 strap (0x5 high, else 0x7), not the map's `rxMask`.
    ThreeChain { cb71: bool },
}
/// `ath9k_hw_init_mfp` for the chip generation.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mfp {
    /// `AR_SREV_9280_20_OR_LATER`: `AR_AES_MUTE_MASK1_FC_MGMT` = 0xc7ff.
    AesMute,
    /// `AR_SREV_9160_10_OR_LATER` below AR9280: `AR_PCU_MISC_MODE2`
    /// `MGMT_CRYPTO_ENABLE` cleared, `NO_CRYPTO_FOR_NON_DATA_PKT` set.
    MiscMode2,
    /// AR5416/AR5418: no register (software management crypto).
    None,
}
impl Profile {
    /// The unchanged single-chain AR9285 profile.
    pub(super) const AR9285: Self = Self {
        rx_chainmask: 1,
        tx_chainmask: 1,
        clock: Clock::Ofdm2g,
        txbuf: 0x380,
        masks: Masks::Factory,
        mfp: Mfp::AesMute,
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
            masks: Masks::Factory,
            mfp: Mfp::AesMute,
        }
    }
    /// AR9280 (two-chain def map) for one band: `ATH9K_CLOCK_RATE_2GHZ_OFDM`
    /// on 2.4 GHz, the fast 5 GHz clock (`ATH9K_HW_CAP_FASTCLOCK` is always
    /// set for AR9280) on 5 GHz, `AR_PCU_TXBUF_CTRL_USABLE_SIZE`.
    pub(super) fn ar9280(rx_chainmask: u8, tx_chainmask: u8, five_ghz: bool) -> Self {
        Self {
            rx_chainmask,
            tx_chainmask,
            clock: if five_ghz {
                Clock::Fast5g
            } else {
                Clock::Ofdm2g
            },
            txbuf: 0x700,
            masks: Masks::Factory,
            mfp: Mfp::AesMute,
        }
    }
    #[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
    /// AR5416/AR5418 (`ar9160 == false`) or AR9160 with their effective
    /// (`fixup_chainmask`) masks: no `ATH9K_HW_CAP_FASTCLOCK` below
    /// AR9280_20, so 5 GHz runs `ATH9K_CLOCK_RATE_5GHZ_OFDM` (40 MHz);
    /// `AR_PCU_TXBUF_CTRL_USABLE_SIZE`.
    pub(super) fn ar5008(
        rx_chainmask: u8,
        tx_chainmask: u8,
        five_ghz: bool,
        ar9160: bool,
        cb71: bool,
    ) -> Self {
        Self {
            rx_chainmask,
            tx_chainmask,
            clock: if five_ghz {
                Clock::Ofdm5g
            } else {
                Clock::Ofdm2g
            },
            txbuf: 0x700,
            masks: Masks::ThreeChain { cb71 },
            mfp: if ar9160 { Mfp::MiscMode2 } else { Mfp::None },
        }
    }
}
/// `hw.c::fixup_chainmask` against the three AR5008 chains.
fn fixup(mask: u8) -> u8 {
    match mask & 7 {
        0 => 7,
        fixed => fixed,
    }
}
/// The effective masks `ath9k_hw_fill_cap_info` + `fixup_chainmask` derive
/// from the retained map (and, for CB71, the live GPIO 0 strap).
fn masks_match(io: &impl Port, image: &[u8], profile: Profile) -> Result<bool, Error> {
    let (map_rx, map_tx) = (image[18], image[19]);
    Ok(match profile.masks {
        Masks::Factory => {
            (1..=3).contains(&profile.rx_chainmask)
                && (1..=3).contains(&profile.tx_chainmask)
                && [map_rx, map_tx] == [profile.rx_chainmask, profile.tx_chainmask]
        }
        Masks::ThreeChain { cb71 } => {
            // The CB71 rule applies exactly when the map lacks 11a.
            if cb71 && image[6] & 1 != 0 {
                return Ok(false);
            }
            let rx = if cb71 {
                if (io.read(0x4048)? >> 14) & 1 != 0 {
                    0x5
                } else {
                    0x7
                }
            } else {
                map_rx
            };
            profile.rx_chainmask == fixup(rx) && profile.tx_chainmask == fixup(map_tx)
        }
    })
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
    if image.len() < 22 || local[0] & 1 != 0 || local == [0; 6] || image[12..18] != local {
        return Err(Error::Packet);
    }
    if !masks_match(io, image, profile)? {
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
    // ah->slottime starts at 20 us; 5 GHz has only the short slot.
    let slot = if profile.clock.is_5ghz() { 9 } else { 20 };
    peer_clocked(io, None, slot, profile.clock)?;
    io.write(0x80, u32::MAX)?; // ISR is W1C; this is not an ordinary readback.
    write(io, 0x8018, 0x700)?;
    opmode(io)?;
    // ath9k_hw_init_mfp. No management key is installed by this profile.
    match profile.mfp {
        Mfp::AesMute => mfp(io)?,
        Mfp::MiscMode2 => modify(io, 0x8344, 0x2, 0x4)?,
        Mfp::None => {}
    }
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
/// channel, as used by `ath9k_hw_init_global_settings`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Clock {
    /// `ATH9K_CLOCK_RATE_2GHZ_OFDM` (44 MHz); USEC latencies stay as the INI
    /// left them and only `AR_USEC_USEC` is rewritten.
    Ofdm2g,
    /// `AR_SREV_9287_13_OR_LATER`: async FIFO at 117 MHz with
    /// `AR_USEC_ASYNC_FIFO` latencies and `AR_D_GBL_IFS_EIFS_ASYNC_FIFO`.
    AsyncFifo,
    /// `ATH9K_CLOCK_FAST_RATE_5GHZ_OFDM` (44 MHz) on a 5 GHz channel
    /// (`IS_CHAN_A_FAST_CLOCK`): SIFS 16 us and no 2 GHz ACK/CTS
    /// workaround; USEC latencies (the fast-clock INI's `rx_lat` 41) and
    /// EIFS stay as the INI left them, as for `Ofdm2g`.
    Fast5g,
    /// `ATH9K_CLOCK_RATE_5GHZ_OFDM` (40 MHz): a 5 GHz channel on a part
    /// without `ATH9K_HW_CAP_FASTCLOCK` (AR5416/AR5418/AR9160). SIFS 16 us,
    /// no 2 GHz ACK/CTS workaround; USEC latencies and EIFS stay as the INI
    /// left them.
    #[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
    Ofdm5g,
}
impl Clock {
    pub(super) fn rate(self) -> u32 {
        match self {
            Self::Ofdm2g | Self::Fast5g => 44,
            Self::Ofdm5g => 40,
            Self::AsyncFifo => 117,
        }
    }
    /// `IS_CHAN_5GHZ` of the channel this clock serves.
    pub(super) fn is_5ghz(self) -> bool {
        matches!(self, Self::Fast5g | Self::Ofdm5g)
    }
    /// `sifstime` of `ath9k_hw_init_global_settings`.
    pub(super) fn sifs_us(self) -> u32 {
        if self.is_5ghz() {
            16
        } else {
            10
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
    if !matches!(slot_us, 9 | 20) || (clock.is_5ghz() && slot_us != 9) {
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
    // Full rate, zero coverage class: Linux's 2 GHz 64us ACK/48us CTS
    // workaround is independent of the selected slot time; on 5 GHz
    // ACK and CTS timeouts are slot + SIFS.
    let rate = clock.rate();
    let sifs = clock.sifs_us();
    let (ack, cts) = if clock.is_5ghz() {
        (slot_us + sifs, slot_us + sifs)
    } else {
        (64, 48)
    };
    write(io, 0x1030, (sifs - 2) * rate)?;
    write(io, 0x1070, slot_us * rate)?;
    modify(io, 0x8014, 0x3fff_3fff, (ack * rate) | ((cts * rate) << 16))?;
    match clock {
        Clock::Ofdm2g | Clock::Fast5g | Clock::Ofdm5g => modify(io, 0x801c, 0x7f, rate - 1)?,
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
