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
fn word(image: &[u8; EEPROM_4K_BYTES], offset: usize) -> u16 {
    let bytes = [image[offset], image[offset + 1]];
    if image[7] & 1 != 0 {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    }
}
pub(super) fn prepare(
    io: &impl Port,
    image: &[u8; EEPROM_4K_BYTES],
    local: [u8; 6],
) -> Result<(), Error> {
    if local[0] & 1 != 0 || local == [0; 6] || image[12..18] != local || image[18..20] != [1, 1] {
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
    peer(io, None, 20)?;
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
    dma(io)?;
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
pub(super) fn peer(
    io: &impl Port,
    bssid: Option<([u8; 6], u16)>,
    slot_us: u32,
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
    // Channel1 full-rate clock44MHz, zero coverage class: Linux's2GHz
    //64us ACK/48us CTS workaround is independent of the selected slot time.
    write(io, 0x1030, (10 - 2) * 44)?;
    write(io, 0x1070, slot_us * 44)?;
    modify(io, 0x8014, 0x3fff_3fff, (64 * 44) | ((48 * 44) << 16))?;
    modify(io, 0x801c, 0x7f, 43)?;
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
pub(super) fn dma(io: &impl Port) -> Result<(), Error> {
    // Linux ath9k_hw_set_dma, AR9285's2KiB TX FIFO workaround and128B bursts.
    modify(io, 0x4024, 0, 4)?;
    modify(io, 0x30, 7, 5)?;
    modify(io, 0x30, 0x3f0, 4 << 4)?;
    modify(io, 0x34, 7, 5)?;
    write(io, 0x8114, 0x200)?;
    write(io, 0x8340, 0x380)?;
    Ok(())
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
