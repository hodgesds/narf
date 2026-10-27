// SPDX-License-Identifier: GPL-2.0-or-later
//! Legacy20 peer association commands; native WMI submission is not a key ACK.
use super::{wire, Error};
use crate::ath10k::wmi_boot::Dialect;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Associated {
    pub bssid: [u8; 6],
    pub frequency: u16,
    pub aid: u16,
    /// Association is separate from RSNA/key installation and port admission.
    pub protected: bool,
}

#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn peer(
    dialect: Dialect,
    bssid: [u8; 6],
    aid: u16,
    capabilities: u16,
    rates: u16,
    protected: bool,
) -> Result<Vec<u8>, Error> {
    peer_on(
        dialect,
        Associated {
            bssid,
            aid,
            frequency: 2412,
            protected,
        },
        capabilities,
        rates,
        false,
    )
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn peer_on(
    dialect: Dialect,
    associated: Associated,
    capabilities: u16,
    rates: u16,
    qos: bool,
) -> Result<Vec<u8>, Error> {
    peer_phy(dialect, associated, capabilities, rates, qos, None)
}
pub(super) fn peer_phy(
    dialect: Dialect,
    associated: Associated,
    capabilities: u16,
    rates: u16,
    qos: bool,
    ht: Option<super::ht::Profile>,
) -> Result<Vec<u8>, Error> {
    let Associated {
        bssid,
        aid,
        frequency,
        protected,
    } = associated;
    if bssid == [0; 6]
        || bssid[0] & 1 != 0
        || !(1..=2007).contains(&aid)
        || rates == 0
        || rates & !0xfff != 0
        || capabilities & 3 != 1
        || (capabilities & 16 != 0) != protected
        || !crate::ath10k::regulatory::Permission::profile_frequency(frequency)
        || frequency > 3000 && rates & 15 != 0
        || ht.is_some() && !qos
    {
        return Err(Error::Malformed);
    }
    let ieee = [2, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    let legacy: Vec<u8> = ieee
        .into_iter()
        .enumerate()
        .filter_map(|(i, rate)| (rates & (1 << i) != 0).then_some(rate))
        .collect();
    let tlv = dialect == Dialect::Tlv;
    let ht_rates: Vec<u8> = (0..8)
        .filter(|mcs| ht.is_some_and(|ht| ht.mcs & (1 << mcs) != 0))
        .collect();
    let (command, size) = match dialect {
        Dialect::Main => (0x6005, 356),
        Dialect::TenOne => (0x9020, 348),
        Dialect::TenTwo | Dialect::TenTwoFour => (0x9020, 352),
        Dialect::TenFour => (0x9026, 356),
        Dialect::Tlv => (
            0x6005,
            76 + 16 + 16 + legacy.len().next_multiple_of(4) + ht_rates.len().next_multiple_of(4),
        ),
    };
    let mut out = wire::packet(command, size)?;
    let at = if tlv {
        wire::put(&mut out, 4, (101 << 16) | 76);
        8
    } else {
        4
    };
    out[at..at + 6].copy_from_slice(&bssid);
    wire::put(&mut out, at + 12, 1); // new association, vdev0
    wire::put(&mut out, at + 16, u32::from(aid));
    // AUTH is Linux's association flag, independent of controlled-port state.
    wire::put(
        &mut out,
        at + 20,
        1 | if protected { 4 } else { 0 }
            | if qos { 2 } else { 0 }
            | if ht.is_some() { 0x1000 } else { 0 }
            | if ht.is_some_and(|h| h.secondary.is_some()) {
                0x2000
            } else {
                0
            },
    );
    wire::put(&mut out, at + 24, u32::from(capabilities));
    wire::put(&mut out, at + 28, 1); // Linux STA listen-interval workaround.
    if let Some(ht) = ht {
        wire::put(&mut out, at + 32, u32::from(ht.capabilities));
        wire::put(&mut out, at + 36, (1 << (13 + (ht.ampdu & 3))) - 1);
        wire::put(&mut out, at + 40, ht.density());
        wire::put(
            &mut out,
            at + 44,
            8 | if ht.short_gi { 4 } else { 0 } | if ht.secondary.is_some() { 2 } else { 0 },
        );
    }
    let mode = if let Some(ht) = ht {
        ht.mode(frequency)
    } else if frequency > 3000 {
        0
    } else if rates & !15 != 0 {
        1
    } else {
        2
    }; // 11A/G/B
    if tlv {
        wire::put(&mut out, at + 48, 1); // one spatial stream, no HT/VHT
        wire::put(&mut out, at + 56, mode);
        wire::put(&mut out, at + 68, legacy.len() as u32);
        wire::put(&mut out, at + 72, ht_rates.len() as u32);
        let padded = legacy.len().next_multiple_of(4);
        wire::put(&mut out, at + 76, (17 << 16) | padded as u32);
        out[at + 80..at + 80 + legacy.len()].copy_from_slice(&legacy);
        let ht_padded = ht_rates.len().next_multiple_of(4);
        wire::put(&mut out, at + 80 + padded, (17 << 16) | ht_padded as u32);
        out[at + 84 + padded..at + 84 + padded + ht_rates.len()].copy_from_slice(&ht_rates);
        wire::put(&mut out, at + 84 + padded + ht_padded, (102 << 16) | 16);
    } else {
        wire::put(&mut out, at + 48, legacy.len() as u32);
        out[at + 52..at + 52 + legacy.len()].copy_from_slice(&legacy);
        wire::put(&mut out, at + 184, ht_rates.len() as u32);
        out[at + 188..at + 188 + ht_rates.len()].copy_from_slice(&ht_rates);
        wire::put(&mut out, at + 320, 1);
        wire::put(&mut out, at + 328, mode);
        if matches!(
            dialect,
            Dialect::TenTwo | Dialect::TenTwoFour | Dialect::TenFour
        ) {
            wire::put(&mut out, at + 348, 0xff); // native10.2 max MCS/NSS fields.
        }
    }
    Ok(out)
}

pub(super) fn up(dialect: Dialect, bssid: [u8; 6], aid: u16) -> Result<Vec<u8>, Error> {
    if !(1..=2007).contains(&aid) || bssid == [0; 6] || bssid[0] & 1 != 0 {
        return Err(Error::Malformed);
    }
    let tlv = dialect == Dialect::Tlv;
    let command = match dialect {
        Dialect::Main | Dialect::Tlv => 0x5005,
        Dialect::TenOne => 0x9015,
        Dialect::TenTwo | Dialect::TenTwoFour => 0x9014,
        Dialect::TenFour => 0x9017,
    };
    let mut out = wire::packet(command, 16 + usize::from(tlv) * 4)?;
    let at = if tlv {
        wire::put(&mut out, 4, (92 << 16) | 16);
        8
    } else {
        4
    };
    wire::put(&mut out, at + 4, u32::from(aid));
    out[at + 8..at + 14].copy_from_slice(&bssid);
    Ok(out)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
