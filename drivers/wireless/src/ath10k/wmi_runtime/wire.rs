// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux ath10k wmi{,-tlv}.{c,h}; no ath11k command shapes are reused.
use super::{Error, Management, ScanEvent};
use crate::ath10k::wmi_boot::{Capabilities, Dialect};
use alloc::vec::Vec;

pub(crate) const MAX_SCAN_SSIDS: usize = 16;
pub(crate) const MAX_SCAN_IE_LEN: u16 = 256;

#[derive(Clone, Copy, Debug)]
pub(super) struct Wire {
    pub dialect: Dialect,
    pub scan: u32,
    pub stop_scan: u32,
    pub channels: u32,
    pub create: u32,
    pub scan_event: u32,
    pub management_event: u32,
}
impl Wire {
    pub fn new(dialect: Dialect) -> Self {
        let (scan, stop_scan, channels, create, scan_event, management_event) = match dialect {
            Dialect::Main | Dialect::Tlv => (0x3001, 0x3002, 0x3003, 0x5001, 0x3001, 0x7001),
            Dialect::TenOne => (0x9000, 0x9001, 0x9002, 0x9011, 0x9000, 0x900c),
            Dialect::TenTwo | Dialect::TenTwoFour => {
                (0x9000, 0x9001, 0x9002, 0x9010, 0x9000, 0x900b)
            }
            Dialect::TenFour => (0x9000, 0x9001, 0x9002, 0x9013, 0x9000, 0x900b),
        };
        Self {
            dialect,
            scan,
            stop_scan,
            channels,
            create,
            scan_event,
            management_event,
        }
    }
    pub fn create(&self, mac: [u8; 6]) -> Result<Vec<u8>, Error> {
        if mac[0] & 1 != 0 || mac == [0; 6] {
            return Err(Error::Malformed);
        }
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.create, 20 + usize::from(tlv) * 4)?;
        let at = if tlv {
            header(&mut out, 86, 20);
            8
        } else {
            4
        };
        put(&mut out, at + 4, 2); // VDEV_TYPE_STA, vdev0/subtypeNONE.
        out[at + 12..at + 18].copy_from_slice(&mac);
        Ok(out)
    }
    pub fn channels(&self, channels: &[u16]) -> Result<Vec<u8>, Error> {
        validate_channels(channels)?;
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(
            self.channels,
            if tlv {
                12 + 28 * channels.len()
            } else {
                4 + 24 * channels.len()
            },
        )?;
        let mut at = 4;
        if tlv {
            put(&mut out, at, (79 << 16) | 4);
            at += 4;
        }
        put(&mut out, at, channels.len() as u32);
        at += 4;
        if tlv {
            put(&mut out, at, (18 << 16) | (28 * channels.len()) as u32);
            at += 4;
        }
        for frequency in channels {
            if tlv {
                put(&mut out, at, (80 << 16) | 24);
                at += 4;
            }
            put(&mut out, at, u32::from(*frequency));
            put(&mut out, at + 4, u32::from(*frequency));
            // PASSIVE, zero TX power and no IBSS/HT/VHT permission. 11G/11A.
            put(&mut out, at + 12, 0x80 | u32::from(*frequency < 3000));
            at += 24;
        }
        Ok(out)
    }
    pub fn scan(&self, sequence: u16, channels: &[u16]) -> Result<Vec<u8>, Error> {
        self.scan_mode(sequence, channels, &[], &[])
    }
    pub fn active_scan(
        &self,
        sequence: u16,
        channels: &[u16],
        ssids: &[Vec<u8>],
        extra_ies: &[u8],
    ) -> Result<Vec<u8>, Error> {
        validate_ssids(ssids)?;
        validate_probe_ies(extra_ies)?;
        self.scan_mode(sequence, channels, ssids, extra_ies)
    }
    pub fn active_channels(
        &self,
        permissions: &[crate::ath10k::regulatory::Permission],
    ) -> Result<Vec<u8>, Error> {
        let mut frequencies = Vec::new();
        frequencies
            .try_reserve_exact(permissions.len())
            .map_err(|_| Error::NoMemory)?;
        frequencies.extend(permissions.iter().map(|p| p.frequency));
        let mut out = self.channels(&frequencies)?;
        let tlv = self.dialect == Dialect::Tlv;
        let mut at = if tlv { 20 } else { 8 };
        for permission in permissions {
            // 11G, with no PASSIVE/IBSS/HT/VHT promotion. Power is half-dBm
            // in max/reg/max_tx fields (wmi_channel), not whole dBm.
            put(&mut out, at + 12, 1);
            out[at + 17] = permission.half_dbm;
            out[at + 18] = permission.half_dbm;
            out[at + 21] = permission.half_dbm;
            at += if tlv { 28 } else { 24 };
        }
        Ok(out)
    }
    fn scan_mode(
        &self,
        sequence: u16,
        channels: &[u16],
        ssids: &[Vec<u8>],
        extra_ies: &[u8],
    ) -> Result<Vec<u8>, Error> {
        validate_channels(channels)?;
        if sequence == 0 || sequence > 4095 {
            return Err(Error::Exhausted);
        }
        let tlv = self.dialect == Dialect::Tlv;
        let main = matches!(self.dialect, Dialect::Main | Dialect::TenFour);
        let common = if tlv {
            100
        } else if main {
            64
        } else {
            60
        };
        let active = !ssids.is_empty();
        let padded_ies = extra_ies.len().div_ceil(4) * 4;
        let extra = 24
            + channels.len() * 4
            + ssids.len() * 36
            + usize::from(active && !tlv) * 8
            + padded_ies
            + usize::from(!extra_ies.is_empty() && !tlv) * 8;
        let mut out = packet(self.scan, common + extra + usize::from(tlv) * 4)?;
        let base = if tlv {
            header(&mut out, 77, 100);
            8
        } else {
            4
        };
        for (i, value) in [
            0xa000 | u32::from(sequence),
            0xa001,
            0,
            1,
            0x15f,
            50,
            150,
            50,
            500,
            0,
            0,
            0,
            20_000,
            5,
            // Keep passive wire compatibility. Active probes advertise CCK
            // and OFDM legacy rates, skip DFS, and retain probe-RX filtering.
            // TLV inverts FILTER_PROBE_REQ just as Linux wmi-tlv.c does.
            if active {
                if tlv {
                    0x5c
                } else {
                    0x7c
                }
            } else if tlv {
                0x11
            } else {
                0x31
            },
        ]
        .iter()
        .enumerate()
        {
            put(&mut out, base + i * 4, *value);
        }
        let mut at = base + common;
        if tlv {
            put(&mut out, base + 64, channels.len() as u32);
            put(&mut out, base + 68, 1); // num_bssids, preceding num_ssids.
            put(&mut out, base + 72, ssids.len() as u32);
            put(&mut out, base + 76, extra_ies.len() as u32);
            put(&mut out, base + 80, 3); // num_probes, unused by PASSIVE.
            put(&mut out, at, (16 << 16) | (4 * channels.len()) as u32);
            at += 4;
        } else {
            put(&mut out, at, 1);
            put(&mut out, at + 4, channels.len() as u32);
            at += 8;
        }
        for frequency in channels {
            put(&mut out, at, u32::from(*frequency));
            at += 4;
        }
        if tlv {
            put(&mut out, at, (19 << 16) | (36 * ssids.len()) as u32);
            at += 4;
        } else if active {
            put(&mut out, at, 2); // WMI_SSID_LIST_TAG
            put(&mut out, at + 4, ssids.len() as u32);
            at += 8;
        }
        for ssid in ssids {
            put(&mut out, at, ssid.len() as u32);
            out[at + 4..at + 4 + ssid.len()].copy_from_slice(ssid);
            at += 36;
        }
        if tlv {
            put(&mut out, at, (19 << 16) | 8);
            at += 4;
        } else {
            put(&mut out, at, 3);
            put(&mut out, at + 4, 1);
            at += 8;
        }
        out[at..at + 6].fill(0xff);
        at += 8;
        if tlv {
            put(&mut out, at, (17 << 16) | padded_ies as u32);
            at += 4;
        } else if !extra_ies.is_empty() {
            put(&mut out, at, 4); // WMI_IE_TAG (wmi.h).
            put(&mut out, at + 4, extra_ies.len() as u32);
            at += 8;
        }
        out[at..at + extra_ies.len()].copy_from_slice(extra_ies);
        at += padded_ies;
        if at != out.len() {
            return Err(Error::Malformed);
        }
        Ok(out)
    }
    pub fn stop_scan(&self, sequence: u16) -> Result<Vec<u8>, Error> {
        if sequence == 0 || sequence > 4095 {
            return Err(Error::Exhausted);
        }
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.stop_scan, 16 + usize::from(tlv) * 4)?;
        let at = if tlv {
            header(&mut out, 78, 16);
            8
        } else {
            4
        };
        put(&mut out, at, 0xa001);
        put(&mut out, at + 4, 0xa000 | u32::from(sequence));
        // Linux STOP_ONE serializes u.scan_id in the shared vdev_id union too.
        put(&mut out, at + 12, u32::from(sequence));
        Ok(out)
    }
    pub fn scan_event(&self, body: &[u8]) -> Result<ScanEvent, Error> {
        let body = if self.dialect == Dialect::Tlv {
            tag(body, 36)?
        } else {
            body
        };
        let event = ScanEvent {
            kind: word(body, 0)?,
            reason: word(body, 4)?,
            frequency: word(body, 8)?,
            request: word(body, 12)?,
            sequence: word(body, 16)?,
            vdev: word(body, 20)?,
        };
        if !event.kind.is_power_of_two() || event.kind & !0x1ff != 0 || event.reason > 4 {
            return Err(Error::Malformed);
        }
        Ok(event)
    }
    pub fn management(&self, body: &[u8], features: u64) -> Result<Management, Error> {
        let tlv = self.dialect == Dialect::Tlv;
        let (head, frame, offset) = if tlv {
            let head = tag(body, 44)?;
            if head.len() < 40 {
                return Err(Error::Malformed);
            }
            (head, tag(body, 17)?, 0)
        } else {
            let tenfour = self.dialect == Dialect::TenFour;
            let fixed = if tenfour {
                28
            } else if features & 1 != 0 {
                40
            } else {
                24
            };
            (
                body.get(..fixed).ok_or(Error::Malformed)?,
                body.get(fixed..).ok_or(Error::Malformed)?,
                if tenfour { 4 } else { 0 },
            )
        };
        let length = word(head, 16 + offset)? as usize;
        if length == 0 || length > 4096 {
            return Err(Error::Malformed);
        }
        let status = word(head, 20 + offset)?;
        let frame = frame.get(..length).ok_or(Error::Malformed)?;
        if !tlv && status & 0x40 != 0 {
            let extent = (length + 3) & !3;
            // EXT_INFO follows padded MPDU; validate before accessing/ignoring.
            body.get(head.len() + extent..head.len() + extent + 8)
                .ok_or(Error::Malformed)?;
        }
        Ok(Management {
            channel: word(head, 0)?,
            snr: word(head, 4)?,
            status,
            frame: owned(frame)?,
        })
    }
}

pub(super) fn validate_ssids(ssids: &[Vec<u8>]) -> Result<(), Error> {
    if ssids.is_empty() || ssids.len() > MAX_SCAN_SSIDS || ssids.iter().any(|s| s.len() > 32) {
        return Err(Error::Unsupported);
    }
    Ok(())
}
pub(super) fn packet(id: u32, body: usize) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(4 + body).map_err(|_| Error::NoMemory)?;
    v.resize(4 + body, 0);
    put(&mut v, 0, id);
    Ok(v)
}
fn header(v: &mut [u8], tag: u16, len: u16) {
    put(v, 4, (u32::from(tag) << 16) | u32::from(len));
}
pub(super) fn put(v: &mut [u8], at: usize, value: u32) {
    v[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn word(v: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        v.get(at..at + 4)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
pub(super) fn owned(v: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(v.len())
        .map_err(|_| Error::NoMemory)?;
    out.extend_from_slice(v);
    Ok(out)
}
fn tag(mut v: &[u8], wanted: u16) -> Result<&[u8], Error> {
    let mut found = None;
    while !v.is_empty() {
        let h = word(v, 0)?;
        let end = 4 + (h & 0xffff) as usize;
        let body = v.get(4..end).ok_or(Error::Malformed)?;
        if h >> 16 == u32::from(wanted) && found.replace(body).is_some() {
            return Err(Error::Malformed);
        }
        v = v.get(end..).ok_or(Error::Malformed)?;
    }
    found.ok_or(Error::Malformed)
}
pub(super) fn validate_channels(channels: &[u16]) -> Result<(), Error> {
    if channels.is_empty() || channels.len() > 64 {
        return Err(Error::Malformed);
    }
    for (i, f) in channels.iter().enumerate() {
        if frequency_to_channel(*f).is_none() || channels[..i].contains(f) {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}
/// Linux wmi.h's WLAN_SCAN_PARAMS_MAX_IE_LEN is 256 for every dialect.
/// Firmware owns SSID and legacy rate generation. Other complete elements
/// remain opaque probe content and grant no station/PHY/policy authority.
pub(in crate::ath10k) fn validate_probe_ies(mut bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > usize::from(MAX_SCAN_IE_LEN) {
        return Err(Error::Unsupported);
    }
    while !bytes.is_empty() {
        let head = bytes.get(..2).ok_or(Error::Malformed)?;
        let end = 2 + usize::from(head[1]);
        let body = bytes.get(2..end).ok_or(Error::Malformed)?;
        match head[0] {
            0 | 1 | 50 => return Err(Error::Unsupported),
            221 if body.len() < 3 => return Err(Error::Malformed),
            255 if body.is_empty() => return Err(Error::Malformed),
            _ => {}
        }
        bytes = &bytes[end..];
    }
    Ok(())
}
pub(super) fn frequency_to_channel(f: u16) -> Option<u8> {
    if (2412..=2472).contains(&f) && (f - 2412) % 5 == 0 {
        return Some(((f - 2407) / 5) as u8);
    }
    if f == 2484 {
        return Some(14);
    }
    if f % 5 != 0 {
        return None;
    }
    let channel = (f.checked_sub(5000)?) / 5;
    (((36..=64).contains(&channel) || (100..=144).contains(&channel)) && channel % 4 == 0
        || matches!(channel, 149 | 153 | 157 | 161 | 165))
    .then_some(channel as u8)
}
pub(super) fn channel_to_frequency(c: u32) -> Option<u16> {
    let f = if c == 14 {
        2484
    } else if (1..=13).contains(&c) {
        2407 + c * 5
    } else if c <= 165 {
        5000 + c * 5
    } else {
        return None;
    };
    frequency_to_channel(f as u16).map(|_| f as u16)
}
pub(super) fn supported(caps: &Capabilities, frequency: u16) -> bool {
    let (low, high) = if frequency < 3000 {
        (caps.low_2ghz, caps.high_2ghz)
    } else {
        (caps.low_5ghz, caps.high_5ghz)
    };
    frequency_to_channel(frequency).is_some() && (low..=high).contains(&u32::from(frequency))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "tests.rs"]
mod tests;

#[path = "station_wire.rs"]
mod station;

#[path = "teardown_wire.rs"]
mod teardown;
