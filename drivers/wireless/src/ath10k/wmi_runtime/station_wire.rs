// SPDX-License-Identifier: GPL-2.0-or-later
//! Native Rust WMI station preparation for each supported firmware dialect.
use super::*;
use crate::ath10k::regulatory::Permission;
impl Wire {
    fn station_ids(self) -> (u32, u32, u32, u32, u32) {
        // RD, PDEV parameter, VDEV_START, PEER_CREATE, VDEV_START_RESPONSE.
        match self.dialect {
            Dialect::Main | Dialect::Tlv => (0x4001, 0x4003, 0x5003, 0x6001, 0x5001),
            Dialect::TenOne => (0x9004, 0x9006, 0x9013, 0x901c, 0x9005),
            Dialect::TenTwo | Dialect::TenTwoFour => (0x9004, 0x9006, 0x9012, 0x901c, 0x9004),
            Dialect::TenFour => (0x9006, 0x9008, 0x9015, 0x9022, 0x9004),
        }
    }
    pub fn domain(self, permission: Permission) -> Result<Vec<u8>, Error> {
        let f = permission.factory;
        let tlv = self.dialect == Dialect::Tlv;
        let main = self.dialect == Dialect::Main;
        // TLV carries pdev_id before the five MAIN fields. 10.x carries
        // DFS region after them. No DFS detector is admitted by this profile.
        let mut out = packet(
            self.station_ids().0,
            if main {
                20
            } else if tlv {
                28
            } else {
                24
            },
        )?;
        let at = if tlv {
            header(&mut out, 81, 24);
            12
        } else {
            4
        };
        for (i, value) in [f.pair, f.pair, f.pair, f.ctl_2ghz, f.ctl_5ghz]
            .into_iter()
            .enumerate()
        {
            put(&mut out, at + i * 4, u32::from(value));
        }
        Ok(out)
    }
    pub fn power(self, permission: Permission) -> Result<Vec<u8>, Error> {
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.station_ids().1, if tlv { 16 } else { 8 })?;
        let at = if tlv {
            header(&mut out, 82, 12);
            12
        } else {
            4
        };
        put(&mut out, at, 3); // Linux native PDEV_PARAM_TXPOWER_LIMIT2G in all six dialects.
        put(&mut out, at + 4, u32::from(permission.half_dbm));
        Ok(out)
    }
    pub fn start_station(
        self,
        permission: Permission,
        beacon: u16,
        dtim: u8,
    ) -> Result<Vec<u8>, Error> {
        if beacon == 0 || dtim == 0 {
            return Err(Error::Malformed);
        }
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.station_ids().2, if tlv { 108 } else { 128 })?;
        let (at, chan) = if tlv {
            header(&mut out, 88, 72);
            put(&mut out, 80, (80 << 16) | 24);
            put(&mut out, 108, 18 << 16); // Empty nested NOA descriptor list.
            (8, 84)
        } else {
            (28, 4)
        };
        put(&mut out, at + 8, u32::from(beacon));
        put(&mut out, at + 12, u32::from(dtim));
        // Legacy 11G, no IBSS/HT/VHT flags, no AP SSID/rate/power or NOA.
        put(&mut out, chan, u32::from(permission.frequency));
        put(&mut out, chan + 4, u32::from(permission.frequency));
        put(&mut out, chan + 12, 1);
        out[chan + 17] = permission.half_dbm;
        out[chan + 18] = permission.half_dbm;
        out[chan + 21] = permission.half_dbm;
        Ok(out)
    }
    pub fn peer(self, bssid: [u8; 6]) -> Result<Vec<u8>, Error> {
        if bssid == [0; 6] || bssid[0] & 1 != 0 {
            return Err(Error::Malformed);
        }
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.station_ids().3, if tlv { 20 } else { 16 })?;
        let at = if tlv {
            header(&mut out, 97, 16);
            8
        } else {
            4
        };
        out[at + 4..at + 10].copy_from_slice(&bssid);
        put(&mut out, at + 12, 1); // Linux WMI_PEER_TYPE_BSS.
        Ok(out)
    }
    pub fn start_response_id(self) -> u32 {
        self.station_ids().4
    }
    pub fn start_response(self, body: &[u8]) -> Result<Option<()>, Error> {
        let b = if self.dialect == Dialect::Tlv {
            tag(body, 40)?
        } else {
            body
        };
        if b.len() != 16 {
            return Err(Error::Malformed);
        }
        // The native Linux generator leaves requestor_id zero. This owner
        // submits exactly one START and never retries an ambiguous result.
        if word(b, 0)? != 0 || word(b, 4)? != 0 {
            return Ok(None);
        }
        if word(b, 8)? != 0 {
            return Err(Error::Malformed);
        }
        let status = word(b, 12)?;
        if status != 0 {
            return Err(Error::Firmware(status));
        }
        Ok(Some(()))
    }
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "station_wire_tests.rs"]
mod tests;
