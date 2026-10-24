// SPDX-License-Identifier: GPL-2.0-or-later
//! Native station teardown commands and correlated firmware event envelopes.
use super::*;

impl Wire {
    // VDEV_DOWN, PEER_DELETE, VDEV_STOP, VDEV_STOPPED. 10.2.4 uses10.2.
    fn teardown_ids(self) -> (u32, u32, u32, u32) {
        match self.dialect {
            Dialect::Main | Dialect::Tlv => (0x5007, 0x6002, 0x5006, 0x5002),
            Dialect::TenOne => (0x9017, 0x901d, 0x9016, 0x9008),
            Dialect::TenTwo | Dialect::TenTwoFour => (0x9016, 0x901d, 0x9015, 0x9007),
            Dialect::TenFour => (0x9019, 0x9023, 0x9018, 0x9007),
        }
    }
    pub fn down_station(self) -> Result<Vec<u8>, Error> {
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.teardown_ids().0, if tlv { 8 } else { 4 })?;
        if tlv {
            header(&mut out, 94, 4);
        }
        Ok(out)
    }
    pub fn delete_peer(self, bssid: [u8; 6]) -> Result<Vec<u8>, Error> {
        if bssid == [0; 6] || bssid[0] & 1 != 0 {
            return Err(Error::Malformed);
        }
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.teardown_ids().1, if tlv { 16 } else { 12 })?;
        let at = if tlv {
            header(&mut out, 98, 12);
            8
        } else {
            4
        };
        out[at + 4..at + 10].copy_from_slice(&bssid);
        Ok(out)
    }
    pub fn stop_station(self) -> Result<Vec<u8>, Error> {
        let tlv = self.dialect == Dialect::Tlv;
        let mut out = packet(self.teardown_ids().2, if tlv { 8 } else { 4 })?;
        if tlv {
            header(&mut out, 93, 4);
        }
        Ok(out)
    }
    pub fn stopped_event_id(self) -> u32 {
        self.teardown_ids().3
    }
    pub fn stopped_response(self, body: &[u8]) -> Result<bool, Error> {
        let body = if self.dialect == Dialect::Tlv {
            tag(body, 41)?
        } else {
            body
        };
        if body.len() != 4 {
            return Err(Error::Malformed);
        }
        Ok(word(body, 0)? == 0)
    }
    pub fn delete_event_id(self) -> Option<u32> {
        (self.dialect == Dialect::Tlv).then_some(0x6007)
    }
    pub fn delete_response(self, body: &[u8], bssid: [u8; 6]) -> Result<bool, Error> {
        if self.dialect != Dialect::Tlv {
            return Err(Error::Unsupported);
        }
        let body = tag(body, 451)?;
        if body.len() != 12 {
            return Err(Error::Malformed);
        }
        Ok(word(body, 0)? == 0 && body[4..10] == bssid)
    }
    pub fn sync_delete_required(self, caps: &Capabilities) -> bool {
        // Only the TLV service map advertises Linux SYNC_DELETE_CMDS.
        self.dialect == Dialect::Tlv && caps.service(self.dialect, 92)
    }
}
