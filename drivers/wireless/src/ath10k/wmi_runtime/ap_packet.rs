// SPDX-License-Identifier: GPL-2.0-or-later
//! Physical ToDS/FromDS AP packet admission before software CCMP/port copy.
use super::{
    ap::{Event, Session, Vdev},
    htt, wire, Error,
};
use alloc::{vec, vec::Vec};

impl Session {
    pub(super) fn management(&mut self, native: super::Management) -> Result<(), Error> {
        if self.vdev != Vdev::Up
            || self.failed
            || native.status & !0x40 != 0
            || wire::channel_to_frequency(native.channel) != Some(self.permission.frequency)
        {
            return Ok(());
        }
        let f = &native.frame;
        if !(24..=2304).contains(&f.len())
            || !matches!(f[0], 0 | 0x20 | 0x40 | 0xb0 | 0xa0 | 0xc0 | 0xd0)
            || f[1] & 0xc7 != 0
            || f[22] & 15 != 0
            || !super::ap_wire::unicast(f[10..16].try_into().unwrap())
            || f[10..16] == self.own.mac
            || f[4..10] != self.own.mac && !(f[0] == 0x40 && f[4..10] == [0xff; 6])
            || f[16..22] != self.own.mac && !(f[0] == 0x40 && f[16..22] == [0xff; 6])
        {
            return Ok(());
        }
        if matches!(f[0], 0xa0 | 0xc0) {
            if f.len() != 26 {
                return Ok(());
            }
            if let Some(peer) = self
                .peers
                .iter_mut()
                .find(|peer| f[10..16] == peer.record.mac)
            {
                Self::advance(&self.data_epoch)?;
                Self::advance(&self.key_epoch)?;
                Self::advance(&peer.denial)?;
                peer.authorized = false;
            }
        }
        self.push(Event::Management(native.frame), false)
    }
    pub(super) fn receive(
        &mut self,
        status: u8,
        id: u16,
        tid: u8,
        mut msdu: htt::rx::Msdu,
    ) -> Result<(), Error> {
        if self.vdev != Vdev::Up
            || self.busy
            || msdu.offload.is_some()
            || !matches!(status, 1 | 6 | 10)
        {
            return Ok(());
        }
        let Some(index) = self
            .peers
            .iter()
            .position(|peer| peer.associated && peer.record.owns(id))
        else {
            return Ok(());
        };
        let word = |at: usize| u32::from_le_bytes(msdu.descriptor[at..at + 4].try_into().unwrap());
        let attention = word(4);
        let start = word(12);
        let errors = (1 << 3)
            | (1 << 4)
            | (1 << 7)
            | (1 << 8)
            | (1 << 13)
            | (1 << 16)
            | (1 << 17)
            | (1 << 27)
            | (1 << 28)
            | (1 << 30);
        if attention & (1 << 31) == 0
            || attention & errors != 0
            || attention & 3 != 3
            || word(104) >> 24 != 4
            || start & 0x7ff != u32::from(id)
            || start & 0x1800 != 0x1000
            || attention & (1 << 9) != 0
            || word(28) & 0x300 != 0
            || word(56) & 0xc000 != 0xc000
            || (word(24) & 0x3fff) as usize != msdu.payload.len()
            || word(20) >> 28 != u32::from(if tid == 16 { 0 } else { tid })
            || !(28..=2324).contains(&msdu.payload.len())
        {
            return Ok(());
        }
        let Some((rate_index, rate)) =
            super::ap_wire::legacy_rate(word(104), self.permission.frequency)
        else {
            return Ok(());
        };
        if self.plan.rates & (1 << rate_index) == 0
            || !self.peers[index]
                .config
                .supported_rates
                .iter()
                .any(|r| r & 127 == rate)
        {
            return Ok(());
        }
        let encrypted = msdu.payload[1] & 0x40 != 0;
        let enctype = start >> 28;
        if !encrypted && (status == 10 || enctype != 7)
            || encrypted && !(enctype == 7 || enctype == 6 && attention & (1 << 29) != 0)
        {
            return Ok(());
        }
        let native_sequence = (start >> 16) & 0xfff;
        msdu.payload.truncate(msdu.payload.len() - 4);
        let f = &msdu.payload;
        if !matches!(f[0], 8 | 0x88)
            || f[1] & 0x87 != 1
            || f[22] & 15 != 0
            || u32::from(u16::from_le_bytes([f[22], f[23]]) >> 4) != native_sequence
            || f[4..10] != self.own.mac
            || f[10..16] != self.peers[index].record.mac
            || f[16..22] == [0; 6]
        {
            return Ok(());
        }
        let header_len = if f[0] == 0x88 {
            if f.len() < 26
                || tid > 7
                || f[24] != tid
                || f[25] != 0
                || self.peers[index].config.wme != Some(true)
            {
                return Ok(());
            }
            26
        } else {
            if tid != 16 {
                return Ok(());
            }
            24
        };
        let header = &f[..header_len];
        let decoded = if encrypted {
            let Some(key) = &self.peers[index].key else {
                return Ok(());
            };
            match key.unprotect(self.own.mac, header, &mut f[header_len..].to_vec()) {
                Ok(plain) => Some(plain),
                Err(_) => return Ok(()),
            }
        } else {
            None
        };
        let body = decoded
            .as_ref()
            .map_or(&f[header_len..], |decoded| decoded.plain.as_slice());
        if !(8..=1508).contains(&body.len()) || body[..6] != [0xaa, 0xaa, 3, 0, 0, 0] {
            return Ok(());
        }
        let ethertype = u16::from_be_bytes([body[6], body[7]]);
        let configured = ethertype == self.plan.settings.control_port.ethertype;
        if ethertype < 0x600
            || status == 6 && (!configured || encrypted)
            || !configured
                && (!self.peers[index].authorized || self.plan.config.privacy && !encrypted)
        {
            return Ok(());
        }
        let control = configured
            || ethertype == narf_wireless::ETH_P_PREAUTH
                && !self.plan.settings.control_port.no_preauth;
        let event = if control {
            if !self.plan.settings.control_port.enabled
                || !self.plan.settings.control_port.over_nl80211
                || body.len() == 8
            {
                return Ok(());
            }
            Event::Control {
                peer: self.peers[index].record.mac,
                ethertype,
                pdu: body[8..].to_vec(),
                unencrypted: !encrypted,
            }
        } else {
            let mut ethernet = Vec::new();
            ethernet
                .try_reserve_exact(6 + 6 + body.len() - 6)
                .map_err(|_| Error::NoMemory)?;
            ethernet.extend_from_slice(&f[16..22]);
            ethernet.extend_from_slice(&self.peers[index].record.mac);
            ethernet.extend_from_slice(&body[6..]);
            Event::Data(ethernet)
        };
        if let Some(decoded) = decoded {
            self.peers[index]
                .key
                .as_mut()
                .ok_or(Error::Failed)?
                .commit(decoded)?;
        }
        // Ordinary preauthentication requires DATA throughout later callback
        // preparation. Only the configured SME EAPOL path may bypass its port.
        self.push(event, !configured)
    }
    /// The caller has proved current original sources, RF/key/port and actual
    /// CE room. A no-credit retry must not call this and spend a second PN.
    pub(super) fn ethernet(
        &mut self,
        ethernet: &[u8],
        control: bool,
        no_encrypt: bool,
    ) -> Result<Option<(Vec<u8>, u8)>, Error> {
        if self.vdev != Vdev::Up
            || self.busy
            || !(14..=1514).contains(&ethernet.len())
            || ethernet[6] & 1 != 0
            || ethernet[6..12] == [0; 6]
            || !control && no_encrypt
        {
            return Ok(None);
        }
        let ethertype = u16::from_be_bytes([ethernet[12], ethernet[13]]);
        if ethertype < 0x600 || !control && ethertype == self.plan.settings.control_port.ethertype {
            return Ok(None);
        }
        let group = ethernet[0] & 1 != 0;
        let peer = self.peers.iter().position(|peer| {
            peer.record.mac == ethernet[..6] && peer.associated && peer.record.mapped()
        });
        let protected = self.plan.config.privacy && !no_encrypt;
        let (qos, tid) = if group {
            if control
                || !self
                    .peers
                    .iter()
                    .any(|peer| peer.authorized && peer.associated && peer.record.mapped())
            {
                return Ok(None);
            }
            if protected && self.default_group.is_none() {
                return Err(Error::Failed);
            }
            (false, 17)
        } else {
            let Some(index) = peer else {
                return Ok(None);
            };
            if !control
                && (!self.peers[index].authorized
                    || self.plan.config.privacy && self.peers[index].key.is_none())
            {
                return Ok(None);
            }
            if protected && self.peers[index].key.is_none() {
                return Err(Error::Failed);
            }
            let qos = self.peers[index].config.wme == Some(true);
            (qos, if qos { 0 } else { 16 })
        };
        let mut header = vec![0; if qos { 26 } else { 24 }];
        header[0] = if qos { 0x88 } else { 8 };
        header[1] = 2 | if protected { 0x40 } else { 0 };
        header[4..10].copy_from_slice(&ethernet[..6]);
        header[10..16].copy_from_slice(&self.own.mac);
        header[16..22].copy_from_slice(&ethernet[6..12]);
        header[22..24].copy_from_slice(&((self.sequence & 4095) << 4).to_le_bytes());
        self.sequence = self.sequence.wrapping_add(1) & 4095;
        let mut body = Vec::new();
        body.try_reserve_exact(ethernet.len() - 6)
            .map_err(|_| Error::NoMemory)?;
        body.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
        body.extend_from_slice(&ethernet[12..]);
        if protected {
            let key = if let Some(index) = peer {
                self.peers[index].key.as_mut().ok_or(Error::Failed)?
            } else {
                &mut self
                    .groups
                    .iter_mut()
                    .find(|group| Some(group.key.id) == self.default_group)
                    .ok_or(Error::Failed)?
                    .key
            };
            let ciphertext = key.protect(self.own.mac, &header, &body)?;
            header.extend_from_slice(&ciphertext);
        } else {
            header.extend_from_slice(&body);
        }
        Ok(Some((header, tid)))
    }
}
