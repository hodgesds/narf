// SPDX-License-Identifier: GPL-2.0-or-later
//! Native TLV P2P roles and firmware NoA facts. These codecs grant no RF,
//! peer, key, pause or completion authority. The independent retained P2P
//! owner must bind original physical/source/policy generations before use.
//! Linux7.3-rc4 mac.c, wmi-tlv.{c,h}, wmi.h and p2p.c.
use super::{wire, Error};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Device,
    Client,
    Go,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Vdev {
    id: u8,
    role: Role,
}
impl Vdev {
    /// Discovery is a genuinely different vdev/MAC. Data roles keep their
    /// real data vdev, never reinterpret a running STA or AP as discovery.
    pub fn discovery() -> Self {
        Self {
            id: 1,
            role: Role::Device,
        }
    }
    pub fn link(role: Role) -> Result<Self, Error> {
        if role == Role::Device {
            return Err(Error::Unsupported);
        }
        Ok(Self { id: 0, role })
    }
    pub fn id(self) -> u8 {
        self.id
    }
    pub fn role(self) -> Role {
        self.role
    }
    pub fn create(self, own: [u8; 6]) -> Result<Vec<u8>, Error> {
        if own == [0; 6] || own[0] & 1 != 0 {
            return Err(Error::Malformed);
        }
        let mut out = wire::packet(0x5001, 24)?;
        wire::put(&mut out, 4, (86 << 16) | 20);
        wire::put(&mut out, 8, u32::from(self.id));
        wire::put(&mut out, 12, if self.role == Role::Go { 1 } else { 2 });
        wire::put(
            &mut out,
            16,
            match self.role {
                Role::Device => 1,
                Role::Client => 2,
                Role::Go => 3,
            },
        );
        out[20..26].copy_from_slice(&own);
        Ok(out)
    }
    pub fn remove(self) -> Result<Vec<u8>, Error> {
        let mut out = wire::packet(0x5002, 8)?;
        wire::put(&mut out, 4, (87 << 16) | 4);
        wire::put(&mut out, 8, u32::from(self.id));
        Ok(out)
    }
    /// mac.c requires non-CCK for P2P_FIND/GO_NEG; actual per-vdev MGMT_RATE
    /// programming selects hardware OFDM6 code3, not a label on a CCK frame.
    pub fn management_rate(self) -> Result<Vec<u8>, Error> {
        let mut out = wire::packet(0x5008, 16)?;
        wire::put(&mut out, 4, (95 << 16) | 12);
        wire::put(&mut out, 8, u32::from(self.id));
        wire::put(&mut out, 12, 25);
        wire::put(&mut out, 16, 3);
        Ok(out)
    }
    pub fn peer(self, mac: [u8; 6], remove: bool) -> Result<Vec<u8>, Error> {
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(Error::Malformed);
        }
        let mut out = wire::packet(
            if remove { 0x6002 } else { 0x6001 },
            if remove { 16 } else { 20 },
        )?;
        wire::put(
            &mut out,
            4,
            if remove {
                (98 << 16) | 12
            } else {
                (97 << 16) | 16
            },
        );
        wire::put(&mut out, 8, u32::from(self.id));
        out[12..18].copy_from_slice(&mac);
        // DEFAULT/self for discovery; data-role BSS/client peers belong to
        // their actual associated AP/GO owner and are not opened by this codec.
        Ok(out)
    }
}
/// One bounded P2P vendor IE for firmware's own GO beacon insertion. Linux
/// removes it from the base BCN_TMPL after this distinct native command.
pub(super) fn go_beacon_ie(vdev: Vdev, ie: &[u8]) -> Result<Vec<u8>, Error> {
    if vdev.role != Role::Go
        || ie.len() < 6
        || ie.len() > 257
        || ie[0] != 221
        || usize::from(ie[1]) + 2 != ie.len()
        || ie[2..6] != [0x50, 0x6f, 0x9a, 9]
    {
        return Err(Error::Malformed);
    }
    attributes(&ie[6..])?;
    let padded = ie.len().next_multiple_of(4);
    let mut out = wire::packet(0xd003, 16 + padded)?;
    wire::put(&mut out, 4, (90 << 16) | 8);
    wire::put(&mut out, 8, u32::from(vdev.id));
    wire::put(&mut out, 12, ie.len() as u32);
    wire::put(&mut out, 16, (17 << 16) | padded as u32);
    out[20..20 + ie.len()].copy_from_slice(ie);
    Ok(out)
}
/// The concatenated attributes of an already bounded vendor stream. Duplicate
/// singleton identity/status attributes are rejected by its role plan; this
/// generic layout check invents no wire uniqueness/order restriction.
pub(super) fn attributes(mut bytes: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let head = bytes.get(..3).ok_or(Error::Malformed)?;
        let length = usize::from(u16::from_le_bytes([head[1], head[2]]));
        let body = bytes.get(3..3 + length).ok_or(Error::Malformed)?;
        out.try_reserve(1).map_err(|_| Error::NoMemory)?;
        out.push((head[0], body));
        bytes = &bytes[3 + length..];
    }
    Ok(out)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Absence {
    pub count: u8,
    pub duration: u32,
    pub interval: u32,
    pub start: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Noa {
    pub index: u8,
    pub opportunistic: bool,
    pub ctwindow: u8,
    pub absences: Vec<Absence>,
}
fn tagged(bytes: &[u8], wanted: u16) -> Result<&[u8], Error> {
    let mut bytes = bytes;
    let mut found = None;
    while !bytes.is_empty() {
        let h = bytes.get(..4).ok_or(Error::Malformed)?;
        let n = usize::from(u16::from_le_bytes([h[0], h[1]]));
        let body = bytes.get(4..4 + n).ok_or(Error::Malformed)?;
        if u16::from_le_bytes([h[2], h[3]]) == wanted && found.replace(body).is_some() {
            return Err(Error::Malformed);
        }
        bytes = &bytes[4 + n..];
    }
    found.ok_or(Error::Malformed)
}
impl Noa {
    /// Only an actual received firmware event for the exact GO may call this.
    /// Repeated/wrapped wire indices are opaque; ownership comes from the
    /// native event/copy epoch, never a guessed monotonically increasing index.
    pub fn event(vdev: Vdev, bytes: &[u8]) -> Result<Option<Self>, Error> {
        if wire::word(bytes, 0)? & 0xffffff != 0xd002 {
            return Ok(None);
        }
        if vdev.role != Role::Go {
            return Err(Error::Unsupported);
        }
        let native = tagged(&bytes[4..], 223)?;
        let info = tagged(&bytes[4..], 69)?;
        if native.len() != 4
            || wire::word(native, 0)? != u32::from(vdev.id)
            || info.len() != 68
            || info[0] & !1 != 0
            || info[3] > 4
        {
            return Err(Error::Malformed);
        }
        if info[0] & 1 == 0 {
            return Ok(None);
        }
        let mut absences = Vec::new();
        absences
            .try_reserve_exact(usize::from(info[3]))
            .map_err(|_| Error::NoMemory)?;
        for i in 0..usize::from(info[3]) {
            let at = 4 + i * 16;
            let count = wire::word(info, at)?;
            let duration = wire::word(info, at + 4)?;
            let interval = wire::word(info, at + 8)?;
            let start = wire::word(info, at + 12)?;
            if count == 0 || count > 255 || duration == 0 || count != 1 && interval < duration {
                return Err(Error::Malformed);
            }
            absences.push(Absence {
                count: count as u8,
                duration,
                interval,
                start,
            });
        }
        Ok(Some(Self {
            index: info[1],
            opportunistic: info[2] & 1 != 0,
            ctwindow: info[2] >> 1,
            absences,
        }))
    }
    /// Source-native encoding differs from IEEE's OPPS bit position. No host
    /// timestamp or schedule is synthesized while translating these facts.
    pub fn information_element(&self) -> Result<Option<Vec<u8>>, Error> {
        if self.absences.len() > 4 {
            return Err(Error::Malformed);
        }
        if self.absences.is_empty() && !self.opportunistic {
            return Ok(None);
        }
        let n = 2 + self.absences.len() * 13;
        let mut out = Vec::new();
        out.try_reserve_exact(9 + n).map_err(|_| Error::NoMemory)?;
        out.extend_from_slice(&[221, (7 + n) as u8, 0x50, 0x6f, 0x9a, 9, 12]);
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&[
            self.index,
            self.ctwindow | if self.opportunistic { 128 } else { 0 },
        ]);
        for absence in &self.absences {
            out.push(absence.count);
            out.extend_from_slice(&absence.duration.to_le_bytes());
            out.extend_from_slice(&absence.interval.to_le_bytes());
            out.extend_from_slice(&absence.start.to_le_bytes());
        }
        Ok(Some(out))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pause {
    pub reason: u32,
    pub stopped: bool,
}
pub(super) fn pause(vdev: Vdev, bytes: &[u8]) -> Result<Option<Pause>, Error> {
    if wire::word(bytes, 0)? & 0xffffff != 0x4005 {
        return Ok(None);
    }
    let body = tagged(&bytes[4..], 230)?;
    if body.len() != 20 {
        return Err(Error::Malformed);
    }
    let reason = wire::word(body, 0)?;
    let action = wire::word(body, 4)?;
    let map = wire::word(body, 8)?;
    if action > 1 {
        return Err(Error::Malformed);
    }
    if map & (1 << vdev.id) == 0 {
        return Ok(None);
    }
    if !matches!(reason, 1 | 4 | 5 | 7 | 8) {
        return Ok(None);
    }
    if reason == 4 && vdev.role != Role::Client || reason == 5 && vdev.role != Role::Go {
        return Err(Error::Malformed);
    }
    Ok(Some(Pause {
        reason,
        stopped: action == 0,
    }))
}
