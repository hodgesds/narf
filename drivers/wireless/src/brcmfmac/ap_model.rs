// SPDX-License-Identifier: GPL-2.0-or-later
//! Independent firmware AP SME, observing actual msgbuf IOCTL/TX bodies.
//! Expected offsets are authored from Linux7.3-rc4 fwil_types.h/cfg80211.c;
//! no production AP wire encoder constructs expected records or receipts.
use alloc::{
    collections::{BTreeMap, VecDeque},
    string::{String, ToString},
    vec,
    vec::Vec,
};
pub(crate) const CLIENT: [u8; 6] = [2, 0x73, 4, 5, 6, 7];
const OWN: [u8; 6] = super::OWN;
pub(crate) const RATES: [u8; 4] = [0x82, 0x84, 0x8b, 0x96];
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
pub(crate) struct Peer {
    pub(crate) authorized: bool,
    pub(crate) ies: Vec<u8>,
}
pub(crate) struct Profile {
    pub(super) handled: bool,
    pub(super) status: i16,
    pub(crate) active: bool,
    pub(crate) up: bool,
    pub(crate) formed: bool,
    pub(crate) peers: BTreeMap<[u8; 6], Peer>,
    vars: BTreeMap<String, u32>,
    ssid: Vec<u8>,
    beacon: u16,
    dtim: u8,
    mask: [u8; 16],
    pub(crate) keys: Vec<Vec<u8>>,
    active_keys: BTreeMap<(u32, [u8; 6]), [u8; 16]>,
    primary_key: Option<u32>,
    pub(crate) packets: Vec<Vec<u8>>,
    pub(crate) events: VecDeque<Vec<u8>>,
    pub(crate) downlink: VecDeque<Vec<u8>>,
    pub(crate) response_on_control: Option<Vec<u8>>,
    pub(crate) vendors: Vec<(u32, Vec<u8>)>,
    /// 0=known, 1=unsupported, 2=write-only disable, 3=enabled/undisableable.
    pub(crate) offload: u8,
    pub(crate) hold_key: bool,
    pub(crate) hold_remove: bool,
    pub(crate) bad_bss: bool,
    /// BSSID this interface's BSS reports (`GET_BSS_INFO`): the primary
    /// address, or a secondary interface's IF ADD address.
    pub(crate) own: [u8; 6],
}
impl Default for Profile {
    fn default() -> Self {
        let vars = [
            ("nmode", 0),
            ("vhtmode", 0),
            ("wme_bss_disable", 0),
            ("apsta", 0),
            ("ap_isolate", 0),
            ("mpc", 1),
            ("mbss", 0),
            ("arpoe", 0),
            ("arp_ol", 0),
            ("ndoe", 0),
            ("wsec", 0),
            ("auth", 0),
            ("wpa_auth", 0),
            ("sup_wpa", 0),
            ("closednet", 0),
            ("chanspec", 0x1006),
            ("qtxpower", 68),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_string(), value))
        .collect();
        Self {
            handled: false,
            status: 0,
            active: false,
            up: true,
            formed: false,
            peers: BTreeMap::new(),
            vars,
            ssid: Vec::new(),
            beacon: 100,
            dtim: 2,
            mask: [0; 16],
            keys: Vec::new(),
            active_keys: BTreeMap::new(),
            primary_key: None,
            packets: Vec::new(),
            events: VecDeque::new(),
            downlink: VecDeque::new(),
            response_on_control: None,
            vendors: Vec::new(),
            offload: 0,
            hold_key: false,
            hold_remove: false,
            bad_bss: false,
            own: OWN,
        }
    }
}
impl Profile {
    pub(crate) fn event(&mut self, kind: u32, mac: [u8; 6], payload: &[u8]) {
        let mut bytes = vec![0; 72 + payload.len()];
        bytes[12..16].copy_from_slice(&[0x88, 0x6c, 0x80, 1]);
        bytes[19..24].copy_from_slice(&[0, 0x10, 0x18, 0, 1]);
        bytes[24..26].copy_from_slice(&2u16.to_be_bytes());
        bytes[28..32].copy_from_slice(&kind.to_be_bytes());
        bytes[44..48].copy_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes[48..54].copy_from_slice(&mac);
        bytes[72..].copy_from_slice(payload);
        self.events.push_back(bytes);
    }
    pub(crate) fn associate(&mut self, mac: [u8; 6], ies: Vec<u8>) {
        assert!(self.active && self.up && self.formed);
        self.peers.insert(
            mac,
            Peer {
                authorized: false,
                ies: ies.clone(),
            },
        );
        self.event(8, mac, &ies);
    }
    pub(crate) fn remove(&mut self, mac: [u8; 6]) {
        if self.peers.remove(&mac).is_some() {
            self.active_keys.retain(|(_, peer), _| *peer != mac);
            self.event(6, mac, &[]);
        }
    }
    pub(super) fn command(&mut self, command: u32, input: &[u8], maximum: u16) -> Option<Vec<u8>> {
        self.status = 0;
        self.handled = true;
        let scalar = |value: u32| Some(value.to_le_bytes().to_vec());
        match command {
            2 => {
                self.up = true;
                Some(Vec::new())
            }
            3 => {
                self.up = false;
                self.formed = false;
                let peers: Vec<_> = self.peers.keys().copied().collect();
                if !self.hold_remove {
                    for mac in peers {
                        self.remove(mac);
                    }
                }
                Some(Vec::new())
            }
            19 => scalar(1),
            20 => {
                assert_eq!(word(input, 0), 1);
                Some(Vec::new())
            }
            75 => scalar(u32::from(self.beacon)),
            76 => {
                self.beacon = word(input, 0) as u16;
                Some(Vec::new())
            }
            77 => scalar(u32::from(self.dtim)),
            78 => {
                self.dtim = word(input, 0) as u8;
                Some(Vec::new())
            }
            114 => {
                let mut out = vec![0; 20];
                out[..4].copy_from_slice(&4u32.to_le_bytes());
                out[4..8].copy_from_slice(&RATES);
                Some(out)
            }
            117 => scalar(u32::from(self.active)),
            118 => {
                self.active = word(input, 0) != 0;
                Some(Vec::new())
            }
            121 | 122 => {
                let mac: [u8; 6] = input.try_into().unwrap();
                if let Some(peer) = self.peers.get_mut(&mac) {
                    peer.authorized = command == 121;
                } else {
                    self.status = -30;
                }
                Some(Vec::new())
            }
            159 => {
                let mut out = (self.peers.len() as u32).to_le_bytes().to_vec();
                for mac in self.peers.keys() {
                    out.extend_from_slice(mac);
                }
                Some(out)
            }
            201 => {
                assert_eq!(input.len(), 12);
                assert_ne!(word(input, 0), 0);
                if !self.hold_remove {
                    self.remove(input[4..10].try_into().unwrap());
                }
                Some(Vec::new())
            }
            26 if self.active || input.len() == 52 => {
                assert_eq!(input.len(), 52);
                let n = word(input, 0) as usize;
                assert!(n <= 32);
                self.ssid = input[4..4 + n].to_vec();
                self.formed = n != 0;
                if n == 0 && !self.hold_remove {
                    let peers: Vec<_> = self.peers.keys().copied().collect();
                    for mac in peers {
                        self.remove(mac);
                    }
                }
                Some(Vec::new())
            }
            136 => {
                let mut out = vec![0; 132];
                out[..4].copy_from_slice(&u32::from(maximum).to_le_bytes());
                let b = &mut out[4..];
                b[..4].copy_from_slice(&109u32.to_le_bytes());
                b[4..8].copy_from_slice(&128u32.to_le_bytes());
                b[8..14].copy_from_slice(&self.own);
                b[14..16].copy_from_slice(&self.beacon.to_le_bytes());
                let cap = 1u16 | if self.vars["wsec"] & 4 != 0 { 16 } else { 0 };
                b[16..18].copy_from_slice(&cap.to_le_bytes());
                b[18] = self.ssid.len() as u8;
                b[19..19 + self.ssid.len()].copy_from_slice(&self.ssid);
                b[52..56].copy_from_slice(&4u32.to_le_bytes());
                b[56..60].copy_from_slice(&RATES);
                b[72..74].copy_from_slice(&(self.vars["chanspec"] as u16).to_le_bytes());
                b[76] = self.dtim;
                if self.bad_bss {
                    b[8] ^= 4;
                }
                Some(out)
            }
            262 | 263 => {
                let end = input.iter().position(|byte| *byte == 0)?;
                let name = core::str::from_utf8(&input[..end]).unwrap();
                let body = &input[end + 1..];
                if ["arpoe", "arp_ol", "ndoe"].contains(&name) {
                    if self.offload == 1
                        || self.offload == 2 && command == 262
                        || self.offload == 3 && command == 263
                    {
                        self.status = -23;
                        return Some(Vec::new());
                    }
                    if self.offload == 3 && command == 262 {
                        return scalar(1);
                    }
                }
                match (command, name) {
                    (262, "event_msgs") => Some(self.mask.to_vec()),
                    (263, "event_msgs") => {
                        self.mask.copy_from_slice(body);
                        Some(Vec::new())
                    }
                    (262, "sta_info") => {
                        // A GET query buffer is zero-padded to the reply
                        // maximum (Linux bcdc.c; `command_scoped` builds
                        // `maximum`-sized bodies), so the body is the
                        // 6-byte MAC followed by zero padding — not
                        // exactly 6 bytes. The MAC is the prefix, as real
                        // firmware reads it.
                        assert!(body.len() >= 6, "sta_info query shorter than a MAC");
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&body[..6]);
                        let Some(peer) = self.peers.get(&mac) else {
                            self.status = -30;
                            return Some(Vec::new());
                        };
                        let mut out = vec![0; 52];
                        out[..2].copy_from_slice(&3u16.to_le_bytes());
                        out[2..4].copy_from_slice(&52u16.to_le_bytes());
                        out[4..6].copy_from_slice(&1u16.to_le_bytes());
                        out[8..12].copy_from_slice(
                            &(0x18u32 | if peer.authorized { 0x20 } else { 0 }).to_le_bytes(),
                        );
                        out[16..22].copy_from_slice(&mac);
                        out[24..28].copy_from_slice(&4u32.to_le_bytes());
                        out[28..32].copy_from_slice(&RATES);
                        Some(out)
                    }
                    (263, "wsec_key") => {
                        assert_eq!(body.len(), 164);
                        let index = word(body, 0);
                        assert!(index <= 3);
                        let len = word(body, 4);
                        assert!(len == 0 || len == 16);
                        if len == 16 {
                            assert_eq!(word(body, 112), 4);
                            let peer: [u8; 6] = body[156..162].try_into().unwrap();
                            assert_eq!(word(body, 116), if peer == [0; 6] { 2 } else { 0 });
                            assert!(peer == [0; 6] || self.peers.contains_key(&peer));
                            self.active_keys
                                .insert((index, peer), body[8..24].try_into().unwrap());
                            if peer == [0; 6] {
                                self.primary_key = Some(index);
                            }
                        } else {
                            self.active_keys.remove(&(index, [0; 6]));
                            if self.primary_key == Some(index) {
                                self.primary_key = None;
                            }
                        }
                        self.keys.push(body.to_vec());
                        Some(Vec::new())
                    }
                    (263, "vndr_ie") => {
                        assert!(body.len() >= 8);
                        assert!(body[..4] == *b"add\0" || body[..4] == *b"del\0");
                        let mut at = 0;
                        while at < body.len() {
                            let adding = body[at..at + 4] == *b"add\0";
                            assert!(adding || body[at..at + 4] == *b"del\0");
                            let count = word(body, at + 4);
                            at += 8;
                            for _ in 0..count {
                                let flags = word(body, at);
                                let n = usize::from(body[at + 5]) + 2;
                                assert_eq!(body[at + 4], 221);
                                let ie = body[at + 4..at + 4 + n].to_vec();
                                if adding {
                                    self.vendors.push((flags, ie));
                                } else {
                                    self.vendors.retain(|old| *old != (flags, ie.clone()));
                                }
                                at += 4 + n;
                            }
                        }
                        assert_eq!(at, body.len());
                        Some(Vec::new())
                    }
                    // cfg80211.c brcmf_cfg80211_start_ap P2P_GO branch:
                    // bsscfg `ssid` (brcmf_ssid_le) then `bss` enable on the
                    // GO's own bsscfg; stop_ap disables it.
                    (263, "ssid") => {
                        assert_eq!(body.len(), 36);
                        let n = word(body, 0) as usize;
                        assert!((1..=32).contains(&n));
                        self.ssid = body[4..4 + n].to_vec();
                        Some(Vec::new())
                    }
                    (263, "bss") => {
                        assert_eq!(body.len(), 8);
                        let enable = word(body, 4) != 0;
                        self.active = enable;
                        self.up = enable;
                        self.formed = enable && !self.ssid.is_empty();
                        if !enable && !self.hold_remove {
                            let peers: Vec<_> = self.peers.keys().copied().collect();
                            for mac in peers {
                                self.remove(mac);
                            }
                        }
                        Some(Vec::new())
                    }
                    (262, name) if self.vars.contains_key(name) => scalar(self.vars[name]),
                    (263, name) if self.vars.contains_key(name) => {
                        assert_eq!(body.len(), 4);
                        self.vars.insert(name.to_string(), word(body, 0));
                        Some(Vec::new())
                    }
                    _ => {
                        self.handled = false;
                        None
                    }
                }
            }
            _ => {
                self.handled = false;
                None
            }
        }
    }
    pub(super) fn hold(&self, command: u32, input: &[u8]) -> bool {
        self.hold_key && command == 263 && input.starts_with(b"wsec_key\0")
    }
    pub(super) fn transmit(&mut self, bytes: &[u8]) {
        assert!(bytes.len() >= 14);
        let control = matches!(u16::from_be_bytes([bytes[12], bytes[13]]), 0x888e | 0x88c7);
        if !self.formed || !self.up {
            return;
        }
        if bytes[0] & 1 == 0 {
            let target = <[u8; 6]>::try_from(&bytes[..6]).unwrap();
            let peer = self.peers.get(&target).unwrap();
            assert!(control || peer.authorized);
            if !control && self.vars["wsec"] & 4 != 0 {
                assert!(self.active_keys.contains_key(&(0, target)));
            }
        } else if !control && self.vars["wsec"] & 4 != 0 {
            assert!(self
                .primary_key
                .is_some_and(|index| self.active_keys.contains_key(&(index, [0; 6]))));
        }
        self.packets.push(bytes.to_vec());
        if control {
            if let Some(response) = self.response_on_control.take() {
                self.downlink.push_back(response);
            }
        }
    }
}
