// SPDX-License-Identifier: GPL-2.0-or-later
//! PCIe firmware-side conversation fixture. It consumes actual published
//! message-ring descriptors and DMA bodies; no host runtime method is replaced.
use super::*;
use crate::brcmfmac::station_transport::Adapter;
use narf_wifi_fixtures::{DhcpServer, NetworkPlan};

pub(crate) const OWN: [u8; 6] = [2, 6, 7, 8, 9, 10];
pub(crate) const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(crate) type TestAdapter = Adapter<Model>;

pub(crate) fn network_plan() -> NetworkPlan {
    NetworkPlan {
        station: OWN,
        bssid: AP,
        server_ip: [10, 78, 0, 1],
        lease_ip: [10, 78, 0, 42],
        netmask: [255, 255, 255, 0],
        lease_seconds: 3600,
    }
}
pub(crate) fn domain() -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}

struct Flow {
    address: u64,
    read: u16,
    depth: u16,
}
pub(super) struct Firmware {
    secured: bool,
    keys_first: bool,
    hold_keys: bool,
    fail_disconnect: bool,
    power_save_error: u32,
    policy_clear: Option<(u32, alloc::sync::Arc<narf_wireless::reg::db::Database>)>,
    last_power_save_error: bool,
    mfp_supported: bool,
    pmf_required: bool,
    mfp_mode: u32,
    mfp_fault: u8,
    mfp_missing: bool,
    phy_profile: Option<(u32, u8)>,
    wide: Option<crate::cyw43439::phy_fixture::Wide>,
    current_chanspec: u16,
    wide_started: bool,
    hold_tx: bool,
    wpa_ie: Option<Vec<u8>>,
    wpa_auth: Option<u32>,
    cipher: Option<u32>,
    supplicant: Option<u32>,
    psk: bool,
    roam_off: bool,
    channel: u8,
    bandwidth: [u32; 2],
    bandwidth_stuck: bool,
    event_posts: VecDeque<(u32, u64)>,
    events: VecDeque<Vec<u8>>,
    rx_posts: VecDeque<(u32, u64)>,
    rx_read: u16,
    rx_write: u16,
    tx_write: u16,
    flows: BTreeMap<u16, Flow>,
    completions: VecDeque<(u32, u16)>,
    tx_history: Vec<(u32, u64)>,
    downlink: VecDeque<Vec<u8>>,
    server: DhcpServer,
    uplink: Vec<Vec<u8>>,
    creates: usize,
    deletes: usize,
    statuses: usize,
}
impl Firmware {
    fn new(secured: bool) -> Self {
        Self {
            secured,
            keys_first: false,
            hold_keys: false,
            fail_disconnect: false,
            power_save_error: 0,
            policy_clear: None,
            last_power_save_error: false,
            mfp_supported: false,
            pmf_required: false,
            mfp_mode: 0,
            mfp_fault: 0,
            mfp_missing: false,
            phy_profile: None,
            wide: None,
            current_chanspec: 0x1006,
            wide_started: false,
            hold_tx: false,
            wpa_ie: None,
            wpa_auth: None,
            cipher: None,
            supplicant: None,
            psk: false,
            roam_off: false,
            channel: 6,
            bandwidth: [7, 7],
            bandwidth_stuck: false,
            event_posts: VecDeque::new(),
            events: VecDeque::new(),
            rx_posts: VecDeque::new(),
            rx_read: 0,
            rx_write: 0,
            tx_write: 0,
            flows: BTreeMap::new(),
            completions: VecDeque::new(),
            tx_history: Vec::new(),
            downlink: VecDeque::new(),
            server: DhcpServer::new(network_plan()),
            uplink: Vec::new(),
            creates: 0,
            deletes: 0,
            statuses: 0,
        }
    }
    pub(super) fn post_event(&mut self, descriptor: &[u8]) {
        self.event_posts.push_back((
            u32::from_le_bytes(descriptor[4..8].try_into().unwrap()),
            u64::from_le_bytes(descriptor[16..24].try_into().unwrap()),
        ));
    }
    pub(super) fn flow(&mut self, descriptor: &[u8]) {
        if descriptor[0] == 3 {
            let id = u16::from_le_bytes(descriptor[22..24].try_into().unwrap());
            assert_eq!(&descriptor[14..20], &OWN);
            assert_eq!(
                u16::from_le_bytes(descriptor[30..32].try_into().unwrap()),
                48
            );
            self.flows.insert(
                id,
                Flow {
                    address: u64::from_le_bytes(descriptor[32..40].try_into().unwrap()),
                    read: 0,
                    depth: u16::from_le_bytes(descriptor[28..30].try_into().unwrap()),
                },
            );
            self.creates += 1;
        } else {
            let id = u16::from_le_bytes(descriptor[8..10].try_into().unwrap());
            assert!(self.flows.remove(&id).is_some());
            assert!(!self.completions.iter().any(|(_, flow)| *flow == id));
            self.deletes += 1;
        }
    }
    fn request_ies(&self) -> Vec<u8> {
        let mut ies = self.wpa_ie.clone().unwrap_or_default();
        if let Some((chains, fault)) = self.phy_profile {
            if fault != 3 {
                ies.extend_from_slice(&self.wide.as_ref().map_or_else(
                    || crate::cyw43439::phy_fixture::request(chains),
                    |wide| {
                        wide.request(chains, self.bandwidth[usize::from(self.channel <= 14)] == 3)
                    },
                ));
            }
            if fault == 8 {
                let index = ies.len() - 37 + 5;
                ies[index] ^= 1;
            }
        }
        ies
    }
    fn response_ies(&self) -> Vec<u8> {
        self.phy_profile.map_or(Vec::new(), |(chains, fault)| {
            if fault == 4 {
                vec![0, 0]
            } else {
                self.wide.as_ref().map_or_else(
                    || crate::cyw43439::phy_fixture::response(self.channel, chains),
                    |wide| wide.response(self.channel, chains),
                )
            }
        })
    }
    pub(super) fn command(&mut self, command: u32, input: &[u8], maximum: u16) -> Vec<u8> {
        if self
            .policy_clear
            .as_ref()
            .is_some_and(|(target, _)| *target == command)
        {
            self.policy_clear.take().unwrap().1.clear();
        }
        self.last_power_save_error = command == self.power_save_error
            && (command == 86 || input.starts_with(b"pm2_sleep_ret\0"));
        self.mfp_missing = command == 262 && input.starts_with(b"mfp\0") && !self.mfp_supported;
        match command {
            1 => 2u32.to_le_bytes().to_vec(),
            23 => {
                if self.mfp_fault == 3 || self.phy_profile.is_some_and(|p| p.1 == 6) {
                    vec![2, 9, 8, 7, 6, 5]
                } else {
                    AP.to_vec()
                }
            }
            217 => {
                let channels: &[u32] = if self.wide.is_some() && self.channel > 14 {
                    &[6, 10, 36, 40, 52, 149, 153, 165, 255]
                } else if self.wide.is_some() {
                    &[1, 2, 6, 10, 11]
                } else if self.channel > 14 {
                    &[6, 36, 52, 149, 165, 255]
                } else {
                    &[1, 6, 11]
                };
                core::iter::once(channels.len() as u32)
                    .chain(channels.iter().copied())
                    .flat_map(u32::to_le_bytes)
                    .collect()
            }
            262 => {
                let mut out = vec![0; usize::from(maximum)];
                if input.starts_with(b"cur_etheraddr\0") {
                    out[..6].copy_from_slice(&OWN);
                } else if input.starts_with(b"nmode\0") {
                    out[..4].copy_from_slice(&u32::from(self.phy_profile.is_some()).to_le_bytes());
                } else if input.starts_with(b"rxchain\0") {
                    out[..4].copy_from_slice(&self.phy_profile.map_or(0, |p| p.0).to_le_bytes());
                } else if input.starts_with(b"chanspecs\0") {
                    let list = self
                        .wide
                        .as_ref()
                        .map_or_else(|| vec![0; 4], |wide| wide.list());
                    out[..list.len()].copy_from_slice(&list);
                } else if input.starts_with(b"chanspec\0") {
                    let channel = if self.phy_profile.is_some_and(|p| p.1 == 2) {
                        0x1808u32
                    } else if self.wide.is_some()
                        && !self.wide.as_ref().is_some_and(|w| {
                            w.fault == crate::cyw43439::phy_fixture::WideFault::CurrentWidth
                        })
                    {
                        u32::from(self.current_chanspec)
                    } else if self.channel <= 14 {
                        0x1000 | u32::from(self.channel)
                    } else {
                        0xd000 | u32::from(self.channel)
                    };
                    out[..4].copy_from_slice(&channel.to_le_bytes());
                } else if input.starts_with(b"mfp\0") {
                    let mode = if self.mfp_fault == 1 && self.mfp_mode == 2 {
                        0
                    } else {
                        self.mfp_mode
                    };
                    out[..4].copy_from_slice(&mode.to_le_bytes());
                } else if input.starts_with(b"assoc_info\0") {
                    out[..4].copy_from_slice(
                        &(if self.mfp_fault == 4 {
                            1503
                        } else if self.phy_profile.is_some() {
                            self.request_ies().len() as u32
                        } else {
                            28u32
                        })
                        .to_le_bytes(),
                    );
                    out[4..8].copy_from_slice(&(self.response_ies().len() as u32).to_le_bytes());
                } else if input.starts_with(b"assoc_req_ies\0") {
                    let ies = if self.phy_profile.is_some() {
                        self.request_ies()
                    } else {
                        pmf_ie()
                    };
                    out[..ies.len()].copy_from_slice(&ies);
                    if self.mfp_fault == 2 {
                        out[20] = 0;
                    }
                } else if input.starts_with(b"assoc_resp_ies\0") {
                    let ies = self.response_ies();
                    out[..ies.len()].copy_from_slice(&ies);
                } else if input.starts_with(b"per_chan_info\0") {
                    let ch = u32::from_le_bytes(input[14..18].try_into().unwrap());
                    let wide = self.wide.as_ref().expect("wide channel query profile");
                    assert!(
                        ch & 255 == u32::from(self.channel)
                            || ch & 255 == u32::from(wide.secondary)
                    );
                    assert_eq!(ch & !255, if self.channel <= 14 { 0x1000 } else { 0xd000 });
                    let flags = 3u32
                        | if self.channel > 14 { 4 } else { 0 }
                        | if ch & 255 == u32::from(wide.secondary)
                            && wide.fault
                                == crate::cyw43439::phy_fixture::WideFault::ChannelRestricted
                        {
                            32
                        } else {
                            0
                        };
                    out[..4].copy_from_slice(&flags.to_le_bytes());
                } else if input.starts_with(b"bw_cap\0") {
                    let band = u32::from_le_bytes(input[7..11].try_into().unwrap());
                    assert!(matches!(band, 1 | 2));
                    let cap = if self.bandwidth_stuck || self.phy_profile.is_some_and(|p| p.1 == 1)
                    {
                        7
                    } else if self.wide_started
                        && self.bandwidth[(band - 1) as usize] == 3
                        && self.wide.as_ref().is_some_and(|w| {
                            w.fault == crate::cyw43439::phy_fixture::WideFault::CapReadback
                        })
                    {
                        1
                    } else {
                        self.bandwidth[(band - 1) as usize]
                    };
                    out[..4].copy_from_slice(&cap.to_le_bytes());
                }
                out
            }
            263 if input.starts_with(b"bw_cap\0") => {
                assert_eq!(input.len(), 15);
                let band = u32::from_le_bytes(input[7..11].try_into().unwrap());
                assert!(matches!(band, 1 | 2));
                self.bandwidth[(band - 1) as usize] =
                    u32::from_le_bytes(input[11..15].try_into().unwrap());
                self.wide_started |= self.bandwidth[(band - 1) as usize] == 3;
                Vec::new()
            }
            263 if input.starts_with(b"escan\0") => {
                let id = u16::from_le_bytes(input[12..14].try_into().unwrap());
                self.event(
                    69,
                    8,
                    0,
                    &scan_result(
                        id,
                        self.secured,
                        self.channel,
                        self.pmf_required,
                        self.phy_profile,
                        self.wide.as_ref(),
                    ),
                );
                self.event(69, 0, 0, &[]);
                Vec::new()
            }
            263 if input.starts_with(b"wpaie\0") => {
                self.wpa_ie = Some(input[6..].to_vec());
                Vec::new()
            }
            263 if input.starts_with(b"mfp\0") => {
                self.mfp_mode = u32::from_le_bytes(input[4..8].try_into().unwrap());
                Vec::new()
            }
            263 if input.starts_with(b"wpa_auth\0") => {
                self.wpa_auth = Some(u32::from_le_bytes(input[9..13].try_into().unwrap()));
                Vec::new()
            }
            263 if input.starts_with(b"sup_wpa\0") => {
                self.supplicant = Some(u32::from_le_bytes(input[8..12].try_into().unwrap()));
                Vec::new()
            }
            134 => {
                self.cipher = Some(u32::from_le_bytes(input[..4].try_into().unwrap()));
                Vec::new()
            }
            263 if input.starts_with(b"roam_off\0") => {
                self.roam_off = input[9..] == [1, 0, 0, 0];
                Vec::new()
            }
            268 => {
                assert_eq!(&input[..4], &[32, 0, 0, 0]);
                assert_eq!(&input[4..36], &[0x11; 32]);
                self.psk = true;
                Vec::new()
            }
            26 => {
                assert_eq!(&input[..8], &[4, 0, 0, 0, b't', b'e', b's', b't']);
                assert_eq!(&input[36..42], &AP);
                assert_eq!(input.len(), 50);
                let chanspec = if self.channel <= 14 {
                    0x1000u16
                } else {
                    0xd000u16
                } | u16::from(self.channel);
                let chanspec = if self.bandwidth[usize::from(self.channel <= 14)] == 3 {
                    self.wide.as_ref().expect("wide native profile").operating
                } else {
                    chanspec
                };
                assert_eq!(&input[48..50], &chanspec.to_le_bytes());
                self.current_chanspec = chanspec;
                let protected_ie = pmf_ie();
                let expected: &[u8] = if self.pmf_required {
                    &protected_ie
                } else if self.secured {
                    &[
                        48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
                    ]
                } else {
                    &[]
                };
                assert_eq!(self.wpa_ie.as_deref(), Some(expected));
                assert!(!self.pmf_required || self.mfp_supported && self.mfp_mode == 2);
                assert!(self.roam_off && (!self.secured || self.psk));
                assert_eq!(self.wpa_auth, Some(if self.secured { 128 } else { 0 }));
                assert_eq!(self.cipher, Some(if self.secured { 4 } else { 0 }));
                assert_eq!(self.supplicant, Some(u32::from(self.secured)));
                self.event(16, 0, 1, &[]);
                if self.secured && self.keys_first && !self.hold_keys {
                    self.event(46, 6, 0, &[]);
                }
                self.event(0, 0, 0, &[]);
                if self.secured && !self.keys_first && !self.hold_keys {
                    self.event(46, 6, 0, &[]);
                }
                Vec::new()
            }
            52 => {
                if !self.fail_disconnect {
                    self.event(16, 0, 0, &[]);
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
    pub(super) fn status(&self, command: u32) -> i16 {
        if self.mfp_missing {
            -23
        } else if command == 52 && self.fail_disconnect || self.last_power_save_error {
            5
        } else {
            0
        }
    }
    pub(super) fn hold_mfp_reply(&self, command: u32, input: &[u8]) -> bool {
        (command == 263
            && input.starts_with(b"bw_cap\0")
            && input[11..15] == [3, 0, 0, 0]
            && self
                .wide
                .as_ref()
                .is_some_and(|w| w.fault == crate::cyw43439::phy_fixture::WideFault::HoldCap))
            || command == 262
                && (self.mfp_fault == 5 && input.starts_with(b"assoc_req_ies\0")
                    || self.phy_profile.is_some_and(|p| p.1 == 5)
                        && input.starts_with(b"assoc_resp_ies\0")
                    || self.wide.as_ref().is_some_and(|w| {
                        w.fault == crate::cyw43439::phy_fixture::WideFault::HoldResponse
                    }) && input.starts_with(b"assoc_resp_ies\0"))
    }
    fn event(&mut self, kind: u32, status: u32, flags: u16, data: &[u8]) {
        let mut bytes = vec![0; 72 + data.len()];
        bytes[12..16].copy_from_slice(&[0x88, 0x6c, 0x80, 1]);
        bytes[19..24].copy_from_slice(&[0, 0x10, 0x18, 0, 1]);
        bytes[24..26].copy_from_slice(&2u16.to_be_bytes());
        bytes[26..28].copy_from_slice(&flags.to_be_bytes());
        bytes[28..32].copy_from_slice(&kind.to_be_bytes());
        bytes[32..36].copy_from_slice(&status.to_be_bytes());
        bytes[44..48].copy_from_slice(&(data.len() as u32).to_be_bytes());
        bytes[48..54].copy_from_slice(&AP);
        bytes[72..].copy_from_slice(data);
        self.events.push_back(bytes);
    }
    pub(super) fn step(&mut self, state: &mut State, control: &mut super::Firmware) {
        while !self.events.is_empty() && !self.event_posts.is_empty() {
            let event = self.events.pop_front().unwrap();
            let (id, address) = self.event_posts.pop_front().unwrap();
            state.dma.get_mut(&address).unwrap()[..event.len()].copy_from_slice(&event);
            complete(
                state,
                usize::from(control.completion_write),
                0xe,
                id,
                (0, event.len() as u16),
                0,
                0,
            );
            control.completion_write =
                (control.completion_write + 1) % (word(state, RINGS + 2 * 16 + 4) as u16);
            put(state, D2HW, &control.completion_write.to_le_bytes());
        }
        let rx_ring = pointer(state, RINGS + 16 + 8);
        if rx_ring != 0 {
            let producer = word(state, H2DW + 4) as u16;
            let depth = word(state, RINGS + 16 + 4) as u16;
            while self.rx_read != producer {
                let at = usize::from(self.rx_read) * 32;
                let post = &state.dma[&rx_ring][at..at + 32];
                assert_eq!(post[0], 0x11);
                self.rx_posts.push_back((
                    u32::from_le_bytes(post[4..8].try_into().unwrap()),
                    u64::from_le_bytes(post[24..32].try_into().unwrap()),
                ));
                self.rx_read = (self.rx_read + 1) % depth;
            }
            put(state, H2DR + 4, &self.rx_read.to_le_bytes());
        }
        for (&id, flow) in &mut self.flows {
            let producer = word(state, H2DW + u32::from(id) * 4) as u16;
            while flow.read != producer {
                let at = usize::from(flow.read) * 48;
                let tx = &state.dma[&flow.address][at..at + 48];
                assert_eq!(&tx[..4], &[0xf, 0, 0, 0]);
                assert_eq!(tx[23], 1);
                let request = u32::from_le_bytes(tx[4..8].try_into().unwrap());
                let body = u64::from_le_bytes(tx[32..40].try_into().unwrap());
                let length = usize::from(u16::from_le_bytes(tx[42..44].try_into().unwrap()));
                let mut ethernet = tx[8..22].to_vec();
                ethernet.extend_from_slice(&state.dma[&body][..length]);
                self.uplink.push(ethernet.clone());
                if let Some(reply) = self.server.receive(&ethernet) {
                    self.downlink.push_back(reply);
                }
                self.tx_history.push((request, body));
                self.completions.push_back((request, id));
                flow.read = (flow.read + 1) % flow.depth;
            }
            put(state, H2DR + u32::from(id) * 4, &flow.read.to_le_bytes());
        }
        if !self.hold_tx {
            while let Some((id, flow)) = self.completions.pop_front() {
                let ring = pointer(state, RINGS + 3 * 16 + 8);
                let at = usize::from(self.tx_write) * 16;
                let entry = &mut state.dma.get_mut(&ring).unwrap()[at..at + 16];
                entry.fill(0);
                entry[0] = 0x10;
                entry[4..8].copy_from_slice(&id.to_le_bytes());
                entry[10..12].copy_from_slice(&flow.to_le_bytes());
                self.tx_write = (self.tx_write + 1) % (word(state, RINGS + 3 * 16 + 4) as u16);
                put(state, D2HW + 4, &self.tx_write.to_le_bytes());
                self.statuses += 1;
            }
        }
        while !self.downlink.is_empty() && !self.rx_posts.is_empty() {
            let bytes = self.downlink.pop_front().unwrap();
            let (id, address) = self.rx_posts.pop_front().unwrap();
            state.dma.get_mut(&address).unwrap()[256..256 + bytes.len()].copy_from_slice(&bytes);
            let ring = pointer(state, RINGS + 4 * 16 + 8);
            let at = usize::from(self.rx_write) * 32;
            let entry = &mut state.dma.get_mut(&ring).unwrap()[at..at + 32];
            entry.fill(0);
            entry[0] = 0x12;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[14..16].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
            entry[16..18].copy_from_slice(&256u16.to_le_bytes());
            entry[18..20].copy_from_slice(&1u16.to_le_bytes());
            self.rx_write = (self.rx_write + 1) % (word(state, RINGS + 4 * 16 + 4) as u16);
            put(state, D2HW + 8, &self.rx_write.to_le_bytes());
        }
    }
}
fn pmf_ie() -> Vec<u8> {
    vec![
        48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 192, 0, 0, 0, 0, 15,
        172, 6,
    ]
}
fn scan_result(
    id: u16,
    secured: bool,
    channel: u8,
    mfp: bool,
    phy: Option<(u32, u8)>,
    wide: Option<&crate::cyw43439::phy_fixture::Wide>,
) -> Vec<u8> {
    let mut ies = vec![0, 4, b't', b'e', b's', b't'];
    if secured {
        if mfp {
            ies.extend_from_slice(&pmf_ie());
        } else {
            ies.extend_from_slice(&[
                48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
            ]);
        }
    }
    if let Some((chains, fault)) = phy {
        let extra = wide.map_or_else(
            || crate::cyw43439::phy_fixture::response(channel, chains),
            |w| w.beacon(channel, chains),
        );
        ies.extend_from_slice(if fault == 9 { &extra[..52] } else { &extra });
    }
    let mut out = vec![0; 12 + 128 + ies.len()];
    let len = out.len();
    out[..4].copy_from_slice(&(len as u32).to_le_bytes());
    out[4..8].copy_from_slice(&109u32.to_le_bytes());
    out[8..10].copy_from_slice(&id.to_le_bytes());
    out[10..12].copy_from_slice(&1u16.to_le_bytes());
    let bss = &mut out[12..];
    bss[..4].copy_from_slice(&109u32.to_le_bytes());
    bss[4..8].copy_from_slice(&((128 + ies.len()) as u32).to_le_bytes());
    bss[8..14].copy_from_slice(&AP);
    bss[16] = if secured { 17 } else { 1 };
    bss[18] = 4;
    bss[19..23].copy_from_slice(b"test");
    let chanspec = if channel <= 14 { 0x1000u16 } else { 0xd000u16 } | u16::from(channel);
    bss[72..74].copy_from_slice(&chanspec.to_le_bytes());
    bss[78..80].copy_from_slice(&(-42i16).to_le_bytes());
    bss[88] = channel;
    bss[116..118].copy_from_slice(&128u16.to_le_bytes());
    bss[120..124].copy_from_slice(&(ies.len() as u32).to_le_bytes());
    bss[128..].copy_from_slice(&ies);
    out
}

#[derive(Clone)]
pub(crate) struct Handle(Rc<IrqSafeSpinLock<State>>);
impl Handle {
    fn change(&self, operation: impl FnOnce(&mut Firmware)) {
        let mut state = self.0.lock();
        operation(state.firmware.as_mut().unwrap().station.as_mut().unwrap());
        firmware_step(&mut state);
    }
    pub(crate) fn keys_first(&self, value: bool) {
        self.change(|f| f.keys_first = value);
    }
    pub(crate) fn mfp_profile(&self, supported: bool, required: bool, fault: u8) {
        self.change(|f| {
            f.mfp_supported = supported;
            f.pmf_required = required;
            f.mfp_fault = fault;
        });
    }
    pub(crate) fn phy_profile(&self, chains: u32, fault: u8) {
        self.change(|f| f.phy_profile = Some((chains, fault)));
    }
    pub(crate) fn wide_profile(&self, wide: crate::cyw43439::phy_fixture::Wide) {
        self.change(|f| {
            f.bandwidth = [wide.caps[1], wide.caps[0]];
            f.wide = Some(wide);
        });
    }
    pub(crate) fn release_wide(&self) {
        self.change(|f| {
            if let Some(wide) = &mut f.wide {
                wide.fault = crate::cyw43439::phy_fixture::WideFault::None;
            }
        });
    }
    pub(crate) fn channel(&self, channel: u8) {
        self.change(|f| f.channel = channel);
    }
    pub(crate) fn hold_wide_bandwidth(&self) {
        self.change(|f| f.bandwidth_stuck = true);
    }
    pub(crate) fn commands(&self) -> Vec<(u32, Vec<u8>, u16)> {
        self.0.lock().firmware.as_ref().unwrap().commands.clone()
    }
    pub(crate) fn hold_keys(&self, value: bool) {
        self.change(|f| f.hold_keys = value);
    }
    pub(crate) fn hold_transmits(&self, value: bool) {
        self.change(|f| f.hold_tx = value);
    }
    pub(crate) fn fail_disconnect(&self) {
        self.change(|f| f.fail_disconnect = true);
    }
    pub(crate) fn clear_policy_on(
        &self,
        command: u32,
        database: alloc::sync::Arc<narf_wireless::reg::db::Database>,
    ) {
        self.change(|f| f.policy_clear = Some((command, database)));
    }
    pub(crate) fn reject_power_save(&self, command: u32) {
        self.change(|f| f.power_save_error = command);
    }
    pub(crate) fn power_commands(&self) -> Vec<(u32, Vec<u8>)> {
        self.0
            .lock()
            .firmware
            .as_ref()
            .unwrap()
            .commands
            .iter()
            .filter(|(command, body, _)| {
                *command == 86 || *command == 263 && body.starts_with(b"pm2_sleep_ret\0")
            })
            .map(|(command, body, _)| (*command, body.clone()))
            .collect()
    }
    pub(crate) fn downlink(&self, bytes: &[u8]) {
        self.change(|f| f.downlink.push_back(bytes.to_vec()));
    }
    pub(crate) fn lose_link(&self) {
        self.change(|f| f.event(16, 0, 0, &[]));
    }
    pub(crate) fn stale_authorization(&self) {
        self.change(|f| {
            f.event(0, 0, 0, &[]);
            f.event(46, 6, 0, &[]);
        });
    }
    pub(crate) fn uplink(&self, bytes: &[u8]) -> bool {
        self.0
            .lock()
            .firmware
            .as_ref()
            .unwrap()
            .station
            .as_ref()
            .unwrap()
            .uplink
            .iter()
            .any(|b| b == bytes)
    }
    pub(crate) fn sent(&self) -> usize {
        self.0
            .lock()
            .firmware
            .as_ref()
            .unwrap()
            .station
            .as_ref()
            .unwrap()
            .uplink
            .len()
    }
    pub(crate) fn stats(&self) -> (usize, usize, usize, usize, bool, usize) {
        let state = self.0.lock();
        let firmware = state.firmware.as_ref().unwrap().station.as_ref().unwrap();
        (
            firmware.creates,
            firmware.deletes,
            firmware.statuses,
            firmware.completions.len(),
            state.dma_enable,
            state.unsafe_free,
        )
    }
    pub(crate) fn last_tx_alive(&self) -> bool {
        let state = self.0.lock();
        let f = state.firmware.as_ref().unwrap().station.as_ref().unwrap();
        f.tx_history
            .last()
            .is_some_and(|(_, address)| !state.dropped_addresses.contains(address))
    }
    pub(crate) fn dropped_addresses(&self) -> BTreeSet<u64> {
        self.0.lock().dropped_addresses.clone()
    }
    pub(crate) fn dma_enable_count(&self) -> usize {
        self.0.lock().dma_enables
    }
    pub(crate) fn dhcp(&self) -> (u32, u32) {
        let s = self.0.lock();
        let seen = s
            .firmware
            .as_ref()
            .unwrap()
            .station
            .as_ref()
            .unwrap()
            .server
            .observations();
        (seen.discovers, seen.requests)
    }
}
pub(crate) fn create(version: u32, secured: bool) -> Result<(TestAdapter, Handle), runtime::Error> {
    create_inner(version, secured, None)
}
pub(crate) fn create_selected(
    version: u32,
    secured: bool,
    selection: &crate::brcmfmac::provision::Selection,
    assets: &crate::brcmfmac::provision::Assets,
) -> Result<(TestAdapter, Handle), runtime::Error> {
    assets
        .proof
        .validate()
        .map_err(|_| runtime::Error::Access)?;
    create_inner(version, secured, Some((selection, assets)))
}
fn create_inner(
    version: u32,
    secured: bool,
    selected: Option<(
        &crate::brcmfmac::provision::Selection,
        &crate::brcmfmac::provision::Assets,
    )>,
) -> Result<(TestAdapter, Handle), runtime::Error> {
    assert!(matches!(version, 5 | 6));
    let (bus, state) = model();
    {
        let mut s = state.lock();
        put(&mut s, SHARED, &version.to_le_bytes());
        if version == 5 {
            put(&mut s, INFO + 52, &4u16.to_le_bytes());
        }
        s.firmware = Some(super::Firmware {
            station: Some(Firmware::new(secured)),
            ..super::Firmware::default()
        });
    }
    // Explicit synthetic board policy exercises the actual CR4 boot owner;
    // these fixture bytes are never registered as deployable firmware/NVRAM.
    let boot = if let Some((selection, assets)) = selected {
        let nvram = boot::pack_nvram(&assets.nvram)?;
        boot::Cr4::claim_selected(bus, pci(), selection)?.boot(&assets.firmware, &nvram)?
    } else {
        let nvram = boot::pack_nvram(b"boardrev=1\n").unwrap();
        boot::Cr4::claim(bus, pci(), profile())?
            .boot(&[0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6], &nvram)?
    };
    let runtime = runtime::Runtime::attach(boot)?;
    Adapter::new(runtime)
        .map(|adapter| (adapter, Handle(state)))
        .map_err(|_| runtime::Error::Protocol)
}
