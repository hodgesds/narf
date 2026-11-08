// SPDX-License-Identifier: GPL-2.0-or-later
//! PCIe firmware-side conversation fixture. It consumes actual published
//! message-ring descriptors and DMA bodies; no host runtime method is replaced.
use super::*;
use crate::brcmfmac::station_transport::Adapter;
use narf_wifi_fixtures::{DhcpServer, NetworkPlan};
#[path = "ap_model.rs"]
pub(crate) mod ap_model;
#[path = "monitor_model.rs"]
pub(crate) mod monitor_model;
#[path = "sdio_ap_firmware.rs"]
pub(crate) mod sdio_ap;

pub(crate) const OWN: [u8; 6] = [2, 6, 7, 8, 9, 10];
pub(crate) const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
/// Address of the modeled secondary interface (IF ADD event address).
pub(crate) const VIF: [u8; 6] = [6, 6, 7, 8, 9, 10];
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
    /// Creating request's `msg.ifidx`.
    ifidx: u8,
}
/// The modeled secondary firmware interface (ifidx 1, bsscfg 1). Its
/// dcmds arrive with `msg.ifidx` 1 and its `brcmf_fil_bsscfg_*` iovars
/// with the `bsscfg:` prefix (Linux 7.3-rc4 `fwil.c`); its events carry
/// ifidx/bsscfgidx 1 (`fweh.c` dispatch). It is either a STA joining
/// [`AP`] or, with [`Handle::enable_vif_ap`], a firmware-SME AP.
#[derive(Default)]
struct Vif {
    ap: Option<ap_model::Profile>,
    /// Associated after a `SET_SSID` on ifidx 1 until `DISASSOC`.
    joined: bool,
    /// Plain values of the bsscfg iovars/dcmds this interface was set.
    sets: Vec<(u32, Vec<u8>)>,
    /// `p2p_da_override`: the P2P Device Address of the discovery bsscfg.
    p2p_device: Option<[u8; 6]>,
    /// The discovery bsscfg (ifidx/bsscfg 1, NOIF) exists (`p2p_disc 1`).
    p2p_discovery: bool,
    /// `BRCMF_E_IF_ROLE_*` of the `p2p_ifadd` connection bsscfg.
    p2p_role: u8,
}
pub(super) struct Firmware {
    ap: Option<ap_model::Profile>,
    vif: Vif,
    /// `msg.ifidx` of the IOCTL being answered (for its status).
    command_ifidx: u8,
    /// Firmware `cap` token list (`brcmf_feat_firmware_capabilities`);
    /// empty answers the historical zero reply.
    caps: Vec<u8>,
    monitor: Option<monitor_model::Profile>,
    raw_downlink: VecDeque<(Vec<u8>, u16)>,
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
    mfp_conversation: Option<crate::cyw43439::mfp_fixture::Conversation>,
    phy_profile: Option<(u32, u8)>,
    wide: Option<crate::cyw43439::phy_fixture::Wide>,
    vht: Option<crate::cyw43439::phy_fixture::Vht80>,
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
    prefix_rx_fallback: bool,
    tx_write: u16,
    flows: BTreeMap<u16, Flow>,
    completions: VecDeque<(u32, u16)>,
    tx_history: Vec<(u32, u64)>,
    downlink: VecDeque<Vec<u8>>,
    server: DhcpServer,
    uplink: Vec<Vec<u8>>,
    creates: usize,
    tids: Vec<u8>,
    tx_priorities: Vec<(u16, u8)>,
    wme_ac_sta: [u8; 16],
    deletes: usize,
    statuses: usize,
    /// `wowl_cap` reply and the `wowl_wakeind` the firmware reports.
    wowl_cap: u32,
    wakeind: u32,
    /// Current `BRCMF_C_SET_PM` mode (`BRCMF_C_GET_PM` answers it).
    pm: u32,
}
impl Firmware {
    /// Inject one real firmware-SME peer loss at the native control setup
    /// boundary; parent register model cannot mutate the private AP model.
    pub(super) fn ap_peer_loss(&mut self, peer: [u8; 6]) {
        self.ap.as_mut().unwrap().remove(peer);
    }

    fn new(secured: bool) -> Self {
        Self {
            ap: None,
            vif: Vif::default(),
            command_ifidx: 0,
            caps: Vec::new(),
            monitor: None,
            raw_downlink: VecDeque::new(),
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
            mfp_conversation: None,
            phy_profile: None,
            wide: None,
            vht: None,
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
            prefix_rx_fallback: false,
            tx_write: 0,
            flows: BTreeMap::new(),
            completions: VecDeque::new(),
            tx_history: Vec::new(),
            downlink: VecDeque::new(),
            server: DhcpServer::new(network_plan()),
            uplink: Vec::new(),
            creates: 0,
            tids: Vec::new(),
            tx_priorities: Vec::new(),
            wme_ac_sta: [0; 16],
            deletes: 0,
            statuses: 0,
            wowl_cap: 0,
            wakeind: 0,
            pm: 0,
        }
    }
    /// Watchdog reset: the session (rings, flows, association, keys)
    /// is lost; the configured profile of this fixture is kept.
    pub(super) fn reboot(&mut self) {
        let mut fresh = Self::new(self.secured);
        fresh.keys_first = self.keys_first;
        fresh.mfp_supported = self.mfp_supported;
        fresh.pmf_required = self.pmf_required;
        fresh.mfp_fault = self.mfp_fault;
        fresh.mfp_missing = self.mfp_missing;
        fresh.phy_profile = self.phy_profile;
        fresh.wide = self.wide.take();
        fresh.vht = self.vht.take();
        fresh.channel = self.channel;
        fresh.wme_ac_sta = self.wme_ac_sta;
        fresh.caps = core::mem::take(&mut self.caps);
        *self = fresh;
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
            if descriptor[1] != 0 {
                // A secondary interface's flow carries its own address.
                assert_eq!(&descriptor[14..20], &VIF);
            } else if self.ap.is_none() {
                assert_eq!(&descriptor[14..20], &OWN);
            } else {
                assert_ne!(&descriptor[14..20], &[0; 6]);
                assert_eq!(descriptor[14] & 1, 0);
            }
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
                    ifidx: descriptor[1],
                },
            );
            self.creates += 1;
            self.tids.push(descriptor[20]);
        } else {
            let id = u16::from_le_bytes(descriptor[8..10].try_into().unwrap());
            assert!(self.flows.remove(&id).is_some());
            assert!(!self.completions.iter().any(|(_, flow)| *flow == id));
            self.deletes += 1;
        }
    }
    fn request_ies(&self) -> Vec<u8> {
        let mut ies = self
            .mfp_conversation
            .as_ref()
            .and_then(|p| p.request.clone())
            .unwrap_or_else(|| self.wpa_ie.clone().unwrap_or_default());
        if let Some(vht) = &self.vht {
            ies.extend_from_slice(&vht.request(
                self.phy_profile.map_or(0, |p| p.0),
                match self.bandwidth[0] {
                    15 => 160,
                    7 => 80,
                    3 => 40,
                    _ => 20,
                },
            ));
            return ies;
        }
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
        let mut ies = self
            .mfp_conversation
            .as_ref()
            .map_or(Vec::new(), |p| p.response());
        if let Some(vht) = &self.vht {
            ies.extend_from_slice(&vht.response(self.channel, self.phy_profile.map_or(0, |p| p.0)));
            return ies;
        }
        ies.extend_from_slice(&self.phy_profile.map_or(Vec::new(), |(chains, fault)| {
            if fault == 4 {
                vec![0, 0]
            } else {
                self.wide.as_ref().map_or_else(
                    || crate::cyw43439::phy_fixture::response(self.channel, chains),
                    |wide| wide.response(self.channel, chains),
                )
            }
        }));
        ies
    }
    /// One IOCTL addressed by `msg.ifidx` (Linux `msgbuf.c`
    /// `brcmf_msgbuf_tx_ioctl`).
    pub(super) fn command_on(
        &mut self,
        ifidx: u8,
        command: u32,
        input: &[u8],
        maximum: u16,
    ) -> Vec<u8> {
        self.command_ifidx = ifidx;
        if ifidx == 0 || input.starts_with(b"bsscfg:interface_remove\0") {
            return self.command(command, input, maximum);
        }
        assert_eq!(ifidx, 1, "only ifidx 1 is modeled");
        // fwil.c brcmf_create_bsscfg: `bsscfg:` + name + NUL + le32 index.
        let plain;
        let input = match input.strip_prefix(b"bsscfg:") {
            Some(rest) if matches!(command, 262 | 263) => {
                let end = rest.iter().position(|byte| *byte == 0).unwrap();
                assert_eq!(&rest[end + 1..end + 5], &1u32.to_le_bytes());
                let mut body = rest[..=end].to_vec();
                body.extend_from_slice(&rest[end + 5..]);
                plain = body;
                &plain[..]
            }
            _ => input,
        };
        if let Some(ap) = self.vif.ap.as_mut() {
            if let Some(reply) = ap.command(command, input, maximum) {
                return reply;
            }
        }
        match command {
            // The secondary STA join completes on bsscfg 1 only.
            26 => {
                assert_eq!(&input[..8], &[4, 0, 0, 0, b't', b'e', b's', b't']);
                assert_eq!(&input[36..42], &AP);
                self.vif.joined = true;
                self.event_on(16, (1, 1), AP, &[]);
                self.events.back_mut().unwrap()[26..28].copy_from_slice(&1u16.to_be_bytes());
                self.event_on(0, (1, 1), AP, &[]);
                Vec::new()
            }
            52 => {
                if core::mem::take(&mut self.vif.joined) {
                    self.event_on(16, (1, 1), AP, &[]);
                }
                Vec::new()
            }
            23 if self.vif.joined => AP.to_vec(),
            23 => vec![0; 6],
            // brcmf_p2p_tx_action_frame: `actframe` on the discovery bsscfg
            // completes on-channel (BRCMF_E_ACTION_FRAME_COMPLETE, status
            // success = ACK) and off-channel
            // (BRCMF_E_ACTION_FRAME_OFF_CHAN_COMPLETE).
            263 if input.starts_with(b"actframe\0") => {
                let da = crate::brcmfmac::p2p_wire::af_da(&input[9..]);
                self.vif.sets.push((command, input.to_vec()));
                for kind in [
                    crate::brcmfmac::p2p_wire::E_ACTION_FRAME_COMPLETE,
                    crate::brcmfmac::p2p_wire::E_ACTION_FRAME_OFF_CHAN_COMPLETE,
                ] {
                    self.event_on(kind, (1, 1), da, &[]);
                }
                Vec::new()
            }
            // brcmf_p2p_escan: bsscfg `p2p_scan` 'E' answers with one
            // partial BRCMF_E_ESCAN_RESULT of the P2P sync_id from the
            // discovery bsscfg and the final success record.
            263 if input.starts_with(b"p2p_scan\0") => {
                self.vif.sets.push((command, input.to_vec()));
                let result = scan_result(
                    crate::brcmfmac::p2p_wire::ESCAN_SYNC_ID,
                    false,
                    self.channel,
                    (false, None),
                    None,
                    None,
                    None,
                );
                self.event(69, 8, 0, &result);
                let bytes = self.events.back_mut().unwrap();
                bytes[70] = 1;
                bytes[71] = 1;
                self.event(69, 0, 0, &[]);
                Vec::new()
            }
            // Read-only queries share the device answers.
            262 => self.command(command, input, maximum),
            _ => {
                self.vif.sets.push((command, input.to_vec()));
                Vec::new()
            }
        }
    }
    pub(super) fn command(&mut self, command: u32, input: &[u8], maximum: u16) -> Vec<u8> {
        if let Some(monitor) = self.monitor.as_mut() {
            if let Some(reply) = monitor.command(command, input, maximum) {
                return reply;
            }
        }
        if let Some(ap) = self.ap.as_mut() {
            if let Some(reply) = ap.command(command, input, maximum) {
                return reply;
            }
        }
        if self
            .policy_clear
            .as_ref()
            .is_some_and(|(target, _)| *target == command)
        {
            self.policy_clear.take().unwrap().1.clear();
        }
        self.last_power_save_error = command == self.power_save_error
            && (command == 86 || input.starts_with(b"pm2_sleep_ret\0"));
        self.mfp_missing = command == 262
            && (input.starts_with(b"mfp\0") && !self.mfp_supported
                || input.starts_with(b"vhtmode\0")
                    && self.vht.as_ref().is_some_and(|p| p.mode.is_none())
                || input.starts_with(b"txstreams\0")
                    && self.vht.as_ref().is_some_and(|p| p.txstreams.is_none())
                || input.starts_with(b"txbf_bfe_cap\0")
                    && self.vht.as_ref().is_some_and(|p| p.txbf[0].is_none())
                || input.starts_with(b"txbf_bfr_cap\0")
                    && self.vht.as_ref().is_some_and(|p| p.txbf[1].is_none()));
        match command {
            // fweh `BRCMF_E_IF` (`struct brcmf_if_event`) for the one
            // modeled secondary STA interface: ifidx 1, bsscfg 1.
            262 if input.starts_with(b"interface_create\0") => {
                let role = u8::from(self.vif.ap.is_some());
                self.event_on(54, (1, 1), VIF, &[1, 1, 0, 1, role]);
                Vec::new()
            }
            262 if input.starts_with(b"cap\0") && !self.caps.is_empty() => {
                let mut caps = self.caps.clone();
                caps.push(0);
                caps
            }
            // p2p.c brcmf_p2p_add_vif / brcmf_p2p_del_vif for the one
            // modeled connection bsscfg (ifidx 1, bsscfg 1, role P2P_GO 3).
            // `struct brcmf_fil_p2p_if_le` type: CLIENT 0 -> role
            // BRCMF_E_IF_ROLE_P2P_CLIENT 2, GO 1 -> BRCMF_E_IF_ROLE_P2P_GO 3.
            263 if input.starts_with(b"p2p_ifadd\0") => {
                self.vif.p2p_role = match input[10 + 6] {
                    0 => 2,
                    1 => 3,
                    kind => panic!("p2p_ifadd type {kind} is not modeled"),
                };
                self.event_on(54, (1, 1), VIF, &[1, 1, 0, 1, self.vif.p2p_role]);
                Vec::new()
            }
            // brcmf_p2p_create_p2pdev: `p2p_da_override`, then `p2p_disc 1`
            // creates the NOIF discovery bsscfg (BRCMF_E_IF ADD, flags
            // BRCMF_E_IF_FLAG_NOIF, role P2P device 4) on ifidx/bsscfg 1;
            // `p2p_disc 0` deletes it again (brcmf_p2p_deinit_discovery).
            263 if input.starts_with(b"p2p_da_override\0") => {
                self.vif.p2p_device = Some(input[16..22].try_into().unwrap());
                Vec::new()
            }
            263 if input.starts_with(b"p2p_disc\0") => {
                let enable = input[9..13] == 1u32.to_le_bytes();
                if enable != self.vif.p2p_discovery {
                    self.vif.p2p_discovery = enable;
                    let action = if enable { 1 } else { 2 };
                    let device = self.vif.p2p_device.expect("p2p_da_override first");
                    self.event_on(54, (1, 1), device, &[1, action, 1, 1, 4]);
                }
                Vec::new()
            }
            262 if input.starts_with(b"p2p_dev\0") => {
                assert!(self.vif.p2p_discovery, "p2p_dev before p2p_disc 1");
                1u32.to_le_bytes().to_vec()
            }
            // brcmf_notify_connect_status_ap: the GO bsscfg's BRCMF_E_LINK
            // with BRCMF_E_REASON_LINK_BSSCFG_DIS (4) completes vif_disabled.
            263 if input.starts_with(b"p2p_ifdis\0") => {
                assert_eq!(&input[10..16], &VIF);
                self.event_on(16, (1, 1), VIF, &[]);
                self.events.back_mut().unwrap()[36..40].copy_from_slice(&4u32.to_be_bytes());
                Vec::new()
            }
            263 if input.starts_with(b"p2p_ifdel\0") => {
                assert_eq!(&input[10..16], &VIF);
                self.event_on(54, (1, 1), VIF, &[1, 2, 0, 1, self.vif.p2p_role]);
                Vec::new()
            }
            263 if input.starts_with(b"bsscfg:interface_remove\0") => {
                assert_eq!(&input[24..28], &1u32.to_le_bytes());
                self.event_on(54, (1, 1), VIF, &[1, 2, 0, 1, 0]);
                Vec::new()
            }
            1 => 2u32.to_le_bytes().to_vec(),
            85 => self.pm.to_le_bytes().to_vec(),
            86 => {
                self.pm = u32::from_le_bytes(input[..4].try_into().unwrap());
                Vec::new()
            }
            23 => {
                if self.mfp_fault == 3 || self.phy_profile.is_some_and(|p| p.1 == 6) {
                    vec![2, 9, 8, 7, 6, 5]
                } else {
                    AP.to_vec()
                }
            }
            217 => {
                let channels: &[u32] = if self.vht.is_some() {
                    &[
                        6, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
                        132, 136, 140, 144, 149, 153, 157, 161, 165,
                    ]
                } else if self.wide.is_some() && self.channel > 14 {
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
                } else if input.starts_with(b"wowl_cap\0") {
                    out[..4].copy_from_slice(&self.wowl_cap.to_le_bytes());
                } else if input.starts_with(b"wowl_wakeind\0") {
                    // brcmf_wowl_wakeind_le: pci_wakeind, ucode_wakeind.
                    out[..4].copy_from_slice(&u32::from(self.wakeind != 0).to_le_bytes());
                    out[4..8].copy_from_slice(&self.wakeind.to_le_bytes());
                } else if input.starts_with(b"nmode\0") {
                    out[..4].copy_from_slice(&u32::from(self.phy_profile.is_some()).to_le_bytes());
                } else if input.starts_with(b"rxchain\0") {
                    out[..4].copy_from_slice(&self.phy_profile.map_or(0, |p| p.0).to_le_bytes());
                } else if input.starts_with(b"vhtmode\0") {
                    out[..4].copy_from_slice(
                        &self
                            .vht
                            .as_ref()
                            .and_then(|p| p.mode)
                            .unwrap_or(0)
                            .to_le_bytes(),
                    );
                } else if input.starts_with(b"txstreams\0") {
                    out[..4].copy_from_slice(
                        &self
                            .vht
                            .as_ref()
                            .and_then(|p| p.txstreams)
                            .unwrap_or(0)
                            .to_le_bytes(),
                    );
                } else if let Some(index) = [&b"txbf_bfe_cap\0"[..], b"txbf_bfr_cap\0"]
                    .iter()
                    .position(|name| input.starts_with(name))
                {
                    out[..4].copy_from_slice(
                        &self
                            .vht
                            .as_ref()
                            .and_then(|p| p.txbf[index])
                            .unwrap_or(0)
                            .to_le_bytes(),
                    );
                } else if input.starts_with(b"wme_ac_sta\0") {
                    out[..16].copy_from_slice(&self.wme_ac_sta);
                } else if input.starts_with(b"chanspecs\0") {
                    let list = self.vht.as_ref().map(|v| v.list()).unwrap_or_else(|| {
                        self.wide
                            .as_ref()
                            .map_or_else(|| vec![0; 4], |wide| wide.list())
                    });
                    out[..list.len()].copy_from_slice(&list);
                } else if input.starts_with(b"chanspec\0") {
                    let channel = if self.phy_profile.is_some_and(|p| p.1 == 2) {
                        0x1808u32
                    } else if self.vht.is_some() {
                        if self.vht.as_ref().is_some_and(|v| {
                            v.fault == crate::cyw43439::phy_fixture::VhtFault::CurrentWidth
                        }) {
                            0xd000 | u32::from(self.channel)
                        } else {
                            u32::from(self.current_chanspec)
                        }
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
                    let mode = if self.mfp_fault == 1 && self.mfp_mode != 0 {
                        0
                    } else {
                        self.mfp_mode
                    };
                    out[..4].copy_from_slice(&mode.to_le_bytes());
                } else if input.starts_with(b"assoc_info\0") {
                    out[..4].copy_from_slice(
                        &(if self.mfp_fault == 4 {
                            1503
                        } else if self.phy_profile.is_some() || self.mfp_conversation.is_some() {
                            self.request_ies().len() as u32
                        } else {
                            28u32
                        })
                        .to_le_bytes(),
                    );
                    out[4..8].copy_from_slice(&(self.response_ies().len() as u32).to_le_bytes());
                } else if input.starts_with(b"assoc_req_ies\0") {
                    let ies = if self.phy_profile.is_some() || self.mfp_conversation.is_some() {
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
                    if let Some(vht) = &self.vht {
                        assert_eq!(ch & !255, 0xd000);
                        let channels: Vec<u8> = if vht.is160() {
                            (0..8).map(|i| vht.center - 14 + i * 4).collect()
                        } else {
                            vec![
                                vht.center - 6,
                                vht.center - 2,
                                vht.center + 2,
                                vht.center + 6,
                            ]
                        };
                        assert!(channels.contains(&((ch & 255) as u8)));
                        let flags = 7u32
                            | if ch & 255 == u32::from(vht.center + 6)
                                && vht.fault
                                    == crate::cyw43439::phy_fixture::VhtFault::ChannelRestricted
                            {
                                32
                            } else {
                                0
                            };
                        out[..4].copy_from_slice(&flags.to_le_bytes());
                        return out;
                    }
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
                    let cap = if self.vht.as_ref().is_some_and(|v| {
                        v.fault == crate::cyw43439::phy_fixture::VhtFault::CapReadback
                    }) && self.wide_started
                        && self.bandwidth[(band - 1) as usize] == 7
                    {
                        3
                    } else if self.bandwidth_stuck || self.phy_profile.is_some_and(|p| p.1 == 1) {
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
                self.wide_started |= self.bandwidth[(band - 1) as usize] > 1;
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
                        (
                            self.pmf_required,
                            self.mfp_conversation.as_ref().map(|p| p.ap.as_slice()),
                        ),
                        self.phy_profile,
                        self.wide.as_ref(),
                        self.vht.as_ref(),
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
                let chanspec = if let Some(vht) = &self.vht {
                    vht.channel(
                        self.channel,
                        match self.bandwidth[0] {
                            15 => 160,
                            7 => 80,
                            3 => 40,
                            _ => 20,
                        },
                    )
                } else if self.bandwidth[usize::from(self.channel <= 14)] == 3 {
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
                let expected_conversation = self
                    .mfp_conversation
                    .as_ref()
                    .map(|p| p.expected_request(self.secured));
                let expected = expected_conversation.as_deref().unwrap_or(expected);
                assert_eq!(self.wpa_ie.as_deref(), Some(expected));
                assert!(self
                    .mfp_conversation
                    .as_ref()
                    .is_none_or(|p| p.mode == self.mfp_mode));
                assert!(
                    self.mfp_conversation.is_some()
                        || !self.pmf_required
                        || self.mfp_supported && self.mfp_mode == 2
                );
                assert!(self.roam_off && (!self.secured || self.psk));
                assert_eq!(self.wpa_auth, Some(if self.secured { 128 } else { 0 }));
                assert_eq!(self.cipher, Some(if self.secured { 4 } else { 0 }));
                assert_eq!(self.supplicant, Some(u32::from(self.secured)));
                self.event(16, 0, 1, &[]);
                let keys = self.mfp_conversation.as_ref().is_none_or(|p| p.keys);
                if self.secured && self.keys_first && !self.hold_keys && keys {
                    self.event(46, 6, 0, &[]);
                }
                self.event(0, 0, 0, &[]);
                if self.secured && !self.keys_first && !self.hold_keys && keys {
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
        if self.command_ifidx != 0 {
            return self
                .vif
                .ap
                .as_ref()
                .filter(|ap| ap.handled)
                .map_or(0, |ap| ap.status);
        }
        if let Some(monitor) = self.monitor.as_ref().filter(|monitor| monitor.handled) {
            return monitor.status;
        }
        if let Some(ap) = self.ap.as_ref().filter(|ap| ap.handled) {
            return ap.status;
        }
        if self.mfp_missing {
            -23
        } else if command == 52 && self.fail_disconnect || self.last_power_save_error {
            5
        } else {
            0
        }
    }
    pub(super) fn hold_mfp_reply(&self, command: u32, input: &[u8]) -> bool {
        if self
            .monitor
            .as_ref()
            .is_some_and(|monitor| monitor.hold(command, input))
        {
            return true;
        }
        if let Some(ap) = &self.ap {
            if ap.hold(command, input) {
                return true;
            }
        }
        if let Some(p) = &self.mfp_conversation {
            use crate::cyw43439::mfp_fixture::Hold;
            if command == 262
                && match p.hold {
                    Hold::None => false,
                    Hold::Mode => input.starts_with(b"mfp\0"),
                    Hold::Request => input.starts_with(b"assoc_req_ies\0"),
                    Hold::Response => input.starts_with(b"assoc_resp_ies\0"),
                }
            {
                return true;
            }
        }
        if let Some(vht) = &self.vht {
            use crate::cyw43439::phy_fixture::VhtFault;
            if command == 263
                && input.starts_with(b"bw_cap\0")
                && input[11..15] == [7, 0, 0, 0]
                && vht.fault == VhtFault::HoldCap
                || command == 262
                    && input.starts_with(b"assoc_resp_ies\0")
                    && vht.fault == VhtFault::HoldResponse
            {
                return true;
            }
        }
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
    /// Event addressed to firmware interface (ifidx, bsscfgidx).
    pub(super) fn event_on(
        &mut self,
        kind: u32,
        (ifidx, bsscfg): (u8, u8),
        source: [u8; 6],
        data: &[u8],
    ) {
        self.event(kind, 0, 0, data);
        let bytes = self.events.back_mut().unwrap();
        bytes[48..54].copy_from_slice(&source);
        bytes[70] = ifidx;
        bytes[71] = bsscfg;
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
        if let Some(monitor) = self.monitor.as_mut() {
            self.raw_downlink.extend(monitor.raw.drain(..));
        }
        if let Some(ap) = self.ap.as_mut() {
            self.events.extend(ap.events.drain(..));
            self.downlink.extend(ap.downlink.drain(..));
        }
        // The secondary AP's SME events come from its own interface.
        if let Some(ap) = self.vif.ap.as_mut() {
            for mut event in ap.events.drain(..) {
                event[70] = 1;
                event[71] = 1;
                self.events.push_back(event);
            }
        }
        while !self.events.is_empty() && !self.event_posts.is_empty() {
            let event = self.events.pop_front().unwrap();
            let (id, address) = self.event_posts.pop_front().unwrap();
            let prefix = word(state, SHARED + 36) as usize;
            let buffer = state.dma.get_mut(&address).unwrap();
            buffer[..prefix].fill(0xa5);
            buffer[prefix..prefix + event.len()].copy_from_slice(&event);
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
                // The descriptor's second byte is the interface index
                // (`msgbuf::TxPost` `CommonHdr.ifidx`): a secondary flow
                // posts with ifidx 1, not 0.
                assert_eq!(&tx[..4], &[0xf, flow.ifidx, 0, 0]);
                assert_eq!(tx[23], 1);
                let request = u32::from_le_bytes(tx[4..8].try_into().unwrap());
                let body = u64::from_le_bytes(tx[32..40].try_into().unwrap());
                let length = usize::from(u16::from_le_bytes(tx[42..44].try_into().unwrap()));
                let mut ethernet = tx[8..22].to_vec();
                ethernet.extend_from_slice(&state.dma[&body][..length]);
                self.uplink.push(ethernet.clone());
                self.tx_priorities.push((id, tx[22] >> 5));
                if flow.ifidx != 0 {
                    if let Some(ap) = self.vif.ap.as_mut() {
                        ap.transmit(&ethernet);
                    }
                } else if let Some(ap) = self.ap.as_mut() {
                    ap.transmit(&ethernet);
                } else if let Some(reply) = self.server.receive(&ethernet) {
                    self.downlink.push_back(reply);
                }
                self.tx_history.push((request, body));
                self.completions.push_back((request, id));
                flow.read = (flow.read + 1) % flow.depth;
            }
            put(state, H2DR + u32::from(id) * 4, &flow.read.to_le_bytes());
        }
        // An actual radio peer may answer M1/M3 before the native TX-status
        // waiter returns. Write its actual RX descriptor in this SAME drain.
        if let Some(ap) = self.ap.as_mut() {
            self.downlink.extend(ap.downlink.drain(..));
        }
        if !self.hold_tx {
            while let Some((id, flow)) = self.completions.pop_front() {
                let ring = pointer(state, RINGS + 3 * 16 + 8);
                // Shared 7 TX status items are 24 bytes (msgbuf.h).
                let size = if word(state, SHARED) & 0xff >= 7 {
                    24
                } else {
                    16
                };
                assert_eq!((word(state, RINGS + 3 * 16 + 4) >> 16) as usize, size);
                assert_ne!(ring, 0);
                let entry = completion_entry(state, 3, usize::from(self.tx_write));
                entry[0] = 0x10;
                entry[4..8].copy_from_slice(&id.to_le_bytes());
                entry[10..12].copy_from_slice(&flow.to_le_bytes());
                self.tx_write = (self.tx_write + 1) % (word(state, RINGS + 3 * 16 + 4) as u16);
                put(state, D2HW + 4, &self.tx_write.to_le_bytes());
                self.statuses += 1;
            }
        }
        while (!self.downlink.is_empty() || !self.raw_downlink.is_empty())
            && !self.rx_posts.is_empty()
        {
            let (bytes, flags) = self
                .raw_downlink
                .pop_front()
                .unwrap_or_else(|| (self.downlink.pop_front().unwrap(), 1));
            let (id, address) = self.rx_posts.pop_front().unwrap();
            let prefix = word(state, SHARED + 36) as usize;
            self.prefix_rx_fallback = prefix != 0 && !self.prefix_rx_fallback;
            let explicit_offset = if self.prefix_rx_fallback { 0 } else { 256 };
            if prefix != 0 {
                state.prefixed_rx_offsets[usize::from(explicit_offset != 0)] += 1;
            }
            let offset = if explicit_offset == 0 { prefix } else { 256 };
            let buffer = state.dma.get_mut(&address).unwrap();
            buffer[..offset].fill(0xa5);
            buffer[offset..offset + bytes.len()].copy_from_slice(&bytes);
            let ring = pointer(state, RINGS + 4 * 16 + 8);
            // Shared 7 RX completion items are 40 bytes (msgbuf.h).
            let size = if word(state, SHARED) & 0xff >= 7 {
                40
            } else {
                32
            };
            assert_eq!((word(state, RINGS + 4 * 16 + 4) >> 16) as usize, size);
            assert_ne!(ring, 0);
            let entry = completion_entry(state, 4, usize::from(self.rx_write));
            entry[0] = 0x12;
            entry[4..8].copy_from_slice(&id.to_le_bytes());
            entry[14..16].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
            entry[16..18].copy_from_slice(&(explicit_offset as u16).to_le_bytes());
            entry[18..20].copy_from_slice(&flags.to_le_bytes());
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
    mfp: (bool, Option<&[u8]>),
    phy: Option<(u32, u8)>,
    wide: Option<&crate::cyw43439::phy_fixture::Wide>,
    vht: Option<&crate::cyw43439::phy_fixture::Vht80>,
) -> Vec<u8> {
    let mut ies = vec![0, 4, b't', b'e', b's', b't'];
    if secured {
        if let Some(ap) = mfp.1 {
            ies.extend_from_slice(ap);
        } else if mfp.0 {
            ies.extend_from_slice(&pmf_ie());
        } else {
            ies.extend_from_slice(&[
                48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
            ]);
        }
    }
    if let Some((chains, fault)) = phy {
        let extra = vht.map(|v| v.beacon(channel, chains)).unwrap_or_else(|| {
            wide.map_or_else(
                || crate::cyw43439::phy_fixture::response(channel, chains),
                |w| w.beacon(channel, chains),
            )
        });
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
    pub(crate) fn ap_program_down_after_setup(&self, admin: narf_net::AdminHandle) {
        self.0.lock().ap_program_down_at_control_read = Some(admin);
    }
    pub(crate) fn ap_program_loss_after_setup(&self, peer: [u8; 6]) {
        self.0.lock().ap_program_loss_at_control_read = Some(peer);
    }
    pub(crate) fn ap_program_fail_index(&self) {
        self.0.lock().ap_program_fail_index_once = true;
    }

    pub(crate) fn enable_monitor(&self, profile: monitor_model::Profile) {
        let mut state = self.0.lock();
        state.ap_authority = Some(Rc::new(core::sync::atomic::AtomicBool::new(true)));
        state
            .firmware
            .as_mut()
            .unwrap()
            .station
            .as_mut()
            .unwrap()
            .monitor = Some(profile);
    }
    pub(crate) fn monitor_change<T>(
        &self,
        change: impl FnOnce(&mut monitor_model::Profile) -> T,
    ) -> T {
        let mut state = self.0.lock();
        let result = change(
            state
                .firmware
                .as_mut()
                .unwrap()
                .station
                .as_mut()
                .unwrap()
                .monitor
                .as_mut()
                .unwrap(),
        );
        firmware_step(&mut state);
        result
    }
    pub(crate) fn monitor_control_prefix(&self, count: usize) {
        self.change(|firmware| {
            for _ in 0..count {
                firmware.event(23, 0, 0, &[]);
            }
            firmware.event(63, 0, 0, &[]);
        });
    }
    pub(crate) fn enable_ap(&self) {
        let mut state = self.0.lock();
        state.ap_authority = Some(Rc::new(core::sync::atomic::AtomicBool::new(true)));
        state
            .firmware
            .as_mut()
            .unwrap()
            .station
            .as_mut()
            .unwrap()
            .ap = Some(ap_model::Profile::default());
    }
    /// The secondary interface is created as a firmware-SME AP (IF ADD
    /// role 1) whose BSS reports the IF ADD address.
    /// The native AP source authority is present (as `enable_ap`) while
    /// the primary interface stays a plain station.
    pub(crate) fn enable_vif_ap(&self) {
        self.0.lock().ap_authority = Some(Rc::new(core::sync::atomic::AtomicBool::new(true)));
        self.change(|f| {
            let mut ap = ap_model::Profile::default();
            ap.own = VIF;
            f.vif.ap = Some(ap);
        });
    }
    /// Firmware `cap` tokens (e.g. `b"ap sta mchan"`).
    pub(crate) fn set_caps(&self, caps: &[u8]) {
        self.change(|f| f.caps = caps.to_vec());
    }
    /// Apply `change` to the secondary AP model.
    pub(crate) fn vif_ap_change<T>(&self, change: impl FnOnce(&mut ap_model::Profile) -> T) -> T {
        let mut state = self.0.lock();
        let station = state.firmware.as_mut().unwrap().station.as_mut().unwrap();
        let result = change(station.vif.ap.as_mut().unwrap());
        firmware_step(&mut state);
        result
    }
    /// Secondary STA dcmds/iovars (plain form) the firmware accepted.
    pub(crate) fn vif_sets(&self) -> Vec<(u32, Vec<u8>)> {
        self.0
            .lock()
            .firmware
            .as_ref()
            .unwrap()
            .station
            .as_ref()
            .unwrap()
            .vif
            .sets
            .clone()
    }
    pub(crate) fn ap_change<T>(&self, change: impl FnOnce(&mut ap_model::Profile) -> T) -> T {
        let mut state = self.0.lock();
        let result = change(
            state
                .firmware
                .as_mut()
                .unwrap()
                .station
                .as_mut()
                .unwrap()
                .ap
                .as_mut()
                .unwrap(),
        );
        firmware_step(&mut state);
        result
    }
    pub(crate) fn ap_revoke(&self) {
        if let Some(present) = self.0.lock().ap_authority.as_ref() {
            present.store(false, core::sync::atomic::Ordering::Release);
        }
    }
    pub(crate) fn prefix_observations(&self) -> ([usize; 3], [usize; 2]) {
        let state = self.0.lock();
        (state.prefixed_completions, state.prefixed_rx_offsets)
    }
    fn change(&self, operation: impl FnOnce(&mut Firmware)) {
        let mut state = self.0.lock();
        operation(state.firmware.as_mut().unwrap().station.as_mut().unwrap());
        firmware_step(&mut state);
    }
    /// The function's PCI PM capability lists PME from D3hot (Linux
    /// `wowl_supported`) and the firmware answers `wowl_cap` with `cap`.
    pub(crate) fn wowl_profile(&self, cap: u32) {
        self.0.lock().pme = true;
        self.change(|f| f.wowl_cap = cap);
    }
    /// The wake indication the firmware latched while the host slept.
    pub(crate) fn wowl_wake(&self, wakeind: u32) {
        self.change(|f| f.wakeind = wakeind);
    }
    /// Current firmware PM mode.
    pub(crate) fn pm(&self) -> u32 {
        self.0
            .lock()
            .firmware
            .as_ref()
            .unwrap()
            .station
            .as_ref()
            .unwrap()
            .pm
    }
    /// Firmware answers D3_INFORM with D3_ACK (confirmed stop).
    pub(crate) fn d3_ack(&self, value: bool) {
        self.0.lock().d3_ack = value;
    }
    /// A device posted write lands after the BME clear.
    pub(crate) fn late_dma(&self, value: bool) {
        self.0.lock().late_dma = value;
    }
    /// (allocated, dropped) host DMA mappings.
    pub(crate) fn mappings(&self) -> (usize, usize) {
        let s = self.0.lock();
        (s.allocated, s.dropped)
    }
    /// Firmware posts `BRCMF_D2H_DEV_FWHALT` (Linux `brcmf_fw_crashed`).
    pub(crate) fn fwhalt(&self) {
        raise_mailbox(&mut self.0.lock(), runtime::mailbox::D2H_DEV_FWHALT);
    }
    /// The dongle lost power across suspend: `INTMASK` reads zero.
    pub(crate) fn power_lost(&self) {
        self.0.lock().registers.insert(PCIE + 0x24, 0);
    }
    /// Every TCM write fails (a refused firmware download).
    pub(crate) fn fail_tcm(&self, value: bool) {
        self.0.lock().fail_tcm = value;
    }
    /// A still-powered dongle answers D0_INFORM (INTMASK stays nonzero).
    pub(crate) fn d0_alive(&self) {
        let mut s = self.0.lock();
        s.d0_alive = true;
        s.registers.insert(PCIE + 0x24, 0x300);
    }
    /// The function fell off the bus.
    pub(crate) fn gone(&self, value: bool) {
        self.0.lock().gone = value;
    }
    /// (watchdog resets, config-shadow rewrites, link-control writes).
    pub(crate) fn resets(&self) -> (usize, usize, Vec<u32>) {
        let s = self.0.lock();
        (s.watchdogs, s.shadow_restores, s.lsc_writes.clone())
    }
    /// ARM CR4 wrapper `ioctrl` (bit 5 = `CPUHALT`).
    pub(crate) fn cr4_ioctrl(&self) -> u32 {
        *self.0.lock().registers.get(&(WRAP + 0x408)).unwrap_or(&0)
    }
    pub(crate) fn dma_enabled(&self) -> bool {
        self.0.lock().dma_enable
    }
    pub(crate) fn wme_ac_sta(&self, rows: [u8; 16]) {
        self.change(|f| f.wme_ac_sta = rows);
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
    pub(crate) fn mfp_conversation(
        &self,
        conversation: crate::cyw43439::mfp_fixture::Conversation,
    ) {
        self.change(|f| f.mfp_conversation = Some(conversation));
    }
    pub(crate) fn key_receipt(&self, foreign: bool) {
        self.change(|f| {
            f.event(46, 6, 0, &[]);
            if foreign {
                f.events.back_mut().unwrap()[48..54].copy_from_slice(&[2, 9, 8, 7, 6, 5]);
            }
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
    pub(crate) fn vht_profile(&self, vht: crate::cyw43439::phy_fixture::Vht80) {
        self.change(|f| {
            f.bandwidth = [vht.caps[1], vht.caps[0]];
            f.vht = Some(vht);
        });
    }
    pub(crate) fn release_vht(&self) {
        self.change(|f| {
            if let Some(vht) = &mut f.vht {
                vht.fault = crate::cyw43439::phy_fixture::VhtFault::None;
            }
        });
    }
    pub(crate) fn channel_adopted(&self) {
        self.change(|f| f.event(63, 0, 0, &[]));
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
    /// Secondary-interface event with an event body (e.g. a P2P action
    /// frame's `wl_event_rx_frame_data` + body on the discovery bsscfg).
    pub(crate) fn secondary_event_data(&self, kind: u32, source: [u8; 6], data: &[u8]) {
        self.change(|f| f.event_on(kind, (1, 1), source, data));
    }
    /// Secondary-interface event from the firmware (`if_idx`/`bsscfg_idx`).
    pub(crate) fn secondary_event(&self, kind: u32, flags: u16, source: [u8; 6]) {
        self.change(|f| {
            f.event_on(kind, (1, 1), source, &[]);
            f.events.back_mut().unwrap()[26..28].copy_from_slice(&flags.to_be_bytes());
        });
    }
    /// `msg.ifidx` of each IOCTL request, parallel to [`Self::commands`].
    pub(crate) fn command_ifidx(&self) -> Vec<u8> {
        self.0
            .lock()
            .firmware
            .as_ref()
            .unwrap()
            .command_ifidx
            .clone()
    }
    /// Live flow rings as (flow id, creating `msg.ifidx`).
    pub(crate) fn flow_ifidx(&self) -> Vec<(u16, u8)> {
        let state = self.0.lock();
        let station = state.firmware.as_ref().unwrap().station.as_ref().unwrap();
        station
            .flows
            .iter()
            .map(|(&id, flow)| (id, flow.ifidx))
            .collect()
    }
    /// Uplink frames the firmware consumed, in order.
    pub(crate) fn uplink_frames(&self) -> Vec<Vec<u8>> {
        let state = self.0.lock();
        state
            .firmware
            .as_ref()
            .unwrap()
            .station
            .as_ref()
            .unwrap()
            .uplink
            .clone()
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
    /// Flow-create TIDs and per-packet (flow id, descriptor priority).
    pub(crate) fn flow_priorities(&self) -> (Vec<u8>, Vec<(u16, u8)>) {
        let state = self.0.lock();
        let firmware = state.firmware.as_ref().unwrap().station.as_ref().unwrap();
        (firmware.tids.clone(), firmware.tx_priorities.clone())
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
    create_inner(version, secured, None, 0, None)
}
/// The same CR4 model discovered as another covered `chip_profile` chip
/// (ChipCommon identity word, chip id, PCI device id), booted through an
/// explicit board profile for that chip. Synthetic identities only.
pub(crate) fn create_chip(
    version: u32,
    secured: bool,
    chip: (u32, u16, u16),
) -> Result<(TestAdapter, Handle), runtime::Error> {
    create_inner(version, secured, None, 0, Some(chip))
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
    create_inner(version, secured, Some((selection, assets)), 0, None)
}
pub(crate) fn create_prefixed(
    secured: bool,
    prefix: u32,
) -> Result<(TestAdapter, Handle), runtime::Error> {
    create_inner(7, secured, None, prefix, None)
}
fn create_inner(
    version: u32,
    secured: bool,
    selected: Option<(
        &crate::brcmfmac::provision::Selection,
        &crate::brcmfmac::provision::Assets,
    )>,
    prefix: u32,
    chip: Option<(u32, u16, u16)>,
) -> Result<(TestAdapter, Handle), runtime::Error> {
    assert!(matches!(version, 5..=7));
    let (bus, state) = model();
    {
        let mut s = state.lock();
        if let Some((identity, id, _)) = chip {
            s.registers.insert(chip::ENUM_BASE, identity);
            use crate::brcmfmac::chip_profile;
            if chip_profile::covered(id) == Some(Some(chip_profile::Cpu::Ca7)) {
                let rambase = chip_profile::tcm_rambase(id, (identity >> 16 & 15) as u8)
                    .expect("CA7 Linux RAM base");
                ca7_layout(&mut s, rambase);
            }
        }
        put(&mut s, SHARED, &version.to_le_bytes());
        put(&mut s, SHARED + 36, &prefix.to_le_bytes());
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
        boot::Cr4::claim_selected(bus, pci(), selection)
            .and_then(|cr4| cr4.boot(&assets.firmware, &nvram))
            .map_err(|refused| refused.error)?
    } else if let Some((identity, id, device)) = chip {
        let pci = boot::PciIdentity { device, ..pci() };
        let profile = boot::BoardProfile {
            chip: id,
            revision_mask: 1 << ((identity >> 16) & 15),
            pci,
            ..profile()
        };
        let nvram = boot::pack_nvram(b"boardrev=1\n")?;
        boot::Cr4::claim(bus, pci, profile)
            .and_then(|cr4| cr4.boot(&[0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6], &nvram))
            .map_err(|refused| refused.error)?
    } else {
        boot_fixture(bus).map_err(|refused| refused.error)?
    };
    let runtime = runtime::Runtime::attach(boot)?;
    Adapter::new(runtime)
        .map(|adapter| {
            (
                adapter.with_reboot(alloc::boxed::Box::new(Reboot)),
                Handle(state),
            )
        })
        .map_err(|_| runtime::Error::Protocol)
}
pub(crate) fn boot_fixture(bus: Model) -> Result<boot::Booted<Model>, boot::Refused<Model>> {
    let nvram = boot::pack_nvram(b"boardrev=1\n").unwrap();
    boot::Cr4::claim(bus, pci(), profile())?.boot(&[0x44, 0x33, 0x22, 0x11, 9, 8, 7, 6], &nvram)
}
/// Retained fixture firmware authority: a transport reset downloads the
/// same synthetic image through the actual CR4 boot owner again.
struct Reboot;
impl crate::brcmfmac::station_transport::Reboot<Model> for Reboot {
    fn boot(
        &mut self,
        bus: Model,
    ) -> Result<runtime::Runtime<Model>, (runtime::Error, Option<Model>)> {
        let booted =
            boot_fixture(bus).map_err(|refused| (refused.error.into(), Some(refused.bus)))?;
        runtime::Runtime::attach(booted).map_err(|error| (error, None))
    }
}
