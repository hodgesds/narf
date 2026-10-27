use super::*;
use crate::cyw43439::{sdpcm::*, Function, Transport, TransportError};
use alloc::collections::VecDeque;
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const OWN: [u8; 6] = [2, 6, 7, 8, 9, 10];
const AP: [u8; 6] = [2, 1, 2, 3, 4, 5];
pub(in crate::cyw43439) struct Bus {
    rx: VecDeque<Vec<u8>>,
    tx: Vec<Vec<u8>>,
    sequence: u8,
    join_events: bool,
    assoc_event: bool,
    join_status: u32,
    secured: bool,
    wpa_ie: Option<Vec<u8>>,
    roam_off: bool,
    disconnect_error: bool,
    preauthorization_packets: usize,
    preauthorization_loss: bool,
    power_save_error: u32,
    hold_power_save: u32,
    power_save_held: bool,
    valid_channels: Vec<u32>,
    policy_clear: Option<(u32, alloc::sync::Arc<narf_wireless::reg::db::Database>)>,
    mfp_supported: bool,
    pmf_required: bool,
    mfp_mode: u32,
    mfp_fault: u8,
    mfp_held: bool,
    phy_profile: Option<(u32, u8)>,
    wide: Option<super::super::phy_fixture::Wide>,
    current_chanspec: u16,
    wide_started: bool,
    bandwidth: u32,
}
impl Bus {
    pub(in crate::cyw43439) fn new() -> Self {
        Self {
            rx: VecDeque::from([packet(0, 0, 8, &[])]),
            tx: Vec::new(),
            sequence: 1,
            join_events: true,
            assoc_event: true,
            join_status: 0,
            secured: false,
            wpa_ie: None,
            roam_off: false,
            disconnect_error: false,
            preauthorization_packets: 0,
            preauthorization_loss: false,
            power_save_error: 0,
            hold_power_save: 0,
            power_save_held: false,
            valid_channels: vec![1, 6],
            policy_clear: None,
            mfp_supported: false,
            pmf_required: false,
            mfp_mode: 0,
            mfp_fault: 0,
            mfp_held: false,
            phy_profile: None,
            wide: None,
            current_chanspec: 0x1006,
            wide_started: false,
            bandwidth: 1,
        }
    }
    pub(in crate::cyw43439) fn set_secured(&mut self, secured: bool) {
        self.secured = secured;
    }
    pub(in crate::cyw43439) fn mfp_profile(&mut self, supported: bool, required: bool, fault: u8) {
        self.mfp_supported = supported;
        self.pmf_required = required;
        self.mfp_fault = fault;
        if fault != 5 {
            self.mfp_held = false;
        }
    }
    pub(in crate::cyw43439) fn phy_profile(&mut self, chains: u32, fault: u8) {
        self.phy_profile = Some((chains, fault));
        self.mfp_held = false;
    }
    pub(in crate::cyw43439) fn wide_profile(&mut self, wide: super::super::phy_fixture::Wide) {
        self.bandwidth = wide.caps[0];
        self.valid_channels = vec![1, 2, 6, 10, 11];
        self.wide = Some(wide);
    }
    pub(in crate::cyw43439) fn release_wide(&mut self) {
        if let Some(wide) = &mut self.wide {
            wide.fault = super::super::phy_fixture::WideFault::None;
        }
        self.mfp_held = false;
    }
    fn request_ies(&self) -> Vec<u8> {
        let mut ies = self.wpa_ie.clone().unwrap_or_default();
        if let Some((chains, fault)) = self.phy_profile {
            if fault != 3 {
                ies.extend_from_slice(&self.wide.as_ref().map_or_else(
                    || super::super::phy_fixture::request(chains),
                    |wide| wide.request(chains, self.bandwidth == 3),
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
                    || super::super::phy_fixture::response(6, chains),
                    |wide| wide.response(6, chains),
                )
            }
        })
    }
    pub(in crate::cyw43439) fn mfp_commands(&self) -> Vec<(u32, Vec<u8>)> {
        self.tx
            .iter()
            .filter_map(|bytes| {
                if bytes[5] & 15 != 0 {
                    return None;
                }
                let size = usize::from(HwHeader::decode(bytes).unwrap().length);
                let command = BcdcHeader::decode(&bytes[12..]).unwrap().cmd;
                let body = &bytes[28..size];
                (matches!(command, 23 | 26 | 134)
                    || body.starts_with(b"mfp\0")
                    || body.starts_with(b"assoc_")
                    || body.starts_with(b"bw_cap\0")
                    || body.starts_with(b"vhtmode\0")
                    || body.starts_with(b"txstreams\0")
                    || body.starts_with(b"chanspec")
                    || body.starts_with(b"wpaie\0"))
                .then(|| (command, body.to_vec()))
            })
            .collect()
    }
    pub(in crate::cyw43439) fn control_count(&self) -> usize {
        self.tx
            .iter()
            .filter(|packet| packet.get(5).is_some_and(|channel| channel & 15 == 0))
            .count()
    }
    pub(in crate::cyw43439) fn queue(&mut self, channel: u8, maximum: u8, payload: &[u8]) {
        self.rx
            .push_back(packet(self.sequence, channel, maximum, payload));
        self.sequence = self.sequence.wrapping_add(1);
    }
    pub(in crate::cyw43439) fn event(
        &mut self,
        kind: u32,
        status: u32,
        flags: u16,
        data: &[u8],
        maximum: u8,
    ) {
        let mut payload = vec![0; 4 + events::EVENT_ENVELOPE_LEN + data.len()];
        payload[..4].copy_from_slice(&[0x20, 0, 0, 0]);
        let event = &mut payload[4..];
        event[12..16].copy_from_slice(&[0x88, 0x6c, 0x80, 1]);
        event[19..24].copy_from_slice(&[0, 0x10, 0x18, 0, 1]);
        event[24..26].copy_from_slice(&2u16.to_be_bytes());
        event[26..28].copy_from_slice(&flags.to_be_bytes());
        event[28..32].copy_from_slice(&kind.to_be_bytes());
        event[32..36].copy_from_slice(&status.to_be_bytes());
        event[44..48].copy_from_slice(&(data.len() as u32).to_be_bytes());
        event[48..54].copy_from_slice(&AP);
        event[events::EVENT_ENVELOPE_LEN..].copy_from_slice(data);
        self.queue(1, maximum, &payload);
    }

    pub(in crate::cyw43439) fn credit_window(&self, credits: u8) -> u8 {
        (self.tx.len() as u8).wrapping_add(credits)
    }

    pub(in crate::cyw43439) fn sent_data(&self) -> usize {
        self.tx.iter().filter(|packet| packet[5] & 15 == 2).count()
    }

    pub(in crate::cyw43439) fn power_commands(&self) -> Vec<(u32, Vec<u8>)> {
        self.tx
            .iter()
            .filter_map(|bytes| {
                if bytes[5] & 15 != 0 {
                    return None;
                }
                let size = usize::from(HwHeader::decode(bytes).unwrap().length);
                let command = BcdcHeader::decode(&bytes[12..]).unwrap().cmd;
                let body = &bytes[28..size];
                (command == 86 || command == 263 && body.starts_with(b"pm2_sleep_ret\0"))
                    .then(|| (command, body.to_vec()))
            })
            .collect()
    }

    pub(in crate::cyw43439) fn clear_policy_on(
        &mut self,
        command: u32,
        database: alloc::sync::Arc<narf_wireless::reg::db::Database>,
    ) {
        self.policy_clear = Some((command, database));
    }
    pub(in crate::cyw43439) fn command_count(&self, command: u32) -> usize {
        self.tx
            .iter()
            .filter(|bytes| {
                bytes[5] & 15 == 0 && BcdcHeader::decode(&bytes[12..]).unwrap().cmd == command
            })
            .count()
    }
    pub(in crate::cyw43439) fn qtxpowers(&self) -> Vec<Vec<u8>> {
        self.tx
            .iter()
            .filter(|bytes| bytes[5] & 15 == 0)
            .filter_map(|bytes| {
                let size = usize::from(HwHeader::decode(bytes).unwrap().length);
                let command = BcdcHeader::decode(&bytes[12..]).unwrap().cmd;
                let body = &bytes[28..size];
                (command == 263 && body.starts_with(b"qtxpower\0")).then(|| body[9..].to_vec())
            })
            .collect()
    }

    pub(in crate::cyw43439) fn reject_power_save(&mut self, command: u32) {
        self.power_save_error = command;
    }

    pub(in crate::cyw43439) fn hold_power_save(&mut self, command: u32) {
        self.hold_power_save = command;
        if command == 0 {
            self.power_save_held = false;
        }
    }
}
impl Transport for Bus {
    fn read32(&mut self, _: Function, _: u32) -> Result<u32, TransportError> {
        Err(TransportError::NotReady)
    }
    fn write32(&mut self, _: Function, _: u32, _: u32) -> Result<(), TransportError> {
        Err(TransportError::NotReady)
    }
    fn read_burst(&mut self, _: Function, _: u32, _: &mut [u8]) -> Result<(), TransportError> {
        Err(TransportError::NotReady)
    }
    fn write_burst(&mut self, _: Function, _: u32, _: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotReady)
    }
}
impl PacketTransport for Bus {
    fn receive_packet(&mut self, bytes: &mut [u8]) -> Result<usize, TransportError> {
        if self.mfp_held {
            return Ok(0);
        }
        if self.power_save_held {
            return Ok(0);
        }
        let Some(packet) = self.rx.pop_front() else {
            return Ok(0);
        };
        bytes[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    fn transmit_packet(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.tx.push(bytes.to_vec());
        if bytes[5] & 15 == 2 {
            return Ok(());
        }
        let size = usize::from(HwHeader::decode(bytes).unwrap().length);
        let request = BcdcHeader::decode(&bytes[12..]).unwrap();
        let body = &bytes[28..size];
        if self
            .policy_clear
            .as_ref()
            .is_some_and(|(command, _)| *command == request.cmd)
        {
            self.policy_clear.take().unwrap().1.clear();
        }
        if request.cmd == self.hold_power_save
            && (request.cmd == 86 || body.starts_with(b"pm2_sleep_ret\0"))
        {
            self.power_save_held = true;
        }
        let maximum = bytes[4].wrapping_add(8);
        let mut response = Vec::new();
        match request.cmd {
            1 => response.extend_from_slice(&2u32.to_le_bytes()),
            23 => response.extend_from_slice(
                if self.mfp_fault == 3 || self.phy_profile.is_some_and(|p| p.1 == 6) {
                    &[2, 9, 8, 7, 6, 5]
                } else {
                    &AP
                },
            ),
            217 => {
                response.extend_from_slice(&(self.valid_channels.len() as u32).to_le_bytes());
                for channel in &self.valid_channels {
                    response.extend_from_slice(&channel.to_le_bytes());
                }
            }
            262 => {
                if body.starts_with(b"cur_etheraddr\0") {
                    response.extend_from_slice(&OWN);
                } else if body.starts_with(b"nmode\0") {
                    response
                        .extend_from_slice(&u32::from(self.phy_profile.is_some()).to_le_bytes());
                } else if body.starts_with(b"rxchain\0") {
                    response.extend_from_slice(&self.phy_profile.map_or(0, |p| p.0).to_le_bytes());
                } else if body.starts_with(b"per_chan_info\0") {
                    let ch = u32::from_le_bytes(body[14..18].try_into().unwrap());
                    assert_eq!(ch & !255, 0x1000);
                    let wide = self.wide.as_ref().expect("wide channel query profile");
                    assert!(matches!(ch & 255, 6) || ch & 255 == u32::from(wide.secondary));
                    let flags = 3u32
                        | if ch & 255 == u32::from(wide.secondary)
                            && wide.fault == super::super::phy_fixture::WideFault::ChannelRestricted
                        {
                            32
                        } else {
                            0
                        };
                    response.extend_from_slice(&flags.to_le_bytes());
                } else if body.starts_with(b"bw_cap\0") {
                    response.extend_from_slice(
                        &(if self.phy_profile.is_some_and(|p| p.1 == 1) {
                            3
                        } else if self.wide_started
                            && self.bandwidth == 3
                            && self.wide.as_ref().is_some_and(|w| {
                                w.fault == super::super::phy_fixture::WideFault::CapReadback
                            })
                        {
                            1
                        } else {
                            self.bandwidth
                        })
                        .to_le_bytes(),
                    );
                } else if body.starts_with(b"chanspecs\0") {
                    response.extend_from_slice(
                        &self
                            .wide
                            .as_ref()
                            .map_or_else(|| vec![0; 4], |wide| wide.list()),
                    );
                } else if body.starts_with(b"chanspec\0") {
                    response.extend_from_slice(
                        &(if self.phy_profile.is_some_and(|p| p.1 == 2) {
                            0x1808u32
                        } else if self.wide.as_ref().is_some_and(|w| {
                            w.fault == super::super::phy_fixture::WideFault::CurrentWidth
                        }) {
                            0x1006
                        } else {
                            u32::from(self.current_chanspec)
                        })
                        .to_le_bytes(),
                    );
                } else if body.starts_with(b"mfp\0") {
                    response.extend_from_slice(
                        &(if self.mfp_fault == 1 && self.mfp_mode == 2 {
                            0
                        } else {
                            self.mfp_mode
                        })
                        .to_le_bytes(),
                    );
                } else if body.starts_with(b"assoc_info\0") {
                    response.extend_from_slice(
                        &(if self.mfp_fault == 4 {
                            1503
                        } else if self.phy_profile.is_some() {
                            self.request_ies().len() as u32
                        } else {
                            28u32
                        })
                        .to_le_bytes(),
                    );
                    response.extend_from_slice(&(self.response_ies().len() as u32).to_le_bytes());
                } else if body.starts_with(b"assoc_req_ies\0") {
                    response.extend_from_slice(&if self.phy_profile.is_some() {
                        self.request_ies()
                    } else {
                        pmf_ie()
                    });
                    if self.mfp_fault == 2 {
                        response[20] = 0;
                    }
                    if self.mfp_fault == 5 {
                        self.mfp_held = true;
                    }
                } else if body.starts_with(b"assoc_resp_ies\0") {
                    response.extend_from_slice(&self.response_ies());
                    if self.phy_profile.is_some_and(|p| p.1 == 5)
                        || self.wide.as_ref().is_some_and(|w| {
                            w.fault == super::super::phy_fixture::WideFault::HoldResponse
                        })
                    {
                        self.mfp_held = true;
                    }
                } else {
                    response.extend_from_slice(&0u32.to_le_bytes());
                }
            }
            263 if body.starts_with(b"escan\0") => {
                let id = u16::from_le_bytes(body[12..14].try_into().unwrap());
                // A late, correlated terminal from the previous scan must
                // not finish this one before its actual partial results.
                let mut old = [0; 12];
                old[..4].copy_from_slice(&12u32.to_le_bytes());
                old[8..10].copy_from_slice(&id.wrapping_sub(1).to_le_bytes());
                self.event(69, 0, 0, &old, maximum);
                self.event(
                    69,
                    8,
                    0,
                    &scan_result_profile(
                        id,
                        self.secured,
                        self.pmf_required,
                        self.phy_profile,
                        self.wide.as_ref(),
                    ),
                    maximum,
                );
                self.event(69, 0, 0, &[], maximum);
            }
            263 if body.starts_with(b"wpaie\0") => self.wpa_ie = Some(body[6..].to_vec()),
            263 if body.starts_with(b"bw_cap\0") => {
                self.bandwidth = u32::from_le_bytes(body[11..15].try_into().unwrap());
                self.wide_started |= self.bandwidth == 3;
                if self.bandwidth == 3
                    && self
                        .wide
                        .as_ref()
                        .is_some_and(|w| w.fault == super::super::phy_fixture::WideFault::HoldCap)
                {
                    self.mfp_held = true;
                }
            }
            263 if body.starts_with(b"mfp\0") => {
                self.mfp_mode = u32::from_le_bytes(body[4..8].try_into().unwrap())
            }
            263 if body.starts_with(b"roam_off\0") => self.roam_off = body[9..] == [1, 0, 0, 0],
            268 => self.secured = true,
            26 if self.join_events => {
                let expected = if self.bandwidth == 3 {
                    self.wide
                        .as_ref()
                        .ok_or(TransportError::BadFraming)?
                        .operating
                } else {
                    0x1006
                };
                if body.get(48..50) != Some(expected.to_le_bytes().as_slice()) {
                    return Err(TransportError::BadFraming);
                }
                self.current_chanspec = expected;
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
                if self.wpa_ie.as_deref() != Some(expected) || !self.roam_off {
                    return Err(TransportError::NotReady);
                }
                if self.pmf_required && (!self.mfp_supported || self.mfp_mode != 2) {
                    return Err(TransportError::NotReady);
                }
                self.event(16, 0, 1, &[], maximum);
                if self.secured {
                    self.event(46, 6, 0, &[], maximum);
                }
                if self.assoc_event {
                    self.event(0, self.join_status, 0, &[], maximum);
                    if self.join_status != 0 {
                        // A stale success cannot authorize a new attempt
                        // to the same peer after this terminal error.
                        self.event(0, 0, 0, &[], maximum);
                    }
                }
            }
            52 if self.disconnect_error => {
                // Firmware rejected the disconnect and old link events can
                // still arrive. None may authorize a subsequent attempt.
                self.event(16, 0, 1, &[], maximum);
                self.event(0, 0, 0, &[], maximum);
            }
            52 => self.event(16, 0, 0, &[], maximum),
            _ => {}
        }
        let mut header = request;
        header.len = response.len() as u32;
        if request.cmd == 52 && self.disconnect_error
            || request.cmd == self.power_save_error
                && (request.cmd == 86 || body.starts_with(b"pm2_sleep_ret\0"))
        {
            header.flags |= bcdc_flag::ERROR;
            header.status = 1;
        }
        if request.cmd == 262 && body.starts_with(b"mfp\0") && !self.mfp_supported {
            header.flags |= bcdc_flag::ERROR;
            header.status = (-23i32) as u32;
        }
        let mut control = header.encode().to_vec();
        control.extend_from_slice(&response);
        self.queue(0, maximum, &control);
        if request.cmd == 26 {
            // Actual SDPCM FIFO records follow the correlated control reply.
            // Its waiter can return at its16-packet budget with data/events
            // still unread; neither the host queue nor command ACK is idle.
            let mut data = [0x71; 4 + 14];
            data[..4].copy_from_slice(&[0x20, 0, 0, 0]);
            data[4..10].copy_from_slice(&OWN);
            data[10..16].copy_from_slice(&AP);
            data[16..18].copy_from_slice(&[8, 0]);
            for _ in 0..self.preauthorization_packets {
                self.queue(CHANNEL_DATA, maximum, &data);
            }
            if self.preauthorization_loss {
                self.event(16, 0, 0, &[], maximum);
            }
        }
        Ok(())
    }
}
fn packet(seq: u8, channel: u8, maximum: u8, data: &[u8]) -> Vec<u8> {
    let mut out = HwHeader {
        length: (12 + data.len()) as u16,
    }
    .encode()
    .to_vec();
    out.extend_from_slice(
        &SwHeader {
            seq,
            channel,
            flags: 0,
            next_len_16: 0,
            data_offset: 12,
            fc_mask: 0,
            max_seq: maximum,
        }
        .encode(),
    );
    out.extend_from_slice(data);
    out
}
pub(in crate::cyw43439) fn domain() -> narf_wireless::reg::RegulatoryDomain {
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
fn scan_request() -> ScanRequest {
    ScanRequest {
        ssids: vec![b"test".to_vec()],
        frequencies_mhz: vec![2412, 2437],
        channels: vec![1, 6],
        active: false,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn join_request(secured: bool) -> AssociateRequest {
    AssociateRequest {
        bssid: AP,
        ssid: b"test".to_vec(),
        frequency_mhz: 2437,
        channel: 6,
        security: if secured {
            SecurityConfig::Wpa2 { psk: [0x11; 32] }
        } else {
            SecurityConfig::Open
        },
        ie: Vec::new(),
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(out) => Some(out),
        Poll::Pending => None,
    }
}
fn scan_result(id: u16, secured: bool) -> Vec<u8> {
    scan_result_profile(id, secured, false, None, None)
}
fn pmf_ie() -> Vec<u8> {
    vec![
        48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 192, 0, 0, 0, 0, 15,
        172, 6,
    ]
}
fn scan_result_profile(
    id: u16,
    secured: bool,
    mfp: bool,
    phy: Option<(u32, u8)>,
    wide: Option<&super::super::phy_fixture::Wide>,
) -> Vec<u8> {
    let mut ies = vec![0, 4, b't', b'e', b's', b't'];
    if secured {
        if mfp {
            ies.extend_from_slice(&pmf_ie());
        } else {
            let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
            ies.extend_from_slice(&[48, rsn.len() as u8]);
            ies.extend_from_slice(&rsn);
        }
    }
    if let Some((chains, fault)) = phy {
        let extra = wide.map_or_else(
            || super::super::phy_fixture::response(6, chains),
            |w| w.beacon(6, chains),
        );
        ies.extend_from_slice(if fault == 9 { &extra[..52] } else { &extra });
    }
    let mut out = vec![0; 12 + 128 + ies.len()];
    let size = out.len();
    out[..4].copy_from_slice(&(size as u32).to_le_bytes());
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
    bss[72..74].copy_from_slice(&0x1006u16.to_le_bytes());
    bss[78..80].copy_from_slice(&(-42i16).to_le_bytes());
    bss[88] = 6;
    bss[116..118].copy_from_slice(&128u16.to_le_bytes());
    bss[120..124].copy_from_slice(&(ies.len() as u32).to_le_bytes());
    bss[128..].copy_from_slice(&ies);
    out
}

fn smoke_cyw_station_boot_scan_open_join_and_disconnect() -> TestResult {
    let Some(Ok(mut station)) = ready(Station::initialize(
        Runtime::new(Bus::new()),
        &[1; 1030],
        domain(),
    )) else {
        return TestResult::Fail("station initialization");
    };
    if station.mac != OWN || station.channels != [1, 6] || !station.supplicant {
        return TestResult::Fail("real firmware identity/channel negotiation");
    }
    let Some(Ok(found)) = ready(station.scan(scan_request())) else {
        return TestResult::Fail("live escan completion");
    };
    if found.len() != 1
        || found[0].bssid != AP
        || found[0].frequency_mhz != 2437
        || found[0].rssi != -42
    {
        return TestResult::Fail("BSS wire result");
    }
    if ready(station.associate(join_request(false))) != Some(Ok(()))
        || station.bssid != Some(AP)
        || ready(station.disconnect()) != Some(Ok(()))
        || station.bssid.is_some()
    {
        return TestResult::Fail("open join/disconnect lifecycle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_boot_scan_open_join_and_disconnect
);

fn smoke_cyw_station_wpa2_waits_for_firmware_keys() -> TestResult {
    let mut bus = Bus::new();
    bus.secured = true;
    let Some(Ok(mut station)) = ready(Station::initialize(Runtime::new(bus), &[1], domain()))
    else {
        return TestResult::Fail("station init");
    };
    let mut request = join_request(true);
    let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
    request.ie.extend_from_slice(&[48, rsn.len() as u8]);
    request.ie.extend_from_slice(&rsn);
    request.ie.extend_from_slice(&[244, 1, 0, 127, 1, 0]);
    if !matches!(ready(station.scan(scan_request())), Some(Ok(_)))
        || ready(station.associate(request)) != Some(Ok(()))
        || station.bssid != Some(AP)
    {
        return TestResult::Fail("WPA2 firmware-supplicant SET_SSID plus FWSUP_COMPLETED contract");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_wpa2_waits_for_firmware_keys
);

fn preauthorization_fixture(
    secured: bool,
    packets: usize,
    loss: bool,
) -> Result<Station<Runtime<Bus>>, &'static str> {
    let mut bus = Bus::new();
    bus.secured = secured;
    bus.preauthorization_packets = packets;
    bus.preauthorization_loss = loss;
    let mut station =
        narf_scheduler::block_on(Station::initialize(Runtime::new(bus), &[1], domain()))
            .map_err(|_| "preauthorization fixture init")?;
    narf_scheduler::block_on(station.scan(scan_request()))
        .map_err(|_| "preauthorization fixture scan")?;
    Ok(station)
}
fn smoke_cyw_station_idle_fence_drops_fifo_backlog_beyond_control_and_receive_budgets() -> TestResult
{
    for secure in [false, true] {
        let Ok(mut station) = preauthorization_fixture(secure, 64, false) else {
            return TestResult::Fail("SDPCM idle fixture");
        };
        if narf_scheduler::block_on(station.associate(join_request(secure))) != Ok(())
            || station.bssid != Some(AP)
            || station.runtime.poll() != Ok(0)
            || station.runtime.pop_data().is_some()
        {
            return TestResult::Fail("SDPCM port opened before genuine FIFO idle or leaked old RX");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_idle_fence_drops_fifo_backlog_beyond_control_and_receive_budgets
);

fn smoke_cyw_station_idle_fence_observes_peer_loss_after_more_than_one_rx_budget() -> TestResult {
    let Ok(mut station) = preauthorization_fixture(true, 64, true) else {
        return TestResult::Fail("SDPCM delayed peer-loss fixture");
    };
    if narf_scheduler::block_on(station.associate(join_request(true))).is_ok()
        || station.bssid.is_some()
        || !station.runtime.is_failed()
        || station.poll().is_ok()
    {
        return TestResult::Fail("join/key events hid terminal peer loss beyond the SDPCM budget");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_idle_fence_observes_peer_loss_after_more_than_one_rx_budget
);

fn smoke_cyw_station_cancel_during_idle_fence_never_publishes_port() -> TestResult {
    let Ok(mut station) = preauthorization_fixture(true, 128, false) else {
        return TestResult::Fail("SDPCM cancelled-idle fixture");
    };
    {
        let mut future = pin!(station.associate(join_request(true)));
        if !future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
        {
            return TestResult::Fail("unretired SDPCM backlog did not yield with port closed");
        }
    }
    if station.bssid.is_some() || station.poll().is_ok() || !station.runtime.is_failed() {
        return TestResult::Fail("cancelled idle fence reopened FullMAC controlled port");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_cancel_during_idle_fence_never_publishes_port
);

fn smoke_cyw_station_rejects_inconsistent_association_ies() -> TestResult {
    use narf_wireless::rsn::*;
    let encoded = |rsn: RsnIe| {
        let body = rsn.encode_body();
        let mut out = vec![48, body.len() as u8];
        out.extend_from_slice(&body);
        out
    };
    let valid = encoded(RsnIe::wpa2_psk_ccmp());
    let mut duplicate = valid.clone();
    duplicate.extend_from_slice(&valid);
    let mut wrong = RsnIe::wpa2_psk_ccmp();
    wrong.pairwise_ciphers = vec![Suite::standard(CIPHER_TKIP)];
    let mut required = RsnIe::wpa2_psk_ccmp();
    required.rsn_capabilities = RSN_CAP_MFP_REQUIRED;
    for (ies, secure, expected) in [
        (valid, false, Error::Unsupported),
        (duplicate, true, Error::Unsupported),
        (encoded(wrong), true, Error::Unsupported),
        (encoded(required), true, Error::Unsupported),
        (vec![48, 20, 1], true, Error::Malformed),
        (vec![127], true, Error::Malformed),
    ] {
        if validate_association_ies(&ies, secure, false) != Err(expected) {
            return TestResult::Fail(
                "association IE policy admitted malformed or unsupported security",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_rejects_inconsistent_association_ies
);

fn smoke_cyw_station_failed_join_cannot_reuse_late_authorization() -> TestResult {
    let mut bus = Bus::new();
    bus.join_status = 1;
    let Some(Ok(mut station)) = ready(Station::initialize(Runtime::new(bus), &[1], domain()))
    else {
        return TestResult::Fail("failed-join fixture initialization");
    };
    if !matches!(ready(station.scan(scan_request())), Some(Ok(_)))
        || ready(station.associate(join_request(false))) != Some(Err(Error::Firmware(1)))
        || !station.runtime.is_failed()
        || station.bssid.is_some()
        || ready(station.associate(join_request(false))) != Some(Err(Error::Failed))
        || station.poll() != Err(Error::Failed)
        || station.bssid.is_some()
    {
        return TestResult::Fail("late old SET_SSID success reopened a failed join lifecycle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_failed_join_cannot_reuse_late_authorization
);

fn smoke_cyw_station_cancel_between_ioctls_closes_runtime() -> TestResult {
    let mut bus = Bus::new();
    bus.assoc_event = false; // LINK alone never opens the controlled port.
    let Some(Ok(mut station)) = ready(Station::initialize(Runtime::new(bus), &[1], domain()))
    else {
        return TestResult::Fail("station init");
    };
    if !matches!(ready(station.scan(scan_request())), Some(Ok(_)))
        || ready(station.associate(join_request(false))).is_some()
        || station.poll() != Err(Error::Failed)
        || station.bssid.is_some()
        || !station.runtime.is_failed()
    {
        return TestResult::Fail("cancelled join reopened or reused runtime");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_cancel_between_ioctls_closes_runtime
);

fn smoke_cyw_scan_wire_bounds_and_offsets() -> TestResult {
    let command = scan_command(7, &[1, 6], &[b"test".to_vec()], false).unwrap();
    if command[..8] != [1, 0, 0, 0, 1, 0, 7, 0]
        || command[44..52] != [255, 255, 255, 255, 255, 255, 2, 1]
        || command[68..76] != [2, 0, 1, 0, 1, 16, 6, 16]
        || command[76..84] != [4, 0, 0, 0, b't', b'e', b's', b't']
    {
        return TestResult::Fail("Linux escan v1 field alignment");
    }
    let valid = scan_result(7, false);
    for end in 0..valid.len() {
        if parse_scan_result(&valid[..end]).is_ok() {
            return TestResult::Fail("truncated BSS accepted");
        }
    }
    for (offset, bytes) in [
        (12, u32::MAX.to_le_bytes()),
        (16, u32::MAX.to_le_bytes()),
        (132, u32::MAX.to_le_bytes()),
    ] {
        let mut bad = valid.clone();
        bad[offset..offset + 4].copy_from_slice(&bytes);
        if parse_scan_result(&bad).is_ok() {
            return TestResult::Fail("unsupported BSS version/length/IE extent accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_scan_wire_bounds_and_offsets
);

fn smoke_cyw_single_band_profile_rejects_firmware_five_ghz_aliases() -> TestResult {
    let mut bus = Bus::new();
    bus.valid_channels = vec![6, 36, 149];
    let mut policy = domain();
    policy.rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 5170,
        freq_end_mhz: 5835,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::empty(),
    });
    let Some(Ok(mut station)) = ready(Station::initialize(Runtime::new(bus), &[1], policy)) else {
        return TestResult::Fail("single-band profile initialization");
    };
    let mut request = scan_request();
    request.channels = vec![36];
    request.frequencies_mhz = vec![5180];
    if station.channels != [6]
        || !matches!(ready(station.scan(request)), Some(Err(Error::Malformed)))
    {
        return TestResult::Fail("CYW43439 acquired 5 GHz from an unexpected firmware channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_single_band_profile_rejects_firmware_five_ghz_aliases
);

fn smoke_cyw_no_ir_preserves_passive_scan_without_association_authority() -> TestResult {
    let mut policy = domain();
    policy.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR;
    let Some(Ok(mut station)) = ready(Station::initialize(Runtime::new(Bus::new()), &[1], policy))
    else {
        return TestResult::Fail("NO_IR passive profile initialization");
    };
    if station.channels != [1, 6]
        || !matches!(ready(station.scan(scan_request())), Some(Ok(_)))
        || ready(station.associate(join_request(false))) != Some(Err(Error::Unsupported))
        || station.bssid.is_some()
    {
        return TestResult::Fail("NO_IR either hid passive receive or granted station TX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_no_ir_preserves_passive_scan_without_association_authority
);

fn smoke_fullmac_transmit_policy_intersects_partial_restrictions() -> TestResult {
    use narf_wireless::reg::{RegFlags, RegRule};
    let mut policy = domain();
    policy.rules.push(RegRule {
        freq_start_mhz: 2410,
        freq_end_mhz: 2420,
        max_bandwidth_mhz: 20,
        max_power_dbm: 4,
        flags: RegFlags::empty(),
    });
    if channel_power(&policy, 1) != Some(4) {
        return TestResult::Fail("partial overlapping power ceiling was ignored");
    }
    for flags in [RegFlags::DFS, RegFlags::NO_IR] {
        policy.rules[1].flags = flags;
        for _ in 0..2 {
            if channel_power(&policy, 1).is_some() || channel_ceiling(&policy, 1, false) != Some(4)
            {
                return TestResult::Fail("overlap restriction lost or passive receive was closed");
            }
            policy.rules.reverse();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_fullmac_transmit_policy_intersects_partial_restrictions
);

fn smoke_cyw_station_rejected_disconnect_cannot_reuse_link() -> TestResult {
    let mut bus = Bus::new();
    bus.disconnect_error = true;
    let Some(Ok(mut station)) = ready(Station::initialize(Runtime::new(bus), &[1], domain()))
    else {
        return TestResult::Fail("disconnect-error fixture initialization");
    };
    if !matches!(ready(station.scan(scan_request())), Some(Ok(_)))
        || ready(station.associate(join_request(false))) != Some(Ok(()))
        || station.bssid != Some(AP)
        || ready(station.disconnect()) != Some(Err(Error::Firmware(1)))
        || station.bssid.is_some()
        || !station.runtime.is_failed()
        || ready(station.associate(join_request(false))) != Some(Err(Error::Failed))
        || station.poll() != Err(Error::Failed)
        || station.bssid.is_some()
    {
        return TestResult::Fail(
            "rejected disconnect reused unconfirmed firmware link/late authorization",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/station",
    smoke_cyw_station_rejected_disconnect_cannot_reuse_link
);
