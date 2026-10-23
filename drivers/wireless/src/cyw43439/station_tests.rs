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
        }
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
        let maximum = bytes[4].wrapping_add(8);
        let mut response = Vec::new();
        match request.cmd {
            1 => response.extend_from_slice(&2u32.to_le_bytes()),
            217 => response.extend_from_slice(&[2, 0, 0, 0, 1, 0, 0, 0, 6, 0, 0, 0]),
            262 => {
                if body.starts_with(b"cur_etheraddr\0") {
                    response.extend_from_slice(&OWN);
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
                self.event(69, 8, 0, &scan_result(id, self.secured), maximum);
                self.event(69, 0, 0, &[], maximum);
            }
            263 if body.starts_with(b"wpaie\0") => self.wpa_ie = Some(body[6..].to_vec()),
            263 if body.starts_with(b"roam_off\0") => self.roam_off = body[9..] == [1, 0, 0, 0],
            268 => self.secured = true,
            26 if self.join_events => {
                let expected: &[u8] = if self.secured {
                    &[
                        48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 0, 0,
                    ]
                } else {
                    &[]
                };
                if self.wpa_ie.as_deref() != Some(expected) || !self.roam_off {
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
            52 => self.event(16, 0, 0, &[], maximum),
            _ => {}
        }
        let mut header = request;
        header.len = response.len() as u32;
        let mut control = header.encode().to_vec();
        control.extend_from_slice(&response);
        self.queue(0, maximum, &control);
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
    let mut ies = vec![0, 4, b't', b'e', b's', b't'];
    if secured {
        let rsn = narf_wireless::rsn::RsnIe::wpa2_psk_ccmp().encode_body();
        ies.extend_from_slice(&[48, rsn.len() as u8]);
        ies.extend_from_slice(&rsn);
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
        if validate_association_ies(&ies, secure) != Err(expected) {
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
