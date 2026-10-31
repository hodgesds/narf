// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual retained station/USB receipts across active associated visits.
use super::*;
const AWAY: [u8; 6] = [2, 0, 0, 0, 0, 3];

struct Air {
    channel: u8,
    ready_ms: u64,
    response: Option<Vec<u8>>,
}
#[derive(Default)]
pub(super) struct Probes {
    packets: Vec<(u8, Vec<u8>)>,
    air: Option<Air>,
    pub(super) hold: bool,
    pub(super) short: bool,
    air_held: bool,
    responses: bool,
    pub(super) suppress_away_beacon: bool,
    consumed: usize,
    truncated: usize,
}
impl AssociatedLink {
    pub(super) fn advance_probe_air(&self) {
        let (channel, receiving, transmitting) = self.radio.physical();
        let mut probes = self.probes.lock();
        let Some(air) = &probes.air else {
            return;
        };
        if air.channel != channel || !transmitting {
            probes.air = None;
            probes.truncated += 1;
            return;
        }
        if probes.air_held || self.clock.now_ms() < air.ready_ms {
            return;
        }
        let air = probes.air.take().unwrap();
        if receiving {
            if let Some(response) = air.response {
                self.radio.bulk.0.lock().queue.push_back(response);
            }
        }
        probes.consumed += 1;
        self.radio.control.0.lock().regs[0x5f8..0x5fc].fill(0);
    }
    pub(super) fn begin_probe(&self, dci: u8, bytes: &[u8]) -> Result<u64, UsbError> {
        let (channel, _, transmitting) = self.radio.physical();
        let mut probes = self.probes.lock();
        let mut peer = self.radio.bulk.0.lock();
        if !transmitting
            || peer.tx.is_some()
            || probes.air.is_some()
            || dci != 4
            || bytes.len() < TX_DESC + 26
            || usize::from(u16::from_le_bytes([bytes[0], bytes[1]])) != bytes.len() - TX_DESC
            || bytes[2] != 32
            || bytes[3] & 1 != 1
            || bytes[..TX_DESC]
                .chunks_exact(2)
                .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]))
                != 0
            || u32::from_le_bytes(bytes[4..8].try_into().unwrap()) != 0x1200
            || u32::from_le_bytes(bytes[16..20].try_into().unwrap()) != 0x100
            || u32::from_le_bytes(bytes[20..24].try_into().unwrap()) != 0x001a0000
        {
            return Err(UsbError::Stall);
        }
        let frame = &bytes[TX_DESC..];
        if frame[0..4] != [0x40, 0, 0, 0]
            || frame[4..10] != [255; 6]
            || frame[10..16] != peer.network.station
            || frame[16..22] != [255; 6]
            || frame[22] & 15 != 0
            || frame[24] != 0
            || frame[25] > 32
            || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) >> 16
                != u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4)
        {
            return Err(UsbError::Stall);
        }
        let ssid = frame
            .get(26..26 + usize::from(frame[25]))
            .ok_or(UsbError::Stall)?;
        let response = if probes.responses && (ssid.is_empty() || ssid == SSID) {
            let mut response = peer.ap.beacon();
            response[0] = 0x50;
            response[4..10].copy_from_slice(&peer.network.station);
            if channel == 6 {
                response[10..16].copy_from_slice(&AWAY);
                response[16..22].copy_from_slice(&AWAY);
            }
            let ds = response
                .windows(3)
                .position(|bytes| bytes == [3, 1, 1])
                .ok_or(UsbError::Stall)?;
            response[ds + 2] = channel;
            if channel == 1 && peer.ht {
                response.extend_from_slice(&super::super::super::super::ht_tests::WMM);
                response.extend_from_slice(&super::super::super::super::ht_tests::elements(255));
            }
            Some(response)
        } else {
            None
        };
        probes.packets.push((channel, bytes.to_vec()));
        // A USB terminal is deliberately independent of actual device-air
        // consumption. Closing TX too soon discards this response above.
        probes.air = Some(Air {
            channel,
            ready_ms: self.clock.now_ms() + (192 + 8 * (frame.len() as u64 + 4)).div_ceil(1000),
            response,
        });
        self.radio.control.0.lock().regs[0x5f8..0x5fc].copy_from_slice(&1u32.to_le_bytes());
        peer.native_tx.push(bytes.to_vec());
        peer.next_receipt += 1;
        let id = peer.next_receipt;
        peer.tx = Some(Tx {
            id,
            bytes: bytes.len(),
            m4: false,
            data: false,
            control: true,
        });
        peer.sent += 1;
        Ok(id)
    }
    pub(super) fn is_probe_receipt(&self, receipt: &u64) -> bool {
        let peer = self.radio.bulk.0.lock();
        peer.tx.as_ref().is_some_and(|tx| tx.id == *receipt)
            && peer
                .native_tx
                .last()
                .is_some_and(|packet| packet.get(TX_DESC) == Some(&0x40))
    }
}
impl AssociatedFixture {
    fn active_request(&self, channels: &[u32], ssid: &[u8]) -> ScanRequest {
        let mut request = self.scan(channels);
        request.active = true;
        request.ssids = vec![ssid.to_vec()];
        request
    }
    fn prepare_active(&self) {
        let mut probes = self.link.probes.lock();
        probes.responses = true;
        // Away discovery must come from a response produced by actual
        // consumption of the native Probe, never the passive fixture beacon.
        probes.suppress_away_beacon = true;
    }
}
fn ies(frame: &[u8], tag: u8) -> Option<&[u8]> {
    let mut at = frame.get(24..)?;
    while !at.is_empty() {
        let length = 2 + usize::from(*at.get(1)?);
        let element = at.get(..length)?;
        if element[0] == tag {
            return Some(&element[2..]);
        }
        at = &at[length..];
    }
    None
}
fn conversation(protected: bool, ht: bool) -> Result<(), &'static str> {
    let h = AssociatedFixture::new(protected, ht)?;
    h.join()?;
    h.prepare_active();
    let network = h.link.radio.bulk.0.lock().network;
    let initial =
        narf_net::dhcp::dhcp_acquire(&h.name, 0).map_err(|_| "EU connected active initial DHCP")?;
    ensure!(
        network.matches_lease(&initial),
        "EU active DHCP before visit"
    );
    h.pump();
    let (old_rx, old_pn, uplinks) = {
        let peer = h.link.radio.bulk.0.lock();
        (peer.rx, peer.replay.last_seen_pn, peer.uplink.len())
    };
    let generation = h.link.radio.control.0.lock().cold_generation;
    let queued = udp_ipv4(
        AP,
        h.device.mac(),
        [10, 88, 0, 42],
        [10, 88, 0, 1],
        7,
        8,
        b"same host ring through actual active RF visits",
    );
    h.device
        .enqueue(&queued, Default::default())
        .map_err(|_| "EU active retained host TX")?;
    let buffered = udp_ipv4(
        h.device.mac(),
        AP,
        [10, 88, 0, 1],
        [10, 88, 0, 42],
        8,
        7,
        b"same native key after active scan",
    );
    let raw = {
        let mut peer = h.link.radio.bulk.0.lock();
        peer.downlink(&buffered)?;
        peer.queue
            .pop_back()
            .ok_or("EU active buffered native RX")?
    };
    h.link.power.lock().buffered.push_back(raw);
    let mut request = h.active_request(&[1, 6], if ht { SSID } else { b"" });
    let mut extra = vec![221, 4, 0x12, 0x34, 0x56, 0x78];
    if ht {
        extra.clear();
        for _ in 0..8 {
            extra.extend_from_slice(&[221, 254]);
            extra.extend_from_slice(&[0x55; 254]);
        }
    }
    request.extra_ies = extra.clone();
    let results = drive(h.device.scan(request))?
        .map_err(|_| "EU connected active cold home/away conversation")?;
    ensure!(
        results
            .iter()
            .any(|bss| bss.bssid == AWAY && bss.channel == 6),
        "EU active result was not generated by the actual away probe response"
    );
    {
        let peer = h.link.radio.bulk.0.lock();
        ensure!(
            peer.rx != old_rx
                && peer.replay.last_seen_pn == old_pn
                && peer.uplink.len() == uplinks
                && peer.ap.phase() == ApPhase::Authorized,
            "EU active visit replaced native key/host ring or consumed queued DATA"
        );
    }
    ensure!(
        h.link.radio.control.0.lock().cold_generation >= generation + 4,
        "EU same-channel active visit lacked both real cold receive boundaries"
    );
    {
        let probes = h.link.probes.lock();
        ensure!(
            probes.packets.len() == 2 && probes.consumed == 2 && probes.truncated == 0,
            "EU active probe host completion replaced independent PHY consumption"
        );
        let mut sequences = Vec::new();
        for (channel, bytes) in &probes.packets {
            let frame = &bytes[TX_DESC..];
            ensure!(
                ies(frame, 0) == Some(if ht { SSID } else { b"" })
                    && ies(frame, 3) == Some([*channel].as_slice())
                    && ies(frame, 45).is_some() == (ht && *channel == 1)
                    && frame.ends_with(&extra)
                    && bytes[16] & 0x80 == 0,
                "EU active directed/wildcard, DS/HT/extra IEs or host SN descriptor"
            );
            sequences.push(u16::from_le_bytes([frame[22], frame[23]]) >> 4);
        }
        ensure!(
            sequences[1] == (sequences[0] + if ht { 1 } else { 3 }) & 4095,
            "EU active Probe did not reserve the persistent non-QoS DATA/EAPOL sequence"
        );
    }
    ensure!(
        h.link.power.lock().consumed == 4
            && h.link.power.lock().truncated == 0
            && !h.link.power.lock().asleep
            && h.device.link_up()
            && h.device.connected_bssid() == Some(AP),
        "EU active PM1/PM0 or original home association continuity"
    );
    ensure!(
        h.device.progress().contains(&buffered),
        "EU active home restore lost buffered original-key downlink"
    );
    h.pump();
    ensure!(
        h.link
            .radio
            .bulk
            .0
            .lock()
            .uplink
            .iter()
            .any(|(bytes, _)| bytes == &queued),
        "EU active return lost original host-ring packet"
    );
    let after = narf_net::dhcp::dhcp_acquire(&h.name, 0)
        .map_err(|_| "EU connected active DHCP after restore")?;
    ensure!(
        network.matches_lease(&after)
            && h.link.radio.bulk.0.lock().error.is_none()
            && h.link.radio.control.0.lock().rf[0x18] & 0xff == 1,
        "EU active final native DHCP/CCMP/physical home"
    );
    Ok(())
}
fn smoke_rtl8188eu_connected_active_open_home_and_away_preserve_native_rings() -> TestResult {
    conversation(false, false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_rtl8188eu_connected_active_wpa2_ht_probe_profile_sequences_and_dhcp() -> TestResult {
    conversation(true, true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_open_home_and_away_preserve_native_rings
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_wpa2_ht_probe_profile_sequences_and_dhcp
);

fn refusal() -> Result<(), &'static str> {
    let h = AssociatedFixture::new(true, true)?;
    h.join()?;
    h.prepare_active();
    let ops = h.link.radio.control.0.lock().ops.len();
    let generation = h.link.radio.control.0.lock().cold_generation;
    for invalid in 0..7 {
        let mut request = h.active_request(&[6], SSID);
        match invalid {
            0 => request.ssids.push(b"second".to_vec()),
            1 => request.extra_ies = vec![221, 2, 1],
            2 => request.extra_ies = vec![3, 1, 6],
            3 => request.channels = vec![5],
            4 => {
                request.duration_tu = Some(2);
                request.duration_mandatory = true;
            }
            5 => {
                request.duration_tu = Some(200);
                request.duration_mandatory = true;
            }
            _ => request.ssids = vec![vec![0; 33]],
        }
        ensure!(
            drive(h.device.scan(request))?.is_err()
                && h.link.radio.control.0.lock().ops.len() == ops
                && h.link.radio.control.0.lock().cold_generation == generation
                && h.link.power.lock().packets.is_empty()
                && h.link.probes.lock().packets.is_empty()
                && h.device.link_up(),
            "EU invalid associated active request touched native hardware or closed home"
        );
    }
    h.domain.lock().rules.push(narf_wireless::reg::RegRule {
        freq_start_mhz: 2430,
        freq_end_mhz: 2431,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: narf_wireless::reg::RegFlags::NO_IR,
    });
    ensure!(
        drive(h.device.scan(h.active_request(&[6], SSID)))?.is_err()
            && h.link.radio.control.0.lock().ops.len() == ops
            && h.device.link_up(),
        "EU associated active occupied-band NO_IR was overridden"
    );
    Ok(())
}
fn smoke_rtl8188eu_connected_active_preflight_refuses_ssid_timing_policy_before_pm1() -> TestResult
{
    refusal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_preflight_refuses_ssid_timing_policy_before_pm1
);

fn retained_probe(source_lost: bool) -> Result<(), &'static str> {
    let h = AssociatedFixture::new(true, true)?;
    h.join()?;
    h.prepare_active();
    h.link.probes.lock().hold = true;
    let mut scan = Box::pin(h.device.scan(h.active_request(&[6], SSID)));
    let mut published = false;
    for _ in 0..4096 {
        ensure!(
            scan.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "EU associated active scan ended before actual held Probe TD"
        );
        if !h.link.probes.lock().packets.is_empty() {
            published = true;
            break;
        }
    }
    ensure!(
        published,
        "EU associated active did not publish native Probe"
    );
    let old_rx = h.link.radio.bulk.0.lock().rx;
    let old_tx = h.link.radio.bulk.0.lock().tx.as_ref().map(|tx| tx.id);
    let ops = h.link.radio.control.0.lock().ops.len();
    let stops = h.link.radio.bulk.0.lock().stops;
    if source_lost {
        h.source.revoke();
        ensure!(
            drive(scan)?.is_err(),
            "EU lost source crossed held active Probe"
        );
    } else {
        drop(scan);
    }
    ensure!(
        !h.device.link_up()
            && h.link.radio.bulk.0.lock().rx == old_rx
            && h.link.radio.bulk.0.lock().tx.as_ref().map(|tx| tx.id) == old_tx
            && h.link.radio.bulk.0.lock().stops == stops
            && h.link.radio.control.0.lock().ops.len() == ops
            && h.link.radio.control.0.lock().unsafe_reuses == 0
            && h.firmware.claim_receive().is_err(),
        "EU cancelled/source-lost active Probe reclaimed its real RX/TX or reused EP0"
    );
    Ok(())
}
fn smoke_rtl8188eu_connected_active_cancel_retains_native_probe_and_rx() -> TestResult {
    retained_probe(false).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_rtl8188eu_connected_active_source_loss_retains_native_probe_and_rx() -> TestResult {
    retained_probe(true).map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_cancel_retains_native_probe_and_rx
);
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_source_loss_retains_native_probe_and_rx
);

fn ambiguous_terminal() -> Result<(), &'static str> {
    for held_air in [false, true] {
        let h = AssociatedFixture::new(true, true)?;
        h.join()?;
        h.prepare_active();
        h.link.probes.lock().air_held = held_air;
        h.link.probes.lock().short = !held_air;
        ensure!(
            drive(h.device.scan(h.active_request(&[6], SSID)))?.is_err()
                && !h.device.link_up()
                && h.link.radio.bulk.0.lock().rx.is_some()
                && h.firmware.claim_receive().is_err(),
            "EU short USB or missing native SCH receipt restored a connected station"
        );
        if held_air {
            ensure!(
                h.link.probes.lock().air.is_some()
                    && h.link.radio.control.0.lock().regs[0x100] & 0xc0 == 0xc0,
                "EU active host delivery improperly closed TX before actual device terminal"
            );
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_connected_active_short_usb_and_actual_sch_terminal_are_distinct() -> TestResult {
    ambiguous_terminal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_short_usb_and_actual_sch_terminal_are_distinct
);

fn fifo() -> Result<(), &'static str> {
    let h = AssociatedFixture::new(true, true)?;
    h.join()?;
    h.prepare_active();
    h.link.probes.lock().responses = false;
    let mut old = h.link.radio.bulk.0.lock().ap.beacon();
    old[0] = 0x50;
    old[10..16].copy_from_slice(&AWAY);
    old[16..22].copy_from_slice(&AWAY);
    let ds = old
        .windows(3)
        .position(|bytes| bytes == [3, 1, 1])
        .ok_or("EU old DS")?;
    old[ds + 2] = 6;
    h.link.radio.bulk.0.lock().queue.push_back(old);
    let generation = h.link.radio.control.0.lock().cold_generation;
    let results = drive(h.device.scan(h.active_request(&[6], SSID)))?
        .map_err(|_| "EU old FIFO active conversation")?;
    ensure!(
        !results
            .iter()
            .any(|bss| bss.bssid == AWAY && bss.channel == 6)
            && h.link.probes.lock().consumed == 1
            && h.link.radio.control.0.lock().cold_generation >= generation + 2
            && h.device.link_up(),
        "EU old physical home copy acquired an away active response generation"
    );
    Ok(())
}
fn smoke_rtl8188eu_connected_active_old_fifo_copy_cannot_become_away_response() -> TestResult {
    fifo().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_old_fifo_copy_cannot_become_away_response
);

fn cold_or_policy_loss() -> Result<(), &'static str> {
    for cold in [false, true] {
        let h = AssociatedFixture::new(true, true)?;
        h.join()?;
        h.prepare_active();
        if cold {
            h.link.radio.control.0.lock().pending_write = Some(0x284);
        } else {
            h.link.probes.lock().hold = true;
        }
        let mut scan = Box::pin(h.device.scan(h.active_request(&[1], SSID)));
        let mut published = false;
        for _ in 0..4096 {
            ensure!(
                scan.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "EU current-policy/cold test ended before real native ownership"
            );
            if if cold {
                h.link.radio.control.0.lock().active_td
            } else {
                !h.link.probes.lock().packets.is_empty()
            } {
                published = true;
                break;
            }
        }
        ensure!(
            published,
            "EU active loss test did not own actual native work"
        );
        let old_rx = h.link.radio.bulk.0.lock().rx;
        let ops = h.link.radio.control.0.lock().ops.len();
        let generation = h.link.radio.control.0.lock().cold_generation;
        if cold {
            h.ht_source.revoke();
        } else {
            h.domain.lock().rules[0].flags = narf_wireless::reg::RegFlags::NO_IR;
        }
        ensure!(
            drive(scan)?.is_err()
                && !h.device.link_up()
                && h.link.radio.bulk.0.lock().rx == old_rx
                && h.link.radio.control.0.lock().ops.len() == ops
                && h.link.radio.control.0.lock().cold_generation == generation
                && h.link.radio.control.0.lock().unsafe_reuses == 0,
            "EU current home policy/HT loss crossed native active wait or reused receipt"
        );
        if cold {
            ensure!(
                h.link.radio.control.0.lock().active_td,
                "EU lost active EP0 receipt"
            );
        } else {
            ensure!(
                h.link.radio.bulk.0.lock().tx.is_some(),
                "EU lost active USB TX receipt"
            );
        }
    }
    Ok(())
}
fn smoke_rtl8188eu_connected_active_current_policy_and_cold_ht_loss_are_terminal() -> TestResult {
    cold_or_policy_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/associated_active_scan",
    smoke_rtl8188eu_connected_active_current_policy_and_cold_ht_loss_are_terminal
);
