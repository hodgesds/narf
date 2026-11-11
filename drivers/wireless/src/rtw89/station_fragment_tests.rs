// SPDX-License-Identifier: GPL-2.0-or-later
//! Public station worker, real WPA2/PMF cryptography, descriptor/RPQ producer.
//! The independent AP reassembles only after authenticating each on-air MPDU;
//! no post-MIC header rewrite or protocol/key/port shortcut is used.
use super::*;
use crate::rtw89::{fragment_wire, packet_core::Error as PacketError};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
struct Piece {
    header: Vec<u8>,
    body: Vec<u8>,
    last: u8,
    pn: Option<u64>,
}
#[derive(Default)]
struct ApFragments {
    piece: Option<Piece>,
    management_replay: narf_wireless::ccmp::ReplayWindow,
}
impl ApFragments {
    fn receive(
        &mut self,
        p: &mut Peer,
        frame: &[u8],
    ) -> Result<(Vec<Vec<u8>>, bool), &'static str> {
        if !crate::rtw89::fragment_rx::fragmented(frame) {
            return p.react(frame);
        }
        let management = frame[0] & 12 == 0;
        let header = if frame[0] == 0x88 { 26 } else { 24 };
        if frame.len() <= header
            || frame[4..10] != AP
            || frame[10..16] != OWN
            || frame[1] & 3 != if management { 0 } else { 1 }
            || management && frame[16..22] != AP
            || frame[0] == 0x88 && frame[24..26] != [0, 0]
        {
            return Err("AP fragment physical address/header/normal-ACK/TID");
        }
        let protected = frame[1] & 0x40 != 0;
        if protected != p.ap.protected() {
            return Err("AP fragment protection policy");
        }
        let mut body = frame[header..].to_vec();
        let mut pn = None;
        if protected {
            let key = p.ap.pairwise_tk().ok_or("AP fragment PTK")?;
            pn = Some(u64::from_le_bytes([
                body[0], body[1], body[4], body[5], body[6], body[7], 0, 0,
            ]));
            let replay = if management {
                &mut self.management_replay
            } else {
                &mut p.replay
            };
            body = narf_wireless::ccmp::unprotect(
                &Ccm,
                &frame[..header],
                &key,
                0,
                management,
                replay,
                &mut body,
            )
            .map_err(|_| "AP original fragment MIC/AAD/PN/management nonce")?;
        }
        let number = frame[22] & 15;
        let more = frame[1] & 4 != 0;
        if number == 0 {
            if !more {
                return Err("AP unfragmented input in fragment lane");
            }
            self.piece = Some(Piece {
                header: frame[..header].to_vec(),
                body,
                last: 0,
                pn,
            });
        } else {
            let entry = self
                .piece
                .as_mut()
                .ok_or("AP fragment without predecessor")?;
            if entry.last + 1 != number
                || entry.header[0] != frame[0]
                || entry.header[1] & !4 != frame[1] & !4
                || entry.header[4..22] != frame[4..22]
                || entry.header[22] & 0xf0 != frame[22] & 0xf0
                || entry.header[23] != frame[23]
                || entry.pn.map(|old| old + 1) != pn
                || entry.body.len() + body.len() > 4096
            {
                return Err("AP fragment original sequence/epoch/consecutive PN");
            }
            entry.last = number;
            entry.pn = pn;
            entry.body.extend_from_slice(&body);
            if !more {
                let entry = self.piece.take().ok_or("AP final fragment ownership")?;
                if management {
                    let mut complete = entry.header;
                    complete[1] &= !0x44;
                    complete[22] &= !15;
                    complete.extend_from_slice(&entry.body);
                    p.actions.push(complete);
                } else {
                    if entry.body.get(..6) != Some(&[0xaa, 0xaa, 3, 0, 0, 0]) {
                        return Err("AP complete fragment RFC1042");
                    }
                    let mut ethernet = entry.header[16..22].to_vec();
                    ethernet.extend_from_slice(&entry.header[10..16]);
                    ethernet.extend_from_slice(&entry.body[6..]);
                    p.uplink.push(ethernet);
                }
            }
        }
        Ok((Vec::new(), p.hold_data))
    }
}
type FragmentPrograms = (Cap<FirmwareBlob, Read>, Cap<FirmwareBlob, Read>);
fn enabled(h: &Harness) -> Result<FragmentPrograms, &'static str> {
    let (qualification, base, companion) = crate::rtw89::radio_policy::tests::fragment_model(None);
    h.model(|io| io.fragments = Some(Arc::new(qualification)));
    if !h.device.refresh_fragment_model() || !Device::bind_sleep_target(&h.device) {
        return Err("public original fragment-capable owner/registration");
    }
    let ap = h.peer.clone();
    let cache = Arc::new(IrqSafeSpinLock::new(ApFragments::default()));
    h.model(|io| {
        io.packets.reaction = Some(Arc::new(move |frame| {
            cache
                .lock()
                .receive(&mut ap.lock(), frame)
                .map_err(|_| PacketError::Packet)
        }))
    });
    Ok((base, companion))
}
fn packet(h: &Harness, tag: u16, len: usize) -> Vec<u8> {
    udp_ipv4(
        AP,
        OWN,
        h.plan.lease_ip,
        h.plan.server_ip,
        tag,
        9,
        &vec![tag as u8; len],
    )
}
fn data(h: &Harness) -> Vec<Vec<u8>> {
    h.model(|io| {
        io.packets
            .transmitted
            .iter()
            .filter(|b| matches!(b[0], 8 | 0x88) && crate::rtw89::fragment_rx::fragmented(b))
            .cloned()
            .collect()
    })
}
fn uplinks(h: &Harness) -> Vec<Vec<u8>> {
    h.peer.lock().uplink.clone()
}
fn release(h: &Harness) -> Result<(), &'static str> {
    h.model(|io| io.packets.complete())
        .map_err(|_| "actual fragment DMA/RPQ completion")?;
    h.pump();
    Ok(())
}
fn wire_train() -> Result<(), &'static str> {
    for protected in [false, true] {
        let h = Harness::new(protected);
        h.join()
            .map_err(|_| "fragment real Open/WPA2 association")?;
        let (_base, _companion) = enabled(&h)?;
        if h.device.fragmentation_threshold() != Some(u32::MAX)
            || h.device.set_fragmentation_threshold(255) != Err(-22)
            || h.device.set_fragmentation_threshold(2347) != Err(-22)
            || h.device.set_fragmentation_threshold(257).is_err()
            || h.device.fragmentation_threshold() != Some(256)
        {
            return Err("public original threshold disabled/range/even normalization");
        }
        h.peer.lock().hold_data = true;
        let original = packet(&h, 7100, 600);
        narf_net::iface::send_on(h.device.name(), &original)
            .map_err(|_| "public fragmented Ethernet enqueue")?;
        h.pump();
        let first = data(&h);
        if first.len() != 1 || !uplinks(&h).is_empty() {
            return Err("partial fragment train delivered Ethernet or published multiple parts");
        }
        let saved = first[0].clone();
        h.pump();
        h.pump();
        if data(&h) != first {
            return Err("held native fragment regenerated/resubmitted PN/SN/ciphertext");
        }
        // A new preference affects future MSDUs only, never this owned train.
        h.device
            .set_fragmentation_threshold(u32::MAX)
            .map_err(|_| "disable with held original train")?;
        for _ in 0..16 {
            if !uplinks(&h).is_empty() {
                break;
            }
            release(&h)?;
        }
        if uplinks(&h).is_empty() {
            return Err("bounded native train did not terminate");
        }
        let complete = data(&h);
        if complete.len() != 3 || complete[0] != saved || uplinks(&h) != [original.clone()] {
            return Err("whole original Ethernet/ciphertext/SN lost across actual terminals");
        }
        let sequence = u16::from_le_bytes([saved[22], saved[23]]) >> 4;
        let pn = |b: &[u8]| u64::from_le_bytes([b[24], b[25], b[28], b[29], b[30], b[31], 0, 0]);
        for (number, part) in complete.iter().enumerate() {
            if u16::from_le_bytes([part[22], part[23]]) >> 4 != sequence
                || part[22] & 15 != number as u8
                || (part[1] & 4 != 0) != (number + 1 < complete.len())
                || part[2..4]
                    != fragment_wire::duration(complete.get(number + 1).map(Vec::len))
                        .unwrap()
                        .to_le_bytes()
                || protected && pn(part) != pn(&saved) + number as u64
            {
                return Err("per-fragment original SN/number/MF/NAV/PN");
            }
        }
        release(&h)?;
        h.peer.lock().hold_data = false;
        let next = packet(&h, 7101, 600);
        narf_net::iface::send_on(h.device.name(), &next).map_err(|_| "next ordinary MSDU")?;
        h.pump();
        if data(&h) != complete || uplinks(&h).last() != Some(&next) {
            return Err("disabled threshold rewrote old train or failed next ordinary path");
        }
        let old = h.device.fragmentation_threshold();
        let desired = crate::rtw89::monitor::Desired::new();
        let selected = desired.snapshot();
        if !desired.set_fragment_threshold(selected, 512) || desired.fragment_threshold() != 512 {
            return Err("physical fragment preference retain");
        }
        let monitor = desired
            .select(selected, 6)
            .ok_or("physical monitor generation")?;
        let rebound = desired
            .select(monitor, 2)
            .ok_or("physical station replacement")?;
        if desired.fragment_threshold() != 512
            || desired.set_fragment_threshold(selected, 1024)
            || desired.current(selected)
            || !desired.current(rebound)
            || old != Some(u32::MAX)
        {
            return Err(
                "old role changed rebound physical preference or preference lost across generation",
            );
        }
    }
    Ok(())
}
fn smoke_rtw8852b_fragment_public_threshold_one_sn_per_part_pn_and_terminal_retry() -> TestResult {
    wire_train().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_public_threshold_one_sn_per_part_pn_and_terminal_retry
);
fn downlink(
    h: &Harness,
    ethernet: &[u8],
    sequence: u16,
    protected: bool,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut frame = vec![8, 2, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&ethernet[6..12]);
    frame.extend_from_slice(&(sequence << 4).to_le_bytes());
    frame.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    frame.extend_from_slice(&ethernet[12..]);
    let mut parts = fragment_wire::split(&frame, 256).ok_or("AP plaintext original split")?;
    if protected {
        let mut p = h.peer.lock();
        let key = p.ap.pairwise_tk().ok_or("AP actual original PTK")?;
        for part in &mut parts {
            part[1] |= 0x40;
            let mut body = part[24..].to_vec();
            let pn = p.pn;
            p.pn += 1;
            let wire =
                narf_wireless::ccmp::protect(&Ccm, &part[..24], &key, pn, 0, 0, false, &mut body)
                    .map_err(|_| "AP original fragment seal")?;
            part.truncate(24);
            part.extend_from_slice(&wire);
        }
    }
    Ok(parts)
}
fn receive() -> Result<(), &'static str> {
    for protected in [false, true] {
        let h = Harness::new(protected);
        h.join().map_err(|_| "RX fragment association")?;
        // RX parsing requires original base/source facts, no invented measured
        // emitter grant. This ordinary owner has NO N52F TX opt-in.
        if h.device.fragmentation_threshold().is_some() {
            return Err("old profile advertised TX fragments");
        }
        let ethernet = udp_ipv4(
            OWN,
            AP,
            h.plan.server_ip,
            h.plan.lease_ip,
            9,
            7102,
            &[0x71; 600],
        );
        let parts = downlink(&h, &ethernet, 0x456, protected)?;
        for (number, part) in parts.iter().enumerate() {
            h.model(|io| io.packets.inject(part))
                .map_err(|_| "actual original RX descriptor")?;
            h.pump();
            let received = h.received();
            if if number + 1 < parts.len() {
                !received.is_empty()
            } else {
                received != [ethernet.clone()]
            } {
                return Err("original RX fragment partial/complete controlled-port delivery");
            }
        }
        for part in &parts {
            h.model(|io| io.packets.inject(part))
                .map_err(|_| "replayed RX descriptor")?;
        }
        h.pump();
        // CCMP rejects replay; Open has no PN/replay authentication promise.
        if protected && !h.received().is_empty() {
            return Err("replayed authenticated fragments delivered");
        }
        if !protected {
            let _ = h.received();
        }
        let next = downlink(&h, &ethernet, 0x457, protected)?;
        for (number, part) in next.iter().enumerate() {
            let mut bad = part.clone();
            if number == 1 {
                let last = bad.len() - 1;
                bad[last] ^= 1;
            }
            h.model(|io| io.packets.inject(&bad))
                .map_err(|_| "forged original RX descriptor")?;
        }
        h.pump();
        if protected && !h.received().is_empty() {
            return Err("fragment MIC failure delivered reassembled DATA");
        }
        if !protected {
            let _ = h.received();
        }
        // Missing predecessor, foreign peer, timeout and group input never
        // combine with the next fresh original sequence.
        let next = downlink(&h, &ethernet, 0x458, protected)?;
        h.model(|io| io.packets.inject(&next[0]))
            .map_err(|_| "partial original")?;
        h.pump();
        h.env.clock.fetch_add(2001, Ordering::AcqRel);
        for part in next.iter().skip(1) {
            h.model(|io| io.packets.inject(part))
                .map_err(|_| "expired continuation")?;
        }
        h.pump();
        if !h.received().is_empty() {
            return Err("expired fragment cache delivered");
        }
        let next = downlink(&h, &ethernet, 0x459, protected)?;
        for part in &next {
            h.model(|io| io.packets.inject(part))
                .map_err(|_| "fresh original after drops")?;
        }
        h.pump();
        if h.received() != [ethernet] {
            return Err("drops poisoned fresh current RX train");
        }
    }
    Ok(())
}
fn smoke_rtw8852b_fragment_original_rx_base_only_pn_mic_timeout_and_controlled_port() -> TestResult
{
    receive().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_original_rx_base_only_pn_mic_timeout_and_controlled_port
);

fn management_boundary() -> Result<(), &'static str> {
    let ap = FakeAp::wpa2(network(), SSID, 1, 42, PMK, ANONCE)
        .and_then(FakeAp::with_basic_1mbps)
        .and_then(|ap| ap.with_pmf(narf_wifi_fixtures::ApPmf::Required))
        .map_err(|_| "real PMF AP for management fragments")?;
    *NEXT_AP.lock() = Some(Box::new(ap));
    let h = Harness::new(true);
    h.join().map_err(|_| "real PMF key/IGTK association")?;
    let (_base, _companion) = enabled(&h)?;
    h.device
        .set_fragmentation_threshold(2346)
        .map_err(|_| "public maximum fragment threshold")?;
    h.peer.lock().hold_data = true;
    let mut action = vec![0xd0, 0, 0, 0];
    action.extend_from_slice(&AP);
    action.extend_from_slice(&OWN);
    action.extend_from_slice(&AP);
    action.extend_from_slice(&[0, 0]);
    action.extend_from_slice(&[3; 3000]);
    {
        let mut retained = h
            .lifecycle
            .retained
            .try_lock()
            .ok_or("public retained management owner")?;
        retained
            .as_mut()
            .ok_or("management same owner")?
            .station_model_management(action.clone())
            .map_err(|_| "current PMF source management train")?;
    }
    h.pump();
    let sent = h.model(|io| {
        io.packets
            .transmitted
            .iter()
            .filter(|b| b[0] == 0xd0 && crate::rtw89::fragment_rx::fragmented(b))
            .cloned()
            .collect::<Vec<_>>()
    });
    if sent.len() != 1 || sent[0].len() != 2358 || !h.peer.lock().actions.is_empty() {
        return Err("2346 plaintext threshold lost actual2358 protected management first MPDU");
    }
    release(&h)?;
    let (sent, headers) = h.model(|io| {
        (
            io.packets
                .transmitted
                .iter()
                .filter(|b| b[0] == 0xd0 && crate::rtw89::fragment_rx::fragmented(b))
                .cloned()
                .collect::<Vec<_>>(),
            io.packets
                .history
                .iter()
                .filter(|s| s.channel == 8)
                .copied()
                .collect::<Vec<_>>(),
        )
    });
    let complete = h.peer.lock().actions.clone();
    if sent.len() != 2
        || complete.len() != 1
        || complete[0][24..] != action[24..]
        || headers.len() < 2
        || headers[headers.len() - 2..]
            .iter()
            .any(|s| s.hardware_sequence)
        || headers[headers.len() - 2].host_sequence != headers[headers.len() - 1].host_sequence
    {
        return Err("PMF fragment management nonce/MIC/body or actual descriptor SW_SN");
    }
    release(&h)?;
    Ok(())
}
fn smoke_rtw8852b_fragment_pmf_2346_threshold_2358_native_body_and_management_sw_sequence(
) -> TestResult {
    management_boundary().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_pmf_2346_threshold_2358_native_body_and_management_sw_sequence
);
fn ampdu_and_source() -> Result<(), &'static str> {
    const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
    let h = Harness::build_full(true, true, true, Some(&RATES), true, None, (true, false));
    h.peer.lock().addba = Some((0, 1));
    h.join().map_err(|_| "fragment/BA station association")?;
    let (_base, _companion) = enabled(&h)?;
    h.device
        .set_fragmentation_threshold(256)
        .map_err(|_| "fragment policy on actual HT peer")?;
    let first = packet(&h, 7103, 20);
    narf_net::iface::send_on(h.device.name(), &first).map_err(|_| "actual small BA trigger")?;
    for _ in 0..16 {
        h.device.drain();
        complete(h.device.apply_edca());
    }
    let large = packet(&h, 7104, 600);
    h.peer.lock().hold_data = true;
    narf_net::iface::send_on(h.device.name(), &large).map_err(|_| "actual operational BA data")?;
    for _ in 0..16 {
        h.device.drain();
        complete(h.device.apply_edca());
    }
    if !data(&h).is_empty()
        || h.model(|io| io.packets.last.and_then(|s| s.agg)) != Some((0, 0))
        || uplinks(&h).last() != Some(&large)
    {
        return Err("operational BA lost actual DONTFRAG/AGG_EN semantics");
    }
    drop(h);
    let h = Harness::new(true);
    h.join().map_err(|_| "source-loss original station")?;
    let (base, _companion) = enabled(&h)?;
    h.device
        .set_fragmentation_threshold(256)
        .map_err(|_| "source-loss original setting")?;
    let before = h.model(|io| io.packets.publications);
    base.revoke();
    let _ = h.device.enqueue(&packet(&h, 7105, 600), TxMeta::default());
    h.pump();
    if h.model(|io| io.packets.publications) != before
        || !h.closed()
        || h.device.fragmentation_threshold().is_some()
    {
        return Err("lost original fragment joint source published/kept metadata live");
    }
    Ok(())
}
fn smoke_rtw8852b_fragment_operational_ba_dontfrag_and_original_source_retirement() -> TestResult {
    ampdu_and_source().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_operational_ba_dontfrag_and_original_source_retirement
);

fn fragmented_handshake() -> Result<(), &'static str> {
    for cancelled in [false, true] {
        let h = Harness::new(true);
        h.peer.lock().hold_m4 = cancelled;
        let peer = h.peer.clone();
        let split = Arc::new(core::sync::atomic::AtomicUsize::new(0));
        let counted = split.clone();
        h.model(|io| {
            io.packets.reaction = Some(Arc::new(move |frame| {
                let (responses, hold) =
                    peer.lock().react(frame).map_err(|_| PacketError::Packet)?;
                let mut native = Vec::new();
                for response in responses {
                    if response.len() > 40
                        && response[0] == 8
                        && response[1] & 0x40 == 0
                        && response.get(24..32) == Some(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e])
                    {
                        let count = response[24..].chunks(64).len();
                        for (number, body) in response[24..].chunks(64).enumerate() {
                            let mut original = response[..24].to_vec();
                            original[22] = (original[22] & 0xf0) | number as u8;
                            if number + 1 < count {
                                original[1] |= 4;
                            } else {
                                original[1] &= !4;
                            }
                            original.extend_from_slice(body);
                            native.push(original);
                        }
                        counted.fetch_add(1, Ordering::AcqRel);
                    } else {
                        native.push(response);
                    }
                }
                Ok((native, hold))
            }))
        });
        h.scan();
        if !cancelled {
            complete(h.device.associate(h.request()))
                .map_err(|_| "native fragmented initial M1/M3 real RSNA")?;
            if !h.device.link_up()
                || split.load(Ordering::Acquire) != 2
                || h.peer.lock().ap.phase() != ApPhase::Authorized
            {
                return Err("fragmented EAPOL skipped actual MIC/nonces/native M4 terminal port");
            }
            let data = packet(&h, 7106, 40);
            narf_net::iface::send_on(h.device.name(), &data)
                .map_err(|_| "real fragmented-handshake PTK data")?;
            h.pump();
            if uplinks(&h).last() != Some(&data) {
                return Err("fragmented handshake derived wrong actual key");
            }
        } else {
            // The pending association owns the retained station (the
            // `Lifecycle` mutex) until it completes or is dropped, so the
            // M4 hold flag is read through a pre-cloned handle, as the
            // other held-M4 composition cases do.
            let controls = h.model(|io| io.packets.controls.clone());
            let mut association = begin_fragment_association(&h);
            let mut held = false;
            for _ in 0..10_000 {
                if association
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return Err("fragmented handshake opened port before held M4 terminal");
                }
                if controls.held.load(Ordering::Acquire) {
                    held = true;
                    break;
                }
            }
            if !held || h.device.link_up() || split.load(Ordering::Acquire) != 2 {
                return Err("native fragmented M3 did not retain exact M4 ownership");
            }
            drop(association);
            h.pump();
            if h.device.link_up()
                || !h.model(|io| io.stopped)
                || h.device
                    .enqueue(&packet(&h, 7107, 40), TxMeta::default())
                    .is_ok()
            {
                return Err("dropped fragmented handshake owner gained key/controlled port");
            }
        }
    }
    Ok(())
}
#[inline(never)]
fn begin_fragment_association(
    h: &Harness,
) -> core::pin::Pin<Box<dyn Future<Output = Result<(), narf_wireless::WirelessError>> + '_>> {
    Box::pin(h.device.associate(h.request()))
}
fn smoke_rtw8852b_fragment_initial_eapol_original_mic_nonce_terminal_and_dropped_owner(
) -> TestResult {
    fragmented_handshake().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_initial_eapol_original_mic_nonce_terminal_and_dropped_owner
);
