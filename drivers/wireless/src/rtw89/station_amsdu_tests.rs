//! Real native descriptors/CCMP/RPQ with multiple Ethernet originals.
use super::*;

const RATES: [u8; 12] = [0x82, 4, 11, 22, 12, 18, 24, 36, 48, 72, 96, 108];
fn harness(protected: bool, large: bool, he: bool, companion: bool) -> Harness {
    let mut he_ies = HE_IES;
    he_ies[7] |= 0x40; // Peer RX A-MSDU-in-A-MPDU; local RX stays unchanged.
    let h = Harness::build_full(
        protected,
        true,
        true,
        Some(&RATES),
        true,
        he.then_some((true, &he_ies[..])),
        (true, companion),
    );
    h.peer.lock().addba = Some((0, 64));
    if large {
        let mut ht = HT_IES;
        ht[3] |= 8;
        h.peer.lock().ht = Some(ht.to_vec());
        let mut beacon = h.peer.lock().ap.beacon();
        beacon.extend_from_slice(&WMM);
        beacon.extend_from_slice(&ht);
        if he {
            beacon.extend_from_slice(&he_ies);
        }
        h.model(|io| io.packets.inject(&beacon)).unwrap();
    }
    h
}
fn frame(h: &Harness, tag: u16, payload: usize) -> Vec<u8> {
    udp_ipv4(
        AP,
        OWN,
        h.plan.lease_ip,
        h.plan.server_ip,
        tag,
        9,
        &vec![tag as u8; payload],
    )
}
fn queue(h: &Harness, frames: &[Vec<u8>]) -> Result<(), &'static str> {
    for frame in frames {
        narf_net::iface::send_on(h.device.name(), frame).map_err(|_| "aggregate enqueue")?;
    }
    Ok(())
}
fn data(h: &Harness) -> Vec<Vec<u8>> {
    h.model(|io| {
        io.packets
            .transmitted
            .iter()
            .filter(|b| b[0] == 0x88)
            .cloned()
            .collect()
    })
}
fn pump(h: &Harness) {
    for _ in 0..16 {
        h.device.drain();
        complete(h.device.apply_edca());
    }
}
fn uplink_frames(h: &Harness) -> Vec<Vec<u8>> {
    let peer = h.peer.lock();
    peer.uplink.clone()
}
fn aggregate_counts(h: &Harness) -> Vec<usize> {
    let peer = h.peer.lock();
    peer.aggregates.clone()
}
fn pn(frame: &[u8]) -> u64 {
    let p = &frame[26..34];
    u64::from_le_bytes([p[0], p[1], p[4], p[5], p[6], p[7], 0, 0])
}
fn run_wire() -> Result<(), &'static str> {
    for (protected, he, buf) in [
        (false, false, 64),
        (true, false, 64),
        (true, true, 64),
        (true, false, 1),
    ] {
        let h = harness(protected, false, he, true);
        h.peer.lock().addba = Some((0, buf));
        h.join().map_err(|_| "aggregate station association")?;
        let first = [frame(&h, 4100, 40), frame(&h, 4101, 50)];
        queue(&h, &first)?;
        pump(&h);
        let first_data = data(&h);
        let aggregate = first_data.last().ok_or("no aggregate native DATA")?;
        if aggregate[24] != 0x80
            || aggregate[1] & 0x80 != 0
            || aggregate[16..22] != AP
            || uplink_frames(&h) != first
            || aggregate_counts(&h) != [2]
            || h.model(|io| {
                io.packets
                    .history
                    .iter()
                    .rev()
                    .find(|s| s.channel == 0)
                    .and_then(|s| s.agg)
            })
            .is_some()
        {
            return Err("standalone A-MSDU actual body/CCMP/NormalAck/one MPDU");
        }
        // BA has now been earned through real ADDBA+native RA limit writes.
        if addba_requests(&h).len() != 1 {
            return Err("aggregate native BA setup");
        }
        let second = [frame(&h, 4102, 60), frame(&h, 4103, 70)];
        h.peer.lock().hold_data = true;
        let before = h.model(|io| io.packets.publications);
        queue(&h, &second)?;
        pump(&h);
        let after = data(&h);
        let last = after.last().ok_or("nested native DATA")?;
        if h.model(|io| io.packets.publications) != before + 1
            || h.model(|io| io.packets.last.and_then(|s| s.agg)) != Some(((buf - 1) as u8, 0))
            || aggregate_counts(&h) != [2, 2]
            || uplink_frames(&h)[2..] != second
            || last[24] != 0x80
            || last[1] & 0x80 != 0
            || protected && pn(last) != pn(aggregate) + 1
        {
            return Err("nested aggregate one PN/native descriptor/BA/owned original prefix");
        }
        pump(&h);
        if h.model(|io| io.packets.publications) != before + 1 {
            return Err("held aggregate resubmitted originals");
        }
        let third = [frame(&h, 4104, 80), frame(&h, 4105, 90)];
        if buf == 1 {
            queue(&h, &third)?;
            // Both a prefix and later a single frame must use this same exact
            // peer-window gate before crypto; repeated Busy consumes no PN/SN.
            pump(&h);
            pump(&h);
            if h.model(|io| io.packets.publications) != before + 1 {
                return Err("buf1 published another MPDU before actual terminal");
            }
        }
        h.peer.lock().hold_data = false;
        h.model(|io| io.packets.complete())
            .map_err(|_| "actual aggregate air terminal")?;
        pump(&h);
        if buf == 1 {
            let delivered = data(&h);
            let next = delivered
                .last()
                .ok_or("buf1 retained prefix did not resume")?;
            let sn = |b: &[u8]| u16::from_le_bytes([b[22], b[23]]) >> 4;
            if h.model(|io| io.packets.publications) != before + 2
                || pn(next) != pn(last) + 1
                || sn(next) != ((sn(last) + 1) & 4095)
                || uplink_frames(&h)[4..] != third
            {
                return Err("buf1 Busy consumed PN/SN or original prefix before actual terminal");
            }
            // Also exercise the inherited one-frame path under the same
            // actual buf1 peer window, with genuine held/released RPQ owners.
            h.peer.lock().hold_data = true;
            queue(&h, &[frame(&h, 4106, 100)])?;
            pump(&h);
            let singles = data(&h);
            let held = singles.last().ok_or("buf1 single native DATA")?;
            if held[24] & 0x80 != 0 {
                return Err("buf1 single became aggregate");
            }
            let published = h.model(|io| io.packets.publications);
            queue(&h, &[frame(&h, 4107, 110)])?;
            pump(&h);
            pump(&h);
            if h.model(|io| io.packets.publications) != published {
                return Err("buf1 single published before actual terminal");
            }
            h.peer.lock().hold_data = false;
            h.model(|io| io.packets.complete())
                .map_err(|_| "buf1 single air terminal")?;
            pump(&h);
            let singles = data(&h);
            let sent = singles.last().ok_or("buf1 single resume")?;
            if h.model(|io| io.packets.publications) != published + 1
                || pn(sent) != pn(held) + 1
                || sn(sent) != ((sn(held) + 1) & 4095)
            {
                return Err("single-frame Busy consumed PN/SN before actual terminal");
            }
        }
        if !h.device.link_up() || h.model(|io| io.packet_error).is_some() {
            return Err("aggregate actual terminal did not preserve station");
        }
    }
    Ok(())
}
fn smoke_rtw8852b_tx_amsdu_native_ccmp_ba_and_single_terminal() -> TestResult {
    match run_wire() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw89/aggregation",
    smoke_rtw8852b_tx_amsdu_native_ccmp_ba_and_single_terminal
);

fn report(mcs: u8, mode: u8, gi: u8) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0] = 6;
    bytes[4] = 16;
    bytes[12..16].copy_from_slice(
        &(u32::from(mcs) | u32::from(mode) << 8 | u32::from(gi) << 10).to_le_bytes(),
    );
    bytes
}
fn run_bounds() -> Result<(), &'static str> {
    let rate_limit = crate::rtw89::tx_amsdu::rate_limit;
    let mut other = report(0, 1, 0);
    other[8] = 1;
    let mut malformed = report(7, 1, 0);
    malformed[4] = 15;
    if rate_limit(&report(2, 1, 0), false) != Some(1)
        || rate_limit(&report(7, 1, 0), false) != Some(1200)
        || rate_limit(&report(11, 3, 5), true) != Some(1200)
        || rate_limit(&report(11, 3, 5), false) != Some(1)
        || rate_limit(&other, false).is_some()
        || rate_limit(&malformed, false) != Some(1)
    {
        return Err("actual rate format/profile/fallback length ceiling");
    }

    for (large, expected) in [(false, 2), (true, 3)] {
        let h = harness(false, large, false, true);
        h.join().map_err(|_| "peer size association")?;
        let frames = [
            frame(&h, 4200, 1400),
            frame(&h, 4201, 1400),
            frame(&h, 4202, 1400),
            frame(&h, 4203, 1400),
        ];
        queue(&h, &frames)?;
        pump(&h);
        if aggregate_counts(&h).first().copied() != Some(expected)
            || data(&h).iter().any(|b| b.len() > 5026)
            || uplink_frames(&h) != frames
        {
            return Err("peer HT/chip5000 body bound or original order");
        }
    }
    for (mcs, expected) in [(2, None), (7, Some(2))] {
        let h = harness(false, false, false, true);
        h.join().map_err(|_| "RC association")?;
        h.model(|io| io.packets.inject_c2h(&report(mcs, 1, 0)))
            .map_err(|_| "actual native RC C2H")?;
        let frames = [
            frame(&h, 4210, 450),
            frame(&h, 4211, 450),
            frame(&h, 4212, 450),
        ];
        queue(&h, &frames)?;
        pump(&h);
        if aggregate_counts(&h).first().copied() != expected || uplink_frames(&h) != frames {
            return Err("native RC report did not bound exact prefix before PN");
        }
    }
    // Host bound is a genuine ordered prefix, not one fake completion per
    // subframe or an unbounded drain of the frame ring.
    {
        let h = harness(false, false, false, true);
        h.join().map_err(|_| "bounded prefix association")?;
        let frames: Vec<_> = (0..9).map(|n| frame(&h, 4250 + n, 30)).collect();
        queue(&h, &frames)?;
        pump(&h);
        if aggregate_counts(&h).first() != Some(&8) || uplink_frames(&h) != frames {
            return Err("native prefix8 bound or all original Ethernet ownership");
        }
    }
    let h = harness(false, false, false, false);
    h.join().map_err(|_| "old program association")?;
    let frames = [frame(&h, 4220, 40), frame(&h, 4221, 50)];
    queue(&h, &frames)?;
    pump(&h);
    if !aggregate_counts(&h).is_empty() || uplink_frames(&h) != frames {
        return Err("absent companion changed old emitter");
    }
    Ok(())
}
fn smoke_rtw8852b_tx_amsdu_peer_chip_current_rc_and_absent_program_bounds() -> TestResult {
    match run_bounds() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw89/aggregation",
    smoke_rtw8852b_tx_amsdu_peer_chip_current_rc_and_absent_program_bounds
);

fn run_prefix() -> Result<(), &'static str> {
    let h = harness(true, false, false, true);
    h.join().map_err(|_| "prefix association")?;
    let a = frame(&h, 4300, 40);
    let mut b = frame(&h, 4301, 50);
    b[15] = 3 << 5; // TID3 shares BE queue, but cannot join TID0.
    let c = frame(&h, 4302, 60);
    queue(&h, &[a.clone(), b.clone(), c.clone()])?;
    pump(&h);
    // TID3 never joins a TID0 subframe, but the later TID0 frame `c` joins
    // `a` at the tail of the TID0 queue (mac80211 keeps one TXQ per TID;
    // `ieee80211_amsdu_aggregate` only looks at that TXQ's tail), so the
    // single A-MSDU carries exactly a + c. The TID0 and TID3 queues are
    // served independently, so only the delivered set is fixed.
    let mut delivered = uplink_frames(&h);
    delivered.sort();
    let mut sent = vec![a, b, c];
    sent.sort();
    if delivered != sent || aggregate_counts(&h) != [2] {
        return Err("same AC must not skip a different original TID");
    }
    // An actual response can deny A-MSDU even with an unrelated dialog token.
    // Linux sets TXQ_NO_AMSDU before matching the token; positive later BA
    // and DELBA cannot revive it for this still-installed physical peer.
    let mut denial = vec![0xd0, 0, 0, 0];
    denial.extend_from_slice(&OWN);
    denial.extend_from_slice(&AP);
    denial.extend_from_slice(&AP);
    denial.extend_from_slice(&[0, 0, 3, 1, 0xf0, 0, 0, 2, 16, 0, 0]);
    h.model(|io| io.packets.inject(&denial))
        .map_err(|_| "native BA denial")?;
    pump(&h);
    let frames = [frame(&h, 4310, 40), frame(&h, 4311, 50)];
    queue(&h, &frames)?;
    pump(&h);
    if !aggregate_counts(&h).is_empty() || uplink_frames(&h)[3..] != frames {
        return Err("mismatched-token native NO_AMSDU did not remain denial-only");
    }
    let mut delba = vec![0xd0, 0, 0, 0];
    delba.extend_from_slice(&OWN);
    delba.extend_from_slice(&AP);
    delba.extend_from_slice(&AP);
    delba.extend_from_slice(&[0, 0, 3, 2, 0, 0, 37, 0]);
    h.model(|io| io.packets.inject(&delba))
        .map_err(|_| "native DELBA")?;
    pump(&h);
    let frames = [frame(&h, 4320, 40), frame(&h, 4321, 50)];
    queue(&h, &frames)?;
    pump(&h);
    if !aggregate_counts(&h).is_empty() || uplink_frames(&h)[5..] != frames {
        return Err("DELBA/positive BA revived sticky NO_AMSDU for same peer");
    }
    Ok(())
}
fn smoke_rtw8852b_tx_amsdu_same_tid_fifo_and_sticky_peer_denial() -> TestResult {
    match run_prefix() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw89/aggregation",
    smoke_rtw8852b_tx_amsdu_same_tid_fifo_and_sticky_peer_denial
);

fn run_retire() -> Result<(), &'static str> {
    let h = harness(true, false, false, true);
    h.join().map_err(|_| "retirement association")?;
    let frames = [frame(&h, 4400, 40), frame(&h, 4401, 50)];
    let before = h.model(|io| io.packets.publications);
    queue(&h, &frames)?;
    // The actual second publication check sees companion loss AFTER dynamic
    // header/body allocation. No native descriptor or host success is earned.
    h.model(|io| io.packets.revoke_amsdu_on_allocate = true);
    pump(&h);
    if h.model(|io| io.packets.publications) != before
        || !h.closed()
        || !uplink_frames(&h).is_empty()
    {
        return Err("companion loss at actual native publication escaped");
    }
    Ok(())
}
fn smoke_rtw8852b_tx_amsdu_original_program_loss_at_native_publication() -> TestResult {
    match run_retire() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/wireless/rtw89/aggregation",
    smoke_rtw8852b_tx_amsdu_original_program_loss_at_native_publication
);
