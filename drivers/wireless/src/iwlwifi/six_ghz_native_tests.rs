//! Source-authored6GHz NVM/UMAC/AP/TFH/RFH compositions. No production
//! channel, security, power receipt or candidate cache is injected directly.
use super::super::super::{
    connection,
    native_band::{Band, Channel},
    six_ghz_power,
};
use super::*;
use narf_wireless::reg::{PowerType6Ghz, RegFlags, RegRule, RegulatoryDomain};

const PASSWORD: &[u8] = b"native-six-H2E-PMF-password";
#[derive(Clone, Copy)]
enum Native {
    Sc,
    Mvm,
    Bz,
}
fn model() -> SixModel {
    SixModel {
        channel: 5,
        regulatory: 0,
        nvm_flags: 0x6001,
        mcc_flags: 0x600d,
        api59: true,
        tpe: 20,
        alias: false,
    }
}
pub(super) fn policy() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5945,
            freq_end_mhz: 7125,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    }
}
pub(super) fn complete_ap_frame(frame: &mut Vec<u8>, model: SixModel) -> R {
    let prefix = if frame[0] == 0x80 { 36 } else { 30 };
    let mut ies = Vec::new();
    let mut rest = frame.get(prefix..).ok_or("6GHz authored AP header")?;
    while !rest.is_empty() {
        let len = usize::from(*rest.get(1).ok_or("6GHz authored AP IE header")?);
        let item = rest.get(..2 + len).ok_or("6GHz authored AP IE extent")?;
        if !matches!(rest[0], 1 | 3 | 50) {
            ies.extend_from_slice(item);
        }
        rest = &rest[2 + len..];
    }
    frame.truncate(prefix);
    frame.extend_from_slice(&ies);
    frame.extend_from_slice(&[1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
    // Authored HE20, HTC_HE, MCS0..7 NSS1/2, no coding/beamforming/PPE.
    frame.extend_from_slice(&[
        255, 22, 35, 1, 0, 0x20, 0, 0, 0, 0, 0x30, 10, 0, 0, 0, 0, 4, 1, 0x30, 0, 0xf0, 0xff, 0xf0,
        0xff,
    ]);
    frame.extend_from_slice(&[
        255,
        12,
        36,
        0xf0,
        0x3f,
        2,
        7,
        0xfc,
        0xff,
        model.channel,
        model.regulatory << 3,
        model.channel,
        0,
        6,
    ]);
    // HE6GHz capability: MPDU spacing4, A-MPDU exp3, MPDU3895, SMPS off.
    frame.extend_from_slice(&[255, 3, 59, 0x1c, 6]);
    frame.extend_from_slice(&super::super::super::qos::INFORMATION_IE);
    frame.extend_from_slice(&[195, 2, 0, model.tpe as u8]);
    Ok(())
}
#[inline(never)]
fn setup(native: Native, six: SixModel, fault: Fault) -> R<Box<Guard>> {
    setup_with_tx(native, six, fault, None)
}
#[inline(never)]
fn setup_with_tx(
    native: Native,
    six: SixModel,
    fault: Fault,
    tx_model: Option<TxModel>,
) -> R<Box<Guard>> {
    let phy = PhyModel {
        width: 0,
        streams: 2,
        rates: if matches!(native, Native::Mvm) { 2 } else { 3 },
        mcc_he: true,
        response_he: true,
    };
    let guard = Guard::build_native_profile(
        true,
        fault,
        None,
        None,
        Some(phy),
        NativeModel {
            receive_model: if matches!(native, Native::Mvm) {
                ReceiveModel::ExplicitV1
            } else {
                ReceiveModel::NativeSc
            },
            tx_model,
            api89: matches!(native, Native::Mvm).then_some(gen3_station_tests::Case::SoCdb),
            bz: matches!(native, Native::Bz)
                .then_some(super::super::super::bz_fixture::Case::WhIntegrated),
            six: Some(six),
        },
    )?;
    let ap = FakeAp::wpa3_sae(
        NETWORK,
        SSID,
        six.channel,
        7,
        PASSWORD,
        narf_wifi_fixtures::ApSaePwe::HashToElement,
        ANONCE,
    )
    .and_then(|ap| ap.with_akms(&[24]))
    .and_then(|ap| ap.with_igtk([0x6b; 16], 5, 0x0102_0304_0506))
    .map_err(|_| "6GHz authored SAE24/PMF peer")?;
    security_tests::install_ap(ap);
    HARNESS.lock().as_mut().unwrap().1.sae_h2e_only = true;
    Ok(Box::new(guard))
}
fn scan(six: SixModel) -> ScanRequest {
    let mut request = scan_request();
    request.channels = vec![u32::from(six.channel)];
    request.frequencies_mhz = vec![5950 + 5 * u32::from(six.channel)];
    request
}
fn request_six(six: SixModel) -> AssociateRequest {
    let mut req = request(true);
    req.channel = u32::from(six.channel);
    req.frequency_mhz = 5950 + 5 * u32::from(six.channel);
    req.security = narf_wireless::SecurityConfig::Wpa3 {
        password: PASSWORD.to_vec(),
    };
    req
}
fn discover(guard: &Guard, six: SixModel) -> R {
    let found =
        run(guard.device().scan(scan(six)), service)?.map_err(|_| "6GHz actual passive scan")?;
    require(
        found.len() == 1
            && found[0].bssid == AP
            && found[0].frequency_mhz == 5975
            && found[0].channel == 5,
        "6GHz explicit copied RFH identity",
    )
}
fn join(guard: &Guard, six: SixModel) -> R {
    discover(guard, six)?;
    run(
        guard
            .device()
            .associate_in_domain(request_six(six), &policy()),
        service,
    )?
    .map_err(|_| "6GHz actual SAE-H2E/PMF station association")?;
    carrier(guard.device(), true)
}
fn close(guard: &Guard) -> R {
    run(guard.device().disassociate(), service)?.map_err(|_| "6GHz native ordered teardown")
}
#[inline(never)]
fn cdb_fifo_bounds() -> R {
    let six = model();
    let mut tx = tx_amsdu_tests::profile(true, true);
    // Actual source TLV40/CDB plus unequal SMEMv4 LMAC geometry. Low
    // channel5 belongs to6GHz LMAC1, whose FIFO is deliberately smaller.
    for fifo in 0..8 {
        let at = 40 + 72 + fifo * 4;
        tx.memory[at..at + 4].copy_from_slice(&1024u32.to_le_bytes());
    }
    let guard = setup_with_tx(Native::Sc, six, Fault::None, Some(tx))?;
    join(&guard, six)?;
    tx_amsdu_tests::enable(&guard)?;
    let small_a = tx_amsdu_tests::packet(0xa1, 50, false);
    let small_b = tx_amsdu_tests::packet(0xa2, 50, false);
    tx_amsdu_tests::pair(&guard, &small_a, &small_b)?;
    require(
        HARNESS.lock().as_ref().unwrap().1.aggregates.len() == 1,
        "6GHz LMAC1 valid small native aggregate was suppressed",
    )?;
    let large_a = tx_amsdu_tests::packet(0xa3, 400, false);
    let large_b = tx_amsdu_tests::packet(0xa4, 400, false);
    tx_amsdu_tests::pair(&guard, &large_a, &large_b)?;
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    require(
        wire.aggregates.len() == 1
            && wire
                .data
                .iter()
                .any(|(frame, protected)| *protected && *frame == large_a)
            && wire
                .data
                .iter()
                .any(|(frame, protected)| *protected && *frame == large_b),
        "6GHz channel5 used larger legacy LMAC0 FIFO or lost native single fallback",
    )?;
    drop(slot);
    close(&guard)
}

#[inline(never)]
fn queued_tpe_blocks_native_data(batch: bool) -> R {
    let six = model();
    let tx = batch.then(|| tx_amsdu_tests::profile(true, true));
    let guard = setup_with_tx(Native::Sc, six, Fault::None, tx)?;
    join(&guard, six)?;
    if batch {
        tx_amsdu_tests::enable(&guard)?;
    }
    let first = tx_amsdu_tests::packet(0xb1, 200, false);
    let second = tx_amsdu_tests::packet(0xb2, 300, false);
    let state = guard
        .device()
        .state
        .try_lock()
        .ok_or("6GHz backlog enqueue owner")?;
    narf_net::iface::send_on(guard.device().name(), &first)
        .map_err(|_| "6GHz backlog first IPC frame")?;
    if batch {
        narf_net::iface::send_on(guard.device().name(), &second)
            .map_err(|_| "6GHz backlog second IPC frame")?;
    }
    drop(state);
    let (before_data, before_aggregate) = {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        //64 genuine unsolicited packets in one posted RFH buffer, then a
        // bound stricter beacon in another. Native poll copies both, while
        // Device's64-notification receive budget leaves the beacon queued.
        wire.firmware
            .inject_packed(&vec![(0xab, 5, 0x8000, &[][..]); 64]);
        let mut stricter = six;
        stricter.tpe = 10;
        let mut beacon = wire.ap.beacon();
        complete_ap_frame(&mut beacon, stricter)?;
        wire.mpdu(&beacon, false);
        (wire.data.len(), wire.aggregates.len())
    };
    drain();
    let state = guard
        .device()
        .state
        .try_lock()
        .ok_or("6GHz backlog publication owner")?;
    require(
        state.hardware.is_failed() && state.needs_reset && !state.hardware.notifications.is_empty(),
        "6GHz TX gate missed a stricter native beacon beyond the receive budget",
    )?;
    drop(state);
    carrier(guard.device(), false)?;
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    require(
        wire.data.len() == before_data && wire.aggregates.len() == before_aggregate,
        "6GHz queued stricter TPE allowed ordinary or aggregate native DATA",
    )
}

#[inline(never)]
fn credit_poll_copies_stricter_tpe_before_publication() -> R {
    let six = model();
    let guard = setup(Native::Sc, six, Fault::None)?;
    join(&guard, six)?;
    let packet = tx_amsdu_tests::packet(0xb3, 100, false);
    let frame = super::super::super::frame_api::transmit_qos(OWN, AP, 0, &packet, true, 0)
        .ok_or("6GHz credit-poll native QoS frame")?;
    let mut state = guard
        .device()
        .state
        .try_lock()
        .ok_or("6GHz credit-poll native owner")?;
    state.hardware.check_six_tx_publication()?; // Caller's prior view is current.
    let (queue, before) = {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        let queue = wire
            .queues
            .iter()
            .find(|(_, tid, live)| *tid == 0 && *live)
            .ok_or("6GHz actual BE queue missing")?
            .0;
        let mut stricter = six;
        stricter.tpe = 10;
        let mut beacon = wire.ap.beacon();
        complete_ap_frame(&mut beacon, stricter)?;
        wire.mpdu(&beacon, false);
        (queue, wire.data.len())
    };
    // wait_tx_space now copies that previously unseen DMA descriptor. The
    // publication must check its new snapshot after this actual credit poll.
    require(
        run(state.hardware.transmit(queue, &frame, 26, None), service)?.is_err()
            && state.hardware.is_failed(),
        "6GHz native credit poll bypassed the final AP power gate",
    )?;
    drop(state);
    // The tail-expression temporary otherwise keeps HARNESS locked while
    // Guard::drop reacquires it to destroy the native model (edition2021).
    let unpublished = HARNESS.lock().as_ref().unwrap().1.data.len() == before;
    require(
        unpublished,
        "6GHz credit poll published DATA using the caller's stale AP power view",
    )
}
fn smoke_iwl_six_ghz_native_sc_mvm_bz_sae24_pmf_power_and_dhcp() -> TestResult {
    check(|| {
        for native in [Native::Sc, Native::Mvm, Native::Bz] {
            for regulatory in 0..=2 {
                let mut six = model();
                six.regulatory = regulatory;
                let guard = setup(native, six, Fault::None)?;
                join(&guard, six)?;
                security_tests::native_keys(24)?;
                let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                    .map_err(|_| "6GHz native protected DHCP DORA")?;
                require(NETWORK.matches_lease(&lease), "6GHz native lease")?;
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                let phy = &wire
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (1, 8))
                    .ok_or("6GHz actual PHY missing")?
                    .2;
                let tpe = &wire
                    .commands
                    .iter()
                    .find(|(g, c, _)| (*g, *c) == (4, 0xc))
                    .ok_or("6GHz actual AP power missing")?
                    .2;
                require(
                    phy[12..15] == [2, 0, 0]
                        && word(phy, 8) == 5
                        && tpe.len() == 28
                        && half(tpe, 2) == u16::from(regulatory)
                        && tpe[4] == 20
                        && tpe[5..25].iter().all(|&b| b == 127)
                        && tpe[25..] == [0; 3],
                    "6GHz native PHY/AP type/TPE wire facts",
                )?;
                let req = wire
                    .phy_requests
                    .last()
                    .ok_or("6GHz actual Association Request missing")?;
                let mut ies = &req[28..];
                let (mut he, mut cap, mut reg) = (false, false, false);
                while !ies.is_empty() {
                    let len = usize::from(ies[1]);
                    require(
                        !matches!(ies[0], 45 | 61 | 191 | 192),
                        "6GHz emitted HT/VHT IE",
                    )?;
                    if ies[0] == 255 {
                        match ies[2] {
                            35 => he = true,
                            59 => cap = ies[3..5] == [0x1c, 6],
                            137 => reg = true,
                            _ => {}
                        }
                    }
                    ies = &ies[2 + len..];
                }
                require(
                    he && cap && reg,
                    "6GHz omitted actual HE/band/regulatory request facts",
                )?;
                drop(slot);
                close(&guard)?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_native_sc_mvm_bz_sae24_pmf_power_and_dhcp
);

fn smoke_iwl_six_ghz_nvm_tail_passive_jobs_and_legacy_channel_alias() -> TestResult {
    check(|| {
        let mut raw = vec![0; 28 + 115 * 4];
        raw[8..12].copy_from_slice(&28u32.to_le_bytes());
        raw[12..16].copy_from_slice(&3u32.to_le_bytes());
        raw[16..20].copy_from_slice(&3u32.to_le_bytes());
        raw[24..28].copy_from_slice(&115u32.to_le_bytes());
        for item in raw[28..].chunks_exact_mut(4) {
            item.copy_from_slice(&0x6001u32.to_le_bytes());
        }
        let nvm = super::super::super::station_api::Nvm::parse(5, &raw)?;
        require(
            nvm.channels.len() == 51
                && nvm.six_channels.len() == 59
                && Channel::six(233).unwrap().index() == Some(109)
                && Channel::six(237).is_none()
                && Channel::from_frequency(5, 2432).is_some_and(|ch| ch.band == Band::Two)
                && Channel::from_frequency(5, 5975).is_some_and(|ch| ch.band == Band::Six)
                && Channel::from_frequency(149, 5745).is_some_and(|ch| ch.band == Band::Five)
                && Channel::from_frequency(149, 6695).is_some_and(|ch| ch.band == Band::Six),
            "6GHz NVM tail or same-number channel/frequency alias",
        )?;
        let mut six = model();
        six.alias = true;
        let guard = setup(Native::Sc, six, Fault::None)?;
        let mut req = scan(six);
        req.channels.clear();
        req.frequencies_mhz.clear();
        let found =
            run(guard.device().scan(req), service)?.map_err(|_| "6GHz all-band passive jobs")?;
        require(
            found.len() == 2
                && found.iter().any(|b| b.frequency_mhz == 2432)
                && found.iter().any(|b| b.frequency_mhz == 5975),
            "6GHz same-BSSID alias replaced scan result",
        )?;
        let state = guard
            .device()
            .state
            .try_lock()
            .ok_or("6GHz passive cache owner")?;
        require(
            state.beacons.len() == 2
                && state.beacons.iter().any(|b| b.band == Band::Two)
                && state.beacons.iter().any(|b| b.band == Band::Six),
            "6GHz same-BSSID alias replaced native candidate",
        )?;
        drop(state);
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        let scans: Vec<_> = wire
            .commands
            .iter()
            .filter(|(g, c, _)| (*g, *c) == (1, 0xd))
            .collect();
        require(
            scans.len() == 2
                && scans[0].2[45] == 51
                && scans[1].2[45] == 59
                && half(&scans[1].2, 8) == 0x802
                && scans[1].2[48..48 + 59 * 8]
                    .chunks_exact(8)
                    .all(|ch| word(ch, 0) >> 30 == 2),
            "6GHz did not retain separate bounded native terminal jobs",
        )?;
        drop(slot);
        let bands = guard.device().get_wireless_info().bands;
        require(
            bands
                .iter()
                .find(|b| b.freq_mhz == 6000)
                .is_some_and(|b| b.channels.len() == 59)
                && guard.device().phy_capabilities(6000).is_none(),
            "6GHz band facts fabricated legacy HT/VHT capability",
        )?;
        run(
            guard
                .device()
                .associate_in_domain(request_six(six), &policy()),
            service,
        )?
        .map_err(|_| "6GHz selected legacy cached alias")?;
        carrier(guard.device(), true)?;
        close(&guard)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_nvm_tail_passive_jobs_and_legacy_channel_alias
);

fn without(mut bytes: &[u8], id: u8, extension: Option<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let len = usize::from(bytes[1]);
        let end = 2 + len;
        if bytes[0] != id || extension.is_some_and(|ext| bytes.get(2) != Some(&ext)) {
            out.extend_from_slice(&bytes[..end]);
        }
        bytes = &bytes[end..];
    }
    out
}
fn smoke_iwl_six_ghz_security_and_missing_mvm_band_api_refuse_before_io() -> TestResult {
    check(|| {
        {
            let six = model();
            let guard = setup(Native::Sc, six, Fault::None)?;
            discover(&guard, six)?;
            let beacon = guard
                .device()
                .state
                .try_lock()
                .ok_or("6GHz negative candidate owner")?
                .beacons[0]
                .clone();
            let local = guard.device().phy;
            let prepare = |beacon: &connection::Beacon, auth: &connection::AuthMethod| {
                super::super::super::six_ghz_station::prepare(
                    beacon,
                    OWN,
                    auth,
                    local,
                    &policy(),
                    None,
                )
            };
            require(
                prepare(&beacon, &connection::AuthMethod::Open).is_err()
                    && prepare(&beacon, &connection::AuthMethod::Wpa2Psk(PMK)).is_err(),
                "6GHz admitted Open/WPA2",
            )?;
            let auth = connection::AuthMethod::Wpa3Sae {
                password: PASSWORD.to_vec(),
            };
            let mut bad = beacon.clone();
            bad.information_elements = without(&beacon.information_elements, 244, None);
            require(prepare(&bad, &auth).is_err(), "6GHz admitted HNP-only peer")?;
            let mut bad = beacon.clone();
            bad.information_elements = without(&beacon.information_elements, 255, Some(59));
            require(
                prepare(&bad, &auth).is_err(),
                "6GHz admitted missing band capability",
            )?;
            let mut bad = beacon.clone();
            bad.information_elements.extend_from_slice(&[45, 26]);
            bad.information_elements.extend_from_slice(&[0; 26]);
            require(
                prepare(&bad, &auth).is_err(),
                "6GHz admitted HT/VHT fallback",
            )?;
            let mut bad = beacon.clone();
            let mut rsn = narf_wireless::rsn::RsnIe::decode_body(beacon.rsn.as_deref().unwrap())
                .ok_or("6GHz authored RSNE")?;
            rsn.rsn_capabilities &= !(narf_wireless::rsn::RSN_CAP_MFP_CAPABLE
                | narf_wireless::rsn::RSN_CAP_MFP_REQUIRED);
            let body = rsn.encode_body();
            bad.rsn = Some(body.clone());
            bad.information_elements = without(&beacon.information_elements, 48, None);
            bad.information_elements
                .extend_from_slice(&[48, body.len() as u8]);
            bad.information_elements.extend_from_slice(&body);
            require(prepare(&bad, &auth).is_err(), "6GHz admitted absent PMF")?;
            require(
                HARNESS.lock().as_ref().unwrap().1.air.is_empty(),
                "6GHz invalid security emitted native TX",
            )?;
        }
        let mut six = model();
        six.api59 = false;
        let guard = setup(Native::Mvm, six, Fault::None)?;
        let before = HARNESS.lock().as_ref().unwrap().1.commands.len();
        require(
            run(guard.device().scan(scan(six)), service)?.is_err(),
            "MVM admitted6GHz without actual API59",
        )?;
        require(
            HARNESS.lock().as_ref().unwrap().1.commands.len() == before
                && guard.device().six_channels.is_empty(),
            "MVM absent API59 performed native6GHz I/O",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_security_and_missing_mvm_band_api_refuse_before_io
);

fn smoke_iwl_six_ghz_tpe_psd_and_current_host_nvm_mcc_ap_type_bounds() -> TestResult {
    check(|| {
        cdb_fifo_bounds()?;
        let power = six_ghz_power::Constraints::parse(
            PowerType6Ghz::Sp,
            &[195, 2, 0, 20, 195, 2, 16, 18, 195, 2, 8, 2, 195, 2, 24, 0],
        )?;
        require(
            power.command()[2..5] == [1, 0, 18]
                && power.command()[9..25] == [0; 16]
                && six_ghz_power::Constraints::parse(PowerType6Ghz::Lpi, &[195, 2, 8, 128])
                    .is_err(),
            "6GHz TPE EIRP/PSD intersection or prohibited PSD",
        )?;
        let ignored = six_ghz_power::Constraints::parse(PowerType6Ghz::Vlp, &[195, 2, 64, 0])?;
        require(
            ignored.command()[2..4] == [2, 0] && ignored.command()[4..25] == [127; 21],
            "6GHz Intel subordinate TPE category",
        )?;
        for (regulatory, bit, nvm) in [(1, 14, false), (2, 13, false), (1, 14, true), (2, 13, true)]
        {
            let mut six = model();
            six.regulatory = regulatory;
            if nvm {
                six.nvm_flags &= !(1 << bit);
            } else {
                six.mcc_flags &= !(1 << bit);
            }
            let guard = setup(Native::Sc, six, Fault::None)?;
            discover(&guard, six)?;
            require(
                run(
                    guard
                        .device()
                        .associate_in_domain(request_six(six), &policy()),
                    service,
                )?
                .is_err(),
                "6GHz AP type exceeded NVM/MCC client facts",
            )?;
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            require(
                wire.air.is_empty()
                    && wire.keys == 0
                    && !wire.commands.iter().any(|(g, c, _)| (*g, *c) == (1, 8)),
                "6GHz prohibited AP type reached PHY/key/TX",
            )?;
        }
        let six = model();
        let guard = setup(Native::Sc, six, Fault::None)?;
        discover(&guard, six)?;
        let mut denied = policy();
        denied.rules.push(RegRule {
            freq_start_mhz: 5970,
            freq_end_mhz: 5980,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::NO_IR,
        });
        guard.policy_db.install(denied.clone());
        require(
            run(
                guard
                    .device()
                    .associate_in_domain(request_six(six), &denied),
                service,
            )?
            .is_err(),
            "6GHz host overlap NO_IR hidden by covering rule",
        )?;
        require(
            HARNESS.lock().as_ref().unwrap().1.air.is_empty(),
            "6GHz host-prohibited native TX",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_tpe_psd_and_current_host_nvm_mcc_ap_type_bounds
);

fn inject_data(frame: &[u8], band: u8, channel: u8, rate: u32, pn: u64) {
    let mut mac = vec![0; 30];
    mac[0] = 0x88;
    mac[1] = 0xc2;
    mac[4..10].copy_from_slice(&OWN);
    mac[10..16].copy_from_slice(&AP);
    mac[16..22].copy_from_slice(&AP);
    mac[22..24].copy_from_slice(&((pn as u16) << 4).to_le_bytes());
    mac[26] = 3;
    mac.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    mac.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    mac.extend_from_slice(&frame[12..]);
    let mut payload = vec![0; 64];
    payload[..2].copy_from_slice(&(mac.len() as u16).to_le_bytes());
    payload[7] = band << 6;
    payload[12..16].copy_from_slice(&0x243u32.to_le_bytes());
    payload[16..20].copy_from_slice(&(127u32 << 24).to_le_bytes());
    payload[36..40].copy_from_slice(&rate.to_le_bytes());
    payload[40] = 50;
    payload[42] = channel;
    payload.extend_from_slice(&mac);
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &payload);
}
fn smoke_iwl_six_ghz_wrong_rfh_band_and_format_do_not_consume_same_pn() -> TestResult {
    check(|| {
        for native in [Native::Sc, Native::Mvm, Native::Bz] {
            let six = model();
            let guard = setup(native, six, Fault::None)?;
            join(&guard, six)?;
            let frame = udp_ipv4(
                OWN,
                AP,
                NETWORK.server_ip,
                NETWORK.lease_ip,
                12000,
                12001,
                b"six-band-pn",
            );
            let pn = HARNESS.lock().as_ref().unwrap().1.next_pn + 100;
            for (band, channel, rate) in [
                (1, 5, 0x400),
                (0, 5, 0x400),
                (2, 6, 0x400),
                (2, 5, 0x300),
                (2, 5, 0x400 | (1 << 11)),
            ] {
                inject_data(&frame, band, channel, rate, pn);
                flush()?;
            }
            require(
                !HARNESS.lock().as_ref().unwrap().1.received.contains(&frame),
                "6GHz wrong band/rate escaped or consumed PN",
            )?;
            inject_data(&frame, 2, 5, 0x400, pn);
            flush()?;
            inject_data(&frame, 2, 5, 0x400, pn);
            flush()?;
            require(
                HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .received
                    .iter()
                    .filter(|f| **f == frame)
                    .count()
                    == 1,
                "6GHz original PN lost to alias/rate or valid replay escaped",
            )?;
            close(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_wrong_rfh_band_and_format_do_not_consume_same_pn
);

fn smoke_iwl_six_ghz_held_ap_power_tightening_and_dropped_policy_owner_close_tx() -> TestResult {
    check(|| {
        queued_tpe_blocks_native_data(false)?;
        queued_tpe_blocks_native_data(true)?;
        credit_poll_copies_stricter_tpe_before_publication()?;
        for drop_waiter in [false, true] {
            let six = model();
            let guard = setup(Native::Sc, six, Fault::HoldSixPower)?;
            discover(&guard, six)?;
            let domain = policy();
            let mut future = Some(Box::pin(
                guard
                    .device()
                    .associate_in_domain(request_six(six), &domain),
            ));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..256 {
                require(
                    future.as_mut().unwrap().as_mut().poll(&mut cx).is_pending(),
                    "6GHz held AP power receipt escaped",
                )?;
                service()?;
                if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                    break;
                }
            }
            require(
                HARNESS.lock().as_ref().unwrap().1.air.is_empty(),
                "6GHz emitted TX before AP power receipt",
            )?;
            if drop_waiter {
                drop(future.take());
                let mut denied = policy();
                denied.rules[0].flags = RegFlags::NO_IR;
                guard.policy_db.install(denied);
            } else {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let mut stricter = six;
                stricter.tpe = 10;
                let mut beacon = wire.ap.beacon();
                complete_ap_frame(&mut beacon, stricter)?;
                wire.mpdu(&beacon, false);
            }
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let (cmd, group, sequence) = wire
                    .held
                    .take()
                    .ok_or("6GHz held AP power command missing")?;
                require((group, cmd) == (4, 0xc), "6GHz held another power command")?;
                wire.fault = Fault::None;
                wire.firmware.inject(cmd, group, sequence, &[]);
            }
            if !drop_waiter {
                require(
                    run(future.take().unwrap(), service)?.is_err(),
                    "6GHz tightened AP TPE retained old emission",
                )?;
            } else {
                for _ in 0..32 {
                    service()?;
                    drain();
                }
            }
            carrier(guard.device(), false)?;
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("6GHz held power owner retained lock")?;
            require(
                state.needs_reset
                    && state.hardware.is_failed()
                    && model::retained(&state.hardware).1 != 0,
                "6GHz failed power owner released uncertain DMA",
            )?;
            drop(state);
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            require(
                wire.air.is_empty() && wire.keys == 0 && wire.data.is_empty(),
                "6GHz held power loss escaped TX/key/port fence",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz",
    smoke_iwl_six_ghz_held_ap_power_tightening_and_dropped_policy_owner_close_tx
);
