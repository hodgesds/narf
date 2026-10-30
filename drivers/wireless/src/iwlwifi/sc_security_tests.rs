//! Actual Sc Device -> retained control -> native key/RX receipts -> RSNA.
//! FakeAp independently verifies the association RSNE and four-way MIC/KDF.
use super::*;
use narf_wifi_fixtures::{ApPmf, ApSaePwe};

const IGTK: [u8; 16] = [0x6b; 16];
const IPN: u64 = 0x0102_0304_0506;
const PASSWORD: &[u8] = b"Sc-native-SAE-password";

fn psk_ap(akm: u8) -> R<FakeAp> {
    FakeAp::wpa2(NETWORK, SSID, 6, 7, PMK, ANONCE)
        .and_then(|ap| ap.with_pmf(ApPmf::Required))
        .and_then(|ap| ap.with_akms(&[akm]))
        .and_then(|ap| ap.with_igtk(IGTK, 5, IPN))
        .map_err(|_| "Sc PMF peer setup")
}
fn sae_ap(akm: u8, pwe: ApSaePwe) -> R<FakeAp> {
    FakeAp::wpa3_sae(NETWORK, SSID, 6, 7, PASSWORD, pwe, ANONCE)
        .and_then(|ap| ap.with_akms(&[akm]))
        .and_then(|ap| ap.with_igtk(IGTK, 5, IPN))
        .map_err(|_| "Sc SAE peer setup")
}
fn install_ap(ap: FakeAp) {
    HARNESS.lock().as_mut().unwrap().1.ap = ap;
}
fn tick() {
    let _ = drain();
    narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        2_000_000,
    )));
}
fn until(mut condition: impl FnMut() -> bool) -> R {
    let deadline = narf_time::Deadline::after_ms(1500);
    loop {
        tick();
        if let Some(error) = HARNESS.lock().as_ref().unwrap().1.error {
            return Err(error);
        }
        if condition() {
            return Ok(());
        }
        if deadline.expired() {
            return Err("Sc native security progress bound");
        }
    }
}
fn associate(guard: &Guard, sae: bool) -> R {
    let mut request = request(true);
    if sae {
        request.security = narf_wireless::SecurityConfig::Wpa3 {
            password: PASSWORD.to_vec(),
        };
    }
    scan(guard.device())?;
    run(
        guard.device().associate_in_domain(request, &policy()),
        service,
    )?
    .map_err(|_| "Sc negotiated native security association")?;
    carrier(guard.device(), true)
}
fn native_keys(akm: u8) -> R {
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    require(
        wire.ap.akm().is_some_and(|km| km.suite_type() == akm)
            && wire.ap.pmf()
            && wire.m4
            && wire.keys == 3,
        "Sc negotiated AKM/PMF or native M4 ownership mismatch",
    )?;
    let keys: Vec<_> = wire
        .commands
        .iter()
        .filter(|(g, c, _)| (*g, *c) == (5, 0x18))
        .map(|(_, _, body)| body.as_slice())
        .collect();
    require(
        keys.len() == 3
            && word(keys[0], 8) == 0
            && word(keys[0], 12) == 0x22
            && word(keys[1], 8) == 1
            && word(keys[1], 12) == 0x4a
            && word(keys[2], 8) == 5
            && word(keys[2], 12) == 0x6a
            && keys[2][16..32] == IGTK
            && keys[2][64..72] == IPN.to_le_bytes(),
        "Sc native PTK/GTK/IGTK flags, identity or authenticated replay floor",
    )?;
    require(
        wire.commands
            .iter()
            .filter(|(g, c, _)| (*g, *c) == (3, 10))
            .all(|(_, _, body)| word(body, 36) == 1),
        "Sc PMF peer lacked native MFP configuration",
    )
}
fn data_after_keys(guard: &Guard) -> R {
    let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
        .map_err(|_| "Sc PMF actual DHCP failed")?;
    require(NETWORK.matches_lease(&lease), "Sc PMF lease terms")?;
    let ethernet = udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        7,
        49152,
        b"Sc negotiated security",
    );
    HARNESS.lock().as_mut().unwrap().1.ethernet(&ethernet);
    flush()?;
    require(
        HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .received
            .contains(&ethernet),
        "Sc negotiated protected IP delivery",
    )
}
fn robust_mpdu(subtype: u8, pn: u64, status: u32, body: &[u8]) {
    let mut frame = vec![0; 24];
    frame[0] = subtype;
    frame[1] = 0x40;
    frame[4..10].copy_from_slice(&OWN);
    frame[10..16].copy_from_slice(&AP);
    frame[16..22].copy_from_slice(&AP);
    frame.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    frame.extend_from_slice(body);
    let mut payload = vec![0; 64];
    payload[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    payload[12..16].copy_from_slice(&status.to_le_bytes());
    payload[40] = 50;
    payload[42] = 6;
    payload.extend_from_slice(&frame);
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &payload);
}
fn replay_floor_and_disconnect(guard: &Guard) -> R {
    // The actual CCM verdict admits an SA Query and its native protected
    // reply. A subsequent replay in the management PN domain and a
    // Protected-bit forgery with a bad MIC must preserve the station.
    robust_mpdu(0xd0, 9, 0x247, &[8, 0, 0x91, 0x7c]);
    until(|| HARNESS.lock().as_ref().unwrap().1.sa_query_reply == Some([8, 1, 0x91, 0x7c]))?;
    robust_mpdu(0xc0, 9, 0x247, &[3, 0]);
    robust_mpdu(0xc0, 10, 0x207, &[3, 0]);
    // A valid MIC for a different explicitly reported native station also
    // cannot tear down station0, regardless of the copied AP MAC header.
    robust_mpdu(0xc0, 10, 0x0100_0247, &[3, 0]);
    for _ in 0..8 {
        tick();
    }
    carrier(guard.device(), true)?;
    // Authored valid BIP at exactly the KDE floor must be dropped even
    // though this is the first robust frame delivered by the fixture.
    let mut header = vec![0; 24];
    header[0] = 0xc0;
    header[4..10].fill(255);
    header[10..16].copy_from_slice(&AP);
    header[16..22].copy_from_slice(&AP);
    let mut key =
        narf_crypto::bip_cmac::Igtk::install(IGTK, 5).map_err(|_| "Sc fixture BIP key")?;
    key.tx_pn = IPN - 1;
    let mut body = 3u16.to_le_bytes().to_vec();
    narf_wireless::mfp::protect_outbound(&mut key, &header, &mut body)
        .map_err(|_| "Sc fixture BIP MIC")?;
    header.extend_from_slice(&body);
    HARNESS.lock().as_mut().unwrap().1.mpdu(&header, false);
    for _ in 0..8 {
        tick();
    }
    carrier(guard.device(), true)?;
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    let valid = wire
        .ap
        .bip_broadcast_deauth(3)
        .map_err(|_| "Sc AP BIP deauth")?;
    wire.mpdu(&valid, false);
    drop(slot);
    until(|| !guard.device().link_up())
}

fn smoke_sc_native_psk_pmf_akm2_6_key_receipts_and_kde_ipn() -> TestResult {
    check(|| {
        for akm in [2, 6] {
            let guard = Guard::new(true, Fault::None)?;
            install_ap(psk_ap(akm)?);
            associate(&guard, false)?;
            native_keys(akm)?;
            data_after_keys(&guard)?;
            replay_floor_and_disconnect(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/security",
    smoke_sc_native_psk_pmf_akm2_6_key_receipts_and_kde_ipn
);

fn smoke_sc_native_sae_ext_key_full_commit_mic_pmf_and_legacy_sae() -> TestResult {
    check(|| {
        for (akm, pwe) in [
            (24, ApSaePwe::HashToElement),
            (8, ApSaePwe::HashToElement),
            (8, ApSaePwe::HuntAndPeck),
        ] {
            let guard = Guard::new(true, Fault::None)?;
            install_ap(sae_ap(akm, pwe)?);
            HARNESS.lock().as_mut().unwrap().1.sae_h2e_only = akm == 24;
            associate(&guard, true)?;
            native_keys(akm)?;
            data_after_keys(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/security",
    smoke_sc_native_sae_ext_key_full_commit_mic_pmf_and_legacy_sae
);

fn smoke_sc_sae_ext_key_wrong_peer_selector_never_installs_native_keys() -> TestResult {
    check(|| {
        let guard = Guard::new(true, Fault::WrongSaeSelector)?;
        install_ap(sae_ap(24, ApSaePwe::HashToElement)?);
        scan(guard.device())?;
        let mut request = request(true);
        request.security = narf_wireless::SecurityConfig::Wpa3 {
            password: PASSWORD.to_vec(),
        };
        require(
            run(
                guard.device().associate_in_domain(request, &policy()),
                service,
            )?
            .is_err(),
            "Sc accepted SAE-EXT-KEY under a different AP suite selector",
        )?;
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        require(
            wire.security_fault_applied && wire.keys == 0 && !wire.m4 && !guard.device().link_up(),
            "Sc selector failure did not precede native keys/M4/carrier",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/security",
    smoke_sc_sae_ext_key_wrong_peer_selector_never_installs_native_keys
);

fn smoke_sc_pmf_held_native_igtk_revocation_retains_dma_and_closed_port() -> TestResult {
    check(|| {
        for which in 0..3 {
            let (firmware, pnvm) = super::super::super::runtime::source::tests::inputs()?;
            let guard = Guard::build_named(true, Fault::HoldIgtk, None, Some((&firmware, &pnvm)))?;
            install_ap(psk_ap(6)?);
            scan(guard.device())?;
            let domain = policy();
            let mut future = Box::pin(guard.device().associate_in_domain(request(true), &domain));
            let deadline = narf_time::Deadline::after_ms(3000);
            loop {
                require(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending(),
                    "Sc PMF association passed held IGTK receipt",
                )?;
                service()?;
                if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                    break;
                }
                if deadline.expired() {
                    return Err("Sc held IGTK did not publish");
                }
                narf_scheduler::sleep_pumps::run();
            }
            carrier(guard.device(), false)?;
            if which == 0 {
                firmware.cap.revoke();
            } else if which == 1 {
                pnvm.cap.revoke();
            } else {
                guard.device().source.revoke_model_pci();
            }
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let (cmd, group, sequence) = wire.held.take().ok_or("Sc held IGTK absent")?;
                require(
                    (group, cmd) == (5, 0x18),
                    "Sc held foreign security command",
                )?;
                wire.fault = Fault::None;
                wire.firmware.inject(cmd, group, sequence, &[]);
            }
            require(
                run(future.as_mut(), service)?.is_err(),
                "Sc revoked IGTK published station",
            )?;
            drop(future);
            guard.device().step(None);
            carrier(guard.device(), false)?;
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("Sc revoked security cleanup retained state")?;
            require(
                state.needs_reset
                    && state.stop_completed
                    && model::retained(&state.hardware).0 > 0
                    && !HARNESS.lock().as_ref().unwrap().1.m4,
                "Sc uncertain IGTK DMA was released or M4/carrier reopened after revoke",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/security",
    smoke_sc_pmf_held_native_igtk_revocation_retains_dma_and_closed_port
);

fn smoke_sc_pmf_native_m4_keeps_closed_copies_out_of_successor_epoch() -> TestResult {
    check(|| {
        let guard = Guard::new(true, Fault::HoldM4)?;
        install_ap(psk_ap(6)?);
        scan(guard.device())?;
        let domain = policy();
        let mut future = Box::pin(guard.device().associate_in_domain(request(true), &domain));
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "Sc PMF fixture passed held M4 TX",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held_tx.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("Sc PMF did not reach held M4");
            }
            narf_scheduler::sleep_pumps::run();
        }
        carrier(guard.device(), false)?;
        let frame = udp_ipv4(
            OWN,
            AP,
            NETWORK.server_ip,
            NETWORK.lease_ip,
            7,
            49152,
            b"Sc PMF closed copy",
        );
        let before = {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let before = wire.next_pn;
            wire.ethernet(&frame);
            before
        };
        for _ in 0..2 {
            narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                2_000_000,
            )));
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "Sc PMF closed copy completed held M4",
            )?;
            service()?;
        }
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (queue, pointer) = wire.held_tx.take().ok_or("Sc PMF held TX missing")?;
            wire.fault = Fault::None;
            wire.firmware.tx_complete(queue, pointer);
        }
        run(future.as_mut(), service)?.map_err(|_| "Sc PMF M4/RX admission failed")?;
        drop(future);
        flush()?;
        require(
            HARNESS.lock().as_ref().unwrap().1.received.is_empty(),
            "Sc PMF pre-M4 native copy escaped after controlled-port admission",
        )?;
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            wire.next_pn = before;
            wire.ethernet(&frame);
        }
        flush()?;
        require(
            HARNESS.lock().as_ref().unwrap().1.received.as_slice() == [frame],
            "Sc PMF closed copy consumed a successor key PN",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/security",
    smoke_sc_pmf_native_m4_keeps_closed_copies_out_of_successor_epoch
);

/// Authenticator Group Message1 under the actual AKM2 exchange's KCK/KEK.
/// Replay counters always advance even when retired key material is offered.
fn rotation(gtk: (u8, [u8; 16]), igtk: Option<([u8; 16], u16, u64)>, counter: u64) -> R {
    use narf_wireless::eapol::KeyFrame;
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    let ptk = wire.ptk.as_ref().ok_or("Sc rotation actual PTK absent")?;
    let mut clear = vec![221, 22, 0, 15, 172, 1, gtk.0, 0];
    clear.extend_from_slice(&gtk.1);
    if let Some((material, id, pn)) = igtk {
        clear.extend_from_slice(&[221, 28, 0, 15, 172, 9]);
        clear.extend_from_slice(&id.to_le_bytes());
        clear.extend_from_slice(&pn.to_le_bytes()[..6]);
        clear.extend_from_slice(&material);
        clear.push(221);
        while clear.len() % 8 != 0 {
            clear.push(0);
        }
    }
    let mut challenge = KeyFrame::empty(16);
    challenge.key_information = 0x1382;
    challenge.key_length = 16;
    challenge.replay_counter = counter;
    challenge.key_data = narf_crypto::aes_kw::aes_wrap(
        ptk.kek
            .as_slice()
            .try_into()
            .map_err(|_| "Sc rotation KEK extent")?,
        &clear,
    )
    .ok_or("Sc rotation AES wrap")?;
    super::super::super::handshake::install_mic(&mut challenge, &ptk.kck);
    let mut ethernet = OWN.to_vec();
    ethernet.extend_from_slice(&AP);
    ethernet.extend_from_slice(&[0x88, 0x8e]);
    ethernet.extend_from_slice(&challenge.into_eapol());
    wire.igtk_expected = igtk;
    wire.gtk_expected = Some(gtk);
    wire.group_rekey = true;
    wire.group_replay = counter;
    wire.group_reply = false;
    wire.ethernet(&ethernet);
    Ok(())
}
fn key_commands() -> usize {
    HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .commands
        .iter()
        .filter(|(group, command, _)| (*group, *command) == (5, 0x18))
        .count()
}
fn acknowledged_rotation(
    gtk: (u8, [u8; 16]),
    igtk: Option<([u8; 16], u16, u64)>,
    counter: u64,
) -> R {
    rotation(gtk, igtk, counter)?;
    until(|| HARNESS.lock().as_ref().unwrap().1.group_reply)
}
fn initial_history_ap() -> R<FakeAp> {
    psk_ap(2)?
        .with_igtk([0xa1; 16], 4, 10)
        .map_err(|_| "Sc native history IGTK")
}
fn smoke_sc_native_igtk_multiple_rotations_reject_retired_material_before_remove_add() -> TestResult
{
    check(|| {
        let guard = Guard::new(true, Fault::None)?;
        install_ap(initial_history_ap()?);
        associate(&guard, false)?;
        acknowledged_rotation((1, [0x77; 16]), Some(([0xb2; 16], 5, 20)), 3)?;
        // A higher authenticated EAPOL counter with identical live material
        // must not reinstall it or lower its already adopted IPN floor.
        let before = key_commands();
        acknowledged_rotation((1, [0x77; 16]), Some(([0xb2; 16], 5, 0)), 4)?;
        require(key_commands() == before, "Sc same-live IGTK reinstalled")?;
        let mut header = vec![0; 24];
        header[0] = 0xc0;
        header[4..10].fill(255);
        header[10..16].copy_from_slice(&AP);
        header[16..22].copy_from_slice(&AP);
        let mut key = narf_crypto::bip_cmac::Igtk::install([0xb2; 16], 5)
            .map_err(|_| "Sc BIP rotation key")?;
        key.tx_pn = 19;
        let mut body = vec![3, 0];
        narf_wireless::mfp::protect_outbound(&mut key, &header, &mut body)
            .map_err(|_| "Sc BIP rotation MIC")?;
        header.extend_from_slice(&body);
        HARNESS.lock().as_mut().unwrap().1.mpdu(&header, false);
        for _ in 0..4 {
            tick();
        }
        carrier(guard.device(), true)?;
        acknowledged_rotation((1, [0x77; 16]), Some(([0xc3; 16], 4, 30)), 5)?;
        acknowledged_rotation((1, [0x77; 16]), Some(([0xd4; 16], 5, 40)), 6)?;
        let before = key_commands();
        rotation((1, [0x77; 16]), Some(([0xa1; 16], 4, 1)), 7)?;
        until(|| !guard.device().link_up())?;
        require(
            key_commands() == before && !HARNESS.lock().as_ref().unwrap().1.group_reply,
            "Sc retired IGTK returned with native REMOVE/ADD or an authenticated reply",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/security",
    smoke_sc_native_igtk_multiple_rotations_reject_retired_material_before_remove_add
);

fn smoke_sc_native_gtk_overwritten_slots_reject_retired_material_before_native_mutation(
) -> TestResult {
    check(|| {
        let guard = Guard::new(true, Fault::None)?;
        install_ap(initial_history_ap()?);
        associate(&guard, false)?;
        acknowledged_rotation((2, [0x88; 16]), None, 3)?;
        acknowledged_rotation((1, [0x89; 16]), None, 4)?;
        acknowledged_rotation((2, [0x8a; 16]), None, 5)?;
        let before = key_commands();
        rotation((1, [0x77; 16]), None, 6)?;
        until(|| !guard.device().link_up())?;
        require(
            key_commands() == before && !HARNESS.lock().as_ref().unwrap().1.group_reply,
            "Sc overwritten retired GTK returned with reset PN/native key mutation",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/security",
    smoke_sc_native_gtk_overwritten_slots_reject_retired_material_before_native_mutation
);
