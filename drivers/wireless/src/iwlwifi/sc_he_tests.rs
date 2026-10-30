//! Authored NVM/firmware/AP HE facts traverse the real Sc Device, native
//! TFH/RFH, key receipts, CCMP replay owner, IPC and kernel DHCP stack.
use super::*;
use narf_wifi_fixtures::ApSaePwe;
const PASSWORD: &[u8] = b"Sc-native-SAE-password";
const IGTK: [u8; 16] = [0x6b; 16];
const IPN: u64 = 0x0102_0304_0506;

pub(super) fn versions(table: &mut Vec<u8>, rates: u8) {
    table.extend_from_slice(&[0x1c, 0, if rates == 3 { 11 } else { 10 }, 0]);
    table.extend_from_slice(&[0xf7, 5, 0, if rates == 3 { 4 } else { 3 }]);
    table.extend_from_slice(&[0xc1, 0, 0, if rates == 3 { 6 } else { 5 }]);
    table.extend_from_slice(&[0x1c, 1, 0, if rates == 3 { 9 } else { 8 }]);
    if rates == 3 {
        table.extend_from_slice(&[0xf5, 5, 0, 4]);
    }
}

pub(super) fn policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![
            RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2482,
                max_bandwidth_mhz: 40,
                max_power_dbm: 17,
                flags: RegFlags::empty(),
            },
            RegRule {
                freq_start_mhz: 5170,
                freq_end_mhz: 5250,
                max_bandwidth_mhz: 80,
                max_power_dbm: 17,
                flags: RegFlags::empty(),
            },
        ],
    }
}

/// Independently authored IEEE elements: HT20/40, VHT80 on5GHz, HE MCS0..7,
/// HTC_HE, no TWT/beamforming/PPE, explicit UORA and ACI-indexed MU EDCA.
pub(super) fn elements(phy: PhyModel, include_he: bool) -> Vec<u8> {
    let channel = phy.channel();
    let mut ht = [0; 26];
    ht[..2].copy_from_slice(&0x6eu16.to_le_bytes());
    ht[2] = 3 | (4 << 2);
    ht[3..3 + usize::from(phy.streams)].fill(255);
    ht[15] = 1;
    let mut out = vec![45, 26];
    out.extend_from_slice(&ht);
    let mut operation = [0; 22];
    operation[0] = channel;
    if phy.width != 0 {
        operation[1] = 5;
    }
    operation[6] = 255;
    out.extend_from_slice(&[61, 22]);
    out.extend_from_slice(&operation);
    if channel > 14 {
        let mut vht = [0; 12];
        vht[..4].copy_from_slice(&((1u32 << 5) | (3 << 23)).to_le_bytes());
        let map = if phy.streams == 2 { 0xfff0u16 } else { 0xfffc };
        vht[4..6].copy_from_slice(&map.to_le_bytes());
        vht[8..10].copy_from_slice(&map.to_le_bytes());
        out.extend_from_slice(&[191, 12]);
        out.extend_from_slice(&vht);
        out.extend_from_slice(&[192, 5, 1, 42, 0, 0xfc, 0xff]);
    }
    out.extend_from_slice(&super::super::super::qos::INFORMATION_IE);
    if include_he {
        let mut he = vec![
            35,
            1,
            0,
            0x20,
            0,
            0,
            0,
            if channel <= 14 { 2 } else { 4 },
            0x30,
            10,
            0,
            0,
            0,
            0,
            4,
            1,
            0x30,
            0,
        ];
        let map = if phy.streams == 2 { 0xfff0u16 } else { 0xfffc };
        he.extend_from_slice(&map.to_le_bytes());
        he.extend_from_slice(&map.to_le_bytes());
        out.extend_from_slice(&[255, he.len() as u8]);
        out.extend_from_slice(&he);
        out.extend_from_slice(&[255, 7, 36, 0xf2, 0x3f, 0, 7, 0xfc, 0xff]);
        out.extend_from_slice(&[255, 2, 37, 0x19]);
        out.extend_from_slice(&[
            255, 14, 38, 0, 3, 0xa4, 5, 0x23, 0xa4, 6, 0x43, 0x43, 7, 0x63, 0x32, 8,
        ]);
    }
    out
}
fn config(width: u8, streams: u8, rates: u8) -> PhyModel {
    PhyModel {
        width,
        streams,
        rates,
        mcc_he: true,
        response_he: true,
    }
}
fn setup(phy: PhyModel, secured: bool, fault: Fault) -> R<Guard> {
    Guard::build(secured, fault, None, None, Some(phy))
}
fn request_for(phy: PhyModel, secured: bool) -> AssociateRequest {
    let mut req = request(secured);
    req.channel = u32::from(phy.channel());
    req.frequency_mhz =
        if phy.channel() <= 14 { 2407 } else { 5000 } + 5 * u32::from(phy.channel());
    req
}
fn discover(guard: &Guard, phy: PhyModel, active: bool) -> R {
    let mut req = scan_request();
    req.channels = vec![u32::from(phy.channel())];
    req.frequencies_mhz =
        vec![if phy.channel() <= 14 { 2407 } else { 5000 } + 5 * u32::from(phy.channel())];
    req.active = active;
    let found = run(guard.device().scan(req), service)?.map_err(|_| "Sc HE native scan failed")?;
    if active {
        probe(phy)?;
    }
    require(
        found.len() == 1 && found[0].channel == u32::from(phy.channel()),
        "Sc HE actual BSS identity",
    )
}
fn probe(phy: PhyModel) -> R {
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    let scan = &wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (1, 0xd))
        .ok_or("Sc HE active scan command absent")?
        .2;
    let at = 48 + 68 * 8 + 12;
    let descriptor = if phy.channel() <= 14 { 4 } else { 8 };
    let offset = usize::from(half(scan, at + descriptor));
    let length = usize::from(half(scan, at + descriptor + 2));
    let facts = narf_wireless::association::phy::ApElements::parse(
        &scan[at + 20 + offset..at + 20 + offset + length],
    )
    .map_err(|_| "Sc active probe actual IE segment extent")?;
    require(
        facts.he_capability().is_some() == phy.mcc_he,
        "Sc active probe HE facts differ from current MCC admission",
    )
}
fn beacon(phy: PhyModel, changed: bool) {
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    let mut frame = wire.ap.beacon();
    let mut ies = elements(phy, true);
    if changed {
        let mut at = 0;
        while at < ies.len() {
            if ies[at] == 255 && ies[at + 2] == 36 {
                ies[at + 6] = 8;
                break;
            }
            at += 2 + usize::from(ies[at + 1]);
        }
    }
    frame.extend_from_slice(&ies);
    if wire.sae_h2e_only {
        frame.extend_from_slice(&[50, 1, 0xfb]);
    }
    wire.mpdu(&frame, false);
}
fn join(guard: &Guard, _phy: PhyModel, req: AssociateRequest) -> R {
    run(guard.device().associate_in_domain(req, &policy()), service)?
        .map_err(|_| "Sc HE native association failed")?;
    carrier(guard.device(), true)
}
fn native_context(phy: PhyModel, expected_he: bool) -> R {
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    let tlc = wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (5, 0xf))
        .ok_or("Sc HE TLC absent")?;
    let sta = wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (3, 10))
        .ok_or("Sc HE STA absent")?;
    let link = wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (3, 9))
        .ok_or("Sc HE LINK absent")?;
    let mac = wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (3, 8))
        .ok_or("Sc HE MAC absent")?;
    let req = wire
        .phy_requests
        .last()
        .ok_or("Sc HE association request absent")?;
    let offered = narf_wireless::association::phy::ApElements::parse(&req[28..])
        .map_err(|_| "Sc HE emitted request extent")?;
    require(
        offered.he_capability().is_some() == expected_he,
        "Sc HE request ignored actual native/NVM/MCC admission",
    )?;
    if !expected_he {
        return require(
            tlc.2[9] != 3 && word(&sta.2, 92) == 0,
            "Sc forbidden HE programmed native contexts",
        );
    }
    require(
        mac.2[24..32] == [1, 0, 0, 0, 0, 0, 0, 0] && word(&mac.2, 32) == 1,
        "Sc HE MAC3 generation/non-ACK owner",
    )?;
    require(
        tlc.2.len() == 44
            && tlc.2[8] == phy.width
            && tlc.2[9] == 3
            && tlc.2[11] == 0
            && word(&tlc.2, 16) == 255
            && word(&tlc.2, 28) == if phy.streams == 2 { 255 } else { 0 }
            && tlc.2[20..28] == [0; 8]
            && tlc.2[32..40] == [0; 8],
        "Sc HE native TLC width/maps/unsupported160/320",
    )?;
    require(
        sta.2.len() == 104
            && word(&sta.2, 40) == u32::from(phy.streams == 2)
            && word(&sta.2, 52) == 1
            && word(&sta.2, 92) == 1
            && sta.2[72..92] == [7; 20],
        "Sc HE native STA NSS/UORA/PPE/HTC",
    )?;
    require(
        link.2.len() == 208
            && word(&link.2, 24) & 0x60 == 0x60
            && link.2[100] == 2
            && link.2[101] == 1
            && link.2[102] == 3
            && half(&link.2, 146) == 1023
            && word(&link.2, 148) == 2
            && word(&link.2, 152) == 0
            && link.2[165] == 7
            && link.2[104..112] == [4, 0, 10, 0, 3, 0, 6, 0],
        "Sc HE native LINK8 fields or removed flags-mask",
    )
}
fn data(guard: &Guard) -> R {
    let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
        .map_err(|_| "Sc HE actual kernel DORA failed")?;
    require(NETWORK.matches_lease(&lease), "Sc HE native lease terms")?;
    let up = udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        7,
        b"Sc HE uplink",
    );
    narf_net::iface::send_on(guard.device().name(), &up).map_err(|_| "Sc HE uplink admission")?;
    flush()?;
    let down = udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        7,
        49152,
        b"Sc HE downlink",
    );
    HARNESS.lock().as_mut().unwrap().1.ethernet(&down);
    flush()?;
    let delivered = {
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        wire.data
            .iter()
            .any(|(e, p)| e == &up && *p == wire.ap.protected())
            && wire.received.contains(&down)
    };
    require(delivered, "Sc HE native bidirectional IP bytes")
}
fn smoke_sc_he_native_open_wpa2_sae24_he20_40_80_two_streams_and_rate_contracts() -> TestResult {
    check(|| {
        for (phy, security) in [
            (config(0, 1, 2), 0),
            (config(1, 2, 3), 1),
            (config(2, 2, 3), 2),
        ] {
            let guard = setup(phy, security != 0, Fault::None)?;
            let mut req = request_for(phy, security != 0);
            if security == 2 {
                let ap = FakeAp::wpa3_sae(
                    NETWORK,
                    SSID,
                    phy.channel(),
                    7,
                    PASSWORD,
                    ApSaePwe::HashToElement,
                    ANONCE,
                )
                .and_then(|ap| ap.with_akms(&[24]))
                .and_then(|ap| ap.with_igtk(IGTK, 5, IPN))
                .map_err(|_| "Sc HE SAE24 AP configuration")?;
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                wire.ap = ap;
                wire.sae_h2e_only = true;
                req.security = narf_wireless::SecurityConfig::Wpa3 {
                    password: PASSWORD.to_vec(),
                };
            }
            discover(&guard, phy, true)?;
            join(&guard, phy, req)?;
            native_context(phy, true)?;
            data(&guard)?;
            beacon(phy, false);
            flush()?;
            carrier(guard.device(), true)?;
            run(guard.device().disassociate(), service)?.map_err(|_| "Sc HE native teardown")?;
            carrier(guard.device(), false)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/he",
    smoke_sc_he_native_open_wpa2_sae24_he20_40_80_two_streams_and_rate_contracts
);

fn inject_data(phy: PhyModel, frame: &[u8], rate: u32, pn: u64, variant: u8) {
    let mut mac = vec![0; 30];
    mac[0] = 0x88;
    mac[1] = 0xc2;
    mac[4..10].copy_from_slice(&OWN);
    mac[10..16].copy_from_slice(&AP);
    mac[16..22].copy_from_slice(&AP);
    mac[22..24].copy_from_slice(&((pn as u16) << 4).to_le_bytes());
    mac[26] = variant;
    mac.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(pn, 0));
    mac.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0]);
    mac.extend_from_slice(&frame[12..]);
    let mut payload = vec![0; 64];
    payload[..2].copy_from_slice(&(mac.len() as u16).to_le_bytes());
    payload[12..16].copy_from_slice(&0x243u32.to_le_bytes());
    payload[16..20].copy_from_slice(&(127u32 << 24).to_le_bytes()); // Native unaggregated QoS BAID.
    payload[36..40].copy_from_slice(&rate.to_le_bytes());
    payload[40] = 50;
    payload[42] = phy.channel();
    payload.extend_from_slice(&mac);
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xc1, 0, 0x8000, &payload);
}
fn smoke_sc_he_native_htc_rate_nss_width_and_replay_preserve_original_ccmp_offsets() -> TestResult {
    check(|| {
        for rates in [2, 3] {
            let phy = config(0, 1, rates);
            let guard = setup(phy, true, Fault::None)?;
            discover(&guard, phy, false)?;
            join(&guard, phy, request_for(phy, true))?;
            for (index, bad, variant) in [
                (0, 0x400, 1),
                (1, 0x400 | if rates == 3 { 32 } else { 16 }, 3),
                (2, 0x400 | (1 << 11), 3),
                (3, 0x408, 3),
            ] {
                let frame = udp_ipv4(
                    OWN,
                    AP,
                    NETWORK.server_ip,
                    NETWORK.lease_ip,
                    7,
                    49152,
                    &[b'H', index],
                );
                let pn = 100 + u64::from(index);
                inject_data(phy, &frame, bad, pn, variant);
                flush()?;
                require(
                    !HARNESS.lock().as_ref().unwrap().1.received.contains(&frame),
                    "Sc invalid HE header/rate mutated receive owner",
                )?;
                inject_data(phy, &frame, 0x400, pn, 3);
                flush()?;
                let count = HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .received
                    .iter()
                    .filter(|f| **f == frame)
                    .count();
                require(
                    count == 1,
                    "Sc rejected HE copy consumed CCMP PN or original IV offset",
                )?;
                inject_data(phy, &frame, 0x400, pn, 3);
                flush()?;
                let count = HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .received
                    .iter()
                    .filter(|f| **f == frame)
                    .count();
                require(count == 1, "Sc valid HE replay escaped original PN owner")?;
            }
            run(guard.device().disassociate(), service)?.map_err(|_| "Sc HE replay teardown")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/he",
    smoke_sc_he_native_htc_rate_nss_width_and_replay_preserve_original_ccmp_offsets
);

fn smoke_sc_he_native_mcc_prohibition_and_missing_response_do_not_open_he_port() -> TestResult {
    check(|| {
        let mut phy = config(0, 1, 2);
        phy.mcc_he = false;
        {
            let guard = setup(phy, false, Fault::None)?;
            discover(&guard, phy, true)?;
            join(&guard, phy, request_for(phy, false))?;
            native_context(phy, false)?;
            data(&guard)?;
            let no_he_probe = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                let scan = &wire
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (1, 0xd))
                    .unwrap()
                    .2;
                let probe = 48 + 68 * 8 + 12;
                let offset = usize::from(half(scan, probe + 4));
                let len = usize::from(half(scan, probe + 6));
                narf_wireless::association::phy::ApElements::parse(
                    &scan[probe + 20 + offset..probe + 20 + offset + len],
                )
                .map_err(|_| "Sc active probe extent")?
                .he_capability()
                .is_none()
            };
            require(no_he_probe, "Sc active probe advertised MCC-forbidden HE")?;
            run(guard.device().disassociate(), service)?.map_err(|_| "Sc HE fallback teardown")?;
        }
        phy.mcc_he = true;
        {
            let guard = setup(phy, false, Fault::None)?;
            discover(&guard, phy, false)?;
            join(&guard, phy, request_for(phy, false))?;
            beacon(phy, false);
            flush()?;
            carrier(guard.device(), true)?;
            beacon(phy, true);
            flush()?;
            carrier(guard.device(), false)?;
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("Sc changed HE beacon retained owner")?;
            require(
                state.needs_reset,
                "Sc changed HE operation left RF owner live",
            )?;
        }
        phy.response_he = false;
        let guard = setup(phy, true, Fault::None)?;
        discover(&guard, phy, false)?;
        require(
            run(
                guard
                    .device()
                    .associate_in_domain(request_for(phy, true), &policy()),
                service,
            )?
            .is_err(),
            "Sc missing HE response admitted HE owner",
        )?;
        carrier(guard.device(), false)?;
        let safe = {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            !wire.m4 && wire.keys == 0 && wire.data.is_empty()
        };
        require(safe, "Sc unconfirmed HE response escaped key/port fence")?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/he",
    smoke_sc_he_native_mcc_prohibition_and_missing_response_do_not_open_he_port
);

fn inputs(phy: PhyModel) -> R<(crate::firmware_asset::Asset, crate::firmware_asset::Asset)> {
    let (write, read) = narf_firmware::bootstrap_authority();
    let mut bytes = super::super::super::firmware_parser_tests::mld_image();
    let mut table = super::super::super::firmware_parser_tests::mld_commands();
    versions(&mut table, phy.rates);
    require(
        word(&bytes, 88) == 48,
        "Sc HE authored executable table tag",
    )?;
    let old = word(&bytes, 92) as usize;
    bytes.splice(96..96 + old.next_multiple_of(4), table.iter().copied());
    bytes[92..96].copy_from_slice(&(table.len() as u32).to_le_bytes());
    for (name, payload) in [
        ("narf-test/iwl-he/executable", bytes.as_slice()),
        ("narf-test/iwl-he/pnvm", &[9u8; 32][..]),
    ] {
        crate::firmware_asset::tests::install(&write, name, payload, true)
            .map_err(|_| "Sc HE source install")?;
    }
    Ok((
        crate::firmware_asset::load(&read, "narf-test/iwl-he/executable", 16 * 1024 * 1024, true)
            .map_err(|_| "Sc HE executable source")?,
        crate::firmware_asset::load(&read, "narf-test/iwl-he/pnvm", 64, true)
            .map_err(|_| "Sc HE PNVM source")?,
    ))
}
fn smoke_sc_he_native_dropped_waiter_and_held_sta_source_or_policy_loss_pin_dma() -> TestResult {
    check(|| {
        for which in 0..3 {
            let phy = config(0, 1, 2);
            let (firmware, pnvm) = inputs(phy)?;
            let guard = Guard::build(
                true,
                Fault::HoldHe,
                None,
                Some((&firmware, &pnvm)),
                Some(phy),
            )?;
            discover(&guard, phy, false)?;
            let domain = policy();
            let mut future = Box::pin(
                guard
                    .device()
                    .associate_in_domain(request_for(phy, true), &domain),
            );
            let deadline = narf_time::Deadline::after_ms(3000);
            loop {
                require(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending(),
                    "Sc HE association passed held native STA",
                )?;
                service()?;
                if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                    break;
                }
                if deadline.expired() {
                    return Err("Sc HE native STA publication bound");
                }
                narf_scheduler::sleep_pumps::run();
            }
            drop(future); // Device control retains the actual native command owner.
            carrier(guard.device(), false)?;
            if which == 0 {
                firmware.cap.revoke();
            } else if which == 1 {
                pnvm.cap.revoke();
            } else {
                guard.policy_db.install({
                    let mut denied = policy();
                    denied.rules[0].max_power_dbm = 1;
                    denied
                });
            }
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let (cmd, group, sequence) = wire.held.take().ok_or("Sc HE held STA missing")?;
                require(
                    (group, cmd) == (3, 10),
                    "Sc HE held a different native context",
                )?;
                wire.fault = Fault::None;
                wire.firmware.inject(cmd, group, sequence, &[]);
            }
            let deadline = narf_time::Deadline::after_ms(1500);
            loop {
                let _ = drain();
                narf_scheduler::block_on_spin(narf_time::sleep_cycles(
                    narf_time::wall::ns_to_cycles(2_000_000),
                ));
                let done = guard
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|state| state.stop_completed);
                if done {
                    break;
                }
                if deadline.expired() {
                    return Err("Sc HE retained native stop bound");
                }
            }
            carrier(guard.device(), false)?;
            let retained = {
                let state = guard
                    .device()
                    .state
                    .try_lock()
                    .ok_or("Sc HE failed owner retained state")?;
                state.needs_reset && model::retained(&state.hardware).0 > 0
            };
            let closed = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                !wire.m4 && wire.keys == 0 && wire.data.is_empty()
            };
            require(
                retained && closed,
                "Sc HE revoked held context released ambiguous DMA or opened port",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/he",
    smoke_sc_he_native_dropped_waiter_and_held_sta_source_or_policy_loss_pin_dma
);
