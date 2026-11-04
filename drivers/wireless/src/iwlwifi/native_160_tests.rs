//! Actual NVM/MCC/TFH/RFH conversations for the common native160 owner.
use super::super::super::{connection, ht_vht, sc_security, station_api};
use super::*;

pub(super) fn policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5330,
            max_bandwidth_mhz: 160,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    }
}
#[derive(Clone, Copy)]
enum Native {
    Sc,
    Api89,
    Bz,
}
fn phy(native: Native, he: bool) -> PhyModel {
    PhyModel {
        width: 3,
        streams: 2,
        rates: if matches!(native, Native::Api89) {
            2
        } else {
            3
        },
        mcc_he: he,
        response_he: he,
    }
}
#[inline(never)]
fn setup(native: Native, secured: bool, he: bool, fault: Fault) -> R<Box<Guard>> {
    Ok(Box::new(Guard::build_native_profile(
        secured,
        fault,
        None,
        None,
        Some(phy(native, he)),
        NativeModel {
            receive_model: if matches!(native, Native::Api89) {
                ReceiveModel::ExplicitV1
            } else {
                ReceiveModel::NativeSc
            },
            tx_model: None,
            api89: matches!(native, Native::Api89).then_some(gen3_station_tests::Case::SoCdb),
            bz: matches!(native, Native::Bz)
                .then_some(super::super::super::bz_fixture::Case::WhIntegrated),
            six: None,
        },
    )?))
}
fn discover(guard: &Guard) -> R {
    let mut request = scan_request();
    request.channels = vec![36];
    request.frequencies_mhz = vec![5180];
    let found =
        run(guard.device().scan(request), service)?.map_err(|_| "native160 actual passive scan")?;
    require(
        found.len() == 1 && found[0].bssid == AP && found[0].channel == 36,
        "native160 actual RFH BSS identity",
    )
}
fn request_wide(secured: bool) -> AssociateRequest {
    let mut request = request(secured);
    request.channel = 36;
    request.frequency_mhz = 5180;
    request
}
fn join(guard: &Guard, secured: bool, domain: &narf_wireless::reg::RegulatoryDomain) -> R {
    discover(guard)?;
    run(
        guard
            .device()
            .associate_in_domain(request_wide(secured), domain),
        service,
    )?
    .map_err(|_| "native160 actual station association")?;
    carrier(guard.device(), true)
}
fn tlc(native: Native) -> R<Vec<u8>> {
    HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (5, 0xf))
        .map(|(_, _, b)| b.clone())
        .ok_or(if matches!(native, Native::Api89) {
            "native160 API89 TLC missing"
        } else {
            "native160 MLD TLC missing"
        })
}
fn tlc_mcs(native: Native, tlc: &[u8], stream: usize, width: usize) -> u32 {
    if matches!(native, Native::Api89) {
        u32::from(half(tlc, 12 + stream * 6 + width * 2))
    } else {
        word(tlc, 16 + stream * 12 + width * 4)
    }
}
fn wire(native: Native, he: bool, width: u8) -> R {
    let tlc = tlc(native)?;
    let at = if matches!(native, Native::Api89) {
        4
    } else {
        8
    };
    require(
        tlc.len()
            == if matches!(native, Native::Api89) {
                28
            } else {
                44
            }
            && tlc[at] == width
            && tlc[at + 1] == if he { 3 } else { 2 },
        "native160 actual TLC ABI/mode/width",
    )?;
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    let body = &wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (1, 8))
        .ok_or("native160 PHY missing")?
        .2;
    require(
        body.len() == 32
            && body[13] == width
            && body[14] == if width == 3 { 3 } else { 1 }
            && body[28] == if width == 3 { 7 } else { 5 },
        "native160 real primary/control/opposite channel geometry",
    )?;
    if width == 3 {
        for stream in 0..2 {
            require(
                tlc_mcs(native, &tlc, stream, 0) == 255
                    && tlc_mcs(native, &tlc, stream, 1) == if he && stream == 1 { 0 } else { 255 }
                    && tlc_mcs(native, &tlc, stream, 2) == 0,
                "native160 distinct80/160 maps or unsupported320 slot",
            )?;
        }
        require(
            tlc[at + 3] == if he { 0 } else { 15 },
            "native160 source SGI width bitmap",
        )?;
        let assoc = wire
            .phy_requests
            .last()
            .ok_or("native160 original Association Request missing")?;
        let mut rest = &assoc[28..];
        let mut vht = None;
        while !rest.is_empty() {
            require(
                rest.len() >= 2 && rest.len() >= 2 + usize::from(rest[1]),
                "native160 request IE bounds",
            )?;
            let body = &rest[2..2 + usize::from(rest[1])];
            if rest[0] == 191 {
                require(
                    vht.is_none() && body.len() == 12,
                    "native160 VHT request duplicate",
                )?;
                vht = Some(body);
            }
            rest = &rest[2 + usize::from(rest[1])..];
        }
        let vht = vht.ok_or("native160 request lacks VHT")?;
        require(
            word(vht, 0) & 0x4c == 0x44 && vht[11] & 0x20 != 0,
            "native160 request did not advertise exact contiguous160/Extended NSS capability",
        )?;
    }
    Ok(())
}
fn close(guard: &Guard) -> R {
    run(guard.device().disassociate(), service)?.map_err(|_| "native160 ordered disconnect")?;
    carrier(guard.device(), false)
}
fn smoke_iwl_native160_sc_api89_bz_he_directional_maps_and_actual_dhcp() -> TestResult {
    check(|| {
        for native in [Native::Sc, Native::Api89, Native::Bz] {
            for secured in [false, true] {
                let guard = setup(native, secured, true, Fault::None)?;
                join(&guard, secured, &policy())?;
                wire(native, true, 3)?;
                let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                    .map_err(|_| "native HE160 real DHCP DORA")?;
                require(NETWORK.matches_lease(&lease), "native HE160 native lease")?;
                close(&guard)?;
            }
            // Exercise the actual SAE-H2E/PMF owner and its parsing fact,
            // including selector123 on a later native bound beacon. A
            // copied160 offer that loses H2E must fail this real RX path.
            let guard = setup(native, true, true, Fault::None)?;
            let password = b"Sc-native-SAE-password";
            let ap = FakeAp::wpa3_sae(
                NETWORK,
                SSID,
                36,
                7,
                password,
                narf_wifi_fixtures::ApSaePwe::HashToElement,
                ANONCE,
            )
            .and_then(|ap| ap.with_akms(&[24]))
            .and_then(|ap| ap.with_igtk([0x6b; 16], 5, 0x0102_0304_0506))
            .map_err(|_| "native160 SAE24/PMF peer")?;
            security_tests::install_ap(ap);
            HARNESS.lock().as_mut().unwrap().1.sae_h2e_only = true;
            discover(&guard)?;
            let mut request = request_wide(true);
            request.security = narf_wireless::SecurityConfig::Wpa3 {
                password: password.to_vec(),
            };
            run(
                guard.device().associate_in_domain(request, &policy()),
                service,
            )?
            .map_err(|_| "native160 actual SAE24/H2E association")?;
            carrier(guard.device(), true)?;
            wire(native, true, 3)?;
            security_tests::native_keys(24)?;
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let mut frame = wire.ap.beacon();
                frame.extend_from_slice(&he_tests::elements(phy(native, true), true));
                frame.extend_from_slice(&[50, 1, 0xfb]);
                wire.mpdu(&frame, false);
            }
            flush()?;
            carrier(guard.device(), true)?;
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "native160 SAE24/PMF actual DHCP DORA")?;
            require(
                NETWORK.matches_lease(&lease),
                "native160 SAE24 native lease",
            )?;
            close(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/native160",
    smoke_iwl_native160_sc_api89_bz_he_directional_maps_and_actual_dhcp
);
fn smoke_iwl_native160_vht_actual_width_sgi_nss_maps_and_protected_data() -> TestResult {
    check(|| {
        for native in [Native::Sc, Native::Api89, Native::Bz] {
            let guard = setup(native, true, false, Fault::None)?;
            join(&guard, true, &policy())?;
            wire(native, false, 3)?;
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "native VHT160 actual DHCP DORA")?;
            require(
                NETWORK.matches_lease(&lease),
                "native VHT160 protected native lease",
            )?;
            close(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/native160",
    smoke_iwl_native160_vht_actual_width_sgi_nss_maps_and_protected_data
);

fn raw_nvm() -> Vec<u8> {
    let mut nvm = vec![0; 28 + 110 * 4];
    nvm[8..12].copy_from_slice(&28u32.to_le_bytes());
    nvm[12..16].copy_from_slice(&3u32.to_le_bytes());
    nvm[16..20].copy_from_slice(&3u32.to_le_bytes());
    nvm[24..28].copy_from_slice(&51u32.to_le_bytes());
    for index in 0..51 {
        nvm[28 + index * 4..32 + index * 4].copy_from_slice(
            &(1u32
                | if (14..22).contains(&index) {
                    1 << 11
                } else {
                    0
                })
            .to_le_bytes(),
        );
    }
    nvm
}
fn smoke_iwl_native160_needs_raw_nvm_and_every_host_mcc_constituent() -> TestResult {
    check(|| {
        require(
            core::mem::size_of::<ht_vht::Negotiated>() <= 128,
            "native160 snapshot enlarged every connection and association future",
        )?;
        let model = phy(Native::Sc, true);
        // This complete AP snapshot goes through the real shared JoinPlan,
        // which confirms its singleton SSID against Beacon::ssid too.
        let mut ies = vec![0, SSID.len() as u8];
        ies.extend_from_slice(SSID);
        ies.extend_from_slice(&[1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
        ies.extend_from_slice(&he_tests::elements(model, true));
        let beacon = super::super::super::connection::Beacon {
            bssid: AP,
            ssid: SSID.to_vec(),
            channel: 36,
            band: super::super::super::native_band::Band::Five,
            interval: 100,
            dtim: 1,
            rsn: None,
            privacy: false,
            capabilities: 1,
            information_elements: ies.clone(),
        };
        let permissions = vec![0xf0d; 51];
        for missing in 0..=8 {
            let mut raw = raw_nvm();
            if missing < 8 {
                raw[28 + (14 + missing) * 4..32 + (14 + missing) * 4]
                    .copy_from_slice(&1u32.to_le_bytes());
            }
            let mut local = station_api::Nvm::parse(4, &raw)?.phy;
            require(
                !local.supports160(),
                "raw NVM inferred an unproved native rate consumer",
            )?;
            local.native_rates = 3;
            let offer = sc_security::Profile::negotiate(
                &beacon,
                OWN,
                &connection::AuthMethod::Open,
                local,
            )?
            .offer;
            let actual = ht_vht::Negotiated::parse_with_offer(
                local,
                &ies,
                36,
                true,
                |width, center| {
                    connection::channel_power_width(&policy(), 36, width, center, &permissions)
                        .is_some()
                },
                offer.as_ref().map(|offer| (offer, false)),
            )?;
            require(
                actual.width == if missing == 8 { 3 } else { 2 },
                "native160 ignored an absent raw NVM constituent",
            )?;
        }
        for index in 14..22 {
            let mut narrowed = permissions.clone();
            narrowed[index] &= !(1 << 11);
            require(
                connection::channel_power_width(&policy(), 36, 3, 50, &narrowed).is_none(),
                "native160 ignored an absent MCC constituent",
            )?;
        }
        let mut narrowed = policy();
        narrowed.rules.push(narf_wireless::reg::RegRule {
            freq_start_mhz: 5310,
            freq_end_mhz: 5330,
            max_bandwidth_mhz: 80,
            max_power_dbm: 1,
            flags: narf_wireless::reg::RegFlags::empty(),
        });
        require(
            connection::channel_power_width(&narrowed, 36, 3, 50, &permissions).is_none()
                && connection::channel_power_width(&narrowed, 36, 2, 42, &permissions) == Some(17),
            "native160 primary-only host admission missed upper constituent restriction",
        )?;
        for center in [42, 51, 106, 155] {
            require(
                connection::channel_power_width(&policy(), 36, 3, center, &permissions).is_none(),
                "native160 accepted a noncanonical/foreign span",
            )?;
        }
        // cfg80211 Table9-272: supp0/ext1 signals160 through HT CCFS2
        // at half NSS. Keep the real two-stream <=80 row, but close the
        // second160 row even though the ordinary AP RX map has two NSS.
        let mut extended = ies.clone();
        let mut at = 0;
        while at < extended.len() {
            let len = usize::from(extended[at + 1]);
            match extended[at] {
                61 => extended[at + 4..at + 6].copy_from_slice(&(50u16 << 5).to_le_bytes()),
                191 => {
                    let info = word(&extended, at + 2) & !(3 << 2) | (1 << 30);
                    extended[at + 2..at + 6].copy_from_slice(&info.to_le_bytes());
                    extended[at + 13] |= 0x20;
                }
                192 => extended[at + 4] = 0,
                _ => {}
            }
            at += 2 + len;
        }
        let mut local = station_api::Nvm::parse(4, &raw_nvm())?.phy;
        local.native_rates = 3;
        let mut extended_beacon = beacon.clone();
        extended_beacon.information_elements = extended.clone();
        let offer = sc_security::Profile::negotiate(
            &extended_beacon,
            OWN,
            &connection::AuthMethod::Open,
            local,
        )?
        .offer;
        let selected = ht_vht::Negotiated::parse_with_offer(
            local,
            &extended,
            36,
            true,
            |_, _| true,
            offer.as_ref().map(|offer| (offer, false)),
        )?;
        let mut body = [0; 44];
        selected.apply_tlc(&mut body);
        require(
            selected.width == 3
                && word(&body, 16) == 255
                && word(&body, 28) == 255
                && word(&body, 20) == 255
                && word(&body, 32) == 0,
            "native160 ignored actual Extended NSS/HT CCFS2 or limited the wrong TLC row",
        )?;
        require(
            selected.confirm(local, &extended, &extended, 36, true)? == selected,
            "native160 lost original shared wide offer on current beacon confirmation",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/native160",
    smoke_iwl_native160_needs_raw_nvm_and_every_host_mcc_constituent
);

fn smoke_iwl_native160_actual_mcc_and_host_narrow_to_genuine_he80() -> TestResult {
    check(|| {
        for native in [Native::Sc, Native::Api89, Native::Bz] {
            for which in 0..3 {
                let guard = setup(native, true, true, Fault::None)?;
                let mut domain = policy();
                if which == 0 {
                    HARNESS.lock().as_mut().unwrap().1.mcc_caps_override =
                        Some(if matches!(native, Native::Api89) {
                            0x110
                        } else {
                            0x10
                        });
                } else if which == 1 {
                    let mut flags = vec![0xf0d; 51];
                    flags[21] &= !(1 << 11);
                    HARNESS.lock().as_mut().unwrap().1.mcc_permissions = Some(flags);
                } else {
                    domain.rules[0].max_bandwidth_mhz = 80;
                    guard.policy_db.install(domain.clone());
                }
                join(&guard, true, &domain)?;
                wire(native, true, 2)?;
                let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                    .map_err(|_| "native160 narrow actual DHCP")?;
                require(NETWORK.matches_lease(&lease), "native160 narrow HE80 lease")?;
                close(&guard)?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/native160",
    smoke_iwl_native160_actual_mcc_and_host_narrow_to_genuine_he80
);

fn smoke_iwl_native160_bad_rfh_rate_keeps_original_packet_number_unconsumed() -> TestResult {
    check(|| {
        for native in [Native::Sc, Native::Api89, Native::Bz] {
            let guard = setup(native, true, true, Fault::None)?;
            join(&guard, true, &policy())?;
            let model = phy(native, true);
            let good = 0x400 | (3 << 11);
            for (index, bad) in [
                (0, 0x400 | (4 << 11)),
                (1, 0x408 | (3 << 11)),
                (2, 0x300 | (4 << 11)),
                (3, 0x30a | (3 << 11)),
                (4, good | (1 << 6)),
            ] {
                let frame = udp_ipv4(
                    OWN,
                    AP,
                    NETWORK.server_ip,
                    NETWORK.lease_ip,
                    7,
                    49152,
                    &[b'W', index],
                );
                let pn = 100 + u64::from(index);
                he_tests::inject_data(model, &frame, bad, pn, 3);
                flush()?;
                require(
                    !HARNESS.lock().as_ref().unwrap().1.received.contains(&frame),
                    "native160 bad rate reached plaintext or mutated PN",
                )?;
                he_tests::inject_data(model, &frame, good, pn, 3);
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
                    "native160 refused rate consumed original CCMP PN",
                )?;
                he_tests::inject_data(model, &frame, good, pn, 3);
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
                    "native160 valid replay escaped original PN owner",
                )?;
            }
            close(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/native160",
    smoke_iwl_native160_bad_rfh_rate_keeps_original_packet_number_unconsumed
);

fn smoke_iwl_native160_late_upper_channel_policy_loss_keeps_held_native_owner() -> TestResult {
    check(|| {
        let guard = setup(Native::Sc, true, true, Fault::HoldHe)?;
        discover(&guard)?;
        let domain = policy();
        let mut future = Box::pin(
            guard
                .device()
                .associate_in_domain(request_wide(true), &domain),
        );
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "native160 association passed actual held STA",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
                break;
            }
            require(
                !deadline.expired(),
                "native160 actual held-STA publication bound",
            )?;
            narf_scheduler::sleep_pumps::run();
        }
        drop(future);
        require(
            HARNESS
                .lock()
                .as_ref()
                .unwrap()
                .1
                .commands
                .iter()
                .any(|(group, command, body)| {
                    (*group, *command) == (1, 8) && body.get(13) == Some(&3)
                }),
            "native160 held STA did not follow the real wide PHY command",
        )?;
        let mut denied = policy();
        denied.rules.push(narf_wireless::reg::RegRule {
            freq_start_mhz: 5310,
            freq_end_mhz: 5330,
            max_bandwidth_mhz: 160,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::NO_IR,
        });
        guard.policy_db.install(denied);
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (cmd, group, sequence) =
                wire.held.take().ok_or("native160 held receipt missing")?;
            require(
                (group, cmd) == (3, 10),
                "native160 held wrong native command",
            )?;
            wire.fault = Fault::None;
            wire.firmware.inject(cmd, group, sequence, &[]);
        }
        let deadline = narf_time::Deadline::after_ms(1500);
        loop {
            let _ = drain();
            narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
                2_000_000,
            )));
            if guard
                .device()
                .state
                .try_lock()
                .is_some_and(|state| state.stop_completed)
            {
                break;
            }
            require(
                !deadline.expired(),
                "native160 upper-span revocation did not fail retained owner",
            )?;
        }
        carrier(guard.device(), false)?;
        let state = guard
            .device()
            .state
            .try_lock()
            .ok_or("native160 failed native owner still locked")?;
        let closed = {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            !wire.m4 && wire.keys == 0 && wire.data.is_empty()
        };
        require(
            state
                .connection
                .as_ref()
                .is_none_or(|connection| !connection.authorized)
                && state.needs_reset
                && model::retained(&state.hardware).0 > 0
                && closed,
            "native160 late context receipt opened port or released uncertain DMA",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/native160",
    smoke_iwl_native160_late_upper_channel_policy_loss_keeps_held_native_owner
);
