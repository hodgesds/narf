//! Authored RF/ALIVE/PNVM and AP facts reach native TFH/RFH, WPA3/PMF,
//! directional TLC/STA programs and the controlled-port DHCP path.
use super::super::super::{bz_fixture, sc_eht};
use super::*;
const PASSWORD: &[u8] = b"native-EHT-SAE24-password";
#[derive(Clone, Copy)]
pub(super) struct Model {
    pub subsystem: u16,
    wh: bool,
    reduced: bool,
    pub selector: bool,
    response: bool,
    response_nss1: bool,
    ppe: bool,
    punctured: bool,
    six: bool,
}
impl Default for Model {
    fn default() -> Self {
        Self {
            subsystem: 0x0050,
            wh: false,
            reduced: false,
            selector: true,
            response: true,
            response_nss1: false,
            ppe: false,
            punctured: false,
            six: false,
        }
    }
}
impl Model {
    pub fn radio(self) -> u32 {
        if self.wh {
            0x20113100
        } else {
            0x20112200
        }
    }
    fn sku(self) -> [u32; 3] {
        [1 | if self.reduced { 1 << 25 } else { 0 }, 2, 3]
    }
    pub fn alive(self) -> Vec<u8> {
        let mut out = vec![0; 144];
        out[..2].copy_from_slice(&0xcafeu16.to_le_bytes());
        for (i, word) in self.sku().into_iter().enumerate() {
            out[116 + i * 4..120 + i * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
    pub fn pnvm_image(self, image: &mut Vec<u8>, mac: u16) {
        image[72..76].copy_from_slice(&103u32.to_le_bytes());
        fn tlv(out: &mut Vec<u8>, tag: u32, body: &[u8]) {
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(body);
            out.resize(out.len().next_multiple_of(4), 0);
        }
        let mut pnvm = Vec::new();
        let sku: Vec<_> = self.sku().into_iter().flat_map(u32::to_le_bytes).collect();
        tlv(&mut pnvm, 64, &sku);
        let mut hw = mac.to_le_bytes().to_vec();
        hw.extend_from_slice(&(if self.wh { 0x113u16 } else { 0x112 }).to_le_bytes());
        tlv(&mut pnvm, 58, &hw);
        tlv(&mut pnvm, 19, &[0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]);
        tlv(image, 74, &pnvm);
    }
    pub fn elements(self, phy: PhyModel, response: bool) -> Vec<u8> {
        if response && !self.response {
            return Vec::new();
        }
        // AP form: 3 octets at <=80 and separately160. Distinct RX/TX
        // nibbles expose copying the wrong direction or width namespace.
        let mut capability = vec![108, 0, 1]; // EHT A-MPDU exponent extension1.
        let mut physical = [0; 9];
        physical[5] = 0x20 | if self.ppe { 8 } else { 0 };
        capability.extend_from_slice(&physical);
        let limited = response && self.response_nss1;
        capability.extend_from_slice(if limited {
            &[0x21, 0x21, 0]
        } else {
            &[0x22, 0x21, 0]
        });
        if phy.width == 3 {
            capability.extend_from_slice(if limited {
                &[0x21, 0x21, 0]
            } else {
                &[0x21, 0x22, 0]
            });
        }
        if self.ppe {
            // Two NSS, only RU20 thresholds: NSS1[2,1], NSS2[4,3].
            // Missing40/80/160/320 inherits within each stream.
            let mut bits = 0x11u32;
            for (at, field) in [(9, 1), (12, 2), (15, 3), (18, 4)] {
                bits |= field << at;
            }
            capability.extend_from_slice(&bits.to_le_bytes()[..3]);
        }
        let mut out = vec![255, capability.len() as u8];
        out.extend_from_slice(&capability);
        let info = match phy.width {
            0 => [0, if self.six { 5 } else { 6 }, 0],
            1 => [1, 8, 0],
            2 => [2, 42, 0],
            _ => [3, 42, 50],
        };
        let mut operation = vec![
            106,
            1 | if self.punctured { 2 } else { 0 },
            0x11,
            0x11,
            0,
            0,
        ];
        operation.extend_from_slice(&info);
        if self.punctured {
            operation.extend_from_slice(&2u16.to_le_bytes());
        }
        out.extend_from_slice(&[255, operation.len() as u8]);
        out.extend_from_slice(&operation);
        if self.selector {
            out.extend_from_slice(&[50, 1, 0xf9]);
        }
        out
    }
}
fn phy(width: u8) -> PhyModel {
    PhyModel {
        width,
        streams: 2,
        rates: 3,
        mcc_he: true,
        response_he: true,
    }
}
#[inline(never)]
fn setup(model: Model, width: u8, bz: Option<bz_fixture::Case>, fault: Fault) -> R<Box<Guard>> {
    setup_sources(model, width, bz, fault, None)
}
#[inline(never)]
fn setup_sources(
    model: Model,
    width: u8,
    bz: Option<bz_fixture::Case>,
    fault: Fault,
    sources: Option<(&crate::firmware_asset::Asset, &crate::firmware_asset::Asset)>,
) -> R<Box<Guard>> {
    let guard = Guard::build_native_eht(
        true,
        fault,
        None,
        sources,
        Some(phy(width)),
        NativeModel {
            receive_model: ReceiveModel::NativeSc,
            tx_model: None,
            api89: None,
            bz,
            six: model.six.then_some(SixModel {
                channel: 5,
                regulatory: 0,
                nvm_flags: 0x6001,
                mcc_flags: 0x600d,
                api59: true,
                tpe: 20,
                alias: false,
            }),
        },
        Some(model),
    )?;
    let ap = FakeAp::wpa3_sae(
        NETWORK,
        SSID,
        if model.six { 5 } else { phy(width).channel() },
        7,
        PASSWORD,
        narf_wifi_fixtures::ApSaePwe::HashToElement,
        ANONCE,
    )
    .and_then(|ap| ap.with_akms(&[24]))
    .and_then(|ap| ap.with_igtk([0x6b; 16], 5, 0x0102_0304_0506))
    .map_err(|_| "native EHT authored SAE24/PMF peer")?;
    security_tests::install_ap(ap);
    Ok(Box::new(guard))
}
fn policy(width: u8) -> narf_wireless::reg::RegulatoryDomain {
    if width == 3 {
        native_160_tests::policy()
    } else {
        he_tests::policy()
    }
}
fn req(width: u8) -> AssociateRequest {
    let mut req = request(true);
    req.channel = u32::from(phy(width).channel());
    req.frequency_mhz = if width >= 2 { 5180 } else { 2437 };
    req.security = narf_wireless::SecurityConfig::Wpa3 {
        password: PASSWORD.to_vec(),
    };
    req
}
fn discover(guard: &Guard, width: u8) -> R {
    let mut scan = scan_request();
    scan.channels = vec![u32::from(phy(width).channel())];
    scan.frequencies_mhz = vec![if width >= 2 { 5180 } else { 2437 }];
    require(
        run(guard.device().scan(scan), service)?
            .map_err(|_| "EHT native scan")?
            .len()
            == 1,
        "EHT source-authored candidate",
    )
}
fn join(guard: &Guard, width: u8) -> R {
    discover(guard, width)?;
    run(
        guard
            .device()
            .associate_in_domain(req(width), &policy(width)),
        service,
    )?
    .map_err(|_| "EHT actual native SAE24 association")?;
    carrier(guard.device(), true)
}
fn close(guard: &Guard) -> R {
    run(guard.device().disassociate(), service)?.map_err(|_| "EHT native teardown")
}
fn tlc() -> R<Vec<u8>> {
    HARNESS
        .lock()
        .as_ref()
        .unwrap()
        .1
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (5, 0xf))
        .map(|(_, _, body)| body.clone())
        .ok_or("EHT native TLC absent")
}
#[inline(never)]
fn six_native(bz: Option<bz_fixture::Case>) -> R {
    let model = Model {
        six: true,
        wh: bz.is_some_and(|case| case.wh()),
        ..Model::default()
    };
    let guard = setup(model, 0, bz, Fault::None)?;
    let mut scan = scan_request();
    scan.channels = vec![5];
    scan.frequencies_mhz = vec![5975];
    require(
        run(guard.device().scan(scan), service)?
            .map_err(|_| "EHT6 native scan")?
            .len()
            == 1,
        "EHT6 actual candidate",
    )?;
    let mut request = req(0);
    request.channel = 5;
    request.frequency_mhz = 5975;
    run(
        guard
            .device()
            .associate_in_domain(request, &six_ghz_tests::policy()),
        service,
    )?
    .map_err(|_| "EHT6 actual native association")?;
    carrier(guard.device(), true)?;
    let lease =
        narf_net::dhcp::dhcp_acquire(guard.device().name(), 0).map_err(|_| "EHT6 native DHCP")?;
    require(
        NETWORK.matches_lease(&lease) && tlc()?[8..10] == [0, 4],
        "EHT6 native mode/lease",
    )?;
    close(&guard)
}
fn smoke_iwl_eht_native_sc_bz_fm_wh_sae24_pmf_and_dhcp() -> TestResult {
    check(|| {
        for (bz, wh) in [
            (None, false),
            (None, true),
            (Some(bz_fixture::Case::FmDiscrete), false),
            (Some(bz_fixture::Case::WhIntegrated), true),
        ] {
            for width in 0..=3 {
                let model = Model {
                    wh,
                    ..Model::default()
                };
                let guard = setup(model, width, bz, Fault::None)?;
                join(&guard, width)?;
                security_tests::native_keys(24)?;
                let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                    .map_err(|_| "EHT protected native DHCP DORA")?;
                require(NETWORK.matches_lease(&lease), "EHT native lease")?;
                let tlc = tlc()?;
                require(
                    tlc.len() == 44
                        && tlc[8] == width
                        && tlc[9] == 4
                        && word(&tlc, 24) == 0
                        && word(&tlc, 36) == 0,
                    "EHT actual mode4/width and zero320 matrices",
                )?;
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                let mac = &wire
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (3, 8))
                    .ok_or("EHT actual response-bound MAC missing")?
                    .2;
                require(
                    mac.len() == 52 && mac[24..32] == [1, 0, 1, 0, 0, 0, 0, 0],
                    "EHT native MACv3 omitted byte26 or aliased HE/UHR fields",
                )?;
                let request = wire
                    .phy_requests
                    .last()
                    .ok_or("EHT actual request absent")?;
                let mut ies = &request[28..];
                let mut seen = 0;
                while !ies.is_empty() {
                    let end = 2 + usize::from(ies[1]);
                    if ies[0] == 255 && ies[2] == 108 {
                        seen += 1;
                        require(
                            ies[3..5] == [0; 2] && ies[10] == 0x20,
                            "EHT request promised unimplemented optional features",
                        )?;
                    }
                    ies = &ies[end..];
                }
                require(
                    seen == 1 && guard.device().get_wireless_info().hw_caps.eht_supported,
                    "EHT actual RF/NVM capability/request fact missing",
                )?;
                drop(slot);
                close(&guard)?;
            }
        }
        six_native(None)?;
        six_native(Some(bz_fixture::Case::WhIntegrated))?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/eht",
    smoke_iwl_eht_native_sc_bz_fm_wh_sae24_pmf_and_dhcp
);

#[inline(never)]
fn source(model: Model, mac: u32, device: u16) -> R<Option<sc_eht::Source>> {
    let mut versions = super::super::super::firmware_parser_tests::mld_commands();
    he_tests::versions(&mut versions);
    versions.extend_from_slice(&[1, 0, 99, 7]);
    let mut image = tx_amsdu_tests::image(&versions, None)?;
    model.pnvm_image(&mut image, (mac >> 4) as u16);
    let parsed =
        super::super::super::parse_ucode(&image).map_err(|_| "EHT authored source parse")?;
    sc_eht::Source::boot(
        device,
        model.subsystem,
        mac,
        model.radio(),
        &parsed,
        &model.alive(),
    )
}
fn smoke_iwl_eht_rf_subsystem_bw_reduced_sku_and_exact_pnvm_source() -> TestResult {
    check(|| {
        for wh in [false, true] {
            for reduced in [false, true] {
                let model = Model {
                    wh,
                    reduced,
                    ..Model::default()
                };
                let selected =
                    source(model, 0x480, 0xe340)?.ok_or("actual FM/WH EHT source absent")?;
                require(
                    selected.reduced == (reduced && !wh) && selected.bandwidth_limit == 320,
                    "EHT reduced FM source aliased WH or generic NVM SKU",
                )?;
                for subsystem in [0x0250, if wh { 0x1735 } else { 0x1730 }] {
                    let narrowed = source(Model { subsystem, ..model }, 0x480, 0xe340)?
                        .ok_or("160-limited EHT source incorrectly inapplicable")?;
                    require(
                        narrowed.bandwidth_limit == 160,
                        "EHT actual subsystem bandwidth limit",
                    )?;
                }
            }
        }
        for subsystem in [0x0514, 0x4514] {
            require(
                source(
                    Model {
                        wh: true,
                        subsystem,
                        ..Model::default()
                    },
                    0x480,
                    0xe340,
                )?
                .is_none(),
                "AX221 WH non-EHT subsystem gained EHT",
            )?;
        }
        require(
            source(Model::default(), 0x470, 0xe340)?.is_none()
                && source(Model::default(), 0x480, 0xffff)?.is_none(),
            "EHT firmware/PCI name substituted for actual MAC/RF profile",
        )?;
        let model = Model::default();
        let mut versions = super::super::super::firmware_parser_tests::mld_commands();
        he_tests::versions(&mut versions);
        versions.extend_from_slice(&[1, 0, 99, 7]);
        let mut image = tx_amsdu_tests::image(&versions, None)?;
        model.pnvm_image(&mut image, 0x48);
        let parsed =
            super::super::super::parse_ucode(&image).map_err(|_| "EHT source negative parse")?;
        let mut bad = model.alive();
        bad[120] ^= 1;
        require(
            sc_eht::Source::boot(0xe340, 0x0050, 0x480, model.radio(), &parsed, &bad).is_err(),
            "EHT ignored one of three actual PNVM SKU words",
        )?;
        bad = model.alive();
        bad.truncate(143);
        require(
            sc_eht::Source::boot(0xe340, 0x0050, 0x480, model.radio(), &parsed, &bad).is_err(),
            "EHT accepted short actual ALIVE",
        )?;
        require(
            sc_eht::Source::boot(0xe340, 0x0050, 0x480, 0x2010d000, &parsed, &model.alive())?
                .is_none()
                && sc_eht::Source::boot(
                    0x272b,
                    0x0050,
                    0x461,
                    0x20112100,
                    &parsed,
                    &model.alive(),
                )?
                .is_none(),
            "EHT admitted GF or unqualified Bz FM stepping",
        )?;
        model_source_reset()
    })
}
#[inline(never)]
fn model_source_reset() -> R {
    let model = Model::default();
    let mut versions = super::super::super::firmware_parser_tests::mld_commands();
    he_tests::versions(&mut versions);
    versions.extend_from_slice(&[1, 0, 99, 7]);
    let mut image = tx_amsdu_tests::image(&versions, None)?;
    model.pnvm_image(&mut image, 0x48);
    let parsed =
        super::super::super::parse_ucode(&image).map_err(|_| "EHT cold source metadata")?;
    let (mut hardware, firmware, trace) = model::station_model();
    let result = (|| {
        model::native_station_identity(&mut hardware, 0xe340, 0x480, model.radio())?;
        model::firmware_profile(&mut hardware, &parsed)?;
        model::eht_boot(&mut hardware, &parsed, model.subsystem, &model.alive())?;
        require(
            hardware.eht_supported(),
            "EHT cold actual ALIVE/PNVM source not retained",
        )?;
        model::firmware_profile(&mut hardware, &parsed)?;
        require(
            !hardware.eht_supported(),
            "EHT metadata-only replacement inherited previous ALIVE",
        )?;
        model::eht_boot(&mut hardware, &parsed, model.subsystem, &model.alive())?;
        model::restart(&mut hardware)?;
        require(
            !hardware.eht_supported(),
            "EHT cold restart inherited previous ALIVE/SKU",
        )
    })();
    // SAFETY: all post-ready RAM endpoint views are local, no future survives,
    // and no physical bus-master or firmware execution ever owned these rings.
    unsafe { model::destroy(hardware) };
    drop((firmware, trace));
    result
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/eht",
    smoke_iwl_eht_rf_subsystem_bw_reduced_sku_and_exact_pnvm_source
);

fn smoke_iwl_eht_mcc_security_missing_response_and_puncturing_fail_closed() -> TestResult {
    check(|| {
        for which in 0..5 {
            let model = Model {
                response: which != 2,
                punctured: which == 3,
                wh: which == 4,
                subsystem: if which == 4 { 0x0514 } else { 0x0050 },
                ..Model::default()
            };
            let guard = setup(model, 2, None, Fault::None)?;
            discover(&guard, 2)?;
            if which == 0 {
                HARNESS.lock().as_mut().unwrap().1.mcc_caps_override = Some(0x118);
            }
            let mut request = req(2);
            if which == 1 {
                request.security = narf_wireless::SecurityConfig::Wpa2 { psk: PMK };
            }
            require(
                run(
                    guard.device().associate_in_domain(request, &policy(2)),
                    service,
                )?
                .is_err(),
                "EHT mandatory selector bypassed MCC/security/response/puncture admission",
            )?;
            carrier(guard.device(), false)?;
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            require(
                !wire.m4
                    && wire.keys == 0
                    && wire.data.is_empty()
                    && !wire
                        .commands
                        .iter()
                        .any(|(g, c, b)| (*g, *c) == (5, 0xf) && b[9] == 4),
                "EHT invalid native contract reached TLC4/key/port",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/eht",
    smoke_iwl_eht_mcc_security_missing_response_and_puncturing_fail_closed
);

fn smoke_iwl_eht_directional_width_maps_response_limits_ampdu_and_ppe_inheritance() -> TestResult {
    check(|| {
        for limited in [false, true] {
            let model = Model {
                response_nss1: limited,
                ppe: true,
                ..Model::default()
            };
            let guard = setup(model, 3, None, Fault::None)?;
            join(&guard, 3)?;
            let tlc = tlc()?;
            require(
                word(&tlc, 16) == 0xfff
                    && word(&tlc, 20) == 0xfff
                    && word(&tlc, 28) == if limited { 0 } else { 0x3ff }
                    && word(&tlc, 32) == if limited { 0 } else { 0xc00 },
                "EHT copied AP TX or80 maps into directional160 source",
            )?;
            let slot = HARNESS.lock();
            let peer = &slot
                .as_ref()
                .unwrap()
                .1
                .commands
                .iter()
                .rev()
                .find(|(g, c, _)| (*g, *c) == (3, 10))
                .ok_or("EHT native STA missing")?
                .2;
            require(
                word(peer, 60) == 4
                    && peer[72..82].chunks_exact(2).all(|pair| pair == [2, 1])
                    && peer[82..92].chunks_exact(2).all(|pair| pair == [4, 3]),
                "EHT native STA exponent/PPE inherited HE or wrong RU/NSS",
            )?;
            drop(slot);
            close(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/eht",
    smoke_iwl_eht_directional_width_maps_response_limits_ampdu_and_ppe_inheritance
);

fn smoke_iwl_eht_original_rfh_rate_bounds_reject_before_same_pn_ownership() -> TestResult {
    check(|| {
        let guard = setup(Model::default(), 3, None, Fault::None)?;
        join(&guard, 3)?;
        for (index, bad) in [
            0x600u32,
            0x50c,
            0x50b,
            0x510,
            0x500 | (4 << 11),
            0x500 | (1 << 27),
            0x500 | (1 << 19),
            0x500 | (4 << 20),
        ]
        .into_iter()
        .enumerate()
        {
            let frame = udp_ipv4(
                OWN,
                AP,
                NETWORK.server_ip,
                NETWORK.lease_ip,
                7,
                49152,
                &[b'E', index as u8],
            );
            let pn = 100 + index as u64;
            he_tests::inject_data(phy(3), &frame, bad, pn, 3);
            flush()?;
            require(
                !HARNESS.lock().as_ref().unwrap().1.received.contains(&frame),
                "EHT invalid original RFH rate reached PN/reorder delivery",
            )?;
            he_tests::inject_data(phy(3), &frame, 0x500 | (3 << 11) | 32, pn, 3);
            flush()?;
            he_tests::inject_data(phy(3), &frame, 0x500 | (3 << 11) | 32, pn, 3);
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
                "EHT invalid rate consumed PN or valid replay was delivered",
            )?;
        }
        close(&guard)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/eht",
    smoke_iwl_eht_original_rfh_rate_bounds_reject_before_same_pn_ownership
);

#[inline(never)]
fn held_owner() -> R {
    let guard = setup(Model::default(), 2, None, Fault::HoldHe)?;
    discover(&guard, 2)?;
    let domain = policy(2);
    let mut association = Box::pin(guard.device().associate_in_domain(req(2), &domain));
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        require(
            association
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "EHT held native STA escaped receipt",
        )?;
        service()?;
        if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
            break;
        }
        if deadline.expired() {
            return Err("EHT native STA publication bound");
        }
        narf_scheduler::sleep_pumps::run();
    }
    drop(association);
    let mut denied = domain.clone();
    denied.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR;
    denied.rules[1].flags = narf_wireless::reg::RegFlags::NO_IR;
    guard.policy_db.install(denied);
    {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        let (cmd, group, sequence) = wire.held.take().ok_or("EHT held STA missing")?;
        require((group, cmd) == (3, 10), "EHT fixture held wrong command")?;
        wire.fault = Fault::None;
        wire.firmware.inject(cmd, group, sequence, &[]);
    }
    let deadline = narf_time::Deadline::after_ms(1500);
    loop {
        drain();
        if guard
            .device()
            .state
            .try_lock()
            .is_some_and(|state| state.stop_completed)
        {
            break;
        }
        if deadline.expired() {
            return Err("EHT retained owner stop bound");
        }
        narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
            2_000_000,
        )));
    }
    carrier(guard.device(), false)?;
    let state = guard
        .device()
        .state
        .try_lock()
        .ok_or("EHT dropped owner retained lock")?;
    require(
        state.needs_reset && state.hardware.is_failed() && model::retained(&state.hardware).0 > 0,
        "EHT ambiguous STA DMA escaped retained stop",
    )?;
    drop(state);
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    require(
        !wire.m4 && wire.keys == 0 && wire.data.is_empty(),
        "EHT stale held STA opened port",
    )?;
    Ok(())
}
#[inline(never)]
fn current_mcc_revokes_eht() -> R {
    let guard = setup(Model::default(), 2, None, Fault::None)?;
    join(&guard, 2)?;
    let mut state = guard
        .device()
        .state
        .try_lock()
        .ok_or("EHT current MCC owner")?;
    let proof = state.hardware.source_fence()?;
    let program = state
        .connection
        .as_ref()
        .ok_or("EHT current station absent")?
        .regulatory_program();
    HARNESS.lock().as_mut().unwrap().1.mcc_caps_override = Some(0x118);
    let current = run(
        super::super::super::connection::regulatory_channels_in_domain(
            &mut state.hardware,
            &policy(2),
        ),
        service,
    )??;
    require(
        current.he_allowed
            && !current.eht_allowed
            && program.refresh_mcc(&policy(2), current).is_err()
            && proof.invoke(|| Ok(())).is_err(),
        "EHT MCCbit8 did not retire already copied source proofs independently of HE",
    )?;
    drop(state);
    drain();
    carrier(guard.device(), false)?;
    Ok(())
}
fn smoke_iwl_eht_held_sta_dropped_waiter_and_current_mcc_stop_owned_dma() -> TestResult {
    check(|| {
        held_owner()?;
        current_mcc_revokes_eht()
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/eht",
    smoke_iwl_eht_held_sta_dropped_waiter_and_current_mcc_stop_owned_dma
);
