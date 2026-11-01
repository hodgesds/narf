//! Native6GHz wide/320 source, channel, power and original-RFH compositions.
use super::super::super::{bz_fixture, six_ghz_span::Span};
use super::*;
const PASSWORD: &[u8] = b"native-320-SAE24-PMF-password";
#[derive(Clone, Copy)]
pub(super) struct Model {
    primary: u8,
    center: u8,
    ap_width: u8,
    expected_width: u8,
    mcc_320: bool,
    mcc_eht: bool,
    regulatory: u8,
    nvm_missing: Option<u8>,
    mcc_missing: Option<u8>,
    nvm_no_160: Option<u8>,
    mcc_no_160: Option<u8>,
    passive_gap: Option<u8>,
    radar_gap: Option<u8>,
    type_gap: Option<u8>,
    psd_prohibited: Option<u8>,
    psd_shift: i8,
    selector: bool,
}
impl Default for Model {
    fn default() -> Self {
        Self {
            primary: 5,
            center: 31,
            ap_width: 4,
            expected_width: 4,
            mcc_320: true,
            mcc_eht: true,
            regulatory: 0,
            nvm_missing: None,
            mcc_missing: None,
            nvm_no_160: None,
            mcc_no_160: None,
            passive_gap: None,
            radar_gap: None,
            type_gap: None,
            psd_prohibited: None,
            psd_shift: 0,
            selector: true,
        }
    }
}
impl Model {
    pub fn nvm_flags(self, index: u8) -> u32 {
        let channel = 1 + 4 * index;
        if self.nvm_missing == Some(channel) {
            0
        } else if self.nvm_no_160 == Some(channel) {
            0x6001
        } else {
            0x6e01
        }
    }
    pub fn mcc_flags(self, index: u8) -> u32 {
        let channel = 1 + 4 * index;
        if self.mcc_missing == Some(channel) {
            0
        } else {
            let flags = if self.mcc_no_160 == Some(channel) {
                0x6009
            } else {
                0x6e09
            };
            let flags = if self.passive_gap == Some(channel) {
                (flags & !8) | 4
            } else {
                flags
            };
            let flags = flags
                | if self.radar_gap == Some(channel) {
                    16
                } else {
                    0
                };
            flags
                & if self.type_gap == Some(channel) {
                    !(1 << 13)
                } else {
                    u32::MAX
                }
        }
    }
    pub fn mcc_caps(self) -> u32 {
        0x18 | if self.mcc_320 { 1 << 16 } else { 0 } | if self.mcc_eht { 0 } else { 1 << 8 }
    }
    fn block_center(self, width: u8) -> u8 {
        if width == 0 {
            return self.primary;
        }
        let block = 4u16 << width;
        ((u16::from(self.primary) - 1) / block * block + block / 2 - 1) as u8
    }
    fn raw_psd(self) -> (Vec<i8>, Vec<i8>) {
        let n = 1usize << self.ap_width.min(3);
        let have = 1usize << self.ap_width;
        let mut first: Vec<i8> = (0..n).map(|i| 10 + i as i8 + self.psd_shift).collect();
        let mut rest: Vec<i8> = (0..have - n)
            .map(|i| 20 + i as i8 + self.psd_shift)
            .collect();
        if let Some(channel) = self.psd_prohibited {
            let low = u16::from(self.center) - 2 * ((1u16 << self.ap_width) - 1);
            let full = usize::from((u16::from(channel) - low) / 4);
            let nlow = (u16::from(self.primary) - 1) / (4 * n as u16) * (4 * n as u16) + 1;
            let offset = usize::from((nlow - low) / 4);
            if (offset..offset + n).contains(&full) {
                first[full - offset] = i8::MIN;
            } else {
                let index = if full < offset { full } else { full - n };
                rest[index] = i8::MIN;
            }
        }
        (first, rest)
    }
    pub fn expected_power(self) -> [u8; 28] {
        let mut out = [0; 28];
        out[2] = self.regulatory;
        out[4..9].copy_from_slice(&[20, 18, 16, 14, 12]);
        out[9..25].fill(127);
        let (first, rest) = self.raw_psd();
        let ap_low = u16::from(self.center) - 2 * ((1u16 << self.ap_width) - 1);
        let n = first.len();
        let nlow = (u16::from(self.primary) - 1) / (4 * n as u16) * (4 * n as u16) + 1;
        let n_offset = usize::from((nlow - ap_low) / 4);
        let used_center = if self.expected_width == 4 {
            self.center
        } else {
            self.block_center(self.expected_width)
        };
        let used_low = u16::from(used_center) - 2 * ((1u16 << self.expected_width) - 1);
        for i in 0..1usize << self.expected_width {
            let full = usize::from((used_low - ap_low) / 4) + i;
            let value = if (n_offset..n_offset + n).contains(&full) {
                first[full - n_offset]
            } else {
                rest[if full < n_offset { full } else { full - n }]
            };
            out[9 + i] = value as u8;
        }
        out
    }
    pub fn complete_ap_frame(self, frame: &mut Vec<u8>) -> R {
        let prefix = if frame[0] == 0x80 { 36 } else { 30 };
        let mut rest = frame.get(prefix..).ok_or("wide6 authored AP header")?;
        let mut ies = Vec::new();
        while !rest.is_empty() {
            let len = usize::from(*rest.get(1).ok_or("wide6 AP IE header")?);
            let item = rest.get(..2 + len).ok_or("wide6 AP IE extent")?;
            if !matches!(rest[0], 1 | 3 | 50) {
                ies.extend_from_slice(item);
            }
            rest = &rest[2 + len..];
        }
        frame.truncate(prefix);
        frame.extend_from_slice(&ies);
        frame.extend_from_slice(&[1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
        let mut he = vec![
            35, 1, 0, 0x20, 0, 0, 0, 12, 0x30, 10, 0, 0, 0, 0, 4, 1, 0x30, 0,
        ];
        he.extend_from_slice(&[0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff, 0xf0, 0xff]);
        frame.extend_from_slice(&[255, he.len() as u8]);
        frame.extend_from_slice(&he);
        let he_width = self.ap_width.min(3);
        let ccfs0 = if he_width == 3 {
            self.block_center(2)
        } else {
            self.center
        };
        let ccfs1 = if he_width == 3 {
            self.block_center(3)
        } else {
            0
        };
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
            self.primary,
            he_width | (self.regulatory << 3),
            ccfs0,
            ccfs1,
            6,
        ]);
        frame.extend_from_slice(&[255, 3, 59, 0x1c, 6]);
        frame.extend_from_slice(&super::super::super::qos::INFORMATION_IE);
        let mut eht = vec![
            108,
            0,
            1,
            if self.ap_width == 4 { 2 } else { 0 },
            0,
            0,
            0,
            0,
            0x20,
            0,
            0,
            0,
            0x22,
            0x22,
            0,
            0x22,
            0x21,
            0,
        ];
        if self.ap_width == 4 {
            eht.extend_from_slice(&[0x21, 0, 0]);
        }
        frame.extend_from_slice(&[255, eht.len() as u8]);
        frame.extend_from_slice(&eht);
        let info = if self.ap_width >= 3 {
            [
                self.ap_width,
                self.block_center(self.ap_width - 1),
                self.center,
            ]
        } else {
            [self.ap_width, self.center, 0]
        };
        frame.extend_from_slice(&[255, 9, 106, 1, 0x11, 0x11, 0, 0, info[0], info[1], info[2]]);
        if self.selector {
            frame.extend_from_slice(&[50, 1, 0xf9]);
        }
        frame.extend_from_slice(&[195, 6, 3, 20, 18, 16, 14, 12]);
        let (first, rest) = self.raw_psd();
        let count = if self.ap_width == 0 {
            1
        } else {
            self.ap_width.min(3) + 1
        };
        frame.extend_from_slice(&[
            195,
            (1 + first.len() + if rest.is_empty() { 0 } else { 1 + rest.len() }) as u8,
            8 | count,
        ]);
        frame.extend(first.iter().map(|value| *value as u8));
        if !rest.is_empty() {
            frame.push(rest.len() as u8);
            frame.extend(rest.iter().map(|value| *value as u8));
        }
        Ok(())
    }
}
pub(super) fn policy() -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5945,
            freq_end_mhz: 7125,
            max_bandwidth_mhz: 320,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    }
}
#[inline(never)]
fn setup(
    wide: Model,
    bz: Option<bz_fixture::Case>,
    reduced: bool,
    subsystem: u16,
    fault: Fault,
) -> R<Box<Guard>> {
    let wh = bz.is_some_and(|case| case.wh());
    let source = eht_tests::Model::wide_source(wh, reduced, subsystem);
    let guard = Guard::build_native_wide(
        true,
        fault,
        None,
        None,
        Some(PhyModel {
            width: 0,
            streams: 2,
            rates: 3,
            mcc_he: true,
            response_he: true,
        }),
        NativeModel {
            receive_model: ReceiveModel::NativeSc,
            tx_model: None,
            api89: None,
            bz,
            six: Some(SixModel {
                channel: wide.primary,
                regulatory: wide.regulatory,
                nvm_flags: 0x6e01,
                mcc_flags: 0x6e0d,
                api59: true,
                tpe: 20,
                alias: false,
            }),
        },
        Some(source),
        Some(wide),
    )?;
    guard.policy_db.install(policy());
    let ap = FakeAp::wpa3_sae(
        NETWORK,
        SSID,
        wide.primary,
        7,
        PASSWORD,
        narf_wifi_fixtures::ApSaePwe::HashToElement,
        ANONCE,
    )
    .and_then(|ap| ap.with_akms(&[24]))
    .and_then(|ap| ap.with_igtk([0x6b; 16], 5, 0x0102_0304_0506))
    .map_err(|_| "native320 SAE24/PMF peer")?;
    security_tests::install_ap(ap);
    Ok(Box::new(guard))
}
fn discover(guard: &Guard, model: Model) -> R {
    let mut scan = scan_request();
    scan.channels = vec![u32::from(model.primary)];
    scan.frequencies_mhz = vec![5950 + 5 * u32::from(model.primary)];
    require(
        run(guard.device().scan(scan), service)?
            .map_err(|_| "native320 actual passive scan")?
            .len()
            == 1,
        "native320 copied band-qualified candidate",
    )
}
fn request_wide(model: Model) -> AssociateRequest {
    let mut req = request(true);
    req.channel = u32::from(model.primary);
    req.frequency_mhz = 5950 + 5 * u32::from(model.primary);
    req.security = narf_wireless::SecurityConfig::Wpa3 {
        password: PASSWORD.to_vec(),
    };
    req
}
fn join_in(guard: &Guard, model: Model, domain: &narf_wireless::reg::RegulatoryDomain) -> R {
    discover(guard, model)?;
    run(
        guard
            .device()
            .associate_in_domain(request_wide(model), domain),
        service,
    )?
    .map_err(|_| "native320 actual full station association")?;
    carrier(guard.device(), true)
}
fn join(guard: &Guard, model: Model) -> R {
    join_in(guard, model, &policy())
}
fn close(guard: &Guard) -> R {
    run(guard.device().disassociate(), service)?.map_err(|_| "native320 ordered teardown")
}
fn observed(model: Model) -> R {
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    let phy = &wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (1, 8))
        .ok_or("native320 PHY absent")?
        .2;
    let tlc = &wire
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| (*g, *c) == (5, 0xf))
        .ok_or("native320 TLC absent")?
        .2;
    let center = if model.expected_width == 4 {
        model.center
    } else {
        model.block_center(model.expected_width)
    };
    let offset = model.primary.abs_diff(center).saturating_sub(2) / 4;
    let ctrl = if model.expected_width == 0 {
        0
    } else {
        (offset & 3) | ((offset & 4) << 1) | if model.primary > center { 4 } else { 0 }
    };
    require(
        phy.len() == 32
            && phy[12] == 2
            && phy[13] == model.expected_width
            && phy[14] == ctrl
            && phy[28] == ctrl ^ 4,
        "native320 PHY band/width/extended control position",
    )?;
    require(
        tlc.len() == 44
            && tlc[8..10] == [model.expected_width, 4]
            && word(tlc, 16) == 0xfff
            && word(tlc, 28) == 0xfff
            && word(tlc, 20) == if model.expected_width >= 3 { 0xfff } else { 0 }
            && word(tlc, 32) == if model.expected_width >= 3 { 0x3ff } else { 0 }
            && word(tlc, 24) == if model.expected_width == 4 { 0x3ff } else { 0 }
            && word(tlc, 36) == 0,
        "native320 TLC directional third slot or fallback width",
    )?;
    Ok(())
}
fn smoke_iwl_six_ghz_320_native_sc_bz_two_rasters_and_all_primary_positions() -> TestResult {
    check(|| {
        for center in [31, 63] {
            for slot in 0..16 {
                let model = Model {
                    primary: center - 30 + 4 * slot,
                    center,
                    ..Model::default()
                };
                let guard = setup(model, None, false, 0x0050, Fault::None)?;
                join(&guard, model)?;
                observed(model)?;
                let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                    .map_err(|_| "native320 encrypted DHCP")?;
                require(NETWORK.matches_lease(&lease), "native320 native DHCP lease")?;
                close(&guard)?;
            }
        }
        for case in [bz_fixture::Case::FmDiscrete, bz_fixture::Case::WhIntegrated] {
            let model = Model::default();
            let guard = setup(model, Some(case), false, 0x0050, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        for ap_width in 0..=3 {
            let model = Model {
                ap_width,
                expected_width: ap_width,
                center: Model::default().block_center(ap_width),
                ..Model::default()
            };
            let guard = setup(model, None, false, 0x0050, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz_320",
    smoke_iwl_six_ghz_320_native_sc_bz_two_rasters_and_all_primary_positions
);

fn smoke_iwl_six_ghz_320_rf_sku_subsystem_and_current_mcc_narrow_to_genuine160() -> TestResult {
    check(|| {
        for (reduced, subsystem, mcc_320) in [
            (true, 0x0050, true),
            (false, 0x0250, true),
            (false, 0x1730, true),
            (false, 0x0050, false),
        ] {
            let model = Model {
                expected_width: 3,
                mcc_320,
                ..Model::default()
            };
            let guard = setup(model, None, reduced, subsystem, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        for (case, reduced, subsystem) in [
            (bz_fixture::Case::FmDiscrete, false, 0x1773),
            (bz_fixture::Case::WhIntegrated, true, 0x0050),
        ] {
            let model = Model::default();
            let guard = setup(model, Some(case), reduced, subsystem, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        // EHT prohibition keeps a genuinely negotiated HE160 owner when
        // the AP does not mandate EHT; it must not use a legacy-band plan.
        let model = Model {
            expected_width: 3,
            mcc_eht: false,
            selector: false,
            ..Model::default()
        };
        let guard = setup(model, None, false, 0x0050, Fault::None)?;
        join(&guard, model)?;
        let mode = {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            wire.commands
                .iter()
                .rev()
                .find(|(g, c, _)| (*g, *c) == (5, 0xf))
                .map(|(_, _, body)| (body[8], body[9]))
        };
        require(
            mode == Some((3, 3)),
            "native320 optional EHT prohibition did not retain HE160",
        )?;
        let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
            .map_err(|_| "native320 optional EHT prohibition encrypted DHCP")?;
        require(
            NETWORK.matches_lease(&lease),
            "native320 HE fallback DHCP lease",
        )?;
        close(&guard)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz_320",
    smoke_iwl_six_ghz_320_rf_sku_subsystem_and_current_mcc_narrow_to_genuine160
);

fn smoke_iwl_six_ghz_320_every_nvm_mcc_host_constituent_and_ap_type_is_bound() -> TestResult {
    check(|| {
        //320 is independent of NO_160; no synthetic NVM320 bit is supplied.
        for nvm in [true, false] {
            let model = Model {
                nvm_no_160: if nvm { Some(49) } else { None },
                mcc_no_160: if nvm { None } else { Some(49) },
                ..Model::default()
            };
            let guard = setup(model, None, false, 0x0050, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        for hole in (1..=61).step_by(4) {
            for nvm in [true, false] {
                let model = Model {
                    primary: if hole == 5 { 9 } else { 5 },
                    nvm_missing: if nvm { Some(hole) } else { None },
                    mcc_missing: if nvm { None } else { Some(hole) },
                    expected_width: match hole {
                        1 => 0,
                        5 | 9 | 13 => 1,
                        17..=29 => 2,
                        _ => 3,
                    },
                    ..Model::default()
                };
                let guard = setup(model, None, false, 0x0050, Fault::None)?;
                join(&guard, model)?;
                observed(model)?;
                close(&guard)?;
            }
        }
        let model = Model {
            regulatory: 2,
            type_gap: Some(49),
            expected_width: 3,
            ..Model::default()
        };
        {
            let guard = setup(model, None, false, 0x0050, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        for radar in [false, true] {
            let model = Model {
                passive_gap: if radar { None } else { Some(49) },
                radar_gap: if radar { Some(49) } else { None },
                expected_width: 3,
                ..Model::default()
            };
            let guard = setup(model, None, false, 0x0050, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        let model = Model {
            expected_width: 3,
            ..Model::default()
        };
        let guard = setup(model, None, false, 0x0050, Fault::None)?;
        let mut restricted = policy();
        restricted.rules.push(narf_wireless::reg::RegRule {
            freq_start_mhz: 6190,
            freq_end_mhz: 6200,
            max_bandwidth_mhz: 320,
            max_power_dbm: 17,
            flags: narf_wireless::reg::RegFlags::NO_IR,
        });
        guard.policy_db.install(restricted.clone());
        join_in(&guard, model, &restricted)?;
        observed(model)?;
        close(&guard)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz_320",
    smoke_iwl_six_ghz_320_every_nvm_mcc_host_constituent_and_ap_type_is_bound
);

fn smoke_iwl_six_ghz_320_tpe_nk_order_fifth_eirp_and_every_occupied_psd_limit() -> TestResult {
    check(|| {
        for (primary, expected) in [
            (
                5,
                [
                    10, 11, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 25, 26, 27,
                ],
            ),
            (
                49,
                [
                    20, 21, 22, 23, 24, 25, 26, 27, 10, 11, 12, 13, 14, 15, 16, 17,
                ],
            ),
        ] {
            let model = Model {
                primary,
                ..Model::default()
            };
            let mut beacon = vec![0; 36];
            beacon[0] = 0x80;
            model.complete_ap_frame(&mut beacon)?;
            let full = Span::new(primary, 4, 31).ok_or("authored320 full span")?;
            let actual = super::super::super::six_ghz_power::Constraints::parse_span(
                narf_wireless::reg::PowerType6Ghz::Lpi,
                &beacon[36..],
                full,
                full,
            )?;
            require(
                actual.command()[4..9] == [20, 18, 16, 14, 12]
                    && actual.command()[9..25] == expected,
                "native320 TPE retained N/K order or lost fifth EIRP",
            )?;
            let guard = setup(model, None, false, 0x0050, Fault::None)?;
            join(&guard, model)?;
            observed(model)?;
            close(&guard)?;
        }
        let model = Model {
            primary: 49,
            psd_prohibited: Some(1),
            ..Model::default()
        };
        let mut beacon = vec![0; 36];
        beacon[0] = 0x80;
        model.complete_ap_frame(&mut beacon)?;
        let full = Span::new(49, 4, 31).unwrap();
        let upper = Span::new(49, 3, 47).unwrap();
        require(
            super::super::super::six_ghz_power::Constraints::parse_span(
                narf_wireless::reg::PowerType6Ghz::Lpi,
                &beacon[36..],
                full,
                full,
            )
            .is_err()
                && super::super::super::six_ghz_power::Constraints::parse_span(
                    narf_wireless::reg::PowerType6Ghz::Lpi,
                    &beacon[36..],
                    full,
                    upper,
                )
                .is_ok(),
            "native320 PSD prohibition ignored occupied frequency or leaked across narrowed span",
        )?;
        let guard = setup(model, None, false, 0x0050, Fault::None)?;
        discover(&guard, model)?;
        require(
            run(
                guard
                    .device()
                    .associate_in_domain(request_wide(model), &policy()),
                service,
            )?
            .is_err(),
            "native320 prohibited PSD reached full-span PHY",
        )?;
        let slot = HARNESS.lock();
        let wire = &slot.as_ref().unwrap().1;
        require(
            wire.air.is_empty() && !wire.commands.iter().any(|(g, c, _)| (*g, *c) == (1, 8)),
            "native320 PSD refusal performed RF/TX I/O",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz_320",
    smoke_iwl_six_ghz_320_tpe_nk_order_fifth_eirp_and_every_occupied_psd_limit
);

fn smoke_iwl_six_ghz_320_original_rfh_band_width_mcs_and_same_pn_ownership() -> TestResult {
    check(|| {
        let model = Model::default();
        let guard = setup(model, None, false, 0x0050, Fault::None)?;
        join(&guard, model)?;
        for (index, bad) in [
            0x600u32,
            0x500 | (5 << 11),
            0x50a | (4 << 11) | (1 << 16),
            0x500 | (4 << 11) | (1 << 27),
            0x500 | (4 << 11) | (1 << 25),
            0x500 | (4 << 11) | (1 << 19),
            0x500 | (4 << 11) | (1 << 17),
            0x400 | (4 << 11),
            0x400 | (3 << 11) | (1 << 17),
            0x500 | (4 << 11) | 16,
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
                &[b'W', index as u8],
            );
            let pn = 200 + index as u64;
            six_ghz_tests::inject_data(&frame, 2, model.primary, bad, pn);
            flush()?;
            require(
                !HARNESS.lock().as_ref().unwrap().1.received.contains(&frame),
                "native320 invalid original RFH rate reached PN/reorder",
            )?;
            six_ghz_tests::inject_data(&frame, 0, model.primary, 0x500 | (4 << 11) | 32, pn);
            flush()?;
            six_ghz_tests::inject_data(&frame, 2, model.primary, 0x500 | (4 << 11) | 32, pn);
            flush()?;
            six_ghz_tests::inject_data(&frame, 2, model.primary, 0x500 | (4 << 11) | 32, pn);
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
                "native320 aliased band consumed PN or valid replay escaped",
            )?;
        }
        close(&guard)
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz_320",
    smoke_iwl_six_ghz_320_original_rfh_band_width_mcs_and_same_pn_ownership
);

#[inline(never)]
fn queued_tpe_tightening() -> R {
    let model = Model::default();
    let guard = setup(model, None, false, 0x0050, Fault::None)?;
    join(&guard, model)?;
    let packet = tx_amsdu_tests::packet(0xd1, 100, false);
    let owner = guard
        .device()
        .state
        .try_lock()
        .ok_or("native320 queued DATA owner")?;
    narf_net::iface::send_on(guard.device().name(), &packet)
        .map_err(|_| "native320 queued IPC frame")?;
    drop(owner);
    let before = {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        wire.firmware
            .inject_packed(&vec![(0xab, 5, 0x8000, &[][..]); 64]);
        let mut beacon = wire.ap.beacon();
        Model {
            psd_shift: -1,
            ..model
        }
        .complete_ap_frame(&mut beacon)?;
        wire.mpdu(&beacon, false);
        wire.data.len()
    };
    drain();
    let owner = guard
        .device()
        .state
        .try_lock()
        .ok_or("native320 final-send owner")?;
    require(
        owner.hardware.is_failed() && owner.needs_reset && !owner.hardware.notifications.is_empty(),
        "native320 queued stricter PSD escaped beyond receive budget",
    )?;
    drop(owner);
    let unpublished = HARNESS.lock().as_ref().unwrap().1.data.len() == before;
    require(
        unpublished,
        "native320 stale PSD reached actual TX publication",
    )
}
#[inline(never)]
fn current_mcc_width_withdrawal() -> R {
    let model = Model::default();
    let guard = setup(model, None, false, 0x0050, Fault::None)?;
    join(&guard, model)?;
    let mut state = guard
        .device()
        .state
        .try_lock()
        .ok_or("native320 current MCC owner")?;
    let proof = state.hardware.source_fence()?;
    let program = state
        .connection
        .as_ref()
        .ok_or("native320 current station absent")?
        .regulatory_program();
    HARNESS.lock().as_mut().unwrap().1.mcc_caps_override = Some(0x18);
    let current = run(
        super::super::super::connection::regulatory_channels_in_domain(
            &mut state.hardware,
            &policy(),
        ),
        service,
    )??;
    require(
        current.he_allowed
            && current.eht_allowed
            && !current.widths.three_twenty
            && program.refresh_mcc(&policy(), current).is_err()
            && proof.invoke(|| Ok(())).is_err(),
        "native320 MCCbit16 withdrawal did not retire copied proofs independently of HE/EHT",
    )?;
    drop(state);
    drain();
    carrier(guard.device(), false)
}
#[inline(never)]
fn held_power_owner() -> R {
    let model = Model::default();
    let guard = setup(model, None, false, 0x0050, Fault::HoldSixPower)?;
    discover(&guard, model)?;
    let domain = policy();
    let mut future = Box::pin(
        guard
            .device()
            .associate_in_domain(request_wide(model), &domain),
    );
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        require(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "native320 held AP power escaped",
        )?;
        service()?;
        if HARNESS.lock().as_ref().unwrap().1.held.is_some() {
            break;
        }
        if deadline.expired() {
            return Err("native320 AP power publication bound");
        }
        narf_scheduler::sleep_pumps::run();
    }
    drop(future);
    let mut denied = domain;
    denied.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR;
    guard.policy_db.install(denied);
    {
        let mut slot = HARNESS.lock();
        let wire = &mut slot.as_mut().unwrap().1;
        let (cmd, group, sequence) = wire.held.take().ok_or("native320 held AP power missing")?;
        require(
            (group, cmd) == (4, 0xc),
            "native320 held another native receipt",
        )?;
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
            return Err("native320 dropped owner stop bound");
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
        .ok_or("native320 dropped power owner retained lock")?;
    require(
        state.needs_reset && state.hardware.is_failed() && model::retained(&state.hardware).1 != 0,
        "native320 dropped power owner released uncertain DMA",
    )?;
    drop(state);
    let slot = HARNESS.lock();
    let wire = &slot.as_ref().unwrap().1;
    require(
        wire.air.is_empty() && wire.keys == 0 && wire.data.is_empty(),
        "native320 held power loss escaped TX/key/port fence",
    )?;
    Ok(())
}
fn smoke_iwl_six_ghz_320_queued_tpe_current_mcc_and_dropped_power_owner_close_tx() -> TestResult {
    check(|| {
        queued_tpe_tightening()?;
        current_mcc_width_withdrawal()?;
        held_power_owner()
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/six_ghz_320",
    smoke_iwl_six_ghz_320_queued_tpe_current_mcc_and_dropped_power_owner_close_tx
);
