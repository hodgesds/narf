use super::*;
use crate::association::{self, Bss, JoinPlan, Phase, SecurityMode};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
const OWN: [u8; 6] = [2, 0, 0, 0, 0, 1];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 2];
macro_rules! check {
    ($condition:expr, $message:literal) => {
        if !$condition {
            return Err($message);
        }
    };
}
macro_rules! smoke {
    ($name:ident, $body:ident) => {
        fn $name() -> TestResult {
            match $body() {
                Ok(()) => TestResult::Pass,
                Err(error) => TestResult::Fail(error),
            }
        }
        kernel_test_in!("wireless/association/phy", $name);
    };
}
fn ht40() -> LocalHt {
    LocalHt::new(
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        HtWidth::TwentyForty,
        HtGi {
            rx20: true,
            tx20: true,
            rx40: true,
            tx40: true,
        },
        0,
        0,
    )
    .unwrap()
}
fn local_ht() -> LocalPhy {
    LocalPhy::ht20(LocalHt::siso20(true, true)).unwrap()
}
fn local_vht() -> LocalPhy {
    LocalPhy::vht80(
        ht40(),
        LocalVht::new(0xfffc, 0xfffc, true, true, 0).unwrap(),
    )
    .unwrap()
}
fn local_vht160() -> LocalPhy {
    LocalPhy::vht160(
        ht40(),
        LocalVht::new(0xfffe, 0xfffe, true, true, 0)
            .unwrap()
            .with_160mhz(true, true),
    )
    .unwrap()
}
fn ap160(primary: u8, center: u8, revised: bool) -> Bss {
    let index = usize::from((primary - (center - 14)) / 4);
    let mut operation = [0; 22];
    operation[0] = primary;
    operation[1] = if index & 1 == 0 { 5 } else { 7 };
    let vht = LocalVht::new(0xfffe, 0xfffe, true, true, 0)
        .unwrap()
        .with_160mhz(true, true)
        .capability_body();
    let center80 = if index < 4 { center - 8 } else { center + 8 };
    bss(
        ht40().capability_body(),
        operation,
        Some((
            vht,
            [
                if revised { 1 } else { 2 },
                if revised { center80 } else { center },
                if revised { center } else { 0 },
                0xfc,
                0xff,
            ],
        )),
        None,
    )
}
fn contiguous160() -> Result<(), &'static str> {
    for center in [50, 114, 163] {
        for index in 0..8 {
            let primary = center - 14 + index * 4;
            for revised in [false, true] {
                let ap = ap160(primary, center, revised);
                let wide =
                    prepare(&ap, local_vht160()).map_err(|_| "valid contiguous160 profile")?;
                let offer = wide.offered_phy().unwrap();
                let expected: Vec<_> = (0..8).map(|i| center - 14 + i * 4).collect();
                check!(
                    offer.width() == Width::OneSixty
                        && offer.center_channel() == center
                        && offer.occupied_channels() == expected
                        && offer.vht().unwrap().tx_sgi160()
                        && offer.vht().unwrap().rx_sgi160(),
                    "160 original geometry/GI or eight occupied channels"
                );
                check!(
                    offer.vht().unwrap().local_capability()
                        == [100, 0, 0, 0, 254, 255, 0, 0, 254, 255, 0, 0],
                    "local contiguous160 capability invented 80+80/NSS/features"
                );
                let narrow = prepare(&ap, local_vht()).map_err(|_| "80 station on160 BSS")?;
                let narrow = narrow.offered_phy().unwrap();
                let start = if index < 4 { 0 } else { 4 };
                check!(
                    narrow.width() == Width::Eighty
                        && narrow.occupied_channels() == &expected[start..start + 4]
                        && narrow.vht().unwrap().local_capability()[0] & 0x4c == 0,
                    "primary80 fallback invented a160 receive promise"
                );
            }
        }
    }
    let original = ap160(36, 50, true);
    let mut plan = ready(&original, local_vht160());
    let mut narrow = ap(true, true, None);
    let facts = bodies(&narrow);
    let mut cap = facts.vht_cap.unwrap();
    cap[0] &= !0x40;
    narrow = bss(
        facts.ht_cap.unwrap(),
        facts.ht_op.unwrap(),
        Some((cap, facts.vht_op.unwrap())),
        None,
    );
    check!(
        plan.association_response(&response(&narrow)) == Ok(Some(7)),
        "160 response could not shrink to primary80"
    );
    check!(
        plan.negotiated_phy().unwrap().width() == Width::Eighty
            && !plan.negotiated_phy().unwrap().vht().unwrap().tx_sgi160(),
        "narrowed response retained unsupported TX SGI160"
    );
    Ok(())
}
smoke!(
    smoke_phy_contiguous160_legacy_revised_and_primary80_fallback,
    contiguous160
);
fn contiguous160_boundaries() -> Result<(), &'static str> {
    let narrow = LocalVht::new(0xfffe, 0xfffe, true, true, 0).unwrap();
    let wide = narrow.with_160mhz(true, true);
    check!(
        LocalPhy::vht160(ht40(), narrow).is_err()
            && LocalPhy::vht80(ht40(), wide).is_err()
            && LocalPhy::vht160(LocalHt::siso20(true, true), wide).is_err(),
        "160 constructor accepted a mismatched local width promise"
    );
    let original = ap160(36, 50, true);
    let facts = bodies(&original);
    for operation in [
        [1, 58, 50, 252, 255],  // Wrong primary80 half.
        [1, 42, 114, 252, 255], // Discontiguous80+80.
        [2, 50, 50, 252, 255],  // Deprecated160 has no second segment.
        [2, 82, 0, 252, 255],   // Noncanonical contiguous block.
        [3, 42, 106, 252, 255], // Explicit80+80.
    ] {
        let invalid = bss(
            facts.ht_cap.unwrap(),
            facts.ht_op.unwrap(),
            Some((facts.vht_cap.unwrap(), operation)),
            None,
        );
        check!(
            prepare(&invalid, local_vht160()).is_err() && prepare(&invalid, local_vht()).is_err(),
            "invalid160 geometry became wide or narrow admission"
        );
    }
    for bits in [0u8, 12] {
        // No160 support or reserved supported-width encoding.
        let mut cap = facts.vht_cap.unwrap();
        cap[0] = (cap[0] & !12) | bits;
        let invalid = bss(
            facts.ht_cap.unwrap(),
            facts.ht_op.unwrap(),
            Some((cap, facts.vht_op.unwrap())),
            None,
        );
        check!(
            prepare(&invalid, local_vht160()).is_err(),
            "160 operation without a legal peer width capability"
        );
    }
    let mut narrow_plan = ready(&ap(true, true, None), local_vht160());
    check!(
        narrow_plan
            .association_response(&response(&original))
            .is_err()
            && narrow_plan.negotiated_phy().is_none(),
        "response expanded an80 scan offer to160"
    );
    let mut cap = facts.vht_cap.unwrap();
    cap[0] &= !64;
    let no_sgi = bss(
        facts.ht_cap.unwrap(),
        facts.ht_op.unwrap(),
        Some((cap, facts.vht_op.unwrap())),
        None,
    );
    let mut plan = ready(&no_sgi, local_vht160());
    check!(
        plan.association_response(&response(&original)) == Ok(Some(7))
            && !plan.negotiated_phy().unwrap().vht().unwrap().tx_sgi160()
            && plan.negotiated_phy().unwrap().vht().unwrap().rx_sgi160(),
        "response newly enabled TX SGI160 or erased the local RX promise"
    );
    Ok(())
}
smoke!(
    smoke_phy_contiguous160_constructor_geometry_response_and_directional_gi,
    contiguous160_boundaries
);
fn element(bytes: &mut Vec<u8>, id: u8, body: &[u8]) {
    bytes.extend_from_slice(&[id, body.len() as u8]);
    bytes.extend_from_slice(body);
}
fn bss(cap: [u8; 26], op: [u8; 22], vht: Option<([u8; 12], [u8; 5])>, selector: Option<u8>) -> Bss {
    let mut bytes = vec![0, 4, b'n', b'a', b'r', b'f', 1, 3, 0x8c, 0x98, 0xb0];
    if let Some(selector) = selector {
        element(&mut bytes, 50, &[selector]);
    }
    element(&mut bytes, 45, &cap);
    element(&mut bytes, 61, &op);
    if let Some((cap, op)) = vht {
        element(&mut bytes, 191, &cap);
        element(&mut bytes, 192, &op);
    }
    Bss {
        bssid: AP,
        ssid: b"narf".to_vec(),
        channel: op[0],
        band: None,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: bytes,
    }
}
fn ap(wide: bool, vht: bool, selector: Option<u8>) -> Bss {
    let cap = if wide {
        ht40()
    } else {
        LocalHt::siso20(true, true)
    }
    .capability_body();
    let mut op = [0; 22];
    op[0] = 36;
    op[1] = if wide { 5 } else { 0 };
    let vht = vht.then(|| {
        (
            LocalVht::new(0xfffc, 0xfffc, true, true, 0)
                .unwrap()
                .capability_body(),
            [1, 42, 0, 0xfc, 0xff],
        )
    });
    bss(cap, op, vht, selector)
}
fn prepare(ap: &Bss, local: LocalPhy) -> Result<JoinPlan, Error> {
    JoinPlan::prepare_with_phy(ap, OWN, b"narf", SecurityMode::Open, local)
}
fn response(ap: &Bss) -> Vec<u8> {
    let mut bytes = vec![0; 30];
    bytes[0] = 0x10;
    bytes[4..10].copy_from_slice(&OWN);
    bytes[10..16].copy_from_slice(&AP);
    bytes[16..22].copy_from_slice(&AP);
    bytes[24] = 1;
    bytes[28] = 7;
    bytes[29] = 0xc0;
    bytes.extend_from_slice(&ap.information_elements);
    bytes
}
fn ready(ap: &Bss, local: LocalPhy) -> JoinPlan {
    let mut plan = prepare(ap, local).unwrap();
    plan.start_authentication().unwrap();
    let mut auth = vec![0; 30];
    auth[0] = 0xb0;
    auth[4..10].copy_from_slice(&OWN);
    auth[10..16].copy_from_slice(&AP);
    auth[16..22].copy_from_slice(&AP);
    auth[26] = 2;
    plan.authentication_response(&auth).unwrap().unwrap();
    plan
}
fn bodies(ap: &Bss) -> ApElements {
    ApElements::parse(&ap.information_elements).unwrap()
}

fn local_encoding() -> Result<(), &'static str> {
    let ht = LocalHt::siso20(true, false).capability_body();
    check!(
        ht[..4] == [0x2c, 0, 0, 255] && ht[4..15] == [0; 11] && ht[15] == 1 && ht[16..] == [0; 10],
        "local HT encoded an unimplemented feature"
    );
    check!(
        ht40().capability_body()[..4] == [0x6e, 0, 0, 255],
        "local HT40 GI/width bits differ from IEEE encoding"
    );
    let asymmetric = LocalHt::new(
        [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [255, 255, 0, 0, 0, 0, 0, 0, 0, 0],
        HtWidth::Twenty,
        HtGi::default(),
        3,
        7,
    )
    .unwrap()
    .capability_body();
    check!(
        asymmetric[..4] == [12, 0, 31, 255] && asymmetric[15] == 7,
        "local asymmetric MCS TX stream metadata or aggregation fields differ"
    );
    for (rx, tx) in [
        (
            [127, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
        (
            [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [127, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ),
    ] {
        check!(
            LocalHt::new(rx, tx, HtWidth::Twenty, HtGi::default(), 0, 0).is_err(),
            "local HT omitted mandatory implemented MCS0..7"
        );
    }
    let actual = LocalHt::siso20(true, true);
    let selected = actual
        .with_tx_selection([0xf0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        .unwrap();
    check!(
        actual.capability_body() == selected.capability_body()
            && actual.with_tx_selection([0; 10]).is_err()
            && actual
                .with_tx_selection([255, 1, 0, 0, 0, 0, 0, 0, 0, 0])
                .is_err(),
        "TX selection changed local capability or exceeded implemented support"
    );
    let mut peer = actual.capability_body();
    peer[3] = 0x3f;
    let mut op = [0; 22];
    op[0] = 36;
    let selected_plan = prepare(
        &bss(peer, op, None, None),
        LocalPhy::ht20(selected).unwrap(),
    )
    .unwrap();
    check!(
        selected_plan.offered_phy().unwrap().ht().tx_mcs()[0] == 0x30
            && selected_plan.offered_phy().unwrap().ht().rx_mcs()[0] == 255,
        "local TX policy escaped intersection or narrowed advertised RX"
    );
    let vht = LocalVht::new(0xfffc, 0xfffd, true, false, 3)
        .unwrap()
        .capability_body();
    check!(
        vht == [0x20, 0, 0x80, 1, 0xfc, 0xff, 0, 0, 0xfd, 0xff, 0, 0],
        "local VHT wire layout differs"
    );
    check!(
        LocalHt::new([0; 10], [255; 10], HtWidth::Twenty, HtGi::default(), 0, 0).is_err(),
        "empty/reserved local MCS admitted"
    );
    check!(
        LocalPhy::ht20(ht40()).is_err()
            && LocalPhy::vht80(
                LocalHt::siso20(false, false),
                LocalVht::new(0xfffc, 0xfffc, false, false, 0).unwrap()
            )
            .is_err(),
        "inconsistent local width admitted"
    );
    check!(
        LocalVht::new(0xffff, 0xfffc, false, false, 0).is_err()
            && LocalVht::new(0xfffc, 0xfffc, false, false, 8).is_err(),
        "invalid local VHT admitted"
    );
    Ok(())
}
smoke!(smoke_phy_local_exact_encoding_and_bounds, local_encoding);

fn parser_extents() -> Result<(), &'static str> {
    let ap = ap(true, true, None);
    let facts = bodies(&ap);
    for (id, body) in [
        (45, facts.ht_cap.unwrap().to_vec()),
        (61, facts.ht_op.unwrap().to_vec()),
        (191, facts.vht_cap.unwrap().to_vec()),
        (192, facts.vht_op.unwrap().to_vec()),
    ] {
        for delta in [-1isize, 1] {
            let mut wrong = Vec::new();
            let mut body = body.clone();
            body.resize((body.len() as isize + delta) as usize, 0);
            element(&mut wrong, id, &body);
            check!(
                ApElements::parse(&wrong).is_err(),
                "short/overlong PHY body admitted"
            );
        }
        let mut duplicate = ap.information_elements.clone();
        element(&mut duplicate, id, &body);
        check!(
            ApElements::parse(&duplicate).is_err(),
            "duplicate PHY admitted"
        );
    }
    let mut tail = ap.information_elements.clone();
    tail.extend_from_slice(&[200, 2, 0]);
    check!(
        ApElements::parse(&tail).is_err() && ApElements::parse(&vec![0; 2050]).is_err(),
        "malformed tail/unbounded parse admitted"
    );
    Ok(())
}
smoke!(
    smoke_phy_exact_singletons_and_complete_extents,
    parser_extents
);

fn orphan_and_reserved() -> Result<(), &'static str> {
    let facts = bodies(&ap(true, true, None));
    for (id, body) in [
        (45, facts.ht_cap.unwrap().to_vec()),
        (61, facts.ht_op.unwrap().to_vec()),
        (191, facts.vht_cap.unwrap().to_vec()),
        (192, facts.vht_op.unwrap().to_vec()),
    ] {
        let mut bytes = Vec::new();
        element(&mut bytes, id, &body);
        check!(
            ApElements::parse(&bytes).is_err(),
            "orphan PHY element admitted"
        );
    }
    for (offset, bit) in [
        (1, 0x20),
        (2, 0x20),
        (12, 0x80),
        (14, 0x80),
        (15, 0x80),
        (16, 1),
    ] {
        let mut cap = facts.ht_cap.unwrap();
        cap[offset] |= bit;
        check!(
            prepare(&bss(cap, facts.ht_op.unwrap(), None, None), local_ht()).is_err(),
            "reserved HT encoding admitted"
        );
    }
    Ok(())
}
smoke!(smoke_phy_orphan_and_reserved_encodings, orphan_and_reserved);

fn selectors() -> Result<(), &'static str> {
    for selector in (0xf8..=0xff).chain([0xf7]) {
        let ht = ap(false, false, Some(selector));
        let vht = ap(true, true, Some(selector));
        check!(
            JoinPlan::prepare(&ht, OWN, b"narf", SecurityMode::Open).is_err(),
            "legacy accepted mandatory selector"
        );
        check!(
            prepare(&ht, local_ht()).is_ok() == (selector == 0xff),
            "HT selector admission differs"
        );
        check!(
            prepare(&vht, local_vht()).is_ok() == matches!(selector, 0xff | 0xfe),
            "VHT selector admission differs"
        );
    }
    for optional in [0x7f, 0x7e, 0x7a] {
        let ap = ap(false, false, Some(optional));
        let plan = JoinPlan::prepare(&ap, OWN, b"narf", SecurityMode::Open).unwrap();
        check!(
            plan.legacy_rates()
                == (
                    (1 << 4) | (1 << 6) | (1 << 8),
                    (1 << 4) | (1 << 6) | (1 << 8)
                ),
            "optional selector became a legacy rate"
        );
    }
    Ok(())
}
smoke!(
    smoke_phy_all_membership_selectors_and_legacy_defaults,
    selectors
);

fn selector_requirements() -> Result<(), &'static str> {
    let mut ap = ap(false, false, None);
    ap.information_elements = vec![0, 4, b'n', b'a', b'r', b'f', 1, 2, 0xff, 0xfe];
    check!(
        prepare(&ap, local_vht()).is_err(),
        "selector-only BSS acquired management rates"
    );
    ap.information_elements = vec![0, 4, b'n', b'a', b'r', b'f', 1, 2, 0x8c, 0xff];
    check!(
        prepare(&ap, local_ht()).is_err(),
        "HT selector accepted absent HT"
    );
    ap.information_elements.pop();
    ap.information_elements[7] = 1;
    let plan = prepare(&ap, local_ht()).unwrap();
    check!(
        plan.offered_phy().is_none(),
        "absent optional HT did not retain legacy"
    );
    Ok(())
}
smoke!(
    smoke_phy_selectors_require_complete_phy_and_legacy_basics,
    selector_requirements
);

struct Raw(Vec<u8>, bool);
impl crate::station_security::RawFrame for Raw {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn unmodified(&self) -> bool {
        self.1
    }
}
fn observation() -> Result<(), &'static str> {
    let ap = ap(false, false, Some(0xff));
    let mut bytes = vec![0; 36];
    bytes[0] = 0x80;
    bytes[4..10].fill(255);
    bytes[10..16].copy_from_slice(&AP);
    bytes[16..22].copy_from_slice(&AP);
    bytes[32] = 100;
    bytes[34] = 1;
    bytes.extend_from_slice(&ap.information_elements);
    let mut frame = Raw(bytes, true);
    check!(
        association::observe(&frame, 36, OWN, None).is_err(),
        "legacy observer accepted HT selector"
    );
    let observed = association::observe_with_phy(&frame, 36, OWN, Some(-42), &local_ht()).unwrap();
    check!(
        observed.bss.information_elements == ap.information_elements
            && observed.bss.signal_dbm == Some(-42),
        "observer changed bound original facts"
    );
    check!(
        prepare(&observed.bss, local_ht()).is_ok(),
        "observer/plan admission disagree"
    );
    check!(
        association::observe_with_phy(&frame, 40, OWN, None, &local_ht()).is_err(),
        "PHY observation ignored retained channel"
    );
    frame.1 = false;
    check!(
        association::observe_with_phy(&frame, 36, OWN, None, &local_ht()).is_err(),
        "modified RAW admitted"
    );
    Ok(())
}
smoke!(
    smoke_phy_observer_and_plan_bind_original_raw_bss,
    observation
);

fn ht_directionality() -> Result<(), &'static str> {
    let mut cap = LocalHt::siso20(false, false).capability_body();
    cap[3] = 0xf0;
    cap[15] = 0;
    let mut op = [0; 22];
    op[0] = 36;
    let local = LocalPhy::ht20(
        LocalHt::new(
            [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [255, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            HtWidth::Twenty,
            HtGi {
                rx20: true,
                tx20: true,
                ..Default::default()
            },
            0,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    let ap = bss(cap, op, None, None);
    let plan = prepare(&ap, local).unwrap();
    let ht = plan.offered_phy().unwrap().ht();
    check!(
        ht.tx_mcs()[0] == 0xf0 && ht.rx_mcs()[0] == 255 && ht.peer_rx_mcs()[0] == 0xf0,
        "HT TX intersection overwrote local RX"
    );
    check!(
        ht.rx_sgi20() && !ht.tx_sgi20() && ht.peer_tx_params() == 0,
        "AP RX GI/undefined TX became local RX bound"
    );
    cap[15] = 1 | 2 | 4;
    let ap = bss(cap, op, None, None);
    check!(
        prepare(&ap, local)
            .unwrap()
            .offered_phy()
            .unwrap()
            .ht()
            .peer_tx_params()
            == 7,
        "distinct peer TX params discarded"
    );
    Ok(())
}
smoke!(
    smoke_phy_ht_directional_mcs_gi_and_peer_tx_facts,
    ht_directionality
);

fn ldpc_directionality() -> Result<(), &'static str> {
    for (local_rx, local_tx, scan_rx, response_rx) in [
        (false, false, true, true),
        (true, false, true, true),
        (false, true, true, true),
        (true, true, false, true),
        (true, true, true, false),
        (true, true, true, true),
    ] {
        let local = LocalPhy::vht80(
            ht40().with_ldpc(local_rx, local_tx),
            LocalVht::new(0xfffe, 0xfffe, true, true, 0)
                .unwrap()
                .with_ldpc(local_rx, local_tx),
        )
        .unwrap();
        let original = ap(true, true, None);
        let facts = bodies(&original);
        let mut ht = facts.ht_cap.unwrap();
        let mut vht = facts.vht_cap.unwrap();
        ht[0] |= u8::from(scan_rx);
        vht[0] |= u8::from(scan_rx) << 4;
        let scan = bss(
            ht,
            facts.ht_op.unwrap(),
            Some((vht, facts.vht_op.unwrap())),
            None,
        );
        let mut plan = ready(&scan, local);
        let offered = plan.offered_phy().unwrap();
        check!(
            offered.ht().rx_ldpc() == local_rx
                && offered.vht().unwrap().rx_ldpc() == local_rx
                && offered.ht().tx_ldpc() == (local_tx && scan_rx)
                && offered.vht().unwrap().tx_ldpc() == (local_tx && scan_rx),
            "LDPC scan directions were conflated"
        );
        ht[0] = (ht[0] & !1) | u8::from(response_rx);
        vht[0] = (vht[0] & !16) | (u8::from(response_rx) << 4);
        let reply = bss(
            ht,
            facts.ht_op.unwrap(),
            Some((vht, facts.vht_op.unwrap())),
            None,
        );
        check!(
            plan.association_response(&response(&reply)) == Ok(Some(7)),
            "compatible LDPC response failed"
        );
        let negotiated = plan.negotiated_phy().unwrap();
        let tx = local_tx && scan_rx && response_rx;
        check!(
            negotiated.ht().rx_ldpc() == local_rx
                && negotiated.vht().unwrap().rx_ldpc() == local_rx
                && negotiated.ht().tx_ldpc() == tx
                && negotiated.vht().unwrap().tx_ldpc() == tx,
            "LDPC response promoted TX or replaced local RX"
        );
        check!(
            negotiated.ht().local_capability()[0] & 1 == u8::from(local_rx)
                && negotiated.vht().unwrap().local_capability()[0] & 16 == u8::from(local_rx) << 4,
            "LDPC local capability encoded peer or transmit support"
        );
    }
    check!(
        LocalHt::siso20(true, true).capability_body()[0] & 1 == 0
            && LocalVht::new(0xfffc, 0xfffc, true, true, 0)
                .unwrap()
                .capability_body()[0]
                & 16
                == 0,
        "LDPC became implicit for existing constructors"
    );
    Ok(())
}
smoke!(
    smoke_phy_ldpc_local_receive_and_bound_transmit_are_independent,
    ldpc_directionality
);

fn rx_stbc_promise() -> Result<(), &'static str> {
    for enabled in [false, true] {
        let ht = ht40().with_rx_stbc(enabled);
        let vht = LocalVht::new(0xfffe, 0xfffe, true, true, 0)
            .unwrap()
            .with_rx_stbc(enabled);
        check!(
            ht.capability_body()[1] & 3 == u8::from(enabled)
                && ht.capability_body()[0] & 128 == 0
                && vht.capability_body()[1] & 7 == u8::from(enabled)
                && vht.capability_body()[0] & 128 == 0,
            "RX STBC1 encoded TX STBC or extra data streams"
        );
        let local = LocalPhy::vht80(ht, vht).unwrap();
        let original = ap(true, true, None);
        let mut plan = ready(&original, local);
        check!(
            plan.offered_phy().unwrap().ht().rx_stbc() == enabled
                && plan.offered_phy().unwrap().vht().unwrap().rx_stbc() == enabled,
            "peer facts replaced local STBC receive promise"
        );
        check!(
            plan.association_response(&response(&original)) == Ok(Some(7)),
            "STBC local promise prevented compatible association"
        );
        check!(
            plan.negotiated_phy().unwrap().ht().rx_stbc() == enabled
                && plan.negotiated_phy().unwrap().vht().unwrap().rx_stbc() == enabled,
            "association response lost local RX STBC promise"
        );
    }
    Ok(())
}
smoke!(
    smoke_phy_rx_stbc1_never_promises_transmit_stbc,
    rx_stbc_promise
);

fn ht_basic_and_narrowing() -> Result<(), &'static str> {
    let scan = ap(false, false, None);
    let facts = bodies(&scan);
    let mut cap = facts.ht_cap.unwrap();
    cap[3] = 15;
    let offered = bss(cap, facts.ht_op.unwrap(), None, None);
    let mut plan = ready(&offered, local_ht());
    cap[3] = 0xf3;
    cap[0] &= !0x20;
    check!(
        plan.association_response(&response(&bss(cap, facts.ht_op.unwrap(), None, None)))
            == Ok(Some(7)),
        "compatible HT response rejected"
    );
    let ht = plan.negotiated_phy().unwrap().ht();
    check!(
        ht.tx_mcs()[0] == 3 && ht.rx_mcs()[0] == 255 && ht.rx_sgi20() && !ht.tx_sgi20(),
        "HT response escaped offer or damaged RX"
    );
    let mut op = facts.ht_op.unwrap();
    op[7] = 1;
    check!(
        prepare(&bss(facts.ht_cap.unwrap(), op, None, None), local_ht()).is_err(),
        "unsupported basic HT MCS admitted at scan"
    );
    let mut plan = ready(&scan, local_ht());
    check!(
        plan.association_response(&response(&bss(facts.ht_cap.unwrap(), op, None, None)))
            .is_err()
            && plan.phase() == Phase::Failed
            && plan.negotiated_phy().is_none(),
        "unsupported response basic HT committed"
    );
    Ok(())
}
smoke!(
    smoke_phy_ht_response_intersection_and_basic_mcs,
    ht_basic_and_narrowing
);

fn ht_geometry() -> Result<(), &'static str> {
    let ap = ap(true, false, None);
    let facts = bodies(&ap);
    let plan = prepare(&ap, local_ht()).unwrap();
    check!(
        plan.offered_phy().unwrap().width() == Width::Twenty
            && plan.offered_phy().unwrap().occupied_channels() == [36],
        "HT20 promoted by wider AP"
    );
    let plan = prepare(&ap, LocalPhy::ht40(ht40()).unwrap()).unwrap();
    check!(
        plan.offered_phy().unwrap().width() == Width::Forty
            && plan.offered_phy().unwrap().occupied_channels() == [36, 40],
        "HT40 geometry differs"
    );
    for (offset, value) in [(0, 40), (1, 6), (1, 1), (1, 4), (1, 7)] {
        let mut op = facts.ht_op.unwrap();
        op[offset] = value;
        let mut wrong = bss(facts.ht_cap.unwrap(), op, None, None);
        wrong.channel = 36;
        check!(
            prepare(&wrong, local_ht()).is_err(),
            "invalid primary/secondary/width accepted"
        );
    }
    Ok(())
}
smoke!(smoke_phy_ht_primary_secondary_and_local_width, ht_geometry);

fn atomic_response() -> Result<(), &'static str> {
    let ap = ap(false, false, None);
    let mut plan = ready(&ap, local_ht());
    let old = plan.legacy_rates();
    let mut bytes = response(&ap);
    element(&mut bytes, 61, &bodies(&ap).ht_op.unwrap());
    check!(
        plan.association_response(&bytes).is_err()
            && plan.phase() == Phase::Failed
            && plan.legacy_rates() == old
            && plan.negotiated_phy().is_none(),
        "late malformed PHY partially committed rates/AID"
    );
    let mut plan = ready(&ap, local_ht());
    let mut bytes = response(&ap);
    bytes[10] ^= 4;
    check!(
        plan.association_response(&bytes) == Ok(None) && plan.phase() == Phase::AwaitAssociation,
        "other peer consumed transaction"
    );
    plan.cancel();
    check!(
        plan.association_response(&response(&ap)) == Err(Error::Busy)
            && plan.negotiated_phy().is_none(),
        "cancelled PHY plan restarted"
    );
    Ok(())
}
smoke!(
    smoke_phy_response_is_atomic_peer_bound_and_cancellable,
    atomic_response
);

fn missing_response_and_selectors() -> Result<(), &'static str> {
    let scan = ap(false, false, Some(0xff));
    let old = prepare(&scan, local_ht()).unwrap().legacy_rates();
    let mut missing = response(&scan);
    missing.truncate(30);
    element(&mut missing, 1, &[0x8c, 0x98, 0xb0]);
    let mut plan = ready(&scan, local_ht());
    check!(
        plan.association_response(&missing).is_err()
            && plan.legacy_rates() == old
            && plan.negotiated_phy().is_none(),
        "missing response HT silently became legacy"
    );
    for selector in [0xfe, 0xfa, 0xf7] {
        let mut plan = ready(&scan, local_ht());
        let mut reply = response(&ap(false, false, None));
        element(&mut reply, 50, &[selector]);
        check!(
            plan.association_response(&reply).is_err() && plan.negotiated_phy().is_none(),
            "response gained unsupported membership"
        );
    }
    Ok(())
}
smoke!(
    smoke_phy_missing_response_and_new_membership_fail_closed,
    missing_response_and_selectors
);

fn local_ie_and_sme() -> Result<(), &'static str> {
    let ap = ap(true, true, None);
    let mut plan = prepare(&ap, local_vht()).unwrap();
    for id in [45, 61, 191, 192] {
        let mut injection = Vec::new();
        element(&mut injection, id, &[0]);
        check!(
            plan.append_sme_ies(&injection).is_err(),
            "caller injected protocol-owned PHY"
        );
    }
    plan.start_authentication().unwrap();
    let mut auth = vec![0; 30];
    auth[0] = 0xb0;
    auth[4..10].copy_from_slice(&OWN);
    auth[10..16].copy_from_slice(&AP);
    auth[16..22].copy_from_slice(&AP);
    auth[26] = 2;
    let request = plan.authentication_response(&auth).unwrap().unwrap();
    let mut ht = None;
    let mut vht = None;
    ies(&request[28..], |id, body| {
        if id == 45 {
            ht = Some(body.to_vec());
        }
        if id == 191 {
            vht = Some(body.to_vec());
        }
        Ok(())
    })
    .unwrap();
    check!(
        ht.as_deref() == Some(ht40().capability_body().as_slice())
            && vht.as_deref()
                == Some(
                    LocalVht::new(0xfffc, 0xfffc, true, true, 0)
                        .unwrap()
                        .capability_body()
                        .as_slice()
                ),
        "request copied peer feature flags"
    );
    check!(
        plan.negotiated_phy().is_none() && plan.phase() == Phase::AwaitAssociation,
        "local capability publication granted association"
    );
    Ok(())
}
smoke!(
    smoke_phy_generated_local_ies_and_caller_injection_denial,
    local_ie_and_sme
);

fn maps_all_entries() -> Result<(), &'static str> {
    for n in 0..8 {
        for a in 0..4 {
            for b in 0..4 {
                let left = !(3 << (2 * n)) | a << (2 * n);
                let right = !(3 << (2 * n)) | b << (2 * n);
                let expected = if a == 3 || b == 3 { 3 } else { a.min(b) };
                check!(
                    intersect_maps(left, right) >> (2 * n) & 3 == expected,
                    "per-NSS VHT intersection differs"
                );
            }
        }
    }
    check!(
        !supports_map(0xfffc, 0) && supports_map(0xfffc, 0xfffc) && !supports_map(0xfffc, 0xfff0),
        "zero/basic VHT map treated as empty"
    );
    Ok(())
}
smoke!(smoke_phy_vht_all_nss_map_encodings, maps_all_entries);

fn vht_directionality() -> Result<(), &'static str> {
    let ap = ap(true, true, None);
    let facts = bodies(&ap);
    let mut cap = facts.vht_cap.unwrap();
    cap[4..6].copy_from_slice(&0xfffcu16.to_le_bytes());
    cap[8..10].copy_from_slice(&0xfffeu16.to_le_bytes());
    cap[0] &= !0x20;
    let local = LocalPhy::vht80(
        ht40(),
        LocalVht::new(0xfffe, 0xfffd, true, true, 0).unwrap(),
    )
    .unwrap();
    let ap = bss(
        facts.ht_cap.unwrap(),
        facts.ht_op.unwrap(),
        Some((cap, facts.vht_op.unwrap())),
        None,
    );
    let plan = prepare(&ap, local).unwrap();
    let vht = plan.offered_phy().unwrap().vht().unwrap();
    check!(
        vht.rx_mcs_map() == 0xfffe
            && vht.tx_mcs_map() == 0xfffc
            && vht.peer_tx_mcs_map() == 0xfffe
            && vht.rx_sgi80()
            && !vht.tx_sgi80(),
        "VHT peer RX replaced local RX or GI"
    );
    let mut plan = ready(&ap, local);
    cap[4..6].copy_from_slice(&0xfffeu16.to_le_bytes());
    cap[0] |= 0x20;
    let reply = bss(
        facts.ht_cap.unwrap(),
        facts.ht_op.unwrap(),
        Some((cap, facts.vht_op.unwrap())),
        None,
    );
    plan.association_response(&response(&reply)).unwrap();
    let vht = plan.negotiated_phy().unwrap().vht().unwrap();
    check!(
        vht.tx_mcs_map() == 0xfffc && !vht.tx_sgi80() && vht.rx_sgi80(),
        "response restored unoffered VHT TX MCS/GI"
    );
    Ok(())
}
smoke!(
    smoke_phy_vht_directional_maps_and_scan_response_bounds,
    vht_directionality
);

fn vht_basic() -> Result<(), &'static str> {
    let ap = ap(true, true, None);
    let facts = bodies(&ap);
    for map in [0u16, 0xfff0, 0xfffd] {
        let mut op = facts.vht_op.unwrap();
        op[3..5].copy_from_slice(&map.to_le_bytes());
        let wrong = bss(
            facts.ht_cap.unwrap(),
            facts.ht_op.unwrap(),
            Some((facts.vht_cap.unwrap(), op)),
            None,
        );
        check!(
            prepare(&wrong, local_vht()).is_err(),
            "unsupported basic VHT map admitted"
        );
        let mut plan = ready(&ap, local_vht());
        check!(
            plan.association_response(&response(&wrong)).is_err()
                && plan.negotiated_phy().is_none(),
            "response basic VHT map committed"
        );
    }
    for (rx, tx) in [(0xfffc, 0xfffd), (0xfffd, 0xfffc)] {
        let local =
            LocalPhy::vht80(ht40(), LocalVht::new(rx, tx, false, false, 0).unwrap()).unwrap();
        let mut cap = facts.vht_cap.unwrap();
        cap[4..6].copy_from_slice(&0xfffdu16.to_le_bytes());
        let mut op = facts.vht_op.unwrap();
        op[3..5].copy_from_slice(&0xfffdu16.to_le_bytes());
        check!(
            prepare(
                &bss(
                    facts.ht_cap.unwrap(),
                    facts.ht_op.unwrap(),
                    Some((cap, op)),
                    None
                ),
                local
            )
            .is_err(),
            "one-direction VHT basic deficiency admitted"
        );
    }
    Ok(())
}
smoke!(
    smoke_phy_vht_basic_mcs_both_directions_and_zero_map,
    vht_basic
);

fn vht_geometry() -> Result<(), &'static str> {
    for center in [42u8, 58, 106, 122, 138, 155, 171] {
        let channels = [center - 6, center - 2, center + 2, center + 6];
        for (i, primary) in channels.iter().enumerate() {
            let mut ht_op = [0; 22];
            ht_op[0] = *primary;
            ht_op[1] = if i % 2 == 0 { 5 } else { 7 };
            let vht = LocalVht::new(0xfffc, 0xfffc, true, true, 0)
                .unwrap()
                .capability_body();
            let ap = bss(
                ht40().capability_body(),
                ht_op,
                Some((vht, [1, center, 0, 0xfc, 0xff])),
                Some(0xfe),
            );
            let plan = prepare(&ap, local_vht()).unwrap();
            let offer = plan.offered_phy().unwrap();
            check!(
                offer.width() == Width::Eighty
                    && offer.center_channel() == center
                    && offer.occupied_channels() == channels,
                "VHT80 primary position/occupied set differs"
            );
        }
    }
    Ok(())
}
smoke!(
    smoke_phy_vht80_all_canonical_primary_positions,
    vht_geometry
);

fn vht_bad_geometry() -> Result<(), &'static str> {
    let ap = ap(true, true, None);
    let facts = bodies(&ap);
    for op in [
        [2, 50, 0, 0xfc, 0xff],
        [3, 42, 155, 0xfc, 0xff],
        [1, 42, 50, 0xfc, 0xff],
        [1, 46, 0, 0xfc, 0xff],
        [1, 58, 0, 0xfc, 0xff],
        [0, 44, 0, 0xfc, 0xff],
    ] {
        check!(
            prepare(
                &bss(
                    facts.ht_cap.unwrap(),
                    facts.ht_op.unwrap(),
                    Some((facts.vht_cap.unwrap(), op)),
                    None
                ),
                local_vht()
            )
            .is_err(),
            "unsupported/noncanonical VHT geometry admitted"
        );
    }
    let mut ht_op = facts.ht_op.unwrap();
    ht_op[1] = 7;
    check!(
        prepare(
            &bss(
                facts.ht_cap.unwrap(),
                ht_op,
                Some((facts.vht_cap.unwrap(), facts.vht_op.unwrap())),
                None
            ),
            local_vht()
        )
        .is_err(),
        "VHT primary disagreed with HT40 pair"
    );
    Ok(())
}
smoke!(
    smoke_phy_vht160_80p80_and_wrong_geometry_denied,
    vht_bad_geometry
);

fn vht_narrow_response() -> Result<(), &'static str> {
    let ap = ap(true, true, None);
    let facts = bodies(&ap);
    for wide in [false, true] {
        let mut ht_op = facts.ht_op.unwrap();
        if !wide {
            ht_op[1] = 0;
        }
        let reply = bss(
            facts.ht_cap.unwrap(),
            ht_op,
            Some((facts.vht_cap.unwrap(), [0, 0, 0, 0xfc, 0xff])),
            None,
        );
        let mut plan = ready(&ap, local_vht());
        plan.association_response(&response(&reply)).unwrap();
        let phy = plan.negotiated_phy().unwrap();
        check!(
            phy.width() == if wide { Width::Forty } else { Width::Twenty },
            "VHT width0 did not delegate to HT"
        );
        check!(
            phy.occupied_channels() == if wide { &[36, 40][..] } else { &[36][..] },
            "narrowed VHT occupied set differs"
        );
    }
    let narrow = bss(
        facts.ht_cap.unwrap(),
        facts.ht_op.unwrap(),
        Some((facts.vht_cap.unwrap(), [0, 0, 0, 0xfc, 0xff])),
        None,
    );
    let mut plan = ready(&narrow, local_vht());
    check!(
        plan.association_response(&response(&ap)).is_err() && plan.negotiated_phy().is_none(),
        "response widened original occupied set"
    );
    Ok(())
}
smoke!(
    smoke_phy_vht_width0_and_response_narrowing_only,
    vht_narrow_response
);

fn supported_rate_selectors() -> Result<(), &'static str> {
    for id in [1, 50] {
        let mut scan = ap(false, false, None);
        if id == 1 {
            scan.information_elements[7] = 4;
            scan.information_elements.insert(11, 0xff);
        } else {
            element(&mut scan.information_elements, 50, &[0xff]);
        }
        let mut plan = ready(&scan, local_ht());
        check!(
            plan.association_response(&response(&scan)) == Ok(Some(7)),
            "selector placement changed valid admission"
        );
        check!(
            plan.legacy_rates()
                == (
                    (1 << 4) | (1 << 6) | (1 << 8),
                    (1 << 4) | (1 << 6) | (1 << 8)
                ),
            "membership leaked into rate bitmap"
        );
        plan.cancel();
        check!(
            plan.negotiated_phy().is_none() && plan.phase() == Phase::Failed,
            "cancel retained a completed PHY result"
        );
    }
    Ok(())
}
smoke!(
    smoke_phy_selectors_in_both_rate_elements_and_cancel,
    supported_rate_selectors
);

fn wpa2_and_security_response() -> Result<(), &'static str> {
    let mut scan = ap(false, false, None);
    scan.capability = 17;
    element(
        &mut scan.information_elements,
        48,
        &crate::rsn::RsnIe::wpa2_psk_ccmp().encode_body(),
    );
    let mut plan =
        JoinPlan::prepare_with_phy(&scan, OWN, b"narf", SecurityMode::Wpa2Psk, local_ht()).unwrap();
    plan.start_authentication().unwrap();
    let mut auth = vec![0; 30];
    auth[0] = 0xb0;
    auth[4..10].copy_from_slice(&OWN);
    auth[10..16].copy_from_slice(&AP);
    auth[16..22].copy_from_slice(&AP);
    auth[26] = 2;
    let request = plan.authentication_response(&auth).unwrap().unwrap();
    let mut rsn = None;
    ies(&request[28..], |id, body| {
        if id == 48 {
            rsn = Some(body.to_vec());
        }
        Ok(())
    })
    .unwrap();
    check!(
        rsn == Some(crate::rsn::RsnIe::wpa2_psk_ccmp().encode_body()),
        "typed path changed negotiated client RSNE"
    );
    let mut reply = response(&scan);
    reply[24] = 17;
    check!(
        plan.association_response(&reply) == Ok(Some(7))
            && plan.negotiated_phy().is_some()
            && plan.security() == SecurityMode::Wpa2Psk,
        "WPA2 typed response rejected"
    );
    let scan = ap(false, false, None);
    let mut plan = ready(&scan, local_ht());
    let old = plan.legacy_rates();
    let mut reply = response(&scan);
    element(
        &mut reply,
        48,
        &crate::rsn::RsnIe::wpa2_psk_ccmp().encode_body(),
    );
    check!(
        plan.association_response(&reply) == Err(Error::UnsupportedSecurity)
            && plan.phase() == Phase::Failed
            && plan.negotiated_phy().is_none()
            && plan.legacy_rates() == old,
        "late RSNE changed Open security or partially committed"
    );
    Ok(())
}
smoke!(
    smoke_phy_wpa2_response_and_security_atomicity,
    wpa2_and_security_response
);

fn disjoint_and_no_malformed_fallback() -> Result<(), &'static str> {
    let scan = ap(false, false, None);
    let facts = bodies(&scan);
    let mut cap = facts.ht_cap.unwrap();
    cap[3] = 0;
    cap[4] = 255;
    check!(
        prepare(&bss(cap, facts.ht_op.unwrap(), None, None), local_ht()).is_err(),
        "disjoint optional HT silently became legacy"
    );
    let mut plan = ready(&scan, local_ht());
    let old = plan.legacy_rates();
    check!(
        plan.association_response(&response(&bss(cap, facts.ht_op.unwrap(), None, None)))
            .is_err()
            && plan.legacy_rates() == old
            && plan.negotiated_phy().is_none(),
        "disjoint response committed"
    );
    let mut malformed = scan.clone();
    element(&mut malformed.information_elements, 45, &cap);
    check!(
        prepare(&malformed, local_ht()).is_err(),
        "malformed optional PHY became fallback"
    );
    let mut op = facts.ht_op.unwrap();
    op[1] = 5;
    check!(
        prepare(&bss(facts.ht_cap.unwrap(), op, None, None), local_ht()).is_err(),
        "HT40 operation with HT20-only AP capability admitted"
    );
    Ok(())
}
smoke!(
    smoke_phy_disjoint_mcs_and_malformed_optional_fail_closed,
    disjoint_and_no_malformed_fallback
);

fn native_element_snapshots() -> Result<(), &'static str> {
    let scan = ap160(36, 50, true);
    let offer = Offer::from_elements(local_vht160(), &scan.information_elements, 36)
        .map_err(|_| "native snapshot original160")?
        .ok_or("native snapshot missing HT")?;
    let plan = prepare(&scan, local_vht160()).map_err(|_| "native snapshot host plan")?;
    check!(
        Some(&offer) == plan.offered_phy()
            && offer.width() == Width::OneSixty
            && offer.occupied_channels() == [36, 40, 44, 48, 52, 56, 60, 64],
        "pure snapshot invented different native PHY facts"
    );
    let reply = ap(true, true, Some(0xfe));
    let negotiated = offer
        .response_elements(&reply.information_elements)
        .map_err(|_| "native snapshot valid primary80 response")?;
    check!(
        negotiated.width() == Width::Eighty
            && negotiated.center_channel() == 42
            && negotiated.occupied_channels() == [36, 40, 44, 48],
        "native response did not retain its real narrower geometry"
    );
    check!(
        Offer::from_elements(local_vht(), &[1, 1, 0x8c], 36) == Ok(None),
        "optional missing PHY could not retain legacy facts"
    );
    Ok(())
}
smoke!(
    smoke_phy_native_element_snapshots_share_exact_offer_and_response_geometry,
    native_element_snapshots
);

fn native_element_validation() -> Result<(), &'static str> {
    let scan = ap(true, true, Some(0xfe));
    let offer = Offer::from_elements(local_vht(), &scan.information_elements, 36)
        .unwrap()
        .unwrap();
    for bytes in [
        vec![],
        vec![1, 0],
        vec![1, 1, 0x8c, 1, 1, 0x98],
        vec![1, 1, 0x8c, 50, 1, 0xff, 50, 1, 0xfe],
        vec![1, 1, 0x82],              // CCK basic on5GHz.
        vec![1, 1, 0x7f],              // Unflagged selector is not a basic legacy rate.
        vec![1, 1, 0x8c, 50, 1, 0xfd], // Unsupported mandatory HE selector.
        vec![1, 9, 0x8c],
        vec![0; 2049],
    ] {
        check!(
            Offer::from_elements(local_vht(), &bytes, 36).is_err()
                && offer.response_elements(&bytes).is_err(),
            "native snapshot malformed rates or unsupported selector admitted"
        );
    }
    for selector in [0xff, 0xfe] {
        check!(
            Offer::from_elements(local_vht(), &[1, 1, 0x8c, 50, 1, selector], 36)
                == Err(Error::UnsupportedRates),
            "mandatory PHY selector admitted without that PHY"
        );
    }
    check!(
        Offer::from_elements(local_vht(), &scan.information_elements, 0).is_err(),
        "native snapshot accepted an invalid primary"
    );
    Ok(())
}
smoke!(
    smoke_phy_native_element_snapshots_derive_selectors_and_reject_malformed_rates,
    native_element_validation
);

fn native_response_cannot_expand_offer() -> Result<(), &'static str> {
    let mut mcs = [0; 10];
    mcs[..2].fill(255);
    let local = LocalPhy::vht80(
        LocalHt::new(
            mcs,
            mcs,
            HtWidth::TwentyForty,
            HtGi {
                rx20: true,
                tx20: true,
                rx40: true,
                tx40: true,
            },
            0,
            0,
        )
        .unwrap(),
        LocalVht::new(0xfffa, 0xfffa, true, true, 0).unwrap(),
    )
    .unwrap();
    let original = ap(true, true, Some(0xfe));
    let facts = bodies(&original);
    let mut ht = facts.ht_cap.unwrap();
    ht[0] &= !0x60;
    let mut vht = facts.vht_cap.unwrap();
    vht[0] &= !0x20;
    let scan = bss(
        ht,
        facts.ht_op.unwrap(),
        Some((vht, facts.vht_op.unwrap())),
        Some(0xfe),
    );
    let offer = Offer::from_elements(local, &scan.information_elements, 36)
        .unwrap()
        .unwrap();
    ht[..2].copy_from_slice(&facts.ht_cap.unwrap()[..2]);
    ht[4] = 255;
    vht[..4].copy_from_slice(&facts.vht_cap.unwrap()[..4]);
    vht[4..6].copy_from_slice(&0xfffau16.to_le_bytes());
    let reply = bss(
        ht,
        facts.ht_op.unwrap(),
        Some((vht, facts.vht_op.unwrap())),
        Some(0xfe),
    );
    let n = offer
        .response_elements(&reply.information_elements)
        .map_err(|_| "native bounded response")?;
    check!(
        n.ht().tx_mcs()[1] == 0
            && n.vht().unwrap().tx_mcs_map() == 0xfffc
            && !n.ht().tx_sgi20()
            && !n.ht().tx_sgi40()
            && !n.vht().unwrap().tx_sgi80(),
        "native response enabled TX NSS/GI omitted from original offer"
    );
    let ht_scan = ap(false, false, None);
    let ht_offer = Offer::from_elements(local, &ht_scan.information_elements, 36)
        .unwrap()
        .unwrap();
    let ht_facts = bodies(&ht_scan);
    let unsolicited = bss(
        ht_facts.ht_cap.unwrap(),
        ht_facts.ht_op.unwrap(),
        Some((facts.vht_cap.unwrap(), [0, 0, 0, 0xfc, 0xff])),
        None,
    );
    check!(
        ht_offer
            .response_elements(&unsolicited.information_elements)
            .is_err(),
        "native response enabled VHT absent from original association offer"
    );
    check!(
        ht_offer
            .response_elements(&original.information_elements)
            .is_err(),
        "native response widened an original20MHz occupied offer"
    );
    Ok(())
}
smoke!(
    smoke_phy_native_response_cannot_add_vht_width_tx_nss_or_gi,
    native_response_cannot_expand_offer
);

fn greenfield_directional_bounds() -> Result<(), &'static str> {
    check!(
        LocalHt::siso20(true, true).capability_body()[0] & 16 == 0,
        "legacy constructor silently acquired greenfield"
    );
    for rx in [false, true] {
        for tx in [false, true] {
            for scan in [false, true] {
                for reply in [false, true] {
                    let local = LocalPhy::ht20(LocalHt::siso20(true, true).with_greenfield(rx, tx))
                        .unwrap();
                    let original = ap(false, false, None);
                    let facts = bodies(&original);
                    let mut cap = facts.ht_cap.unwrap();
                    cap[0] = (cap[0] & !16) | (u8::from(scan) << 4);
                    let bss = bss(cap, facts.ht_op.unwrap(), None, None);
                    let mut plan = ready(&bss, local);
                    check!(
                        plan.offered_phy().unwrap().ht().rx_greenfield() == rx,
                        "AP receive facts narrowed local greenfield decoder"
                    );
                    cap[0] = (cap[0] & !16) | (u8::from(reply) << 4);
                    let response_bss = self::bss(cap, facts.ht_op.unwrap(), None, None);
                    check!(
                        plan.association_response(&response(&response_bss)) == Ok(Some(7)),
                        "greenfield response did not retain HT geometry/security"
                    );
                    let ht = plan.negotiated_phy().unwrap().ht();
                    check!(
                        ht.rx_greenfield() == rx && ht.tx_greenfield() == (tx && scan && reply),
                        "greenfield TX escaped local/scan/response intersection"
                    );
                    check!(
                        (ht.local_capability()[0] & 16 != 0) == rx,
                        "TX/AP greenfield changed local advertised receive promise"
                    );
                }
            }
        }
    }
    Ok(())
}
smoke!(
    smoke_phy_greenfield_directional_local_offer_and_response_bounds,
    greenfield_directional_bounds
);

/// VHT80 AP on primary36 with explicit HT/VHT capability edits.
fn ap_with(ht_rx_stbc: bool, vht_cap: impl Fn(&mut [u8; 12])) -> Bss {
    let original = ap(true, true, None);
    let facts = bodies(&original);
    let ht = ht40().with_rx_stbc(ht_rx_stbc).capability_body();
    let mut vht = facts.vht_cap.unwrap();
    vht_cap(&mut vht);
    bss(
        ht,
        facts.ht_op.unwrap(),
        Some((vht, facts.vht_op.unwrap())),
        None,
    )
}

fn tx_stbc_directionality() -> Result<(), &'static str> {
    let ht = ht40().with_tx_stbc(true);
    let vht = LocalVht::new(0xfffc, 0xfffc, true, true, 0)
        .unwrap()
        .with_tx_stbc(true);
    check!(
        ht.capability_body()[0] & 0x80 != 0
            && ht.capability_body()[1] & 3 == 0
            && vht.capability_body()[0] & 0x80 != 0
            && vht.capability_body()[1] & 7 == 0
            && ht40().capability_body()[0] & 0x80 == 0,
        "Tx STBC encoding differs or implied Rx STBC"
    );
    let local = LocalPhy::vht80(ht, vht).unwrap();
    for scan in [false, true] {
        for reply in [false, true] {
            let stbc = |on: bool| ap_with(on, move |c| c[1] = (c[1] & !7) | u8::from(on));
            let mut plan = ready(&stbc(scan), local);
            let offer = plan.offered_phy().unwrap();
            check!(
                offer.ht().tx_stbc() == scan
                    && offer.vht().unwrap().tx_stbc() == scan
                    && offer.ht().peer_rx_stbc_streams() == u8::from(scan),
                "offer Tx STBC ignored peer Rx STBC"
            );
            check!(
                plan.association_response(&response(&stbc(reply))) == Ok(Some(7)),
                "Tx STBC prevented a compatible response"
            );
            let negotiated = plan.negotiated_phy().unwrap();
            check!(
                negotiated.ht().tx_stbc() == (scan && reply)
                    && negotiated.vht().unwrap().tx_stbc() == (scan && reply),
                "response restored or lost Tx STBC"
            );
        }
    }
    let plain = ready(&ap_with(true, |c| c[1] |= 1), local_vht());
    check!(
        !plain.offered_phy().unwrap().ht().tx_stbc()
            && !plain.offered_phy().unwrap().vht().unwrap().tx_stbc(),
        "Tx STBC enabled without the local opt-in"
    );
    Ok(())
}
smoke!(
    smoke_phy_tx_stbc_requires_local_opt_in_and_peer_rx_in_offer_and_response,
    tx_stbc_directionality
);

fn beamforming_roles() -> Result<(), &'static str> {
    let base = LocalVht::new(0xfffc, 0xfffc, true, true, 0).unwrap();
    let full = VhtBeamforming {
        su_beamformee_sts: Some(4),
        su_beamformer_sounding: Some(2),
        mu_beamformee: true,
    };
    for bad in [
        VhtBeamforming {
            su_beamformee_sts: Some(1),
            ..Default::default()
        },
        VhtBeamforming {
            su_beamformee_sts: Some(9),
            ..Default::default()
        },
        VhtBeamforming {
            su_beamformer_sounding: Some(1),
            ..Default::default()
        },
        VhtBeamforming {
            mu_beamformee: true,
            ..Default::default()
        },
    ] {
        check!(
            base.with_beamforming(bad).is_err(),
            "invalid beamforming role accepted"
        );
    }
    let vht = base.with_beamforming(full).unwrap();
    let cap = le32(&vht.capability_body()[..4]);
    check!(
        cap & (1 << 11 | 1 << 12 | 1 << 20) == (1 << 11 | 1 << 12 | 1 << 20)
            && cap >> 13 & 7 == 3
            && cap >> 16 & 7 == 1
            && cap & 1 << 19 == 0
            && le32(&base.capability_body()[..4]) & 0x1f_f800 == 0,
        "beamforming capability bits differ or station claimed MU beamformer"
    );
    let local = LocalPhy::vht80(ht40(), vht).unwrap();
    // AP: SU beamformer (4 sounding dimensions), MU beamformer, SU beamformee.
    let roles = |bfer: bool, mu: bool, bfee: bool| {
        ap_with(false, move |c| {
            let mut info = le32(&c[..4]) & !(0x1f_f800);
            if bfer {
                info |= 1 << 11 | 3 << 16;
            }
            if mu {
                info |= 1 << 19;
            }
            if bfee {
                info |= 1 << 12 | 2 << 13;
            }
            c[..4].copy_from_slice(&info.to_le_bytes());
        })
    };
    let mut plan = ready(&roles(true, true, true), local);
    let offer = plan.offered_phy().unwrap();
    let vht_offer = offer.vht().unwrap();
    check!(
        vht_offer.su_beamformee()
            && vht_offer.mu_beamformee()
            && vht_offer.su_beamformer()
            && vht_offer.peer_sounding_dimensions() == Some(4)
            && vht_offer.peer_beamformee_sts() == Some(3)
            && offer.advertised_vht_capability() == vht.capability_body(),
        "complementary AP roles did not enable local beamforming facts"
    );
    check!(
        plan.association_response(&response(&roles(true, false, false))) == Ok(Some(7)),
        "beamforming prevented a compatible response"
    );
    let negotiated = plan.negotiated_phy().unwrap().vht().unwrap();
    check!(
        negotiated.su_beamformee() && !negotiated.mu_beamformee() && !negotiated.su_beamformer(),
        "response beamforming roles were not intersected"
    );
    // Without an AP SU beamformer the request drops SU/MU beamformee
    // (mac80211 ieee80211_add_vht_ie); without MU beamformer only MU.
    let plan = prepare(&roles(false, false, true), local).unwrap();
    let advertised = le32(&plan.offered_phy().unwrap().advertised_vht_capability()[..4]);
    check!(
        advertised & (1 << 12 | 7 << 13 | 1 << 20) == 0 && advertised & 1 << 11 != 0,
        "beamformee advertised to an AP that cannot sound"
    );
    let mut request = plan.assoc.clone();
    let tail = request.split_off(request.len() - 12);
    check!(
        tail[..4] == advertised.to_le_bytes() && request[request.len() - 2..] == [191, 12],
        "association request VHT IE is not the narrowed advertisement"
    );
    let plan = prepare(&roles(true, false, false), local).unwrap();
    let advertised = le32(&plan.offered_phy().unwrap().advertised_vht_capability()[..4]);
    check!(
        advertised & 1 << 20 == 0 && advertised & 1 << 12 != 0,
        "MU beamformee advertised to an AP without MU beamformer"
    );
    let mut later = ready(&roles(false, false, false), local);
    check!(
        later.association_response(&response(&roles(true, true, true))) == Ok(Some(7))
            && !later
                .negotiated_phy()
                .unwrap()
                .vht()
                .unwrap()
                .su_beamformee()
            && !later
                .negotiated_phy()
                .unwrap()
                .vht()
                .unwrap()
                .su_beamformer(),
        "response restored beamforming roles absent from the scan offer"
    );
    Ok(())
}
smoke!(
    smoke_phy_vht_beamforming_roles_are_complementary_and_narrowed,
    beamforming_roles
);

/// VHT80 operation on primary36 (seg0 42) with a selectable AP width/ext
/// NSS field, RX map and HT Operation CCFS2.
fn ext_ap(supp: u32, ext: u32, capable: bool, ccfs1: u8, ccfs2: u8) -> Bss {
    let mut op = [0; 22];
    op[0] = 36;
    op[1] = 5;
    let mode = u16::from(ccfs2) << 5;
    op[2..4].copy_from_slice(&mode.to_le_bytes());
    let mut vht = LocalVht::new(0xfffa, 0xfffa, true, true, 0)
        .unwrap()
        .capability_body();
    let info = le32(&vht[..4]) & !(3 << 2) | supp << 2 | ext << 30;
    vht[..4].copy_from_slice(&info.to_le_bytes());
    if capable {
        vht[11] |= 0x20;
    }
    bss(
        ht40().capability_body(),
        op,
        Some((vht, [1, 42, ccfs1, 0xfc, 0xff])),
        None,
    )
}
fn local_two_stream_160(ext: bool) -> LocalPhy {
    LocalPhy::vht160(
        ht40(),
        LocalVht::new(0xfffa, 0xfffa, true, true, 0)
            .unwrap()
            .with_160mhz(true, true)
            .with_extended_nss_bw(ext),
    )
    .unwrap()
}

fn extended_nss_bw() -> Result<(), &'static str> {
    check!(
        local_two_stream_160(true).vht.unwrap().capability_body()[11] & 0x20 != 0
            && local_two_stream_160(false).vht.unwrap().capability_body()[11] & 0x20 == 0,
        "Extended NSS BW Capable bit differs"
    );
    // Table 9-272: supp0 + ext1/2 = 160 at half NSS, ext3 = 3/4, signalled
    // through HT Operation CCFS2 (mac80211 ieee80211_chandef_vht_oper).
    for (ext, nss_map) in [(1, 0xfffe), (2, 0xfffe), (3, 0xfffe)] {
        let ap = ext_ap(0, ext, true, 0, 50);
        let plan = prepare(&ap, local_two_stream_160(true)).map_err(|_| "ext NSS AP refused")?;
        let offer = plan.offered_phy().unwrap();
        check!(
            offer.width() == Width::OneSixty
                && offer.center_channel() == 50
                && !offer.discontiguous()
                && offer.vht().unwrap().tx_mcs_map() == nss_map,
            "ext NSS 160 geometry or reduced NSS differs"
        );
        // A station that does not interpret the field reads it as0: VHT80.
        let legacy =
            prepare(&ap, local_two_stream_160(false)).map_err(|_| "ext NSS AP rejected")?;
        let offer = legacy.offered_phy().unwrap();
        check!(
            offer.width() == Width::Eighty
                && offer.center_channel() == 42
                && offer.vht().unwrap().tx_mcs_map() == 0xfffa,
            "non-capable station used Extended NSS BW"
        );
    }
    // supp1 + ext3 keeps full NSS at 160 via CCFS1; supp1 + ext1 uses CCFS2
    // only when CCFS1 is zero.
    let full = prepare(&ext_ap(1, 3, true, 50, 0), local_two_stream_160(true))
        .map_err(|_| "supp1/ext3 refused")?;
    check!(
        full.offered_phy().unwrap().width() == Width::OneSixty
            && full.offered_phy().unwrap().vht().unwrap().tx_mcs_map() == 0xfffa,
        "supp1/ext3 160 was NSS-limited"
    );
    let via_ccfs2 = prepare(&ext_ap(1, 1, true, 0, 50), local_two_stream_160(true))
        .map_err(|_| "supp1/ext1 CCFS2 refused")?;
    check!(
        via_ccfs2.offered_phy().unwrap().center_channel() == 50,
        "supp1/ext1 ignored CCFS2"
    );
    // The AP's field is ignored unless it also sets Extended NSS BW Capable.
    let unflagged = prepare(&ext_ap(0, 1, false, 0, 50), local_two_stream_160(true))
        .map_err(|_| "unflagged ext AP refused")?;
    check!(
        unflagged.offered_phy().unwrap().width() == Width::Eighty,
        "AP Extended NSS BW field used without its capable bit"
    );
    // Reserved supp2 + ext1/2 combinations fail closed for a capable station.
    for ext in [1, 2] {
        check!(
            prepare(&ext_ap(2, ext, true, 0, 0), local_two_stream_160(true)).is_err()
                && prepare(&ext_ap(2, ext, true, 0, 0), local_two_stream_160(false)).is_ok(),
            "reserved Extended NSS BW combination handled incorrectly"
        );
    }
    Ok(())
}
smoke!(
    smoke_phy_extended_nss_bw_table_and_ccfs2_follow_local_capability,
    extended_nss_bw
);

fn ap80p80(primary: u8, seg0: u8, seg1: u8, deprecated: bool, supp: u32) -> Bss {
    let channels = [seg0 - 6, seg0 - 2, seg0 + 2, seg0 + 6];
    let index = channels.iter().position(|c| *c == primary).unwrap();
    let mut op = [0; 22];
    op[0] = primary;
    op[1] = if index & 1 == 0 { 5 } else { 7 };
    let mut vht = LocalVht::new(0xfffe, 0xfffe, true, true, 0)
        .unwrap()
        .capability_body();
    vht[0] = (vht[0] & !12) | (supp << 2) as u8 | 0x40;
    bss(
        ht40().capability_body(),
        op,
        Some((
            vht,
            [if deprecated { 3 } else { 1 }, seg0, seg1, 0xfc, 0xff],
        )),
        None,
    )
}
fn local_80p80() -> LocalPhy {
    LocalPhy::vht160(
        ht40(),
        LocalVht::new(0xfffe, 0xfffe, true, true, 0)
            .unwrap()
            .with_80p80(true, true),
    )
    .unwrap()
}

fn discontiguous_80p80() -> Result<(), &'static str> {
    check!(
        local_80p80().vht.unwrap().capability_body()[0] & 0x4c == 0x48,
        "local 80+80 did not advertise Supported Channel Width Set2"
    );
    for (primary, seg0, seg1) in [(36, 42, 106), (104, 106, 42), (149, 155, 58)] {
        for deprecated in [false, true] {
            let ap = ap80p80(primary, seg0, seg1, deprecated, 2);
            let plan = prepare(&ap, local_80p80()).map_err(|_| "valid 80+80 refused")?;
            let offer = plan.offered_phy().unwrap();
            let low = seg0.min(seg1);
            let high = seg0.max(seg1);
            let expected = [
                low - 6,
                low - 2,
                low + 2,
                low + 6,
                high - 6,
                high - 2,
                high + 2,
                high + 6,
            ];
            check!(
                offer.width() == Width::OneSixty
                    && offer.discontiguous()
                    && offer.center_channel() == seg0
                    && offer.secondary_center_channel() == Some(seg1)
                    && offer.occupied_channels() == expected,
                "80+80 segments/occupied channels differ"
            );
            // Local 160-only or 80 stations use the primary80 segment.
            for narrow in [local_vht160(), local_vht()] {
                let plan = prepare(&ap, narrow).map_err(|_| "80+80 BSS refused narrow station")?;
                let offer = plan.offered_phy().unwrap();
                check!(
                    offer.width() == Width::Eighty
                        && !offer.discontiguous()
                        && offer.center_channel() == seg0
                        && offer.occupied_channels() == [seg0 - 6, seg0 - 2, seg0 + 2, seg0 + 6],
                    "narrow station did not fall back to primary80"
                );
            }
        }
    }
    // Adjacent (a contiguous160), overlapping, noncanonical, AP without
    // 80+80 support or primary outside seg0 all fail closed.
    for ap in [
        ap80p80(36, 42, 58, false, 2),
        ap80p80(36, 42, 50, true, 2),
        ap80p80(36, 42, 107, false, 2),
        ap80p80(36, 42, 106, false, 1),
        ap80p80(36, 42, 0, true, 2),
    ] {
        check!(
            prepare(&ap, local_80p80()).is_err(),
            "invalid 80+80 geometry admitted"
        );
    }
    let mut wrong_primary = ap80p80(36, 42, 106, false, 2);
    let facts = bodies(&wrong_primary);
    let mut vht_op = facts.vht_op.unwrap();
    vht_op[1] = 106;
    vht_op[2] = 42;
    wrong_primary = bss(
        facts.ht_cap.unwrap(),
        facts.ht_op.unwrap(),
        Some((facts.vht_cap.unwrap(), vht_op)),
        None,
    );
    check!(
        prepare(&wrong_primary, local_80p80()).is_err(),
        "primary outside the seg0 80MHz segment admitted"
    );
    // A response may narrow 80+80 to its primary80, never widen to it.
    let original = ap80p80(36, 42, 106, false, 2);
    let mut plan = ready(&original, local_80p80());
    check!(
        plan.association_response(&response(&ap(true, true, None))) == Ok(Some(7))
            && plan.negotiated_phy().unwrap().width() == Width::Eighty
            && !plan.negotiated_phy().unwrap().discontiguous(),
        "80+80 response could not narrow to primary80"
    );
    let mut plan = ready(&ap(true, true, None), local_80p80());
    check!(
        plan.association_response(&response(&original)).is_err(),
        "response widened an 80 offer to 80+80"
    );
    Ok(())
}
smoke!(
    smoke_phy_vht_80p80_segments_fallback_and_invalid_geometry,
    discontiguous_80p80
);
