use super::chip_8922a;
use super::efuse_be::BeFactory;
use super::eht::EhtStation;
use super::ppe_tests::{IES_E1_EHT_PPE_NSS2, IES_H1_HE_PPE_NSS1};
use super::ra_mask::{HeCaps, HtCaps, VhtCaps};
use super::station_8922a::*;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::association::{phy::Width, six_ghz::SixGhzChannel};
use narf_wireless::reg::PowerType6Ghz;

fn factory() -> BeFactory {
    BeFactory {
        mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        rfe_type: 0,
        xtal_cap: 0,
        country: [b'U', b'S'],
        phycap: [0u8; chip_8922a::PHYCAP_SIZE],
        cv: None,
        thermal_k: None,
        secure: super::efuse_be::SecureInfo::disabled(),
    }
}

fn facet() -> Result<EhtStation, TestResult> {
    EhtStation::new_8922ae().ok_or(TestResult::Fail("8922AE EHT facet must build"))
}

fn base_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        band: Band::Ghz5,
        width_mhz: 160,
        primary: 36,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        six_ghz: None,
    }
}

fn smoke_rtw89_8922a_admit_eht_golden() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let mut st = match admit(&f, facet, &mut pool, &base_req()) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("valid EHT admission refused"),
    };
    if st.own != f.mac
        || st.peer != base_req().peer
        || st.macid != 0
        || st.band != Band::Ghz5
        || st.width_mhz != 160
        || st.primary != 36
        || st.nss != 2
        || st.aid != 7
        || !pool.is_used(0)
    {
        return TestResult::Fail("admitted station record mismatch");
    }
    // Default CCTL wiring: identical to the standalone builder.
    if st.default_cctl != super::cctl_g7::build_default(0, false).unwrap() {
        return TestResult::Fail("default CCTL wiring mismatch");
    }
    // Assoc CCTL golden, hand-computed from the Linux assoc
    // builder (fw.c) + fw.h masks: 5 GHz non-P2P => OFDM6
    // lowest rate; EHT + zero puncturing => all-ones subchannel
    // mask; AID 7 + station mode; HE peer => BSR bit.
    let a = &st.assoc_cctl;
    if a.c0 != 0x80
        || a.w[0] != 0x0600_0000
        || a.m[0] != 0x0600_0000
        || a.w[1] != 0x4000_0000
        || a.m[1] != 0xF000_0000
        || a.w[2] != 0
        || a.m[2] != 0x40
        || a.w[3] != 0
        || a.m[3] != 0x4000_0000
        || a.w[4] != 0xFFFF_0000
        || a.m[4] != 0xFFFF_0007
        || a.w[5] != 0
        || a.m[5] != 0x3FF
        || a.w[6] != 0x8000_0007
        || a.m[6] != 0x8000_0FFF
        || a.w[7] != 0
        || a.m[7] != 0
        || a.w[8] != 2
        || a.m[8] != 2
        || a.w[14] != 0
        || a.m[14] != 0
        || a.w[15] != 0
        || a.m[15] != 0
    {
        return TestResult::Fail("assoc CCTL golden mismatch");
    }
    // Facet overrides off => no TXWD EHT override bits.
    if st.txwd_info_eht() != Some((0, 0)) {
        return TestResult::Fail("facet TXWD EHT fields must be zero");
    }
    // BA-CAM: acquire + H2C golden (entry index = bitmap + 8).
    let idx = match st.bacam.acquire(0) {
        Ok(idx) => idx,
        Err(_) => return TestResult::Fail("BA-CAM acquire TID 0 failed"),
    };
    if idx != 0 {
        return TestResult::Fail("BA-CAM first slot must be 0");
    }
    let h2c = match st.ba_h2c(0, 0, 0, idx as u32) {
        Ok(h2c) => h2c,
        Err(_) => return TestResult::Fail("BA-CAM H2C build failed"),
    };
    if h2c.w0 != 0x3 || h2c.w1 != 0x0800_0100 {
        return TestResult::Fail("BA-CAM H2C golden mismatch");
    }
    st.release_macid(&mut pool);
    if pool.is_used(0) {
        return TestResult::Fail("MACID release failed");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_assoc_2g_ap() -> TestResult {
    // Direct assoc-builder golden, second arm set: 2.4 GHz
    // non-P2P => CCK1 lowest rate; AP mode => DATA_DCM mask;
    // EHT off => puncturing ignored; pads packed 2 bits each;
    // no station mode, no HE peer.
    let t = match super::cctl_g7::build_assoc(
        5,
        true,
        false,
        1,
        true,
        false,
        0x00FF,
        [1, 2, 3, 0, 0],
        1,
        false,
        false,
    ) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("valid assoc build refused"),
    };
    if t.c0 != 0x85
        || t.w[0] != 0x0600_0000
        || t.m[0] != 0x0600_0000
        || t.w[1] != 0
        || t.m[1] != 0xF000_0000
        || t.w[2] != 0
        || t.m[2] != 0x40
        || t.w[3] != 0
        || t.m[3] != 0x4000_0000
        || t.w[4] != 1
        || t.m[4] != 0x107
        || t.w[5] != 0x39
        || t.m[5] != 0x3FF
        || t.w[6] != 1
        || t.m[6] != 0x8000_0FFF
        || t.w[8] != 0
        || t.m[8] != 2
    {
        return TestResult::Fail("2G AP assoc golden mismatch");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_admit_refusals() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let mut req = base_req();
    let lpi = SixGhzAdmission {
        power: PowerType6Ghz::Lpi,
        tpe_dbm: None,
    };
    let cases: [(Request, Error); 12] = [
        (
            Request {
                band: Band::Ghz6,
                ..req
            },
            Error::SixGhzPowerMissing,
        ),
        (
            Request {
                band: Band::Ghz6,
                width_mhz: 40,
                six_ghz: Some(lpi),
                ..req
            },
            Error::SixGhzWidthUnsupported,
        ),
        (
            Request {
                band: Band::Ghz6,
                width_mhz: 20,
                six_ghz: Some(SixGhzAdmission {
                    power: PowerType6Ghz::Lpi,
                    tpe_dbm: Some(20),
                }),
                ..req
            },
            Error::SixGhzTpeNotStandard,
        ),
        (
            Request {
                band: Band::Ghz6,
                width_mhz: 20,
                six_ghz: Some(SixGhzAdmission {
                    power: PowerType6Ghz::Sp,
                    tpe_dbm: Some(-19),
                }),
                ..req
            },
            Error::SixGhzTpeBelowMinimum,
        ),
        (
            Request {
                six_ghz: Some(lpi),
                ..req
            },
            Error::SixGhzContextUnexpected,
        ),
        (
            Request {
                width_mhz: 320,
                ..req
            },
            Error::WidthNotAdvertised,
        ),
        (
            Request {
                width_mhz: 10,
                ..req
            },
            Error::WidthNotAdvertised,
        ),
        (Request { nss: 0, ..req }, Error::NssOutOfRange),
        (Request { nss: 3, ..req }, Error::NssOutOfRange),
        (Request { primary: 0, ..req }, Error::BadPrimary),
        (Request { aid: 0x1000, ..req }, Error::AidOutOfRange),
        (Request { port: 8, ..req }, Error::PortOutOfRange),
        // No pads refusal case: production parses the Assoc PPE pads
        // from `peer_ies` (infallible, always five 2-bit values), so
        // there is no `pads` request field and no `PadsOutOfRange`
        // refusal anymore; pads coverage lives in
        // `smoke_rtw89_8922a_admit_ppe_from_peer_ies`.
    ];
    for (case, want) in cases.iter() {
        match admit(&f, facet, &mut pool, case) {
            Err(got) if got == *want => {}
            _ => return TestResult::Fail("refusal case mismatch"),
        }
    }
    // Refusals must not consume MACIDs.
    let first = match pool.alloc() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("pool drained by refusals"),
    };
    if first != 0 {
        return TestResult::Fail("refused request consumed a MACID");
    }
    pool.free(0);
    // The legal 80 MHz request admits.
    req.width_mhz = 80;
    let st = match admit(&f, facet, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("legal 80 MHz admission refused"),
    };
    if st.width_mhz != 80 || st.macid != 0 {
        return TestResult::Fail("80 MHz admission record mismatch");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_admit_ppe_from_peer_ies() -> TestResult {
    // Admission parses the Assoc PPE pads from the peer's IEs:
    // the E1 fixture (EHT PPE, NSS=2) yields [3, 1, 0, 3, 1],
    // packed 2 bits each into assoc CCTL w5: 3 | 1<<2 | 0<<4 |
    // 3<<6 | 1<<8 = 0x1C7. The same request with empty IEs
    // admits with zero pads (no EHT/HE peer), as before.
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let req = Request {
        peer_ies: IES_E1_EHT_PPE_NSS2,
        ..base_req()
    };
    let st = match admit(&f, facet, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("admission with peer IEs refused"),
    };
    if st.pads != [3, 1, 0, 3, 1] || st.assoc_cctl.w[5] != 0x1C7 {
        return TestResult::Fail("admitted station pads mismatch");
    }
    st.release_macid(&mut pool);
    let st = match admit(&f, facet, &mut pool, &base_req()) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("admission without peer IEs refused"),
    };
    if st.pads != [0; 5] || st.assoc_cctl.w[5] != 0 {
        return TestResult::Fail("empty-IE admission pads must stay zero");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_admit_6ghz_tpe_power_program() -> TestResult {
    let ap80 = SixGhzChannel {
        primary: 5,
        primary_mhz: 5975,
        width: Width::Eighty,
        discontiguous: false,
        center_mhz: 5985,
        center2_mhz: None,
    };
    // The 8922A TPE entry point is the shared mac80211/regd.c
    // parse (the 8852C template's goldens): local EIRP
    // 20/40/80 (raw 72/80/88) constrains to 26 dBm, the
    // regulatory-client PSD (N = 4, primary subchannel 1, raw
    // 40) to 23 dBm, and the intersected constraint is the min.
    let eirp = [195, 4, 0x02, 72, 80, 88];
    let both = [195, 4, 0x02, 72, 80, 88, 195, 5, 0x1b, 30, 40, 50, 60];
    let cases: [(&[u8], Option<i8>); 5] = [
        (&eirp, Some(26)),
        (&both, Some(23)),
        // Subordinate category: validated, unused.
        (&[195, 2, 0x40, 0], None),
        // EIRP count 3 with two values: invalid, ignored.
        (&[195, 3, 0x03, 10, 10], None),
        // PSD count 0: one value for every subchannel, (21-19)/2 + 13.
        (&[195, 2, 0x08, 21], Some(14)),
    ];
    for (ies, expected) in cases {
        if tpe(ies, &ap80) != Ok(expected) {
            return TestResult::Fail("8922A 6GHz TPE differs from mac80211/regd.c");
        }
    }
    // 80+80 and a primary outside the AP channel refuse.
    if tpe(
        &eirp,
        &SixGhzChannel {
            discontiguous: true,
            ..ap80
        },
    ) != Err(())
    {
        return TestResult::Fail("80+80 AP channel must refuse TPE");
    }
    if tpe(
        &eirp,
        &SixGhzChannel {
            primary_mhz: 7000,
            ..ap80
        },
    ) != Err(())
    {
        return TestResult::Fail("primary outside AP channel must refuse TPE");
    }
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let mut req = base_req();
    req.band = Band::Ghz6;
    req.width_mhz = 20;
    req.primary = 5;
    // LPI without a TPE admits with an unconstrained program:
    // phy.c `rtw89_phy_get_tpe_constraint` with no TPE is
    // `dbm_to_mac(S8_MAX)` = 63.
    req.six_ghz = Some(SixGhzAdmission {
        power: PowerType6Ghz::Lpi,
        tpe_dbm: None,
    });
    let st = match admit(&f, facet, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("6GHz LPI admission refused"),
    };
    let program = match st.six_ghz() {
        Some(program) => program,
        None => return TestResult::Fail("6GHz station records no power program"),
    };
    if program.power != PowerType6Ghz::Lpi
        || program.tpe_dbm.is_some()
        || program.tpe_mac != 63
        || program.reg_6ghz_power() != 1
        || st.band != Band::Ghz6
        || st.width_mhz != 20
        || st.primary != 5
    {
        return TestResult::Fail("6GHz LPI power program mismatch");
    }
    // Standard Power with the intersected TPE (23 dBm) admits;
    // the MAC-unit constraint is 23 << 1 = 46.
    let tpe_std = match tpe(&both, &ap80) {
        Ok(Some(c)) => c,
        _ => return TestResult::Fail("STD TPE must compute"),
    };
    req.six_ghz = Some(SixGhzAdmission {
        power: PowerType6Ghz::Sp,
        tpe_dbm: Some(tpe_std),
    });
    let st = match admit(&f, facet, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("6GHz STD admission refused"),
    };
    let program = match st.six_ghz() {
        Some(program) => program,
        None => return TestResult::Fail("6GHz STD station records no power program"),
    };
    if program.power != PowerType6Ghz::Sp
        || program.tpe_dbm != Some(23)
        || program.tpe_mac != 46
        || program.reg_6ghz_power() != 2
    {
        return TestResult::Fail("6GHz STD power program mismatch");
    }
    // VLP admits; a 2.4/5 GHz station records no program.
    req.six_ghz = Some(SixGhzAdmission {
        power: PowerType6Ghz::Vlp,
        tpe_dbm: None,
    });
    let st = match admit(&f, facet, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("6GHz VLP admission refused"),
    };
    if st.six_ghz().is_some_and(|p| p.reg_6ghz_power() != 0) {
        return TestResult::Fail("6GHz VLP power program mismatch");
    }
    let st5 = match admit(&f, facet, &mut pool, &base_req()) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("5GHz admission refused"),
    };
    if st5.six_ghz().is_some() {
        return TestResult::Fail("5GHz station must record no 6GHz program");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_macid_pool() -> TestResult {
    let mut pool = MacIdPool::new();
    for want in 0..32u8 {
        let got = match pool.alloc() {
            Ok(got) => got,
            Err(_) => return TestResult::Fail("pool exhausted early"),
        };
        if got != want || !pool.is_used(want) {
            return TestResult::Fail("pool allocation order mismatch");
        }
    }
    if pool.alloc() != Err(Error::NoMacId) {
        return TestResult::Fail("full pool must refuse");
    }
    pool.free(31);
    if pool.is_used(31) || pool.alloc() != Ok(31) {
        return TestResult::Fail("pool free/realloc mismatch");
    }
    // Total no-ops: out-of-range and double free are safe.
    pool.free(99);
    pool.free(31);
    if pool.is_used(31) {
        return TestResult::Fail("double free corrupted pool");
    }
    if !pool.is_used(30) {
        return TestResult::Fail("pool state corrupted by no-op frees");
    }
    TestResult::Pass
}

const MLD_ADDR: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

fn link1_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
        band: Band::Ghz2,
        width_mhz: 40,
        primary: 6,
        nss: 2,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: true,
        punctured: 0,
        peer_ies: &[],
        has_he: true,
        mgq_rpt_en: false,
        p2p: false,
        // 2.4 GHz link: no 6 GHz admission (production refuses
        // `Some` on non-6 GHz bands with `SixGhzContextUnexpected`).
        six_ghz: None,
    }
}

fn two_links() -> [LinkRequest<'static>; 2] {
    [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: link1_req(),
        },
    ]
}

fn smoke_rtw89_8922a_mld_admit_two_links() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let links = two_links();
    let mld = match admit_mld(&f, facet, &mut pool, MLD_ADDR, &links) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("valid two-link MLD admission refused"),
    };
    if mld.mld_addr != MLD_ADDR
        || mld.base_macid != 0
        || mld.aid != 7
        || mld.port != 0
        || mld.link_count() != 2
        || mld.is_empty()
    {
        return TestResult::Fail("MLD station record mismatch");
    }
    // Strided per-link MACIDs: link 0 -> base 0, link 1 -> base + 16.
    let l0 = match mld.link(0) {
        Some(v) => v,
        None => return TestResult::Fail("link 0 missing"),
    };
    let l1 = match mld.link(1) {
        Some(v) => v,
        None => return TestResult::Fail("link 1 missing"),
    };
    if l0.macid() != 0
        || l0.mac_idx() != 0
        || l0.index != 0
        || l1.macid() != 16
        || l1.mac_idx() != 1
        || l1.index != 1
    {
        return TestResult::Fail("per-link MACID/index mismatch");
    }
    if !pool.is_used(0) || !pool.is_used(16) || pool.is_used(1) || pool.is_used(17) {
        return TestResult::Fail("MLD pool reservation mismatch");
    }
    // Designated link is the first added (link 0).
    if mld.designated_link().map(|link| link.link_id) != Some(0) {
        return TestResult::Fail("designated link must be link 0");
    }
    // Per-link CCTL composition: link 0's tables are the
    // single-link golden (macid 0, 5 GHz OFDM6); link 1's
    // differ exactly where the link differs — c0 carries
    // macid 16, w1 carries the 2.4 GHz CCK1 lowest rate
    // (value 0), while the shared AID-7 + station-mode w6
    // and the HE BSR w8 agree.
    if l0.station.default_cctl != super::cctl_g7::build_default(0, false).unwrap()
        || l0.station.assoc_cctl.c0 != 0x80
        || l0.station.assoc_cctl.w[1] != 0x4000_0000
    {
        return TestResult::Fail("link 0 CCTL mismatch");
    }
    if l1.station.default_cctl != super::cctl_g7::build_default(16, false).unwrap() {
        return TestResult::Fail("link 1 default CCTL mismatch");
    }
    let a1 = &l1.station.assoc_cctl;
    if a1.c0 != 0x90
        || a1.w[0] != 0x0600_0000
        || a1.w[1] != 0
        || a1.m[1] != 0xF000_0000
        || a1.w[4] != 0xFFFF_0000
        || a1.m[4] != 0xFFFF_0007
        || a1.w[6] != 0x8000_0007
        || a1.m[6] != 0x8000_0FFF
        || a1.w[8] != 2
        || a1.m[8] != 2
    {
        return TestResult::Fail("link 1 assoc CCTL golden mismatch");
    }
    // Facet TXWD EHT fields are per link and agree (zero
    // overrides off on both).
    if mld.txwd_info_eht(0) != Some((0, 0)) || mld.txwd_info_eht(1) != Some((0, 0)) {
        return TestResult::Fail("per-link TXWD EHT fields mismatch");
    }
    if mld.txwd_info_eht(9).is_some() {
        return TestResult::Fail("unknown link must have no TXWD fields");
    }
    // A one-link MLD admits too (single negotiated link):
    // base 0, one link, still an MLD (BA-CAM MLD_EN set).
    let mut pool1 = MacIdPool::new();
    let one = [LinkRequest {
        link_id: 0,
        req: base_req(),
    }];
    let mut single = match admit_mld(&f, facet, &mut pool1, MLD_ADDR, &one) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("one-link MLD admission refused"),
    };
    if single.link_count() != 1 || single.base_macid != 0 {
        return TestResult::Fail("one-link MLD record mismatch");
    }
    let idx = match single.acquire_bacam(0) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("one-link BA-CAM acquire failed"),
    };
    let h2c = match single.ba_h2c(0, 0, 0, idx as u32) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("one-link BA-CAM H2C failed"),
    };
    if h2c.w0 != 0x3 || h2c.w1 != 0x0800_0500 {
        return TestResult::Fail("one-link BA-CAM H2C golden mismatch");
    }
    // Tear the fixtures down through the MLD path and check
    // the pool is fully reusable afterwards.
    mld.release_all(&mut pool);
    if pool.is_used(0) || pool.is_used(16) {
        return TestResult::Fail("MLD release_all leaked MACIDs");
    }
    single.release_all(&mut pool1);
    if pool1.is_used(0) || pool1.is_used(16) {
        return TestResult::Fail("one-link release_all leaked MACIDs");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_mld_ba_cam() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let links = two_links();
    let mut mld = match admit_mld(&f, facet, &mut pool, MLD_ADDR, &links) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("valid two-link MLD admission refused"),
    };
    // Designated link 0 (macid 0, mac_idx 0): MLD_EN set,
    // BAND_SEL clear, entry index = bitmap 0 + 8 dynamic.
    let idx = match mld.acquire_bacam(0) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("designated BA-CAM acquire failed"),
    };
    if idx != 0 {
        return TestResult::Fail("designated BA-CAM first slot must be 0");
    }
    let h2c = match mld.ba_h2c(0, 0, 0, idx as u32) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("designated BA-CAM H2C failed"),
    };
    if h2c.w0 != 0x3 || h2c.w1 != 0x0800_0500 {
        return TestResult::Fail("MLD BA-CAM H2C golden mismatch");
    }
    match mld.release_bacam(idx) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("designated BA-CAM release failed"),
    };
    // Remove the designated link: link 1 (macid 16,
    // mac_idx 1) becomes designated, so the next H2C
    // carries its MACID and BAND_SEL set.
    let removed = match mld.remove_link(&mut pool, 0) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("designated link removal failed"),
    };
    if removed.macid() != 0 || mld.designated_link().map(|link| link.link_id) != Some(1) {
        return TestResult::Fail("designated link must move to link 1");
    }
    let idx = match mld.acquire_bacam(0) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("link 1 BA-CAM acquire failed"),
    };
    let h2c = match mld.ba_h2c(0, 0, 0, idx as u32) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("link 1 BA-CAM H2C failed"),
    };
    if h2c.w0 != 0x1003 || h2c.w1 != 0x0800_0700 {
        return TestResult::Fail("link 1 BA-CAM H2C golden mismatch");
    }
    match mld.release_bacam(idx) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("link 1 BA-CAM release failed"),
    };
    mld.release_all(&mut pool);
    TestResult::Pass
}

fn smoke_rtw89_8922a_mld_teardown_and_fallback() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let links = two_links();
    let mut mld = match admit_mld(&f, facet, &mut pool, MLD_ADDR, &links) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("valid two-link MLD admission refused"),
    };
    // Adding a third link to a full MLD is refused; removing
    // an unknown link is refused; neither disturbs the MLD.
    let third = LinkRequest {
        link_id: 2,
        req: Request {
            peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBD],
            band: Band::Ghz5,
            width_mhz: 80,
            primary: 44,
            ..base_req()
        },
    };
    if mld.add_link(&f, facet, &third) != Err(Error::TooManyLinks) {
        return TestResult::Fail("full MLD must refuse a third link");
    }
    if mld.remove_link(&mut pool, 9) != Err(Error::LinkNotFound) {
        return TestResult::Fail("unknown link removal must refuse");
    }
    if mld.link_count() != 2 {
        return TestResult::Fail("refused add/remove disturbed the MLD");
    }
    // Per-link teardown: drop link 1, the MLD survives on
    // link 0 (single-link operation of the MLD).
    let removed = match mld.remove_link(&mut pool, 1) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("link 1 removal failed"),
    };
    if removed.macid() != 16
        || mld.link_count() != 1
        || mld.designated_link().map(|link| link.link_id) != Some(0)
        || !pool.is_used(0)
        || pool.is_used(16)
    {
        return TestResult::Fail("link 1 teardown state mismatch");
    }
    // Re-add link 1 on a new channel: it retakes instance
    // index 1 and MACID 16 (lowest free instance slot).
    let rejoin = LinkRequest {
        link_id: 1,
        req: Request {
            peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
            band: Band::Ghz5,
            width_mhz: 80,
            primary: 44,
            ..base_req()
        },
    };
    let macid = match mld.add_link(&f, facet, &rejoin) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("link 1 re-add failed"),
    };
    if macid != 16 || mld.link_count() != 2 || !pool.is_used(16) {
        return TestResult::Fail("link 1 re-add state mismatch");
    }
    // Drop link 0: link 1 becomes designated. Drop link 1:
    // the MLD is empty and the pool is fully free.
    match mld.remove_link(&mut pool, 0) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("link 0 removal failed"),
    };
    if mld.designated_link().map(|link| link.link_id) != Some(1) || pool.is_used(0) {
        return TestResult::Fail("link 0 teardown state mismatch");
    }
    match mld.remove_link(&mut pool, 1) {
        Ok(_) => {}
        Err(_) => return TestResult::Fail("final link removal failed"),
    };
    if !mld.is_empty() || pool.is_used(0) || pool.is_used(16) {
        return TestResult::Fail("empty MLD state mismatch");
    }
    // Single-link fallback: the plain single-link path
    // reuses the freed pool (MACID 0) exactly as before.
    let st = match admit(&f, facet, &mut pool, &base_req()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("single-link fallback admission refused"),
    };
    if st.macid != 0 {
        return TestResult::Fail("single-link fallback must reuse MACID 0");
    }
    st.release_macid(&mut pool);
    TestResult::Pass
}

fn smoke_rtw89_8922a_mld_refusals() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    let links = two_links();
    // Zero links, three links, bad link ID.
    if admit_mld(&f, facet, &mut pool, MLD_ADDR, &[]) != Err(Error::NoLinks) {
        return TestResult::Fail("zero-link MLD must refuse");
    }
    let three = [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: link1_req(),
        },
        LinkRequest {
            link_id: 2,
            req: Request {
                peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBD],
                band: Band::Ghz5,
                width_mhz: 80,
                primary: 44,
                ..base_req()
            },
        },
    ];
    if admit_mld(&f, facet, &mut pool, MLD_ADDR, &three) != Err(Error::TooManyLinks) {
        return TestResult::Fail("three-link MLD must refuse");
    }
    let bad_id = [LinkRequest {
        link_id: 15,
        req: base_req(),
    }];
    if admit_mld(&f, facet, &mut pool, MLD_ADDR, &bad_id) != Err(Error::LinkIdOutOfRange) {
        return TestResult::Fail("link ID 15 must refuse");
    }
    // Cross-link refusals, one per case.
    let dup_id = [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 0,
            req: link1_req(),
        },
    ];
    let dup_addr = [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: Request {
                peer: base_req().peer,
                ..link1_req()
            },
        },
    ];
    let dup_chan = [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: Request {
                peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBC],
                band: Band::Ghz5,
                width_mhz: 80,
                primary: 36,
                ..base_req()
            },
        },
    ];
    let aid_mismatch = [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: Request {
                aid: 8,
                ..link1_req()
            },
        },
    ];
    let port_mismatch = [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: Request {
                port: 1,
                ..link1_req()
            },
        },
    ];
    let six_ghz = [
        LinkRequest {
            link_id: 0,
            req: base_req(),
        },
        LinkRequest {
            link_id: 1,
            req: Request {
                band: Band::Ghz6,
                primary: 5,
                ..link1_req()
            },
        },
    ];
    let cases: [(&[LinkRequest], Error); 6] = [
        (&dup_id, Error::DuplicateLinkId),
        (&dup_addr, Error::DuplicateLinkAddr),
        (&dup_chan, Error::DuplicateChannel),
        (&aid_mismatch, Error::AidMismatch),
        (&port_mismatch, Error::PortMismatch),
        (&six_ghz, Error::SixGhzPowerMissing),
    ];
    for (case, want) in cases.iter() {
        match admit_mld(&f, facet, &mut pool, MLD_ADDR, case) {
            Err(got) if got == *want => {}
            _ => return TestResult::Fail("MLD refusal case mismatch"),
        }
    }
    // Refusals must not consume MACIDs.
    let next = match pool.alloc() {
        Ok(next) => next,
        Err(_) => return TestResult::Fail("pool drained by MLD refusals"),
    };
    if next != 0 {
        return TestResult::Fail("refused MLD consumed a MACID");
    }
    pool.free(0);
    // Base exhaustion: a full pool has no free strided pair.
    let mut full = MacIdPool::new();
    for _ in 0..32 {
        match full.alloc() {
            Ok(_) => {}
            Err(_) => return TestResult::Fail("pool fill failed"),
        };
    }
    if admit_mld(&f, facet, &mut full, MLD_ADDR, &links) != Err(Error::NoMacId) {
        return TestResult::Fail("full pool must refuse an MLD");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_mld_base_interleave() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    // A single-link station holding slot 0 pushes the first
    // MLD base to 1: links take MACIDs 1 and 17.
    let mut pool = MacIdPool::new();
    let single = match admit(&f, facet, &mut pool, &base_req()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("single-link admission refused"),
    };
    if single.macid != 0 {
        return TestResult::Fail("single-link setup mismatch");
    }
    let links = two_links();
    let mld = match admit_mld(&f, facet, &mut pool, MLD_ADDR, &links) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("interleaved MLD admission refused"),
    };
    if mld.base_macid != 1
        || mld.link(0).map(|link| link.macid()) != Some(1)
        || mld.link(1).map(|link| link.macid()) != Some(17)
    {
        return TestResult::Fail("interleaved MLD base mismatch");
    }
    mld.release_all(&mut pool);
    if pool.is_used(1) || pool.is_used(17) || !pool.is_used(0) {
        return TestResult::Fail("interleaved release state mismatch");
    }
    single.release_macid(&mut pool);
    // Slots 0..17 held: base 0 is blocked by slot 0, base 1
    // by slot 17, so the first MLD base is 2 (MACIDs 2, 18).
    let mut crowded = MacIdPool::new();
    for _ in 0..18 {
        match crowded.alloc() {
            Ok(_) => {}
            Err(_) => return TestResult::Fail("crowded pool fill failed"),
        };
    }
    let mld2 = match admit_mld(&f, facet, &mut crowded, MLD_ADDR, &links) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("crowded MLD admission refused"),
    };
    if mld2.base_macid != 2
        || mld2.link(0).map(|link| link.macid()) != Some(2)
        || mld2.link(1).map(|link| link.macid()) != Some(18)
    {
        return TestResult::Fail("crowded MLD base mismatch");
    }
    // Sixteen MLDs exhaust the pool exactly (16 bases x 2
    // strided slots); the seventeenth has no pair left.
    let mut fleet = MacIdPool::new();
    for _ in 0..16 {
        let _ = match admit_mld(&f, facet, &mut fleet, MLD_ADDR, &links) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("fleet MLD admission refused"),
        };
    }
    if admit_mld(&f, facet, &mut fleet, MLD_ADDR, &links) != Err(Error::NoMacId) {
        return TestResult::Fail("16-MLD fleet must exhaust the pool");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_eht_golden);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_admit_ppe_from_peer_ies
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_assoc_2g_ap);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_refusals);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_admit_6ghz_tpe_power_program
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_macid_pool);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_admit_legacy_golden
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_legacy_ht);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_legacy_vht);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_legacy_he);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_admit_legacy_refusals
);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_mixed_mode_coexistence
);

// ── Legacy-mode admission fixtures ─────────────────────────────────────

fn legacy_req() -> Request<'static> {
    Request {
        peer: [0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB],
        band: Band::Ghz2,
        width_mhz: 20,
        primary: 6,
        nss: 1,
        aid: 7,
        port: 0,
        ap_mode: false,
        station_mode: true,
        eht_support: false,
        punctured: 0,
        peer_ies: &[],
        has_he: false,
        mgq_rpt_en: false,
        p2p: false,
        // 2.4 GHz legacy request: no 6 GHz power program, and
        // production refuses `Some` on any non-6 GHz band.
        six_ghz: None,
    }
}

fn legacy_caps() -> LegacyCaps {
    LegacyCaps {
        supp_rates: 0xFFF,
        ht: None,
        vht: None,
        he: None,
        rssi: 40,
        er_cap: false,
    }
}

fn smoke_rtw89_8922a_admit_legacy_golden() -> TestResult {
    let f = factory();
    let mut pool = MacIdPool::new();
    let mut st = match admit_legacy(&f, &legacy_caps(), &mut pool, &legacy_req()) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("valid legacy admission refused"),
    };
    if st.own != f.mac
        || st.peer != legacy_req().peer
        || st.macid != 0
        || st.band != Band::Ghz2
        || st.width_mhz != 20
        || st.primary != 6
        || st.nss != 1
        || st.aid != 7
        || st.mode() != LegacyMode::Legacy
        || !pool.is_used(0)
    {
        return TestResult::Fail("admitted legacy station record mismatch");
    }
    if st.default_cctl != super::cctl_g7::build_default(0, false).unwrap() {
        return TestResult::Fail("legacy default CCTL wiring mismatch");
    }
    // Assoc CCTL golden, hand-computed from the Linux assoc
    // builder (fw.c) + fw.h masks: 2.4 GHz non-P2P => CCK1
    // lowest rate (w1 0); EHT off => no punctured-subchannel
    // arm (w4 0, m4 port mask only); no HE peer => BSR bit
    // clear (w8 0); AID 7 + station mode.
    let a = &st.assoc_cctl;
    if a.c0 != 0x80
        || a.w[0] != 0x0600_0000
        || a.m[0] != 0x0600_0000
        || a.w[1] != 0
        || a.m[1] != 0xF000_0000
        || a.w[2] != 0
        || a.m[2] != 0x40
        || a.w[3] != 0
        || a.m[3] != 0x4000_0000
        || a.w[4] != 0
        || a.m[4] != 0x7
        || a.w[5] != 0
        || a.m[5] != 0x3FF
        || a.w[6] != 0x8000_0007
        || a.m[6] != 0x8000_0FFF
        || a.w[7] != 0
        || a.m[7] != 0
        || a.w[8] != 0
        || a.m[8] != 2
        || a.w[14] != 0
        || a.m[14] != 0
        || a.w[15] != 0
        || a.m[15] != 0
    {
        return TestResult::Fail("legacy assoc CCTL golden mismatch");
    }
    // Legacy stations program no EHT TXWD override.
    if st.txwd_info_eht() != Some((0, 0)) {
        return TestResult::Fail("legacy TXWD EHT fields must be zero");
    }
    // RA golden, hand-computed from phy.c
    // `rtw89_phy_ra_sta_update` via ra_mask: supp 0xFFF on
    // 2.4 GHz => mode CCK|OFDM (3), mask trimmed to
    // OFDM|SUBCCK (0xFF5); strong RSSI (raw 40 -> halved 20
    // -> level-0 all-ones floor); bw 20 (0); ss 0.
    // w0 = mode 3 << 1 | mac 0 = 0x6; w4 = mode_eht 3.
    let ra = match st.ra_h2c(0, false, false) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("legacy RA build refused"),
    };
    if ra != [0x6, 0xFF5, 0, 0, 3, 0] {
        return TestResult::Fail("legacy RA golden mismatch");
    }
    // Update flags land in w0 bits 30/31.
    let ra = match st.ra_h2c(0, true, true) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("legacy RA upd build refused"),
    };
    if ra != [0xC000_0006, 0xFF5, 0, 0, 3, 0] {
        return TestResult::Fail("legacy RA upd bits mismatch");
    }
    // BA-CAM: acquire + H2C golden (entry index = bitmap + 8).
    let idx = match st.bacam.acquire(0) {
        Ok(idx) => idx,
        Err(_) => return TestResult::Fail("legacy BA-CAM acquire TID 0 failed"),
    };
    if idx != 0 {
        return TestResult::Fail("legacy BA-CAM first slot must be 0");
    }
    let h2c = match st.ba_h2c(0, 0, 0, idx as u32) {
        Ok(h2c) => h2c,
        Err(_) => return TestResult::Fail("legacy BA-CAM H2C build failed"),
    };
    if h2c.w0 != 0x3 || h2c.w1 != 0x0800_0100 {
        return TestResult::Fail("legacy BA-CAM H2C golden mismatch");
    }
    st.release_macid(&mut pool);
    if pool.is_used(0) {
        return TestResult::Fail("legacy MACID release failed");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_admit_legacy_ht() -> TestResult {
    let f = factory();
    let mut pool = MacIdPool::new();
    let caps = LegacyCaps {
        supp_rates: 0xFF,
        ht: Some(HtCaps {
            rx_mask: [0xFF, 0, 0, 0],
            sgi20: false,
            sgi40: true,
            rx_stbc: false,
            ldpc: true,
        }),
        vht: None,
        he: None,
        rssi: 40,
        er_cap: false,
    };
    let req = Request {
        band: Band::Ghz5,
        width_mhz: 40,
        primary: 36,
        ..legacy_req()
    };
    let st = match admit_legacy(&f, &caps, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("valid HT admission refused"),
    };
    if st.macid != 0 || st.mode() != LegacyMode::Ht || st.width_mhz != 40 {
        return TestResult::Fail("admitted HT station record mismatch");
    }
    // Assoc golden, 5 GHz arm: OFDM6 lowest rate; EHT off
    // => w4 0, m4 port mask only; no HE peer => w8 0.
    let a = &st.assoc_cctl;
    if a.c0 != 0x80
        || a.w[1] != 0x4000_0000
        || a.m[1] != 0xF000_0000
        || a.w[4] != 0
        || a.m[4] != 0x7
        || a.w[6] != 0x8000_0007
        || a.w[8] != 0
        || a.m[8] != 2
    {
        return TestResult::Fail("HT assoc CCTL golden mismatch");
    }
    // RA golden, hand-computed: mode HT|OFDM (6), HT MCS0-7
    // 1SS (0xFF<<12) + legacy 0xFF<<4, trimmed to
    // 0xFF010; bw 40 (1); SGI40 + LDPC.
    // w0 = 6<<1 | 1<<6 | sgi<<21 | ldpc<<22 = 0x60004C;
    // w3 = band 5 GHz << 29; w4 = mode 6 | bw 1 << 8.
    let ra = match st.ra_h2c(0, false, false) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("HT RA build refused"),
    };
    if ra != [0x60004C, 0xFF010, 0, 0x2000_0000, 0x106, 0] {
        return TestResult::Fail("HT RA golden mismatch");
    }
    st.release_macid(&mut pool);
    TestResult::Pass
}

fn smoke_rtw89_8922a_admit_legacy_vht() -> TestResult {
    let f = factory();
    let mut pool = MacIdPool::new();
    let caps = LegacyCaps {
        supp_rates: 0xFF,
        ht: None,
        vht: Some(VhtCaps {
            rx_mcs_map: 0xFE,
            sgi80: true,
            sgi160: false,
            rx_stbc: false,
            rx_ldpc: true,
        }),
        he: None,
        rssi: 40,
        er_cap: false,
    };
    let req = Request {
        band: Band::Ghz5,
        width_mhz: 80,
        primary: 36,
        ..legacy_req()
    };
    let st = match admit_legacy(&f, &caps, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("valid VHT admission refused"),
    };
    if st.macid != 0 || st.mode() != LegacyMode::Vht || st.width_mhz != 80 {
        return TestResult::Fail("admitted VHT station record mismatch");
    }
    // RA golden, hand-computed: mode VHT|OFDM (10), VHT
    // NSS0 cap 2 (MCS9, 0x3FF<<12) + legacy 0xFF<<4,
    // trimmed to 0x3FF010; bw 80 (2); SGI80 + LDPC.
    // w0 = 10<<1 | 2<<6 | sgi<<21 | ldpc<<22 = 0x600094;
    // w3 = band 5 GHz << 29; w4 = mode 10 | bw 2 << 8.
    let ra = match st.ra_h2c(0, false, false) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("VHT RA build refused"),
    };
    if ra != [0x600094, 0x3FF010, 0, 0x2000_0000, 0x20A, 0] {
        return TestResult::Fail("VHT RA golden mismatch");
    }
    st.release_macid(&mut pool);
    TestResult::Pass
}

fn smoke_rtw89_8922a_admit_legacy_he() -> TestResult {
    let f = factory();
    let mut pool = MacIdPool::new();
    let caps = LegacyCaps {
        supp_rates: 0xFF,
        ht: None,
        vht: None,
        he: Some(HeCaps {
            rx_mcs_80: 0xFE,
            rx_mcs_160: 0,
            rx_mcs_80p80: 0,
            has_80p80: false,
            stbc_under_80: true,
            ldpc_in_payload: true,
            dcm_16qam: false,
            partial_bw_er: false,
        }),
        rssi: 40,
        er_cap: false,
    };
    let req = Request {
        band: Band::Ghz5,
        width_mhz: 80,
        primary: 36,
        aid: 9,
        has_he: true,
        peer_ies: IES_H1_HE_PPE_NSS1,
        ..legacy_req()
    };
    let st = match admit_legacy(&f, &caps, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("valid HE admission refused"),
    };
    if st.macid != 0 || st.mode() != LegacyMode::He || st.width_mhz != 80 {
        return TestResult::Fail("admitted HE station record mismatch");
    }
    // Assoc golden, HE arm: OFDM6 lowest rate; peer IE pads
    // [2, 1, 0, 2, 1] packed into w5 (0x186); HE peer => BSR bit
    // (w8 2); AID 9 + station mode.
    let a = &st.assoc_cctl;
    if a.c0 != 0x80
        || a.w[1] != 0x4000_0000
        || a.m[1] != 0xF000_0000
        || a.w[4] != 0
        || a.m[4] != 0x7
        || a.w[5] != 0x186
        || a.m[5] != 0x3FF
        || a.w[6] != 0x8000_0009
        || a.m[6] != 0x8000_0FFF
        || a.w[8] != 2
        || a.m[8] != 2
    {
        return TestResult::Fail("HE assoc CCTL golden mismatch");
    }
    // RA golden, hand-computed: mode HE|OFDM (18), HE NSS0
    // cap 2 (MCS11, 0xFFF<<12) + legacy 0xFF<<4, trimmed
    // to 0xFFF010; bw 80 (2); STBC + LDPC; fixed GI/LTF
    // 2XHE08 (w3 fix_en + fix 3) and band 5 GHz.
    // w0 = 18<<1 | 2<<6 | ldpc<<22 | stbc<<23 = 0xC000A4;
    // w4 = mode 18 | bw 2 << 8 = 0x212.
    let ra = match st.ra_h2c(0, false, false) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("HE RA build refused"),
    };
    if ra != [0xC000A4, 0xFFF010, 0, 0x2000_3800, 0x212, 0] {
        return TestResult::Fail("HE RA golden mismatch");
    }
    st.release_macid(&mut pool);
    TestResult::Pass
}

fn smoke_rtw89_8922a_admit_legacy_refusals() -> TestResult {
    let f = factory();
    let mut pool = MacIdPool::new();
    let req = legacy_req();
    let caps = legacy_caps();
    let cases: [(Request, LegacyCaps, Error); 10] = [
        (
            Request {
                band: Band::Ghz6,
                ..req
            },
            caps,
            Error::SixGhzPowerMissing,
        ),
        (
            Request {
                eht_support: true,
                ..req
            },
            caps,
            Error::EhtInLegacyRequest,
        ),
        (
            req,
            LegacyCaps {
                supp_rates: 0,
                ..caps
            },
            Error::NoSupportedRates,
        ),
        (
            Request {
                width_mhz: 320,
                ..req
            },
            caps,
            Error::WidthNotAdvertised,
        ),
        (
            Request {
                width_mhz: 10,
                ..req
            },
            caps,
            Error::WidthNotAdvertised,
        ),
        (Request { nss: 0, ..req }, caps, Error::NssOutOfRange),
        (Request { nss: 3, ..req }, caps, Error::NssOutOfRange),
        (Request { primary: 0, ..req }, caps, Error::BadPrimary),
        (Request { aid: 0x1000, ..req }, caps, Error::AidOutOfRange),
        (Request { port: 8, ..req }, caps, Error::PortOutOfRange),
    ];
    for (case_req, case_caps, want) in cases.iter() {
        match admit_legacy(&f, case_caps, &mut pool, case_req) {
            Err(got) if got == *want => {}
            _ => return TestResult::Fail("legacy refusal case mismatch"),
        }
    }
    // Refusals must not consume MACIDs.
    let first = match pool.alloc() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("pool drained by legacy refusals"),
    };
    if first != 0 {
        return TestResult::Fail("refused legacy request consumed a MACID");
    }
    pool.free(0);
    // The legal request admits.
    let st = match admit_legacy(&f, &caps, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("legal legacy admission refused"),
    };
    if st.macid != 0 || st.mode() != LegacyMode::Legacy {
        return TestResult::Fail("legal legacy admission record mismatch");
    }
    TestResult::Pass
}

fn smoke_rtw89_8922a_mixed_mode_coexistence() -> TestResult {
    let f = factory();
    let facet = match facet() {
        Ok(facet) => facet,
        Err(e) => return e,
    };
    let mut pool = MacIdPool::new();
    // EHT station takes MACID 0.
    let eht_st = match admit(&f, facet, &mut pool, &base_req()) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("mixed EHT admission refused"),
    };
    if eht_st.macid != 0 {
        return TestResult::Fail("mixed EHT MACID must be 0");
    }
    // Legacy-only station takes MACID 1.
    let legacy_st = match admit_legacy(&f, &legacy_caps(), &mut pool, &legacy_req()) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("mixed legacy admission refused"),
    };
    if legacy_st.macid != 1 || legacy_st.mode() != LegacyMode::Legacy {
        return TestResult::Fail("mixed legacy MACID/mode mismatch");
    }
    // HT station takes MACID 2.
    let ht_caps = LegacyCaps {
        supp_rates: 0xFF,
        ht: Some(HtCaps {
            rx_mask: [0xFF, 0, 0, 0],
            sgi20: false,
            sgi40: true,
            rx_stbc: false,
            ldpc: true,
        }),
        vht: None,
        he: None,
        rssi: 40,
        er_cap: false,
    };
    let ht_req = Request {
        band: Band::Ghz5,
        width_mhz: 40,
        primary: 36,
        ..legacy_req()
    };
    let ht_st = match admit_legacy(&f, &ht_caps, &mut pool, &ht_req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("mixed HT admission refused"),
    };
    if ht_st.macid != 2 || ht_st.mode() != LegacyMode::Ht {
        return TestResult::Fail("mixed HT MACID/mode mismatch");
    }
    if !pool.is_used(0) || !pool.is_used(1) || !pool.is_used(2) || pool.is_used(3) {
        return TestResult::Fail("mixed pool state mismatch");
    }
    // Neither station programs EHT TXWD overrides (the EHT
    // facet's are off; the legacy station has none).
    if eht_st.txwd_info_eht() != Some((0, 0)) || legacy_st.txwd_info_eht() != Some((0, 0)) {
        return TestResult::Fail("mixed TXWD EHT fields must be zero");
    }
    // The legacy station's RA carries its own MACID (w0 mac
    // field): the same caps as the golden test, on MACID 1.
    let ra = match legacy_st.ra_h2c(0, false, false) {
        Ok(ra) => ra,
        Err(_) => return TestResult::Fail("mixed legacy RA build refused"),
    };
    if ra != [0x106, 0xFF5, 0, 0, 3, 0] {
        return TestResult::Fail("mixed legacy RA golden mismatch");
    }
    // Releasing the legacy MACID frees exactly that slot
    // for a new legacy station; the EHT and HT stations
    // are untouched.
    legacy_st.release_macid(&mut pool);
    if pool.is_used(1) || !pool.is_used(0) || !pool.is_used(2) {
        return TestResult::Fail("mixed release corrupted pool");
    }
    let again = match admit_legacy(&f, &legacy_caps(), &mut pool, &legacy_req()) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("mixed legacy re-admission refused"),
    };
    if again.macid != 1 || again.mode() != LegacyMode::Legacy {
        return TestResult::Fail("mixed legacy re-admission MACID mismatch");
    }
    again.release_macid(&mut pool);
    ht_st.release_macid(&mut pool);
    eht_st.release_macid(&mut pool);
    if pool.is_used(0) || pool.is_used(1) || pool.is_used(2) {
        return TestResult::Fail("mixed final release failed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_mld_admit_two_links
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_mld_ba_cam);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_mld_teardown_and_fallback
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_mld_refusals);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_mld_base_interleave
);
