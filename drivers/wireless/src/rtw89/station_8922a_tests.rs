use super::chip_8922a;
use super::efuse_be::BeFactory;
use super::eht::EhtStation;
use super::ppe_tests::IES_E1_EHT_PPE_NSS2;
use super::ra_mask::{HeCaps, HtCaps, VhtCaps};
use super::station_8922a::*;
use narf_kernel_test::{kernel_test_in, TestResult};

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
    let cases: [(Request<'_>, Error); 8] = [
        (
            Request {
                band: Band::Ghz6,
                ..req
            },
            Error::SixGhzPowerMissing,
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

kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_eht_golden);
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_8922a_admit_ppe_from_peer_ies
);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_assoc_2g_ap);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_refusals);
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

fn legacy_req() -> Request {
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
        pads: [0; 5],
        has_he: false,
        mgq_rpt_en: false,
        p2p: false,
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
        pads: [1, 2, 0, 0, 0],
        ..legacy_req()
    };
    let st = match admit_legacy(&f, &caps, &mut pool, &req) {
        Ok(st) => st,
        Err(_) => return TestResult::Fail("valid HE admission refused"),
    };
    if st.macid != 0 || st.mode() != LegacyMode::He || st.width_mhz != 80 {
        return TestResult::Fail("admitted HE station record mismatch");
    }
    // Assoc golden, HE arm: OFDM6 lowest rate; caller
    // pads [1, 2] packed into w5; HE peer => BSR bit (w8 2);
    // AID 9 + station mode.
    let a = &st.assoc_cctl;
    if a.c0 != 0x80
        || a.w[1] != 0x4000_0000
        || a.m[1] != 0xF000_0000
        || a.w[4] != 0
        || a.m[4] != 0x7
        || a.w[5] != 0x9
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
    let cases: [(Request, LegacyCaps, Error); 11] = [
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
        (
            Request {
                pads: [4, 0, 0, 0, 0],
                ..req
            },
            caps,
            Error::PadsOutOfRange,
        ),
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
