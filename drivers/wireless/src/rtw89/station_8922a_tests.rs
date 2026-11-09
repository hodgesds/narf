use super::chip_8922a;
use super::efuse_be::BeFactory;
use super::eht::EhtStation;
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

fn base_req() -> Request {
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
        pads: [0; 5],
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
    let cases: [(Request, Error); 9] = [
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
        (
            Request {
                pads: [4, 0, 0, 0, 0],
                ..req
            },
            Error::PadsOutOfRange,
        ),
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
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_assoc_2g_ap);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_admit_refusals);
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_8922a_macid_pool);
