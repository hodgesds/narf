use super::super::power::{self, Io};
use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    bytes: Vec<u8>,
    hash: u64,
    count: u32,
    operations: usize,
    fail: Option<usize>,
    denied: bool,
    ignore: bool,
    gone: bool,
    pending: bool,
    now: u64,
}
impl Model {
    fn new(seed: u8, _rx: u8) -> Self {
        Self {
            bytes: vec![seed; 0x20000],
            hash: 14695981039346656037,
            count: 0,
            operations: 0,
            fail: None,
            denied: false,
            ignore: false,
            gone: false,
            pending: false,
            now: 0,
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn record(&mut self, words: [u32; 3]) {
        self.count += 1;
        for word in words {
            for byte in word.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        Ok(self.bytes[a as usize])
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        if self.gone {
            return Ok(u32::MAX);
        }
        Ok(u32::from_le_bytes(
            self.bytes[a as usize..a as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize] = v;
        }
        self.record([1, a, u32::from(v)]);
        Ok(())
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        if !self.ignore {
            self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        }
        self.record([4, a, v]);
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, u: u64) {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += u;
        self.record([8, u as u32, 0]);
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        if self.denied {
            Err(Error::Policy)
        } else {
            Ok(())
        }
    }
    async fn rf_read(&mut self, _: u8, _: u32, _: u32) -> Result<u32, Error> {
        Err(Error::Table)
    }
    async fn rf_write(&mut self, _: u8, _: u32, _: u32, _: u32) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn begin(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn end(&mut self, _: super::super::rfk::Kind) -> Result<(), Error> {
        Err(Error::Table)
    }
    async fn pause(&mut self) -> Result<u32, Error> {
        self.access()?;
        let saved = u32::from_le_bytes(self.bytes[0xc348..0xc34c].try_into().unwrap()) & 65535;
        self.record([32, 0, saved]);
        Ok(saved)
    }
    async fn resume(&mut self, saved: u32) -> Result<(), Error> {
        self.access()?;
        self.record([64, 0, saved]);
        Ok(())
    }
}

fn plan(negative: bool, sharp: u8) -> Plan {
    let mut p = defaults::DEFAULT;
    for (i, v) in p.byrate.iter_mut().enumerate() {
        *v = if negative {
            -((i * 3 % 120) as i8)
        } else {
            80 - (i % 20) as i8
        };
    }
    p.offset = [-16, -7, 2, 15, 0];
    for n in 0..2 {
        for i in 0..8 {
            p.limits[n][i] = if negative {
                -11 - i as i8 * 3 - n as i8
            } else {
                40 + i as i8 * 2 + n as i8
            };
        }
        for i in 0..3 {
            p.ru[n][i] = if negative {
                -7 - i as i8 * 3 - n as i8
            } else {
                28 + i as i8 * 2 + n as i8
            };
        }
    }
    p.shape = [sharp, if sharp != 0 { 3 } else { 0 }];
    p
}
fn smoke_rtw89_b_power_source_units_and_full_pages_match_frozen_references() -> TestResult {
    for &(seed, negative, sharp, count, hash) in CASES {
        let mut io = Model::new(seed, 0);
        let mut owner = Power::default();
        // SAFETY: exact inert B words and explicitly private power configuration only.
        let r = unsafe { owner.prepare(&mut io, &plan(negative, sharp)) };
        if r != Ok(()) || owner.state() != State::Configured || io.count != count || io.hash != hash
        {
            return TestResult::Fail(
                "B source power units/pages/shape/reference differ from the frozen reference",
            );
        }
    }
    let mut baseline = Model::new(0xa5, 0);
    let mut owner = Power::default();
    // SAFETY: finite inert power baseline, no hardware or emission grant.
    if unsafe { owner.prepare(&mut baseline, &plan(true, 1)) } != Ok(()) {
        return TestResult::Fail("power baseline");
    }
    for fail in 0..baseline.operations {
        let mut io = Model::new(0xa5, 0);
        io.fail = Some(fail);
        let mut owner = Power::default();
        // SAFETY: inject every actual access failure into owned words.
        if unsafe { owner.prepare(&mut io, &plan(true, 1)) }.is_ok()
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("partial source power completed");
        }
        let n = io.operations;
        // SAFETY: one partial attempt must reject before touching the model.
        if unsafe { owner.prepare(&mut io, &plan(true, 1)) } != Err(Error::Terminal)
            || io.operations != n
        {
            return TestResult::Fail("source power replayed");
        }
    }
    for variant in 0..3 {
        let mut io = Model::new(0xa5, 0);
        let mut owner = Power::default();
        match variant {
            0 => io.ignore = true,
            1 => io.denied = true,
            _ => io.gone = true,
        };
        // SAFETY: ignored controls or denied current authority cannot earn completion.
        if unsafe { owner.prepare(&mut io, &plan(true, 1)) }.is_ok()
            || owner.state() != State::Preparing
        {
            return TestResult::Fail("unverified power controls completed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_power_source_units_and_full_pages_match_frozen_references
);
fn element(id: u32, rfe: u8, size: u8, entries: &[u8]) -> Element {
    let mut bytes = vec![0, 0, rfe, size];
    bytes.extend_from_slice(&((entries.len() / usize::from(size)) as u32).to_le_bytes());
    bytes.extend_from_slice(entries);
    Element {
        id,
        version: [0; 4],
        bytes,
    }
}
fn smoke_rtw89_b_power_rfe_selection_signed_decoding_and_invalid_override_fail_closed() -> TestResult
{
    let a = element(9, 0, 9, &[0, 0, 0, 0, 4, 0xf9, 0xfe, 1, 6]);
    let b = element(9, 11, 9, &[0, 0, 0, 0, 4, 0xe1, 0xe5, 0xfd, 3]);
    let c = element(9, 0, 9, &[0, 0, 0, 0, 4, 20, 24, 28, 32]);
    let d = element(9, 11, 11, &[0, 0, 0, 0, 4, 0xa1, 0xc1, 0xe1, 0xf1, 0, 0]);
    let elements = [a, b, c, d];
    let exact = Plan::from_elements(&elements, 11).unwrap();
    let default = Plan::from_elements(&elements, 7).unwrap();
    if exact.byrate[..4] != [-95, -63, -31, -15]
        || default.byrate[..4] != [20, 24, 28, 32]
        || exact.byrate[4..] != [0; 40]
        || exact.offset != [0; 5]
    {
        return TestResult::Fail("power RFE last-match/default/legacy zero extension changed");
    }
    let lmt = element(10, 0, 7, &[0, 1, 2, 1, 0, 0, 0xf9]);
    let ru = element(13, 0, 5, &[2, 1, 0, 0, 0xf5]);
    let shape = element(16, 0, 4, &[0, 1, 0, 3]);
    let p = Plan::from_elements(&[lmt, ru, shape], 1).unwrap();
    if p.limits[1][7] != -7 || p.ru[1][2] != -11 || p.shape != [0, 3] {
        return TestResult::Fail("signed source limit/RU/shape decode changed");
    }
    for bad in 0..8 {
        let mut e = element(9, 0, 11, &[0, 0, 0, 0, 4, 80, 80, 80, 80, 0, 0]);
        match bad {
            0 => e.bytes.pop().map(|_| ()).unwrap(),
            1 => e.bytes[0] = 1,
            2 => e.bytes[3] = 0,
            3 => e.bytes[8] = 3,
            4 => e.bytes[10] = 8,
            5 => e.bytes[11] = 4,
            6 => e.bytes[17] = 5,
            _ => {
                e.bytes[3] = 12;
                e.bytes.push(1);
            }
        }
        if Plan::from_elements(&[e], 1).is_ok() {
            return TestResult::Fail("malformed present power override fell back");
        }
    }
    if Plan::from_elements(&[], 255).is_ok()
        || Plan::from_elements(&[], 1).unwrap() != defaults::DEFAULT
    {
        return TestResult::Fail("power missing-only exact B fallback");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_power_rfe_selection_signed_decoding_and_invalid_override_fail_closed
);
fn smoke_rtw89_b_power_plan_selects_actual_primary_limits_fir_and_binding() -> TestResult {
    use narf_wireless::association::channel::Band;
    let Ok(initial) = Plan::fixture_defaults() else {
        return TestResult::Fail("initial power fixture");
    };
    if initial.channel() != Profile::INITIAL
        || initial.limits_and_ru() != (channels::CHANNELS[0].limits, channels::CHANNELS[0].ru)
    {
        return TestResult::Fail("initial plan lost its exact channel1 source limits");
    }
    let digest = |plan: &Plan| {
        let mut hash = narf_crypto::sha256::Sha256::new();
        plan.bind(&mut hash);
        hash.finalize()
    };
    let mut seen = alloc::vec::Vec::new();
    for primary in 1..=14u8 {
        let Some(profile) = Profile::new(Band::Ghz2, primary) else {
            return TestResult::Fail("typed2.4GHz primary refused");
        };
        let Ok(plan) = Plan::fixture_defaults_for_channel(profile) else {
            return TestResult::Fail("per-channel power fixture");
        };
        let source = channels::CHANNELS[usize::from(primary - 1)];
        if plan.channel() != profile || plan.limits_and_ru() != (source.limits, source.ru) {
            return TestResult::Fail("plan did not select the actual primary limits/RU");
        }
        let fir = profile.cck_fir(0);
        if (primary == 14) != (fir[0] == 0x023b13ff)
            || profile.cck_fir(1)[0] == fir[0] && primary != 14
        {
            return TestResult::Fail("CCK DFIR shape/channel14 selection differs from Linux");
        }
        let hash = digest(&plan);
        if seen.contains(&hash) {
            return TestResult::Fail("distinct primaries share one power binding");
        }
        seen.push(hash);
    }
    if digest(&initial) != seen[0] {
        return TestResult::Fail("channel1 fixture binding changed between constructors");
    }
    // Linux rtw8852b_table.c WW: 40MHz CCK is invalid on1/2 and12..14.
    let at = |primary: u8| channels::CHANNELS[usize::from(primary - 1)].limits[0][2];
    if at(1) != 0 || at(2) != 0 || at(3) != 50 || at(6) != 56 || at(12) != 0 || at(14) != 0 {
        return TestResult::Fail("frozen per-channel limits differ from the Linux table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_power_plan_selects_actual_primary_limits_fir_and_binding
);
/// Linux rtw8852b_table.c 5GHz: `rtw89_8852b_txpwr_lmt_5g[20MHz][ntx][rs][bf][WW]`
/// and `_lmt_ru_5g` at `rtw89_channel_to_idx`, band-1 byrate without CCK, and
/// `rtw8852bx_set_tx_shape` writing no CCK DFIR on 5GHz.
fn smoke_rtw89_b_power_plan_selects_5ghz_ww_limits_without_cck() -> TestResult {
    use narf_wireless::association::channel::Band;
    let digest = |plan: &Plan| {
        let mut hash = narf_crypto::sha256::Sha256::new();
        plan.bind(&mut hash);
        hash.finalize()
    };
    let mut seen = alloc::vec::Vec::new();
    for (slot, primary) in super::super::operating_channel::GHZ5
        .into_iter()
        .enumerate()
    {
        let Some(profile) = Profile::new(Band::Ghz5, primary) else {
            return TestResult::Fail("typed5GHz primary refused");
        };
        let Ok(plan) = Plan::fixture_defaults_for_channel(profile) else {
            return TestResult::Fail("5GHz power fixture");
        };
        let source = channels::CHANNELS_5GHZ[slot];
        if plan.limits_and_ru() != (source.limits, source.ru)
            || plan.byrate[..4] != [0; 4]
            || plan.byrate[4..] != defaults::DEFAULT.byrate[4..]
            || source
                .limits
                .iter()
                .any(|row| row[..4] != [0; 4] || row[4] == 0)
        {
            return TestResult::Fail("5GHz plan limits/RU/byrate differ from the Linux tables");
        }
        let mut fir = false;
        if plan
            .visit(|a, _, _| {
                fir |= (0x12300..0x12320).contains(&a);
                Ok(())
            })
            .is_err()
            || fir
        {
            return TestResult::Fail("5GHz power program wrote the 2.4GHz CCK DFIR");
        }
        let hash = digest(&plan);
        if seen.contains(&hash) {
            return TestResult::Fail("distinct 5GHz primaries share one power binding");
        }
        seen.push(hash);
    }
    // Spot values from rtw89_8852b_txpwr_lmt_5g / _ru_5g (WW, 20MHz).
    let at = |primary: u8| {
        let slot = super::super::operating_channel::GHZ5
            .iter()
            .position(|&p| p == primary)
            .unwrap();
        channels::CHANNELS_5GHZ[slot]
    };
    if at(36).limits[0][4] != 42
        || at(36).limits[1][7] != 14
        || at(52).limits[0][6] != 52
        || at(144).limits[0][4] != 68
        || at(149).limits[1][4] != 16
        || at(48).ru[0] != [12, 26, 38]
        || at(177).ru[1] != [16, 30, 40]
    {
        return TestResult::Fail("frozen 5GHz limits differ from the Linux table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_power_plan_selects_5ghz_ww_limits_without_cck
);
/// phy.c `rtw89_phy_fill_txpwr_limit_{40m,80m}_ax` and `_ru_{40m,80m}_ax`
/// over the frozen rtw8852b_table.c rows: center/primary/subchannel sources,
/// the 0p5 minimum, zero CCK on 5GHz, and the page bytes the plan emits.
fn smoke_rtw89_b_power_plan_fills_wide_limit_and_ru_pages_like_linux() -> TestResult {
    use super::super::operating_channel::Width;
    let c2 = |ch: u8| channels::CHANNELS[usize::from(ch - 1)];
    let c5 = |ch: u8| {
        let i = super::super::operating_channel::GHZ5
            .iter()
            .position(|&p| p == ch)
            .unwrap();
        channels::CHANNELS_5GHZ[i]
    };
    // 2.4GHz HT40: primary 1, secondary above, center 3.
    let Some(ht40) = Profile::new_2ghz_40(1, true) else {
        return TestResult::Fail("2.4GHz HT40 profile");
    };
    let Ok(plan) = Plan::fixture_defaults_for_channel(ht40) else {
        return TestResult::Fail("2.4GHz HT40 power fixture");
    };
    for n in 0..2 {
        if plan.limits[n][0..2] != c2(1).limits[n][0..2]
            || plan.limits[n][2..4] != c2(3).limits[n][2..4]
            || plan.limits[n][4..6] != c2(1).limits[n][4..6]
            || plan.limits[n][6..8] != c2(1).limits[n][6..8]
            || plan.extra[n][0..2] != c2(5).limits[n][6..8]
            || plan.extra[n][14..16] != channels::MCS40_2GHZ[0].1[n]
            || plan.ru[n] != c2(1).ru[n]
            || plan.ru_extra[n][0] != c2(5).ru[n]
            || plan.ru_extra[n][1] != [0; 3]
        {
            return TestResult::Fail("2.4GHz HT40 page differs from Linux fill_40m");
        }
    }
    // 5GHz VHT80: primary 44 (UPPER), center 42, subchannels 36..48.
    let Some(vht80) = Profile::new_5ghz(44, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile");
    };
    let Ok(plan) = Plan::fixture_defaults_for_channel(vht80) else {
        return TestResult::Fail("5GHz 80MHz power fixture");
    };
    let row40 = |c: u8| {
        channels::MCS40_5GHZ
            .iter()
            .find(|(center, _)| *center == c)
            .unwrap()
            .1
    };
    for n in 0..2 {
        let (low, high) = (row40(38)[n], row40(46)[n]);
        if plan.limits[n][0..4] != [0; 4]
            || plan.limits[n][4..6] != c5(44).limits[n][4..6]
            || plan.limits[n][6..8] != c5(36).limits[n][6..8]
            || plan.extra[n][0..2] != c5(40).limits[n][6..8]
            || plan.extra[n][2..4] != c5(44).limits[n][6..8]
            || plan.extra[n][4..6] != c5(48).limits[n][6..8]
            || plan.extra[n][14..16] != low
            || plan.extra[n][16..18] != high
            || plan.extra[n][22..24] != channels::MCS80_5GHZ[0].1[n]
            || plan.extra[n][28..30] != [low[0].min(high[0]), low[1].min(high[1])]
            || plan.ru[n] != c5(36).ru[n]
            || plan.ru_extra[n] != [c5(40).ru[n], c5(44).ru[n], c5(48).ru[n]]
        {
            return TestResult::Fail("5GHz 80MHz page differs from Linux fill_80m");
        }
    }
    let digest = |plan: &Plan| {
        let mut hash = narf_crypto::sha256::Sha256::new();
        plan.bind(&mut hash);
        hash.finalize()
    };
    let narrow = Plan::fixture_defaults_for_channel(vht80.narrowed()).unwrap();
    if digest(&plan) == digest(&narrow) || narrow.extra != [[0; 32]; 2] {
        return TestResult::Fail("wide plan aliases the 20MHz binding");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_power_plan_fills_wide_limit_and_ru_pages_like_linux
);
/// Linux rtw8852a_table.c (SHA256 b5ff4992...) TX-power tables, verbatim:
/// the 24-entry byrate cfg, the 12 delta-swing arrays, and the four sparse
/// limit tables (2184 + 2327 + 1092 + 1950 designated entries), with the
/// phy.c WW-fallback rule for a zero entry under another regd.
fn smoke_rtw89_a_power_tables_match_linux_txpwr_tables() -> TestResult {
    if tables_a::BYRATE.len() != 24
        || tables_a::LMT_2G.len() != 2184
        || tables_a::LMT_5G.len() != 2327
        || tables_a::LMT_RU_2G.len() != 1092
        || tables_a::LMT_RU_5G.len() != 1950
    {
        return TestResult::Fail("A TX-power table entry counts differ from Linux");
    }
    // phy.c `rtw89_phy_load_txpwr_byrate` decode: band 0 is exactly the B
    // frozen byrate (both chips share the values); band 1 has no CCK row.
    let (by0, off0) = tables_a::byrate(0);
    let (by1, off1) = tables_a::byrate(1);
    if by0 != defaults::DEFAULT.byrate
        || by1[..4] != [0; 4]
        || by1[4..] != defaults::DEFAULT.byrate[4..]
        || off0 != [0; 5]
        || off1 != [0; 5]
    {
        return TestResult::Fail("A byrate decode differs from the Linux cfg table");
    }
    let lmt = tables_a::lmt;
    let ru = tables_a::lmt_ru;
    let ww = tables_a::WW;
    // 2.4GHz WW spot values (ch is `rtw89_channel_to_idx`).
    if lmt(false, 0, 0, 0, 0, ww, 0) != 56
        || lmt(false, 0, 0, 1, 0, ww, 0) != 58
        || lmt(false, 0, 0, 2, 0, ww, 0) != 58
        || lmt(false, 0, 1, 2, 1, ww, 0) != 34
        || lmt(false, 0, 0, 0, 0, ww, 13) != 76
        || lmt(false, 0, 1, 0, 0, ww, 13) != 64
        || lmt(false, 0, 0, 2, 0, ww, 11) != 54
        || lmt(false, 1, 0, 2, 0, ww, 2) != 56
        || ru(false, 0, 0, ww, 0) != 32
        || ru(false, 2, 0, ww, 0) != 52
        || ru(false, 2, 1, ww, 0) != 40
    {
        return TestResult::Fail("A 2.4GHz WW limits/RU differ from the Linux table");
    }
    // 5GHz WW spot values.
    if lmt(true, 0, 0, 1, 0, ww, 0) != 30
        || lmt(true, 0, 1, 2, 1, ww, 0) != 6
        || lmt(true, 0, 0, 2, 0, ww, 8) != 52
        || lmt(true, 0, 0, 1, 0, ww, 37) != 54
        || lmt(true, 1, 0, 2, 0, ww, 1) != 30
        || lmt(true, 2, 0, 2, 0, ww, 3) != 30
        || lmt(true, 0, 0, 1, 0, ww, 48) != 0
        || ru(true, 0, 0, ww, 0) != 22
        || ru(true, 2, 1, ww, 0) != 18
        || ru(true, 0, 1, ww, 46) != 16
        || ru(true, 0, 0, ww, 52) != 0
    {
        return TestResult::Fail("A 5GHz WW limits/RU differ from the Linux table");
    }
    // phy.c `rtw89_phy_read_txpwr_limit{,_ru}` WW fallback: a zero entry
    // under the requested regd falls back to WW; an unlisted regd reads 0
    // raw and WW through the fallback. (FCC ch1 CCK is 76, not WW's 56;
    // ETSI ch13 MCS is 58.)
    if tables_a::lmt_or_ww(false, 0, 0, 0, 0, tables_a::FCC, 0) != 76
        || tables_a::lmt_or_ww(false, 0, 0, 2, 0, tables_a::ETSI, 12) != 58
        || tables_a::lmt(false, 0, 0, 0, 0, 8, 0) != 0
        || tables_a::lmt_or_ww(false, 0, 0, 0, 0, 8, 0) != 56
        || tables_a::lmt_ru_or_ww(false, 2, 0, tables_a::FCC, 0) != 76
    {
        return TestResult::Fail("A regd limit fallback differs from phy.c");
    }
    // `rtw89_8852a_trk_cfg` delta-swing rows (fw.h trk types 4..=15).
    if !tables_a::delta_swing(4, 0).is_some_and(|r| r[..4] == [0, 1, 1, 2])
        || !tables_a::delta_swing(4, 2).is_some_and(|r| r[29] == 9)
        || !tables_a::delta_swing(8, 0).is_some_and(|r| r[..4] == [0, 1, 1, 1])
        || !tables_a::delta_swing(8, 0).is_some_and(|r| r[29] == 7)
        || !tables_a::delta_swing(15, 0).is_some_and(|r| r[29] == 10)
        || tables_a::delta_swing(8, 1).is_some()
        || tables_a::delta_swing(0, 0).is_some()
        || tables_a::delta_swing(3, 0).is_some()
        || tables_a::delta_swing(16, 0).is_some()
        || tables_a::delta_swing(4, 3).is_some()
    {
        return TestResult::Fail("A delta-swing trk_cfg mapping differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_power_tables_match_linux_txpwr_tables
);
/// Linux rtw8852a_table.c WW 20MHz rows, end to end through the A plan:
/// per-primary limits/RU, band-1 byrate without CCK, no shape step, and
/// distinct bindings per primary (and per chip: the A ch1 binding differs
/// from the B ch1 binding even where the rows agree).
fn smoke_rtw89_a_power_plan_selects_actual_primary_limits() -> TestResult {
    use narf_wireless::association::channel::Band;
    let digest = |plan: &Plan| {
        let mut hash = narf_crypto::sha256::Sha256::new();
        plan.bind(&mut hash);
        hash.finalize()
    };
    let Ok(initial) = Plan::fixture_defaults_a() else {
        return TestResult::Fail("initial A power fixture");
    };
    if initial.channel() != Profile::INITIAL
        || initial.chip() != Chip::A
        || initial.byrate != tables_a::byrate(0).0
        || initial.offset != [0; 5]
        || initial.shape != [0; 2]
        || initial.limits_and_ru()
            != (
                [[56, 0, 0, 0, 58, 0, 58, 0], [44, 0, 0, 0, 46, 0, 46, 34]],
                [[32, 42, 52], [20, 30, 40]],
            )
    {
        return TestResult::Fail("initial A plan lost its exact channel1 source limits");
    }
    let Ok(baseline) = Plan::fixture_defaults() else {
        return TestResult::Fail("initial B power fixture");
    };
    if baseline.chip() != Chip::B || digest(&initial) == digest(&baseline) {
        return TestResult::Fail("A ch1 binding aliases the B ch1 binding");
    }
    let mut seen = alloc::vec::Vec::new();
    for primary in 1..=14u8 {
        let Some(profile) = Profile::new(Band::Ghz2, primary) else {
            return TestResult::Fail("typed2.4GHz primary refused");
        };
        let Ok(plan) = Plan::fixture_defaults_a_for_channel(profile) else {
            return TestResult::Fail("per-channel A power fixture");
        };
        if plan.channel() != profile
            || plan.chip() != Chip::A
            || plan.limits_and_ru() != channel20_a(profile)
            || plan.byrate != tables_a::byrate(0).0
            || plan.shape != [0; 2]
        {
            return TestResult::Fail("A plan did not select the actual primary limits/RU");
        }
        let hash = digest(&plan);
        if seen.contains(&hash) {
            return TestResult::Fail("distinct 2.4GHz primaries share one A power binding");
        }
        seen.push(hash);
    }
    if digest(&initial) != seen[0] {
        return TestResult::Fail("channel1 A fixture binding changed between constructors");
    }
    // Hardcoded WW rows: ch12/ch13 differ from B, ch14 is CCK-only.
    let at = |primary: u8| {
        let profile = Profile::new(Band::Ghz2, primary).unwrap();
        Plan::fixture_defaults_a_for_channel(profile).unwrap()
    };
    if at(12).limits_and_ru()
        != (
            [[56, 0, 0, 0, 56, 0, 54, 0], [44, 0, 0, 0, 42, 0, 42, 34]],
            [[32, 42, 52], [20, 30, 40]],
        )
        || at(13).limits_and_ru()
            != (
                [[48, 0, 0, 0, 52, 0, 50, 0], [38, 0, 0, 0, 40, 0, 40, 34]],
                [[32, 36, 40], [20, 30, 26]],
            )
        || at(14).limits_and_ru()
            != (
                [[76, 0, 0, 0, 0, 0, 0, 0], [64, 0, 0, 0, 0, 0, 0, 0]],
                [[0, 0, 0], [0, 0, 0]],
            )
    {
        return TestResult::Fail("frozen A 2.4GHz limits differ from the Linux table");
    }
    // 5GHz: no CCK byrate, no shape, and the A table covers only 25 of the
    // 28 primaries (169/173/177 are unlisted cells and read 0, unlike B).
    let mut seen5 = alloc::vec::Vec::new();
    for primary in super::super::operating_channel::GHZ5 {
        let Some(profile) = Profile::new(Band::Ghz5, primary) else {
            return TestResult::Fail("typed5GHz primary refused");
        };
        let Ok(plan) = Plan::fixture_defaults_a_for_channel(profile) else {
            return TestResult::Fail("5GHz A power fixture");
        };
        if plan.limits_and_ru() != channel20_a(profile)
            || plan.byrate[..4] != [0; 4]
            || plan.byrate[4..] != tables_a::byrate(1).0[4..]
            || plan.shape != [0; 2]
        {
            return TestResult::Fail("5GHz A plan limits/RU/byrate differ from the Linux tables");
        }
        let hash = digest(&plan);
        if seen5.contains(&hash) {
            return TestResult::Fail("distinct 5GHz primaries share one A power binding");
        }
        seen5.push(hash);
    }
    let at5 = |primary: u8| {
        let profile = Profile::new(Band::Ghz5, primary).unwrap();
        Plan::fixture_defaults_a_for_channel(profile).unwrap()
    };
    if at5(144).limits[0][4] != 54
        || at5(144).limits[1][7] != 30
        || at5(149).limits[1][4] != 16
        || at5(52).limits[0][6] != 52
        || at5(36).ru != [[22, 30, 30], [8, 18, 18]]
        || at5(48).ru[1] != [4, 16, 18]
        || at5(169).limits != [[0; 8]; 2]
        || at5(169).ru != [[0; 3]; 2]
        || at5(177).limits != [[0; 8]; 2]
    {
        return TestResult::Fail("frozen A 5GHz limits differ from the Linux table");
    }
    // No shape writes on either band: `rtw8852a_set_txpwr` has no
    // tx-shape step, so the A program writes neither the CCK DFIR nor
    // the 0x14494 shape word (the B 2.4GHz program writes both).
    for primary in [1u8, 36] {
        let band = if primary == 1 { Band::Ghz2 } else { Band::Ghz5 };
        let profile = Profile::new(band, primary).unwrap();
        let plan = Plan::fixture_defaults_a_for_channel(profile).unwrap();
        let mut shape = false;
        if plan
            .visit(|a, _, _| {
                shape |= a == 0x14494 || (0x12300..0x12320).contains(&a);
                Ok(())
            })
            .is_err()
            || shape
        {
            return TestResult::Fail("A power program wrote a tx-shape control");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_power_plan_selects_actual_primary_limits
);
/// Firmware-element override over the A static tables: the shared byrate/
/// limit/RU selection still applies, the missing-only fallback is the A
/// static plan (not B's), rfe 255 fails closed, and a TX_SHAPE_LMT
/// element is ignored (Linux `rtw8852a_set_txpwr` has no shape step).
fn smoke_rtw89_a_power_rfe_selection_and_static_fallback() -> TestResult {
    let a = element(9, 0, 9, &[0, 0, 0, 0, 4, 0xf9, 0xfe, 1, 6]);
    let b = element(9, 11, 9, &[0, 0, 0, 0, 4, 0xe1, 0xe5, 0xfd, 3]);
    let c = element(9, 0, 9, &[0, 0, 0, 0, 4, 20, 24, 28, 32]);
    let d = element(9, 11, 11, &[0, 0, 0, 0, 4, 0xa1, 0xc1, 0xe1, 0xf1, 0, 0]);
    let elements = [a, b, c, d];
    let exact = Plan::from_elements_a(&elements, 11).unwrap();
    let default = Plan::from_elements_a(&elements, 7).unwrap();
    if exact.byrate[..4] != [-95, -63, -31, -15]
        || default.byrate[..4] != [20, 24, 28, 32]
        || exact.byrate[4..] != [0; 40]
        || exact.offset != [0; 5]
        || exact.chip() != Chip::A
    {
        return TestResult::Fail("A power RFE last-match/default byrate changed");
    }
    let lmt = element(10, 0, 7, &[0, 1, 2, 1, 0, 0, 0xf9]);
    let ru = element(13, 0, 5, &[2, 1, 0, 0, 0xf5]);
    let shape = element(16, 0, 4, &[0, 1, 0, 3]);
    let p = Plan::from_elements_a(&[lmt, ru, shape], 1).unwrap();
    if p.limits[1][7] != -7 || p.ru[1][2] != -11 || p.shape != [0; 2] {
        return TestResult::Fail("A power limit/RU override or shape ignore changed");
    }
    if Plan::from_elements_a(&[], 255).is_ok()
        || Plan::from_elements_a(&[], 1).unwrap() != Plan::fixture_defaults_a().unwrap()
        || Plan::from_elements_a(&[], 1).unwrap() == Plan::fixture_defaults().unwrap()
    {
        return TestResult::Fail("A power missing-only fallback is not the A static plan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_power_rfe_selection_and_static_fallback
);
/// phy.c `rtw89_phy_fill_txpwr_limit_{40m,80m}_ax` and `_ru_{40m,80m}_ax`
/// over the A WW rows: center/primary/subchannel sources, the 0p5 minimum,
/// zero CCK on 5GHz, and the page bytes the A plan emits.
fn smoke_rtw89_a_power_plan_fills_wide_pages_like_linux() -> TestResult {
    use super::super::operating_channel::Width;
    // 2.4GHz HT40: primary 1, secondary above, center 3.
    let Some(ht40) = Profile::new_2ghz_40(1, true) else {
        return TestResult::Fail("2.4GHz HT40 profile");
    };
    let Ok(plan) = Plan::fixture_defaults_a_for_channel(ht40) else {
        return TestResult::Fail("2.4GHz HT40 A power fixture");
    };
    for n in 0..2 {
        let (cck20, cck40, ofdm, mcs20, mcs40, ru1, ru5) = if n == 0 {
            (
                [56, 0],
                [58, 0],
                [58, 0],
                [58, 0],
                [56, 0],
                [32, 42, 52],
                [32, 42, 52],
            )
        } else {
            (
                [44, 0],
                [46, 0],
                [46, 0],
                [46, 34],
                [46, 34],
                [20, 30, 40],
                [20, 30, 40],
            )
        };
        if plan.limits[n][0..2] != cck20
            || plan.limits[n][2..4] != cck40
            || plan.limits[n][4..6] != ofdm
            || plan.limits[n][6..8] != mcs20
            || plan.extra[n][0..2] != mcs20
            || plan.extra[n][14..16] != mcs40
            || plan.ru[n] != ru1
            || plan.ru_extra[n][0] != ru5
            || plan.ru_extra[n][1] != [0; 3]
        {
            return TestResult::Fail("2.4GHz HT40 A page differs from Linux fill_40m");
        }
    }
    // 5GHz VHT80: primary 44 (UPPER), center 42, subchannels 36..48.
    let Some(vht80) = Profile::new_5ghz(44, Width::Mhz80) else {
        return TestResult::Fail("5GHz 80MHz profile");
    };
    let Ok(plan) = Plan::fixture_defaults_a_for_channel(vht80) else {
        return TestResult::Fail("5GHz 80MHz A power fixture");
    };
    for n in 0..2 {
        let (ofdm, mcs, mcs40, mcs80, ru36, ru40, ru44, ru48) = if n == 0 {
            (
                [30, 0],
                [30, 0],
                [30, 0],
                [30, 0],
                [22, 30, 30],
                [22, 30, 30],
                [22, 30, 30],
                [20, 30, 30],
            )
        } else {
            (
                [18, 0],
                [18, 6],
                [18, 6],
                [18, 6],
                [8, 18, 18],
                [8, 18, 18],
                [8, 18, 18],
                [4, 16, 18],
            )
        };
        if plan.limits[n][0..4] != [0; 4]
            || plan.limits[n][4..6] != ofdm
            || plan.limits[n][6..8] != mcs
            || plan.extra[n][0..2] != mcs
            || plan.extra[n][2..4] != mcs
            || plan.extra[n][4..6] != mcs
            || plan.extra[n][14..16] != mcs40
            || plan.extra[n][16..18] != mcs40
            || plan.extra[n][22..24] != mcs80
            || plan.extra[n][28..30] != mcs40
            || plan.ru[n] != ru36
            || plan.ru_extra[n] != [ru40, ru44, ru48]
        {
            return TestResult::Fail("5GHz 80MHz A page differs from Linux fill_80m");
        }
    }
    let digest = |plan: &Plan| {
        let mut hash = narf_crypto::sha256::Sha256::new();
        plan.bind(&mut hash);
        hash.finalize()
    };
    let narrow = Plan::fixture_defaults_a_for_channel(vht80.narrowed()).unwrap();
    if digest(&plan) == digest(&narrow) || narrow.extra != [[0; 32]; 2] {
        return TestResult::Fail("wide A plan aliases the 20MHz binding");
    }
    // A supports 20/40/80MHz only; 160MHz is refused like on B.
    let Some(wide160) = Profile::new_5ghz_160(44) else {
        return TestResult::Fail("5GHz 160MHz profile");
    };
    if Plan::fixture_defaults_a_for_channel(wide160).is_ok() {
        return TestResult::Fail("160MHz A plan was admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_power_plan_fills_wide_pages_like_linux
);
/// The A program through `Power::prepare` on the inert model: the AX
/// byrate/offset/limit/RU words land with the A table values (RF units
/// shifted >> 1 at emit), the reference-control tail lands, no tx-shape
/// word is written on either band, and a replay is refused.
fn smoke_rtw89_a_power_prepare_emits_ax_program_without_shape() -> TestResult {
    let word = |io: &Model, a: u32| {
        u32::from_le_bytes(io.bytes[a as usize..a as usize + 4].try_into().unwrap())
    };
    for (primary, band, byrate0, lmt0, ru0) in [
        (
            1u8,
            narf_wireless::association::channel::Band::Ghz2,
            0x2828_2828u32,
            0x0000_001cu32,
            0x0000_0010u32,
        ),
        (
            36u8,
            narf_wireless::association::channel::Band::Ghz5,
            0x0000_0000u32,
            0x0000_0000u32,
            0x0000_000bu32,
        ),
    ] {
        let profile = Profile::new(band, primary).unwrap();
        let plan = Plan::fixture_defaults_a_for_channel(profile).unwrap();
        let mut io = Model::new(0xa5, 0);
        let mut owner = Power::default();
        // SAFETY: exact inert A words and explicitly private power configuration only.
        let r = unsafe { owner.prepare(&mut io, &plan) };
        if r != Ok(()) || owner.state() != State::Configured || io.count != 49 {
            return TestResult::Fail("A power prepare did not emit the 49 AX words");
        }
        if word(&io, 0xd2c0) != byrate0
            || word(&io, 0xd2ec) != lmt0
            || word(&io, 0xd33c) != ru0
            || io.bytes[0x14494..0x14498] != [0xa5; 4]
            || io.bytes[0x12300..0x12304] != [0xa5; 4]
            || io.bytes[0x15804..0x15808] == [0xa5; 4]
            || io.bytes[0xd200..0xd204] == [0xa5; 4]
        {
            return TestResult::Fail("A power prepare words/reference/shape differ from Linux");
        }
        // SAFETY: one completed attempt must reject before touching the model.
        if unsafe { owner.prepare(&mut io, &plan) } != Err(Error::Terminal) {
            return TestResult::Fail("A power prepare replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_power_prepare_emits_ax_program_without_shape
);
