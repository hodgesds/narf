use super::super::mac::ChipId;
use super::*;
use alloc::vec;
use narf_capabilities::{object_table, CapSlot, CapType, Rights};
use narf_kernel_test::{kernel_test_in, TestResult};
fn authority() -> Cap<FirmwareBlob, Read> {
    let (index, generation) = object_table::register(FirmwareBlob::KIND);
    // SAFETY: private freshly registered firmware object, exact Read type/rights;
    // no unsigned device/firmware lookup or production policy is bypassed.
    unsafe {
        Cap::mint(CapSlot::new(
            generation,
            index,
            Read::BITS,
            FirmwareBlob::KIND as u32,
        ))
    }
}
fn board() -> Board {
    Board {
        identity: [7; 32],
        mac: [2, 4, 6, 8, 10, 12],
        device: 0xb852,
    }
}
fn image(board: Board) -> [u8; LENGTH] {
    let mut b = [0; LENGTH];
    b[..4].copy_from_slice(b"N52B");
    b[4..8].copy_from_slice(&[2, 0, 128, 0]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    b[14..16].copy_from_slice(&board.device.to_le_bytes());
    b[16..48].copy_from_slice(&board.identity);
    b[48..54].copy_from_slice(&board.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 3]);
    b[58..60].copy_from_slice(&4i16.to_le_bytes());
    b[60..62].copy_from_slice(&76i16.to_le_bytes());
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
    b[64..66].copy_from_slice(&48i16.to_le_bytes());
    b[66..68].copy_from_slice(&56i16.to_le_bytes());
    b
}
fn domain() -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    }
}
fn smoke_rtw8852b_wmm_measured_recipe_is_distinct_from_legacy_full_radio() -> TestResult {
    let base = board();
    let cap = authority();
    let legacy = image(base);
    let mut old = Qualification::from_verified(&legacy, Some([3; 32]), base, cap).unwrap();
    old.model_domain = Some(alloc::sync::Arc::new(domain()));
    if old.wmm_allowed() != Ok(false) {
        return TestResult::Fail("legacy full-radio qualification silently granted WMM");
    }
    let mut bytes = legacy;
    bytes[57] = 7;
    if Qualification::from_verified(&bytes, Some([3; 32]), base, cap).is_ok() {
        return TestResult::Fail("old digest reused by new WMM emission recipe");
    }
    // Frozen previous BE/TID0 CCK1 recipe: those measured bytes cannot admit
    // the new source DATA_RATE program, even though wire flags remain7.
    let mut old_recipe = narf_crypto::sha256::Sha256::new();
    old_recipe.update(b"B WMM v1 AP response-bound; BE/TID0 CCK1 raw26 halfwords13; noHT/BA/UAPSD/TSPEC; source H2C MAC9 class15 fourAC ACK; BE ECWmin>=5 max>=10 AIFSN>=3 TXOP0 SIFS10 long20/short9; noAP ACM BE; bounded AIFS8bit");
    old_recipe.update(&[221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0]);
    let mut old_identity = narf_crypto::sha256::Sha256::new();
    old_identity.update(b"NARF RTL8852B WMM BE/TID0 legacy1 optional operating recipe v1");
    old_identity.update(&base.identity());
    old_identity.update(&old_recipe.finalize());
    bytes[16..48].copy_from_slice(&old_identity.finalize());
    if !matches!(
        Qualification::from_verified(&bytes, Some([3; 32]), base, cap),
        Err(Error::Identity)
    ) {
        return TestResult::Fail(
            "previous CCK1 WMM qualification admitted richer legacy DATA rates",
        );
    }
    bytes[16..48].copy_from_slice(&base.wmm().identity());
    let mut qualified = match Qualification::from_verified(&bytes, Some([3; 32]), base, cap) {
        Ok(q) => q,
        Err(_) => return TestResult::Fail("exact signed WMM recipe rejected"),
    };
    qualified.model_domain = Some(alloc::sync::Arc::new(domain()));
    if !qualified.matches(base)
        || qualified.wmm_allowed() != Ok(true)
        || base.wmm().identity() == base.identity()
    {
        return TestResult::Fail("WMM recipe/current measured authority not bound");
    }
    cap.revoke();
    if qualified.wmm_allowed() != Err(Error::Authority) {
        return TestResult::Fail("WMM accepted revoked actual qualification cap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/wmm",
    smoke_rtw8852b_wmm_measured_recipe_is_distinct_from_legacy_full_radio
);
fn smoke_rtw89_b_full_radio_artifact_cannot_reuse_basic_and_is_revocable() -> TestResult {
    let board = board();
    let bytes = image(board);
    let cap = authority();
    if !matches!(
        Qualification::from_verified(&bytes, None, board, cap),
        Err(Error::Unsigned)
    ) {
        return TestResult::Fail("unsigned B calibration accepted");
    }
    let calibration = Qualification::from_verified(&bytes, Some([3; 32]), board, cap).unwrap();
    if !calibration.matches(board) || calibration.check(&domain()).is_err() {
        return TestResult::Fail("exact measured calibration bound rejected");
    }
    for end in 0..bytes.len() {
        if Qualification::from_verified(&bytes[..end], Some([3; 32]), board, cap).is_ok() {
            return TestResult::Fail("truncated calibration accepted");
        }
    }
    for at in [0, 4, 6, 8, 12, 14, 16, 48, 54, 55, 56, 57, 68, 127] {
        let mut bad = bytes;
        bad[at] ^= 1;
        if Qualification::from_verified(&bad, Some([3; 32]), board, cap).is_ok() {
            return TestResult::Fail("different board/recipe/profile calibration accepted");
        }
    }
    cap.revoke();
    if !matches!(calibration.current(), Err(Error::Authority))
        || !matches!(
            Qualification::from_verified(&bytes, Some([3; 32]), board, cap),
            Err(Error::Authority)
        )
    {
        return TestResult::Fail("revoked B qualification remained usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_artifact_cannot_reuse_basic_and_is_revocable
);
fn smoke_rtw89_b_full_radio_all_emission_peaks_obey_every_current_rule() -> TestResult {
    let board = board();
    let bytes = image(board);
    let cal = Qualification::from_verified(&bytes, Some([3; 32]), board, authority()).unwrap();
    for variant in 0..8 {
        let mut d = domain();
        match variant {
            0 => d.rules[0].max_power_dbm = 10,
            1 => d.rules[0].max_bandwidth_mhz = 10,
            2 => d.rules[0].flags = narf_wireless::reg::RegFlags::INDOOR_ONLY,
            3 => d.rules[0].freq_start_mhz = 2403,
            4 => d.rules[0].freq_end_mhz = 2421,
            5 => d.rules.clear(),
            7 => d.rules[0].flags = narf_wireless::reg::RegFlags::NO_IR,
            _ => d.rules.push(narf_wireless::reg::RegRule {
                freq_start_mhz: 2402,
                freq_end_mhz: 2422,
                max_bandwidth_mhz: 20,
                max_power_dbm: 10,
                flags: narf_wireless::reg::RegFlags::empty(),
            }),
        }
        if cal.check(&d) != Err(Error::Policy) {
            return TestResult::Fail(
                "restrictive overlapping/current channel rule did not close calibration",
            );
        }
    }
    let mut bytes = bytes;
    bytes[60..62].copy_from_slice(&43i16.to_le_bytes());
    let cal = Qualification::from_verified(&bytes, Some([3; 32]), board, authority()).unwrap();
    if cal.check(&domain()) != Err(Error::Policy) {
        return TestResult::Fail("signed conducted peak plus antenna exceeded board ceiling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_all_emission_peaks_obey_every_current_rule
);

struct FactoryModel {
    rfe: u8,
    cut: u8,
    trim: u8,
}
impl super::super::power::Io for FactoryModel {
    fn read8(&mut self, _: u32) -> Result<u8, super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn read16(&mut self, a: u32) -> Result<u16, super::super::power::Error> {
        if a == 10 {
            Ok(32)
        } else {
            Err(super::super::power::Error::Access)
        }
    }
    fn read32(&mut self, _: u32) -> Result<u32, super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn write32(&mut self, _: u32, _: u32) -> Result<(), super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, super::super::power::Error> {
        Err(super::super::power::Error::Access)
    }
}
impl super::super::factory::Source for FactoryModel {
    fn profile(&self) -> (ChipId, u8) {
        (ChipId::Rtl8852B, self.cut)
    }
    async fn physical(
        &mut self,
        start: u16,
        out: &mut [u8],
    ) -> Result<(), super::super::power::Error> {
        out.fill(255);
        match (start, out.len()) {
            (0, 1216) => {
                let mut cursor = 4;
                for (offset, b) in [
                    (0x400, [2, 4]),
                    (0x402, [6, 8]),
                    (0x404, [10, 12]),
                    (0x2ca, [self.rfe, b'U']),
                    (0x2cc, [b'S', 255]),
                ] {
                    let block = offset / 8;
                    out[cursor] = (block >> 4) as u8;
                    out[cursor + 1] = ((block & 15) << 4) as u8 | (15 ^ (1 << ((offset % 8) / 2)));
                    out[cursor + 2..cursor + 4].copy_from_slice(&b);
                    cursor += 4;
                }
            }
            (0x580, 128) => out[127] = self.trim,
            _ => return Err(super::super::power::Error::Access),
        }
        Ok(())
    }
}
struct Files {
    version: [u8; 4],
    body: u8,
}
impl super::super::prepared::Files for Files {
    fn load(&mut self, _: &'static str) -> Result<alloc::vec::Vec<u8>, super::super::fw::FwError> {
        let mut b = vec![0; 52];
        b[4..8].copy_from_slice(&self.version);
        b[24..28].copy_from_slice(&0x100u32.to_le_bytes());
        b[32..36].copy_from_slice(&0x8000u32.to_le_bytes());
        b[36..40].copy_from_slice(&4u32.to_le_bytes());
        b[51] = self.body;
        Ok(b)
    }
}
fn ready<T>(f: impl core::future::Future<Output = T>) -> Option<T> {
    use core::{
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_full_radio_identity_binds_actual_factory_and_verified_assets() -> TestResult {
    let device = narf_bus::DeviceId {
        vendor: 0x10ec,
        device: 0xb852,
        class: 0x028000,
        subsystem_vendor: 1,
        subsystem_id: 2,
    };
    let mut identities = alloc::vec::Vec::new();
    for variant in 0..6 {
        let mut model = FactoryModel {
            rfe: if variant == 1 { 5 } else { 1 },
            cut: if variant == 2 { 0 } else { 1 },
            trim: if variant == 3 { 254 } else { 255 },
        };
        let mut factory = Factory::default();
        if ready(factory.read(&mut model)) != Some(Ok(())) {
            return TestResult::Fail("real factory parser fixture");
        }
        let image = super::super::prepared::load(
            &mut Files {
                version: [0, 29, 29, 18],
                body: u8::from(variant == 4),
            },
            ChipId::Rtl8852B,
            model.cut,
        )
        .unwrap();
        let assets = Assets::from_prepared(&image).unwrap();
        let mut device = device;
        if variant == 5 {
            device.subsystem_id = 3;
        }
        let identity = Board::new(
            &factory,
            device,
            &assets,
            &Plan::from_assets(&assets, model.rfe).unwrap(),
            &super::super::firmware_phycap::Receipt::decode([0x00000403, 0, 0, 0]).unwrap(),
        )
        .unwrap()
        .identity();
        if identities.contains(&identity) {
            return TestResult::Fail(
                "different actual cut/RFE/trim/firmware/subsystem reused calibration identity",
            );
        }
        identities.push(identity);
        let newer = super::super::prepared::load(
            &mut Files {
                version: [0, 29, 122, 0],
                body: 0,
            },
            ChipId::Rtl8852B,
            model.cut,
        )
        .unwrap();
        let newer = Assets::from_prepared(&newer).unwrap();
        if Board::new(
            &factory,
            device,
            &newer,
            &Plan::from_assets(&newer, model.rfe).unwrap(),
            &super::super::firmware_phycap::Receipt::decode([0x00000403, 0, 0, 0]).unwrap(),
        ) != Err(Error::Identity)
        {
            return TestResult::Fail("unsupported coex ABI acquired measured board identity");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_identity_binds_actual_factory_and_verified_assets
);

/// Explicit inert artifact/policy boundary for native revocation regressions.
/// This never installs a global policy or grants a real attach/calibration.
pub(in crate::rtw89) fn revocable_model() -> (Qualification, Cap<FirmwareBlob, Read>) {
    let board = board();
    let cap = authority();
    let mut calibration =
        Qualification::from_verified(&image(board), Some([3; 32]), board, cap).unwrap();
    calibration.model_domain = Some(alloc::sync::Arc::new(domain()));
    (calibration, cap)
}
pub(in crate::rtw89) fn revoke_on_publication_model() -> (Qualification, Cap<FirmwareBlob, Read>) {
    let (mut qualification, cap) = revocable_model();
    qualification.model_revoke_before_publication = true;
    (qualification, cap)
}

fn expanded_record(base: &Qualification, magic: &[u8; 4], binding: [u8; 32]) -> [u8; 128] {
    let mut bytes = [0; 128];
    bytes[..4].copy_from_slice(magic);
    bytes[4..8].copy_from_slice(&[1, 0, 128, 0]);
    bytes[8..12].copy_from_slice(&128u32.to_le_bytes());
    bytes[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    bytes[14..16].copy_from_slice(&base.board.device.to_le_bytes());
    bytes[16..48].copy_from_slice(&binding);
    bytes[48..54].copy_from_slice(&base.board.mac);
    bytes[54..58].copy_from_slice(&[1, 20, 1, 3]);
    bytes
}
/// Explicit inert authenticated-record boundary for native register tests;
/// no production attach, measured RF envelope or physical receipt is minted.
pub(in crate::rtw89) fn rf_tracking_model(
    window: super::super::rf_tracking::Window,
    aggregate: bool,
) -> (
    Qualification,
    Cap<FirmwareBlob, Read>,
    Cap<FirmwareBlob, Read>,
) {
    let board = board();
    let flags = Program::Ampdu.flags();
    let mut bytes = image(board.with_programs(flags));
    bytes[57] = flags;
    let base_cap = authority();
    let mut base = Qualification::from_verified(&bytes, Some([3; 32]), board, base_cap).unwrap();
    base.model_domain = Some(alloc::sync::Arc::new(domain()));
    if aggregate {
        let request = amsdu::AmsduRequest::new(&base).unwrap();
        let mut record = expanded_record(&base, b"N52A", request.binding);
        record[58..60].copy_from_slice(&5000u16.to_le_bytes());
        record[60] = 8;
        base.amsdu = Some(
            amsdu::Amsdu::from_verified(&base, &request, &record, Some([3; 32]), authority())
                .unwrap(),
        );
    }
    let request = rf_tracking::Request::new(&base).unwrap();
    let mut record = expanded_record(&base, b"N52T", request.binding);
    record[58..60].copy_from_slice(&window.low.to_le_bytes());
    record[60..62].copy_from_slice(&window.high.to_le_bytes());
    let tracking_cap = authority();
    base.rf_tracking = Some(
        rf_tracking::Tracking::from_verified(&base, &request, &record, Some([3; 32]), tracking_cap)
            .unwrap(),
    );
    (base, base_cap, tracking_cap)
}

fn smoke_rtw8852b_periodic_dpk_signed_joint_program_window_and_current_caps() -> TestResult {
    use super::super::rf_tracking::Window;
    let window = Window {
        low: 100,
        high: 140,
    };
    let (mut base, base_cap, tracking_cap) = rf_tracking_model(window, false);
    if base.rf_tracking_window() != Ok(Some(window)) || base.with_current(|| Ok(7)) != Ok(7) {
        return TestResult::Fail("actual signed tracking record/current power window");
    }
    let request = rf_tracking::Request::new(&base).unwrap();
    let candidate_cap = authority();
    let mut record = expanded_record(&base, b"N52T", request.binding);
    record[58..60].copy_from_slice(&100u16.to_le_bytes());
    record[60..62].copy_from_slice(&140u16.to_le_bytes());
    for signer in [None, Some([4; 32])] {
        if rf_tracking::Tracking::from_verified(&base, &request, &record, signer, candidate_cap)
            .is_ok()
        {
            return TestResult::Fail("unsigned/different signer periodic RF program");
        }
    }
    for length in 0..128 {
        if rf_tracking::Tracking::from_verified(
            &base,
            &request,
            &record[..length],
            Some([3; 32]),
            candidate_cap,
        )
        .is_ok()
        {
            return TestResult::Fail("truncated periodic RF program");
        }
    }
    for at in [0, 4, 8, 12, 14, 16, 48, 54, 55, 56, 57, 62, 127] {
        let mut bad = record;
        bad[at] ^= 1;
        if rf_tracking::Tracking::from_verified(&base, &request, &bad, Some([3; 32]), candidate_cap)
            .is_ok()
        {
            return TestResult::Fail("malformed/other identity periodic RF program");
        }
    }
    let mut bad = record;
    bad[58..60].copy_from_slice(&141u16.to_le_bytes());
    if rf_tracking::Tracking::from_verified(&base, &request, &bad, Some([3; 32]), candidate_cap)
        .is_ok()
    {
        return TestResult::Fail("inverted measured PWSF window");
    }
    let (with_aggregate, _, _) = rf_tracking_model(window, true);
    let joint = rf_tracking::Request::new(&with_aggregate).unwrap();
    if joint.binding == request.binding
        || rf_tracking::Tracking::from_verified(
            &with_aggregate,
            &joint,
            &record,
            Some([3; 32]),
            candidate_cap,
        )
        .is_ok()
    {
        return TestResult::Fail(
            "tracking-only RF envelope silently admitted joint A-MSDU program",
        );
    }
    alloc::sync::Arc::make_mut(base.model_domain.as_mut().unwrap()).rules[0].max_power_dbm = 1;
    if base.with_current(|| Ok(7)).is_ok() {
        return TestResult::Fail("periodic RF ignored tightened actual host power");
    }
    base.model_domain = Some(alloc::sync::Arc::new(domain()));
    tracking_cap.revoke();
    if base.current().is_ok() || base.with_current(|| Ok(7)).is_ok() {
        return TestResult::Fail("actual tracking cap revocation left native RF authority");
    }
    base_cap.revoke();
    if base.rf_tracking_window().is_ok() {
        return TestResult::Fail("old base source revived tracking window");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/tracking",
    smoke_rtw8852b_periodic_dpk_signed_joint_program_window_and_current_caps
);

fn smoke_rtw89_b_each_calibration_packet_and_response_peak_is_independently_required() -> TestResult
{
    let board = board();
    for offset in [62, 64, 66] {
        let mut bytes = image(board);
        bytes[offset..offset + 2].copy_from_slice(&80i16.to_le_bytes());
        let q = Qualification::from_verified(&bytes, Some([3; 32]), board, authority()).unwrap();
        if q.check(&domain()) != Err(Error::Policy) {
            return TestResult::Fail("one emission class escaped measured ceiling");
        }
    }
    let mut old = image(board);
    old[4] = 1;
    if Qualification::from_verified(&old, Some([3; 32]), board, authority()).is_ok() {
        return TestResult::Fail("basic v1 supplied full radio authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_each_calibration_packet_and_response_peak_is_independently_required
);

fn smoke_rtw89_b_full_radio_publication_runs_inside_current_signed_scope() -> TestResult {
    let (mut grant, cap) = revocable_model();
    let mut published = 0;
    if grant.with_current(|| {
        published += 1;
        Ok(())
    }) != Ok(())
        || published != 1
    {
        return TestResult::Fail("current full radio scope did not publish");
    }
    alloc::sync::Arc::make_mut(grant.model_domain.as_mut().unwrap()).rules[0].max_power_dbm = 1;
    if grant
        .with_current(|| {
            published += 1;
            Ok(())
        })
        .is_ok()
        || published != 1
    {
        return TestResult::Fail("full radio scope ignored current host policy");
    }
    grant.model_domain = Some(alloc::sync::Arc::new(domain()));
    cap.revoke();
    if grant
        .with_current(|| {
            published += 1;
            Ok(())
        })
        .is_ok()
        || published != 1
    {
        return TestResult::Fail("revoked full radio scope executed publication");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_full_radio_publication_runs_inside_current_signed_scope
);

fn smoke_rtw8852b_operating_programs_each_require_their_own_signed_identity() -> TestResult {
    let base = board();
    let cap = authority();
    // Unknown bits, missing base bits and QosAll without WMM are rejected.
    for flags in [1u8, 11, 0x13, 0x83] {
        if Program::valid(flags) {
            return TestResult::Fail("invalid program flag combination accepted");
        }
    }
    if !Program::valid(3) || !Program::valid(7) || !Program::valid(15) {
        return TestResult::Fail("valid program flags rejected");
    }
    if Program::QosAll.flags() != 15 || Program::Wmm.flags() != 7 {
        return TestResult::Fail("program flag bytes differ");
    }
    // WMM identity is unchanged by the generalization (frozen chain).
    let mut wmm = narf_crypto::sha256::Sha256::new();
    wmm.update(b"NARF RTL8852B WMM BE/TID0 legacy12 optional operating recipe v2");
    wmm.update(&base.identity());
    wmm.update(&super::super::station_control::wmm_fingerprint());
    if base.wmm().identity() != wmm.finalize() {
        return TestResult::Fail("WMM recipe identity changed");
    }
    let qos = base.with_programs(15);
    if qos.identity() == base.wmm().identity() || qos.identity() == base.identity() {
        return TestResult::Fail("all-AC program shares an existing identity");
    }
    // A flags7 record cannot be promoted to 15, and a 15 record needs the
    // chained identity.
    let mut bytes = image(base.wmm());
    bytes[57] = 15;
    if Qualification::from_verified(&bytes, Some([3; 32]), base, cap).is_ok() {
        return TestResult::Fail("WMM record promoted to all-AC QoS");
    }
    let mut bytes = image(qos);
    bytes[57] = 15;
    let Ok(mut granted) = Qualification::from_verified(&bytes, Some([3; 32]), base, cap) else {
        return TestResult::Fail("genuine all-AC record rejected");
    };
    granted.model_domain = Some(alloc::sync::Arc::new(domain()));
    if granted.allows(Program::QosAll) != Ok(true)
        || granted.wmm_allowed() != Ok(true)
        || !granted.matches(base)
    {
        return TestResult::Fail("all-AC record did not grant its programs");
    }
    let mut bytes = image(base.wmm());
    bytes[57] = 7;
    let Ok(mut wmm_only) = Qualification::from_verified(&bytes, Some([3; 32]), base, cap) else {
        return TestResult::Fail("WMM record rejected");
    };
    wmm_only.model_domain = Some(alloc::sync::Arc::new(domain()));
    if wmm_only.allows(Program::QosAll) != Ok(false) {
        return TestResult::Fail("WMM record granted all-AC QoS");
    }
    cap.revoke();
    if granted.allows(Program::QosAll).is_ok() {
        return TestResult::Fail("revoked record still grants all-AC QoS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_operating_programs_each_require_their_own_signed_identity
);

fn smoke_rtw8852b_he_program_requires_ht_and_its_own_signed_identity() -> TestResult {
    let base = board();
    let cap = authority();
    let he = Program::He.flags();
    let ht = Program::Ht.flags();
    // He requires Ht, which requires WMM and firmware RA.
    if he != 0x77 || ht != 0x37 || !Program::valid(he) {
        return TestResult::Fail("HE program flag byte differs");
    }
    for flags in [0x47u8, 0x57, 0x67, 0x43] {
        if Program::valid(flags) {
            return TestResult::Fail("HE accepted without HT/firmware RA/WMM");
        }
    }
    let chained = base.with_programs(he);
    if chained.identity() == base.with_programs(ht).identity() {
        return TestResult::Fail("HE program shares the HT identity");
    }
    // An HT20 record cannot be promoted to HE.
    let mut bytes = image(base.with_programs(ht));
    bytes[57] = he;
    if Qualification::from_verified(&bytes, Some([3; 32]), base, cap).is_ok() {
        return TestResult::Fail("HT record promoted to HE");
    }
    let mut bytes = image(chained);
    bytes[57] = he;
    let Ok(mut granted) = Qualification::from_verified(&bytes, Some([3; 32]), base, cap) else {
        return TestResult::Fail("genuine HE record rejected");
    };
    granted.model_domain = Some(alloc::sync::Arc::new(domain()));
    if granted.allows(Program::He) != Ok(true) || granted.allows(Program::Ht) != Ok(true) {
        return TestResult::Fail("HE record did not grant HE and HT");
    }
    let mut bytes = image(base.with_programs(ht));
    bytes[57] = ht;
    let Ok(mut ht_only) = Qualification::from_verified(&bytes, Some([3; 32]), base, cap) else {
        return TestResult::Fail("HT record rejected");
    };
    ht_only.model_domain = Some(alloc::sync::Arc::new(domain()));
    if ht_only.allows(Program::He) != Ok(false) {
        return TestResult::Fail("HT record granted HE");
    }
    cap.revoke();
    if granted.allows(Program::He).is_ok() {
        return TestResult::Fail("revoked record still grants HE");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_he_program_requires_ht_and_its_own_signed_identity
);

fn smoke_rtw8852b_repeat_flr_lifecycle_requires_its_own_signed_identity() -> TestResult {
    let base = board();
    let cap = authority();
    let repeat = base.lifecycle(Lifecycle::Repeat);
    let mut chain = narf_crypto::sha256::Sha256::new();
    chain.update(
        b"NARF RTL8852B repeat observed-FLR PCI lifecycle v1;SER-L2 reset or S3 resume;same boot",
    );
    chain.update(&base.identity());
    if base.lifecycle(Lifecycle::Initial) != base
        || repeat.identity() != chain.finalize()
        || repeat.identity() == base.identity()
        || repeat.wmm().identity() == base.wmm().identity()
    {
        return TestResult::Fail("repeat lifecycle identity is not a distinct frozen chain");
    }
    // An initial-lifecycle record never qualifies a reset/resumed generation.
    if Qualification::from_verified(&image(base), Some([3; 32]), repeat, cap).is_ok() {
        return TestResult::Fail("initial-lifecycle record qualified a repeat FLR lifecycle");
    }
    let Ok(granted) = Qualification::from_verified(&image(repeat), Some([3; 32]), repeat, cap)
    else {
        return TestResult::Fail("genuine repeat-lifecycle record rejected");
    };
    if !granted.matches(repeat) || granted.matches(base) {
        return TestResult::Fail("repeat-lifecycle record matched the initial lifecycle");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_repeat_flr_lifecycle_requires_its_own_signed_identity
);

fn smoke_rtw8852b_ampdu_program_requires_ht_and_its_own_signed_identity() -> TestResult {
    let base = board();
    let cap = authority();
    let ampdu = Program::Ampdu.flags();
    let ht = Program::Ht.flags();
    // Ampdu requires HT20, which requires WMM and firmware RA.
    if ampdu != 0xb7 || !Program::valid(ampdu) || !Program::valid(ampdu | Program::He.bit()) {
        return TestResult::Fail("A-MPDU program flag byte differs");
    }
    for flags in [0x87u8, 0x97, 0xa7, 0x83] {
        if Program::valid(flags) {
            return TestResult::Fail("A-MPDU accepted without HT/firmware RA/WMM");
        }
    }
    let chained = base.with_programs(ampdu);
    if chained.identity() == base.with_programs(ht).identity() {
        return TestResult::Fail("A-MPDU program shares the HT identity");
    }
    // An HT20 record cannot be promoted to A-MPDU.
    let mut bytes = image(base.with_programs(ht));
    bytes[57] = ampdu;
    if Qualification::from_verified(&bytes, Some([3; 32]), base, cap).is_ok() {
        return TestResult::Fail("HT record promoted to A-MPDU");
    }
    let mut bytes = image(chained);
    bytes[57] = ampdu;
    let Ok(mut granted) = Qualification::from_verified(&bytes, Some([3; 32]), base, cap) else {
        return TestResult::Fail("genuine A-MPDU record rejected");
    };
    granted.model_domain = Some(alloc::sync::Arc::new(domain()));
    if granted.allows(Program::Ampdu) != Ok(true) || granted.allows(Program::He) != Ok(false) {
        return TestResult::Fail("A-MPDU record grants differ");
    }
    cap.revoke();
    if granted.allows(Program::Ampdu).is_ok() {
        return TestResult::Fail("revoked record still grants A-MPDU");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_ampdu_program_requires_ht_and_its_own_signed_identity
);

fn smoke_rtw8852b_amsdu_companion_binds_exact_base_program_signer_and_current_power() -> TestResult
{
    let base = board();
    let flags = Program::Ampdu.flags();
    let mut bytes = image(base.with_programs(flags));
    bytes[57] = flags;
    let base_cap = authority();
    let mut qualified =
        Qualification::from_verified(&bytes, Some([3; 32]), base, base_cap).unwrap();
    qualified.model_domain = Some(alloc::sync::Arc::new(domain()));
    if qualified.amsdu_allowed() != Ok(false) || qualified.allows(Program::Ampdu) != Ok(true) {
        return TestResult::Fail("old A-MPDU record silently authorizes expanded A-MSDU");
    }
    let request = amsdu::AmsduRequest::new(&qualified).unwrap();
    if request.name != "rtw89/rtw8852b-tx-amsdu-v1-020406080a0c.bin" {
        return TestResult::Fail("actual companion provisioning name");
    }
    let mut expanded = [0; 128];
    expanded[..4].copy_from_slice(b"N52A");
    expanded[4..8].copy_from_slice(&[1, 0, 128, 0]);
    expanded[8..12].copy_from_slice(&128u32.to_le_bytes());
    expanded[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    expanded[14..16].copy_from_slice(&base.device.to_le_bytes());
    expanded[16..48].copy_from_slice(&request.binding);
    expanded[48..54].copy_from_slice(&base.mac);
    expanded[54..58].copy_from_slice(&[1, 20, 1, 3]);
    expanded[58..60].copy_from_slice(&5000u16.to_le_bytes());
    expanded[60] = 8;
    let cap = authority();
    for signer in [None, Some([4; 32])] {
        if amsdu::Amsdu::from_verified(&qualified, &request, &expanded, signer, cap).is_ok() {
            return TestResult::Fail("unsigned/different signer expanded RF program");
        }
    }
    for length in 0..128 {
        if amsdu::Amsdu::from_verified(
            &qualified,
            &request,
            &expanded[..length],
            Some([3; 32]),
            cap,
        )
        .is_ok()
        {
            return TestResult::Fail("truncated expanded RF program");
        }
    }
    for at in [0, 4, 8, 12, 14, 16, 48, 54, 55, 56, 57, 58, 60, 61, 127] {
        let mut bad = expanded;
        bad[at] ^= 1;
        if amsdu::Amsdu::from_verified(&qualified, &request, &bad, Some([3; 32]), cap).is_ok() {
            return TestResult::Fail("different identity/shape/reserved expanded RF program");
        }
    }
    // Same board/program but a different actual measured power record must
    // earn its own binding, even when both records remain individually valid.
    let mut different = bytes;
    different[62..64].copy_from_slice(&39i16.to_le_bytes());
    let other = Qualification::from_verified(&different, Some([3; 32]), base, authority()).unwrap();
    if amsdu::AmsduRequest::new(&other).unwrap().binding == request.binding {
        return TestResult::Fail("companion identity omitted actual installed record digest");
    }
    let other_request = amsdu::AmsduRequest::new(&other).unwrap();
    if amsdu::Amsdu::from_verified(&other, &other_request, &expanded, Some([3; 32]), cap).is_ok()
        || amsdu::Amsdu::from_verified(&other, &request, &expanded, Some([3; 32]), cap).is_ok()
    {
        return TestResult::Fail("actual companion transplanted to another measured base record");
    }
    qualified.amsdu = Some(
        amsdu::Amsdu::from_verified(&qualified, &request, &expanded, Some([3; 32]), cap).unwrap(),
    );
    if qualified.amsdu_allowed() != Ok(true) || qualified.with_current(|| Ok(7)) != Ok(7) {
        return TestResult::Fail("genuine expanded program current base/power admission");
    }
    alloc::sync::Arc::make_mut(qualified.model_domain.as_mut().unwrap()).rules[0].max_power_dbm = 1;
    if qualified.with_current(|| Ok(7)).is_ok() {
        return TestResult::Fail("expanded program bypassed tightened actual host power");
    }
    qualified.model_domain = Some(alloc::sync::Arc::new(domain()));
    cap.revoke();
    if qualified.amsdu_allowed().is_ok() || qualified.with_current(|| Ok(7)).is_ok() {
        return TestResult::Fail("revoked actual companion remained ordinary emission authority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/aggregation",
    smoke_rtw8852b_amsdu_companion_binds_exact_base_program_signer_and_current_power
);

fn smoke_rtw8852b_lps_joint_artifact_binds_all_current_optional_programs() -> TestResult {
    let profile = super::super::lps_wire::Profile::for_version([0, 29, 29, 15]).unwrap();
    for version in [
        [0, 27, 32, 1],
        [0, 29, 28, 255],
        [0, 29, 122, 0],
        [0, 29, 127, 0],
        [0, 29, 128, 0],
    ] {
        if super::super::lps_wire::Profile::for_version(version).is_some() {
            return TestResult::Fail("unadmitted B full-radio firmware gained LPS producer");
        }
    }
    let window = super::super::rf_tracking::Window {
        low: 0x30,
        high: 0xc0,
    };
    let (mut base, _, tracking_cap) = rf_tracking_model(window, true);
    if base.sleep_profile() != Ok(None) {
        return TestResult::Fail("old expanded radio silently entered LPS");
    }
    let request = lps::Request::new(&base, profile).unwrap();
    let mut record = expanded_record(&base, b"N52P", request.binding);
    record[58..62].copy_from_slice(&profile.version);
    let cap = authority();
    for signer in [None, Some([4; 32])] {
        if lps::Sleep::from_verified(&base, &request, profile, &record, signer, cap).is_ok() {
            return TestResult::Fail("unsigned/wrong signer joint LPS accepted");
        }
    }
    for at in [0, 4, 8, 12, 14, 16, 48, 54, 58, 61, 62, 127] {
        let mut bad = record;
        bad[at] ^= 1;
        if lps::Sleep::from_verified(&base, &request, profile, &bad, Some([3; 32]), cap).is_ok() {
            return TestResult::Fail("malformed/source-mismatched LPS joint record accepted");
        }
    }
    let (other, _, _) = rf_tracking_model(window, false);
    if lps::Request::new(&other, profile).unwrap().binding == request.binding {
        return TestResult::Fail("LPS erased actual installed A-MSDU companion binding");
    }
    let old_digest = base.rf_tracking.as_ref().unwrap().digest();
    let (narrow, _, _) = rf_tracking_model(
        super::super::rf_tracking::Window {
            low: 0x40,
            high: 0x80,
        },
        true,
    );
    if narrow.rf_tracking.as_ref().unwrap().digest() == old_digest
        || lps::Request::new(&narrow, profile).unwrap().binding == request.binding
    {
        return TestResult::Fail("LPS erased actual tracking window/raw-record binding");
    }
    base.lps = Some(
        lps::Sleep::from_verified(&base, &request, profile, &record, Some([3; 32]), cap).unwrap(),
    );
    if base.sleep_profile() != Ok(Some(profile)) || base.with_current(|| Ok(9)) != Ok(9) {
        return TestResult::Fail("exact joint LPS current scopes rejected");
    }
    cap.revoke();
    if base.sleep_profile().is_ok() || base.with_current(|| Ok(9)).is_ok() {
        return TestResult::Fail("revoked LPS companion retained native permission");
    }
    tracking_cap.revoke();
    if base.current().is_ok() {
        return TestResult::Fail("joint LPS bypassed revoked original tracking source");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/runtime_sleep",
    smoke_rtw8852b_lps_joint_artifact_binds_all_current_optional_programs
);

/// Explicit authenticated-record boundary for actual inert Native/NativeIo
/// tests, like rf_tracking_model; no real attach/RFK or measurement is minted.
pub(in crate::rtw89) fn lps_model(
    effect: Option<alloc::sync::Arc<dyn Fn() + Send + Sync>>,
) -> (
    Qualification,
    Cap<FirmwareBlob, Read>,
    Cap<FirmwareBlob, Read>,
) {
    let (mut base, base_cap, _) = rf_tracking_model(
        super::super::rf_tracking::Window {
            low: 100,
            high: 140,
        },
        false,
    );
    let profile = super::super::lps_wire::Profile::for_version([0, 29, 29, 15]).unwrap();
    let request = lps::Request::new(&base, profile).unwrap();
    let mut record = expanded_record(&base, b"N52P", request.binding);
    record[58..62].copy_from_slice(&profile.version);
    let cap = authority();
    base.lps = Some(
        lps::Sleep::from_verified(&base, &request, profile, &record, Some([3; 32]), cap).unwrap(),
    );
    base.model_native_before_publication = effect;
    (base, base_cap, cap)
}

/// Authenticated-record/RFK fixture boundary only, shared by actual Native and
/// public worker fixtures. Production only loads an actually signed N52F file.
pub(in crate::rtw89) fn fragment_model(
    effect: Option<alloc::sync::Arc<dyn Fn() + Send + Sync>>,
) -> (
    Qualification,
    Cap<FirmwareBlob, Read>,
    Cap<FirmwareBlob, Read>,
) {
    let (mut base, original, _) = rf_tracking_model(
        super::super::rf_tracking::Window {
            low: 100,
            high: 140,
        },
        true,
    );
    let profile = super::super::lps_wire::Profile::for_version([0, 29, 29, 15]).unwrap();
    let ps = lps::Request::new(&base, profile).unwrap();
    let mut record = expanded_record(&base, b"N52P", ps.binding);
    record[58..62].copy_from_slice(&profile.version);
    base.lps = Some(
        lps::Sleep::from_verified(&base, &ps, profile, &record, Some([3; 32]), authority())
            .unwrap(),
    );
    base.model_native_before_publication = effect;
    let request = fragment::Request::new(&base).unwrap();
    let record = fragment_record(&base, &request);
    let companion = authority();
    base.fragments = Some(
        fragment::Fragments::from_verified(&base, &request, &record, Some([3; 32]), companion)
            .unwrap(),
    );
    (base, original, companion)
}
fn fragment_record(base: &Qualification, request: &fragment::Request) -> [u8; 128] {
    let mut bytes = expanded_record(base, b"N52F", request.binding);
    bytes[58..60].copy_from_slice(&2346u16.to_le_bytes());
    bytes[60..64].copy_from_slice(&[16, 0, 3, 1]);
    bytes
}
fn smoke_rtw8852b_fragment_full_joint_companion_preserves_prior_records_and_current_grants(
) -> TestResult {
    let (mut base, original, _) = fragment_model(None);
    base.fragments = None;
    let old = fragment::Request::new(&base).unwrap();
    if base.fragments_allowed() != Ok(false) || base.current().is_err() {
        return TestResult::Fail("absent fragment record changed prior native program");
    }
    let bytes = fragment_record(&base, &old);
    for offset in [
        0, 4, 8, 12, 14, 16, 47, 48, 54, 57, 58, 60, 61, 62, 63, 64, 127,
    ] {
        let mut bad = bytes;
        bad[offset] ^= 1;
        if fragment::Fragments::from_verified(&base, &old, &bad, Some([3; 32]), authority()).is_ok()
        {
            return TestResult::Fail("N52F accepted malformed/source/digest/size/sequence program");
        }
    }
    if fragment::Fragments::from_verified(&base, &old, &bytes, None, authority()).is_ok()
        || fragment::Fragments::from_verified(&base, &old, &bytes, Some([4; 32]), authority())
            .is_ok()
    {
        return TestResult::Fail("N52F bypassed original signer/source");
    }
    for kind in 0..3 {
        let (mut changed, _, _) = fragment_model(None);
        changed.fragments = None;
        match kind {
            0 => changed.lps = None,
            1 => changed.rf_tracking = None,
            _ => changed.amsdu = None,
        }
        if fragment::Request::new(&changed).unwrap().binding == old.binding {
            return TestResult::Fail("N52F joint binding lost actual A/T/P optional program");
        }
    }
    original.revoke();
    if fragment::Fragments::from_verified(&base, &old, &bytes, Some([3; 32]), authority()).is_ok() {
        return TestResult::Fail("N52F recaptured revoked installed original base");
    }
    let (base, original, companion) = fragment_model(None);
    if base.fragments_allowed() != Ok(true) || base.with_current(|| Ok(3)) != Ok(3) {
        return TestResult::Fail("N52F actual finite joint current/invoke chain");
    }
    companion.revoke();
    if base.fragments_allowed().is_ok() || base.with_current(|| Ok(3)).is_ok() {
        return TestResult::Fail("revoked N52F retained fragment emission");
    }
    original.revoke();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/fragmentation",
    smoke_rtw8852b_fragment_full_joint_companion_preserves_prior_records_and_current_grants
);

/// Explicit inert N52C boundary: authenticated test records only; no
/// production attach, measured envelope or physical receipt is minted.
pub(in crate::rtw89) fn channel_model(
    primary: u8,
    peak_qdbm: i16,
) -> (
    Qualification,
    Cap<FirmwareBlob, Read>,
    Cap<FirmwareBlob, Read>,
    Board,
) {
    let (mut base, base_cap) = revocable_model();
    let profile = super::super::operating_channel::Profile::from_primary(primary).unwrap();
    let mut board = board();
    board.identity = [primary; 32];
    let request = channel::Request::new(&base, profile, board.with_programs(base.flags)).unwrap();
    let record = channel_record(&base, &request, primary, peak_qdbm);
    let cap = authority();
    let channel = channel::Channel::from_verified(
        &base,
        &request,
        profile,
        board.with_programs(base.flags),
        &record,
        Some([3; 32]),
        cap,
    )
    .unwrap();
    base.channels.push(channel);
    (base, base_cap, cap, board)
}
fn channel_record(
    base: &Qualification,
    request: &channel::Request,
    primary: u8,
    peak_qdbm: i16,
) -> [u8; 128] {
    let mut record = expanded_record(base, b"N52C", request.binding);
    record[54..58].copy_from_slice(&[1, 20, primary, base.flags]);
    record[58..60].copy_from_slice(&4i16.to_le_bytes());
    record[60..62].copy_from_slice(&76i16.to_le_bytes());
    for at in [62, 64, 66] {
        record[at..at + 2].copy_from_slice(&peak_qdbm.to_le_bytes());
    }
    record
}
pub(in crate::rtw89) fn band_domain() -> narf_wireless::reg::RegulatoryDomain {
    let mut domain = domain();
    domain.rules[0].freq_end_mhz = 2472;
    domain
}
fn smoke_rtw89_b_channel_record_binds_noninitial_identity_signer_and_occupied_span() -> TestResult {
    use super::super::operating_channel::Profile;
    use narf_wireless::association::channel::Band;
    let six = Profile::new(Band::Ghz2, 6).unwrap();
    let (mut base, base_cap, record_cap, board) = channel_model(6, 40);
    // Channel1/14 never get a noninitial record; v2 is not reinterpreted.
    for primary in [1, 14] {
        let profile = Profile::new(Band::Ghz2, primary).unwrap();
        if channel::Request::new(&base, profile, board.with_programs(base.flags)).is_ok() {
            return TestResult::Fail("N52C admitted the initial or CCK-only primary");
        }
    }
    let request = channel::Request::new(&base, six, board.with_programs(base.flags)).unwrap();
    let good = channel_record(&base, &request, 6, 40);
    for (signer, bytes, profile, label) in [
        (Some([4; 32]), good, six, "foreign signer"),
        (None, good, six, "unsigned record"),
        (
            Some([3; 32]),
            channel_record(&base, &request, 7, 40),
            six,
            "wrong primary byte",
        ),
        (
            Some([3; 32]),
            good,
            Profile::new(Band::Ghz2, 7).unwrap(),
            "record reused for another primary",
        ),
    ] {
        let rebuilt = channel::Request::new(&base, profile, board.with_programs(base.flags));
        if rebuilt.is_ok_and(|request| {
            channel::Channel::from_verified(
                &base,
                &request,
                profile,
                board.with_programs(base.flags),
                &bytes,
                signer,
                authority(),
            )
            .is_ok()
        }) {
            return TestResult::Fail(label);
        }
    }
    let mut other = board;
    other.identity = [0x55; 32];
    if channel::Channel::from_verified(
        &base,
        &request,
        six,
        other.with_programs(base.flags),
        &good,
        Some([3; 32]),
        authority(),
    )
    .is_ok()
    {
        return TestResult::Fail("N52C accepted another per-channel identity");
    }
    if !base.channel_matches(six, board)
        || base.channel_matches(six, other)
        || base.channel_allowed(six) != Ok(true)
        || base.channel_allowed(Profile::new(Band::Ghz2, 7).unwrap()) != Ok(false)
        || base.channel_allowed(Profile::INITIAL) != Ok(true)
    {
        return TestResult::Fail("N52C admission did not follow the signed record");
    }
    // Host rule covers only channel1: selecting 6 fails and leaves 1 active.
    if base.select(six).is_ok() || base.active() != 1 || base.with_current(|| Ok(1)) != Ok(1) {
        return TestResult::Fail("channel6 selected outside its occupied span");
    }
    base.model_domain = Some(alloc::sync::Arc::new(band_domain()));
    if base.select(six).is_err() || base.active() != 6 || base.with_current(|| Ok(6)) != Ok(6) {
        return TestResult::Fail("current channel6 record did not gate publication");
    }
    // A record whose peaks exceed the current ceiling is refused at select.
    let (mut hot, _, _, _) = channel_model(9, 80);
    hot.model_domain = Some(alloc::sync::Arc::new(band_domain()));
    if hot.select(Profile::new(Band::Ghz2, 9).unwrap()).is_ok() || hot.active() != 1 {
        return TestResult::Fail("channel9 peaks exceeded the host ceiling");
    }
    // A later companion change retires the old joint binding.
    let (mut joint, _, _) = fragment_model(None);
    let flags = joint.flags;
    let request = channel::Request::new(&joint, six, board.with_programs(flags)).unwrap();
    let record = channel_record(&joint, &request, 6, 40);
    let channel = channel::Channel::from_verified(
        &joint,
        &request,
        six,
        board.with_programs(flags),
        &record,
        Some([3; 32]),
        authority(),
    )
    .unwrap();
    joint.channels.push(channel);
    joint.model_domain = Some(alloc::sync::Arc::new(band_domain()));
    if joint.channel_allowed(six) != Ok(true)
        || request.binding
            == channel::Request::new(&base, six, board.with_programs(base.flags))
                .unwrap()
                .binding
    {
        return TestResult::Fail("N52C joint binding ignored installed companions");
    }
    joint.fragments = None;
    if joint.channel_allowed(six).is_ok() || joint.select(six).is_ok() {
        return TestResult::Fail("N52C survived a changed companion set");
    }
    record_cap.revoke();
    if base.with_current(|| Ok(6)).is_ok() || base.select(Profile::INITIAL).is_err() {
        return TestResult::Fail("revoked N52C kept emitting or blocked channel1 return");
    }
    if base.select(six).is_ok() {
        return TestResult::Fail("revoked N52C reselected");
    }
    base_cap.revoke();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_channel_record_binds_noninitial_identity_signer_and_occupied_span
);

/// 5GHz N52C: a typed 5GHz primary binds its own record (distinct recipe and
/// name), is admitted and selectable under a plain, AUTO_BW/NO_160MHZ, DFS or
/// NO_IR host span; an unknown flag refuses and keeps channel1 active. A
/// DFS / NO_IR span is passive-only: frame TX (`tx_current`) needs a witness
/// grant for that primary under the current policy snapshot, which `select`
/// of another primary and a policy replacement both end.
fn smoke_rtw89_b_5ghz_channel_record_admits_passive_dfs_host_span() -> TestResult {
    use super::super::operating_channel::Profile;
    use narf_wireless::association::channel::Band;
    use narf_wireless::reg::{RegFlags, RegRule};
    let a36 = Profile::new(Band::Ghz5, 36).unwrap();
    let (mut base, _base_cap, _record_cap, board) = channel_model(36, 40);
    let Ok(request) = channel::Request::new(&base, a36, board.with_programs(base.flags)) else {
        return TestResult::Fail("N52C refused a typed 5GHz primary");
    };
    if !request.name.contains("-ch36-")
        || channel::Request::new(
            &base,
            Profile::new(Band::Ghz5, 40).unwrap(),
            board.with_programs(base.flags),
        )
        .is_ok_and(|other| other.binding == request.binding)
    {
        return TestResult::Fail("5GHz N52C name/binding not per primary");
    }
    let rule = |start, end, flags| RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz: 80,
        max_power_dbm: 20,
        flags,
    };
    let mut open = domain();
    open.rules.push(rule(5170, 5250, RegFlags::empty()));
    let mut radar = domain();
    radar.rules.push(rule(5170, 5250, RegFlags::DFS));
    let mut passive = domain();
    passive.rules.push(rule(5170, 5250, RegFlags::NO_IR));
    // wireless-regdb AUTO-BW / NO_160MHZ restrict nothing at 20MHz.
    let mut auto = domain();
    auto.rules
        .push(rule(5170, 5250, RegFlags::AUTO_BW | RegFlags::NO_160MHZ));
    let mut unknown = domain();
    unknown
        .rules
        .push(rule(5170, 5250, RegFlags::from_bits_retain(1 << 12)));
    for (domain, admitted, passive_only, label) in [
        (radar, true, true, "DFS 5GHz span not admitted passively"),
        (
            passive,
            true,
            true,
            "NO_IR 5GHz span not admitted passively",
        ),
        (unknown, false, false, "unknown rule flag admitted"),
        (auto, true, false, "AUTO_BW/NO_160MHZ 5GHz span refused"),
        (open, true, false, "non-DFS 5GHz span refused"),
    ] {
        let policy = alloc::sync::Arc::new(domain);
        base.model_domain = Some(policy.clone());
        if base.select(Profile::INITIAL).is_err()
            || base.channel_allowed(a36) != Ok(admitted)
            || base.select(a36).is_ok() != admitted
            || base.active() != if admitted { 36 } else { 1 }
        {
            return TestResult::Fail(label);
        }
        if !admitted {
            continue;
        }
        // RX/RF publication stays open; frame TX needs the witness grant.
        if base.current().is_err() || base.tx_current().is_ok() == passive_only {
            return TestResult::Fail("passive-only span changed TX admission");
        }
        base.grant_passive_tx(Some((36, policy.clone())));
        if base.tx_current().is_err() {
            return TestResult::Fail("witness grant did not admit TX");
        }
        // Same rules, new snapshot: the grant is bound to its policy.
        base.model_domain = Some(alloc::sync::Arc::new(policy.as_ref().clone()));
        if base.tx_current().is_ok() == passive_only {
            return TestResult::Fail("passive TX grant outlived its policy snapshot");
        }
        base.model_domain = Some(policy.clone());
        // Retuning elsewhere drops it; returning does not revive it.
        if base.select(Profile::INITIAL).is_err()
            || base.select(a36).is_err()
            || base.tx_current().is_ok() == passive_only
        {
            return TestResult::Fail("passive TX grant survived a retune");
        }
        base.grant_passive_tx(None);
    }
    // A 2.4GHz span is never passive-admitted: NO_IR still refuses there.
    let mut low = domain();
    for r in low.rules.iter_mut() {
        r.flags |= RegFlags::NO_IR;
    }
    base.model_domain = Some(alloc::sync::Arc::new(low));
    if base.select(Profile::INITIAL).is_ok() {
        return TestResult::Fail("2.4GHz NO_IR span admitted");
    }
    base.model_domain = Some(alloc::sync::Arc::new(domain()));
    if base.select(Profile::INITIAL).is_err() || base.active() != 1 {
        return TestResult::Fail("cross-band return to channel1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_5ghz_channel_record_admits_passive_dfs_host_span
);
