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
    for variant in 0..7 {
        let mut d = domain();
        match variant {
            0 => d.rules[0].max_power_dbm = 10,
            1 => d.rules[0].max_bandwidth_mhz = 10,
            2 => d.rules[0].flags = narf_wireless::reg::RegFlags::INDOOR_ONLY,
            3 => d.rules[0].freq_start_mhz = 2403,
            4 => d.rules[0].freq_end_mhz = 2421,
            5 => d.rules.clear(),
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
    calibration.model_domain = Some(domain());
    (calibration, cap)
}
pub(in crate::rtw89) fn revoke_on_publication_model() -> (Qualification, Cap<FirmwareBlob, Read>) {
    let (mut qualification, cap) = revocable_model();
    qualification.model_revoke_before_publication = true;
    (qualification, cap)
}

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
    grant.model_domain.as_mut().unwrap().rules[0].max_power_dbm = 1;
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
    grant.model_domain = Some(domain());
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
