use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
fn authority() -> Cap<FirmwareBlob, Read> {
    // Fresh live FirmwareBlob/Read fixture authority, minted via the
    // safe `Cap::bootstrap` path (SEC-B5, #1293: `Cap::mint` is
    // crate-private to `capabilities/`).
    Cap::bootstrap()
}
fn board() -> Board {
    Board {
        identity: [7; 32],
        mac: [2, 4, 6, 8, 10, 12],
        device: 0xb852,
        chip: ChipId::Rtl8852B,
    }
}
fn image(board: Board) -> [u8; LENGTH] {
    let mut b = [0; LENGTH];
    b[..4].copy_from_slice(b"N52B");
    b[4..8].copy_from_slice(&[1, 0, 96, 0]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    b[14..16].copy_from_slice(&board.device.to_le_bytes());
    b[16..48].copy_from_slice(&board.identity);
    b[48..54].copy_from_slice(&board.mac);
    b[54..58].copy_from_slice(&[1, 20, 1, 0]);
    b[58..60].copy_from_slice(&4i16.to_le_bytes());
    b[60..62].copy_from_slice(&76i16.to_le_bytes());
    b[62..64].copy_from_slice(&40i16.to_le_bytes());
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
fn smoke_rtw89_b_calibration_artifact_is_signed_exact_and_revocable() -> TestResult {
    let board = board();
    let bytes = image(board);
    let cap = authority();
    if !matches!(
        Calibration::from_verified(&bytes, None, board, cap),
        Err(Error::Unsigned)
    ) {
        return TestResult::Fail("unsigned B calibration accepted");
    }
    let calibration = Calibration::from_verified(&bytes, Some([3; 32]), board, cap).unwrap();
    if !calibration.matches(board) || calibration.check(&domain()).is_err() {
        return TestResult::Fail("exact measured calibration bound rejected");
    }
    for end in 0..bytes.len() {
        if Calibration::from_verified(&bytes[..end], Some([3; 32]), board, cap).is_ok() {
            return TestResult::Fail("truncated calibration accepted");
        }
    }
    for at in [0, 4, 6, 8, 12, 14, 16, 48, 54, 55, 56, 57, 64, 95] {
        let mut bad = bytes;
        bad[at] ^= 1;
        if Calibration::from_verified(&bad, Some([3; 32]), board, cap).is_ok() {
            return TestResult::Fail("different board/recipe/profile calibration accepted");
        }
    }
    cap.revoke();
    if !matches!(calibration.current(), Err(Error::Authority))
        || !matches!(
            Calibration::from_verified(&bytes, Some([3; 32]), board, cap),
            Err(Error::Authority)
        )
    {
        return TestResult::Fail("revoked B qualification remained usable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_calibration_artifact_is_signed_exact_and_revocable
);
fn smoke_rtw89_b_calibration_peak_obeys_every_current_channel_rule() -> TestResult {
    let board = board();
    let bytes = image(board);
    let cal = Calibration::from_verified(&bytes, Some([3; 32]), board, authority()).unwrap();
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
    let cal = Calibration::from_verified(&bytes, Some([3; 32]), board, authority()).unwrap();
    if cal.check(&domain()) != Err(Error::Policy) {
        return TestResult::Fail("signed conducted peak plus antenna exceeded board ceiling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_calibration_peak_obeys_every_current_channel_rule
);

struct FactoryModel {
    chip: ChipId,
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
        (self.chip, self.cut)
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
fn smoke_rtw89_b_calibration_identity_binds_actual_factory_and_verified_assets() -> TestResult {
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
            chip: ChipId::Rtl8852B,
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
        let identity = Board::new(&factory, device, &assets).unwrap().identity();
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
        if Board::new(&factory, device, &newer) != Err(Error::Identity) {
            return TestResult::Fail("unsupported coex ABI acquired measured board identity");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_calibration_identity_binds_actual_factory_and_verified_assets
);
fn smoke_rtw89_a_calibration_is_n5ab_and_new_a_binds_factory_and_assets() -> TestResult {
    // The N5AB artifact: signed, exact and revocable, mirroring B.
    let board = Board {
        identity: [7; 32],
        mac: [2, 4, 6, 8, 10, 12],
        device: 0x8852,
        chip: ChipId::Rtl8852A,
    };
    let mut bytes = image(board);
    bytes[..4].copy_from_slice(b"N5AB");
    let cap = authority();
    if !matches!(
        Calibration::from_verified(&bytes, None, board, cap),
        Err(Error::Unsigned)
    ) {
        return TestResult::Fail("unsigned A calibration accepted");
    }
    let calibration = Calibration::from_verified(&bytes, Some([3; 32]), board, cap).unwrap();
    if !calibration.matches(board) || calibration.check(&domain()).is_err() {
        return TestResult::Fail("exact measured A calibration bound rejected");
    }
    cap.revoke();
    if !matches!(calibration.current(), Err(Error::Authority)) {
        return TestResult::Fail("revoked A qualification remained usable");
    }
    // The A board identity: real A factory + verified A assets, both
    // BTC ABI rows admitted, newer ABI refused.
    let device = narf_bus::DeviceId {
        vendor: 0x10ec,
        device: 0x8852,
        class: 0x028000,
        subsystem_vendor: 1,
        subsystem_id: 2,
    };
    let mut model = FactoryModel {
        chip: ChipId::Rtl8852A,
        rfe: 5,
        cut: 1,
        trim: 255,
    };
    let mut factory = Factory::default();
    if ready(factory.read(&mut model)) != Some(Ok(())) {
        return TestResult::Fail("real A factory parser fixture");
    }
    let mut identity = None;
    for version in [[0, 13, 37, 0], [0, 13, 0, 0]] {
        let image = super::super::prepared::load(
            &mut Files { version, body: 0 },
            ChipId::Rtl8852A,
            model.cut,
        )
        .unwrap();
        let assets = Assets::from_prepared(&image).unwrap();
        let next = Board::new_a(&factory, device, &assets).unwrap().identity();
        if identity == Some(next) {
            return TestResult::Fail("both A BTC ABI rows reused one calibration identity");
        }
        identity = Some(next);
    }
    let image = super::super::prepared::load(
        &mut Files {
            version: [0, 14, 0, 0],
            body: 0,
        },
        ChipId::Rtl8852A,
        model.cut,
    )
    .unwrap();
    let newer = Assets::from_prepared(&image).unwrap();
    if Board::new_a(&factory, device, &newer).is_ok() {
        return TestResult::Fail("unsupported A coex ABI acquired measured board identity");
    }
    let mut bad_device = device;
    bad_device.device = 0xb852;
    let image = super::super::prepared::load(
        &mut Files {
            version: [0, 13, 37, 0],
            body: 0,
        },
        ChipId::Rtl8852A,
        model.cut,
    )
    .unwrap();
    let assets = Assets::from_prepared(&image).unwrap();
    if Board::new_a(&factory, bad_device, &assets).is_ok() {
        return TestResult::Fail("B device acquired an A board identity");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_calibration_is_n5ab_and_new_a_binds_factory_and_assets
);

/// Explicit inert artifact/policy boundary for native revocation regressions.
/// This never installs a global policy or grants a real attach/calibration.
pub(in crate::rtw89) fn revocable_model() -> (Calibration, Cap<FirmwareBlob, Read>) {
    let board = board();
    let cap = authority();
    let mut calibration =
        Calibration::from_verified(&image(board), Some([3; 32]), board, cap).unwrap();
    calibration.model_domain = Some(domain());
    (calibration, cap)
}
fn smoke_rtw8852c_calibration_record_is_n5cb_and_never_a_b_record() -> TestResult {
    let b = board();
    let c = Board {
        device: 0xc852,
        chip: ChipId::Rtl8852C,
        ..b
    };
    let mut bytes = image(c);
    let cap = authority();
    // A B-magic record never admits the C board.
    if Calibration::from_verified(&bytes, Some([3; 32]), c, cap).is_ok() {
        return TestResult::Fail("N52B record admitted an RTL8852C board");
    }
    bytes[..4].copy_from_slice(b"N5CB");
    let calibration = match Calibration::from_verified(&bytes, Some([3; 32]), c, cap) {
        Ok(calibration) => calibration,
        Err(_) => return TestResult::Fail("exact N5CB calibration refused"),
    };
    if !calibration.matches(c) || calibration.matches(b) || calibration.check(&domain()).is_err() {
        return TestResult::Fail("C calibration bound to the wrong board or span");
    }
    // ... and an N5CB record never admits the B board.
    let mut b_bytes = image(b);
    b_bytes[..4].copy_from_slice(b"N5CB");
    if Calibration::from_verified(&b_bytes, Some([3; 32]), b, cap).is_ok() {
        return TestResult::Fail("N5CB record admitted an RTL8852B board");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_calibration_record_is_n5cb_and_never_a_b_record
);
fn smoke_rtw8851b_calibration_record_is_n51b_and_never_a_b_or_c_record() -> TestResult {
    let b = board();
    let n51 = Board {
        device: 0xb851,
        chip: ChipId::Rtl8851B,
        ..b
    };
    let c = Board {
        device: 0xc852,
        chip: ChipId::Rtl8852C,
        ..b
    };
    let cap = authority();
    let mut bytes = image(n51);
    // Neither a B nor a C magic admits the RTL8851B board.
    for magic in [b"N52B", b"N5CB"] {
        bytes[..4].copy_from_slice(magic);
        if Calibration::from_verified(&bytes, Some([3; 32]), n51, cap).is_ok() {
            return TestResult::Fail("B/C calibration magic admitted an RTL8851B board");
        }
    }
    bytes[..4].copy_from_slice(b"N51B");
    if Calibration::from_verified(&bytes, None, n51, cap).is_ok() {
        return TestResult::Fail("unsigned N51B calibration accepted");
    }
    let calibration = match Calibration::from_verified(&bytes, Some([3; 32]), n51, cap) {
        Ok(calibration) => calibration,
        Err(_) => return TestResult::Fail("exact N51B calibration refused"),
    };
    if !calibration.matches(n51)
        || calibration.matches(b)
        || calibration.matches(c)
        || calibration.check(&domain()).is_err()
    {
        return TestResult::Fail("RTL8851B calibration bound to the wrong board or span");
    }
    // An N51B record never admits a B or C board.
    for other in [b, c] {
        let mut o = image(other);
        o[..4].copy_from_slice(b"N51B");
        if Calibration::from_verified(&o, Some([3; 32]), other, cap).is_ok() {
            return TestResult::Fail("N51B record admitted an RTL8852B/C board");
        }
    }
    // Only the shipped-firmware BTC ABI row has an RTL8851B identity.
    if super::super::coex_native::Protocol51::for_version([0, 29, 41, 5]).is_none()
        || super::super::coex_native::Protocol51::for_version([0, 29, 28, 0]).is_some()
        || super::super::coex_native::Protocol51::for_version([0, 29, 133, 0]).is_some()
    {
        return TestResult::Fail("RTL8851B BTC ABI rows wrong");
    }
    cap.revoke();
    if calibration.current().is_ok() {
        return TestResult::Fail("revoked N51B calibration still current");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8851b_calibration_record_is_n51b_and_never_a_b_or_c_record
);

fn be_factory() -> super::super::efuse_be::BeFactory {
    super::super::efuse_be::BeFactory {
        mac: [2, 4, 6, 8, 10, 12],
        rfe_type: 1,
        xtal_cap: 0x20,
        country: [b'U', b'S'],
        phycap: [0u8; 0x38],
        cv: Some(1),
        thermal_k: None,
        secure: super::super::efuse_be::SecureInfo::disabled(),
    }
}
fn be_container(a_idx: u8, b_idx: u8) -> alloc::vec::Vec<u8> {
    // Same synthetic element container as the `radio_assets` BE
    // fixture: MFW header + five aid-0 PHY elements (BB id 2, GAIN
    // id 3, RADIO_A id 4, RADIO_B id 5, NCTL id 8). One (addr, value)
    // pair per table; the gain pair decodes as LNA band 0 path 0.
    const MFW: usize = 16;
    const INFO: usize = 16;
    const HEADER: usize = 32;
    const SIZE: usize = 4;
    const AID: usize = 12;
    const INDEX: usize = 24;
    fn pair(a: u32, v: u32) -> alloc::vec::Vec<u8> {
        [a.to_le_bytes(), v.to_le_bytes()].concat()
    }
    let mut bytes = vec![0; MFW + INFO + 16];
    bytes[0] = 255;
    bytes[1] = 1;
    bytes[MFW + 4..MFW + 8].copy_from_slice(&((MFW + INFO) as u32).to_le_bytes());
    bytes[MFW + 8..MFW + 12].copy_from_slice(&16u32.to_le_bytes());
    let add = |bytes: &mut alloc::vec::Vec<u8>, id: u32, idx: u8, payload: &[u8]| {
        let start = bytes.len();
        bytes.resize(start + HEADER, 0);
        bytes[start..start + 4].copy_from_slice(&id.to_le_bytes());
        bytes[start + SIZE..start + SIZE + 4]
            .copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[start + AID..start + AID + 2].copy_from_slice(&0u16.to_le_bytes());
        bytes[start + INDEX] = idx;
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().div_ceil(16) * 16, 0);
    };
    add(&mut bytes, 2, 0, &pair(0x100, 1));
    add(&mut bytes, 3, 0, &pair(0x00000000, 0x01020304));
    add(&mut bytes, 4, a_idx, &pair(0x60, 1));
    add(&mut bytes, 5, b_idx, &pair(0x60, 1));
    add(&mut bytes, 8, 0, &pair(0x100, 1));
    bytes
}
fn smoke_rtw89_be_calibration_record_is_n22a_and_new_be_binds_factory_and_assets() -> TestResult {
    let device = narf_bus::DeviceId {
        vendor: 0x10ec,
        device: 0x8922,
        class: 0x028000,
        subsystem_vendor: 1,
        subsystem_id: 2,
    };
    let factory = be_factory();
    let assets = match Assets::parse_for(ChipId::Rtl8922A, &be_container(0, 1)) {
        Ok(assets) => assets,
        Err(_) => return TestResult::Fail("8922A five-table fixture container refused"),
    };
    let be_board = match Board::new_be(&factory, device, &assets) {
        Ok(board) => board,
        Err(_) => return TestResult::Fail("exact RTL8922A factory/assets refused a board"),
    };
    // The identity binds RFE, cut, PHY-cap, firmware tables and the
    // PCI subsystem: varying any one must change it.
    let mut identities = alloc::vec::Vec::new();
    identities.push(be_board.identity());
    for variant in 0..5 {
        let mut factory = factory.clone();
        let mut device = device;
        match variant {
            0 => factory.rfe_type = 5,
            1 => factory.cv = Some(0),
            2 => factory.phycap[7] = 0x53,
            3 => device.subsystem_id = 3,
            _ => device.device = 0x892b,
        }
        let identity = match Board::new_be(&factory, device, &assets) {
            Ok(board) => board.identity(),
            Err(_) => {
                return TestResult::Fail("admitted RTL8922A variant refused a board");
            }
        };
        if identities.contains(&identity) {
            return TestResult::Fail(
                "different actual RFE/cut/PHY-cap/subsystem/device reused calibration identity",
            );
        }
        identities.push(identity);
    }
    // Refusals: wrong vendor/device, RFE 255, missing cut, C assets.
    let mut bad_device = device;
    bad_device.vendor = 0x10eb;
    let mut bad_rfe = factory.clone();
    bad_rfe.rfe_type = 255;
    let mut no_cut = factory.clone();
    no_cut.cv = None;
    let c_assets = Assets::parse_for(ChipId::Rtl8852C, &be_container(1, 0)).unwrap();
    for (factory, device, assets) in [
        (&factory, bad_device, &assets),
        (
            &factory,
            narf_bus::DeviceId {
                device: 0xc852,
                ..device
            },
            &assets,
        ),
        (&bad_rfe, device, &assets),
        (&no_cut, device, &assets),
        (&factory, device, &c_assets),
    ] {
        if Board::new_be(factory, device, assets).is_ok() {
            return TestResult::Fail("wrong vendor/device/RFE/cut/assets acquired a BE board");
        }
    }
    // The N22A record round-trips on the BE board and never admits a
    // B, C or 51B board; no other family magic admits the BE board.
    let b = board();
    let c = Board {
        device: 0xc852,
        chip: ChipId::Rtl8852C,
        ..b
    };
    let n51 = Board {
        device: 0xb851,
        chip: ChipId::Rtl8851B,
        ..b
    };
    let cap = authority();
    let mut bytes = image(be_board);
    for magic in [b"N52B", b"N5CB", b"N51B"] {
        bytes[..4].copy_from_slice(magic);
        if Calibration::from_verified(&bytes, Some([3; 32]), be_board, cap).is_ok() {
            return TestResult::Fail("B/C/51B calibration magic admitted an RTL8922A board");
        }
    }
    bytes[..4].copy_from_slice(b"N22A");
    let calibration = match Calibration::from_verified(&bytes, Some([3; 32]), be_board, cap) {
        Ok(calibration) => calibration,
        Err(_) => return TestResult::Fail("exact N22A calibration refused"),
    };
    if !calibration.matches(be_board)
        || calibration.matches(b)
        || calibration.matches(c)
        || calibration.matches(n51)
        || calibration.check(&domain()).is_err()
    {
        return TestResult::Fail("RTL8922A calibration bound to the wrong board or span");
    }
    for other in [b, c, n51] {
        let mut o = image(other);
        o[..4].copy_from_slice(b"N22A");
        if Calibration::from_verified(&o, Some([3; 32]), other, cap).is_ok() {
            return TestResult::Fail("N22A record admitted an RTL8852B/C/51B board");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_be_calibration_record_is_n22a_and_new_be_binds_factory_and_assets
);
