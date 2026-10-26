use super::mac_tests::{ready, Model};
use super::*;
use crate::rtw88::{
    efuse::Factory,
    phy,
    power_policy::{Board, Error as PowerError, Source},
};
use alloc::{vec, vec::Vec};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};
pub(super) fn make_factory(rfe: u8, base: u8) -> Factory {
    let mut raw = [255; 768];
    raw[0x120..0x126].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    raw[0xb9] = 0x33;
    raw[0xc1] = 0;
    raw[0xca] = rfe;
    raw[0xd0..0xd2].copy_from_slice(&[25, 26]);
    raw[0x10] = base;
    raw[0x10 + 42] = base.saturating_add(1);
    for at in [0x10, 0x10 + 42] {
        raw[at + 6] = 40;
        raw[at + 11] = 0;
    }
    Factory::for_test_with_trims(raw, [1; 19]).unwrap()
}
pub(super) fn domain() -> narf_wireless::reg::RegulatoryDomain {
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
pub(super) fn image(board: Board, factory: &Factory) -> Vec<u8> {
    let mut bytes = vec![0; 640];
    bytes[..4].copy_from_slice(b"N22C");
    for (at, value) in [(4, 2u16), (6, 128), (12, 0x10ec), (14, 0xc822), (60, 2)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[8..12].copy_from_slice(&640u32.to_le_bytes());
    bytes[16..48].copy_from_slice(&board.identity());
    bytes[48..54].copy_from_slice(&factory.mac());
    bytes[54] = 1;
    bytes[55] = 3;
    for (at, value) in [(56, 4i16), (58, 76), (62, 40), (64, 40)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    for path in 0..2 {
        for index in 0..128 {
            let value = ((index as i16) * 2 + if path == 0 { 0 } else { 8 }).min(256);
            let at = 128 + path * 256 + index * 2;
            bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
    }
    bytes
}
pub(super) fn source(bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>) -> Source {
    Source::Verified {
        bytes,
        signer: Some([7; 32]),
        cap,
    }
}
fn prepared() -> (Owner<Model>, Factory, Board) {
    let mut owner = ready();
    narf_scheduler::block_on(owner.prepare_mac()).unwrap();
    let factory = make_factory(0, 60);
    let info = narf_scheduler::block_on(owner.prepare_phy_tables(&factory)).unwrap();
    let board = Board::new(
        &factory,
        info,
        owner.hardware_info().unwrap(),
        owner.image_digest().unwrap(),
    )
    .unwrap();
    owner.io.trace.clear();
    (owner, factory, board)
}
fn smoke_rtw8822ce_signed_board_permission_composes_with_real_owner_and_current_policy(
) -> TestResult {
    let (mut owner, factory, board) = prepared();
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    let policy = domain();
    let permission =
        match owner.qualify_with(&factory, &policy, source(image(board, &factory), cap)) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("same-owner signed board qualification failed"),
        };
    if permission.eirp_limit_qdbm() != 76
        || owner.current_power(permission, &policy) != Ok([36, 32])
        || !owner.io.trace.is_empty()
        || owner.phase() != Phase::PhyTablesPrepared
    {
        return TestResult::Fail(
            "measured gain/antenna bounds or qualification-only state incorrect",
        );
    }
    let mut lower = policy.clone();
    lower.rules[0].max_power_dbm = 17;
    if owner.current_power(permission, &lower) != Err(Error::Power(PowerError::Policy)) {
        return TestResult::Fail("old programmed gain token survived restrictive live policy");
    }
    let replacement = owner
        .qualify_with(&factory, &lower, Source::Registered)
        .unwrap();
    if owner.current_power(replacement, &lower) != Ok([32, 28]) {
        return TestResult::Fail(
            "tightened measured gain bounds did not preserve per-path geometry",
        );
    }
    lower.rules[0].max_power_dbm = 10;
    if owner.qualify_with(&factory, &lower, Source::Registered)
        != Err(Error::Power(PowerError::Policy))
    {
        return TestResult::Fail("calibration peak was ignored under low regulatory ceiling");
    }
    let mut overlap = policy.clone();
    let mut rule = overlap.rules[0].clone();
    rule.freq_start_mhz = 2406;
    overlap.rules.push(rule);
    if owner.qualify_with(&factory, &overlap, Source::Registered)
        != Err(Error::Power(PowerError::Policy))
    {
        return TestResult::Fail("permissive row erased narrower overlapping channel restriction");
    }
    let mut no_p2p = policy.clone();
    no_p2p.rules[0].flags = narf_wireless::reg::RegFlags::NO_P2P;
    if owner.current_power(permission, &no_p2p) != Ok([36, 32]) {
        return TestResult::Fail("STA qualification incorrectly required P2P permission");
    }
    cap.revoke();
    if owner.current_power(permission, &policy) != Err(Error::Power(PowerError::Authority))
        || owner.qualify_with(&factory, &policy, Source::Registered)
            != Err(Error::Power(PowerError::Authority))
        || !owner.io.trace.is_empty()
    {
        return TestResult::Fail(
            "revoked actual calibration cap admitted gains or touched native DMA",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_signed_board_permission_composes_with_real_owner_and_current_policy
);
fn smoke_rtw8822ce_power_qualification_rejects_unsigned_malformed_and_foreign_identity(
) -> TestResult {
    let (owner, factory, board) = prepared();
    let good = image(board, &factory);
    for mutation in 0..20 {
        let mut bytes = good.clone();
        let mut signer = Some([7; 32]);
        match mutation {
            0 => signer = None,
            1 => bytes[0] ^= 1,
            2 => {
                bytes.pop();
            }
            3 => bytes.push(0),
            4 => bytes[12] ^= 1,
            5 => bytes[16] ^= 1,
            6 => bytes[48] ^= 2,
            7 => bytes[54] = 2,
            8 => bytes[55] = 0,
            9 => bytes[60] = 1,
            10 => bytes[66] = 1,
            11 => bytes[56..58].copy_from_slice(&(-1i16).to_le_bytes()),
            12 => bytes[58..60].copy_from_slice(&257i16.to_le_bytes()),
            13 => bytes[128..130].copy_from_slice(&32766i16.to_le_bytes()),
            14 => bytes[62..64].copy_from_slice(&32767i16.to_le_bytes()),
            15 => bytes[8] ^= 1,
            16 => bytes[4] = 1,
            17 => bytes[64..66].copy_from_slice(&i16::MAX.to_le_bytes()),
            18 => bytes[64..66].copy_from_slice(&257i16.to_le_bytes()),
            _ => bytes[55] = 1,
        }
        let cap = Cap::<FirmwareBlob, Read>::bootstrap();
        if (Source::Verified { bytes, signer, cap })
            .load(board)
            .is_ok()
        {
            return TestResult::Fail("unqualified board envelope became a TX grant");
        }
    }
    let mut response = good.clone();
    response[64..66].copy_from_slice(&76i16.to_le_bytes());
    let response = source(response, Cap::bootstrap()).load(board).unwrap();
    if response.permission(&domain()) != Err(PowerError::Policy) {
        return TestResult::Fail("unqualified hardware automatic-response RF peak authorized RX");
    }
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    cap.revoke();
    if !matches!(
        source(good.clone(), cap).load(board),
        Err(PowerError::Authority)
    ) {
        return TestResult::Fail("already-revoked cap was accepted at qualification load");
    }
    let info = owner.phy_info().unwrap();
    let hardware = owner.hardware_info().unwrap();
    let digest = owner.image_digest().unwrap();
    for mutation in 0..5 {
        let mut raw = *factory.logical();
        let mut trims = *factory.trims();
        let mut hw = hardware;
        let mut fw = digest;
        let mut profile = info;
        match mutation {
            0 => raw[0x120] ^= 2,
            1 => trims[0] ^= 1,
            2 => hw.protocol ^= 1,
            3 => fw[0] ^= 1,
            _ => {
                raw[0xb9] ^= 1;
                profile.crystal ^= 1;
            }
        }
        let changed = Factory::for_test_with_trims(raw, trims).unwrap();
        let other = Board::new(&changed, profile, hw, fw).unwrap();
        let cap = Cap::<FirmwareBlob, Read>::bootstrap();
        if !matches!(
            source(good.clone(), cap).load(other),
            Err(PowerError::Identity)
        ) {
            return TestResult::Fail(
                "board/MAC/OTP/hardware/firmware substitution reused qualification",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_power_qualification_rejects_unsigned_malformed_and_foreign_identity
);
fn smoke_rtw8822ce_qualification_preserves_source_factory_ceilings_and_unknown_gain_holes(
) -> TestResult {
    let (owner, _, _) = prepared();
    let hardware = owner.hardware_info().unwrap();
    let digest = owner.image_digest().unwrap();
    for (rfe, maximum) in [(0, [48, 49]), (5, [44, 45])] {
        let factory = make_factory(rfe, 60);
        let info = phy::Info {
            rfe,
            ..owner.phy_info().unwrap()
        };
        let board = Board::new(&factory, info, hardware, digest).unwrap();
        let mut bytes = image(board, &factory);
        for at in (128..640).step_by(2) {
            bytes[at..at + 2].copy_from_slice(&0i16.to_le_bytes());
        }
        let cap = Cap::<FirmwareBlob, Read>::bootstrap();
        let calibration = source(bytes, cap).load(board).unwrap();
        let permission = calibration.permission(&domain()).unwrap();
        if calibration.gains(permission, &domain()) != Ok(maximum) {
            return TestResult::Fail(
                "measurement grant exceeded exact source factory/PG/all-region ceiling",
            );
        }
    }
    let factory = make_factory(0, 60);
    let board = Board::new(&factory, owner.phy_info().unwrap(), hardware, digest).unwrap();
    let mut bytes = image(board, &factory);
    for at in (128..640).step_by(2) {
        bytes[at..at + 2].copy_from_slice(&i16::MAX.to_le_bytes());
    }
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    if !matches!(
        source(bytes.clone(), cap)
            .load(board)
            .unwrap()
            .permission(&domain()),
        Err(PowerError::NoMeasuredGain)
    ) {
        return TestResult::Fail("unmeasured gain defaulted to zero power");
    }
    for (path, index, bound) in [(0, 12, 30i16), (0, 24, 68), (0, 25, 90), (1, 7, 50)] {
        let at = 128 + path * 256 + index * 2;
        bytes[at..at + 2].copy_from_slice(&bound.to_le_bytes());
    }
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    let calibration = source(bytes, cap).load(board).unwrap();
    let permission = calibration.permission(&domain()).unwrap();
    if calibration.gains(permission, &domain()) != Ok([24, 7]) {
        return TestResult::Fail(
            "gain holes/nonmonotonic measurements were promoted or mixed across paths",
        );
    }
    for base in [0, 11, 128, 255] {
        let factory = make_factory(0, base);
        if Board::new(&factory, owner.phy_info().unwrap(), hardware, digest)
            != Err(PowerError::FactoryPower)
        {
            return TestResult::Fail(
                "erased/underflowing factory index wrapped into a larger gain",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_qualification_preserves_source_factory_ceilings_and_unknown_gain_holes
);
