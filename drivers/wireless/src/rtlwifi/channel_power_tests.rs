use super::super::{prepare::Phase, radio::tests::channel_owner};
use super::*;
use narf_wireless::reg::RegFlags;
include!("radio/power_golden.rs");
use alloc::{boxed::Box, vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
pub(crate) fn factory() -> Factory {
    let mut logical = [0; 512];
    for (at, value) in [(0, 0x8129u16), (0xd6, 0x10ec), (0xd8, 0x8179)] {
        logical[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    logical[0x10..0x16].fill(30);
    logical[0x16..0x1b].fill(20);
    logical[0x1b] = 0x23;
    logical[0xb8] = 0x7f;
    Factory {
        mac: [2, 7, 8, 9, 10, 11],
        logical,
    }
}
fn artifact(factory: &Factory) -> Vec<u8> {
    // Synthetic measured envelopes for arithmetic only, never registered on
    // a real device: conducted qdBm=index*2, antenna upper bound+2dBi.
    let mut bytes = vec![0; HEADER + ROW];
    bytes[..4].copy_from_slice(b"NEPC");
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&(HEADER as u16).to_le_bytes());
    bytes[8..12].copy_from_slice(&((HEADER + ROW) as u32).to_le_bytes());
    bytes[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    bytes[14..16].copy_from_slice(&0x8179u16.to_le_bytes());
    bytes[16..48].copy_from_slice(&radio::factory_identity(factory));
    bytes[48..54].copy_from_slice(&factory.mac);
    bytes[56..58].copy_from_slice(&8i16.to_le_bytes());
    bytes[58..60].copy_from_slice(&80i16.to_le_bytes());
    bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
    bytes[62..64].copy_from_slice(&1u16.to_le_bytes());
    bytes[HEADER] = 1;
    for class in 0..2 {
        for index in 0..64 {
            let at = HEADER + 4 + class * 128 + index * 2;
            bytes[at..at + 2].copy_from_slice(&(index as i16 * 2).to_le_bytes());
        }
    }
    bytes
}
pub(crate) fn calibration(factory: &Factory) -> Calibration {
    Calibration::from_verified(&artifact(factory), Some([0x44; 32]), factory).unwrap()
}
pub(crate) fn calibration_with_cap(factory: &Factory, cap: Cap<FirmwareBlob, Read>) -> Calibration {
    let mut calibration = calibration(factory);
    calibration.authority = Some(cap);
    calibration
}
fn smoke_rtl8188ee_retained_signed_calibration_epoch_encloses_native_wmm_operation() -> TestResult {
    let mut calibration = calibration(&factory());
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    calibration.authority = Some(cap);
    let calls = core::cell::Cell::new(0);
    if calibration.permission(&domain(17), 1).is_err()
        || calibration.with_current(|| {
            calls.set(calls.get() + 1);
            Ok(7)
        }) != Ok(7)
    {
        return TestResult::Fail(
            "EE exact retained calibration rejected current native publication",
        );
    }
    cap.revoke();
    if calibration.permission(&domain(17), 1) != Err(Error::Authority)
        || calibration.with_current(|| {
            calls.set(calls.get() + 1);
            Ok(8)
        }) != Err(super::super::prepare::Error::Power(Error::Authority))
        || calls.get() != 1
    {
        return TestResult::Fail("EE revoked signed record reached actual WMM native operation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/wmm",
    smoke_rtl8188ee_retained_signed_calibration_epoch_encloses_native_wmm_operation
);
pub(crate) fn domain(power: i8) -> narf_wireless::reg::RegulatoryDomain {
    use narf_wireless::reg::*;
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: power,
            flags: RegFlags::empty(),
        }],
    }
}
fn run<F: Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("unexpected channel fixture wait"),
    }
}

pub(crate) fn smoke_rtl8188ee_factory_gain_selection_matches_frozen_reference() -> TestResult {
    for &(channel, mode, nibble, cck, ofdm) in LINUX_POWER {
        let mut factory = factory();
        factory.logical[0xc1] = mode;
        factory.logical[0x1b] = 0x20 | nibble;
        if factory_gains(&factory, channel) != Ok((cck, ofdm)) {
            return TestResult::Fail(
                "8188EE EFUSE/signed-nibble/PG gain arithmetic differs from frozen reference data",
            );
        }
    }
    let mut invalid = factory();
    invalid.logical[0x11] = 255;
    if factory_gains(&invalid, 1) != Err(Error::FactoryPower) {
        return TestResult::Fail("erased factory power invented fallback gains");
    }
    invalid = factory();
    invalid.logical[0x16] = 0;
    invalid.logical[0x1b] = 8;
    if factory_gains(&invalid, 1) != Err(Error::FactoryPower) {
        return TestResult::Fail("negative factory difference wrapped into high power");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_factory_gain_selection_matches_frozen_reference
);

pub(crate) fn smoke_rtl8188ee_signed_power_exact_board_identity_and_rules() -> TestResult {
    let factory = factory();
    let bytes = artifact(&factory);
    if Calibration::from_verified(&bytes, None, &factory).err() != Some(Error::Unsigned) {
        return TestResult::Fail("unsigned calibration minted permission");
    }
    for at in [0, 4, 6, 8, 12, 14, 54, 62, 64, HEADER + 1] {
        let mut malformed = bytes.clone();
        malformed[at] ^= 1;
        if Calibration::from_verified(&malformed, Some([1; 32]), &factory).is_ok() {
            return TestResult::Fail("malformed calibration profile accepted");
        }
    }
    let mut other = factory.clone();
    other.logical[0x10] ^= 1;
    if Calibration::from_verified(&bytes, Some([1; 32]), &other).err() != Some(Error::Identity) {
        return TestResult::Fail("different full EFUSE map borrowed calibration");
    }
    let calibration = calibration(&factory);
    let permission = calibration.permission(&domain(17), 1).unwrap();
    if permission.gains() != ([30; 4], [30, 30, 30, 29, 28, 27, 25, 25])
        || permission.eirp_limit_qdbm() != 68
    {
        return TestResult::Fail("measured upper bound/factory PG intersection mismatch");
    }
    let mut rules = domain(17);
    let mut restrictive = rules.rules[0].clone();
    restrictive.max_power_dbm = 10;
    rules.rules.push(restrictive);
    if calibration.permission(&rules, 1).unwrap().gains() != ([16; 4], [16; 8]) {
        return TestResult::Fail("narrower overlapping power limit ignored");
    }
    rules.rules[1].flags = RegFlags::NO_IR;
    if calibration.permission(&rules, 1) != Err(Error::Policy) {
        return TestResult::Fail("NO_IR channel acquired measured TX permission");
    }
    rules.rules[1].flags = RegFlags::empty();
    rules.rules[1].freq_start_mhz = 2410;
    if calibration.permission(&rules, 1) != Err(Error::Policy)
        || calibration.permission(&domain(17), 12) != Err(Error::Policy)
        || calibration.permission(&domain(17), 6) != Err(Error::NoMeasuredGain)
    {
        return TestResult::Fail("partial/unqualified channel minted permission");
    }
    // A valid signer and a permissive deployment cannot exceed the separate
    // Linux EE channel-plan/world ceiling. Use high real factory indices so
    // this regression cannot pass merely because another bound was lower.
    let mut high_factory = factory.clone();
    high_factory.logical[0x10..0x16].fill(60);
    high_factory.logical[0x16..0x1b].fill(50);
    let mut high = artifact(&high_factory);
    high[58..60].copy_from_slice(&120i16.to_le_bytes());
    let measured = Calibration::from_verified(&high, Some([1; 32]), &high_factory).unwrap();
    let bounded = measured.permission(&domain(30), 1).unwrap();
    if bounded.eirp_limit_qdbm() != 80 || bounded.gains() != ([36; 4], [36; 8]) {
        return TestResult::Fail("signed board/host policy raised Linux EE20dBm ceiling");
    }
    for class in 0..2 {
        for index in 0..64 {
            let at = HEADER + 4 + class * 128 + index * 2;
            let bound = if index == 50 { 100i16 } else { UNKNOWN };
            high[at..at + 2].copy_from_slice(&bound.to_le_bytes());
        }
    }
    let over = Calibration::from_verified(&high, Some([1; 32]), &high_factory).unwrap();
    if over.permission(&domain(30), 1) != Err(Error::NoMeasuredGain) {
        return TestResult::Fail("over20dBm-only measurement minted a transmit grant");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_signed_power_exact_board_identity_and_rules
);

pub(crate) fn smoke_rtl8188ee_channel_real_retained_gain_geometry_and_readback() -> TestResult {
    let factory = factory();
    let permission = calibration(&factory).permission(&domain(17), 1).unwrap();
    let (mut owner, port) = channel_owner(&factory);
    if run(owner.configure_channel(permission)).is_err()
        || owner.phase() != Phase::ChannelConfigured
        || owner.channel_permission() != Some(permission)
        || port.rf(0x18) != 0xc01
        || (port.word(0xe08) >> 8) & 255 != 30
        || port.word(0x86c) >> 8 != 0x1e1e1e
        || port.word(0xe00) != 0x1d1e1e1e
        || port.word(0xe04) != 0x19191b1c
        || port.word(0xe10) != 0
        || port.word(0x600) >> 24 & 4 == 0
        || port.word(0x800) & 1 != 0
        || port.word(0x900) & 1 != 0
        || port.word(0x300) >> 8 & 255 != 255
        || port.word(0x100) & 0xcf != 0
        || port.word(0xb0) != 0
        || port.word(0xb8) != 0
    {
        return TestResult::Fail("native channel gains/bandwidth/readback or parked gates");
    }
    let mut other = factory.clone();
    other.mac[5] ^= 1;
    let wrong = calibration(&other).permission(&domain(17), 1).unwrap();
    let before = port.accesses();
    if run(owner.configure_channel(wrong))
        != Err(super::super::prepare::Error::Power(Error::Identity))
        || port.accesses() != before
        || owner.channel_permission() != Some(permission)
    {
        return TestResult::Fail("other board permission reached native channel I/O");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_channel_real_retained_gain_geometry_and_readback
);

pub(crate) fn smoke_rtl8188ee_channel_fault_and_cancel_are_terminal_without_tx() -> TestResult {
    let factory = factory();
    let permission = calibration(&factory).permission(&domain(17), 1).unwrap();
    let (mut baseline, port) = channel_owner(&factory);
    assert!(run(baseline.configure_channel(permission)).is_ok());
    let count = port.accesses();
    drop(baseline);
    for fault in 0..count {
        let (mut owner, port) = channel_owner(&factory);
        port.fail_at(fault);
        if run(owner.configure_channel(permission)).is_ok()
            || owner.phase() != Phase::Failed
            || owner.channel_permission().is_some()
        {
            return TestResult::Fail("channel fault committed permission");
        }
        let before = port.accesses();
        if run(owner.configure_channel(permission)) != Err(super::super::prepare::Error::State)
            || port.accesses() != before
        {
            return TestResult::Fail("failed channel retried register operation");
        }
    }
    for reg in [0xe08, 0x86c, 0xe00, 0xe04, 0x603, 0x840] {
        let (mut owner, port) = channel_owner(&factory);
        port.ignore(reg);
        if run(owner.configure_channel(permission)).is_ok() || owner.phase() != Phase::Failed {
            return TestResult::Fail("ignored gain/channel write fabricated completion");
        }
    }
    for delay in 1..=3 {
        let (mut owner, port) = channel_owner(&factory);
        port.pause_after(delay);
        let mut future = Box::pin(owner.configure_channel(permission));
        let status = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        drop(future);
        if status.is_ready()
            || owner.phase() != Phase::Failed
            || owner.channel_permission().is_some()
            || port.word(0x300) >> 8 & 255 != 255
            || port.word(0x100) & 0xcf != 0
        {
            return TestResult::Fail("cancelled channel admitted TX or released terminal owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/channel",
    smoke_rtl8188ee_channel_fault_and_cancel_are_terminal_without_tx
);
