use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn factory() -> Factory {
    Factory {
        cut: 1,
        mac: [2, 0, 0, 0, 0, 1],
        cck_power: [30; 6],
        ht40_power: [20; 5],
        crystal_cap: 0x20,
        channel_plan: 0x7f,
        thermal: 0x18,
        board_option: 0,
    }
}
/// Synthetic dimensional bounds for arithmetic regressions only. This is not
/// a qualified RTL8188EU RF curve and is never registered for real hardware.
fn fixture() -> Vec<u8> {
    let mut bytes = vec![0; HEADER + ROW];
    bytes[..4].copy_from_slice(b"N8PC");
    bytes[4..6].copy_from_slice(&1u16.to_le_bytes());
    bytes[6..8].copy_from_slice(&(HEADER as u16).to_le_bytes());
    bytes[8..12].copy_from_slice(&((HEADER + ROW) as u32).to_le_bytes());
    bytes[12..41].copy_from_slice(&factory_bytes(factory(), 0x0bda, 0x8179));
    bytes[41] = 1;
    bytes[42..44].copy_from_slice(&8i16.to_le_bytes()); // conservative +2dBi
    bytes[44..46].copy_from_slice(&80i16.to_le_bytes()); // qualified20dBm EIRP
    bytes[46..48].copy_from_slice(&1u16.to_le_bytes());
    bytes[64] = 1;
    for x in bytes[HEADER + 4..].chunks_exact_mut(2) {
        x.copy_from_slice(&UNKNOWN.to_le_bytes());
    }
    for (class, index, bound) in [
        (0, 18, 56i16),
        (0, 19, 60),
        (0, 20, 61),
        (0, 31, 0),
        (1, 16, 56),
        (1, 17, 60),
        (1, 18, 61),
        (1, 21, 0),
    ] {
        let at = HEADER + 4 + class * 128 + index * 2;
        bytes[at..at + 2].copy_from_slice(&bound.to_le_bytes());
    }
    bytes
}
fn parse(bytes: &[u8]) -> Result<Calibration, Error> {
    Calibration::from_verified(
        bytes,
        Some([0x55; 32]),
        [0x77; 32],
        factory(),
        0x0bda,
        0x8179,
    )
}
fn rule(power: i8) -> narf_wireless::reg::RegRule {
    narf_wireless::reg::RegRule {
        freq_start_mhz: 2402,
        freq_end_mhz: 2472,
        max_bandwidth_mhz: 20,
        max_power_dbm: power,
        flags: narf_wireless::reg::RegFlags::empty(),
    }
}
fn domain(power: i8) -> narf_wireless::reg::RegulatoryDomain {
    narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![rule(power)],
    }
}
fn smoke_rtl8188eu_signed_power_exact_identity_and_no_unsigned_bypass() -> TestResult {
    let bytes = fixture();
    if Calibration::from_verified(&bytes, None, [0; 32], factory(), 0x0bda, 0x8179).err()
        != Some(Error::Unsigned)
    {
        return TestResult::Fail("unsigned bringup profile minted RF calibration");
    }
    // Every bound factory/USB identity byte must match the current snapshot.
    for offset in 12..41 {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        if parse(&bad).err() != Some(Error::Identity) {
            return TestResult::Fail("factory/USB identity mismatch admitted");
        }
    }
    let c = parse(&bytes).unwrap();
    if c.signer != [0x55; 32] || c.digest != [0x77; 32] {
        return TestResult::Fail("registry signature identity lost");
    }
    let p = c.permission(&domain(17), 1).unwrap();
    if p.gains(factory(), 0x0bda, 0x8179, 1) != Ok((19, 17))
        || p.gains(factory(), 0x0bda, 0x8179, 6) != Err(Error::Identity)
        || p.gains(factory(), 0x2357, 0x010c, 1) != Err(Error::Identity)
    {
        return TestResult::Fail("opaque gain token detached from exact device/channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_signed_power_exact_identity_and_no_unsigned_bypass
);
fn smoke_rtl8188eu_power_bounds_antenna_fraction_and_factory_ceiling() -> TestResult {
    let bytes = fixture();
    let c = parse(&bytes).unwrap();
    let p = c.permission(&domain(17), 1).unwrap();
    if p.eirp_limit_qdbm() != 68 || p.gains(factory(), 0x0bda, 0x8179, 1) != Ok((19, 17)) {
        return TestResult::Fail(
            "fractional conducted+antenna ceiling rounded down or factory gain exceeded",
        );
    }
    let mut qualified = bytes.clone();
    qualified[44..46].copy_from_slice(&64i16.to_le_bytes());
    let c = parse(&qualified).unwrap();
    if c.permission(&domain(17), 1)
        .unwrap()
        .gains(factory(), 0x0bda, 0x8179, 1)
        != Ok((18, 16))
    {
        return TestResult::Fail("board-qualified EIRP was not intersected");
    }
    if c.permission(&domain(15), 1).err() != Some(Error::NoMeasuredGain) {
        return TestResult::Fail("missing low-power measurement was fabricated");
    }
    let mut unknown = bytes.clone();
    for p in unknown[HEADER + 4..].chunks_exact_mut(2) {
        p.copy_from_slice(&UNKNOWN.to_le_bytes());
    }
    if parse(&unknown).unwrap().permission(&domain(17), 1).err() != Some(Error::NoMeasuredGain) {
        return TestResult::Fail("unknown gain interpolated or defaulted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_power_bounds_antenna_fraction_and_factory_ceiling
);
fn smoke_rtl8188eu_power_intersects_all_regulatory_restrictions() -> TestResult {
    let c = parse(&fixture()).unwrap();
    let mut d = domain(20);
    d.rules.push(rule(16));
    if c.permission(&d, 1)
        .unwrap()
        .gains(factory(), 0x0bda, 0x8179, 1)
        != Ok((18, 16))
    {
        return TestResult::Fail("more permissive overlapping rule won");
    }
    d.rules.reverse();
    if c.permission(&d, 1)
        .unwrap()
        .gains(factory(), 0x0bda, 0x8179, 1)
        != Ok((18, 16))
    {
        return TestResult::Fail("regulatory restriction depends on row order");
    }
    d.rules.push(rule(17));
    d.rules[2].freq_start_mhz = 2410;
    if c.permission(&d, 1).err() != Some(Error::Policy) {
        return TestResult::Fail("part-band restriction ignored");
    }
    d.rules.pop();
    for flag in [
        narf_wireless::reg::RegFlags::DFS,
        narf_wireless::reg::RegFlags::NO_IR,
    ] {
        d.rules[0].flags = flag;
        if c.permission(&d, 1).err() != Some(Error::Policy) {
            return TestResult::Fail("unsupported rule flag ignored");
        }
    }
    if c.permission(&domain(20), 6).err() != Some(Error::Policy) {
        return TestResult::Fail("runtime profile silently retuned");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_power_intersects_all_regulatory_restrictions
);
fn smoke_rtl8188eu_power_artifact_bounded_shape_and_measurements() -> TestResult {
    let bytes = fixture();
    for len in 0..bytes.len() {
        if parse(&bytes[..len]).is_ok() {
            return TestResult::Fail("truncated calibration accepted");
        }
    }
    for (at, value) in [
        (4, 2),
        (6, 63),
        (8, 0),
        (41, 0),
        (42, 255),
        (46, 0),
        (48, 1),
        (64, 0),
        (65, 1),
        (68, 1),
        (69, 2),
    ] {
        let mut bad = bytes.clone();
        bad[at] = value;
        if parse(&bad).is_ok() {
            return TestResult::Fail("malformed calibration shape/value accepted");
        }
    }
    let mut extra = bytes.clone();
    extra.extend_from_slice(&bytes[HEADER..]);
    let len = extra.len() as u32;
    extra[8..12].copy_from_slice(&len.to_le_bytes());
    extra[46] = 2;
    if parse(&extra).is_ok() {
        return TestResult::Fail("duplicate/unsorted channel curve accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_power_artifact_bounded_shape_and_measurements
);

fn native_permission(factory: Factory) -> Permission {
    native_calibration(factory)
        .permission(&domain(17), 1)
        .unwrap()
}
fn native_calibration(factory: Factory) -> Calibration {
    let mut bytes = fixture();
    bytes[12..41].copy_from_slice(&factory_bytes(factory, 0x0bda, 0x8179));
    // Omit the unrelated parser test's below-factory/above-qualified points.
    for at in [HEADER + 4 + 31 * 2, HEADER + 132 + 21 * 2] {
        bytes[at..at + 2].copy_from_slice(&UNKNOWN.to_le_bytes());
    }
    Calibration::from_verified(
        &bytes,
        Some([0x55; 32]),
        [0x77; 32],
        factory,
        0x0bda,
        0x8179,
    )
    .unwrap()
}
fn smoke_rtl8188eu_measured_gains_verified_before_mac_tx() -> TestResult {
    use super::super::firmware_transport_tests::{prepared_receiver, Op};
    use super::super::receive_runtime::Phase;
    let (control, firmware, _, mut radio) = prepared_receiver();
    narf_scheduler::block_on(radio.start()).unwrap();
    let permission = native_permission(firmware.factory().unwrap());
    control.0.lock().ops.clear();
    if narf_scheduler::block_on(radio.enable_transmit(permission)).is_err()
        || radio.phase() != Phase::Active
    {
        return TestResult::Fail("qualified gain activation failed");
    }
    let m = control.0.lock();
    let read = |a: usize| u32::from_le_bytes(m.regs[a..a + 4].try_into().unwrap());
    if (read(0xe08) >> 8) & 255 != 19
        || read(0x86c) & 0xffffff00 != 0x13131300
        || read(0xe00) != 0x11111111
        || read(0xe04) != 0x11111111
        || read(0x440) & 0xfffff != 1
        || m.regs[0x100] & 0xc0 != 0xc0
    {
        return TestResult::Fail("verified measured gains/rate ceiling not programmed");
    }
    let opened = m
        .ops
        .iter()
        .position(|op| matches!(op,Op::Write(0x100,b) if b[0]&0xc0==0xc0))
        .unwrap();
    for address in [0xe08, 0x86c, 0xe00, 0xe04, 0x440] {
        let confirmed = m
            .ops
            .iter()
            .rposition(|op| matches!(op,Op::Read(a,4) if *a==address))
            .unwrap();
        if confirmed >= opened {
            return TestResult::Fail("MAC TX opened before each gain readback");
        }
    }
    drop(m);
    narf_scheduler::block_on(radio.stop()).unwrap();
    if control.0.lock().regs[0x100] & 0xc0 != 0 {
        return TestResult::Fail("active MAC did not close before host stop");
    }
    narf_scheduler::block_on(radio.start()).unwrap();
    if radio.phase() != Phase::Receiving || control.0.lock().regs[0x100] & 0xc0 != 0x80 {
        return TestResult::Fail("resume silently reopened TX without reauthorization");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_measured_gains_verified_before_mac_tx
);
fn smoke_rtl8188eu_measured_gain_or_tx_gate_cancellation_is_terminal() -> TestResult {
    use super::super::firmware_transport::{Error as FwError, Stage};
    use super::super::firmware_transport_tests::prepared_receiver;
    use super::super::receive_runtime::{Error as RadioError, Phase};
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    for pending in [0xe08, 0x100] {
        let (control, firmware, _, mut radio) = prepared_receiver();
        narf_scheduler::block_on(radio.start()).unwrap();
        let permission = native_permission(firmware.factory().unwrap());
        control.0.lock().pending_write = Some(pending);
        let mut attempt = alloc::boxed::Box::pin(radio.enable_transmit(permission));
        let mut context = Context::from_waker(Waker::noop());
        if !matches!(attempt.as_mut().poll(&mut context), Poll::Pending)
            || !control.0.lock().active_td
        {
            return TestResult::Fail("fixture did not submit an owned gain/TX gate TD");
        }
        drop(attempt);
        let operations = control.0.lock().ops.len();
        if radio.phase() != Phase::Failed
            || firmware.status().stage != Stage::Failed
            || firmware.status().error != Some(FwError::Cancelled)
            || narf_scheduler::block_on(radio.enable_transmit(permission)) != Err(RadioError::State)
            || radio.poll() != Err(RadioError::State)
            || control.0.lock().ops.len() != operations
            || control.0.lock().unsafe_reuses != 0
        {
            return TestResult::Fail(
                "cancelled gain/TX gate reused ambiguous EP0 or admitted packet I/O",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_measured_gain_or_tx_gate_cancellation_is_terminal
);
fn smoke_rtl8188eu_tx_permission_rechecks_real_owner_before_io() -> TestResult {
    use super::super::firmware_transport_tests::prepared_receiver;
    use super::super::receive_runtime::{Error as RadioError, Phase};
    let (control, firmware, _, mut radio) = prepared_receiver();
    narf_scheduler::block_on(radio.start()).unwrap();
    let wrong = parse(&fixture())
        .unwrap()
        .permission(&domain(17), 1)
        .unwrap();
    let operations = control.0.lock().ops.len();
    if narf_scheduler::block_on(radio.enable_transmit(wrong))
        != Err(RadioError::Power(Error::Identity))
        || radio.phase() != Phase::Receiving
        || control.0.lock().ops.len() != operations
        || control.0.lock().regs[0x100] & 0xc0 != 0x80
    {
        return TestResult::Fail("other factory token reached USB or opened TX");
    }
    if firmware.usb_identity() != Some((0x0bda, 0x8179)) {
        return TestResult::Fail("native USB identity was not retained");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_tx_permission_rechecks_real_owner_before_io
);

fn smoke_rtl8188eu_signed_power_then_real_retained_native_management_tx() -> TestResult {
    use super::super::firmware_transport_tests::{prepared_receiver, Op};
    use super::super::receive_runtime::Error as RadioError;
    use narf_wireless::association::{Bss, JoinPlan, SecurityMode};
    let (control, firmware, bulk, mut radio) = prepared_receiver();
    narf_scheduler::block_on(radio.start()).unwrap();
    let own = firmware.factory().unwrap().mac;
    let peer = [2, 0, 0, 0, 0, 2];
    let bss = Bss {
        bssid: peer,
        ssid: b"narf".to_vec(),
        channel: 1,
        band: None,
        signal_dbm: None,
        capability: 1,
        beacon_interval: 100,
        information_elements: vec![0, 4, b'n', b'a', b'r', b'f', 1, 1, 0x82],
    };
    let mut plan = JoinPlan::prepare(&bss, own, b"narf", SecurityMode::Open).unwrap();
    let frame = plan.start_authentication().unwrap();
    if radio.submit_management(frame) != Err(RadioError::State)
        || !bulk.state.lock().sent.is_empty()
    {
        return TestResult::Fail("management escaped without measured-power activation");
    }
    let permission = native_permission(firmware.factory().unwrap());
    narf_scheduler::block_on(radio.enable_transmit(permission)).unwrap();
    let mut forged = frame.to_vec();
    forged[10] ^= 2;
    if radio.submit_management(&forged) != Err(RadioError::State)
        || !bulk.state.lock().sent.is_empty()
    {
        return TestResult::Fail("management TX accepted a foreign local transmitter");
    }
    bulk.state.lock().tx_pending = true;
    radio.submit_management(frame).unwrap();
    for _ in 0..100 {
        if radio.poll_delivery().unwrap().is_some() {
            return TestResult::Fail("quiet TX invented a completion");
        }
    }
    if bulk.state.lock().sent.len() != 1 {
        return TestResult::Fail("pending TX reposted its owned buffer");
    }
    bulk.state.lock().tx_pending = false;
    if radio.poll_delivery().unwrap().unwrap().native_bytes != 30 {
        return TestResult::Fail("native TX did not retire exact receipt");
    }
    let sent = bulk.state.lock().sent[0].1.clone();
    if sent[32..] != *frame || sent[20..24] != [0, 0, 0x1a, 0] {
        return TestResult::Fail("actual native TX changed frame/rate/retry profile");
    }
    let m = control.0.lock();
    let opened = m
        .ops
        .iter()
        .rposition(|op| matches!(op,Op::Write(0x100,b) if b[0]&0xc0==0xc0))
        .unwrap();
    let submitted = m
        .ops
        .iter()
        .rposition(|op| matches!(op, Op::Write(0xfffc, _)))
        .unwrap();
    if submitted <= opened {
        return TestResult::Fail("USB TX published before verified MAC/power gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless",
    smoke_rtl8188eu_signed_power_then_real_retained_native_management_tx
);

#[path = "station_tests.rs"]
mod station_tests;

#[path = "dhcp_composition_tests.rs"]
mod dhcp_composition_tests;

#[path = "ht_tests.rs"]
mod ht_tests;
