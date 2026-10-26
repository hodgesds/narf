//! Native Rust transport fixtures. RF receipts are device-side inputs, never
//! inferred from the production driver's completion state or expected data.
use super::*;
use crate::rtw88::{
    calibration8821c::{Error as QualificationError, Request, Source},
    efuse::Factory8821c,
    firmware_lifecycle::{Lifecycle, Stage},
    firmware_transport::Phase,
};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_wireless::reg::{RegFlags, RegulatoryDomain};

struct Fixture {
    lifecycle: Lifecycle<Backend<Port, Block>>,
    factory: Factory8821c,
    port: Port,
    drops: Arc<AtomicUsize>,
    request: Request,
}
fn fixture(rfe: u8, swing: u8) -> Result<Fixture, &'static str> {
    let (backend, port, drops) = allocated();
    let mut firmware = image();
    firmware[0] = 0x21;
    let lifecycle = Lifecycle::new(0xc821);
    narf_scheduler::block_on(lifecycle.initialize_bytes(|| Ok(backend), firmware))
        .map_err(|_| "C21 calibration fixture firmware failed")?;
    {
        let mut m = port.0.lock();
        m.bytes[0xf0..0xf4].copy_from_slice(&(3u32 << 12).to_le_bytes());
        m.bytes[0x1a0] = 0x19;
        m.bytes[0x1a6..0x1aa]
            .copy_from_slice(&((7u32 << 16) | (1 << 19) | (1 << 21) | (3 << 26)).to_le_bytes());
    }
    narf_scheduler::block_on(lifecycle.prepare_mac())
        .map_err(|_| "C21 calibration fixture inactive MAC failed")?;
    let mut raw = [255; 512];
    raw[0xd0..0xd6].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    raw[0xb9] = 0x33;
    raw[0xba] = 25;
    raw[0xc6] = swing;
    raw[0xca] = rfe;
    let factory = Factory8821c::for_test(raw).map_err(|_| "C21 factory fixture invalid")?;
    narf_scheduler::block_on(lifecycle.prepare_phy8821c(&factory))
        .map_err(|_| "C21 calibration fixture retained PHY failed")?;
    {
        let mut m = port.0.lock();
        m.bytes[0x2908..0x290c].copy_from_slice(&(25u32 << 10).to_le_bytes());
        m.bytes[0x2820..0x2824].fill(0);
        m.bytes[0x1bf0..0x1bf4].fill(0);
        m.rf_written = false;
        m.thermal_triggered = false;
        m.thermal_conversions = 0;
    }
    let request = narf_scheduler::block_on(lifecycle.calibration_request8821c(&factory))
        .map_err(|_| "C21 calibration request failed")?;
    Ok(Fixture {
        lifecycle,
        factory,
        port,
        drops,
        request,
    })
}
fn envelope(request: &Request) -> Vec<u8> {
    let mut bytes = vec![0; 128];
    bytes[..4].copy_from_slice(b"N21Q");
    for (at, value) in [(4, 1u16), (6, 128), (12, 0x10ec), (14, 0xc821)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[8..12].copy_from_slice(&128u32.to_le_bytes());
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54] = 1;
    bytes[55] = 20;
    for (at, value) in [(56, 4i16), (58, 76), (60, 40)] {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[62] = 20;
    bytes[63] = 30;
    bytes[64..66].copy_from_slice(b"US");
    bytes
}
fn source(bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>) -> Source {
    Source::Verified {
        bytes,
        signer: Some([7; 32]),
        cap,
    }
}
fn domain() -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 20,
            flags: RegFlags::empty(),
        }],
    }
}
fn smoke_rtw8821ce_measured_iqk_same_native_owner_and_literal_commands() -> TestResult {
    for (rfe, raw_swing, expected_swing, rfctl, cck) in [
        (0, 0, 0x200, 0x700000, 0x7532),
        (2, 3, 0x16a, 0x10000, 0xfc84),
        (4, 6, 0x101, 0x10000, 0xfc84),
        (6, 9, 0xb6, 0x700000, 0x7532),
    ] {
        let f = match fixture(rfe, raw_swing) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let (frame, ring, bells) = {
            let m = f.port.0.lock();
            let result = (
                m.frame.lock().bytes.clone(),
                m.ring.lock().bytes.clone(),
                m.doorbells,
            );
            result
        };
        let result = narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            source(envelope(&f.request), Cap::bootstrap()),
            || Ok(domain()),
        ));
        let info = match result {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("qualified C21 IQK continuation failed"),
        };
        if (
            info.channel,
            info.bandwidth_mhz,
            info.thermal_before,
            info.thermal_after,
            info.swing,
            info.iqk_status,
        ) != (1, 20, 25, 25, expected_swing, 0)
            || f.lifecycle.status().stage != Stage::Calibration8821cPrepared
            || narf_scheduler::block_on(f.lifecycle.calibration_info8821c()) != Some(info)
        {
            return TestResult::Fail(
                "C21 IQK receipt lost channel/thermal or historical checkpoint",
            );
        }
        let mut general = [0; 32];
        general[..12].copy_from_slice(&[1, 255, 13, 0, 12, 0, 0, 0, 0, 0, 48, 0]);
        let mut phydm = [0; 32];
        phydm[..12].copy_from_slice(&[1, 255, 17, 0, 16, 0, 1, 0, rfe, 4, 3, 0x11]);
        let mut iqk = [0; 32];
        iqk[..8].copy_from_slice(&[1, 255, 14, 0, 9, 0, 2, 0]);
        let calls = {
            let m = f.port.0.lock();
            if m.commands != [general, phydm, iqk]
                || m.command_ring.pending()
                || m.command_index != 0x30003
                || m.continuation != 8
                || m.iqk_reads != 2
                || word(&m.bytes, 0x2820) != 0
                || word(&m.bytes, 0x2860) & 0x70fff != 0xc01
                || word(&m.bytes, 0xcb8) & 0xf50000 != rfctl
                || word(&m.bytes, 0xa80) & 0xffff != cck
                || word(&m.bytes, 0xc1c) >> 21 != u32::from(expected_swing)
                || [
                    0x1d00, 0x1d04, 0x1d08, 0x1d0c, 0x1d10, 0x1d2c, 0x1d30, 0x1d34,
                ]
                .into_iter()
                .any(|reg| word(&m.bytes, reg) != 0)
                || m.bytes[0x100] & 0xcf != 0
                || m.bytes[0x522] != 255
                || m.frame.lock().bytes != frame
                || m.ring.lock().bytes != ring
                || m.doorbells != bells
            {
                return TestResult::Fail("C21 source channel/IQK bytes, fresh receipt, parked state or retained firmware DMA changed");
            }
            m.calls
        };
        let retained = narf_scheduler::block_on(f.lifecycle.retained.lock());
        let Some(owner) = retained.as_ref() else {
            return TestResult::Fail("C21 IQK discarded native owner");
        };
        if owner.phase() != Phase::Calibration8821cPrepared
            || owner.phy_info().is_some()
            || owner.hardware_info().is_none()
            || owner.image_digest().is_none()
        {
            return TestResult::Fail("C21 calibration became C22/operating/station admission");
        }
        drop(retained);
        // The C22 command still clears old IQK; C21 clear=0 is chip-specific.
        if crate::rtw88::command::iqk(2)[8] != 1
            || f.port.0.lock().calls != calls
            || f.drops.load(Ordering::SeqCst) != 0
        {
            return TestResult::Fail("C21 IQK altered C22 semantics or freed native DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_measured_iqk_same_native_owner_and_literal_commands
);

fn smoke_rtw8821ce_calibration_missing_or_invalid_assets_are_retryable_without_io() -> TestResult {
    let f = match fixture(2, 6) {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let good = envelope(&f.request);
    let calls = f.port.0.lock().calls;
    for mutation in 0..25 {
        let mut bytes = good.clone();
        let mut signer = Some([7; 32]);
        let cap = Cap::<FirmwareBlob, Read>::bootstrap();
        match mutation {
            0 => signer = None,
            1 => bytes.clear(),
            2 => {
                bytes.pop();
            }
            3 => bytes.push(0),
            4 => bytes[0] ^= 1,
            5 => bytes[4] = 2,
            6 => bytes[6] = 64,
            7 => bytes[8] = 127,
            8 => bytes[12] ^= 1,
            9 => bytes[14] ^= 1,
            10 => bytes[16] ^= 1,
            11 => bytes[48] ^= 1,
            12 => bytes[54] = 2,
            13 => bytes[55] = 40,
            14 => bytes[56..58].copy_from_slice(&(-1i16).to_le_bytes()),
            15 => bytes[58..60].copy_from_slice(&257i16.to_le_bytes()),
            16 => bytes[60..62].copy_from_slice(&257i16.to_le_bytes()),
            17 => bytes[62] = 26,
            18 => bytes[63] = 24,
            19 => bytes[63] = 64,
            20 => bytes[64] = b'C',
            21 => bytes[127] = 1,
            22 => cap.revoke(),
            23 => bytes[60..62].copy_from_slice(&76i16.to_le_bytes()),
            _ => bytes[62] = 40,
        }
        let result = narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            Source::Verified { bytes, signer, cap },
            || Ok(domain()),
        ));
        if result.is_ok()
            || f.port.0.lock().calls != calls
            || f.lifecycle.status().stage != Stage::PhyTablesPrepared
        {
            return TestResult::Fail("invalid C21 envelope touched native registers or poisoned retryable PHY checkpoint");
        }
    }
    if narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
        &f.factory,
        Source::Registered,
        || Ok(domain()),
    ))
    .is_ok()
        || f.port.0.lock().calls != calls
        || f.lifecycle.status().stage != Stage::PhyTablesPrepared
    {
        return TestResult::Fail(
            "missing measured C21 asset allocated/touched hardware or lost checkpoint",
        );
    }
    for mutation in 0..8 {
        let mut policy = domain();
        match mutation {
            0 => policy.country_code = *b"CN",
            1 => policy.rules.clear(),
            2 => policy.rules[0].freq_start_mhz = 2403,
            3 => policy.rules[0].max_bandwidth_mhz = 10,
            4 => policy.rules[0].max_power_dbm = 10,
            5 => policy.rules[0].flags = RegFlags::DFS,
            6 => policy.rules[0].flags = RegFlags::NO_IR,
            _ => {
                let mut rule = policy.rules[0].clone();
                rule.freq_start_mhz = 2406;
                rule.flags = RegFlags::NO_IR;
                policy.rules.push(rule);
            }
        }
        if narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            source(good.clone(), Cap::bootstrap()),
            || Ok(policy.clone()),
        )) != Err(Error::Calibration8821c(QualificationError::Policy))
            || f.port.0.lock().calls != calls
            || f.lifecycle.status().stage != Stage::PhyTablesPrepared
        {
            return TestResult::Fail(
                "C21 calibration ignored current country/bandwidth/overlap/power/NO_IR",
            );
        }
    }
    let mut policy = domain();
    policy.rules[0].flags = RegFlags::NO_P2P;
    if narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
        &f.factory,
        source(good, Cap::bootstrap()),
        || Ok(policy.clone()),
    ))
    .is_err()
    {
        return TestResult::Fail(
            "retryable C21 asset/policy rejection prevented later measured calibration",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_calibration_missing_or_invalid_assets_are_retryable_without_io
);

fn smoke_rtw8821ce_iqk_actual_receipts_thermal_and_transport_failures_are_terminal() -> TestResult {
    for outcome in 0..9 {
        let f = match fixture(4, 6) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let expected = {
            let mut m = f.port.0.lock();
            match outcome {
                0 => {
                    m.iqk_complete = false;
                    Error::Timeout
                }
                1 => {
                    m.bytes[0x1bf0] = 1;
                    Error::Prerequisite
                }
                2 => {
                    m.bytes[0x1bf2] = 1;
                    Error::Prerequisite
                }
                3 => {
                    m.bytes[0x2820..0x2824].copy_from_slice(&0xabcdeu32.to_le_bytes());
                    Error::Prerequisite
                }
                4 => {
                    m.ignore_rf = true;
                    Error::Prerequisite
                }
                5 => {
                    m.bytes[0x2908..0x290c].copy_from_slice(&(31u32 << 10).to_le_bytes());
                    Error::Calibration8821c(QualificationError::Thermal)
                }
                6 => {
                    m.fail = Some(m.calls);
                    Error::Access
                }
                7 => {
                    m.bytes[0xf3] |= 8;
                    Error::Unsupported
                }
                _ => {
                    m.command_stall = true;
                    Error::Timeout
                }
            }
        };
        if narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            source(envelope(&f.request), Cap::bootstrap()),
            || Ok(domain()),
        )) != Err(expected)
            || f.lifecycle.status().stage != Stage::Failed
            || narf_scheduler::block_on(f.lifecycle.calibration_info8821c()).is_some()
        {
            return TestResult::Fail(
                "C21 IQK ignored missing/failing/stale RF receipt, thermal or transport failure",
            );
        }
        let calls = f.port.0.lock().calls;
        if outcome == 0 && f.port.0.lock().iqk_reads != 300 {
            return TestResult::Fail("C21 IQK wait did not honor actual300-poll bound");
        }
        if narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            source(envelope(&f.request), Cap::bootstrap()),
            || Ok(domain()),
        )) != Err(Error::State)
            || f.port.0.lock().calls != calls
        {
            return TestResult::Fail("failed C21 calibration replayed retained native owner");
        }
        drop(f.lifecycle);
        if f.drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("terminal C21 calibration freed published firmware DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_iqk_actual_receipts_thermal_and_transport_failures_are_terminal
);

fn smoke_rtw8821ce_iqk_pending_revocation_policy_thermal_and_cancel_retain_owner() -> TestResult {
    for outcome in 0..5 {
        let f = match fixture(2, 6) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let cap = Cap::<FirmwareBlob, Read>::bootstrap();
        let policy = Arc::new(IrqSafeSpinLock::new(domain()));
        {
            let mut m = f.port.0.lock();
            m.hold_delay = Some(if outcome == 0 {
                13
            } else if outcome == 1 {
                10
            } else {
                20000
            });
            m.command_stall = outcome == 1;
        }
        let mut future = Box::pin(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            source(envelope(&f.request), cap),
            || Ok(policy.lock().clone()),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx) != Poll::Pending {
            return TestResult::Fail("C21 pending calibration fixture missed real wait");
        }
        let calls = f.port.0.lock().calls;
        let commands = f.port.0.lock().commands.len();
        if outcome == 0 {
            drop(future);
            if f.lifecycle.status().error != Some(Error::Cancelled) {
                return TestResult::Fail("C21 RF-write cancellation lost terminal receipt");
            }
        } else {
            match outcome {
                1 => cap.revoke(),
                2 => policy.lock().rules[0].flags = RegFlags::NO_IR,
                3 => {
                    f.port.0.lock().bytes[0x2908..0x290c]
                        .copy_from_slice(&(31u32 << 10).to_le_bytes());
                }
                _ => {
                    let mut m = f.port.0.lock();
                    m.fail = Some(m.calls);
                }
            }
            {
                let mut m = f.port.0.lock();
                m.hold_delay = None;
                m.command_stall = false;
            }
            let expected = match outcome {
                1 => Error::Calibration8821c(QualificationError::Authority),
                2 => Error::Calibration8821c(QualificationError::Policy),
                3 => Error::Calibration8821c(QualificationError::Thermal),
                _ => Error::Access,
            };
            if future.as_mut().poll(&mut cx) != Poll::Ready(Err(expected)) {
                return TestResult::Fail(
                    "resumed C21 wait published after qualification/policy/thermal/device loss",
                );
            }
            drop(future);
            if outcome <= 2 && f.port.0.lock().calls != calls {
                return TestResult::Fail(
                    "revoked C21 qualification/current policy reached native operation",
                );
            }
        }
        if f.lifecycle.status().stage != Stage::Failed
            || f.port.0.lock().commands.len() != commands
            || f.drops.load(Ordering::SeqCst) != 0
        {
            return TestResult::Fail(
                "C21 cancellation/revocation replaced owner, issued another command or freed DMA",
            );
        }
        drop(f.lifecycle);
        if f.drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("cancelled C21 IQK freed published buffers onDrop");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_iqk_pending_revocation_policy_thermal_and_cancel_retain_owner
);

fn smoke_rtw8821ce_fresh_meter_conversions_bound_both_sides_of_actual_iqk() -> TestResult {
    for samples in [[25, 26], [31, 26], [25, 31]] {
        let f = match fixture(2, 6) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        {
            let mut m = f.port.0.lock();
            // The stale pre-conversion register lies outside the envelope.
            // Only the independent two-second device conversion changes it.
            m.bytes[0x2908..0x290c].copy_from_slice(&(5u32 << 10).to_le_bytes());
            m.thermal_values = Some(samples);
        }
        let result = narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            source(envelope(&f.request), Cap::bootstrap()),
            || Ok(domain()),
        ));
        if samples == [25, 26] {
            if result.is_err()
                || result
                    .as_ref()
                    .is_ok_and(|i| (i.thermal_before, i.thermal_after) != (25, 26))
                || f.port.0.lock().thermal_conversions != 2
                || f.lifecycle.status().stage != Stage::Calibration8821cPrepared
            {
                return TestResult::Fail(
                    "fresh C21 conversion did not precede both thermal samples",
                );
            }
        } else if result != Err(Error::Calibration8821c(QualificationError::Thermal))
            || f.lifecycle.status().stage != Stage::Failed
            || f.port.0.lock().thermal_conversions != if samples[0] == 31 { 1 } else { 2 }
            || narf_scheduler::block_on(f.lifecycle.calibration_info8821c()).is_some()
        {
            return TestResult::Fail(
                "C21 fresh out-of-envelope conversion admitted calibration receipt",
            );
        }
        drop(f.lifecycle);
        if f.drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 fresh thermal result freed actual published mappings");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_fresh_meter_conversions_bound_both_sides_of_actual_iqk
);

fn smoke_rtw8821ce_thermal_conversion_pending_cancel_and_authority_loss_are_terminal() -> TestResult
{
    for outcome in 0..3 {
        let f = match fixture(4, 3) {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let cap = Cap::<FirmwareBlob, Read>::bootstrap();
        let policy = Arc::new(IrqSafeSpinLock::new(domain()));
        f.port.0.lock().hold_delay = Some(2_000_000);
        let mut operation = Box::pin(f.lifecycle.prepare_calibration8821c_with(
            &f.factory,
            source(envelope(&f.request), cap),
            || Ok(policy.lock().clone()),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if operation.as_mut().poll(&mut cx) != Poll::Pending {
            return TestResult::Fail("C21 conversion did not retain pending real wait");
        }
        let before = f.port.0.lock().calls;
        if outcome == 0 {
            drop(operation);
        } else {
            if outcome == 1 {
                cap.revoke();
            } else {
                policy.lock().rules[0].flags = RegFlags::NO_IR;
            }
            f.port.0.lock().hold_delay = None;
            let expected = Error::Calibration8821c(if outcome == 1 {
                QualificationError::Authority
            } else {
                QualificationError::Policy
            });
            if operation.as_mut().poll(&mut cx) != Poll::Ready(Err(expected)) {
                return TestResult::Fail(
                    "C21 resumed conversion ignored current signed/regulatory authority",
                );
            }
            drop(operation);
        }
        if f.lifecycle.status().stage != Stage::Failed
            || f.port.0.lock().calls != before
            || !f.port.0.lock().commands.is_empty()
            || f.drops.load(Ordering::SeqCst) != 0
        {
            return TestResult::Fail(
                "cancelled/revoked C21 conversion published calibration commands or lost owner",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_thermal_conversion_pending_cancel_and_authority_loss_are_terminal
);
