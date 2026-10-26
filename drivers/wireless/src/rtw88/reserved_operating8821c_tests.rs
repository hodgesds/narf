//! Actual retained reserved-DMA firmware/MAC/PHY/IQK/parked power composition.
use super::*;
use crate::rtw88::operating8821c::{Request as PowerRequest, Source as PowerSource};
fn calibrated() -> Result<(Fixture, Cap<FirmwareBlob, Read>), &'static str> {
    let f = fixture(2, 3)?;
    let cap = Cap::bootstrap();
    narf_scheduler::block_on(f.lifecycle.prepare_calibration8821c_with(
        &f.factory,
        source(envelope(&f.request), cap),
        || Ok(domain()),
    ))
    .map_err(|_| "C21 power fixture did not complete genuine modeled IQK")?;
    Ok((f, cap))
}
fn artifact(request: &PowerRequest) -> Vec<u8> {
    let mut b = vec![0; 160];
    b[..4].copy_from_slice(b"N21P");
    b[4..8].copy_from_slice(&[1, 0, 160, 0]);
    b[8..12].copy_from_slice(&160u32.to_le_bytes());
    b[12..16].copy_from_slice(&[0xec, 0x10, 0x21, 0xc8]);
    b[16..48].copy_from_slice(&request.identity);
    b[48..54].copy_from_slice(&request.mac);
    b[54..56].copy_from_slice(&[1, 20]);
    for (at, value) in [(56, 4i16), (58, 76), (60, 48), (62, 44)] {
        b[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    b[64..68].copy_from_slice(&[20, 30, b'U', b'S']);
    for i in 0..12 {
        b[68 + i] = 8 + i as u8;
        b[80 + 2 * i..82 + 2 * i].copy_from_slice(&(32i16 + i as i16).to_le_bytes());
    }
    b
}
fn power_source(bytes: Vec<u8>, cap: Cap<FirmwareBlob, Read>) -> PowerSource {
    PowerSource::Verified {
        bytes,
        cap,
        signer: Some([8; 32]),
    }
}
fn request(f: &Fixture) -> Result<PowerRequest, &'static str> {
    narf_scheduler::block_on(f.lifecycle.operating_request8821c(&f.factory))
        .map_err(|_| "C21 operating request missing same-owner IQK receipt")
}
fn smoke_rtw8821ce_parked_operating_power_retry_native_txagc_and_retained_owner() -> TestResult {
    let (f, _) = match calibrated() {
        Ok(f) => f,
        Err(e) => return TestResult::Fail(e),
    };
    let request = match request(&f) {
        Ok(r) => r,
        Err(e) => return TestResult::Fail(e),
    };
    let mut receipt = match narf_scheduler::block_on(f.lifecycle.calibration_info8821c()) {
        Some(info) => info,
        None => return TestResult::Fail("C21 missing retained calibration receipt"),
    };
    receipt.thermal_before = 29;
    receipt.thermal_after = 27;
    receipt.iqk_status ^= 1 << 20;
    if crate::rtw88::operating8821c::request(f.request.clone(), receipt).identity
        != request.identity
    {
        return TestResult::Fail("C21 measured program identity incorrectly binds variable valid thermal/status receipts");
    }
    let baseline = f.port.0.lock().calls;
    let mut bad = artifact(&request);
    bad[16] ^= 1;
    if narf_scheduler::block_on(f.lifecycle.prepare_operating8821c_with(
        &f.factory,
        power_source(bad, Cap::bootstrap()),
        || Ok(domain()),
    ))
    .is_ok()
        || f.lifecycle.status().stage != Stage::Calibration8821cPrepared
        || f.port.0.lock().calls != baseline
    {
        return TestResult::Fail(
            "C21 invalid operating asset wrote or consumed retryable IQK owner",
        );
    }
    let cap = Cap::bootstrap();
    let result = narf_scheduler::block_on(f.lifecycle.prepare_operating8821c_with(
        &f.factory,
        power_source(artifact(&request), cap),
        || Ok(domain()),
    ));
    let info = match result {
        Ok(info) => info,
        Err(_) => {
            return TestResult::Fail("C21 measured parked operating-power continuation failed")
        }
    };
    {
        let m = f.port.0.lock();
        if [
            0x1d00, 0x1d04, 0x1d08, 0x1d0c, 0x1d10, 0x1d2c, 0x1d30, 0x1d34,
        ]
        .map(|r| word(&m.bytes, r))
            != [0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0, 0, 0, 0, 0]
            || word(&m.bytes, 0x440) != 0x15f
            || m.bytes[0x100] & 0xcf != 0
            || m.bytes[0x522] != 255
            || m.continuation != 10
        {
            return TestResult::Fail("C21 actual TXAGC/RRSR words or closed native gates differ");
        }
    }
    if info.identity != request.identity
        || info.thermal != 25
        || info.response_rates != 0x15f
        || f.lifecycle.status().stage != Stage::Operating8821cPrepared
        || narf_scheduler::block_on(f.lifecycle.operating_info8821c()) != Some(info)
        || narf_scheduler::block_on(f.lifecycle.prepare_operating8821c_with(
            &f.factory,
            power_source(artifact(&request), cap),
            || Ok(domain()),
        ))
        .is_ok()
    {
        return TestResult::Fail("C21 parked power receipt replayed or lost exact identity");
    }
    let drops = f.drops.clone();
    drop(f);
    if drops.load(Ordering::SeqCst) != 0 {
        return TestResult::Fail("C21 operating-power success reclaimed published firmware DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/power",
    smoke_rtw8821ce_parked_operating_power_retry_native_txagc_and_retained_owner
);
fn smoke_rtw8821ce_operating_power_exact_bounds_and_partial_io_fail_closed() -> TestResult {
    for fault in 0..8 {
        let (f, _) = match calibrated() {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let request = match request(&f) {
            Ok(r) => r,
            Err(e) => return TestResult::Fail(e),
        };
        let mut b = artifact(&request);
        let cap = Cap::bootstrap();
        let before = f.port.0.lock().calls;
        match fault {
            0 => b[68] = 31,
            1 => b[80..82].copy_from_slice(&76i16.to_le_bytes()),
            2 => b[64] = 26,
            3 => b[104] = 1,
            4 => cap.revoke(),
            5 => {
                f.port.0.lock().ignore_write = Some(0x1d04);
            }
            6 => {
                f.port.0.lock().fail = Some(before + 3);
            }
            _ => b[62..64].copy_from_slice(&76i16.to_le_bytes()),
        }
        let result = narf_scheduler::block_on(f.lifecycle.prepare_operating8821c_with(
            &f.factory,
            power_source(b, cap),
            || Ok(domain()),
        ));
        if result.is_ok() || narf_scheduler::block_on(f.lifecycle.operating_info8821c()).is_some() {
            return TestResult::Fail(
                "C21 unqualified per-rate/response/thermal or partial power programming admitted",
            );
        }
        let expected = if matches!(fault, 2 | 5 | 6) {
            Stage::Failed
        } else {
            Stage::Calibration8821cPrepared
        };
        if f.lifecycle.status().stage != expected
            || !matches!(fault, 2 | 5 | 6) && f.port.0.lock().calls != before
        {
            return TestResult::Fail(
                "C21 preflight/partial power failure changed wrong owner stage",
            );
        }
        let drops = f.drops.clone();
        drop(f);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 failed power programming freed firmware DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/power",
    smoke_rtw8821ce_operating_power_exact_bounds_and_partial_io_fail_closed
);
fn smoke_rtw8821ce_operating_power_yield_cancel_source_policy_and_device_loss_retain_dma(
) -> TestResult {
    for fault in 0..5 {
        let (f, calcap) = match calibrated() {
            Ok(f) => f,
            Err(e) => return TestResult::Fail(e),
        };
        let request = match request(&f) {
            Ok(r) => r,
            Err(e) => return TestResult::Fail(e),
        };
        let cap = Cap::bootstrap();
        let policy = Arc::new(IrqSafeSpinLock::new(domain()));
        let current = policy.clone();
        let mut operation = Box::pin(f.lifecycle.prepare_operating8821c_with(
            &f.factory,
            power_source(artifact(&request), cap),
            move || Ok(current.lock().clone()),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        if operation.as_mut().poll(&mut cx).is_ready()
            || word(&f.port.0.lock().bytes, 0x1d00) != 0x0b0a0908
        {
            return TestResult::Fail("C21 power fixture missed real first TXAGC publication/yield");
        }
        let calls = f.port.0.lock().calls;
        match fault {
            0 => (),
            1 => cap.revoke(),
            2 => calcap.revoke(),
            3 => policy.lock().rules[0].flags = RegFlags::NO_IR,
            _ => f.port.0.lock().fail = Some(calls),
        }
        if fault != 0 && !matches!(operation.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return TestResult::Fail(
                "C21 power continuation ignored current authority after yield",
            );
        }
        drop(operation);
        if f.lifecycle.status().stage != Stage::Failed
            || narf_scheduler::block_on(f.lifecycle.operating_info8821c()).is_some()
            || fault < 4 && f.port.0.lock().calls != calls
        {
            return TestResult::Fail(
                "C21 cancelled/revoked power continuation wrote or published readiness",
            );
        }
        let drops = f.drops.clone();
        drop(f);
        if drops.load(Ordering::SeqCst) != 0 {
            return TestResult::Fail("C21 cancelled operating power released native DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c/power",
    smoke_rtw8821ce_operating_power_yield_cancel_source_policy_and_device_loss_retain_dma
);
