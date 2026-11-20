//! Native EU-only measurement, source retention and literal USB descriptor cases.
use super::super::super::{
    firmware_transport::{Executable, Owner},
    firmware_transport_tests::{initialized_registered_firmware, Fake, Op},
    ht_runtime::{self, Grant},
    wmm_runtime::Proof,
};
use super::{domain, native_calibration, native_permission};
use alloc::{sync::Arc, vec, vec::Vec};
use narf_capabilities::{Cap, Read};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

pub(super) const WMM: [u8; 26] = [
    221, 24, 0, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa5, 0, 0, 0x27, 0xa5, 0, 0, 0x42, 0x43, 94, 0,
    0x62, 0x32, 47, 0,
];
pub(super) fn elements(tx: u8) -> Vec<u8> {
    // Literal 1SS LGI HT20 capability plus primary1 operation/basic MCS0..7.
    let mut b = vec![45, 26, 12, 0, 0, tx];
    b.resize(28, 0);
    b[17] = 1;
    b.extend_from_slice(&[61, 22, 1, 0, 0, 0, 0, 0, 255]);
    b.resize(52, 0);
    b
}
pub(super) fn artifact(base: &Proof, executable: Executable) -> Vec<u8> {
    let (factory, digest, _) = base.calibration().binding();
    let mut b = vec![0; 1184];
    b[..4].copy_from_slice(b"N8HT");
    b[4..8].copy_from_slice(&[1, 0, 160, 0]);
    b[8..12].copy_from_slice(&1184u32.to_le_bytes());
    b[12..16].copy_from_slice(&factory[..4]);
    b[16..48].copy_from_slice(&ht_runtime::request(base, executable).binding);
    b[48..77].copy_from_slice(&factory);
    b[80..112].copy_from_slice(&digest);
    b[112..118].copy_from_slice(&factory[8..14]);
    b[118..124].copy_from_slice(&[1, 20, 1, 0, 0, 0]);
    b[124..126].copy_from_slice(&8i16.to_le_bytes());
    b[126..128].copy_from_slice(&80i16.to_le_bytes());
    // Inert dimensional upper envelopes, never registered as physical measurements.
    for row in b[160..].chunks_exact_mut(128) {
        for (i, b) in row.chunks_exact_mut(2).enumerate() {
            b.copy_from_slice(&(i as i16 * 2).to_le_bytes());
        }
    }
    b
}
pub(super) struct Qualification {
    pub(super) proof: Arc<Proof>,
    pub(super) grant: Arc<Grant>,
    pub(super) cap: Cap<FirmwareBlob, Read>,
    pub(super) legacy: Cap<FirmwareBlob, Read>,
    pub(super) source: Cap<FirmwareBlob, Read>,
    pub(super) domain: Arc<IrqSafeSpinLock<narf_wireless::reg::RegulatoryDomain>>,
}
pub(super) fn qualify(firmware: &Arc<Owner<Fake>>) -> Result<Qualification, &'static str> {
    let factory = firmware.factory().ok_or("EU HT factory")?;
    let legacy = Cap::bootstrap();
    let cap = Cap::bootstrap();
    let domain = Arc::new(IrqSafeSpinLock::new(domain(17)));
    let proof = Proof::model(
        native_calibration(factory),
        native_permission(factory),
        legacy,
        domain.clone(),
    );
    let executable = firmware.executable().ok_or("EU HT executable")?;
    let source = executable
        .source_cap()
        .ok_or("EU HT missing actual uploaded cap")?;
    let grant = Arc::new(
        Grant::parse(
            proof.clone(),
            executable,
            factory.ht40_power[0],
            &artifact(&proof, executable),
            Some([7; 32]),
            cap,
        )
        .map_err(|_| "EU inert HT measurement parser")?,
    );
    Ok(Qualification {
        proof,
        grant,
        cap,
        legacy,
        source,
        domain,
    })
}
fn result(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn smoke_rtl8188eu_ht20_exact_eu_gain_source_and_measurement_binding() -> TestResult {
    result(|| {
        let (control, firmware) = initialized_registered_firmware();
        let q = qualify(&firmware)?;
        if q.grant.gains() != Ok([30; 8]) {
            return Err("EU source zero-delta/factory/curve ceiling changed");
        }
        let executable = firmware.executable().ok_or("EU executable")?;
        let b = artifact(&q.proof, executable);
        for at in [
            0, 4, 6, 8, 12, 14, 16, 48, 76, 77, 80, 112, 118, 119, 120, 121, 128,
        ] {
            let mut wrong = b.clone();
            wrong[at] ^= 1;
            if Grant::parse(
                q.proof.clone(),
                executable,
                32,
                &wrong,
                Some([7; 32]),
                q.cap,
            )
            .is_ok()
            {
                return Err("EU malformed/foreign/old program granted HT");
            }
        }
        if Grant::parse(q.proof.clone(), executable, 32, &b, None, q.cap).is_ok()
            || Grant::parse(
                q.proof.clone(),
                executable,
                32,
                &b[..1183],
                Some([7; 32]),
                q.cap,
            )
            .is_ok()
        {
            return Err("EU unsigned/truncated HT granted");
        }
        let mut unknown = b.clone();
        for v in unknown[160..].chunks_exact_mut(2) {
            v.copy_from_slice(&i16::MAX.to_le_bytes());
        }
        if Grant::parse(
            q.proof.clone(),
            executable,
            32,
            &unknown,
            Some([7; 32]),
            q.cap,
        )
        .is_ok()
        {
            return Err("EU unknown measured MCS permitted");
        }
        let before = control.0.lock().ops.len();
        q.source.revoke();
        if q.grant.gains().is_ok()
            || narf_scheduler::block_on(firmware.read8(0x100)).is_ok()
            || control.0.lock().ops.len() != before
        {
            return Err("EU revoked executable reached native EP0");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_exact_eu_gain_source_and_measurement_binding
);
fn smoke_rtl8188eu_ht20_parked_program_native_error_cancel_and_sources() -> TestResult {
    result(|| {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        for case in 0..5 {
            let (control, firmware) = initialized_registered_firmware();
            let q = qualify(&firmware)?;
            let receive =
                super::super::super::receive_runtime::Permission::from_domain(&domain(17))
                    .map_err(|_| "EU RX permission")?;
            let mut receiver = super::super::super::receive_runtime::Receiver::new(
                firmware.clone(),
                super::super::super::firmware_transport_tests::Bulk::new(control.clone()),
                receive,
            )
            .map_err(|_| "EU retained receiver")?;
            if case == 1 {
                control.0.lock().fail_write = Some(0xe14);
            }
            if case >= 2 {
                control.0.lock().pending_write = Some(0xe10);
            }
            let result = {
                let mut operation = alloc::boxed::Box::pin(receiver.install_ht(q.grant.clone()));
                let first = operation
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()));
                if case >= 2 {
                    if first != Poll::Pending || !control.0.lock().active_td {
                        return Err("EU HT cancellation did not own EP0 TD");
                    }
                    if case == 3 {
                        q.cap.revoke();
                    } else if case == 4 {
                        q.source.revoke();
                    }
                    if case >= 3
                        && operation
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop()))
                            .is_pending()
                    {
                        return Err("EU revoked held HT EP0 republished");
                    }
                    None
                } else {
                    Some(first)
                }
            };
            let model = control.0.lock();
            if model.regs[0x100] & 0xc0 != 0 || model.unsafe_reuses != 0 {
                return Err("EU parked HT opened MAC or reused EP0");
            }
            if case == 0
                && (result != Some(Poll::Ready(Ok(())))
                    || !model
                        .ops
                        .iter()
                        .any(|op| matches!(op,Op::Write(0xe10,b) if b==&[30;4])))
            {
                return Err("EU parked native HT writes failed");
            }
            if case == 1 && !matches!(result, Some(Poll::Ready(Err(_)))) {
                return Err("EU HT native write failure ignored");
            }
            if case >= 2 && !model.active_td {
                return Err("EU cancelled HT TD was reclaimed");
            }
            if case >= 1 && receiver.phase() != super::super::super::receive_runtime::Phase::Failed
            {
                return Err("EU cancelled/failed HT owner was reusable");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/ht20",
    smoke_rtl8188eu_ht20_parked_program_native_error_cancel_and_sources
);
