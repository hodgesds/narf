//! Actual immutable signed registry records fence native CE/HTT and host
//! publication; no loader-name reopen or caller authorization boolean.
use super::*;
use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};
fn attach(
    h: &Harness,
) -> Result<
    [narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>; 2],
    &'static str,
> {
    let (source, caps) = crate::ath10k::firmware_source::fixture()?;
    h.model(|m| m.sources = Some(source));
    Ok(caps)
}
fn smoke_ath10k_source_revoked_before_native_station_publication_has_no_receipt() -> TestResult {
    (|| {
        for index in 0..2 {
            let h = Harness::new(4, Dialect::Tlv, true);
            let caps = attach(&h)?;
            h.scan()?;
            let before = h.model(|m| m.sent.len());
            caps[index].revoke();
            if !matches!(
                drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                Poll::Ready(Err(_))
            ) || h.model(|m| m.sent.len()) != before
                || !h.never_opened()
            {
                return Err("revoked executable/BDF published native station state");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/source",
    smoke_ath10k_source_revoked_before_native_station_publication_has_no_receipt
);
fn smoke_ath10k_source_revoke_inside_native_wait_keeps_old_owner_after_reinstall() -> TestResult {
    (|| {
        for index in 0..2 {
            let h = Harness::new(4, Dialect::Tlv, true);
            let caps = attach(&h)?;
            h.scan()?;
            h.model(|m| {
                m.station = Some(StationFixture::new());
                m.station.as_mut().unwrap().stall = Some(2);
            });
            let mut f = Box::pin(h.device.associate_for_test(h.request(), [0x73; 32]));
            let mut cx = Context::from_waker(Waker::noop());
            for _ in 0..4096 {
                if f.as_mut().poll(&mut cx).is_ready() {
                    return Err("source held native START absent");
                }
            }
            caps[index].revoke();
            if !matches!(f.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
                return Err("native waiter ignored revoked exact source");
            }
            drop(f);
            let (fresh, _) = crate::ath10k::firmware_source::fixture()?;
            fresh.check().map_err(|_| "fresh replacement source")?;
            h.pump();
            if !h.never_opened()
                || !h.model(|m| m.ce.as_ref().unwrap().retained())
                || !matches!(
                    drive(h.device.associate_for_test(h.request(), [0x73; 32])),
                    Poll::Ready(Err(_))
                )
            {
                return Err("source reinstall relabelled uncertain live CE/native station");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/source",
    smoke_ath10k_source_revoke_inside_native_wait_keeps_old_owner_after_reinstall
);
fn smoke_ath10k_source_revoke_at_rx_ipc_and_guard_free_stack_boundary_denies_old_copy() -> TestResult
{
    use crate::ath10k::interface::ReceivePoint;
    (|| {
        for index in 0..2 {
            for point in [ReceivePoint::AfterFrameAllocation, ReceivePoint::BeforeCallbackAdmission] {
                let h = Harness::new(4, Dialect::Tlv, true);
                let caps = attach(&h)?;
                h.join()?;
                let fired = Arc::new(AtomicBool::new(false));
                let flag = fired.clone();
                let authorized = Arc::new(AtomicBool::new(false));
                let authorization = authorized.clone();
                let cap = caps[index];
                h.device.set_receive_hook_for_test(move |p| {
                    if p == point && !flag.swap(true, Ordering::AcqRel) {
                        authorization.store(caps.iter().all(|c|c.invoke(narf_capabilities::NoopOp).is_ok()),Ordering::Release);
                        cap.revoke();
                    }
                });
                let (_, down) = packets();
                let before = narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets;
                h.model(|m| { let f=m.data.as_mut().unwrap(); let frame=f.downlink(&down); f.queue.push_back(frame); });
                h.pump();
                if !fired.load(Ordering::Acquire) || !authorized.load(Ordering::Acquire) || !h.closed()
                    || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before {
                    return Err("revoked executable/BDF released a copied native RX into successor publication");
                }
                // An authorized IPC copy already exists when the later stack
                // callback hook fires. Revocation suppresses that callback;
                // it cannot retroactively unpublish a prior IPC transaction.
                if h.received(&down)!=(point==ReceivePoint::BeforeCallbackAdmission) || h.received(&down) {
                    return Err("source revocation changed exact authorized IPC/callback ordering");
                }
                let (replacement,_)=crate::ath10k::firmware_source::fixture()?;
                replacement.check().map_err(|_|"replacement source registry")?;
                if cap.invoke(narf_capabilities::NoopOp).is_ok() {
                    return Err("source reinstall resurrected the exact revoked blob cap");
                }
                h.model(|m| {let f=m.data.as_mut().unwrap();let later=f.downlink(&down);f.queue.push_back(later);});
                h.pump();
                let (up,_)=packets();
                if !h.closed() || h.received(&down)
                    || h.device.enqueue(&up,narf_net::TxMeta::plain()).is_ok()
                    || narf_net::iface::lookup(&h.name).unwrap().stats.rx_packets != before {
                    return Err("source reinstall revived the old native receive/publication owner");
                }
            }
        }
        Ok(())
    })().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/source",
    smoke_ath10k_source_revoke_at_rx_ipc_and_guard_free_stack_boundary_denies_old_copy
);
fn smoke_ath10k_source_revoked_while_real_m4_pending_never_opens_and_keeps_payload() -> TestResult {
    (|| {
        let h = Harness::new(4, Dialect::Tlv, true);
        let caps = attach(&h)?;
        h.model(|m| m.data.as_mut().unwrap().hold_m4 = true);
        h.scan()?;
        let mut f = Box::pin(h.device.associate_for_test(h.request(), [0x73; 32]));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..4096 {
            if f.as_mut().poll(&mut cx).is_ready() {
                return Err("source held native M4 absent");
            }
        }
        caps[1].revoke();
        if !matches!(f.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return Err("revoked BDF committed pending M4");
        }
        drop(f);
        h.pump();
        if !h.never_opened()
            || !h.model(|m| {
                m.ce.as_ref().unwrap().retained()
                    && m.inner.storage.as_ref().unwrap().tx.pending() == 1
            })
        {
            return Err("source revocation reclaimed uncertain M4 payload or admitted carrier");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/source",
    smoke_ath10k_source_revoked_while_real_m4_pending_never_opens_and_keeps_payload
);
