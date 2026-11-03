//! Explicit/private native WMI receive and final source/copy fences.
use super::*;
use core::sync::atomic::{AtomicU32, Ordering};
async fn register(h: &Harness, b: &Bound, source: Arc<Source>, prefix: &[u8]) -> Result<(), i32> {
    let a = RadioControlAuthority::bind(b.admin.clone(), &b.iface, 0, b.index, source)
        .and_then(RadioControlAuthority::reserve)
        .map_err(|_| 1)?;
    let emission = a.native_emission_for(b.iface.as_ref()).map_err(|_| 1)?;
    let event = a.event_authority().map_err(|_| 1)?;
    let install = b
        .subscriptions
        .prepare(event, emission.clone(), 0xd0, prefix)?;
    let mut r = h.device.radio.lock().await;
    r.bind_roc_subscriptions(b.subscriptions.clone())
        .map_err(|_| 16)?;
    let retired = r
        .install_roc_filter(install, &|| {
            if emission.current() {
                Ok(())
            } else {
                Err(radio::Error::Failed)
            }
        })
        .await
        .map_err(|_| 5)?;
    drop(r);
    drop(retired);
    Ok(())
}
fn response(h: &Harness, frequency: u16, ra: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 24];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&ra);
    frame[10..16].copy_from_slice(&[2, 0, 0, 0, 0x10, 0xcc]);
    frame[16..22].fill(255);
    frame.extend_from_slice(body);
    h.model(|m| {
        let old = m.frequency;
        m.frequency = frequency;
        super::super::super::super::management_frame(m, frame.clone());
        m.frequency = old;
    });
    frame
}
fn raw_messages(source: &Source) -> Vec<Vec<u8>> {
    source
        .messages
        .lock()
        .iter()
        .filter(|m| m.get(16) == Some(&59))
        .cloned()
        .collect()
}
fn attribute(mut b: &[u8], wanted: u16) -> Option<&[u8]> {
    while b.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes([b[0], b[1]]));
        if len < 4 || len > b.len() {
            return None;
        }
        if u16::from_ne_bytes([b[2], b[3]]) & 0x3fff == wanted {
            return Some(&b[4..len]);
        }
        b = b.get((len + 3) & !3..)?;
    }
    None
}
async fn private(
    h: &Harness,
    b: &Bound,
    a: &RadioControlAuthority,
    request: MgmtTxRequest,
) -> Result<bool, radio::Error> {
    let emission = a
        .native_emission_for(b.iface.as_ref())
        .map_err(|_| radio::Error::Failed)?;
    let owner = owner(b, a).map_err(|_| radio::Error::Failed)?;
    let mut r = h.device.radio.lock().await;
    r.bind_roc_subscriptions(b.subscriptions.clone())?;
    r.begin_private_frame(0, owner, 91, &request, || {
        h.policy.lock().clone().ok_or(radio::Error::Unsupported)
    })
    .await?;
    r.begin_roc_action(91, &request, emission.clone(), || {
        h.policy.lock().clone().ok_or(radio::Error::Unsupported)
    })
    .await?;
    drop(r);
    for _ in 0..65536 {
        if !emission.current() {
            return Err(radio::Error::Failed);
        }
        service(h, Some(b)).await?;
        if let Some(status) = h.device.radio.lock().await.take_roc_action_status(91)? {
            return Ok(status);
        }
        narf_scheduler::yield_now().await;
    }
    Err(radio::Error::Timeout)
}
fn raw_registration() -> Result<(), &'static str> {
    for (v, d) in [(1, Dialect::Main), (4, Dialect::Tlv), (6, Dialect::TenFour)] {
        let h = harness(v, d, false, true);
        let b = Bound::new(&h)?;
        let before = h.model(|m| m.sent.len());
        if !matches!(
            drive(register(&h, &b, b.source.clone(), &[4, 9])),
            Poll::Ready(Ok(()))
        ) || h.model(|m| m.sent.len()) != before
            || h.device.radio.try_lock().unwrap().scan_in_progress()
        {
            return Err("registration manufactured native RF/capture/peer authority");
        }
        // Real overlap semantics apply across endpoints, including empty prefixes.
        let other = Arc::new(Source::new());
        if drive(register(&h, &b, other.clone(), &[4])) != Poll::Ready(Err(114))
            || drive(register(&h, &b, other.clone(), &[])) != Poll::Ready(Err(114))
        {
            return Err("overlapping Action registration replaced original source");
        }
        let old = response(&h, 5180, OWN, &[4, 9, 1]);
        // No native ROC exists: registration alone cannot surface even an
        // actual WMI event at a geometrically valid channel.
        if !matches!(
            drive(register(&h, &b, other.clone(), &[4, 10])),
            Poll::Ready(Ok(()))
        ) || !raw_messages(&b.source).is_empty()
        {
            return Err("ungranted WMI prefix became registered raw capture");
        }
        arm(&h, d, false, true);
        start(&h, &b)?;
        response(&h, 2412, OWN, &[4, 9, 2]);
        response(&h, 5180, [255; 6], &[4, 9, 3]);
        response(&h, 5180, OWN, &[8, 1, 4]);
        response(&h, 5180, OWN, &[4, 11, 5]);
        let wanted = response(&h, 5180, OWN, &[4, 9, 6]);
        for _ in 0..32 {
            if !matches!(drive(service(&h, Some(&b))), Poll::Ready(Ok(()))) {
                return Err("native WMI receive progress");
            }
        }
        let messages = raw_messages(&b.source);
        let [event] = messages.as_slice() else {
            return Err("native unicast/prefix/frequency admission omitted or duplicated response");
        };
        if attribute(&event[20..], 3) != Some(b.index.to_ne_bytes().as_slice())
            || attribute(&event[20..], 38) != Some(5180u32.to_ne_bytes().as_slice())
            || attribute(&event[20..], 51) != Some(wanted.as_slice())
            || attribute(&event[20..], 51) == Some(old.as_slice())
            || !raw_messages(&other).is_empty()
        {
            return Err(
                "native WMI event changed raw bytes/frequency/receiver or grafted old prefix",
            );
        }
        cancel(&h, &b)?;
    }
    Ok(())
}
fn smoke_ath10k_offchannel_registration_requires_real_foreign_unicast_wmi_and_prefix() -> TestResult
{
    raw_registration().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_offchannel_registration_requires_real_foreign_unicast_wmi_and_prefix
);

fn implicit_wait() -> Result<(), &'static str> {
    for protected in [false, true] {
        let h = harness(4, Dialect::Tlv, protected, true);
        if protected {
            h.join()?;
            let actual_htt_management = h.model(|m| {
                m.native_management.len() == 2
                    && m.native_management[0].get(..2) == Some(&[0xb0, 0])
                    && m.native_management[1].get(..2) == Some(&[0, 0])
                    && m.sent
                        .iter()
                        .filter(|bytes| {
                            bytes.get(..2) == Some(&[1, 0]) && bytes.get(8..10) == Some(&[1, 0x65])
                        })
                        .count()
                        == 2
                    && m.inner
                        .storage
                        .as_ref()
                        .is_some_and(|storage| storage.tx.pending() == 0)
            });
            if !actual_htt_management {
                return Err("secure private FRAME lacked actual HTT3 auth/assoc DMA terminals");
            }
        }
        let b = Bound::new(&h)?;
        if drive(register(&h, &b, b.source.clone(), &[4, 9])) != Poll::Ready(Ok(())) {
            return Err("private response registration");
        }
        let before = h.model(|m| m.sent.len());
        for malformed in 0..8 {
            let mut request = action();
            match malformed {
                0 => request.duration = 1,
                1 => request.duration = 9,
                2 => request.duration = 501,
                3 => request.offchannel_ok = false,
                4 => request.frequency_mhz = 0,
                5 => request.frame[10] ^= 2,
                6 => request.frame[24] = 8,
                _ => request.frequency_mhz = 2412, // NO_CCK needs real rate authority.
            }
            let domain = h.policy.lock().clone().ok_or("private admission domain")?;
            let r = h.device.radio.try_lock().unwrap();
            if r.validate_private_frame(91, &request, &domain).is_ok() || r.scan_in_progress() {
                return Err("malformed private FRAME obtained RF ownership before validation");
            }
        }
        if h.model(|m| m.sent.len()) != before {
            return Err("pure private FRAME admission emitted native commands");
        }
        let signals = arm(&h, Dialect::Tlv, protected, true);
        let a = b.authority()?;
        let mut request = action();
        request.duration = 100;
        let mut operation = alloc::boxed::Box::pin(private(&h, &b, &a, request));
        let mut cx = Context::from_waker(Waker::noop());
        let mut entered_wait = false;
        for _ in 0..512 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("private FRAME invented completed response wait at publication");
            };
            if signals.descriptors.load(Ordering::Acquire) != 0
                && h.device.radio.try_lock().is_some()
            {
                entered_wait = true;
                break;
            }
        }
        if !entered_wait || signals.descriptors.load(Ordering::Acquire) != 1 {
            return Err("private response wait did not follow its actual native descriptor");
        }
        // Source can inspect a native response only while actual private
        // RF ownership remains, even though no public ROC cookie is emitted.
        let wanted = response(&h, 5180, OWN, &[4, 9, 0x44]);
        for _ in 0..128 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("native packet ACK cut off the private response tail");
            };
            if !raw_messages(&b.source).is_empty() {
                break;
            }
        }
        if raw_messages(&b.source)
            .iter()
            .all(|m| attribute(&m[20..], 51) != Some(wanted.as_slice()))
            || b.source
                .messages
                .lock()
                .iter()
                .any(|m| matches!(m.get(16), Some(55 | 56)))
            || signals.deletes.load(Ordering::Acquire) != 0
        {
            return Err("private wait lost response or released its DA peer/publicly aliased ROC");
        }
        h.device
            .radio
            .try_lock()
            .unwrap()
            .expire_roc_for_test()
            .map_err(|_| "actual private native interval")?;
        signals.stop_receipt.store(false, Ordering::Release);
        for _ in 0..64 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("private host timer invented native scan/home terminal");
            }
        }
        signals.stop_receipt.store(true, Ordering::Release);
        if !matches!(drive(operation.as_mut()), Poll::Ready(Ok(true)))
            || h.device.radio.try_lock().unwrap().scan_in_progress()
            || signals.deletes.load(Ordering::Acquire) != 1
            || protected && !h.device.link_up()
        {
            return Err("private ACK/wait did not retain exact STOP/peer/home retirement");
        }
        drop(operation);
        drop(a);
    }
    Ok(())
}
fn smoke_ath10k_private_frame_keeps_response_window_after_ack_until_native_home_terminal(
) -> TestResult {
    implicit_wait().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_private_frame_keeps_response_window_after_ack_until_native_home_terminal
);

fn copied_boundaries() -> Result<(), &'static str> {
    for boundary in 0..5 {
        let h = harness(4, Dialect::Tlv, false, true);
        let b = Bound::new(&h)?;
        if drive(register(&h, &b, b.source.clone(), &[4, 9])) != Poll::Ready(Ok(())) {
            return Err("copied-boundary native subscription");
        }
        arm(&h, Dialect::Tlv, false, true);
        start(&h, &b)?;
        response(&h, 5180, OWN, &[4, 9, 0x55]);
        let mut copy = None;
        for _ in 0..32 {
            let mut r = h.device.radio.try_lock().unwrap();
            if !matches!(
                drive(r.service_roc(
                    false,
                    || h.policy.lock().clone().ok_or(radio::Error::Unsupported),
                    || Ok(())
                )),
                Poll::Ready(Ok(_))
            ) {
                return Err("native copied-prefix progress");
            }
            copy = r.take_roc_capture();
            if copy.is_some() {
                break;
            }
        }
        let copy = copy.ok_or("actual native WMI copy before callback boundary")?;
        let ran = Arc::new(AtomicU32::new(0));
        let entered = ran.clone();
        let radio = h.device.radio.clone();
        let policy = h.policy.clone();
        let subscriptions = b.subscriptions.clone();
        let source = b.source.clone();
        let iface = b.iface.clone();
        let admin = b.admin.clone();
        let index = b.index;
        *b.source.callback.lock() = Some(Callback(alloc::boxed::Box::new(move || {
            // Preparation's dynamic source callbacks run outside native
            // State. Reentrant mutation is real, not a cached bool/epoch edit.
            if radio.try_lock().is_none() {
                entered.store(100, Ordering::Release);
                return;
            }
            match boundary {
                0 => {
                    let a = RadioControlAuthority::bind(admin, &iface, 0, index, source.clone())
                        .and_then(RadioControlAuthority::reserve)
                        .unwrap();
                    let guard = a.native_emission_for(iface.as_ref()).unwrap();
                    let install = subscriptions
                        .prepare(a.event_authority().unwrap(), guard.clone(), 0xd0, &[4, 10])
                        .unwrap();
                    let result = drive(async {
                        let mut r = radio.lock().await;
                        let retired = r
                            .install_roc_filter(install, &|| {
                                if guard.current() {
                                    Ok(())
                                } else {
                                    Err(radio::Error::Failed)
                                }
                            })
                            .await?;
                        drop(r);
                        drop(retired);
                        Ok::<(), radio::Error>(())
                    });
                    entered.store(
                        if matches!(result, Poll::Ready(Ok(()))) {
                            1
                        } else {
                            100
                        },
                        Ordering::Release,
                    );
                }
                1 => {
                    policy.lock().as_mut().unwrap().rules[1].flags =
                        narf_wireless::reg::RegFlags::NO_IR;
                    entered.store(1, Ordering::Release);
                }
                2 => {
                    source.live.retire().notify();
                    entered.store(1, Ordering::Release);
                }
                3 => {
                    radio.try_lock().unwrap().expire_roc_for_test().unwrap();
                    entered.store(1, Ordering::Release);
                }
                _ => {
                    entered.store(1, Ordering::Release);
                }
            }
        })));
        let prepared = copy.prepare(b.iface.as_ref());
        let domain = h.policy.lock().clone().ok_or("current copied-domain")?;
        let result = prepared.and_then(|p| copy.deliver(p, &domain));
        if ran.load(Ordering::Acquire) != 1
            || result.is_ok() != (boundary == 4)
            || raw_messages(&b.source).len() != usize::from(boundary == 4)
        {
            return Err("copied WMI crossed reentrant filter/source/policy/native-expiry boundary or held State");
        }
    }
    Ok(())
}
fn smoke_ath10k_offchannel_copied_receive_rechecks_after_source_callbacks_before_delivery(
) -> TestResult {
    copied_boundaries().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_offchannel_copied_receive_rechecks_after_source_callbacks_before_delivery
);

fn private_source_loss() -> Result<(), &'static str> {
    for source_loss in [false, true] {
        let h = harness(4, Dialect::Tlv, false, true);
        let b = Bound::new(&h)?;
        if drive(register(&h, &b, b.source.clone(), &[4, 9])) != Poll::Ready(Ok(())) {
            return Err("retained private wait source");
        }
        let signals = arm(&h, Dialect::Tlv, false, true);
        let a = b.authority()?;
        let mut request = action();
        request.duration = 500;
        let mut operation = alloc::boxed::Box::pin(private(&h, &b, &a, request));
        let mut cx = Context::from_waker(Waker::noop());
        let mut entered_wait = false;
        for _ in 0..512 {
            if operation.as_mut().poll(&mut cx).is_ready() {
                return Err("private cleanup fixture did not retain native wait");
            };
            if signals.descriptors.load(Ordering::Acquire) != 0
                && h.device.radio.try_lock().is_some()
            {
                entered_wait = true;
                break;
            }
        }
        if !entered_wait || signals.descriptors.load(Ordering::Acquire) != 1 {
            return Err("private source-loss boundary did not reach its native descriptor");
        }
        drop(operation);
        drop(a);
        if source_loss {
            b.source.live.retire().notify();
        } else {
            h.device.close_before_lock_for_test();
        }
        let before = raw_messages(&b.source).len();
        response(&h, 5180, OWN, &[4, 9, 0x66]);
        signals.stop_receipt.store(false, Ordering::Release);
        let mut cleanup = alloc::boxed::Box::pin(async {
            let mut r = h.device.radio.lock().await;
            r.service_roc(
                true,
                || h.policy.lock().clone().ok_or(radio::Error::Unsupported),
                || Ok(()),
            )
            .await
        });
        for _ in 0..64 {
            if cleanup.as_mut().poll(&mut cx).is_ready() {
                return Err("lost private waiter invented terminal cleanup");
            }
        }
        signals.stop_receipt.store(true, Ordering::Release);
        if !matches!(drive(cleanup.as_mut()), Poll::Ready(Ok(None))) {
            return Err("retained private wait lost exact STOP/peer terminal cleanup");
        }
        drop(cleanup);
        if raw_messages(&b.source).len() != before
            || h.device.radio.try_lock().unwrap().scan_in_progress()
            || signals.deletes.load(Ordering::Acquire) != 1
        {
            return Err(
                "lost private source emitted a tail response or abandoned native ownership",
            );
        }
    }
    Ok(())
}
fn smoke_ath10k_private_waiter_source_or_host_loss_retains_stop_without_stale_response(
) -> TestResult {
    private_source_loss().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/offchannel",
    smoke_ath10k_private_waiter_source_or_host_loss_retains_stop_without_stale_response
);
