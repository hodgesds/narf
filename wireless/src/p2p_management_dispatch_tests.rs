//! Real delegated control-WDEV REGISTER_FRAME dispatch. A held driver
//! callback is only a shared boundary model, never a native capture grant.
use super::*;
fn request(
    child: &Child,
    source: Arc<Source>,
    frame_type: u16,
) -> Result<Vec<Vec<u8>>, &'static str> {
    dispatch::send(
        child,
        source,
        58,
        &[
            (101, &frame_type.to_ne_bytes()),
            (91, &[4, 9, 0x50, 0x6f, 0x9a, 9]),
        ],
    )
}
fn terminal() -> Result<(), &'static str> {
    let parent = fixture()?;
    let child = paired_child(&parent)?;
    let source = Arc::new(Source::new());
    if !request(&child, source.clone(), 0xd0)?.is_empty() {
        return Err("management registration acknowledged queued callback");
    }
    narf_scheduler::poll_one_round();
    if child.radio.inner.start_polls.load(Ordering::Acquire) == 0
        || !source.1.lock().is_empty()
        || child.radio.inner.management_registration.lock().is_some()
        || child.radio.link_up()
        || narf_net::iface::lookup(child.radio.name()).is_some()
    {
        return Err("REGISTER_FRAME invented terminal/native started/UP/netdev facts");
    }
    dispatch::complete(&child);
    if child.radio.inner.management_registration.lock().as_ref()
        != Some(&(0xd0, alloc::vec![4, 9, 0x50, 0x6f, 0x9a, 9]))
        || source.1.lock().len() != 1
        || source.1.lock()[0].get(16..20) != Some(&0i32.to_ne_bytes())
    {
        return Err("actual management callback lost its frame type, prefix or terminal ACK");
    }
    let invalid = request(&child, Arc::new(Source::new()), 0xd1)?;
    if invalid.len() != 1 || invalid[0].get(16..20) != Some(&(-22i32).to_ne_bytes()) {
        return Err("management selector accepted frame-control flags as a subtype");
    }
    child
        .radio
        .inner
        .management_errno
        .store(114, Ordering::Release);
    let refused = Arc::new(Source::new());
    if !request(&child, refused.clone(), 0xd0)?.is_empty() {
        return Err("native management refusal was not deferred");
    }
    dispatch::complete(&child);
    if refused.1.lock().len() != 1
        || refused.1.lock()[0].get(16..20) != Some(&(-114i32).to_ne_bytes())
    {
        return Err("native EALREADY was replaced by a queued success or unrelated errno");
    }
    Ok(())
}
fn control_wdev_management_registration_waits_for_real_callback_and_preserves_native_errno(
) -> TestResult {
    terminal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_management_registration_waits_for_real_callback_and_preserves_native_errno
);
fn lost() -> Result<(), &'static str> {
    for cause in 0..5 {
        let parent = fixture()?;
        let child = paired_child(&parent)?;
        let source = Arc::new(Source::new());
        if !request(&child, source.clone(), 0xd0)?.is_empty() {
            return Err("pending actual management registration admission");
        }
        narf_scheduler::poll_one_round();
        match cause {
            0 => source.0.store(false, Ordering::Release),
            1 => child.cap.revoke(),
            2 => parent.daemon.revoke(),
            3 => {
                child.radio.inner.generation.fetch_add(1, Ordering::AcqRel);
            }
            _ => {
                parent
                    .admin
                    .move_to_net_ns(27)
                    .map_err(|_| "actual management parent namespace transfer")?;
            }
        }
        dispatch::complete(&child);
        if child.radio.inner.management_registration.lock().is_some()
            || child.radio.inner.start_drops.load(Ordering::Acquire) != 1
            || source
                .1
                .lock()
                .iter()
                .any(|reply| reply.get(16..20) == Some(&0i32.to_ne_bytes()))
        {
            return Err("closed/revoked/transferred/replaced management owner registered or published old success");
        }
    }
    Ok(())
}
fn control_wdev_management_registration_rechecks_exact_source_grants_namespace_and_mode(
) -> TestResult {
    lost().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_management_registration_rechecks_exact_source_grants_namespace_and_mode
);
