//! Real WDEV/namespace/deferred FRAME route. The callback is a boundary
//! model; native TXS and dual packet retirement are tested in MT76 itself.
use super::*;
static EVENTS: IrqSafeSpinLock<Vec<(u64, u32, Vec<u8>)>> = IrqSafeSpinLock::new(Vec::new());
static CAPTURING: AtomicBool = AtomicBool::new(false);
fn event(namespace: u64, group: u32, bytes: &[u8]) {
    if CAPTURING.load(Ordering::Acquire) && bytes.get(16) == Some(&60) {
        EVENTS.lock().push((namespace, group, bytes.to_vec()));
    }
}
struct Capture(Option<fn(u64, u32, &[u8])>);
impl Capture {
    fn new() -> Self {
        EVENTS.lock().clear();
        CAPTURING.store(true, Ordering::Release);
        Self(narf_net::netlink_generic::install_event_sink(event))
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        CAPTURING.store(false, Ordering::Release);
        if let Some(old) = self.0 {
            narf_net::netlink_generic::install_event_sink(old);
        }
        EVENTS.lock().clear();
    }
}
fn attribute(mut bytes: &[u8], wanted: u16) -> Option<&[u8]> {
    while bytes.len() >= 4 {
        let length = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if length < 4 || length > bytes.len() {
            return None;
        }
        if u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff == wanted {
            return Some(&bytes[4..length]);
        }
        bytes = bytes.get((length + 3) & !3..)?;
    }
    None
}
fn frame(child: &Child) -> Vec<u8> {
    let mut bytes = alloc::vec![0;30];
    bytes[0] = 0xd0;
    bytes[4..10].copy_from_slice(&[2, 0, 0, 0, 0x79, 9]);
    bytes[10..16].copy_from_slice(&child.radio.mac());
    bytes[16..22].fill(0xff);
    bytes[24..].copy_from_slice(&[4, 9, 0x50, 0x6f, 0x9a, 9]);
    bytes
}
fn request(child: &Child, source: Arc<Source>, frame: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    dispatch::send(
        child,
        source,
        59,
        &[
            (38, &2412u32.to_ne_bytes()),
            (51, frame),
            (87, &25u32.to_ne_bytes()),
            (108, &[]),
        ],
    )
}
fn terminal() -> Result<(), &'static str> {
    let _capture = Capture::new();
    for ack in [false, true] {
        EVENTS.lock().clear();
        let parent = fixture()?;
        let child = child(&parent, None, 27)?;
        child.radio.management_tx_ack.store(ack, Ordering::Release);
        let source = Arc::new(Source::new());
        let frame = frame(&child);
        if !request(&child, source.clone(), &frame)?.is_empty() {
            return Err("FRAME returned cookie before actual callback completed");
        }
        narf_scheduler::poll_one_round();
        if child.radio.inner.start_polls.load(Ordering::Acquire) == 0
            || child.radio.management_tx.lock().is_some()
            || !EVENTS.lock().is_empty()
            || !source.1.lock().is_empty()
            || child.radio.link_up()
            || narf_net::iface::lookup(child.radio.name()).is_some()
        {
            return Err("pending WDEV FRAME invented ACK/cookie/native completion or a netdev");
        }
        dispatch::complete(&child);
        let sent = child
            .radio
            .management_tx
            .lock()
            .clone()
            .ok_or("real management callback missing")?;
        if sent.0 == 0 || sent.1 != 2412 || sent.2 != frame || !sent.3 || sent.4 != 25 {
            return Err("WDEV FRAME lost exact cookie/frame/channel/options");
        }
        let events = EVENTS.lock().clone();
        let [(namespace, group, message)] = events.as_slice() else {
            return Err("management completion omitted or duplicated actual status event");
        };
        if *namespace != 27
            || *group != 19
            || message.get(4..6) != Some(crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes().as_slice())
            || message.get(8..16) != Some([0; 8].as_slice())
            || attribute(&message[20..], 153)
                != Some(child.registration.id().to_ne_bytes().as_slice())
            || attribute(&message[20..], 3).is_some()
            || attribute(&message[20..], 51) != Some(frame.as_slice())
            || attribute(&message[20..], 88) != Some(sent.0.to_ne_bytes().as_slice())
            || attribute(&message[20..], 92).is_some() != ack
        {
            return Err("FRAME status changed real WDEV/namespace/cookie/frame or fabricated ACK");
        }
        let replies = source.1.lock();
        let reply = replies
            .iter()
            .find(|m| m.get(16) == Some(&59))
            .ok_or("terminal FRAME cookie reply missing")?;
        if attribute(&reply[20..], 88) != Some(sent.0.to_ne_bytes().as_slice())
            || !replies
                .iter()
                .any(|m| m.get(16..20) == Some(0i32.to_ne_bytes().as_slice()))
        {
            return Err("terminal management cookie/ACK lost original actual request");
        }
    }
    Ok(())
}
fn control_wdev_frame_waits_for_native_callback_and_reports_exact_multicast_status() -> TestResult {
    terminal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_frame_waits_for_native_callback_and_reports_exact_multicast_status
);

fn lost() -> Result<(), &'static str> {
    let _capture = Capture::new();
    for cause in 0..5 {
        EVENTS.lock().clear();
        let parent = fixture()?;
        let child = paired_child(&parent)?;
        let source = Arc::new(Source::new());
        if !request(&child, source.clone(), &frame(&child))?.is_empty() {
            return Err("held FRAME admission completed early");
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
                    .move_to_net_ns(29)
                    .map_err(|_| "actual FRAME parent namespace transfer")?;
            }
        }
        dispatch::complete(&child);
        if child.radio.management_tx.lock().is_some()
            || child.radio.inner.start_drops.load(Ordering::Acquire) != 1
            || !EVENTS.lock().is_empty()
            || source
                .1
                .lock()
                .iter()
                .any(|reply| reply.get(16..20) == Some(0i32.to_ne_bytes().as_slice()))
        {
            return Err(
                "revoked/replaced/transferred WDEV FRAME published late native success/status",
            );
        }
    }
    Ok(())
}
fn control_wdev_frame_rechecks_source_child_parent_namespace_and_mode_before_status() -> TestResult
{
    lost().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/control_wdev",
    control_wdev_frame_rechecks_source_child_parent_namespace_and_mode_before_status
);
