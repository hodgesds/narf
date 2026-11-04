//! Actual station IFINDEX deferred FRAME boundary; no native RF/ACK fabricated.
use super::*;
use narf_net::netlink_generic::{build_replies_with_endpoint, ReplyOptions, RequestContext};
static TARGET: AtomicU32 = AtomicU32::new(0);
static EVENTS: IrqSafeSpinLock<Vec<(u64, Vec<u8>)>> = IrqSafeSpinLock::new(Vec::new());
fn attribute(mut bytes: &[u8], kind: u16) -> Option<&[u8]> {
    while bytes.len() >= 4 {
        let n = usize::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
        if n < 4 || n > bytes.len() {
            return None;
        }
        if u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff == kind {
            return Some(&bytes[4..n]);
        }
        bytes = bytes.get((n + 3) & !3..)?;
    }
    None
}
fn event(ns: u64, group: u32, b: &[u8]) {
    let target = TARGET.load(Ordering::Acquire);
    if target != 0
        && group == 19
        && b.get(4..6) == Some(crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes().as_slice())
        && b.get(16) == Some(&60)
        && b.get(20..).and_then(|a| attribute(a, 3)) == Some(target.to_ne_bytes().as_slice())
    {
        EVENTS.lock().push((ns, b.to_vec()));
    }
}
struct Capture(Option<fn(u64, u32, &[u8])>);
impl Drop for Capture {
    fn drop(&mut self) {
        TARGET.store(0, Ordering::Release);
        if let Some(old) = self.0 {
            narf_net::netlink_generic::install_event_sink(old);
        }
        EVENTS.lock().clear();
    }
}
fn send(f: &Fixture) -> Result<Vec<Vec<u8>>, &'static str> {
    send_original(f.ifindex, f.radio.mac(), &f.admin, f.source.clone())
}
fn send_original(
    ifindex: u32,
    own: [u8; 6],
    admin: &AdminHandle,
    source: Arc<dyn DeferredReplySink>,
) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut attrs = Vec::new();
    let mut frame = alloc::vec![0;26];
    frame[0] = 0xd0;
    frame[4..10].fill(255);
    frame[10..16].copy_from_slice(&own);
    frame[16..22].fill(255);
    frame[24] = 4;
    for (kind, value) in [
        (3u16, ifindex.to_ne_bytes().to_vec()),
        (38, 5180u32.to_ne_bytes().to_vec()),
        (51, frame),
        (108, Vec::new()),
        (135, Vec::new()),
    ] {
        attrs.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
        attrs.extend_from_slice(&kind.to_ne_bytes());
        attrs.extend_from_slice(&value);
        attrs.resize((attrs.len() + 3) & !3, 0);
    }
    let mut b = alloc::vec![0;20];
    b[..4].copy_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
    b[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
    b[6..8].copy_from_slice(&5u16.to_ne_bytes());
    b[8..12].copy_from_slice(&0x10cc_0101u32.to_ne_bytes());
    b[16] = 59;
    b[17] = 1;
    b.extend_from_slice(&attrs);
    build_replies_with_endpoint(
        &b,
        ReplyOptions::default(),
        RequestContext {
            admin: Some(admin),
            portid: 91,
            ..RequestContext::default()
        },
        source,
    )
    .map_err(|_| "station FRAME netlink framing")
}
fn check() -> Result<(), &'static str> {
    let _capture = Capture(narf_net::netlink_generic::install_event_sink(event));
    let _ = crate::nl80211::register();
    for boundary in 0..7 {
        let f = fixture()?;
        f.radio.mode.store(2, Ordering::Release);
        f.radio.radio_mgmt.store(true, Ordering::Release);
        f.radio.mgmt_acked.store(boundary == 0, Ordering::Release);
        f.radio.station_sme.store(false, Ordering::Release); // This path must not require userspace SME.
        TARGET.store(f.ifindex, Ordering::Release);
        EVENTS.lock().clear();
        if !send(&f)?.is_empty() {
            return Err("station FRAME acknowledged before native callback");
        }
        for _ in 0..256 {
            if f.radio.start_polls.load(Ordering::Acquire) != 0 {
                break;
            }
            narf_scheduler::poll_one_round();
        }
        if f.radio.start_polls.load(Ordering::Acquire) == 0
            || f.radio.mgmt_cookie.load(Ordering::Acquire) != 0
            || !EVENTS.lock().is_empty()
            || !f.source.1.lock().is_empty()
        {
            return Err("station FRAME held phase invented native status/cookie");
        }
        match boundary {
            2 => f.daemon.revoke(),
            3 => f.cap.revoke(),
            4 => f.source.0.store(false, Ordering::Release),
            5 => f.radio.generation.store(2, Ordering::Release),
            6 => {
                f.admin
                    .move_to_net_ns(0x10cc)
                    .map_err(|_| "station namespace transfer")?;
            }
            _ => {}
        }
        f.radio.start_ready.store(true, Ordering::Release);
        for _ in 0..256 {
            narf_scheduler::poll_one_round();
            if f.radio.start_drops.load(Ordering::Acquire) != 0 {
                break;
            }
        }
        let events = EVENTS.lock().clone();
        if boundary < 2 {
            let [(ns, b)] = events.as_slice() else {
                return Err("station FRAME missing exact single native status");
            };
            let cookie = f.radio.mgmt_cookie.load(Ordering::Acquire);
            if *ns != 0
                || cookie == 0
                || attribute(&b[20..], 3) != Some(f.ifindex.to_ne_bytes().as_slice())
                || attribute(&b[20..], 153).is_some()
                || attribute(&b[20..], 88) != Some(cookie.to_ne_bytes().as_slice())
                || attribute(&b[20..], 92).is_some() != (boundary == 0)
            {
                return Err("station FRAME changed IFINDEX/cookie/native ACK or invented WDEV");
            }
        } else if !events.is_empty() || f.radio.mgmt_cookie.load(Ordering::Acquire) != 0 {
            return Err("revoked/transferred/replaced station FRAME published native success");
        }
    }
    Ok(())
}
fn station_native_frame_retains_original_source_ifindex_and_terminal_status() -> TestResult {
    check().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    station_native_frame_retains_original_source_ifindex_and_terminal_status
);

fn station_frame_registration_waits_for_native_callback_and_original_source() -> TestResult {
    let check = || -> Result<(), &'static str> {
        let _ = crate::nl80211::register();
        for boundary in 0..5 {
            let f = fixture()?;
            f.radio.mode.store(2, Ordering::Release);
            f.radio.radio_mgmt.store(true, Ordering::Release);
            f.radio.station_sme.store(false, Ordering::Release);
            let mut attrs = Vec::new();
            for (kind, value) in [
                (3u16, f.ifindex.to_ne_bytes().to_vec()),
                (101, 0xd0u16.to_ne_bytes().to_vec()),
                (91, alloc::vec![4, 9]),
            ] {
                attrs.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
                attrs.extend_from_slice(&kind.to_ne_bytes());
                attrs.extend_from_slice(&value);
                attrs.resize((attrs.len() + 3) & !3, 0);
            }
            let mut b = alloc::vec![0;20];
            b[..4].copy_from_slice(&((20 + attrs.len()) as u32).to_ne_bytes());
            b[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
            b[6..8].copy_from_slice(&5u16.to_ne_bytes());
            b[8..12].copy_from_slice(&0x10cc_0202u32.to_ne_bytes());
            b[16] = 58;
            b[17] = 1;
            b.extend_from_slice(&attrs);
            let replies = build_replies_with_endpoint(
                &b,
                ReplyOptions::default(),
                RequestContext {
                    admin: Some(&f.admin),
                    portid: 92,
                    ..RequestContext::default()
                },
                f.source.clone(),
            )
            .map_err(|_| "station REGISTER_FRAME framing")?;
            if !replies.is_empty() || f.radio.management_registration.lock().is_some() {
                return Err("station registration ACKed or installed before native callback");
            }
            for _ in 0..256 {
                if f.radio.start_polls.load(Ordering::Acquire) != 0 {
                    break;
                }
                narf_scheduler::poll_one_round();
            }
            if f.radio.start_polls.load(Ordering::Acquire) == 0 || !f.source.1.lock().is_empty() {
                return Err("specific native registration did not enter held boundary");
            }
            match boundary {
                1 => f.cap.revoke(),
                2 => f.daemon.revoke(),
                3 => f.source.0.store(false, Ordering::Release),
                4 => f.radio.generation.store(2, Ordering::Release),
                _ => {}
            }
            f.radio.start_ready.store(true, Ordering::Release);
            for _ in 0..256 {
                narf_scheduler::poll_one_round();
                if f.radio.start_drops.load(Ordering::Acquire) != 0 {
                    break;
                }
            }
            if boundary == 0 {
                let installed = f.radio.management_registration.lock().clone();
                if installed != Some((0xd0, alloc::vec![4, 9])) || f.source.1.lock().len() != 1 {
                    return Err("station registration lost actual type/prefix/native terminal ACK");
                }
            } else if f.radio.management_registration.lock().is_some() {
                return Err(
                    "revoked/replaced registration installed a source or new native filter",
                );
            }
        }
        Ok(())
    };
    check().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    station_frame_registration_waits_for_native_callback_and_original_source
);

/// The native terminal proof is independent of a callback's own true result.
/// Late callbacks may retire the original native owner while keeping the
/// actual request socket/interface/grant otherwise valid.
struct CompletionProof(Arc<AtomicBool>);
impl crate::ap_control::RadioFrameCompletion for CompletionProof {
    fn current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
struct LateRadio {
    radio: Arc<Radio>,
    live: Arc<AtomicBool>,
    armed: AtomicBool,
    boundary: u8,
    completed: AtomicU32,
}
impl Interface for LateRadio {
    fn name(&self) -> &str {
        self.radio.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.radio.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.radio.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.radio.tx
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for LateRadio {
    fn wiphy_id(&self) -> u64 {
        if self.boundary == 2 && self.armed.load(Ordering::Acquire) {
            self.live.store(false, Ordering::Release);
        }
        self.radio.wiphy_id()
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        self.radio.get_wireless_info()
    }
    async fn scan(&self, _: crate::ScanRequest) -> Result<Vec<crate::BssInfo>, WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    async fn disassociate(&self) -> Result<(), WirelessError> {
        Ok(())
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }
    fn current_iftype(&self) -> u32 {
        8
    }
    fn radio_control_generation(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(1)
    }
    fn reserve_radio_control(
        &self,
    ) -> Result<Option<Arc<dyn ApControlReservation>>, WirelessError> {
        self.radio.serial.try_reserve().map(Some)
    }
    fn async_p2p_netdev_management_tx_control(&self) -> bool {
        true
    }
    fn supports_offchannel_mgmt_tx(&self) -> bool {
        true
    }
    async fn mgmt_tx_radio_async(
        &self,
        authority: &RadioControlAuthority,
        cookie: u64,
        _: crate::MgmtTxRequest,
    ) -> Result<bool, WirelessError> {
        authority.check_for(self)?;
        // This shared-boundary fixture models the terminal native callback;
        // family fixtures independently prove its real firmware ACK producer.
        self.completed.fetch_add(1, Ordering::AcqRel);
        let proof = Arc::new(CompletionProof(self.live.clone()));
        authority.complete_frame_for(self, cookie, proof.clone())?;
        if authority.complete_frame_for(self, cookie, proof).is_ok()
            || authority.frame_completion_current(Some(cookie + 1)).is_ok()
        {
            return Err(WirelessError::HardwareError);
        }
        if self.boundary == 3 {
            self.live.store(false, Ordering::Release);
            if authority.frame_completion_current(Some(cookie)).is_ok() {
                return Err(WirelessError::HardwareError);
            }
            self.live.store(true, Ordering::Release);
            if authority.clone().current().is_ok() {
                return Err(WirelessError::HardwareError);
            }
            return Err(WirelessError::Denied);
        }
        self.armed.store(true, Ordering::Release);
        Ok(true)
    }
}
struct LateRegistered(Arc<LateRadio>);
impl Interface for LateRegistered {
    fn name(&self) -> &str {
        self.0.name()
    }
    fn mac(&self) -> [u8; 6] {
        self.0.mac()
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.0.rx_ring()
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.0.tx_ring()
    }
}
struct LateSocket {
    radio: Arc<LateRadio>,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
}
impl core::fmt::Debug for LateSocket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LateSocket").finish_non_exhaustive()
    }
}
impl DeferredReplySink for LateSocket {
    fn current(&self) -> bool {
        if self.radio.boundary == 1 && self.radio.armed.load(Ordering::Acquire) {
            self.radio.live.store(false, Ordering::Release);
        }
        true
    }
    fn deliver(&self, b: Vec<u8>) -> Result<(), i32> {
        self.messages.lock().push(b);
        Ok(())
    }
}
fn late_completion() -> Result<(), &'static str> {
    let _capture = Capture(narf_net::netlink_generic::install_event_sink(event));
    let _ = crate::nl80211::register();
    for boundary in 0..4 {
        let name =
            narf_net::iface::register("client-frame-final%d", [2, 0, 0, 0, 0x76, 0x40], reject);
        let _binding = Binding(name.clone());
        let radio = Arc::new(Radio::new(name));
        radio.mode.store(8, Ordering::Release);
        radio.p2p_roles.store(true, Ordering::Release);
        let late = Arc::new(LateRadio {
            radio,
            live: Arc::new(AtomicBool::new(true)),
            armed: AtomicBool::new(false),
            boundary,
            completed: AtomicU32::new(0),
        });
        let cap = narf_net::registry()
            .register(
                &narf_net::bootstrap_authority(),
                LateRegistered(late.clone()),
            )
            .map_err(|_| "late FRAME registered original iface")?;
        let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
        let admin = narf_net::stack::control_registered(&narf_net::stack::StackAttach {
            iface: cap,
            daemon,
        })
        .map_err(|_| "late FRAME original delegated grant")?
        .admin;
        let iface: Arc<dyn WirelessNetIface> = late.clone();
        crate::registry::register(iface);
        narf_net::iface::set_link_state(late.name(), true);
        let ifindex = narf_net::iface::lookup(late.name())
            .ok_or("late FRAME actual ifindex")?
            .ifindex;
        let source = Arc::new(LateSocket {
            radio: late.clone(),
            messages: IrqSafeSpinLock::new(Vec::new()),
        });
        TARGET.store(ifindex, Ordering::Release);
        EVENTS.lock().clear();
        if !send_original(ifindex, late.mac(), &admin, source.clone())?.is_empty() {
            return Err("late FRAME escaped deferred native callback");
        }
        for _ in 0..256 {
            narf_scheduler::poll_one_round();
            if !source.messages.lock().is_empty() {
                break;
            }
        }
        if late.completed.load(Ordering::Acquire) != 1 {
            return Err("late FRAME did not reach exact single native terminal");
        }
        let events = EVENTS.lock().len();
        let messages = source.messages.lock();
        if boundary == 0 {
            if events != 1 || !messages.iter().any(|b| b.get(16) == Some(&59)) {
                return Err("current native FRAME proof lost status/cookie");
            }
        } else if events != 0 || messages.iter().any(|b| b.get(16) == Some(&59)) {
            return Err(
                "late virtual/source callback retired native owner but FRAME published success",
            );
        }
    }
    Ok(())
}
fn client_frame_completion_receipt_denies_after_late_source_and_virtual_callbacks() -> TestResult {
    late_completion().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "wireless/radio_control",
    client_frame_completion_receipt_denies_after_late_source_and_virtual_callbacks
);
