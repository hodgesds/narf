//! Captured native userspace-SME futures across real netdev replacement.
use super::*;
use core::{
    future::Future,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

const NAME: &str = "wifi-sme-life";
const OWNER: u32 = 41;
const REPLACEMENT_OWNER: u32 = 93;

struct HeldSme {
    base: SmeStub,
    case: u8,
    ready: AtomicBool,
    started: AtomicUsize,
    continued: AtomicUsize,
}
impl HeldSme {
    fn new(case: u8, ready: bool) -> Self {
        Self {
            base: SmeStub {
                rx: IrqSafeSpinLock::new(None),
                tx: IrqSafeSpinLock::new(None),
                registered: core::sync::atomic::AtomicU32::new(0),
                external_status: core::sync::atomic::AtomicU32::new(0),
                assoc_comeback: AtomicBool::new(false),
            },
            case,
            ready: AtomicBool::new(ready),
            started: AtomicUsize::new(0),
            continued: AtomicUsize::new(0),
        }
    }
    async fn receipt(&self) {
        self.started.fetch_add(1, Ordering::AcqRel);
        core::future::poll_fn(|_| {
            if self.ready.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        self.continued.fetch_add(1, Ordering::AcqRel);
    }
}
impl Interface for HeldSme {
    fn name(&self) -> &str {
        NAME
    }
    fn mac(&self) -> [u8; 6] {
        SME_MAC
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.base.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.base.tx
    }
}
#[async_trait::async_trait]
impl crate::WirelessNetIface for HeldSme {
    fn supports_userspace_mlme(&self) -> bool {
        true
    }
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        let mut info = crate::WirelessNetIface::get_wireless_info(&self.base);
        info.base_name = NAME.into();
        info
    }
    async fn scan(
        &self,
        _: crate::ScanRequest,
    ) -> Result<Vec<crate::BssInfo>, crate::WirelessError> {
        Ok(Vec::new())
    }
    async fn associate(&self, _: crate::AssociateRequest) -> Result<(), crate::WirelessError> {
        Ok(())
    }
    async fn disassociate(&self) -> Result<(), crate::WirelessError> {
        Ok(())
    }
    async fn set_config(&self, _: crate::WirelessConfig) -> Result<(), crate::WirelessError> {
        Err(crate::WirelessError::NotSupported)
    }
    async fn mlme_authenticate(
        &self,
        _: crate::MlmeAuthRequest,
    ) -> Result<Vec<u8>, crate::WirelessError> {
        self.receipt().await;
        if self.case == 1 {
            Err(crate::WirelessError::Timeout)
        } else {
            Ok(SME_AUTH_RESP.to_vec())
        }
    }
    async fn mlme_associate(
        &self,
        _: crate::MlmeAssocRequest,
    ) -> Result<Vec<u8>, crate::WirelessError> {
        self.receipt().await;
        if self.case == 5 {
            return Err(crate::WirelessError::Timeout);
        }
        if self.case == 4 {
            return Ok(sme_assoc_comeback());
        }
        let mut frame = alloc::vec![0; 30];
        frame[0] = 0x10;
        frame[4..10].copy_from_slice(&SME_MAC);
        frame[10..16].copy_from_slice(&SME_PEER);
        frame[16..22].copy_from_slice(&SME_PEER);
        if self.case == 3 {
            frame[26..28].copy_from_slice(&1u16.to_le_bytes());
        }
        Ok(frame)
    }
    async fn mlme_deauthenticate(
        &self,
        _: [u8; 6],
        _: u16,
    ) -> Result<Vec<u8>, crate::WirelessError> {
        self.receipt().await;
        Ok(SME_DEAUTH.to_vec())
    }
    async fn mlme_disassociate(&self, _: [u8; 6], _: u16) -> Result<Vec<u8>, crate::WirelessError> {
        self.receipt().await;
        Ok(SME_DISASSOC.to_vec())
    }
    async fn mgmt_tx(&self, _: u64, _: crate::MgmtTxRequest) -> Result<bool, crate::WirelessError> {
        self.receipt().await;
        Ok(true)
    }
    async fn external_auth_status(&self, _: [u8; 6], _: u16) -> Result<(), crate::WirelessError> {
        self.receipt().await;
        Ok(())
    }
}
struct LifetimeRig;
impl Drop for LifetimeRig {
    fn drop(&mut self) {
        CACHE.lock().retain(|c| c.name != NAME);
        station::unregister_wdev(NAME);
        crate::registry::unregister(NAME);
        narf_net::iface::unregister(NAME);
        REPLACE_ON_EVENT.store(0, Ordering::Release);
    }
}
fn register(case: u8, ready: bool) -> (Arc<HeldSme>, u32) {
    let iface = Arc::new(HeldSme::new(case, ready));
    narf_net::iface::register(NAME, SME_MAC, |_, _| Ok(()));
    narf_net::iface::set_link_state(NAME, true);
    crate::registry::register(iface.clone());
    let index = narf_net::netlink_route::ifindex_for_name(NAME).unwrap();
    (iface, index)
}
fn replacement(case: u8) -> (Arc<HeldSme>, u32) {
    narf_net::iface::unregister(NAME);
    let (iface, index) = register(case, true);
    station::set_owner_for_link(NAME, 0, index, REPLACEMENT_OWNER, Some(SME_MAC)).unwrap();
    station::set_control_port_for_link(NAME, 0, index, true).unwrap();
    (iface, index)
}
fn execution(case: u8) -> MlmeExec {
    match case {
        0 | 1 => MlmeExec::Authenticate(crate::MlmeAuthRequest {
            peer: SME_PEER,
            ssid: b"sme-net".to_vec(),
            frequency_mhz: 2437,
            auth_type: 0,
            auth_data: Vec::new(),
            ie: Vec::new(),
        }),
        2..=5 => MlmeExec::Associate(crate::MlmeAssocRequest {
            peer: SME_PEER,
            ssid: b"sme-net".to_vec(),
            frequency_mhz: 2437,
            ie: Vec::new(),
            prev_bssid: None,
            use_mfp: false,
            control_port: crate::ControlPort::default(),
            privacy: true,
        }),
        6 => MlmeExec::Deauthenticate {
            peer: SME_PEER,
            reason: 3,
        },
        7 => MlmeExec::Disassociate {
            peer: SME_PEER,
            reason: 3,
        },
        8 => MlmeExec::MgmtTx {
            cookie: 77,
            request: crate::MgmtTxRequest {
                frequency_mhz: 2437,
                frame: alloc::vec![0xd0; 24],
                offchannel_ok: false,
                duration: 0,
            },
        },
        _ => MlmeExec::ExternalAuth {
            bssid: SME_PEER,
            status: 0,
        },
    }
}
fn events(index: u32) -> Vec<u8> {
    INTEROP_EVENTS
        .lock()
        .iter()
        .filter_map(|(ns, group, msg)| {
            (*ns == 0 && *group == 19 && find_attr(&msg[20..], 3) == Some(&index.to_ne_bytes()[..]))
                .then_some(msg[16])
        })
        .collect()
}
fn expected(case: u8) -> Vec<u8> {
    match case {
        0 | 1 => alloc::vec![AUTHENTICATE],
        2 | 3 => alloc::vec![ASSOCIATE, CONNECT],
        4 => alloc::vec![ASSOCIATE, ASSOC_COMEBACK],
        5 => alloc::vec![ASSOCIATE],
        6 => alloc::vec![DEAUTHENTICATE],
        7 => alloc::vec![DISASSOCIATE],
        8 => alloc::vec![FRAME_TX_STATUS],
        _ => Vec::new(),
    }
}
fn retired(held: bool) -> Result<(), &'static str> {
    super::super::register();
    let _sink = SinkRestore(narf_net::netlink_generic::install_event_sink(interop_sink));
    for case in 0..10 {
        let _rig = LifetimeRig;
        let (old, index) = register(case, false);
        station::set_owner_for_link(NAME, 0, index, OWNER, Some(SME_PEER)).unwrap();
        let mut future = core::pin::pin!(run_mlme(old.clone(), 0, index, execution(case)));
        let mut cx = Context::from_waker(Waker::noop());
        INTEROP_EVENTS.lock().clear();
        if held
            && (!future.as_mut().poll(&mut cx).is_pending()
                || old.started.load(Ordering::Acquire) != 1)
        {
            return Err("native SME receipt was not actually held");
        }
        let (new, new_index) = replacement(case);
        old.ready.store(true, Ordering::Release);
        if new_index == index
            || future.as_mut().poll(&mut cx).is_pending()
            || old.started.load(Ordering::Acquire) != usize::from(held)
            || old.continued.load(Ordering::Acquire) != 0
            || new.started.load(Ordering::Acquire) != 0
            || station::conn_owner(NAME) != REPLACEMENT_OWNER
            || !station::control_port_over_nl80211(NAME)
            || !INTEROP_EVENTS.lock().is_empty()
        {
            return Err(
                "retired SME polled native continuation or changed replacement owner/events",
            );
        }
        let mut current = core::pin::pin!(run_mlme(new.clone(), 0, new_index, execution(case)));
        if current.as_mut().poll(&mut cx).is_pending()
            || new.started.load(Ordering::Acquire) != 1
            || new.continued.load(Ordering::Acquire) != 1
            || events(new_index) != expected(case)
            || station::conn_owner(NAME) != if case == 3 { 0 } else { REPLACEMENT_OWNER }
        {
            return Err(
                "current-generation SME failed native completion/owner/notification behavior",
            );
        }
    }
    Ok(())
}
fn smoke_nl80211_sme_retired_before_first_native_poll_is_closed() -> TestResult {
    retired(false).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_sme_retired_before_first_native_poll_is_closed
);
fn smoke_nl80211_sme_held_exchange_replacement_cancels_native_continuation() -> TestResult {
    retired(true).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_sme_held_exchange_replacement_cancels_native_continuation
);

fn smoke_nl80211_sme_namespace_change_cancels_held_auth_and_association() -> TestResult {
    super::super::register();
    let _sink = SinkRestore(narf_net::netlink_generic::install_event_sink(interop_sink));
    for case in [0, 2, 3, 4] {
        let _rig = LifetimeRig;
        let (old, index) = register(case, false);
        let mut future = core::pin::pin!(run_mlme(old.clone(), 0, index, execution(case)));
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("held namespace SME baseline");
        }
        narf_net::kernel_admin(NAME)
            .unwrap()
            .move_to_net_ns(73)
            .unwrap();
        station::set_owner_for_link(NAME, 73, index, REPLACEMENT_OWNER, Some(SME_MAC)).unwrap();
        INTEROP_EVENTS.lock().clear();
        old.ready.store(true, Ordering::Release);
        if future.as_mut().poll(&mut cx).is_pending()
            || old.continued.load(Ordering::Acquire) != 0
            || station::conn_owner(NAME) != REPLACEMENT_OWNER
            || !INTEROP_EVENTS.lock().is_empty()
        {
            return TestResult::Fail(
                "old namespace native SME resumed or changed current ownership",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_sme_namespace_change_cancels_held_auth_and_association
);

static REPLACE_ON_EVENT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
fn replacing_sink(ns: u64, group: u32, message: &[u8]) {
    interop_sink(ns, group, message);
    if message.get(16).is_some_and(|cmd| {
        REPLACE_ON_EVENT
            .compare_exchange(*cmd, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }) {
        let _ = replacement(0);
    }
}
fn smoke_nl80211_sme_publication_replacement_preserves_new_owner() -> TestResult {
    super::super::register();
    let _rig = LifetimeRig;
    let _sink = SinkRestore(narf_net::netlink_generic::install_event_sink(
        replacing_sink,
    ));
    let (old, index) = register(3, true);
    station::set_owner_for_link(NAME, 0, index, OWNER, Some(SME_PEER)).unwrap();
    INTEROP_EVENTS.lock().clear();
    REPLACE_ON_EVENT.store(ASSOCIATE, Ordering::Release);
    let mut future = core::pin::pin!(run_mlme(old, 0, index, execution(3)));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx).is_pending()
        || station::conn_owner(NAME) != REPLACEMENT_OWNER
        || !station::control_port_over_nl80211(NAME)
        || events(index) != alloc::vec![ASSOCIATE]
        || INTEROP_EVENTS.lock().len() != 1
    {
        return TestResult::Fail(
            "old association failure cleared new owner after MLME publication replacement",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_sme_publication_replacement_preserves_new_owner
);

fn smoke_nl80211_connect_publication_replacement_suppresses_old_port_authorized() -> TestResult {
    super::super::register();
    let _rig = LifetimeRig;
    let _sink = SinkRestore(narf_net::netlink_generic::install_event_sink(
        replacing_sink,
    ));
    let (old, index) = register(2, true);
    let _guard = begin_operation(NAME, 0, index).unwrap();
    CACHE
        .lock()
        .iter_mut()
        .find(|c| c.matches(NAME, 0, index))
        .unwrap()
        .results = alloc::vec![(
        crate::BssInfo {
            bssid: SME_PEER,
            ssid: b"sme-net".to_vec(),
            frequency_mhz: 2437,
            channel: 6,
            rssi: -40,
            security: crate::scan::BssSecurity::Wpa2,
        },
        Vec::new()
    )];
    INTEROP_EVENTS.lock().clear();
    REPLACE_ON_EVENT.store(CONNECT, Ordering::Release);
    let mut future = core::pin::pin!(execute(
        old,
        narf_net::kernel_admin(NAME).unwrap(),
        0,
        index,
        Operation::Connect {
            ssid: b"sme-net".to_vec(),
            bssid: Some(SME_PEER),
            frequency_mhz: Some(2437),
            cred: Credential::Psk(Zeroizing::new([0x11; 32])),
            ie: Vec::new(),
            owner: None,
        }
    ));
    let mut cx = Context::from_waker(Waker::noop());
    if future.as_mut().poll(&mut cx).is_pending()
        || station::conn_owner(NAME) != REPLACEMENT_OWNER
        || events(index) != alloc::vec![CONNECT]
        || INTEROP_EVENTS.lock().len() != 1
    {
        return TestResult::Fail(
            "old CONNECT emitted PORT_AUTHORIZED after event callback replaced its netdev",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_connect_publication_replacement_suppresses_old_port_authorized
);
