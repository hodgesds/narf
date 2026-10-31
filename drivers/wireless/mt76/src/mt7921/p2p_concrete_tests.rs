//! Real concrete control registration/delegation and the same retained
//! Session body as Hardware. The model supplies only native MCU/DMA events.
use super::*;
use crate::mt7921::firmware_transport::boot_p2p::{self, Request as P2pRequest};
use narf_wireless::ap_control::RadioControlAuthority;
#[path = "p2p_coexist_tests.rs"]
mod coexist;
#[derive(Debug)]
struct Source {
    live: AtomicBool,
    close_on_ready: AtomicBool,
    messages: IrqSafeSpinLock<Vec<Vec<u8>>>,
    controls: IrqSafeSpinLock<Vec<AdminHandle>>,
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        self.live.load(Ordering::Acquire)
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(125);
        }
        let ready = message.get(16) == Some(&55);
        self.messages.lock().push(message);
        if ready && self.close_on_ready.load(Ordering::Acquire) {
            self.live.store(false, Ordering::Release);
        }
        Ok(())
    }
    fn retain_control_admin(&self, admin: AdminHandle) -> Result<(), i32> {
        if !self.current() || !admin.is_control_child() {
            return Err(1);
        }
        self.controls.lock().push(admin);
        Ok(())
    }
    fn control_admin(&self, name: &str, ns: u64) -> Option<AdminHandle> {
        if !self.current() {
            return None;
        }
        self.controls
            .lock()
            .iter()
            .find(|admin| admin.authorize_interface(name, ns).is_ok())
            .cloned()
    }
}
struct Concrete {
    binding: crate::iface::ap_tests::Binding,
    child: Arc<crate::iface::p2p::P2pDeviceIface>,
    iface: Arc<dyn WirelessNetIface>,
    source: Arc<Source>,
}
impl Concrete {
    fn authority(&self) -> Result<Arc<RadioControlAuthority>, &'static str> {
        let wdev = narf_wireless::registry::control_for(self.child.as_ref())
            .ok_or("actual concrete WDEV")?;
        let admin = self
            .source
            .control_admin(self.child.name(), 0)
            .ok_or("actual source-retained concrete child admin")?;
        RadioControlAuthority::bind_wdev(admin, &self.iface, 0, wdev.id(), self.source.clone())
            .and_then(RadioControlAuthority::reserve)
            .map(Arc::new)
            .map_err(|_| "actual concrete child request reservation")
    }
}
fn setup() -> Result<(NativeSession, Concrete), &'static str> {
    setup_features(0x80)
}
#[inline(never)]
fn setup_features(features: u8) -> Result<(NativeSession, Concrete), &'static str> {
    use narf_wireless::reg::{RegFlags, RegRule, RegulatoryDomain};
    let base = firmware(32);
    let fw = Firmware::prepare(&base.patch, &super::super::p2p::wm_features(features))
        .map_err(|_| "actual native WM CNM receipt")?;
    let policy = Arc::new(CurrentPolicy {
        database: narf_wireless::reg::db::Database::new(),
        hold_bss_ack: AtomicBool::new(false),
    });
    policy.database.install(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2472,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::NO_IR,
        }],
    });
    let mut backend = Model::new();
    backend.tx_policy = Some(policy);
    backend.roc = Some(Arc::new(RocModel::default()));
    let mut session = Box::new(Session::new(backend, fw));
    run(session.run()).map_err(|_| "actual concrete P2P firmware boot")?;
    let info = run(session.initialize_radio()).map_err(|_| "actual concrete P2P NIC identity")?;
    let profile = session
        .firmware
        .p2p_profile()
        .map_err(|_| "actual immutable WM profile")?;
    let binding = crate::iface::ap_tests::bind_profile(info, Some(profile))?;
    let parent: Arc<dyn WirelessNetIface> = binding.iface.clone();
    let index = narf_net::iface::lookup(parent.name())
        .ok_or("actual physical parent index")?
        .ifindex;
    let source = Arc::new(Source {
        live: AtomicBool::new(true),
        close_on_ready: AtomicBool::new(false),
        messages: IrqSafeSpinLock::new(Vec::new()),
        controls: IrqSafeSpinLock::new(Vec::new()),
    });
    let create =
        RadioControlAuthority::bind(binding.admin.clone(), &parent, 0, index, source.clone())
            .and_then(RadioControlAuthority::reserve)
            .map_err(|_| "actual creating parent source")?;
    static NEXT: AtomicU32 = AtomicU32::new(1);
    let name = alloc::format!("p2p-native{}", NEXT.fetch_add(1, Ordering::Relaxed));
    let child = binding
        .iface
        .create_p2p_device(
            &create,
            &narf_net::bootstrap_authority(),
            0,
            &name,
            Some([2, 0, 0, 0, 0x79, 0xa1]),
        )
        .map_err(|_| "actual concrete control-only producer")?;
    let iface: Arc<dyn WirelessNetIface> = child.clone();
    Ok((
        session,
        Concrete {
            binding,
            child,
            iface,
            source,
        },
    ))
}
fn execute(
    session: &mut Session<Model>,
    concrete: &Concrete,
    request: P2pRequest,
) -> Result<(), Error> {
    let authority = concrete.authority().map_err(|_| Error::Authority)?;
    run(Box::pin(boot_p2p::run_session(
        session,
        Arc::downgrade(&concrete.child),
        authority,
        request,
        Arc::new(AtomicBool::new(true)),
        concrete.binding.iface.mac(),
    )))
}
fn lifecycle() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    if concrete.child.started_current()
        || concrete.child.link_up()
        || narf_net::iface::lookup(concrete.child.name()).is_some()
        || concrete.child.rx_ring().lock().is_some()
        || concrete.child.tx_ring().lock().is_some()
        || concrete
            .binding
            .admin
            .authorize_interface(concrete.child.name(), 0)
            .is_ok()
        || concrete
            .binding
            .iface
            .get_wireless_info()
            .modes
            .contains(narf_wireless::iface::WirelessModes::P2P)
    {
        return Err(
            "concrete metadata invented a started owner/netdev/UP/parent grant/advertised role",
        );
    }
    let first = session.backend.frames.len();
    execute(&mut session, &concrete, P2pRequest::Start).map_err(|_| "concrete native START")?;
    if !concrete.child.started_current()
        || !matches!(session.state, State::RadioReady(_))
        || session.backend.receive_open
        || session.security.is_some()
        || !session.backend.frames[first..]
            .iter()
            .filter_map(|(_, frame)| uni(frame, 1))
            .any(|body| {
                body.get(10..16) == Some(&concrete.child.mac())
                    && body.get(8) == Some(&1)
                    && body.first() == Some(&1)
            })
        || !session.backend.frames[first..]
            .iter()
            .filter_map(|(_, frame)| uni(frame, 2))
            .any(|body| {
                body.len() == 36
                    && body[0] == 1
                    && body[9] == 1
                    && body[10] == 1
                    && body[17] == 1
                    && body[12..16] == [2, 0, 2, 0]
                    && body[24..26] == [0, 0]
            })
    {
        return Err("actual START failed child-MAC DEV receipt or published packet/key authority");
    }
    let count = session.backend.frames.len();
    execute(&mut session, &concrete, P2pRequest::Start).map_err(|_| "idempotent actual START")?;
    if session.backend.frames.len() != count {
        return Err("already-started concrete wdev repeated native setup");
    }
    execute(&mut session, &concrete, P2pRequest::Stop).map_err(|_| "concrete native STOP/reset")?;
    if !session.backend.frames[count..]
        .iter()
        .filter_map(|(_, frame)| uni(frame, 2))
        .any(|body| {
            body.len() == 36
                && body[0] == 1
                && body[8] == 0
                && body[24..26] == 18u16.to_le_bytes()
                && body[30..32] == 18u16.to_le_bytes()
        })
    {
        return Err("concrete STOP used another interface's BSS or BMC WCID");
    }
    if concrete.child.started_current()
        || session.p2p_owner.is_some()
        || !matches!(session.state, State::RadioReady(_))
    {
        return Err("concrete STOP released host owner before native retirement");
    }
    Ok(())
}
fn mt76_concrete_p2p_control_child_uses_actual_grants_mac_and_native_bss_receipts() -> TestResult {
    lifecycle().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_concrete_p2p_control_child_uses_actual_grants_mac_and_native_bss_receipts
);
fn legacy() -> Result<(), &'static str> {
    let (mut session, concrete) = setup_features(0)?;
    if concrete.child.async_roc_control() || concrete.child.max_remain_on_channel_duration_ms() != 0
    {
        return Err("concrete legacy WM invented CNM/ROC feature reporting");
    }
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "legacy concrete START invented a CNM prerequisite")?;
    if !concrete.child.started_current() {
        return Err("legacy concrete native BSS was not published");
    }
    let before = session.backend.frames.len();
    if execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 1,
            frequency_mhz: 2437,
            duration_ms: 50,
        },
    ) != Err(Error::UnsupportedFirmware)
        || session.backend.frames.len() != before
        || !concrete.child.started_current()
    {
        return Err("legacy WM ROC refusal wrote hardware or destroyed valid device owner");
    }
    execute(&mut session, &concrete, P2pRequest::Stop)
        .map_err(|_| "legacy concrete native STOP")?;
    Ok(())
}
fn mt76_concrete_p2p_legacy_wm_starts_device_without_invented_cnm_or_roc() -> TestResult {
    legacy().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_concrete_p2p_legacy_wm_starts_device_without_invented_cnm_or_roc
);

fn finite_roc() -> Result<(), &'static str> {
    let (mut session, concrete) = setup()?;
    execute(&mut session, &concrete, P2pRequest::Start).map_err(|_| "concrete start before ROC")?;
    execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 0x79,
            frequency_mhz: 2437,
            duration_ms: 500,
        },
    )
    .map_err(|_| "concrete actual ROC grant/commit")?;
    if session.p2p_roc_current(0x79, 2437) != Ok(true)
        || !concrete
            .source
            .messages
            .lock()
            .iter()
            .any(|message| message.get(16) == Some(&55))
    {
        return Err("actual concrete CNM grant failed source-bound ready publication");
    }
    let expires = match session
        .p2p_owner
        .as_ref()
        .and_then(|owner| owner.cnm.lease())
        .map(|lease| lease.phase)
    {
        Some(crate::mt7921::p2p_cnm::Phase::Granted { expires_ns, .. }) => expires_ns,
        _ => return Err("actual concrete native finite grant missing"),
    };
    session.backend.ticks.set(expires);
    run(Box::pin(boot_p2p::maintain_session(
        &mut session,
        Arc::downgrade(&concrete.child),
        concrete.binding.iface.mac(),
    )))
    .map_err(|_| "actual concrete background expiry")?;
    if session.p2p_roc_current(0x79, 2437) != Ok(false)
        || !concrete.child.started_current()
        || !concrete
            .source
            .messages
            .lock()
            .iter()
            .any(|message| message.get(16) == Some(&56))
    {
        return Err(
            "concrete maintenance failed terminal native expiry while preserving started wdev",
        );
    }
    // Explicit STOP terminates an active lease only after actual native
    // retirement. Cancel already owns its expiry; later STOP cannot repeat it.
    execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 0x7a,
            frequency_mhz: 2437,
            duration_ms: 500,
        },
    )
    .map_err(|_| "actual ROC before explicit STOP")?;
    execute(&mut session, &concrete, P2pRequest::Stop).map_err(|_| "concrete stop during ROC")?;
    execute(&mut session, &concrete, P2pRequest::Start)
        .map_err(|_| "actual restart before cancel")?;
    execute(
        &mut session,
        &concrete,
        P2pRequest::Roc {
            cookie: 0x7b,
            frequency_mhz: 2437,
            duration_ms: 500,
        },
    )
    .map_err(|_| "actual ROC before cancel")?;
    execute(&mut session, &concrete, P2pRequest::Cancel(0x7b))
        .map_err(|_| "concrete actual cancellation")?;
    execute(&mut session, &concrete, P2pRequest::Stop)
        .map_err(|_| "concrete stopped cancelled wdev")?;
    let expired = concrete
        .source
        .messages
        .lock()
        .iter()
        .filter(|message| message.get(16) == Some(&56))
        .count();
    if expired != 3 {
        return Err("explicit STOP lost original ROC expiry or repeated cancel's terminal event");
    }
    let tokens: Vec<u8> = session
        .backend
        .frames
        .iter()
        .filter_map(|(_, frame)| uni(frame, 0x27))
        .filter(|body| body.len() == 28 && body[4..6] == [0, 0])
        .map(|body| body[9])
        .collect();
    if tokens != [1, 2, 3] {
        return Err("normal device stop/recreation reset the PHY-global native CNM sequence");
    }
    Ok(())
}
fn mt76_concrete_p2p_background_owner_expires_only_actual_finite_cnm_grant() -> TestResult {
    finite_roc().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_concrete_p2p_background_owner_expires_only_actual_finite_cnm_grant
);

fn pending() -> Result<(), &'static str> {
    use core::task::{Context, Waker};
    for cause in 0..3 {
        let (mut session, concrete) = setup()?;
        let hold = Arc::new(Hold::default());
        session.backend.p2p_hold = Some(hold.clone());
        let alive = Arc::new(AtomicBool::new(true));
        let authority = concrete.authority()?;
        let mut native = Box::pin(boot_p2p::run_session(
            &mut session,
            Arc::downgrade(&concrete.child),
            authority,
            P2pRequest::Start,
            alive.clone(),
            concrete.binding.iface.mac(),
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..8192 {
            if native.as_mut().poll(&mut cx).is_ready() {
                return Err("concrete START completed before held native BSS ACK");
            }
            // Repeated native polls remain bounded; no host START publication.
            if concrete.child.started_current() {
                return Err("held concrete native START published early");
            }
            if hold.seen.load(Ordering::Acquire) {
                break;
            }
        }
        if !hold.seen.load(Ordering::Acquire) {
            return Err("actual concrete P2P BSS wait seam not reached");
        }
        match cause {
            0 => concrete.binding.daemon.revoke(),
            1 => {
                concrete
                    .binding
                    .admin
                    .move_to_net_ns(27)
                    .map_err(|_| "actual parent namespace transfer during native START")?;
                concrete
                    .binding
                    .admin
                    .move_to_net_ns(0)
                    .map_err(|_| "actual parent namespace return")?;
            }
            _ => alive.store(false, Ordering::Release),
        }
        hold.release.store(true, Ordering::Release);
        let expected = if cause == 2 {
            Error::Cancelled
        } else {
            Error::Authority
        };
        if run(native) != Err(expected)
            || session.p2p_owner.is_some()
            || !matches!(session.state, State::RadioReady(_))
            || concrete.child.started_current()
        {
            return Err("concrete lost source/parent/caller bypassed native reset or host terminal retirement");
        }
        if cause == 2 && concrete.authority().is_err() {
            return Err("terminal concrete cancellation stranded native serialization lease");
        }
    }
    Ok(())
}
fn mt76_concrete_p2p_native_wait_rechecks_daemon_parent_epoch_and_caller_until_reset() -> TestResult
{
    pending().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_concrete_p2p_native_wait_rechecks_daemon_parent_epoch_and_caller_until_reset
);
