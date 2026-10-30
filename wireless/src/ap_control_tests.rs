use super::*;
use alloc::{boxed::Box, string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use narf_capabilities::{Cap, Invoke};
use narf_ipc::{Consumer, Producer};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};

#[path = "ap_dispatch_tests.rs"]
mod dispatch;

struct Radio {
    name: String,
    mode: AtomicU32,
    generation: AtomicU64,
    start_ready: AtomicBool,
    start_polls: AtomicU32,
    starts: AtomicU32,
    start_drops: AtomicU32,
    rx: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}
impl Radio {
    fn new(name: String) -> Self {
        Self {
            name,
            mode: AtomicU32::new(3),
            generation: AtomicU64::new(1),
            start_ready: AtomicBool::new(false),
            start_polls: AtomicU32::new(0),
            starts: AtomicU32::new(0),
            start_drops: AtomicU32::new(0),
            rx: IrqSafeSpinLock::new(None),
            tx: IrqSafeSpinLock::new(None),
        }
    }
}
impl Interface for Radio {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        [2, 0, 0, 0, 0x76, 0x40]
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        true
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx
    }
}
#[async_trait::async_trait]
impl WirelessNetIface for Radio {
    fn get_wireless_info(&self) -> crate::WirelessIfaceInfo {
        crate::WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac(),
            bands: Vec::new(),
            modes: crate::iface::WirelessModes::AP,
            hw_caps: crate::iface::HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
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
        self.mode.load(Ordering::Acquire)
    }
    fn supports_ap(&self) -> bool {
        true
    }
    fn ap_control_generation(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.generation.load(Ordering::Acquire))
    }
    async fn start_ap_async(
        &self,
        authority: &ApControlAuthority,
        _: crate::ApConfig,
    ) -> Result<(), WirelessError> {
        struct BorrowedWaiter<'a>(&'a AtomicU32);
        impl Drop for BorrowedWaiter<'_> {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }
        let _waiter = BorrowedWaiter(&self.start_drops);
        core::future::poll_fn(|cx| {
            authority.check_for(self)?;
            self.start_polls.fetch_add(1, Ordering::AcqRel);
            if self.start_ready.load(Ordering::Acquire) {
                self.starts.fetch_add(1, Ordering::AcqRel);
                core::task::Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                core::task::Poll::Pending
            }
        })
        .await
    }
}
struct Registered(Arc<Radio>);
impl Interface for Registered {
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
        &self.0.rx
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.0.tx
    }
}
#[derive(Debug)]
struct Source(AtomicBool, IrqSafeSpinLock<Vec<Vec<u8>>>);
impl Source {
    fn new() -> Self {
        Self(AtomicBool::new(true), IrqSafeSpinLock::new(Vec::new()))
    }
}
impl DeferredReplySink for Source {
    fn current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    fn deliver(&self, message: Vec<u8>) -> Result<(), i32> {
        if !self.current() {
            return Err(125);
        }
        self.1.lock().push(message);
        Ok(())
    }
}
struct Fixture {
    _binding: Binding,
    ifindex: u32,
    radio: Arc<Radio>,
    iface: Arc<dyn WirelessNetIface>,
    source: Arc<Source>,
    admin: AdminHandle,
    daemon: Cap<narf_net::stack::StackDaemon, Invoke>,
}
struct Binding(String);
impl Drop for Binding {
    fn drop(&mut self) {
        crate::registry::unregister(&self.0);
        narf_net::registry().unregister(&self.0);
        narf_net::iface::unregister(&self.0);
    }
}
fn reject(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}
fn fixture() -> Result<Fixture, &'static str> {
    let name = narf_net::iface::register("ap-current-proof%d", [2, 0, 0, 0, 0x76, 0x40], reject);
    let binding = Binding(name.clone());
    let radio = Arc::new(Radio::new(name.clone()));
    let iface: Arc<dyn WirelessNetIface> = radio.clone();
    let authority = narf_net::bootstrap_authority();
    let cap = narf_net::registry()
        .register(&authority, Registered(radio.clone()))
        .map_err(|_| "AP grant fixture driver registration")?;
    let daemon = Cap::<narf_net::stack::StackDaemon, Invoke>::bootstrap();
    let admin =
        narf_net::stack::control_registered(&narf_net::stack::StackAttach { iface: cap, daemon })
            .map_err(|_| "AP grant fixture actual delegated administration")?
            .admin;
    crate::registry::register(iface.clone());
    if !narf_net::iface::set_link_state(&name, true) {
        return Err("AP fixture administrative UP");
    }
    let ifindex = narf_net::iface::lookup(&name)
        .ok_or("AP fixture ifindex")?
        .ifindex;
    Ok(Fixture {
        _binding: binding,
        ifindex,
        radio,
        iface,
        source: Arc::new(Source::new()),
        admin,
        daemon,
    })
}

fn current_ap_authority_cannot_survive_revoked_source_grants() -> TestResult {
    let fixture = match fixture() {
        Ok(fixture) => fixture,
        Err(error) => return TestResult::Fail(error),
    };
    let authority = match ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    ) {
        Ok(authority) => authority,
        Err(_) => return TestResult::Fail("actual AP administration did not bind"),
    };
    if authority.current() != Ok(()) || authority.check_for(fixture.radio.as_ref()) != Ok(()) {
        return TestResult::Fail("current native AP grant refused its concrete interface");
    }
    fixture.daemon.revoke();
    if authority.current() != Err(WirelessError::Denied)
        || ApControlAuthority::bind(
            fixture.admin.clone(),
            &fixture.iface,
            0,
            fixture.ifindex,
            fixture.source.clone(),
        )
        .is_ok()
    {
        return TestResult::Fail("prior AP grant bypassed current delegated source revocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ap_control",
    current_ap_authority_cannot_survive_revoked_source_grants
);

fn ap_authority_fences_mode_aba_receiver_replacement_and_closed_source() -> TestResult {
    let fixture = match fixture() {
        Ok(fixture) => fixture,
        Err(error) => return TestResult::Fail(error),
    };
    let old = match ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    ) {
        Ok(authority) => authority,
        Err(_) => return TestResult::Fail("AP generation fixture did not bind"),
    };
    let other = Radio::new(String::from("another-ap"));
    if old.check_for(&other) != Err(WirelessError::Denied) {
        return TestResult::Fail("an AP grant replayed against another concrete receiver");
    }
    fixture.radio.mode.store(2, Ordering::Release);
    fixture.radio.generation.store(2, Ordering::Release);
    if old.current() != Err(WirelessError::Denied) {
        return TestResult::Fail("AP request survived entry into station mode");
    }
    fixture.radio.mode.store(3, Ordering::Release);
    fixture.radio.generation.store(3, Ordering::Release);
    if old.current() != Err(WirelessError::Denied) {
        return TestResult::Fail("AP mode ABA resurrected an old request");
    }
    let current = match ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    ) {
        Ok(authority) => authority,
        Err(_) => return TestResult::Fail("new AP generation could not bind"),
    };
    fixture.source.0.store(false, Ordering::Release);
    if current.current() != Err(WirelessError::Denied) {
        return TestResult::Fail("closed request source kept AP operation authority");
    }
    let source = Arc::new(Source::new());
    let replacement_guard = match ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        source,
    ) {
        Ok(authority) => authority,
        Err(_) => return TestResult::Fail("new source could not bind current AP"),
    };
    crate::registry::unregister(fixture.radio.name());
    let replacement: Arc<dyn WirelessNetIface> = Arc::new(Radio::new(fixture.radio.name.clone()));
    crate::registry::register(replacement);
    if replacement_guard.current() != Err(WirelessError::Denied) {
        return TestResult::Fail("same-name replacement resurrected the old AP object");
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ap_control",
    ap_authority_fences_mode_aba_receiver_replacement_and_closed_source
);

fn ap_admission_cannot_follow_a_transferred_interface_into_another_namespace() -> TestResult {
    let fixture = match fixture() {
        Ok(fixture) => fixture,
        Err(error) => return TestResult::Fail(error),
    };
    let before = match ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex,
        fixture.source.clone(),
    ) {
        Ok(authority) => authority,
        Err(_) => return TestResult::Fail("namespace AP fixture grant"),
    };
    if ApControlAuthority::bind(
        fixture.admin.clone(),
        &fixture.iface,
        0,
        fixture.ifindex + 1,
        fixture.source.clone(),
    )
    .is_ok()
    {
        return TestResult::Fail("AP admission replaced the original request ifindex");
    }
    if fixture.admin.move_to_net_ns(0x7640).is_err() {
        return TestResult::Fail("actual AP fixture namespace transfer");
    }
    if before.current() != Err(WirelessError::Denied)
        || ApControlAuthority::bind(
            fixture.admin.clone(),
            &fixture.iface,
            0,
            fixture.ifindex,
            fixture.source.clone(),
        )
        .is_ok()
    {
        return TestResult::Fail(
            "old-namespace AP request followed a current handle's new namespace",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "wireless/ap_control",
    ap_admission_cannot_follow_a_transferred_interface_into_another_namespace
);
