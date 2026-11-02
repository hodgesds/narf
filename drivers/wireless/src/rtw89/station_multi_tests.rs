// SPDX-License-Identifier: GPL-2.0-or-later
//! Two independently keyed native controller/HTT-free PCI packet models,
//! registered through the production family publisher and context callback.
use super::*;
use crate::rtw89::{endpoints, interface};

const SECOND: [u8; 6] = [2, 4, 6, 8, 10, 14];
impl Harness {
    fn function(own: [u8; 6], kept: Option<&str>) -> Self {
        let mut io = DriverModel::for_station(own);
        io.packets.consume = true;
        io.packets.release = true;
        let env = Arc::new(Env {
            clock: io.clock.clone(),
            entropy: AtomicBool::new(true),
        });
        let peer = Arc::new(IrqSafeSpinLock::new(Peer::for_station(true, own)));
        let plan = peer.lock().plan;
        let actor = peer.clone();
        io.packets.reaction = Some(Arc::new(move |bytes| {
            actor
                .lock()
                .react(bytes)
                .map_err(|_| crate::rtw89::packet_core::Error::Packet)
        }));
        let lifecycle = Arc::new(Lifecycle::new(io));
        let name = kept
            .and_then(narf_net::iface::rebind_name)
            .unwrap_or_else(|| narf_net::iface::reserve_name("r89-multi%d"));
        let device = Arc::new(Device::new(name, own, lifecycle.clone(), env.clone()));
        interface::publish(device.clone()).unwrap();
        narf_net::iface::set_link_state(name, true);
        device.admit_for_test();
        complete(device.activate()).unwrap();
        lifecycle
            .retained
            .try_lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .io
            .packets
            .inject(&peer.lock().ap.beacon())
            .unwrap();
        Self {
            device,
            lifecycle,
            peer,
            env,
            plan,
            native_dispatch: true,
        }
    }
    fn routed_data(&self, body: &[u8]) -> bool {
        let frame = udp_ipv4(
            AP,
            self.plan.station,
            self.plan.lease_ip,
            self.plan.server_ip,
            7001,
            9,
            body,
        );
        let before = self.peer.lock().uplink.len();
        let accepted = narf_net::iface::send_on(self.device.name(), &frame).is_ok();
        endpoints::drain();
        self.pump();
        let delivered = {
            let peer = self.peer.lock();
            peer.uplink.len() == before + 1 && peer.uplink.last() == Some(&frame)
        };
        accepted && delivered
    }
}

fn smoke_rtw8852b_two_native_functions_keep_keys_dma_and_revocation_independent() -> TestResult {
    let first = Harness::function(OWN, None);
    let second = Harness::function(SECOND, None);
    let joined = first.join().is_ok() && second.join().is_ok();
    let first_key = { first.peer.lock().ap.pairwise_tk() };
    let second_key = { second.peer.lock().ap.pairwise_tk() };
    if !joined
        || first.device.name() == second.device.name()
        || first_key.is_none()
        || second_key.is_none()
        || first_key == second_key
        || !first.routed_data(b"first")
        || !second.routed_data(b"second")
    {
        return TestResult::Fail("two independently keyed native stations did not route");
    }
    // The first function holds an actual published MPDU without its terminal
    // receipt; the second still progresses its own TXBD/RPQ and CCMP PN.
    first.peer.lock().hold_data = true;
    if !first.routed_data(b"held-first") || !second.routed_data(b"independent-terminal") {
        return TestResult::Fail("one function's native terminal wait blocked another");
    }
    first.model(|io| io.packets.authority.revoke());
    endpoints::drain();
    first.pump();
    if first.device.link_up() || !second.routed_data(b"second-after-first-revocation") {
        return TestResult::Fail("function authority loss crossed netdev/key lifetimes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/multiple",
    smoke_rtw8852b_two_native_functions_keep_keys_dma_and_revocation_independent
);

fn smoke_rtw8852b_native_function_rebind_retires_only_its_dispatch_generation() -> TestResult {
    let first = Harness::function(OWN, None);
    let second = Harness::function(SECOND, None);
    if first.join().is_err() || second.join().is_err() {
        return TestResult::Fail("dual native rebind fixture join");
    }
    let old = endpoints::cookie(first.device.name()).unwrap();
    let second_cookie = endpoints::cookie(second.device.name()).unwrap();
    let delivery = first.device.delivery_for_test();
    let name = interface::withdraw_keep_name(&first.device);
    let mut waiting = Box::pin(first.device.wait_withdrawn());
    if !waiting
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        .is_pending()
        || endpoints::cookie(&name) != Some(old)
        || narf_net::iface::lookup(&name).is_none()
        || !second.routed_data(b"second-during-old-ingress")
    {
        return TestResult::Fail("retirement released a name with an in-flight old ingress");
    }
    drop(delivery);
    complete(waiting);
    if !first
        .lifecycle
        .retained
        .try_lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .retire()
    {
        return TestResult::Fail("old generation did not earn native DMA reclamation");
    }
    let replacement = Harness::function(OWN, Some(&name));
    if replacement.join().is_err()
        || replacement.device.name() != name
        || endpoints::cookie(&name) == Some(old)
        || endpoints::cookie(second.device.name()) != Some(second_cookie)
        || endpoints::send(old, &[0; 14], TxMeta::plain()).is_ok()
        || !replacement.routed_data(b"new-generation")
        || !second.routed_data(b"second-survived-rebind")
    {
        return TestResult::Fail("rebind reused a retired callback or disturbed another function");
    }
    // A second withdrawal of the retired shell cannot unpublish the new one.
    interface::withdraw(&first.device);
    first.device.drain();
    if !replacement.routed_data(b"stale-remove-ignored") {
        return TestResult::Fail("stale old-shell removal withdrew the replacement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/multiple",
    smoke_rtw8852b_native_function_rebind_retires_only_its_dispatch_generation
);
