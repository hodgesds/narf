//! The production captured-target helper over actual native runtime fixtures.
//! Retained events never look up the ambient TEST_DEV successor.
use super::*;
use narf_net::iface::{OpenStopEvent, OpenStopTarget};

#[derive(Debug)]
struct Recorder(IrqSafeSpinLock<Option<OpenStopEvent>>);
impl OpenStopTarget for Recorder {
    fn transition(&self, event: OpenStopEvent) {
        *self.0.lock() = Some(event);
    }
}
fn ownership() -> Result<(), &'static str> {
    let old = up_down(FwCfg::default())?;
    let target = old.netdev.admin_target();
    let recorder = Arc::new(Recorder(IrqSafeSpinLock::new(None)));
    let snapshot = narf_net::iface::lookup(old.name).ok_or("actual original ndo registration")?;
    ensure!(
        narf_net::iface::set_open_stop_target(&snapshot, recorder.clone()),
        "native ndo recorder"
    );
    let admin = narf_net::stack::kernel_admin(old.name).ok_or("actual ndo metadata authority")?;
    admin.set_link(true).map_err(|_| "actual original ndo UP")?;
    let up = recorder
        .0
        .lock()
        .take()
        .ok_or("actual retained UP transition")?;
    // A second real runtime fixture becomes the ambient test dispatcher.
    // Delivering the old callback must still address its captured receiver.
    let next = up_down(FwCfg::default())?;
    target.transition(up.clone());
    ensure!(
        old.netdev.admin_up() && !next.netdev.admin_up(),
        "retained ndo receiver changed to successor"
    );
    old.netdev.request_admin(false);
    admin
        .move_to_net_ns(0x7611)
        .map_err(|_| "actual ndo namespace transfer")?;
    target.transition(up.clone());
    ensure!(
        !old.netdev.admin_up() && !next.netdev.admin_up(),
        "stale UP survived namespace change"
    );
    admin
        .move_to_net_ns(0)
        .map_err(|_| "actual ndo namespace return")?;
    target.transition(up.clone());
    ensure!(
        !old.netdev.admin_up(),
        "namespace round trip revived old UP generation"
    );
    admin
        .set_link(false)
        .map_err(|_| "actual original ndo DOWN")?;
    let down = recorder
        .0
        .lock()
        .take()
        .ok_or("actual retained DOWN transition")?;
    ensure!(
        narf_net::iface::retire_for_rebind(old.name),
        "actual ndo retirement"
    );
    let name = narf_net::iface::rebind_name(old.name).ok_or("original ndo name")?;
    narf_net::iface::register(name, old.netdev.mac(), test_send);
    old.netdev.request_admin(true);
    next.netdev.request_admin(true);
    target.transition(down);
    target.transition(up);
    ensure!(
        !old.netdev.admin_up() && next.netdev.admin_up(),
        "retired DOWN cleaned successor or stale UP restarted old device"
    );
    Ok(())
}
fn ath11k_native_ndo_target_retains_receiver_and_refuses_stale_up_generations() -> TestResult {
    ownership().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath11k/admin_target",
    ath11k_native_ndo_target_retains_receiver_and_refuses_stale_up_generations
);
