//! Stable-interface recovery: a retired generation hands its `wlan%d`
//! netdev (ifindex, operator state, counters) to the next generation through
//! `narf_net::iface::retire_for_rebind`/`rebind_name`, as mac80211
//! `ieee80211_restart_hw` keeps the `net_device` across a firmware restart.
use super::*;
use crate::ath10k::interface;

/// Associate a rebound generation. Its carrier counters continue the old
/// netdev's, so `Harness::join`'s first-carrier checks do not apply.
fn associate(h: &Harness) -> Result<(), &'static str> {
    h.scan()?;
    if !matches!(
        drive(h.device.associate_for_test(h.request(), [0x73; 32])),
        Poll::Ready(Ok(()))
    ) || !h.device.link_up()
    {
        return Err("rebound generation failed to associate");
    }
    Ok(())
}

fn smoke_ath10k_recovery_rebinds_same_wlan_name_ifindex_and_operator_state() -> TestResult {
    for (version, dialect) in [(1, Dialect::Main), (4, Dialect::Tlv), (6, Dialect::TenFour)] {
        let result = (|| {
            let old = Harness::new(version, dialect, true);
            old.join()?;
            let name = old.name.clone();
            let before = narf_net::iface::lookup(&name).ok_or("old netdev")?;
            // The production retire path for this generation.
            old.device.retire_host();
            interface::remember_rebind(&name);
            if narf_net::iface::lookup(&name).is_some() {
                return Err("retired generation still registered");
            }
            // No other wlan%d allocation can take the retired name.
            let foreign = narf_net::iface::reserve_name("wlan%d");
            if foreign == name {
                return Err("retired name reallocated to another device");
            }
            drop(old);
            let (rebound, rebind) = interface::generation_name();
            if rebound != name || !rebind {
                return Err("recovery generation did not rebind the retired name");
            }
            *NEXT_NAME.lock() = Some(rebound);
            let new = Harness::new(version, dialect, true);
            let after = narf_net::iface::lookup(&new.name).ok_or("rebound netdev")?;
            let (up, down) = packets();
            if new.name != name
                || after.ifindex != before.ifindex
                || after.carrier
                || after.carrier_up_count != before.carrier_up_count
                || before.xmit(&up).is_ok()
            {
                return Err("rebind lost ifindex/counters or kept the old send hook");
            }
            associate(&new)?;
            narf_net::iface::send_on(&new.name, &up).map_err(|_| "rebound uplink")?;
            new.pump();
            let bytes = new.model(|m| m.data.as_mut().unwrap().downlink(&down));
            new.model(|m| m.data.as_mut().unwrap().queue.push_back(bytes));
            new.pump();
            if !new.received(&down) || !new.model(|m| m.data.as_ref().unwrap().uplink.contains(&up))
            {
                return Err("rebound generation data path");
            }
            // A publication with nothing retired allocates a fresh name.
            let (fresh, rebind) = interface::generation_name();
            if rebind || fresh == name {
                return Err("generation without a retired name reused one");
            }
            Ok(())
        })();
        if let Err(e) = result {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_recovery_rebinds_same_wlan_name_ifindex_and_operator_state
);

fn smoke_ath10k_rebind_name_refused_when_registered_or_never_retired() -> TestResult {
    let h = Harness::new(4, Dialect::Tlv, false);
    // A live registered name is never handed out again.
    interface::remember_rebind(&h.name);
    let (name, rebind) = interface::generation_name();
    if rebind || name == h.name {
        return TestResult::Fail("registered netdev name handed to a new generation");
    }
    // An unknown name falls back to a fresh allocation.
    interface::remember_rebind("wlan-never");
    let (fresh, rebind) = interface::generation_name();
    if rebind || fresh == "wlan-never" {
        return TestResult::Fail("never-retired name rebound");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/recovery",
    smoke_ath10k_rebind_name_refused_when_registered_or_never_retired
);
