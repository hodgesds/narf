//! Concrete P2P-client group netdev metadata lifecycle: legacy NEW/DEL of
//! iftype 8 on the actual registered parent, its own Ethernet entry and
//! vif slot, role admission and worker-ordered native retirement.
use super::*;
fn group_netdev() -> Result<(), &'static str> {
    let (_session, concrete) = setup()?;
    let parent = concrete.binding.iface.clone();
    if !parent.supports_virtual_interfaces() || parent.async_control_iftypes() != 1 << 10 {
        return Err("type 8 NEW must route through the legacy netdev path");
    }
    // The fixture parent is an AP: no group link beside a home AP.
    if !matches!(
        parent.new_virtual_interface("p2p-grp0", 8, None),
        Err(WirelessError::Busy)
    ) {
        return Err("group netdev admitted beside a home AP");
    }
    parent.set_iftype(2).map_err(|_| "home station role")?;
    if !matches!(
        parent.new_virtual_interface("p2p-grp0", 9, None),
        Err(WirelessError::NotSupported)
    ) {
        return Err("GO netdev invented without a non-home AP owner");
    }
    let group = parent
        .new_virtual_interface("p2p-grp0", 8, None)
        .map_err(|_| "P2P-client group netdev NEW")?;
    let entry = narf_net::iface::lookup("p2p-grp0").ok_or("group Ethernet entry")?;
    if group.current_iftype() != 8
        || group.wiphy_id() != parent.wiphy_id()
        || group.mac() == parent.mac()
        || group.mac() == concrete.child.mac()
        || group.mac()[0] & 3 != 2
        || group.link_up()
        || entry.carrier
        || group.rx_ring().lock().is_some()
        || group.tx_ring().lock().is_some()
        || group.control_namespace().is_some()
        || !narf_wireless::registry::list()
            .iter()
            .any(|iface| Arc::ptr_eq(iface, &group))
        || group.get_wireless_info().modes != narf_wireless::iface::WirelessModes::STATION
    {
        return Err("group netdev metadata, address, carrier or rings");
    }
    if !matches!(
        parent.new_virtual_interface("p2p-grp1", 8, None),
        Err(WirelessError::Busy)
    ) {
        return Err("second concurrent group link admitted");
    }
    if !matches!(parent.set_iftype(3), Err(WirelessError::Busy))
        || !matches!(parent.set_iftype(6), Err(WirelessError::Busy))
    {
        return Err("home role left station beside a group netdev");
    }
    // No native group vif before the first join: nothing to retire.
    group.delete_virtual_interface().map_err(|_| "group DEL")?;
    if narf_net::iface::lookup("p2p-grp0").is_some()
        || narf_wireless::registry::list()
            .iter()
            .any(|iface| Arc::ptr_eq(iface, &group))
        || group.delete_virtual_interface().is_ok()
    {
        return Err("DEL left the netdev discoverable or repeated");
    }
    // The slot stays owned until the worker's ordered retirement.
    if !matches!(
        parent.new_virtual_interface("p2p-grp2", 8, None),
        Err(WirelessError::Busy)
    ) {
        return Err("group slot reused before native retirement");
    }
    run(Box::pin(parent.poll_p2p_group()));
    let again = parent
        .new_virtual_interface("p2p-grp0", 8, None)
        .map_err(|_| "group NEW after retirement")?;
    again
        .delete_virtual_interface()
        .map_err(|_| "second group DEL")?;
    run(Box::pin(parent.poll_p2p_group()));
    parent
        .set_iftype(3)
        .map_err(|_| "home AP after group retirement")?;
    Ok(())
}
fn mt76_p2p_group_netdev_new_del_owns_slot_and_ethernet_entry() -> TestResult {
    group_netdev().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_group_netdev_new_del_owns_slot_and_ethernet_entry
);
