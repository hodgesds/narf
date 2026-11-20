//! Native firmware-owned HT20/SGI admission through SDPCM/BCDC.
use super::*;

fn wire_and_data() -> Result<(), &'static str> {
    let h = Harness::new_features(false, None, None, Some((1, 0)))?;
    let mut expected = [0; 26];
    expected[..4].copy_from_slice(&[32, 16, 31, 255]);
    expected[15] = 1;
    if !h.device.get_wireless_info().hw_caps.ht_supported
        || h.device
            .phy_capabilities(2400)
            .is_none_or(|caps| caps.ht != expected || caps.vht.is_some())
        || h.device.phy_capabilities(5000).is_some()
        || h.device.phy_capabilities(6000).is_some()
        || h.device.state.try_lock().unwrap().station.ht_connection()
    {
        return Err("actual nmode/rxchain/bandwidth receipts did not bound HT capability");
    }
    h.scan_and_associate(false)?;
    if !h.device.state.try_lock().unwrap().station.ht_connection()
        || !h
            .bus
            .firmware
            .lock()
            .mfp_commands()
            .iter()
            .any(|(id, bytes)| *id == 262 && bytes.starts_with(b"assoc_resp_ies\0"))
    {
        return Err("firmware HT request/response receipts did not precede port publication");
    }
    ready(h.device.disassociate())?.map_err(|_| "HT native teardown")?;
    if h.device.state.try_lock().unwrap().station.ht_connection() || h.device.link_up() {
        return Err("HT teardown retained verified PHY metadata/port");
    }
    drop(h);
    for (secured, pmf) in [(false, false), (true, false), (true, true)] {
        composition_phy(secured, pmf, Some((1, 0)))?;
    }
    Ok(())
}
fn smoke_cyw_ht20_native_capability_receipts_open_wpa2_pmf_dhcp_and_ip() -> TestResult {
    wire_and_data().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht20",
    smoke_cyw_ht20_native_capability_receipts_open_wpa2_pmf_dhcp_and_ip
);

fn denied() -> Result<(), &'static str> {
    for flags in [
        narf_wireless::reg::RegFlags::INDOOR_ONLY,
        narf_wireless::reg::RegFlags::from_bits_retain(16),
    ] {
        let db = Arc::new(narf_wireless::reg::db::Database::new());
        let mut policy = firmware::domain();
        policy.rules[0].flags = flags;
        db.install(policy);
        let h = Harness::new_features(true, Some(db), None, Some((1, 0)))?;
        if h.scan_and_associate(true).is_ok()
            || h.bus.firmware.lock().command_count(26) != 0
            || h.device.link_up()
        {
            return Err("unqualified indoor/unknown rule admitted native HT station TX");
        }
    }
    for (chains, fault) in [(0, 0), (8, 0), (1, 1)] {
        if Harness::new_features(true, None, None, Some((chains, fault))).is_ok() {
            return Err("invalid native RX-chain/wider-bandwidth receipt admitted HT");
        }
    }
    for fault in [2, 3, 4, 6, 8, 9] {
        let h = Harness::new_features(true, None, None, Some((1, fault)))?;
        if h.scan_and_associate(true).is_ok()
            || h.device.link_up()
            || h.device.connected_bssid().is_some()
            || h.device.state.try_lock().unwrap().station.ht_connection()
        {
            return Err("wide/current-peer/HT/MCS/WMM downgrade opened FullMAC port");
        }
        if fault == 9 && h.bus.firmware.lock().command_count(26) != 0 {
            return Err("missing AP WMM reached native join publication");
        }
        h.device.drain();
        if h.device.link_up() {
            return Err("late native HT events revived denied owner");
        }
    }
    Ok(())
}
fn smoke_cyw_ht20_probe_and_actual_phy_receipt_denials() -> TestResult {
    denied().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht20",
    smoke_cyw_ht20_probe_and_actual_phy_receipt_denials
);

fn cancelled() -> Result<(), &'static str> {
    let h = Harness::new_features(true, None, None, Some((1, 5)))?;
    if h.scan_and_associate(true).is_ok() {
        return Err("held native HT association response opened port");
    }
    h.bus.firmware.lock().phy_profile(1, 0);
    h.device.drain();
    if h.device.link_up()
        || h.device.connected_bssid().is_some()
        || h.device.state.try_lock().unwrap().station.ht_connection()
        || h.scan_and_associate(true).is_ok()
    {
        return Err("cancelled HT verification reused native receipt/owner");
    }
    Ok(())
}
fn smoke_cyw_ht20_cancelled_actual_association_response_cannot_reauthorize() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht20",
    smoke_cyw_ht20_cancelled_actual_association_response_cannot_reauthorize
);
