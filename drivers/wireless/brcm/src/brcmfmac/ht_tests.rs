//! Native firmware-owned HT20/SGI admission through CR4/common-ring DMA.
use super::*;

fn wire_and_data() -> Result<(), &'static str> {
    for version in [5, 6] {
        let h =
            Harness::new_features(version, false, false, false, 36, None, (None, Some((7, 0))))?;
        let mut expected = [0; 26];
        expected[..6].copy_from_slice(&[32, 16, 31, 255, 255, 255]);
        expected[15] = 1;
        for band in [2400, 5000] {
            if h.device
                .phy_capabilities(band)
                .is_none_or(|caps| caps.ht != expected || caps.vht.is_some())
            {
                return Err("actual PCIe RX chains/BW receipt lost bounded HT capability");
            }
        }
        if h.device.phy_capabilities(6000).is_some()
            || h.device.state.try_lock().unwrap().station.ht_connection()
        {
            return Err("PCIe HT capability fabricated6GHz or active PHY metadata");
        }
        h.associate(false)?;
        if !h.device.state.try_lock().unwrap().station.ht_connection()
            || !h
                .bus
                .commands()
                .iter()
                .any(|(id, bytes, _)| *id == 262 && bytes.starts_with(b"assoc_resp_ies\0"))
        {
            return Err("PCIe actual HT request/response verification missing");
        }
        ready(h.device.disassociate())?.map_err(|_| "PCIe HT disconnect")?;
        if h.device.state.try_lock().unwrap().station.ht_connection() || h.bus.stats().5 != 0 {
            return Err("PCIe HT teardown retained port or freed published DMA");
        }
        drop(h);
        for (secured, pmf, channel) in [(false, false, 6), (true, false, 36), (true, true, 149)] {
            composition_phy(version, secured, secured, false, channel, pmf, Some((7, 0)))?;
        }
    }
    Ok(())
}
fn smoke_brcmf_ht20_native_capability_open_wpa2_pmf_dual_band_dhcp_and_ip() -> TestResult {
    wire_and_data().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht20",
    smoke_brcmf_ht20_native_capability_open_wpa2_pmf_dual_band_dhcp_and_ip
);

fn denied() -> Result<(), &'static str> {
    for version in [5, 6] {
        for (chains, fault) in [(0, 0), (8, 0), (7, 1)] {
            if Harness::new_features(
                version,
                true,
                false,
                false,
                6,
                None,
                (None, Some((chains, fault))),
            )
            .is_ok()
            {
                return Err("PCIe invalid RX-chain/wider BW receipt enabled HT");
            }
        }
        for fault in [2, 3, 4, 6, 8, 9] {
            let h = Harness::new_features(
                version,
                true,
                false,
                false,
                6,
                None,
                (None, Some((7, fault))),
            )?;
            if h.associate(true).is_ok()
                || h.device.link_up()
                || h.device.connected_bssid().is_some()
                || h.device.state.try_lock().unwrap().station.ht_connection()
                || h.bus.stats().5 != 0
            {
                return Err("PCIe wide/foreign/downgraded HT receipt admitted or freed DMA");
            }
            if fault == 9 && h.bus.commands().iter().any(|(id, _, _)| *id == 26) {
                return Err("PCIe absent WMM reached native join");
            }
            h.bus.stale_authorization();
            h.pump();
            if h.device.link_up() {
                return Err("PCIe late HT events revived denied owner");
            }
        }
    }
    Ok(())
}
fn smoke_brcmf_ht20_native_probe_current_peer_and_phy_denials() -> TestResult {
    denied().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht20",
    smoke_brcmf_ht20_native_probe_current_peer_and_phy_denials
);

fn cancelled() -> Result<(), &'static str> {
    for version in [5, 6] {
        let h = Harness::new_features(version, true, false, false, 6, None, (None, Some((7, 5))))?;
        if h.associate(true).is_ok() {
            return Err("PCIe held HT verification opened port");
        }
        h.bus.phy_profile(7, 0);
        h.bus.stale_authorization();
        h.pump();
        if h.device.link_up()
            || h.device.connected_bssid().is_some()
            || h.device.state.try_lock().unwrap().station.ht_connection()
            || h.bus.stats().5 != 0
            || h.associate(true).is_ok()
        {
            return Err("PCIe cancelled native PHY verification revived owner or freed DMA");
        }
    }
    Ok(())
}
fn smoke_brcmf_ht20_cancelled_actual_phy_verification_retains_dma() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht20",
    smoke_brcmf_ht20_cancelled_actual_phy_verification_retains_dma
);
