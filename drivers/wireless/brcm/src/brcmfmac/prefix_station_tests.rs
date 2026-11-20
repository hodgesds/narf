// SPDX-License-Identifier: GPL-2.0-or-later
//! Full physical-ring firmware conversation; the station/port are never mocked.
use super::*;

fn composition_prefixed(prefix: u32, secured: bool, keys_first: bool) -> Result<(), &'static str> {
    let h = Harness::new_details(
        7,
        secured,
        keys_first,
        false,
        6,
        None,
        Configuration {
            mfp: None,
            phy: None,
            wide: None,
            vht: None,
            prefix,
            chip: None,
        },
    )?;
    let native = h.bus.clone();
    // Includes scan's real event buffer, original BSS/key/controlled port,
    // DHCP DORA, bidirectional kernel IP, held actual TX-status DMA, PS
    // acknowledgements and actual disconnect/flow-delete receipts.
    composition_native(h, secured, false, false)?;
    let (rings, offsets) = native.prefix_observations();
    if rings.contains(&0) || offsets.contains(&0) {
        return Err("native composition skipped a prefixed ring or explicit/shared RX path");
    }
    Ok(())
}
fn smoke_brcmf_v7_prefixed_open_scan_station_and_actual_dhcp_ip_terminals() -> TestResult {
    for prefix in [1, 4] {
        if let Err(error) = composition_prefixed(prefix, false, false) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/prefix",
    smoke_brcmf_v7_prefixed_open_scan_station_and_actual_dhcp_ip_terminals
);
fn smoke_brcmf_v7_prefixed_wpa2_requires_native_key_receipts_before_dhcp_ip() -> TestResult {
    for prefix in [2, 3] {
        for keys_first in [false, true] {
            if let Err(error) = composition_prefixed(prefix, true, keys_first) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/prefix",
    smoke_brcmf_v7_prefixed_wpa2_requires_native_key_receipts_before_dhcp_ip
);
