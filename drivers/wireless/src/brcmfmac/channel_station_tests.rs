// SPDX-License-Identifier: GPL-2.0-or-later
//! BCM43602 dual-band admission through the actual retained msgbuf owner.
use super::*;

fn smoke_brcmf_native_5ghz_open_wpa2_to_dhcp_and_bidirectional_ip() -> TestResult {
    for version in [5, 6] {
        for channel in [36, 149] {
            for secure in [false, true] {
                if let Err(error) = composition_channel(version, secure, secure, false, channel) {
                    return TestResult::Fail(error);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_brcmf_native_5ghz_open_wpa2_to_dhcp_and_bidirectional_ip
);

fn scan_request(channels: &[u32], active: bool) -> ScanRequest {
    ScanRequest {
        ssids: vec![b"test".to_vec()],
        frequencies_mhz: Vec::new(),
        channels: channels.to_vec(),
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies: Vec::new(),
    }
}
fn policy() -> Result<(), &'static str> {
    use narf_wireless::reg::{RegFlags, RegRule};
    let (adapter, bus) = firmware::create(6, false).map_err(|_| "native dual-band runtime")?;
    bus.channel(36);
    let mut domain = firmware::domain();
    domain.rules.push(RegRule {
        freq_start_mhz: 5170,
        freq_end_mhz: 5250,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: RegFlags::empty(),
    });
    domain.rules.push(RegRule {
        freq_start_mhz: 5175,
        freq_end_mhz: 5185,
        max_bandwidth_mhz: 20,
        max_power_dbm: 17,
        flags: RegFlags::NO_IR,
    });
    let mut station = ready(Station::initialize(adapter, &[], domain))?
        .map_err(|_| "NO_IR dual-band station initialization")?;
    if !station.channels.contains(&36) || station.channels.contains(&255) {
        return Err("NO_IR removed passive reception or unknown channel was admitted");
    }
    let before = bus.commands().len();
    if !matches!(
        ready(station.scan(scan_request(&[6, 36], true)))?,
        Err(Error::Unsupported)
    ) || bus.commands().len() != before
    {
        return Err("permissive channel hid a restricted active-probe channel");
    }
    let found = ready(station.scan(scan_request(&[36], false)))?
        .map_err(|_| "NO_IR passive native scan")?;
    if found.len() != 1 || found[0].channel != 36 || found[0].frequency_mhz != 5180 {
        return Err("5 GHz passive BSS was lost or aliased to 2.4 GHz");
    }
    let before = bus.commands().len();
    let mut request = Harness::request(false);
    request.channel = 36;
    request.frequency_mhz = 5180;
    if ready(station.associate(request))? != Err(Error::Unsupported)
        || bus.commands().len() != before
        || station.bssid.is_some()
    {
        return Err("NO_IR partial overlap acquired native association/TX authority");
    }
    Ok(())
}
fn smoke_brcmf_5ghz_no_ir_keeps_passive_discovery_and_closes_all_active_tx() -> TestResult {
    policy().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_brcmf_5ghz_no_ir_keeps_passive_discovery_and_closes_all_active_tx
);

fn discovery() -> Result<(), &'static str> {
    let harness = Harness::new_channel(6, false, false, false, 36)?;
    let info = harness.device.get_wireless_info();
    if info.bands.len() != 2
        || info.bands[0].freq_mhz != 2400
        || info.bands[0].channels != [6]
        || info.bands[1].freq_mhz != 5000
        || info.bands[1].channels != [36, 52, 149, 165]
        || info.hw_caps.ht_supported
        || info.hw_caps.vht_supported
    {
        return Err("dual-band facade differs from actual valid channels/current policy");
    }
    harness.scan()?;
    let commands = harness.bus.commands();
    let caps: Vec<&[u8]> = commands
        .iter()
        .filter(|(cmd, input, _)| *cmd == 263 && input.starts_with(b"bw_cap\0"))
        .map(|(_, input, _)| &input[7..])
        .collect();
    if caps != [&[2, 0, 0, 0, 1, 0, 0, 0][..], &[1, 0, 0, 0, 1, 0, 0, 0][..]] {
        return Err("native firmware bandwidth was not limited to 20 MHz on both bands");
    }
    let body = commands
        .iter()
        .find_map(|(cmd, input, _)| (*cmd == 263 && input.starts_with(b"escan\0")).then_some(input))
        .ok_or("native escan command absent")?;
    // iovar's six bytes precede the exact escan v1 channel count/list.
    if body[74..78] != [1, 0, 1, 0] || body[78..80] != [0x24, 0xd0] {
        return Err("5 GHz escan chanspec/count differs from Linux wire values");
    }
    Ok(())
}
fn smoke_brcmf_5ghz_wiphy_and_native_scan_use_actual_band() -> TestResult {
    discovery().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_brcmf_5ghz_wiphy_and_native_scan_use_actual_band
);

fn smoke_brcmf_wide_firmware_bandwidth_cannot_publish_the_twenty_mhz_profile() -> TestResult {
    let Ok((adapter, bus)) = firmware::create(6, false) else {
        return TestResult::Fail("native bandwidth fixture");
    };
    bus.hold_wide_bandwidth();
    if !matches!(
        ready(Station::initialize(adapter, &[], firmware::domain())),
        Ok(Err(Error::Unsupported))
    ) || bus
        .commands()
        .iter()
        .any(|(cmd, _, _)| matches!(cmd, 2 | 26 | 217))
    {
        return TestResult::Fail(
            "unconfirmed firmware width reached WLC_UP/channel or association admission",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/channel",
    smoke_brcmf_wide_firmware_bandwidth_cannot_publish_the_twenty_mhz_profile
);
