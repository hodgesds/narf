// SPDX-License-Identifier: GPL-2.0-or-later
//! PMF offload through actual SDPCM/BCDC controls and correlated peer events.
use super::*;

const REQUIRED_RSN: [u8; 28] = [
    48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 192, 0, 0, 0, 0, 15,
    172, 6,
];

fn smoke_cyw_required_pmf_native_receipts_dhcp_and_exact_ip() -> TestResult {
    composition_mfp(true, true).map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmf",
    smoke_cyw_required_pmf_native_receipts_dhcp_and_exact_ip
);

fn wire() -> Result<(), &'static str> {
    let h = Harness::new_config(true, None, Some((true, true, 0)))?;
    if h.device.cipher_suites() != [0x000f_ac04, 0x000f_ac06] {
        return Err("firmware MFP capability was absent from wiphy cipher suites");
    }
    h.scan_and_associate(true)?;
    let commands = h.bus.firmware.lock().mfp_commands();
    let cipher = commands
        .iter()
        .position(|(id, _)| *id == 134)
        .ok_or("PMF missing cipher command")?;
    let set = commands
        .iter()
        .position(|(id, bytes)| *id == 263 && bytes == b"mfp\0\x02\0\0\0")
        .ok_or("PMF native mode2 bytes")?;
    if set <= cipher
        || !commands
            .iter()
            .any(|(id, bytes)| *id == 262 && bytes.starts_with(b"assoc_req_ies\0"))
        || !h
            .device
            .state
            .try_lock()
            .unwrap()
            .station
            .management_protection()
    {
        return Err("PMF mode/actual association receipt ordering");
    }
    ready(h.device.disassociate())?.map_err(|_| "PMF native disconnect")?;
    if h.device
        .state
        .try_lock()
        .unwrap()
        .station
        .management_protection()
        || h.device.link_up()
    {
        return Err("PMF disconnect retained protected-port metadata");
    }
    Ok(())
}
fn smoke_cyw_required_pmf_wire_cipher_order_actual_negotiation_and_teardown() -> TestResult {
    wire().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmf",
    smoke_cyw_required_pmf_wire_cipher_order_actual_negotiation_and_teardown
);

fn denied() -> Result<(), &'static str> {
    for fault in 0..=4 {
        let h = Harness::new_config(true, None, Some((fault != 0, true, fault)))?;
        if fault == 0 && h.device.cipher_suites() != [0x000f_ac04] {
            return Err("unsupported firmware advertised BIP management cipher");
        }
        if h.scan_and_associate(true).is_ok()
            || h.device.link_up()
            || h.device.connected_bssid().is_some()
            || h.device
                .state
                .try_lock()
                .unwrap()
                .station
                .management_protection()
        {
            return Err("unsupported/downgraded/mismatched PMF authorized the host port");
        }
        if fault == 0 && h.bus.firmware.lock().command_count(26) != 0 {
            return Err("missing MFP capability still submitted SET_SSID");
        }
        h.device.drain();
        if h.device.link_up() {
            return Err("late PMF events revived a rejected link");
        }
    }
    Ok(())
}
fn smoke_cyw_required_pmf_capability_readback_peer_and_request_denials() -> TestResult {
    denied().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmf",
    smoke_cyw_required_pmf_capability_readback_peer_and_request_denials
);

fn cancelled() -> Result<(), &'static str> {
    let h = Harness::new_config(true, None, Some((true, true, 5)))?;
    // The bounded harness drops the actual association waiter while its
    // assoc_req_ies IOCTL is outstanding, after key/link events already arrived.
    if h.scan_and_associate(true).is_ok() {
        return Err("held PMF receipt opened port");
    }
    h.bus.firmware.lock().mfp_profile(true, true, 0);
    h.device.drain();
    if h.device.link_up()
        || h.device.connected_bssid().is_some()
        || h.device
            .state
            .try_lock()
            .unwrap()
            .station
            .management_protection()
    {
        return Err("cancelled PMF verification reused a late successful receipt");
    }
    Ok(())
}
fn smoke_cyw_required_pmf_cancelled_native_receipt_cannot_reauthorize() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmf",
    smoke_cyw_required_pmf_cancelled_native_receipt_cannot_reauthorize
);

fn nl_connect_attrs() -> Vec<u8> {
    fn attr(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        bytes.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
    }
    let mut bytes = Vec::new();
    attr(&mut bytes, 52, b"test");
    attr(&mut bytes, 6, &AP);
    attr(&mut bytes, 38, &2437u32.to_ne_bytes());
    attr(&mut bytes, 254, &[0x11; 32]);
    for (kind, value) in [
        (66, 1u32),
        (75, 2),
        (76, 0x000fac02),
        (73, 0x000fac04),
        (74, 0x000fac04),
    ] {
        attr(&mut bytes, kind, &value.to_ne_bytes());
    }
    // Literal required-PMF CCMP/PSK RSNE, zero PMKIDs, BIP-CMAC128.
    attr(&mut bytes, 42, &REQUIRED_RSN);
    bytes
}

fn nl_connect() -> Result<(), &'static str> {
    for supported in [false, true] {
        let h = Harness::new_config(true, None, Some((supported, true, 0)))?;
        if h.device.supports_wpa2_mfp_offload() != supported {
            return Err("native MFP/supplicant probes did not reach CONNECT capability");
        }
        if supported {
            ready(h.device.scan(ScanRequest {
                ssids: vec![b"test".to_vec()],
                frequencies_mhz: vec![2437],
                channels: vec![6],
                active: false,
                random_mac: None,
                colocated_6ghz: false,
                duration_tu: None,
                duration_mandatory: false,
                extra_ies: Vec::new(),
            }))?
            .map_err(|_| "PMF typed-SME preflight discovery")?;
            let mut ocv = REQUIRED_RSN;
            ocv[21] = 64; // Caller promises operating-channel validation.
            let before = h.bus.firmware.lock().control_count();
            let result = ready(h.device.associate(AssociateRequest {
                bssid: AP,
                ssid: b"test".to_vec(),
                frequency_mhz: 2437,
                channel: 6,
                security: narf_wireless::SecurityConfig::Wpa2 { psk: [0x11; 32] },
                ie: ocv.to_vec(),
            }))?;
            if !matches!(result, Err(WirelessError::NotSupported))
                || h.bus.firmware.lock().control_count() != before
                || h.device.link_up()
            {
                return Err("PMF canonical RSNE discarded caller OCV promise after native writes");
            }
        }
        let before = h.bus.firmware.lock().control_count();
        let result = ready(narf_wireless::nl80211::connect_for_test(
            h.device.clone(),
            &nl_connect_attrs(),
        ))?;
        if !supported {
            if result != Err(95) || h.bus.firmware.lock().control_count() != before {
                return Err("unsupported nl80211 PMF CONNECT reached native commands");
            }
        } else if result.is_err()
            || !h.device.link_up()
            || h.device.connected_bssid() != Some(AP)
            || !h
                .device
                .state
                .try_lock()
                .unwrap()
                .station
                .management_protection()
            || !h
                .bus
                .firmware
                .lock()
                .mfp_commands()
                .iter()
                .any(|(id, bytes)| *id == 262 && bytes.starts_with(b"assoc_req_ies\0"))
        {
            return Err("nl80211 required-PMF CONNECT did not complete native verification");
        }
    }
    Ok(())
}
fn smoke_cyw_required_pmf_nl80211_connect_reaches_native_offload() -> TestResult {
    nl_connect().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmf",
    smoke_cyw_required_pmf_nl80211_connect_reaches_native_offload
);
