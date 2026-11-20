// SPDX-License-Identifier: GPL-2.0-or-later
//! Required PMF through actual CR4/common-ring control DMA and firmware events.
use super::*;

fn conversation() -> Result<(), &'static str> {
    for version in [5, 6] {
        for keys_first in [false, true] {
            composition_mfp(version, true, keys_first, false, 6, true)?;
        }
    }
    Ok(())
}
fn smoke_brcmf_required_pmf_native_key_orders_dhcp_and_exact_ip() -> TestResult {
    conversation().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/pmf",
    smoke_brcmf_required_pmf_native_key_orders_dhcp_and_exact_ip
);

fn denied() -> Result<(), &'static str> {
    for version in [5, 6] {
        for fault in 0..=4 {
            let h = Harness::new_profile(
                version,
                true,
                false,
                false,
                6,
                None,
                Some((fault != 0, true, fault)),
            )?;
            if fault == 0 && h.device.cipher_suites() != [0x000f_ac04] {
                return Err("PCIe firmware without MFP advertised BIP cipher");
            }
            if h.associate(true).is_ok()
                || h.device.link_up()
                || h.device.connected_bssid().is_some()
                || h.device
                    .state
                    .try_lock()
                    .unwrap()
                    .station
                    .management_protection()
                || h.bus.stats().5 != 0
            {
                return Err("PCIe unsupported/downgraded/foreign PMF authorized or freed live DMA");
            }
            if fault == 0 && h.bus.commands().iter().any(|(id, _, _)| *id == 26) {
                return Err("PCIe missing MFP support submitted SET_SSID");
            }
            h.bus.stale_authorization();
            h.pump();
            if h.device.link_up() {
                return Err("PCIe late PMF events revived rejected link");
            }
        }
    }
    Ok(())
}
fn smoke_brcmf_required_pmf_capability_and_correlated_receipt_denials() -> TestResult {
    denied().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/pmf",
    smoke_brcmf_required_pmf_capability_and_correlated_receipt_denials
);

fn wire() -> Result<(), &'static str> {
    let h = Harness::new_profile(6, true, true, false, 6, None, Some((true, true, 0)))?;
    if h.device.cipher_suites() != [0x000f_ac04, 0x000f_ac06] {
        return Err("PCIe actual firmware MFP probe did not reach wiphy cipher suites");
    }
    h.associate(true)?;
    let commands = h.bus.commands();
    let cipher = commands
        .iter()
        .position(|(id, _, _)| *id == 134)
        .ok_or("PCIe PMF missing WSEC")?;
    let set = commands
        .iter()
        .position(|(id, bytes, _)| *id == 263 && bytes == b"mfp\0\x02\0\0\0")
        .ok_or("PCIe PMF mode bytes")?;
    if set <= cipher
        || !commands
            .iter()
            .any(|(id, bytes, _)| *id == 262 && bytes.starts_with(b"assoc_req_ies\0"))
        || !h
            .device
            .state
            .try_lock()
            .unwrap()
            .station
            .management_protection()
    {
        return Err("PCIe PMF lacked ordered cipher/mode/actual association receipts");
    }
    ready(h.device.disassociate())?.map_err(|_| "PCIe PMF disconnect")?;
    if h.device
        .state
        .try_lock()
        .unwrap()
        .station
        .management_protection()
        || h.device.link_up()
        || h.bus.stats().5 != 0
    {
        return Err("PCIe PMF teardown retained authorization or freed uncertain mappings");
    }
    Ok(())
}
fn smoke_brcmf_required_pmf_cipher_order_verification_and_teardown() -> TestResult {
    wire().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/pmf",
    smoke_brcmf_required_pmf_cipher_order_verification_and_teardown
);

fn cancelled() -> Result<(), &'static str> {
    for version in [5, 6] {
        let h = Harness::new_profile(version, true, false, false, 6, None, Some((true, true, 5)))?;
        if h.associate(true).is_ok() {
            return Err("PCIe held PMF request receipt opened port");
        }
        h.bus.mfp_profile(true, true, 0);
        h.bus.stale_authorization();
        h.pump();
        if h.device.link_up()
            || h.device.connected_bssid().is_some()
            || h.device
                .state
                .try_lock()
                .unwrap()
                .station
                .management_protection()
            || h.bus.stats().5 != 0
        {
            return Err("PCIe cancelled PMF waiter revived link or reclaimed posted DMA");
        }
    }
    Ok(())
}
fn smoke_brcmf_required_pmf_cancelled_native_verification_retains_dma() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/pmf",
    smoke_brcmf_required_pmf_cancelled_native_verification_retains_dma
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
    // MFPC|MFPR with the IEEE default BIP-CMAC128 management suite.
    attr(
        &mut bytes,
        42,
        &[
            48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 192, 0,
        ],
    );
    bytes
}

fn nl_connect() -> Result<(), &'static str> {
    for version in [5, 6] {
        for supported in [false, true] {
            let h = Harness::new_profile(
                version,
                true,
                false,
                false,
                6,
                None,
                Some((supported, true, 0)),
            )?;
            if h.device.supports_wpa2_mfp_offload() != supported {
                return Err("PCIe native MFP capability did not reach CONNECT");
            }
            let before = h.bus.commands();
            let result = ready(narf_wireless::nl80211::connect_for_test(
                h.device.clone(),
                &nl_connect_attrs(),
            ))?;
            if !supported {
                if result != Err(95) || h.bus.commands() != before {
                    return Err("unsupported PCIe nl80211 PMF CONNECT wrote native commands");
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
                    .commands()
                    .iter()
                    .any(|(id, bytes, _)| *id == 262 && bytes.starts_with(b"assoc_req_ies\0"))
                || h.bus.stats().5 != 0
            {
                return Err("PCIe nl80211 PMF CONNECT missed native receipts or retained DMA");
            }
        }
    }
    Ok(())
}
fn smoke_brcmf_required_pmf_nl80211_connect_reaches_native_offload() -> TestResult {
    nl_connect().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/pmf",
    smoke_brcmf_required_pmf_nl80211_connect_reaches_native_offload
);
