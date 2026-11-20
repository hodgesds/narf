// SPDX-License-Identifier: GPL-2.0-or-later
//! Caller Probe Request IEs through the native `vndr_ie` iovar.
//!
//! Expected bytes are literal Linux `brcmf_vndr_ie` records
//! (`cmd[4] count:u32 BRCMF_VNDR_IE_PRBREQ_FLAG:u32 element`), built here
//! independently of the driver encoder.
use super::*;

const VENDOR_A: [u8; 8] = [221, 6, 0x00, 0x90, 0x4c, 0x04, 0xaa, 0xbb];
const VENDOR_B: [u8; 7] = [221, 5, 0x50, 0x6f, 0x9a, 0x09, 0x01];

fn request(extra_ies: Vec<u8>, active: bool) -> ScanRequest {
    ScanRequest {
        ssids: vec![b"test".to_vec()],
        frequencies_mhz: vec![2437],
        channels: vec![6],
        active,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies,
    }
}
fn record(command: &[u8; 4], element: &[u8]) -> Vec<u8> {
    let mut out = command.to_vec();
    out.extend_from_slice(&[1, 0, 0, 0, 0x10, 0, 0, 0]);
    out.extend_from_slice(element);
    out
}
fn iovar(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"vndr_ie\0".to_vec();
    for record in records {
        out.extend_from_slice(record);
    }
    out
}
fn sets(harness: &Harness, name: &[u8]) -> Vec<Vec<u8>> {
    harness
        .bus
        .firmware
        .lock()
        .set_vars()
        .into_iter()
        .filter(|body| body.starts_with(name))
        .collect()
}
fn scan(harness: &Harness, ies: Vec<u8>, active: bool) -> Result<(), &'static str> {
    let found = ready(harness.device.scan(request(ies, active)))?
        .map_err(|_| "scan with Probe Request IEs")?;
    if found.len() != 1 || found[0].bssid != AP {
        return Err("Probe Request IEs changed the escan result");
    }
    Ok(())
}

fn lifecycle() -> Result<(), &'static str> {
    let harness = Harness::new(false)?;
    let mut both = VENDOR_A.to_vec();
    both.extend_from_slice(&VENDOR_B);
    scan(&harness, both.clone(), true)?;
    let all = harness.bus.firmware.lock().set_vars();
    let install = all
        .iter()
        .position(|body| body.starts_with(b"vndr_ie\0"))
        .ok_or("vndr_ie was not installed")?;
    let escan = all
        .iter()
        .position(|body| body.starts_with(b"escan\0"))
        .ok_or("escan absent")?;
    if install > escan {
        return Err("Probe Request IEs were installed after escan started");
    }
    if all[install] != iovar(&[record(b"add\0", &VENDOR_A), record(b"add\0", &VENDOR_B)]) {
        return Err("vndr_ie add records differ from Linux brcmf_vndr_ie");
    }
    // Linux skips an unchanged saved Probe Request set.
    scan(&harness, both, false)?;
    if sets(&harness, b"vndr_ie\0").len() != 1 {
        return Err("unchanged Probe Request IEs were reprogrammed");
    }
    scan(&harness, VENDOR_B.to_vec(), true)?;
    scan(&harness, Vec::new(), true)?;
    let expected = [
        iovar(&[record(b"add\0", &VENDOR_A), record(b"add\0", &VENDOR_B)]),
        iovar(&[
            record(b"del\0", &VENDOR_A),
            record(b"del\0", &VENDOR_B),
            record(b"add\0", &VENDOR_B),
        ]),
        iovar(&[record(b"del\0", &VENDOR_B)]),
    ];
    if sets(&harness, b"vndr_ie\0") != expected {
        return Err("Probe Request IE replacement/removal differs from Linux del/add order");
    }
    // A subsequent scan without IEs leaves firmware untouched.
    scan(&harness, Vec::new(), true)?;
    if sets(&harness, b"vndr_ie\0").len() != 3 {
        return Err("empty request rewrote an already empty firmware set");
    }
    harness.scan_and_associate(false)
}
fn smoke_cyw_scan_probe_request_ies_native_vndr_ie_lifecycle() -> TestResult {
    lifecycle().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/scan_ies",
    smoke_cyw_scan_probe_request_ies_native_vndr_ie_lifecycle
);

fn rejection() -> Result<(), &'static str> {
    let harness = Harness::new(false)?;
    let mut six = Vec::new();
    for _ in 0..6 {
        six.extend_from_slice(&VENDOR_B);
    }
    let mut oversized = Vec::new();
    for _ in 0..2 {
        oversized.extend_from_slice(&[221, 255, 0x00, 0x90, 0x4c, 0x04]);
        oversized.extend_from_slice(&[0; 251]);
    }
    let cases: [(Vec<u8>, WirelessError); 7] = [
        // Firmware has no representation for standard element IDs.
        (vec![50, 1, 0x0c], WirelessError::NotSupported),
        // Firmware generates the WPA and WMM vendor elements itself.
        (
            vec![221, 6, 0x00, 0x50, 0xf2, 0x01, 1, 0],
            WirelessError::NotSupported,
        ),
        (
            vec![221, 7, 0x00, 0x50, 0xf2, 0x02, 0, 1, 0],
            WirelessError::NotSupported,
        ),
        (
            vec![221, 4, 0x00, 0x90, 0x4c, 0x04],
            WirelessError::InvalidArgs,
        ),
        (vec![221, 9, 0x00, 0x90, 0x4c], WirelessError::InvalidArgs),
        (six, WirelessError::NotSupported),
        (oversized, WirelessError::NotSupported),
    ];
    let before = harness.bus.firmware.lock().control_count();
    for (ies, expected) in cases {
        if ready(harness.device.scan(request(ies, true)))?.err() != Some(expected) {
            return Err("inexpressible Probe Request IEs were not refused");
        }
    }
    if harness.bus.firmware.lock().control_count() != before {
        return Err("refused Probe Request IEs reached firmware");
    }
    // Five elements fit Linux's parse limit and 512-byte saved buffer.
    let mut five = Vec::new();
    for _ in 0..5 {
        five.extend_from_slice(&VENDOR_B);
    }
    scan(&harness, five, true)?;
    // A firmware refusal leaves the installed set unknown: terminal.
    harness.bus.firmware.lock().refuse_vndr_ie(true);
    if ready(harness.device.scan(request(VENDOR_A.to_vec(), true)))?.is_ok()
        || !harness
            .device
            .state
            .try_lock()
            .unwrap()
            .station
            .runtime
            .is_failed()
    {
        return Err("refused vndr_ie update did not poison the firmware lifecycle");
    }
    if sets(&harness, b"escan\0").len() != 1 {
        return Err("escan ran after a refused Probe Request IE update");
    }
    Ok(())
}
fn smoke_cyw_scan_probe_request_ies_refuse_inexpressible_and_failed_updates() -> TestResult {
    rejection().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/scan_ies",
    smoke_cyw_scan_probe_request_ies_refuse_inexpressible_and_failed_updates
);
