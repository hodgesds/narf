// SPDX-License-Identifier: GPL-2.0-or-later
//! Probe Request vendor IEs through the actual retained msgbuf IOCTL ring.
//! Expected bodies are literal Linux `brcmf_vndr_ie` records.
use super::*;

const VENDOR: [u8; 8] = [221, 6, 0x00, 0x90, 0x4c, 0x04, 0xaa, 0xbb];

fn request(extra_ies: Vec<u8>) -> ScanRequest {
    ScanRequest {
        ssids: vec![b"test".to_vec()],
        frequencies_mhz: Vec::new(),
        channels: vec![6],
        active: true,
        random_mac: None,
        colocated_6ghz: false,
        duration_tu: None,
        duration_mandatory: false,
        extra_ies,
    }
}
fn record(command: &[u8; 4]) -> Vec<u8> {
    let mut out = command.to_vec();
    out.extend_from_slice(&[1, 0, 0, 0, 0x10, 0, 0, 0]);
    out.extend_from_slice(&VENDOR);
    out
}
fn native(version: u32) -> Result<(), &'static str> {
    let (adapter, bus) = firmware::create(version, false).map_err(|_| "native msgbuf runtime")?;
    let mut station = ready(Station::initialize(adapter, &[], firmware::domain()))?
        .map_err(|_| "native station initialization")?;
    let start = bus.commands().len();
    let found = ready(station.scan(request(VENDOR.to_vec())))?
        .map_err(|_| "native scan with Probe Request IEs")?;
    if found.len() != 1 || found[0].bssid != AP {
        return Err("native escan result changed by Probe Request IEs");
    }
    ready(station.scan(request(Vec::new())))?.map_err(|_| "native scan clearing IEs")?;
    let commands = bus.commands();
    // (is vndr_ie, body after the iovar name) for vndr_ie/escan, in order.
    let ordered: Vec<(bool, &[u8])> = commands[start..]
        .iter()
        .filter(|(cmd, _, _)| *cmd == 263)
        .filter_map(|(_, input, _)| {
            if let Some(body) = input.strip_prefix(b"vndr_ie\0") {
                Some((true, body))
            } else {
                input.starts_with(b"escan\0").then_some((false, &[][..]))
            }
        })
        .collect();
    let add = record(b"add\0");
    let del = record(b"del\0");
    if ordered
        != [
            (true, add.as_slice()),
            (false, &[][..]),
            (true, del.as_slice()),
            (false, &[][..]),
        ]
    {
        return Err("native vndr_ie add/del did not precede each changed escan");
    }
    Ok(())
}
fn smoke_brcmf_scan_probe_request_ies_native_msgbuf_vndr_ie() -> TestResult {
    for version in [5, 6] {
        if let Err(error) = native(version) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/scan_ies",
    smoke_brcmf_scan_probe_request_ies_native_msgbuf_vndr_ie
);
