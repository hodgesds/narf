// SPDX-License-Identifier: GPL-2.0-or-later
//! Negotiated firmware WMM (`wme_ac_sta`) and all-priority SDPCM data.
//! Expected maps are worked by hand from Linux brcmfmac
//! `brcmf_wifi_prioritize_acparams`/`brcmf_map_prio_to_prec`.
use super::*;
use crate::cyw43439::station::wmm;

/// WMM default EDCA rows (AIFSN/ECWmin/ECWmax): BE 3/4/10, BK 7/4/10,
/// VI 2/3/4, VO 2/2/3, as {ACI, ECW, TXOP le16} in AC_BE..AC_VO order.
const DEFAULT_ROWS: [u8; 16] = [
    0x03, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 0x5e, 0, 0x62, 0x32, 0x2f, 0,
];
/// The same rows with admission control mandatory on AC_VO.
const VO_ACM_ROWS: [u8; 16] = [
    0x03, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 0x5e, 0, 0x72, 0x32, 0x2f, 0,
];
/// Rank sums BE17/BK21/VI9, VO demoted to BE's17: VI ranks 3, BE/VO 1.
const VO_ACM_MAP: [u8; 8] = [1, 0, 0, 1, 3, 3, 1, 1];

fn vectors() -> Result<(), &'static str> {
    if wmm::DEFAULT_AC_PRIORITY != [1, 0, 0, 1, 2, 2, 3, 3] {
        return Err("default map differs from brcmf_init_wmm_prio");
    }
    let station = wmm::prioritize;
    if station(&[0; 16]) != Ok(wmm::DEFAULT_AC_PRIORITY)
        || station(&DEFAULT_ROWS) != Ok(wmm::DEFAULT_AC_PRIORITY)
        || station(&VO_ACM_ROWS) != Ok(VO_ACM_MAP)
        || station(&DEFAULT_ROWS[..12]).is_ok()
    {
        return Err("EDCA ranking differs from brcmf_wifi_prioritize_acparams");
    }
    let default: Vec<u8> = (0..8)
        .map(|p| wmm::precedence(&wmm::DEFAULT_AC_PRIORITY, p))
        .collect();
    let demoted: Vec<u8> = (0..8).map(|p| wmm::precedence(&VO_ACM_MAP, p)).collect();
    if default != [2, 0, 1, 3, 4, 5, 6, 7] || demoted != [2, 0, 1, 3, 6, 7, 2, 2] {
        return Err("SDIO precedence differs from brcmf_map_prio_to_prec");
    }
    let fifos: Vec<u8> = (0..8).map(wmm::fifo).collect();
    if fifos != [0, 1, 1, 0, 2, 2, 3, 3] {
        return Err("msgbuf FIFO differs from brcmf_flowring_prio2fifo");
    }
    Ok(())
}
fn smoke_cyw_wmm_edca_ranking_precedence_and_fifo_vectors() -> TestResult {
    vectors().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/wmm",
    smoke_cyw_wmm_edca_ranking_precedence_and_fifo_vectors
);

fn uplink(tos: u8) -> Vec<u8> {
    let plan = network_plan();
    let mut bytes = udp_ipv4(AP, OWN, plan.lease_ip, plan.server_ip, 49152, 7, b"qos");
    bytes[15] = tos; // IPv4 TOS/DS field.
    bytes
}
fn data_priorities(harness: &Harness) -> Vec<u8> {
    harness
        .bus
        .firmware
        .lock()
        .data_packets()
        .iter()
        .map(|packet| packet[13])
        .collect()
}

fn negotiated() -> Result<(), &'static str> {
    let harness = Harness::new(false)?;
    harness.bus.firmware.lock().wme_ac_sta(Some(VO_ACM_ROWS));
    harness.scan_and_associate(false)?;
    let map = harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .ac_priority();
    if map != Some(VO_ACM_MAP) {
        return Err("negotiated firmware EDCA state was not reported");
    }
    let before = data_priorities(&harness).len();
    // CS1/AF21/EF/CS6 → 802.1D 1/3/6/7 (RFC 8325 mapping); the SDPCM
    // window granted by the last control reply bounds this to four frames.
    for tos in [0x20, 0x48, 0xb8, 0xc0] {
        harness
            .device
            .enqueue(&uplink(tos))
            .map_err(|_| "QoS uplink admission")?;
        for _ in 0..4 {
            harness.device.drain();
        }
    }
    if data_priorities(&harness)[before..] != [1, 3, 6, 7] {
        return Err("BDC header did not carry the classified 802.1D priority");
    }
    ready(harness.device.disassociate())?.map_err(|_| "disconnect")?;
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .ac_priority()
        .is_some()
    {
        return Err("negotiated WMM state survived disconnect");
    }
    // Firmware without the iovar keeps Linux's default map.
    let harness = Harness::new(true)?;
    harness.bus.firmware.lock().wme_ac_sta(None);
    harness.scan_and_associate(true)?;
    if harness
        .device
        .state
        .try_lock()
        .unwrap()
        .station
        .ac_priority()
        != Some(wmm::DEFAULT_AC_PRIORITY)
    {
        return Err("refused wme_ac_sta did not keep the default map");
    }
    Ok(())
}
fn smoke_cyw_wmm_negotiated_state_and_all_priority_bdc_data() -> TestResult {
    negotiated().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/wmm",
    smoke_cyw_wmm_negotiated_state_and_all_priority_bdc_data
);
