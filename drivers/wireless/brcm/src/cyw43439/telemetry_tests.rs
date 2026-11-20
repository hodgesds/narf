// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-AC host queue/traffic telemetry through actual CYW SDPCM/BDC data.
use super::*;
use crate::cyw43439::telemetry::{ac_of, Ac, AcStats};

fn uplink(tos: u8) -> Vec<u8> {
    let plan = network_plan();
    let mut bytes = udp_ipv4(
        AP,
        OWN,
        plan.lease_ip,
        plan.server_ip,
        49152,
        7,
        b"telemetry",
    );
    bytes[15] = tos;
    bytes
}

fn telemetry() -> Result<(), &'static str> {
    let order: [u8; 8] = core::array::from_fn(|p| ac_of(p as u8) as u8);
    if order != [Ac::Be as u8, 3, 3, 2, 1, 1, 0, 0] {
        return Err("802.1D to AC map differs from ieee802_1d_to_ac");
    }
    let h = Harness::new(true)?;
    if h.device.station_info().is_some() {
        return Err("station telemetry reported without a connection");
    }
    h.scan_and_associate(true)?;
    // EF (802.1D 6 → VO) and CS1 (1 → BK) are submitted to firmware.
    let ef = uplink(0xb8);
    let cs1 = uplink(0x20);
    for frame in [&ef, &cs1] {
        h.device.enqueue(frame).map_err(|_| "uplink admission")?;
        for _ in 0..4 {
            h.device.drain();
        }
    }
    let p = network_plan();
    let down = udp_ipv4(OWN, AP, p.server_ip, p.lease_ip, 7, 49152, b"down");
    h.bus.downlink(&down);
    for _ in 0..4 {
        h.device.drain();
    }
    let stats = h.device.ac_statistics();
    let tx = |bytes: usize| AcStats {
        tx_frames: 1,
        tx_bytes: bytes as u64,
        ..Default::default()
    };
    if stats[Ac::Vo as usize] != tx(ef.len())
        || stats[Ac::Bk as usize] != tx(cs1.len())
        || stats[Ac::Be as usize].rx_frames != 1
        || stats[Ac::Be as usize].rx_bytes != down.len() as u64
        || stats[Ac::Vi as usize] != AcStats::default()
    {
        return Err("per-AC counters differ from the classified data path");
    }
    let info = h.device.station_info().ok_or("station info absent")?;
    if info.tx_packets != Some(2) || info.rx_packets != Some(1) || info.tx_failed != Some(0) {
        return Err("GET_STATION totals differ from per-AC counters");
    }
    // A frame queued but flushed by disconnect is a host drop on its AC.
    h.device
        .state
        .try_lock()
        .unwrap()
        .tx_queue_for_test(uplink(0x88));
    ready(h.device.disassociate())?.map_err(|_| "disconnect")?;
    let stats = h.device.ac_statistics();
    if stats[Ac::Vi as usize].tx_dropped != 1 || stats[Ac::Vo as usize].tx_frames != 1 {
        return Err("disconnect flush was not counted as a VI drop");
    }
    if h.device.station_info().is_some() {
        return Err("station telemetry outlived the connection");
    }
    Ok(())
}
fn smoke_cyw_per_ac_queue_and_traffic_telemetry() -> TestResult {
    telemetry().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/telemetry",
    smoke_cyw_per_ac_queue_and_traffic_telemetry
);
