// SPDX-License-Identifier: GPL-2.0-or-later
//! Negotiated firmware WMM and per-FIFO msgbuf station flows.
//! Linux brcmfmac `flowring.c` keeps one station flow per
//! `brcmf_flowring_prio2fifo` FIFO, creates it with the first frame's
//! priority as TID and posts each frame with its own `skb->priority`.
use super::*;
use crate::cyw43439::station::wmm;

/// WMM default rows with admission control on AC_VO (see CYW wmm tests).
const VO_ACM_ROWS: [u8; 16] = [
    0x03, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 0x5e, 0, 0x72, 0x32, 0x2f, 0,
];

fn uplink(tos: u8) -> Vec<u8> {
    let mut bytes = packets().0;
    bytes[15] = tos; // IPv4 TOS/DS field.
    bytes
}

fn native(version: u32, secured: bool) -> Result<(), &'static str> {
    let h = Harness::new_channel(version, secured, secured, false, 6)?;
    h.bus.wme_ac_sta(VO_ACM_ROWS);
    h.associate(secured)?;
    if h.device.state.try_lock().unwrap().station.ac_priority() != Some([1, 0, 0, 1, 3, 3, 1, 1]) {
        return Err("negotiated msgbuf firmware EDCA state was not reported");
    }
    let (tids_before, sent_before) = h.bus.flow_priorities();
    // DF(0) creates FIFO0; AF21(3) shares it; EF(6) creates FIFO3; CS6(7)
    // shares that one. Each descriptor keeps its own 802.1D priority.
    for tos in [0x00, 0x48, 0xb8, 0xc0] {
        let frame = uplink(tos);
        h.device
            .enqueue(&frame)
            .map_err(|_| "QoS uplink admission")?;
        h.pump();
        if !h.bus.uplink(&frame) {
            return Err("prioritized native msgbuf frame was not posted");
        }
    }
    let (tids, sent) = h.bus.flow_priorities();
    let tids = &tids[tids_before.len()..];
    let sent = &sent[sent_before.len()..];
    let priorities: Vec<u8> = sent.iter().map(|(_, p)| *p).collect();
    if tids != [0, 6]
        || priorities != [0, 3, 6, 7]
        || sent[0].0 != sent[1].0
        || sent[2].0 != sent[3].0
        || sent[0].0 == sent[2].0
    {
        return Err("msgbuf flows/descriptors differ from Linux per-FIFO station rings");
    }
    if (0..8).map(wmm::fifo).collect::<Vec<u8>>() != [0, 1, 1, 0, 2, 2, 3, 3] {
        return Err("FIFO table differs from brcmf_flowring_prio2fifo");
    }
    Ok(())
}
fn smoke_brcmf_wmm_negotiated_state_and_per_fifo_native_flows() -> TestResult {
    for version in [5, 6, 7] {
        for secured in [false, true] {
            if let Err(error) = native(version, secured) {
                return TestResult::Fail(error);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/wmm",
    smoke_brcmf_wmm_negotiated_state_and_per_fifo_native_flows
);
