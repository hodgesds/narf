// SPDX-License-Identifier: GPL-2.0-or-later
//! Literal Linux policy and actual native RX/TX/watchdog composition.
use super::*;
use dm::edca::{Edca, Vendor, REG_EDCA_BE_PARAM};
use h2c::WirelessMode::{B, G, N24};

fn be_writes(port: &BePort) -> usize {
    port.0
        .lock()
        .writes
        .iter()
        .filter(|&&(width, reg, _)| width == 4 && reg == 0x508)
        .count()
}

fn smoke_rtl8723be_edca_source_policy() -> TestResult {
    let port = BePort::new();
    let mut edca = Edca::default();
    edca.received(&beacon(PEER, [0, 0x40, 0x96]), PEER, true);
    kt_assert!(edca.watchdog(&port, N24).is_ok());
    kt_assert_eq!(port.reg32(0x508), 0x3e_a430);
    edca.tx_bytes = 10;
    edca.rx_bytes = 40; // equality is upload (strict >).
    kt_assert!(edca.watchdog(&port, N24).is_ok());
    kt_assert!(!edca.downlink);
    let count = be_writes(&port);
    edca.tx_bytes += 10;
    edca.rx_bytes += 41;
    kt_assert!(edca.watchdog(&port, N24).is_ok());
    kt_assert!(edca.downlink && edca.turbo);
    kt_assert_eq!(port.reg32(0x508), 0x5e_a630);
    kt_assert_eq!(be_writes(&port), count + 1);
    // Every eligible pass writes, including unchanged direction.
    let count = be_writes(&port);
    kt_assert!(edca.watchdog(&port, G).is_ok());
    kt_assert_eq!(port.reg32(0x508), 0x6e_a42b);
    kt_assert_eq!(be_writes(&port), count + 1);
    // BE restore is a software reset, not a default BE register write.
    edca.downlink = true;
    edca.non_be = true;
    let count = be_writes(&port);
    kt_assert!(edca.watchdog(&port, G).is_ok());
    kt_assert!(!edca.turbo && !edca.non_be && !edca.downlink);
    kt_assert_eq!(be_writes(&port), count);
    edca.disable_framebursting = true;
    kt_assert!(edca.watchdog(&port, G).is_ok());
    kt_assert_eq!(be_writes(&port), count);
    // Mode B skips even the flag-reset branch, but latches byte totals.
    edca.turbo = true;
    edca.downlink = true;
    edca.non_be = true;
    edca.tx_bytes = u64::MAX - 1;
    edca.rx_bytes = u64::MAX - 2;
    kt_assert!(edca.watchdog(&port, B).is_ok());
    kt_assert!(edca.turbo && edca.downlink && !edca.non_be);
    kt_assert_eq!(be_writes(&port), count);
    edca.disable_framebursting = false;
    edca.tx_bytes = 3; // wrapping deltas: TX=5, RX=5 -> upload.
    edca.rx_bytes = 2;
    kt_assert!(edca.watchdog(&port, N24).is_ok());
    kt_assert_eq!(port.reg32(0x508), 0x3e_a430);
    for vendor in [Vendor::Ralink, Vendor::Atheros] {
        let mut biased = Edca::default();
        let oui = if vendor == Vendor::Ralink {
            [0, 0x0c, 0x43]
        } else {
            [0, 3, 0x7f]
        };
        biased.received(&beacon(PEER, oui), PEER, true);
        biased.tx_bytes = 4;
        biased.rx_bytes = 1;
        kt_assert!(biased.watchdog(&port, G).is_ok());
        kt_assert!(biased.downlink);
        biased.tx_bytes += 5;
        biased.rx_bytes += 1;
        kt_assert!(biased.watchdog(&port, G).is_ok());
        kt_assert!(!biased.downlink);
    }
    // Counters are per owner; u64 multiplication follows source wrapping.
    let mut other = Edca::default();
    other.received(&beacon(PEER, [0, 0x40, 0x96]), PEER, true);
    other.tx_bytes = (1u64 << 62) + 1;
    other.rx_bytes = 5;
    kt_assert!(other.watchdog(&port, N24).is_ok());
    kt_assert!(other.downlink);
    TestResult::Pass
}

fn beacon(peer: [u8; 6], oui: [u8; 3]) -> Vec<u8> {
    let mut bytes = vec![0; 36];
    bytes[0] = 0x80;
    bytes[4..10].fill(0xff);
    bytes[10..16].copy_from_slice(&peer);
    bytes[16..22].copy_from_slice(&peer);
    bytes.extend_from_slice(&[221, 3, oui[0], oui[1], oui[2]]);
    bytes
}

fn smoke_rtl8723be_edca_peer_bounds_and_window() -> TestResult {
    for (oui, expected) in [
        ([0, 3, 0x7f], Vendor::Atheros),
        ([0, 0x13, 0x74], Vendor::Atheros),
        ([0, 0x10, 0x18], Vendor::Broadcom),
        ([0, 0x0a, 0xf7], Vendor::Broadcom),
        ([0, 5, 0xb5], Vendor::Broadcom),
        ([0, 0x0c, 0x43], Vendor::Ralink),
        ([0, 0x40, 0x96], Vendor::Cisco),
        ([0, 0x50, 0x43], Vendor::Marvell),
    ] {
        let mut state = Edca::default();
        let bytes = beacon(PEER, oui);
        state.received(&bytes, PEER, false);
        kt_assert_eq!(state.vendor, Vendor::Unknown);
        state.received(&bytes, PEER, true);
        kt_assert_eq!(state.vendor, expected);
        kt_assert_eq!(state.rx_bytes, 0); // broadcast is not unicast stats.
    }
    let cisco = [0, 0x17, 0x94, 1, 2, 3];
    let mut state = Edca::default();
    state.received(&beacon(cisco, [0, 3, 0x7f]), cisco, true);
    kt_assert_eq!(state.vendor, Vendor::Atheros); // source precedence
    state.received(&beacon(cisco, [0, 0, 0]), cisco, true);
    kt_assert_eq!(state.vendor, Vendor::Cisco); // address fallback
    state.received(&beacon(PEER, [0, 0x0c, 0x43]), cisco, true);
    kt_assert_eq!(state.vendor, Vendor::Cisco); // foreign BSSID
    let mut malformed = beacon(PEER, [0, 0x40, 0x96]);
    malformed[37] = 20; // truncated IE: never read its OUI.
    state.received(&malformed, PEER, true);
    kt_assert_eq!(state.vendor, Vendor::Unknown);
    malformed[37] = 1; // short OUI
    state.received(&malformed, PEER, true);
    kt_assert_eq!(state.vendor, Vendor::Unknown);
    let mut probe_response = beacon(PEER, [0, 0x40, 0x96]);
    probe_response[0] = 0x50;
    state.received(&probe_response, PEER, true);
    kt_assert_eq!(state.vendor, Vendor::Unknown);
    let bytes = beacon(PEER, [0, 0x40, 0x96]);
    state.received(&bytes[..40], PEER, true);
    kt_assert_eq!(state.vendor, Vendor::Unknown);
    state.linked_tick(true);
    state.linked_tick(true);
    state.received(&bytes, PEER, true);
    kt_assert_eq!(state.vendor, Vendor::Cisco);
    state.linked_tick(true);
    state.received(&beacon(PEER, [0, 0x0c, 0x43]), PEER, true);
    kt_assert_eq!(state.vendor, Vendor::Cisco); // recognition window closed
    state.linked_tick(false);
    kt_assert_eq!(state.vendor, Vendor::Unknown);
    TestResult::Pass
}

fn linked() -> Option<(Prepared<BePort, Block>, BePort)> {
    let (mut owner, port) = owner()?;
    port.set8(hw::REG_BCN_PSR_RPT + 1, 0xc0);
    owner.start_packets().ok()?;
    run(owner.prepare_station_peer(PEER, 0x0fff, 0x0015, 0x0421)).ok()?;
    run(owner.complete_station_peer(PEER, 5)).ok()?;
    run(owner.install_rtl8723be_rate_mask(
        h2c::Peer {
            legacy: 0x0fff,
            ht: Some([0xff, 0]),
            sgi20: false,
            sgi40: false,
        },
        false,
        0,
    ))
    .ok()?;
    Some((owner, port))
}

fn receive(owner: &mut Prepared<BePort, Block>, bytes: &[u8], crc: bool, c2h: bool) {
    let slot = owner.packet.receive;
    owner.buffers[slot].write_bytes(0, bytes).unwrap();
    owner.buffers[slot]
        .write_bytes(bytes.len(), &[0; 4])
        .unwrap();
    let ring = owner.receive.as_mut().unwrap();
    let end = if slot + 1 == owner.depth { 1 << 30 } else { 0 };
    ring.write32(
        slot * 32,
        (bytes.len() + 4) as u32 | (u32::from(crc) << 14) | end,
    )
    .unwrap();
    ring.write32(slot * 32 + 8, u32::from(c2h) << 28).unwrap();
    ring.write32(slot * 32 + 12, 4).unwrap();
    assert!(owner.poll_receive_step().is_ok());
}

fn smoke_rtl8723be_native_edca_counts_and_watchdog() -> TestResult {
    let Some((mut owner, port)) = linked() else {
        return TestResult::Fail("linked fixture");
    };
    receive(&mut owner, &beacon(PEER, [0, 0x40, 0x96]), false, false);
    kt_assert_eq!(owner.packet.be8723.edca.vendor, Vendor::Cisco);
    kt_assert!(owner.packet.be8723.dm.is_none());
    kt_assert_eq!(owner.packet.be8723.edca.rx_bytes, 0);
    kt_assert!(run(owner.rtl8723be_dm_watchdog(40, 1000)).is_ok());
    kt_assert_eq!(port.reg32(0x508), 0x3e_a430);
    let mut frame = vec![0; 28];
    frame[0] = 0x40; // unicast management also counts
    frame[4..10].copy_from_slice(&PEER);
    frame[10..16].copy_from_slice(&be::be_factory().mac);
    let slot = owner.packet.next[1];
    kt_assert!(owner.submit(&frame, 0).is_ok());
    kt_assert_eq!(owner.packet.be8723.edca.tx_bytes, 28);
    let word = tx_word(&owner, 1, slot, 0);
    owner.tx[1].write32(slot * 64, word & !OWN).unwrap();
    kt_assert!(owner.poll_delivery().unwrap().is_some());
    let mut data = vec![0; 128];
    data[0] = 8;
    data[4..10].copy_from_slice(&be::be_factory().mac);
    receive(&mut owner, &data, true, false); // CRC errors never count
    kt_assert_eq!(owner.packet.be8723.edca.rx_bytes, 0);
    receive(&mut owner, &data, false, false);
    kt_assert_eq!(owner.packet.be8723.edca.rx_bytes, 132); // includes FCS
    kt_assert!(run(owner.rtl8723be_dm_watchdog(40, 3000)).is_ok());
    kt_assert_eq!(port.reg32(0x508), 0x5e_a630); // 132 > 4*28
                                                 // Source LPS gate skips EDCA; no pseudo snapshot is consumed.
    let before = be_writes(&port);
    owner.packet.leisure = true;
    kt_assert!(run(owner.rtl8723be_dm_watchdog(40, 5000)).is_ok());
    kt_assert_eq!(be_writes(&port), before);
    owner.packet.leisure = false;
    // set_qos reset does not write the BE row or discard byte snapshots.
    owner.packet.be8723.edca.reset();
    kt_assert!(!owner.packet.be8723.edca.turbo);
    kt_assert_eq!(owner.packet.be8723.edca.tx_bytes, 28);
    kt_assert_eq!(owner.packet.be8723.edca.rx_bytes, 132);
    TestResult::Pass
}

fn smoke_rtl8723be_edca_failed_io_is_terminal() -> TestResult {
    for lazy_init in [false, true] {
        let Some((mut owner, port)) = linked() else {
            return TestResult::Fail("linked fixture");
        };
        let start = port.0.lock().writes.len();
        if lazy_init {
            port.0.lock().deny = true;
        } else {
            port.0.lock().fail_write32 = Some(REG_EDCA_BE_PARAM);
        }
        kt_assert!(run(owner.rtl8723be_dm_watchdog(40, 1000)).is_err());
        kt_assert_eq!(owner.phase, Phase::Failed);
        let before = port.0.lock().writes.len();
        kt_assert!(run(owner.rtl8723be_dm_watchdog(40, 3000)).is_err());
        kt_assert_eq!(port.0.lock().writes.len(), before);
        if !lazy_init {
            kt_assert_eq!(be_writes(&port), 0);
            // ATC follows EDCA and must not run after its failed write.
            kt_assert!(port.0.lock().writes[start..]
                .iter()
                .all(|&(_, reg, _)| reg != dm::REG_MAC_PHY_CTRL));
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_edca_source_policy
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_edca_peer_bounds_and_window
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_native_edca_counts_and_watchdog
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723be",
    smoke_rtl8723be_edca_failed_io_is_terminal
);
