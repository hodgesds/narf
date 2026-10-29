//! HT LDPC and one-stream RX STBC over the retained native station owner.
//! Firmware `ht_cap_info` LDPC 0x0040 / RX_LDPC 0x1000 / TX_LDPC 0x2000 /
//! RX_STBC 0x0030, IEEE LDPC 0x0001 / TX STBC 0x0080 / RX STBC 0x0300,
//! native PEER_STBC 0x8000 / PEER_LDPC 0x10000, RC TX_STBC 0x20 and HT-SIG2
//! STBC bits4..5 / FEC bit6 are independent source-cited facts (Linux
//! `ath10k/mac.c::{ath10k_get_ht_cap,ath10k_peer_assoc_h_ht}`, `wmi.h`,
//! `mac80211/ht.c::ieee80211_ht_cap_ie_to_sta_ht_cap`). No production encoder
//! generates these vectors.
use super::*;

/// Firmware HT word → IEEE capability low/high bytes of our request IE.
fn local(ht: u32) -> u16 {
    let ldpc = ht & 0x40 != 0 || ht & 0x3000 == 0x3000;
    u16::from(ldpc) | if ht & 0x30 != 0 { 0x100 } else { 0 }
}
fn enable(h: &Harness, ht: u32, ap: u16) {
    super::ht_conversation_tests::enable(h);
    {
        let mut r = h.device.radio.try_lock().unwrap();
        r.htt.wmi.caps.as_mut().unwrap().ht = ht;
    }
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        for ie in [f.ht_offer.as_mut(), f.ht_response.as_mut()]
            .into_iter()
            .flatten()
        {
            ie[2] |= ap as u8;
            ie[3] |= (ap >> 8) as u8;
        }
        f.ht_request_coding = local(ht);
    });
}
fn inject(h: &Harness, frame: Vec<u8>, sig2: u32) {
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.rx_phy = Some((8, 7, sig2));
        f.queue.push_back(frame);
    });
    h.pump();
}

fn smoke_ath10k_coding_native_service_bits_select_band_ht_capability() -> TestResult {
    (|| {
        for (version, dialect) in BAND_DIALECTS {
            // Firmware word, expected IEEE capability bits beyond 0x000c.
            for (ht, extra) in [
                (0x41, 0x0001),
                (0x3001, 0x0001),
                (0x1001, 0),      // RX_LDPC alone is not Linux's LDPC_CODING.
                (0x2001, 0),      // TX_LDPC alone likewise.
                (0x11, 0x0100),   // One RX STBC stream.
                (0x31, 0x0100),   // Three-stream firmware: one-stream profile.
                (0x09, 0),        // TX STBC needs more than one TX chain.
                (0x3071, 0x0101), // Both coding facts together.
                (0x70, 0),        // Coding bits never imply HT enablement.
            ] {
                let h = Harness::new_on_ht(version, dialect, false, false, 5180, 0x8348, Some(ht));
                for band in [2400, 5000] {
                    let actual = h.device.phy_capabilities(band).map(|p| p.ht);
                    let expected = (ht & 1 != 0).then(|| {
                        let mut body = [0; 26];
                        let cap: u16 = 0x0c | extra | if band == 5000 { 2 } else { 0 };
                        body[..2].copy_from_slice(&cap.to_le_bytes());
                        body[2] = 24;
                        body[3] = 255;
                        body[15] = 1;
                        body
                    });
                    if actual != expected {
                        return Err("band HT body did not follow exact firmware coding bits");
                    }
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/coding",
    smoke_ath10k_coding_native_service_bits_select_band_ht_capability
);

fn smoke_ath10k_coding_peer_assoc_masks_ldpc_and_asymmetric_stbc() -> TestResult {
    (|| {
        // firmware, AP IEEE caps, native peer_ht_caps, peer flags, RC extra.
        for (ht, ap, native, flags, rc) in [
            (0x43, 0x0001, 0x002d, 0x1_0000, 0),  // Mutual LDPC.
            (0x03, 0x0001, 0x002c, 0, 0),         // No local LDPC: masked.
            (0x43, 0x0000, 0x002c, 0, 0),         // AP without LDPC RX.
            (0x13, 0x0080, 0x00ac, 0x8000, 0x20), // AP TX STBC, our RX.
            (0x03, 0x0080, 0x002c, 0, 0),         // No local RX STBC.
            (0x13, 0x0300, 0x002c, 0, 0),         // AP RX STBC needs our TX.
            (0x3033, 0x0381, 0x00ad, 0x1_8000, 0x20),
        ] {
            for (version, dialect) in BAND_DIALECTS {
                let h = Harness::new(version, dialect, true);
                enable(&h, ht, ap);
                h.model(|m| {
                    let f = m.data.as_mut().unwrap();
                    f.ht_capabilities = native;
                    f.ht_peer_flags = flags;
                    f.ht_rate_caps = rc;
                });
                h.join()?;
                let (up, down) = packets();
                narf_net::iface::send_on(&h.name, &up).map_err(|_| "coding native TX enqueue")?;
                h.pump();
                if !h.model(|m| m.data.as_ref().unwrap().uplink.contains(&up)) {
                    return Err("coding PEER_ASSOC or software CCMP TX failed");
                }
                let frame = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
                inject(&h, frame, 0x80);
                if !h.received(&down) || !h.device.link_up() {
                    return Err("coding profile rejected an ordinary HT PPDU");
                }
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/coding",
    smoke_ath10k_coding_peer_assoc_masks_ldpc_and_asymmetric_stbc
);

fn smoke_ath10k_coding_rx_ppdu_ldpc_and_stbc_checks_precede_replay() -> TestResult {
    (|| {
        // firmware, rejected HT-SIG2, accepted HT-SIG2.
        for (ht, bad, good) in [
            (0x03, 0x40, 0x00),   // LDPC needs our advertised promise.
            (0x43, 0x20, 0x40),   // STBC needs our RX STBC promise.
            (0x03, 0x10, 0x80),   // One-stream STBC without RX promise.
            (0x13, 0x20, 0x10),   // Two-stream STBC is never promised.
            (0x13, 0x30, 0x90),   // Reserved STBC value.
            (0x3013, 0x60, 0x50), // Paired directional LDPC + RX STBC.
        ] {
            let h = Harness::new(4, Dialect::Tlv, true);
            enable(&h, ht, 0);
            h.join()?;
            let (_, down) = packets();
            let frame = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
            inject(&h, frame.clone(), bad);
            if h.received(&down) || !h.device.link_up() {
                return Err("unadvertised native coding reached or poisoned data owner");
            }
            inject(&h, frame.clone(), good);
            if !h.received(&down) {
                return Err("native coding denial consumed encrypted replay PN");
            }
            inject(&h, frame, good);
            if h.received(&down) {
                return Err("coding admission enabled ordinary CCMP replay");
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/coding",
    smoke_ath10k_coding_rx_ppdu_ldpc_and_stbc_checks_precede_replay
);
