//! Linux EE SGI descriptor/RA-mask and actual negotiated/native receive path.
use super::*;

fn smoke_rtl8188ee_sgi20_peer_direction_native_txd_and_ra_mask() -> TestResult {
    check(|| {
        for protected in [false, true] {
            for peer_sgi in [false, true] {
                for mcs in 0u8..8 {
                    let h = Harness::new_profile(protected, true);
                    let mut elements = ht::tests::ap_elements(1 << mcs);
                    if peer_sgi {
                        elements[2] |= 0x20;
                    }
                    h.peer.lock().ht = Some(elements);
                    let fallback = narf_capabilities::Cap::bootstrap();
                    *h.env.fallback.lock() = Some((fallback, h.firmware.identity().unwrap(), true));
                    ht_join(&h)?;
                    if h.device.fallback_for_test() != Some(true) {
                        return Err("SGI fixture did not retain the actual NEFB grant");
                    }
                    let public = h.device.phy_capabilities(2400).ok_or("SGI PHY absent")?;
                    if public.ht[0] & 0x60 != 0x20 {
                        return Err("local SGI20 promise changed width/GI40");
                    }
                    let up = packet(&h, 1, true);
                    h.device
                        .enqueue(&up, TxMeta::default())
                        .map_err(|_| "SGI enqueue")?;
                    h.pump();
                    let model = h.packet.model.lock();
                    if h.peer.lock().uplink.last() != Some(&up) {
                        return Err("SGI descriptor lost original encrypted/plain DATA");
                    }
                    let descriptor = model.descriptors.last().ok_or("SGI native TX absent")?;
                    // rtl88ee_tx_fill_desc uses >DESC92C_RATEMCS0; MCS0
                    // deliberately retains LGI even with negotiated SGI20.
                    let sgi = peer_sgi && mcs != 0;
                    if word(descriptor, 20) & 0x7f != u32::from(12 + mcs) | u32::from(sgi) << 6
                        || word(descriptor, 16) & ((1 << 10) | (1 << 25))
                            != u32::from(peer_sgi) << 10
                    {
                        return Err("native SGI/MCS/BW/DISFB fields differ from Linux cases");
                    }
                    let mask = model
                        .commands
                        .iter()
                        .rev()
                        .find(|(id, _)| *id == 0x84)
                        .ok_or("native RA mask command absent")?;
                    if (mask.1[4] & 0x20 != 0) != peer_sgi {
                        return Err("RA SGI bit was not the negotiated peer RX promise");
                    }
                    drop(model);
                    complete(h.device.disassociate()).map_err(|_| "SGI disconnect")?;
                }
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/sgi20",
    smoke_rtl8188ee_sgi20_peer_direction_native_txd_and_ra_mask
);

fn smoke_rtl8188ee_sgi20_native_rx_and_large_amsdu_preserve_pn() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = Harness::new_profile(protected, true);
            // This AP's own receive promise remains LGI. It may transmit
            // SGI20 to our independent advertised SGI20 receiver.
            ht_join(&h)?;
            for source in 0..2 {
                let down = packet(&h, source, false);
                let raw = h.peer.lock().downlink(&down)?;
                let mut phy = [0; 28];
                phy[27] = 2;
                h.packet
                    .emit_native(
                        &raw,
                        if source == 0 { 0x153 } else { 0x53 },
                        0,
                        (source != 0).then_some(phy.as_slice()),
                    )
                    .unwrap();
                h.pump();
                if h.received() != vec![down] || !h.device.link_up() {
                    return Err("native RXD/PHY SGI20 lost ordinary DATA");
                }
                if protected {
                    h.packet.emit_native(&raw, 0x153, 0, Some(&phy)).unwrap();
                    h.pump();
                    if !h.received().is_empty() {
                        return Err("SGI metadata bypassed pairwise PN replay");
                    }
                }
            }
            let frames = rx_amsdu_tests::large_frames(&h, 307);
            let raw = aggregate(&h, &frames, 1000)?;
            h.packet.emit_native(&raw, 0x153, 0, None).unwrap();
            h.pump();
            if h.received() != frames {
                return Err("SGI20 whole7935 aggregate failed local RX promise");
            }
            complete(h.device.disassociate()).map_err(|_| "SGI RX teardown")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/sgi20",
    smoke_rtl8188ee_sgi20_native_rx_and_large_amsdu_preserve_pn
);
