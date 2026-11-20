//! Native 9100-byte DMA reception, negotiated RX capacity and atomic security.
use super::*;

pub(super) fn large_frames(h: &Harness, last: usize) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for n in 0..6 {
        let mut frame = packet(h, n, false);
        frame.resize(if n == 5 { last } else { 1514 }, 0x55);
        frames.push(frame);
    }
    frames
}

fn smoke_rtl8188ee_rx7935_native_prefix_fcs_and_whole_security() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = Harness::new_profile(protected, true);
            ht_join(&h)?;
            let caps = h.device.phy_capabilities(2400).ok_or("HT facade absent")?;
            if u16::from_le_bytes(caps.ht[..2].try_into().unwrap()) & 0x800 == 0 {
                return Err("public HT MAX_AMSDU promise absent");
            }
            let count = retained(&h);
            // Five padded1522-byte subframes + final315 = exactly7935.
            let frames = large_frames(&h, 307);
            let raw = aggregate(&h, &frames, 101)?;
            if raw.len() != 26 + 7935 + if protected { 16 } else { 0 } {
                return Err("independent 7935-byte fixture geometry changed");
            }
            let mut phy = [0; 28];
            phy[4] = 100;
            h.packet
                .emit_native(&raw, 0x53, 0, Some(&phy))
                .map_err(|_| "9100-slot native prefix/body/FCS extent")?;
            h.pump();
            if h.received() != frames || retained(&h) != count || !h.device.link_up() {
                return Err("full7935 RX lost bytes, DMA or carrier");
            }
            if protected {
                h.packet.emit_native(&raw, 0x53, 0, Some(&phy)).unwrap();
                h.pump();
                if !h.received().is_empty() {
                    return Err("7935-byte aggregate replay accepted");
                }
            }
            complete(h.device.disassociate()).map_err(|_| "RX7935 teardown")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rx7935",
    smoke_rtl8188ee_rx7935_native_prefix_fcs_and_whole_security
);

fn smoke_rtl8188ee_rx7935_oversize_bad_suffix_and_revoked_source() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = Harness::new_profile(protected, true);
            ht_join(&h)?;
            let too_large = aggregate(&h, &large_frames(&h, 308), 102)?;
            h.packet.emit_native(&too_large, 0x53, 0, None).unwrap();
            h.pump();
            if !h.received().is_empty() {
                return Err("7936-byte body exceeded local RX capacity");
            }
            let good = large_frames(&h, 307);
            let mut bad = good.clone();
            bad[5][12..14].copy_from_slice(&[0x88, 0x8e]);
            let malformed = aggregate(&h, &bad, 102)?;
            h.packet.emit_native(&malformed, 0x53, 0, None).unwrap();
            h.pump();
            if !h.received().is_empty() {
                return Err("large aggregate malformed suffix exposed prefix");
            }
            let valid = aggregate(&h, &good, 102)?;
            h.packet.emit_native(&valid, 0x53, 0, None).unwrap();
            h.pump();
            if h.received() != good {
                return Err("rejected large aggregate consumed valid PN");
            }
            let raw = aggregate(&h, &good, 103)?;
            h.packet.emit_native(&raw, 0x53, 0, None).unwrap();
            h.ht_source.as_ref().unwrap().1.revoke();
            h.pump();
            if !h.received().is_empty() || h.device.link_up() {
                return Err("queued large RX survived qualification revocation");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rx7935",
    smoke_rtl8188ee_rx7935_oversize_bad_suffix_and_revoked_source
);
