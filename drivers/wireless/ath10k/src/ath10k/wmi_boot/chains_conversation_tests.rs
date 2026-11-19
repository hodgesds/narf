//! Native two-stream HT/TX-STBC, actual RSNA/DHCP/IP and pre-PN PHY bounds.
use super::*;
pub(super) fn enable(h: &Harness) {
    let primary = h.request().channel as u8;
    // IEEE HT20: SMPS disabled, SGI20, LDPC, TX STBC and RX STBC1;
    // two exact MCS0..15 streams, TX MCS defined equal to RX.
    let mut ies = vec![45, 26, 0xad, 1, 0x1b, 255, 255];
    ies.extend_from_slice(&[0; 10]);
    ies.push(1);
    ies.extend_from_slice(&[0; 10]);
    ies.extend_from_slice(&[61, 22, primary]);
    ies.extend_from_slice(&[0; 21]);
    h.model(|m| {
        let f = m.data.as_mut().unwrap();
        f.wmm_offer = Some(WMM_PARAMETERS.to_vec());
        f.wmm_response = Some(WMM_PARAMETERS.to_vec());
        f.ht_offer = Some(ies.clone());
        f.ht_response = Some(ies);
        f.ht_expected = true;
        f.ht_mcs_more = [255, 0, 0];
        f.ht_peer_nss = 2;
        f.ht_request_nss = 2;
        f.ht_request_coding = 0x181;
        f.ht_capabilities = 0x1ad;
        f.ht_peer_flags = 0x18000;
        f.ht_rate_caps = 0x61;
        f.rx_phy = Some((8, 15, 0x40));
    });
}
fn smoke_ath10k_two_streams_and_tx_stbc_native_six_dialects_rsn_dhcp_ip() -> TestResult {
    (|| {
        for (version, dialect) in BAND_DIALECTS {
            for secured in [false, true] {
                composition_radio(version, dialect, secured, false, false, 5180, TestPhy::Mimo)?;
            }
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/chains",
    smoke_ath10k_two_streams_and_tx_stbc_native_six_dialects_rsn_dhcp_ip
);
fn smoke_ath10k_two_stream_ppdu_mcs_stbc_and_response_maps_precede_same_pn() -> TestResult {
    (|| {
        let h =
            Harness::new_on_profile(4, Dialect::Tlv, true, false, 5180, 0x8348, (Some(0x7b), 2));
        enable(&h);
        h.join()?;
        let (_, down) = packets();
        let encrypted = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
        for (mcs, sig2) in [(16, 0), (15, 0x10), (31, 0x40)] {
            h.model(|m| {
                let f = m.data.as_mut().unwrap();
                f.rx_phy = Some((8, mcs, sig2));
                f.queue.push_back(encrypted.clone());
            });
            h.pump();
            if h.received(&down) {
                return Err("unselected HT MCS/NSTS escaped native chain bounds");
            }
        }
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.rx_phy = Some((8, 15, 0x40));
            f.queue.push_back(encrypted);
        });
        h.pump();
        if !h.received(&down) {
            return Err("invalid multi-stream metadata consumed PN before valid MCS15");
        }
        let old = h
            .device
            .radio
            .try_lock()
            .unwrap()
            .htt
            .wmi
            .htc
            .transport
            .chain_sent
            .clone();
        if old.len() != 3 {
            return Err("actual native chain/NSS program not retained through RSNA/data");
        }
        drop(h);
        // A two-stream scan offer may narrow to one stream in the actual
        // response. The local request stays two-stream; native peer/rate and
        // receive admissions must use the narrower response, before PN.
        let h =
            Harness::new_on_profile(4, Dialect::Tlv, true, false, 5180, 0x8348, (Some(0x7b), 2));
        enable(&h);
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.ht_response.as_mut().unwrap()[6] = 0;
            f.ht_mcs_more = [0; 3];
            f.ht_peer_nss = 1;
            f.ht_rate_caps = 0x60;
            f.rx_phy = Some((8, 7, 0x40));
        });
        h.join()?;
        let encrypted = h.model(|m| m.data.as_mut().unwrap().downlink(&down));
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.rx_phy = Some((8, 15, 0x40));
            f.queue.push_back(encrypted.clone());
        });
        h.pump();
        if h.received(&down) {
            return Err("response-narrowed peer inherited scan-offer second stream");
        }
        h.model(|m| {
            let f = m.data.as_mut().unwrap();
            f.rx_phy = Some((8, 7, 0x40));
            f.queue.push_back(encrypted);
        });
        h.pump();
        if !h.received(&down) {
            return Err("response NSS rejection consumed same-PN first-stream packet");
        }
        Ok(())
    })()
    .map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/ath10k/chains",
    smoke_ath10k_two_stream_ppdu_mcs_stbc_and_response_maps_precede_same_pn
);
