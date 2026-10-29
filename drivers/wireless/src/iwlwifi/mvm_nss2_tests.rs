//! Tag5 `NSS2` program: HT MCS 8..15, ADD_STA `STA_FLG_MIMO_EN_MIMO2`
//! (`iwl_mvm_sta_send_to_fw`) and the TLC NSS2 rate map on every valid TX
//! chain (`rs_fw_set_supp_rates`, `rs_fw_set_active_chains`), Linux v7.2
//! `mvm/`.
use super::super::super::mvm_boot::feature_bits;
use super::*;

/// HT IEs whose AP receives MCS 0..15 (`rx_mask[1]`), with `cap0` as the
/// low HT Capability Information byte.
fn mimo_ies(cap0: u8) -> Vec<u8> {
    let mut ies = ht_ies();
    ies[2] = cap0;
    ies[6] = 0xff;
    ies
}

/// (ADD_STA MIMO_EN, TLC chains, TLC NSS2 MCS map) of the latest join.
fn streams(h: &Harness, version: u8) -> Result<(u32, u8, u16), &'static str> {
    let actor = h.actor.lock();
    let sta = actor
        .commands
        .iter()
        .rev()
        .find(|(g, c, b)| {
            *g == 1
                && *c == 0x18
                && b.len() == 48
                && u32::from_le_bytes([b[24], b[25], b[26], b[27]]) & (3 << 28) != 0
        })
        .ok_or("ADD_STA PHY profile absent")?;
    let tlc = actor
        .commands
        .iter()
        .rev()
        .find(|(g, c, _)| *g == 5 && *c == 15)
        .ok_or("TLC configuration absent")?;
    let flags = u32::from_le_bytes([sta.2[20], sta.2[21], sta.2[22], sta.2[23]]);
    let at = if version == 4 { 18 } else { 16 };
    Ok((
        (flags >> 28) & 3,
        tlc.2[6],
        u16::from_le_bytes([tlc.2[at], tlc.2[at + 1]]),
    ))
}

fn nss2_harness(features: u16, version: u8, cap0: u8) -> Result<Harness, &'static str> {
    let emission = if features == 0 { 2 } else { 5 };
    let h = Harness::build_features(false, true, emission, version, false, false, features)?;
    {
        let mut ap = h.actor.lock();
        ap.beacon_ies = Some(mimo_ies(cap0));
        ap.response_ies = Some(mimo_ies(cap0));
    }
    Ok(h)
}

fn smoke_mvm_nss2_program_sets_mimo2_tlc_map_and_both_chains() -> TestResult {
    check(|| {
        for version in [3, 4] {
            let h = nss2_harness(feature_bits::NSS2, version, 0x2c)?;
            // HT MCS15 (MCS7 + RATE_MCS_NSS_MSK_V2), SGI.
            h.actor.lock().rx_rate = 0x0010_0217;
            h.join()?;
            if streams(&h, version)? != (1, 3, 0xff) {
                return Err("NSS2 ADD_STA MIMO2/TLC chains/NSS2 map");
            }
            if version == 3 {
                let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
                    .map_err(|_| "NSS2 DORA over two-stream receive rates")?;
                if !NETWORK.matches_lease(&lease) {
                    return Err("NSS2 DORA leased wrong address");
                }
            }
            let start = {
                let mut actor = h.actor.lock();
                actor.closing = true;
                actor.commands.len()
            };
            run(h.device.disassociate())?.map_err(|_| "NSS2 ordered close")?;
            leaving_deauthentication_preceded_teardown(&h, start)?;
            if h.retained() != (0, 0, 0) || h.device.link_up() {
                return Err("NSS2 close left native resources");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nss2",
    smoke_mvm_nss2_program_sets_mimo2_tlc_map_and_both_chains
);

fn smoke_mvm_nss2_not_granted_stays_siso() -> TestResult {
    check(|| {
        // A two-stream AP with the tag2 program: SISO, one chain, no map.
        let h = nss2_harness(0, 3, 0x2c)?;
        h.join()?;
        if streams(&h, 3)? != (0, 1, 0) {
            return Err("MIMO encodings without a tag5 NSS2 program");
        }
        run(h.device.disassociate())?.map_err(|_| "SISO close")?;
        if h.retained() != (0, 0, 0) {
            return Err("SISO close left native resources");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nss2",
    smoke_mvm_nss2_not_granted_stays_siso
);

fn smoke_mvm_nss2_refused_toward_single_stream_or_static_smps_peer() -> TestResult {
    check(|| {
        // An AP receiving MCS 0..7 only: NSS2 is never offered.
        let h = Harness::build_features(false, true, 5, 3, false, false, feature_bits::NSS2)?;
        if h.join().is_ok() {
            return Err("NSS2 accepted toward a single-stream AP");
        }
        drop(h);
        // A static-SMPS AP (SM Power Save 0) receives one stream.
        let h = nss2_harness(feature_bits::NSS2, 3, 0x20)?;
        if h.join().is_ok() {
            return Err("NSS2 accepted toward a static-SMPS AP");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/nss2",
    smoke_mvm_nss2_refused_toward_single_stream_or_static_smps_peer
);
