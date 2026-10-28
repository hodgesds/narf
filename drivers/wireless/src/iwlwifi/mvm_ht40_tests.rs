//! Tag5 `HT40` program: a 40MHz PHY context (`iwl_mvm_phy_ctxt_cmd_data`,
//! `iwl_mvm_get_ctrl_pos`), ADD_STA `STA_FLG_FAT_EN_40MHZ`
//! (`iwl_mvm_sta_send_to_fw`) and TLC `max_ch_width`/SGI40
//! (`rs_fw_bw_from_sta_bw`, `rs_fw_sgi_cw_support`), Linux v7.2 `mvm/`.
use super::super::super::mvm_boot::feature_bits;
use super::*;

/// The fixture BSS on channel 1 operating 20/40MHz with secondary channel 5
/// (HT Operation SCA + any-width) and HT Capabilities SUP_WIDTH_20_40 |
/// SGI_40.
fn ht40_ies() -> Vec<u8> {
    let mut ies = ht_ies();
    ies[2] |= 2 | 64;
    ies[31] = 1 | 4;
    ies
}

/// A policy whose single rule covers the 2402..2442MHz span of channels
/// 1+5 with a 40MHz bandwidth.
fn wide_domain(bandwidth: u32) -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2442,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: 10,
            flags: RegFlags::empty(),
        }],
    }
}

fn last(h: &Harness, group: u8, command: u8, pick: impl Fn(&[u8]) -> bool) -> Option<Vec<u8>> {
    h.actor
        .lock()
        .commands
        .iter()
        .rev()
        .find(|(g, c, b)| *g == group && *c == command && pick(b))
        .map(|(_, _, b)| b.clone())
}

/// (PHY width, control position, ADD_STA FAT_EN, TLC max_ch_width, TLC SGI
/// bitmap) of the latest join.
fn widths(h: &Harness) -> Result<(u8, u8, u32, u8, u8), &'static str> {
    let phy = last(h, 1, 8, |b| b[4] == 1).ok_or("PHY context absent")?;
    let sta = last(h, 1, 0x18, |b| {
        b.len() == 48 && u32::from_le_bytes([b[24], b[25], b[26], b[27]]) & (3 << 26) != 0
    })
    .ok_or("ADD_STA PHY profile absent")?;
    let tlc = last(h, 5, 15, |_| true).ok_or("TLC configuration absent")?;
    let flags = u32::from_le_bytes([sta[20], sta[21], sta[22], sta[23]]);
    Ok((phy[18], phy[19], (flags >> 26) & 3, tlc[4], tlc[22]))
}

fn ht40_harness(features: u16, wide_nvm: bool) -> Result<Harness, &'static str> {
    let emission = if features == 0 { 2 } else { 5 };
    let h = Harness::build_nvm(false, true, emission, 3, false, false, features, wide_nvm)?;
    h.db.install(wide_domain(40));
    {
        let mut ap = h.actor.lock();
        ap.beacon_ies = Some(ht40_ies());
        ap.response_ies = Some(ht40_ies());
    }
    Ok(h)
}

fn smoke_mvm_ht40_program_prepares_40mhz_phy_sta_tlc_and_closes() -> TestResult {
    check(|| {
        let h = ht40_harness(feature_bits::HT40, true)?;
        {
            let mut ap = h.actor.lock();
            ap.phy_width = [1, 0];
            // HT MCS7, SGI, RATE_MCS_CHAN_WIDTH_40.
            ap.rx_rate = 0x0010_0a07;
        }
        h.join()?;
        if widths(&h)? != (1, 0, 1, 1, 3) {
            return Err("HT40 PHY/ADD_STA/TLC width encoding");
        }
        let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .map_err(|_| "HT40 DORA over 40MHz receive rates")?;
        if !NETWORK.matches_lease(&lease) {
            return Err("HT40 DORA leased wrong address");
        }
        let start = {
            let mut actor = h.actor.lock();
            actor.closing = true;
            actor.commands.len()
        };
        run(h.device.disassociate())?.map_err(|_| "HT40 ordered close")?;
        leaving_deauthentication_preceded_teardown(&h, start)?;
        // The removal carries the same 40MHz context (actor-validated).
        if last(&h, 1, 8, |b| b[4] == 3).is_none_or(|b| b[18..20] != [1, 0]) {
            return Err("HT40 PHY removal width");
        }
        if h.retained() != (0, 0, 0) || h.device.link_up() {
            return Err("HT40 close left native resources");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ht40",
    smoke_mvm_ht40_program_prepares_40mhz_phy_sta_tlc_and_closes
);

fn smoke_mvm_ht40_not_granted_keeps_20mhz_everywhere() -> TestResult {
    check(|| {
        // A 40MHz BSS with the tag2 program: 20MHz PHY, no FAT, TLC 20MHz.
        let h = ht40_harness(0, true)?;
        h.join()?;
        if widths(&h)? != (0, 0, 0, 0, 1) {
            return Err("HT40 encodings without a tag5 HT40 program");
        }
        run(h.device.disassociate())?.map_err(|_| "HT20 close")?;
        if h.retained() != (0, 0, 0) {
            return Err("HT20 close left native resources");
        }
        drop(h);
        // QOS_TIDS alone toward the same BSS stays 20MHz too.
        let h = ht40_harness(feature_bits::QOS_TIDS, true)?;
        h.join()?;
        if widths(&h)?.0 != 0 || widths(&h)?.2 != 0 {
            return Err("QOS_TIDS program widened the channel");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ht40",
    smoke_mvm_ht40_not_granted_keeps_20mhz_everywhere
);

fn smoke_mvm_ht40_refused_without_40mhz_authority() -> TestResult {
    check(|| {
        // Host policy limited to 20MHz: HT40 is dropped from the offer, so
        // its program is never selectable and nothing is published.
        let h = ht40_harness(feature_bits::HT40, true)?;
        h.db.install(wide_domain(20));
        if h.join().is_ok() {
            return Err("HT40 accepted under a 20MHz-only policy");
        }
        drop(h);
        // NVM without NVM_CHANNEL_40MHZ: never offered.
        let h = ht40_harness(feature_bits::HT40, false)?;
        if h.join().is_ok() {
            return Err("HT40 accepted without NVM 40MHz permission");
        }
        drop(h);
        // A 20MHz BSS: never offered.
        let h = ht40_harness(feature_bits::HT40, true)?;
        {
            let mut ap = h.actor.lock();
            ap.beacon_ies = Some(ht_ies());
            ap.response_ies = Some(ht_ies());
        }
        if h.join().is_ok() {
            return Err("HT40 accepted toward a 20MHz BSS");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ht40",
    smoke_mvm_ht40_refused_without_40mhz_authority
);

fn smoke_mvm_ht40_response_narrowing_fails_closed() -> TestResult {
    check(|| {
        // The prepared 40MHz context cannot follow a response that drops
        // the secondary channel: association fails without a carrier.
        let h = ht40_harness(feature_bits::HT40, true)?;
        {
            let mut ap = h.actor.lock();
            ap.phy_width = [1, 0];
            ap.response_ies = Some(ht_ies());
        }
        if h.join().is_ok() {
            return Err("HT40 accepted a 20MHz association response");
        }
        if h.device.link_up() {
            return Err("narrowed HT40 response left a carrier");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ht40",
    smoke_mvm_ht40_response_narrowing_fails_closed
);

fn smoke_mvm_ht40_nss2_combined_program() -> TestResult {
    check(|| {
        // One signed HT40|NSS2 program: 40MHz PHY/STA/TLC plus MIMO2.
        let h = ht40_harness(feature_bits::HT40 | feature_bits::NSS2, true)?;
        {
            let mut ap = h.actor.lock();
            let mut ies = ht40_ies();
            ies[6] = 0xff;
            ap.beacon_ies = Some(ies.clone());
            ap.response_ies = Some(ies);
            ap.phy_width = [1, 0];
        }
        h.join()?;
        let sta = last(&h, 1, 0x18, |b| {
            b.len() == 48 && u32::from_le_bytes([b[24], b[25], b[26], b[27]]) & (3 << 26) != 0
        })
        .ok_or("ADD_STA PHY profile absent")?;
        let tlc = last(&h, 5, 15, |_| true).ok_or("TLC configuration absent")?;
        if widths(&h)? != (1, 0, 1, 1, 3)
            || (u32::from_le_bytes([sta[20], sta[21], sta[22], sta[23]]) >> 28) & 3 != 1
            || tlc[16..18] != [0xff, 0]
            || tlc[6] != 3
        {
            return Err("HT40|NSS2 combined encodings");
        }
        run(h.device.disassociate())?.map_err(|_| "HT40|NSS2 close")?;
        if h.retained() != (0, 0, 0) {
            return Err("HT40|NSS2 close left native resources");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/ht40",
    smoke_mvm_ht40_nss2_combined_program
);
