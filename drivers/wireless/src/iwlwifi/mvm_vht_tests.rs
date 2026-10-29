//! Tag5 `VHT` program on a 5GHz 80MHz BSS: an 80MHz PHY context
//! (`iwl_mvm_phy_ctxt_cmd_data`, `iwl_mvm_get_ctrl_pos`), ADD_STA FAT_EN
//! (`iwl_mvm_sta_send_to_fw`) and the TLC VHT mode and rate map
//! (`rs_fw_vht_set_enabled_rates`), Linux v7.2 `mvm/`.
use super::super::super::mvm_boot::feature_bits;
use super::*;

const VHT80: u16 = feature_bits::HT40 | feature_bits::VHT;

/// Channel 36 operating 80MHz around center 42: HT 20/40 with secondary
/// 40 (SCA), SGI20/40, VHT SGI80 with MCS 0..9 on one stream and a VHT
/// Operation of width 1 / CCFS0 42 / basic MCS 0..7.
fn vht_ies(width: u8) -> Vec<u8> {
    let mut ies = ht_ies();
    ies[2] |= 2 | 64;
    ies[30] = 36;
    ies[31] = 1 | 4;
    let mut cap = [0; 12];
    cap[0] = 1 << 5;
    cap[4..6].copy_from_slice(&0xfffeu16.to_le_bytes());
    cap[8..10].copy_from_slice(&0xfffeu16.to_le_bytes());
    ies.extend_from_slice(&[191, 12]);
    ies.extend_from_slice(&cap);
    ies.extend_from_slice(&[192, 5, width, 42, 0, 0xfc, 0xff]);
    ies
}

fn five_ghz(bandwidth: u32) -> RegulatoryDomain {
    RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5250,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: 10,
            flags: RegFlags::empty(),
        }],
    }
}

fn vht_harness(features: u16, width: u8) -> Result<Harness, &'static str> {
    let emission = if features == 0 { 2 } else { 5 };
    let h = Harness::build_nvm(false, true, emission, 3, false, false, features, 2)?;
    h.db.install(five_ghz(80));
    {
        let mut ap = h.actor.lock();
        ap.security.ap =
            FakeAp::open(NETWORK, b"net", 36, 7).map_err(|_| "5GHz fixture AP config")?;
        ap.channel = 36;
        ap.beacon_ies = Some(vht_ies(width));
        ap.response_ies = Some(vht_ies(width));
    }
    Ok(h)
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

/// (PHY width, control position, ADD_STA FAT_EN, TLC max_ch_width, TLC
/// mode, TLC SGI bitmap, TLC NSS1 map) of the latest join.
/// See [`profile`].
type VhtProfile = (u8, u8, u32, u8, u8, u8, u16);

fn profile(h: &Harness) -> Result<VhtProfile, &'static str> {
    let phy = last(h, 1, 8, |b| b[4] == 1).ok_or("PHY context absent")?;
    let sta = last(h, 1, 0x18, |b| {
        b.len() == 48 && u32::from_le_bytes([b[24], b[25], b[26], b[27]]) & (3 << 26) != 0
    })
    .ok_or("ADD_STA PHY profile absent")?;
    let tlc = last(h, 5, 15, |_| true).ok_or("TLC configuration absent")?;
    let flags = u32::from_le_bytes([sta[20], sta[21], sta[22], sta[23]]);
    Ok((
        phy[18],
        phy[19],
        (flags >> 26) & 3,
        tlc[4],
        tlc[5],
        tlc[22],
        u16::from_le_bytes([tlc[12], tlc[13]]),
    ))
}

fn smoke_mvm_vht80_program_prepares_80mhz_vht_and_closes() -> TestResult {
    check(|| {
        let h = vht_harness(VHT80, 1)?;
        {
            let mut ap = h.actor.lock();
            ap.phy_width = [2, 1];
            // VHT MCS9, RATE_MCS_CHAN_WIDTH_80, SGI.
            ap.rx_rate = 0x0010_1309;
        }
        h.join()?;
        if profile(&h)? != (2, 1, 3, 2, 2, 7, 0x3ff) {
            return Err("VHT80 PHY/ADD_STA/TLC encoding");
        }
        let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .map_err(|_| "VHT80 DORA over VHT receive rates")?;
        if !NETWORK.matches_lease(&lease) {
            return Err("VHT80 DORA leased wrong address");
        }
        let start = {
            let mut actor = h.actor.lock();
            actor.closing = true;
            actor.commands.len()
        };
        run(h.device.disassociate())?.map_err(|_| "VHT80 ordered close")?;
        leaving_deauthentication_preceded_teardown(&h, start)?;
        if last(&h, 1, 8, |b| b[4] == 3).is_none_or(|b| b[18..20] != [2, 1]) {
            return Err("VHT80 PHY removal width");
        }
        if h.retained() != (0, 0, 0) || h.device.link_up() {
            return Err("VHT80 close left native resources");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/vht",
    smoke_mvm_vht80_program_prepares_80mhz_vht_and_closes
);

fn smoke_mvm_vht_not_granted_stays_ht() -> TestResult {
    check(|| {
        // HT40 alone toward the 80MHz VHT BSS: 40MHz HT (control 36 below
        // center 38), TLC HT mode, no VHT map.
        let h = vht_harness(feature_bits::HT40, 1)?;
        h.actor.lock().phy_width = [1, 0];
        h.join()?;
        if profile(&h)? != (1, 0, 1, 1, 1, 3, 0xff) {
            return Err("VHT encodings without a tag5 VHT program");
        }
        run(h.device.disassociate())?.map_err(|_| "HT40 5GHz close")?;
        if h.retained() != (0, 0, 0) {
            return Err("HT40 5GHz close left native resources");
        }
        drop(h);
        // The tag2 program: 20MHz HT.
        let h = vht_harness(0, 1)?;
        h.join()?;
        if profile(&h)? != (0, 0, 0, 0, 1, 1, 0xff) {
            return Err("VHT BSS widened the tag2 program");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/vht",
    smoke_mvm_vht_not_granted_stays_ht
);

fn smoke_mvm_vht_refused_without_80mhz_authority() -> TestResult {
    check(|| {
        // A 40MHz-limited policy drops VHT80 from the offer.
        let h = vht_harness(VHT80, 1)?;
        h.db.install(five_ghz(40));
        if h.join().is_ok() {
            return Err("VHT80 accepted under a 40MHz policy");
        }
        drop(h);
        // A 20/40MHz VHT BSS (VHT Operation width 0) is never offered.
        let h = vht_harness(VHT80, 0)?;
        if h.join().is_ok() {
            return Err("VHT80 accepted toward a 40MHz VHT BSS");
        }
        drop(h);
        // A VHT program without HT40 names an unsupported set.
        let h = vht_harness(feature_bits::VHT, 1)?;
        if h.join().is_ok() {
            return Err("VHT program accepted without HT40");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/vht",
    smoke_mvm_vht_refused_without_80mhz_authority
);

const VHT160: u16 = VHT80 | feature_bits::WIDTH_160;

/// [`vht_ies`] for a contiguous 160MHz BSS: VHT Capabilities 160MHz +
/// SGI160 and a VHT Operation with CCFS0 42 / CCFS1 50.
fn vht160_ies() -> Vec<u8> {
    let mut ies = vht_ies(1);
    ies[80] |= 4 | 64;
    ies[96] = 50;
    ies
}

fn vht160_harness(features: u16, bandwidth: u32) -> Result<Harness, &'static str> {
    let emission = if features == 0 { 2 } else { 5 };
    let h = Harness::build_nvm(false, true, emission, 3, false, false, features, 3)?;
    h.db.install(RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 5170,
            freq_end_mhz: 5330,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: 10,
            flags: RegFlags::empty(),
        }],
    });
    {
        let mut ap = h.actor.lock();
        ap.security.ap =
            FakeAp::open(NETWORK, b"net", 36, 7).map_err(|_| "5GHz fixture AP config")?;
        ap.channel = 36;
        ap.beacon_ies = Some(vht160_ies());
        ap.response_ies = Some(vht160_ies());
    }
    Ok(h)
}

fn smoke_mvm_vht160_program_prepares_160mhz_and_closes() -> TestResult {
    check(|| {
        let h = vht160_harness(VHT160, 160)?;
        {
            let mut ap = h.actor.lock();
            // Control 36 is 70MHz below center 50: iwl_mvm_get_ctrl_pos 3.
            ap.phy_width = [3, 3];
            // VHT MCS9, RATE_MCS_CHAN_WIDTH_160, SGI.
            ap.rx_rate = 0x0010_1b09;
        }
        h.join()?;
        if profile(&h)? != (3, 3, 3, 3, 2, 15, 0x3ff) {
            return Err("VHT160 PHY/ADD_STA/TLC encoding");
        }
        let tlc = last(&h, 5, 15, |_| true).ok_or("TLC configuration absent")?;
        if tlc[14..16] != 0x3ffu16.to_le_bytes() || tlc[16..20] != [0; 4] {
            return Err("VHT160 TLC IWL_TLC_MCS_PER_BW_160 map");
        }
        let lease = narf_net::dhcp::dhcp_acquire(h.device.name(), 0)
            .map_err(|_| "VHT160 DORA over 160MHz receive rates")?;
        if !NETWORK.matches_lease(&lease) {
            return Err("VHT160 DORA leased wrong address");
        }
        let start = {
            let mut actor = h.actor.lock();
            actor.closing = true;
            actor.commands.len()
        };
        run(h.device.disassociate())?.map_err(|_| "VHT160 ordered close")?;
        leaving_deauthentication_preceded_teardown(&h, start)?;
        if last(&h, 1, 8, |b| b[4] == 3).is_none_or(|b| b[18..20] != [3, 3]) {
            return Err("VHT160 PHY removal width");
        }
        if h.retained() != (0, 0, 0) || h.device.link_up() {
            return Err("VHT160 close left native resources");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/vht",
    smoke_mvm_vht160_program_prepares_160mhz_and_closes
);

fn smoke_mvm_vht160_not_granted_or_not_permitted_stays_80mhz() -> TestResult {
    check(|| {
        // VHT80 toward the 160MHz BSS: its primary 80MHz block only.
        let h = vht160_harness(VHT80, 160)?;
        h.actor.lock().phy_width = [2, 1];
        h.join()?;
        if profile(&h)? != (2, 1, 3, 2, 2, 7, 0x3ff) {
            return Err("160MHz BSS widened a VHT80 program");
        }
        run(h.device.disassociate())?.map_err(|_| "VHT80 close")?;
        if h.retained() != (0, 0, 0) {
            return Err("VHT80 close left native resources");
        }
        drop(h);
        // An 80MHz-limited policy drops WIDTH_160 from the offer.
        let h = vht160_harness(VHT160, 80)?;
        if h.join().is_ok() {
            return Err("VHT160 accepted under an 80MHz policy");
        }
        drop(h);
        // An 80MHz BSS (no CCFS1) never offers WIDTH_160.
        let h = vht160_harness(VHT160, 160)?;
        {
            let mut ap = h.actor.lock();
            ap.beacon_ies = Some(vht_ies(1));
            ap.response_ies = Some(vht_ies(1));
        }
        if h.join().is_ok() {
            return Err("VHT160 accepted toward an 80MHz BSS");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/vht",
    smoke_mvm_vht160_not_granted_or_not_permitted_stays_80mhz
);
